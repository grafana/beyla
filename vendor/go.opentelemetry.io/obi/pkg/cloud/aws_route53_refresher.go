// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud // import "go.opentelemetry.io/obi/pkg/cloud"

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
)

// route53EscapedWildcard is the octal escape that Route53 returns for a "*" wildcard label.
const route53EscapedWildcard = `\052`

const DefaultRoute53RefreshInterval = 5 * time.Minute

// Non-public special-purpose allocations from the IANA IPv4 and IPv6 registries.
// The exceptions below preserve reachable allocations within these ranges.
var route53NonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // Current network
	netip.MustParsePrefix("100.64.0.0/10"),   // Shared address space (carrier-grade NAT)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // Documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // Deprecated IPv6 relay addresses
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // Documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // Documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved
	netip.MustParsePrefix("64:ff9b:1::/48"),  // Local IPv4-to-IPv6 translation
	netip.MustParsePrefix("100::/64"),        // Discard-only
	netip.MustParsePrefix("100:0:0:1::/64"),  // Dummy addresses
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),   // Documentation
	netip.MustParsePrefix("3fff::/20"),       // Documentation
	netip.MustParsePrefix("5f00::/16"),       // Segment routing
}

var route53PublicExceptions = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.9/32"),
	netip.MustParsePrefix("192.0.0.10/32"),
	netip.MustParsePrefix("2001::/32"), // Teredo: IPv6 carried over IPv4; reachability depends on the embedded IPv4 address.
	netip.MustParsePrefix("2001:1::1/128"),
	netip.MustParsePrefix("2001:1::2/128"),
	netip.MustParsePrefix("2001:1::3/128"),
	netip.MustParsePrefix("2001:3::/32"),
	netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:30::/28"),
}

type Route53Client interface {
	ListHostedZonesByVPC(context.Context, *route53.ListHostedZonesByVPCInput, ...func(*route53.Options)) (*route53.ListHostedZonesByVPCOutput, error)
	ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

type Route53Inventory struct {
	RefreshInterval time.Duration
	VPCID           string
	VPCRegion       string
	initialized     bool
	backoff         time.Duration
	client          Route53Client
	hostedZoneIDs   []string
}

func NewRoute53Inventory(client Route53Client, hostedZoneIDs []string) *Route53Inventory {
	return &Route53Inventory{
		RefreshInterval: DefaultRoute53RefreshInterval,
		client:          client,
		hostedZoneIDs:   slices.Clone(hostedZoneIDs),
	}
}

func (i *Route53Inventory) Name() string { return "route53" }

func (i *Route53Inventory) Refresh(ctx context.Context, snapshot *MetadataSnapshot) error {
	err := i.refresh(ctx, snapshot)
	if err == nil {
		i.initialized = true
		i.backoff = 0
		return nil
	}
	if !i.initialized && route53AccessDenied(err) {
		permissions := "route53:ListResourceRecordSets, route53:ListHostedZones"
		if i.VPCID != "" && i.VPCRegion != "" {
			permissions += ", route53:ListHostedZonesByVPC"
		}
		return fmt.Errorf("%w: grant %s and restart OBI to enable Route53 name resolution: %w", ErrMetadataUnavailable, permissions, err)
	}
	if (retry.ThrottleErrorCode{Codes: retry.DefaultThrottleErrorCodes}).IsErrorThrottle(err) == aws.TrueTernary {
		if i.backoff == 0 {
			i.backoff = i.RefreshInterval
		}
		const maxBackoffMultiplier = 8
		if i.backoff < i.RefreshInterval*maxBackoffMultiplier {
			i.backoff *= 2
		}
	}
	return err
}

func (i *Route53Inventory) refresh(ctx context.Context, snapshot *MetadataSnapshot) error {
	zones, err := i.discoverZones(ctx)
	if err != nil {
		return err
	}
	publicNames := map[string]string{}
	privateNames := map[string]string{}
	hasReadableZone := false
	var accessDenied error
	for _, zone := range zones {
		if !i.zoneSelected(zone.id) {
			continue
		}
		zoneNames, err := i.readZoneRecords(ctx, zone)
		if err != nil {
			if route53AccessDenied(err) {
				accessDenied = err
				continue
			}
			return err
		}
		hasReadableZone = true
		names := privateNames
		if zone.public {
			names = publicNames
		}
		for ip, name := range zoneNames {
			if previous, ok := names[ip]; !ok || name < previous {
				names[ip] = name
			}
		}
	}
	if !hasReadableZone && accessDenied != nil {
		return accessDenied
	}
	maps.Copy(snapshot.ServiceByIP, publicNames)
	maps.Copy(snapshot.ServiceByIP, privateNames)
	return nil
}

func (i *Route53Inventory) zoneSelected(zoneID string) bool {
	if len(i.hostedZoneIDs) == 0 {
		return true
	}
	zoneID = strings.TrimPrefix(zoneID, "/hostedzone/")
	for _, configuredID := range i.hostedZoneIDs {
		if strings.TrimPrefix(configuredID, "/hostedzone/") == zoneID {
			return true
		}
	}
	return false
}

func route53AccessDenied(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) &&
		(apiErr.ErrorCode() == "AccessDenied" || apiErr.ErrorCode() == "AccessDeniedException")
}

func (i *Route53Inventory) readZoneRecords(ctx context.Context, zone route53Zone) (map[string]string, error) {
	names := map[string]string{}
	pages := route53.NewListResourceRecordSetsPaginator(i.client, &route53.ListResourceRecordSetsInput{HostedZoneId: &zone.id})
	for pages.HasMorePages() {
		out, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Route53 records for hosted zone %q: %w", zone.id, err)
		}
		for _, record := range out.ResourceRecordSets {
			addRoute53Record(names, record, zone.public)
		}
	}
	return names, nil
}

type route53Zone struct {
	id     string
	public bool
}

func (i *Route53Inventory) discoverZones(ctx context.Context) ([]route53Zone, error) {
	var zones []route53Zone
	pages := route53.NewListHostedZonesPaginator(i.client, &route53.ListHostedZonesInput{})
	for pages.HasMorePages() {
		out, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Route53 hosted zones: %w", err)
		}
		for _, zone := range out.HostedZones {
			if zone.Config == nil || !zone.Config.PrivateZone {
				zones = append(zones, route53Zone{id: aws.ToString(zone.Id), public: true})
			}
		}
	}
	if i.VPCID == "" || i.VPCRegion == "" {
		return zones, nil
	}
	input := &route53.ListHostedZonesByVPCInput{
		VPCId: &i.VPCID, VPCRegion: types.VPCRegion(i.VPCRegion),
	}
	for {
		out, err := i.client.ListHostedZonesByVPC(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("listing Route53 hosted zones for VPC %q: %w", i.VPCID, err)
		}
		for _, zone := range out.HostedZoneSummaries {
			zones = append(zones, route53Zone{id: aws.ToString(zone.HostedZoneId)})
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		input.NextToken = out.NextToken
	}
	return zones, nil
}

func addRoute53Record(next map[string]string, record types.ResourceRecordSet, public bool) {
	if record.Type != types.RRTypeA && record.Type != types.RRTypeAaaa {
		return
	}
	name := strings.TrimSuffix(strings.ToLower(aws.ToString(record.Name)), ".")
	if name == "" || strings.Contains(name, "*") || strings.Contains(name, route53EscapedWildcard) {
		return
	}
	for _, resource := range record.ResourceRecords {
		addr, err := netip.ParseAddr(aws.ToString(resource.Value))
		if err != nil || (record.Type == types.RRTypeA) != addr.Is4() {
			continue
		}
		addr = addr.Unmap()
		if public && !route53PublicAddress(addr) {
			continue
		}
		ip := addr.String()
		// DNS names need not be unique per IP; keep selection independent of API order.
		if previous, ok := next[ip]; !ok || name < previous {
			next[ip] = name
		}
	}
}

// RefreshDelay spreads initial discovery across the interval and jitters later
// polls by up to 20 percent. Throttling backs off to at most eight intervals.
func (i *Route53Inventory) RefreshDelay(initial bool) time.Duration {
	interval := i.RefreshInterval
	if initial {
		return time.Duration(rand.Int64N(int64(interval)))
	}
	if i.backoff > interval {
		interval = i.backoff
	}
	return interval - interval/5 + time.Duration(rand.Int64N(int64(2*(interval/5)+1)))
}

func route53PublicAddress(addr netip.Addr) bool {
	if addr.IsPrivate() || !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range route53PublicExceptions {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range route53NonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
