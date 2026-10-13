// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud // import "go.opentelemetry.io/obi/pkg/internal/cloud"

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// route53EscapedWildcard is the octal escape that Route53 returns for a "*" wildcard label.
const route53EscapedWildcard = `\052`

const DefaultRoute53RefreshInterval = 5 * time.Minute

type Route53Client interface {
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

type Route53Inventory struct {
	RefreshInterval time.Duration
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
	for _, zone := range i.hostedZoneIDs {
		pages := route53.NewListResourceRecordSetsPaginator(i.client, &route53.ListResourceRecordSetsInput{HostedZoneId: &zone})
		for pages.HasMorePages() {
			out, err := pages.NextPage(ctx)
			if err != nil {
				if (retry.ThrottleErrorCode{Codes: retry.DefaultThrottleErrorCodes}).IsErrorThrottle(err) == aws.TrueTernary {
					if i.backoff == 0 {
						i.backoff = i.RefreshInterval
					}
					const maxBackoffMultiplier = 8
					if i.backoff < i.RefreshInterval*maxBackoffMultiplier {
						i.backoff *= 2
					}
				}
				return fmt.Errorf("listing Route53 records for hosted zone %q: %w", zone, err)
			}
			for _, record := range out.ResourceRecordSets {
				addRoute53Record(snapshot.ServiceByIP, record)
			}
		}
	}
	i.backoff = 0
	return nil
}

func addRoute53Record(next map[string]string, record types.ResourceRecordSet) {
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
		ip := addr.Unmap().String()
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
