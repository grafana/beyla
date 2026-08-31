// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"net"
	"strings"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func dnsEventExpireHandler(emitSpans func([]request.Span)) func(key dnsparser.DNSId, span *request.Span) {
	return func(_ dnsparser.DNSId, span *request.Span) {
		// final status is -1, which means we never received a response
		if span.Status == -1 && emitSpans != nil {
			span.Status = int(dnsparser.RCodeRefused)
			emitSpans([]request.Span{*span})
		}
	}
}

func readDNSEventIntoSpan(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[DNSInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	l := min(int(event.Len), len(event.Buf[:]))

	msg := dnsmessage.Message{}
	if err := msg.Unpack(event.Buf[:l]); err != nil {
		return request.Span{}, true, err
	}

	peer := ""
	hostname := ""
	hostPort := 0
	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	dnsID := dnsparser.DNSId{HostPID: event.Pid.HostPid, ID: event.Id}

	curName := ""
	if len(msg.Questions) > 0 {
		curName = msg.Questions[0].Name.String()
	}

	span, ok := parseCtx.dnsEvents.Get(dnsID)

	// The transaction ID is 0 in the unconnected resolver case, so the pairing key
	// degenerates to (HostPID, 0) and collides across a process's concurrent DNS
	// transactions. A different question name means a collision rather than a
	// retransmit, so start a fresh span: otherwise the stale occupant suppresses
	// this answer at the duplicate guard below.
	if ok && span.Path != "" && curName != "" && span.Path != curName {
		ok = false
	}

	if !ok {
		span = &request.Span{
			Type:              request.EventTypeDNS,
			Method:            "",
			Statement:         "",
			Path:              "",
			Peer:              peer,
			PeerPort:          int(event.Conn.S_port),
			Host:              hostname,
			HostPort:          hostPort,
			ContentLength:     0,
			RequestStart:      int64(event.Tp.Ts),
			Start:             int64(event.Tp.Ts),
			End:               int64(event.Tp.Ts + 1),
			TraceID:           trace.TraceID(event.Tp.TraceId),
			SpanID:            trace.SpanID(event.Tp.SpanId),
			ParentSpanID:      trace.SpanID(event.Tp.ParentId),
			ParentConditional: event.ParentStatus == parentStatusConditional,
			Status:            int(-1),
			Pid: request.PidInfo{
				HostPID:   app.PID(event.Pid.HostPid),
				UserPID:   app.PID(event.Pid.UserPid),
				Namespace: event.Pid.Ns,
			},
		}
	}

	if len(msg.Questions) > 0 {
		span.Method = dnsparser.Type(msg.Questions[0].Type).String()
		span.Path = curName
	}

	var addresses []string

	for _, answer := range msg.Answers {
		var str string
		switch answer.Header.Type {
		case dnsmessage.TypeA:
			ipv4 := answer.Body.(*dnsmessage.AResource)
			str = net.IP(ipv4.A[:]).String()
		case dnsmessage.TypeAAAA:
			ipv6 := answer.Body.(*dnsmessage.AAAAResource)
			str = net.IP(ipv6.AAAA[:]).String()
		}
		if str != "" {
			addresses = append(addresses, str)
		}
	}

	if span.Status == int(dnsparser.RCodeSuccess) && len(span.Statement) > 0 {
		return *span, true, nil // ignore duplicate
	}

	if len(addresses) > 0 {
		if span.Statement != "" {
			addresses = append(addresses, span.Statement)
		}
		span.Statement = strings.Join(addresses, ",")
	}

	parseCtx.dnsEvents.Add(dnsID, span)

	var responseCode uint16

	prevStatus := span.Status

	if msg.Response {
		responseCode = uint16(msg.RCode)
		span.Status = int(responseCode)
		span.End = int64(event.Tp.Ts)
	} else {
		return *span, true, nil // ignore until we get a response or never hear back
	}

	if prevStatus == span.Status && span.Status != int(dnsparser.RCodeSuccess) {
		return *span, true, nil // ignore duplicate errors
	}

	return *span, false, nil
}
