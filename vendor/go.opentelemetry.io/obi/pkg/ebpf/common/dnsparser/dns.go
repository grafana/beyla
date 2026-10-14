// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dnsparser // import "go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"

import "fmt"

type DNSId struct {
	HostPID uint32
	ID      uint16
}

type Type uint16

const (
	// ResourceHeader.Type and Question.Type
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41

	// Question.Type
	TypeWKS   Type = 11
	TypeHINFO Type = 13
	TypeMINFO Type = 14
	TypeAXFR  Type = 252
	TypeALL   Type = 255
)

var typeNames = map[Type]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
	TypeOPT:   "OPT",
	TypeWKS:   "WKS",
	TypeHINFO: "HINFO",
	TypeMINFO: "MINFO",
	TypeAXFR:  "AXFR",
	TypeALL:   "ALL",
}

// An RCode is a DNS response status code.
type RCode uint16

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
// Header.RCode values.
const (
	RCodeSuccess        RCode = 0  // NOERROR
	RCodeFormatError    RCode = 1  // FORMERR
	RCodeServerFailure  RCode = 2  // SERVFAIL
	RCodeNameError      RCode = 3  // NXDOMAIN
	RCodeNotImplemented RCode = 4  // NOTIMP
	RCodeRefused        RCode = 5  // REFUSED
	RcodeYXDomain       RCode = 6  // YXDOMAIN
	RcodeYXRRSet        RCode = 7  // YXRRSET
	RcodeNXRRSet        RCode = 8  // NXRRSET
	RcodeNotAuth        RCode = 9  // NOTAUTH
	RcodeNotZone        RCode = 10 // NOTZONE
	RcodeDSO            RCode = 11 // DSOTYPENI
)

var rCodeNames = map[RCode]string{
	RCodeSuccess:        "NoError",
	RCodeFormatError:    "FormErr",
	RCodeServerFailure:  "ServFail",
	RCodeNameError:      "NXDomain",
	RCodeNotImplemented: "NotImp",
	RCodeRefused:        "Refused",
	RcodeYXDomain:       "YXDomain",
	RcodeYXRRSet:        "YXRRSet",
	RcodeNXRRSet:        "NXRRSet",
	RcodeNotAuth:        "NotAuth",
	RcodeNotZone:        "NotZone",
	RcodeDSO:            "DSOTYPENI",
}

// String implements fmt.Stringer.String.
func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("%d", t)
}

// String implements fmt.Stringer.String.
func (r RCode) String() string {
	if n, ok := rCodeNames[r]; ok {
		return n
	}
	return fmt.Sprintf("%d", r)
}
