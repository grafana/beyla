package transport

import (
	"fmt"
	"strconv"
	"strings"
)

// Protocol value stores the L4 transport protocol (TCP, UDP....) according to
// the values taken from the list of "Standard well-defined IP protocols" from uapi/linux/in.h
type Protocol uint8

const (
	IP       = Protocol(0)
	ICMP     = Protocol(1)
	IGMP     = Protocol(2)
	IPIP     = Protocol(4)
	TCP      = Protocol(6)
	EGP      = Protocol(8)
	PUP      = Protocol(12)
	UDP      = Protocol(17)
	IDP      = Protocol(22)
	TP       = Protocol(29)
	DCCP     = Protocol(33)
	IPV6     = Protocol(41)
	RSVP     = Protocol(46)
	GRE      = Protocol(47)
	ESP      = Protocol(50)
	AH       = Protocol(51)
	MTP      = Protocol(92)
	BEETPH   = Protocol(94)
	ENCAP    = Protocol(98)
	PIM      = Protocol(103)
	COMP     = Protocol(108)
	L2TP     = Protocol(115)
	SCTP     = Protocol(132)
	UDPLITE  = Protocol(136)
	MPLS     = Protocol(137)
	ETHERNET = Protocol(143)
	RAW      = Protocol(255)

// TODO: consider adding an extra byte to Protocol to support this protocol
//
//	MPTCP = Protocol(262)
)

// String representation of the Protocol enum
//
//nolint:cyclop
func (p Protocol) String() string {
	switch p {
	case IP:
		return "IP"
	case ICMP:
		return "ICMP"
	case IGMP:
		return "IGMP"
	case IPIP:
		return "IPIP"
	case TCP:
		return "TCP"
	case EGP:
		return "EGP"
	case PUP:
		return "PUP"
	case UDP:
		return "UDP"
	case IDP:
		return "IDP"
	case TP:
		return "TP"
	case DCCP:
		return "DCCP"
	case IPV6:
		return "IPV6"
	case RSVP:
		return "RSVP"
	case GRE:
		return "GRE"
	case ESP:
		return "ESP"
	case AH:
		return "AH"
	case MTP:
		return "MTP"
	case BEETPH:
		return "BEETPH"
	case ENCAP:
		return "ENCAP"
	case PIM:
		return "PIM"
	case COMP:
		return "COMP"
	case L2TP:
		return "L2TP"
	case SCTP:
		return "SCTP"
	case UDPLITE:
		return "UDPLITE"
	case MPLS:
		return "MPLS"
	case ETHERNET:
		return "ETHERNET"
	case RAW:
		return "RAW"
	}
	return strconv.Itoa(int(p))
}

// ParseProtocol returns the Protocol enum from the provided string
//
//nolint:cyclop
func ParseProtocol(str string) (Protocol, error) {
	switch strings.ToUpper(str) {
	case "IP":
		return IP, nil
	case "ICMP":
		return ICMP, nil
	case "IGMP":
		return IGMP, nil
	case "IPIP":
		return IPIP, nil
	case "TCP":
		return TCP, nil
	case "EGP":
		return EGP, nil
	case "PUP":
		return PUP, nil
	case "UDP":
		return UDP, nil
	case "IDP":
		return IDP, nil
	case "TP":
		return TP, nil
	case "DCCP":
		return DCCP, nil
	case "IPV6":
		return IPV6, nil
	case "RSVP":
		return RSVP, nil
	case "GRE":
		return GRE, nil
	case "ESP":
		return ESP, nil
	case "AH":
		return AH, nil
	case "MTP":
		return MTP, nil
	case "BEETPH":
		return BEETPH, nil
	case "ENCAP":
		return ENCAP, nil
	case "PIM":
		return PIM, nil
	case "COMP":
		return COMP, nil
	case "L2TP":
		return L2TP, nil
	case "SCTP":
		return SCTP, nil
	case "UDPLITE":
		return UDPLITE, nil
	case "MPLS":
		return MPLS, nil
	case "ETHERNET":
		return ETHERNET, nil
	case "RAW":
		return RAW, nil
	}
	return 0, fmt.Errorf("unknown protocol %q", str)
}
