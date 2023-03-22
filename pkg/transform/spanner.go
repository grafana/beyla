package transform

import (
	"bytes"
	"net"
	"strconv"
	"time"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"

	"github.com/gavv/monotime"
)

// HTTPRequestSpan contains the information being submitted as
type HTTPRequestSpan struct {
	Method   string
	Path     string
	Route    string
	Peer     string
	PeerPort int
	Host     string
	HostPort int
	LocalIP  string
	Status   int
	Start    time.Time
	End      time.Time
}

var localIP = getLocalIPv4()

func getLocalIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func ConvertToSpan(in <-chan nethttp.HTTPRequestTrace, out chan<- HTTPRequestSpan) {
	cnv := newConverter()
	for trace := range in {
		out <- cnv.convert(&trace)
	}
}

func newConverter() converter {
	return converter{
		monoClock: monotime.Now,
		clock:     time.Now,
	}
}

type converter struct {
	clock     func() time.Time
	monoClock func() time.Duration
}

func extractHostPort(b []uint8) (string, int) {
	addrLen := bytes.IndexByte(b, 0)
	if addrLen < 0 {
		addrLen = len(b)
	}

	peer := ""
	peerPort := 0

	if addrLen > 0 {
		addr := string(b[:addrLen])
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			peer = addr
		} else {
			peer = ip
			peerPort, _ = strconv.Atoi(port)
		}
	}

	return peer, peerPort
}

func (c *converter) convert(trace *nethttp.HTTPRequestTrace) HTTPRequestSpan {
	now := time.Now()
	monoNow := c.monoClock()
	startDelta := monoNow - time.Duration(trace.StartMonotimeNs)
	endDelta := monoNow - time.Duration(trace.EndMonotimeNs)

	// From C, assuming 0-ended strings
	methodLen := bytes.IndexByte(trace.Method[:], 0)
	if methodLen < 0 {
		methodLen = len(trace.Method)
	}
	pathLen := bytes.IndexByte(trace.Path[:], 0)
	if pathLen < 0 {
		pathLen = len(trace.Path)
	}

	peer, peerPort := extractHostPort(trace.RemoteAddr[:])
	host, hostPort := extractHostPort(trace.Host[:])

	return HTTPRequestSpan{
		Method:   string(trace.Method[:methodLen]),
		Path:     string(trace.Path[:pathLen]),
		Peer:     peer,
		PeerPort: peerPort,
		Host:     host,
		HostPort: hostPort,
		LocalIP:  localIP,
		Start:    now.Add(-startDelta),
		End:      now.Add(-endDelta),
		Status:   int(trace.Status),
	}
}
