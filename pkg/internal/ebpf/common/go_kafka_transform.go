package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/request"
)

func ReadGoKafkaRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GoKafkaClientInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	info, err := ProcessKafkaRequest(event.Buf[:])

	if err == nil {
		return GoKafkaToSpan(&event, info), false, nil
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

func GoKafkaToSpan(event *GoKafkaClientInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	return request.Span{
		Type:           request.EventTypeKafkaClient,
		Method:         data.Operation.String(),
		OtherNamespace: data.ClientID,
		Path:           data.Topic,
		Peer:           peer,
		PeerPort:       int(event.Conn.S_port),
		Host:           hostname,
		HostPort:       hostPort,
		ContentLength:  0,
		RequestStart:   int64(event.StartMonotimeNs),
		Start:          int64(event.StartMonotimeNs),
		End:            int64(event.EndMonotimeNs),
		Status:         0,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}
}
