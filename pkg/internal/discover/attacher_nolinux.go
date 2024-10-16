//go:build !linux

package discover

func (ta *TraceAttacher) init() error {
	return nil
}

func (ta *TraceAttacher) close() {}
