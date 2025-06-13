package meta

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/kubecache/informer"
)

type fakeObserver struct {
	errorRate int
	count     int
}

func (f *fakeObserver) ID() string {
	return fmt.Sprintf("%p", f)
}

func (f *fakeObserver) On(_ *informer.Event) error {
	f.count++
	if f.errorRate > 0 && f.count%f.errorRate == 0 {
		return errors.New("fake error on " + f.ID())
	}
	return nil
}

func TestNotificationErrors(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	log := slog.With("test", "TestNotificationErrors")
	n := NewBaseNotifier(log)
	fo5 := &fakeObserver{errorRate: 5}
	fo10 := &fakeObserver{errorRate: 10}
	foNever1 := &fakeObserver{errorRate: 0}
	fonever2 := &fakeObserver{errorRate: 0}
	n.Subscribe(fo5)
	n.Subscribe(foNever1)
	n.Subscribe(fo10)
	n.Subscribe(fonever2)

	for i := 0; i < 20; i++ {
		n.Notify(&informer.Event{})
	}

	// check that the observers that return an error are unsubscribed
	assert.Equal(t, 5, fo5.count)
	assert.Equal(t, 10, fo10.count)
	assert.Equal(t, 20, foNever1.count)
	assert.Equal(t, 20, fonever2.count)
}
