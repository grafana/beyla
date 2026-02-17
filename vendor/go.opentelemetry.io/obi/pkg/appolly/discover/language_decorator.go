// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func llog() *slog.Logger {
	return slog.With("component", "LanguageDecorator")
}

func LanguageDecoratorProvider(
	cfg *obi.Config,
	input, output *msg.Queue[[]Event[ProcessAttrs]],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		instrumentableCache, _ := lru.New[uint64, svc.InstrumentableType](1000)
		ld := languageDecorator{
			in:           input.Subscribe(msg.SubscriberName("LanguageDecorator")),
			out:          output,
			typeCache:    instrumentableCache,
			log:          llog(),
			ignoredPaths: cfg.Discovery.ExcludedLinuxSystemPaths,
		}
		return ld.decorate, nil
	}
}

type languageDecorator struct {
	in           <-chan []Event[ProcessAttrs]
	out          *msg.Queue[[]Event[ProcessAttrs]]
	typeCache    *lru.Cache[uint64, svc.InstrumentableType]
	log          *slog.Logger
	ignoredPaths []string
}

func (ld *languageDecorator) isIgnoredPath(exePath string) bool {
	for _, prefix := range ld.ignoredPaths {
		if strings.HasPrefix(exePath, prefix) {
			return true
		}
	}
	return false
}

var (
	_findInodeForPID  = FindINodeForPID
	_executableReady  = ExecutableReady
	_findProcLanguage = procs.FindProcLanguage
)

func (ld *languageDecorator) decorateEvent(ev *Event[ProcessAttrs]) {
	if exePath, ready := _executableReady(ev.Obj.pid); ready {
		if ld.isIgnoredPath(exePath) {
			return
		}
		if ino, err := _findInodeForPID(ev.Obj.pid); err == nil {
			if t, ok := ld.typeCache.Get(ino); ok {
				ev.Obj.detectedType = t
				return
			}
			t := _findProcLanguage(ev.Obj.pid)
			ev.Obj.detectedType = t
			ld.typeCache.Add(ino, t)
		}
	}
}

func (ld *languageDecorator) decorate(ctx context.Context) {
	defer ld.out.Close()
	swarms.ForEachInput(ctx, ld.in, ld.log.Debug, func(instrumentables []Event[ProcessAttrs]) {
		for i := range instrumentables {
			ev := &instrumentables[i]
			if ev.Type == EventCreated {
				ld.decorateEvent(ev)
			}
		}
		ld.out.SendCtx(ctx, instrumentables)
	})
}
