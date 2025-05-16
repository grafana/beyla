package meta

import (
	"fmt"
	"log/slog"
	"slices"
	"time"

	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla/v2/pkg/kubecache/informer"
)

type Informers struct {
	BaseNotifier

	log    *slog.Logger
	config *informersConfig

	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods     cache.SharedIndexInformer
	nodes    cache.SharedIndexInformer
	services cache.SharedIndexInformer

	waitForSync chan struct{}

	// localInstance is true if the current informer instance runs inside a Beyla instance
	// if it runs as part of the k8s-cache service, it is false
	localInstance bool
}

type timestamped interface {
	FromTime() time.Time
}

func (inf *Informers) Subscribe(observer Observer) {
	inf.BaseNotifier.Subscribe(observer)

	var fromTime time.Time
	if conn, ok := observer.(timestamped); ok {
		fromTime = conn.FromTime()
	}

	// as a "welcome" message, we send the whole kube metadata to the new observer
	pods := inf.pods.GetStore().List()
	var nodes, services []any
	if !inf.config.disableNodes {
		nodes = inf.nodes.GetStore().List()
	}
	if !inf.config.disableServices {
		services = inf.services.GetStore().List()
	}
	storedEntities := make([]any, 0, len(pods)+len(nodes)+len(services))
	storedEntities = append(storedEntities, pods...)
	storedEntities = append(storedEntities, nodes...)
	storedEntities = append(storedEntities, services...)
	for _, entity := range inf.sortAndCut(storedEntities, fromTime) {
		fmt.Println("submitting created for", entity.(*indexableEntity).Name)
		if err := observer.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: entity.(*indexableEntity).EncodedMeta,
		}); err != nil {
			inf.log.Debug("error notifying observer. Unsubscribing", "observerID", observer.ID(), "error", err)
			inf.BaseNotifier.Unsubscribe(observer)
			return
		}
	}
	// until the informer waitForSync, we won't send the sync_finished event to remote beyla clients
	// TODO: in some very slowed-down environments (e.g. tests with -race conditions), this last message might
	// be sent and executed before the rest of previous updates have been processed and submitted.
	// In production, it might mean that few initialization updates are sent right before the "sync_finished" signal.
	// To fix that we should rearchitecture this to not directly invoking the notifications but enqueuing them
	// in a synchronized list.
	// Given the amount of work and complexity, we can afford this small delay, as the data eventually
	// reaches the client right after the sync_finished signal.
	go func() {
		<-inf.waitForSync

		// notify the end of synchronization, so the client knows that already has a snapshot
		// of all the existing resources
		fmt.Println("submitting sync_finished")
		if err := observer.On(&informer.Event{
			Type: informer.EventType_SYNC_FINISHED,
		}); err != nil {
			inf.log.Debug("error notifying observer. Unsubscribing", "observerID", observer.ID(), "error", err)
			inf.BaseNotifier.Unsubscribe(observer)
			return
		}
		fmt.Println("submitted sync_finished")
	}()
}

// sorts the list of entities by status time and cuts the list from the given timestamp.
// If the timestamp is zero, the list is not cut.
// The returned list is sorted in ascending order by status time.
func (inf *Informers) sortAndCut(list []any, cutFrom time.Time) []any {
	if inf.localInstance {
		// this feature is only useful for minimizing traffic with the k8s-cache service
		return list
	}
	slices.SortFunc(list, func(i, j any) int {
		it := i.(*indexableEntity).EncodedMeta.StatusTime.AsTime()
		jt := j.(*indexableEntity).EncodedMeta.StatusTime.AsTime()
		return it.Compare(jt)
	})
	if cutFrom.IsZero() {
		return list
	}
	// despite internally using time.Timem the Kubernetes API stores the timestamps in seconds
	// we remove any nanosecond trace in the current time to allow returning elements belonging
	// to the same second of the cutFrom timestamp
	cutFrom = cutFrom.Truncate(time.Second)

	elementsFromTS, _ := slices.BinarySearchFunc(list, cutFrom, func(e any, ts time.Time) int {
		ets := e.(*indexableEntity).EncodedMeta.StatusTime.AsTime()
		return ets.Compare(ts)
	})
	return list[elementsFromTS:]
}
