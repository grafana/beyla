package tcmanager

import (
	"context"
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
)

type IMIfaceMap map[int]*ifaces.Interface

type InterfaceManagerCB func(iface *ifaces.Interface)
type interfaceManagerCBMap map[uint64]InterfaceManagerCB

type InterfaceManager struct {
	filter                *InterfaceFilter
	monitorMode           MonitorMode
	channelBufferLen      int
	pollPeriod            time.Duration
	registerer            *ifaces.Registerer
	log                   *slog.Logger
	mutex                 sync.Mutex
	wg                    sync.WaitGroup
	interfaces            IMIfaceMap
	ifaceAddedCallbacks   interfaceManagerCBMap
	ifaceRemovedCallbacks interfaceManagerCBMap
	nextCallbackID        uint64
}

func NewInterfaceManager() *InterfaceManager {
	return &InterfaceManager{
		filter:                nil,
		monitorMode:           DefaultMonitorMode,
		channelBufferLen:      DefaultChannelBufferLen,
		pollPeriod:            DefaultPollPeriod,
		registerer:            nil,
		log:                   slog.With("component", "interface_manager"),
		mutex:                 sync.Mutex{},
		wg:                    sync.WaitGroup{},
		interfaces:            IMIfaceMap{},
		ifaceAddedCallbacks:   interfaceManagerCBMap{},
		ifaceRemovedCallbacks: interfaceManagerCBMap{},
		nextCallbackID:        0,
	}
}

func (im *InterfaceManager) Start(ctx context.Context) {
	im.log.Debug("Starting InterfaceManager", "monitor_mode", im.monitorMode)

	if im.registerer != nil {
		return
	}

	var informer ifaces.Informer

	if im.monitorMode == MonitorPoll {
		informer = ifaces.NewPoller(im.pollPeriod, im.channelBufferLen)
	} else {
		informer = ifaces.NewWatcher(im.channelBufferLen)
	}

	registerer := ifaces.NewRegisterer(informer, im.channelBufferLen)

	im.log.Debug("Subscribing for events")

	ifaceEvents, err := registerer.Subscribe(ctx)

	if err != nil {
		im.log.Error("instantiating interfaces' informer", "error", err)
		return
	}

	im.registerer = registerer

	im.wg.Add(1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				im.shutdown()
				im.wg.Done()
				return
			case event := <-ifaceEvents:
				im.log.Debug("received event", "event", event)
				switch event.Type {
				case ifaces.EventAdded:
					im.onInterfaceAdded(&event.Interface)
				case ifaces.EventDeleted:
					im.onInterfaceRemoved(&event.Interface)
				default:
					im.log.Warn("unknown event type", "event", event)
				}
			}
		}
	}()
}

func (im *InterfaceManager) Wait() {
	im.wg.Wait()
}

func (im *InterfaceManager) shutdown() {
	im.log.Debug("TC initiated shutdown")

	im.mutex.Lock()
	defer im.mutex.Unlock()

	im.interfaces = IMIfaceMap{}
	im.registerer = nil

	im.log.Debug("TC completed shutdown")
}

func (im *InterfaceManager) onInterfaceAdded(i *ifaces.Interface) {
	cbMap := interfaceManagerCBMap{}

	func() {
		im.mutex.Lock()
		defer im.mutex.Unlock()

		if im.filter != nil && !im.filter.IsAllowed(i.Name) {
			im.log.Debug("Interface now allowed", "interface", i.Name)
			return
		}

		im.interfaces[i.Index] = i

		cbMap = maps.Clone(im.ifaceAddedCallbacks)
	}()

	for _, cb := range cbMap {
		cb(i)
	}
}

func (im *InterfaceManager) onInterfaceRemoved(i *ifaces.Interface) {
	cbMap := interfaceManagerCBMap{}

	func() {
		im.mutex.Lock()
		defer im.mutex.Unlock()

		delete(im.interfaces, i.Index)

		cbMap = maps.Clone(im.ifaceRemovedCallbacks)
	}()

	for _, cb := range cbMap {
		cb(i)
	}
}

func (im *InterfaceManager) InterfaceName(ifaceIndex int) (string, bool) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	if iface, ok := im.interfaces[ifaceIndex]; ok {
		return iface.Name, true
	}

	return "", false
}

func (im *InterfaceManager) SetInterfaceFilter(filter *InterfaceFilter) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	im.filter = filter
}

func (im *InterfaceManager) SetMonitorMode(mode MonitorMode) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	im.monitorMode = mode
}

func (im *InterfaceManager) SetChannelBufferLen(channelBufferLen int) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	im.channelBufferLen = channelBufferLen
}

func (im *InterfaceManager) SetPollPeriod(period time.Duration) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	im.pollPeriod = period
}

func (im *InterfaceManager) AddInterfaceAddedCallback(cb InterfaceManagerCB) uint64 {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	im.nextCallbackID++
	im.ifaceAddedCallbacks[im.nextCallbackID] = cb

	return im.nextCallbackID
}

func (im *InterfaceManager) AddInterfaceRemovedCallback(cb InterfaceManagerCB) uint64 {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	im.nextCallbackID++
	im.ifaceRemovedCallbacks[im.nextCallbackID] = cb

	return im.nextCallbackID
}

func (im *InterfaceManager) RemoveCallback(id uint64) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	delete(im.ifaceAddedCallbacks, id)
	delete(im.ifaceRemovedCallbacks, id)
}

func (im *InterfaceManager) Interfaces() IMIfaceMap {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	return maps.Clone(im.interfaces)
}
