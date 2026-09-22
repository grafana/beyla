// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package uprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

const traceFSEventName = "probe"

var findTraceFS = sync.OnceValues(func() (string, error) {
	mounts, err := procfs.GetMounts()
	if err == nil {
		if root := writableTraceFSMount(mounts); root != "" {
			return root, nil
		}
		for _, mount := range mounts {
			if mount.FSType == "debugfs" && mount.Root == "/" && mountIsWritable(mount) {
				root := filepath.Join(unescapeMountPath(mount.MountPoint), "tracing")
				if info, statErr := os.Stat(root); statErr == nil && info.IsDir() {
					return root, nil
				}
			}
		}
	}

	// this is a defensive measure against maybe /proc/self/mountinfo not being
	// ready or cannot be consumed. we try the usual suspects for tracefs/debugfs.
	for _, candidate := range []struct {
		path   string
		fsType int64
	}{
		{path: "/sys/kernel/tracing", fsType: unix.TRACEFS_MAGIC},
		{path: "/sys/kernel/debug/tracing", fsType: unix.TRACEFS_MAGIC},
		{path: "/sys/kernel/debug/tracing", fsType: unix.DEBUGFS_MAGIC},
	} {
		var stat unix.Statfs_t
		if statErr := unix.Statfs(candidate.path, &stat); statErr == nil &&
			stat.Type == candidate.fsType && stat.Flags&unix.ST_RDONLY == 0 {
			return candidate.path, nil
		}
	}

	if err != nil {
		return "", fmt.Errorf("finding tracefs mount: %w", err)
	}
	return "", errors.New("neither debugfs nor tracefs has a writable mount")
})

func writableTraceFSMount(mounts []*procfs.MountInfo) string {
	for _, mount := range mounts {
		if mount.FSType == "tracefs" && mount.Root == "/" && mountIsWritable(mount) {
			return unescapeMountPath(mount.MountPoint)
		}
	}
	return ""
}

func mountIsWritable(mount *procfs.MountInfo) bool {
	_, writable := mount.Options["rw"]
	return writable
}

func unescapeMountPath(path string) string {
	return strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	).Replace(path)
}

func attachTraceFS(path string, prog *ebpf.Program, opts Options) (io.Closer, error) {
	if path == "" {
		return nil, errors.New("attaching uprobe through tracefs: executable path is empty")
	}

	groupName, err := randomTraceFSGroup()
	if err != nil {
		return nil, err
	}
	links := make([]*traceFSLink, 0, len(opts.Addresses))
	var group *traceFSEventGroup
	for i, address := range opts.Addresses {
		link, err := attachTraceFSEvent(path, prog, opts, address, groupName, fmt.Sprintf("%s_%d", traceFSEventName, i))
		if err != nil {
			if group != nil {
				return nil, errors.Join(err, (&traceFSLinks{links: links, group: group}).Close())
			}
			return nil, err
		}
		links = append(links, link)
		if group == nil {
			group = &traceFSEventGroup{eventsFile: link.event.eventsFile, name: groupName}
		}
	}

	return &traceFSLinks{links: links, group: group}, nil
}

func attachTraceFSEvent(
	path string,
	prog *ebpf.Program,
	opts Options,
	address uint64,
	group string,
	name string,
) (*traceFSLink, error) {
	event, err := createTraceFSEvent(path, address, opts.RefCtrOffset, opts.Return, group, name)
	if err != nil {
		return nil, err
	}

	fd, err := openTraceFSPerfEvent(event.id, opts.PID)
	if err != nil {
		return nil, errors.Join(err, event.Close())
	}
	closeOnError := func(attachErr error) (*traceFSLink, error) {
		return nil, errors.Join(attachErr, unix.Close(fd), event.Close())
	}

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
		return closeOnError(fmt.Errorf("attaching BPF program to tracefs uprobe: %w", err))
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return closeOnError(fmt.Errorf("enabling tracefs uprobe: %w", err))
	}

	return &traceFSLink{fd: fd, event: event}, nil
}

type traceFSEvent struct {
	id         uint64
	eventsFile string
	group      string
	name       string
	once       sync.Once
	err        error
}

func createTraceFSEvent(
	path string,
	address uint64,
	refCtrOffset uint64,
	ret bool,
	group string,
	name string,
) (*traceFSEvent, error) {
	root, err := findTraceFS()
	if err != nil {
		return nil, err
	}

	event := &traceFSEvent{
		eventsFile: filepath.Join(root, "uprobe_events"),
		group:      group,
		name:       name,
	}

	command := traceFSEventCommand(path, address, refCtrOffset, ret, event.group, event.name)
	if err := writeTraceFSCommand(event.eventsFile, command); err != nil {
		return nil, fmt.Errorf("creating tracefs uprobe %q: %w", command, err)
	}

	idPath := filepath.Join(root, "events", event.group, event.name, "id")
	idText, err := os.ReadFile(idPath)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("reading tracefs uprobe ID: %w", err), event.Close())
	}
	event.id, err = strconv.ParseUint(strings.TrimSpace(string(idText)), 10, 64)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("parsing tracefs uprobe ID: %w", err), event.Close())
	}

	return event, nil
}

func randomTraceFSGroup() (string, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generating tracefs uprobe group: %w", err)
	}
	return fmt.Sprintf("obi_%x", suffix), nil
}

func traceFSEventCommand(path string, address, refCtrOffset uint64, ret bool, group, name string) string {
	prefix := "p" // uprobe
	if ret {
		prefix = "r" // uretprobe
	}
	target := fmt.Sprintf("%s:%#x", path, address)
	if refCtrOffset != 0 {
		target += fmt.Sprintf("(%#x)", refCtrOffset) // usdt
	}
	return fmt.Sprintf("%s:%s/%s %s", prefix, group, name, target)
}

func writeTraceFSCommand(eventsFile, command string) error {
	f, err := os.OpenFile(eventsFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(command)
	return err
}

func (e *traceFSEvent) Close() error {
	e.once.Do(func() {
		e.err = writeTraceFSCommand(e.eventsFile, fmt.Sprintf("-:%s/%s", e.group, e.name))
	})
	return e.err
}

type traceFSEventGroup struct {
	eventsFile string
	name       string
	once       sync.Once
	err        error
}

func (g *traceFSEventGroup) Close() error {
	// this trick of writing a tracefs command with empty event allows us to remove all tracefs probes
	// at once. It was first introduced in 5.20, by commit 95c104c378dc. 5.19 and earlier reject the empty event name with EINVAL,
	// so we remove those one by one.
	g.once.Do(func() {
		g.err = writeTraceFSCommand(g.eventsFile, fmt.Sprintf("-:%s/", g.name))
	})
	return g.err
}

func openTraceFSPerfEvent(eventID uint64, pid uint32) (int, error) {
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      eventID,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}
	targetPID := -1
	cpu := 0
	if pid != 0 {
		targetPID = int(pid)
		cpu = -1
	}

	fd, err := unix.PerfEventOpen(&attr, targetPID, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("opening tracefs uprobe perf event: %w", err)
	}
	return fd, nil
}

type traceFSLink struct {
	fd      int
	event   *traceFSEvent
	fdOnce  sync.Once
	fdError error
}

func (l *traceFSLink) closePerfEvent() error {
	l.fdOnce.Do(func() {
		l.fdError = unix.Close(l.fd)
	})
	return l.fdError
}

func (l *traceFSLink) Close() error {
	return errors.Join(l.closePerfEvent(), l.event.Close())
}

type traceFSLinks struct {
	links []*traceFSLink
	group *traceFSEventGroup
	once  sync.Once
	err   error
}

func (l *traceFSLinks) Close() error {
	l.once.Do(func() {
		errs := make([]error, len(l.links))
		var wg sync.WaitGroup
		for i, link := range l.links {
			wg.Go(func() { errs[i] = link.closePerfEvent() })
		}
		wg.Wait()

		// attempt to delete the whole group first, if you are on 5.20+, it will
		// work.
		groupErr := l.group.Close()
		if groupErr == nil {
			l.err = errors.Join(errs...)
			return
		}

		// cleanup one by one, which is slow.
		eventErrs := make([]error, len(l.links))
		for i, link := range l.links {
			wg.Go(func() { eventErrs[i] = link.event.Close() })
		}
		wg.Wait()
		if eventErr := errors.Join(eventErrs...); eventErr != nil {
			l.err = errors.Join(errors.Join(errs...), groupErr, eventErr)
			return
		}
		l.err = errors.Join(errs...)
	})
	return l.err
}
