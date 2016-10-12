package monitor

import (
	"path/filepath"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/elastic/gosigar/cgroup"
	"github.com/elastic/gosigar/container"
	"github.com/elastic/gosigar/container/process"
	"github.com/elastic/gosigar/container/process/watcher"
	"github.com/elastic/gosigar/container/process/watcher/netlink"
	"github.com/elastic/gosigar/container/tools/docker"
	"github.com/elastic/procfs"
)

var log = logrus.WithField("package", "gosigar.container.monitor")

type contain struct {
	id      string
	tool    container.ContainerTool
	data    *container.Data
	process process.Process
	cgroup  func() (*cgroup.Stats, error)
}

type monitor struct {
	ptable         *process.Table
	ptableListener process.TableEventChannel
	cgroup         *cgroup.Reader
	factory        *container.ContainerToolFactory

	data     map[int]contain // Map of PIDs to containers.
	dataLock sync.RWMutex

	// Stop controls.
	once sync.Once
	done chan struct{}
	wg   sync.WaitGroup
}

func New(rootfs string) (*monitor, error) {
	if rootfs == "" {
		rootfs = "/"
	}
	procFS, err := procfs.NewFS(filepath.Join(rootfs, procfs.DefaultMountPoint))
	if err != nil {
		return nil, err
	}

	pwatcher, err := netlink.NewProcessWatcher()
	if err != nil {
		return nil, err
	}

	ptable := process.NewTable(procFS, pwatcher)
	if err != nil {
		return nil, err
	}

	cgroup, err := cgroup.NewReader(rootfs, true)
	if err != nil {
		return nil, err
	}

	factory := container.NewContainerToolFactory()
	err = docker.Register(factory, docker.Config{})
	if err != nil {
		log.WithError(err).Warn("docker metadata will not be available")
	}

	tableEvents := make(chan *process.TableEvent, 1)
	listener := ptable.Listen(tableEvents)
	m := &monitor{
		ptable:         ptable,
		ptableListener: listener,
		cgroup:         cgroup,
		factory:        factory,
		done:           make(chan struct{}),
	}

	go func() {
		defer ptable.StopListening(listener)

		for {
			select {
			case <-m.done:
				return
			case event := <-tableEvents:
				log.Debug("received table event")
				m.handleProcessTableEvent(event)
			}
		}
	}()

	if err = ptable.Start(); err != nil {
		return nil, err
	}

	log.WithField("monitor", m).Debug("starting monitor")
	return m, nil
}

func (m *monitor) handleProcessTableEvent(event *process.TableEvent) {
	m.dataLock.Lock()
	defer m.dataLock.Unlock()

	switch event.Type {
	case watcher.ProcessAdd:
		stats, err := m.cgroup.GetStatsForProcess(event.Proc.PID)
		if err != nil {
			log.WithField("process", event.Proc).Warn("failed to get cgroup stats from process")
			return
		}

		if stats == nil {
			log.WithField("pid", event.Proc.PID).Debug("process is not in a cgroup")
			return
		}

		var data *container.Data
		id, tool, err := m.factory.ContainerTool(stats.Path)
		if err != nil {
			log.WithFields(logrus.Fields{
				"process":     event.Proc,
				"cgroup-path": stats.Path,
			}).Info("could not find container tool for process")
		} else {
			data, err = tool.GetContainerData(id)
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					"tool": tool,
					"id":   id,
				}).Warn("failed to get data for container")
			}
		}

		c := contain{
			id:      id,
			tool:    tool,
			data:    data,
			process: event.Proc,
			cgroup: func() (*cgroup.Stats, error) {
				return m.cgroup.GetStatsForProcess(event.Proc.PID)
			},
		}
		m.data[event.Proc.PID] = c

		log.WithField("container", c).Debug("new container")
	case watcher.ProcessRemove:
		c, found := m.data[event.Proc.PID]
		if found {
			delete(m.data, event.Proc.PID)
			log.WithField("container", c).Debug("container stopped")
		}
	}
}
