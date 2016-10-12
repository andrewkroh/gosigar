package netlink

import (
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/elastic/gosigar/container/process/watcher"
	"github.com/elastic/gosigar/psnotify"
	"github.com/pkg/errors"
)

var log = logrus.WithField("package", "gosigar.container.watcher.process.netlink")

type processWatcher struct {
	psnotify *psnotify.Watcher
	once     sync.Once
	done     chan struct{}
	wg       sync.WaitGroup
}

func NewProcessWatcher() (watcher.ProcessWatcher, error) {
	return &processWatcher{
		done: make(chan struct{}),
	}, nil
}

func (w *processWatcher) Start(eventChan chan watcher.ProcessEvent) error {
	// If using Docker then you will need: --cap-add=NET_ADMIN --net=host
	var err error
	w.psnotify, err = psnotify.NewWatcher()
	if err != nil {
		return errors.Wrap(err, "failed to create psnotify watcher")
	}

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer w.psnotify.Close()

		for {
			select {
			case <-w.done:
				return
			case err = <-w.psnotify.Error:
				log.WithError(err).Error("error in psnotify watcher")
			case forkEvent := <-w.psnotify.Fork:
				log.WithField("event", forkEvent).Info("received netlink fork event")
				// Regular fork, parent process is the originator.
				if forkEvent.ChildPid == forkEvent.ChildTgid {
					eventChan <- watcher.ProcessEvent{
						Type:   watcher.ProcessAdd,
						PID:    forkEvent.ChildPid,
						Source: watcher.Netlink,
					}
				}
			case execEvent := <-w.psnotify.Exec:
				log.WithField("event", execEvent).Info("received netlink exec event")
				eventChan <- watcher.ProcessEvent{
					Type:   watcher.ProcessAdd,
					PID:    execEvent.Pid,
					Source: watcher.Netlink,
				}
			case exitEvent := <-w.psnotify.Exit:
				log.WithField("event", exitEvent).Info("received netlink exit event")
				eventChan <- watcher.ProcessEvent{
					Type:   watcher.ProcessRemove,
					PID:    exitEvent.Pid,
					Source: watcher.Netlink,
				}
			}
		}
	}()

	/// Watch all processes.
	err = w.psnotify.Watch(-1, psnotify.PROC_EVENT_ALL)
	if err != nil {
		w.Stop()
		return errors.Wrap(err, "failed to add watch for all processes")
	}

	return nil
}

func (w *processWatcher) Stop() error {
	w.once.Do(func() {
		close(w.done)
		w.wg.Wait()
		log.Debug("stopped netlink process watcher")
	})

	return nil
}
