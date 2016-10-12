package process

import (
	"sync"

	"github.com/elastic/gosigar/container/process/watcher"
	"github.com/elastic/procfs"
)

type TableEvent struct {
	Type watcher.ProcessEventType
	Proc Process
}

type TableEventChannel struct {
	ID int
	c  chan *TableEvent
}

type Table struct {
	data     map[int]Process
	dataLock sync.Mutex

	listenerId   int
	listeners    map[int]*TableEventChannel
	listenerLock sync.RWMutex

	procFS  procfs.FS
	watcher watcher.ProcessWatcher
	events  chan watcher.ProcessEvent
}

func NewTable(fs procfs.FS, w watcher.ProcessWatcher) *Table {
	return &Table{
		data:      map[int]Process{},
		listeners: map[int]*TableEventChannel{},
		procFS:    fs,
		watcher:   w,
		events:    make(chan watcher.ProcessEvent, 1),
	}
}

func (t *Table) Start() error {
	// Initialize table with all processes.
	allProcs, err := t.procFS.AllProcs()
	if err != nil {
		return err
	}

	for _, p := range allProcs {
		if err := t.AddProc(p); err != nil {
			log.WithError(err).WithField("pid", p.PID).Warn("ignoring process")
		}
	}

	if t.watcher == nil {
		return nil
	}

	// Setup the watcher to receive notifications from the OS about process changes.
	if err := t.watcher.Start(t.events); err != nil {
		return err
	}

	go func() {
		// The watcher will close the events channel when it's done.
		for event := range t.events {
			log.WithField("event", event).Debug("received netlink event")
			switch event.Type {
			case watcher.ProcessAdd:
				if err := t.AddPID(event.PID); err != nil {
					log.WithError(err).WithField("pid", event.PID).Warn("ignoring process")
				}
			case watcher.ProcessRemove:
				t.Remove(event.PID)
			default:
				log.WithField("event", event).Errorf("unhandled watcher.ProcessEventType")
			}
		}
	}()

	return nil
}

func (t *Table) Stop() error {
	return t.watcher.Start(t.events)
}

func (t *Table) AddPID(pid int) error {
	proc, err := t.procFS.NewProc(pid)
	if err != nil {
		return err
	}

	return t.AddProc(proc)
}

func (t *Table) AddProc(proc procfs.Proc) error {
	process, err := NewProcess(proc)
	if err != nil {
		return err
	}

	// Add process if it does not exist.
	t.dataLock.Lock()
	existingProc, exists := t.data[process.PID]
	if exists && isSameProcess(existingProc, process) {
		t.dataLock.Unlock()
		return nil
	}

	t.data[process.PID] = process
	t.dataLock.Unlock()

	log.WithField("process", process).Debug("added process to table")
	t.notifyListeners(watcher.ProcessAdd, process)
	return nil
}

func (t *Table) Remove(pid int) {
	t.dataLock.Lock()
	process, exists := t.data[pid]
	delete(t.data, pid)
	t.dataLock.Unlock()

	if exists {
		log.WithField("process", process).Debug("removed process from table")
		t.notifyListeners(watcher.ProcessRemove, process)
	}
}

func (t *Table) Select(where func(Process) bool) map[int]Process {
	t.dataLock.Lock()
	defer t.dataLock.Unlock()

	selected := map[int]Process{}
	for pid, process := range t.data {
		if where == nil || where(process) {
			selected[pid] = process
		}
	}

	return selected
}

func (t *Table) notifyListeners(typ watcher.ProcessEventType, p Process) {
	t.listenerLock.RLock()
	defer t.listenerLock.RUnlock()

	event := &TableEvent{Type: typ, Proc: p}
	for _, listener := range t.listeners {
		listener.c <- event
	}

}

func (t *Table) Listen(c chan *TableEvent) TableEventChannel {
	t.listenerLock.Lock()
	defer t.listenerLock.Unlock()

	t.listenerId++
	tec := TableEventChannel{ID: t.listenerId, c: c}
	t.listeners[t.listenerId] = &tec
	return tec
}

func (t *Table) StopListening(c TableEventChannel) {
	t.listenerLock.Lock()
	defer t.listenerLock.Unlock()

	l, ok := t.listeners[c.ID]
	if !ok {
		log.WithField("id", c.ID).Warn("Could not stop listener, ID not found")
		return
	}

	close(l.c)
	delete(t.listeners, l.ID)
}
