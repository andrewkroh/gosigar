package watcher

type ProcessEventType int

const (
	ProcessAdd ProcessEventType = iota
	ProcessRemove
)

type ProcessWatchSource int

const (
	Netlink ProcessWatchSource = iota
)

type ProcessEvent struct {
	PID    int
	Type   ProcessEventType
	Source ProcessWatchSource
}

type ProcessWatcher interface {
	Start(events chan ProcessEvent) error

	Stop() error
}
