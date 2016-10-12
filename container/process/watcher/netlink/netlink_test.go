// +build linux

package netlink

import (
	"testing"

	"github.com/elastic/gosigar/container/process/watcher"
)

// Verify that netlinkProcessWatcher implements the ProcessWatcher interface.
var _ watcher.ProcessWatcher = &processWatcher{}

func TestNetlinkEvents(t *testing.T) {
	w, err := NewProcessWatcher()
	if err != nil {
		t.Fatal(err)
	}

	events := make(chan watcher.ProcessEvent, 1)
	err = w.Start(events)
	if err != nil {
		t.Fatal(err)
	}

	for e := range events {
		t.Log(e)
		return
	}

	t.Fatal("no netlink events received")
}
