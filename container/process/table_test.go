package process

import (
	"testing"

	"github.com/elastic/gosigar/container/process/watcher"
	"github.com/elastic/procfs"
	"github.com/stretchr/testify/assert"
)

type listener struct {
	Type    watcher.ProcessEventType
	Process Process
}

func (l *listener) ProcessTableChanged(t watcher.ProcessEventType, p Process) {
	l.Type = t
	l.Process = p
}

func TestTableStart(t *testing.T) {
	fs, err := procfs.NewFS("../fixtures")
	if err != nil {
		t.Fatal(err)
	}

	table := NewTable(fs, nil)
	if assert.NoError(t, table.Start()) {
		assert.True(t, len(table.Select(nil)) > 0)
	}
}

func TestTableAddAndNotify(t *testing.T) {
	fs, err := procfs.NewFS("../fixtures")
	if err != nil {
		t.Fatal(err)
	}

	table := NewTable(fs, nil)

	l := &listener{}
	table.listeners[l] = struct{}{}

	table.AddPID(26231)
	assert.Equal(t, 26231, l.Process.PID)
}
