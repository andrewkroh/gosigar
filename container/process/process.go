package process

import (
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/elastic/procfs"
)

var log = logrus.WithField("package", "gosigar.container.process")

type Process struct {
	procfs.Proc
	PPID      int
	PGID      int
	Command   string
	CmdLine   string
	startTime uint64

	Namespaces procfs.Namespaces
}

func NewProcess(proc procfs.Proc) (Process, error) {
	stat, err := proc.NewStat()
	if err != nil {
		return Process{}, err
	}

	cmdline, err := proc.CmdLine()
	if err != nil {
		return Process{}, err
	}

	namespaces, err := proc.NewNamespaces()
	if err != nil && !os.IsNotExist(err) {
		return Process{}, err
	}

	return Process{
		Proc:       proc,
		PPID:       stat.PPID,
		PGID:       stat.PGRP,
		Command:    stat.Comm,
		CmdLine:    strings.Join(cmdline, " "),
		Namespaces: namespaces,
	}, nil
}

// HasNetworkNamespace returns true if the process has a network namespace that
// differs from the network namespace of this process (self).
func (p Process) HasUniqueNetworkNamespace() (bool, error) {
	// TODO: Cache self network namespace.
	self, err := p.FS().Self()
	if err != nil {
		return false, err
	}

	selfNS, err := self.NewNamespaces()
	if err != nil {
		return false, err
	}

	selfNetNS, foundSelfNetNS := selfNS["net"]
	procNetNS, foundProcNetNS := p.Namespaces["net"]

	return foundSelfNetNS && foundProcNetNS && selfNetNS != procNetNS, nil
}

func isSameProcess(p1 Process, p2 Process) bool {
	return p1.PID == p2.PID && p1.startTime == p2.startTime
}
