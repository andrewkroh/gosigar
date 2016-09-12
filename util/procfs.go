package util

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

// FS represents the pseudo-filesystem proc, which provides an interface to
// kernel data structures.
type FS string

// DefaultMountPoint is the common mount point of the proc filesystem.
const DefaultMountPoint = "/proc"

// NewFS returns a new FS mounted under the given mountPoint. It will error
// if the mount point can't be read.
func NewFS(mountPoint string) (FS, error) {
	info, err := os.Stat(mountPoint)
	if err != nil {
		return "", fmt.Errorf("could not read %s: %s", mountPoint, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("mount point %s is not a directory", mountPoint)
	}

	return FS(mountPoint), nil
}

// Path returns the path of the given subsystem relative to the procfs root.
func (fs FS) Path(p ...string) string {
	return path.Join(append([]string{string(fs)}, p...)...)
}

// NewProc returns a process for the given pid.
func (fs FS) NewProc(pid int) (Proc, error) {
	if _, err := os.Stat(fs.Path(strconv.Itoa(pid))); err != nil {
		return Proc{}, err
	}
	return Proc{PID: pid, fs: fs}, nil
}

// Self returns a process for the current process.
func (fs FS) Self() (Proc, error) {
	p, err := os.Readlink(fs.Path("self"))
	if err != nil {
		return Proc{}, err
	}
	pid, err := strconv.Atoi(strings.Replace(p, string(fs), "", -1))
	if err != nil {
		return Proc{}, err
	}
	return fs.NewProc(pid)
}

// Proc provides information about a running process.
type Proc struct {
	// The process ID.
	PID int

	fs FS
}

func (p Proc) path(pa ...string) string {
	return p.fs.Path(append([]string{strconv.Itoa(p.PID)}, pa...)...)
}
