package util

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNamespaces(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}

	fs, err := NewFS(DefaultMountPoint)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := fs.NewProc(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}

	ns, err := proc.NewNamespaces()
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, ns, "empty list of namespaces")
}
