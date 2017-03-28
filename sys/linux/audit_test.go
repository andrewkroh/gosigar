package linux

import (
	"encoding/hex"
	"flag"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

var hexdump = flag.Bool("hexdump", false, "dump kernel responses to stdout in hexdump -C format")

var euid = os.Geteuid()

func TestAuditClientGetStatus(t *testing.T) {
	if euid != 0 {
		t.Skip("must be root to get audit status")
	}

	status, err := getStatus(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Status: %+v", status)
}

func TestAuditClientGetStatusPermissionError(t *testing.T) {
	euid := os.Geteuid()
	if euid == 0 {
		// Drop privs.
		if err := syscall.Setuid(1000); err != nil {
			t.Fatal(err)
		}
		defer syscall.Setuid(euid)
	}

	status, err := getStatus(t)
	assert.Nil(t, status, "status should be nil")
	assert.Equal(t, syscall.EPERM, err)
}

func getStatus(t testing.TB) (*AuditStatus, error) {
	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	return c.GetStatus()
}

func TestAuditClientSetPID(t *testing.T) {
	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.SetPID(0)
	if err != nil {
		t.Fatal(err)
	}
}
