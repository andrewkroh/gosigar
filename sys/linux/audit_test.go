package linux

import (
	"encoding/hex"
	"flag"
	"io"
	"os"
	"testing"
)

var hexdump = flag.Bool("hexdump", false, "dump kernel responses to stdout in hexdump -C format")

func TestAuditClientGetStatus(t *testing.T) {
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

	status, err := c.GetStatus()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", status)
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
