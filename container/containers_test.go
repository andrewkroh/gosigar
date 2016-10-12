package container

import (
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
)

func TestMonitor(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	mon, err := newMonitor("")
	if err != nil {
		t.Fatal(err)
	}

	_ = mon
	time.Sleep(100 * time.Minute)
}
