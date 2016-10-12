package main

import (
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/elastic/gosigar/container/monitor"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	m, err := monitor.New("")
	if err != nil {
		logrus.WithError(err).Error("failed to create monitor")
	}

	_ = m
	time.Sleep(time.Hour)
}
