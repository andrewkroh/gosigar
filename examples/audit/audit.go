// +build linux

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/elastic/gosigar/sys/linux"
	"github.com/pkg/errors"
)

var (
	fs      = flag.NewFlagSet("auditd", flag.ExitOnError)
	debug   = fs.Bool("d", false, "enable debug output to stderr")
	bufSize = fs.Int("buf", linux.MAX_AUDIT_MESSAGE_LENGTH, "netlink receive buffer size")
	diag    = fs.String("diag", "", "dump raw information from kernel to file")
)

func enableLogger() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
	})
}

func main() {
	fs.Parse(os.Args[1:])

	if *debug {
		enableLogger()
	}

	if err := read(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func read() error {
	if os.Geteuid() != 0 {
		return errors.New("you must be root to receive audit data")
	}

	// Write netlink response to a file for further analysis or for writing
	// tests cases.
	var diagWriter io.Writer
	if *diag != "" {
		f, err := os.OpenFile(*diag, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		diagWriter = f
	}

	var readBuf []byte
	if *bufSize > 0 {
		readBuf = make([]byte, *bufSize)
	}

	log.Debugln("starting netlink client")
	client, err := linux.NewNetlinkClient(syscall.NETLINK_AUDIT, readBuf, diagWriter)
	if err != nil {
		return err
	}

	log.Debugln("sending message to kernel registering our PID as the audit daemon")
	if err = linux.AuditSetPID(client, os.Getpid()); err != nil {
		return errors.Wrap(err, "failed to set audit PID")
	}

	for {
		msgs, err := client.Receive(false, linux.ParseNetlinkAuditMessage)
		if err != nil {
			return errors.Wrap(err, "receive failed")
		}

		for _, m := range msgs {
			if m.Header.Type < 1300 || m.Header.Type >= 2100 {
				continue
			}

			auditMsg, err := linux.ParseAuditMessage(m)
			if err != nil {
				log.WithError(err).Error("Failed to parse audit message")
			}

			if auditMsg.RecordType == linux.AUDIT_EOE {
				continue
			}

			log.WithField("event", auditMsg).Infof("Received record type %v", auditMsg.RecordType)
		}
	}

	return nil
}
