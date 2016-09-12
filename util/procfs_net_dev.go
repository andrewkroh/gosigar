package util

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
)

// NetDev is single line parsed from /proc/net/dev or /proc/[pid]/net/dev.
type NetDevLine struct {
	Name         string `json:"name"`          // The name of the interface.
	RxBytes      uint64 `json:"rx_bytes"`      // Cumulative count of bytes received.
	RxPackets    uint64 `json:"rx_packets"`    // Cumulative count of packets received.
	RxErrors     uint64 `json:"rx_errors"`     // Cumulative count of receive errors encountered.
	RxDropped    uint64 `json:"rx_dropped"`    // Cumulative count of packets dropped while receiving.
	RxFIFO       uint64 `json:"rx_fifo"`       // Cumulative count of FIFO buffer errors.
	RxFrame      uint64 `json:"rx_frame"`      // Cumulative count of packet framing errors.
	RxCompressed uint64 `json:"rx_compressed"` // Cumulative count of compressed packets received by the device driver.
	RxMulticast  uint64 `json:"rx_multicast"`  // Cumulative count of multicast frames received by the device driver.
	TxBytes      uint64 `json:"tx_bytes"`      // Cumulative count of bytes transmitted.
	TxPackets    uint64 `json:"tx_packets"`    // Cumulative count of packets transmitted.
	TxErrors     uint64 `json:"tx_errors"`     // Cumulative count of transmit errors encountered.
	TxDropped    uint64 `json:"tx_dropped"`    // Cumulative count of packets dropped while transmitting.
	TxFIFO       uint64 `json:"tx_fifo"`       // Cumulative count of FIFO buffer errors.
	TxCollisions uint64 `json:"tx_collisions"` // Cumulative count of collisions detected on the interface.
	TxCarrier    uint64 `json:"tx_carrier`     // Cumulative count of carrier losses detected by the device driver.
	TxCompressed uint64 `json:"tx_compressed"` // Cumulative count of compressed packets transmitted by the device driver.
}

// NetDev is parsed from /proc/net/dev or /proc/[pid]/net/dev.
type NetDev []NetDevLine

// NewNetDev returns kernel/system statistics read from /proc/net/dev.
func NewNetDev() (NetDev, error) {
	fs, err := NewFS(DefaultMountPoint)
	if err != nil {
		return NetDev{}, err
	}

	return fs.NewNetDev()
}

// NewNetDev returns an information about current kernel/system statistics.
func (fs FS) NewNetDev() (NetDev, error) {
	return newNetDev(fs.Path("net/dev"))
}

// NewNetDev returns network device stats from /proc/[pid]/net/dev.
func (p Proc) NewNetDev() (NetDev, error) {
	return newNetDev(p.path("net/dev"))
}

func newNetDev(file string) (NetDev, error) {
	f, err := os.Open(file)
	if err != nil {
		return NetDev{}, err
	}
	defer f.Close()

	var nd NetDev
	s := bufio.NewScanner(f)
	for s.Scan() {
		// Skip the header lines.
		if bytes.Contains(s.Bytes(), []byte{'|'}) {
			continue
		}

		line, err := nd.parseLine(s.Text())
		if err != nil {
			return nd, err
		}

		nd = append(nd, *line)
	}

	return nd, nil
}

func (nd NetDev) parseLine(rawLine string) (*NetDevLine, error) {
	parts := strings.SplitN(rawLine, ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid net/dev line, missing colon")
	}
	fields := strings.Fields(strings.TrimSpace(parts[1]))

	var err error
	line := &NetDevLine{}

	// Interface Name
	line.Name = strings.TrimSpace(parts[0])
	if line.Name == "" {
		return nil, errors.New("invalid net/dev line, empty interface name")
	}

	// RX
	line.RxBytes, err = strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return nil, err
	}
	line.RxPackets, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return nil, err
	}
	line.RxErrors, err = strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return nil, err
	}
	line.RxDropped, err = strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return nil, err
	}
	line.RxFIFO, err = strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return nil, err
	}
	line.RxFrame, err = strconv.ParseUint(fields[5], 10, 64)
	if err != nil {
		return nil, err
	}
	line.RxCompressed, err = strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return nil, err
	}
	line.RxMulticast, err = strconv.ParseUint(fields[7], 10, 64)
	if err != nil {
		return nil, err
	}

	// TX
	line.TxBytes, err = strconv.ParseUint(fields[8], 10, 64)
	if err != nil {
		return nil, err
	}
	line.TxPackets, err = strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return nil, err
	}
	line.TxErrors, err = strconv.ParseUint(fields[10], 10, 64)
	if err != nil {
		return nil, err
	}
	line.TxDropped, err = strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return nil, err
	}
	line.TxFIFO, err = strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return nil, err
	}
	line.TxCollisions, err = strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return nil, err
	}
	line.TxCarrier, err = strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return nil, err
	}
	line.TxCompressed, err = strconv.ParseUint(fields[15], 10, 64)
	if err != nil {
		return nil, err
	}

	return line, nil
}
