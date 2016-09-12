package util

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetDevLine(t *testing.T) {
	const rawLine = `  eth0: 1 2 3    4    5     6          7         8 9  10    11    12    13     14       15          16`

	line, err := NetDev{}.parseLine(rawLine)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "eth0", line.Name)
	assert.EqualValues(t, 1, line.RxBytes)
	assert.EqualValues(t, 2, line.RxPackets)
	assert.EqualValues(t, 3, line.RxErrors)
	assert.EqualValues(t, 4, line.RxDropped)
	assert.EqualValues(t, 5, line.RxFIFO)
	assert.EqualValues(t, 6, line.RxFrame)
	assert.EqualValues(t, 7, line.RxCompressed)
	assert.EqualValues(t, 8, line.RxMulticast)
	assert.EqualValues(t, 9, line.TxBytes)
	assert.EqualValues(t, 10, line.TxPackets)
	assert.EqualValues(t, 11, line.TxErrors)
	assert.EqualValues(t, 12, line.TxDropped)
	assert.EqualValues(t, 13, line.TxFIFO)
	assert.EqualValues(t, 14, line.TxCollisions)
	assert.EqualValues(t, 15, line.TxCarrier)
	assert.EqualValues(t, 16, line.TxCompressed)
}

func TestNewNetDev(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}

	fs, err := NewFS(DefaultMountPoint)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fs.NewNetDev()
	if err != nil {
		t.Fatal(err)
	}

	proc, err := fs.NewProc(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	_, err = proc.NewNetDev()
	if err != nil {
		t.Fatal(err)
	}
}
