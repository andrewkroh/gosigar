package windows

import (
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNtQuerySystemProcessorPerformanceInformation(t *testing.T) {
	cpus, err := NtQuerySystemProcessorPerformanceInformation()
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, cpus, runtime.NumCPU())

	for i, cpu := range cpus {
		assert.NotZero(t, cpu.IdleTime)
		assert.NotZero(t, cpu.KernelTime)
		assert.NotZero(t, cpu.UserTime)

		t.Logf("CPU=%v SystemProcessorPerformanceInformation=%v", i, cpu)
	}
}

func TestNtQueryProcessBasicInformation(t *testing.T) {
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(syscall.Getpid()))
	if err != nil {
		t.Fatal(err)
	}

	info, err := NtQueryProcessBasicInformation(h)
	if err != nil {
		t.Fatal(err)
	}

	assert.EqualValues(t, os.Getpid(), info.UniqueProcessId)
	assert.EqualValues(t, os.Getppid(), info.InheritedFromUniqueProcessId)

	t.Logf("NtQueryProcessBasicInformation: %+v", info)
}
