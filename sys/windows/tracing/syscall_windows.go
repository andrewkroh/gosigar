package tracing

import (
	"syscall"
	"runtime"

	"github.com/elastic/gosigar/sys/windows"
)

var INVALID_PROCESSTRACE_HANDLE syscall.Handle

func init() {
	version := windows.GetWindowsVersion()

	// OpenTrace requires special error checking on 32-bit Windows 7 and Windows Vista.
	// XXX(akroh): This check would also apply to Server 2008, but I'm not sure if it's needed for 2008.
	if runtime.GOARCH == "386" && version.Major == 6 && (version.Minor == 0 || version.Minor == 1) {
		INVALID_PROCESSTRACE_HANDLE = 0x00000000FFFFFFFF
	}
}

type EventTraceLogfile struct {
	LogFileName *uint16 // Name of the log file used by the event tracing session. Specify a value for this member if you are consuming from a log file.
	LoggerName  *uint16 // Name of the event tracing session. Specify a value for this member if you want to consume events in real time.
	CurrentTime uint64     // On output, the current time, in 100-nanosecond intervals since midnight, January 1, 1601.
	BuffersRead uint32  // On output, the number of buffers processed.
	ProcessTraceMode uint32 // Modes for processing events.
	CurrentEvent EventTrace // On output, an EVENT_TRACE structure that contains the last event processed.
	LogfileHeader TraceLogfileHeader // On output, a TRACE_LOGFILE_HEADER structure that contains general information about the session and the computer on which the session ran.
	BufferCallback *uintptr // Pointer to the BufferCallback function that receives buffer-related statistics for each buffer ETW flushes. ETW calls this callback after it delivers all the events in the buffer. This callback is optional.
	BufferSize uint32 // On output, contains the size of each buffer, in bytes.
	Filled uint32 // On output, contains the number of bytes in the buffer that contain valid information.
	EventsLost uint32  // Not used.
	EventCallback *uintptr // Pointer to the EventCallback function that ETW calls for each event in the buffer
	IsKernelTrace uint32
	Context uintptr // Context data that a consumer can specify when calling OpenTrace. If the consumer uses EventRecordCallback to consume events, ETW sets the UserContext member of the EVENT_RECORD structure to this value.
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363773(v=vs.85).aspx
type EventTrace struct {
	Header EventTraceHeader
	InstanceId uint32
	ParentInstanceId uint32
	ParentGuid syscall.GUID
	MofData uintptr
	MofLength uint32
	BufferContext ETWBufferContext
}

type EventTraceHeader struct {
	Size uint8
	FieldTypeFlags uint16
	Type uint8
	Level uint8
	Version uint16
	ThreadID uint32
	ProcessID uint32
	TimeStamp int64
	GUID uint64
	ProcessorTime uint64
}

// ETW_BUFFER_CONTEXT
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363716(v=vs.85).aspx
type ETWBufferContext struct {
	ProcessorNumber uint8 // The number of the CPU on which the provider process was running. The number is zero on a single processor computer.
	Alignment uint8 // Alignment between events (always eight).
	LoggerId uint16 // Identifier of the session that logged the event.
}

// TRACE_LOGFILE_HEADER
type TraceLogfileHeader struct {
	BufferSize uint32
	Version uint32
	ProviderVersion uint32
	NumberOfProcessors uint32
	EndTime int64
	TimerResolution uint32
	MaximumFileSize uint32
	LogFileMode uint32
	BuffersWritten uint32
	LogInstanceGUID syscall.GUID
	LoggerName      *uint16
	LogFileName *uint16
	TimeZone syscall.Timezoneinformation
	BootTime int64
	PerfFreq int64
	StartTime int64
	ReservedFlags uint32
	BuffersLost uint32
}

// Use "GOOS=windows go generate -v -x ." to generate the source.

// Add -trace to enable debug prints around syscalls.
//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output zsyscall_windows.go syscall_windows.go

// Windows API calls
//sys   _OpenTrace(logfile *EventTraceLogfile) (h syscall.Handle) = sechost.OpenTrace
