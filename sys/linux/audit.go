// +build linux

package linux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

//go:generate bash -c "go run mk_audit_msg_types.go && gofmt -w audit_msg_types.go"
//go:generate bash -c "perl mk_audit_syscalls.pl > audit_syscalls.go && gofmt -w audit_syscalls.go"
//go:generate perl mk_audit_arches.pl

const (
	// https://github.com/linux-audit/audit-userspace/blob/990aa27ccd02f9743c4f4049887ab89678ab362a/lib/libaudit.h#L435
	MAX_AUDIT_MESSAGE_LENGTH = 8970
)

var (
	errInvalidAuditHeader = errors.New("invalid audit message header")
)

type AuditMessage struct {
	RecordType AuditMessageType // Record type from netlink header.
	Timestamp  time.Time        // Timestamp parsed from payload in netlink message.
	Sequence   int              // Sequence parsed from payload.
	RawData    string           // Raw payload as a string.
}

func ParseAuditMessage(msg syscall.NetlinkMessage) (*AuditMessage, error) {
	timestamp, seq, err := parseAuditHeader(msg.Data)
	if err != nil {
		return nil, err
	}

	return &AuditMessage{
		RecordType: AuditMessageType(msg.Header.Type),
		Timestamp:  timestamp,
		Sequence:   seq,
		RawData:    string(msg.Data),
	}, nil
}

// parseAuditHeader parses the timestamp and sequence number from the audit
// message header that has the form of "audit(1490137971.011:50406):".
func parseAuditHeader(line []byte) (time.Time, int, error) {
	// Find tokens.
	start := bytes.IndexRune(line, '(')
	if start == -1 {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	dot := bytes.IndexRune(line[start:], '.')
	if dot == -1 {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	dot += start
	sep := bytes.IndexRune(line[dot:], ':')
	if sep == -1 {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	sep += dot
	end := bytes.IndexRune(line[sep:], ')')
	if end == -1 {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	end += sep

	// Parse timestamp.
	sec, err := strconv.ParseInt(string(line[start+1:dot]), 10, 64)
	if err != nil {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	msec, err := strconv.ParseInt(string(line[dot+1:sep]), 10, 64)
	if err != nil {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	tm := time.Unix(sec, msec*int64(time.Millisecond))

	// Parse sequence.
	sequence, err := strconv.Atoi(string(line[sep+1 : end]))
	if err != nil {
		return time.Time{}, 0, errInvalidAuditHeader
	}

	return tm, sequence, nil
}

// ParseNetlinkAuditMessage parses an audit message received from the kernel.
// Audit messages differ significantly from typical netlink messages in that
// a single message is sent and the length in the header should be ignored.
// This is why syscall.ParseNetlinkMessage is not used.
func ParseNetlinkAuditMessage(buf []byte) ([]syscall.NetlinkMessage, error) {
	if len(buf) < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL
	}

	r := bytes.NewReader(buf)
	m := syscall.NetlinkMessage{}
	if err := binary.Read(r, binary.LittleEndian, &m.Header); err != nil {
		return nil, err
	}
	m.Data = buf[syscall.NLMSG_HDRLEN:]

	return []syscall.NetlinkMessage{m}, nil
}

// AuditSetPID sends a netlink message to the kernel telling it the PID of
// netlink listener that should receive the audit messages.
// https://github.com/linux-audit/audit-userspace/blob/990aa27ccd02f9743c4f4049887ab89678ab362a/lib/libaudit.c#L432-L464
func AuditSetPID(client NetlinkSendReceiver, pid int) error {
	status := AuditStatus{
		Mask: AuditStatusPID,
		PID:  uint32(pid),
	}

	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  uint16(AUDIT_SET),
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		},
		Data: status.ToWireFormat(),
	}

	_, err := client.Send(msg)
	// XXX: This should use sequence number to look for an ACK to our message.
	return err
}

// audit_status

// https://github.com/linux-audit/audit-kernel/blob/v4.7/include/uapi/linux/audit.h#L318-L325
type AuditStatusMask uint32

const (
	AuditStatusEnabled AuditStatusMask = 1 << iota
	AuditStatusFailure
	AuditStatusPID
	AuditStatusRateLimit
	AuditStatusBacklogLimit
	AuditStatusBacklogWaitTime
)

var sizeofAuditStatus = int(unsafe.Sizeof(AuditStatus{}))

// https://github.com/linux-audit/audit-kernel/blob/v4.7/include/uapi/linux/audit.h#L413-L427
type AuditStatus struct {
	Mask            AuditStatusMask // Bit mask for valid entries.
	Enabled         uint32          // 1 = enabled, 0 = disabled
	Failure         uint32          // Failure-to-log action.
	PID             uint32          // PID of auditd process.
	RateLimit       uint32          // Messages rate limit (per second).
	BacklogLimit    uint32          // Waiting messages limit.
	Lost            uint32          // Messages lost.
	Backlog         uint32          // Messages waiting in queue.
	FeatureBitmap   uint32          // Bitmap of kernel audit features (previously to 3.19 it was the audit api version number).
	BacklogWaitTime uint32          // Message queue wait timeout.
}

func (s AuditStatus) ToWireFormat() []byte {
	buf := bytes.NewBuffer(make([]byte, sizeofInetDiagReqV2))
	buf.Reset()
	if err := binary.Write(buf, binary.LittleEndian, s); err != nil {
		// This never returns an error.
		panic(err)
	}
	return buf.Bytes()
}
