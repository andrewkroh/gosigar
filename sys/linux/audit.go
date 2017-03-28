// +build linux

package linux

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"
)

const (
	// AuditMessageMaxLength is the maximum length of an audit message (data
	// portion of a NetlinkMessage).
	// https://github.com/linux-audit/audit-userspace/blob/990aa27ccd02f9743c4f4049887ab89678ab362a/lib/libaudit.h#L435
	AuditMessageMaxLength = 8970
)

// Audit command and control message types.
const (
	AuditGet uint16 = iota + 1000
	AuditSet
)

// AuditClient is a client for communicating with the Linux kernels audit
// interface over netlink.
type AuditClient struct {
	netlink *NetlinkClient
}

// NewAuditClient creates a new AuditClient. The resp parameter is optional. If
// provided resp will receive a copy of all data read from the netlink socket.
// This is useful for debugging purposes.
func NewAuditClient(resp io.Writer) (*AuditClient, error) {
	buf := make([]byte, AuditMessageMaxLength)

	netlink, err := NewNetlinkClient(syscall.NETLINK_AUDIT, buf, resp)
	if err != nil {
		return nil, err
	}

	return &AuditClient{netlink: netlink}, nil
}

func (c *AuditClient) GetStatus() (*AuditStatus, error) {
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  AuditGet,
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		},
		Data: nil,
	}

	// Send AUDIT_GET message to the kernel.
	seq, err := c.netlink.Send(msg)
	if err != nil {
		return nil, errors.Wrap(err, "failed sending request")
	}

	// Get the ack message which is a NLMSG_ERROR type whose error code is SUCCESS.
	ack, err := c.getReply(seq)
	if err != nil {
		return nil, err
	}
	fmt.Printf("ACK: %+v\n", ack)

	if ack.Header.Type != syscall.NLMSG_ERROR {
		return nil, errors.Errorf("unexpected ACK to GET, type=%d", ack.Header.Type)
	}

	if err := ParseNetlinkError(ack.Data); err != NLE_SUCCESS {
		if len(ack.Data) >= 16 {
			// Read the third int, its the failure code.
			errno := syscall.Errno(binary.LittleEndian.Uint32(ack.Data[3*4:]))
			return nil, errno
		}
		return nil, err
	}

	// Get the audit_status reply message. It has the same sequence number as
	// our original request.
	reply, err := c.getReply(seq)
	if err != nil {
		return nil, err
	}
	fmt.Printf("REPLY: %+v\n", reply)

	if reply.Header.Type != AuditGet {
		return nil, errors.Errorf("unexpected reply to GET, type%d", reply.Header.Type)
	}

	replyStatus := &AuditStatus{}
	if err := replyStatus.fromWireFormat(reply.Data); err != nil {
		return nil, err
	}

	return replyStatus, nil
}

// getReply reads from the netlink socket and find the message with the given
// sequence number. Any non-matching messages are dropped. The caller should
// inspect the returned message's type, flags, and error code.
func (c *AuditClient) getReply(seq uint32) (*syscall.NetlinkMessage, error) {
	var msgs []syscall.NetlinkMessage
	var err error

	// Retry the non-blocking read multiple times until a response is received.
	for i := 0; i < 10; i++ {
		msgs, err = c.netlink.Receive(true, syscall.ParseNetlinkMessage)
		if err != nil {
			switch err {
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				time.Sleep(50 * time.Millisecond)
				continue
			default:
				return nil, errors.Wrap(err, "error receiving audit netlink packet")
			}
		}

		break
	}

	var rtn *syscall.NetlinkMessage
	for i, msg := range msgs {
		// Find matching sequence number.
		if msg.Header.Seq == seq {
			//return &msg, nil
			rtn = &msg
		}
		fmt.Printf("resp %d: %+v\n", i, msg)
	}
	if rtn != nil {
		return rtn, nil
	}

	return nil, errors.New("no reply received")
}

func (c *AuditClient) Set(status AuditStatus) error {
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  AuditSet,
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		},
		Data: status.toWireFormat(),
	}

	seq, err := c.netlink.Send(msg)
	if err != nil {
		return errors.Wrap(err, "failed sending request")
	}

	reply, err := c.getReply(seq)
	if err != nil {
		return err
	}

	fmt.Printf("reply: %+v\n", reply)

	if reply.Header.Type == syscall.NLMSG_ERROR {
		err := ParseNetlinkError(reply.Data)
		if err == NLE_SUCCESS {
			return nil
		}

		if len(reply.Data) > sizeofAuditStatus {
			replyStatus := &AuditStatus{}
			replyStatus.fromWireFormat(reply.Data[4:])
			fmt.Printf("%+v\n", replyStatus)
			fmt.Println("failure:", syscall.Errno(replyStatus.Failure))
			return syscall.Errno(replyStatus.Failure)
		}
		return err
	}

	return errors.Errorf("invalid response, bad type %d", reply.Header.Type)
}

// SetPID sends a netlink message to the kernel telling it the PID of
// netlink listener that should receive the audit messages.
// https://github.com/linux-audit/audit-userspace/blob/990aa27ccd02f9743c4f4049887ab89678ab362a/lib/libaudit.c#L432-L464
func (c *AuditClient) SetPID(pid int) error {
	netlinkPID := uint32(pid)
	if netlinkPID == 0 {
		netlinkPID = c.netlink.pid
	}

	status := AuditStatus{
		Mask:    AuditStatusEnabled | AuditStatusPID,
		Enabled: 1,
		PID:     netlinkPID,
	}
	return c.Set(status)
}

// RawAuditMessage is a raw audit message received from the kernel.
type RawAuditMessage struct {
	MessageType uint16
	RawData     []byte // RawData is backed by the read buffer so make a copy.
}

// Receive reads an audit message from the netlink socket. If you are going to
// use the returned message then you should make a copy of the raw data before
// calling receive again because the raw data is backed by the read buffer.
func (c *AuditClient) Receive(nonBlocking bool) (*RawAuditMessage, error) {
	msgs, err := c.netlink.Receive(nonBlocking, parseNetlinkAuditMessage)
	if err != nil {
		return nil, err
	}

	// ParseNetlinkAuditMessage always return a slice with 1 item.
	return &RawAuditMessage{
		MessageType: msgs[0].Header.Type,
		RawData:     msgs[0].Data,
	}, nil
}

// Close closes the AuditClient and frees any associated resources.
func (c *AuditClient) Close() error {
	return c.netlink.Close()
}

// parseNetlinkAuditMessage parses an audit message received from the kernel.
// Audit messages differ significantly from typical netlink messages in that
// a single message is sent and the length in the header should be ignored.
// This is why syscall.ParseNetlinkMessage is not used.
func parseNetlinkAuditMessage(buf []byte) ([]syscall.NetlinkMessage, error) {
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

// audit_status message

// AuditStatusMask is a bitmask used to convey the fields used in AuditStatus.
// https://github.com/linux-audit/audit-kernel/blob/v4.7/include/uapi/linux/audit.h#L318-L325
type AuditStatusMask uint32

// Mask types for AuditStatus.
const (
	AuditStatusEnabled AuditStatusMask = 1 << iota
	AuditStatusFailure
	AuditStatusPID
	AuditStatusRateLimit
	AuditStatusBacklogLimit
	AuditStatusBacklogWaitTime
)

var sizeofAuditStatus = int(unsafe.Sizeof(AuditStatus{}))

// AuditStatus is a status message and command and control message exchanged
// between the kernel and user-space.
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

func (s AuditStatus) toWireFormat() []byte {
	buf := bytes.NewBuffer(make([]byte, sizeofInetDiagReqV2))
	buf.Reset()
	if err := binary.Write(buf, binary.LittleEndian, s); err != nil {
		// This never returns an error.
		panic(err)
	}
	return buf.Bytes()
}

func (s *AuditStatus) fromWireFormat(buf []byte) error {
	r := bytes.NewReader(buf)
	return binary.Read(r, binary.LittleEndian, s)
}
