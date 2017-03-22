// +build linux

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"syscall"
)

// Generic Netlink Client

type NetlinkSender interface {
	Send(msg syscall.NetlinkMessage) (uint32, error)
}

type NetlinkReceiver interface {
	Receive(nonBlocking bool, p NetlinkParser) ([]syscall.NetlinkMessage, error)
}

type NetlinkSendReceiver interface {
	NetlinkSender
	NetlinkReceiver
}

type NetlinkParser func([]byte) ([]syscall.NetlinkMessage, error)

type NetlinkClient struct {
	fd         int                      // File descriptor used for communication.
	lsa        *syscall.SockaddrNetlink // Netlink local socket address.
	seq        uint32                   // Sequence number used in outgoing messages.
	readBuf    []byte
	respWriter io.Writer
}

func NewNetlinkClient(proto int, readBuf []byte, resp io.Writer) (*NetlinkClient, error) {
	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, err
	}

	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err = syscall.Bind(s, lsa); err != nil {
		syscall.Close(s)
		return nil, err
	}

	if len(readBuf) == 0 {
		// Default size used in libnl.
		readBuf = make([]byte, os.Getpagesize())
	}

	return &NetlinkClient{
		fd:         s,
		lsa:        lsa,
		readBuf:    readBuf,
		respWriter: resp,
	}, nil
}

func (c *NetlinkClient) Send(msg syscall.NetlinkMessage) (uint32, error) {
	msg.Header.Seq = atomic.AddUint32(&c.seq, 1)
	return msg.Header.Seq, syscall.Sendto(c.fd, serialize(msg), 0, c.lsa)
}

func (c *NetlinkClient) Receive(nonBlocking bool, p NetlinkParser) ([]syscall.NetlinkMessage, error) {
	var flags int
	if nonBlocking {
		flags |= syscall.MSG_DONTWAIT
	}

	// XXX (akroh): A possible enhancement is to use the MSG_PEEK flag to
	// check the message size and increase the buffer size to handle it all.
	nr, from, err := syscall.Recvfrom(c.fd, c.readBuf, flags)
	if err != nil {
		// EAGAIN or EWOULDBLOCK will be returned for non-blocking reads where
		// the read would normally have blocked.
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL
	}
	fromNetlink, ok := from.(*syscall.SockaddrNetlink)
	if ok && fromNetlink.Pid != 0 {
		// Spoofed packet received on audit netlink socket.
		return nil, syscall.EINVAL
	}

	buf := c.readBuf[:nr]

	// Dump raw data for inspection purposes.
	if c.respWriter != nil {
		if _, err := c.respWriter.Write(buf); err != nil {
			return nil, err
		}
	}

	msgs, err := p(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse netlink messages: %v", err)
	}

	return msgs, nil
}

// Close closes the netlink client's raw socket.
func (c *NetlinkClient) Close() error {
	return syscall.Close(c.fd)
}

// Netlink Error Code Handling

// ParseNetlinkError parses the errno from the data section of a
// syscall.NetlinkMessage. If netlinkData is less than 4 bytes an error
// describing the problem will be returned.
func ParseNetlinkError(netlinkData []byte) error {
	if len(netlinkData) >= 4 {
		errno := -binary.LittleEndian.Uint32(netlinkData[:4])
		return NetlinkErrno(errno)
	}
	return errors.New("received netlink error (data too short to read errno)")
}

// NetlinkErrno represent the error code contained in a netlink message of
// type NLMSG_ERROR.
type NetlinkErrno uint32

// Netlink error codes.
const (
	NLE_SUCCESS NetlinkErrno = iota
	NLE_FAILURE
	NLE_INTR
	NLE_BAD_SOCK
	NLE_AGAIN
	NLE_NOMEM
	NLE_EXIST
	NLE_INVAL
	NLE_RANGE
	NLE_MSGSIZE
	NLE_OPNOTSUPP
	NLE_AF_NOSUPPORT
	NLE_OBJ_NOTFOUND
	NLE_NOATTR
	NLE_MISSING_ATTR
	NLE_AF_MISMATCH
	NLE_SEQ_MISMATCH
	NLE_MSG_OVERFLOW
	NLE_MSG_TRUNC
	NLE_NOADDR
	NLE_SRCRT_NOSUPPORT
	NLE_MSG_TOOSHORT
	NLE_MSGTYPE_NOSUPPORT
	NLE_OBJ_MISMATCH
	NLE_NOCACHE
	NLE_BUSY
	NLE_PROTO_MISMATCH
	NLE_NOACCESS
	NLE_PERM
	NLE_PKTLOC_FILE
	NLE_PARSE_ERR
	NLE_NODEV
	NLE_IMMUTABLE
	NLE_DUMP_INTR
	NLE_ATTRSIZE
)

// https://github.com/thom311/libnl/blob/libnl3_2_28/lib/error.c
var netlinkErrorMsgs = map[NetlinkErrno]string{
	NLE_SUCCESS:           "Success",
	NLE_FAILURE:           "Unspecific failure",
	NLE_INTR:              "Interrupted system call",
	NLE_BAD_SOCK:          "Bad socket",
	NLE_AGAIN:             "Try again",
	NLE_NOMEM:             "Out of memory",
	NLE_EXIST:             "Object exists",
	NLE_INVAL:             "Invalid input data or parameter",
	NLE_RANGE:             "Input data out of range",
	NLE_MSGSIZE:           "Message size not sufficient",
	NLE_OPNOTSUPP:         "Operation not supported",
	NLE_AF_NOSUPPORT:      "Address family not supported",
	NLE_OBJ_NOTFOUND:      "Object not found",
	NLE_NOATTR:            "Attribute not available",
	NLE_MISSING_ATTR:      "Missing attribute",
	NLE_AF_MISMATCH:       "Address family mismatch",
	NLE_SEQ_MISMATCH:      "Message sequence number mismatch",
	NLE_MSG_OVERFLOW:      "Kernel reported message overflow",
	NLE_MSG_TRUNC:         "Kernel reported truncated message",
	NLE_NOADDR:            "Invalid address for specified address family",
	NLE_SRCRT_NOSUPPORT:   "Source based routing not supported",
	NLE_MSG_TOOSHORT:      "Netlink message is too short",
	NLE_MSGTYPE_NOSUPPORT: "Netlink message type is not supported",
	NLE_OBJ_MISMATCH:      "Object type does not match cache",
	NLE_NOCACHE:           "Unknown or invalid cache type",
	NLE_BUSY:              "Object busy",
	NLE_PROTO_MISMATCH:    "Protocol mismatch",
	NLE_NOACCESS:          "No Access",
	NLE_PERM:              "Operation not permitted",
	NLE_PKTLOC_FILE:       "Unable to open packet location file",
	NLE_PARSE_ERR:         "Unable to parse object",
	NLE_NODEV:             "No such device",
	NLE_IMMUTABLE:         "Immutable attribute",
	NLE_DUMP_INTR:         "Dump inconsistency detected, interrupted",
	NLE_ATTRSIZE:          "Attribute max length exceeded",
}

func (e NetlinkErrno) Error() string {
	if msg, found := netlinkErrorMsgs[e]; found {
		return msg
	}

	return netlinkErrorMsgs[NLE_FAILURE]
}
