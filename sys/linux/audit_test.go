package linux

import (
	"os"
	"syscall"
	"testing"
	"fmt"
	"encoding/binary"
)

func TestAuditClientGetStatus(t *testing.T) {
	c, err := NewAuditClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.GetStatus()
	if err != nil {
		t.Fatal(err)
	}

	msgs, err := c.netlink.Receive(false, syscall.ParseNetlinkMessage)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("length msgs", len(msgs))
	if len(msgs) == 0 {
		t.Fatal("expected to receive a message")
	}
	m := msgs[0]
	t.Logf("%+v", m)

	status := &AuditStatus{}
	status.fromWireFormat(m.Data)
	t.Logf("%+v", status)
}

func TestAuditClientSetPID(t *testing.T) {
	c, err := NewAuditClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.SetPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}

	//m, err := c.Receive(false)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//status := &AuditStatus{}
	//status.fromWireFormat(m.RawData)
	//t.Log(m.MessageType)
	//t.Logf("%+v", status)
	//
	//assert.EqualValues(t, AuditGet, m.MessageType, "expected AUDIT_GET message type")
	//assert.EqualValues(t, os.Getpid(), status.PID)

	msgs, err := c.netlink.Receive(false, syscall.ParseNetlinkMessage)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) == 0 {
		t.Fatal("expected to receive a message")
	}

	msgs, err = auditGetReply(msgs, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	msg := msgs[0]



	t.Logf("%+v", msg)

	if msg.Header.Type == syscall.NLMSG_ERROR {
		err := ParseNetlinkError(msg.Data)
		t.Log(err, syscall.Errno(uint32(err.(NetlinkErrno))))
	}
	status := &AuditStatus{}
	status.fromWireFormat(msg.Data)
	t.Logf("%+v", status)
	t.Log(syscall.Errno(status.Failure))
}

func auditGetReply(msgs []syscall.NetlinkMessage, seq uint32, chkAck bool) (ret []syscall.NetlinkMessage, err error) {
	done:
	for {
		dbrk := false
		for _, m := range msgs {
			if m.Header.Seq != seq {
				// Wasn't the sequence number we are looking for, just discard it
				continue
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				e := int32(binary.LittleEndian.Uint32(m.Data[0:4]))
				if e == 0 {
					// ACK response from the kernel; if chkAck is true
					// we just return as there is nothing left to do
					if chkAck {
						break done
					}
					// Otherwise, keep going so we can get the response
					// we want
					continue
				} else {
					return ret, fmt.Errorf("auditGetReply: error while recieving reply -%d", e)
				}
			}
			ret = append(ret, m)
			if (m.Header.Flags & syscall.NLM_F_MULTI) == 0 {
				// If it's not a multipart message, once we get one valid
				// message just return
				dbrk = true
				break
			}
		}
		if dbrk {
			break
		}
	}
	return ret, nil
}