package linux

import (
	"os"
	"syscall"
	"testing"
)

func TestAuditClientSetPID(t *testing.T) {
	c, err := NewAuditClient(nil)
	if err != nil {
		t.Fatal(err)
	}

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
	msg := msgs[0]
	t.Logf("%+v", msg)

	if msg.Header.Type == syscall.NLMSG_ERROR {
		err := ParseNetlinkError(msg.Data)
		t.Log(err)
	}
	status := &AuditStatus{}
	status.fromWireFormat(msg.Data)
	t.Logf("%+v", status)
	t.Log(syscall.Errno(status.Failure))
}
