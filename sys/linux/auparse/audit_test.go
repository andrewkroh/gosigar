// +build linux

package linux

import (
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const syscallMsg = `audit(1490137971.011:50406): arch=c000003e syscall=42 ` +
	`success=yes exit=0 a0=15 a1=7ffd83722200 a2=6e a3=ea60 items=1 ppid=1 ` +
	`pid=1229 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 ` +
	`fsgid=0 tty=(none) ses=4294967295 comm="master" ` +
	`exe="/usr/libexec/postfix/master" ` +
	`subj=system_u:system_r:postfix_master_t:s0 key=(null)`

const sockaddrMsg = `audit(1490239193.510:97026): saddr=02000050A9FEA9FE0000000000000000`

const useracctMsg = `audit(1489636977.805:19623808): user pid=28395 uid=0 ` +
	`auid=700 ses=12286 msg='op=PAM:accounting acct="root" exe="/bin/su" ` +
	`hostname=? addr=? terminal=pts/0 res=success'`

const acvMsg = `audit(1418211771.996:29): avc:  denied  { read } for  pid=1494 ` +
	`comm="auditd" name="audit" dev=xvdf ` +
	`ino=49153 scontext=unconfined_u:system_r:auditd_t:s0 ` +
	`tcontext=unconfined_u:object_r:var_log_t:s0 tclass=dir`

const userCmd = `audit(1490297778.146:20058446): user pid=30681 uid=497 ` +
	`auid=700 ses=11988 msg='cwd="/" ` +
	`cmd=2F7573722F6C696236342F6E6167696F732F706C7567696E732F636865636B5F617374657269736B5F7369705F7065657273202D7020313033 ` +
	`terminal=? res=success'`

func TestAuditStatusMask(t *testing.T) {
	assert.EqualValues(t, 0x0001, AuditStatusEnabled)
	assert.EqualValues(t, 0x0002, AuditStatusFailure)
	assert.EqualValues(t, 0x0004, AuditStatusPID)
	assert.EqualValues(t, 0x0008, AuditStatusRateLimit)
	assert.EqualValues(t, 0x00010, AuditStatusBacklogLimit)
	assert.EqualValues(t, 0x00020, AuditStatusBacklogWaitTime)
}

func TestAuditMessageType(t *testing.T) {
	// https://github.com/linux-audit/audit-kernel/blob/v4.7/include/uapi/linux/audit.h#L53-L72
	assert.EqualValues(t, 1000, AUDIT_GET)
	assert.EqualValues(t, 1019, AUDIT_GET_FEATURE)
}

func TestParseAuditMessage(t *testing.T) {
	nlm := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type: 1300,
		},
		Data: []byte(syscallMsg),
	}

	msg, err := ParseAuditMessage(nlm)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(msg)
	assert.EqualValues(t, 1300, msg.RecordType)
	assert.EqualValues(t, 50406, msg.Sequence)
}

func TestParseAuditHeader(t *testing.T) {
	_, seq, err := parseAuditHeader([]byte(syscallMsg))
	if err != nil {
		t.Fatal(err)
	}

	assert.EqualValues(t, 50406, seq)
}

func BenchmarkParseAuditHeader(b *testing.B) {
	msg := []byte(syscallMsg)
	for i := 0; i < b.N; i++ {
		_, _, err := parseAuditHeader(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAuditHeaderRegex(b *testing.B) {
	var auditMessageRegex = regexp.MustCompile(`^audit\((\d+).(\d+):(\d+)\):`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matches := auditMessageRegex.FindStringSubmatch(syscallMsg)
		if len(matches) != 4 {
			b.Fatal(errInvalidAuditHeader)
		}

		sec, _ := strconv.ParseInt(matches[1], 10, 64)
		msec, _ := strconv.ParseInt(matches[2], 10, 64)
		_ = time.Unix(sec, msec*int64(time.Millisecond))
		_, _ = strconv.Atoi(matches[3])
	}
}
