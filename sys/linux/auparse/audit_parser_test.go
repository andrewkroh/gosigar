package linux_test

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"encoding/json"

	"github.com/elastic/gosigar/sys/linux"
	"github.com/stretchr/testify/assert"
)

const (
	syscallMsg = `audit(1490137971.011:50406): arch=c000003e syscall=42 ` +
		`success=yes exit=0 a0=15 a1=7ffd83722200 a2=6e a3=ea60 items=1 ppid=1 ` +
		`pid=1229 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 ` +
		`fsgid=0 tty=(none) ses=4294967295 comm="master" ` +
		`exe="/usr/libexec/postfix/master" ` +
		`subj=system_u:system_r:postfix_master_t:s0 key=(null)`

	avcMsg = `audit(1418211771.996:29): avc:  denied  { read } for  pid=1494 ` +
		`comm="auditd" name="audit" dev=xvdf ` +
		`ino=49153 scontext=unconfined_u:system_r:auditd_t:s0 ` +
		`tcontext=unconfined_u:object_r:var_log_t:s0 tclass=dir`

	userCmdMsg = `audit(1490297778.146:20058446): user pid=30681 uid=497 ` +
		`auid=700 ses=11988 msg='cwd="/" ` +
		`cmd=2F7573722F6C696236342F6E6167696F732F706C7567696E732F636865636B5F617374657269736B5F7369705F7065657273202D7020313033 ` +
		`terminal=? res=success'`

	chauthtokenMsg = `audit(1279423171.106:100): user ` +
		`pid=2034 uid=0 auid=0 msg='op=change password id=501 exe="/usr/bin/passwd" ` +
		`(hostname=?, addr=?, terminal=pts/0 res=success)'`

	loginMsg = `audit(1343908063.093:193): login pid=3171 uid=0 old auid=4294967295 new auid=42 old ses=4294967295 new ses=12 `
)

var errParseFailure = errors.New("failed to parse audit message")

const (
	auditHeaderSeperator = "):"
)

var (
	keyValueRegex = regexp.MustCompile(`[a-z0-9_]+=`)

	// avcMessageRegex matches the beginning of AVC messages to parse the
	// seresult and seperms parameters. Example: "avc:  denied  { read } for  "
	avcMessageRegex = regexp.MustCompile(`avc:\s+(\w+)\s+\{\s*(.*)\s*\}\s+for\s+`)
)

func fixAuditLine(typ linux.AuditMessageType, msg string) (string, error) {
	switch typ {
	case linux.AUDIT_AVC:
		i := avcMessageRegex.FindStringSubmatchIndex(msg)
		if len(i) != 3*2 {
			return "", errParseFailure
		}
		perms := strings.Fields(msg[i[4]:i[5]])
		msg = fmt.Sprintf("seresult=%v seperms=%v %v", msg[i[2]:i[3]], strings.Join(perms, ","), msg[i[1]:])
	case linux.AUDIT_LOGIN:
		msg = strings.Replace(msg, "old ", "old_", 2)
		msg = strings.Replace(msg, "new ", "new_", 2)
	}

	return msg, nil
}

func removeAuditHeader(msg string) (string, error) {
	start := strings.Index(msg, auditHeaderSeperator)
	if start == -1 {
		return "", errParseFailure
	}

	return msg[start+len(auditHeaderSeperator):], nil
}

func parseAuditLine(typ linux.AuditMessageType, msg string) (map[string]string, error) {
	msg, err := removeAuditHeader(msg)
	if err != nil {
		return nil, err
	}

	msg, err = fixAuditLine(typ, msg)
	if err != nil {
		return nil, err
	}

	data := map[string]string{
		"type":    typ.String(),
		"raw_msg": msg,
	}

	keyIndexes := keyValueRegex.FindAllStringSubmatchIndex(msg, -1)
	for i, keyIndex := range keyIndexes {
		key := msg[keyIndex[0] : keyIndex[1]-1]
		var value string

		if i < len(keyIndexes)-1 {
			nextKeyIndex := keyIndexes[i+1]
			value = TrimQuotesAndSpace(msg[keyIndex[1]:nextKeyIndex[0]])
		} else {
			value = TrimQuotesAndSpace(msg[keyIndex[1]:len(msg)])
		}

		if value == "" || value == "?" {
			continue
		}

		data[key] = value
	}

	return data, nil
}

func TrimQuotesAndSpace(v string) string {
	isQuote := func(r rune) bool {
		if r == '\'' || r == '"' || r == ' ' {
			return true
		}
		return false
	}
	return strings.TrimFunc(v, isQuote)
}

func TestFixAuditLine(t *testing.T) {
	tests := []struct {
		typ linux.AuditMessageType
		in  string
		out string
	}{
		{
			linux.AUDIT_AVC,
			`avc:  denied  { read } for  pid=1494`,
			`seresult=denied seperms=read pid=1494`,
		},
		{
			linux.AUDIT_LOGIN,
			`login pid=26125 uid=0 old auid=4294967295 new auid=0 old ses=4294967295 new ses=1172`,
			`login pid=26125 uid=0 old_auid=4294967295 new_auid=0 old_ses=4294967295 new_ses=1172`,
		},
	}

	for _, tc := range tests {
		msg, err := fixAuditLine(tc.typ, tc.in)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, tc.out, msg)
	}
}

func TestParseAuditLine(t *testing.T) {
	do := func(typ linux.AuditMessageType, m string) {
		data, err := parseAuditLine(typ, m)
		if err != nil {
			t.Fatal(err)
		}
		json, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(string(json))
		assert.Equal(t, "c000003e", data["arch"])
	}

	do(linux.AUDIT_SYSCALL, syscallMsg)
	do(linux.AUDIT_USER_CMD, userCmdMsg)
	do(linux.AUDIT_AVC, avcMsg)
	do(linux.AUDIT_GRP_CHAUTHTOK, chauthtokenMsg)
	do(linux.AUDIT_LOGIN, loginMsg)
}

// item represents a token returned from the scanner.
type item struct {
	typ itemType // Token type, such as itemVariable.
	pos int      // The starting position, in bytes, of this item in the input string.
	val string   // Value, such as "${".
}

func (i item) String() string {
	switch {
	case i.typ == itemEOF:
		return "EOF"
	default:
		return i.val
	}
}

// itemType identifies the type of lex items.
type itemType int

// lex tokens.
const (
	itemError itemType = iota + 1
	itemText
	itemKey
	itemSeperator
	itemValue
	itemEOF
)

const eof = -1

// stateFn represents the state of the scanner as a function that returns the
// next state.
type stateFn func(*lexer) stateFn

// lexer holds the state of the scanner.
type lexer struct {
	name    string    // used only for error reports.
	input   string    // the string being scanned.
	start   int       // start position of this item.
	pos     int       // current position in the input.
	width   int       // width of last rune read from input.
	lastPos int       // position of most recent item returned by nextItem
	items   chan item // channel of scanned items.
}
