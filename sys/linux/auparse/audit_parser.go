package linux

import (
	"bytes"
	"strconv"
	"syscall"
	"time"
)

// Enrichment

type FieldEnricher func(value string) (map[string]interface{}, error)

var enrichers = map[string]FieldEnricher{
	"arch": func(value string) (map[string]interface{}, error) {
		num, err := strconv.ParseInt(value, 16, 64)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"arch": AuditArch(num).String(),
		}, nil
	},
	"syscall": func(value string) (map[string]interface{}, error) {
		num, err := strconv.Atoi(value)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"syscall": AuditSyscalls["x86_64"][num],
		}, nil
	},
}

func Enrich(data map[string]string) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range data {
		f, found := enrichers[k]
		if !found {
			out[k] = v
			continue
		}

		enriched, err := f(v)
		if err != nil {
			out[k] = v
		} else {
			for x, y := range enriched {
				out[x] = y
			}
		}
	}
	return out
}

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
