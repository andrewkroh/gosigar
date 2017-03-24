// package auparse provides utilities for parsing Linux audit messages.
package auparse

//go:generate bash -c "go run mk_audit_msg_types.go && gofmt -w audit_msg_types.go"
//go:generate bash -c "perl mk_audit_syscalls.pl > audit_syscalls.go && gofmt -w audit_syscalls.go"
//go:generate perl mk_audit_arches.pl
