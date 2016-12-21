// +build windows

package tracing

import "testing"

func TestOpenTrace(t *testing.T) {
	l := EventTraceLogfile{}
	l.LogFileName
	_OpenTrace()
}
