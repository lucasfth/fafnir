//go:build unix

package runner

import (
	"bytes"
	"context"
	"testing"
)

func TestChildSignalExitStatus(t *testing.T) {
	var out bytes.Buffer
	code, err := Run(context.Background(), t.TempDir(), []string{"/bin/sh", "-c", "kill -TERM $$"}, nil, nil, &out, &out)
	if err != nil || code != 143 {
		t.Fatalf("signal exit=%d err=%v", code, err)
	}
}
