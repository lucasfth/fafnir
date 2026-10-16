package runner

import (
	"bytes"
	"context"
	"testing"
)

func TestShellStartupControlsRejectedBeforeExecution(t *testing.T) {
	for _, name := range []string{"SHELLOPTS", "BASHOPTS", "PS4", "BASH_XTRACEFD"} {
		t.Run(name, func(t *testing.T) {
			var out, diag bytes.Buffer
			_, e := Run(context.Background(), t.TempDir(), []string{"/bin/bash", "-c", `test "$APP_TOKEN" = synthetic-sentinel`}, map[string]string{name: "xtrace", "APP_TOKEN": "synthetic-sentinel"}, nil, &out, &diag)
			if e == nil || out.Len() != 0 || diag.Len() != 0 {
				t.Fatal("shell startup control reached child or leaked output")
			}
		})
	}
}
