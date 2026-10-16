package runner

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

func TestChildEnvironmentAndArgumentBoundaries(t *testing.T) {
	t.Setenv("FAFNIR_PRIVATE_KEY", "must-not-reach-child")
	t.Setenv("BW_SESSION", "must-not-reach-child")
	t.Setenv("APP_VALUE", "inherited")
	var out, errout bytes.Buffer
	code, err := Run(context.Background(), t.TempDir(), []string{"/bin/sh", "-c", `printf '%s|%s|%s|%s' "$APP_VALUE" "${FAFNIR_PRIVATE_KEY-unset}" "${BW_SESSION-unset}" "$1"; exit 7`, "test", "$(touch never); literal"}, map[string]string{"APP_VALUE": "configured"}, nil, &out, &errout)
	if err != nil || code != 7 {
		t.Fatalf("exit=%d error=%v", code, err)
	}
	if got := out.String(); got != "configured|unset|unset|$(touch never); literal" {
		t.Fatalf("unexpected child output %q", got)
	}
}

func TestRejectsInjectedExecutionControls(t *testing.T) {
	for _, name := range []string{"GOFLAGS", "GOWORK", "GOENV", "CC", "CXX", "CGO_CFLAGS", "CFLAGS", "LDFLAGS", "PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "PYTHONPATH", "BASH_ENV", "FAFNIR_PRIVATE_KEY", "BW_SESSION", "SOPS_AGE_KEY_CMD", "GIT_CONFIG_COUNT", "INVALID-NAME"} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := Run(context.Background(), t.TempDir(), []string{"/bin/sh", "-c", "echo child-ran"}, map[string]string{name: "sensitive-value"}, nil, &out, &out)
			if err == nil || out.Len() != 0 {
				t.Fatalf("control variable allowed: %s", name)
			}
			if strings.Contains(err.Error(), "sensitive-value") {
				t.Fatal("error leaked secret")
			}
		})
	}
}

func TestMissingExecutableAndCancellation(t *testing.T) {
	_, err := Run(context.Background(), t.TempDir(), []string{"/not-a-fafnir-program"}, nil, nil, os.Stdout, os.Stderr)
	if err == nil {
		t.Fatal("missing executable accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Run(ctx, t.TempDir(), []string{"/bin/sh", "-c", "echo should-not-run"}, nil, nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("cancelled operation launched")
	}
}
