package runner

import (
	"bytes"
	"context"
	"testing"
)

func TestApplicationCloudCredentialsRemainUsable(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-not-authorized")
	var out bytes.Buffer
	code, err := Run(context.Background(), t.TempDir(), []string{"/bin/sh", "-c", `printf '%s' "$AWS_SECRET_ACCESS_KEY"`}, map[string]string{"AWS_SECRET_ACCESS_KEY": "explicit-app-credential"}, nil, &out, &out)
	if err != nil || code != 0 || out.String() != "explicit-app-credential" {
		t.Fatalf("explicit app credentials rejected: exit=%d err=%v", code, err)
	}
}
