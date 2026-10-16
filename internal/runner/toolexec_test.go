package runner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoToolexecRejectedBeforeChild(t *testing.T) {
	goexe, e := exec.LookPath("go")
	if e != nil {
		t.Skip("Go executable not on PATH")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "wrapper-ran")
	wrapper := filepath.Join(dir, "wrapper")
	if e = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module synthetic.example/test\n\ngo 1.27.0\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	script := "#!/bin/sh\nprintf ran > '" + strings.ReplaceAll(marker, "'", "'\\''") + "'\nexec \"$@\"\n"
	if e = os.WriteFile(wrapper, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	secret := "-toolexec=" + wrapper
	_, e = Run(context.Background(), dir, []string{goexe, "build", "."}, map[string]string{"GOFLAGS": secret}, nil, &out, &out)
	if e == nil || out.Len() != 0 {
		t.Fatal("Go control allowed child execution")
	}
	if strings.Contains(e.Error(), secret) {
		t.Fatal("error exposed control value")
	}
	if _, e = os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("wrapper ran")
	}
}
