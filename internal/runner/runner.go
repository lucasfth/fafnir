// Package runner launches applications without forwarding decryption credentials.
package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

var variable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Restricted reports names that must not be supplied by decrypted configuration.
func Restricted(name string) bool {
	upper := strings.ToUpper(name)
	for _, p := range []string{"FAFNIR_", "SOPS_", "AGE_", "BW_", "GIT_", "LD_", "DYLD_", "CGO_"} {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	switch upper {
	case "SHELLOPTS", "BASHOPTS", "PS4", "BASH_XTRACEFD", "ZSHENV", "ZSH_DEBUG_CMD":
		return true
	case "GOFLAGS", "GOWORK", "GOENV", "CC", "CXX", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "AR", "FC", "PKG_CONFIG":
		return true
	case "PATH", "HOME", "USER", "LOGNAME", "SHELL", "ENV", "BASH_ENV", "ZDOTDIR", "CDPATH", "IFS", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME", "RUBYOPT", "RUBYLIB", "PERL5OPT", "PERL5LIB", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "GODEBUG", "GOTOOLCHAIN", "GOPATH", "GOROOT", "SSLKEYLOGFILE", "VAULT_TOKEN", "VAULT_ADDR", "BITWARDENCLI_APPDATA_DIR":
		return true
	}
	return false
}

func credential(name string) bool {
	u := strings.ToUpper(name)
	for _, p := range []string{"FAFNIR_", "SOPS_", "AGE_", "BW_"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	switch u {
	case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH", "VAULT_TOKEN", "VAULT_ADDR", "BITWARDENCLI_APPDATA_DIR":
		return true
	}
	return false
}

// Run never constructs a shell command from args. A caller can explicitly choose a
// shell, but decrypted values cannot change its control variables or arguments.
func Run(ctx context.Context, dir string, args []string, values map[string]string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 || args[0] == "" {
		return 1, errors.New("a program is required after --")
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	for name, value := range values {
		if !variable.MatchString(name) || Restricted(name) || strings.ContainsRune(value, 0) {
			return 1, errors.New("secrets contain a reserved or invalid environment variable")
		}
	}
	env := make(map[string]string)
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if ok && !credential(name) {
			env[name] = value
		}
	}
	for name, value := range values {
		env[name] = value
	}
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	childEnv := make([]string, 0, len(names))
	for _, name := range names {
		childEnv = append(childEnv, name+"="+env[name])
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = childEnv
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return 1, errors.New("could not start requested program")
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if ctx.Err() != nil {
		return 1, ctx.Err()
	}
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return exit.ExitCode(), nil
	}
	return 1, errors.New("requested program failed")
}
