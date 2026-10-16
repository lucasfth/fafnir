// Package cli exposes the same operations to scripts and interactive users.
package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/lucasfth/fafnir/internal/crypt"
	"github.com/lucasfth/fafnir/internal/custody"
	"github.com/lucasfth/fafnir/internal/project"
	"github.com/lucasfth/fafnir/internal/runner"
	"golang.org/x/term"
)

const Version = "0.1.0-dev"
const help = `Fafnir — repository secrets, established encryption.

Usage: fafnir [global options] command [command options]
Run fafnir in a terminal for guided actions.

Global options (before command):
  --dir PATH          Repository directory (default current directory)
  --state-dir PATH    Private local trust state (default user config/fafnir)
  --key-file PATH     Explicit owner-only private identity file
  --account NAME      Native keychain account (default default)
  --paste-key         Masked identity input for this invocation only
  --accessible        Plain interactive prompts

Commands:
  key create                         Create identity in selected storage
  key import                         Paste identity into selected storage
  key public                         Public recipient: safe to share with team
  key export --output PATH           Private key backup: never send to coworkers
  key export --reveal --yes           Explicit sensitive terminal reveal
  key delete --yes                   Delete identity from selected storage
  init --file .env --recipient AGE... Initialize explicit file pair and approval
  trust --yes                        Approve displayed repository policy locally
  seal [--file .env] [--replace]       Encrypt plaintext to .env.fafnir
  open [--file .env] [--replace]       Restore plaintext without printing values
  run [--file .env] -- PROGRAM ARGS    Decrypt into child environment, not a file
  check [--staged] [--decrypt]         Structure/policy; optionally authenticate/sync
  grant --file .env --recipient AGE   Authorize coworker's public recipient
  revoke --file .env --recipient AGE --yes
                                     Remove recipient with fresh encryption
  hook install                       Install a non-overwriting staged-blob guard

Global options precede commands. Repeat --recipient for multiple recipients.
Plaintext .env remains gitignored. Share public recipients, never private keys.
Encryption is not a sandbox or proof of author identity/freshness.
`

type options struct {
	dir, state, keyfile, account string
	paste, accessible            bool
}
type app struct {
	options
	in        io.Reader
	out, diag io.Writer
	ctx       context.Context
	cached    string
}

func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}
func tty(w any) bool { f, ok := w.(*os.File); return ok && term.IsTerminal(int(f.Fd())) }

// Execute never echoes unrecognized argument values or raw decrypted input.
func Execute(ctx context.Context, args []string, in io.Reader, out, diag io.Writer) int {
	cfg, err := os.UserConfigDir()
	if err != nil {
		fmt.Fprintln(diag, "cannot locate user configuration directory")
		return 1
	}
	a := &app{options: options{dir: ".", state: filepath.Join(cfg, "fafnir"), account: "default"}, in: in, out: out, diag: diag, ctx: ctx}
	fs := flag.NewFlagSet("fafnir", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&a.dir, "dir", a.dir, "")
	fs.StringVar(&a.state, "state-dir", a.state, "")
	fs.StringVar(&a.keyfile, "key-file", "", "")
	fs.StringVar(&a.account, "account", a.account, "")
	fs.BoolVar(&a.paste, "paste-key", false, "")
	fs.BoolVar(&a.accessible, "accessible", false, "")
	if fs.Parse(args) != nil {
		if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
			fmt.Fprint(out, help)
			return 0
		}
		fmt.Fprintln(diag, "invalid global options; use fafnir help")
		return 2
	}
	cmd := fs.Args()
	if a.account == "" || safe(a.account) != a.account || len(a.account) > 128 {
		fmt.Fprintln(diag, "invalid keychain account label")
		return 2
	}
	if len(cmd) == 0 {
		if !tty(in) || !tty(diag) {
			fmt.Fprintln(diag, "a command is required outside an interactive terminal; use fafnir help")
			return 2
		}
		err = a.menu()
		if err != nil {
			fmt.Fprintln(diag, safe(err.Error()))
			return 1
		}
		return 0
	}
	if cmd[0] == "help" || cmd[0] == "--help" || cmd[0] == "-h" {
		fmt.Fprint(out, help)
		return 0
	}
	if cmd[0] == "version" {
		fmt.Fprintln(out, Version)
		return 0
	}
	code, err := a.command(cmd)
	if err != nil {
		fmt.Fprintln(diag, "fafnir:", safe(err.Error()))
		if code == 0 {
			code = 1
		}
	}
	return code
}
func (a *app) store() custody.Store {
	if a.keyfile != "" {
		return custody.NewFile(a.keyfile)
	}
	return custody.NewKeychain(a.account)
}
func (a *app) identity() (string, error) {
	if a.cached != "" {
		return a.cached, nil
	}
	if a.paste {
		v, e := a.secret("Private decryption key — secret; current invocation only")
		if e != nil {
			return "", e
		}
		if _, e = crypt.Public(v); e != nil {
			return "", errors.New("invalid private identity")
		}
		a.cached = v
		return v, nil
	}
	return a.store().Get()
}

func (a *app) publicPath() string {
	if a.keyfile != "" {
		return a.keyfile + ".pub"
	}
	sum := sha256.Sum256([]byte(a.account))
	return filepath.Join(a.state, "public", fmt.Sprintf("%x.pub", sum))
}

func (a *app) publicRoot(create bool) (*os.Root, string, error) {

	path := a.publicPath()
	dir := filepath.Dir(path)
	if a.keyfile != "" && create {
		parentPath := filepath.Dir(a.keyfile)
		parentEntry, err := os.Lstat(parentPath)
		if err != nil || parentEntry.Mode()&os.ModeSymlink != 0 {
			return nil, "", errors.New("unsafe public recipient storage")
		}
		privateParent, err := filepath.EvalSymlinks(parentPath)
		if err != nil {
			return nil, "", errors.New("unsafe public recipient storage")
		}
		parentInfo, err := os.Stat(privateParent)
		if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
			return nil, "", errors.New("insecure public recipient storage directory")
		}
		if !os.SameFile(parentEntry, parentInfo) {
			return nil, "", errors.New("unsafe public recipient storage")
		}
	}
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, "", errors.New("cannot prepare public recipient storage")
		}
	}
	entry, err := os.Lstat(dir)
	if err != nil || entry.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("unsafe public recipient storage")
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, "", errors.New("cannot open public recipient storage")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, "", errors.New("insecure public recipient storage directory")
	}
	current, err := user.Current()
	if err != nil {
		return nil, "", errors.New("cannot verify public recipient storage owner")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid, parseErr := strconv.ParseUint(current.Uid, 10, 32)
	if !ok || parseErr != nil || stat.Uid != uint32(uid) {
		return nil, "", errors.New("public recipient storage is not owned by current user")
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, "", errors.New("cannot open public recipient storage")
	}
	return root, filepath.Base(path), nil

}

func (a *app) savePublic(id string) error {
	return a.writePublic(id, true)
}

func (a *app) writePublic(id string, publish bool) error {
	pub, err := crypt.Public(id)
	if err != nil {
		return err
	}
	root, name, err := a.publicRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	if st, err := root.Lstat(name); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
			return errors.New("unsafe public recipient cache")
		}
		current, err := user.Current()
		if err != nil {
			return errors.New("cannot verify public recipient cache owner")
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		uid, parseErr := strconv.ParseUint(current.Uid, 10, 32)
		if !ok || parseErr != nil || stat.Uid != uint32(uid) {
			return errors.New("public recipient cache is not owned by current user")
		}
		f, err := root.Open(name)
		if err != nil {
			return errors.New("cannot read public recipient cache")
		}
		opened, statErr := f.Stat()
		b, readErr := io.ReadAll(io.LimitReader(f, 513))
		_ = f.Close()
		if statErr != nil || !os.SameFile(st, opened) || readErr != nil || strings.TrimSpace(string(b)) != pub {
			return errors.New("cached public recipient differs; remove it explicitly before replacing identity")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect public recipient cache")
	}
	if !publish {
		return nil
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("cannot save public recipient")
	}
	_, writeErr := f.WriteString(pub + "\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("cannot save public recipient")
	}
	return nil
}
func (a *app) public() (string, error) {
	root, name, e := a.publicRoot(false)
	if e != nil {
		return "", errors.New("public recipient not cached; create or import your identity first")
	}
	defer root.Close()
	st, e := root.Lstat(name)
	if e != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 || st.Size() > 512 {
		return "", errors.New("invalid public recipient cache")
	}
	current, e := user.Current()
	if e != nil {
		return "", errors.New("cannot verify public recipient cache owner")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	uid, parseErr := strconv.ParseUint(current.Uid, 10, 32)
	if !ok || parseErr != nil || stat.Uid != uint32(uid) {
		return "", errors.New("public recipient cache is not owned by current user")
	}
	f, e := root.Open(name)
	if e != nil {
		return "", errors.New("cannot read public recipient cache")
	}
	opened, e := f.Stat()
	b, readErr := io.ReadAll(io.LimitReader(f, 513))
	_ = f.Close()
	if e != nil || !os.SameFile(st, opened) || readErr != nil || len(b) > 512 {
		return "", errors.New("cannot read public recipient cache")
	}
	v := strings.TrimSpace(string(b))
	if crypt.ValidateRecipients([]string{v}) != nil {
		return "", errors.New("invalid cached public recipient")
	}
	return v, nil
}

type recipients []string

func (r *recipients) String() string     { return strings.Join(*r, ",") }
func (r *recipients) Set(v string) error { *r = append(*r, v); return nil }
func (a *app) command(args []string) (int, error) {
	if args[0] == "key" {
		return 0, a.key(args[1:])
	}
	if args[0] == "hook" {
		if len(args) != 2 || args[1] != "install" {
			return 2, errors.New("use hook install")
		}
		p, e := project.Open(a.dir, a.state)
		if e != nil {
			return 1, e
		}
		defer p.Close()
		exe, e := os.Executable()
		if e != nil {
			return 1, e
		}
		e = p.InstallHook(exe)
		if e == nil {
			fmt.Fprintln(a.diag, "Installed staged-blob guard; hooks are defense in depth and can be bypassed.")
		}
		return 0, e
	}
	fs := flag.NewFlagSet("command", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("file", ".env", "")
	replace := fs.Bool("replace", false, "")
	yes := fs.Bool("yes", false, "")
	staged := fs.Bool("staged", false, "")
	decrypt := fs.Bool("decrypt", false, "")
	var rec recipients
	fs.Var(&rec, "recipient", "")
	if e := fs.Parse(args[1:]); e != nil {
		return 2, errors.New("invalid command options; use fafnir help")
	}
	if args[0] != "run" && len(fs.Args()) != 0 {
		return 2, errors.New("unexpected positional arguments")
	}
	p, e := project.Open(a.dir, a.state)
	if e != nil {
		return 1, e
	}
	defer p.Close()
	switch args[0] {
	case "init":
		if len(rec) == 0 {
			pub, e := a.public()
			if e != nil {
				return 1, e
			}
			rec = append(rec, pub)
		}
		if e = crypt.ValidateRecipients(rec); e != nil {
			return 1, e
		}
		fmt.Fprintf(a.diag, "Initialize %s -> %s.fafnir\nPublic recipients:\n", safe(*file), safe(*file))
		for _, r := range rec {
			fmt.Fprintln(a.diag, r, "\n  SHA-256:", fingerprint(r))
		}
		if !*yes {
			if e = a.confirm("Have you verified ownership and the fingerprint through a trusted channel? Approve this file scope?"); e != nil {
				return 1, e
			}
		}
		e = p.Init(project.Config{Version: 1, Pairs: []project.Pair{{Plain: *file, Encrypted: *file + ".fafnir", Recipients: rec}}})
	case "trust":
		c, e := p.ReadPolicy()
		if e != nil {
			return 1, e
		}
		a.showPolicy(c)
		if !*yes {
			if e = a.confirm("Trust this exact policy after verifying recipients through a trusted channel?"); e != nil {
				return 1, e
			}
		}
		e = p.Approve(c)
	case "check":
		var id string
		if *decrypt {
			id, e = a.identity()
			if e != nil {
				return 1, e
			}
		}
		messages, ce := p.Check(*staged, id)
		for _, m := range messages {
			fmt.Fprintln(a.diag, safe(m))
		}
		return 0, ce
	case "seal", "open", "run", "grant", "revoke":
		if args[0] == "run" && len(fs.Args()) == 0 {
			return 2, errors.New("run requires -- PROGRAM ARGS")
		}
		var id string
		id, e = a.identity()
		if e != nil {
			return 1, e
		}
		switch args[0] {
		case "seal":
			e = p.Seal(*file, id, *replace)
		case "open":
			e = p.Restore(*file, id, *replace)
		case "run":
			plain, e := p.Decrypt(*file, id)
			if e != nil {
				return 1, e
			}
			values, e := crypt.ParseEnv(plain)
			if e != nil {
				return 1, e
			}
			dir, e := filepath.Abs(a.dir)
			if e != nil {
				return 1, e
			}
			return runner.Run(a.ctx, dir, fs.Args(), values, a.in, a.out, a.diag)
		default:
			if len(rec) != 1 {
				return 2, errors.New("grant/revoke requires one --recipient public key")
			}
			if e = crypt.ValidateRecipients(rec); e != nil {
				return 1, e
			}
			c, e := p.Config()
			if e != nil {
				return 1, e
			}
			var old []string
			for _, pair := range c.Pairs {
				if pair.Plain == *file {
					old = pair.Recipients
				}
			}
			if len(old) == 0 {
				return 1, errors.New("file pair is not configured")
			}
			next := slices.Clone(old)
			if args[0] == "grant" {
				if slices.Contains(old, rec[0]) {
					return 1, errors.New("recipient already authorized")
				}
				next = append(next, rec[0])
			} else {
				if !slices.Contains(old, rec[0]) {
					return 1, errors.New("recipient is not authorized")
				}
				next = slices.DeleteFunc(next, func(s string) bool { return s == rec[0] })
				fmt.Fprintln(a.diag, "Removal cannot revoke historical ciphertext or copied credentials; rotate service credentials when needed.")
			}
			fmt.Fprintf(a.diag, "%s access to %s for public recipient %s\n", args[0], safe(*file), rec[0])
			if !*yes {
				if e = a.confirm("Verified recipient and scope? Apply this access change?"); e != nil {
					return 1, e
				}
			}
			e = p.Grant(*file, id, next)
			if e == nil {
				fmt.Fprintln(a.diag, "Encrypted artifact and policy updated locally. Review and publish through your normal Git workflow; nothing committed or pushed.")
			}
		}
	default:
		return 2, errors.New("unknown command; use fafnir help")
	}
	if e == nil {
		fmt.Fprintln(a.diag, "Completed", args[0])
	}
	return 0, e
}
func (a *app) showPolicy(c project.Config) {
	for _, p := range c.Pairs {
		fmt.Fprintf(a.diag, "%s -> %s\n", safe(p.Plain), safe(p.Encrypted))
		for _, r := range p.Recipients {
			fmt.Fprintln(a.diag, "  Public recipient:", safe(r))
			fmt.Fprintln(a.diag, "  SHA-256:", fingerprint(r))
		}
	}
}
func (a *app) key(args []string) error {
	if len(args) == 0 {
		return errors.New("key requires create, import, public, export or delete")
	}
	fs := flag.NewFlagSet("key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("output", "", "")
	reveal := fs.Bool("reveal", false, "")
	yes := fs.Bool("yes", false, "")
	if fs.Parse(args[1:]) != nil || len(fs.Args()) != 0 {
		return errors.New("invalid key options")
	}
	switch args[0] {
	case "public":
		v, e := a.public()
		if e != nil {
			return e
		}
		fmt.Fprintln(a.diag, "Public recipient — safe to share with your team")
		fmt.Fprintln(a.diag, "SHA-256:", fingerprint(v))
		fmt.Fprintln(a.out, v)
		return nil
	case "create", "import":
		var id string
		var e error
		if args[0] == "create" {
			id, e = crypt.GenerateIdentity()
		} else {
			id, e = a.secret("Paste private decryption key — secret; never send to coworkers")
		}
		if e != nil {
			return e
		}
		if _, e = crypt.Public(id); e != nil {
			return errors.New("invalid private identity")
		}
		if e = a.writePublic(id, false); e != nil {
			return e
		}
		if e = a.store().Set(id); e != nil {
			return e
		}
		if e = a.savePublic(id); e != nil {
			return errors.New("private identity stored but public cache publication failed; retry import to repair cache")
		}
		fmt.Fprintln(a.diag, "Identity stored. Back it up explicitly before relying on it. Share only `fafnir key public`.")
		return nil
	case "export":
		if (*output == "") == (!*reveal) {
			return errors.New("choose exactly one: --output PATH or --reveal")
		}
		if *reveal && (!tty(a.in) || !tty(a.out)) {
			return errors.New("private-key reveal requires an interactive terminal; use --output for a private file")
		}
		fmt.Fprintln(a.diag, "Private decryption key — secret; never send to coworkers. Clipboard history, files and terminal recordings may retain copies.")
		if !*yes {
			if e := a.confirm("Export this private identity for your own backup/device transfer?"); e != nil {
				return e
			}
		}
		id, e := a.identity()
		if e != nil {
			return e
		}
		if *output != "" {
			if e = custody.NewFile(*output).Set(id); e != nil {
				return e
			}
			fmt.Fprintln(a.diag, "Private backup written; move it to protected storage.")
			return nil
		}
		fmt.Fprintln(a.out, id)
		return nil
	case "delete":
		if !*yes {
			if e := a.confirm("Delete the selected private identity? Ensure you have a working backup."); e != nil {
				return e
			}
		}
		if e := a.store().Delete(); e != nil {
			return e
		}
		p := a.publicPath()
		if root, e := os.OpenRoot(filepath.Dir(p)); e == nil {
			_ = root.Remove(filepath.Base(p))
			_ = root.Close()
		}
		fmt.Fprintln(a.diag, "Private identity deleted. Existing copies and ciphertext are not revoked.")
		return nil
	default:
		return errors.New("unknown key operation")
	}
}

func fingerprint(public string) string {
	sum := sha256.Sum256([]byte(public))
	return fmt.Sprintf("%x", sum)
}
