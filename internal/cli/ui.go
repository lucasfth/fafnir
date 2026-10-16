package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/google/shlex"
	"github.com/lucasfth/fafnir/internal/project"
	"golang.org/x/term"
)

func nativeTheme(_ bool) *huh.Styles {
	t := huh.ThemeBase(false)
	// ThemeBase supplies layout only; replace help styles which otherwise carry RGB defaults.
	clear := lipgloss.NewStyle()
	t.Help.ShortKey = clear.Bold(true)
	t.Help.ShortDesc = clear
	t.Help.ShortSeparator = clear
	t.Help.FullKey = clear.Bold(true)
	t.Help.FullDesc = clear
	t.Help.FullSeparator = clear
	t.Help.Ellipsis = clear
	t.Focused.Title = clear.Bold(true)
	t.Focused.NoteTitle = clear.Bold(true)
	t.Focused.SelectSelector = clear.SetString("> ").Bold(true)
	t.Focused.FocusedButton = clear.Reverse(true).Padding(0, 2)
	t.Focused.BlurredButton = clear.Padding(0, 2)
	t.Focused.TextInput.Placeholder = clear
	t.Blurred = t.Focused
	t.Blurred.Base = clear.PaddingLeft(1).BorderStyle(lipgloss.HiddenBorder()).BorderLeft(true)
	t.Group.Title = clear.Bold(true)
	return t
}
func (a *app) form(fields ...huh.Field) error {
	if !tty(a.in) || !tty(a.diag) {
		return errors.New("interactive input required; provide explicit command options")
	}
	f := huh.NewForm(huh.NewGroup(fields...)).WithInput(a.in).WithOutput(a.diag).WithTheme(huh.ThemeFunc(nativeTheme)).WithAccessible(a.accessible || os.Getenv("NO_COLOR") != "")
	if e := f.Run(); e != nil {
		return errors.New("cancelled; no approval given")
	}
	return nil
}
func (a *app) confirm(title string) error {
	var yes bool
	if e := a.form(huh.NewConfirm().Title(title).Affirmative("Approve").Negative("Cancel").Value(&yes)); e != nil {
		return e
	}
	if !yes {
		return errors.New("cancelled; no approval given")
	}
	return nil
}
func (a *app) secret(title string) (string, error) {
	if !tty(a.in) || !tty(a.diag) {
		return "", errors.New("private identity paste requires a terminal; use an owner-only key file for automation")
	}
	// ReadPassword disables echo in both normal and accessible modes, unlike a generic accessible text field.
	f := a.in.(*os.File)
	fmt.Fprintln(a.diag, title)
	fmt.Fprint(a.diag, "> ")
	b, e := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(a.diag)
	if e != nil {
		return "", errors.New("private identity input cancelled")
	}
	defer clear(b)
	if len(b) > 4096 {
		return "", errors.New("private identity input exceeds limit")
	}
	return strings.TrimSpace(string(b)), nil
}
func (a *app) text(title, initial string) (string, error) {
	v := initial
	e := a.form(huh.NewInput().Title(title).Value(&v).CharLimit(4096))
	return v, e
}
func (a *app) selectPair() (string, error) {
	p, e := project.Open(a.dir, a.state)
	if e != nil {
		return "", e
	}
	defer p.Close()
	c, e := p.Config()
	if e != nil {
		return "", e
	}
	opts := make([]huh.Option[string], 0, len(c.Pairs))
	for _, pair := range c.Pairs {
		opts = append(opts, huh.NewOption(safe(pair.Plain)+" → "+safe(pair.Encrypted), pair.Plain))
	}
	var v string
	e = a.form(huh.NewSelect[string]().Title("Select file / environment scope").Options(opts...).Value(&v))
	return v, e
}
func (a *app) menu() error {
	fmt.Fprintln(a.diag, "Fafnir · repository secrets")
	fmt.Fprintln(a.diag, "Public recipients are for sharing. Private decryption keys are not.")
	var action string
	e := a.form(huh.NewSelect[string]().Title("What would you like to do?").Options(
		huh.NewOption("Set up this repository", "init"), huh.NewOption("Encrypt local changes", "seal"), huh.NewOption("Restore a plaintext file", "open"), huh.NewOption("Run a program with secrets", "run"), huh.NewOption("Check repository safety", "check"), huh.NewOption("Approve repository policy", "trust"), huh.NewOption("Grant coworker access", "grant"), huh.NewOption("Revoke recipient access", "revoke"), huh.NewOption("Manage identity and recovery", "key"), huh.NewOption("Install staged Git guard", "hook"), huh.NewOption("Exit", "exit")).Value(&action))
	if e != nil {
		return e
	}
	if action == "exit" {
		return nil
	}
	if action == "key" {
		return a.keyMenu()
	}
	if action == "hook" {
		_, e = a.command([]string{"hook", "install"})
		return e
	}
	if action == "init" {
		file, e := a.text("Plaintext file (encrypted copy adds .fafnir)", ".env")
		if e != nil {
			return e
		}
		pub, e := a.public()
		if e != nil {
			return errors.New("create or import your identity using Manage identity first")
		}
		other, e := a.text("Public recipients (comma-separated; verify ownership)", pub)
		if e != nil {
			return e
		}
		args := []string{"init", "--file", file}
		for _, r := range strings.Split(other, ",") {
			args = append(args, "--recipient", strings.TrimSpace(r))
		}
		_, e = a.command(args)
		return e
	}
	if action == "trust" {
		_, e = a.command([]string{"trust"})
		return e
	}
	if action == "check" {
		_, e = a.command([]string{"check", "--decrypt"})
		return e
	}
	file, e := a.selectPair()
	if e != nil {
		return e
	}
	args := []string{action, "--file", file}
	if action == "grant" || action == "revoke" {
		r, e := a.text("Coworker's PUBLIC recipient — never their private key", "")
		if e != nil {
			return e
		}
		args = append(args, "--recipient", r)
	}
	if action == "run" {
		program, e := a.text("Program and arguments (quotes supported; no shell expansion)", "")
		if e != nil {
			return e
		}
		argv, e := parseProgram(program)
		if e != nil {
			return e
		}
		args = append(args, "--")
		args = append(args, argv...)
	}
	_, e = a.command(args)
	return e
}
func (a *app) keyMenu() error {
	var action string
	e := a.form(huh.NewSelect[string]().Title("Identity and recovery").Options(huh.NewOption("Create an identity in native keychain / selected key file", "create"), huh.NewOption("Import private identity from my password manager", "import"), huh.NewOption("Public recipient — safe to share with your team", "public"), huh.NewOption("Private decryption key — secret; backup/export only", "export"), huh.NewOption("Delete selected private identity", "delete")).Value(&action))
	if e != nil {
		return e
	}
	args := []string{action}
	if action == "export" {
		path, e := a.text("Private backup file (owner-only; not in Git)", "")
		if e != nil {
			return e
		}
		if path == "" {
			return errors.New("export destination is required")
		}
		args = append(args, "--output", path)
	}
	return a.key(args)
}

func parseProgram(value string) ([]string, error) {
	args, e := shlex.Split(value)
	if e != nil || len(args) == 0 || args[0] == "" {
		return nil, errors.New("enter a program with balanced argument quotes")
	}
	return args, nil
}
