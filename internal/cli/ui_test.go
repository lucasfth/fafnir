package cli

import (
	"strings"
	"testing"
)

func TestProgramArgumentsAreLiteral(t *testing.T) {
	got, err := parseProgram(`node "a file.js" '$(touch nope)'`)
	if err != nil || len(got) != 3 || got[1] != "a file.js" || got[2] != "$(touch nope)" {
		t.Fatalf("argv=%q err=%v", got, err)
	}
	if _, err = parseProgram(`node "unterminated`); err == nil {
		t.Fatal("unterminated argument accepted")
	}
}
func TestSanitizesTerminalControlledLabels(t *testing.T) {
	if got := safe("file\x1b[2J\n\u202Ename"); strings.ContainsAny(got, "\x1b\n\u202E") {
		t.Fatal("terminal controls retained")
	}
}
