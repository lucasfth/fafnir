package project

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/lucasfth/fafnir/internal/crypt"
)

const raceRounds = 32

// raceDestination repeatedly replaces path with a regular old value and a link
// outside the project. os.Root must keep every project operation under its root.
func raceDestination(path, outside string, old []byte) (<-chan struct{}, <-chan error) {
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		signaled := false
		defer func() {
			if !signaled {
				close(started)
			}
		}()
		for i := 0; i < raceRounds; i++ {
			link := fmt.Sprintf("%s.race-link-%d", path, i)
			if err := os.Symlink(outside, link); err != nil {
				done <- err
				return
			}
			if err := os.Rename(link, path); err != nil {
				_ = os.Remove(link)
				done <- err
				return
			}
			if i == 0 {
				close(started)
				signaled = true
			}
			runtime.Gosched()
			regular := fmt.Sprintf("%s.race-regular-%d", path, i)
			if err := os.WriteFile(regular, old, 0600); err != nil {
				done <- err
				return
			}
			if err := os.Rename(regular, path); err != nil {
				_ = os.Remove(regular)
				done <- err
				return
			}
			runtime.Gosched()
		}
		done <- nil
	}()
	return started, done
}

func assertOutsideSentinel(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		t.Fatalf("outside sentinel metadata changed: %v, %v", info, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("outside sentinel changed: %q, %v", got, err)
	}
}

func assertEncryptedValue(t *testing.T, data []byte, identity, recipient, want string) {
	t.Helper()
	plain, err := crypt.Decrypt(data, identity, []string{recipient})
	if err != nil {
		t.Fatal(err)
	}
	values, err := crypt.ParseEnv(plain)
	if err != nil || values["TOKEN"] != want {
		t.Fatalf("encrypted value = %q, %v", values["TOKEN"], err)
	}
}

func TestFilesystemRaceDoesNotEscapeProjectRoot(t *testing.T) {
	t.Run("seal destination", func(t *testing.T) {
		f := newFixture(t)
		defer f.p.Close()
		oldPlain := []byte("TOKEN=old\n")
		newPlain := []byte("TOKEN=new\n")
		f.put(t, ".env", string(oldPlain))
		f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
		if err := f.p.Seal(".env", f.identity, false); err != nil {
			t.Fatal(err)
		}
		oldCipher, err := os.ReadFile(filepath.Join(f.root, ".env.fafnir"))
		if err != nil {
			t.Fatal(err)
		}
		f.put(t, ".env", string(newPlain))
		outside := filepath.Join(t.TempDir(), "sentinel")
		outsideData := []byte("outside sentinel must remain unchanged\n")
		if err := os.WriteFile(outside, outsideData, 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(outside, 0640); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(f.root, ".env.fafnir")
		for attempt := 0; attempt < 16; attempt++ {
			started, done := raceDestination(path, outside, oldCipher)
			<-started
			err := f.p.Seal(".env", f.identity, true)
			if raceErr := <-done; raceErr != nil {
				t.Fatal(raceErr)
			}
			info, statErr := os.Lstat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				got, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !bytes.Equal(got, oldCipher) {
					assertEncryptedValue(t, got, f.identity, f.recipient, "new")
				}
			}
			_ = err // A race can be safely rejected after an old/new on-root outcome.
			assertOutsideSentinel(t, outside, outsideData, 0640)
		}
	})

	t.Run("restore destination", func(t *testing.T) {
		f := newFixture(t)
		defer f.p.Close()
		oldPlain := []byte("TOKEN=old\n")
		newPlain := []byte("TOKEN=new\n")
		f.put(t, ".env", string(oldPlain))
		f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
		if err := f.p.Seal(".env", f.identity, false); err != nil {
			t.Fatal(err)
		}
		f.put(t, ".env", string(newPlain))
		if err := f.p.Seal(".env", f.identity, true); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "sentinel")
		outsideData := []byte("outside sentinel must remain unchanged\n")
		if err := os.WriteFile(outside, outsideData, 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(outside, 0640); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(f.root, ".env")
		for attempt := 0; attempt < 16; attempt++ {
			started, done := raceDestination(path, outside, oldPlain)
			<-started
			err := f.p.Restore(".env", f.identity, true)
			if raceErr := <-done; raceErr != nil {
				t.Fatal(raceErr)
			}
			info, statErr := os.Lstat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				got, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				values, parseErr := crypt.ParseEnv(got)
				if parseErr != nil || values["TOKEN"] != "old" && values["TOKEN"] != "new" {
					t.Fatalf("restore outcome outside old/new/error contract (operation error %v): %q, %v", err, got, parseErr)
				}
			}
			assertOutsideSentinel(t, outside, outsideData, 0640)
		}
	})
}
