// Package crypt restricts the standard SOPS dotenv format to explicit X25519 identities.
package crypt

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/stores/dotenv"
)

const MaxFileSize = 1 << 20
const MaxCiphertextSize = 8 << 20
const maxRecipients = 64

// This explicit SOPS suffix is reserved and rejected as an input variable suffix.
const neverPlain = "_fafnir_never_plaintext"

var keyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var metadataName = regexp.MustCompile(`^sops_age__list_([0-9]+)__map_(recipient|enc)$`)

func safeError() error { return errors.New("invalid or unauthenticated encrypted configuration") }
func GenerateIdentity() (string, error) {
	id, e := age.GenerateX25519Identity()
	if e != nil {
		return "", safeError()
	}
	return id.String(), nil
}
func Public(v string) (string, error) {
	id, e := age.ParseX25519Identity(v)
	if e != nil {
		return "", safeError()
	}
	return id.Recipient().String(), nil
}
func ValidateRecipients(values []string) error {
	if len(values) == 0 || len(values) > maxRecipients {
		return safeError()
	}
	seen := map[string]bool{}
	for _, v := range values {
		r, e := age.ParseX25519Recipient(v)
		if e != nil || r.String() != v || seen[v] {
			return safeError()
		}
		seen[v] = true
	}
	return nil
}

// parseDocument accepts a deliberately defined dotenv subset without evaluating interpolation.
// Output values are semantic strings; quotes and whitespace are normalized on restore.
func parseDocument(plain []byte) (sops.TreeBranch, error) {
	if len(plain) > MaxFileSize || !utf8.Valid(plain) || bytes.IndexByte(plain, 0) >= 0 {
		return nil, safeError()
	}
	lines := strings.Split(strings.ReplaceAll(string(plain), "\r\n", "\n"), "\n")
	seen := map[string]bool{}
	var branch sops.TreeBranch
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			branch = append(branch, sops.TreeItem{Key: sops.Comment{Value: line[1:]}})
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(line[7:])
		}
		name, rhs, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		rhs = strings.TrimSpace(rhs)
		if !ok || !keyName.MatchString(name) || strings.HasPrefix(name, "sops_") || strings.HasSuffix(name, neverPlain) || seen[name] {
			return nil, safeError()
		}
		seen[name] = true
		var value string
		if len(rhs) > 0 && (rhs[0] == '\'' || rhs[0] == '"') {
			q := rhs[0]
			rhs = rhs[1:]
			var b strings.Builder
			closed := false
			for !closed {
				for j := 0; j < len(rhs); j++ {
					c := rhs[j]
					if c == q {
						tail := strings.TrimSpace(rhs[j+1:])
						if tail != "" && !strings.HasPrefix(tail, "#") {
							return nil, safeError()
						}
						closed = true
						break
					}
					if q == '"' && c == '\\' {
						j++
						if j >= len(rhs) {
							return nil, safeError()
						}
						switch rhs[j] {
						case 'n':
							b.WriteByte('\n')
						case 'r':
							b.WriteByte('\r')
						case 't':
							b.WriteByte('\t')
						case '\\', '"':
							b.WriteByte(rhs[j])
						default:
							return nil, safeError()
						}
					} else {
						b.WriteByte(c)
					}
				}
				if !closed {
					i++
					if i >= len(lines) {
						return nil, safeError()
					}
					b.WriteByte('\n')
					rhs = lines[i]
				}
			}
			value = b.String()
		} else {
			if strings.ContainsAny(rhs, "$`") {
				return nil, safeError()
			}
			if p := strings.IndexByte(rhs, '#'); p >= 0 {
				rhs = rhs[:p]
			}
			value = strings.TrimSpace(rhs)
		}
		for _, r := range value {
			if r < 32 && r != '\n' && r != '\r' && r != '\t' || r == 127 {
				return nil, safeError()
			}
		}
		branch = append(branch, sops.TreeItem{Key: name, Value: value})
	}
	return branch, nil
}
func ParseEnv(plain []byte) (map[string]string, error) {
	b, e := parseDocument(plain)
	if e != nil {
		return nil, e
	}
	m := map[string]string{}
	for _, item := range b {
		if k, ok := item.Key.(string); ok {
			m[k] = item.Value.(string)
		}
	}
	return m, nil
}
func emitDocument(branch sops.TreeBranch) ([]byte, error) {
	var b strings.Builder
	for _, item := range branch {
		if c, ok := item.Key.(sops.Comment); ok {
			decoded, e := strconv.Unquote(c.Value)
			if e != nil || strconv.Quote(decoded) != c.Value || strings.ContainsAny(decoded, "\r\n") {
				return nil, safeError()
			}
			b.WriteByte('#')
			b.WriteString(decoded)
			b.WriteByte('\n')
			continue
		}
		k, ok := item.Key.(string)
		if !ok {
			return nil, safeError()
		}
		v, ok := item.Value.(string)
		if !ok || !utf8.ValidString(v) {
			return nil, safeError()
		}
		b.WriteString(k)
		b.WriteByte('=')
		decoded, e := strconv.Unquote(v)
		if e != nil || strconv.Quote(decoded) != v {
			return nil, safeError()
		}
		b.WriteString(v)
		b.WriteByte('\n')
	}
	out := []byte(b.String())
	if _, e := parseDocument(out); e != nil {
		return nil, e
	}
	return out, nil
}
func Encrypt(plain []byte, recipients []string) ([]byte, error) {
	if e := ValidateRecipients(recipients); e != nil {
		return nil, e
	}
	branch, e := parseDocument(plain)
	if e != nil {
		return nil, e
	}
	if len(branch) == 0 {
		return nil, safeError()
	}
	for i := range branch {
		if c, ok := branch[i].Key.(sops.Comment); ok {
			branch[i].Key = sops.Comment{Value: strconv.Quote(c.Value)}
		} else {
			v, ok := branch[i].Value.(string)
			if !ok {
				return nil, safeError()
			}
			branch[i].Value = strconv.Quote(v)
		}
	}
	if _, e = emitDocument(branch); e != nil {
		return nil, e
	}
	group := make(sops.KeyGroup, 0, len(recipients))
	for _, r := range recipients {
		k, e := sopsage.MasterKeyFromRecipient(r)
		if e != nil {
			return nil, safeError()
		}
		group = append(group, k)
	}
	tree := sops.Tree{Branches: sops.TreeBranches{branch}, Metadata: sops.Metadata{KeyGroups: []sops.KeyGroup{group}, UnencryptedSuffix: neverPlain, Version: "3.13.3", LastModified: time.Now().UTC().Truncate(time.Second)}}
	key, errs := tree.GenerateDataKey()
	if len(errs) > 0 {
		return nil, safeError()
	}
	defer clear(key)
	cipher := aes.NewCipher()
	mac, e := tree.Encrypt(key, cipher)
	if e != nil {
		return nil, safeError()
	}
	tree.Metadata.MessageAuthenticationCode, e = cipher.Encrypt(mac, key, tree.Metadata.LastModified.Format(time.RFC3339))
	if e != nil {
		return nil, safeError()
	}
	out, e := (&dotenv.Store{}).EmitEncryptedFile(tree)
	if e != nil || len(out) > MaxCiphertextSize {
		return nil, safeError()
	}
	return out, nil
}

// inspectRaw rejects unknown provider and policy fields before the SOPS metadata decoder.
func inspectRaw(data []byte) error {
	if len(data) == 0 || len(data) > MaxCiphertextSize || !utf8.Valid(data) {
		return safeError()
	}
	seen := map[string]bool{}
	var count int
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			if !encryptedToken(string(line[1:]), "comment") {
				return safeError()
			}
			continue
		}
		k, v, ok := strings.Cut(string(line), "=")
		if !ok || seen[k] {
			return safeError()
		}
		seen[k] = true
		if strings.HasPrefix(k, "sops_") {
			switch k {
			case "sops_mac":
				if !encryptedToken(v, "str") {
					return safeError()
				}
				continue
			case "sops_lastmodified", "sops_unencrypted_suffix", "sops_version":
				continue
			}
			m := metadataName.FindStringSubmatch(k)
			if m == nil {
				return safeError()
			}
			n, e := strconv.Atoi(m[1])
			if e != nil || n < 0 || n >= maxRecipients || strconv.Itoa(n) != m[1] {
				return safeError()
			}
			if m[2] == "recipient" {
				count++
			}
			continue
		}
		if !keyName.MatchString(k) || strings.HasSuffix(k, neverPlain) {
			return safeError()
		}
		if !encryptedToken(v, "str") {
			return safeError()
		}
	}
	if count == 0 || count > maxRecipients {
		return safeError()
	}
	return nil
}
func load(data []byte, recipients []string) (sops.Tree, error) {
	if ValidateRecipients(recipients) != nil || inspectRaw(data) != nil {
		return sops.Tree{}, safeError()
	}
	tree, e := (&dotenv.Store{}).LoadEncryptedFile(data)
	if e != nil {
		return sops.Tree{}, safeError()
	}
	m := tree.Metadata
	if len(m.KeyGroups) != 1 || m.ShamirThreshold != 0 || m.UnencryptedSuffix != neverPlain || m.EncryptedSuffix != "" || m.UnencryptedRegex != "" || m.EncryptedRegex != "" || m.UnencryptedCommentRegex != "" || m.EncryptedCommentRegex != "" || m.MACOnlyEncrypted || m.LastModified.IsZero() || !strings.HasPrefix(m.MessageAuthenticationCode, "ENC[AES256_GCM,") {
		return sops.Tree{}, safeError()
	}
	actual := make([]string, 0, len(m.KeyGroups[0]))
	for _, k := range m.KeyGroups[0] {
		a, ok := k.(*sopsage.MasterKey)
		if !ok {
			return sops.Tree{}, safeError()
		}
		actual = append(actual, a.Recipient)
	}
	sort.Strings(actual)
	expected := slices.Clone(recipients)
	sort.Strings(expected)
	if !slices.Equal(actual, expected) {
		return sops.Tree{}, safeError()
	}
	if len(tree.Branches) != 1 || len(tree.Branches[0]) == 0 {
		return sops.Tree{}, safeError()
	}
	return tree, nil
}
func Inspect(data []byte, recipients []string) error { _, e := load(data, recipients); return e }
func Decrypt(data []byte, identity string, recipients []string) ([]byte, error) {
	tree, e := load(data, recipients)
	if e != nil {
		return nil, e
	}
	id, e := age.ParseX25519Identity(identity)
	if e != nil {
		return nil, safeError()
	}
	var key []byte
	for _, master := range tree.Metadata.KeyGroups[0] {
		mk := master.(*sopsage.MasterKey)
		if mk.Recipient != id.Recipient().String() {
			continue
		}
		sopsage.ParsedIdentities{id}.ApplyToMasterKey(mk)
		key, e = mk.Decrypt()
		if e == nil {
			break
		}
	}
	if len(key) != 32 {
		return nil, safeError()
	}
	defer clear(key)
	cipher := aes.NewCipher()
	stored, e := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, key, tree.Metadata.LastModified.Format(time.RFC3339))
	if e != nil {
		return nil, safeError()
	}
	expected, ok := stored.(string)
	if !ok {
		return nil, safeError()
	}
	// SOPS tolerates invalid encrypted comments; verify those independently first.
	for _, item := range tree.Branches[0] {
		if c, ok := item.Key.(sops.Comment); ok {
			v, e := cipher.Decrypt(c.Value, key, ":")
			if e != nil {
				return nil, safeError()
			}
			if _, ok := v.(sops.Comment); !ok {
				return nil, safeError()
			}
		}
	}
	computed, e := tree.Decrypt(key, cipher)
	if e != nil || subtle.ConstantTimeCompare([]byte(computed), []byte(expected)) != 1 {
		return nil, safeError()
	}
	out, e := emitDocument(tree.Branches[0])
	if e != nil {
		return nil, safeError()
	}
	return out, nil
}
func Rekey(data []byte, identity string, oldRecipients, newRecipients []string) ([]byte, error) {
	plain, e := Decrypt(data, identity, oldRecipients)
	if e != nil {
		return nil, e
	}
	defer clear(plain)
	return Encrypt(plain, newRecipients)
}

// Profile describes the intentionally narrow interoperable SOPS profile.
func Profile() string {
	return fmt.Sprintf("SOPS dotenv, age X25519, maximum %d recipients", maxRecipients)
}

var tokenSyntax = regexp.MustCompile(`^ENC\[AES256_GCM,data:[A-Za-z0-9+/=]*,iv:[A-Za-z0-9+/=]+,tag:[A-Za-z0-9+/=]+,type:(str|comment)\]$`)

func encryptedToken(value, kind string) bool {
	return tokenSyntax.MatchString(value) && strings.HasSuffix(value, ",type:"+kind+"]")
}
