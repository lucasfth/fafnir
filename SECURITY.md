# Security policy and implementation rationale

Fafnir is new security-sensitive software. It has not received an independent security audit. Use synthetic credentials while evaluating it. Passing tests, model reviews and established dependencies do not establish production readiness.

The [2026-10-16 model-assisted review](docs/security-audit-2026-10-16.md) records scopes, failed provider attempts, confirmed defects and executed corrections. It does not replace an independent audit.

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/lucasfth/fafnir/security/advisories/new). Do not post vulnerabilities, credentials, private keys, or plaintext secrets in public issues. Use synthetic reproductions and redact sensitive material even in private reports.

## Cryptographic boundary

Fafnir reuses SOPS' established dotenv document format, AES-GCM value cipher, authenticated document MAC and age X25519 key wrapping. It does not define an encryption algorithm, password KDF, recovery phrase, key-wrapping protocol or custom ciphertext envelope. `.env.fafnir` is an application filename, not a new cryptographic format.

Each file has an independently generated data key. Each approved age public recipient can unwrap that file's data key using its private identity. Granting a recipient updates the encrypted artifact, not only a policy label. Removing recipients re-encrypts with a new data key; this cannot revoke old ciphertext or actual application credentials already disclosed.

Only explicit native X25519 identities/recipients are accepted. Fafnir does not call generic SOPS key-service dispatch for decryption; encryption constructs only validated native age master keys. SOPS' upstream Go packages still transitively link provider/keyservice code: this is not a minimal-dependency claim. No SSH-key discovery, plugins, cloud providers or Vault endpoints are authorized by ciphertext. Repository policy is pinned locally outside the checkout; editing repository policy does not approve itself. Review new recipient ownership over a trusted channel.

No application value is returned or published before its AEAD and the document MAC authenticate. Fafnir stores canonical quoted dotenv representations as SOPS string leaves, including empty values (`""`), so SOPS' empty-string encryption exception cannot leave variable presence/names unauthenticated. This is a restricted plaintext mapping within the standard SOPS format, not a new cipher/envelope; stock SOPS decryption produces quoted dotenv values. Fafnir requires this profile and does not accept arbitrary stock SOPS files. Quotes/whitespace are normalized on restore; semantic values are preserved, and synchronization compares parsed values, not byte-identical formatting. No interpolation or shell substitution is evaluated; ambiguous unquoted `$`/backticks, unsupported escapes/control characters, duplicate/reserved variable names and unsupported paths are refused.

Comments are encrypted and individually authenticated, but SOPS excludes comments from its document MAC. Removing, duplicating or reordering intact encrypted comments is not detected. Comments must not carry application security semantics. Structural checks without a decryption identity are explicitly weaker and cannot prove authenticity or author identity. AEAD does not stop replay or cross-file substitution of valid same-policy ciphertext; use reviewed revisions and deployment approvals.

## Primary references and concrete consequences

- Phillip Rogaway, *Authenticated-Encryption with Associated-Data* (2002): https://web.cs.ucdavis.edu/~rogaway/papers/ad.pdf . Bind names/context using the established engine's authenticated data rather than adding ad hoc encryption or a second MAC. Fafnir does not claim that the SOPS format binds a file to a Git path/environment; valid same-policy files can be substituted and must be reviewed as such.
- David McGrew, RFC 5116, *An Interface and Algorithms for Authenticated Encryption* (2008): https://www.rfc-editor.org/rfc/rfc5116 . Authenticated decryption must not expose partial output on failure. Tests must cover tampering, truncation and authenticated-data changes, not only round trips.
- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: GCM and GMAC* (2007): https://csrc.nist.gov/pubs/sp/800/38/d/final . Nonce/key requirements belong to the selected maintained implementation. Fafnir does not implement GCM or generate cipher nonces itself.
- Saltzer and Schroeder, *The Protection of Information in Computer Systems* (1975), basic principles: https://web.mit.edu/saltzer/www/publications/protection/Basic.html . Use fail-safe defaults, economy of mechanism, least privilege and complete mediation: no silent storage fallback, no arbitrary key-provider dispatch, explicit recipient approvals, minimal subprocess surface.
- C2SP age specification: https://c2sp.org/age . Use age's native APIs and key syntax; do not write an alternate age decoder or crypto implementation.
- SOPS documentation: https://getsops.io/_print/docs/ . Use native tree/cipher/store operations and authenticate its MAC before emit. Do not trust encryption markers alone.
- Go traversal-resistant APIs: https://go.dev/blog/osroot . Root filesystem operations and separately reject symlinks/unsafe permissions; root containment alone is not a no-symlink or atomic no-replace guarantee.

These references guide implementation; none constitutes an audit of Fafnir.

## Dependency advisory review

Pinned integration candidates were resolved from the Go module proxy: SOPS v3.13.3 and age v1.3.2. The exact resolved graph is in go.mod/go.sum. Re-run vulnerability analysis when changing dependencies; a version above these fixes is not a guarantee against every vulnerability.

| Advisory | Affected surface and decision |
| --- | --- |
| https://github.com/getsops/sops/security/advisories/GHSA-hqjv-fvgv-rh27 | Dotenv/INI metadata unflattening could exhaust memory before 3.13.0. Pin newer SOPS, bound inputs/recipient counts and fuzz malformed metadata. |
| https://github.com/getsops/sops/security/advisories/GHSA-x4cm-pcq4-39j4 | `exec-file --filename` path traversal before 3.13.0 could leave plaintext. Fafnir does not call SOPS exec-file; rooted atomic publication is reviewed separately. |
| https://github.com/getsops/sops/security/advisories/GHSA-pvcx-747w-54qw | Privilege switching corrections in 3.13.0 and 3.13.2. Fafnir does not offer privilege switching and does not invoke SOPS exec-env. |
| https://github.com/getsops/sops/security/advisories/GHSA-jgf3-f6rg-8x3h | Untrusted Vault addresses can receive ambient tokens. Do not use generic backend dispatch at all; accept explicit age-only metadata before recovery. |
| https://github.com/FiloSottile/age/security/advisories/GHSA-32gq-x56h-299c | CVE-2024-56327 / GO-2024-3344: plugin-name validation, fixed upstream 1.2.1. Applies to plugin-capable Go APIs as well as CLI, not a break of X25519. Pin age 1.3.2 and reject plugins. |

The previously inaccessible Ubuntu notice USN-8372-1 was resolved through https://lists.ubuntu.com/archives/ubuntu-security-announce/2026-June/010684.html . Ubuntu backported the age fix to 1.1.1-1ubuntu0.24.04.3+esm1 for Ubuntu Pro; that distro version is not an upstream minimum. Upstream reference: https://pkg.go.dev/vuln/GO-2024-3344 .

## Key custody and manual transfer

Native OS keychain is the default. Explicit owner-only key files support headless systems. Never silently copy private material to a fallback. Public-recipient caching allows sharing without unlocking the private identity. Manual import/export supports saving an identity in Bitwarden or any other password manager without a vault adapter or Node runtime.

Private-file enrollment/export refuses paths beneath detected Git worktrees and conventional bare repositories, even when ignored. Public-recipient cache directories/files must be private and owned by the current user; direct symlink cache paths are rejected. Enrollment performs nonpublishing cache preflight, stores the private identity, and only then publishes its public recipient. A failed private-store operation must not advertise an unsaved identity.

Private identity input is a masked terminal operation, not a command argument. Normal UI/logs must not contain private keys, plaintext dotenv values or raw backend diagnostics. Private export is deliberately sensitive and requires explicit destination/consent. Terminal reveal can persist in scrollback/recordings. Manual clipboard transfer can persist in history or synced devices; Fafnir does not access or clear the clipboard. Copying an identity is not rotation.

macOS uses the native Security.framework binding from Keybase instead of the `security` command, avoiding secret-bearing command text. CGO/native SDK is needed for macOS native keychain builds; no-CGO builds fail explicitly rather than degrading storage. Other supported native stores require their platform services. Actual native keychain behavior requires opt-in live smoke verification with disposable identities.

## Local execution limits

The child program receives the selected application secrets, not Fafnir decryption credentials. Arguments are passed as an argv vector, not a constructed shell command. Dangerous environment control names are rejected, and key-provider credentials are stripped before launching. This is defense in depth, not a sandbox: an authorized application/dependency can read and exfiltrate all secrets it receives. Don't decrypt production credentials for untrusted PR code.

Shell tracing/startup controls, including `SHELLOPTS`, `BASHOPTS`, `PS4` and `BASH_XTRACEFD`, are rejected before child creation. Unrelated inherited application credentials are not comprehensively scrubbed: `run` is not an isolated environment.

Plaintext `.env` is a normal readable local file. File permissions do not protect it from the same account, root, editors, agents, backup tools, memory capture or malware. Go does not guarantee heap zeroization; crashes and OS paging/core dumps may retain data. File cleanup cannot be promised after SIGKILL or power loss.

Git ignores and hooks are bypassable. Staged checks must read index blobs, not assume the working tree is what will be committed. Hooks cannot repair previously published plaintext history. Rotate exposed application credentials; do not assume encryption of a later version repairs exposure.

Git reads disable replacement-object resolution, lazy fetching and transports, bound subprocess output, and read only configured artifacts/policy bodies. Initialization checks actual Git ignore decisions; glob/control/trailing-space paths are rejected. Custom `core.hooksPath` is explicitly unsupported and hook installation refuses it. Restoring into a tracked plaintext path is refused. Access changes preserve an external ciphertext-only recovery journal before publishing: interrupted operations roll back on the next project operation, retaining the journal and refusing unrelated-edit conflicts. Grant/revoke does not change configured file paths and does not rewrite ignore rules; it preflights the existing ignore file. Initialization can fail after writing public policy/ignore state; review and explicitly approve/retry rather than assuming a failed initialization completed.

Trust confirmation pins the exact reviewed policy snapshot, not whatever policy is reread after the prompt. Filesystem-alias comparisons conservatively combine NFC normalization and case folding across plaintext, ciphertext and tracked paths; original requested path spellings are preserved for I/O and ignores. Linked-worktree hooks check the committing directory and reject a mismatched index override; each worktree requires its own approval. Git's effective ignore decision is still authoritative: unsupported normalization/configuration cases fail closed.

The final 2026-10-16 govulncheck v1.1.4 verbose scan reports zero reachable and zero imported-package findings after updating gRPC to v1.83.2. One required-module finding, GO-2026-5932 (`golang.org/x/crypto/openpgp`), remains outside Fafnir's imported/called packages. See the audit record for command environment and limits.

## Required release checks

Unit/integration tests, race detector, parser fuzz smoke, real synthetic CLI workflows, terminal review, native keychain smoke, dependency vulnerability analysis and independent security/specification review. Establish release signing/provenance, checksums, SBOM and a private security-reporting/update procedure before publishing packages. No release/deployment is implicit in local implementation.
