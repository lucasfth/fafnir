# Fafnir design

Status: implemented locally and exercised with synthetic secrets; see ../../verification.md for exact evidence and remaining independent-review/release gates.

## Purpose

Fafnir is a Go CLI for encrypted secrets in existing repositories. A user can install one binary, initialize a repository, and use guided menus without learning subcommands. Applications continue reading ordinary environment variables or their existing plaintext dotenv files. Fafnir is not a secret server, a sandbox, or a new cryptographic protocol.

Repository: https://github.com/lucasfth/fafnir. Lucas reported enabling open-source visibility/workflows; the last API read still returned private, so no visibility or workflow execution claim is made here. No production-readiness or independent-audit claim follows from implementation.

## Confirmed requirements

- Go implementation. No JavaScript; no TypeScript is currently necessary.
- Reuse maintained encryption packages and established storage formats. Do not implement ciphers, nonce generation protocols, password KDFs, key wrapping, or a proprietary envelope format.
- Keep plaintext `.env` ignored; track its encrypted counterpart as `.env.fafnir`.
- Support explicit pairs such as `.env.production` and `.env.production.fafnir`.
- Native OS keychain by default, explicit owner-only key files for headless systems, and manual private-identity import/export for storage in any password manager or offline location. No password-manager integration, silent fallback or automatic private-key copying.
- Individual developer identities, separate project/environment access policies, and independently held recovery material. Do not reuse Muninn keys.
- Interactive presentation inherits the terminal's palette, with equally usable explicit commands for automation. No hardcoded Catppuccin palette or application-owned theme is required.
- Security verification precedes real-secret adoption.

## Installation and adoption

Ship native Go binaries with pinned versions and verified release artifacts. Go installation, Homebrew, and CI distribution should invoke the same implementation, not separate wrappers containing business logic. Package-manager publication is a separate authorized release operation.

An existing repository needs a Fafnir installation, explicit encrypted/plaintext pairs, public recipient policy, and authorized identities outside Git. Applications do not need a runtime SDK. Existing package scripts can invoke the binary without adding JavaScript adapters.

Initialization never assumes that adding a package establishes trust. It must show recipient fingerprints and the intended environment, and require deliberate local approval. Local approval is stored outside the checkout; a changed repository cannot approve its own recipient or backend changes.

## Interactive interface

Use Charm's Huh forms and Lip Gloss styling directly in Go, rather than spawning the Gum shell utility. Huh offers selections, inputs, confirmation and accessible prompts; this preserves one executable and avoids secret-bearing shell interpolation.

Running `fafnir` in an interactive terminal opens a compact action menu:

- Set up this repository.
- Encrypt local changes.
- Restore an encrypted file.
- Run a program with secrets.
- Check repository safety and synchronization.
- Manage authorized recipients and recovery.

Show the repository, selected environment, file pair and precise state. Distinguish ciphertext-structure checks, cryptographically verified decryption, synchronization, and Git tracking. Never label ciphertext secure merely because it has an encryption marker.

Display filenames, variable names, counts and recipient fingerprints, not plaintext secret values or private keys during normal operation. Sanitize terminal control characters in repository-controlled labels and errors. Provide a dedicated masked import prompt that accepts the user's paste without echo or persistent input history. Do not access or modify the clipboard automatically. Private-identity export is a separate explicit sensitive operation with a warning and deliberate destination selection; terminal reveal, if selected, may persist in scrollback or recordings. Never include private material in ordinary UI summaries, logs or errors. Hidden input alone does not establish a safe import/export flow; verify it on the real terminal.

Theme behavior:

- Inherit the terminal's default foreground/background and standard ANSI 16-color palette. A terminal configured with Catppuccin supplies its own Latte/Mocha colors; Fafnir does not detect or name the terminal theme.
- Do not hardcode RGB or 256-color values, query the full palette, or ship a Catppuccin palette dependency. Theme changes follow the terminal's own behavior; do not promise automatic switching in every emulator.
- Use restrained borders, bold/underline/reverse emphasis and standard ANSI accent/status colors. Preserve the terminal background and avoid low-contrast faint text for essential content.
- Respect `NO_COLOR`, provide accessible/plain prompts, and never use color alone to convey state.
- Noninteractive execution never starts a menu, asks for missing input, or auto-approves trust. It exits with actionable diagnostics.
- UI and diagnostics use stderr; machine output, where explicitly requested, remains clean on stdout.
- Restore terminal state on cancellation, resize and failure. Exit the UI before launching an interactive child program.

## File lifecycle

Proposed command contract, not implemented commands:

- `fafnir init`: approve explicit pairs and recipients; ensure plaintext paths are ignored. Refuse already-tracked plaintext and explain that untracking cannot repair historical exposure. Do not rewrite Git history or rotate external credentials automatically.
- `fafnir seal`: encrypt the chosen local source to its paired destination. Write ciphertext atomically and preserve the previous destination on failure. Refuse a differing existing destination without an explicit overwrite decision, with cancellation as the interactive default. Validate recipient policy before encryption.
- `fafnir open`: authenticate and decrypt before publishing plaintext. Refuse a differing existing plaintext destination unless the user explicitly chooses replacement. Create plaintext owner-only; reject unsafe destination symlinks and unsafe parent conditions. Do not delete the encrypted source.
- `fafnir run -- <program> <args...>`: decrypt into the child environment without intentionally writing a plaintext dotenv file. Spawn with an argument vector, not a constructed shell string. Preserve child exit status and interactive signals. The tool does not promise that the child or OS never persists memory or environment contents.
- `fafnir check`: inspect staged Git blobs for plaintext and invalid encrypted artifacts, not merely working-tree paths. Verify authentication and local synchronization when the required identities are available. Without keys, report the narrower structural/policy result explicitly.

Configured secrets override inherited variables of the same name; unrelated application environment variables remain available. Remove Fafnir decryption credentials from the launched application's environment; collisions in the secrets file are rejected, not reintroduced. Define the exact credential/control-variable policy before implementation. Do not implicitly layer multiple environments or execute dotenv interpolation, command substitutions or repository hooks. Imported environment-control variables require a documented rejection policy before launch; a secrets file is not permission to change executable lookup, dynamic loading, key providers or tool configuration implicitly.

No background watcher, automatic bidirectional merge, plaintext conflict copy, automatic Git stage/commit/push, or transparent force operation. Failed decryption never launches a child with ciphertext or incomplete secrets.

Plaintext dotenv is application-compatible working state, not protected storage. Editors, backups, local agents and dependencies may read it. `run` reduces deliberate disk exposure but does not protect secrets from code it launches.

## Key custody and authorization

Use individual age identities as the leading developer-key option. The default runtime storage is the native OS keychain; explicit owner-only key files support headless systems. A user may instead paste a private identity into a dedicated masked prompt for the current invocation, or explicitly choose to save it in the native keychain. Never silently persist pasted material or fall back when a keychain is locked or unavailable. Distinguish missing identities, locked storage, authentication failures and backend errors.

Manual portability is the password-manager workflow: explicitly export the private identity, save it yourself in Bitwarden, another password manager or offline storage, then paste/import it on another machine when needed. Fafnir does not need vault credentials, a Bitwarden session, a password-manager CLI, Node.js or a third-party vault SDK. Do not implement password-manager authentication or encryption. The portable private identity is distinct from a password-manager master password, the public recipient and the application credentials encrypted inside `.env.fafnir`. Any separate recovery representation must use the selected engine's established format, not a new Fafnir recovery protocol.

Key custody must support explicit enrollment/storage, retrieval and deliberate removal. Storage selection, key-file paths and keychain item references are locally approved, outside Git; neither encrypted metadata nor repository configuration can choose them. Validate imported identities and show the derived public recipient fingerprint for approval. Switching storage or copying an identity is not rotation and does not revoke old copies. Require explicit confirmation before replacing or deleting private material.

No automatic clipboard reads, writes or timed clearing: clearing cannot reliably erase clipboard-manager history or synced copies and might destroy newer user clipboard contents. Explain those risks before manual private-key transfer. Never place private identities in command arguments or print them except through the explicit sensitive-export flow. Do not export the same private identity to every teammate; authorize their individual public recipients instead.

### Coworker onboarding and key labels

The UI must use distinct labels, not an ambiguous `Share key` action:

- `Public recipient — safe to share with your team`: show/export the public recipient and fingerprint without unlocking or exposing private material. This is the only key-sharing action in ordinary collaboration menus.
- `Private decryption key — secret; never send to coworkers`: available only in the separate sensitive backup/export flow, with an explicit exposure warning.

Each coworker creates their own identity and sends their public recipient to an existing authorized maintainer. Verify the recipient's ownership/fingerprint through a trusted channel before approving it; a display name or repository-supplied label is not proof of ownership. The maintainer selects the exact repository/environment/file scope, approves the recipient locally and uses an authorized identity to rewrap the existing file DEK for that recipient through the selected engine. Updating policy alone does not grant access: the relevant encrypted artifacts must also be updated and published through the repository's normal authorized review/commit/push workflow. Do not automatically commit or push.

After pulling the updated ciphertext, the coworker decrypts using their own private identity to restore the gitignored `.env`, or runs the application with decrypted environment variables. A public recipient alone cannot decrypt. Never instruct the maintainer to send their private identity, recovery material, plaintext `.env` or raw DEK to grant access. Sharing private material is for a user's deliberate backup/device transfer, not normal team onboarding.

Onboarding review shows exactly which files/environments become accessible. Include a real synthetic two-identity scenario: the coworker fails to decrypt before enrollment, succeeds after the selected artifacts are updated, and still fails for an ungranted environment. Removing access must explain historical ciphertext/credential limitations and use the established rotation procedure.

Public policy can live in Git. Private identities, recovery material and trusted local approvals cannot. Do not silently use unrelated SSH keys, cloud credentials, Vault tokens or plugins from the user's ambient environment.

Treat encrypted-file metadata as untrusted before authentication: validate approved recipient identities, permitted backend types and allowed endpoints before attempting key recovery. An implementation must show that backend dispatch cannot bypass this policy.

For CI, prefer workload identity with explicitly authorized KMS where the platform supports it. Do not give production decryption access to untrusted PR jobs or unrelated repositories. Provider support requires provider-specific review; the product is not committed to enabling every SOPS backend.

Removing a recipient requires rotating the file's DEK as appropriate, but cannot revoke old ciphertext or values already obtained. Offboarding and compromise procedures must distinguish DEK rotation, identity replacement and rotation of actual service credentials.

## Cryptographic engine selection gate

The implementation uses pinned SOPS tree/cipher/dotenv APIs and native age X25519 identities. Every semantic value is converted to a canonical quoted dotenv literal before SOPS encryption, making empty strings nonempty authenticated leaves. Stock SOPS dotenv decryption recovers those literals; arbitrary stock SOPS documents are not accepted by Fafnir's restricted profile. Quotes/whitespace normalize on restore without silently changing supported semantic values. This is an established ciphertext format, not a new cryptographic envelope. Comments are individually encrypted/authenticated but their deletion/reordering is not authenticated by SOPS' document MAC.

SOPS' Go dependency graph still includes provider/keyservice packages; the implementation does not claim those are absent. Decryption validates raw metadata and invokes only an explicit injected native age identity, never ambient provider discovery. The selected macOS keychain binding uses native Security.framework via CGO. See SECURITY.md and the verification record for source evidence, dependency fixes and unexercised platform limits.

Use synthetic values to prove supported dotenv semantics, including comments, quoting, multiline values, whitespace, Unicode, empty strings and malformed/duplicate keys. Unsupported constructs must be rejected with non-secret diagnostics rather than silently changing values. If inline SOPS cannot meet the agreed compatibility/security contract, return for a backend/storage trade-off decision; do not invent a replacement encryption scheme.

## Threat boundaries

Protect confidentiality of secrets from readers of Git ciphertext when authorized keys remain protected. Authenticate ciphertext before exposing decrypted contents. Protect local users against malicious metadata, unsafe path writes and unintended credential-provider access.

An attacker able to modify application code can exfiltrate secrets when that code is authorized to run. Fafnir cannot make an untrusted build safe. A compromised user account, authorized malicious child, administrator, debugger, memory dump or stolen authorized identity is outside the confidentiality guarantee.

Encryption alone does not prove author identity or freshness. A repository writer may replay an older valid ciphertext. Trusted revision selection and deployment approvals remain necessary; key-recipient configuration is not an author-signature policy.

## Verification and release gates

Before real-secret use:

1. Review a versioned threat model, backend API evidence, licenses, dependency inventory and current upstream advisories.
2. Validate trust-policy enforcement before key-provider execution, including malicious metadata, unauthorized recipient changes and attempted network credential exfiltration.
3. Keep regression coverage for tampering, truncation, resource limits, malformed metadata, duplicate dotenv keys, symlink/path attacks, interrupted writes and preservation of previous files. Fuzz repository-controlled parsers and policy inputs.
4. Exercise local workflows with synthetic secrets through the actual CLI and pseudoterminal: init, seal, open, cancellation, run, synchronization conflicts, staged-blob checks and recovery on a separate identity context. Verify exit status, signals, quoting, environment precedence, logs and file permissions.
5. Visually inspect terminal-native styling under light and dark Catppuccin terminal profiles and at least one non-Catppuccin profile; exercise accessible/plain mode, no-color, narrow windows, resize and non-TTY behavior. Verify no app-owned RGB palette escapes are emitted. Parser/style tests alone are not visual acceptance.
6. Evaluate plaintext lifecycle in keychain, editor, crash, error and child-process paths. Do not promise Go heap zeroization or guaranteed cleanup after SIGKILL/power loss.
   Include synthetic-identity checks for locked/unavailable keychain, missing or malformed identity, unexpected public recipient, masked paste import, explicit persistence decisions, sensitive export, no decryption-credential forwarding to the launched child, no fallback/cross-provider copies and successful recovery without the original machine. Exercise cancellation without partial persistence; confirm ordinary terminal output contains no private material and no automatic clipboard API is used. Real native keychain enrollment/retrieval requires a live test, not only mocks.
7. Review packaging integrity, pinned dependencies, signed/provenanced releases, checksums, SBOM and security-reporting/update procedures.
8. Obtain independent security review of the exact release before production-secret adoption. Model reviews and test passes supplement, not replace, that review.

Git protection is defense in depth. The tool must refuse plaintext tracked paths even when `git add -f` bypasses ignores. Hooks must inspect staged blobs, compose safely with existing hooks and remain bypassable local assistance, not a complete security boundary. Encryption markers are necessary format hints, never proof of authentication or absence of plaintext. CI enforcement without decryption keys has explicitly narrower guarantees.

## Evidence and unresolved verification

- SOPS documentation describes ENV support, per-file data keys, authenticated per-value encryption, recipient wrapping and process environment injection. These are documented capabilities, not exercised Fafnir behavior.
- SOPS advisory GHSA-hqjv-fvgv-rh27 identifies dotenv/INI metadata memory exhaustion and a 3.13.0 fix.
- GHSA-x4cm-pcq4-39j4 identifies plaintext temporary-file path traversal and a 3.13.0 fix.
- GHSA-pvcx-747w-54qw documents UID/GID handling corrections in 3.13.0 and supplementary-group/environment corrections in 3.13.2.
- GHSA-jgf3-f6rg-8x3h documents ambient Vault-token exfiltration via malicious metadata. Its allowlist mitigation must be explicit; an upgrade alone is not authorization policy.
- USN-8372-1 was resolved via Ubuntu's archived announcement and upstream GHSA-32gq-x56h-299c/GO-2024-3344: plugin-name execution before age 1.2.1. Pinned age 1.3.2 includes the fix; native X25519-only policy rejects plugins.
- Go integration, synthetic CLI flows and native macOS keychain round-trip were exercised. Scoped model reviews are not an independent security audit. See ../../verification.md for exact commands, compiler prerequisites, failures corrected and limits.

## References

- https://github.com/charmbracelet/gum
- https://github.com/charmbracelet/huh
- https://github.com/charmbracelet/lipgloss
- https://getsops.io/_print/docs/
- https://github.com/getsops/sops/security/advisories
- https://github.com/getsops/sops/security/advisories/GHSA-hqjv-fvgv-rh27
- https://github.com/getsops/sops/security/advisories/GHSA-x4cm-pcq4-39j4
- https://github.com/getsops/sops/security/advisories/GHSA-pvcx-747w-54qw
- https://github.com/getsops/sops/security/advisories/GHSA-jgf3-f6rg-8x3h
- https://ubuntu.com/security/notices/USN-8372-1
