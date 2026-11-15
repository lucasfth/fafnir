<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/fafnir-logo-mocha.svg">
    <img src="docs/assets/fafnir-logo-latte.svg" width="96" alt="Fafnir rounded interlock with a keyhole and an eye">
  </picture>
</p>
<h1 align="center">Fafnir</h1>
<p align="center">A Go CLI for repository secrets, using SOPS and age.</p>

<p align="center">
  <a href="https://go.dev/"><img alt="Go" src="https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white"></a>
  <a href="https://github.com/getsops/sops"><img alt="SOPS" src="https://img.shields.io/badge/SOPS-age-5E5E5E"></a>
  <a href="https://www.apple.com/macos/"><img alt="macOS" src="https://img.shields.io/badge/macOS-4c4f69?logo=apple&amp;logoColor=white"></a>
  <a href="https://www.linux.org/"><img alt="Linux" src="https://img.shields.io/badge/Linux-4c4f69?logo=linux&amp;logoColor=white"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache--2.0-8839ef"></a>
</p>

<p align="center"><a href="#overview">Overview</a> · <a href="#getting-started">Getting started</a> · <a href="#coworker-access">Coworker access</a> · <a href="SECURITY.md">Security</a> · <a href="#development">Development</a></p>

## Overview

Fafnir keeps plaintext `.env` files ignored and their encrypted `.env.fafnir` counterparts in Git. Applications keep their existing dotenv loaders or receive environment variables through `fafnir run`. No application SDK, Node runtime, password-manager integration or custom cryptographic protocol.

Named after the dragon who guards a treasure hoard in Norse legend: Fafnir (**Fafner** in Danish). Here, the treasure is your repository’s secrets.

> [!WARNING]
> **Experimental — not independently audited.**
>
> Use synthetic credentials while evaluating Fafnir. Do not rely on it as your only backup or use it for production secrets yet. Passing tests and AI-assisted reviews are not a security certification.
>
> File formats and commands may change before a stable release. Read [SECURITY.md](SECURITY.md) and the [review findings and limitations](docs/security-audit-2026-10-16.md) before use.

## Documentation

| Document | Purpose |
| --- | --- |
| [Security policy and research](SECURITY.md) | Threat model, primary references, dependency advisories and limitations |
| [Security review and remediation](docs/security-audit-2026-10-16.md) | Model coverage, confirmed findings, corrections and final local checks |
| [Approved design](docs/superpowers/specs/2026-10-16-fafnir-design.md) | Product contract and verification requirements |
| [Implementation plan](docs/superpowers/plans/2026-10-16-fafnir-implementation.md) | Package boundaries and execution contract |
| [Executed verification](docs/verification.md) | Fresh local checks, synthetic smoke results and unverified release/platform limits |


## Getting started

### Install

Fafnir is a beta (`2026.0.0-beta.1`, versioned `YEAR.MINOR.PATCH`). There are no prebuilt binaries: Nix (and Homebrew, once published) build from source. Both builds enable CGO, which macOS keychain support needs.

**Nix** (flakes enabled):

```sh
nix profile install github:lucasfth/fafnir
# or try it without installing:
nix run github:lucasfth/fafnir -- help
```

**Homebrew** is planned (`brew install lucasfth/tap/fafnir`) but not available until the first tag and tap are published; a draft, unverified formula is in [`packaging/homebrew`](packaging/homebrew/fafnir.rb).

The flake pins `nixpkgs-unstable` because Fafnir needs Go 1.27, which is newer than some weekly channels. On Linux, native storage needs a running Secret Service; headless systems can use an explicit protected key file instead.

<details>
<summary>Build from source</summary>

Prerequisites: Git and [Go 1.27+](https://go.dev/doc/install). On macOS, install Apple's Command Line Tools if missing (`xcode-select --install`); native keychain support needs CGO and the Apple SDK.

```sh
git clone https://github.com/lucasfth/fafnir.git
cd fafnir
(
  set -eu
  if [ "$(uname -s)" = Darwin ]; then
    if ! xcrun --find clang >/dev/null 2>&1 || ! xcrun --show-sdk-path >/dev/null 2>&1; then
      echo "Install Apple Command Line Tools with xcode-select --install, then retry." >&2
      exit 1
    fi
    CGO_ENABLED=1 SDKROOT="$(xcrun --show-sdk-path)" CC="$(xcrun --find clang)" make build
  else
    make build
  fi
  mkdir -p "$HOME/.local/bin"
  install -m 755 bin/fafnir "$HOME/.local/bin/fafnir"
) && export PATH="$HOME/.local/bin:$PATH" && fafnir help
```

Keep the `export PATH="$HOME/.local/bin:$PATH"` line in your shell startup file (`~/.zshrc` for zsh or `~/.bashrc` for bash) if that directory is not already on PATH. The export above applies to the current terminal only. You can leave the Fafnir checkout and return to your application repository after installation.

The macOS command explicitly selects Apple's compiler to avoid a Nix compiler on PATH that cannot locate Apple frameworks. It does not substitute a key-file backend. No-CGO macOS builds report native storage unavailable rather than silently storing plaintext elsewhere.

</details>


### Create your identity once

```sh
fafnir key create  # creates and stores your private identity locally
fafnir key public  # prints your age1… public recipient; safe to send to your team
```

Default storage is the macOS Keychain or Linux Secret Service. Reuse the identity across repositories; each file still needs a grant. Never send the private key to a coworker. Keep a protected [recovery copy](#manual-backup-and-recovery). If an identity already exists, skip creation instead of replacing it.

Running `fafnir` in an interactive terminal opens guided actions. It inherits standard terminal colors and supports `--accessible` and `NO_COLOR`; no separate palette configuration.

### Essential commands

```sh
fafnir key create
fafnir key public
fafnir init --file .env
fafnir seal
fafnir check --decrypt
fafnir run -- npm run dev
```

To populate the first file, create or copy an ignored `.env` from your project's example, run `chmod 600 .env`, and **edit it with your editor to replace placeholders with the actual configuration** before sealing. Values must match the intended deployment; Fafnir does not discover or fetch them. `init` uses your cached public recipient unless you pass explicit `--recipient` options, and asks you to confirm the scope.

`seal` writes `.env.fafnir`; `init` creates `.fafnir.json` and ignore rules. Review `git status --short` and the policy/ciphertext changes, then include `.fafnir.json`, `.env.fafnir` and the relevant ignore rules in your normal commit/PR/push workflow. **Fafnir never stages, commits, pushes or merges.** Publishing after sealing is an ordinary Git operation; committing without sealing does not encrypt anything. Never add plaintext or private identities.

`seal` and `open` refuse differing destinations unless `--replace` is explicit.

Restore normalizes quotes/whitespace while preserving supported environment values; synchronization compares parsed values, not byte-identical formatting. The restricted SOPS profile encrypts the quoted representation of every value, including `""` for empty strings. Stock SOPS can decrypt this dotenv profile, but arbitrary stock SOPS documents are not accepted. Comments are encrypted, but deletion or reordering of intact comments is not detected by SOPS' document MAC. No interpolation or command substitution is evaluated. Duplicate/reserved keys, unsupported control/escape syntax and glob/control/trailing-space filenames are refused rather than guessed.

`run` decrypts directly into the launched process environment without intentionally creating `.env`; it passes arguments literally, preserves program exit status, strips decryption credentials and rejects unsafe injected execution-control names. It is not a sandbox: the child and its dependencies can read every secret they receive.

<details>
<summary>Optional key-file, multi-environment, backup and Git workflows</summary>

#### Explicit key file / isolated state

Global options go **before** commands. Create a private directory yourself:

```sh
mkdir -m 700 ~/.config/fafnir-keys
fafnir --key-file ~/.config/fafnir-keys/development.key key create
fafnir --key-file ~/.config/fafnir-keys/development.key init --file .env
fafnir --key-file ~/.config/fafnir-keys/development.key seal
```

Keys require owner-only files and private containing directories. `--state-dir` selects local policy approval storage; it must be outside the repository. Default storage is your user configuration directory under `fafnir`. No private key belongs in Git or command arguments.

#### Multiple environments

```sh
fafnir init --file .env.production --recipient age1PUBLIC_RECIPIENT
fafnir seal --file .env.production
fafnir run --file .env.production -- ./server
```

Replace the example with an actual verified public recipient. Each file pair has its own recipient scope. A development grant does not automatically grant production access. Do not put genuine secrets in public browser configuration or bundles.

#### Manual backup and recovery

Back up your identity to your own password manager before relying on encrypted configuration. Fafnir does not need vault credentials or a password-manager CLI.

1. Export outside every repository:

   ```sh
   fafnir key export --output "$HOME/fafnir-recovery.key"
   ```

2. Save the file or its complete contents in a secure password-manager entry. Verify the saved entry and retain its public recipient (`fafnir key public`) for comparison during recovery.
3. Delete the temporary plaintext export after verification:

   ```sh
   rm "$HOME/fafnir-recovery.key"
   ```

Time Machine and other backups may capture the export; deleting the file does not erase those copies. Use a location appropriate for your backup policy. Never commit or send the private identity to coworkers.

On a replacement machine, install Fafnir and restore instead of creating a new identity:

```sh
fafnir key import  # masked paste from your password manager
fafnir key public  # compare with the original public recipient
```

Pull your previously sealed and published repository configuration, review the policy and run `fafnir trust`. Restoring the same identity restores decryption access to files still encrypted to that recipient; it does not grant access to additional scopes or recover unpublished files.

`key public` reads the public-recipient cache, not the private key; it alone is not proof that private-key storage or recovery works. Verify recovery by decrypting known ciphertext, for example `fafnir check --decrypt` when you have access to every configured scope.

`key import` saves into the selected native keychain or explicit key file. `--paste-key` supplies a masked identity for one invocation without persisting it. As a last resort, `key export --reveal` reveals the private key in the terminal after confirmation; recordings and scrollback may retain it. Clipboard history and sync may retain copied keys. Fafnir never reads, writes or clears the clipboard automatically. Copying an identity to your own device is not rotation. Do not delete an identity until recovery is verified.

#### Git safeguards

Initialization ignores configured plaintext paths and permits their encrypted counterparts. It refuses already-tracked plaintext; adding ignores does not remove old history or rotate exposed credentials.

```sh
fafnir check
fafnir check --staged
fafnir check --staged --decrypt
fafnir hook install
```

Without `--decrypt`, ciphertext checks are structural/policy only, not proof of authentication. With a key, checks authenticate ciphertext and compare semantic local values when a plaintext copy exists. Staged checking reads configured artifacts and policy directly from index object IDs; Git replacements/lazy fetching/transports are disabled. Hooks are opt-in and refuse existing hook files and custom `core.hooksPath` rather than reporting a guard that Git would not run. Hooks are bypassable; use checks in your existing CI policy too. Do not give production decryption identities to untrusted PR jobs. Use `--yes` only when deliberately authorizing explicit noninteractive policy or sensitive operations; no-TTY execution never prompts or auto-approves missing trust.

Interrupted grant/revoke publication is protected by a ciphertext-only journal in local private state. The next operation rolls back an interrupted change; unrelated edits cause a refusal with the journal retained. A recipient change leaves configured filenames unchanged and therefore does not rewrite ignore rules.

</details>

### Native keychain and platform notes

macOS native keychain support requires CGO and the Apple SDK. Linux native storage requires an available Secret Service; headless systems can use an explicit private key file.

## Coworker access

The UI deliberately distinguishes:

- **Public recipient — safe to share with your team.** Coworkers send this to the maintainer.
- **Private decryption key — secret; never send to coworkers.** Keep in native storage or your own protected backup.

1. Coworker creates their own identity and runs `fafnir key public`.
2. Verify the public recipient and owner through a trusted channel.
3. An existing recipient grants exactly the selected scope, following the team's maintainer/PR convention:

   ```sh
   fafnir grant --file .env --recipient age1COWORKER_PUBLIC_RECIPIENT
   ```

4. Review and commit/publish the changed encrypted artifact and `.fafnir.json` through the normal repository workflow.
5. Coworker pulls, reviews recipients and explicitly approves the policy with `fafnir trust`, then uses `fafnir open` or `fafnir run -- …`.

Changing policy alone is insufficient; the encrypted artifact must be updated. Private keys, raw data keys and plaintext `.env` never need to be sent to grant access.

**No separate grant-admin role exists.** Any recipient holding a private identity that decrypts a file can add or remove recipients for that file, or share its plaintext. A "maintainer-only" restriction is a team convention enforced by repository permissions and PR review of the policy **and** ciphertext, not by Fafnir. Development access does not grant access to a separately encrypted production file.

```sh
fafnir revoke --file .env --recipient age1COWORKER_PUBLIC_RECIPIENT
```

Revocation re-encrypts current data but cannot revoke older ciphertext or credentials already copied. Rotate actual service credentials when withdrawing access or responding to compromise.


## Development

```sh
make build
make test
make check
```

CI verifies Linux and macOS with race tests, vet, a build, and platform-specific vulnerability scans. Go module/build caches are reused; tests still execute on every run (`-count=1`). A consistent `-trimpath` setting avoids separate path-sensitive build variants. Markdown and logo-only changes skip this workflow, and newer commits cancel superseded runs on the same branch or pull request. You can run verification manually from GitHub Actions when needed.

Native keychain integration uses only disposable synthetic test identities when explicitly enabled:

```sh
FAFNIR_TEST_KEYCHAIN=1 go test ./internal/custody -run Keychain -v
```

The test deletes only its own randomly named item. Do not use real keys in tests. [Executed verification](docs/verification.md) records the passing local build/vet/fresh race suite, native macOS keychain round-trip, bounded fuzz smoke, built-binary workflows and remaining limits. CI is configured for Linux/macOS but no GitHub run is claimed passing. This workstation needed explicit Apple `SDKROOT`/`CC`; default-compiler builds are not claimed passing.

## License

Copyright 2026 Lucas Frey Torres Hanson.

Fafnir's original code, documentation, and logo assets are licensed under the [Apache License, Version 2.0](LICENSE) (`Apache-2.0`). Distributed on an **AS IS** basis, without warranties or conditions of any kind, subject to the license terms.

Third-party dependencies retain their respective licenses and attribution requirements; this license does not relicense SOPS or any other dependency.
