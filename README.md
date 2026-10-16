<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/fafnir-logo-mocha.svg">
    <img src="docs/assets/fafnir-logo-latte.svg" width="96" alt="Fafnir rounded interlock with a keyhole">
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

Build from this checkout using Go 1.27 or newer:

```sh
go build -trimpath -o bin/fafnir ./cmd/fafnir
./bin/fafnir help
```

macOS native keychain builds require CGO and the Apple SDK (Command Line Tools). Linux native storage requires an available Secret Service; headless systems can use an explicit private key file. No-CGO macOS builds report native storage unavailable rather than silently storing plaintext elsewhere.

If a Nix compiler on PATH cannot locate Apple framework headers, select the installed Apple toolchain explicitly for each build/check command:

```sh
SDKROOT="$(xcrun --show-sdk-path)" CC="$(xcrun --find clang)" go build -trimpath -o bin/fafnir ./cmd/fafnir
```

This fixes compiler selection; it does not disable CGO or substitute a key-file backend.

Put the binary on your own PATH when ready. Running `fafnir` in an interactive terminal opens guided actions. It inherits standard terminal colors and supports `--accessible` and `NO_COLOR`; no separate palette configuration.

### Essential commands

```sh
fafnir key create
fafnir key public
fafnir init --file .env
fafnir seal
fafnir check --decrypt
fafnir run -- npm run dev
```

Create or edit ignored `.env` with your existing editor, then seal deliberately. `seal` and `open` refuse differing destinations unless `--replace` is explicit. Nothing automatically stages, commits, pushes or merges.

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

You can save your private identity yourself in Bitwarden, another password manager or offline storage. Fafnir does not need vault credentials or a Bitwarden CLI.

```sh
fafnir key export --output /path/to/private-directory/fafnir.key
fafnir key import
```

`key import` accepts a masked paste and saves into the explicitly selected native keychain or key file. `--paste-key` supplies a masked identity for the current invocation without persisting it. `key export --reveal` is an explicit interactive terminal reveal and requires confirmation; recordings and scrollback may retain it. Clipboard history and sync may retain copied private keys. Fafnir never reads, writes or clears the clipboard automatically. Copying an identity to your own device is not rotation. Keep an independent recovery copy before deleting an identity:

```sh
fafnir key delete
```

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
3. An authorized maintainer grants exactly the selected scope:

   ```sh
   fafnir grant --file .env --recipient age1COWORKER_PUBLIC_RECIPIENT
   ```

4. Review and commit/publish the changed encrypted artifact and `.fafnir.json` through the normal repository workflow.
5. Coworker pulls, reviews recipients and explicitly approves the policy with `fafnir trust`, then uses `fafnir open` or `fafnir run -- …`.

Changing policy alone is insufficient; the encrypted artifact must be updated. Private keys, raw data keys and plaintext `.env` never need to be sent to grant access.

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
