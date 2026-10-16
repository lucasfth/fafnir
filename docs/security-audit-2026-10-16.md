# Security review and remediation — 2026-10-16

This is an AI-assisted source review and local verification record, **not an independent professional security audit, certification or production-readiness approval**. All fixtures contained synthetic identities and values. No commit, push, release or deployment was performed.

## Review coverage and models

| Reviewer | Scope | Outcome |
| --- | --- | --- |
| Three parallel security-reviewer agents | Encryption/parser profile; repository/trust/Git/recovery; identity custody/CLI/runner | Concrete findings below; scoped static re-reviews returned no remaining important findings after corrections. Underlying model identities were not exposed by this agent interface, so these are not claimed as three distinct model families. |
| `neo-proxy/claude-opus-4-8` | Independent tool-free source packet: crypto, project/recovery, custody, runner, CLI, SECURITY.md | Completed static review. No new exploitable finding; noted deliberate fail-closed refusal of CRLF-normalized ciphertext as an interoperability limitation. Does not constitute validation of later edits. |
| `neo-proxy/grok-4.7` | Same independent source packet | Timed out at 240 seconds; no completed review, not counted as passing. |
| `mimer/Qwen3.8-27B-UD-Q6_K_L.gguf` | Same packet | Endpoint returned HTTP 404; review unavailable. |
| `opencode-zen/gemini-3.8-flash` | Same packet | Upstream HTTP 402 insufficient funds; review unavailable. |
| `neo-proxy/deepseek-flash` | Same independent source packet | Timed out at 180 seconds; no completed review, not counted as passing. |
| TypeSafe `jev-latest` | One batched semantic request over explicit pre-remediation source/evidence | HTTP 403. Security, contract and test-evidence Noul probabilities are **unavailable**, not zero and not a pass. |

The tool-free model packet contained only explicitly selected source and security documentation, not credential files or Git history. Failed provider attempts were not retried with alternate credentials. Model output was treated as hypotheses: parent-side execution and source tracing decided corrections.

## Findings and corrections

| Finding | Correction | Verification |
| --- | --- | --- |
| P1: trust prompt could approve a policy different from the displayed snapshot | `Approve(reviewed Config)` compares the reviewed canonical digest with the current policy while locked; CLI passes the displayed config | Stale-review policy test rejects changed policy and accepts only a newly reviewed snapshot |
| P1: Unicode-equivalent tracked paths could bypass plaintext restoration guard | NFC normalization plus case folding for conservative comparisons only | NFD/NFC tracked-alias and case-alias regressions pass |
| P2: aliasing file scopes could carry different recipient sets | Reject filesystem-equivalent path collisions across all plaintext/encrypted roles | Cross-role Unicode/case collision regressions pass |
| P2: shared worktree hook checked the installation worktree | Hook uses committing working directory and validates index selection; each worktree retains independent local approval | Actual temporary `git commit` through installed hook: unapproved worktree refused, approved valid commit accepted, forced plaintext refused, prepared alternate index refused |
| P2: shell startup controls could enable tracing/logging of secrets | Reject `SHELLOPTS`, `BASHOPTS`, `PS4`, `BASH_XTRACEFD` and related startup controls before child creation | Red-before/green-after shell-control tests; built CLI refuses synthetic tracing configuration without leaking its token |
| P2: private keys could be enrolled/exported into Git paths | Refuse file storage beneath detected worktree or conventional bare-repository roots | Indexed-missing and new-unignored destination tests, plus actual CLI export refusal |
| P2: public-recipient cache accepted permissive/symlinked storage | Private owned directories/files, direct-parent/final symlink checks, bounded reads and opened-file identity verification | Insecure directory/file and symlink cache tests; public retrieval still does not require private keychain unlock |
| P2: failed private enrollment could publish an unrecoverable candidate public recipient | Separate nonpublishing cache preflight from publication; store private identity successfully before publishing recipient | Regression observed cache leakage before correction, then passed with original identity intact and no candidate cache |
| Low: zero-padded age metadata indices enabled cardinality/CPU amplification before SOPS parsing | Require canonical decimal index spelling before decoder, retaining strict 0–63 limit and raw-name deduplication | Direct raw-preflight test rejects leading-zero aliases and many aliases before SOPS |

The alias correction initially rewrote stored names to NFC, which changes scope on normalization-sensitive filesystems. Static re-review caught this; filesystem and policy spelling are now preserved verbatim. Only comparisons normalize. The NFD-spelling test configures Git's byte-preserving `core.precomposeUnicode=false` on this macOS host to model Linux behavior. With macOS default precomposition, an unrepresentable effective ignore decision is refused instead of silently approving an unignored file; this is not a claim of universal Unicode-filename support.

Some first versions of the linked-worktree test accidentally used a location-only shim or directly invoked the helper. Those results were not accepted as proof. The final test retains actual `git commit` commands for every important case and the helper runs the project check rather than independently rejecting the index environment.

## Executed local checks

Environment: Go 1.27.2, Darwin arm64, on 2026-10-16. A fresh **plain `go build ./...`** failed with `fatal error: CoreFoundation/CoreFoundation.h: No such file or directory`. Headers exist in Apple Command Line Tools; native checks used explicit per-command toolchain selection:

```sh
SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
CC=/Library/Developer/CommandLineTools/usr/bin/clang \
go test -race -count=1 -v ./...
```

| Check | Result |
| --- | --- |
| `go build ./...` with explicit Apple settings | Passed |
| `go vet ./...` with explicit Apple settings | Passed |
| `go test -race -count=1 -v ./...` with explicit Apple settings | Five test packages passed; command package has no tests. The only general-suite skip is opt-in native keychain. |
| `FAFNIR_TEST_KEYCHAIN=1 go test -race -count=1 ./internal/custody -run TestKeychainRoundTripOptIn -v` with explicit Apple settings | Passed on current code, disposable random account only |
| `go mod verify` | All modules verified |
| `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -show verbose ./...` with explicit Apple settings | Zero reachable and zero imported-package findings; one required-module finding remains, described below |
| Built CLI synthetic smoke | Init, seal, authentication/sync, open, run, unsaved-file preservation, Git private-backup refusal, shell-tracing refusal passed |

Named new regressions include `TestPolicyChangeRequiresExplicitApproval`, `TestNormalizeConfigRejectsUnicodeAndCasePathAliasesAcrossRoles`, `TestCheckDetectsNFDTrackedAliasForNFCPlaintext`, `TestSharedLinkedWorktreeHookUsesCommittingWorktreeAndRejectsIndexOverride`, `TestInitializationPreservesRequestedUnicodeSpelling`, `TestRawMetadataRejectsNoncanonicalIndices`, `TestShellStartupControlsRejectedBeforeExecution`, `TestFileStoreRejectsRepositoryAncestors`, and the public-cache/enrollment tests in `internal/cli/cli_test.go`.

The detailed dependency scan first found non-reachable GO-2026-6443 in gRPC v1.83.1. Updated to v1.83.2 and reran: no imported-package findings remain. Required-module GO-2026-5932 concerns the unmaintained `golang.org/x/crypto/openpgp` package; the scanner reports that Fafnir neither imports nor calls the affected package. `golang.org/x/crypto` is still required for maintained packages used by dependencies. No claim of vulnerability-free dependencies is made. See https://pkg.go.dev/vuln/GO-2026-5932 and https://pkg.go.dev/vuln/GO-2026-6443.

## README and requested logo

README now uses the repository conventions: centered concise title/description, restrained real-technology badges, navigation, overview/documentation table, visible essential commands and a labelled expandable optional-workflow section. Experimental security warning remains prominent; no audit/build/license badge was fabricated.

Historical logo verification: the initial coiled-dragon draft was raster-previewed and checked in an isolated local Chrome README render; it was subsequently rejected and removed. The approved replacements are `docs/assets/fafnir-logo-latte.svg` and `docs/assets/fafnir-logo-mocha.svg`: rounded interlocks with a smooth keyhole and subtle swept-back tip. README uses a `<picture>` dark-media source with the Latte image as fallback. The earlier browser result does not establish GitHub rendering or light/dark switching for these replacement assets.

## Remaining limits

- These model reviews are not an independent human audit. No production-secret approval is implied.
- Linux native keychain/runtime, GitHub CI and package publication were not exercised.
- Default compiler selection on this workstation still fails; explicit Apple-toolchain verification is clearly distinguished.
- Existing quoted dotenv normalization remains, not byte-identical restore. Unsupported syntax is rejected, not evaluated. No new user approval for a byte-identical contract is implied by this audit.
- Comments are individually encrypted/authenticated but deletion/reordering is excluded from SOPS' document MAC; same-policy ciphertext replay/path substitution remains outside the guarantee.
- Directory sync/recovery ordering and synthetic interruption tests are not a power-loss durability experiment.
- Git hooks are bypassable; run is not a sandbox and does not remove all unrelated inherited application credentials.
- Public key caching cannot defend against a compromised same-user account; private custody and trusted recipient verification remain necessary.
