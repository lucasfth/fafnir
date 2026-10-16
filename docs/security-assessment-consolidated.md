# Security assessment — 2026-10-16

AI-assisted assessment using synthetic credentials, not an independent audit or certification.

## Executed and passed

Offline, nonroot Linux container with read-only source and dropped capabilities:

- `go test -race ./...`
- `go vet ./...`
- CLI build and `--help`.
- `test/built-cli-workflow.sh` and `test/mock-credentials-workflow.sh` against the compiled binary.
- `FuzzParseEnv`: 30 seconds, 15,185 executions.
- `FuzzInspect`: 30 seconds, 55,983 executions.

All steps and the aggregate returned exit 0. Fuzz counts plateaued; these were bounded runs, not exhaustive coverage.

Tests covered ciphertext and metadata tampering, wrong identity/recipient policy, nil plaintext on rejection, semantic dotenv round-trips, controlled filesystem swaps, child credential filtering and literal argument handling. IV/tag mutations alter the first matching token, not every field. The child probe deliberately prints synthetic application credentials to check delivery; it does not establish absence of all leakage.

## Findings and changes

**No new application vulnerability confirmed within this scope.** No reproducible metadata-parser bypass was found. Model allegations about SOPS types, MAC construction, Go `clear` and comment associated data were rejected by source inspection.

Added regression tests and compiled CLI checks, integrated CLI checks into CI, and added bounded scheduled fuzzing. Fixed a test-script invocation failure by using `sh`; earlier failed receipts remain separate. No production cryptographic fix was required.

Strix completed without vulnerability reports but could not build the actual application offline. Its replica tests are not counted as implementation evidence. Actual-source tests separately covered the targeted crypto and CLI gaps.

## Not verified

- Native macOS keychain denial/locked-state and revocation paths.
- Real power-loss recovery or directory-entry durability.
- Current dependency advisory scan results; `go vet` is not `govulncheck`.
- Native release artifacts and provenance/SBOM attestations.
- Exhaustive parsing, TUI/key-export leakage or arbitrary side channels.
- Independent human review or certification.

Encryption does not establish authorship or freshness. Revocation cannot erase historical copies. Programs receiving decrypted secrets can disclose them; `fafnir run` is not a sandbox.

## Evidence identity

Base commit: `d206c4c4ea12b3d2d7b5ea4eb00e7733d15c31ba`, plus assessment changes.

Tested archive SHA-256: `13bd303a9bb92e887e970f9b08c3e5a8a50fe0c2b1227a9c45aae98ca96b97a2`.

Raw archive, command log and exit receipt retained in assessment-host directory `final-gap-20261016-r8`; independently read back. Completed at 21:31:57 Copenhagen time, 2026-10-16. This identifies the earlier tested snapshot, not the subsequently rebased and trimmed PR. GitHub CI must validate the submitted commit separately.
