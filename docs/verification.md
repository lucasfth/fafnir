# Verification — 2026-10-16

This record describes local execution, not GitHub CI, a release, an independent audit or production-secret approval. All identities, dotenv values and repositories exercised were disposable synthetic fixtures.

The later [model-assisted security review and remediation](security-audit-2026-10-16.md) supersedes this initial verification snapshot for audit fixes, current dependency-scan results, fresh regression runs and README/logo rendering evidence. This original record remains historical evidence, not a claim that earlier dependency counts are current.

## Environment

Go 1.27.2, Darwin arm64. Default `CC=cc` resolved to a compiler that could not locate Apple framework headers. Apple Command Line Tools and the required headers were present. All native build/vet/race/keychain checks below therefore used these explicit per-command settings:

```sh
SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
CC=/Library/Developer/CommandLineTools/usr/bin/clang \
go test -race -count=1 -v ./...
```

No global Go configuration or system compiler settings were changed. Default-compiler builds are not claimed passing. The macOS CGO/native-keychain implementation was built, not replaced by a no-CGO fallback.

## Executed checks

| Surface | Observed result |
| --- | --- |
| `go build ./...` | Exit 0 with the Apple toolchain settings above |
| `go vet ./...` | Exit 0 with those settings |
| `go test -race -count=1 -v ./...` | Five packages passed; command package has no tests; opt-in keychain test skipped in this general run |
| `FAFNIR_TEST_KEYCHAIN=1 go test -race -count=1 ./internal/custody -run TestKeychainRoundTripOptIn -v` | Passed; real native keychain set/get/delete using only its own random test account |
| `govulncheck v1.1.4 ./...` | Zero reachable vulnerabilities; reports one non-reachable finding in imported packages and one in required modules |
| `FuzzParseEnv` | Bounded five-second smoke, 19,863 executions, passed; not exhaustive fuzzing |
| `FuzzInspect` | Bounded five-second smoke, 15,048 executions, passed; not exhaustive fuzzing |
| Built CLI | Synthetic identity creation, init, seal, check/decrypt, denied access before grant, grant, trusted-policy refresh, child environment execution, open, differing-local-file refusal/preservation, revoke and denial after removal passed |
| Current profile attacks through built CLI | Empty values observed as ENC tokens; injected raw empty variable and datatype/newline differential refused; staged valid artifacts accepted and forced plaintext staging refused |
| Stock SOPS v3.13.3 | Successfully decrypted a Fafnir artifact with dotenv input/output types; application values including empty string recovered as quoted dotenv literals |
| Sized pseudoterminal | Guided native menu rendered, action labels visible, no application RGB palette escapes observed; cancel probe stopped its own disposable child |
| Masked terminal import | Exact synthetic identity saved at 0600; private bytes absent from captured terminal transcript |

An initial zero-size pseudoterminal did not render the menu and the probe timed out; it was stopped. A subsequent 100×32 sized pseudoterminal rendered correctly. A masked-import probe hit an automation cleanup race after the child had exited; readback confirmed exit 0, exact synthetic key and no echo. No GUI terminal windows were opened.

An early built-binary smoke used ciphertext written before the hardened quoted-value profile; the new profile correctly refused that old experimental fixture. Fresh fixtures on the current profile passed. No compatibility promise exists for pre-release experimental files, and no real secrets were used.

## Named regression evidence from the fresh verbose race run

- `TestRepositoryAndCoworkerWorkflow`
- `TestRecipientsGrantAndRevoke`
- `TestTamperingReturnsNoPlaintext`
- `TestEmptyVariableSetAuthenticated`
- `TestMalformedDatatypesRejectedWithoutPanic`
- `TestCipherDatatypeNewlineDifferential`
- `TestEmptyCommentAndControlBoundary`
- `TestAcceptedPlaintextAlwaysRestorable`
- `TestCaseAliasTrackedPlaintextRefused`
- `TestFailedAdditionalInitPreservesPolicyAndRetries`
- `TestHookRefusesXDGGlobalConfiguration`
- `TestHookRefusesNondefaultHooksPath`
- `TestInterruptedInitializationAllowsOrdinaryRetry/first`
- `TestInterruptedInitializationAllowsOrdinaryRetry/additional`
- `TestRestoreRejectsTrackedPlaintext`
- `TestTrackingErrorsFailClosed`
- `TestIgnoreUnsafePathsAndNestedOverrides`
- `TestStagedChecksIgnoreUnrelatedLargeObjectsAndReplacementRefs`
- `TestGrantPreflightPreservesArtifacts`
- `TestInterruptedAccessChangeRollsBackOnNextOperation/{journal,artifact,policy,approval}`
- `TestGoToolexecRejectedBeforeChild`

The empty-value injection, malformed-datatype newline panic, runner control-variable rejection, tracked restoration, corrupt-index, unsafe-ignore, large-object, grant-preflight and custom-hook findings were observed failing before their respective corrections. Delegated initial package tests were written first but not executed by delegates; this was not a clean red/green cycle for every implemented function.

## Review and limitations

Scoped model reviews covered crypto/custody/runner, CLI/specification and project trust/filesystem/Git/recovery boundaries. Important findings were reproduced and corrected. The final project static review returned no important findings in its assigned scope; this is not independent human audit. Crypto review found no remaining critical/high issue after remediation; its final recoverability edge cases are covered by the accepted-input preflight and regression.

Not established:

- Independent security audit, formal proof or absence of unknown vulnerabilities.
- Linux native keychain runtime or Linux CI success; local checks ran on macOS.
- Light/dark/non-Catppuccin visual acceptance on real user terminals; the PTY checks output structure and palette escapes, not theme appearance.
- Power-loss durability experiments. Directory synchronization ordering was reviewed and process-interruption states exercised; no crashable-filesystem harness was run.
- Published release, signed/provenanced artifacts, SBOM publication or package-manager installation.
- GitHub workflow execution. No implementation commits or pushes were authorized in this session.

Initialization leaves conservative ignore rules if a later step fails or rolls back; the policy/approval authority is recovered, and ordinary initialization can retry. Case-folded tracking checks intentionally refuse case-only collisions even on case-sensitive systems. Comments are individually encrypted/authenticated but their deletion/order is not covered by the SOPS document MAC. Quotes/whitespace normalize; supported semantic values are preserved. See [SECURITY.md](../SECURITY.md).
