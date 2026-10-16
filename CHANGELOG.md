# Changelog

## Unreleased

- Introduce Go-only repository secrets tooling with paired ignored plaintext and tracked encrypted files.
- Add explicit individual identities, native keychain/file custody and manual password-manager backup/import.
- Add terminal-native guided forms and scriptable commands for file encryption/restoration, scoped coworker access, trust approval, staged Git checks and child environment execution.
- Document threat boundaries, source papers/standards, dependency advisories and required independent-review gates.
- Bind trust approval to the reviewed policy snapshot; harden Unicode alias checks without rewriting requested filenames and check the committing worktree's index through shared hooks.
- Reject shell tracing controls, private identity files beneath Git repositories, unsafe public cache storage and noncanonical metadata index aliases; publish public recipients only after successful private enrollment.
- Add audit regression coverage, detailed model-review outcomes and gRPC v1.83.2 advisory remediation.
- Apply the standard README presentation and add approved rounded-interlock/keyhole SVG marks in Catppuccin Latte and Mocha, selected by light/dark image media.
- License Fafnir's original work under Apache-2.0, with copyright attribution and a README license badge.
- Update govulncheck to v1.9.0 for Go 1.27 parser compatibility; CI selects the latest Go 1.27 patch and completes both platform jobs independently.
- Reuse consistent trimpath build artifacts in CI, execute uncached race tests, skip Markdown/logo-only changes, and cancel superseded verification runs while retaining both platform vulnerability scans.

No release has been published. Verification results are recorded only after execution.
