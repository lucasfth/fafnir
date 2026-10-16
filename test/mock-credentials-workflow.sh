#!/bin/sh
set -eu

fafnir=${1:?usage: mock-credentials-workflow.sh PATH-TO-FAFNIR}
fafnir=$(cd "$(dirname "$fafnir")" && pwd)/$(basename "$fafnir")
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
chmod 700 "$root"
repo="$root/repo"
state="$root/state"
key="$root/owner.key"
argv="$root/argv"
stderr="$root/stderr"
probe="$root/probe"
mkdir -m 700 "$repo"
git init -q "$repo"

run() {
	"$fafnir" --dir "$repo" --state-dir "$state" --key-file "$key" "$@"
}

cat >"$probe" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$@" >"$MOCK_ARGV"
printf '%s|%s|%s|%s|%s|%s\n' "$APP_TOKEN" "${FAFNIR_PRIVATE_KEY-unset}" "${BW_SESSION-unset}" "${SOPS_AGE_KEY_CMD-unset}" "$AWS_SECRET_ACCESS_KEY" "${GIT_CONFIG_COUNT-unset}"
printf 'synthetic-child-stderr\n' >&2
EOF
chmod 700 "$probe"

run key create >/dev/null
recipient=$(run key public)
run init --recipient "$recipient" --yes >/dev/null
cat >"$repo/.env" <<'EOF'
APP_TOKEN=synthetic-cli-token
AWS_SECRET_ACCESS_KEY=synthetic-explicit-app-credential
EOF
chmod 600 "$repo/.env"
run seal >/dev/null
! grep -q 'synthetic-' "$repo/.env.fafnir"

output=$(env FAFNIR_PRIVATE_KEY=synthetic-ambient-fafnir-key BW_SESSION=synthetic-ambient-bw-session SOPS_AGE_KEY_CMD=synthetic-ambient-sops-command AWS_SECRET_ACCESS_KEY=synthetic-ambient-aws-key GIT_CONFIG_COUNT=synthetic-inherited-git-control MOCK_ARGV="$argv" \
	"$fafnir" --dir "$repo" --state-dir "$state" --key-file "$key" run -- "$probe" '$(touch never); literal argument' 2>"$stderr")
[ "$output" = 'synthetic-cli-token|unset|unset|unset|synthetic-explicit-app-credential|synthetic-inherited-git-control' ]
[ "$(cat "$argv")" = '$(touch never); literal argument' ]
[ "$(cat "$stderr")" = 'synthetic-child-stderr' ]
