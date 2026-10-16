#!/bin/sh
set -eu

fafnir=${1:?usage: built-cli-workflow.sh PATH-TO-FAFNIR}
fafnir=$(cd "$(dirname "$fafnir")" && pwd)/$(basename "$fafnir")
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
chmod 700 "$root"
out="$root/out"
diag="$root/diag"
repo="$root/repo"
mkdir -m 700 "$repo"
git init -q "$repo"

run() {
	key=$1 state=$2 expected=$3
	shift 3
	if "$fafnir" --dir "$repo" --state-dir "$state" --key-file "$key" "$@" >"$out" 2>"$diag"; then
		status=0
	else
		status=$?
	fi
	if [ "$expected" = success ] && [ "$status" -ne 0 ]; then
		cat "$diag" >&2
		return 1
	fi
	if [ "$expected" = failure ] && [ "$status" -eq 0 ]; then
		printf 'unexpected success: %s\n' "$*" >&2
		return 1
	fi
	cat "$out"
}

alice_key="$root/alice.key"
alice_state="$root/alice-state"
bob_key="$root/bob.key"
bob_state="$root/bob-state"
run "$alice_key" "$alice_state" success key create >/dev/null
alice=$(run "$alice_key" "$alice_state" success key public)
run "$bob_key" "$bob_state" success key create >/dev/null
bob=$(run "$bob_key" "$bob_state" success key public)
[ "$alice" != "$bob" ]
run "$alice_key" "$alice_state" success init --recipient "$alice" --yes >/dev/null
printf "TOKEN='synthetic value'\nEMPTY=\nUNICODE=ravn-æ\n" >"$repo/.env"
chmod 600 "$repo/.env"
run "$alice_key" "$alice_state" success seal >/dev/null
! grep -q 'synthetic value' "$repo/.env.fafnir"
run "$alice_key" "$alice_state" success check --decrypt >/dev/null
run "$bob_key" "$bob_state" success trust --yes >/dev/null
run "$bob_key" "$bob_state" failure run -- /bin/sh -c 'exit 0' >/dev/null
run "$alice_key" "$alice_state" success grant --recipient "$bob" --yes >/dev/null
run "$bob_key" "$bob_state" failure run -- /bin/sh -c 'exit 0' >/dev/null
run "$bob_key" "$bob_state" success trust --yes >/dev/null
[ "$(run "$bob_key" "$bob_state" success run -- /bin/sh -c "printf '%s|%s|%s' \"\$TOKEN\" \"\$EMPTY\" \"\$UNICODE\"")" = 'synthetic value||ravn-æ' ]
rm "$repo/.env"
run "$bob_key" "$bob_state" success open >/dev/null
[ "$(run "$alice_key" "$alice_state" success run -- /bin/sh -c "printf '%s|%s|%s' \"\$TOKEN\" \"\$EMPTY\" \"\$UNICODE\"")" = 'synthetic value||ravn-æ' ]
printf 'TOKEN=local-unsaved\n' >"$repo/.env"
git -C "$repo" add -f .env
run "$alice_key" "$alice_state" failure check --staged >/dev/null
