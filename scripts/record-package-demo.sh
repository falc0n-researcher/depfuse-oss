#!/usr/bin/env bash
# Paced terminal demo for asciinema / agg GIF generation.
set -euo pipefail
cd "$(dirname "$0")/.."

export TERM="${TERM:-xterm-256color}"
export COLUMNS="${COLUMNS:-140}"
export DEPFUSE_OFFLINE=1
export DEPFUSE_SKIP_AUTO_COLLECT=1
export DEPFUSE_INTEL_DB=./testdata/intel.db
export DEPFUSE_COLOR=1
unset DEPFUSE_NO_COLOR

printf '\n\033[1;36m$\033[0m ./bin/depfuse package express@4.17.1 --depth 2\n\n'
sleep 1

# Capture once with colors (non-TTY), then replay line-by-line for smooth GIF frames.
CAP=$(mktemp)
./bin/depfuse package express@4.17.1 --depth 2 >"$CAP" 2>&1

while IFS= read -r line || [[ -n "$line" ]]; do
	printf '%s\n' "$line"
	sleep 0.05
done <"$CAP"

rm -f "$CAP"
sleep 2
