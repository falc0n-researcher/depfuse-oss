#!/usr/bin/env bash
# Paced terminal demo for asciinema / agg GIF generation.
set -euo pipefail
cd "$(dirname "$0")/.."

printf '\n\033[1;36m$\033[0m ./bin/depfuse package express@4.17.1 --depth 2\n\n'
sleep 1

export DEPFUSE_OFFLINE=1
export DEPFUSE_SKIP_AUTO_COLLECT=1
export DEPFUSE_INTEL_DB=./testdata/intel.db

# Replay output line-by-line so GIF frames capture the scroll.
./bin/depfuse package express@4.17.1 --depth 2 2>&1 | while IFS= read -r line; do
	printf '%s\n' "$line"
	sleep 0.055
done

sleep 2
