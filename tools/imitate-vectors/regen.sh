#!/usr/bin/env bash
#
# Regenerate device/testdata/imitate_vectors.txt from the vendored reference.
# Self-contained: needs only cargo + the committed src/reference.rs (no upstream
# repo). After running, `go test ./device/ -run TestImitateGoldenVectors` must
# still pass — that is the proof the vectors and the Go port agree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$REPO_ROOT/device/testdata/imitate_vectors.txt"

cargo run --quiet --manifest-path "$SCRIPT_DIR/Cargo.toml" -- "$OUT"
echo "Regenerated $OUT"
echo "Appending whole-fill vectors (Go oracle)…"
( cd "$REPO_ROOT" && IMITATE_GEN_WHOLE=1 go test ./device/ -run TestGenWholeVectors -count=1 )
echo "Appended whole-fill vectors to $OUT"
