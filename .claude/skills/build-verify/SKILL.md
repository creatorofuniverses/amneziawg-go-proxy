---
name: build-verify
description: Build the amneziawg-go binary and run the full test suite (including the gofmt TestFormatting gate), then report pass/fail. Use before committing or opening a PR to confirm the change is sound.
---

# build-verify

Verify a change to amneziawg-go builds cleanly and passes tests.

## Steps

1. Build with version generation:
   ```bash
   make
   ```
   `make` regenerates `version.go` and compiles. A bare `go build` skips version generation — prefer `make`.

2. Run the full test suite:
   ```bash
   go test ./...
   ```
   This includes `TestFormatting`, which fails if any file is not `gofmt`-clean. If it fails, run `gofmt -w <files>` and re-run.

3. Report results plainly:
   - Build: ok / failed (with the compiler error).
   - Tests: pass / fail (name the failing test and paste the relevant output).
   - If `TestFormatting` failed, list the files that need formatting and offer to run `gofmt -w` on them.

## Notes

- Do not claim success unless both `make` and `go test ./...` actually succeeded — quote the output.
- The network-namespace integration tests (`./tests/netns.sh`) need root/netns and are not part of this skill; mention them only if the change touches TUN/conn behavior.
