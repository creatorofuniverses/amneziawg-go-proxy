# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Go implementation of AmneziaWG — a WireGuard variant with DPI-evasion obfuscation. Forked from WireGuard-Go; this `-proxy` fork adds the `outline/` dialer + fallback glue. Module: `github.com/amnezia-vpn/amneziawg-go`, Go 1.24.4, no CGO.

## Build / test

- `make` — **always regenerates `version.go`** from `git describe`, then builds. Use it instead of a bare `go build` so the version is correct. `make` marks `version.go` as `--assume-unchanged` afterward.
- `go test ./...` — runs all tests. This includes `TestFormatting`, which fails the build if any file isn't `gofmt`-clean. Run `gofmt -w` (or rely on the format hook) before committing.
- `./tests/netns.sh <path-to-built-binary>` — network-namespace integration tests (Linux, needs root/netns).
- Run a single test: `go test ./device -run TestName`.

## Code layout

Platform-specific files use build tags, not just filename suffixes (e.g. `//go:build linux || darwin || freebsd || openbsd`). When editing platform code, check the build tag — the matching Windows/BSD/wasm variant usually needs the parallel change. Core logic lives in `device/`; sockets in `conn/`; TUN abstraction in `tun/`; UAPI control socket in `ipc/`.

## Conventions

- **Commits:** conventional-commit prefixes (`feat:`, `fix:`, `chore:`, `refactor:`). Keep the SPDX `// SPDX-License-Identifier: MIT` header on new source files.
- **PRs:** branch off `master`, open a PR, squash-merge with a conventional-commit title.
- **Upstream:** keep changes isolated and minimal where practical so upstream `amneziawg-go` merges stay clean — concentrate fork-specific logic in `outline/` rather than scattering edits through core files.

## Runtime gotchas

- Env vars: `LOG_LEVEL` (verbose/debug|error|silent, default error), `WG_TUN_FD` / `WG_UAPI_FD` (pre-opened fds for daemonization), `WG_TUN_NAME_FILE` (macOS), `WG_PROCESS_FOREGROUND` (internal).
- Junk/signature packet sizes must stay under the system MTU or packets fragment.
- Traffic imitation: the UAPI key `imitate_protocol=none|quic|dns|stun|sip` (default `none`) shapes outgoing padding/junk to resemble a real protocol. It is sender-only, length-invariant, and cosmetic (a vanilla peer interops unchanged). The byte-exact port of the `amneziawg-proxy` `transform.rs` fill lives in `device/obf_imitate.go`; `fillPadding` shapes S-padding, `fillJunk` shapes `Jc` junk. Built incrementally in tiers (1 = S-padding, 2 = junk; see `docs/superpowers/plans/`). Byte-exactness is locked by `device/testdata/imitate_vectors.txt` + `TestImitateGoldenVectors` — regenerate vectors via `tools/imitate-vectors/regen.sh` if the fill changes.
- Interface naming differs per platform: macOS wants `utun[0-9]+` (or `utun` to auto-select), Windows wants numeric names.
