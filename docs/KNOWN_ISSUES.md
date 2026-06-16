# Known Issues

Tracked problems that are understood but deliberately deferred. Each entry records
what the issue is, how it manifests, why it's been left for later, and the options
for fixing it — so a future change can pick it up with full context.

---

## KI-1: Data race on the AWG header/msgType config read path (test-visible, pre-existing)

**Status:** deferred (low priority — does not affect the default test suite or
typical production use).

**Severity:** real data race under `go test -race`; benign in practice today (see
"Why deferred").

### What it is

The Go race detector flags a genuine data race between the receive goroutine and
`IpcSet`:

- **Read (lock-free):** `Device.DeterminePacketTypeAndPadding`
  (`device/receive.go:563`, hot read around `:568`/`:580`), called from
  `RoutineReceiveIncoming` (`device/receive.go:142`). It reads the AWG magic-header
  / message-type configuration without a lock.
- **Write:** `ipcSetDevice.mergeWithDevice` (`device/uapi.go:720`), reached via
  `Device.IpcSetOperation` → `Device.IpcSet`. When `IpcSet` applies `h1`–`h4` (and
  the derived msgType defaults) it writes those same fields.

When configuration arrives *after* the device's receive routines are already
running, the lock-free read races the write.

### How it manifests

- Only under `-race`. The default `go test ./...` (no `-race`) is green.
- Surfaces in the AWG ping integration tests, which call `IpcSet` from
  `genTestPair` (`device/device_test.go`) after the device is up. Three tests
  already carry the workaround comment
  `// Run test with -race=false to avoid the race for setting the default msgTypes 2 times`
  (`device/device_test.go:227`, `:252`, `:278`). The most recent,
  `TestAWGDevicePingImitateIPacket`, inherits the same behavior — it is *not* a new
  race introduced by traffic-imitation Tier 3.

### Why deferred (lower blast radius first)

- It predates the traffic-imitation work and lives in the **core AWG
  header-config path**, not in the imitation code. The Tier 3 `imitateObf` adapter
  is independently race-clean (its only shared state is an `atomic.Uint64` counter,
  verified under `-race`).
- A real fix means editing the lock-free read path in core, which cuts against the
  fork's "keep changes isolated/minimal for clean upstream merges" rule
  (see `CLAUDE.md` → Conventions → Upstream). That deserves its own change, not a
  rider on a feature branch.
- In production, `IpcSet` normally runs at startup before traffic flows, so the
  window is not exercised in the common case.

### Options for a future fix

1. **Atomic-ize the config reads** (preferred for correctness, mirrors existing
   pattern): make the header/msgType fields read atomically on the receive path,
   the same way `deviceImitate.proto` is an `atomic.Uint32` read lock-free on the
   send path (see the design's §8 concurrency note). Lowest contention, no
   per-packet lock.
2. **Tighten the test setup**: have `genTestPair` finish all `IpcSet` configuration
   *before* the device starts receiving, so the test no longer races. This removes
   the test symptom and the `-race=false` comments without touching production
   code — but leaves the underlying lock-free-read/late-write race in place for any
   real caller that reconfigures a live device.

A complete fix likely does **1** (close the actual race) and then drops the
`-race=false` workaround comments and the test-only mitigation.
