# imitate-vectors

Generates the byte-exact golden vectors in
[`device/testdata/imitate_vectors.txt`](../../device/testdata/imitate_vectors.txt)
that pin the Go traffic-imitation port (`device/obf_imitate.go`) to the
server-side Rust reference, `amneziawg-proxy`'s `transform.rs`.

The Go test `TestImitateGoldenVectors` reads that committed file and asserts the
Go `imitateFillPrefix` reproduces every vector. This crate is what *produces*
the file — so the reference lives in **this** repo and you never need the
upstream proxy repo to regenerate it.

## Regenerate the vectors

Self-contained — needs only `cargo` and the committed `src/reference.rs`:

```sh
./regen.sh          # writes ../../device/testdata/imitate_vectors.txt
cd ../.. && go test ./device/ -run TestImitateGoldenVectors   # must pass
```

`go test` passing after a regen is the proof the vectors and the Go port agree.

## How it binds to the upstream reference

`src/reference.rs` is **vendored** (a committed copy), not a live dependency:

- It contains, copied **verbatim**, the only code needed to reproduce
  `apply_padding`'s output: the PRNG (`fnv1a_seed`, `lcg_step`) and the four
  protocol writers (QUIC / DNS / STUN / SIP), plus `apply_padding` itself.
- Two tiny local stand-ins replace the upstream types `apply_padding` touches
  (`Protocol`, `DnsEcho`). The server-only classification helpers
  (`apply_awg_transform`, `apply_quic_padding_typed`) and the test-only
  `build_padded_packet` are omitted — they don't affect `apply_padding`'s bytes.
- Provenance (source path + pinned commit) is in the header of `src/reference.rs`.

**Refresh against a newer upstream** (only when you want to track upstream
changes — requires a checkout of `wiresock/amneziawg-install`):

```sh
IMITATE_UPSTREAM_REPO=/path/to/amneziawg-install ./vendor.sh
# then bump PINNED_COMMIT in vendor.sh, ./regen.sh, and re-run the Go test
```

`vendor.sh` re-extracts `src/reference.rs` from the pinned upstream commit. If
upstream restructures `transform.rs`, update the line ranges in `vendor.sh`.

## Files

- `src/reference.rs` — vendored, **do not edit by hand** (regenerate via `vendor.sh`).
- `src/main.rs` — the dumper (grid + buffer layout; must mirror the Go golden test).
- `vendor.sh` — re-vendor `reference.rs` from a pinned upstream commit (loose bind).
- `regen.sh` — regenerate the committed golden vectors from the vendored crate.
