#!/usr/bin/env bash
#
# Regenerate src/reference.rs by vendoring the relevant functions from the
# upstream amneziawg-proxy `transform.rs`. This is the "loose bind" to the
# original: day-to-day you never need the upstream repo (the vendored
# src/reference.rs is committed), but running this script refreshes the vendored
# copy against a (newer) upstream checkout.
#
# We vendor ONLY what the vector dumper needs — the PRNG + the four protocol
# writers + apply_padding — and provide local stand-ins for the two upstream
# types apply_padding touches (Protocol, DnsEcho). The server-side
# classification helpers (apply_awg_transform, apply_quic_padding_typed) and the
# test-only build_padded_packet are intentionally omitted; they do not affect
# apply_padding's output.
#
# Faithfulness is proven by regen.sh + the Go test TestImitateGoldenVectors:
# the committed device/testdata/imitate_vectors.txt must reproduce exactly.
set -euo pipefail

# Upstream source. Override the repo location with IMITATE_UPSTREAM_REPO.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_REPO="${IMITATE_UPSTREAM_REPO:-$SCRIPT_DIR/../../../amneziawg-install}"
UPSTREAM_PATH="amneziawg-proxy/src/transform.rs"
PINNED_COMMIT="549bba8ae7548de1cf0264e33e0110462ec18a99"

# Line ranges within the pinned transform.rs (verified against PINNED_COMMIT).
APPLY_PADDING_RANGE="30,41"   # pub fn apply_padding { ... }
WRITERS_RANGE="152,725"       # section header .. end of lcg_step (PRNG + 4 writers)

src_file="$(mktemp)"
trap 'rm -f "$src_file"' EXIT

if ! git -C "$UPSTREAM_REPO" cat-file -e "$PINNED_COMMIT" 2>/dev/null; then
  echo "ERROR: pinned commit $PINNED_COMMIT not found in $UPSTREAM_REPO" >&2
  echo "       set IMITATE_UPSTREAM_REPO to a checkout of wiresock/amneziawg-install" >&2
  exit 1
fi
head_commit="$(git -C "$UPSTREAM_REPO" rev-parse HEAD)"
if [ "$head_commit" != "$PINNED_COMMIT" ]; then
  echo "WARN: upstream HEAD ($head_commit) != pinned ($PINNED_COMMIT)." >&2
  echo "      Extracting from the PINNED commit content regardless." >&2
fi

git -C "$UPSTREAM_REPO" show "$PINNED_COMMIT:$UPSTREAM_PATH" > "$src_file"

out="$SCRIPT_DIR/src/reference.rs"
{
  cat <<HEADER
// VENDORED — DO NOT EDIT BY HAND. Regenerate with ./vendor.sh.
//
// Source:  $UPSTREAM_PATH
// Repo:    wiresock/amneziawg-install (https://github.com/wiresock/amneziawg-install)
// Commit:  $PINNED_COMMIT
//
// Vendored verbatim: apply_padding + the PRNG (fnv1a_seed, lcg_step) + the four
// protocol writers (QUIC/DNS/STUN/SIP). Local stand-ins below replace the two
// upstream types apply_padding references (Protocol, DnsEcho). Omitted from
// upstream (not needed to reproduce apply_padding's bytes): apply_awg_transform,
// apply_quic_padding_typed, build_padded_packet, and the #[cfg(test)] module.
#![allow(dead_code)]

/// Local stand-in for amneziawg-proxy's responder::Protocol.
#[derive(Clone, Copy)]
pub enum Protocol {
    Quic,
    Dns,
    Stun,
    Sip,
}

/// Local stand-in for amneziawg-proxy's responder::DnsEcho. apply_dns_padding's
/// signature references it; the vector dumper only ever passes None.
pub struct DnsEcho {
    pub txid: [u8; 2],
    pub qname: Vec<u8>,
    pub qtype: [u8; 2],
}

HEADER
  sed -n "${APPLY_PADDING_RANGE}p" "$src_file"
  echo
  sed -n "${WRITERS_RANGE}p" "$src_file"
} > "$out"

echo "Wrote $out from $PINNED_COMMIT"
