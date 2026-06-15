// VENDORED — DO NOT EDIT BY HAND. Regenerate with ./vendor.sh.
//
// Source:  amneziawg-proxy/src/transform.rs
// Repo:    wiresock/amneziawg-install (https://github.com/wiresock/amneziawg-install)
// Commit:  549bba8ae7548de1cf0264e33e0110462ec18a99
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

pub fn apply_padding(data: &mut [u8], pad_size: usize, proto: Protocol) {
    if pad_size == 0 || pad_size >= data.len() {
        return;
    }

    match proto {
        Protocol::Quic => apply_quic_padding_short(data, pad_size),
        Protocol::Dns => apply_dns_padding(data, pad_size, None),
        Protocol::Stun => apply_stun_padding(data, pad_size),
        Protocol::Sip => apply_sip_padding(data, pad_size),
    }
}

// ---------------------------------------------------------------------------
// Protocol-specific padding implementations
// ---------------------------------------------------------------------------

/// QUIC short-header 1-RTT padding (all AWG phases — see `apply_quic_padding_typed`).
///
/// Emits a QUIC 1-RTT short-header byte (RFC 9000 §17.3.1) followed by
/// pseudo-random bytes simulating an encrypted QUIC 1-RTT payload:
///   - byte 0: `0x40 | (spin<<5) | (reserved=00) | (key_phase<<2) | pn_len`
///     — form=0, fixed=1, random spin bit, random key-phase bit, random PN len.
///   - bytes 1+: pseudo-random (simulating DCID + encrypted payload).
///
/// Note: the short header has no version field or length field — the
/// remaining bytes after byte 0 are indistinguishable from random data,
/// which is the correct appearance for 1-RTT QUIC ciphertext.
fn apply_quic_padding_short(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    let mut state = fnv1a_seed(payload);

    // Short header first byte: 0 1 S R R K P P
    //   form=0, fixed=1, spin=random, reserved=00, key_phase=random, pn_len=random
    let spin = ((state >> 8) as u8) & 0x01;
    state = lcg_step(state);
    let key_phase = ((state >> 8) as u8) & 0x01;
    state = lcg_step(state);
    let pn_len_bits = (state as u8) & 0x03;
    state = lcg_step(state);

    padding[0] = 0x40 | (spin << 5) | (key_phase << 2) | pn_len_bits;

    for byte in padding[1..].iter_mut() {
        *byte = (state >> 16) as u8;
        state = lcg_step(state);
    }
}

/// FNV-1a seed from first 64 bytes of payload for PRNG initialisation.
fn fnv1a_seed(payload: &[u8]) -> u32 {
    let mut state: u32 = 0x811c_9dc5;
    for &b in payload.iter().take(64) {
        state ^= b as u32;
        state = state.wrapping_mul(0x0100_0193);
    }
    state
}

/// DNS message header length (RFC 1035 §4.1.1).
const DNS_HEADER_LEN: usize = 12;
/// Root-label question length: QNAME `0x00` + QTYPE(2) + QCLASS(2).
const DNS_ROOT_QUESTION_LEN: usize = 5;
/// EDNS0 OPT RR fixed prefix: root NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
const DNS_OPT_FIXED_LEN: usize = 11;
/// EDNS0 option header: OPTION-CODE(2) + OPTION-LENGTH(2).
const DNS_OPT_OPTION_HDR_LEN: usize = 4;
/// Smallest pad prefix that fits the full OPT framing with a root-label question.
const DNS_OPT_MIN: usize =
    DNS_HEADER_LEN + DNS_ROOT_QUESTION_LEN + DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN; // 32
/// EDNS0 OPT advertised UDP payload size (modern resolver default, RFC 6891).
const DNS_OPT_UDP_SIZE: u16 = 1232;
/// EDNS0 option code for the opaque cover payload. 65001 (0xFDE9) is in the
/// IANA "local/experimental" range (RFC 6891 §6.1.2): resolvers must ignore
/// unknown options regardless of length, so this carries the ciphertext without
/// the zero-content expectation that option code 12 (Padding, RFC 7830) implies.
const DNS_OPT_COVER_CODE: u16 = 0xFDE9;

/// DNS-style padding: a realistic EDNS *response* whose Additional-section
/// `OPT (41)` record (RFC 6891) accounts for every byte of the UDP datagram
/// after the fixed prefix. The encrypted AWG payload becomes the opaque
/// option-data of a single unknown EDNS option, so the whole datagram parses as
/// one well-formed DNS message with no trailing bytes — while looking like the
/// ordinary EDNS traffic that dominates the modern internet, rather than the
/// `TYPE NULL` answer used previously (which is essentially never seen in the
/// wild and is a strong fingerprint).
///
/// Layout (root-label question; `question_len` grows when a real QNAME is echoed):
///
/// ```text
/// Bytes 0..pad_size (rewritten):
///   [ Header 12 B ][ Question 5 B ][ OPT fixed 11 B ][ option hdr 4 B ][ zero-fill ]
/// Bytes pad_size..total (intact):
///   [ encrypted AWG payload ]
///   ^--- zero-fill + payload are the OPT option-data (OPTION-LENGTH covers them);
///        the OPT RDLENGTH covers the option header + option-data, so every byte
///        is inside the OPT RR and nothing is left dangling.
/// ```
///
/// - **Header** (12 B): TXID from payload bytes 0-1; flags `0x8180`
///   (QR=1, RD=1, RA=1, NOERROR) — RD is echoed so the response matches the
///   client's `RD=1` queries. `QDCOUNT=1`, `ANCOUNT=0`, `ARCOUNT=1`.
/// - **Question** (5 B): root-label QNAME + `QTYPE A` + `QCLASS IN`.
/// - **OPT RR** (11 B fixed + 4 B option header): root NAME, `TYPE OPT (41)`,
///   CLASS = advertised UDP size 1232, TTL field 0 (ext-rcode/version/flags),
///   `RDLENGTH = total_len - (12 + question_len + 11)`, then one option
///   `{code = 0xFDE9 (unknown), length = total_len - (12 + question_len + 15)}`.
///
/// For `pad_size < DNS_OPT_MIN` the OPT framing does not fit; the function falls
/// back to [`apply_dns_padding_null`], which keeps the previous `TYPE NULL`
/// behaviour for those rare small pads (response S-values are normally far
/// larger). Returns immediately when `pad_size == 0`.
fn apply_dns_padding(data: &mut [u8], pad_size: usize, echo: Option<&DnsEcho>) {
    if pad_size == 0 {
        return;
    }
    if pad_size < DNS_OPT_MIN {
        apply_dns_padding_null(data, pad_size);
        return;
    }

    let total_len = data.len();
    let (padding, payload) = data.split_at_mut(pad_size);

    // Build the question section. When the client's most recent query fits the
    // pad prefix, echo its QNAME/QTYPE and reuse its transaction ID so the
    // response mirrors the request (RFC 1035 §4.1.1). Otherwise fall back to a
    // root-label question with a payload-derived ID.
    let mut qbuf = [0u8; 259]; // max QNAME 255 (incl. root) + QTYPE 2 + QCLASS 2
    let (question, txid): (&[u8], [u8; 2]) = match echo {
        Some(e)
            if e.qname.len() + 4 <= qbuf.len()
                && DNS_HEADER_LEN + e.qname.len() + 4 + DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN
                    <= pad_size =>
        {
            let qn = e.qname.len();
            qbuf[..qn].copy_from_slice(&e.qname);
            qbuf[qn..qn + 2].copy_from_slice(&e.qtype);
            qbuf[qn + 2..qn + 4].copy_from_slice(&[0x00, 0x01]); // QCLASS IN
            (&qbuf[..qn + 4], e.txid)
        }
        _ => {
            qbuf[..5].copy_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // root QNAME + A + IN
            let txid = [
                payload.first().copied().unwrap_or(0),
                payload.get(1).copied().unwrap_or(0),
            ];
            (&qbuf[..5], txid)
        }
    };

    write_dns_opt_response(padding, total_len, txid, question);
}

/// Write an EDNS OPT-framed DNS response header into `padding` (the `pad_size`
/// prefix), with `question` already encoded (QNAME wire bytes + QTYPE + QCLASS).
///
/// Caller guarantees `padding.len() >= DNS_HEADER_LEN + question.len()
/// + DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN`, so every field below is in
/// range. The OPT option-data spans the rest of the datagram (the zero-filled
/// tail of `padding` plus the untouched payload after it).
fn write_dns_opt_response(padding: &mut [u8], total_len: usize, txid: [u8; 2], question: &[u8]) {
    let opt_off = DNS_HEADER_LEN + question.len();
    // RDLENGTH covers the option header + option-data = everything after the
    // RDLENGTH field. OPTION-LENGTH covers just the option-data.
    let rdlength = total_len
        .saturating_sub(opt_off + DNS_OPT_FIXED_LEN)
        .min(u16::MAX as usize) as u16;
    let opt_len = total_len
        .saturating_sub(opt_off + DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN)
        .min(u16::MAX as usize) as u16;

    // Header (12 B).
    padding[0] = txid[0];
    padding[1] = txid[1];
    padding[2] = 0x81; // QR=1, opcode=0, AA=0, TC=0, RD=1
    padding[3] = 0x80; // RA=1, Z=0, RCODE=NOERROR
    padding[4] = 0x00;
    padding[5] = 0x01; // QDCOUNT = 1
    padding[6] = 0x00;
    padding[7] = 0x00; // ANCOUNT = 0 (NODATA)
    padding[8] = 0x00;
    padding[9] = 0x00; // NSCOUNT = 0
    padding[10] = 0x00;
    padding[11] = 0x01; // ARCOUNT = 1 (the OPT RR)

    // Question.
    padding[DNS_HEADER_LEN..opt_off].copy_from_slice(question);

    // OPT RR fixed prefix (11 B) + option header (4 B).
    let [rl_hi, rl_lo] = rdlength.to_be_bytes();
    let [oc_hi, oc_lo] = DNS_OPT_COVER_CODE.to_be_bytes();
    let [ol_hi, ol_lo] = opt_len.to_be_bytes();
    let [us_hi, us_lo] = DNS_OPT_UDP_SIZE.to_be_bytes();
    #[rustfmt::skip]
    let opt: [u8; DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN] = [
        0x00,           // NAME: root label (OPT must use the root name)
        0x00, 0x29,     // TYPE  = OPT (41)
        us_hi, us_lo,   // CLASS = requestor's UDP payload size (1232)
        0x00, 0x00, 0x00, 0x00, // TTL: ext-RCODE 0, EDNS version 0, flags 0 (DO=0)
        rl_hi, rl_lo,   // RDLENGTH = option header + option-data
        oc_hi, oc_lo,   // OPTION-CODE = 0xFDE9 (unknown / local-use)
        ol_hi, ol_lo,   // OPTION-LENGTH = option-data bytes (zero-fill tail + payload)
    ];
    padding[opt_off..opt_off + opt.len()].copy_from_slice(&opt);

    // Zero-fill the remaining padding bytes; they are the leading part of the
    // OPT option-data (the rest is the untouched payload after `pad_size`).
    for byte in padding[opt_off + opt.len()..].iter_mut() {
        *byte = 0x00;
    }
}

/// Legacy `TYPE NULL` DNS padding, retained only for `pad_size < DNS_OPT_MIN`
/// (too small for the OPT framing). A NULL RR (RFC 1035 §3.3.10) carries opaque
/// RDATA of any length, so for `pad_size >= 28` it still covers the whole
/// datagram; smaller pads degrade to header(+question) only, with the count
/// fields advertising just the sections that physically fit.
fn apply_dns_padding_null(data: &mut [u8], pad_size: usize) {
    let total_len = data.len();
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    let tx_hi = payload.first().copied().unwrap_or(0);
    let tx_lo = payload.get(1).copied().unwrap_or(0);

    let qdcount: u8 = if pad_size >= 17 { 1 } else { 0 };
    let ancount: u8 = if pad_size >= 28 { 1 } else { 0 };

    let rdlength: u16 = total_len.saturating_sub(28).min(u16::MAX as usize) as u16;
    let [rl_hi, rl_lo] = rdlength.to_be_bytes();

    #[rustfmt::skip]
    let fixed: [u8; 28] = [
        tx_hi, tx_lo,
        0x81, 0x80,             // Flags: QR=1, RD=1, RA=1, RCODE=NOERROR
        0x00, qdcount,
        0x00, ancount,
        0x00, 0x00,
        0x00, 0x00,
        0x00,                   // QNAME: root label
        0x00, 0x01,             // QTYPE  = A
        0x00, 0x01,             // QCLASS = IN
        0x00,                   // answer NAME: root label
        0x00, 0x0a,             // TYPE  = NULL (10)
        0x00, 0x01,             // CLASS = IN
        0x00, 0x00, 0x00, 0x3c, // TTL = 60
        rl_hi, rl_lo,           // RDLENGTH = total_len - 28
    ];

    let advertised_len: usize = if pad_size >= 28 {
        28
    } else if pad_size >= 17 {
        17
    } else {
        12
    };
    let copy_len = std::cmp::min(padding.len(), advertised_len);
    padding[..copy_len].copy_from_slice(&fixed[..copy_len]);

    for byte in padding[copy_len..].iter_mut() {
        *byte = 0x00;
    }
}

/// STUN-style padding: a Binding Success Response with valid attributes.
///
/// The proxy can only rewrite the AWG padding prefix and must leave the
/// encrypted payload untouched, so the leading bytes mimic a STUN Binding
/// Success Response — the natural reply to the client's Binding Request cover
/// traffic. The message carries type `0x0101`, the RFC 5389 magic cookie, a
/// transaction ID derived from the payload, and, when the padding is large
/// enough, an `XOR-MAPPED-ADDRESS` attribute (the attribute that makes a
/// response read as a real STUN reply) followed by a `SOFTWARE` attribute that
/// fills the remainder of the advertised message.
///
/// The advertised message length covers exactly the TLVs written, so a strict
/// STUN parser stops before the WireGuard payload — which trails undissected,
/// as a short STUN message does inside an oversized datagram — instead of
/// reading it as an attribute whose bogus length overruns the buffer (the
/// "Malformed Packet" fingerprint). Padding shorter than the 20-byte STUN
/// header copies the longest available header prefix; 15-byte install-script
/// padding still carries the type, length, magic cookie, and partial
/// transaction ID.
fn apply_stun_padding(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    let mut state = fnv1a_seed(payload);
    macro_rules! next {
        () => {{
            let v = state;
            state = lcg_step(state);
            v
        }};
    }

    const COOKIE: u32 = 0x2112_A442;

    // Transaction ID, derived purely from the payload seed and consumed before
    // any attribute randomness so it stays stable across pad sizes (a given
    // payload always yields the same 96-bit transaction ID, independent of how
    // many attributes happen to fit the padding).
    let mut txn = [0u8; 12];
    for chunk in txn.chunks_mut(4) {
        chunk.copy_from_slice(&next!().to_be_bytes());
    }

    // Attribute area available within the padding. A STUN message length is
    // always a multiple of 4; below a full 20-byte header there is no room for
    // any attribute.
    let body = if pad_size > 20 {
        (pad_size - 20) & !0b11usize
    } else {
        0
    };

    // Write attributes into [20, 20 + written) as well-formed TLVs. A STUN
    // dissector reads the advertised `written` bytes as attributes, so each TLV
    // must frame itself exactly: a bogus length would overrun and flag the
    // packet malformed.
    let mut written = 0usize;

    // XOR-MAPPED-ADDRESS (0x0020), IPv4: 4-byte TLV header + 8-byte value. This
    // is what makes the message read as a genuine Binding response.
    if body - written >= 12 {
        let port = (next!() >> 16) as u16;
        let addr = next!();
        let xport = port ^ (COOKIE >> 16) as u16; // X-Port
        let xaddr = addr ^ COOKIE; // X-Address
        let off = 20 + written;
        padding[off..off + 2].copy_from_slice(&0x0020u16.to_be_bytes());
        padding[off + 2..off + 4].copy_from_slice(&8u16.to_be_bytes());
        padding[off + 4] = 0x00; // reserved
        padding[off + 5] = 0x01; // address family = IPv4
        padding[off + 6..off + 8].copy_from_slice(&xport.to_be_bytes());
        padding[off + 8..off + 12].copy_from_slice(&xaddr.to_be_bytes());
        written += 12;
    }

    // SOFTWARE (0x8022) fills the rest of the body with one attribute so the
    // padding region is accounted for in the advertised length. The value length
    // is a multiple of 4, so the TLV ends on a 4-byte boundary; it is clamped to
    // 124 because RFC 5389 §15.10 requires a SOFTWARE value below 128 bytes (124
    // is the largest 4-aligned length under that). Any padding past the attribute
    // is zeroed below as trailing bytes beyond the advertised length. The value
    // is printable ASCII for a clean UTF-8 string.
    let remaining = body - written;
    if remaining >= 4 {
        let vlen = std::cmp::min(remaining - 4, 124);
        let off = 20 + written;
        padding[off..off + 2].copy_from_slice(&0x8022u16.to_be_bytes());
        padding[off + 2..off + 4].copy_from_slice(&(vlen as u16).to_be_bytes());
        for b in padding[off + 4..off + 4 + vlen].iter_mut() {
            *b = 0x20 + (next!() % 0x5F) as u8;
        }
        written += 4 + vlen;
    }

    // Header is built after `written` is known. Copy as much as fits; a partial
    // header still carries the type, length, cookie and a partial transaction ID.
    //
    // `written` is bounded regardless of pad_size: at most XOR-MAPPED-ADDRESS (12)
    // + SOFTWARE header (4) + the RFC 5389 §15.10 value cap (124) = 140 bytes. It
    // is `body` that grows with pad_size, but `body` only gates how large the
    // (capped) SOFTWARE value is — it is never advertised. So `written as u16`
    // cannot truncate and the advertised length always equals the bytes written.
    debug_assert!(
        written <= u16::MAX as usize,
        "advertised STUN message length must fit the u16 length field"
    );
    let mut header = [0u8; 20];
    header[0..2].copy_from_slice(&0x0101u16.to_be_bytes()); // Binding Success Response
    header[2..4].copy_from_slice(&(written as u16).to_be_bytes());
    header[4..8].copy_from_slice(&COOKIE.to_be_bytes());
    header[8..20].copy_from_slice(&txn);
    let copy_len = std::cmp::min(padding.len(), header.len());
    padding[..copy_len].copy_from_slice(&header[..copy_len]);

    // Any bytes between the advertised message end and the padding end sit beyond
    // the STUN length; zero them (undissected, like the trailing WG payload).
    if let Some(tail) = padding.get_mut(20 + written..) {
        for b in tail.iter_mut() {
            *b = 0x00;
        }
    }
}

fn decimal_digits(mut value: usize) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// `core::fmt::Write` adapter that formats into a fixed stack buffer, so SIP
/// header lines can be built with `write!` without per-packet heap allocation.
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl core::fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let end = self.len.checked_add(bytes.len()).ok_or(core::fmt::Error)?;
        if end > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

/// SIP-style padding: a SIP *response* header block packed into the padding.
///
/// The padded packet is emitted by the proxy *toward the client*, so it is the
/// server side of the conversation — real SIP responses start with a
/// `SIP/2.0 <status>` line (RFC 3261 §7.2). Mirroring the client's request-side
/// padding, the response greedily packs the status line plus as many mandatory
/// headers as fit — `Via` (with a per-packet `branch`), `From`, `To`, `Call-ID`,
/// `CSeq` — in canonical order, so a DPI that inspects only the leading bytes of
/// the datagram sees a realistic SIP response header block rather than a bare
/// status line. The WireGuard payload (the message body) begins at byte
/// `pad_size`.
///
/// Because the proxy sees the whole datagram, it can append a `Content-Length`
/// that covers the *entire* body (the space-fill remainder of the padding plus
/// the untouched WG payload), so the datagram is a single framed SIP message
/// with no trailing/"extraneous" bytes — but only when the full mandatory header
/// set already fit, so headers are never displaced by `Content-Length`.
///
/// A complete header block cannot fit in small padding sizes (a minimal realistic
/// response is ~150–200 B), so below that the message is intentionally
/// incomplete: whole-message parsers note missing headers, but the inspected
/// prefix stays SIP-shaped. Padding too small for a complete status line plus a
/// terminating blank line (`\r\n\r\n`) falls back to a status-line fragment with a CRLF suffix.
fn apply_sip_padding(data: &mut [u8], pad_size: usize) {
    use core::fmt::Write as _;

    let total_len = data.len();
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }
    let len = padding.len();

    // Per-packet deterministic values derived from the payload (no global RNG,
    // no per-packet allocation).
    let mut st = fnv1a_seed(payload);
    macro_rules! next {
        () => {{
            let v = st;
            st = lcg_step(st);
            v
        }};
    }
    const STATUS: [&str; 3] = ["100 Trying", "180 Ringing", "200 OK"];
    const HOSTS: [&str; 3] = ["sip.example.com", "pbx.example.net", "voip.example.org"];
    const METHODS: [&str; 3] = ["INVITE", "OPTIONS", "REGISTER"];
    let status_idx = next!() as usize % STATUS.len();
    let host = HOSTS[next!() as usize % HOSTS.len()];
    let method = METHODS[next!() as usize % METHODS.len()];
    let branch = next!();
    let from_tag = next!();
    let to_tag = next!();
    let call_id = next!();
    // Last value reads the state directly (no further `next!`), so the final draw
    // leaves no dead write to `st`.
    let cseq = 1 + (st % 100_000);

    let mut pos = 0usize;
    let mut scratch = [0u8; 128];
    // Append a CRLF-terminated header line if it — plus the 2-byte closing blank
    // line — still fits in the padding region. Returns whether it was written.
    macro_rules! put_line {
        ($($arg:tt)*) => {{
            let written = {
                let mut w = SliceWriter { buf: &mut scratch, len: 0 };
                if write!(w, $($arg)*).is_ok() { Some(w.len) } else { None }
            };
            match written {
                Some(n) if pos + n + 2 <= len => {
                    padding[pos..pos + n].copy_from_slice(&scratch[..n]);
                    pos += n;
                    true
                }
                _ => false,
            }
        }};
    }

    // The status line is mandatory. Try the seed-chosen status first, then the
    // remaining ones (rotating), so a complete status line is emitted whenever
    // *any* fits — e.g. the shorter "200 OK" still fits sizes where "180 Ringing"
    // would not. Only when none fits (padding shorter than the smallest status
    // line) fall back to a status-line fragment with a CRLF suffix.
    let mut status_written = false;
    for k in 0..STATUS.len() {
        let status = STATUS[(status_idx + k) % STATUS.len()];
        if put_line!("SIP/2.0 {status}\r\n") {
            status_written = true;
            break;
        }
    }
    if !status_written {
        const FRAG: &[u8] = b"SIP/2.0 100 Trying\r\n";
        let take = FRAG.len().min(len);
        padding[..take].copy_from_slice(&FRAG[..take]);
        for b in padding[take..].iter_mut() {
            *b = b' ';
        }
        if len >= 2 {
            padding[len - 2] = b'\r';
            padding[len - 1] = b'\n';
        }
        return;
    }

    // Mandatory response headers in canonical order; stop at the first that does
    // not fit so the emitted set stays a contiguous, in-order prefix. (A response
    // echoes Via/From/To/Call-ID/CSeq; Max-Forwards is request-only.)
    let all_mandatory =
        put_line!("Via: SIP/2.0/UDP {host}:5060;branch=z9hG4bK{branch:08x};rport\r\n")
            && put_line!("From: <sip:caller@{host}>;tag={from_tag:08x}\r\n")
            && put_line!("To: <sip:callee@{host}>;tag={to_tag:08x}\r\n")
            && put_line!("Call-ID: {call_id:08x}@{host}\r\n")
            && put_line!("CSeq: {cseq} {method}\r\n");

    // Only when every mandatory header fit, append a Content-Length covering the
    // entire body — the space-fill remainder of the padding plus the WG payload —
    // so the datagram frames as one SIP message with no extraneous bytes. The
    // declared length equals total_len - header_end, so the header_end (which
    // includes the value's own digit count) must satisfy a fixed point.
    //
    // A single header width has rare unsolvable sizes (body lands on 11, 102,
    // 1003, ...). RFC 3261 HCOLON allows the whitespace after the colon to vary,
    // so we try one and two spaces: their unsolvable points are disjoint, so a
    // correct Content-Length is always emitted whenever the mandatory headers fit.
    if all_mandatory {
        'content_length: for sws in 1..=2usize {
            for digits in 1..=decimal_digits(total_len) {
                let header_end =
                    pos + "Content-Length:".len() + sws + digits + b"\r\n\r\n".len();
                if header_end > len {
                    break; // this width's line + blank line does not fit
                }
                if decimal_digits(total_len - header_end) == digits {
                    let body = total_len - header_end;
                    let written = match sws {
                        1 => put_line!("Content-Length: {body}\r\n"),
                        _ => put_line!("Content-Length:  {body}\r\n"),
                    };
                    debug_assert!(written, "Content-Length line must fit when header_end <= len");
                    break 'content_length;
                }
            }
        }
    }

    // Closing blank line, then space-fill the rest of the padding region. The
    // message body is these spaces followed by the WG payload at byte `pad_size`.
    if pos + 2 <= len {
        padding[pos] = b'\r';
        padding[pos + 1] = b'\n';
        pos += 2;
    }
    for b in padding[pos..].iter_mut() {
        *b = b' ';
    }
}

/// Linear congruential generator step (glibc constants).
fn lcg_step(state: u32) -> u32 {
    state.wrapping_mul(1_103_515_245).wrapping_add(12345)
}
