//! Dumps golden vectors for the Go imitation port's byte-exactness test.
//!
//! Output format (one line per case): `<proto> <pad> <payload_hex> <output_hex>`.
//! The grid (4 protocols × 4 payloads × 8 pad sizes) and the buffer layout
//! (payload placed at data[pad..], then apply_padding rewrites data[..pad]) MUST
//! match `device/obf_imitate_golden_test.go`, which reconstructs each case the
//! same way and asserts the Go port reproduces `output_hex` exactly.
//!
//! Usage: `imitate-vectors <output-path>` (or set IMITATE_VECTORS_OUT).

mod reference;

use reference::{apply_padding, Protocol};
use std::fmt::Write as _;

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("IMITATE_VECTORS_OUT").ok())
        .expect("usage: imitate-vectors <output-path>  (or set IMITATE_VECTORS_OUT)");

    let protos = [
        ("quic", Protocol::Quic),
        ("dns", Protocol::Dns),
        ("stun", Protocol::Stun),
        ("sip", Protocol::Sip),
    ];
    let payloads: [&[u8]; 4] = [
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        b"the quick brown fox jumps over the lazy dog!!",
        &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        &[0u8; 40],
    ];
    let pads = [10usize, 16, 20, 32, 40, 64, 150, 200];

    let mut out = String::new();
    for (pname, proto) in protos {
        for &payload in payloads.iter() {
            for &pad in pads.iter() {
                let mut data = vec![0u8; pad + payload.len()];
                data[pad..].copy_from_slice(payload);
                apply_padding(&mut data, pad, proto);

                let mut hex = String::new();
                for b in &data {
                    write!(hex, "{:02x}", b).unwrap();
                }
                let mut phex = String::new();
                for b in payload {
                    write!(phex, "{:02x}", b).unwrap();
                }
                writeln!(out, "{} {} {} {}", pname, pad, phex, hex).unwrap();
            }
        }
    }

    std::fs::write(&out_path, out).expect("write vectors");
    eprintln!("wrote golden vectors to {out_path}");
}
