// SPDX-License-Identifier: MIT

package device

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// quicV1InitialSalt is the QUIC v1 Initial salt (RFC 9001 §5.2). Public and
// fixed: any observer can derive these keys and read the benign SNI — which is
// the point of the qinit I-packet (Tier 4): defeating cheap line-rate SNI filtering.
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with the
// "tls13 " label prefix and a zero-length context, as QUIC Initial derivation uses.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	if length > 0xFFFF {
		panic("hkdfExpandLabel: length exceeds uint16")
	}
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0x00) // zero-length context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err) // only fails on absurd length; inputs here are fixed-size
	}
	return out
}

// deriveInitialKeys returns the client Initial AEAD key (16), IV (12), and
// header-protection key (16) for a destination connection ID (RFC 9001 §5.2).
func deriveInitialKeys(dcid []byte) (key, iv, hp []byte) {
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		panic(err)
	}
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	key = hkdfExpandLabel(clientSecret, "quic key", 16)
	iv = hkdfExpandLabel(clientSecret, "quic iv", 12)
	hp = hkdfExpandLabel(clientSecret, "quic hp", 16)
	return key, iv, hp
}

// newAESGCM builds an AES-128-GCM AEAD (16-byte tag) for the Initial payload.
func newAESGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// headerProtectionMask returns the 5-byte-relevant AES-ECB header-protection
// mask (RFC 9001 §5.4.3): a single AES block over the 16-byte ciphertext sample.
func headerProtectionMask(hp, sample []byte) []byte {
	if len(sample) != aes.BlockSize {
		panic("headerProtectionMask: sample must be exactly 16 bytes")
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		panic(err)
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	return mask
}

// appendQUICVarint appends v in QUIC variable-length integer encoding (RFC 9000 §16).
func appendQUICVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(0x40|(v>>8)), byte(v))
	case v <= 1073741823:
		return append(b, byte(0x80|(v>>24)), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(0xc0|(v>>56)), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// --- TLS 1.3 ClientHello (generic, valid; static JA3 — not a browser's; Ib tier) ---

func appendU8Vec(b, body []byte) []byte {
	if len(body) > 0xFF {
		panic("appendU8Vec: body exceeds 255 bytes")
	}
	return append(append(b, byte(len(body))), body...)
}

func appendU16Vec(b, body []byte) []byte {
	if len(body) > 0xFFFF {
		panic("appendU16Vec: body exceeds 65535 bytes")
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}
func tlsExtension(extType uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, extType)
	return appendU16Vec(b, data)
}

// buildClientHello returns a complete TLS 1.3 ClientHello handshake message
// (type + u24 length + body) advertising the given SNI. Fixed cipher suites,
// x25519 key share, ALPN h3, and QUIC transport parameters — a clean, parseable
// ClientHello whose JA3 is static (matching a real browser is the deferred Ib tier).
// scid is the Source Connection ID from the enclosing QUIC Initial header; it is
// echoed into initial_source_connection_id per RFC 9000 §7.3.
func buildClientHello(sni string, scid []byte) []byte {
	var exts []byte

	// server_name (0x0000): server_name_list{ host_name(0x00) | name }
	sniList := append([]byte{0x00}, binary.BigEndian.AppendUint16(nil, uint16(len(sni)))...)
	sniList = append(sniList, sni...)
	exts = append(exts, tlsExtension(0x0000, appendU16Vec(nil, sniList))...)

	// supported_versions (0x002b): u8 list of [TLS 1.3 = 0x0304]
	exts = append(exts, tlsExtension(0x002b, appendU8Vec(nil, []byte{0x03, 0x04}))...)

	// supported_groups (0x000a): u16 list of [x25519 = 0x001d]
	exts = append(exts, tlsExtension(0x000a, appendU16Vec(nil, []byte{0x00, 0x1d}))...)

	// key_share (0x0033): client_shares{ group(x25519) | key_exchange(32 rand) }
	pub := make([]byte, 32)
	rand.Read(pub)
	ks := append([]byte{0x00, 0x1d}, appendU16Vec(nil, pub)...)
	exts = append(exts, tlsExtension(0x0033, appendU16Vec(nil, ks))...)

	// signature_algorithms (0x000d): ecdsa_p256_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
	exts = append(exts, tlsExtension(0x000d, appendU16Vec(nil, []byte{0x04, 0x03, 0x08, 0x04, 0x04, 0x01}))...)

	// application_layer_protocol_negotiation (0x0010): ["h3"]
	exts = append(exts, tlsExtension(0x0010, appendU16Vec(nil, appendU8Vec(nil, []byte("h3"))))...)

	// quic_transport_parameters (0x0039): initial_source_connection_id (0x0f) = SCID.
	// RFC 9000 §7.3 requires this to equal the Initial header's Source Connection ID;
	// the connection-ID lengths used here are <64, so the QUIC varint ids/lengths are
	// single bytes.
	qtp := append([]byte{0x0f, byte(len(scid))}, scid...)
	exts = append(exts, tlsExtension(0x0039, qtp)...)

	body := []byte{0x03, 0x03} // legacy_version = TLS 1.2
	random := make([]byte, 32)
	rand.Read(random)
	body = append(body, random...)
	body = appendU8Vec(body, nil)                                         // legacy_session_id: empty
	body = appendU16Vec(body, []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03}) // cipher_suites
	body = appendU8Vec(body, []byte{0x00})                                // compression: null
	body = appendU16Vec(body, exts)                                       // extensions

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

// buildCryptoFrame wraps data in a QUIC CRYPTO frame (type 0x06) at offset 0.
func buildCryptoFrame(data []byte) []byte {
	b := appendQUICVarint([]byte{0x06}, 0) // type + offset
	b = appendQUICVarint(b, uint64(len(data)))
	return append(b, data...)
}
