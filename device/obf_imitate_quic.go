// SPDX-License-Identifier: MIT

package device

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
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
