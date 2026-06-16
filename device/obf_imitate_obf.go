// SPDX-License-Identifier: MIT

package device

import (
	"strconv"
	"sync/atomic"
)

// imitateObf is the obf-registry adapter for mechanism C (I-packets). It fills an
// entire I-packet datagram with protocol-conformant filler via imitateFillWhole,
// parallel to randObf (device/obf_rand.go) but protocol-shaped instead of random.
// Registered in obfBuilders as q/dns/stun/sip, configured e.g. as i1=<q 600>.
//
// Like randObf it is cosmetic on the wire: Deobfuscate is a no-op accept and
// DeobfuscatedLen is 0, so the I-packet carries no real payload and a vanilla peer
// drops it as undecryptable junk — exactly today's randObf behavior.
type imitateObf struct {
	length  int
	proto   imitateProto
	counter atomic.Uint64 // per-packet seed source; .Add(1) so consecutive I-packets differ
}

// newImitateObf returns an obfBuilder bound to proto. The builder parses the
// I-packet length from the tag value (<q 600> => length 600), matching randObf's
// "<r N>" length syntax. The same *imitateObf may be invoked concurrently for
// multiple peers' handshakes, so the seed counter is atomic.
func newImitateObf(proto imitateProto) obfBuilder {
	return func(val string) (obf, error) {
		length, err := strconv.Atoi(val)
		if err != nil {
			return nil, err
		}
		return &imitateObf{length: length, proto: proto}, nil
	}
}

func (o *imitateObf) Obfuscate(dst, src []byte) {
	seed := imitateJunkSeed(o.counter.Add(1))
	imitateFillWhole(dst[:o.length], seed, o.proto)
}

func (o *imitateObf) Deobfuscate(dst, src []byte) bool {
	// Cosmetic filler; nothing to validate (mirrors randObf).
	return true
}

func (o *imitateObf) ObfuscatedLen(n int) int { return o.length }

func (o *imitateObf) DeobfuscatedLen(n int) int { return 0 }
