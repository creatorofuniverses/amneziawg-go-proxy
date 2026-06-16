# Go Implementation of AmneziaWG

AmneziaWG is a contemporary version of the WireGuard protocol. It's a fork of WireGuard-Go and offers protection against detection by Deep Packet Inspection (DPI) systems. At the same time, it retains the simplified architecture and high performance of the original.

The precursor, WireGuard, is known for its efficiency but had issues with detection due to its distinctive packet signatures.
AmneziaWG addresses this problem by employing advanced obfuscation methods, allowing its traffic to blend seamlessly with regular internet traffic.
As a result, AmneziaWG maintains high performance while adding an extra layer of stealth, making it a superb choice for those seeking a fast and discreet VPN connection.

> **This `-proxy` fork** adds **native client-side traffic imitation**: instead of
> filling the obfuscation padding and junk with random ("unknown encrypted") bytes,
> it can shape them to look like real **QUIC / DNS / STUN / SIP**, and can send a
> fake **QUIC Initial advertising a benign SNI**. This is a byte-exact port of the
> server-side [`amneziawg-proxy` `transform.rs`](https://github.com/wiresock/amneziawg-install)
> brought into the core so it also shapes **client → server** traffic. See
> [Traffic imitation](#traffic-imitation) below. The feature is opt-in and
> off by default — without it the binary behaves exactly like upstream `amneziawg-go`.

## Usage

Simply run:

```
$ amneziawg-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/amneziawg/wg0.sock`, which will result in amneziawg-go shutting down.

To run amneziawg-go without forking to the background, pass `-f` or `--foreground`:

```
$ amneziawg-go -f wg0
```
When an interface is running, you may use [`amneziawg-tools `](https://github.com/amnezia-vpn/amneziawg-tools) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; you should run amnezia-wg instead of using default linux kernel module.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.
This runs on MacOS, you should use it from [amneziawg-apple](https://github.com/amnezia-vpn/amneziawg-apple)

### Windows

This runs on Windows, you should use it from [amneziawg-windows](https://github.com/amnezia-vpn/amneziawg-windows), which uses this as a module.


## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://github.com/creatorofuniverses/amneziawg-go-proxy
$ cd amneziawg-go-proxy
$ make
```

> This fork builds the same `amneziawg-go` binary as upstream; `make` regenerates
> `version.go` from `git describe` before building.

## Configuration

> [!NOTE]
> If there is no value specified (for any param), AWG treats it as 0

### Junk packets

The amount of junk packets specified in `Jc` with a random size between `Jmin` and `Jmax` would be generated and sent prior every handshake

- `Jc: int`, recommended range is 4-12
- `Jmin: int` <= `Jmax:int`

> [!TIP]
> Junk packets do not carry any actual data, so there is no need to specify it on both sides. General recommendation is to use it on the client side only

> [!IMPORTANT]
> If Jmax >= system MTU (not the one specified in AWG), then the system can fracture this packet into fragments, which looks suspicious from the censor side

### Message paddings

- `S1: int` - padding of handshake initial message
- `S2: int` - padding of handshake response message
- `S3: int` - padding of handshake cookie message
- `S4: int` - padding of transport messages

### Message headers

Every message in wireguard has `uint32` type at the beginning of the packet. This field could be controlled by specifying the params below:

- `H1: string` - header range of handshake initial message
- `H2: string` - header range of handshake initial message
- `H3: string` - header range of handshake cookie message
- `H4: string` - header range of transport message

Values could be specified as:
- range: `x-y`, x <= y; e.g. `123-456`
- single value `1234`

### Custom signature packets

These packets are sent prior to **every handshake initiation**, in the same way as
Junk packets — so in practice they are sent by the **initiator** (normally the
client). Each of `I1`–`I5` is configured independently and becomes **one separate
datagram on the wire**.

- `I1: string`
- `I2: string`
- `I3: string`
- `I4: string`
- `I5: string`

**When / how they fire:**
- They are sent **before** the handshake-initiation message, once per handshake.
- **Sending order is by index** (`I1`, then `I2`, … `I5`). An unset/empty slot is
  simply **skipped** — the others keep their relative order.
- **You do not have to fill them sequentially or contiguously.** Setting only `I3`
  is valid (one packet is sent); setting `I2` + `I4` sends two packets, `I2` then
  `I4`. There is no requirement to set `I1` first.
- Each `Ix` value is **one obf-chain** whose tags are concatenated into that single
  datagram — e.g. `I1 = <b 0xc0ffee><r 200><t>` produces **one** packet of
  `3 + 200 + 4 = 207` bytes (static bytes, then 200 random bytes, then a timestamp).
- They carry no real data, so there is no need to set them on both peers — a vanilla
  peer drops each as an unrecognized datagram. Client-side only is the recommendation.

**Example:**
```
# Two distinct fake packets before each handshake: a QUIC Initial with an SNI,
# then a 600-byte fake DNS response. Slots I3-I5 are unset and skipped.
I1 = <qinit www.google.com>
I2 = <dns 600>
```

Value is a sequence of one or more tags specified below:
- `<b 0x[seq]>` - static bytes tag. Dumps `[seq]` as-is to the packet. `[seq]` is hex-encoded sequence which represents bytes sequence (2 hex numbers per byte) and is always even-sized
- `<r [size]>` - random bytes tag. Dumps `[size]` amount of randomly-generated bytes to the packet
- `<rd [size]>` - random digits tag. Dumps `[size]` amount of randomly-generated bytes from `[0-9]` set to the packet
- `<rc [size]>` - random chars tag. Dumps `[size]` amount of randomly-generated bytes from `[a-zA-Z] set to the packet
- `<t>` - timestamp tag. Dumps 4-bytes long current system time in UNIX format

Tags added by this fork ([Traffic imitation](#traffic-imitation)):
- `<q [size]>` - emits a `[size]`-byte fake **QUIC** 1-RTT datagram
- `<dns [size]>` - emits a `[size]`-byte fake **DNS** response datagram
- `<stun [size]>` - emits a `[size]`-byte fake **STUN** Binding Success datagram
- `<sip [size]>` - emits a `[size]`-byte fake **SIP** response datagram
- `<qinit [domain]>` - emits a 1200-byte fake **QUIC v1 Initial** carrying a TLS 1.3 ClientHello whose SNI is `[domain]` (e.g. `<qinit www.google.com>`)

> [!IMPORTANT]
> The fork's imitation tags (`<q>`, `<dns>`, `<stun>`, `<sip>`, `<qinit>`) each
> produce a **complete, self-contained datagram** of that protocol. Use **one of
> them alone** in an `Ix` slot — concatenating other tags before/after (e.g.
> `<b 0x..><qinit ..>`) prepends bytes that break the protocol framing, so it would
> no longer parse as QUIC/DNS/etc. The classic tags (`<b>`, `<r>`, `<rd>`, `<rc>`,
> `<t>`) are the ones meant to be chained together.

> [!TIP]
> Custom signature packets does not carry any actual data, so there is no need to specify it on both sides. General recommendation is to use it on the client side only

> [!IMPORTANT]
> If the final size of any packet exceeds system MTU, it would be fractured into fragments, which looks suspicious

## Traffic imitation

> Added by this fork. Off by default — omit these keys and behaviour is identical to upstream.

AmneziaWG already defeats *byte-signature* DPI (its `S` padding and `H` header
randomization remove WireGuard's fixed fields). But the padding and junk it sends
are high-entropy bytes that a censor can still classify as **"unknown encrypted."**
Traffic imitation closes that gap: it rewrites those same bytes into
**protocol-conformant filler** so the flow looks like an allowed protocol
(QUIC/DNS/STUN/SIP), and can prepend a fake **QUIC Initial with a benign SNI**.

This is a byte-exact port of the server-side
[`amneziawg-proxy` `transform.rs`](https://github.com/wiresock/amneziawg-install)
(`amneziawg-proxy/src/transform.rs`) — which only shaped *server → client* — brought
natively into the core. Because WireGuard is peer-symmetric, the patched side shapes
**whichever direction it sends**, and it additionally shapes the junk packets and
I-packets the original sidecar proxy could not.

### What it defeats (and what it does not)

| DPI technique | Addressed by |
|---|---|
| Byte-signature (WireGuard fixed fields) | AWG itself (`S` / `H`) — already shipped |
| Protocol-positive ("is this an allowed protocol?") | **`imitate_protocol` + the `q`/`dns`/`stun`/`sip` I-packet tags** |
| Flow-consistency (both directions look like the protocol) | **`imitate_protocol`** (it also shapes junk, not just real packets) |
| Cheap line-rate SNI filtering | **`<qinit domain>`** (fake QUIC Initial carrying that SNI) |
| Statistical / behavioural (sizes, timing, duration) | **Nothing here** — out of scope |
| Active probing of the server | Not included (this is send-path shaping only) |

The rewrite is **cosmetic and length-invariant**: a receiver only size-matches the
padding and validates the header *after* it, never inspecting padding content. So an
imitating peer **interoperates with a stock (vanilla) peer unchanged** — you can turn
it on for the client alone, against an unmodified server.

### `imitate_protocol`

A single device-level key that shapes the obfuscation padding (`S1`–`S4`) and the
junk packets (`Jc`) to resemble the chosen protocol:

```
imitate_protocol = none | quic | dns | stun | sip      # default: none
```

This is a fork-specific key that standard `amneziawg-tools` do not pass through from
a config file; set it directly on the control socket after the interface is up
(see the UAPI `set=1` operation), or via tooling that forwards it.

### Imitation I-packets

The `<q>` / `<dns>` / `<stun>` / `<sip>` / `<qinit>` tags above plug into the existing
`I1`–`I5` mechanism, so they need no special tooling — just put them in the config:

```
I1 = <qinit www.google.com>
I2 = <q 600>
```

`<qinit domain>` builds a real, fully packet-protected QUIC v1 Initial (RFC 9001
well-known salt, standard-library crypto — no uTLS dependency); any observer can
derive the keys and read the benign SNI, which is the point. It defeats cheap SNI
filtering but does **nothing** against a censor running a full QUIC state machine
(the fake handshake never completes), and its TLS fingerprint (JA3/JA4) is a fixed
generic one, not a specific browser's — matching a real browser fingerprint is
planned follow-on work.