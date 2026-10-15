# T7 — Metasploit Framework: meterpreter TLV protocol and handlers

**Target:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\metasploit`
**Corpus:** 15,080 files — 8,570 `.rb` (Ruby). Largest target in the mission.
**Evidence class:** `[source]` — **no compiled Metasploit/meterpreter binary exists on disk.** Every claim below is source-derived. There is zero binary evidence for this target, and nothing here should be read as byte-level confirmation.

> **Provenance.** The originally assigned diver (`msf-diver`) died at the write step with the
> message *"I have all the protocol evidence I need. Let me now write the report"* and left
> nothing on disk. The Lead took the target over directly and the analysis below is the Lead's
> own, re-derived from source. Coverage is scoped — see §9.

---

## 1. Architecture

Metasploit is not a C2 in the same sense as Sliver, Havoc or Mythic. It is a **modular
exploitation framework** with a post-exploitation payload subsystem. The relevant lens for this
mission:

```
msfconsole / msfvenom
  └── lib/msf/core/            framework core
       ├── handler/            how a session comes back (reverse_*, bind_*)
       ├── payload/            the staging logic (stager -> stage)
       └── exploit/            module mixins
  └── lib/rex/                 the "Ruby Exploitation" library
       ├── rex/post/meterpreter/   THE IMPLANT PROTOCOL (this report's focus)
       ├── rex/encoder/            payload encoders
       └── rex/payloads/           payload assembly
  └── modules/                 ~4,000 modules (not enumerated — see §9)
```

The critical split: **`lib/rex/post/meterpreter/` is the operator-side implementation of the
implant wire protocol.** It does not contain the implant — the actual meterpreter payload is a
C binary built from a separate repository. So this report reconstructs the **protocol and the
control surface** with high fidelity, and reconstructs **implant internals from the operator's
expectations of them** — which is a real but weaker form of evidence. Stated plainly rather
than blurred.

---

## 2. The meterpreter TLV protocol — exact byte layout

**Source:** `lib/rex/post/meterpreter/packet.rb:795-841` — the header layout is documented
verbatim in a source comment authored by the Metasploit developers.

### 2.1 Packet header — 32 bytes, fixed

```
offset  size  field             source
------  ----  ----------------  ----------------------------------------
  0      4    XOR KEY           packet.rb:808, 831
  4     16    Session GUID      packet.rb:809, 835 (GUID_SIZE=16, :165)
 20      4    Encrypt flags     packet.rb:810, 832
 24      4    Packet length     packet.rb:811, 833
 28      4    Packet type       packet.rb:812, 834
 32      X    Packet data       packet.rb:813
```

**`PACKET_HEADER_SIZE = XOR_KEY_SIZE(4) + GUID_SIZE(16) + ENCRYPTED_FLAGS_SIZE(4) + PACKET_LENGTH_SIZE(4) + PACKET_TYPE_SIZE(4) = 32`**
[source: `packet.rb:831-835`]

All of these are **big-endian**, or at least packed with `N` (32-bit big-endian unsigned).
[source: `packet.rb:990` — `pack('NNNA*A*')`]

### 2.2 The XOR layer

```ruby
def to_r(session_guid = nil, key = nil)
  xor_key = (rand(254) + 1).chr + (rand(254) + 1).chr + (rand(254) + 1).chr + (rand(254) + 1).chr
  raw = (session_guid || NULL_GUID).dup
  tlv_data = GroupTlv.instance_method(:to_r).bind(self).call
  ...
  xor_key + xor_bytes(xor_key, raw)
end
```

[source: `packet.rb:980-997`]

Three facts that matter:

1. **The XOR key is 4 bytes, randomly generated per packet, and its range is 1..254 per byte** —
   never 0. `rand(254) + 1` excludes zero deliberately. [source: `packet.rb:981`]
2. **The XOR is applied to the entire packet body including the header**, not just the payload.
   [source: `packet.rb:996` — `xor_bytes(xor_key, raw)` where `raw` starts with the GUID]
3. **The XOR key is transmitted in the clear, prepended to the packet.**
   [source: `packet.rb:996` — `xor_key + xor_bytes(...)`]

So the outer encoding is **obfuscation, not encryption**: read the first 4 bytes, XOR the rest.
It defeats naive signature matching and nothing else. Anyone who knows the format decodes it in
one step. This is worth stating without hedging — the XOR layer provides no confidentiality.

### 2.3 Packet types

[source: `packet.rb:12-16`]

| Constant | Value | Meaning |
|---|---|---|
| `PACKET_TYPE_REQUEST` | **0** | encrypted/negotiated request |
| `PACKET_TYPE_RESPONSE` | **1** | response |
| `PACKET_TYPE_CONFIG` | **2** | configuration packet — **exempt from encryption** (see §2.5) |
| `PACKET_TYPE_PLAIN_REQUEST` | **10** | pre-encryption request |
| `PACKET_TYPE_PLAIN_RESPONSE` | **11** | pre-encryption response |

The PLAIN variants exist so the session can operate **before** key negotiation completes — e.g.
the negotiation request itself must be able to travel. [source: `packet.rb:863-871` — a response
to a `PLAIN_REQUEST` is itself `PLAIN_RESPONSE`]

### 2.4 TLV meta-types — bit flags, not enums

[source: `packet.rb:21-41`]

| Constant | Value | Notes |
|---|---|---|
| `TLV_META_TYPE_NONE` | `0` | |
| `TLV_META_TYPE_STRING` | `1 << 16` | 65536 |
| `TLV_META_TYPE_UINT` | `1 << 17` | 131072 |
| `TLV_META_TYPE_RAW` | `1 << 18` | 262144 |
| `TLV_META_TYPE_BOOL` | `1 << 19` | 524288 |
| `TLV_META_TYPE_QWORD` | `1 << 20` | 1048576 |
| `TLV_META_TYPE_COMPRESSED` | `1 << 29` | **excluded from the mask** |
| `TLV_META_TYPE_GROUP` | `1 << 30` | container |
| `TLV_META_TYPE_COMPLEX` | `1 << 31` | |

**Design detail worth flagging:** the type field is a **bitmask where the high bits carry the
meta-type and the low bits carry the specific field number.** `TLV_META_MASK` deliberately
**excludes** `COMPRESSED` so that any type can additionally be flagged compressed —
[source: `packet.rb:31-41`], with the developer's own comment: *"Exclude compressed from the
mask since other meta types (e.g. RAW) can also be compressed"*. So a compressed raw blob is
`RAW | COMPRESSED`. Compression is orthogonal to type.

**TLV namespaces** [source: `packet.rb:46-49`]:

| Namespace | Base |
|---|---|
| `TLV_RESERVED` | 0 |
| `TLV_EXTENSIONS` | 20000 |
| `TLV_USER` | 40000 |
| `TLV_TEMP` | 60000 |

### 2.5 Encryption in the packet body

When `encrypt_flags` is non-zero, the packet data is not raw TLV:

```
Encrypt flags == 0  ->  packet data is plain TLV
Encrypt flags == 1  ->  IV (16 bytes) || AES-256-CBC ciphertext
```

[source: `packet.rb:815-827` — developer comment; `:839-841` for the flag constants]

| Constant | Value |
|---|---|
| `ENC_FLAG_NONE` | `0x0` |
| `ENC_FLAG_AES256` | `0x1` |
| `ENC_FLAG_AES128` | `0x2` |

[source: `packet.rb:839-841`]

**Cipher: AES in CBC mode**, IV random per packet, prefixed to the ciphertext in cleartext.
[source: `packet.rb:960-971`, `:988-990`]

```ruby
raise ArgumentError.new('AES key width must be 128 or 256 bits') unless (size == 128 || size == 256)
aes = OpenSSL::Cipher.new("AES-#{size}-CBC")
```

[source: `packet.rb:960-962`]

**CONFIG packets are never encrypted** — explicit guard at [source: `packet.rb:986`]:
`if @type != PACKET_TYPE_CONFIG && key && key[:key] && ...`. CONFIG packets carry C2 transport
configuration (§4) and travel in the clear by design.

### 2.6 Documented vulnerability in the decrypt path

```ruby
def decrypt_packet(key, encrypt_flags, data)
  # TODO: throw an error if the expected encryption isn't the same as the given
  #       as this could be an indication of hijacking or side-channel packet addition
  #       as highlighted by Justin Steven on github.
  if key && key[:key] && key[:type] && encrypt_flags == key[:type] && ...
```

[source: `packet.rb:1002-1006`]

This is a **live, developer-acknowledged weakness in production code**. The decrypt path does
not hard-fail when the received `encrypt_flags` disagrees with the negotiated key type. The
comment attributes the observation to a named external researcher (Justin Steven) and describes
the consequence in the developers' own words: **hijacking or side-channel packet addition.**

The condition at `:1006` does compare `encrypt_flags == key[:type]`, so the case is *partially*
handled — but the `else` branch at `:1009` is the fallthrough, and the TODO indicates the
authors consider the handling insufficient. The distinction between "checked" and "enforced"
matters here, and the source says it is not enforced. Recorded as a finding with the source's
own uncertainty, not resolved beyond it.

---

## 3. Key negotiation — RSA-2048 → AES

**Source:** `lib/rex/post/meterpreter/client_core.rb:776-815`

```
1. Operator generates a fresh RSA-2048 keypair per session       [client_core.rb:779]
2. Sends COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION with
   TLV_TYPE_RSA_PUB_KEY = public key DER                         [:782-783]
3. Implant generates the symmetric key, RSA-encrypts it with
   PKCS#1 v1.5 padding, returns it as TLV_TYPE_ENC_SYM_KEY       [:787, :791]
4. Operator derives expected key length from TLV_TYPE_SYM_KEY_TYPE
   AES128 -> 16 bytes, AES256 -> 32 bytes                        [:789]
5. Private-decrypts with PKCS1_PADDING, takes first N bytes      [:791-795]
```

**The implant chooses the symmetric key. The operator only supplies the public key.** That is
the correct direction and means a passive observer cannot recover the session key.

### 3.1 The weak-key flag

```ruby
sym_key = key_dec_data[0..key_length - 1]
is_weak_key = false
if key_dec_data.length > key_length
  key_dec_data = key_dec_data[key_length...]
  if key_dec_data.length > 0
    key_strength = key_dec_data[0]
    is_weak_key = key_strength != "\x00"
  end
end
```

[source: `client_core.rb:795-802`]

The plaintext after RSA decryption may carry a **trailing byte past the key** that flags a weak
key. The operator parses it and surfaces it as `weak_key?: is_weak_key` [source: `:815`]. This
means the protocol has an explicit affordance for the implant to declare its own key weak, and
the operator records it rather than refusing. That is a protocol-level design decision worth
noting: **weakness is reported, not rejected.**

### 3.2 Re-negotiation after migration

```ruby
# Post-migration the session doesn't have encryption any more.
...
# Renegotiate TLV encryption on the migrated session
client.tlv_enc_key = negotiate_tlv_encryption
```

[source: `client_core.rb:684`, `:728`, `:743`]

**Process migration destroys the TLV encryption and forces a full re-negotiation.** This is a
direct consequence of migrating into another process's address space — the key material does
not survive. Operationally: **migration is a detectable moment**, because a fresh RSA-2048 key
exchange and a new AES key must cross the wire immediately after it. That is a strong detection
signal and it falls out of the source rather than from speculation.

---

## 4. Core command set — numerically resolved

**Sources:** `lib/rex/post/meterpreter/core_ids.rb:13-48`

`EXTENSION_ID_CORE = 0` [source: `core_ids.rb:13`] — which fixes every core command ID to its
literal value:

| Command | ID | Note |
|---|---|---|
| `CORE_CHANNEL_CLOSE` | 1 | |
| `CORE_CHANNEL_EOF` | 2 | |
| `CORE_CHANNEL_INTERACT` | 3 | |
| `CORE_CHANNEL_OPEN` | 4 | |
| `CORE_CHANNEL_READ` | 5 | |
| `CORE_CHANNEL_SEEK` | 6 | |
| `CORE_CHANNEL_TELL` | 7 | |
| `CORE_CHANNEL_WRITE` | 8 | |
| `CORE_CONSOLE_WRITE` | 9 | |
| `CORE_ENUMEXTCMD` | 10 | enumerate available extension commands |
| `CORE_GET_SESSION_GUID` | 11 | |
| `CORE_LOADLIB` | 12 | **load a library into the session** |
| `CORE_MACHINE_ID` | 13 | |
| `CORE_MIGRATE` | 14 | process migration |
| `CORE_NATIVE_ARCH` | 15 | |
| **`CORE_NEGOTIATE_TLV_ENCRYPTION`** | **16** | the §3 handshake |
| `CORE_PATCH_UUID` | 17 | |
| `CORE_PIVOT_ADD` | 18 | |
| `CORE_PIVOT_REMOVE` | 19 | |
| `CORE_PIVOT_SESSION_DIED` | 20 | |
| `CORE_SET_SESSION_GUID` | 21 | |
| `CORE_SET_UUID` | 22 | |
| `CORE_SHUTDOWN` | 23 | |
| `CORE_TRANSPORT_ADD` | 24 | **add a fallback C2 transport** |
| `CORE_TRANSPORT_CHANGE` | 25 | |
| `CORE_TRANSPORT_GETCERTHASH` | 26 | TLS cert hash pinning |
| `CORE_TRANSPORT_LIST` | 27 | |
| `CORE_TRANSPORT_NEXT` | 28 | **failover to next transport** |
| `CORE_TRANSPORT_PREV` | 29 | |
| `CORE_TRANSPORT_REMOVE` | 30 | |
| `CORE_TRANSPORT_SETCERTHASH` | 31 | |
| `CORE_TRANSPORT_SET_TIMEOUTS` | 32 | |
| `CORE_TRANSPORT_SLEEP` | 33 | **implant-side sleep control** |
| `CORE_PIVOT_SESSION_NEW` | 34 | |

[source: `core_ids.rb:15-48`]

### 4.1 The transport subsystem is the resilience mechanism

Commands 24–33 are a complete **in-implant transport manager**. The implant can hold multiple
C2 transports, switch between them (`NEXT`/`PREV`), add and remove them at runtime, pin TLS
certificate hashes, and control its own sleep interval — all **remotely, over an established
session**.

`CORE_TRANSPORT_NEXT` (28) is the failover primitive: when a C2 path dies, the implant rotates
to the next configured transport. Combined with `CORE_TRANSPORT_SLEEP` (33) for operator-driven
beacon control, this makes the implant's comms posture **runtime-mutable and not fixed at
build time**. Compare: Sliver's beacon has `Interval`/`Jitter` set at registration (T1 §3);
Metasploit can retune a live session's transports and sleep.

---

## 5. Encryption-related TLV types

[source: `packet.rb:95-103`]

| TLV | Value | Type |
|---|---|---|
| `TLV_TYPE_MACHINE_ID` | `STRING \| 460` | host identity |
| `TLV_TYPE_UUID` | `RAW \| 461` | |
| `TLV_TYPE_SESSION_GUID` | `RAW \| 462` | matches header GUID field |
| **`TLV_TYPE_RSA_PUB_KEY`** | `RAW \| 550` | operator's RSA-2048 public key DER |
| **`TLV_TYPE_SYM_KEY_TYPE`** | `UINT \| 551` | AES128 / AES256 selector |
| **`TLV_TYPE_SYM_KEY`** | `RAW \| 552` | symmetric key, **plaintext path** |
| **`TLV_TYPE_ENC_SYM_KEY`** | `RAW \| 553` | symmetric key, **RSA-encrypted path** |

Note the **both** key paths: `TLV_TYPE_SYM_KEY` (552) carries an unencrypted symmetric key,
and `TLV_TYPE_ENC_SYM_KEY` (553) carries the RSA-wrapped one. The fallback at
`client_core.rb:805` uses the plaintext path when `key_enc` is nil:

```ruby
else
  sym_key = response.get_tlv_value(TLV_TYPE_SYM_KEY)
```

**A session can therefore be established with a cleartext symmetric key** if the implant
returns TLV 552 instead of 553. The operator code accepts this without error. That is the
protocol's available degraded mode and it is worth knowing it exists.

### 5.1 C2 configuration TLVs (never encrypted — CONFIG packets)

[source: `packet.rb:114-139`]

| TLV | Value | Purpose |
|---|---|---|
| `TLV_TYPE_SESSION_EXPIRY` | `UINT \| 700` | session expiration |
| `TLV_TYPE_EXITFUNC` | `UINT \| 701` | **exit function selection** |
| `TLV_TYPE_DEBUG_LOG` | `STRING \| 702` | debug log path |
| `TLV_TYPE_EXTENSION` | `GROUP \| 703` | extension info |
| `TLV_TYPE_C2` | `GROUP \| 704` | a C2/transport grouping |
| `TLV_TYPE_C2_COMM_TIMEOUT` | `UINT \| 705` | |
| `TLV_TYPE_C2_RETRY_TOTAL` | `UINT \| 706` | |
| `TLV_TYPE_C2_RETRY_WAIT` | `UINT \| 707` | |
| `TLV_TYPE_C2_URL` | `STRING \| 708` | `scheme://host:port/uri` |
| `TLV_TYPE_C2_URI` | `STRING \| 709` | appended URI (HTTP/S) |
| `TLV_TYPE_C2_PROXY_URL` | `STRING \| 710` | **proxy** |
| `TLV_TYPE_C2_PROXY_USER` | `STRING \| 711` | |
| `TLV_TYPE_C2_PROXY_PASS` | `STRING \| 712` | |
| `TLV_TYPE_C2_GET` | `GROUP \| 713` | GET param group |
| `TLV_TYPE_C2_POST` | `GROUP \| 714` | POST param group |
| `TLV_TYPE_C2_HEADERS` | `STRING \| 715` | custom headers |
| `TLV_TYPE_C2_UA` | `STRING \| 716` | user agent |
| `TLV_TYPE_C2_UUID_HEADER` | `STRING \| 725` | **which header carries the UUID** |

This block is the **malleable C2 profile**, expressed as protocol fields. Proxy support,
custom headers, custom UA, configurable GET/POST parameter names, retry timing, and a
configurable UUID header name — the implant can be told to blend its traffic at runtime.

Also notable: `TLV_TYPE_EXITFUNC` (701) — the implant is told **which exit function to use**,
i.e. how to terminate. And `TLV_TYPE_PIVOT_ID` / `TLV_TYPE_PIVOT_STAGE_DATA` /
`TLV_TYPE_PIVOT_NAMED_PIPE_NAME` at 650/651/653 [source: `packet.rb:107-109`].

---

## 6. Handlers — how a session returns

**Directory:** `lib/msf/core/handler/` — 26 handler implementations.

### 6.1 Reverse handlers

| Handler | File size | Notes |
|---|---|---|
| `reverse_tcp` | 6.7 KB | classic reverse connect |
| `reverse_http` | **18.7 KB** | largest — HTTP staging + callback |
| `reverse_https` | 1.0 KB | thin subclass of reverse_http |
| `reverse_named_pipe` | 1.4 KB | Windows named pipe |
| `reverse_tcp_ssl` | 2.1 KB | TLS-wrapped reverse TCP |
| `reverse_tcp_double` | 7.4 KB | **two-stage connection** |
| `reverse_tcp_double_ssl` | 9.0 KB | double + TLS |
| `reverse_tcp_all_ports` | 1.1 KB | |
| `reverse_udp` | 8.9 KB | |
| `reverse_sctp` | 6.5 KB | SCTP transport |
| `reverse_ssh` | 5.4 KB | SSH transport |
| `reverse\comm.rb` | 1.3 KB | shared comm logic |
| `reverse\ssl.rb` | 0.5 KB | shared SSL logic |

### 6.2 Bind and cloud handlers

`bind_tcp` (6.3 KB), `bind_named_pipe` (12.8 KB), `bind_udp` (5.8 KB), `bind_sctp` (5.1 KB),
plus two notable **cloud API** handlers:

- `bind_aws_instance_connect.rb` (11 KB)
- `bind_aws_ssm.rb` (12.2 KB)

**C2 over AWS Systems Manager and EC2 Instance Connect.** This is a genuinely different
exfil/C2 posture from every other target in this corpus: the traffic is legitimate AWS API
traffic to AWS endpoints, authenticated with normal AWS credentials. There is no attacker-owned
listener to find and no anomalous destination — the destination *is* Amazon. Detection has to
move to behavioural/credential analysis rather than network indicators. This is the most
interesting handler finding in T7 and it deserves to be called out on its own.

### 6.3 The double-transport handlers

`reverse_tcp_double` (7.4 KB) and `reverse_tcp_double_ssl` (9.0 KB) implement a **two-connection
staging design** — the session is split across two separate TCP connections. Worth flagging
because it is a deliberate architectural choice to complicate single-flow detection and
reassembly.

### 6.4 Discovery handlers

`find_port`, `find_shell`, `find_tag`, `find_tty` — utilities for locating an existing session
or shell rather than creating one.

---

## 7. Stager → stage chain

Metasploit's staging model, structurally:

```
stager (small)  --[network]-->  stage (large, e.g. meterpreter)
```

The stager is deliberately tiny, connects back, and downloads/executes the stage. This is why
`reverse_http` is by far the largest handler: HTTP staging needs URI checksums, request
verification, and payload delivery logic.

`lib/rex/payloads/meterpreter/uri_checksum.rb` (referenced via `include` in `client_core.rb`)
implements a **URI checksum scheme** — the staging URI encodes a checksum so the handler can
distinguish a genuine stager callback from a scanner or researcher probing the endpoint. That
is an anti-detection measure built into the staging path.

**Detailed stager/stage byte-level analysis was NOT completed.** See §9.

---

## 8. Encoders

**Directory:** `lib/rex/encoder/` and `lib/rex/payloads/`

Not analyzed in this pass. Recorded as a gap. The encoder family (including the well-known
polymorphic `shikata_ga_nai`) is a distinct subsystem and deserves its own pass — it is a
**payload-obfuscation** topic, separate from the wire protocol that is this report's focus, so
the gap is defensible but real.

---

## 9. Scope boundaries — what was NOT covered

Stated explicitly so this report is not over-read:

1. **The stager/stage byte-level chain** — the actual staging protocols and the key negotiation
   *during* staging were not traced in detail. The §7 description is structural.
2. **Encoders** (`lib/rex/encoder/`) — not analyzed at all.
3. **Handlers** — enumerated and sized (§6) but the individual `reverse_*`/`bind_*`
   implementations were not read line-by-line. The AWS handlers are named from the file
   inventory and their significance is inferred from their names and size, not from reading
   them.
4. **The ~4,000 modules** (`modules/`) — deliberately not enumerated. Not in scope.
5. **The meterpreter implant itself** — not on disk, not in this repo. All implant-side
   behaviour (injection technique, persistence, evasion, AMSI interaction) is **unknown and
   unrecoverable from this target.**
6. **`packet_dispatcher.rb` (22.7 KB)** and `client_core.rb` beyond the negotiation path —
   only partially read.
7. **The `tlv.rb` extension files** (21 of them, incl. `stdapi/tlv.rb` 11.9 KB,
   `extapi/tlv.rb` 8.3 KB, `android/tlv.rb` 5.7 KB) — inventoried, not analyzed. These define
   the per-extension TLV and command namespaces and are the path to the full post-exploitation
   command surface.
8. **No binary evidence of any kind.** No compiled meterpreter, no `msfvenom` output, no
   runtime capture. Every claim in this report is `[source]`.
9. `lib/rex/post/meterpreter/packet.rb` is 1,120 lines; §2 covers the header/protocol core
   (~lines 795–1,031) and the constant blocks. The TLV encoding helpers at 460–560 were read
   for the packing primitives but not exhaustively.

---

## 10. Cross-target comparison

| Dimension | Metasploit (T7) | Sliver (T1) | Havoc (T5) | Pupy (T6) |
|---|---|---|---|---|
| Wire framing | **32-byte header + XOR(4-byte key)** | gRPC/HTTP | `[SIZE][0xDEADBEEF][AgentID][CmdID][ReqID]` | rpyc over transport |
| Bulk cipher | **AES-128/256-CBC, IV per packet** | *(pending)* | AES-256-CTR, **fixed IV** | RC4, drop-3072 |
| KEX | **RSA-2048 → AES, implant-chosen key** | *(pending)* | AES key **cleartext** at register | ECPV brainpoolP384r1 |
| Transport resilience | **runtime-mutable transport list + AWS SSM/IC** | WireGuard/HTTP/gRPC | profile-driven | obfs3/WebSocket |
| Obfuscation layer | XOR (weak, disclosed) | — | — | obfs3 (strong) |
| Known design weakness | **decrypt path doesn't enforce enc-type match (TODO in source)** | — | fixed IV reuse | RC4 by spec |

**The distinctive Metasploit contribution** is not its crypto — CBC with a per-packet IV is
sound, but the XOR layer is decoration and the protocol carries a self-documented weakness. Its
genuine advantages are (a) **runtime-mutable transports with failover**, and (b) **C2 over
legitimate AWS APIs**, which is a detection problem rather than a network problem. Those two
things are the reason Metasploit belongs in this corpus despite being a general exploitation
framework rather than a purpose-built C2.

---

## 11. Reproducing this

```powershell
$m = "C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\metasploit"
# the protocol core — header layout is documented in-source at :795-841
Get-Content "$m\lib\rex\post\meterpreter\packet.rb" | Select-Object -Skip 794 -First 47
# key negotiation
Get-Content "$m\lib\rex\post\meterpreter\client_core.rb" | Select-Object -Skip 775 -First 40
# command IDs
Get-Content "$m\lib\rex\post\meterpreter\core_ids.rb"
# handlers
Get-ChildItem "$m\lib\msf\core\handler" -Recurse -File -Filter *.rb
```
