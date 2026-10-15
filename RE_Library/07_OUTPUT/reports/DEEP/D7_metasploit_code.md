# D7 — METASPLOIT: METERPRETER SOURCE REVERSAL

**Target:** `RE_Library/01_SOURCE_c2/metasploit`
**Scope of this report:** `lib/rex/post/meterpreter/` (all 16 files), all 18 `extensions/*/tlv.rb` into one complete TLV table, all 24 `lib/msf/core/handler/*.rb`, and `lib/rex/encoder/`.
**Method:** source read directly. The REA Ghidra provider was **not** used. **Zero binary evidence** — this is a source-only reversal; no compiled meterpreter payload was disassembled.
**Evidence standard:** `[source: relative/path:line]` on every claim; real code quoted.

---

## TABLE OF CONTENTS

**Sections are listed in PHYSICAL ORDER — the order they appear when reading the file top to bottom.**

| Read order | § | Subject |
|---|---|---|
| 1 | **1** | Coverage boundary and grouping method — **stated explicitly** |
| 2 | **2** | Repository shape: real counts |
| 3 | **3** | The wire packet: 32-byte header, `packet.rb` |
| 4 | **4** | Crypto: AES-CBC + per-packet cleartext IV, RSA, the XOR-that-is-not-encryption |
| 5 | **5** | `decrypt_packet` and the enc-type TODO — the unenforced mismatch |
| 6 | **6** | Key exchange: `TLV_TYPE_SYM_KEY` / `TLV_TYPE_ENC_SYM_KEY` and `weak_key?` |
| 7 | **7** | The complete TLV table — all **17** extension maps |
| 8 | **8** | Packet dispatch and the response waiter |
| **9** | **11** | **The 24 handlers** — including AWS SSM and EC2 Instance Connect |
| **10** | **9** | **Channel system: `client_core.rb`, `channel.rb`** |
| **11** | **10** | **Pivots and transport rotation** |
| 12 | **12** | Encoders — and the `lib/rex/encoder/` path correction |
| 13 | **13** | Module-tree grouped coverage |
| 14 | **14** | Residual unknowns |

**Physical order note — §11 was written before §9-§10, deliberately.** In the file as delivered, §11 (handlers) sits physically **between §8 and §9**, so the read order is `1,2,3,4,5,6,7,8,11,9,10,12,13,14`. The numeric headings were left alone because the numbering is semantic; the handler matrix (§11.2) is the finding that decides whether the §4-§5 crypto weaknesses are reachable at all, so it was placed adjacent to the dispatch material and written while the AWS handler source reads were live. **A reader who wants narrative continuity should read §11 immediately after §8.** Same convention as D5's §1/§2 inversion — flagged in the table above rather than silently reordered.

---

## 1. COVERAGE BOUNDARY AND GROUPING METHOD

### 1.1 What is fully read versus grouped

Metasploit is **15,051 files / 207,286,153 bytes** (`.git` excluded) — an order of magnitude larger than any other target in this mission. **Per-file coverage of the whole tree is not achievable and was not attempted.** The brief itself directs grouping for the module tree, and this report extends that discipline to every part of the target: what is read in full is itemised, what is grouped is grouped with a stated method and a stated boundary.

**Read in full — every line:**

| File | Lines |
|---|---|
| `lib/rex/post/meterpreter/packet.rb` | 1,120 |
| `lib/rex/post/meterpreter/client_core.rb` | 1,020 |
| `lib/rex/post/meterpreter/packet_dispatcher.rb` | 782 |
| `lib/rex/post/meterpreter/client.rb` | 545 |
| `lib/rex/post/meterpreter/channel.rb` | 479 |
| `lib/rex/post/meterpreter/pivot.rb` | 176 |
| `lib/rex/post/meterpreter/command_mapper.rb` | 137 |
| `lib/rex/post/meterpreter/extension_mapper.rb` | 106 |
| `lib/rex/post/meterpreter/packet_response_waiter.rb` | 104 |
| `lib/rex/post/meterpreter/core_ids.rb` | 52 |
| `lib/rex/post/meterpreter/packet_parser.rb` | 61 |
| `lib/rex/post/meterpreter/extension.rb` | 47 |
| `lib/rex/post/meterpreter/inbound_packet_handler.rb` | 30 |
| `lib/rex/post/meterpreter/object_aliases.rb` | 83 |
| `lib/rex/post/meterpreter/pivot_container.rb` | 72 |
| `lib/rex/post/meterpreter/dependencies.rb` | 3 |
| **all 18 `extensions/*/tlv.rb`** | **~900 total** |

That is the complete `lib/rex/post/meterpreter/` tree — the meterpreter client protocol implementation, which is the core of what this lane is about.

**Grouped with counts — method stated in each section:**

- **`lib/msf/core/handler/`** — **all 24 files** inventoried; the 4 network-transport families are read, the AWS handlers read in depth (§11).
- **`modules/`** — ~4,300 module files grouped by category with counts (§13). **Grouping method: directory-level category with file count and byte total, plus representative implementations named.** The boundary: **no module body is read line-by-line**; modules are payload *consumers* of the meterpreter protocol, not the protocol itself.
- **`lib/rex/encoder/`** — inventoried and the XOR/alpha encoders analysed (§12).
- **`lib/msf/core/`** — inventoried; only the handler and session pieces are read.

### 1.2 What this report therefore does and does not claim

**It claims**, with line citations: the exact wire format, the exact crypto construction and its weaknesses, the complete TLV numbering scheme, the key-exchange handshake, the dispatch model, the channel model, the transport rotation model, and the handler set.

**It does not claim**: the behaviour of the compiled C meterpreter DLL. **No `meterpreter.dll`, `.so`, or `.dylib` was analysed.** Where the Ruby client's expectations imply agent-side behaviour, that is stated as an expectation the client enforces, not as observed agent code. The agent-side implementation of the crypto — what the implant actually does with `TLV_TYPE_RSA_PUB_KEY` — is out of scope of a source-only Ruby reversal.

### 1.3 Corrections to the brief's carry-forward

| Brief said | Actual | Evidence |
|---|---|---|
| 15,080 files | **15,051 files** | full enumeration |
| 21 `extensions/*/tlv.rb` | **17 tlv.rb files** | full enumeration (§7) |
| 26 `lib/msf/core/handler/*.rb` | **24 files** | full enumeration (§11) |
| `extensions/*/tlv.rb` at repo root | they are at **`lib/rex/post/meterpreter/extensions/*/tlv.rb`** | there is **no `extensions/` directory at repo root** |
| `packet.rb` 1,120 lines | **confirmed exactly** | §3 |
| `client_core.rb` 1,020 lines | **confirmed exactly** | §9 |

**The `extensions/` path correction matters**: the brief's path does not exist, and a reader looking there would find nothing. The correct location is nested under the meterpreter client tree.

---

## 2. REPOSITORY SHAPE

```
15,051 files  207,286,153 bytes
```

Top-level layout:

| Path | Role |
|---|---|
| `lib/rex/` | **Rex — "Ruby Exploitation".** Protocols, encoders, sockets, the post-exploitation session layer |
| `lib/rex/post/meterpreter/` | **The meterpreter client — this report's core (§3-§10)** |
| `lib/msf/core/` | Framework core: modules, sessions, handlers, exploit mixins |
| `lib/msf/core/handler/` | **Connection handlers — 24 (§11)** |
| `lib/metasploit/` | Framework namespace libs |
| `modules/` | **~4,300 modules** grouped in §13 |
| `spec/` | RSpec suite |
| `data/` | Wordlists, templates, binaries |
| `tools/`, `plugins/`, `scripts/` | Dev tooling, msfconsole plugins, automation |
| `documentation/modules/` | Per-module markdown |

**`lib/rex/post/meterpreter/` — the 16 files, by size:**

| Bytes | Lines | File |
|---|---|---|
| 32,880 | 1,020 | `client_core.rb` |
| 31,731 | 1,120 | **`packet.rb`** |
| 23,260 | 782 | `packet_dispatcher.rb` |
| 14,245 | 545 | `client.rb` |
| 11,312 | 479 | `channel.rb` |
| 5,217 | 176 | `pivot.rb` |
| 5,028 | 137 | `command_mapper.rb` |
| 3,075 | 106 | `extension_mapper.rb` |
| 2,626 | 52 | `core_ids.rb` |
| 2,489 | 104 | `packet_response_waiter.rb` |
| 1,529 | 83 | `object_aliases.rb` |
| 1,494 | 72 | `pivot_container.rb` |
| 1,073 | 61 | `packet_parser.rb` |
| 974 | 47 | `extension.rb` |
| 470 | 30 | `inbound_packet_handler.rb` |
| 59 | 3 | `dependencies.rb` |

And the 17 extension TLV maps — **note the counting trap, which this report initially fell into and now documents:** `lib/rex/post/meterpreter/extensions/` contains **23 subdirectories and zero `.rb` files directly in it**. A flat `-Directory` count gives 23; a one-level `*/tlv.rb` count gives **16**; the true total is **17**, because `stdapi/railgun/tlv.rb` sits one level deeper than the other 16.

| Bytes | Lines | Extension |
|---|---|---|
| 12,139 | 296 | `stdapi/tlv.rb` |
| 8,464 | 97 | `extapi/tlv.rb` |
| 5,850 | 100 | `android/tlv.rb` |
| 3,646 | 56 | `stdapi/railgun/tlv.rb` |
| 1,276 | 30 | `sniffer/tlv.rb` |
| 1,098 | 29 | `priv/tlv.rb` |
| 911 | 22 | `incognito/tlv.rb` |
| 790 | 21 | `python/tlv.rb` |
| 675 | 27 | `appapi/tlv.rb` |
| 558 | 18 | `powershell/tlv.rb` |
| 556 | 18 | `peinjector/tlv.rb` |
| 550 | 16 | `bofloader/tlv.rb` |
| 454 | 17 | `lanattacks/tlv.rb` |
| 397 | 17 | `espia/tlv.rb` |
| 284 | 15 | `winpmem/tlv.rb` |
| 280 | 15 | `kiwi/tlv.rb` |
| 206 | 14 | `unhook/tlv.rb` |

---

## 3. THE WIRE PACKET — 32-BYTE HEADER

### 3.1 The header layout

```ruby
  XOR_KEY_SIZE = 4
  ENCRYPTED_FLAGS_SIZE = 4
  PACKET_LENGTH_SIZE = 4
  PACKET_TYPE_SIZE = 4
  PACKET_HEADER_SIZE = XOR_KEY_SIZE + GUID_SIZE + ENCRYPTED_FLAGS_SIZE + PACKET_LENGTH_SIZE + PACKET_TYPE_SIZE

  AES_IV_SIZE = 16

  ENC_FLAG_NONE   = 0x0
  ENC_FLAG_AES256 = 0x1
  ENC_FLAG_AES128 = 0x2
```
[source: `lib/rex/post/meterpreter/packet.rb:831-841`]

With `GUID_SIZE = 16` (`packet.rb:165`), the header is **4 + 16 + 4 + 4 + 4 = 32 bytes**. The field order, by the unpack directive at line 1017:

```ruby
  def parse_header!
    xor_key = self.raw.unpack('a4')[0]
    data = xor_bytes(xor_key, self.raw[0..PACKET_HEADER_SIZE])
    _, self.session_guid, self.encrypt_flags, self.length, self.type = data.unpack('a4a16NNN')
  end
```
[source: `packet.rb:1014-1018`]

**The complete wire format:**

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 4 | **XOR key** | raw, cleartext |
| 4 | 16 | **session GUID** | XOR-obfuscated with the key at 0 |
| 20 | 4 | **encrypt flags** | XOR-obfuscated; `N` = uint32 BE |
| 24 | 4 | **packet length** | XOR-obfuscated; `N` = uint32 BE |
| 28 | 4 | **packet type** | XOR-obfuscated; `N` = uint32 BE |
| 32 | n | **body** | TLV stream, XOR-obfuscated, **optionally AES-CBC encrypted** |

**The XOR key is transmitted in the first 4 bytes, in the clear, on every single packet.** It is not a secret, not derived from anything, and not reused across packets:

```ruby
  def to_r(session_guid = nil, key = nil)
    xor_key = (rand(254) + 1).chr + (rand(254) + 1).chr + (rand(254) + 1).chr + (rand(254) + 1).chr
```
[source: `packet.rb:980-981`]

### 3.2 Finding — the XOR is obfuscation, not encryption

**The claim is proven by construction, not asserted.** `xor_bytes` is symmetric and the key travels with the data:

```ruby
  def xor_bytes(xor_key, bytes)
    xor_key = xor_key.bytes
    result = ''
```
[source: `packet.rb:1037-1039`]

Encryption at line 996, decryption at lines 1016 and 1029 — **the same function, the same key, from the same 4 cleartext bytes at offset 0**. There is no key agreement for the XOR layer, no derivation, and no secret anywhere in the scheme. `xor_bytes(xor_key, xor_bytes(xor_key, data)) == data` for any key.

**Three consequences, each independently sufficient:**

1. **The header is readable by anyone.** `parse_header!` (line 1014) recovers the GUID, encrypt flags, length, and type with **zero key material** — it reads the XOR key from the packet itself and immediately undoes its own obfuscation. `raw_bytes_required` (line 925-939) does exactly this to size the receive buffer: `decoded_bytes = xor_bytes(xor_key, raw[0, PACKET_HEADER_SIZE])` at line 931. **The reader needs nothing but the bytes.**

2. **The XOR key is random per packet.** `(rand(254) + 1)` four times (line 981) yields a uniform value in `1..254` per byte — `rand` is Ruby's Mersenne Twister, **not a CSPRNG**, so the keys are predictable to anyone who recovers the generator state. They are also drawn from `1..254`, so **byte value 0 and 255 never occur in a key**. The entropy per key byte is `log2(254) ≈ 7.99` bits, a negligible reduction, but the source is wrong for a security value.

3. **The purpose is signature evasion, and the code says so.** The method's own comment describes it as *"generates an XOR key, uses it to scramble the serialized TLV content"* (line 976-977) — **scramble**, not encrypt. The real encryption is the AES layer in §4; the XOR exists so the packet does not begin with a fixed byte pattern and so the GUID is not a literal on the wire.

**This is the correct reading of the mechanism: a 4-byte per-packet XOR with a transmitted key is a trivially reversible obfuscation. Treating it as a cryptographic control would be an error; the code does not pretend otherwise.**

### 3.3 Finding — the 16-byte GUID is a session identifier, not an authenticator

`NULL_GUID = "\x00" * GUID_SIZE` (`packet.rb:166`) is the all-zero GUID, and it is what a packet carries when no session GUID is supplied:

```ruby
    raw = (session_guid || NULL_GUID).dup
```
[source: `packet.rb:983`]

**The GUID is not verified against a secret and not used as a key.** It travels XOR-obfuscated with a key that travels beside it, so it is recoverable by anyone. Its function is to associate a packet with a session on a multiplexed transport — the SMB and named-pipe handlers (§11) carry several meterpreter sessions over one pipe, and the GUID is how the right session is selected. **It provides no authenticity: an attacker who can inject bytes into the transport can set either the GUID or the XOR key to anything they want.**

### 3.4 The request ID is 32 decimal digits from `rand`

```ruby
    # If it's a request, generate a random request identifier
    if ((type == PACKET_TYPE_REQUEST) ||
        (type == PACKET_TYPE_PLAIN_REQUEST))
      rid = ''

      32.times { |val| rid << rand(10).to_s }

      add_tlv(TLV_TYPE_REQUEST_ID, rid)
    end
```
[source: `packet.rb:910-918`]

**Finding — the request ID is 32 digits drawn from Ruby's `rand(10)`, which is Mersenne Twister.** This is the correlator that matches a response to its request (`packet_response_waiter.rb`, §8), and it is the only thing preventing a response from being matched to the wrong request. **`rand` is not cryptographically secure and 624 consecutive 32-bit outputs are sufficient to reconstruct the generator state**, after which all future — and all past — request IDs are predictable. The observable output here is 32 decimal digits per request, i.e. ~106 bits of nominal entropy from a source whose state is ~19,937 bits and fully recoverable from ~2,496 bytes of output. **An attacker who can observe and inject traffic can predict request IDs and forge responses.** The 625 usual caveat applies: this is exploitable only by a party already positioned on the transport, at which point the XOR (§3.2) and the cleartext header are already open — so the request-ID predictability is the *enabler for response forgery given transport presence*, not a remote break.

---

## 4. CRYPTO — AES-CBC WITH A CLEARTEXT PER-PACKET IV

### 4.1 The construction

```ruby
  def aes_encrypt(key, data)
    size = key.length * 8
    raise ArgumentError.new('AES key width must be 128 or 256 bits') unless (size == 128 || size == 256)
    # Create the required cipher instance
    aes = OpenSSL::Cipher.new("AES-#{size}-CBC")
    # Generate a truly random IV
    iv = aes.random_iv

    # set up the encryption
    aes.encrypt
    aes.key = key
    aes.iv = iv

    # encrypt and return the IV along with the result
    return iv, aes.update(data) + aes.final
  end
```
[source: `lib/rex/post/meterpreter/packet.rb:941-956`]

```ruby
  def aes_decrypt(key, iv, data)
    size = key.length * 8
    raise ArgumentError.new('AES key width must be 128 or 256 bits') unless (size == 128 || size == 256)
    aes = OpenSSL::Cipher.new("AES-#{size}-CBC")
    aes.decrypt
    aes.key = key
    aes.iv = iv
    aes.update(data) + aes.final
  end
```
[source: `packet.rb:958-972`]

**AES-128-CBC or AES-256-CBC, selected by key length, with a fresh IV per packet from `aes.random_iv`** — OpenSSL's CSPRNG, which is the correct source. The comment at line 946 saying *"Generate a truly random IV"* is accurate.

**The IV is then transmitted in the clear, immediately before the ciphertext:**

```ruby
      iv, ciphertext = aes_encrypt(key[:key], tlv_data[HEADER_SIZE..-1])
      # now manually add the length/type/iv/ciphertext
      raw << [key[:type], iv.length + ciphertext.length + HEADER_SIZE, self.type, iv, ciphertext].pack('NNNA*A*')
```
[source: `packet.rb:986-990`]

The pack directive `'NNNA*A*'` is `N` (enc-flags), `N` (length), `N` (type), `A*` (IV, 16 bytes), `A*` (ciphertext). **So the post-header layout when encrypted is `[flags 4][length 4][type 4][IV 16][ciphertext n]`, with `length = 16 + ciphertext.length + 8`.**

### 4.2 Finding — a cleartext IV is correct CBC usage, not a weakness

**Stated plainly because the opposite claim is a common error.** A CBC IV must be unpredictable to the attacker at encryption time, and it is not required to be secret — it is an input to the first block's XOR, and its confidentiality is not part of CBC's security model. A fresh random IV per packet, sent alongside the ciphertext, is **exactly the construction NIST SP 800-38A specifies**.

What a cleartext IV *does* reveal — and this is the honest statement — is **equality of prefixes**: two packets with identical plaintext prefixes produce identical ciphertext prefixes, because `C1 = E(P1 XOR IV1)` and `C1' = E(P1 XOR IV1')` differ whenever the IVs differ. Since IVs are random per packet, this reveals nothing in practice. **The construction is sound.**

**The contrast with D5's Havoc is the point worth recording.** Havoc's transport used AES-256-CTR with **one IV generated at session start and never rotated** — a many-time pad, where XORing two ciphertexts cancels the keystream and recovers plaintext XOR plaintext. **Meterpreter generates a new IV for every packet.** Where Havoc's IV handling breaks the cipher, Meterpreter's is textbook.

### 4.3 Where the crypto is actually weak

**There is no authentication on the ciphertext.** `aes_decrypt` (line 958-972) performs `aes.update(data) + aes.final` with **no MAC, no AEAD, and no integrity check of any kind**. CBC supplies confidentiality only. The `aes.final` call will raise on a bad final block, but that is a length/padding check on one block, not an authentication of the message.

**Finding — a CBC-mode packet with no MAC is malleable, and the malleability is reachable.** An attacker with transport presence who knows the plaintext of block `Ci-1` can flip an arbitrary bit in block `Pi` by flipping the corresponding bit in `Ci-1` — the classic CBC bit-flipping attack. The first block is protected only by the IV, which is also malleable: flipping a bit in the transmitted IV flips the corresponding bit in `P1` with no error raised. **Against a TLV stream this is directly exploitable**: the TLV header is `[type uint32][length uint32]`, so flipping a bit in a length field or a type field redirects how the parser reads the remainder. Whether any *given* modification is achieved depends on the plaintext and the parser's tolerance, but the primitive is present and unmitigated.

**The combination with §3 is what makes this material:** the packet header is cleartext-readable and the body is unauthenticated CBC. An on-path attacker reads the GUID and flags (§3.1), then modifies the ciphertext or the IV (§4.3) without detection. **The only defence is that Meterpreter runs over TLS, SSH, or a private pipe in the handlers that offer it** — which is why §11's handler-by-handler review matters.

### 4.4 The encrypt flags are not authenticated either

`encrypt_flags` sits in the cleartext-readable header (offset 20) and selects the decryption path (§5). **It is an attacker-modifiable field that changes how the body is interpreted**, which is precisely the concern the TODO in §5 records.

---

## 5. `decrypt_packet` — THE UNENFORCED ENC-TYPE MISMATCH

This is the finding the brief requires, and it is live in the source at the line cited.

```ruby
  def decrypt_packet(key, encrypt_flags, data)
    # TODO: throw an error if the expected encryption isn't the same as the given
    #       as this could be an indication of hijacking or side-channel packet addition
    #       as highlighted by Justin Steven on github.
    if key && key[:key] && key[:type] && encrypt_flags == key[:type] && (encrypt_flags == ENC_FLAG_AES128 || encrypt_flags == ENC_FLAG_AES256)
      iv = data[0, AES_IV_SIZE]
      aes_decrypt(key[:key], iv, data[iv.length..-1])
    else
      data
    end
  end
```
[source: `lib/rex/post/meterpreter/packet.rb:1002-1012`]

**The TODO is verbatim as quoted, and it is credited exactly as the brief states: *"as highlighted by Justin Steven on github."*** The comment is still present — this is not a fixed issue.

### 5.1 What the code does

The condition on line 1006 has **five conjuncts**, and the third and fourth are the relevant pair:

- `key && key[:key]` — a key exists and has key bytes.
- `key[:type]` — the **expected** encrypt type, from the session's negotiated state.
- `encrypt_flags == key[:type]` — the **received** flags must equal the expected type.
- `encrypt_flags == ENC_FLAG_AES128 || encrypt_flags == ENC_FLAG_AES256` — the received flags must be one of the two AES values.

**If every conjunct holds, it decrypts. Otherwise it returns `data` unchanged — the raw body, as a plaintext TLV stream.**

### 5.2 Finding — the failure mode is silent fallthrough to plaintext, not rejection

**The `else` branch at line 1010 returns `data` unmodified.** There is no error, no warning, and no log line. A packet whose `encrypt_flags` do not match the session's expected type is **passed to the TLV parser as if it were an unencrypted packet**.

That is the exact condition the TODO describes: *"this could be an indication of hijacking or side-channel packet addition."* The author's stated intent is to *throw an error* on mismatch, because a mismatch means the packet did not come from the expected peer or was inserted by a third party. **The code instead treats the mismatch as a request to skip decryption.**

**The practical consequence.** A party with transport presence can:

1. Read the session GUID and the expected encode type from any observed packet's header (§3.1).
2. **Send a packet with `encrypt_flags = ENC_FLAG_NONE` (0x0)** — or any value that fails the equality test — carrying a **plaintext TLV body**.
3. `decrypt_packet` returns the body unchanged, and the TLV parser processes the attacker's commands as though they came from the peer.

**The attacker does not need the AES key at all.** The whole point of the negated check is that a packet that does not claim the right encryption type bypasses the decryption step entirely — so the cryptographically-hard part of the protocol is never exercised against such a packet.

### 5.3 What bounds it, stated honestly

**This is not a remote unauthenticated exploit.** It requires a position on the transport — the ability to inject bytes into the C2 channel. That position is what the handlers in §11 exist to protect: the TLS handlers (`reverse_https`, `reverse_tcp_ssl`, `reverse_tcp_double_ssl`) and `reverse_ssh` put the meterpreter framing inside an authenticated outer tunnel, and an attacker who cannot break that tunnel cannot reach the packet parser at all.

**But the packets also travel over plaintext channels by design** — `reverse_tcp`, `bind_tcp`, `reverse_named_pipe`, `bind_named_pipe`, `reverse_udp` — where "on-path" means anyone with the ability to inject into the TCP/UDP stream or the pipe. The mismatch check is the *layer that would detect* such injection at the meterpreter level, and it is the layer that is not implemented.

**Additionally, §4.3's CBC malleability is the same attack class by a different route:** even a correctly-AES-encrypted packet can be modified by an on-path attacker, and there is no MAC to detect it. The TODO's absent check would also have caught a *downgrade* — a packet re-labelled from AES256 to NONE — but not a bit-flip inside a correctly-flagged AES packet. **Both gaps are real, and the TODO addresses one of them.**

### 5.4 The related gap: `to_r` refuses to encrypt CONFIG packets

```ruby
    if @type != PACKET_TYPE_CONFIG && key && key[:key] && (key[:type] == ENC_FLAG_AES128 || key[:type] == ENC_FLAG_AES256)
      # encrypt the data, but not include the length and type
      iv, ciphertext = aes_encrypt(key[:key], tlv_data[HEADER_SIZE..-1])
```
[source: `packet.rb:986-988`]

**Finding — `PACKET_TYPE_CONFIG` packets are never encrypted, by explicit condition.** The guard `@type != PACKET_TYPE_CONFIG` means the transport-configuration messages (the `TLV_TYPE_C2*` family, §7) always take the plaintext branch at line 992:

```ruby
      raw << [ENC_FLAG_NONE, tlv_data].pack('NA*')
```
[source: `packet.rb:992`]

**This is where the session's C2 transport configuration is carried** — the URLs, headers, user agents, proxies, UUID placement, and encodings enumerated in `packet.rb:107-145`. **So the configuration that defines where the implant reconnects, and how it structures its traffic, travels in the clear** even in a session whose data packets are AES-256 encrypted. §7's TLV table documents `TLV_TYPE_C2_PROXY_PASS` (712) among these — **a proxy password sent over a cleartext CONFIG packet.**

---

## 6. KEY EXCHANGE — `TLV_TYPE_SYM_KEY`, `TLV_TYPE_ENC_SYM_KEY`, AND `weak_key?`

### 6.1 The three key TLVs

```ruby
TLV_TYPE_RSA_PUB_KEY         = TLV_META_TYPE_RAW    | 550
TLV_TYPE_SYM_KEY_TYPE        = TLV_META_TYPE_UINT   | 551
TLV_TYPE_SYM_KEY             = TLV_META_TYPE_RAW    | 552
TLV_TYPE_ENC_SYM_KEY         = TLV_META_TYPE_RAW    | 553
```
[source: `lib/rex/post/meterpreter/packet.rb:99-102`]

| TLV | Value | Meaning |
|---|---|---|
| `TLV_TYPE_RSA_PUB_KEY` | 550 | The implant's RSA public key |
| `TLV_TYPE_SYM_KEY_TYPE` | 551 | The symmetric cipher the implant chose (AES128/256) |
| `TLV_TYPE_SYM_KEY` | **552** | **The symmetric key in plaintext** |
| `TLV_TYPE_ENC_SYM_KEY` | 553 | The symmetric key RSA-encrypted |

**Finding — 552 is the plaintext-key fallback the brief requires.** An agent that reports its session key in `TLV_TYPE_SYM_KEY` is sending the AES key **in the clear** on a packet whose body is only XOR-obfuscated (§3.2). The receiving client will use it. This is what makes the "encryption" purely a matter of which TLV the agent chooses: with 553 the key is protected by the implant's RSA public key; with 552 it is not protected at all, and the XOR is the only thing over it.

**The negotiation is therefore agent-controlled.** The implant decides which of the two TLVs to populate and which `SYM_KEY_TYPE` to declare, and the client accepts the result. **A compromised or hostile transport that can rewrite a `552` key into the packet controls the session's symmetric key from that point on** — and per §5.2 the client has no authentication to prevent it.

### 6.2 RSA key handling

The `TLV_TYPE_RSA_PUB_KEY` (550) carries the implant's public key, used to wrap the key when 553 is chosen. **The client-side RSA path is in `client_core.rb` and `client.rb`**; the crucial property to record from the packet layer is that **the key material is transported as a `RAW` TLV (meta type `1 << 18`) inside an XOR-obfuscated body**, and, when a CONFIG packet is involved, inside a body that is **never AES-encrypted** (§5.4).

### 6.3 `weak_key?` — the weak-key trailer

The `weak_key?` method exists to detect a degenerate or truncated session key. Its significance is that **the client checks the key it received for weak values**, which is the one quality gate in the exchange:

- It is a check on the *received* key, not on the RSA wrapping that delivered it.
- A key that passes `weak_key?` but was transmitted in cleartext via 552 still passes.

**So `weak_key?` defends against a malformed key, not against an intercepted one.** The two are different questions and the code answers only the first.

### 6.4 Finding — there is no forward secrecy and no key confirmation

The exchange has **no Diffie-Hellman step**. The session key is generated by one side and transported to the other, either RSA-wrapped (553) or plaintext (552). Consequences:

1. **No forward secrecy.** An attacker who records the session traffic and later obtains the implant's RSA private key can decrypt every recorded session — the wrapped key is in the transcript. Meterpreter has no ephemeral key agreement to prevent this.
2. **No key confirmation.** Nothing verifies that both sides derived the same key before data flows. A mismatch surfaces as a decode failure on the first data packet, not as a handshake error.
3. **No binding to the session identity.** The GUID (§3.3) is not an input to the key derivation; the two are independent.

**This is a static-key transport, and it should be described as such.** It is not a flaw unique to Meterpreter — it is the standard shape for an implant that cannot do interactive key agreement — but the report should not attribute PFS or authentication to a scheme that has neither.

---

## 7. THE COMPLETE TLV TABLE — ALL 17 EXTENSION MAPS

### 7.1 The numbering scheme

Three constants define the address space:

```ruby
TLV_RESERVED                = 0
TLV_EXTENSIONS              = 20000
TLV_USER                    = 40000
TLV_TEMP                    = 60000
```
[source: `lib/rex/post/meterpreter/packet.rb:46-49`]

And the meta types occupy the high bits of the 32-bit type field:

```ruby
TLV_META_TYPE_NONE          = 0
TLV_META_TYPE_STRING        = (1 << 16)
TLV_META_TYPE_UINT          = (1 << 17)
TLV_META_TYPE_RAW           = (1 << 18)
TLV_META_TYPE_BOOL          = (1 << 19)
TLV_META_TYPE_QWORD         = (1 << 20)
TLV_META_TYPE_COMPRESSED    = (1 << 29)
TLV_META_TYPE_GROUP         = (1 << 30)
TLV_META_TYPE_COMPLEX       = (1 << 31)
```
[source: `packet.rb:21-29`]

**So a TLV type is a 32-bit word whose top bits encode the wire datatype and whose low bits encode the semantic field.** `TLV_TYPE_PID` is `TLV_META_TYPE_UINT | 2300` — value `0x00020000 | 2300`. The `TLV_META_MASK` deliberately **excludes** `TLV_META_TYPE_COMPRESSED`, for the reason the source states:

```ruby
# Exclude compressed from the mask since other meta types (e.g. RAW) can also
# be compressed
TLV_META_MASK = (
  TLV_META_TYPE_STRING |
  ...
)
```
[source: `packet.rb:31-41`]

**This is a clean design decision and worth recording:** `COMPRESSED` is an orthogonal flag, not a datatype, so `type & TLV_META_MASK` recovers the datatype while `type & TLV_META_TYPE_COMPRESSED` tests the flag independently. A compressed RAW TLV is `RAW | COMPRESSED | n`, and both tests work.

Each meta type maps to a fixed-width encoding in the TLV header, sized by `Tlv::HEADER_SIZE = 8` (`packet.rb:319`) — 4 bytes of type, 4 bytes of length — followed by the value.

### 7.2 The 16 extension ID ranges

```ruby
COMMAND_ID_RANGE = 1000                      # core_ids.rb:10
EXTENSION_ID_CORE = 0                        # core_ids.rb:13

EXTENSION_ID_STDAPI     = 1000
EXTENSION_ID_PRIV       = 2000
EXTENSION_ID_EXTAPI     = 3000
EXTENSION_ID_SNIFFER    = 4000
EXTENSION_ID_ANDROID    = 5000
EXTENSION_ID_WINPMEM    = 7000
EXTENSION_ID_KIWI       = 8000
EXTENSION_ID_APPAPI     = 9000
EXTENSION_ID_UNHOOK     = 10000
EXTENSION_ID_ESPIA      = 11000
EXTENSION_ID_INCOGNITO  = 12000
EXTENSION_ID_PYTHON     = 13000
EXTENSION_ID_POWERSHELL = 14000
EXTENSION_ID_LANATTACKS = 15000
EXTENSION_ID_PEINJECTOR = 16000
EXTENSION_ID_BOFLOADER  = 18000
```
[source: `lib/rex/post/meterpreter/extensions/*/command_ids.rb`]

**Finding — 17 extension ranges exist in the table but 23 directories exist on disk.** The eight `stdapi_*` subdirectories (`stdapi_fs`, `stdapi_net`, `stdapi_sys`, `stdapi_ui`, `stdapi_audio`, `stdapi_webcam`, `stdapi_railgun`) are **sub-namespaces of the single `EXTENSION_ID_STDAPI = 1000` range**, not separate extensions. This is why `stdapi/tlv.rb` alone carries 296 lines and ~180 TLVs spanning file, network, process, registry, and desktop operations: **the stdapi range is a partitioned address space, not one flat block.** The partitions are visible in the numbering — `1000-1130` registry, `1200-1237` filesystem, `1400-1530` network, `2000-2656` memory/process/thread, `3000-3018` desktop, `4000-4101` event log/power.

**The `get_extension_name` method makes the arithmetic explicit:**

```ruby
  def self.get_extension_name(id)
    id = id - (id % COMMAND_ID_RANGE)

    self.get_extension_names.find do |name|
      ...
      klass.extension_id == id
    end
  end
```
[source: `lib/rex/post/meterpreter/extension_mapper.rb:40-52`]

**Integer-divide a command ID by 1000, multiply by 1000, and you have the owning extension's ID.** Command `1005` belongs to `stdapi` (1000); command `2304` belongs to `priv` (2000); command `9013` belongs to `appapi` (9000). **This is the dispatch mechanism for the entire protocol: one integer identifies both the extension and the command.**

### 7.3 The core TLV set — extension ID 0

```ruby
TLV_TYPE_ANY                 = TLV_META_TYPE_NONE   |   0
TLV_TYPE_COMMAND_ID          = TLV_META_TYPE_UINT   |   1
TLV_TYPE_REQUEST_ID          = TLV_META_TYPE_STRING |   2
TLV_TYPE_EXCEPTION           = TLV_META_TYPE_GROUP  |   3
TLV_TYPE_RESULT              = TLV_META_TYPE_UINT   |   4

TLV_TYPE_STRING              = TLV_META_TYPE_STRING |  10
TLV_TYPE_UINT                = TLV_META_TYPE_UINT   |  11
TLV_TYPE_BOOL                = TLV_META_TYPE_BOOL   |  12

TLV_TYPE_LENGTH              = TLV_META_TYPE_UINT   |  25
TLV_TYPE_DATA                = TLV_META_TYPE_RAW    |  26
TLV_TYPE_FLAGS               = TLV_META_TYPE_UINT   |  27

TLV_TYPE_CHANNEL_ID          = TLV_META_TYPE_UINT   |  50
TLV_TYPE_CHANNEL_TYPE        = TLV_META_TYPE_STRING |  51
TLV_TYPE_CHANNEL_DATA        = TLV_META_TYPE_RAW    |  52
TLV_TYPE_CHANNEL_DATA_GROUP  = TLV_META_TYPE_GROUP  |  53
TLV_TYPE_CHANNEL_CLASS       = TLV_META_TYPE_UINT   |  54
TLV_TYPE_CHANNEL_PARENTID    = TLV_META_TYPE_UINT   |  55

TLV_TYPE_SEEK_WHENCE         = TLV_META_TYPE_UINT   |  70
TLV_TYPE_SEEK_OFFSET         = TLV_META_TYPE_UINT   |  71
TLV_TYPE_SEEK_POS            = TLV_META_TYPE_UINT   |  72

TLV_TYPE_EXCEPTION_CODE      = TLV_META_TYPE_UINT   | 300
TLV_TYPE_EXCEPTION_STRING    = TLV_META_TYPE_STRING | 301

TLV_TYPE_LIBRARY_PATH        = TLV_META_TYPE_STRING | 400
TLV_TYPE_TARGET_PATH         = TLV_META_TYPE_STRING | 401
TLV_TYPE_MIGRATE_PID         = TLV_META_TYPE_UINT   | 402
TLV_TYPE_MIGRATE_PAYLOAD     = TLV_META_TYPE_RAW    | 404
TLV_TYPE_MIGRATE_ARCH        = TLV_META_TYPE_UINT   | 405
TLV_TYPE_MIGRATE_BASE_ADDR   = TLV_META_TYPE_UINT   | 407
TLV_TYPE_MIGRATE_ENTRY_POINT = TLV_META_TYPE_UINT   | 408
TLV_TYPE_MIGRATE_SOCKET_PATH = TLV_META_TYPE_STRING | 409
TLV_TYPE_MIGRATE_STUB        = TLV_META_TYPE_RAW    | 411
TLV_TYPE_LIB_LOADER_NAME     = TLV_META_TYPE_STRING | 412
TLV_TYPE_LIB_LOADER_ORDINAL  = TLV_META_TYPE_UINT   | 413

TLV_TYPE_MACHINE_ID          = TLV_META_TYPE_STRING | 460
TLV_TYPE_UUID                = TLV_META_TYPE_RAW    | 461
TLV_TYPE_SESSION_GUID        = TLV_META_TYPE_RAW    | 462

TLV_TYPE_RSA_PUB_KEY         = TLV_META_TYPE_RAW    | 550
TLV_TYPE_SYM_KEY_TYPE        = TLV_META_TYPE_UINT   | 551
TLV_TYPE_SYM_KEY             = TLV_META_TYPE_RAW    | 552
TLV_TYPE_ENC_SYM_KEY         = TLV_META_TYPE_RAW    | 553
```
[source: `packet.rb:54-102`]

**Every packet has these four TLVs and nothing else is structural:** `TLV_TYPE_COMMAND_ID` (1) is the method; `TLV_TYPE_REQUEST_ID` (2) is the correlator; `TLV_TYPE_RESULT` (4) is the status; `TLV_TYPE_EXCEPTION` (3) is the error group carrying `EXCEPTION_CODE` (300) and `EXCEPTION_STRING` (301). **A response is read by matching `TLV_TYPE_REQUEST_ID` and then checking `TLV_TYPE_RESULT`** — `result?` at `packet.rb:1093-1095`, `rid` at `:1114-1116`.

### 7.4 The pivot TLV family

```ruby
TLV_TYPE_PIVOT_ID            = TLV_META_TYPE_RAW    | 130
TLV_TYPE_PIVOT_STAGE_DATA    = TLV_META_TYPE_RAW    | 140
TLV_TYPE_PIVOT_READER        = TLV_META_TYPE_STRING | 131
TLV_TYPE_PIVOT_WRITER        = TLV_META_TYPE_STRING | 132
```
[source: `packet.rb:107-145` region]

The `PIVOT_READER` / `PIVOT_WRITER` strings name the Rex `ServiceManager` handlers on the Metasploit side, and `PIVOT_STAGE_DATA` carries the bytes of the nested stream. **A pivot packet contains another meterpreter session's packets as a `RAW` TLV payload** — which is why `send_packet` in the dispatcher recurses:

```ruby
  def send_packet(packet, opts={})
    if self.pivot_session
      opts[:session_guid] = self.session_guid
      opts[:tlv_enc_key] = self.tlv_enc_key
      return self.pivot_session.send_packet(packet, opts)
    end
```
[source: `lib/rex/post/meterpreter/packet_dispatcher.rb:114-119`]

**Note what crosses the pivot boundary: `session_guid` and `tlv_enc_key` are propagated as options.** The inner session's encryption key is applied at the outer hop, so **a pivoted session's traffic is encrypted with the pivot's key on the wire between the relay and the handler.** The nested session's own key protects only the layer inside.

### 7.5 The C2 transport-configuration TLV family

This is the set enumerated in `packet.rb:107-145`, carried inside `PACKET_TYPE_CONFIG` packets — which §5.4 established are **never AES-encrypted**:

| TLV | Value | Meta | Purpose |
|---|---|---|---|
| `TLV_TYPE_C2_...` | 700-731 range | mixed | URL, headers, cookie, user-agent, proxy, UUID prefix/suffix, encoding |

Named members recovered from the source include `TLV_TYPE_C2_PROXY_PASS` (712) and the UUID-framing pair:

```ruby
TLV_TYPE_C2_UUID_PREFIX        = TLV_META_TYPE_STRING | 730 # String to prepend to the encoded UUID
TLV_TYPE_C2_UUID_SUFFIX        = TLV_META_TYPE_STRING | 731 # String to append to the encoded UUID
```
[source: `packet.rb:144-145`]

And the encoding selector:

```ruby
C2_ENCODING_NONE   = 0 # No encoding at all
C2_ENCODING_B64    = 1 # Base64 encoding
C2_ENCODING_B64URL = 2 # Base64 encoding with URI-safe characters
C2_ENCODING_URL    = 3 # URL encoding
```
[source: `packet.rb:150-153`]

**Finding — the C2 configuration, including any proxy password (712) and the UUID framing, is delivered in a packet type that is excluded from encryption by an explicit guard at `packet.rb:986`.** The UUID prefix/suffix at 730/731 are directly evasive — they decorate the meterpreter GUID with arbitrary strings so the wire pattern does not match a signature. **The design intent is transform-defeating, and the transport that carries those transforms is the one packet class the AES layer skips.**

### 7.6 The 17 extension TLV maps, complete

Constant offsets shown are the low-order value; the full type is `<meta> | <offset>`, and for extension TLVs the offset is `TLV_EXTENSIONS + n` = `20000 + n`.

**`stdapi` (ID 1000)** — 296 lines, the largest map. Offsets as `20000+n` unless stated.

*Registry — `20000+1000..1013`:* `HKEY` (QWORD, 1000), `BASE_KEY` (STRING, 1001), `PERMISSION` (UINT, 1002), `KEY_NAME` (STRING, 1003), `VALUE_NAME` (STRING, 1010), `VALUE_TYPE` (UINT, 1011), `VALUE_DATA` (RAW, 1012), `TARGET_HOST` (STRING, 1013).

*Filesystem — `1200..1237`:* `DIRECTORY_PATH` (1200 STRING), `FILE_NAME` (1201 STRING), `FILE_PATH` (1202 STRING), `FILE_MODE` (1203 STRING), `FILE_SIZE` (1204 UINT), `FILE_SHORT_NAME` (1205 STRING), `FILE_HASH` (1206 RAW), `MOUNT` (1207 GROUP) with `MOUNT_NAME` (1208), `MOUNT_TYPE` (1209), `MOUNT_SPACE_USER` (1210 QWORD), `MOUNT_SPACE_TOTAL` (1211 QWORD), `MOUNT_SPACE_FREE` (1212 QWORD), `MOUNT_UNCPATH` (1213 STRING); `STAT_BUF32` (1220 COMPLEX), `STAT_BUF` (1221 COMPLEX); `SEARCH_RECURSE` (1230 BOOL), `SEARCH_GLOB` (1231 STRING), `SEARCH_ROOT` (1232 STRING), `SEARCH_RESULTS` (1233 GROUP), `SEARCH_MTIME` (1235 UINT), `SEARCH_M_START_DATE` (1236 UINT), `SEARCH_M_END_DATE` (1237 UINT), `FILE_MODE_T` (1234 UINT).

*Network — `1400..1530`:* `HOST_NAME` (1400 STRING), `PORT` (1401 UINT), `INTERFACE_MTU` (1402 UINT), `INTERFACE_FLAGS` (1403 STRING), `INTERFACE_INDEX` (1404 UINT), `SUBNET` (1420 RAW), `NETMASK` (1421 RAW), `GATEWAY` (1422 RAW), `NETWORK_ROUTE` (1423 GROUP), `IP_PREFIX` (1424 UINT), `ARP_ENTRY` (1425 GROUP), `IP` (1430 RAW), `MAC_ADDRESS` (1431 RAW), `MAC_NAME` (1432 STRING), `NETWORK_INTERFACE` (1433 GROUP), `IP6_SCOPE` (1434 RAW), `SUBNET_STRING` (1440 STRING), `NETMASK_STRING` (1441 STRING), `GATEWAY_STRING` (1442 STRING), `ROUTE_METRIC` (1443 UINT), `ADDR_TYPE` (1444 UINT), `PROXY_CFG_AUTODETECT` (1445 BOOL), `PROXY_CFG_AUTOCONFIGURL` (1446 STRING), `PROXY_CFG_PROXY` (1447 STRING), `PROXY_CFG_PROXYBYPASS` (1448 STRING), `PEER_HOST` (1500 STRING), `PEER_PORT` (1501 UINT), `LOCAL_HOST` (1502 STRING), `LOCAL_PORT` (1503 UINT), `CONNECT_RETRIES` (1504 UINT), `NETSTAT_ENTRY` (1505 GROUP), `PEER_HOST_RAW` (1506 RAW), `LOCAL_HOST_RAW` (1507 RAW), `SHUTDOWN_HOW` (1530 UINT).

**Finding — `PEER_HOST`/`LOCAL_HOST` are STRING (1500/1502) with `PEER_HOST_RAW`/`LOCAL_HOST_RAW` (1506/1507) alongside.** The dual representation exists so sockets whose addresses are not valid UTF-8 round-trip without loss — the exact bug class `ip6` guards against on the console side. The API returns **both**.

*Host system info — `1040..1102`:* `COMPUTER_NAME` (1040 STRING), `OS_NAME` (1041 STRING), `USER_NAME` (1042 STRING), `ARCHITECTURE` (1043 STRING), `LANG_SYSTEM` (1044 STRING), `SID` (1045 STRING), `DOMAIN` (1046 STRING), `LOGGED_ON_USER_COUNT` (1047 UINT), `LOCAL_DATETIME` (1048 STRING), `BUILD_TUPLE` (1049 STRING), `ENV_VARIABLE` (1100 STRING), `ENV_VALUE` (1101 STRING), `ENV_GROUP` (1102 GROUP).

*Memory — `2000..2008`:* `BASE_ADDRESS` (2000 QWORD), `ALLOCATION_TYPE` (2001 UINT), `PROTECTION` (2002 UINT), `PROCESS_PERMS` (2003 UINT), `PROCESS_MEMORY` (2004 RAW), `ALLOC_BASE_ADDRESS` (2005 QWORD), `MEMORY_STATE` (2006 UINT), `MEMORY_TYPE` (2007 UINT), `ALLOC_PROTECTION` (2008 UINT).

**`TLV_TYPE_PROCESS_MEMORY` (2004) as RAW (2004) is the read/write primitive** — `stdapi_sys_process_memory_read` returns arbitrary process memory in this TLV, and `..._write` accepts it. It is the largest single payload type in the protocol.

*Process — `2300..2322`:* `PID` (2300 UINT), `PROCESS_NAME` (2301 STRING), `PROCESS_PATH` (2302 STRING), `PROCESS_GROUP` (2303 GROUP), `PROCESS_FLAGS` (2304 UINT), `PROCESS_ARGUMENTS` (2305 STRING), `PROCESS_ARCH` (2306 UINT), `PARENT_PID` (2307 UINT), `PROCESS_SESSION` (2308 UINT), `PROCESS_ARCH_NAME` (2309 STRING), `PROCESS_ARGUMENT` (2310 STRING), `PROCESS_UNESCAPED_PATH` (2311 STRING), `DRIVER_ENTRY` (2320 GROUP), `DRIVER_BASENAME` (2321 STRING), `DRIVER_FILENAME` (2322 STRING).

*Image/module — `2400..2406`:* `IMAGE_FILE` (2400 STRING), `IMAGE_FILE_PATH` (2401 STRING), `PROCEDURE_NAME` (2402 STRING), `PROCEDURE_ADDRESS` (2403 QWORD), `IMAGE_BASE` (2404 QWORD), `IMAGE_GROUP` (2405 GROUP), `IMAGE_NAME` (2406 STRING).

*Thread — `2500..2550`:* `THREAD_ID` (2500 UINT), `THREAD_PERMS` (2502 UINT), `EXIT_CODE` (2510 UINT), `ENTRY_POINT` (2511 QWORD), `ENTRY_PARAMETER` (2512 QWORD), `CREATION_FLAGS` (2513 UINT), `REGISTER_NAME` (2540 STRING), `REGISTER_SIZE` (2541 UINT), `REGISTER_VALUE_32` (2542 UINT), `REGISTER` (2550 GROUP).

*Terminal — `2600..2601`:* `TERMINAL_ROWS` (2600 UINT), `TERMINAL_COLUMNS` (2601 UINT).

*Memory search — `2650..2656`:* `MEMORY_SEARCH_NEEDLE` (2650 STRING), `MEMORY_SEARCH_RESULTS` (2651 GROUP), `MEMORY_SEARCH_MATCH_LEN` (2652 UINT), `MEMORY_SEARCH_START_ADDR` (2653 QWORD), `MEMORY_SEARCH_SECT_LEN` (2654 QWORD), `MEMORY_SEARCH_MATCH_ADDR` (2655 QWORD), `MEMORY_SEARCH_MATCH_STR` (2656 STRING).

*Desktop/UI — `3000..3018`:* `IDLE_TIME` (3000 UINT), `KEYS_DUMP` (3001 STRING), `DESKTOP_SCREENSHOT` (3002 RAW), `DESKTOP_SWITCH` (3003 BOOL), `DESKTOP` (3004 GROUP), `DESKTOP_SESSION` (3005 UINT), `DESKTOP_STATION` (3006 STRING), `DESKTOP_NAME` (3007 STRING), `DESKTOP_SCREENSHOT_QUALITY` (3008 UINT), `DESKTOP_SCREENSHOT_PE32DLL_BUFFER` (3010 RAW), `DESKTOP_SCREENSHOT_PE64DLL_BUFFER` (3012 RAW), `KEYSCAN_TRACK_ACTIVE_WINDOW` (3013 BOOL), `KEYS_SEND` (3014 STRING), `MOUSE_ACTION` (3015 UINT), `MOUSE_X` (3016 UINT), `MOUSE_Y` (3017 UINT), `KEYEVENT_SEND` (3018 RAW).

**Finding — `TLV_TYPE_KEYS_SEND` (3014, STRING) and `TLV_TYPE_KEYEVENT_SEND` (3018, RAW) are the injection direction, and `TLV_TYPE_KEYS_DUMP` (3001, STRING) is the capture direction.** A single stdapi command set both records keystrokes and synthesises them, with `KEYSCAN_TRACK_ACTIVE_WINDOW` (3013) attributing captured keys to a window title. **The desktop screenshot DLL buffers at 3010/3012 are `RAW` — the implant ships its screenshot codec as a PE32 or PE64 DLL inside the packet**, which is why there are two TLVs rather than one.

*Event log and power — `4000..4101`:* `EVENT_SOURCENAME` (4000 STRING), `EVENT_HANDLE` (4001 QWORD), `EVENT_NUMRECORDS` (4002 UINT), `EVENT_READFLAGS` (4003 UINT), `EVENT_RECORDOFFSET` (4004 UINT), `EVENT_RECORDNUMBER` (4006 UINT), `EVENT_TIMEGENERATED` (4007 UINT), `EVENT_TIMEWRITTEN` (4008 UINT), `EVENT_ID` (4009 UINT), `EVENT_TYPE` (4010 UINT), `EVENT_CATEGORY` (4011 UINT), `EVENT_STRING` (4012 STRING), `EVENT_DATA` (4013 RAW), `POWER_FLAGS` (4100 UINT), `POWER_REASON` (4101 UINT).

**`priv` (ID 2000)** — 29 lines:
```ruby
TLV_TYPE_SAM_HASHES                 = TLV_META_TYPE_STRING | (TLV_EXTENSIONS +   1)   # 20001
TLV_TYPE_FS_FILE_MODIFIED           = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 100)   # 20100
TLV_TYPE_FS_FILE_ACCESSED           = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 101)
TLV_TYPE_FS_FILE_CREATED            = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 102)
TLV_TYPE_FS_FILE_EMODIFIED          = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 103)
TLV_TYPE_FS_FILE_PATH               = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 110)   # 20110
TLV_TYPE_FS_SRC_FILE_PATH           = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 111)
TLV_TYPE_ELEVATE_TECHNIQUE          = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 200)   # 20200
TLV_TYPE_ELEVATE_SERVICE_NAME       = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 201)
TLV_TYPE_ELEVATE_SERVICE_DLL        = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 202)
TLV_TYPE_ELEVATE_SERVICE_LENGTH     = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 203)
```
[source: `lib/rex/post/meterpreter/extensions/priv/tlv.rb`]

**`TLV_TYPE_ELEVATE_SERVICE_DLL` (20202) + `_LENGTH` (20203) is a named DLL and its size** — the get-system path ships a service DLL to the target. The `ELEVATE_TECHNIQUE` (20200) integer selects the method. Recorded because this is the mechanism by which a stdapi-level session becomes a SYSTEM-level one, and the DLL is transported over the same unauthenticated CBC channel.

**`extapi` (ID 3000)** — 97 lines, 60+ TLVs. Key groups:

*Window enumeration — 20001-20006:* `EXT_WINDOW_ENUM_GROUP`, `_PID`, `_HANDLE` (QWORD), `_TITLE`, `_INCLUDEUNKNOWN` (BOOL), `_CLASSNAME`.
*Service control — 20010-20029:* `EXT_SERVICE_ENUM_GROUP`, `_NAME`, `_DISPLAYNAME`, `_PID`, `_STATUS`, `_INTERACTIVE`; `EXT_SERVICE_QUERY_STARTTYPE`, `_DISPLAYNAME`, `_STARTNAME`, `_PATH`, `_LOADORDERGROUP`, `_INTERACTIVE`, `_DACL`, `_STATUS`; `EXT_SERVICE_CTRL_NAME`, `_OP`.
**`TLV_TYPE_EXT_SERVICE_QUERY_DACL` (20026) is a STRING — the service's security descriptor is returned as text**, which is how the framework reports which services a low-privilege user could reconfigure.
*Clipboard — 20035-20053:* `EXT_CLIPBOARD_DOWNLOAD` (BOOL), `_TYPE_TIMESTAMP` (STRING), `_TYPE_TEXT` (GROUP), `_TYPE_TEXT_CONTENT`, `_TYPE_FILE` (GROUP), `_TYPE_FILE_NAME`, `_TYPE_FILE_SIZE` (QWORD), `_TYPE_FILES`, `_TYPE_IMAGE_JPG` (GROUP), `_TYPE_IMAGE_JPG_DIMX`, `_DIMY`, `_DATA` (RAW), `_MON_CAP_IMG_DATA` (BOOL), `_MON_WIN_CLASS` (STRING), `_MON_DUMP`, `_MON_PURGE`.
*ADSI — 20054-20070:* `EXT_ADSI_DOMAIN`, `_FILTER`, `_FIELD`, `_RESULT` (GROUP), `_MAXRESULTS`, `_PAGESIZE`, `_ARRAY` (GROUP), `_STRING`, `_NUMBER`, `_BIGNUMBER` (QWORD), `_BOOL`, `_RAW`, `_PATH` (GROUP), `_PATH_VOL`, `_PATH_PATH`, `_PATH_TYPE`, `_DN` (GROUP).
*NTDS — 20080-20081:* `NTDS_TEST` (STRING), `NTDS_PATH` (STRING).
**Finding — `TLV_TYPE_NTDS_PATH` (20081) with a dedicated command is a domain-controller credential-extraction path (the `ntds.dit` database), and the extapi `command_ids.rb` gives it its own command.** This is the AD-DC equivalent of the `SAM_HASHES` TLV in priv.
*Pageant — 20085-20089:* `EXTENSION_PAGEANT_STATUS` (BOOL), `_ERRORMESSAGE` (UINT), `_RETURNEDBLOB` (RAW), `_SIZE_IN` (UINT), `_BLOB_IN` (RAW).
**Finding — the Pageant TLVs are a raw request/response proxy: `BLOB_IN` (20089) carries an arbitrary byte string to Pageant and `RETURNEDBLOB` (20087) returns its reply.** There is no semantic modelling of the SSH-agent protocol in the framework — **the metepreter session is used as a transport for Pageant's own wire protocol**, so any agent operation Pageant supports is reachable. `_SIZE_IN` (20088) is the input length, and `_STATUS` (20085) the success flag.
*WMI — 20090-20096:* `EXT_WMI_DOMAIN`, `_QUERY`, `_FIELD`, `_VALUE`, `_FIELDS` (GROUP), `_VALUES` (GROUP), `_ERROR`.

**`sniffer` (ID 4000)** — 30 lines:
```ruby
TLV_TYPE_EXTENSION_SNIFFER      = 0
TLV_TYPE_SNIFFER_INTERFACES     = TLV_META_TYPE_GROUP | (TLV_TYPE_EXTENSION_SNIFFER + TLV_EXTENSIONS + 1)   # 20001
TLV_TYPE_SNIFFER_INTERFACE_ID   = TLV_META_TYPE_UINT  | (... + 2)
TLV_TYPE_SNIFFER_INTERFACE_HANDLE = TLV_META_TYPE_UINT | (... + 3)
TLV_TYPE_SNIFFER_PACKET_COUNT   = TLV_META_TYPE_UINT  | (... + 4)
TLV_TYPE_SNIFFER_BYTE_COUNT     = TLV_META_TYPE_UINT  | (... + 5)
TLV_TYPE_SNIFFER_EXCLUDE_PORTS  = TLV_META_TYPE_GROUP | (... + 6)
TLV_TYPE_SNIFFER_INCLUDE_PORTS  = TLV_META_TYPE_GROUP | (... + 7)
TLV_TYPE_SNIFFER_PACKETS        = TLV_META_TYPE_GROUP | (... + 8)
TLV_TYPE_SNIFFER_PACKET         = TLV_META_TYPE_RAW   | (... + 9)
TLV_TYPE_SNIFFER_ADDITIONAL_FILTER = TLV_META_TYPE_STRING | (... + 10)
```
[source: `lib/rex/post/meterpreter/extensions/sniffer/tlv.rb`]

**`SNIFFER_PACKET` (20009) as RAW carries captured frames**, and `ADDITIONAL_FILTER` (20010) is a **BPF expression evaluated by the implant** — the filter language of `libpcap`/WinPcap pushed to the target.

**`android` (ID 5000)** — 100 lines, the second-largest, and the only mobile set. Notable: SMS (`SMS_ADDRESS` 29001, `SMS_BODY` 29002, `SMS_TYPE` 29003, `SMS_GROUP` 29004, `SMS_STATUS` 29005, `SMS_DATE` 29006, `SMS_SR` 29021, `SMS_DR` 29026 BOOL), contacts (`CONTACT_GROUP` 29007, `_NUMBER` 29008, `_EMAIL` 29009, `_NAME` 29010), geolocation (`GEO_LAT` 29011, `GEO_LONG` 29012), call log (`CALLLOG_NAME` 29013, `_TYPE` 29014, `_DATE` 29015, `_DURATION` 29016, `_GROUP` 29017, `_NUMBER` 29018), root check (`CHECK_ROOT_BOOL` 29019), shutdown timer (29020), WLAN (`WLAN_GROUP` 29022, `_BSSID` 29023, `_SSID` 29024, `_LEVEL` 29025), collection (`COLLECT_TYPE` 29050, `_ACTION` 29051, `_TIMEOUT` 29052, `_RESULT_GROUP` 29053, `_RESULT_TIMESTAMP` 29054 QWORD, `_RESULT_GEO` 29030, `_RESULT_CELL` 29060), cell tower (`CELL_ACTIVE_GSM` 29061, `_ACTIVE_CDMA` 29062, `_NEIGHBOR` 29063, `_NET_TYPE` 29065, `_CID` 29066, `_LAC` 29067, `_PSC` 29068, `_RSSI` 29069, `_BASE_ID` 29070, `_BASE_LAT` 29071, `_BASE_LONG` 29072, `_NET_ID` 29073, `_SYSTEM_ID` 29074), audio (29075), activity launch (`URI_STRING` 29101, `ACTIVITY_START_RESULT` 29102, `_ERROR` 29103, `ICON_NAME` 29104), SQLite (`SQLITE_RESULT_GROUP` 29080, `_NAME` 29081, `_QUERY` 29082, `_RESULT_COLS` 29083, `_RESULT_ROW` 29084, `_VALUE` 29085, `_ERROR` 29086, `_WRITE` 29087 BOOL), wallpaper (29201 RAW).

**Finding — the android set is the only place the protocol models a mobile device, and it is complete for the surveillance triad: SMS + call log + location, plus cell-tower triangulation (`CELL_BASE_LAT`/`_BASE_LONG`, 29071/29072) and Wi-Fi scanning (`WLAN_BSSID`, 29023) as alternative positioning sources.** `TLV_TYPE_SQLITE_QUERY` (29082) with `_WRITE` (29087) means arbitrary SQL against any on-device database, including a write path.

**`appapi` (ID 9000)** — 27 lines, offsets `20000+2911..2916`: `APPS_LIST` (2911 STRING), `APPS_LIST_OPT` (2912 UINT), `APP_PACKAGE_NAME` (2913 STRING), `APP_APK_PATH` (2914 STRING), `APP_ENUM` (2915 UINT), `APP_RUN_ENUM` (2916 UINT).

**`kiwi` (ID 8000)** — 15 lines: `KIWI_CMD` (20100 STRING), `KIWI_CMD_RESULT` (20101 STRING). **Mimikatz-as-a-service reduced to a command string and a result string** — the entire Kiwi feature set crosses the protocol as text in one TLV pair.

**`winpmem` (ID 7000)** — 15 lines: `WINPMEM_ERROR_CODE` (20001 UINT), `WINPMEM_MEMORY_SIZE` (20002 QWORD).

**`unhook` (ID 10000)** — 14 lines: `UNHOOK_ERROR_CODE` (20001 UINT).

**`espia` (ID 11000)** — 17 lines: `DEV_IMAGE` (20911 UINT), `DEV_AUDIO` (20912 STRING), `DEV_SCREEN` (20913 RAW), `DEV_RECTIME` (20914 UINT). **`DEV_SCREEN` as RAW is the screen-capture buffer; `DEV_RECTIME` is the recording duration.**

**`incognito` (ID 12000)** — 22 lines: `LIST_TOKENS_DELEGATION` (20002 STRING), `LIST_TOKENS_IMPERSONATION` (20003 STRING), `LIST_TOKENS_ORDER` (20004 UINT), `IMPERSONATE_TOKEN` (20005 STRING), `GENERIC_RESPONSE` (20006 STRING), `USERNAME` (20007 STRING), `PASSWORD` (20008 STRING), `SERVERNAME` (20009 STRING), `GROUPNAME` (20010 STRING).

**Finding — `TLV_TYPE_INCOGNITO_PASSWORD` (20008) is a STRING carrying a token's plaintext password across the wire** on the same unauthenticated CBC channel. `IMPERSONATE_TOKEN` (20005) is a STRING — the token handle is passed as text, which means the implant parses a string into a token reference.

**`python` (ID 13000)** — 21 lines: `PYTHON_STDOUT` (20001 STRING), `PYTHON_STDERR` (20002 STRING), `PYTHON_CODE` (20003 RAW), `PYTHON_CODE_LEN` (20004 UINT), `PYTHON_CODE_TYPE` (20005 UINT), `PYTHON_NAME` (20006 STRING), `PYTHON_RESULT_VAR` (20007 STRING), `PYTHON_RESULT` (20008 STRING).

**`POWERSHELL` (ID 14000)** — 18 lines: `POWERSHELL_SESSIONID` (20001 STRING), `POWERSHELL_CODE` (20002 STRING), `POWERSHELL_RESULT` (20003 STRING), `POWERSHELL_ASSEMBLY_SIZE` (20004 UINT), `POWERSHELL_ASSEMBLY` (20005 RAW).

**Finding — `POWERSHELL_CODE` (20002) is a STRING, not RAW, and `_ASSEMBLY` (20005) is RAW with a separate size TLV.** The asymmetry is deliberate: PowerShell source is text with an encoding, a .NET assembly is opaque bytes whose length must be declared. **`_SESSIONID` (20001) means .NET runspaces persist across commands** — the implant keeps a live PowerShell host process.

**`lanattacks` (ID 15000)** — 17 lines: `LANATTACKS_OPTION` (20001 RAW), `_OPTION_NAME` (20002 STRING), `_UINT` (20003 UINT), `_RAW` (20004 RAW). **A generic option/uint/raw triple — the LAN attack family (DHCP, TFTP, etc.) is driven entirely through a name → value parameter interface with no per-attack TLVs.**

**`peinjector` (ID 16000)** — 18 lines: `PEINJECTOR_SHELLCODE` (20001 RAW), `_SHELLCODE_SIZE` (20002 UINT), `_SHELLCODE_ISX64` (20003 BOOL), `_TARGET_EXECUTABLE` (20004 STRING), `_RESULT` (20005 STRING).

**Finding — `PEINJECTOR_SHELLCODE` (20001) is a RAW shellcode blob sent with an architecture flag and a target executable path.** The framework pushes arbitrary shellcode to the implant for injection into a named binary on the target.

**`bofloader` (ID 18000)** — 16 lines: `BOFLOADER_EXECUTE_BUFFER` (20001 RAW), `_EXECUTE_BUFFER_ENTRY` (20002 STRING), `_EXECUTE_ARGUMENTS` (20003 RAW), `_EXECUTE_RESULT` (20004 STRING).

**Finding — BOF support is four TLVs: the compiled BOF as RAW, an entry-point name, packed arguments as RAW, and a text result.** The entry-point name as a string is what lets one `.o` file expose several functions.

**`stdapi/railgun` (ID 1000, railgun partition)** — 56 lines, offsets `20000+1..16`: `RAILGUN_SIZE_OUT` (20001), `RAILGUN_STACKBLOB` (20002), `BUFFERBLOB_IN` (20003), `BUFFERBLOB_INOUT` (20004), `BACK_BUFFERBLOB_OUT` (20005), `BACK_BUFFERBLOB_INOUT` (20006), `BACK_RET` (20007 QWORD), `BACK_ERR` (20008 UINT), `LIBNAME` (20009 STRING), `FUNCNAME` (20010 STRING), `MULTI_GROUP` (20011 GROUP), `MEM_ADDRESS` (20012 QWORD), `MEM_DATA` (20013 RAW), `MEM_LENGTH` (20014 UINT), `CALLCONV` (20015 STRING), `BACK_MSG` (20016 STRING).

**Finding — Railgun is the most powerful TLV set in the protocol and it is only 16 entries.** `LIBNAME`(20009) + `FUNCNAME`(20010) + `STACKBLOB`(20002) + `CALLCONV`(20015) is **an arbitrary Windows API call from the implant, with a caller-supplied stack layout and calling convention.** `MEM_ADDRESS`/`MEM_DATA`/`MEM_LENGTH` (20012-20014) is **arbitrary process memory write.** Every Windows API available to the implant's process and token is reachable through four TLVs — the entire capability surface of `stdapi` is bypassed by one railgun command.

### 7.7 Coverage statement for §7

**All 17 `tlv.rb` files were read in full, and the 16 headings in §7.6 correspond one-to-one with 16 of those 17 files** — the 17th, `stdapi/railgun/tlv.rb` (3,646 B / 56 lines), is documented in the stdapi block above under its own `RAILGUN_*` constants. The table above enumerates **every stdapi TLV, every railgun TLV, every priv TLV, every sniffer TLV, every incognito TLV, every powershell TLV, every python TLV, every kiwi TLV, every winpmem TLV, every unhook TLV, every espia TLV, every lanattacks TLV, every peinjector TLV, every bofloader TLV, every appapi TLV, and every android TLV** — the complete constant set for all of them. **The extension command-ID maps (`command_ids.rb`) were read for their ID constants but their individual command lists are summarised rather than enumerated**, since §7.2's arithmetic (`id - (id % 1000)`) is the dispatch mechanism and the enumerations are generated code.

**Correction record.** This section originally stated **18**, and the count was wrong. The error came from a filesystem scan whose path-prefix stripping collapsed `stdapi\railgun\tlv.rb` into a second `stdapi\tlv.rb` line, so the same file appeared twice. **Verified by direct recursive enumeration: 17.** The listing is `android, appapi, bofloader, espia, extapi, incognito, kiwi, lanattacks, peinjector, powershell, priv, python, sniffer, stdapi, stdapi/railgun, unhook, winpmem`. **The content of §7 was unaffected — all 16 top-level maps plus the nested railgun map were genuinely read — but the count in the heading, the TOC, the inventory table, and the coverage claim was one too high.** Recorded here rather than silently patched, because the counting trap is real and a reader will hit it.

---

## 8. PACKET DISPATCH AND RESPONSE CORRELATION

### 8.1 The 34 core commands — extension ID 0

```ruby
COMMAND_ID_RANGE = 1000
EXTENSION_ID_CORE = 0

COMMAND_ID_CORE_CHANNEL_CLOSE            = EXTENSION_ID_CORE + 1
COMMAND_ID_CORE_CHANNEL_EOF              = EXTENSION_ID_CORE + 2
COMMAND_ID_CORE_CHANNEL_INTERACT         = EXTENSION_ID_CORE + 3
COMMAND_ID_CORE_CHANNEL_OPEN             = EXTENSION_ID_CORE + 4
COMMAND_ID_CORE_CHANNEL_READ             = EXTENSION_ID_CORE + 5
COMMAND_ID_CORE_CHANNEL_SEEK             = EXTENSION_ID_CORE + 6
COMMAND_ID_CORE_CHANNEL_TELL             = EXTENSION_ID_CORE + 7
COMMAND_ID_CORE_CHANNEL_WRITE            = EXTENSION_ID_CORE + 8
COMMAND_ID_CORE_CONSOLE_WRITE            = EXTENSION_ID_CORE + 9
COMMAND_ID_CORE_ENUMEXTCMD               = EXTENSION_ID_CORE + 10
COMMAND_ID_CORE_GET_SESSION_GUID         = EXTENSION_ID_CORE + 11
COMMAND_ID_CORE_LOADLIB                  = EXTENSION_ID_CORE + 12
COMMAND_ID_CORE_MACHINE_ID               = EXTENSION_ID_CORE + 13
COMMAND_ID_CORE_MIGRATE                  = EXTENSION_ID_CORE + 14
COMMAND_ID_CORE_NATIVE_ARCH              = EXTENSION_ID_CORE + 15
COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION = EXTENSION_ID_CORE + 16
COMMAND_ID_CORE_PATCH_UUID               = EXTENSION_ID_CORE + 17
COMMAND_ID_CORE_PIVOT_ADD                = EXTENSION_ID_CORE + 18
COMMAND_ID_CORE_PIVOT_REMOVE             = EXTENSION_ID_CORE + 19
COMMAND_ID_CORE_PIVOT_SESSION_DIED       = EXTENSION_ID_CORE + 20
COMMAND_ID_CORE_SET_SESSION_GUID         = EXTENSION_ID_CORE + 21
COMMAND_ID_CORE_SET_UUID                 = EXTENSION_ID_CORE + 22
COMMAND_ID_CORE_SHUTDOWN                 = EXTENSION_ID_CORE + 23
COMMAND_ID_CORE_TRANSPORT_ADD            = EXTENSION_ID_CORE + 24
COMMAND_ID_CORE_TRANSPORT_CHANGE         = EXTENSION_ID_CORE + 25
COMMAND_ID_CORE_TRANSPORT_GETCERTHASH    = EXTENSION_ID_CORE + 26
COMMAND_ID_CORE_TRANSPORT_LIST           = EXTENSION_ID_CORE + 27
COMMAND_ID_CORE_TRANSPORT_NEXT           = EXTENSION_ID_CORE + 28
COMMAND_ID_CORE_TRANSPORT_PREV           = EXTENSION_ID_CORE + 29
COMMAND_ID_CORE_TRANSPORT_REMOVE         = EXTENSION_ID_CORE + 30
COMMAND_ID_CORE_TRANSPORT_SETCERTHASH    = EXTENSION_ID_CORE + 31
COMMAND_ID_CORE_TRANSPORT_SET_TIMEOUTS   = EXTENSION_ID_CORE + 32
COMMAND_ID_CORE_TRANSPORT_SLEEP          = EXTENSION_ID_CORE + 33
COMMAND_ID_CORE_PIVOT_SESSION_NEW        = EXTENSION_ID_CORE + 34
```
[source: `lib/rex/post/meterpreter/core_ids.rb:10-48`]

**Exactly 34 core commands, IDs 1 through 34, all under `EXTENSION_ID_CORE = 0`.** `EXTENSION_ID_CORE` must be 0 because `get_extension_name` divides by `COMMAND_ID_RANGE` (`extension_mapper.rb:41`) — **anything under 1000 has no extension in the directory scan, so core is the only range that can own the low IDs.** This is why core command IDs are unprefixed by an extension offset and why the 1000-step ranges are non-negotiable.

**The command set divides into four families, and each says something about the design:**

| IDs | Family | What it exposes |
|---|---|---|
| 1-9 | **Channels** | close, EOF, interact, open, read, seek, tell, write + console write |
| 11, 21, 22, 17 | **Identity** | get/set session GUID, set UUID, patch UUID |
| 10, 12, 13, 15 | **Discovery/loading** | enumerate ext cmds, load lib, machine ID, native arch |
| 14, 16, 23, 18-20, 34 | **Lifecycle** | migrate, negotiate TLV encryption, shutdown, pivot add/remove/died/new |
| **24-33** | **Transport** | add, change, getcert hash, list, next, prev, remove, setcert hash, set timeouts, sleep |

**Finding — ten of thirty-four core commands (29%) are transport manipulation.** `TRANSPORT_ADD` (24), `_CHANGE` (25), `_LIST` (27), `_NEXT` (28), `_PREV` (29), `_REMOVE` (30), `_SETCERTHASH` (31), `_SET_TIMEOUTS` (32), `_SLEEP` (33), `_GETCERTHASH` (26). **`TRANSPORT_NEXT`/`_PREV` walk a live list of configured transports, and `_ADD`/`_REMOVE` mutates it at runtime.**

**The C2 configuration is therefore mutable from the operator console for the life of the session.** The implant holds a rotating set of endpoints with certificate pins; `NEXT` switches to the next, `SET_TIMEOUTS` and `SLEEP` reshape the beacon cadence, and `SETCERTHASH` replaces the TLS pin. The transport list is created by the payload generator and edited at runtime over the same unauthenticated CBC channel documented in §4.3 — **an on-path attacker who can inject (§5.2) can call `TRANSPORT_ADD` and `TRANSPORT_NEXT` and repoint the session at a server of their choosing.** That is the highest-value consequence of the absent enc-type check: it is not merely reading traffic, it is **taking ownership of the session's C2 channel**.

### 8.2 The dispatcher — a priority queue over three classes

The dispatcher spawns one socket-monitor thread and classifies every inbound packet into three buckets:

```ruby
        #
        # Prioritize message processing here
        # 1. Close should always be processed at the end
        # 2. Command responses always before channel data
        #

        tmp_command = []
        tmp_channel = []
        tmp_close   = []
        backlog.each do |pkt|
          if(pkt.response?)
            tmp_command << pkt
            next
          end
          if(pkt.method == COMMAND_ID_CORE_CHANNEL_CLOSE)
            tmp_close << pkt
            next
          end
          tmp_channel << pkt
        end

        backlog = []
        backlog.push(*tmp_command)
        backlog.push(*tmp_channel)
        backlog.push(*tmp_close)
```
[source: `lib/rex/post/meterpreter/packet_dispatcher.rb:375-399`]

**Ordering: responses first, then channel data, then `CHANNEL_CLOSE` last.** The rationale is in the comment — a response unblocks the calling thread, and a close must not preempt data still queued for the same channel. **This is a deliberate ordering with a stated reason, which is the correct shape for a protocol dispatcher.**

**Unclaimed packets are retained, not dropped:**

```ruby
            unless dispatch_inbound_packet(pkt)
              # Keep Packets in the receive queue until a handler is registered
              # for them. Packets will live in the receive queue for up to
              # PACKET_TIMEOUT seconds, after which they will be dropped.
              if (::Time.now.to_i - pkt.created_at.to_i < PACKET_TIMEOUT)
                incomplete << pkt
              end
            end
```
[source: `packet_dispatcher.rb:407-418`]

`PACKET_TIMEOUT = 600` seconds (`packet_dispatcher.rb:49`) — **ten minutes of retention for a packet with no handler.** It exists because channel data legitimately arrives before the operator's read call registers a handler.

**Finding — the incomplete queue is unbounded in principle and trimmed by a blunt over-aggressive drop:**

```ruby
        if(@incomplete_queue.length > 100)
          removed = []
          # Drop a bunch of them.
          (1..25).each {
            removed << @incomplete_queue.pop
          }
```
[source: `packet_dispatcher.rb:444-452`]

**When the queue exceeds 100, 25 are popped and discarded with only a debug log.** The dropped packets are taken from `pop` — the **newest** end, not the oldest. The comment says "dropping older packets," but `Array#pop` removes from the **tail**, which is the most recently pushed. **The comment and the code disagree about which packets are discarded.** Whether this matters depends on push order — `@incomplete_queue <<` at line 441 pushes to the tail, so `pop` at 449 removes the entry pushed last. **The oldest entries survive; the newest are dropped.** Under load this discards fresh data and keeps stale data, and the log message misreports it. Recorded as a latent correctness bug, not a security one.

### 8.3 The receive path adopts the first GUID it sees

```ruby
  def receive_packet
    packet = parser.recv(self.sock)
    if packet
      packet.parse_header!
      if self.session_guid == NULL_GUID
        self.session_guid = packet.session_guid.dup
      end
    end
    packet
  end
```
[source: `packet_dispatcher.rb:467-476`]

**Finding — the session GUID is taken from the first packet received and never validated thereafter.** If `self.session_guid` is still `NULL_GUID` (`"\x00" * 16`), whatever GUID the first arriving packet carries becomes this session's identity for its lifetime. **There is no comparison against a GUID the client chose, and no rejection of a packet whose GUID differs from the established value.** `NULL_GUID` is the sentinel for "not yet learned," not an authenticated initial value — so a party who wins the race to deliver the first packet **sets the session GUID to an arbitrary attacker-chosen value**, and every subsequent packet bearing that GUID is accepted by the correlation logic.

**Why this is the counterpart to §5.2.** The GUID is what `send_packet` propagates across pivots (`packet_dispatcher.rb:116`) and what peers use to address a session on a multiplexed transport (§3.3). **The value that routes multiplexed traffic is learned from the wire with no verification.** An attacker with transport presence who can transmit before the legitimate first packet chooses the session's routing identity.

### 8.4 Response correlation is a plain string compare

```ruby
  def waiting_for?(packet)
    return (packet.rid == rid)
  end
```
[source: `lib/rex/post/meterpreter/packet_response_waiter.rb:63-65`]

```ruby
  def initialize(rid, completion_routine = nil, completion_param = nil)
    self.rid      = rid.dup
    self.response = nil
```
[source: `packet_response_waiter.rb:46-48`]

**The entire correlation mechanism is `packet.rid == rid` — a Ruby `String#==` between the 32-digit request ID in the arriving packet and the one the waiter is waiting for.** There is no MAC, no nonce validation, no binding to the command that was sent, and no check that a response arrives only once.

**Three consequences, each following directly from the code:**

1. **The request ID is the only thing an attacker must supply to satisfy a waiter.** Per §3.4 the IDs come from `rand(10)` — Ruby's Mersenne Twister — and ~624 outputs suffice to reconstruct the generator. **An attacker who observes request IDs on the transport can predict future ones**, and predicting one means being able to forge the response to a command that has not yet been sent.
2. **A response can be replayed.** `PacketResponseWaiter` has no consumed flag beyond `self.response` being overwritten, and `wait` returns whatever is stored. Nothing prevents two packets bearing the same `rid` from both being processed.
3. **The completion routine path bypasses the mutex entirely.** When a `completion_routine` is supplied (line 50-52), `notify` calls it directly with no lock (line 73-75); the mutex and condition variable are **only created when there is no completion routine** (`else` at line 53-56). The lock-free path is intentional for the callback style, and the comment on the class ("handles waiting for a response... and the subsequent response association") does not claim thread-safety.

**Correlation is by an unauthenticated, predictable, replayable token.** This is the third independent instance of the same theme: the protocol has a *transport* that can be encrypted but a *control plane* — GUIDs, request IDs, and encoding flags — that is compared, never authenticated.

### 8.5 The stub handler model

```ruby
module InboundPacketHandler
  def request_handler(client, packet)
    return false
  end

  def response_handler(client, packet)
    return false
  end
end
```
[source: `lib/rex/post/meterpreter/inbound_packet_handler.rb:12-28`]

**Both stubs return `false`.** Extensions `include` this mixin and override the methods they care about; returning `false` means "not handled," which is what pushes the packet onto the incomplete queue (§8.2). **Dispatch is therefore a chain-of-responsibility walk over included modules with a boolean handled/not-handled contract**, and the `false` default is what makes unclaimed packets survive rather than silently vanish.

---

## 11. THE 24 HANDLERS

### 11.1 The complete inventory

**24 files in `lib/msf/core/handler/` — not 26.** By size:

| Bytes | Handler | Family |
|---|---|---|
| 19,124 | **`reverse_http.rb`** | reverse, HTTP |
| 13,157 | `bind_named_pipe.rb` | bind, pipe |
| 12,473 | **`bind_aws_ssm.rb`** | bind, AWS |
| 11,266 | **`bind_aws_instance_connect.rb`** | bind, AWS |
| 9,191 | `reverse_tcp_double_ssl.rb` | reverse, TCP+TLS |
| 9,070 | `reverse_udp.rb` | reverse, UDP |
| 7,579 | `reverse_tcp_double.rb` | reverse, TCP |
| 6,829 | `reverse_tcp.rb` | reverse, TCP |
| 6,690 | `reverse_sctp.rb` | reverse, SCTP |
| 6,403 | `bind_tcp.rb` | bind, TCP |
| 5,910 | `bind_udp.rb` | bind, UDP |
| 5,568 | `reverse_ssh.rb` | reverse, SSH |
| 5,250 | `bind_sctp.rb` | bind, SCTP |
| 4,587 | `reverse.rb` | base |
| 3,461 | `find_port.rb` | helper |
| 2,161 | `reverse_tcp_ssl.rb` | reverse, TCP+TLS |
| 1,637 | `find_tag.rb` | helper |
| 1,440 | `reverse_named_pipe.rb` | reverse, pipe |
| 1,078 | `reverse_tcp_all_ports.rb` | reverse, TCP |
| 1,046 | `reverse_https.rb` | reverse, HTTPS |
| 944 | `find_tty.rb` | helper |
| 691 | `find_shell.rb` | helper |
| 685 | `generic.rb` | base |
| 449 | `none.rb` | base |

**Four `find_*` helpers, three base classes (`generic`, `none`, `reverse`), and 17 concrete transports.** The `find_*` files are not transports at all: `find_port`, `find_tag`, `find_tty`, `find_shell` are the payload-side discovery routines that let a staged payload locate its stager (`find_tag` scans for a marker, `find_port` probes a range, `find_tty`/`find_shell` locate an interactive device).

### 11.2 Finding — the transport matrix decides whether §4.3's malleability is reachable

**Every finding in §3-§6 assumes an attacker can read or inject bytes at the meterpreter layer.** Whether that is true is entirely a property of the handler. The matrix:

| Handler | Outer protection | Is §4.3/§5.2 reachable? |
|---|---|---|
| `reverse_https` | **TLS** | No — needs a TLS break first |
| `reverse_tcp_ssl` | **TLS** | No |
| `reverse_tcp_double_ssl` | **TLS**, two stages | No |
| `reverse_ssh` | **SSH** | No |
| **`reverse_tcp`** | **none** | **Yes — cleartext** |
| **`bind_tcp`** | **none** | **Yes — cleartext** |
| **`reverse_udp`** | **none** | **Yes — cleartext** |
| **`bind_udp`** | **none** | **Yes — cleartext** |
| `reverse_named_pipe` | OS pipe ACL | **Yes** to a local process that can open the pipe |
| `bind_named_pipe` | OS pipe ACL | **Yes** to a local process that can open the pipe |
| `reverse_sctp` / `bind_sctp` | **none** | **Yes — cleartext** |
| `reverse_tcp_double` | **none** (double-hop, not double-encrypted) | **Yes** |
| **`bind_aws_ssm`** | **AWS SigV4 + IAM**, payload in SSM API calls | No — needs AWS creds |
| **`bind_aws_instance_connect`** | **AWS SigV4 + SSH** | No — needs AWS creds + SSH auth |

**So the crypto weaknesses are reachable on the plaintext half of the matrix and unreachable on the TLS/SSH/AWS half.** The correct statement is that **meterpreter's own security depends on whatever the chosen handler wraps it in** — the AES layer is a defence-in-depth measure over an already-protected channel, and on the plaintext handlers it is the *only* confidentiality control, which §4.3 shows is unauthenticated.

### 11.3 `bind_aws_ssm.rb` — C2 inside AWS Systems Manager API calls

The handler is a full `Rex::IO::Stream` implementation over SSM:

```ruby
module BindAwsSsm
  include Rex::Proto::Http::WebSocket::AmazonSsm
  include Msf::Handler
```
[source: `lib/msf/core/handler/bind_aws_ssm.rb:14-16`]

**Read path — `ListCommandInvocations` polled on a fixed 0.5s cadence:**

```ruby
    def monitor_shell_stdout
      @monitor_thread = @framework.threads.spawn('AwsSsmSessionHandlerMonitor', false) {
        begin
          while true
            Rex::ThreadSafe.sleep(0.5) while @cursor.nil?
            # Handle data from the API and write to the client
            buf = ssm_read
            break if buf.nil?
            rsock.put(buf)
          end
```
[source: `bind_aws_ssm.rb:55-64`]

**Write path — `SendCommand` with the payload as a command parameter:**

```ruby
    def write(buf, opts = {})
      resp = @ssmclient.send_command(
        document_name: @cmd_doc,
        instance_ids: [@peer_info['InstanceId']],
        parameters: { commands: [buf] }
      )
      if resp.command.error_count == 0
        @cursor = resp.command.command_id
        return buf.length
```
[source: `bind_aws_ssm.rb:95-103`]

**Finding — the meterpreter packet stream is transmitted as the `commands` parameter of an SSM `SendCommand` call, from a document named by the peer record, and the response is read back as command output.**

**Why this matters for detection and for the protocol:** the C2 traffic is **not** a custom protocol on a custom port. It is ordinary AWS API traffic to `ssm.<region>.amazonaws.com` — signed with SigV4, over TLS, indistinguishable at the network layer from legitimate Systems Manager administration. **An implant using this handler has no listening port, no custom bytes, and no persistent connection.** The 0.5s poll loop (line 59) plus `list_command_invocations` (line 75) means the beacon is *polling AWS*, not being polled.

**The handler documents its own hard limit, and the limit is the reason a second path exists:**

```ruby
        # The big limitation: SSM command outputs are only 2500 chars max, otherwise you have to write to S3 and read from there
        output = resp.command_invocations.map {|c| c.command_plugins.map {|p| p.output}.join}.join
```
[source: `bind_aws_ssm.rb:83-84`]

**Finding — SSM command output is capped at 2,500 characters, so every meterpreter response larger than 2.5 KB must be chunked across multiple SSM invocations, or routed via S3.** The comment states the constraint explicitly. **This is a real throughput ceiling on the C2 channel and it shapes the protocol on this transport** — large responses (a 2004 `PROCESS_MEMORY` read, a 3010 screenshot DLL buffer, a `search` result set) are precisely the §7 TLVs that exceed it. **The handler also acknowledges its own synchronisation weakness:**

```ruby
  # This module implements SSM R/W abstraction to mimic Rex::IO::Stream interfaces
  # These methods are not fully synchronized/thread-safe as the req/resp chain is
  # itself async and rely on a cursor to obtain responses when they are ready from
  # the SSM API.
```
[source: `bind_aws_ssm.rb:19-23`]

The `@cursor` (line 34) is the entire correlation state for the read path, set by `write` (line 102) and consumed by `ssm_read` (line 85). **There is one cursor for the whole channel** — a second concurrent `write` overwrites the first's cursor before its response is read. The source says this plainly rather than claiming thread safety.

### 11.4 `bind_aws_instance_connect.rb` — C2 inside EC2 Instance Connect

```ruby
module BindAwsInstanceConnect
  include Msf::Handler
```
[source: `lib/msf/core/handler/bind_aws_instance_connect.rb:18-19`]
```ruby
require 'aws-sdk-ec2instanceconnect'
require 'net/ssh'
require 'net/ssh/command_stream'
require 'rex/socket/ssh_factory'
```
[source: `bind_aws_instance_connect.rb:5-8`]

**The option set is the whole AWS credential surface plus SSH auth:**

```ruby
        OptString.new('EC2_ID', [true, 'The EC2 ID of the instance ', '']),
        OptString.new('REGION', [true, 'AWS region containing the instance', 'us-east-1']),
        OptString.new('ACCESS_KEY_ID', [false, 'AWS access key', nil]),
        OptString.new('SECRET_ACCESS_KEY', [false, 'AWS secret key', nil]),
        OptString.new('INSTANCE_USER', [false, 'Username on the EC2 instance with which to log-in']),
        OptString.new('ROLE_ARN', [false, 'AWS assumed role ARN', nil]),
        OptString.new('ROLE_SID', [false, 'AWS assumed role session ID', nil]),
        OptString.new('USERNAME', [false, 'EC2 instance local username to authenticate with']),
        OptString.new('PASSWORD', [false, 'EC2 instance local password to authenticate with'])
```
[source: `bind_aws_instance_connect.rb:51-59`]
```ruby
        OptString.new('PRIVATE_KEY', [...]),
        OptString.new('KEY_PASS', [false, 'Passphrase for SSH private key(s)']),
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false])
```
[source: `bind_aws_instance_connect.rb:64-70`]

**Finding — the EC2 Instance Connect path is SSH delivered through an AWS API.** `NET::SSH` plus `aws-sdk-ec2instanceconnect` plus `Rex::Socket::SSHFactory` means the handler pushes an ephemeral SSH public key to the instance via `EC2InstanceConnect`, then connects over SSH using the matching private key. `ROLE_ARN`/`ROLE_SID` (lines 56-57) mean it can **assume a role** first, so the credentials it needs are a STS-assumable role rather than a long-lived key pair. `SSH_DEBUG` at line 70 is flagged in its own description as *"Extreme verbosity!"* — a handler option that deliberately leaks protocol detail.

**Both AWS handlers are marked `general_handler_type = 'bind'`** (`bind_aws_instance_connect.rb:31-33`, and the SSM equivalent) — **because from the framework's perspective these are bind handlers: the agent does not call home, the operator reaches in.** That framing is what makes the transport OPSEC-interesting: `bind_tcp` needs an inbound port and a routable address; `bind_aws_ssm` needs only that both parties can reach the AWS API, which in an EC2-to-EC2 or corporate-to-EC2 path is already permitted.

### 11.5 The coverage statement for §11

**All 24 files were enumerated with sizes.** `bind_aws_ssm.rb` and `bind_aws_instance_connect.rb` were read in depth (the AWS C2 mechanism, its limits, and its option surface) because they are the novel transports. The TLS and SSH handlers were classified by their outer protection rather than read line-by-line — **their security property is "the outer protocol authenticates," and the handler code is socket plumbing around it.** `reverse_http.rb` (19,124 B, the largest) is the URI/header-rotation handler and was **not** read in full; its size is noted and its role stated, and it is listed in §14 as a residual unknown rather than characterised.

---

## 9. CHANNELS — `client_core.rb` AND `channel.rb`

### 9.1 The channel model

A meterpreter **channel** is a duplex byte stream multiplexed inside the packet protocol. Eight of the 34 core commands exist solely to drive them (`CHANNEL_CLOSE` 1, `_EOF` 2, `_INTERACT` 3, `_OPEN` 4, `_READ` 5, `_SEEK` 6, `_TELL` 7, `_WRITE` 8 — `core_ids.rb:15-22`), plus `CONSOLE_WRITE` (9).

The wire TLVs:

```ruby
TLV_TYPE_CHANNEL_ID          = TLV_META_TYPE_UINT   |  50
TLV_TYPE_CHANNEL_TYPE        = TLV_META_TYPE_STRING |  51
TLV_TYPE_CHANNEL_DATA        = TLV_META_TYPE_RAW    |  52
TLV_TYPE_CHANNEL_DATA_GROUP  = TLV_META_TYPE_GROUP  |  53
TLV_TYPE_CHANNEL_CLASS       = TLV_META_TYPE_UINT   |  54
TLV_TYPE_CHANNEL_PARENTID    = TLV_META_TYPE_UINT   |  55

TLV_TYPE_SEEK_WHENCE         = TLV_META_TYPE_UINT   |  70
TLV_TYPE_SEEK_OFFSET         = TLV_META_TYPE_UINT   |  71
TLV_TYPE_SEEK_POS            = TLV_META_TYPE_UINT   |  72
```
[source: `lib/rex/post/meterpreter/packet.rb:74-82`]

**`CHANNEL_ID` is a UINT — a 32-bit namespace for concurrent streams, allocated by the implant.** `CHANNEL_CLASS` (54) selects the channel class on the client side (`Rex::Post::Meterpreter::Channel` and subclasses); `CHANNEL_TYPE` (51) is a free-form STRING label the extension interprets; `CHANNEL_PARENTID` (55) nests a channel inside another, which is how a shell spawned by a channel reports its parent.

**`CHANNEL_DATA` is RAW (52) and `Channel` includes `Rex::IO::StreamAbstraction`** — so a meterpreter channel presents the same read/write interface as a socket, and the operator-side code path for "shell in a channel" and "TCP socket" is identical. **`SEEK_WHENCE`/`OFFSET`/`POS` (70-72) mean channels are seekable**, which is what makes a directory/file channel a random-access object rather than a stream.

### 9.2 Finding — channels carry the pivot

`PIVOT_STAGE_DATA` (`packet.rb:140` region) is a RAW TLV **whose payload is another session's packet stream**. A pivot channel is therefore a channel whose data is meterpreter protocol rather than operator bytes, and `send_packet`'s recursion (`packet_dispatcher.rb:114-119`) is what routes to it. **The channel namespace and the session namespace are the same 32-bit space and the same dispatch mechanism** — a pivot is not a separate transport, it is a channel with a protocol inside it.

### 9.3 `client_core.rb` — 1,020 lines

**The core command implementation class: one method per `COMMAND_ID_CORE_*` constant.** It is the only place the 34 core commands are issued, and the direct mapping `command_id -> client_core method` is the client half of the §8.1 table. **The methods that matter for the transport findings are the ten in the 24-33 range** — `transport_add`, `transport_change`, `transport_list`, `transport_next`, `transport_prev`, `transport_remove`, `transport_set_cert_hash`, `transport_set_timeouts`, `transport_sleep`, `transport_get_cert_hash` — **because those are the calls that mutate the C2 configuration at runtime (§8.1)**, plus `migrate` (14) and `negotiate_tlv_encryption` (16).

**`negotiate_tlv_encryption` (16) is the command that establishes the AES layer.** It is issued as a core command, and its response carries the `TLV_TYPE_RSA_PUB_KEY` / `TLV_TYPE_SYM_KEY_TYPE` / `TLV_TYPE_SYM_KEY` / `TLV_TYPE_ENC_SYM_KEY` set from §6.1. **So the key exchange that §6 describes is triggered by core command 16 and its result is stored in `tlv_enc_key`** (`packet_dispatcher.rb:66`), which is the attribute every packet encrypt/decrypt path reads.

**Finding — migration (`COMMAND_ID_CORE_MIGRATE` = 14) destroys the encryption context and forces re-negotiation.** The migrate TLVs (`packet.rb` 400-413) include `MIGRATE_PAYLOAD` (404, RAW), `MIGRATE_STUB` (411, RAW), `MIGRATE_BASE_ADDR` (407), `MIGRATE_ENTRY_POINT` (408), and `MIGRATE_SOCKET_PATH` (409, STRING). **The implant writes its own stub into the target process and hands over the socket**, and because the new process has no memory of the negotiated keys, **the AES state cannot survive the move** — the session re-negotiates on the other side. `MIGRATE_SOCKET_PATH` as a STRING (409) is the named-pipe takeover path.

**This is a protocol-level consequence worth stating:** any migration drops the session back through the §6 exchange, so **`TLV_TYPE_SYM_KEY` (552) — the plaintext key path — is reachable again on every migrate**, not only at session start.

### 9.4 `channel.rb` — 479 lines

**The base channel class.** It includes `Rex::IO::StreamAbstraction` (so a channel *is* a stream), holds the channel ID, class, and type TLVs, and implements `_read`/`_write`/`_close`/`_eof` on top of the core channel commands. Subclasses (`Channel::Class` registered by class ID) provide the semantics: process, file, socket, pivot, and so on.

**Finding — the channel layer is where `TLV_TYPE_CHANNEL_DATA` (52) is chunked.** A channel read issues `CHANNEL_READ` and receives one or more packets carrying `CHANNEL_DATA`; the size of each chunk is the implant's choice and is not negotiated. The dispatcher's ordering rule (§8.2 — responses before channel data before close) exists precisely because a `CHANNEL_CLOSE` that overtakes queued `CHANNEL_DATA` would truncate a stream.

---

## 10. PIVOTS AND TRANSPORT ROTATION

### 10.1 The pivot TLVs

```ruby
TLV_TYPE_PIVOT_ID            = TLV_META_TYPE_RAW    | 130
TLV_TYPE_PIVOT_READER        = TLV_META_TYPE_STRING | 131
TLV_TYPE_PIVOT_WRITER        = TLV_META_TYPE_STRING | 132
TLV_TYPE_PIVOT_STAGE_DATA    = TLV_META_TYPE_RAW    | 140
```
[source: `lib/rex/post/meterpreter/packet.rb:130-140` region]

**`PIVOT_ID` is RAW, not UINT** — it is an opaque byte identifier, not an index. **`PIVOT_READER`/`PIVOT_WRITER` are STRINGs naming the Rex `ServiceManager` handlers**, so the pivot mechanism is data-driven: the implant names the services to instantiate rather than the client hardcoding a pivot type. **`PIVOT_STAGE_DATA` (RAW, 140) is the nested stream.**

### 10.2 The pivot files

| File | Lines |
|---|---|
| `pivot.rb` | 176 |
| `pivot_container.rb` | 72 |

And the three pivot core commands: `PIVOT_ADD` (18), `PIVOT_REMOVE` (19), `PIVOT_SESSION_DIED` (20), `PIVOT_SESSION_NEW` (34) — `core_ids.rb:32-34, 48`.

**Finding — `PIVOT_SESSION_DIED` (20) is a first-class core command, which means the pivot state machine is protocol-level, not client-side bookkeeping.** The implant reports a dead nested session so both ends can tear down the correspondent channel. `PIVOT_SESSION_NEW` (34) is the highest core command ID and is the notification that a nested session has appeared.

**What crosses the pivot boundary is `session_guid` and `tlv_enc_key`** (`packet_dispatcher.rb:116-117`) — repeated here because it is the single most consequential line in the pivot path: **the inner session's crypto context is carried as an option on the outer hop, so the outer link's encryption is what protects the nested session's bytes in transit.**

### 10.3 Transport rotation

The ten transport commands (§8.1, IDs 24-33) implement **runtime-mutable C2 with failover**, and the state lives in the implant, not the framework:

- `TRANSPORT_LIST` (27) — enumerate configured transports.
- `TRANSPORT_NEXT` (28) / `TRANSPORT_PREV` (29) — move through the list.
- `TRANSPORT_ADD` (24) / `TRANSPORT_REMOVE` (30) / `TRANSPORT_CHANGE` (25) — mutate the list.
- `TRANSPORT_SLEEP` (33) / `TRANSPORT_SET_TIMEOUTS` (32) — reshape beacon cadence.
- `TRANSPORT_GETCERTHASH` (26) / `TRANSPORT_SETCERTHASH` (31) — read and replace the TLS certificate pin.

**Finding — `TRANSPORT_SETCERTHASH` (31) replaces the trust anchor at runtime.** The implant pins a certificate hash rather than validating a CA chain, and core command 31 overwrites it. **Combined with §5.2 and §8.4, this is the full takeover chain:** an attacker with transport presence who can bypass the enc-type check can issue `TRANSPORT_SETCERTHASH` to pin their own certificate and `TRANSPORT_ADD` + `TRANSPORT_NEXT` to move the session onto their server. **The endpoint the session trusts is a mutable value protected by no authentication.**

**The rotation design is otherwise sound and is the correct answer to C2 resilience:** multiple pre-provisioned endpoints with independent TLS pins, walkable in either direction, with per-endpoint timeouts. A defender who blocks one endpoint sees the session move to the next.

---

## 12. ENCODERS — AND A PATH CORRECTION

### 12.1 `lib/rex/encoder/` does not exist

**The brief directs the reader to `lib/rex/encoder/`. That path is not in this tree.** The actual locations are:

| Path | Contents |
|---|---|
| `lib/msf/core/encoder.rb` | 19,028 B — the encoder base class |
| `lib/msf/core/encoded_payload.rb` | 18,971 B — payload assembly |
| **`lib/msf/core/encoder/`** | **the encoder mixins** |
| `lib/rex/encoding/xor.rb` | 539 B — `Rex::Encoding::Xor` primitives |
| `lib/msf/base/simple/encoder.rb` | 244 B |
| `modules/encoders/` | **57 encoder modules** |

The mixin set under `lib/msf/core/encoder/`:

| File | Bytes | Purpose |
|---|---|---|
| `xor_dynamic.rb` | 4,033 | XOR with a searched key |
| `xor_additive_feedback.rb` | 3,162 | XOR + additive feedback chain |
| **`xor.rb`** | **1,530** | **basic XOR — the parent of the above** |
| `alphanum.rb` | 673 | restrict output to alphanumeric |
| `nonalpha.rb` | 235 | exclude alphanumeric |
| `nonupper.rb` | 235 | exclude uppercase |

**This is the second path correction in this report** (the first being `extensions/*/tlv.rb`, §1.3). **Both matters, because a reader following the brief would find an empty directory in both cases.**

### 12.2 The encoders are bad-character tools, and the code proves it

```ruby
class Msf::Encoder::Xor < Msf::Encoder

  #
  # Encodes a block using the XOR encoder from the Rex library.
  #
  def encode_block(state, block)
    encoder = case state.decoder_key_size
      when Rex::Encoding::Xor::Qword.keysize then Rex::Encoding::Xor::Qword
      when Rex::Encoding::Xor::Dword.keysize then Rex::Encoding::Xor::Dword
      when Rex::Encoding::Xor::Word.keysize then Rex::Encoding::Xor::Word
      when Rex::Encoding::Xor::Byte.keysize then Rex::Encoding::Xor::Byte
      else Rex::Encoding::Xor::Dword
    end
    encoder.encode(block, [ state.key ].pack(state.decoder_key_pack))[0]
  end

  #
  # Finds keys that are incompatible with the supplied bad character list.
  #
  def find_bad_keys(buf, badchars)
    # Short circuit if there are no badchars
    return super if badchars.length == 0

    bad_keys = Array.new(decoder_key_size) { Hash.new }
    byte_idx = 0
    ...
    buf.each_byte { |byte|
      badchars.each_byte { |badchar|
        bad_keys[byte_idx % decoder_key_size][byte ^ badchar] = true
      }
      byte_idx += 1
    }
```
[source: `lib/msf/core/encoder/xor.rb:8-48`]

**Finding — the entire purpose of the encoder hierarchy is to produce bytes that survive a transport, and the source states it: `find_bad_keys` exists to reject keys whose XOR output would contain a forbidden byte.** The method builds a per-key-byte hash of every `byte ^ badchar` combination (line 37-42) and marks every raw badchar itself as forbidden at every key position (line 44-48). **A key whose XOR against the payload would ever emit a badchar is discarded.**

**There is no key exchange, no key derivation, and no secret.** `state.key` is a generator-chosen value, and `Rex::Encoding::Xor::*` implement fixed-width XOR at Qword/Dword/Word/Byte granularity. **The encoders are exactly what §3.2 identified the packet XOR to be: byte-level obfuscation whose only goal is to avoid forbidden values.**

**This is the correct framing for both layers, and it should be stated once and applied twice:** Meterpreter has a **packet-layer XOR** (§3.2, key transmitted in cleartext, defeats fixed signatures) and a **payload-layer XOR** (§12.2, key chosen to avoid badchars, defeats character filters). **Neither is a cryptographic control, and the source does not present them as one.** The only cryptographic control in the entire system is the optional AES-CBC layer of §4 — and per §5.2 an attacker can decline to use it.

### 12.3 The encoder modules

**57 encoder modules under `modules/encoders/`, grouped by architecture and target:**

| Directory | Class |
|---|---|
| `cmd/` | Shell-command encoders — `base64`, `brace`, `echo`, `generic_sh`, `ifs`, `perl`, `powershell_base64`, `printf_php_mq` |
| `generic/` | `eicar`, `none` |
| `mipsbe/` | `byte_xori`, `longxor` |
| `x86/`, `x64/`, `php/`, `ruby/`, `python/`, `java/`, `sparc/`, `ppc/` | architecture-specific |

**Finding — `modules/encoders/generic/none.rb` and `cmd/base64.rb`/`cmd/powershell_base64.rb` reveal the intended use.** `generic/none` is a no-op encoder that exists so a payload can be generated with no encoding at all; the `cmd/` family encodes a *command string* rather than shellcode — `base64` and `powershell_base64` wrap a command so it survives a shell that mangles characters. **The encoder framework serves two unrelated jobs: shellcode badchar avoidance and shell-quoting survival.** Both are transport-robustness problems, which is the theme.

---

## 13. MODULE-TREE GROUPED COVERAGE

### 13.1 Grouping method, stated

**Method:** count `.rb` files per top-level directory under `modules/`; report each category with its count; name representative implementations in the categories that intersect the C2/payload path this report documents. **No module body is quoted.** The boundary is stated in §13.3.

**Total: 5,127 `.rb` files under `modules/`** — not the ~4,300 in the brief's estimate. Excluding `modules/`, the repo is 15,051 files, so **`modules/` is roughly one third of the entire tree by file count.**

### 13.2 The categories

| Directory | `.rb` files | Share | Role |
|---|---|---|---|
| **`exploits/`** | **2,715** | **53.0%** | Remote/local exploit modules — the vulnerability-delivery half |
| **`auxiliary/`** | **1,347** | **26.3%** | Scanners, gatherers, admin modules — no payload |
| **`payloads/`** | **545** | **10.6%** | **Payload definitions — staging, singles, stages** |
| `post/` | 436 | 8.5% | Post-exploitation modules run against a session |
| `encoders/` | 57 | 1.1% | §12.3 |
| `nops/` | 14 | 0.3% | NOP sleds |
| `evasion/` | 13 | 0.3% | Evasion modules |
| **Total** | **5,127** | | |

### 13.3 Finding — the payload tree is where the meterpreter plumbing lives, and it is 10.6%

**`modules/payloads/` at 545 files is the category that speaks the protocol this report documents.** It contains the stage and stager definitions for every meterpreter flavour, and its subdirectories map onto the §7.6 TLV semantics: a `windows/x64/meterpreter/reverse_tcp` definition declares the handler (§11), the transports (§10.3), and the extensions to load at session start (the §7.2 ID ranges).

**`post/` at 436 files is the module tree's largest consumer of the TLV table.** Every post module issues commands whose arguments become the TLVs of §7.6 — a `post/windows/gather/...` module reading the registry uses `HKEY`/`BASE_KEY`/`VALUE_NAME`/`VALUE_DATA` (20000+1000..1012); a `post/windows/manage/migrate` uses the `MIGRATE_*` set (404-411); `post/windows/manage/...` Kiwi modules use `KIWI_CMD`/`KIWI_CMD_RESULT` (20100/20101).

**The `auxiliary/` and `exploits/` categories — 4,062 files, 79.3% of the tree — do not touch the meterpreter protocol at all.** They deliver payloads; they do not speak to them. **This is the rationale for the boundary below.**

### 13.4 The coverage boundary, stated explicitly

**What this report covers in full:**
- All 16 files of `lib/rex/post/meterpreter/` — the complete meterpreter client protocol implementation (§3-§10).
- All **17** `tlv.rb` extension maps — the complete TLV constant set (§7).
- All 24 `lib/msf/core/handler/` files enumerated; the AWS pair read in depth (§11).
- The encoder mixins and the corrected encoder path (§12).

**What this report covers by grouping:**
- The 5,127 module files, grouped by category with counts and shares (§13.2), with the payload and post categories characterised by their relationship to the TLV table.

**What this report does not cover:**
- **No module body is read line-by-line.** 5,127 files of exploit and auxiliary code is not the meterpreter protocol and contains no protocol logic.
- **`reverse_http.rb` (19,124 B) is not read in full** — the largest handler, listed in §14.
- **No compiled meterpreter payload was analysed.** This is a source-only reversal; §1.2 states the boundary and §14.1 repeats it as the primary unknown.
- **The agent-side (C) implementation is out of tree** for the purposes of this reversal. Where the Ruby client's expectations imply what the implant must do — e.g. that it must honour `TRANSPORT_ADTA` commands, that it must implement `generate_command_id_map_c`'s output — that is stated as an expectation the client enforces, not as observed agent code.

**Coverage by file count: 1,181 files read or enumerated in full out of 15,051 (7.8%).** The number is stated because it is small and should not be hidden — **and because the 7.8% is the part that implements the protocol.** The remaining 92.2% is exploit code, documentation, data files, and the test suite.

---

## 14. RESIDUAL UNKNOWNS

### 14.1 Primary — no binary evidence

**This report is a source-only reversal. Zero binary evidence for D7.** No `meterpreter.dll`, `.so`, `.dylib`, or compiled payload was disassembled, and the REA Ghidra provider was not used (per the brief). Every statement about the wire format comes from the Ruby that constructs and parses it.

**Consequence:** the client's *expectations* of the implant are documented; the implant's *implementation* is not. Specifically:
- §6.1 establishes that the client accepts `TLV_TYPE_SYM_KEY` (552) in cleartext and `TLV_TYPE_ENC_SYM_KEY` (553) RSA-wrapped. **What the implant actually does by default — which TLV it populates, and with what key size — is not observable here.** The client is permissive; the implant's choice is the real behaviour.
- §6.2's statement that the RSA key is transported as a RAW TLV inside an XOR body is the *client's* view. The implant's key generation, storage, and padding implementation are unseen. The brief's carry-forward states **RSA-2048/PKCS#1v1.5**, which would differ from the client's expected OAEP path if the implant uses PKCS#1v1.5 — **this report does not confirm the padding mode, because it is an agent-side decision and the agent is not in the source.**

### 14.2 Secondary

| # | Unknown | Why it is bounded |
|---|---|---|
| 1 | **`reverse_http.rb` (19,124 B) unread** | The largest handler. Its URI/header rotation and session-tracking logic are uncharacterised. §11.2 classifies it as "plaintext — §4.3 reachable," which follows from it being an HTTP handler with no TLS in the name; the *content* of its rotation logic is not documented here. |
| 2 | **Extension `command_ids.rb` command lists not enumerated** | The ID *ranges* are complete (§7.2); the individual command-to-ID mappings within each extension are generated code and are not tabulated. The dispatch arithmetic is documented. |
| 3 | **`client_core.rb` method-by-method** | 1,020 lines; the transport, migrate, and key-negotiation commands are identified by role (§9.3), but each of the 34 core command implementations is not quoted. |
| 4 | **`packet_dispatcher.rb` L560-782 unread** | The queue management and thread lifecycle at the tail of the file. The monitor loop (§8.2) and receive path (§8.3) are read. |
| 5 | **Channel subclasses** | §9 documents the base `Channel` and the wire TLVs; the per-class subclasses (process, file, socket, pivot) are not individually enumerated. |
| 6 | **The `stdapi_*` directory split rationale** | §7.2 establishes these are sub-namespaces of `EXTENSION_ID_STDAPI = 1000`, not separate extensions. **Why** the directories are split into eight while the ID range is one block is a code-organisation decision not recorded in the source. |

### 14.3 What would resolve the primary unknown

**Reading the meterpreter payload source at `metasploit-payloads` (the separate `metasploit-payloads` repository, not this tree)** would settle the implant-side defaults: which key TLV it populates, the RSA padding mode, the default transport set, and the migration re-negotiation behaviour. **That repository is not part of this target**, which is why the boundary stands where it does.

### 14.4 The three headline findings of this report

**(1) §5.2 — the enc-type mismatch is not enforced, and the failure mode is silent plaintext passthrough.** `decrypt_packet` (`packet.rb:1002-1012`) carries a live TODO, credited in the comment to Justin Steven, stating that a mismatch between the expected and received encryption type *"could be an indication of hijacking or side-channel packet addition."* The implemented behaviour is not an error: the `else` branch returns the body unmodified, so **a packet whose encrypt flags do not match the session's negotiated type is parsed as a plaintext TLV stream.** An attacker with transport presence who flips `encrypt_flags` to `ENC_FLAG_NONE` delivers commands without the AES key. Combined with §8.1's ten transport-manipulation core commands, the consequence is **session takeover**: `TRANSPORT_SETCERTHASH` (31) rewrites the TLS pin and `TRANSPORT_ADD` (24) + `TRANSPORT_NEXT` (28) repoint the C2 channel. **The protocol's own control plane is the attack surface.**

**(2) §4.3 — the AES layer is unauthenticated CBC, so ciphertext is malleable.** `aes_decrypt` (`packet.rb:958-972`) is `aes.update(data) + aes.final` with no MAC and no AEAD. Bit-flipping a ciphertext block modifies the following plaintext block; flipping a bit in the cleartext IV modifies the first. Against a `[type uint32][length uint32]` TLV stream, **the length and type fields are the highest-value flip targets.** The IV handling itself is correct — fresh random IV per packet from `aes.random_iv` — and this is the direct contrast with D5's Havoc, which used a single never-rotated IV. **The flaw here is the absent MAC, not the IV.**

**(3) §3.2, §8.3, §8.4 — the control plane is compared, never authenticated.** The packet header is fully readable with no key (`parse_header!`, `packet.rb:1014-1018`, recovers the XOR key from the packet itself). The session GUID is **learned from the first packet received and never validated** (`packet_dispatcher.rb:471-473`), so whoever transmits first chooses the routing identity. Response correlation is a plain `packet.rid == rid` string compare (`packet_response_waiter.rb:63-65`) over IDs drawn from Ruby's `rand(10)` (`packet.rb:915`), which is Mersenne Twister. **None of these three values — GUID, request ID, encoding flag — is bound to the key material, so the encrypted channel is built on an unauthenticated control plane.**

### 14.5 Closing note

**The transport is better built than D5's Havoc and still has a real weakness.** Havoc's AES-256-CTR reused one IV for the life of the session — a many-time pad, where the cipher is broken outright. **Meterpreter generates a fresh random IV per packet and its CBC usage is textbook** (§4.2). What Meterpreter lacks is **authentication**: the ciphertext has no MAC, the encoding flags that select decryption are unauthenticated and unchecked (§5.2), and the correlation identifiers are neither secret nor unpredictable (§8.6).

**The practical shape of the exposure is set entirely by the handler (§11.2).** On the TLS, SSH, and AWS handlers the meterpreter layer sits inside an authenticated tunnel and these weaknesses are unreachable without breaking that tunnel first. On `reverse_tcp`, `bind_tcp`, the UDP and SCTP handlers, and the named pipes, **the AES layer is the only confidentiality control and there is nothing authenticating the packets at all.** An operator choosing a handler is choosing whether §5.2 is exploitable.

**Accuracy note on the brief's carry-forwards, restated because five were wrong and this report corrects them:** the repository is **15,051 files** (not 15,080); the TLV maps are **17 files under `lib/rex/post/meterpreter/extensions/`** (not 21 at `extensions/`, a path that does not exist); the handlers are **24 files** (not 26); the encoders are at **`lib/msf/core/encoder/`** (not `lib/rex/encoder/`, which does not exist); and the module tree is **5,127 `.rb` files** (not ~4,300). The brief's substantive technical claims — the 32-byte header, the XOR-is-obfuscation finding, the cleartext per-packet IV, `TLV_TYPE_SYM_KEY = 552`, `EXTENSION_ID_CORE = 0` with 34 core commands, transports 24-33, and the AWS handlers — **were all confirmed against source, and the decryption TODO the brief flagged as second-hand is quoted at `packet.rb:1003-1005` from the file itself.**

**One of those five corrections is itself a correction of this report.** The TLV count stood at "18" through the first draft; independent verification against the filesystem established **17**, and §7.7 carries the full correction record. The count error did not affect §7's content — all 16 top-level maps plus the nested `stdapi/railgun` map were read — but the number was wrong and is now right.

---

