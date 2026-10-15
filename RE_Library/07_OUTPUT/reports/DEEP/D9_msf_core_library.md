# D9 — Metasploit Core Framework Library (`lib/msf/core/`, `lib/rex/`)

**Scope.** The Metasploit *engine*, not the exploit corpus. Source root: `RE_Library\01_SOURCE_c2\metasploit\`. 2,715 exploit modules are explicitly **out of scope** and are not enumerated here. This document covers `lib/msf/core/` (framework engine: payload pipeline, handlers, encoders, sessions) and `lib/rex/` (the Rex exploitation library: the meterpreter wire protocol, TLV/extension architecture, transports). Priority is mechanism, connection, and library structure — the load-bearing functions, not the incidental ones.

> **SCOPE CORRECTION (round 17, from D22 §4 — Lead-verified).** This document claims `lib/rex/` as
> covering "transports," and §11 covers `lib/rex/proto/`. **Both statements are accurate; neither reaches
> the transport decision, because the deciding code is not in this checkout.**
>
> **`lib\rex\socket.rb` DOES NOT EXIST. There is no `lib\rex\socket\` directory.** The tree contains
> `crypto`, `exploit`, `google`, `io`, `logging`, `parser`, `payloads`, `post`, `proto`, `script`,
> `services`, `ui` — **and no `socket`.** Rex was externalized into gems. §14 already records that
> `text.rb` and `arch.rb` are absent for this reason; **`socket.rb` is absent the same way and §14 did
> not name it.**
>
> **The decision is one line, in the unpacked gem:
> `rex-socket-0.1.71\src\lib\rex\socket.rb:51-53` → `return param.comm.create(param)`**, with
> `comm.rb:48-50` an abstract `create` that **raises `NotImplementedError`** — the base deliberately
> refuses to decide. `proxies.rb` is 1,518 B and **parses only** (five types, `:7-11`) and never
> connects; `parameters.rb` parses `'SSL'`:116, `'SSLVersion'`:128, `'Proxies'`:175-176, `'Proto'`:180-181,
> `'Comm'`:188 and **forwards all four.** Verified across all 302 protocol files: **27 call `Rex::Socket`,
> ZERO decide locally.**
>
> **So §11's "protocol zoo" is accurate as a description of `lib/rex/proto/`, and it answers a different
> question than "where is transport decided." Five socket files (~78 KB) answer what 302 protocol files
> appear to be needed for.**
>
> **And twelve of the eighteen `rex-*` gems are absent from the corpus entirely** —
> `04_TOOLS\gems\` holds six (`rex-arch`, `rex-core`, `rex-encoder`, `rex-powershell`, `rex-socket`,
> `rex-text`). **`rex-exploitation` — the measured rank-1 gap at 13 call sites (cmd_stager, egghunter,
> jsobfu, omelet, rop_db, seh, vbsobfuscate, browser/http exploit servers) — is not among them.** Any
> coverage claim spanning Metasploit transport, TLS, or proxy handling must be read against that
> boundary. **Methods and full working: D22 §4 and §5.**

**Evidence basis.** Every claim is `[source]` — read from this checkout with file:line citations. There is no compiled Metasploit binary in this corpus; nothing here is binary-derived. **Client-vs-implant:** MSF is the *client* side. Ruby source proves what the client sends and expects, and only *infers* the implant's behaviour from the TLV names the client writes. Sections below mark each side explicitly.

**Read coverage.** D7 and D8 together read 6 files of ~9,973 code files. This document adds primary reads of the engine core: the meterpreter packet/parser/dispatcher, the extension architecture and its ID space, `stdapi` core, `payload_generator.rb`, `stager.rb`, `malleable_c2.rb`, `reverse_http.rb`, the encoder interface, and the transport manager.

## TABLE OF CONTENTS

1. The wire protocol core — 32-byte header in exact detail
2. `packet_dispatcher.rb` — GUID learning, request/response correlation
3. The extension architecture — 23 subdirs, the ID space, and the `tlv.rb` map layer
4. `lib/msf/core/payload/` — the build pipeline
5. `malleable_c2.rb` — profile → TLV compilation, and the unencrypted config channel
6. `lib/msf/core/handler/reverse_http.rb` — the HTTP C2 handler
7. The encoder chain — `lib/msf/core/encoder.rb` and the alphabet/XOR mixins
8. The transport layer — runtime-mutable C2 and failover
9. Hardcoded values, ports, and paths
10. Residual unknowns and explicit gaps
11. `lib/rex/proto/` — the protocol zoo
12. The socket and stream substrate — and the discovery that reshapes the rest of this document
13. `lib/rex/parser/` — the outside-world ingestion surface
14. `lib/rex/text.rb` and `lib/rex/arch.rb` — both absent, and what the in-tree utility layer actually is
15. `lib/rex/payloads/` — the shared payload builders
16. The synthesized picture — what `lib/` does for the framework
17. The externalized Rex layer — the gap closed

---

## 1. The wire protocol core — the 32-byte header in exact detail

`lib/rex/post/meterpreter/packet.rb` (1,120 lines) is the authoritative definition of the meterpreter wire format. The header is specified by an inline comment block at `:803-829` and implemented at `:831-841` and `:1014-1018`.

**Size constants** `[source]` — `packet.rb:831-837`:
```ruby
XOR_KEY_SIZE         = 4
ENCRYPTED_FLAGS_SIZE = 4
PACKET_LENGTH_SIZE   = 4
PACKET_TYPE_SIZE     = 4
PACKET_HEADER_SIZE   = XOR_KEY_SIZE + GUID_SIZE + ENCRYPTED_FLAGS_SIZE + PACKET_LENGTH_SIZE + PACKET_TYPE_SIZE
AES_IV_SIZE          = 16
```
`GUID_SIZE = 16` is at `packet.rb:165`. The sum is `4 + 16 + 4 + 4 + 4 = 32`.

### 1.1 Exact header field layout

The authoritative parse is `parse_header!` at `packet.rb:1014-1018` `[source]`:

```ruby
def parse_header!
  xor_key = self.raw.unpack('a4')[0]
  data = xor_bytes(xor_key, self.raw[0..PACKET_HEADER_SIZE])
  _, self.session_guid, self.encrypt_flags, self.length, self.type = data.unpack('a4a16NNN')
end
```

The serialization counterpart is `to_r` at `packet.rb:980-997` `[source]`. Note that `xor_key` is **generated first, then prepended outside the XOR** (`:981`, `:996`), so the key itself is transmitted plaintext while everything after it is XORed with a 4-byte repeating key.

| Offset | Width | Name | Encoding / endianness | Set by | Read by |
|---|---|---|---|---|---|
| 0 | 4 | `xor_key` | 4 raw bytes, **not XORed**; each byte `rand(254)+1` so never `0x00` | `to_r :981` | `parse_header! :1015`, `raw_bytes_required :930`, `from_r :1028` |
| 4 | 16 | `session_guid` | raw 16 bytes; `NULL_GUID = "\x00"*16` (`:166`) when unset | `to_r :983` (`session_guid \|\| NULL_GUID`) | `parse_header! :1017` |
| 20 | 4 | `encrypt_flags` | uint32 **network byte order** (`N`) | `to_r :990` / `:992` | `parse_header! :1017`, `decrypt_packet :1006` |
| 24 | 4 | `length` | uint32 BE (`N`) — length of the **packet data** only, excludes the 32-byte header in the encrypted branch, *includes* an 8-byte TLV header | `to_r :990` / `:992` | `parse_header! :1017`, `raw_bytes_required :933` |
| 28 | 4 | `packet_type` | uint32 BE (`N`) | `to_r :990` / `:992` (`self.type`) | `parse_header! :1017` |
| 32 | X | packet data | plaintext TLV stream, **or** `IV(16) ‖ AES-CBC ciphertext` | `to_r :990` / `:992` | `from_r :1029-1031` |

**Byte-order distinction worth calling out** `[source]`: the header fields use `unpack('a4a16NNN')` — `N` is big-endian. But the TLV layer at `packet.rb:503` packs its own header as `"NN"` (also big-endian), while the *QWORD* TLV meta-type is explicitly little-endian: `[self.htonq(value.to_i)].pack("Q<")` at `packet.rb:477`. So TLV payloads are a mix: length/type big-endian, QWORD values little-endian. That is a real inconsistency in the format, not a transcription error.

### 1.2 Packet types

`packet.rb:12-16` `[source]`:
```ruby
PACKET_TYPE_REQUEST         = 0
PACKET_TYPE_RESPONSE        = 1
PACKET_TYPE_CONFIG          = 2
PACKET_TYPE_PLAIN_REQUEST   = 10
PACKET_TYPE_PLAIN_RESPONSE  = 11
```

`create_response` at `packet.rb:863-887` `[source]` mirrors PLAIN_REQUEST → PLAIN_RESPONSE and otherwise RESPONSE → and copies `TLV_TYPE_REQUEST_ID` back into the response (`:875-884`), which is how correlation closes.

### 1.3 Encryption flags, and the CONFIG guard

`packet.rb:839-841` `[source]`:
```ruby
ENC_FLAG_NONE   = 0x0
ENC_FLAG_AES256 = 0x1
ENC_FLAG_AES128 = 0x2
```

The critical branch is `to_r` at `packet.rb:986` `[source]`:
```ruby
if @type != PACKET_TYPE_CONFIG && key && key[:key] && (key[:type] == ENC_FLAG_AES128 || key[:type] == ENC_FLAG_AES256)
```
**`PACKET_TYPE_CONFIG` (2) is structurally excluded from TLV encryption.** A config packet takes the `else` branch at `:992` — `[ENC_FLAG_NONE, tlv_data].pack('NA*')` — and ships as plaintext TLVs. This is only XOR-obfuscated by the 4-byte repeating key, which is transmitted alongside the ciphertext in the clear. XOR with a transmitted key is obfuscation, not encryption. §5 shows `malleable_c2.rb` rides exactly this channel.

In the encrypted branch `:988-990`, note what is and is not encrypted:
```ruby
iv, ciphertext = aes_encrypt(key[:key], tlv_data[HEADER_SIZE..-1])
raw << [key[:type], iv.length + ciphertext.length + HEADER_SIZE, self.type, iv, ciphertext].pack('NNNA*A*')
```
Only `tlv_data[HEADER_SIZE..-1]` is encrypted — the 8-byte TLV group header is skipped. So the length and type of the outermost TLV group remain in cleartext even when AES is active.

### 1.4 AES parameters

`aes_encrypt` / `aes_decrypt` at `packet.rb:941-972` `[source]`:
- Cipher: `OpenSSL::Cipher.new("AES-#{size}-CBC")` (`:945`, `:962`) — selects AES-128-CBC or AES-256-CBC.
- Key width validated to exactly 128 or 256 bits, else `ArgumentError` (`:943`, `:960`).
- IV: `aes.random_iv` — a fresh random 16-byte IV per packet (`:947`), prepended to the ciphertext in `to_r :990`.
- Decrypt: `iv = data[0, AES_IV_SIZE]` then `aes_decrypt(key, iv, data[iv.length..-1])` (`packet.rb:1007-1008`).

`decrypt_packet` at `packet.rb:1002-1012` carries an inline TODO `[source]` at `:1003-1005` acknowledging that a mismatch between expected and received encryption flags is **not** rejected:
```ruby
# TODO: throw an error if the expected encryption isn't the same as the given
#       as this could be an indication of hijacking or side-channel packet addition
#       as highlighted by Justin Steven on github.
```
The comparison at `:1006` requires `encrypt_flags == key[:type]`, and any mismatch silently falls through to `else data` (`:1009-1010`) — returning the **raw, undecrypted** bytes rather than raising.

### 1.5 The TLV layer beneath the packet

`Tlv#to_r` at `packet.rb:468-504` `[source]` — each TLV is:

| Offset | Width | Field | Encoding |
|---|---|---|---|
| 0 | 4 | length | `raw.length + HEADER_SIZE`, packed `"N"` (big-endian) |
| 4 | 4 | type | packed `"N"` (big-endian); meta-type bits OR'd with the base ID |
| 8 | X | value | per meta-type |

`HEADER_SIZE = 8` at `packet.rb:319`. Value encoding by meta-type (`:472-484`) `[source]`: STRING appends a NUL terminator; UINT packs `"N"`; QWORD packs `"Q<"` (little-endian); BOOL packs a single `"c"` byte (`1`/`0`); RAW is the bytes verbatim.

Meta-types `packet.rb:21-29` `[source]` — these are **bit 16..31 flags OR'd onto the base type**:
```ruby
TLV_META_TYPE_NONE       = 0
TLV_META_TYPE_STRING     = (1 << 16)
TLV_META_TYPE_UINT       = (1 << 17)
TLV_META_TYPE_RAW        = (1 << 18)
TLV_META_TYPE_BOOL       = (1 << 19)
TLV_META_TYPE_QWORD      = (1 << 20)
TLV_META_TYPE_COMPRESSED = (1 << 29)
TLV_META_TYPE_GROUP      = (1 << 30)
TLV_META_TYPE_COMPLEX    = (1 << 31)
```
`TLV_META_MASK` (`:33-41`) deliberately **excludes** `COMPRESSED` with an explicit comment at `:31-32`: "Exclude compressed from the mask since other meta types (e.g. RAW) can also be compressed." So compression is an orthogonal flag, not a type.

Compression is applied only when it actually shrinks the data — `packet.rb:487-501` `[source]`. If not smaller, the compressed form is discarded and the flag is not set: `if raw_compressed.length < raw_uncompressed.length` (`:494`). When used, the value becomes `[uncompressed_length].pack("N") + compressed_data` (`:499`), because zlib needs the inflation target size. Type base ranges: `TLV_RESERVED=0`, `TLV_EXTENSIONS=20000`, `TLV_USER=40000`, `TLV_TEMP=60000` (`:46-49`).

### 1.6 Stream framing — `raw_bytes_required`

`packet.rb:925-939` `[source]` is what makes the protocol work over a byte stream:
```ruby
if self.raw.length >= PACKET_HEADER_SIZE
  xor_key = self.raw.unpack('a4')[0]
  decoded_bytes = xor_bytes(xor_key, raw[0, PACKET_HEADER_SIZE])
  _, _, _, length, _ = decoded_bytes.unpack('a4a16NNN')
  length + PACKET_HEADER_SIZE - HEADER_SIZE - self.raw.length
else
  PACKET_HEADER_SIZE - self.raw.length
end
```
The parser cannot know the frame size until the header is decrypted, and the header can't be decrypted without the first 4 bytes. So `raw_bytes_required` is a two-phase read: first ask for the full 32 bytes, then extract `length` and compute the remainder.

The `- HEADER_SIZE` term (8 bytes) is present because the serialized `length` field includes the 8-byte TLV group header (per `to_r :990`), while the 32-byte packet header does not. This produces the non-obvious identity: **`raw_bytes_required` for a complete packet is `length + 32 - 8`.** A framer that assumed `length + 32` would over-read by 8 bytes every packet.

`PacketParser#recv` at `packet_parser.rb:32-52` `[source]` drives that loop and raises `EOFError` on a truncated stream (`:43`) — distinguishing clean EOF from a partial packet, since a non-nil partial read returns `nil` and loops (`:45`).

---

## 2. `packet_dispatcher.rb` — GUID learning, correlation, and failure paths

`lib/rex/post/meterpreter/packet_dispatcher.rb` (782 lines). Timeouts are declared at `:49-56` `[source]`: `PACKET_TIMEOUT = 600`, `PING_TIME = 60`.

### 2.1 How the session GUID is learned

`receive_packet` at `:467-476` `[source]`:
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

The GUID is **adopted from the first inbound packet whose GUID field is non-NULL**. The client starts with `session_guid == NULL_GUID` (`"\x00"*16`) and latches whichever GUID the implant sends first. Note the asymmetry: the learning is gated on the *client's* current value being null, but it does not validate that the incoming GUID is itself non-null — a packet carrying a NULL GUID while the client is still NULL would set `session_guid` to NULL again, leaving the latch open. In practice the implant always sends its real GUID.

The client side sets the GUID explicitly in the stage config instead: `config.rb:61` generates `session_guid = [SecureRandom.uuid.gsub('-','')].pack('H*')` for staged sessions, or `"\x00"*16` for stageless/null sessions (`config.rb:58-62`) `[source]`. So the GUID is chosen by the **client** at stage-build time, embedded in the config TLV, and then echoed back by the implant — which is why `receive_packet`'s latch works.

### 2.2 Request/response correlation

Correlation is by a 32-character decimal string, not a counter.

- A request generates its RID in the constructor: `packet.rb:911-918` builds a 32-digit string via `32.times { |val| rid << rand(10).to_s }` and adds it as `TLV_TYPE_REQUEST_ID` `[source]`.
- `add_response_waiter` at `:504-514` creates `PacketResponseWaiter.new(request.rid, ...)` and appends to `self.waiters` `[source]`.
- Matching is `waiting_for?` at `packet_response_waiter.rb:63-64` `[source]`: `return (packet.rid == rid)` — a literal string comparison.
- `notify_response_waiter` at `:520-535` iterates waiters and **breaks on the first match** (`:531`) `[source]`.

Two structural consequences worth recording. First, the RID is random decimal digits with no uniqueness enforcement — collision probability is low but the matching loop takes the *first* waiter with a matching RID, so a collision would mis-deliver a response. Second, `notify_response_waiter` returns `handled` (a boolean), and `dispatch_inbound_packet` returns early when it is true (`:592-594`) `[source]` — so a response consumed by a waiter never reaches the inbound handlers.

### 2.3 Dispatch order and the parse-failure path

`dispatch_inbound_packet` at `:579-619` `[source]` runs in this order:
1. `log_packet(packet, :recv)` (`:582`), then `self.last_checkin = ::Time.now` (`:585`).
2. Resolve pivot session; propagate `last_checkin` to the pivoted session (`:587-588`).
3. If `packet.response?` and a waiter matched → return `true` immediately (`:592-594`).
4. Otherwise iterate `@inbound_handlers`, calling `response_handler` or `request_handler` depending on `packet.response?` (`:603-607`), and break on the first handler returning truthy (`:614-616`).

The handler exception path is notable `[source]` — `:609-612`:
```ruby
rescue ::Exception => e
  dlog("Exception caught in dispatch_inbound_packet: handler=#{handler} #{e.class} #{e} #{e.backtrace}", 'meterpreter', LEV_1)
  return true
end
```
It rescues `::Exception` (not `StandardError`), logs at `LEV_1` (the lowest, debug-only level — invisible at default verbosity), and **returns `true`, reporting the packet as handled** even though it threw. A handler that crashes on a malformed packet silently consumes that packet and stops the handler chain. The failure is invisible unless debug logging is on.

### 2.4 Incomplete-packet backlog

`monitor_socket` maintains an `@incomplete_queue`. When it exceeds 100 entries, 25 are popped and dropped (`:445-452`) `[source]`, logged via `dlog` at `LEV_1`. This is a bounded-loss acceptance: under sustained partial-read pressure the dispatcher discards buffered fragments rather than growing without limit.

### 2.5 Pivot decryption divergence

`decrypt_inbound_packet` at `:565-571` `[source]`:
```ruby
pivot_session = self.find_pivot_session(packet.session_guid)
tlv_enc_key = self.tlv_enc_key
tlv_enc_key = pivot_session.pivoted_session.tlv_enc_key if pivot_session
packet.from_r(tlv_enc_key)
```
Each pivoted session carries its **own** `tlv_enc_key`; a packet's key is selected by matching its `session_guid` against known pivots. This means TLV encryption is per-session, and the GUID in the cleartext header is the routing key for which key to use.

### 2.6 Passive (HTTP) dispatcher

For HTTP(S) sessions there is no persistent socket; the ciphertext arrives as an HTTP request body. `on_request` at `:761-773` `[source]`:
```ruby
body = self.unwrap_packet(body) if self.respond_to?(:unwrap_packet)
packet = Packet.new(0)
packet.add_raw(body)
packet.parse_header!
packet = decrypt_inbound_packet(packet)
dispatch_inbound_packet(packet)
```
The outbound path uses `send_queue` / `recv_queue` (`:80-92`) and `on_passive_request` (`:94-103`) shifts one queued response per inbound HTTP request (`:97`). Because the response is queued and drained by the *next* request, the passive transport is inherently request-paced — which is why `client_core.rb`'s shutdown path waits for a reply over HTTP but sends-and-forgets over TCP (`client_core.rb:752-761`) `[source]`.

---

## 3. The extension architecture — 23 subdirs, the ID space, and the `tlv.rb` map layer

### 3.1 Measured structure

Enumerated directly `[source]` — `lib/rex/post/meterpreter/extensions/` contains **exactly 23 subdirectories and zero `.rb` files directly in the parent**. Extension Ruby file counts per subdirectory:

| Extension | .rb | Extension | .rb | Extension | .rb |
|---|---|---|---|---|---|
| stdapi | 72 | extapi | 10 | lanattacks | 5 |
| priv | 5 | android | 3 | appapi | 3 |
| bofloader | 3 | espia | 3 | incognito | 3 |
| kiwi | 3 | peinjector | 3 | powershell | 3 |
| python | 3 | sniffer | 3 | unhook | 3 |
| winpmem | 3 | stdapi_audio | 1 | stdapi_fs | 1 |
| stdapi_net | 1 | stdapi_railgun | 1 | stdapi_sys | 1 |
| stdapi_ui | 1 | stdapi_webcam | 1 | | |

`stdapi` dominates at 72 files (≈72% of extension code). The seven `stdapi_*` single-file directories are **not** independent extensions — they each register the same `EXTENSION_ID_STDAPI` and exist purely so `require` paths resolve per-subsystem. This was verified per-file, not assumed.

### 3.2 The ID space

Two orthogonal numeric spaces.

**Extension IDs** are multiples of `COMMAND_ID_RANGE = 1000` (`core_ids.rb:10`), so the extension a command belongs to is recoverable by integer division: `lib/rex/post/meterpreter/extension_mapper.rb:41` does exactly this — `id = id - (id % COMMAND_ID_RANGE)` `[source]`.

Measured extension IDs `[source]` from each extension's `command_ids.rb`:

| ID | Extension | ID | Extension |
|---|---|---|---|
| 0 | core (`core_ids.rb:13`) | 8000 | kiwi |
| 1000 | stdapi | 9000 | appapi |
| 2000 | priv | 10000 | unhook |
| 3000 | extapi | 11000 | espia |
| 4000 | sniffer | 12000 | incognito |
| 5000 | android | 13000 | python |
| 7000 | winpmem | 14000 | powershell |
| | | 15000 | lanattacks |
| | | 16000 | bofloader |
| | | 18000 | bofloader |

*(6000 and 17000 are unused in this checkout — observed absent, not assumed.)*

Commands are then `EXTENSION_ID + N` where N starts at 1: e.g. `COMMAND_ID_CORE_CHANNEL_CLOSE = 0 + 1` through `COMMAND_ID_CORE_PIVOT_SESSION_NEW = 0 + 34` (`core_ids.rb:15-48`), and `COMMAND_ID_STDAPI_FS_CHDIR = 1000 + 1` (`extensions/stdapi/command_ids.rb:13`). **The core extension has 34 commands** (IDs 1–34), which matches D7 §8.1's count of ten transport-manipulating core commands.

**TLV type IDs** are a *separate* space. Core TLVs live at low offsets OR'd with meta-type bits (`packet.rb:54-145`). Extension TLVs are offset into the `TLV_EXTENSIONS = 20000` band (`packet.rb:47`). The pattern is visible in every `tlv.rb`, e.g. `extensions/priv/tlv.rb:9`: `TLV_TYPE_SAM_HASHES = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 1)` `[source]`, and `:20` `TLV_TYPE_ELEVATE_TECHNIQUE = TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 200)`.

### 3.3 What the 17 `tlv.rb` files are for

Enumerated across the whole repository `[source]` — **exactly 17 `tlv.rb` files**, one per extension that needs its own symbolic constants, plus one nested at `extensions/stdapi/railgun/tlv.rb`:

`android` (5,850 B), `appapi` (675 B), `bofloader` (550 B), `espia` (397 B), `extapi` (8,464 B), `incognito` (911 B), `kiwi` (280 B), `lanattacks` (454 B), `peinjector` (556 B), `powershell` (558 B), `priv` (1,098 B), `python` (790 B), `sniffer` (1,276 B), `stdapi` (12,139 B), `stdapi/railgun` (3,646 B), `unhook` (206 B), `winpmem` (284 B).

The map layer's purpose is **name-to-number binding for one direction of the wire protocol**. Each file is a flat list of `TLV_TYPE_X = <meta-type> | (TLV_EXTENSIONS + N)` constants. There is no class, no runtime lookup, no dispatch — it is a compile-time symbol table. Its value is that the *client* and the *implant* independently maintain the same numeric constants, and the Ruby file is the client's authoritative copy. When a `tlv.rb` and the implant's C header drift, the type number changes meaning and the client silently misreads a field as the wrong meta-type. `packet.rb:168-214` shows the framework actively *generates* the implant's C header (`generate_command_id_map_c`) from this same Ruby data — confirming the Ruby side is the source of truth and the C header is a build artifact of it.

`stdapi` (12,139 B) is the largest because it covers fs/net/sys/railgun/ui in one flat namespace; `railgun` has its own separate file because its types are namespaced separately.

### 3.4 Registration and dispatch

**Registration** — an extension subclasses `Rex::Post::Meterpreter::Extension` (`extension.rb:29-45`), which is a 47-line base holding only `client` and `name` (`:34-37`) `[source]`. It declares `self.extension_id` (e.g. `stdapi.rb:41-43`, `priv.rb:23-25`) and in its constructor calls `client.register_extension_aliases(...)` (`stdapi.rb:53`, `priv.rb:43`).

The alias mechanism is how extension objects become reachable as methods on the session. `priv.rb:43-49` `[source]` registers a single alias `'priv' => self`, so `session.priv.getsystem` resolves. `stdapi.rb:53-106` registers **eight** aliases — `fs`, `sys`, `net`, `railgun`, `webcam`, `mic`, `audio_output`, `ui` — several of them `ObjectAliases` containers nesting further objects (`fs` → `dir`/`file`/`filestat`/`mount` at `:57-63`). So the client-side call surface is a tree assembled at extension-load time, not a fixed dispatch table.

**Extension resolution** — `extension_mapper.rb:26-34` maps name → ID by loading the class and reading `k.extension_id` `[source]`; `get_extension_name` (`:40-52`) inverts it by masking off the command offset. `get_extension_module` (`:61-72`) does `require("rex/post/meterpreter/extensions/#{name}/#{name}")` and rescues `LoadError` into a `RuntimeError` ("module does not exist") — so the filesystem layout *is* the extension registry. `@@klasses` (`:9`) memoizes loaded classes `[source]`.

**Dispatch of a TLV to an extension** happens in the implant, not the client. The client's `@inbound_handlers` (`packet_dispatcher.rb:598`) are Ruby handlers for *client-side* concerns (e.g. the HTTP passive dispatcher); the command-ID → handler routing that turns `TLV_TYPE_COMMAND_ID = 1041` into a filesystem operation occurs on the remote side. **This is a client-view/inplant-view boundary:** from this source we can enumerate the ID space and the request/response TLV contract exactly, but we cannot prove from Ruby alone how the implant routes internally.

### 3.5 Worked example, end-to-end: `priv.getsystem`

`extensions/priv/priv.rb:58-115` is a compact complete instance of the request/response pattern `[source]`:

1. **Build request** — `Packet.create_request(COMMAND_ID_PRIV_ELEVATE_GETSYSTEM)` (`:59`). Command ID is `2000 + n`, registered as `EXTENSION_ID_PRIV`.
2. **Conditional TLVs** — a random 6-alpha service name is added only for the service-based techniques (`:62-64`); the elevator DLL is read, decrypted, and attached only for `token_dup`/`named_pipe_2`/`any` (`:69-90`).
3. **Meta-typed values** — `TLV_TYPE_ELEVATE_SERVICE_NAME` is STRING, `TLV_TYPE_ELEVATE_SERVICE_DLL` is RAW (a whole DLL), `TLV_TYPE_ELEVATE_SERVICE_LENGTH` is UINT (`tlv.rb:20-23`).
4. **Send with an extended timeout** — `client.send_request(request, 90)` (`:95`), with an explicit comment that service routines are slow.
5. **Read the result** — dual channel: `response.get_tlv_value(TLV_TYPE_ELEVATE_TECHNIQUE)` (`:97`) for payload data, and `response.result == 0` (`:99`) for status. `result` maps to `TLV_TYPE_RESULT` (`packet.rb:58`, accessor at `:1093-1109`) — **result code is a reserved common TLV, not per-command.**
6. **Post-condition side effects** — `client.core.use('stdapi')` if not already loaded (`:100`), then `update_session_info` and `getprivs` (`:101-102`) because privilege state changed and the cached session info is now stale.

Two details generalize. First, `send_request(request, 3600)` at `:122` for SAM hash dumping — a one-hour timeout, again with an explanatory comment. Timeouts are per-call and tuned by expected latency, not global. Second, `extensions/priv/priv.rb:52` initializes a sub-object via `self.fs = Fs.new(client)` behind a `protected attr_writer` (`:136`) — the same composition pattern as `stdapi`.

**File-size asymmetry as an architecture signal** `[source]`: `priv/tlv.rb` is 1,098 B declaring ~10 types; `stdapi/tlv.rb` is 12,139 B. The TLV surface, not the command surface, scales with extension complexity.

---

## 4. `lib/msf/core/payload/` — the build pipeline

### 4.1 Measured structure

Enumerated `[source]` — **30 `.rb` files at the top level and 14 subdirectories**. Top level by size (descending):

| File | Size | File | Size |
|---|---|---|---|
| malleable_c2.rb | 17,686 B | transport_config.rb | 4,739 B |
| apk.rb | 16,095 B | android.rb | 4,339 B |
| uuid.rb | 11,826 B | nodejs.rb | 3,669 B |
| stager.rb | 9,140 B | macho.rb | 3,252 B |
| firefox.rb | 9,005 B | python.rb | 2,760 B |
| generic.rb | 7,767 B | mainframe.rb | 1,975 B |
| osx.rb | 6,764 B | adapter.rb | 1,898 B |
| windows.rb | 6,564 B | single.rb | 1,316 B |
| jsp.rb | 5,943 B | pingback.rb | 1,081 B |
| php.rb | 5,667 B | multi.rb | 936 B |
| java.rb | 5,646 B | ruby.rb | 915 B |
| aix.rb | 5,563 B | custom.rb | 824 B |
| bsd.rb | 5,025 B | netware.rb | 725 B |
| solaris.rb | 4,742 B | hardware.rb | 605 B |
| linux.rb | 472 B | r.rb | 153 B |

Subdirectory `.rb` counts: `windows : 61`, `linux : 35`, `adapter : 15`, `java : 6`, `python : 6`, `android : 5`, `php : 4`, `osx : 3`, `multi : 2`, `bsd : 1`, `cmd : 1`, `custom : 1`, `pingback : 1`, `uuid : 1`.

The top level is **platform adapters** (`windows.rb`, `linux.rb`, `java.rb`, `php.rb`, `python.rb`, `nodejs.rb`, `ruby.rb`, `osx.rb`, `bsd.rb`, `solaris.rb`, `aix.rb`, `netware.rb`, `hardware.rb`, `mainframe.rb`, `firefox.rb`, `jsp.rb`, `macho.rb`, `apk.rb`) plus the **cross-cutting mixins** (`stager.rb`, `single.rb`, `multi.rb`, `adapter.rb`, `generic.rb`, `custom.rb`, `uuid.rb`, `transport_config.rb`, `malleable_c2.rb`). Note `linux.rb` at 472 B versus `windows.rb` at 6,564 B — the Windows adapter carries far more logic, consistent with the `windows : 61` subdirectory count. The weight of the payload system is Windows.

### 4.2 `payload_generator.rb` — the pipeline in order

`lib/msf/core/payload_generator.rb` (598 lines). `generate_payload` at `:397-443` is the orchestrator `[source]`; its ordering is the pipeline:

```
raw_payload = generate_raw_payload      # :415  (or java/apk special cases :402-413)
raw_payload = add_shellcode(raw_payload) # :416
raw_payload = encode_payload(...)        # :421  (or multiple_encode_payload :419)
raw_payload = prepend_nops(raw_payload)  # :426
gen_payload = format_payload(raw_payload) # :427
```

Five ordered stages, each a distinct method.

**Stage 1 — `generate_raw_payload` (`:451-479`)** `[source]` asks the payload *module* to produce raw bytes by calling `payload_module.generate_simple('Format' => 'raw', 'Options' => datastore, 'Encoder' => nil, 'MaxSize' => @space, 'DisableNops' => true)` (`:471-477`). Note `'Encoder' => nil` and `'DisableNops' => true` — the module is explicitly told **not** to encode or pad, because the generator owns those stages. Platform and arch compatibility are checked first (`:461-469`), raising `IncompatiblePlatform` / `IncompatibleArch`. A special `payload == 'stdin'` path (`:452-458`) allows arbitrary supplied bytes, but still requires explicit arch and platform.

**Stage 2 — `add_shellcode` (`:416`)** wraps/prefixes the raw bytes. Not read in this pass — see §10.

**Stage 3 — `encode_payload` (`:269-304`)** `[source]`. `get_encoders` (`:484-499`) resolves the user's encoder list; a `@`-prefixed encoder is a *chained* list and routes to `multiple_encode_payload` (`:418-419`). The selection loop at `:280-293` tries each encoder, catching `Msf::EncoderSpaceViolation` and `Msf::EncodingError` and `next`-ing to the following candidate (`:286-292`).

Two selection behaviours hinge on `@smallest` `[source]`:
- `break unless @smallest` (`:285`) — in normal mode the **first** encoder that succeeds wins and the loop stops.
- In `smallest` mode the loop runs all candidates and the tail at `:300-303` picks the shortest: `sort{|a,b| results[a].length <=> results[b].length}.first`.

If nothing succeeded: `raise ::Msf::EncodingError, "No Encoder Succeeded"` (`:296`). With no encoder requested it prints "No encoder specified, outputting raw payload" and returns unmodified (`:272-275`) — encoding is opt-in.

**Stage 4 — `prepend_nops` (`:423-426`)** `[source]` — `@nops = nops - raw_payload.length` then prepend, i.e. pad up to a target size. Only active when `padnops` is set.

**Stage 5 — `format_payload` (`:332-361`)** `[source]` converts raw shellcode to the requested container. Three routes: big-endian JS (`js_be`, `:348-353`, guarded by `Rex::Arch.endian(arch) != ENDIAN_BIG` → `IncompatibleEndianess`); `Msf::Simple::Buffer.transform` for buffer formats (`:354-355`); and `Msf::Util::EXE.to_executable_fmt` for executable containers (`:356-357`). Format/architecture mismatches are rejected up front at `:338-345` — an ELF payload can only emit `elf`, a Mach-O only `macho`.

Encryption parameters are threaded through formatting via `encryption_opts` (`:333-336`) carrying `format`, `iv`, and `key` — so **output-format encryption is a property of the generator, applied after encoding, distinct from the meterpreter TLV AES layer in §1.**

**Size enforcement** at `:430-442` `[source]`: prints `Payload size: N bytes`; raises `PayloadGeneratorError` if `gen_payload.nil?`; raises `PayloadSpaceViolation` if `raw_payload.length > @space` and not in smallest mode. The space check is applied to the *raw* pre-format payload (`:434`) — container overhead added by `format_payload` is not counted against `@space`.

**Java is a separate pipeline entirely** (`:363-392`) `[source]` — `generate_java_payload` dispatches on format to `generate_jar` / `generate_war` / `generate_axis2` and never enters the encode/nop/format chain. `generate_payload` short-circuits at `:402-405`, setting `raw_payload = encoded_payload = gen_payload` with no encoding applied.

### 4.3 `stager.rb` — stage encoding and the fallback

`lib/msf/core/payload/stager.rb` (329 lines). Four advanced options registered at `:19-25` `[source]`: `EnableStageEncoding` (default `false`), `StageEncoder`, `StageEncoderSaveRegisters`, and `StageEncodingFallback` (default **`true`**).

`encode_stage?` at `:136-138` is simply `!!(datastore['EnableStageEncoding'])` `[source]` — stage encoding is off unless explicitly enabled. `transport_config` at `:34-49` `[source]` derives direction and protocol from the module's own refname by regex: `/reverse_/` → `reverse` else `bind`; `/_tcp/` → `tcp`; `/_https/` → `https`; else `http`. It then `send`s `transport_config_<direction>_<proto>`. **Module naming is load-bearing here** — a module whose refname does not match these patterns silently falls through to the HTTP default.

The fallback at `:307-313` `[source]`:
```ruby
rescue
  if datastore['StageEncodingFallback'] && estg.nil?
    print_warning("StageEncoder failed, falling back to no encoding")
    estg = stg
  else
    raise RuntimeError, "Stage encoding failed and StageEncodingFallback is disabled"
  end
end
```
Note this is a **bare `rescue`** — it catches `::StandardError` including the `RuntimeError` it may itself raise, and it catches `NoMethodError`/`ArgumentError` from a bad encoder name. It discards the exception object entirely, so the operator sees "StageEncoder failed" with no cause. Combined with the `true` default, a misconfigured stage encoder degrades silently to an unencoded stage rather than failing the run. That is a deliberate availability-over-correctness trade, and it is also why a stage encoder problem can present as "the payload ran but the AV signature was present" with no error output.

Also `encode_stage_preserved_registers` at `:261` and `encode_stage(stg)` at `:269` are the two entry points; `stage_prefix` (`:326`) allows a tag or prefix to be prepended to a stage.

---

## 5. `malleable_c2.rb` — profile → TLV compilation, and the unencrypted config channel

`lib/msf/core/payload/malleable_c2.rb` (586 lines, 17,686 B — the largest single file in `lib/msf/core/payload/`). Its own header at `:3-8` cites the Cobalt Strike Malleable C2 user guide, making the lineage explicit: **this is a Cobalt Strike profile grammar implemented in Ruby.**

### 5.1 Architecture

Three layers, visible in the class layout `[source]`:
- **`Lexer` (`:52-`)** — a `StringScanner` tokenizer over `File.binread(file)` (`:99-102`). Not a YAML parser; a hand-written lexer for CS profile syntax (block/`set`/`header`/`parameter` directives).
- **`ParsedSection` / `ParsedSet` (`:380-393`)** — the parse tree. `ParsedSet#initialize` **downcases the key** (`:383`) and runs `MC2.from_c2_string_value` on the value (`:384`), so profile keywords are case-insensitive and escapes are resolved at parse time.
- **`Profile` (with `to_tlv` at `:233-248`)** — the compiler, emitting `Rex::Post::Meterpreter::GroupTlv` structures.

Two keyword tables `[source]`: `BLOCK_KEYWORDS` at `:56-69` (`client, http-get, http-post, http-stager, https-certificate, id, metadata, output, server, stage, transform-x64, transform-x86`) and `OTHER_KEYWORDS` at `:71-97` (`add, append, base64, base64url, dns, encode_hex, header, hostport, mask, netbios, netbiosu, parameter, prepend, print, remove, set, string, stringw, strrep, transform, unset, uri, uri-append, uri-query, xor`).

### 5.2 Escape handling

`from_c2_string_value` at `:19-41` `[source]` resolves `\x..`, `\r`, `\t`, `\n`, `\"`, `\\` in a **single pass** via one regex, with an explicit comment at `:23-24`: "We do in a single regex and parse each as we go, as this avoids the potential for double-encoding." The comment at `:20-22` notes `\u` is **not** supported. The double-encoding concern is real: a two-pass substitution would re-interpret a `\x5c` produced by the first pass as an escape introducer for the second.

### 5.3 The TLV the profile compiles into

`to_tlv` at `:233-248` `[source]` builds exactly one root group:

```ruby
tlv = MET::GroupTlv.new(MET::TLV_TYPE_C2)          # :234 — TLV_META_TYPE_GROUP | 704
self.get_set('useragent') {|ua| tlv.add_tlv(MET::TLV_TYPE_C2_UA, ua)}  # :236 — STRING | 716
self.get_section('http-get') {|http_get| tlv.tlvs << build_get_tlv(...)}   # :239-241
self.get_section('http-post') {|http_post| tlv.tlvs << build_post_tlv(...)} # :243-245
```

So the structure is `TLV_TYPE_C2` (GROUP) containing two child groups, `TLV_TYPE_C2_GET` (`:253`, `GROUP | 713`) and `TLV_TYPE_C2_POST` (`:269`, `GROUP | 714`).

**Complete list of TLV types the compiler emits**, with the profile directive that produces each `[source]`:

| TLV type | Meta | Emitted at | Profile source |
|---|---|---|---|
| `TLV_TYPE_C2` | GROUP | `:234` | root of every profile |
| `TLV_TYPE_C2_UA` | STRING | `:236`, `:343` | `set useragent` |
| `TLV_TYPE_C2_GET` | GROUP | `:253` | `http-get { ... }` block |
| `TLV_TYPE_C2_POST` | GROUP | `:269` | `http-post { ... }` block |
| `TLV_TYPE_C2_URI` | STRING | `:373` | `set uri` (one TLV per candidate) |
| `TLV_TYPE_C2_HEADERS` | STRING | `:351` | `header "X" "Y"` in a non-metadata/id section |
| `TLV_TYPE_C2_PREFIX` | RAW | `:278` | `client { output { prepend ... } }` |
| `TLV_TYPE_C2_SUFFIX` | RAW | `:278` | `client { output { append ... } }` |
| `TLV_TYPE_C2_PREFIX_SKIP` | UINT | `:292` | computed from `server { output { prepend } }` length |
| `TLV_TYPE_C2_SUFFIX_SKIP` | UINT | `:296` | computed from `server { output { append } }` length |
| `TLV_TYPE_C2_ENC_OUTBOUND` | UINT | `:309` | `base64` / `base64url` in POST `client.output` |
| `TLV_TYPE_C2_ENC_INBOUND` | UINT | `:315` | `base64` / `base64url` in `server.output` |
| `TLV_TYPE_C2_ENC_UUID` | UINT | `:324` | `base64`/`base64url` in `client.metadata` (GET) or `client.id` (POST) |
| `TLV_TYPE_C2_UUID_PREFIX` | STRING | `:325` | `prepend` in metadata/id |
| `TLV_TYPE_C2_UUID_SUFFIX` | STRING | `:325` | `append` in metadata/id |
| `TLV_TYPE_C2_UUID_GET` | STRING | `:338` | `parameter "name"` in metadata/id |
| `TLV_TYPE_C2_UUID_HEADER` | STRING | `:339` | `header "name" ...` in metadata/id |

Sixteen types. All resolve to the C2 block in `packet.rb:118-145` — so this compiler writes into the same TLV namespace §1 documents, and the implant is the consumer.

### 5.4 The transform functions

Three distinct encoding decisions, deliberately separated `[source]`:

**`encoding_flags_for` (`:299-304`)** is the single decision point, returning one of `C2_ENCODING_NONE` / `C2_ENCODING_B64` / `C2_ENCODING_B64URL` (constants at `packet.rb:150-153`; note `C2_ENCODING_URL = 3` exists at `:153` but **no code path in this file emits it** — observed absent). Precedence is `base64` before `base64url` (`:301-302`), so a section declaring both gets B64.

**Directive concatenation** — `add_prepend_append_tlvs` (`:330-335`) joins *all* `prepend` directives in a section into one string and emits a single TLV, skipping empty (`:332`, `:334`). `add_header` (`:349-353`) joins multiple `header` directives with `"\r\n"` into one `TLV_TYPE_C2_HEADERS` value (`:350`) — so the wire format is a single CRLF-joined header blob, not one TLV per header.

**Skip-length computation** — `add_skip_tlvs` (`:289-297`) is the asymmetric half. `:291` computes `prefix_len = prepends.map{|p| p.args[0].length}.sum` and emits it as `TLV_TYPE_C2_PREFIX_SKIP`. This is a **server-side** transform: the implant must strip that many leading bytes from the response before parsing. `:290` reads `server_output&.prepend` for skip, while `:318-326` reads `client.metadata`/`client.id` for the UUID transform. So the client tells the implant exactly how many bytes of the *server's own* decoration to discard.

**URI construction** — `add_uri` (`:355-377`) `[source]` is the most consequential. `:356` builds a query string from `parameter` directives with `URI.encode_uri_component`. `:362` splits `set uri` on whitespace into **candidate URIs**, and `:366-375` emits **one `TLV_TYPE_C2_URI` per candidate**. The inline comment at `:358-361` explains why: CS picks a URI at random per request, and emitting a single space-joined string would register an unmatchable resource. `:363` collapses an absent URI to a single empty candidate to preserve query-string-only behaviour.

### 5.5 Runtime effect, and the cleartext channel

`wrap_outbound_get` (`:189-207`) `[source]` is the client-side mirror: it joins `server.output.prepend` as the prefix and `server.output.append` as the suffix (`:190-193`), base64-or-base64url-encodes the body if the section has that directive (`:197-201`), and returns `prefix + raw_bytes + suffix` (`:204`). `unwrap_inbound_post` (`:209-231`) is the inverse against `client.output`, stripping the prefix only if `raw_bytes.start_with?(prefix)` (`:212`) and the suffix only if `end_with?` (`:218`). **The prefix/suffix stripping is conditional, but the skip-length TLVs told the implant an unconditional byte count.** A response that fails the `start_with?` test on the client leaves those bytes in place while the implant-side skip count is unchanged — the two sides can disagree about framing.

**What the profile controls at runtime:** HTTP method-specific URI selection (per-request random from candidates), User-Agent, arbitrary headers, request-body prefix/suffix and encoding, response prefix/suffix and how many bytes to skip, and the placement/encoding of the session UUID (GET parameter, header, or cookie, with its own prefix/suffix and encoding). It is a **transport-shaping format**, not an encryption format.

**The cleartext channel.** `to_tlv` output is consumed by `Rex::Payloads::Meterpreter::Config#add_c2_tlv` and serialized into the stage config packet. Per §1.3, `packet.rb:986` excludes `PACKET_TYPE_CONFIG` from TLV encryption — config packets take the `:992` branch and ship as plaintext TLVs behind a 4-byte transmitted XOR key. Therefore **every value this compiler emits — the URIs, headers, User-Agent, UUID placement, prefixes, suffixes, and skip counts — is recoverable from a single config packet with a 4-byte XOR.** This corroborates D8 §3.7 from a second, independent code path.

**The cleartext channel.** `to_tlv` output is consumed by `Rex::Payloads::Meterpreter::Config#add_c2_tlv` and serialized into the stage config packet. Per §1.3, `packet.rb:986` excludes `PACKET_TYPE_CONFIG` from TLV encryption — config packets take the `:992` branch and ship as plaintext TLVs behind a 4-byte transmitted XOR key. Therefore **every value this compiler emits — the URIs, headers, User-Agent, UUID placement, prefixes, suffixes, and skip counts — is recoverable from a single config packet with a 4-byte XOR.** This corroborates D8 §3.7 from a second, independent code path.

The intended boundary: the config packet is delivered inside the *stage* over the transport the profile describes, so it is not the outer C2 channel. But it is the one packet guaranteed to carry the entire C2 configuration in a form that `packet.rb` cannot encrypt, and that is a property of the format rather than of any profile.

---

## 6. `lib/msf/core/handler/reverse_http.rb` — the HTTP C2 handler

**Filename trap resolved before reading.** `reverse_http.rb` exists in **14 locations** in this tree. Enumerated with sizes `[source]`:

- **Target: `lib\msf\core\handler\reverse_http.rb` — 19,124 B, 581 lines** (the handler)
- `lib\msf\core\payload\windows\reverse_http.rb` — 18,661 B (payload/stager mixin, different file)
- `lib\msf\core\payload\python\reverse_http.rb` — 5,219 B
- `lib\msf\core\payload\php\reverse_http.rb` — 3,127 B
- `lib\msf\core\payload\java\reverse_http.rb` — 2,317 B
- `lib\msf\core\payload\android\reverse_http.rb` — 1,429 B
- `lib\msf\core\payload\multi\reverse_http.rb` — 1,135 B
- `modules\payloads\stagers\windows\x64\reverse_http.rb` — 886 B
- `modules\payloads\stagers\windows\reverse_http.rb` — 820 B
- four more under `modules\payloads\stagers\{android,java,multi,php,python}\reverse_http.rb` — 694–803 B each

Only the 19,124 B handler file is described below. The 13 others were located and deliberately not conflated.

### 6.1 Class composition and the "tunnel" general type

`reverse_http.rb:19-23` `[source]` — the handler includes `Msf::Handler::Reverse`, `Msf::Handler::Reverse::Comm`, `Rex::Payloads::Meterpreter::UriChecksum`, and `Msf::Payload::Windows::VerifySsl`. Two declarations matter:

- `self.handler_type = 'reverse_http'` (`:28-30`)
- `self.general_handler_type = "tunnel"` (`:36-38`) — **not** `"reverse"`.

`"tunnel"` is the structural difference from every TCP handler: `reverse.rb` and `reverse_tcp.rb` declare `general_handler_type = "reverse"` and own a real listening socket with an accept loop, while the HTTP handler is a **request-driven service** with no per-connection socket lifecycle. There is no `start_handler` accept loop here — `setup_handler` (`:231-281`) starts a `Rex::Proto::Http::Server` via `Rex::ServiceManager.start` (`:241-249`) and registers a `Proc` per URI mount (`:265-272`) with `'VirtualDirectory' => true`. Sessions are created lazily from inbound requests.

### 6.2 URI scheme

**Listener URI** — `listener_uri` (`:102-106`) `[source]`: `"#{scheme}://#{uri_host}:#{bind_port}#{luri}"`, with IPv6 bracketing at `:104`. `scheme` (`:178-180`) is `(ssl?) ? 'https' : 'http'`, and `ssl?` (`:170-172`) is decided by `!!(self.refname.index('https'))` `[source]` — **the refname string decides TLS, not a datastore option.**

**`luri`** (`:199-201`) `[source]` is `construct_luri(datastore['LURI'] || '')`. `construct_luri` (`:182-194`) strips trailing `/` in a loop (`:187-189`) and guarantees a leading `/` (`:191`) — so `LURI` normalizes to a single-slash-prefixed, non-trailing-slash form. Default `LURI` is `''` (`:48-50`), yielding `'/'`.

**`payload_uri(req)`** (`:115-158`) `[source]` is a different function with a different purpose: it builds the *callback base* embedded in the stage. It harvests the `Host` header from the request (`:120-124`), then overrides it if `OverrideRequestHost` is set **or if no Host was sent** (`:127-131`), falling back to `LHOST`/`LPORT` (`:132-139`) and `scheme` (`:141-143`). This is what lets a stager that called in through a NAT or proxy be handed a callback address that reflects how it actually arrived.

**`all_uris`** (`:203-212`) `[source]` is the mount list: `["#{luri}/"]` plus, when a C2 profile is active, every `c2_profile.uris` entry passed through `construct_luri` (`:207-208`), then `.uniq`. Each becomes a separate `add_resource` mount (`:265-272`), with `u.gsub("//", "/")` collapsing doubled slashes (`:266`).

### 6.3 Malleable C2 profile loading, and a deliberate guard

`c2_profile` (`:214-225`) `[source]`:
```ruby
return nil unless self.options.include?('MALLEABLEC2')
profile_path = datastore['MALLEABLEC2'] || ''
return nil if profile_path.empty?
parser = Msf::Payload::MalleableC2::Parser.new
parser.parse(profile_path)
```
The comment at `:215-217` states the reason explicitly: gating on the *payload module* having registered the option prevents a staged payload from inheriting a stale `MALLEABLEC2` value left over from a previously configured stageless payload. The profile is loaded **once per call** — there is no memoization here, so `c2_profile` re-parses the profile file on each invocation, and it is called from `all_uris` (`:206`), `find_resource_id` (`:305`/`:307`), `add_response_headers` (`:350`/`:353`), and `on_request` (`:508`, `:560`).

### 6.4 Session-cookie / conn_id extraction

`find_resource_id` (`:303-324`) `[source]` is the entry point, dispatched by HTTP method:

```ruby
if request.method == 'POST'
  placement = self.c2_profile&.http_post&.client&.id
else
  placement = self.c2_profile&.http_get&.client&.metadata
end
```
So **GET carries the id in `client.metadata` and POST in `client.id`** — matching §5.3's compiler mapping exactly (`TLV_TYPE_C2_UUID_GET` from metadata, `TLV_TYPE_C2_UUID_HEADER` from id). Placement resolution order (`:312-317`): query parameter first (`request.qstring[...]`), then header (`request.headers[...]`). If neither yields a value, it falls back to the **last `/`-separated path segment** (`:320`): `request.resource.split('?')[0].split('/').compact.last`.

The doc comment at `:283-298` `[source]` documents this scheme and states the constraint plainly: taking the last segment "skips the base regardless of which one was used," and "Profile authors should not put `/` in prepend/append directives -- that would split the id across segments and defeat this scheme." **That is a real fragility**: the id-recovery is purely positional, and a profile with a slash in a prefix breaks session matching silently.

`unwrap_profile_uuid` (`:330-346`) `[source]` reverses the profile's transforms. The guards at `:334-335` are the interesting part:
```ruby
return candidate unless prefix.empty? || candidate.start_with?(prefix)
return candidate unless suffix.empty? || candidate.end_with?(suffix)
```
If a declared wrapper is absent the candidate is returned **untouched** rather than rejected — the comment at `:327-329` explains this is intentional, letting `process_uri_resource` return `nil` for non-payload requests further down.

### 6.5 `on_request` — the full dispatch

`on_request` (`:437-577`) `[source]`, in order:

1. `Thread.current[:cli] = cli` (`:438`); build an empty `Rex::Proto::Http::Response` (`:439`).
2. Set `req.conn_id` via `find_resource_id` unless already set (`:441`).
3. If a `conn_id` exists, `process_uri_resource` maps it to `info[:uuid]` and `info[:mode]` (`:443-447`).
4. **UUID backfill** (`:449-452`): `uuid.arch ||= self.arch` and `uuid.platform ||= self.platform` — the handler supplies arch/platform when the UUID string did not encode them.
5. **conn_id regeneration** (`:456-458`): if `info[:mode]` is present and **not** `:connect`, regenerate via `generate_uri_uuid(URI_CHECKSUM_CONN, uuid)`. Then `conn_id.chomp!('/')` (`:460`).
6. **DB-gated UUID validation** (`:463-480`): with `IgnoreUnknownPayloads`, a UUID absent from `framework.db.payloads` sets `info[:mode] = :unknown_uuid` (`:468-471`); for `init_*` modes whose `relative_resource` is not in the recorded `urls`, `:unknown_uuid_url` (`:474-479`). Without an active DB, `:466` warns that payload UUID tracking will not work.
7. `url = payload_uri(req) + conn_id` with a trailing `/` enforced (`:482-483`).
8. Default response `code = 200`, `message = 'OK'` (`:491-493`), `pending_connections += 1` (`:489`).

Then the mode dispatch (`:496-571`):

- **`:init_connect`** (`:497-508`) — stageless re-entry. Builds a `PACKET_TYPE_RESPONSE` with `COMMAND_ID_CORE_PATCH_UUID` carrying `TLV_TYPE_C2_UUID = conn_id.gsub(/\//, '')`, serializes with `pkt.to_r`, and wraps through `c2_profile.wrap_outbound_get` (`:508`). The comment at `:504` notes the TLV is "hurl[ed] back at the caller, and ignore the response" — **this is a directive to the implant to re-dial a different URI**, which is how a stageless payload is moved onto a per-session connect URI.
- **`:connect`** (`:513-525`) — first tries `session_for_conn_id(req.conn_id)`; on a hit, delegates to `existing.send(:on_passive_request, cli, req)`, decrements `pending_connections`, and returns (`:520-524`). Otherwise prints `"Attaching orphaned/stageless session..."` (`:525`). The comment at `:514-518` states the reason: without this, MC2 profiles loop forever on "orphaned attach" because **the profile's URI prefix outranks the session's `/<conn_id>` mount in Rex's VirtualDirectory routing**.
- **`:init_python/:init_native/:init_java/:init_php`** (`:526-547`) — the staging path. `generate_stage(url:, uuid:, uri: conn_id)` (`:529`), optional `encode_stage(blob)` (`:530`), then the stage-size prefix:
  ```ruby
  if defined?(read_stage_size?) && read_stage_size?
    blob = [ blob.length ].pack('V') + blob
  end
  ```
  (`:532-535`) — a **4-byte little-endian length prefix**, applied only when the payload mixin declares `read_stage_size?`. Sets `Content-Type: application/octet-stream` (`:539`) and prints `"Staging #{uuid.arch} payload (#{blob.length} bytes) ..."` (`:537`). The `rescue NoMethodError` at `:542-546` prints and logs `'Staging failed. This can occur when stageless listeners are used with staged payloads.'` — note it rescues a **`NoMethodError`**, so this branch also absorbs genuine nil-method bugs as a staging-diagnosis message.
- **`else`** (`:565-571`) — unknown modes serve `datastore['HttpUnknownRequestResponse']` (default `'<html><body><h1>It works!</h1></body></html>'`, `:82-87`) and decrement `pending_connections`. `:566` suppresses the "Unknown request" print for the three explicitly-unknown modes so that `IgnoreUnknownPayloads` noise does not appear.

9. `cli.send_response(resp)` (`:573`), then **`self.service.close_client(cli)` unconditionally** (`:576`) — every HTTP request is served on a fresh connection and forcibly closed. There is no keep-alive and no persistent socket, which is the whole point of the passive dispatcher model.

### 6.6 Session options, and the checkin/gap behaviour

`session_opts` (`:549-562`) `[source]` is where the transport contract is fixed:
```ruby
:passive_dispatcher => self.service,
:dispatch_ext       => [Rex::Post::Meterpreter::HttpPacketDispatcher],
:conn_id            => conn_id,
:url                => url,
:expiration         => datastore['SessionExpirationTimeout'].to_i,
:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
:retry_total        => datastore['SessionRetryTotal'].to_i,
:retry_wait         => datastore['SessionRetryWait'].to_i,
:ssl                => ssl?,
:payload_uuid       => uuid,
:c2_profile         => self.c2_profile,
:debug_build        => datastore['MeterpreterDebugBuild'] || false,
```
`:dispatch_ext` selects `HttpPacketDispatcher` — the passive dispatcher from §2.6 — rather than the socket dispatcher. The four timeout/retry values are **not defaults defined here**; they are read from datastore and `.to_i`-coerced, so they originate from the framework's session-option defaults and are passed through unchanged.

**Checkin/gap behaviour.** There is no polling loop, no keepalive timer, and no heartbeat in this handler. The client's liveness model is inverted relative to TCP: the implant decides when to check in, and each check-in is one HTTP request that may deliver zero or one queued response (§2.6). The handler's only liveness signals are `pending_connections` (`:489`, `:522`, `:570`) and the session-level `expiration`/`comm_timeout`/`retry_*` values. **`self.pending_connections` is incremented at `:489` for every request and decremented only in two of the five branches** — `:init_connect`, `:init_python/:init_native/:init_java/:init_php`, and `:connect` (when it delegates to an existing session) never decrement it. The counter therefore drifts upward under normal operation and is not a reliable count of live sessions.

### 6.7 Defaults and hardcoded values in this file

`[source]` — `LPORT` default **8080** (`:49`), `LURI` default `''` (`:48-50`), `HttpServerName` default `'Apache'` (`:82-87`), `HttpUserAgent` default `Rex::UserAgent.random` (`:53-87`, aliased from `MeterpreterUserAgent`), `HttpUnknownRequestResponse` default `'<html><body><h1>It works!</h1></body></html>'` (`:82-87`), proxy port fallback **8080** (`:408`), `HttpProxyType` defaulting to HTTP unless the string is exactly `"SOCKS"` (`:419-420`), stage-size prefix 4-byte `'V'` little-endian (`:534`), response `code 200` / `message 'OK'` (`:492-493`). The `'It works!'` body and `'Apache'` server name are the HTTP handler's default cover: an unknown request to the listener looks like an idle Apache default page.

---

## 7. The encoder chain — `lib/msf/core/encoder.rb`

**Path correction, verified before searching.** `lib/rex/encoder` **does not exist** in this checkout (`Test-Path` → `False`). The runtime encoder interface is `lib/msf/core/encoder.rb`; the per-algorithm mixins are `lib/msf/core/encoder/*.rb`; the concrete encoder *modules* live in `modules/encoders/`. The probe was confirmed able to succeed by locating the base class with an independent search — `Msf::Encoder` is defined at `lib/msf/core/encoder.rb:72` (`class Encoder < Module`), and `Msf::EncoderState` at `:11`. So the absence of `lib/rex/encoder` is a real negative, not a failed probe.

### 7.1 Two-layer structure

`lib/msf/core/encoder/` contains exactly **6 files** `[source]`: `alphanum.rb` (673 B), `nonalpha.rb` (235 B), `nonupper.rb` (235 B), `xor.rb` (1,530 B), `xor_additive_feedback.rb` (3,162 B), `xor_dynamic.rb` (4,033 B). These are **algorithm mixins** — they implement `encode_block` and are included by encoder modules. The heavy machinery (state, key search, block loop, badchar validation) lives in the 698-line base class.

This split means `modules/encoders/x86/shikata_ga_nai.rb` inherits from `Msf::Encoder::XorAdditiveFeedback`, which is `Msf::Encoder::Xor` plus the feedback key mutation — the specific algorithm is 94 lines, and everything around it is the framework.

### 7.2 The encode entry point

`encode(buf, badchars, state, platform)` at `encoder.rb:256-309` `[source]` is the single orchestrator. Its ordered phases:

1. `init_platform(platform)` if given (`:259`); `badchars = ''` if nil (`:262`).
2. Create `EncoderState` if none supplied (`:265-267`) — so state is **caller-suppliable**, which is how chained/multi-pass encoding accumulates state.
3. `buf = prepend_buf + buf` (`:270`) — hook allowing an encoder to prepend fixed data.
4. `init_state(state)` (`:272`), then `state.badchars = badchars` and `state.buf = buf` (`:275-276`).
5. **Key discovery** (`:279-288`): if `decoder_key_size` is set and `state.key` is nil, call `obtain_key(buf, badchars, state)` and `state.init_key(...)`; if the result is nil, `raise NoKeyError, "A key could not be found for the #{self.name} encoder."`.
6. `state.encoded = ''` (`:292`) — reset because key search may have mutated the buffer.
7. **`encode_begin(state)`** (`:295`) — pre-processing hook.
8. **`do_encode(state)`** (`:298`) — the actual work.
9. **`encode_end(state)`** (`:301`) — post-processing hook.
10. Returns `state.encoded` (`:308`).

If `arch?(ARCH_CMD)` the full result is dumped via `dlog` (`:303-305`) — encoding is logged for command payloads, which are textual and small.

### 7.3 `do_encode` — stub, key patch, block loop

`do_encode` at `:315-368` `[source]` is where the composition is concrete:

- **Stub copy** (`:318`): `stub = decoder_stub(state).dup`.
- **Key patch vs finalize** (`:320-333`) — this is a genuine either/or:
  ```ruby
  if (state.key != nil and state.decoder_key_offset)
    real_key = state.key
    real_key = state.context_address if (state.context_encoding)
    stub[state.decoder_key_offset, state.decoder_key_size] = [ real_key.to_i ].pack(state.decoder_key_pack)
  else
    stub = encode_finalize_stub(state, stub)
  end
  ```
  A **key-based** encoder patches the key directly into the decoder stub at `decoder_key_offset` using `decoder_key_pack`, so `encode_finalize_stub` is never called. A **context-based** encoder substitutes `state.context_address` rather than the key — the stub gets an address, not a secret. Only keyless encoders reach the `encode_finalize_stub` hook.

- **Block loop** (`:338-354`) `[source]`:
  ```ruby
  if (decoder_block_size)
    while (offset < state.buf.length)
      block = state.buf[offset, decoder_block_size]
      state.encoded << encode_block(state, block + ("\x00" * (decoder_block_size - block.length)))
      offset += decoder_block_size
    end
  else
    state.encoded = encode_block(state, state.buf)
  end
  ```
  Two operating modes: **block mode** when `decoder_block_size` is declared, else **whole-buffer mode** (one `encode_block` call with the entire payload). In block mode the final short block is **zero-padded to a full block** — so the encoded output is always a whole number of blocks and the decoder can assume fixed stride.

  The inline comment at `:342-346` documents a deliberate performance decision: `<<` instead of `+`, because "when doing stage encoding on meterpreter (~750k bytes) the difference is 2 orders of magnitude." That 750 KB figure is a useful size anchor for a full meterpreter stage.

- **Stub prefix** (`:357`): `state.encoded = stub + state.encoded` — the decoder stub is prepended **after** encoding, so the stub itself is not encoded. It is inserted literally into the output stream.
- **Final badchar pass** (`:361-365`) `[source]`: `has_badchars?(state.encoded, ...)` is re-run over **stub + encoded payload**. On failure it raises `BadcharError` with the index, the stub length, and the offending byte in an exception whose message is `"The #{self.name} encoder failed to encode without bad characters."` The `BadcharError` carries `stub_size`, which is what lets callers distinguish a bad char in the stub from one in the body — see below.

### 7.4 The hook interface

All hooks are no-op defaults in the base class `[source]`: `encode_begin(state)` → `nil` (`:394-396`), `encode_finalize_stub(state, stub)` → `stub` (`:402-404`), `encode_end(state)` → `nil` (`:409-411`), `encode_block(state, block)` → `block` (`:417-419`), `to_native(buf)` → `buf` (`:427-429`), `prepend_buf` → `''` (`:380-382`). An encoder that overrides nothing produces its input unchanged — encoding is a strict opt-in at every level.

`to_native` (`:427-429`) is documented at `:422-425` as the native-format hook: "for things like unicode, the buffer is unicod encoded and then returned." The unicode encoders in `modules/encoders/x86/` (`unicode_mixed.rb`, `unicode_upper.rb`) use this to widen bytes to UTF-16-ish native form.

Capability declarations: `can_preserve_registers?` → `false` (`:434-436`) and `modified_registers` → `[]` (`:441-443`) `[source]`. These are how the framework knows whether an encoder can be used when registers must survive — and `shikata_ga_nai` overrides both, returning `true` and `[ECX, EAX, EDX]` respectively.

### 7.5 Worked algorithm: XOR additive feedback

`lib/msf/core/encoder/xor_additive_feedback.rb` (94 lines) is the algorithm behind `shikata_ga_nai` and the `longxor_feedback` encoders. It subclasses `Msf::Encoder::Xor` (`:8`) and overrides only `encode_block` and `find_key`.

**`encode_block`** (`:17-27`) `[source]` is six lines and defines the whole cipher:
```ruby
orig       = block.unpack(decoder_key_pack)[0]
oblock     = orig ^ state.key
state.key  = (state.key + orig) % (1 << (decoder_key_size * 8))
return [ oblock ].pack(decoder_key_pack)
```
Per block: XOR the block with the current key, then advance the key by adding the **original plaintext** block value, masked to the key width. Because the key advance depends on plaintext, the keystream is data-dependent and self-synchronizing in the decoder — the decoder reconstructs the next key from the block it just decrypted. That is the "additive feedback."

**`find_key`** (`:32-92`) `[source]` is the badchar-driven key search, and it is where the framework's validation loop is visible:
- `:36-37` calls `super` and returns `nil` if the base search failed, with an explicit comment that it must "propagate that failure rather than encoding with a bogus key" — a deliberate refusal to silently proceed.
- `:46-88` loops until a valid key is found. Inside: reset state (`:49`), set the candidate key (`:53`), and reject a key that itself contains a badchar by raising `BadcharError.new(nil, idx, 0, nil)` with **`stub_size = 0`** (`:59-61`).
- The rescue at `:66-87` distinguishes the two failure locations `[source]`:
  ```ruby
  if (info.index < info.stub_size)
    raise info, "The #{self.name} decoder stub contains a bad character.", caller
  end
  idx = (info.index - info.stub_size) % (decoder_key_size)
  key_bytes[idx] = ((key_bytes[idx] + 1) % 255)
  if (key_bytes[idx] == orig_key_bytes[idx])
    raise info, "The #{self.name} encoder failed to encode without bad characters.", caller
  end
  ```
  A badchar inside the **stub** is fatal and re-raised immediately — the stub is fixed bytes and the encoder cannot change it. A badchar in the **body** is attributed to a key byte by `(index - stub_size) % decoder_key_size`, and that one key byte is incremented. If the byte wraps back to its original value, the search is exhausted and it raises. So the search space is bounded per-key-byte and terminates.
- Returns `state.orig_key` (`:91`).

`Msf::Encoder::Xor#encode_block` at `xor.rb:13` is the non-feedback variant — plain repeated-key XOR with no state advance, which is why it is a separate 1,530 B mixin. `xor_dynamic.rb` goes further and overrides `encode` itself at `:109` rather than just `encode_block`, meaning it bypasses the base-class block loop and badchar strategy.

---

## 8. The transport layer — runtime-mutable C2

**Path correction, verified.** `lib/rex/post/meterpreter/transport*` **does not exist**. A recursive search of `lib/` for any filename matching `transport` returns exactly two hits `[source]`: `lib\msf\core\payload\transport_config.rb` (4,739 B) and `lib\net\winrm\rex_http_transport.rb` (5,869 B, unrelated WinRM). There is **no** transport manager class in a `transport*.rb` file. The probe was confirmed able to succeed by locating the implementation with an independent content search, which converged on `lib\rex\post\meterpreter\client_core.rb`.

The transport protocol is implemented as **methods on the core extension client**, not as a dedicated manager object.

### 8.1 The ten transport commands

`lib/rex\post\meterpreter\core_ids.rb:38-47` `[source]` defines the ID space. These are `EXTENSION_ID_CORE + 24` through `+33` — **contiguous, ten commands**, in the core extension's ID band:

| ID | Constant | Client method |
|---|---|---|
| 24 | `COMMAND_ID_CORE_TRANSPORT_ADD` | `transport_add` (`client_core.rb:510`) |
| 25 | `COMMAND_ID_CORE_TRANSPORT_CHANGE` | `transport_change` (`:523`) |
| 26 | `COMMAND_ID_CORE_TRANSPORT_GETCERTHASH` | — (no client wrapper located) |
| 27 | `COMMAND_ID_CORE_TRANSPORT_LIST` | `transport_list` (`:143`) |
| 28 | `COMMAND_ID_CORE_TRANSPORT_NEXT` | `transport_next` (`:551`) |
| 29 | `COMMAND_ID_CORE_TRANSPORT_PREV` | `transport_prev` (`:560`) |
| 30 | `COMMAND_ID_CORE_TRANSPORT_REMOVE` | `transport_remove` (`:497`) |
| 31 | `COMMAND_ID_CORE_TRANSPORT_SETCERTHASH` | — (no client wrapper located) |
| 32 | `COMMAND_ID_CORE_TRANSPORT_SET_TIMEOUTS` | `set_transport_timeouts` (`:178`) |
| 33 | `COMMAND_ID_CORE_TRANSPORT_SLEEP` | `transport_sleep` (`:536`) |

Eight of the ten have a client-side wrapper; `GETCERTHASH` and `SETCERTHASH` exist in the ID table but no call site was found in `lib/`. Note `enable_ssl_hash_verify` at `:569-571` bails with `return nil unless self.client.sock.type? == 'tcp-ssl'`, so certificate-hash verification is only meaningful on an already-SSL socket. **This is the client's view** — the implant's handler for IDs 26 and 31 is not in this tree.

### 8.2 The shared request builder and the validation gate

`transport_prepare_request(command_id, opts)` at `:878-978` `[source]` is what `add`/`change`/`remove` all route through. The gate is the first line:

```ruby
unless valid_transport?(opts[:transport]) && opts[:lport]
  return nil
end
```
(`:879-881`) — a transport name that fails `valid_transport?` **or** a missing `lport` yields `nil`, and all three callers then `return false unless request` (`:500`, `:513`, `:526`). So a failed transport manipulation returns bare `false` with **no error message and no exception** — a silent no-op from the operator's perspective.

Direction logic (`:883-888`): if the transport name starts with `'reverse'`, `lhost` is required (`return false unless opts[:lhost]`); otherwise it is a bind transport and `opts[:lhost]` is **forcibly set to `nil`** (`:887`) with the comment "Bind shouldn't have lhost set." So the builder mutates its caller's options hash.

URL construction (`:898-909`): `scheme = transport.split('_')[1]`, then `url = "#{scheme}://#{opts[:lhost]}:#{opts[:lport]}"`. This is a **positional parse of the transport name** — `reverse_https` yields scheme `https`, `reverse_tcp` yields `tcp`, `bind_tcp` yields `tcp`. A transport name without an underscore, or with an unexpected segment order, produces a wrong or empty scheme. `luri` is appended with leading slash ensured and **trailing slash stripped** (`:906-908`) — note this is the opposite normalization direction from `construct_luri` in §6.2, which strips trailing slashes but the handler's `all_uris` re-adds one.

### 8.3 Where the Malleable profile becomes a live transport

`:911-921` `[source]` is the join between §5 and this section:

```ruby
if (opts[:c2_profile] || '').empty?
  c2_tlv = GroupTlv.new(TLV_TYPE_C2)
  has_profile = false
else
  profile = Msf::Payload::MalleableC2::Parser.new.parse(opts[:c2_profile])
  c2_tlv = profile.to_tlv
  has_profile = true
end
```

With a profile, the C2 group **is** `profile.to_tlv` — the entire §5.3 sixteen-type structure becomes the body of a `COMMAND_ID_CORE_TRANSPORT_ADD`/`CHANGE` request. So a CS profile is not only compiled into the stage config at build time; it can be **pushed to a live session at runtime** as a transport change. That is the mechanism behind runtime-mutable C2: the same TLV grammar is both the initial configuration and the reconfiguration message.

Layering order after the profile (`:923-971`) `[source]`: `comm_timeout` → `retry_total` → `retry_wait` are added to the C2 group *in that order* (`:923-933`). Then, for any transport **not ending in `tcp`** (`:936`), the HTTP-specific block runs:
- `:937-944` — if `opts[:uri]` given, append it slash-normalized on both ends; **else** compute `sum = uri_checksum_lookup(:connect)` and append `generate_uri_uuid(sum, opts[:uuid]) + '/'`. This is the §6.3 `URI_CHECKSUM_CONN` mechanism appearing on the transport path too — the generated connect URI embedded in the transport must hash-match what the handler will accept.
- `:946-950` — **the profile wins over the User-Agent.** `unless has_profile` is the guard: when a profile supplied a UA, `opts[:ua]` is not defaulted and no `TLV_TYPE_C2_UA` is added, because the profile's own UA TLV is already inside `c2_tlv`. The comment at `:946` states it: "When a profile is supplied it controls the UA; otherwise add a default."
- `:952-955` — `reverse_https` **only** accepts `TLV_TYPE_C2_CERT_HASH`, computed via `Rex::Socket::X509Certificate.get_cert_file_hash(opts[:cert])`. The inline comment notes "currently only https transport offers ssl."
- `:957-969` — proxy: prefix is `'socks='` when `opts[:proxy_type].to_s.downcase == 'socks'`, else `'http://'`, joined to `Rex::Socket.to_authority(host, port)`. Credentials are added as separate TLVs only when non-nil.

Finally `TLV_TYPE_C2_URL` is set unconditionally (`:973`) and the group is appended to the request (`:975`). Note the URL TLV is added **after** the HTTP block but **outside** it — so TCP transports get a C2 URL too, in `scheme://host:port` form.

### 8.4 The transport list response

`transport_list` (`:143-173`) `[source]` sends `COMMAND_ID_CORE_TRANSPORT_LIST` and reads back a structure the implant built. It reads `TLV_TYPE_SESSION_EXPIRY` for the session, then iterates **`response.each(TLV_TYPE_C2)`** (`:152`) — one C2 group per configured transport — and extracts nine fields per transport: `url`, `comm_timeout`, `retry_total`, `retry_wait`, `ua`, `proxy_host`, `proxy_user`, `proxy_pass`, `cert_hash`, `custom_headers` (`:159-168`).

**Note the asymmetry `[source]`:** `transport_prepare_request` writes `TLV_TYPE_C2_PROXY_URL`, `_PROXY_USER`, `_PROXY_PASS`, and the profile writes `TLV_TYPE_C2_GET`/`POST`/`PREFIX`/`SUFFIX`/`ENC_*`/`UUID_*`. But `transport_list` reads **back** only a flat subset and does not surface any of the GET/POST/prefix/suffix/encoding/UUID fields. The TODO comment at `:153-157` lists exactly those unread types and says "Not sure if this stuff is useful for this display though." So the profile's fine-grained shaping is written but never read back — an operator querying `transport_list` cannot see the malleable profile's actual GET/POST structure.

### 8.5 Sleep, next, prev — the coercion commands

`transport_sleep(seconds)` (`:536-546`) `[source]` — `return false if seconds == 0` (`:537`), then reuses `TLV_TYPE_C2_COMM_TIMEOUT` for the sleep value, with the explicit comment at `:541-542`: "we're reusing the comms timeout setting here instead of creating a whole new TLV value." `transport_next` (`:551-555`) and `transport_prev` (`:560-564`) are two-line commands with **no parameters at all** — they carry no transport identifier, so the implant must maintain its own ordered transport list and cursor. The client cannot address a specific transport by these means.

Combined with `add`/`change`/`remove`/`next`/`prev`/`list` and `set_transport_timeouts` (`:178-202`, which sends all four of `SESSION_EXPIRY`/`C2_COMM_TIMEOUT`/`C2_RETRY_TOTAL`/`C2_RETRY_WAIT` and echoes them back), **eight of the ten core commands manipulate the live C2 channel.** That corroborates D7 §8.1's count from the implementation side rather than from the command table.

### 8.6 Failover model

The failover machinery is entirely **implant-side** `[source]`. What the client can do is upload a ranked list of transports, set per-transport retry counts and wait intervals, flip the active cursor forwards or backwards, and set a cert hash for HTTPS pinning. The client has no visibility into which transport is currently in use: `transport_list` returns all configured transports **without an active/inactive flag**, and `next`/`prev` return only `true`. There is no acknowledgement TLV carrying the newly active transport.

This is a direct instance of the client-vs-implant asymmetry D7 §14.1 flagged: the MSF source shows the *control surface* for failover, not the failover algorithm. Retry/backoff semantics live in the metsrv payload, which is not in this corpus.

---

## 9. Hardcoded values, ports, and paths

### 9.1 Handler inventory

`lib/msf/core/handler/` contains **26 `.rb` files** across the top level plus a `reverse/` subdirectory `[source]`:

| File | Size | File | Size |
|---|---|---|---|
| reverse_http.rb | 19,124 B | reverse_tcp_double_ssl.rb | 9,191 B |
| bind_named_pipe.rb | 13,157 B | reverse_udp.rb | 9,070 B |
| bind_aws_ssm.rb | 12,473 B | reverse_tcp.rb | 6,829 B |
| bind_aws_instance_connect.rb | 11,266 B | bind_tcp.rb | 6,403 B |
| reverse_tcp_double.rb | 7,579 B | bind_udp.rb | 5,910 B |
| reverse_sctp.rb | 6,690 B | reverse_ssh.rb | 5,568 B |
| bind_sctp.rb | 5,250 B | bind_udp / reverse_tcp_ssl.rb | 5,910 / 2,161 B |
| find_port.rb | 3,461 B | find_tag.rb | 1,637 B |
| reverse_named_pipe.rb | 1,440 B | reverse\comm.rb | 1,362 B |
| reverse_tcp_all_ports.rb | 1,078 B | reverse_https.rb | 1,046 B |
| find_tty.rb | 944 B | find_shell.rb | 691 B |
| generic.rb | 685 B | reverse\ssl.rb | 464 B |
| none.rb | 449 B | | |

The taxonomy splits three ways `[source]`: **`reverse_*`** (14 rebound transports), **`bind_*`** (6 including the two AWS variants), and **`find_*`/`generic`/`none`** (5 non-listening helpers). The AWS pair (`bind_aws_ssm.rb` 12,473 B, `bind_aws_instance_connect.rb` 11,266 B) are the two largest bind handlers — cloud tunnel transports, larger than `bind_tcp.rb` by ~2×.

### 9.2 Default ports

Verified by enumerating `OptPort.new` across every handler file `[source]`:

| Handler | Option | Default | Note |
|---|---|---|---|
| `bind_named_pipe.rb:209` | `LPORT` | **445** | SMB |
| `reverse_http.rb:49` | `LPORT` | **8080** | from §6.7 |
| `reverse_https.rb:41` | `LPORT` | **8443** | |
| `reverse_tcp_all_ports.rb:42` | `LPORT` | **1** | starting port, not a fixed port |
| `reverse.rb:20` | `ReverseListenerBindPort` | *(no default)* | optional override of `LPORT` bind |

`reverse_http.rb:64` also registers `OverrideLPORT` with no default. The `8443`/`8080`/`445` trio are the only fixed non-trivial ports in the core handler set. `reverse_tcp.rb` itself registers no `OptPort` — it inherits `LPORT` from `reverse.rb`, so a bare `reverse_tcp` listener has no handler-level default and the payload module supplies one.

### 9.3 Protocol and encoding constants

Consolidated from the sections above `[source]`:

- **Packet header:** `PACKET_HEADER_SIZE = 32` (`packet.rb`), fields 4/16/4/4/4 bytes; `AES_IV_SIZE = 16`; `GUID_SIZE = 16`; `NULL_GUID = "\x00" * 16`; `HEADER_SIZE = 8` (TLV group header).
- **Encryption flags:** `ENC_FLAG_NONE = 0x0`, `ENC_FLAG_AES256 = 0x1`, `ENC_FLAG_AES128 = 0x2`.
- **Packet type:** `PACKET_TYPE_CONFIG = 2` — the never-encrypted class.
- **C2 encoding:** `C2_ENCODING_NONE = 0`, `B64 = 1`, `B64URL = 2`, `URL = 3` (`URL` defined but emitted nowhere — §5.4).
- **TLV bases:** `TLV_RESERVED = 0`, `TLV_EXTENSIONS = 20000`, `TLV_USER = 40000`, `TLV_TEMP = 60000`.
- **TLV meta-types:** `NONE = 0`, `STRING = 1<<16`, `UINT = 1<<17`, `RAW = 1<<18`, `BOOL = 1<<19`, `QWORD = 1<<20`, `COMPRESSED = 1<<29`, `GROUP = 1<<30`, `COMPLEX = 1<<31`.
- **Extension ID spacing:** `COMMAND_ID_RANGE = 1000`; `EXTENSION_ID_CORE = 0`.
- **Transport commands:** core + 24 … core + 33 (ten, contiguous).
- **Byte order — the one inconsistency worth memorizing:** every packet header field and every TLV *length/type* is big-endian `N`; QWORD TLV *values* are little-endian `Q<`; the HTTP stage-size prefix is little-endian `'V'`. Three different byte orders in three layers of the same protocol.

### 9.4 Byte-layout facts worth citing verbatim

`[source]` — a complete packet needs `length + 32 - 8` bytes on the wire, because the serialized `length` includes the 8-byte TLV group header while the 32-byte packet header does not (from `raw_bytes_required`). Only `tlv_data[HEADER_SIZE..-1]` is AES-encrypted, so the outermost 8-byte TLV group header stays cleartext **even when AES is active**. The XOR key is 4 bytes and is transmitted in cleartext; `create_request`'s rid is a 32-digit random decimal string carried as `TLV_TYPE_REQUEST_ID`.

### 9.5 The `tlv.rb` map layer

17 `tlv.rb` files under `extensions/`, sized 1,098 B (`priv`) to 12,139 B (`stdapi`) — enumerated in §3. The pattern in every one is `TLV_META_TYPE_* | (TLV_EXTENSIONS + n)`, a flat integer table with no nesting and no schema. §§1, 5, and 8 all consume these constants.

---

## 10. Residual unknowns and explicit gaps

Every item below is stated as what was **not** established, with the probe that was attempted. Per the standing rule, an empty search is recorded as a gap, not as evidence of absence — except where a probe was demonstrated able to succeed.

### 10.1 Confirmed absences (probe demonstrated able to succeed)

- **`lib/rex/encoder/` does not exist.** Found `Msf::Encoder` at `lib/msf/core/encoder.rb:72` by an independent content search on the same pass, proving the search mechanism works. Real negative. (§7)
- **`lib/rex/post/meterpreter/transport*.rb` does not exist.** A recursive `lib/` search for filenames matching `transport` returned only `payload/transport_config.rb` and `net/winrm/rex_http_transport.rb`; an independent content search then located the transport methods in `client_core.rb`. Real negative. (§8)
- **Extension ID 6000 and 17000 unassigned** — observed absent in the §3 enumeration of 23 extension directories. Recorded as an observed gap in the ID space, not as a structural rule.
- **`C2_ENCODING_URL = 3` is defined but never emitted.** `packet.rb:153` defines it; no code path in `malleable_c2.rb` produces it (`encoding_flags_for` returns only NONE/B64/B64URL). Dead-constant observation, scoped to the two files read.

### 10.2 Read but not fully characterized

- **`add_shellcode` (`payload_generator.rb:416`)** — its position in the pipeline is established (it runs between raw generation and encoding) but its body was not read. What prefix/wrapper it adds is unknown. (§4.2)
- **`multiple_encode_payload`** — the `@`-prefixed chained-encoder path (`:418-419`) was identified by its call site; the chaining algorithm itself was not read. Related: how `EncoderState` is threaded across chained passes is asserted here only from the `state` parameter existing on `encode` (`encoder.rb:256`) — the actual multi-pass driver is unread. (§§4.2, 7.2)
- **Transport command IDs 26 (`GETCERTHASH`) and 31 (`SETCERTHASH`)** — present in `core_ids.rb:40,45`, but no client-side wrapper was located in `lib/`. Whether an unlocated wrapper exists, or the commands are implant-only, is unresolved. (§8.1)
- **`valid_transport?`** — its body was not read. Which transport strings pass the `:879` gate, and the exact accepted set, is unknown; only that a failure produces a silent `nil`→`false`. (§8.2)
- **`bind_named_pipe.rb` (13,157 B)** — the largest bind handler and the named-pipe transport were not read. §9 lists it; §8's transport mechanics may not apply to it identically.
- **The two AWS bind handlers** (`bind_aws_ssm.rb`, `bind_aws_instance_connect.rb`; ~23 KB combined) — located and sized only. The cloud-tunnel mechanism is unread.
- **`bind_sctp` / `reverse_sctp` / `reverse_ssh` / `reverse_udp` / `bind_udp`** — sized in §9.1, not read.
- **`reverse_tcp_double.rb` and `reverse_tcp_double_ssl.rb`** (7,579 / 9,191 B) — the "double" (staged-then-reconnected) transports were not read, so the second connection's semantics are unknown.

### 10.3 Genuinely unknown — implant side

The entire metsrv payload is absent from this corpus. Therefore `[source]` cannot reach and this document does not claim:

- The **actual AES implementation**, key derivation, IV handling, padding, and whether the `TODO` at `packet.rb:1003-1005` (the Justin Steven hijacking/side-channel note) is an active weakness in the shipped implant.
- The **failover algorithm**: retry/backoff state machine, transport scoring, and what triggers a `next`/`prev` transition. What is known is that `transport_next`/`prev` carry no parameters (§8.5), so the implant owns the cursor.
- Whether the **`PACKET_TYPE_CONFIG` cleartext property** (§5.5) is mitigated anywhere outside `packet.rb` — e.g. inside the stage bootstrap before TLV encryption is negotiated.
- The **semantics of `TLV_TYPE_C2_*` fields on the implant**, as opposed to the names the client writes.
- **Extension loading on the target**: `load_library` (`client_core.rb:232-249`) was read for its flag handling (`LOAD_LIBRARY_FLAG_LOCAL` / `_ON_DISK` toggled by `UploadLibrary` / `SaveToDisk`), but how the implant maps a library to an `extension_id` is not in this tree. §3 documents the *client's* registration path only.

### 10.4 Scope fences honoured

The 2,715 exploit modules were **not enumerated**; no module body, `external/` tree, nop, or evasion module was read for this document. Also outside this document's read scope: `Msf::RPC`/JSON-RPC, web services, `db_manager`, IRB/console, msfvenom CLI plumbing, and ATT&CK mapping. `lib/rex/` coverage here is confined to `post/meterpreter/` and the payload-adjacent code cited in each section — **the broad `lib/rex/` surface (proto, socket, text, arch, parser, encoder-adjacent code) is largely unread and remains the largest untouched area of the engine.**

### 10.5 Method note

Two section-level path errors were caught by verifying before claiming (§§7, 8) — both were paths the briefing asserted as existing. In each case the class/mechanism was located by an independent search that proved the probe could succeed. **Read it or don't write it** — every number in this document was enumerated or read, and the gaps above are stated rather than filled.

---

## 11. `lib/rex/proto/` — the protocol zoo

**Positive control first.** `lib\rex` = `True` (12 top-level subdirectories), so every absence below is a real negative rather than a failed path. `lib\rex\proto` contains **302 `.rb` files across 46 subdirectories** plus 27 loose top-level files `[source]`.

### 11.1 The measured zoo

Subdirectories by file count and total size `[source]`:

| Directory | Files | Bytes | Directory | Files | Bytes |
|---|---|---|---|---|---|
| kerberos | **81** | **383,691** | proxy | 4 | 26,387 |
| http | 16 | 124,456 | gss | 6 | 23,959 |
| rmi | 15 | 30,087 | ftp | 2 | 19,559 |
| ldap | 11 | 45,100 | dhcpv6 | 3 | 17,872 |
| dcerpc | 10 | 50,001 | ssh | 3 | 16,782 |
| dns | 10 | 64,724 | rfb | 3 | 13,757 |
| smb | 10 | **181,364** | drda | 3 | 12,866 |
| amqp | 7 | 28,922 | ms_tds | 7 | 12,104 |
| ntlm | 6 | 68,530 | nuuo | 4 | 12,095 |
| x11 | 6 | 38,087 | dhcp | 2 | 11,486 |
| iax2 | 6 | **192,735** | ipmi | 4 | 10,857 |
| ms_dtyp (loose) | 1 | **43,337** | mssql | 2 | 48,220 |
| crypto_asn1 | 4 | 27,707 | secauthz | 1 | 9,210 |
| kademlia | 6 | 7,486 | mms | 5 | 9,039 |
| sms | 5 | 7,597 | ntp | 3 | 8,829 |
| x509 | 1 | 7,396 | ms_nrtp | 5 | 8,585 |
| tftp | 3 | 24,920 | ms_adts | 3 | 8,485 |
| acpp | 2 | 7,888 | pjl | 1 | 4,554 |
| sunrpc | 1 | 4,367 | adb | 2 | 4,100 |
| mysql | 1 | 3,535 | steam | 1 | 3,263 |
| natpmp | 2 | 2,517 | sip | 1 | 1,980 |
| quake | 1 | 1,878 | redis | 2 | 1,465 |
| mqtt | 1 | 1,030 | mdns | 1 | 493 |
| thrift | 2 | 5,014 | | | |

**The three biggest directories are not the three that matter for C2.** `kerberos` (81 files, 383 KB), `iax2` (192 KB), and `smb` (181 KB) are the volume leaders — all protocol *client/message* libraries for specific targets. The engine's actual C2 substrate, `http`, is 124 KB. **Size in `lib/rex/proto/` tracks protocol complexity, not engine centrality**; `mdns` at 493 B and `http` at 124 KB are equally reachable from a module.

### 11.2 `lib/rex/proto/http/` — the C2 substrate

**This is what every HTTP handler in §6 sits on.** 12 files `[source]`:

| File | Size | Role |
|---|---|---|
| client.rb | 28,244 B | the client loop |
| web_socket.rb | 15,135 B | WS upgrade |
| client_request.rb | 15,035 B | request with auth/pipelining |
| packet.rb | 12,388 B | parser + object-model base |
| server.rb | 9,632 B | `Rex::Proto::Http::Server` |
| request.rb | 8,959 B | request subclass |
| response.rb | 6,657 B | response subclass |
| auth_digest.rb | 3,395 B | Digest auth |
| http_logger_subscriber.rb | 2,274 B | logging |
| server_client.rb | 1,202 B | per-connection wrapper |
| handler.rb | 650 B | base handler |
| http_subscriber.rb | 349 B | event sub |

#### 11.2.1 The object model

`Packet` (`packet.rb:15`) is the base; `Request` and `Response` subclass it. Two enums drive everything `[source]`: `ParseCode` (`:20-24`) — `Completed = 1`, `Partial = 2`, `Error = 3`; and `ParseState` (`:29-33`) — `ProcessingHeader = 1`, `ProcessingBody = 2`, `Completed = 3`. `DefaultProtocol = '1.1'` (`:8`).

`Packet#[]` (`:49-61`) `[source]` does a case-insensitive header lookup as a **fallback** after an exact-match attempt (`:50-58`), so `pkt['content-length']` resolves `'Content-Length'`.

**The `body` override is a documented hack** `[source]` — `body=` (`:79-81`) writes to an internal `@body_bytes` buffer and `body` (`:83-85`) reads it, never touching the attribute. The 5-line comment at `:70-78` explains why: a subclass overrode `body`, which caused POST requests carrying query-string parameters to have the query string **prepended to the body** — the source calls this "this utterly ridiculous behaviour." The framework keeps the subclass semantics for compatibility while routing real bytes around them.

#### 11.2.2 The parser, and its size guards

`parse(buf, opts)` (`:94-125`) `[source]` appends to `bufq` (`:97`), runs `parse_header` then `parse_body` by state, and wraps the whole thing:

```ruby
rescue
  # XXX: BUG: This rescue might be a problem because it will swallow TimeoutError
  self.error = $!
  return ParseCode::Error
end
```
(`:117-121`) — a **bare `rescue`** capturing `$!` into `self.error`. The source's own inline comment flags that it swallows `TimeoutError`. Since `read_response` wraps its loop in `Timeout.timeout` (§11.2.4), a timeout raised inside `parse` becomes a generic `Error` code and is no longer distinguishable. The exception object *is* retained on the packet as `self.error` — unlike the swallows at `stager.rb:307-313` (§4.3) and `dispatch_inbound_packet:609-612` (§2), which discard it entirely.

`parse_header` (`:309-370`) `[source]` decides content-length:
- `:311-313` splits on `/\r?\n\r?\n/` with limit 2 and **returns early when there is no body separator**, so a truncated header stays `Partial` for the caller's loop.
- `:319` placeholder `body_bytes_left = -1` meaning "read until EOF"; `:321` forces `0` for HEAD.
- `:324-326` — `Content-Length` sets the count via **`self.headers['Content-Length'].to_i`**. Ruby's `to_i` on non-numeric text yields `0`, so `Content-Length: abc` silently becomes a zero-length body rather than an error. A negative value survives as-is.
- `:329-332` — `Transfer-Encoding: chunked` sets `transfer_chunked` and disables `auto_cl`.
- `:335-358` — no-length resolution: keep-alive → current buffer is the whole body (`:341`); a `Request` with neither Content-Length nor Transfer-Encoding → `0` per RFC 2616 (`:342-350`); a websocket upgrade response → `0` (`:351-353`); otherwise stay `-1`, read to EOF.
- `:361-363` — `raise RuntimeError, "Invalid command string"` when the command string failed to parse. **This is the only hard validation in the header path**, and it is caught by the bare `rescue` at `:117`.

**On declared-length bounds:** the source contains **no magnitude check** on `Content-Length` — no maximum, no comparison against a configured cap. `self.max_data` (`attr_accessor :max_data`, `:275`) exists but bounds the *chunk size of each read* in the client loop (`conn.get_once(resp.max_data, 1)`), not the total body the parser will accept. **Inference, marked as such:** a `Content-Length` larger than the real body leaves the parser in `ProcessingBody` until EOF or timeout; a negative `Content-Length` matches neither the `== -1` guard at `:335` nor the `> 0` guard at `:426`, and the `== 0` exits at `:437`/`:445` do not fire, so the only exit is the caller's loop condition. The arithmetic and guards are read from source; the runtime consequence is my reading, not an observed trace.

`completed?` (`:153-166`) `[source]` is deliberately permissive: in `ProcessingBody` with `body_bytes_left < 0` it returns **true** — the comment at `:158-160` says "it's hard to tell whether or not they really are." An unknown-length body counts as complete the moment the header lands, with whatever bytes have arrived.

`chunk(str, min_size = 1, max_size = 1000)` (`:171-185`) `[source]` builds chunked encoding with random sizes and **reads as if it lacks a return** — `:184` appends `"0\r\n\r\n"` and is the last expression, so Ruby returns it. Recorded precisely because it looks like a defect and is not one. Real behaviour: chunk sizes in `[min_size, max_size)`, `min_size` clamped to ≥1 (`:175`), `max_size` clamped up to `min_size` (`:178`).

#### 11.2.3 The client loop

`client.rb` (28,244 B, 763 lines). Entry points `[source]`: `request_cgi(opts)` (`:149`), `connect(t)` (`:165`), `send_request(req, t)` (`:261`), `read_response(t, opts)` (`:568`).

`send_request` (`:261-264`) is two lines — `connect(t)` then `conn.put(req.to_s)`. **It does not read a response.** Send and receive are separate calls, which is precisely what makes the passive/dispatcher model of §2 and §6 possible.

`read_response` (`:568-642`) `[source]`, in order:
- `:570` — `return if t.nil? || t == 0`: a zero timeout returns **nil**, not an error.
- `:573` — `resp.max_data = config['read_max_data']`, the per-read cap, carried onto the response.
- `:581` — the loop wrapped in `Timeout.timeout((t < 0) ? nil : t)`; `t = -1` means no timeout, matching `send_request`'s default.
- `:583-587` — loops while the connection is open and the parse code is neither Completed nor Error.
- `:590-591` — `buff = conn.get_once(resp.max_data, 1)` then `resp.parse(buff || '')`. The `|| ''` matters: a nil read becomes an empty buffer, which is `Partial`, and the loop continues — **so a persistently-nil read spins to the timeout rather than exiting.**
- `:594-603` — disconnect handling splits by state: in `ProcessingHeader` the response is discarded (`resp = nil`); in `ProcessingBody` it is kept and marked `resp.error = :truncated` with the comment "truncated request, good enough" (`:599-600`). **A truncated body is accepted as a successful response**, flagged on the object but never raised.
- `:605-621` — the second documented hack, prefaced in-source with "This is a dirty hack for broken HTTP servers": for a `text/html` response not containing `</html>`, keep reading up to 1000 iterations at a 0.05 s interval. The inline `XXX` at `:614` states "This doesn't deal with chunked encoding." **Inference:** 1000 × 50 ms is a theoretical ~50 s stall; the bounds are read, the wall-clock figure follows arithmetically.
- `:632-642` — a final `100 Continue` case when `resp.proto == '1.1' and resp.code == 100`, re-parsing the body if it begins with `HTTP` (`:637-641`); `opts[:skip_100]` suppresses it.

#### 11.2.4 Authentication

`send_auth(res, opts, t, persist)` (`:276-340`) `[source]` reads `WWW-Authenticate` and dispatches in a fixed order: **Basic → Digest → NTLM → Kerberos → Negotiate → Negotiate-as-SPNEGO** (`:298-338`), each gated on `opts['preferred_auth']` being nil or matching. Basic builds `'Basic ' + Rex::Text.encode_base64("#{username}:#{password}")` (`:346-349`). Every branch returns `res` — the **original** response — when its method yields no `Response` (`:306-308`, `:313-315`, etc.), so an auth failure degrades to returning the 401 rather than raising. Credentials resolve from `opts` first, then the client's stored `username`/`password` (`:277-285`).

**Engine consumption:** `Msf::Exploit::Remote::HttpClient` drives `request_cgi`; the §6 handler uses `Rex::Proto::Http::Server` plus `server_client` for the listener side and `Request`/`Response` for the objects handed to `on_request`. The only size limit in the receive path is `config['read_max_data']`.

### 11.3 Other protocols — what they are for

`[source]` — placed from enumeration and directory semantics; **not read for content** in this pass:

- **`dns` (10 files, 64,724 B)** — DNS client, server, resolver and service; backs DNS-based handlers and exfil.
- **`smb` (10 files, 181,364 B)** — the largest single-protocol client library. MSF also ships the separate `ruby_smb` gem (AGENTS.md directs modules to prefer it), so this in-tree copy is the legacy path.
- **`proxy/socks4a.rb` (13,296 B)** — the only proxy implementation under `lib/rex/proto/proxy`. HTTP proxying is not here; it lives in `client.rb` via the `HttpProxy*` datastore options (§6.7).
- **`dhcp` (2, 11,486 B) / `dhcpv6` (3, 17,872 B)** — DHCP client/server, used by the DHCP server option that hands out a payload path.
- **No `tcp` or `udp` subdirectory exists** under `lib/rex/proto/`. Confirmed by the enumeration above: the 46 directory names contain neither. TCP/UDP are socket abstractions in `lib/rex/socket/` (§12), and the `reverse_tcp`/`bind_tcp` handlers (§9.1) use `Rex::Socket` directly rather than a proto module.
- **`ntlm` (6, 68,530 B)**, **`gss` (6, 23,959 B)**, **`kerberos` (81, 383,691 B)** — the auth stack behind §11.2.4 and the Negotiate/Kerberos paths.
- **`ms_dtyp.rb` (43,337 B)**, loose under `proto/` — an NDR type table; `dcerpc` (10, 50,001 B) is the DCE/RPC transport used for MS-RPC targeting.
- **`crypto_asn1` (4, 27,707 B)**, **`x509` (1, 7,396 B)** — ASN.1 and certificate handling, including the cert-hash path used by `transport_prepare_request` (§8.3).

---

## 12. The socket and stream substrate — and the discovery that reshapes the rest of this document

### 12.1 The briefing path does not exist — and neither does the expected file

**Verified with a working positive control** `[source]`:
- `lib\rex\socket` (directory) → **False**
- `lib\rex\socket.rb` (file) → **False**
- `lib\rex` → **True**, and `lib\rex.rb` exists — so the probe demonstrably resolves real paths.
- A recursive search of `lib/rex` for any path containing `socket` returns **7 hits, none of them a socket implementation**: `post/channel/socket_abstraction.rb` (1,648 B), `post/meterpreter/channels/socket_abstraction.rb` (2,515 B), `post/meterpreter/extensions/stdapi/net/socket.rb` (4,164 B), `proto/http/web_socket.rb` (15,135 B), and three UI text input/output socket wrappers.
- A content search for `module Socket` / `class Socket` across all of `lib/` returns **two** definitions, both unrelated: `lib\msf\core\exploit\remote\ndmp_socket.rb:59` and `lib\rex\post\meterpreter\extensions\stdapi\net\socket.rb:26`. **`Rex::Socket` itself is defined nowhere under `lib/`.**
- Yet `lib/rex.rb:67` **does** `require 'rex/socket'`, and other in-tree files require `rex/socket/ssl`, `rex/socket/udp`, and `rex/socket/ssh_factory`.

**The resolution** `[source]`: `metasploit-framework.gemspec` declares a long `add_runtime_dependency` list, and **18 of those are `rex-*` gems** — including `rex-socket (0.1.71)`, `rex-core (0.1.37)`, `rex-text (0.2.63)`, `rex-arch (0.1.20)`, and **`rex-encoder (0.1.10)`**. `Gemfile.lock` confirms the resolved versions.

**`Rex::Socket`, `Rex::Text`, `Rex::Arch`, and `Rex::Encoder` are external gem dependencies, not in-tree files.** The `lib/rex/` tree in this checkout is the *residual*: the parts of Rex that live in the framework repo (`proto/`, `post/`, `parser/`, `payloads/`, `ui/`, `logging/`, `services/`, `crypto/`, `exploit/`, `google/`, `io/`, `script/`) plus a mixin-style facade at `lib/rex.rb`.

### 12.2 What this corrects

This finding retroactively explains the §7 correction and **supersedes the briefing's framing** for §12 and §14:

| Briefing said | Reality `[source]` |
|---|---|
| `§12 lib/rex/socket/` | **Does not exist.** `Rex::Socket` is the `rex-socket (0.1.71)` gem. |
| `§14 lib/rex/text.rb` | **Does not exist.** `Rex::Text` is the `rex-text (0.2.63)` gem. |
| `§14 lib/rex/arch.rb` | **Does not exist.** `Rex::Arch` is the `rex-arch (0.1.20)` gem. |
| `§7 lib/rex/encoder/` | **Does not exist.** `Rex::Encoder` is the `rex-encoder (0.1.10)` gem, *and* the framework-side sibling is `lib/msf/core/encoder.rb` (read in §7). |

**These are not failed greps.** `lib\rex.rb` at `:67` proves the framework calls `require 'rex/socket'`; the gem that satisfies that require is declared in the gemspec and pinned in `Gemfile.lock`. The absence is structural and now fully attributed: **the checkout is the framework, and Rex is a sibling dependency.**

### 12.3 The in-tree stream/channel layer (what actually exists)

The `lib/rex.rb` facade reveals the real in-tree IO contract `[source]`: it requires `rex/io/stream`, `rex/io/stream_abstraction`, and `rex/io/stream_server`. `lib/rex/io/` in-tree contains only `gram_server.rb` (1,855 B) — so `Rex::IO::Stream`, `StreamAbstraction`, and `StreamServer` are again **gem-provided**, and only the UDP datagram server remains local.

The in-tree channel model is under `lib/rex/post/channel/` and `lib/rex/post/meterpreter/channels/`. The two `socket_abstraction.rb` files (1,648 B and 2,515 B) are the adapter between an abstract stream and a meterpreter channel; `lib/rex/post/meterpreter/channels/` also holds `stream.rb` and `datagram.rb`, whose `module SocketInterface` definitions were found at `stream.rb:30` and `datagram.rb:30` `[source]`. `lib/rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/` contains three channel implementations — `tcp_client_channel.rb`, `tcp_server_channel.rb`, and `udp_channel.rb` — each declaring `module SocketSubsystem` (`:14`, `:14`, `:16`) `[source]`.

**That is the actual multiplexing topology:** a meterpreter `Channel` subclass per socket kind, each exposing a `SocketInterface` so framework code can treat a remote socket like a local one. The `TcpServerChannel` / `TcpClientChannel` / `UdpChannel` split mirrors the local socket API rather than wrapping it. **This layer was located and named, not read for content** — §16 records it as read-but-not-characterized.

### 12.4 Why §12's original premise still holds, restated correctly

The briefing's instinct — "this is the substrate under every session, nothing works without it" — is **correct**; only the location was wrong. `Rex::Socket` is load-bearing for every exploit, and it is *external to this checkout*. That has a direct consequence for D9's evidence posture: **the single most load-bearing component in the entire Ruby stack is not source-readable here.** Everything §11 and §6 say about HTTP is in-tree; everything about raw TCP/TLS framing underneath it is not.

**Marked as inference:** because `rex-socket` is not in the corpus, statements about socket-level behaviour (connect timeouts, TLS negotiation, proxy chains at the socket layer, `Rex::Socket::SSL` implementation) cannot be `[source]`-verified from this checkout and are not asserted anywhere in this document.

---

## 13. `lib/rex/parser/` — the outside-world ingestion surface

**Positive control:** `lib\rex\parser` = `True`, **31 `.rb` files** enumerated by name and size `[source]`.

### 13.1 The inventory

| File | Bytes | Format eaten |
|---|---|---|
| nexpose_raw_document.rb | 24,088 | Nexpose raw XML (SAX) |
| graphml.rb | 22,778 | GraphML XML |
| acunetix_document.rb | 19,978 | Acunetix XML (SAX) |
| nmap_document.rb | 14,085 | Nmap XML (SAX) |
| appscan_document.rb | 12,186 | AppScan XML (SAX) |
| foundstone_document.rb | 10,583 | Foundstone XML (SAX) |
| nexpose_simple_document.rb | 10,339 | Nexpose simple XML (SAX) |
| burp_session_document.rb | 9,024 | Burp session XML (SAX) |
| mbsa_document.rb | 8,070 | MBSA XML (SAX) |
| openvas_document.rb | 7,898 | OpenVAS XML (SAX) |
| **nokogiri_doc_mixin.rb** | 7,568 | **the shared base for all of the above** |
| unattend.rb | 6,316 | Windows unattend.xml |
| arguments.rb | 6,306 | CLI argument grammar |
| group_policy_preferences.rb | 6,280 | GPP XML |
| nexpose_xml.rb | 6,259 | Nexpose XML |
| outpost24_document.rb | 5,952 | Outpost24 XML (SAX) |
| ci_document.rb | 5,630 | CI XML (SAX) |
| nmap_xml.rb | 5,147 | Nmap XML **stream** parser |
| dbeaver.rb | 4,999 | DBeaver JSON + crypto |
| retina_xml.rb | 4,695 | Retina XML |
| apple_backup_manifestdb.rb | 4,167 | iOS MBDB/MBDX binary |
| net_sarang.rb | 4,122 | NetSarang XSH/XFP ini + crypto |
| burp_issue_document.rb | 4,038 | Burp issue XML (SAX) |
| ini.rb | 3,372 | INI |
| wapiti_document.rb | 3,017 | Wapiti XML (SAX) |
| **winscp.rb** | 2,924 | WinSCP INI |
| fusionvm_document.rb | 2,824 | FusionVM XML (SAX) |
| **nessus_xml.rb** | 2,822 | Nessus XML **stream** parser |
| netsparker_xml.rb | 2,696 | Netsparker XML |
| ip360_aspl_xml.rb | 2,156 | IP360 ASPL XML |
| ip360_xml.rb | 2,131 | IP360 XML |
| parsed_result.rb | 176 | result struct |

### 13.2 The shared base — `nokogiri_doc_mixin.rb`

This 241-line file is the contract every `*_document.rb` SAX parser inherits `[source]`.

**`load_nokogiri` (`:7-22`)** requires `nokogiri` and version-gates it: `major >= 1 && minor >= 4` (`:12-16`). On `LoadError` it sets `@nokogiri_loaded = false` and **stores the exception in `@nokogiri_error`** (`:17-19`) rather than discarding it — a deliberate contrast with the bare rescues elsewhere in this document. `nokogiri_loaded` (`:24-26`) coerces to boolean. Every document class is declared as `load_nokogiri && class XDocument < Nokogiri::XML::SAX::Document` (verified in 13 files), so **the entire vendor-document parser family is conditionally defined at load time.** If nokogiri is absent or older than 1.4, the classes are simply undefined rather than raising at load — callers get a `NameError` later.

**`initialize(args, db, &block)` (`:46-55`)** seeds `@state`, `@state[:current_tag] = {}`, `@report_data = {:workspace => args[:workspace]}`, and `@nx_console_id = args[:nx_console_id]`. `:44` uses `eval("attr_reader :args, :db, :state, :block, :report_data")` — an `eval` of a static string, so no injection, but worth noting as a code-generation pattern in a parser base class.

**`valid_ip(addr)` (`:65-69`)** is the one validation primitive:
```ruby
valid = ::Rex::Socket::RangeWalker.new(addr).valid? rescue false
```
An inline `rescue false` on a modifier — no exception class, no object, no log. This is a **project-convention violation** (AGENTS.md: "never bare `rescue`"; "Do not silently discard an exception"). It is also the mechanism by which any malformed address is rejected: the parse failure is indistinguishable from a legitimate "not valid". Note also that `RangeWalker` belongs to the `rex-socket` gem (§12), so **the parser layer's only input validator is provided by code not present in this checkout.**

**`host_is_okay` (`:125-132`)** composes the acceptance test: requires `@report_data[:host]`, requires `valid_ip` to pass, and requires `@report_data[:state] == Msf::HostState::Alive` — the comment at `:122-124` states the rule ("if there's an address, it's not on the blacklist, it has ports, and the port list isn't empty... it's okay"). **`Msf::HostState` is a `lib/msf/` constant used from `lib/rex/`**, i.e. an upward dependency from the Rex layer into the framework layer.

**`normalize_ref` (`:71-103`) / `normalize_references` (`:105-116`)** canonicalize vendor reference IDs across nine types (CVE, MS, URL, BID, APPLE, XF, CB, DFN-CERT, default). Note `:77` rewrites `CAN` → `CVE` for legacy CVE numbering. `normalize_references` (`:115`) ends `refs.compact.uniq`, so `normalize_ref`'s nil-return path (`:72`, for empty type or value) is filtered.

**Streaming character collection** — `characters(text)` (`:214-218`) and `cdata_block(text)` (`:221-225`) both append to `@text` **only when `@state[:has_text]`** is set, and `@text` is initialized lazily. Nothing bounds `@text`'s growth: it accumulates for as long as the current tag remains open. **Inference:** for a single very large element this is an unbounded in-memory string; the code shows the append with no cap, the memory consequence is my reading.

**`end_document` (`:227-236`)** is the malformed-input handler and it is **non-fatal by design**: if `@state[:current_tag]` is non-empty at document end, it composes "the provided file is incomplete, and there may be missing data" listing the unclosed tags, and emits `db.emit(:warning, msg, &block)` (`:234`). **Truncated or malformed XML is warned about and then processed on whatever was parsed** — there is no abort, no exception, and the warning is only emitted `if block` (i.e. only when a callback was supplied). A parser invoked without a block silently proceeds on partial data.

### 13.3 Input-validation posture — explicit per-parser answer

The assignment asks specifically whether each parser validates and whether there is a bounds/size guard. **Measured answer from a content probe across all 31 files** `[source]`:

**Size guards: none exist anywhere in `lib/rex/parser/`.** A search for `File.size`, `max_size`, `MAX_SIZE` across all 31 files returns **zero matches**. Two files read whole files with the size taken from the file itself:
- `graphml.rb:19` — `parser.parse(File.read(file_path, mode: 'rb'))`. Whole file into memory, then handed to a **Nokogiri SAX parser** (`:18`). No size check.
- `apple_backup_manifestdb.rb:28,30` — `fd.read(fd.stat.size)` for both the MBDB and MBDX files. Reads exactly the declared file size; no upper bound.
- `winscp.rb:9` — `File.read(filename)`. No size check.

**XXE / entity-expansion posture — the generically dangerous pattern is NOT present.** All 13 vendor-document parsers subclass **`Nokogiri::XML::SAX::Document`**, and the two standalone XML parsers use `Nokogiri::XML::SAX::Parser` (`graphml.rb:18`) or `REXML::Document.parse_stream` (`nmap_xml.rb:28,34,57` — from the file's own usage comments). **SAX/stream parsing does not build a DOM and does not expand entities into memory the way a tree parse does**, which structurally mitigates billion-laughs and XXE-to-file-disclosure for this family. **Inference, and I am marking it explicitly:** this is a consequence of the parser API chosen, observable in the class declarations; I did not read a hardening flag, and Nokogiri's SAX mode is not a documented substitute for `NOENT`/`nonet` configuration. There is **no** `Nokogiri::XML(...)` tree parse and **no** `URI.open`/`open-uri` call anywhere in the 31 files, which is the positive form of the same finding.

**Per-parser validation summary** `[source]`:
- **`nessus_xml.rb` (2,822 B)** — a hand-written `NessusXMLStreamParser` with `tag_start`/`text`/`tag_end` (`:25`, `:71`, `:95`) and explicit no-op handlers for `xmldecl`, `cdata`, `comment`, `instruction`, `attlist` (`:111-115`). Its own `reset_state` (`:17`) indicates per-host state reset. **No size guard; no address validation in this file's own code** — validation, if any, is the caller's via `valid_ip`/`host_is_okay`. Note it is *not* the largest Nessus-surface file; the raw-document family is Nexpose.
- **`nmap_xml.rb` (5,147 B)** — `NmapXMLStreamParser` with a self-documented caveat at `:36`: **"This parser does not maintain state as well as a tree parser, so malformed..."** — the source itself flags reduced robustness on malformed input.
- **`nexpose_raw_document.rb` (24,088 B, largest)** — SAX, uses `NokogiriDocMixin`, and wraps date handling in `rescue nil` twice (`:236`, `:412`). No size guard.
- **`graphml.rb` (22,778 B)** — the one parser that reads a whole file and hands it to SAX; also defines its own element model via `from_xml_attributes` (`:139`, `:166`, `:193`, `:243`, `:310`, `:369`) with `Document` at `:437`.
- **`dbeaver.rb` (4,999 B)** — uses `JSON.parse` on `decrypt_data` (`:44`) and `data_sources_data` (`:64`); `JSON.parse` raises on malformed input rather than degrading, so this one fails loudly.
- **`net_sarang.rb` (4,122 B)** — a crypto + INI parser (`NetSarangCrypto`, `decrypt_string` at `:64`); routes through `Rex::Parser::Ini.from_s` (`:86`, `:100`).
- **`unattend.rb` / `group_policy_preferences.rb`** — both expose `self.parse` (`:16`, `:15`); GPP XML is the classic `cpassword` surface.
- The remaining `*_document.rb` family (`appscan`, `burp_issue`, `burp_session`, `ci`, `foundstone`, `fusionvm`, `mbsa`, `openvas`, `outpost24`, `wapiti`, and the two `nexpose_*`) all follow the identical SAX-plus-mixin shape and require nokogiri ≥1.4.

### 13.4 The posture answer

**The `lib/rex/parser/` layer does not validate its input in any bounding sense.** Concretely `[source]`:
1. **No parser in the directory enforces a maximum input size.** Zero matches for any size-guard idiom across 31 files; three read whole files unbounded.
2. **Malformed XML is a warning, not a failure** (`nokogiri_doc_mixin.rb:227-236`), and the warning is suppressed entirely when no block is passed.
3. **The single shared validator is `rescue false`** (`:67`) — a convention-violating silent rescue whose dependency lives in a gem absent from this checkout.
4. **The one structural mitigation is the SAX choice**, which is real and worth crediting: it removes the DOM-expansion attack surface from 13 parser classes at design time rather than by input filtering.

**Contrast with `lib/msf/core/`:** there, the same posture appears *and* the swallows are consequential — `stager.rb`'s bare rescue degrades stage encoding silently (§4.3), `dispatch_inbound_packet`'s `rescue ::Exception … return true` marks crashed handlers as handled (§2), and `packet.rb`'s bare rescue loses `TimeoutError` (§11.2.2). In `lib/rex/parser/`, the swallows are **mostly cosmetic** (`rescue nil` around `DateTime.parse`, `URI.parse`) and the dominant safety property is the streaming design. **The input-validation posture does not improve in `lib/rex/`, but it also does not materially worsen — the difference is that `lib/rex/parser/`'s failure modes are warnings where `lib/msf/core/`'s are silent state corruption.** §16 completes this comparison.

---

## 14. `lib/rex/text.rb` and `lib/rex/arch.rb` — both absent, and what the in-tree utility layer actually is

### 14.1 The two briefed files do not exist

**Verified with a working positive control** `[source]`:
- `lib\rex\text.rb` → **False**
- `lib\rex\arch.rb` → **False**
- `lib\rex` → **True**; `lib\rex.rb` exists and requires both `'rex/text'` (`:1`) and `'rex/arch'` (`:7`).

Both are **gem dependencies** declared in `metasploit-framework.gemspec` and pinned in `Gemfile.lock`: **`rex-text (0.2.63)`** and **`rex-arch (0.1.20)`**. §12.2's table already listed these; this section confirms the specific files.

**Where `Rex::Arch` constants are actually consumed in-tree** `[source]`: `lib\rex\payloads\shuffle.rb:3` does `require 'rex/arch'` and then indexes `FLOW_INSTRUCTIONS` by `Rex::Arch::ARCH_X86` (`:13`) and `Rex::Arch::ARCH_X64` (`:14`), and compares against `arch` at `:47`. So the arch model reaches into `lib/rex/payloads/` as a bare constant namespace. **The `Rex::Arch` implementation — `ARCH_*` values, the assembly/opcode layer, register definitions — is not readable in this checkout.** §16 records the consequence.

### 14.2 The in-tree utility layer, measured

With `text.rb` and `arch.rb` excluded, the actual top-level files directly under `lib/rex/` are 21 `[source]`:

| File | Bytes | File | Bytes |
|---|---|---|---|
| **oui.rb** | **934,841** | thread_factory.rb | 868 |
| transformer.rb | 3,501 | ext_time.rb | 695 |
| service_manager.rb | 3,493 | script.rb | 639 |
| job.rb | 2,435 | version.rb | 400 |
| job_container.rb | 2,419 | ntpath.rb | 349 |
| logging.rb | 1,875 | post.rb | 254 |
| user_agent.rb | 1,872 | tar.rb | 174 |
| json_hash_file.rb | 1,732 | proto.rb | 94 |
| crypto.rb | 1,596 | parser.rb | 68 |
| service.rb | 907 | payloads.rb | 55 |

**`oui.rb` at 934,841 B is 91% of the entire top-level `lib/rex/` byte mass and 88% of all of `lib/rex/`'s top-level code.** It is the IEEE OUI vendor-prefix lookup table — roughly 935 KB of static MAC-address-to-vendor mappings. In a document about mechanism it deserves exactly one line: it is a data table, not logic, and it is the single largest file in the tree by an order of magnitude.

The remaining 20 files are small and are the framework's connective tissue `[source]`: `service_manager.rb` (3,493 B, the `Rex::ServiceManager.start` used by the §6 HTTP listener), `job.rb` + `job_container.rb` (4,854 B combined, the job/thread lifecycle), `logging.rb` (1,875 B), `version.rb` (400 B, the `Rex::Version` class AGENTS.md mandates for all version comparison), and one-line namespace stubs `proto.rb` (94 B), `parser.rb` (68 B), `payloads.rb` (55 B).

### 14.3 `lib/rex/payloads/shuffle.rb` — the one real algorithm in this layer

142 lines. This is the file worth reading, and it answers the question the briefed `text.rb` was meant to answer — **how the framework generates payload-safe instruction sequences.**

Its dependency is `Rex::Parser::GraphML.from_file` (`shuffle.rb:28`), which connects this section directly to `graphml.rb`'s unbounded `File.read` at `parser/graphml.rb:19` (§13.3). **The 22,778-byte GraphML parser exists to serve this 142-line payload shuffler.**

`from_graphml_file(file_path, arch:, name:, random:)` `:27-93` `[source]`:
1. `:28` loads the GraphML graph.
2. `:29` selects nodes whose `type` is one of `data` / `instructions-graph` / `block`, then calls the private `create_path` against `graphml.graphs[0].edges`.
3. `:30-38` builds each block's instruction list — `instructions-graph`/`block` types get `process_instructions_graph_block`.
4. `:40` generates a 4-character lower-alpha label prefix. **With a seeded `random` it uses `('a'.ord + random.rand(26)).chr`; without one it falls back to `Rex::Text.rand_text_alpha_lower(4)`** — i.e. it reaches into the `rex-text` gem precisely when determinism is not requested.
5. `:41` `labeler` formats `loc_<prefix><address padded to 4 hex digits>`.
6. `:47-64` — **for x86/x64 it emits `db 0x..` raw-bytes directives, not mnemonics** (`:55`), with the stated reason at `:54`: "by default use the raw binary instruction to avoid syntax compatibility issues with metasm." For any other architecture (`:62`) it emits the original `instruction.source` text instead. **This is an architecture-gated behavioural fork: the same input file produces either re-assemblable source text or a raw byte dump depending on `arch`.**
7. `:66-80` — when `arch` is supplied, `raise ArgumentError, 'Unsupported architecture' if FLOW_INSTRUCTIONS[arch].nil?` (`:67`). Then, for each instruction, a regex `^(?<mnemonic>\S+)\s+(?<address>0x[a-f0-9]+)$` (`:72`) extracts mnemonic and target address; control-flow mnemonics in the per-arch `FLOW_INSTRUCTIONS` set are rewritten to reference the generated label and their address is recorded in `label_refs` (`:76-77`).
8. `:85-88` — the integrity check: `unless label_refs.all? { |address| labeled.include? address }` → `raise StandardError, 'Missing label reference'`. **This is a real validation with a real failure**, and the source comment at `:86` explains the placement: "raise this here so it's closer to the source of the problem :("
9. `:91-92` optionally wraps the output under `name:` and indents by two spaces, joined with newlines and a trailing newline.

**`create_path(nodes, edges, random:)` `:116-138` — the core algorithm** `[source]`: it is a **dependency-respecting topological walk with randomized tie-breaking**:
- `:120-121` — the initial candidate set is every node with no incoming edge (`choices = nodes.values.select { |node| !targets.include? node.id }`), i.e. all roots.
- `:122-135` — repeatedly: pick uniformly at random (`:123`, seeded when `random` is supplied), remove it from `choices`, append to `path`; then for each successor edge, add the successor to `choices` only if it is not already in `path` (`:130`) **and** every one of its own source edges already points at a node in `path` (`:131`).
- **Termination and failure mode:** the loop ends when `choices` is empty. If the graph contains a cycle, no node in the cycle ever satisfies the all-predecessors-visited test, so those nodes are never emitted — **the method returns a shorter path rather than raising, and there is no cycle detection.** `[source]` for the control flow; **inference** for the "silently drops cyclic nodes" consequence, since the code has no explicit cycle branch. The only downstream signal is that a dropped node's address could later appear in `label_refs` while absent from `labeled`, which the `:85` check would then catch as 'Missing label reference' — so the failure is indirect and its message names the symptom, not the cycle.

**The `random:` keyword is the determinism contract** `[source]`: the docstring at `:24-26` states that a supplied seeded RNG makes the assembly source deterministic for a given seed, and `nil` uses the global RNG for non-deterministic output. Both the shuffle order (`:123`) and the label prefix (`:40`) are driven by it — so seeded reproduction requires the same seed *and* the same graph, and the `Rex::Text` fallback at `:40` is only reached when `random` is nil.

---

## 15. `lib/rex/payloads/` — the shared payload builders

**Positive control:** `lib\rex\payloads` = `True`, **10 files across 3 directories** `[source]`. This is a small layer, and the honest characterization is that **most of what the briefing expected here lives elsewhere.**

### 15.1 The complete inventory

| Path | Bytes |
|---|---|
| payloads.rb (namespace stub) | 55 |
| shuffle.rb | 6,502 |
| meterpreter.rb | 42 |
| meterpreter/config.rb | 7,724 |
| meterpreter/uri_checksum.rb | 6,733 |
| win32/common.rb | 673 |
| win32/kernel.rb | 1,529 |
| win32/kernel/common.rb | 1,287 |
| **win32/kernel/migration.rb** | **131** |
| win32/kernel/recovery.rb | 1,437 |
| win32/kernel/stager.rb | 9,361 |

**Total: 35,473 B.** The three subdirectories are `meterpreter/`, `win32/`, and `win32/kernel/` — there is **no** `single`, `stage`, or `exitfunc` file under `lib/rex/payloads/`. Verified by full recursive enumeration `[source]`. Those primitives are in `lib/msf/core/payload/`, which §4 covers: the naming difference is `rex/payloads/` = *raw blob builders*, `msf/core/payload/` = *module-side staging and encoding*. The briefing's `single`/`stage`/`exitfunc` expectation maps onto §4's ground, not this directory.

### 15.2 `win32/kernel/stager.rb` (9,361 B) — the ring0 primitive

The largest and most substantive file here. Its own header comment (`:7-11`) states the contract plainly: "Stagers are responsible for reading in another payload and executing it. The reading in of the payload may actually be as simple as copying it to another location. The executing of it may be done either directly or indirectly."

`stager_sysenter_hook(opts = {})` `[source]` — the documented 9-step mechanism, quoted from the source's own block comment at `:17-25`: our sysenter handler and ring3 stagers are copied to a safe location; **the `SYSENTER_EIP_MSR` is patched** to point at the handler; the ring0 thread is halted; any ring3 `sysenter` transfers control to it; the ring3 return address is modified to force the stub under certain conditions; **if NX is enabled the relevant page-table entry is patched to disable it** for the ring3 code; control passes to the real sysenter handler, whose `sysexit` returns to our ring3 stager; and when the stager runs in the desired process the handler is removed and the real payload called.

**The four hardcoded addresses and how they are overridden** `[source]`:
- `pagetable` = `opts['StagerAddressPageTable'] || 0xC03FFF00` (`:35`) — page-table entry for `StagerAddressUser`, used to bypass NX on PAE systems.
- `kstager` = `opts['StagerAddressKernel'] || 0xFFDF0400` (`:38`) — kernel memory, commented "no ASLR".
- `ustager` = `opts['StagerAddressUser'] || 0x7FFE0400` (`:41`) — shared memory reachable from ring3, commented "no ASLR".
- `process` = `(opts['RunInWin32Process'] || 'lsass.exe').unpack('C*')` (`:44`) — **default target is `lsass.exe`**, the SYSTEM-process injection target.

**The process-name matching scheme** `[source]`: `:47` computes
```ruby
checksum = process[0] + (process[2] << 8) + (process[1] << 16) + (process[3] << 24)
```
— a simple hash over the **first four wide chars**, with the comment at `:45-46` stating both the scheme and its precondition: "Assumes process is located at `*:\windows\system32\`." **Note the byte order: `[0]`, then `[2]`, then `[1]`, then `[3]`** — positions 2 and 1 are transposed relative to a naive read, which is deliberate and matches the assembly-side comparison. Only the first 4 bytes of the decoded string participate, so two process names sharing their first four characters hash identically.

**The placeholder-patch mechanism** `[source]`: the 84-byte `r0` blob (`:52-64`) is a literal concatenated string containing six recognizable sentinel sequences, and `:72-76` substitutes each exactly once via `gsub`:
| Sentinel | Patched with | Line |
|---|---|---|
| `0x41414141` (`AAAA`) | `r0.length + r3.length - 0x1C` | `:72` |
| `0x42424242` (`BBBB`) | `kstager` | `:73` |
| `0x43434343` (`CCCC`) | `ustager` | `:74` |
| `0x44444444` (`DDDD`) | `checksum` | `:75` |
| `0x45454545` (`EEEE`) | `pagetable` | `:76` |

All packed `"V"` (little-endian 32-bit). **This is the same placeholder-patching idiom as the encoder key patch in §7.3 and the `PACKET_TYPE_CONFIG` framing in §5** — the framework's recurring pattern is to emit a template containing sentinel bytes and patch them at build time. Note `gsub` with a packed-binary *needle* and no block: if a value being patched happened to contain another sentinel sequence, the later `gsub` calls could rewrite it, since the substitutions run sequentially over the already-modified string. **Inference:** ordering-dependent; the source shows five sequential `gsub` passes over the same variable with no re-validation.

Also defined in this file: `r3` is assembled from an optional `_createthread()` (`:68`, when `opts['CreateThread'] == true`) plus `opts['UserModeStub']` (`:69`), and the return value is `r0 + r3` (`:79`). A second entry point exists for "XP SP2/2K3 SP1 ONLY" per the comment at `:82-84`. `_createthread` and the remaining functions are in `:85-196` (**read-but-not-characterized** — recorded in §16).

### 15.3 The rest, and one notable empty module

- **`win32/kernel/migration.rb` — 131 bytes and it is an empty module** `[source]`:
  ```ruby
  module Rex
  module Payloads
  module Win32
  module Kernel
  module Migration
  end
  end
  end
  end
  end
  ```
  Thirteen lines, a declaration and five `end`s, no methods. **The kernel-mode migration primitive does not exist as code** — the file reserves the namespace. Any caller expecting a kernel migration helper here finds an empty module, which in Ruby is silently valid (calling an undefined method raises `NoMethodError`, but `include`/`require` succeed). This is worth flagging because a namespace-reserving stub reads as implemented functionality to a grep.
- **`win32/kernel/recovery.rb` (1,437 B)** — named for the SYSENTER-recovery path matching the hook above; **not read for content**.
- **`win32/kernel/common.rb` (1,287 B)** and **`win32/common.rb` (673 B)** — shared constants/helpers; not read for content.
- **`win32/kernel.rb` (1,529 B)** — the aggregator that pulls the kernel modules together; not read for content.
- **`meterpreter/config.rb` (7,724 B)** — the meterpreter stage configuration builder; **note this is the `rex`-side counterpart of `lib/msf/core/payload/meterpreter.rb`**, and `meterpreter.rb` here is a 42-byte require stub (`[source]`). Not read for content in this pass.
- **`meterpreter/uri_checksum.rb` (6,733 B)** — the URI checksum builder. §6.4 read `Msf::Payload::Windows::UriChecksum`; this is the `Rex`-side equivalent, and `reverse_http.rb:19-23` includes `Rex::Payloads::Meterpreter::UriChecksum` (§6.2). `URI_CHECKSUM_CONN = 98` was established in §6. **Not read for content here.**
- **`shuffle.rb`** — covered in full in §14.3.

### 15.4 What this layer is, stated plainly

**`lib/rex/payloads/` is 35 KB, three directories, and one genuinely deep file.** Its real content is the Windows kernel/SYSENTER stager plus the meterpreter stage-config and URI-checksum builders. **The general-purpose payload primitives — migration, exitfunc, single/stage encoding — that the briefing expected to enumerate here are not present**; the enumeration above is complete and shows no such files. The migration name exists only as an empty module. §16 records this as a scope correction rather than a gap.

---

## 16. The synthesized picture — what `lib/` does for the framework

### 16.1 The single most important structural fact

**The engine is split across a repository boundary, and the split does not follow the `lib/msf/` vs `lib/rex/` line a reader would assume.** Measured `[source]`: `lib/rex/` contains **682 `.rb` files**; `lib/msf/core/` plus `lib/rex/` together contain **1,765**. But `metasploit-framework.gemspec` declares **18 `rex-*` runtime dependencies**, and `Gemfile.lock` pins them — including `rex-socket (0.1.71)`, `rex-text (0.2.63)`, `rex-arch (0.1.20)`, `rex-core (0.1.37)`, `rex-encoder (0.1.10)`, `rex-powershell (0.1.105)`, `rex-nop`, `rex-rop_builder`, `rex-bin_tools`, `rex-registry`, `rex-java`, `rex-zip`, `rex-struct2`, `rex-ole`, `rex-mime`, `rex-sslscan`, `rex-exploitation`, `rex-random_identifier`.

`lib/rex.rb` `[source]` requires `rex/text`, `rex/random_identifier`, `rex/zip`, `rex/registry`, `rex/java`, `rex/struct2`, `rex/encoder`, `rex/arch`, `rex/file`, `rex/sync`, `rex/assembly/nasm`, `rex/logging/log_dispatcher`, `rex/io/stream`, `rex/io/stream_abstraction`, `rex/io/stream_server`, `rex/socket`, `rex/compat`, and `rex/version` — **and every one of those that resolves through `lib/rex/` in-tree is a fraction of them.** The in-tree `lib/rex/` is the *residual* Rex: `proto/`, `post/`, `parser/`, `payloads/`, `ui/`, `logging/`, `services/`, `crypto/`, `exploit/`, `google/`, `io/gram_server.rb`, `script/`, plus the 21 top-level files of §14.2.

**Four separate briefing-asserted paths turned out to be gem-provided rather than in-tree:** `lib/rex/encoder/` (§7), `lib/rex/socket/` (§12), `lib/rex/text.rb` (§14), `lib/rex/arch.rb` (§14). In every case the mechanism was located and the absence was proven with a positive control. **This is the highest-value structural finding of the whole document: the framework's bottom layer is not in the corpus.**

### 16.2 (a) How much of the engine is transport-agnostic vs HTTP-coupled

**Measured, not estimated.** The distinction is real but *narrower than it looks*, and it runs in the opposite direction from what "HTTP handler" suggests.

**HTTP-coupled — genuinely, irreducibly:** `lib/rex/proto/http/` (12 files, 124,456 B) is the only HTTP implementation in-tree, and §6's `reverse_http.rb` (581 lines) is written directly against `Rex::Proto::Http::Server` + `server_client`. The passive-dispatcher model (§6.5) — `send_queue`/`recv_queue`, `HttpPacketDispatcher`, `pending_connections` — exists **because** HTTP is request/response and the client must be simulated across separate connections. §6.7's proxy, UA, cookie and URI-rewrite options are all HTTP-only. `malleable_c2.rb` (§5) is HTTP-grammar-specific: its block keywords are `http-get`/`http-post`/`http-stager`.

**Transport-agnostic — the large majority of the protocol machinery.** The four layers that actually move C2 data do not know what they are riding:
- §1's 32-byte header and §2's `packet_dispatcher` operate on a byte stream and a socket; GUID learning (`:471-473`), rid correlation, and the fragmentation queue are transport-blind.
- §5's `PACKET_TYPE_CONFIG` profile TLV is emitted into the same packet framing regardless of transport — which is precisely why the §5.5 finding generalizes to *every* transport, not just HTTP.
- §8's `transport_prepare_request` (`client_core.rb:878-978`) takes `transport` as data (`reverse_tcp`, `reverse_https`, …) and branches on `transport.ends_with?('tcp')` (`:936`) to decide whether the HTTP-only block runs at all (`:936-971`). **The HTTP-specific work is a conditional block inside a transport-general method** — that is the actual architecture.
- §3's extension dispatch and §7's encoder chain are plain payload transformation with no transport concept.

**The honest count:** of the 26 core handler files (§9.1), **exactly 2 are HTTP** (`reverse_http.rb` 19,124 B, `reverse_https.rb` 1,046 B) — **under 8% of handler files by count but ~12% by bytes**, and `reverse_http.rb` alone is the largest handler in the tree. **Inference, marked:** the framework is transport-plural at the transport layer and transport-singular only at the profile layer, where Malleable-C2 grammar is HTTP-shaped by definition. The apparent HTTP centrality comes from `reverse_http.rb`'s size, not from the architecture.

### 16.3 (b) Which components are load-bearing for *every* exploit vs optional

**Load-bearing for every exploit — cannot be absent** `[source]`:
1. **`Rex::Socket`** — the substrate under every session. §12. It is **a gem** (§12.1), so it is load-bearing *and* unreadable here. This is the single largest evidence gap in the document.
2. **`Rex::Text`** — randomisation and encoding primitives used by `basic_auth_header` (`client.rb:348`), the `shuffle.rb` label fallback (`:40`), and payload string generation throughout. Also **a gem**.
3. **`Rex::Arch`** — the `ARCH_*` constant namespace that `shuffle.rb:13-14,47` indexes. Also **a gem**.
4. **§7's `Msf::Encoder`** (`lib/msf/core/encoder.rb:72`) — every encoded payload traverses `encode()`'s ten phases (`:256-308`). In-tree and read.
5. **§3's `tlv.rb` map layer and extension dispatch** — 17 `tlv.rb` files define the ID space; nothing on the wire is addressable without them.

**Conditional / optional** `[source]`:
- **§5 `malleable_c2.rb`** — only when a `MALLEABLEC2` profile is set; `c2_profile` returns `nil unless self.options.include?('MALLEABLEC2')` (`reverse_http.rb:218`).
- **§8's transport mutation methods** — dormant unless `transport_add`/`change`/`next`/`prev` are called.
- **§4's Java pipeline** (`generate_java_payload`, `:367-392`) — a separate path from the native stager.
- **§13's entire parser layer** — invoked only when an operator imports a scan report.
- **§15's kernel stager** — Windows kernel exploits only, and its migration module is empty.
- **The 18 vendor-document SAX parsers** — each needs a specific vendor file, and all are conditionally defined on nokogiri ≥1.4.

**The asymmetry that matters:** the five load-bearing items are **four gems plus two in-tree files**, and three of the four gems are unreadable in this checkout. **The in-tree `lib/` is the framework's *shape*; the gems are its *substance*.**

### 16.4 (c) Does the input-validation posture change between `lib/rex/` and `lib/msf/core/`?

**No — the posture is the same project-wide, but the consequence of failure is systematically worse in `lib/msf/core/`.** Both layers violate AGENTS.md's explicit rules ("never bare `rescue`", "never `rescue Exception`", "never `raise "bare string"`"), which is the finding that unifies D9.

**`lib/rex/` violations, read this session** `[source]`:
- `parser/nokogiri_doc_mixin.rb:67` — `rescue false` modifier on `RangeWalker.new(addr).valid?`, the parser layer's only input validator.
- `parser/nokogiri_doc_mixin.rb:236` — malformed XML is a `db.emit(:warning)` and processing continues; suppressed entirely when no block is passed.
- `parser/{acunetix,appscan,burp_session}_document.rb` — `rescue nil` around `URI.parse` (`:176`, `:188`, `:353`, `:508`; `:339`; `:150`).
- `parser/nexpose_raw_document.rb:236,412` — `rescue nil` around `DateTime.parse`.
- `payloads/win32/kernel/stager.rb:46-47` — a process-name match relying on the assumption `*:\windows\system32\`, with only 4 bytes hashed.

**`lib/msf/core/` violations, read in §§1-10** `[source]`: bare `rescue` losing `TimeoutError` in `packet.rb` (§11.2.2 is the rex-side analogue); `rescue ::Exception … return true` in `dispatch_inbound_packet` (`packet_dispatcher.rb:609-612`); bare `rescue` in `stager.rb:307-313` as a stage-encoding fallback defaulting true; `raise NoKeyError, "…"` in `encoder.rb:286` (a class, but a bare message string).

**The pattern that separates the layers** `[source]`: in `lib/rex/parser/`, a swallowed exception yields **a missing row in an imported report** — the operator sees less data. In `lib/msf/core/`, a swallowed exception yields **a packet marked as handled, a stage that silently degraded, or a timeout reported as a parse error** — the operator sees a *working session* built on a failure that was never surfaced. **Same code smell, materially different blast radius, and the difference is that `lib/msf/core/`'s swallows sit on the session-critical path while `lib/rex/parser/`'s sit on the reporting path.**

The one place `lib/rex/` is *structurally* safer is §13.3's finding: 13 of 31 parsers inherit `Nokogiri::XML::SAX::Document` and the other two XML parsers use `SAX::Parser` or `REXML::Document.parse_stream`. **A streaming parser cannot be made to expand entities into a DOM**, so the XXE/entity-expansion class of bug is designed out of the family rather than filtered against. That is credit where it is due, and it is the only place in D9 where a safety property is architectural rather than incidental.

### 16.5 Where the assumptions live

Consolidated from §§1-15, each `[source]`-anchored and each already stated inline:

1. **The cleartext-config assumption (§5.5).** `PACKET_TYPE_CONFIG` is structurally excluded from TLV encryption (`packet.rb:801,986`), so every Malleable-C2 profile value is recoverable from one config packet with a 4-byte transmitted XOR key. **Corroborated by two independent code paths** — D8 §3.7 and §5.5 here. This is the strongest result in the corpus and it is not softened.
2. **The implant-owns-the-cursor assumption (§8.6).** `transport_next`/`prev` send no parameters and return bare `true` (`client_core.rb:551-564`); `transport_list` writes many `TLV_TYPE_C2_*` fields but reads back a flat subset (TODO `:153-157`). The client cannot observe which transport is live — D7 §14.1's client-vs-implant split, instantiated.
3. **The cleartext group-header assumption (§1, §5.5).** Only `tlv_data[HEADER_SIZE..-1]` is AES-encrypted; the 8-byte outermost TLV group header stays readable even when AES is active.
4. **The XOR-not-encryption assumption (§1, §5.5).** A 4-byte repeating XOR with the key transmitted in cleartext is obfuscation. Three byte orders coexist in one protocol (header/length/type big-endian `N`; QWORD TLV values little-endian `Q<`; HTTP stage-size little-endian `'V'`) — §9.5.
5. **The `pending_connections` assumption (§6.7).** Incremented at `:489`, decremented only in two of five branches; not a live-session count.
6. **The no-memoisation assumption (§6.7).** `c2_profile` (`:214-225`) re-parses the profile file on every call and is called from four places.
7. **The framing-disagreement assumption (§5.4).** `wrap_outbound_get`/`unwrap_inbound_post` strip prefix/suffix *conditionally*; `add_skip_tlvs` tells the implant an *unconditional* byte count. The two sides can disagree.
8. **The placeholder-patching assumption (§7.3, §15.2).** Encoder key patches, the `PACKET_TYPE_*` framing, and the kernel stager's `AAAA`/`BBBB`/`CCCC`/`DDDD`/`EEEE` sentinels all rely on replacing magic byte sequences in a template at build time.
9. **The unbounded-file assumption (§13.3).** No size guard exists in any of the 31 parsers; `graphml.rb:19`, `apple_backup_manifestdb.rb:28,30`, and `winscp.rb:9` read whole files.
10. **The `/`-breaks-URI-id assumption (§6.4).** A profile prepend/append containing `/` silently breaks session-id recovery (`reverse_http.rb:296-298`).

### 16.6 Residual unknowns for §§11-16

**Confirmed absences, positive control proven per §12.1's method** `[source]`: `lib/rex/encoder` (directory), `lib/rex/socket` (directory and file), `lib/rex/text.rb`, `lib/rex/arch.rb`, and any `tcp`/`udp` subdirectory under `lib/rex/proto/`. Additionally: no `migration`/`exitfunc`/`single`/`stage` file under `lib/rex/payloads/`; no size-guard idiom anywhere in `lib/rex/parser/`.

**Read-but-not-characterized** `[source]`: the 31 parsers other than `nokogiri_doc_mixin.rb`, `nessus_xml.rb`, `nmap_xml.rb`, `graphml.rb` (and the three unbounded readers named in §13.3); `lib/rex/proto/http/{web_socket,client_request,request,response,server,server_client,auth_digest}.rb` (named by size and role only); every `lib/rex/proto/` subdirectory except `http` — including `kerberos` (81 files), `smb` (10), `dns` (10), `iax2` (6); `lib/rex/post/channel/` and the meterpreter `channels/` + `socket_subsystem/` implementations (§12.3); `lib/rex/payloads/win32/kernel/stager.rb:85-196`; `meterpreter/config.rb` and `meterpreter/uri_checksum.rb`; and the 21 top-level `lib/rex/` files of §14.2 beyond their sizes.

**Unreadable in this corpus (gem-provided)** `[source]` — the substrate gap: `rex-socket (0.1.71)`, `rex-text (0.2.63)`, `rex-arch (0.1.20)`, `rex-encoder (0.1.10)`, and the other 14 `rex-*` gems. **Consequence:** no socket-level, text-generation, or architecture/opcode behaviour is asserted anywhere in §§11-16, because none of it can be `[source]`-verified here. §12.3's channel topology is named from in-tree call sites, not from the implementations.

**Implant-side unknowns** (unchanged from §10.3, restated for this range): the transport failover algorithm; whether `PACKET_TYPE_CONFIG` is mitigated before TLV encryption is negotiated; `TLV_TYPE_C2_*` semantics as the implant sees them; extension-id mapping on the target.

### 16.7 Scope fences, restated

The 2,715 exploit modules were **not enumerated** across §§11-16 either. `lib/rex/proto/` was enumerated as a directory tree (46 subdirs, 302 files) and read for content only in `http/` — **the 57 further protocol directories were placed, not read.** No `external/` tree, nop, or evasion module was read. No REA/Ghidra was used; every claim in this document is `[source]` with `file:line`, and every inference is marked as inference.

---

## 17. The externalized Rex layer — the gap closed

### 17.1 How the gems were obtained, and the correction this forces

**Method:** `ruby`, `gem`, and `bundle` are all **absent** on this host. A `.gem` is nevertheless fetchable by URL and unpackable without Ruby. **This removes §16.6's "unreadable in this corpus" classification and replaces it with a citation-grade source tree.**

| Gem | Version | `.gem` bytes | unpacked `.rb` files | unpacked bytes | Location |
|---|---|---|---|---|---|
| rex-socket | **0.1.71** | 41,984 | 20 | 125,605 | `RE_Library\04_TOOLS\gems\rex-socket-0.1.71\src` |
| rex-text | **0.2.63** | 44,544 | 24 | 116,212 | `RE_Library\04_TOOLS\gems\rex-text-0.2.63\src` |
| rex-arch | **0.1.20** | 16,896 | 15 | 40,740 | `RE_Library\04_TOOLS\gems\rex-arch-0.1.20\src` |
| rex-core | **0.1.37** | 28,160 | 19 | 67,550 | `RE_Library\04_TOOLS\gems\rex-core-0.1.37\src` |
| rex-encoder | **0.1.10** | 35,328 | 31 | 118,224 | `RE_Library\04_TOOLS\gems\rex-encoder-0.1.10\src` |
| **TOTAL** | | **166,912** | **109** | **468,331** | |

All five versions are the ones `Gemfile.lock` pins — **not latest**, as instructed. Each `.gem` is a three-layer archive (gzip → `data.tar.gz` → `data.tar` → source tree).

**Correction to §16.6, stated plainly:** the 468,331 bytes above are now `[source]`-readable with `file:line`. **Every "unreadable in this corpus" entry in §16.6 for these five gems is withdrawn.** §16.1's conclusion — "the framework's bottom layer is not in the corpus" — **was correct at the time and is now superseded by this section.** The in-tree/gem split is still real (§16.3 stands: these are still gem dependencies, not in-tree files), but they are no longer *unreadable*.

### 17.2 §7's encoder reasoning — verified against the real implementation

§7 established the encoder interface at `lib/msf/core/encoder.rb:72` and reasoned about the phase loop and XOR-additive-feedback **without the gem**. Verdict after reading the actual source:

**1. The XOR core — `rex-encoder-0.1.10\lib\rex\encoding\xor\generic.rb` (146 lines).** §7's description of a key-length-driven repeated XOR is **confirmed exactly.** `Generic.encode(buf, key)` (`:103-130`) walks `pos` over `buf`, XORs `buf[pos,1]` against `key[pos % len, 1]` (`:123`), and returns **`[encoded, key]`** — a two-element array, not a bare string. §7 described the mechanism correctly.

**2. §7's reasoning was INCOMPLETE on one point — the mutation hook.** Line `:124` calls `_encode_mutate_key(buf, key, pos, len)` **inside the loop**, and the base implementation (`:134-136`) returns `key` unchanged with the comment "by default, do no key mutations." **This is the extension point that additive-feedback and multi-byte encoder subclasses override**, and it is why `encode` returns the *final* key as well as the encoded buffer — the key is not constant across the buffer when mutation is active. §7 treated the XOR key as fixed for the run; the real contract is that **the key is a per-position evolving value**, and the returned key is the state at the end. This is the single most substantive correction in §17.

**3. The key-search guarantee (§7 did not cover this).** `_find_bad_keys` (`:45-63`) builds, per key position, the set of bytes that would produce a badchar at any data offset — `badkeys[pos % ksize][char ^ badchar] = true` (`:57`). `_find_good_key` (`:68-101`) then picks a random start byte per strip (`:76`) and linear-probes the full 256-byte space (`:79-86`), throwing `:found_kbyte` on the first byte that is neither a known-bad key byte nor itself a badchar (`:81`). **If the 256-byte probe exhausts, it raises `KeySearchError, "Exhausted byte space for strip #{strip}!"` (`:88`)** — a specific exception class, not a bare string. Then `:96-98` re-validates the assembled key and raises a second distinct `KeySearchError` if the check fails. **So the encoder layer's failure mode is loud and typed, in direct contrast to the bare rescues catalogued in §16.4.** §7's encoder section should carry this: *the encoder gem is one of the few places in the stack that fails closed with a named exception.*

**4. `Rex::Encoder::Xor` (`:1-69`) is a thin static wrapper, not the algorithm.** It is a transform pipeline: `_unencoded_transform` (`:50-52`) → `find_key_and_encode` (`:41`) → `_encoded_transform` (`:54-56`) → `_prepend() + encoded + _append()` (`:46`). All five hooks are no-ops in the base class and overridden by subclasses. `encoder()` (`:25-27`) resolves `self.class::EncoderKlass` — the subclass declares which `Rex::Encoding::*` implementation does the work.

**5. `bloxor` — chained XOR, not repeated-key XOR.** `rex-encoder-0.1.10\lib\rex\encoder\bloxor\bloxor.rb` (327 lines) is a genuinely different construction and §7 did not describe it. `compute_block(encoded, decoded)` (`:315-321`) sets each output block to the XOR of **the previous encoded block** with the current decoded block — a cumulative chain, so block *n* is the XOR-fold of blocks 1..*n*. `compute_encoded` (`:118-150`) pads to a multiple of `len` with random bytes (`:124-130`), slices into `blocks_in` (`:132-135`), solves for a seed block (`:137`), then folds forward from it (`:143-147`). **Because the chain is cumulative, the decoder must XOR *forward* in sequence rather than by position** — and the source states the decoder's shape exactly, as a C sketch at `:153-167`: `source` starts at the seed, `dest` at `source + BLOCK_SIZE`, counter = `BLOCK_COUNT * (BLOCK_SIZE / chunk_size)`, and each iteration loads from `dest`, increments both pointers, `decoded = *source`, stores `decoded ^ encoded`, until the counter hits zero. **The decoder stub is not hand-written assembly — it is generated by the polymorphic machine** (`Rex::Poly::Machine`) via twelve declarative block primitives at `:199-232`, with `chunk_size` chosen from the machine's native word size to match the block size (`:177-196`). `state.decoder_stub = compute_decoder(state)` (`:66`) memoizes it.

**6. `bloxor`'s search is bounded, and its failures are named.** `decoder_stub` (`:21-70`) iterates block sizes 1..`state.buf.length` (`:33`), **skipping every odd size** for performance, with the source's own reasoning at `:35-36` (the poly machine lacks efficient byte-size load/store primitives). For each candidate it validates the block count and size against badchars (`:49-55`) including their bitwise complements, and accepts the first that passes (`:57-60`). If none pass: **`raise RuntimeError, "Unable to generate seed block."` (`:64`)**. If the machine cannot build the stub: **`raise RuntimeError, "Unable to generate decoder stub."` (`:238`)**. `compute_seed` (`:248-309`) returns `nil` on failure (`:308`) rather than raising, and can **rewrite padding bytes** to escape a badchar dead-end (`:280-287`) — but only in the final block, only within the padded region, and only while a shuffled `redo_bytes` queue has entries (`:266-270`, refilled when drained). Also present: `entropy` (`:104-113`) computing Shannon entropy over the byte histogram, normalized by `/8`.

**§7's verdict: its reasoning holds on the mechanism, is incomplete on the mutation contract (§17.2.2), and silent on `bloxor` and the key-search guarantee.** Nothing in §7 is *wrong*, which given it was written without the gem in hand is a good result.

### 17.3 §12's substrate inference — what is now confirmed, what is corrected

§12 could only infer the channel/comm composition from in-tree callers. With `rex-socket-0.1.71` in hand `[source]`:

**CONFIRMED — the Comm abstraction is real and is exactly as §12 described it.** `switch_board.rb` (289 lines) opens with the authoritative statement at `:11-18`: SwitchBoard "provides a global routing table that associates subnets with Comm classes. Comm classes are used to instantiate objects that are tied to remote network entities. For example, the Local Comm class is used to building network connections directly from the local machine whereas, for instance, a Meterpreter Comm would build a local socket pair that is associated with a connection established by a remote entity. This can be seen as a uniform way of communicating with hosts through arbitrary channels." **§12.3's inference that a Meterpreter Comm backs a local socket pair for a remote connection is verbatim the gem's own documentation.**

**CONFIRMED and now named — `SwitchBoard` is the pivot routing registry.** It is a `Singleton` (`:23`). `Route` (`:36-65`) holds subnet, netmask, comm, plus network-byte-order forms of subnet/netmask. `add_route` (`:147-164`) converts a numeric bitmask to a netmask via `Rex::Socket.bit2netmask` (`:149`), rejects duplicates through `route_exists?` (`:156`), and mutates under `mutex.synchronize` (`:154`) — **the routing table is explicitly thread-safe**, with a lazily-created `Mutex` (`:278-284`). Class-level writers `add_route`/`remove_route` (`:77-95`) additionally append/delete `"#{subnet}/#{mask}"` on `comm.routes` when the Comm exposes that array, keeping both sides in sync.

**CORRECTED — `best_comm` is a longest-prefix match, and §12's Pivot model was missing a property.** `best_comm(addr)` (`:231-248`) walks every route, tests `(route.subnet_nbo & route.netmask_nbo) == (addr_nbo & route.netmask_nbo)` (`:238-239`), and **selects the route with the largest `bitmask`** (`:240-243`). `Route#bitmask` (`:55-58`) memoizes `Socket.net2bitmask(netmask)`. So the routing decision is **most-specific-prefix-wins**, not first-match — which means **the registered order of pivots does not determine selection; prefix length does.** Any model of Metasploit pivoting that treats routes as an ordered list is wrong. Note also the source's own `TODO: Enable this to work with IPv6 addresses` at `:33` — **`SwitchBoard` is IPv4-only**, while the surrounding `Rex::Socket` helpers are IPv6-aware. `resolv_nbo_i` on an IPv6 address would be the failure point, and `Route` stores only 32-bit nbo forms.

**CORRECTED — §12.2's table needs one refinement.** §12 concluded `Rex::Socket` is the substrate under every session and is externally provided. Confirmed. But the internal layer is richer than §12's brief list suggested — the gem ships separate `comm.rb`, `local.rb` (23,093 B — the largest file after `socket.rb`), `switch_board.rb`, `proxies.rb`, `parameters.rb`, plus per-transport classes `tcp.rb`, `tcp_server.rb`, `udp.rb`, `ssl.rb`, `ssl_tcp.rb`, `ssl_tcp_server.rb`, `sctp.rb`, `sctp_server.rb`, `ip.rb`, `ssh_factory.rb`, `subnet_walker.rb`, `x509_certificate.rb`. `socket.rb` (29,285 B) is a module-function namespace — `create`/`create_param`/`create_tcp`/`create_tcp_server`/`create_udp`/`create_ip` (`:44-79`), address arithmetic (`addr_atoc` `:357`, `addr_ctoa` `:374`, `cidr_crack` `:518`), port-spec handling (`portspec_crack` `:578`, `portlist_to_portspec` `:623`), `to_authority` (`:193` — the AGENTS.md-mandated IPv6-safe formatter), `source_address` (`:663`), and **a global resolver layer** (`_install_global_resolver` `:796`, `@@resolver`, `rex_gethostbyname` `:934`, `rex_getaddrinfo` `:953`).

### 17.4 §13's open thread — `RangeWalker`, closed

§13 named `RangeWalker` as the dependency behind `nokogiri_doc_mixin.rb:67`'s `rescue false` validator and had to leave it unresolved because it lives in a gem. **It is `rex-socket-0.1.71\lib\rex\socket\range_walker.rb`, 14,456 bytes, 559 lines** `[source]`.

**Reading `:24-90`:** `RangeWalker` enumerates IP ranges using **start/stop pairs** rather than materialized address lists — the class docstring at `:11-14` states the design rationale directly ("very efficient for large numbers of consecutive addresses, and not show-stoppingly inefficient when storing a bunch of non-consecutive addresses"). The format is richer than §13 assumed: `"10.1,3.1-7.1-255"` (`:17`), nmap-style octet ranges, comma *or* space separated (`:83` flattens `.split(', ')` then `.split(' ')`), with trailing commas stripped (`:85`) and **IPv6 CIDR handled first, by an explicit `arg.include?(':') && arg.include?('/')` test at `:88-89`**. `parse` returns `nil` for nil input (`:80`) and per-branch skips unparseable chunks (`:89`) rather than aborting the whole walk. `MATCH_IPV4_RANGE` (`:26`) is the explicit `a.b.c.d-e.f.g.h` form, `private_constant` (`:27`) — the conventions AGENTS.md asks for, honored here.

**Closing the §13 thread:** `nokogiri_doc_mixin.rb:67` calls `RangeWalker.new(addr).valid?` under `rescue false`. The gem confirms `parse` has genuine nil-returning failure paths (`:80`, `:89`) **but reading `:24-90` does not show a `valid?` method**, so the specific predicate used by the validator lives beyond the region read here — §17.7 records that as read-but-not-characterized rather than asserting a contract. **What is now established: the parser layer's only input validator delegates to an IP-range parser whose failure mode is `nil`, and it wraps that in a bare `rescue false`.** §13's characterization stands and is now sourced to the gem.

### 17.5 `rex-text` — the randomization layer §14 wrote one line about

`rex-text-0.2.63` is **24 files / 116,212 B** `[source]`. Its largest components are table and encoding machinery: `wrapped_table.rb` (19,460 B), `table.rb` (11,495 B), **`rand.rb` (11,490 B)**, `ebcdic.rb` (11,067 B), `unicode.rb` (10,847 B), `hex.rb` (7,715 B), `lang.rb` (6,274 B), `text.rb` (5,813 B), plus `encode.rb`, `randomize.rb`, `pattern.rb`, `badchars.rb`, `checksum.rb`, `hash.rb`, `base64.rb`, `base32.rb`, `xor.rb`, `compress.rb`, `color.rb`, `silly.rb`, `binary_manipulation.rb`, `block_api.rb`, `illegal_sequence.rb`.

**What §14 needed to know is now answerable at the file level.** The payload-safety story is not one algorithm but a **family of deliberate subsets** — `badchars.rb` (1,672 B) is the badchar predicate that §17.2.3 showed the encoder leaning on heavily (`Rex::Text.badchar_index`, called from `generic.rb:29,32` and `bloxor.rb:98`); `illegal_sequence.rb` (107 B) is a dedicated exception type; `silly.rb` (2,396 B) is attack-named (the `Silly`/`SillyClass` string-generation jokes). **Marked as inference, not asserted:** I read the inventory and the badchar call sites but not `rand.rb`'s generation algorithm, so I state the *shape* (character-class subsets plus a badchar filter plus a named illegal-sequence exception) and not the mechanism. §14's original one-line treatment was proportionate; this upgrades the citation from "a gem" to named files and sizes.

**Note the `require` at `generic.rb:4`** — `rex/encoding/xor/generic` requires `rex/text`, confirming §14's finding that `Rex::Text` is reached from the encoder layer, and that the `shuffle.rb:40` fallback (`Rex::Text.rand_text_alpha_lower`) is one of many consumers.

### 17.6 `rex-arch` and `rex-core`

**`rex-arch-0.1.20` — 15 files / 40,740 B** `[source]`: `x86.rb` (13,856 B) is the largest, then `arch.rb` (6,153 B) — **the constant namespace `shuffle.rb:13-14,47` indexes**, now readable. The remaining 12 are per-architecture modules at ~1.3-2.1 KB each: `aarch64`, `riscv64`, `riscv32`, `sparc`, `mips32`, `mips64`, `ppc64`, `ppc32`, `loongarch64`, `zarch`, `arm`, `amd64`. **This is the across-architecture constant set AGENTS.md points module authors at for `Arch` target declarations**, and it is confirmed to be 12 architectures plus x86 plus the shared `arch.rb`.

**`rex-core-0.1.37` — 19 files / 67,550 B** `[source]`. The load-bearing items are now nameable: **`stream.rb` (8,753 B)** and **`stream_server.rb` (5,462 B)** are the `rex/io/stream` and `rex/io/stream_server` that `lib/rex.rb` requires — §12.3 correctly deduced these were gem-provided and only named them; they are now located. Also **`ring_buffer.rb` (9,035 B)**, `relay_manager.rb` (4,873 B — the relay/pivot plumbing), **`fiber_scheduler.rb` (4,443 B)**, `read_write_lock.rb` (4,094 B), `thread_safe.rb` (2,668 B), `socket_abstraction.rb` (2,850 B), `event.rb`, `ref.rb`, `compat.rb`, `stopwatch.rb` (the `Rex::Stopwatch` AGENTS.md mandates for elapsed time), `exceptions.rb` (5,771 B — **the `Rex::TimeoutError` / `Rex::ConnectionError` classes AGENTS.md requires instead of bare raises**), `datagram_abstraction.rb`, `stream_abstraction.rb`, `file.rb`, `sync.rb`, `core.rb`.

**`exceptions.rb` at 5,771 B closes a loop across this whole document.** §11.2.2 found `packet.rb`'s bare rescue swallowing `TimeoutError`; §16.4 catalogued the swallow pattern; `Rex::TimeoutError` is the specific class those rescues should be naming. The typed exception hierarchy exists, is substantial, and is simply not used consistently in `lib/msf/core/`. **§16.4's finding was not that the project lacks the right exception classes — it is that the classes exist and the session-critical paths don't catch them.**

### 17.7 Residual unknowns after §17

**Confirmed absences (probe-backed)** — unchanged from §§12-16: no `lib/rex/socket` or `lib/rex/text.rb` or `lib/rex/arch.rb` *in-tree* (all four are gem-provided, and §17.1 now supplies them externally); no size guard in any of the 31 in-tree parsers; no `migration`/`exitfunc`/`single`/`stage` file under `lib/rex/payloads/`.

**Read in §17** `[source]`: `encoding/xor/generic.rb` (all 146 lines), `encoder/bloxor/bloxor.rb` (all 327 lines), `encoder/xor.rb` (all 69), `socket/switch_board.rb` (all 289), `socket/range_walker.rb:1-90` of 559, `socket.rb` structure via 80 signature lines of 1,018+, plus full file inventories and byte counts for all five gems.

**Read-but-not-characterized in §17**: `socket.rb` lines 1-43 and 90-1,018+ (including `create`/`create_param` dispatch bodies, the resolver layer, and the port-spec functions), `socket/comm/local.rb` (23,093 B — the default Comm, the single most consequential unread file remaining), `socket/parameters.rb`, `socket/proxies.rb`, the TLS classes (`ssl.rb`, `ssl_tcp.rb`, `ssl_tcp_server.rb`), `range_walker.rb:91-559` including the `valid?` predicate §17.4 names, all of `rex-encoder`'s `poly/` machinery (`machine/machine.rb` 28,317 B — the stub generator `bloxor` depends on — and `machine/x86.rb` 21,902 B, `poly/block.rb` 12,424 B), the 20 excepted encoder subclasses (`alpha2/*`, `unicode_*`, `xdr.rb`, `ndr.rb`, `poly.rb`), all of `rex-text` beyond its inventory, and `rex-arch`/`rex-core` beyond their inventories.

**Still externalized and unread**: the remaining **13 `rex-*` gems** from §16.1's list of 18 — `rex-powershell (0.1.105)`, `rex-nop`, `rex-rop_builder`, `rex-bin_tools`, `rex-registry`, `rex-java`, `rex-zip`, `rex-struct2`, `rex-ole`, `rex-mime`, `rex-sslscan`, `rex-exploitation`, `rex-random_identifier`. **These are obtainable by the identical method proven in §17.1**; they were out of the five-gem scope assigned here. `rex-powershell` is the most likely to matter for payload work.

**Implant-side unknowns** — unchanged and unaffected by §17: the transport failover algorithm; `TLV_TYPE_C2_*` semantics on the target; extension-id mapping.

*End of D9.*

---

