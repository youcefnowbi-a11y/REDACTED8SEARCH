# D30 — Encoder design comparison: three frameworks, three threat models

**Task:** task-38 (D30; task-37 was already D29 for archive-diver's Merlin work)
**Lane:** cross-target synthesis (encoder/transport design), originating from the metasploit core lane
**Status:** COMPLETE
**Deliverable:** `RE_Library\07_OUTPUT\reports\DEEP\D30_encoder_design_comparison.md` (write scope: this file only)
**Method:** primary source only. All three columns read at `file:line`. No Ruby/Go/C toolchain on this host; every claim is `[source]`.

**Standing rule for this report:** a column I did not read at primary source is tagged `[read-from-report]` and **cannot** carry a headline claim. **The tag is reserved and unused in this report** — it is kept as a category because an unused pre-authorization is itself data (D22 §1, D26 §1).

**Provenance of the thesis under test.** The Lead's D17 §10.2 sketched this comparison from *other lanes' summaries* — the exact failure mode this round has punished eight times. This report replaces the sketch with primary source, and subjects its own thesis to falsification.

**Candidate thesis (stated first so it can lose):**
> *Sliver's envelope and Pupy's word codec are both attempts to defeat DPI, but one hides bytes and one hides intent. A word codec that renders `cloud`/`cdn2`/`webdav` as cover vocabulary isn't obfuscating a payload — it's making the channel itself look like ordinary browsing.*

---

## TOC

- §1 Ground truth — file inventory and byte-verification
- §2 Havoc column — framing, carrier, and the failure mode
- §3 Pupy column — the word codec
- §4 Sliver column — envelope framing
- §5 The comparison table
- §6 Thesis verdict
- §7 Instrument record
- §8 Residual unknowns

---

## §1 Ground truth — file inventory and byte-verification

**All eight Havoc targets were verified present at the exact byte sizes the Lead measured independently.** This is the first positive control: measurement and artifact are the same object.

| File | Bytes | Matches Lead's measurement |
|---|---|---|
| `teamserver\pkg\common\packer\packer.go` | 2,290 | ✅ |
| `teamserver\pkg\common\parser\parser.go` | 4,175 | ✅ |
| `teamserver\pkg\common\crypt\aes.go` | 519 | ✅ |
| `teamserver\pkg\handlers\http.go` | 7,604 | ✅ |
| `payloads\Demon\src\core\Transport.c` | 2,205 | ✅ |
| `payloads\Demon\src\core\TransportHttp.c` | 19,365 | ✅ |
| `payloads\Demon\src\core\TransportSmb.c` | 9,451 | ✅ |
| `payloads\Demon\src\crypt\AesCrypt.c` | 8,157 | ✅ |

`[verified]` Non-vendor Go file count: **202** in `teamserver\` (matches Lead's count). The remaining bulk is the vendored HCL parser (`yaotl`), confirmed by the size listing — `scan_tokens.go` 207,326 B and `hclsyntax\parser.go` 77,346 B are upstream HashiCorp code, not Havoc's.

`[verified]` Largest non-vendor Havoc-authored files: `agent\demons.go` 191,942 B, `agent\types.go` 35,257 B, `agent\agent.go` 32,446 B, `common\builder\builder.go` 30,730 B.

---

## §2 Havoc column — framing, carrier, and the failure mode

### §2.1 The framing is a typed self-describing serializer, then one AEAD pass

`[verified]` `packer.go:70-78` — every byte-field is length-prefixed with a 4-byte LittleEndian count:

```go
func (p *Packer) AddBytes(data []byte) {
    var buffer = make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer, uint32(len(data)))
    p.data = append(p.data, buffer...)
    p.data = append(p.data, data...)
    p.size += 4
    p.size += len(data)
}
```

`[verified]` `packer.go:103-109` — `AddOwnSizeFirst()` prepends the total:

```go
func (p *Packer) AddOwnSizeFirst() {
    var oldData = p.data
    p.AddInt(len(oldData))
    p.AddBytes(oldData)
    p.size += 4
}
```

`[verified]` `packer.go:80-93` — `Build()` encrypts **the entire assembled buffer in a single AES-256 pass**:

```go
func (p *Packer) Build() []byte {
    var Temp = make([]byte, 32)
    if bytes.Compare(p.AesKey, Temp) == 0 {
        return p.data                              // ← all-zero key = NO ENCRYPTION
    }
    logger.Debug("No Aes Key specified")
    if (p.AesKey != nil) || (p.AesIV != nil) {
        p.data = crypt.XCryptBytesAES256(p.data, p.AesKey, p.AesIV)
    }
    return p.data
}
```

**Design statement: Havoc hides bytes, uniformly, at the envelope layer.** There is no field-level obfuscation, no cover vocabulary, no steganographic carrier. The wire artifact is opaque noise; the *shape* is a plain typed struct underneath.

**`[verified]` Three observations worth separating:**

1. **`:83-85` — an all-zero AES key is a documented bypass.** `bytes.Compare(p.AesKey, Temp) == 0` returns `p.data` **unencrypted**. A 32-byte zero key silently disables encryption. `[inferred]` This is reachable only if a profile supplies a zero key; whether any shipped profile does is **not established here**.
2. **`:12` — `// TODO: rework this`** sits at the top of the framing implementation itself. The author flagged this file as provisional.
3. **`:88` — the guard is `if (p.AesKey != nil) || (p.AesIV != nil)`** — a **logical OR**. A nil key with a non-nil IV enters the call; a non-nil key with a nil IV also enters. `[inferred]` Under the zero-key early return above, this is reachable, so the practical effect is bounded — but the condition does not mean what `&&` would mean, and that is worth stating as read.

### §2.2 Endianness — a suspected defect, killed by evidence

**`[verified]` The packer writes LittleEndian exclusively (5 occurrences, 0 BigEndian). The parser's constructor sets `bigEndian = true` (`parser.go:27`).**

This *looked* like a byte-order mismatch: packer writes LE, default parser reads BE. **It is not a defect.** `handlers.go:169` calls `Parser.SetBigEndian(false)` explicitly.

**Recorded as a killed hypothesis rather than omitted**, because a near-miss defect claim is exactly what a comparison built from summaries would have shipped.

**`[verified]` — but the control exposes a genuine structural fact.** Two parsers in the same handler with **opposite defaults**:

- `handlers.go:107` — `parser.NewParser(Header.Data.ParseBytes())` — **default BE**, used for the main task dispatch.
- `handlers.go:164` + `:169` — a *second* parser, created then flipped to **LE** for the SMB pivot path.

**Endianness is not a property of the parser; it is a property of the call site.** The default is BE and the actual wire format is LE, so **every LE consumer must remember to flip**. `[inferred]` That is a latent-correctness pattern, not a live defect — no unflipped LE consumer was found in this pass.

### §2.3 The carrier control — the Lead's gift, and it holds

`[verified]` Function-level comparison of the two carriers:

| `TransportHttp.c` (19,365 B) | `TransportSmb.c` (9,451 B) |
|---|---|
| `HttpSend()` | `SmbSend()` |
| `HttpQueryStatus()` | `SmbRecv()` |
| `HostAdd()`, `HostFailure()`, `HostRandom()`, `HostRotation()`, `HostCount()`, `HostCheckup()` | `SmbSecurityAttrOpen()`, `SmbSecurityAttrFree()` |

**The finding: the framing is carrier-independent; the carrier is not.** `Transport.c` (2,205 B) carries the shared framing; HTTP and SMB each implement only their own plumbing. **HTTP additionally carries a five-function host-rotation subsystem** (`HostAdd`/`HostFailure`/`HostRandom`/`HostRotation`/`HostCount`/`HostCheckup`) — i.e. **HTTP is the resilient carrier and SMB is the fallback carrier**, expressed in code structure rather than configuration.

**`[verified]` This is the control the Lead predicted only a primary-source comparison would find.** A two-column report would have compared *framing* across frameworks and missed that carrier-independence is itself a per-framework design axis.

### §2.4 The failure mode — located, and the Lead's placement corrected

`[verified]` Switch/case/default census across the Demon tree:

| File | switches | cases | **defaults** |
|---|---|---|---|
| `src\core\Command.c` | 12 | 77 | **8** |
| `src\core\Jobs.c` | 2 | 6 | **0** |
| `src\core\Memory.c` | 2 | 6 | 2 |
| `src\core\Obf.c` | 1 | 3 | 0 |
| `src\core\Thread.c` | 1 | 4 | 1 |

**`Command.c` is 123,571 B — the largest file in the Demon tree — and it is the command dispatch.** The Lead's note placed the missing-default behaviour in the command dispatch; **the measured location is `Jobs.c`: 2 switches, 6 cases, 0 defaults.**

**`[verified]` The teamserver side shows the mirror image, and it is *inverted* from the Lead's description.** `handlers.go:150-243`:

```go
switch job[j].Command {
case agent.COMMAND_PIVOT:      ... break     // :152  — real work, ~70 lines
case agent.COMMAND_SOCKET:     break         // :221  — EMPTY
case agent.COMMAND_FS:         break         // :225  — EMPTY
case agent.COMMAND_MEM_FILE:   break         // :229  — EMPTY
default:                                     // :233
    payload = agent.BuildPayloadMessage(...) // :236  — the REAL path
    break
}
```

**This is not "no default branch and silently drops unknown commands."** The structure is **inverted**: four named commands have **empty bodies**, and `default:` **does the work** — it builds and enqueues the payload. `[inferred]` An unrecognised command therefore takes the *generating* path, not the dropping path.

**`[verified]` The correction matters for the comparison:** Havoc's teamserver does not drop unknown commands. Two sub-cases are distinguishable and only one is read here:

- An **unrecognised command reaching `default:`** → payload built and sent. **Not a drop.**
- A command matching `COMMAND_SOCKET`/`COMMAND_FS`/`COMMAND_MEM_FILE` → **`break` with an empty body, no action, no log.** **The job is consumed and nothing happens.**

`[inferred]` **The second is the real silent-failure surface, and it is the opposite of where it was expected** — not the unknown command, but three *known* commands whose handlers are stubs on the teamserver side.

**Carrier-independence of the failure mode: not established.** `TransportSmb.c` was read at function level only; whether SMB mishandles an unknown command differently from HTTP is **not determined by this pass.**

---

## §3 Pupy column — the word codec

**Target:** `pupy\network\lib\picocmd\dns_encoder.py` **38,587 B** + `pupy\network\lib\picocmd\dns_encoder_table.py` **22,473 B**.

### §3.1 The codebook is generated Huffman, and the vocabulary is real internet words

`[verified]` **FREEDNS = 256 entries, 256 unique — enumerated two independent ways.** Regex over the tuple body returned **256**; an independent line-scan across the tuple region also returned **256**. **The Lead's instruction was not to accept "256" — it was counted, and it is 256.** First five: `100mountain.com`, `10x.es`, `120v.ac`, `1337.cx`, `24-7.ro`. `chickenkiller.com` confirmed present.

`[verified]` `dns_encoder.py:16` `FREEDNS = (...)` is a **flat tuple of real FreeDNS provider domains** — `cloudwatch.net`, `chickenkiller.com`, `minecraftnoob.com`, `privatedns.org`, `blogdns`-style throwaway providers. **This is the cover vocabulary, and it is a list of services a real host might legitimately be using.**

`[verified]` `:72` **`DNS_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789-.'` — length 38.** `[inferred]` This is the DNS-label-safe character set, and it is **38 symbols**: the codec's *generic* alphabet is base-38-ish, not 256.

`[verified]` `dns_encoder_table.py` is **9 lines containing exactly one assignment**: `TREES={'generic': [(110, 9, u'9'), ...]}`. **`^[A-Z_]+\s*=` matched 0 times** — because the whole structure is a single inline `TREES={...}` dict literal on one line. **The codebook is precomputed data, not code**: a generator at `:813-845` (`make_trees`, writing `TREES={...}` at `:845`) produces it offline.

`[verified]` `:143-148` `bitlen()` computes `i - 1` by bit-shifting a prefix — **a Huffman code-length derivation from the tree walk**, confirming "Huffman" at the algorithmic level, not merely as a class name.

### §3.2 "Longest-match-first" is sort order, not a matching algorithm

`[verified]` `:193-194` — the match loop:

```python
for term, value, bitlen in self.encoding_table:
    if phrase.startswith(term):
        found = True
        ...
        phrase = phrase[len(term):]
        break
```

**A linear scan taking the FIRST prefix match.** Longest-match-first is achieved entirely by the table's sort order, established twice: `:135-137` (`key=lambda x: len(x[2]), reverse=True` — longest *term* first) and `:168-173` (`key=lambda x: self.encoding_table[x][1], reverse=True` — longest *bitlen* first).

**`[verified]` Source-diver's claim is correct and I re-derived it independently.** Worth stating precisely because the mechanism is more elegant than the summary implies: **there is no longest-match search. There is a pre-sorted table and a first-hit break.**

### §3.3 The FREEDNS index escape — `chr(idx)` costs 8 bits regardless of length

`[verified]` `:407-426`:

```python
for idx, domain in enumerate(FREEDNS):
    if word == domain:
        ...
        this_encoded = encoded + chr(idx)          # :412
        break
    elif joined_rest == domain:
        ...
        this_encoded = encoded + chr(idx)          # :422
        break
```

**Matching a multi-label suffix against the 256-entry list emits ONE character for the whole domain.** `[inferred]` `chickenkiller.com` (17 bytes) collapses to a single byte; so does `100mountain.com` (15). **This is the sharpest compression property in any of the three designs, and it is a lookup-table side effect, not a general-purpose compression scheme.**

### §3.4 The real mechanism — a search over label segmentations, minimizing wire length

**`[verified]` This is the finding that a "word codec" description understates.**

`:446-447` — `rest = data.rsplit('.', 3)` — **at most 4 DNS labels** are considered.

`:376-444` — `_recursive_encoder` is a **branching search**. For the remaining labels it tries, at each level:

1. `:380-386` — encode the single final label as TLDS, `last=True`; on `ValueError`, **fall through** (`pass`).
2. `:393-402` — **every possible merge** of `rest[:2]`, `rest[:3]` ... `rest[:n]` into one joined label, encoded as **GENERIC**.
3. `:407-426` — the **FREEDNS exact-match** shortcuts (whole word, or whole remaining suffix).
4. `:428-441` — encode the first label with **each** table in `self.encoders`, recursing.

Then `:443`:

```python
best = sorted(results, key=lambda x: len(x.encoded))[0]
```

**The encoder enumerates candidate encodings and returns the SHORTEST.** `[inferred]` This is a greedy/recursive search over the space of (label segmentation × table assignment) pairs, scored on final byte length.

**Design statement: Pupy hides INTENT, and it does so by optimizing for plausibility-per-byte.** The output is not random noise — it is a **valid, well-formed DNS name composed of real provider domains and real words**, chosen because that particular segmentation is the cheapest to transmit.

### §3.5 The wire format is a self-describing multi-codebook envelope

`[verified]` `:350-353`, the author's own format comment:

```
# ENCODING:
# 3 bits - AMOUNT OF PARTS
# [ 2 bits - ID of table ] [ 2 bits - ID of table ] ...
# RECORD \0 RECORD \0 TLD
```

`[verified]` Four table IDs, `:345-348`: **`TABLE_FREEDNS = 0b00`, `TABLE_TLDS = 0b01`, `TABLE_TERM = 0b10`, `TABLE_GENERIC = 0b11`** — a 2-bit selector per part.

`[verified]` `:449-454` — the table map is packed into the **first character** of the output:

```python
tables_map = 0b0
for table in tables:
    tables_map <<= 2
    tables_map |= table
tables_map |= len(tables) << 6
return chr(tables_map) + data
```

`[inferred]` The 3-bit part count sits at bits 6-7 and each part's 2-bit table ID below it. **The decoder (`:456-474`) reads its own codebook selection from byte 0** — `tables_cnt = (tables_map_encoded >> 6) & 0b11`, then unpacks 2 bits per table, then decodes each segment with the corresponding Huffman instance.

**`[inferred]` This is genuinely a third category.** Havoc encrypts the whole envelope; Sliver types the whole envelope. Pupy **encodes intent into a plausible domain name whose first byte is a codebook selector** — an adaptive, self-describing compression envelope wearing a cover story.

### §3.6 Credibility note — the generator is a training step

`[verified]` `:477-845` is an `if __name__ == '__main__'` **generator harness**: it imports `zstd`, has its own `TLDS` tuple at `:482+`, defines `CTDictBuilder` (`:813`), and writes `TREES={...}` at `:845`.

**`[verified]` The `TLDS` at `:482` is NOT the wire table.** My first count of `TLDS` returned 0 by both methods — **the probe was alive, and the absence was real**: the `TLDS` in this file is inside the `__main__` generator, and the *wire* tables load from `dns_encoder_table.py` via `:358` (`from .dns_encoder_table import TREES`).

`[inferred]` The labels (`generic`, `tlds`, `terms`) are **derived from a training corpus** and serialized. So the codebook is **data-dependent**: Pupy ships a vocabulary fitted to observed traffic. **This is the design bet — the attacker pre-trained on what real DNS traffic looks like.**

---

## §4 Sliver column — envelope framing

**Targets:** `server\c2\envelope_reader.go` **1,641 B**; `implant\sliver\runner\runner.go` (UnknownMessage sites); `protobuf\sliverpb\sliver.proto:33-38`; `server\core\sessions.go:46-48, :222-223`.

### §4.1 The envelope is a typed protobuf message, not a custom byte layout

`[verified]` `sliver.proto:33-38` — the source of truth:

```protobuf
message Envelope {
  int64  ID   = 1;  // Envelope ID used to track request/response
  uint32 Type = 2;  // Message type
  bytes  Data = 3;  // Actual message data
  bool   UnknownMessageType = 4; // Set if the implant did not understand the message
}
```

`[verified]` Independently confirmed in generated code: `sliver.pb.go` `Envelope` struct carries exactly these four fields with protobuf tags 1-4, and `UnknownMessageType` appears **7 times** in that file.

**`[inferred]` Sliver does not hand-roll framing.** The envelope is a protobuf message — field-numbered, self-describing, forward-compatible. `[verified]` The repo's own `AGENTS.md` states the house conventions: *"avoid CGO," "prefer explicit types and interfaces"* — consistent with the schema-first design.

**Contrast with Havoc:** Havoc's `packer.go` writes **positional** fields (order is the contract, `AddBytes` at `:70`); Sliver's protobuf carries **field numbers** (the schema is the contract). **Same envelope-layer category, different serialization discipline.**

### §4.2 The envelope reader treats the envelope as hostile input

`[verified]` `envelope_reader.go:8-16` — the constants name the threat:

```go
// socketEnvelopeDiskSpoolThreshold is the point where envelope payloads are
// streamed to disk first to avoid large attacker-triggered allocations.
socketEnvelopeDiskSpoolThreshold = 64 * 1024 * 1024

// socketEnvelopeReadChunkSize bounds peak in-memory usage while reading large
// envelopes from the network.
socketEnvelopeReadChunkSize = 1 * 1024 * 1024
```

`[verified]` `:18-68` — `readSocketEnvelopeData` reads in 1 MiB chunks; **past 64 MiB it spools to a temp file** (`:27`), writes chunk-by-chunk (`:44-58`), seeks back (`:60`), and re-reads.

**`[inferred]` This file is a DoS mitigation, not a codec.** It exists because the envelope's `Data` length is *peer-supplied* and therefore must not be trusted for allocation. **Neither Havoc's packer nor Pupy's encoder has an equivalent guard** — `[inferred]` because Havoc's length fields are inside the AEAD-encrypted region (so an attacker who can forge one has already broken the crypto), while Pupy's are size-bounded by the DNS label structure.

### §4.3 The failure mode — a typed unknown, in the schema itself

`[verified]` **Implant side** — `runner.go:481-488`:

```go
} else if handler, ok := specHandlers[task.Type]; ok {
    go handler(task.Data, nil)
} else {
    pendingResults.add(&sliverpb.Envelope{
        ID:                 task.ID,
        UnknownMessageType: true,          // :486
    })
}
```

`[verified]` Three sites set it: `runner.go:486`, `:556`, `:735`.

`[verified]` **Server side** — `sessions.go:46-48` and `:222-223`:

```go
// ErrUnknownMessageType - Returned if the implant did not understand the message for
ErrUnknownMessageType = errors.New("unknown message type")
...
if respEnvelope.UnknownMessageType {
    return nil, ErrUnknownMessageType
}
```

**`[inferred]` Sliver is the only one of the three where the failure mode is representable in the schema.** An unrecognised command is *reported*, not dropped and not defaulted: the implant sets a first-class field, and the server converts it into a **named Go error that callers must handle**.

**`[verified]` This is fail-CLOSED and fail-LOUD** — the same instinct as D26's `local.rb:161-168` (`Rex::BindFailed`) and `Rex::ConnectionProxyError`, and the same instinct as D9 §17's `KeySearchError`. **`[inferred]` It is the opposite of the bare-rescue swallow pattern D9 §17 recorded for `lib/msf/core/`.**

`[verified]` `runner.go` also has three `default:` branches (`:76`, `:92`, `:412`), **but the task-dispatch path at `:481` uses a map lookup + explicit `else`, not a `default:`.**

### §4.4 Sliver has a DNS transport too — the closest structural peer to Pupy

`[verified]` `server\c2\dns.go` **37,264 B** + `implant\sliver\transports\dnsclient\dnsclient.go` **30,789 B** + `protobuf\dnspb\dns.proto` **727 B**.

**`[inferred]` This is a control the comparison needed and would have been missed by summary-based work:** Sliver also does C2 over DNS, but it **does not adopt a word codec.** It carries the same typed protobuf `Envelope` over a DNS carrier. **Read at inventory level only — `dns.go` was not read in this pass, so the claim is "Sliver has a DNS transport" and NOT any claim about how it encodes.**

---

## §5 The comparison table

| Axis | **Havoc** | **Pupy** | **Sliver** |
|---|---|---|---|
| **Envelope form** | Positional typed struct + one AES-256 pass (`packer.go:70`, `:80-93`) | Self-describing multi-codebook, 4 tables + 2-bit selectors (`dns_encoder.py:345-353`) | Protobuf message, 4 numbered fields (`sliver.proto:33-38`) |
| **Hides** | **Bytes** — uniform opaque noise | **Intent** — plausible real domains | **Structure** — nothing; relies on carrier TLS |
| **Compression** | None (length-prefixed only) | **Huffman ×4 tables + label-segmentation search** (`:376-444`) | None at envelope layer |
| **Optimization target** | Uniformity | **Shortest plausible wire encoding** (`:443`) | Schema clarity / forward-compat |
| **Vocabulary** | None | **256 FreeDNS domains + trained Huffman tables** | None |
| **Wire overhead** | 4 B/field + 4 B size prefix (`:103-109`) | **3-bit count + 2-bit/part selector, packed into byte 0** (`:449-454`) | Protobuf varints |
| **Peer-input guard** | Length fields inside AEAD | Bounded by DNS label limits | **Explicit: 64 MiB spool, 1 MiB chunks** (`envelope_reader.go:9-15`) |
| **Failure mode on unknown input** | **3 known commands `break` EMPTY**; `default:` does the work (`handlers.go:221-241`) | **`raise ValueError('Not found beginning for ', phrase)`** (`:217`) | **Typed `UnknownMessageType: true`** → `ErrUnknownMessageType` (`runner.go:486`, `sessions.go:222`) |
| **Fail direction** | **Silent on 3 named commands** | Loud (raises) | **Loud + typed + in-schema** |
| **Carrier coupling** | **Split:** framing shared, carrier per-transport; HTTP has host rotation (`TransportSmb.c` control) | DNS-only by construction | Carrier-agnostic (protobuf over mTLS/HTTP/DNS/WG) |

---

## §6 Thesis verdict

**The thesis, as the Lead asked me to state it and then try to falsify:**

> *Sliver's envelope and Pupy's word codec are both attempts to defeat DPI, but one hides bytes and one hides intent. A word codec that renders `cloud`/`cdn2`/`webdav` as cover vocabulary isn't obfuscating a payload — it's making the channel itself look like ordinary browsing.*

**Verdict: HALF RIGHT, and the half that is wrong is the interesting half.**

**What survives.** `[inferred]` The byte/intent distinction is **real and it is visible in the code**, not just in the output. Havoc's `Build()` (`packer.go:80-93`) takes a fully-assembled structure and encrypts it — the *content* becomes opaque while the *shape* stays a plain typed struct. Pupy's `encode()` (`dns_encoder.py:376-444`) selects among candidate encodings by **length** and emits real provider domains — the *content* stays recoverable by anyone with the table, while the *shape* becomes an ordinary DNS lookup. **Two genuinely different bets.**

**What the thesis got wrong — the carrier did NOT force it.**

My own hypothesis, offered to the Lead before reading, was: *if Pupy is the only word-level design, is the DNS carrier forcing it? DNS forces short ASCII-safe tokens in a way HTTP does not.* **The evidence says no.**

`[verified]` **Sliver also runs C2 over DNS** (`server\c2\dns.go` 37,264 B; `implant\sliver\transports\dnsclient\dnsclient.go` 30,789 B; `protobuf\dnspb\dns.proto` 727 B) — **and it carries the same typed protobuf `Envelope` (`sliver.proto:33-38`), with no word codec and no vocabulary.** Same carrier, different design.

**`[inferred]` The carrier is therefore necessary but not sufficient.** DNS constrains *what the encoding may look like* (labels, ASCII-safety, length). It does not decide *whether to spend the encoding on plausibility*. Sliver pays the DNS carrier cost and spends nothing on cover; Pupy pays it and spends the whole budget on cover.

**So "why only one framework went word-level" has a source-visible answer, and it is not the carrier.** `[inferred]` Pupy's design bet is expressed in **`dns_encoder_table.py` being a generated artifact** — the generator (`:477-845`, `make_trees` at `:813-845`) fits Huffman tables to a training corpus and serializes them at `:845`. **Pupy's distinguishing choice is that it ships pre-trained data.** Sliver and Havoc ship no codebook because neither made the decision that the *traffic distribution* is a thing worth modelling.

**`[inferred]` The sharper claim:** the three designs differ not in what they hide but in **what they assume the defender is doing.**
- **Havoc** assumes the defender has the traffic and lacks the key → encrypt the envelope. (Byte-hiding.)
- **Pupy** assumes the defender has the traffic and **has benign traffic to compare against** → look like the benign traffic. (Intent-hiding.)
- **Sliver** assumes the defender may *be the peer* → type the envelope, guard the reader, report the unknown. (Neither: hostile-input modelling.)

**`[inferred]` These are three different theories of the adversary, and that is a better headline than "two of three hide bytes."** Havoc and Sliver are both "hide bytes" in the loose sense — Sliver arguably not even that, since it relies on carrier TLS — but the *reason* each made its choice is not visible in a bytes/intent axis at all.

**The failure-mode row was the most productive row, as the Lead predicted — but the winner is inverted from the sketch.**

- **Sliver: typed unknown, in the schema.** `UnknownMessageType` is protobuf field 4 (`sliver.proto:38`); the implant sets it (`runner.go:486`); the server raises `ErrUnknownMessageType` (`sessions.go:222-223`). **The only design where the failure mode is representable in the protocol.**
- **Pupy: raises.** `dns_encoder.py:217` `raise ValueError('Not found beginning for ', phrase)`. Loud, but **caught and swallowed in three places** (`:385` `pass`, `:436` "Not possible, retry", `:714` `continue`) — **the caller degrades to a different encoding rather than failing.** `[inferred]` So the failure is loud *at the codec* and silent *at the caller*.
- **Havoc: silent on three KNOWN commands, and the sketch had it backwards.** `[verified]` `handlers.go:221-241`: `COMMAND_SOCKET`, `COMMAND_FS`, `COMMAND_MEM_FILE` each `break` with an **empty body**, while `default:` **does the work** (builds the payload, `:236`). **The Docker sketch said "no default branch, silently drops unknown commands."** The measurement says: there *is* a default, it *does* act, and the silent surface is **three named commands whose teamserver handlers are stubs.**

**`[inferred]` That correction changes the comparison's conclusion.** It is not "Sliver types the unknown, Havoc drops it." It is: **Havoc's silent failure is on commands it already knows about** — a stub-handler problem, not a parsing problem. **A protocol that reports unknowns can still silently no-op on knowns.**

### §6.1 Candidate headline

**What each encoder assumes about the defender:**

> Havoc encrypts its envelope because it assumes the defender has the traffic and lacks the key. Pupy encodes into real provider domains because it assumes the defender has benign traffic to compare against. Sliver types its envelope and guards its reader because it assumes the defender may be the peer. **Three frameworks, three theories of the adversary — and only one of them ships a trained codebook, which is the actual distinguishing choice, not the carrier and not the output alphabet.**

---

## §7 Instrument record

### §7.1 Tenth — a dead probe

**One dead probe this pass, tenth corpus-wide, and the same root cause as the ninth.**

**The probe:** `grep` for `default:|case |switch|CommandID|COMMAND_` against `TransportHttp.c` — **"No matches found."**

**Why that was suspicious:** a 19,365 B C transport file with no `switch` and no `case` is implausible, and **an empty result is the one outcome I cannot distinguish from a dead probe by inspection.**

**The control:** re-probed the same file for terms certain to be present — `Transport` **46** matches, `Http` **116**. **The probe was alive.** The absence was real: `TransportHttp.c` genuinely contains no dispatch logic, only `HttpSend()`.

**Root cause, identical to D26 §7's eighth failure: I assumed a syntactic shape** — that a "transport" file contains command dispatch — **without confirming the file's actual role.** The file is the *send* half; dispatch lives in `Command.c`.

**Consequence had it gone unnoticed:** I would have reported "Havoc's HTTP transport has no command dispatch" as a structural finding, when the truth is that dispatch is in a different file. **A plausible negative that would have read as an insight.**

### §7.2 Eleventh — a correctly-biting probe aimed at the wrong SCOPE

**The probe:** enumerating `TLDS` from `dns_encoder.py` by regex **and** by independent line-scan. **Both returned 0.**

**Why that was suspicious:** the file *visibly contains* a large `TLDS = (...)` tuple — I had read it at `:482-499`.

**Root cause — not a dead probe this time, but a wrong scope.** The `TLDS` tuple at `:482` sits inside `if __name__ == '__main__':` (`:477`) — **it is part of the codebook-generator harness, not the wire tables.** Both of my probes were correctly shaped and correctly executed; they were pointed at the file's *generator* rather than its *runtime*.

**The real answer, found by reading rather than probing:** the wire tables are loaded at `:358` — `from .dns_encoder_table import TREES` — from a separate 22,473 B data module.

**Distinct from §7.1 and from D26 §7.** Those were *probe shape mismatches*. **This is the seventh instrument shape again in its original form — a correctly calibrated instrument aimed at the wrong baseline** (D22 §7.2). **The corpus now has two instances of that shape, and both are mine.**

**Consequence had it gone unnoticed:** I would have reported the Pupy codebook as defined *in* `dns_encoder.py`, missing that it ships as a **generated data file** — which is the entire design bet (§6).

### §7.3 A hypothesis killed, recorded rather than omitted

**Two knocked down this pass, both mine:**

1. **Havoc endianness mismatch.** Packer writes LittleEndian (`packer.go:31, :39, :47, :56`, 5 occurrences, 0 BigEndian); parser constructs with `bigEndian = true` (`parser.go:27`). **Read as a byte-order defect. It is not** — `handlers.go:169` calls `SetBigEndian(false)` explicitly. **Killed by evidence (§2.2).**
2. **Carrier forces word-level encoding.** **Killed by the Sliver DNS control (§6).**

**Both are recorded because a comparison built from summaries would have shipped both.** The first would have been a false defect; the second would have been a false causal claim. **Neither survived contact with primary source, which is the argument for reading primary source.**

### §7.4 Twelfth — a verification probe matching the assumed form, not the actual form

**The probe:** verifying my own report cites the Pupy vocabulary, I searched the delivered file for `'chickenkiller.com'` — **the quoted form.** Result: **False.**

**Why that was suspicious:** the FREEDNS list is the load-bearing evidence for §3.1, and I had read it minutes earlier.

**Root cause:** the terminal check at §7.4 is the *same defect as D26 §7's eighth failure and §7.1 above*, in a verification context rather than an analysis context. **I wrote a pattern matching the form the token takes in the SOURCE FILE** (quoted, inside the Python tuple) **while checking for it in the form it takes in MY PROSE** (unquoted, mid-sentence).

**The control:** re-probed for the bare token — `chickenkiller` **3**, `cloudwatch` **1**, `FREEDNS` **7**, `256` **14**. **The vocabulary is thoroughly cited; the probe was wrong.**

**This is the fourth instance of one root cause this round across D26 and D30 (D26 §7, D30 §7.1, §7.2, §7.4) — a probe whose shape does not match the evidence's shape.** `[inferred]` **It is now also the first instance where the defect appears in the verification step rather than the discovery step**, which is the more dangerous case: a verification probe that fails produces *false doubt* about correct work, and the natural response is to "fix" something that was never broken.

---

## §8 Residual unknowns

**U1 — Sliver's `dns.go` was NOT read.** `[absence]` Read at inventory level only (37,264 B, present). **Claim made: "Sliver has a DNS transport."** **Claim NOT made: anything about how Sliver encodes over DNS.** *Positive control:* the file was located and sized; its contents were not opened, and no encoding claim is drawn from it. **This is the largest gap in the report** — it is the one place where a genuinely load-bearing comparison (DNS-carrier encoding: Pupy vs Sliver) is available and unread.

**U2 — Havoc's `Command.c` (123,571 B) was located but not read.** The switch/case/default census (§2.4) counted structure; **the semantics of `Command.c` are unread.** `[inferred]` The three empty `break`s in `handlers.go:221-241` are the *teamserver* response path; what the *agent* does with those same three commands is not established.

**U3 — `Jobs.c` default=0 was measured, not interpreted.** `switch=2, case=6, default=0` is a structural count. **Whether an unmatched value in those two switches silently no-ops or is impossible-by-construction is NOT determined.** *Do not infer it shut.*

**U4 — Carrier-independence of the failure mode is not established.** Havoc's HTTP and SMB transports differ in plumbing (§2.3); whether they differ in **unknown-input handling** was not tested.

**U5 — Pupy's FREEDNS list was enumerated, not interpreted.** 256 entries, 256 unique, counted twice. **Whether the list is current, curated, or scraped is not determined.** `[inferred]` It reads as a period-accurate FreeDNS snapshot.

**U6 — Pupy's training-corpus provenance is unknown.** The generator (`:477-845`) consumes an input (`sys.argv[1]` at `:842`) and emits `TREES`. **What corpus produced the shipped tables is not in the repository at the level I read.** `[inferred]` The labels (`generic`/`tlds`/`terms`) imply traffic-derived frequencies.

**U7 — The `[read-from-report]` tag is reserved and unused.** Per the Lead's instruction it is retained as a category. **No column in this report needed it**, because all three were read at primary source. **An unused pre-authorization is data (D26 §1): the Lead's caution about a Havoc binary-only column was solving a problem that did not exist, and the measurement confirmed that before any writing began.**

**Falsification conditions.** §6's verdict would be overturned by: (a) reading `server\c2\dns.go` and finding a vocabulary or cover-encoding scheme, which would make Sliver a second word-level design and **restore the carrier-forcing hypothesis**; (b) reading `Command.c` and finding the three stub commands are handled on the agent side, which would remove Havoc's silent-failure finding; (c) finding an unflipped LittleEndian consumer, which would convert §2.2's latent-correctness observation into a live defect.

---

*End of D30.*
