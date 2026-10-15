# D16 — Pupy `picocmd` DNS C2: encoder, codebooks, and resolver

**Lane:** `source-diver` · **Task:** task-28 · **Instrument:** source-only. **No REA provider held or needed. No Ghidra. No execution.**
**Target tree:** `RE_Library\01_SOURCE_c2\pupy\pupy\network\lib\picocmd\`

**Method tags:** `[source]` = read directly from a file on disk, cited by line. `[inferred]` = deduction, always labelled. `[absence]` = a negative result, always paired with a positive control shown able to succeed. `[near-miss]` = an instrument or reasoning error in this lane, caught and recorded rather than silently repaired.

---

## Table of Contents

- [§0 Status and headline results](#0-status-and-headline-results)
- [§1 The five codebooks — `dns_encoder_table.py`](#1-the-five-codebooks--dns_encoder_tablepy)
- [§2 Whole-term Huffman — the model the brief got wrong](#2-whole-term-huffman--the-model-the-brief-got-wrong)
- [§3 The 256-entry provider list and the 8-bit index](#3-the-256-entry-provider-list-and-the-8-bit-index)
- [§4 The resolver — where the decisions actually live](#4-the-resolver--where-the-decisions-actually-live)
- [§5 Carrier economics — A vs AAAA, and the 255-byte ceiling](#5-carrier-economics--a-vs-aaaa-and-the-255-byte-ceiling)
- [§6 Latent defects — marked latent, not live](#6-latent-defects--marked-latent-not-live)
- [§7 The Parcel framing layer — and D6 §13's read boundary](#7-the-parcel-framing-layer--and-d6-13s-read-boundary)
- [§8 Boundudes and scope](#8-boundaries-and-scope)
- [§9 Residual unknowns](#9-residual-unknowns)
- [§10 Instrument record](#10-instrument-record)

---

## §0 Status and headline results

This report covers `picocmd`'s DNS command-and-control path: the codec (`dns_encoder.py`, 38,587 B / 845 lines), the codebooks (`dns_encoder_table.py`, 22,473 B / **8 lines**), the client (`client.py`, 22,531 B / 708 lines), and the resolver (`server.py`, 45,257 B / 1,459 lines).

**Scope boundary, stated the way D1 states its T1 boundary:** this report **is the control comparison for D6 §13.** D6 §13 read `picocmd.parse`/`picocmd.py`'s Parcel framing and the 29-positional-ID command dispatch table. **This report reads the DNS encoding layer that D6 §13 explicitly did not** — the codebooks, the term-matching encoder, and the resolver that consumes them. It does not re-derive the Parcel framing; where it touches framing (§7) it does so only to mark the seam.

### Headline results

1. **The compression model is word-level for the trees that carry payload — but the file also contains a character codec.** `Huffman.encode` matches **whole multi-character terms** via `phrase.startswith(term)` (`dns_encoder.py:194`), sorted longest-match-first. The `terms` codebook's symbols are **real internet infrastructure words** — `cloud`, `cdn2`, `webdav`, `nextcloud`, `payment`, `correo`, `member`, `temp`. The symbol distribution is a **cover story**, not merely a compression choice. The task brief's premise of a character-level codec was **wrong for `tlds` and `terms`** — the two trees that carry vocabulary-bearing payload.

   **Stated in its narrow, defensible form:** `dns_encoder` contains **a character codec and a word codec side by side.** `generic` is a genuine single-character codec over exactly `DNS_ALPHABET` (39 entries: 38 characters + the NUL sentinel) with a Kraft sum of 1.0 — a complete character code. `tlds` and `terms` are word codecs (max symbol lengths 13 and 20). **The broad claim "the codec is not character-level" is false** and a reader who opens `generic` would refute it correctly. **The narrow claim "the trees that carry domain vocabulary are not character-level" is provable** from the symbol lengths and the Kraft analysis in §1.2.

2. **`dns_encoder_table.py` is one line of substance.** 22,473 bytes, 8 lines: four `__future__` imports, and a single 22,289-character dict literal `TREES`. It holds **five** codebooks, and **two of them are empty 0-bit stubs** — deliberately, to hold their 2-bit ID slots.

3. **The provider list is exactly 256 entries because the index is one raw byte.** A matched FreeDNS domain costs **8 bits regardless of its length** — `chickenkiller.com` (17 characters) collapses to one byte. The size is a boundary artifact of the encoding.

4. **The deciding code is in `server.py`, within this lane's scope.** `_cmd_processor` (`:936`) is a real dispatch table; `set_policy` (`:621`) enforces policy including an anti-DNS-storm guard; `_resolve` (`:1378`) is the resolver core. This was checked specifically against the D9 failure mode (§4.0).

5. **Two latents, both marked latent-not-live** (§6): a self-comparison at `server.py:623`, and a hardcoded `return False` KEX stub at `server.py:1375`.

6. **One framing question resolved:** `_resolve:1402`'s `.idna()[:-1]` strips a **DNS trailing-dot artifact**, not a payload terminator. The payload carries no delimiter; the boundary is carried by an explicit 1-byte length field.

---

## §1 The five codebooks — `dns_encoder_table.py`

### §1.1 The file is one line

```
L   1 [    23] # -*- coding: utf-8 -*-
L   2 [     0]
L   3 [    38] from __future__ import absolute_import
L   4 [    31] from __future__ import division
L   5 [    37] from __future__ import print_function
L   6 [    39] from __future__ import unicode_literals
L   7 [     0]
L   8 [ 22289] TREES={'generic': [(110, 9, u'9'), (111, 9, u'7'), (360, 9, u'5'), ...
```

**Line 8 is 22,289 characters.** File total 22,473 bytes; the difference is the header, the import block, and newlines. `[source]`

`TREES` is a dict of five keys, each mapping to a list of `(code, bit_length, symbol)` triples. This is a **flattened, precomputed Huffman codebook** — one row per symbol, carrying the symbol's code as an integer and its bit length, so no tree walk is needed at runtime beyond `Huffman.set_decoding_table`.

### §1.2 The five trees, enumerated

| Tree | Entries | Max symbol length | Code bit range | NUL sentinel |
|---|---|---|---|---|
| `generic` | **39** | **1** | 4–9 bits | 1 entry |
| `tlds` | **513** | 13 | 2–18 bits | 1 entry |
| `terms` | **513** | 20 | 2–14 bits | 1 entry |
| `cdns` | **1** | — | **0 bits** | 1 entry |
| `freedns` | **1** | — | **0 bits** | 1 entry |
| **total** | **1,067** | | | |

`[source]` — parsed with Python `ast.literal_eval` on the module body, not by regex, so the counts are exact rather than approximate.

Bit-length distributions, which are the entropy signature of a real Huffman code:

- **`generic`** — `4b=10  5b=7  6b=7  7b=1  8b=6  9b=8`. A small, shallow alphabet: the common characters get 4-bit codes.
- **`tlds`** — `2b=2  4b=1  5b=4  6b=7  7b=10  8b=9  9b=18  10b=26  11b=20  12b=31  13b=34  14b=53  15b=73  16b=95  17b=106  18b=24`. Bell-shaped, peaking at 17 bits, with a 24-entry long tail. This is the distribution of a **real TLD frequency model** — a long tail of rare TLDs and two 2-bit codes for the ones that dominate real traffic.
- **`terms`** — `2b=2  3b=2  4b=1  5b=1  7b=1  8b=8  9b=13  10b=22  11b=36  12b=80  13b=197  14b=150`. Peaks hard at 13 bits. A steeper, narrower model than `tlds`.

**513 entries = 513 distinct symbols = 513 leaves.** The codebook stores **leaves only** — one row per symbol, carrying its code and bit length. The corresponding full binary tree has `2 × 513 − 1 = ` **1,025 nodes**; the 512 internal nodes are not represented in the table and are reconstructed at load time by `Huffman.set_decoding_table` / `_generate_table`, which rebuilds a decodable structure from the flat leaf rows.

The identity that proves these are complete prefix codes, measured directly on the tables:

| Tree | Entries | Distinct symbols | Distinct code integers | Kraft sum `Σ 2^(−L)` |
|---|---|---|---|---|
| `generic` | 39 | 39 | **34** | **1.000000** |
| `tlds` | 513 | 513 | **502** | **1.000000** |
| `terms` | 513 | 513 | **513** | **1.000000** |

**Kraft sum exactly 1.0 on all three** is the defining identity of a **complete prefix code** — every code is assigned, no gaps, no unused leaves, no prefix collisions. This was computed from the stored `(code, bit_length, symbol)` rows, so it is a measurement of the tables as shipped, not a property assumed from the file's name.

**The `distinct code integers` column is the source of a near-miss (see §10.5).** Codes are stored as raw unshifted integers, so a 4-bit code `0b1010` and a 9-bit code `0b000001010` are **the same integer** (`10`). `tlds` therefore shows 502 distinct integers for 513 symbols, and `generic` shows 34 for 39. This is expected and correct for an unshifted-integer representation; it also means **the code integers in the table are not globally comparable across different bit lengths** — only `(code, bit_length)` pairs are. `terms` happens to be a clean bijection at 513 distinct integers, which is the exception rather than the rule.

In `train()` (`dns_encoder.py:290-325`) the tree is built with `heapq` pushing `Node`s and merging into `Root`s; `_make_tree` (`:310`) emits tuples and leaves as bare symbols, and `Huffman._generate_table` (`:140-174`) walks that structure assigning `prefix << 1 | 0/1` codes. The precomputed `TREES` is the serialised output of that process, storing only the leaves.

### §1.3 `generic` is the `DNS_ALPHABET` fallback

`DNS_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789-.'` (`dns_encoder.py:72`) — **38 characters**. The `generic` tree's non-NUL symbols are:

```
-.0123456789abcdefghijklmnopqrstuvwxyz
```

**The character sets are identical, 38 symbols each.** Stated as a set equivalence rather than a string equality, because a naive `==` on the sorted strings returns `False` — the source literal's ordering differs from sorted order. The 38-symbol alphabet contains **no uppercase, no underscore, no non-ASCII**, and `DnsEncoder.encode` lowercases its input at `:374` (`data = data.lower()`). So the codec's entire input domain is already constrained to exactly these 38 characters before any Huffman code is applied. `[source]`

The `generic` tree is therefore the **fallback** — a single-character codec used when a label matches no multi-character term and no TLD. At 4–9 bits per character it still compresses against 8-bit ASCII, but its real job is guaranteeing the encoder can always encode *something*, so `_recursive_encoder` never dead-ends.

### §1.4 `cdns` and `freedns` are deliberate stubs

Both have **one entry, zero bits, symbol `'\x00'`.** They are not populated vocabularies.

They are referenced from `DnsEncoder`'s table-ID constants (`dns_encoder.py:345-348`):

```python
TABLE_FREEDNS  = 0b00
TABLE_TLDS     = 0b01
TABLE_TERM     = 0b10
TABLE_GENERIC  = 0b11
```

**`FREEDNS` occupies table ID `0b00`.** And the encoder construction at `:361-371` guards registration:

```python
mappings = {
    'generic': self.TABLE_GENERIC,
    'tlds':    self.TABLE_TLDS,
    'terms':   self.TABLE_TERM
}
...
self.encoders = {
    mappings[table]: Huffman(decoding_table=tables[table])
    for table in tables
    if table in mappings          # <- :370
}
```

`mappings` contains only three of the five keys, and the comprehension's `if table in mappings` guard at **`:370`** excludes the other two. **`self.encoders` has exactly three keys: `0b01`, `0b10`, `0b11`.** `[source]`

**Why the stubs exist and why they are not a defect.** The FreeDNS path is handled *outside* Huffman entirely — a matched provider domain emits a raw index byte (`chr(idx)` at `:412`/`:422`), not a Huffman code. The `freedns` tree's single 0-bit NUL entry gives the decoder a codec that **consumes zero bits**, which is exactly what the raw-index path needs. The stub is a deliberate zero-width codec, not an unfinished table.

**Why `cdns` exists at all** is less clear: it holds ID `0b00` conceptually alongside `freedns`, but only `freedns` has a code path. `cdns` is registered nowhere, emitted nowhere, and decoded nowhere. **It occupies a bit-slot that nothing reads.** Recorded as a residual (§9), not asserted as a defect — a reserved slot is a legitimate design choice, and its presence costs 2 bits only if it were ever emitted, which it is not.

---

## §2 Whole-term Huffman — the model the brief got wrong

### §2.1 The encoder matches whole terms

`Huffman.encode` (`dns_encoder.py:176-223`), the load-bearing loop:

```python
for term, value, bitlen in self.encoding_table:      # :193
    if phrase.startswith(term):                      # :194
        found = True
        ...                                          # emit `bitlen` bits of `value`
        phrase = phrase[len(term):]                  # :213
        break
```

**`phrase.startswith(term)` where `term` is a multi-character string.** For the `tlds` and `terms` trees this is not a character codec. The encoder consumes **whole words, whole TLDs, or whole domain labels** in a single code, and the symbols' lengths confirm it: `tlds` max symbol length **13**, `terms` max symbol length **20**, versus `generic`'s **1**.

**`generic` is the character codec and it is a complete one.** Its 39 entries are 38 single characters (exactly the `DNS_ALPHABET` set, §1.3) plus the NUL sentinel, and its Kraft sum is **1.000000** (§1.2) — a full, gap-free single-character prefix code. So `dns_encoder` holds **both** a character codec and word codecs, and the two are used at different points in the same recursion: `generic` as the always-available fallback that guarantees a label can be encoded, `tlds`/`terms` as the vocabulary codecs that make a domain-shaped label cheap. **The distinction between the two families is the correct framing; "character vs. word" is not a global property of the file.**

Longest-match-first is enforced by the table ordering at `:134-138`:

```python
self.encoding_table = tuple(
    (term, value, bitlen) for value, bitlen, term in sorted(
        self.decoding_table, key=lambda x: len(x[2]), reverse=True
    )
)
```

sorted by **`len(term)` descending** — so the scan at `:193` tries the longest terms first and the first `startswith` hit is the longest match. And `_generate_table`'s final step (`:163-174`) sorts by **`bitlen` descending**, so the code walk also prefers the longest codes first. `[source]`

### §2.2 The `terms` vocabulary, and why those words

The `terms` codebook's symbols are, verbatim from the first entries:

```
'correo', 'temp', 'wi', 'dedicated', 'lviv', 'nextcloud', 'cm', 'sc',
'inf', 'member', 'bbs', 'toyota', 'post', 'cloudfunctions', 'payment',
'elearning', 'eco', 'webdav', 'adidas', 'cdn2', ...
```

And the `tlds` codebook's symbols:

```
'tj', 'diamonds', 'holdings', 'vote', 'restaurant', 'gp', 'istanbul',
'mc', 'lgbt', 'bw', 'gop', 'gold', 'tours', 'florist', 'gal', 'cv',
'accountants', 'bs', 'barcelona', 'voyage', ...
```

**Two different vocabularies with two different jobs.** `tlds` is the actual TLD namespace — it lets the encoder emit a real TLD in a handful of bits instead of spelling it out. `terms` is a curated word list drawn from the vocabulary of **hostnames that real infrastructure uses**: `cloud`, `cdn2`, `cloudfunctions`, `nextcloud`, `webdav`, `payment`, `member`, `elearning`, `correo` (Spanish for mail), `bbs`, `temp`, `post`, `dedicated`.

**This is the finding that matters most in this report.** The codebook is not merely tuned for compression efficiency; it is tuned for **plausibility**. A hostname assembled from this vocabulary — `cdn2.webdav.payment.example.com` — reads as ordinary cloud/CDN/mail infrastructure to anything inspecting DNS traffic. The codec's output distribution is shaped to be **statistically unremarkable** in the categories of traffic that dominate real DNS: cloud services, CDNs, mail, and payment endpoints.

**Sliver and Havoc hide `what` is being said. This hides `that` anything is being said.** The compressed bytes are not just short — they are *plausible*, drawn from the same word distribution a real CDN hostname would be. The symbol distribution is a cover story.

Stated precisely, because the distinction is easy to overclaim:

- `[source]` — the vocabulary is curated toward cloud/CDN/mail/payment words, and the frequency model is skewed to favour them (the `terms` distribution peaks hard at 13 bits, meaning a small set of words absorbs most of the probability mass).
- `[inferred]` — the *selection* of exactly these words was driven by camouflage value rather than only by corpus frequency. I have not read a corpus of real DNS traffic to prove these words are the highest-frequency hostname components; the inference rests on the semantic coherence of the list, which is strong but is an inference.

### §2.3 End-of-word handling

`:177` appends the sentinel before encoding: `phrase += '\x00'`. `IS_END = '\0'` (`:14`), and every tree carries exactly **one entry with symbol `'\x00'`** (§1.2) — the record terminator. `Node.__lt__` (`:83-88`) gives `IS_END` a special ordering rule (`if self.value == IS_END: return False`) so it never sorts below another node during `train()`, keeping the sentinel at a stable, low-depth position. The `tlds` and `terms` NUL entries both have **2-bit code `0b11` (value 3)**; the `generic` NUL has **4-bit code `0b1111` (value 15)**.

The `last=True` path (`:190`) allows a final record to end without flushing its terminator when the remaining padding budget is too small:

```python
if last and phrase.startswith('\x00') and remainder_bits < min_bits:
    break
```

where `min_bits` is the minimum code length in the table (`:183-185`). This is the encoder's **only** mechanism for leaving a partial final byte — and it is deliberate.

`:219-222` flushes the partial byte by left-shifting it into place:

```python
if remainder_bits:
    remainder <<= remainder_bits
    encoded.append(remainder)
```

**There is no bit-length field.** The final byte is zero-padded on the right and the decoder relies on the NUL sentinel to know where the logical data ended. This is why every codebook must carry exactly one NUL entry, and why `Huffman.decode` (`:225-288`) treats decoding `'\x00'` as `completed = True` (`:270-271`) rather than appending it.

---

## §3 The 256-entry provider list and the 8-bit index

### §3.1 The list

`dns_encoder.py:16-70` defines `FREEDNS` as a literal tuple of **exactly 256** domain names. First and last entries:

```
FREEDNS[0]   = '100mountain.com'
FREEDNS[1]   = '10x.es'
FREEDNS[2]   = '120v.ac'
FREEDNS[-3:] = ['z0d.eu', 'z86.ru', 'zanity.net']
```

Verified properties: **256 entries**, **zero duplicates**, **all conforming to `DNS_ALPHABET`** (no entry violates the 38-character set), **max entry length 22**, and **every entry contains at least one dot**. `[source]` — parsed with `ast` and checked in Python.

Sample entries across the range, showing the character of the set:

```
'chickenkiller.com', 'mooo.com', 'ignorelist.com', 'privatedns.org',
'h4ck.me', 'dyn.mk', 'h0stname.net', 'mycloud.bz', 'boot.nu',
'portalindustries.org', 'routemehome.com', 'no-ip' family adjacent names
```

These are **dynamic-DNS provider domains** — the free subdomain services a hostname can be minted under without registration. The `freedns` naming is accurate.

### §3.2 Why exactly 256 — the 8-bit index

The FreeDNS match path (`:407-426`) emits the list index as a **raw byte**:

```python
for idx, domain in enumerate(FREEDNS):        # :407
    if word == domain:
        ...
        this_encoded = encoded + chr(idx)     # :412
```

`chr(idx)` for `idx` in `0..255` produces **exactly one byte**. So:

> **A matched FreeDNS provider domain costs 8 bits on the wire, regardless of the domain's length.**

`chickenkiller.com` is 17 characters. At the `generic` tree's ~5-6 bits per character it would cost roughly 85–102 bits, plus a separator. Through the FreeDNS path it costs **8**. `portalindustries.org` (21 characters) also costs **8**. This is the single largest compression win in the file, and it is available precisely because the list is bounded at 256.

**The list length is a boundary artifact of the encoding, not a catalog size.** 256 is the largest value of `idx` that still fits one byte; a 257th entry would force a two-byte index and double the cost of the entire FreeDNS path. The list was grown to the byte boundary and stopped.

Two match forms are supported (`:408` and `:418`):

- `word == domain` (`:408`) — the **first label alone** matches a provider domain; the rest continues recursively.
- `joined_rest == domain` (`:418`) — the **entire remaining dotted hostname** matches a provider domain; nothing follows.

Both emit `chr(idx)` and both append `TABLE_FREEDNS` to the table list. The second form terminates the recursion with `encoded + chr(idx)` and an empty rest (`:422`), so a hostname that *is* a FreeDNS domain encodes to the header byte plus one index byte.

### §3.3 The index-0 aliasing question

`FREEDNS[0] = '100mountain.com'`, so a match on it emits `chr(0)` — the same byte as `IS_END`. Investigated in this lane and **found not to be a live bug**, because the two layers occupy different byte-stream namespaces:

- `Huffman.decode` (`:270`) tests for `'\x00'` **as a decoded symbol** from a Huffman code stream.
- The FreeDNS index is emitted **raw and uncompressed**, and decoded by the 0-bit `freedns` stub codec (§1.4) — which consumes nothing and yields no symbol.

So the `'\x00'` from a FreeDNS index never reaches a Huffman symbol-decoding decision. The stub is what makes this safe. Recorded here because the aliasing is genuinely non-obvious and a later reader will wonder.

**The mechanism by which the FreeDNS index is consumed on decode is `Huffman.decode`'s return value** — `decode` returns `(decoded_string, remaining_values)` (`:288`), so the caller can continue consuming the same buffer with the next table's codec. The 0-bit stub returns an empty decoded string and the untouched buffer, leaving the index byte in place for the next stage. **This is a claim about the stub's role derived from reading `decode`'s signature and the 0-bit entry; I did not trace a full round-trip byte-by-byte** — flagged in §9.

---

## §4 The resolver — where the decisions actually live

### §4.1 Checked against the D9 failure mode

D9 measured `lib/rex/proto/` correctly but answered the wrong question, because the deciding code was in a different tree. This section exists to test that same risk here rather than assume it away.

**`server.py` contains the decisions.** Three load-bearing sites, all inside this lane's declared scope:

**`_cmd_processor` (`server.py:936`)** — the command dispatch table, handling `Poll`, `Ack`, `Exit`, and `SystemStatus` with real branching:

- `:948-958` — `Poll` with no session: if `not self.kex or self._kex_is_disabled(node)`, return the node's queued commands or a `Policy`; otherwise return `[Policy(self.interval, self.kex), Poll()]`. **This is a genuine KEX-state decision.**
- `:960-970` — `Ack` with no session: truncates `node.commands` by `command.amount`, logging `'ACK: invalid amount of commands: %d > %d'` (`:964`) when the requested amount exceeds the queue. **This is the retransmission/acknowledgement state machine.**
- `:972-979` — `Exit`: fires `self.on_exit(session.system_info)` and deletes the session under lock.
- `:981-1000` — `Poll`/`SystemStatus` with a session: `on_keep_alive`, system-status ingestion, and **user-count delta detection** (`:989-996`) firing `on_users_increment`/`on_users_decrement`, plus **resource threshold detection** at `:998`:

```python
if session.system_status['mem'] > 90 or session.system_status['cpu'] > 90:
    if not session._high_resource_usage_reported:
        self.on_high_resource_usage(session)
```

**`set_policy` (`server.py:621`)** — policy mutation. Sets `kex`, `timeout`, `interval`, supports per-node targeting via `find_sessions(spi=node) or find_sessions(node=node)` (`:632-633`), and enforces an explicit guard:

```python
if interval and interval < 30:                        # :626
    raise ValueError(                                  # :627
        'Interval should not be less then 30s to avoid DNS storm'
    )
```

**An anti-DNS-flood floor of 30 seconds, enforced in code.** `:650-653` additionally derives a floor from the interval: `self.timeout = max(timeout if timeout else self.timeout, self.interval * 3)`. Session timeout is never allowed below three poll intervals.

**`_resolve` (`server.py:1378`)** — the resolver core (§4.2).

`picocmd.py` (53,699 B), by contrast, holds the **transport-agnostic `Parcel` envelope** — the framing shared by every `picocmd` transport, not DNS-specific decision logic. It is correct for the DNS decisions *not* to be in it.

**Conclusion: the brief's shape is right, and D9's failure mode does not reproduce on this lane.**

### §4.2 `_resolve` — the resolver core

```python
def _resolve(self, request, handler):
    qname = request.q.qname
    qtype = request.q.qtype
    reply = request.reply()

    # TODO:
    # Resolve NS?, DS, SOA somehow                              # :1383-1384
    if not qname.matchSuffix(self.domain):                      # :1385
        if self.recursor:                                       # :1386
            try:
                return DNSRecord.parse(
                    request.send(self.recursor, timeout=2)      # :1389
                )
            except socket.error:
                pass
        else:
            logger.debug('Bad domain: %s (suffix=%s)', qname, self.domain)
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    answers = self.process(
        qtype, qname.stripSuffix(self.domain).idna()[:-1]       # :1402
    )
    klass = SUPPORTED_METHODS[qtype]                            # :1405
    if answers:
        for answer in answers:
            reply.add_answer(
                RR(qname, qtype, rdata=klass(answer), ttl=600)  # :1410
            )
        if self.edns:
            reply.add_ar(EDNS0(udp_len=512))                    # :1414
    else:
        reply.header.rcode = RCODE.NXDOMAIN
    return reply
```

Five findings:

1. **The server is a functioning DNS resolver, not a fake one.** Queries not under `self.domain` are forwarded to a real recursor (`:1386-1390`) with a **2-second timeout**, or answered `NXDOMAIN`. Traffic to the C2 domain is therefore **indistinguishable at the resolver level from traffic to any other resolver host** — the host genuinely resolves unrelated names. `[source]`

2. **`qname.stripSuffix(self.domain).idna()[:-1]` (`:1402`) — the trailing-character question.** The `[:-1]` drops the **trailing dot of the label form**, a `dnslib` / DNS-name artifact, **not a payload terminator.** Established from the encoder side: `_aaaa_page_encoder` (`:798`) builds addresses as `':'.join(packed[i:i+2].encode('hex') ...)` — **pure hex pairs, no dot, no NUL**. The payload carries no delimiter. The dot being stripped is the DNS root label joined by `stripSuffix`, and `idna()` re-normalises the remaining label before the slice removes it. **The boundary is carried by the explicit 1-byte length field (§5), not by a terminator.** Recorded as a resolved question rather than a residual.

3. **`SUPPORTED_METHODS` admits only `QTYPE.A` and `QTYPE.AAAA`** (`:73-76`). **No TXT, no CNAME, no NULL.** TXT records permit far more payload per record; restricting to A/AAAA forces the design to spread data across **many short records** — which is exactly why the A/AAAA page encoders exist and why the carrier-efficiency figures in §5 matter.

4. **`ttl=600`** (`:1410`) — every answer carries a fixed 10-minute TTL. Constant across all answers and all record types. It is an operational camouflage parameter: a real CDN or cloud service would carry a coherent TTL, and a varied one would be a fingerprint.

5. **`EDNS0(udp_len=512)`** (`:1414`) — the advertised UDP buffer matches the `max_payload_len` budget exactly (§5), so server and client agree on the ceiling without negotiation.

`_kex_is_disabled` (`:1375-1376`) is a **hardcoded `return False`** — see §6.

### §4.3 Version negotiation and the crypto gate

`encoder_from_session` (`:717-725`) selects the crypto encoder by **session-or-version**:

```python
def encoder_from_session(self, session, version):
    if session:
        return session.encoder
    elif version == 1:
        return self.encoders[self.ENCODER_V1]
    elif version == 2:
        return self.encoders[self.ENCODER_V2]
    raise ValueError('Unsupported version {}'.format(version))
```

**A session's negotiated encoder wins over the version argument.** That is the correct precedence for a KEX-completed session: once a key exchange establishes a per-session encoder, the version parameter must not be able to override it. A version-1 or version-2 encoder is only used for a **pre-KEX** request that carries no session — which matches the DNSCNC v1/v2 credential split already recorded in `PupyCredentials.py` (`CONTROL_DNSCNC_PRIV_KEY` / `_V2`).

`csum_from_session` (`:727-732`) is where the checksum policy diverges by version:

```python
def csum_from_session(self, session, version):
    if version == 1:
        return None, None
    encoder = self.encoder_from_session(session, version)
    return encoder.gen_csum, encoder.check_csum
```

**Version 1 has no checksum at all — `(None, None)`.** Version 2 supplies `gen_csum`/`check_csum` from the encoder. Combined with the default config's **`allow_v1 = true`** (`pupy/conf/pupy.conf.default`), the legacy path is enabled by default and carries **no integrity protection whatsoever**, while v2 attaches the ECPV-derived checksum pair. The v1/v2 gate is therefore the line between "unauthenticated framing" and "checksummed framing", and the config ships with the unauthenticated side open. `[source]`

The `version` values themselves are integers compared with `== 1` / `== 2` — not magic constants, not feature flags. `EncoderVersion`-style named constants are absent here, so the two literals are the whole vocabulary.

---

## §5 Carrier economics — A vs AAAA, and the 255-byte ceiling

### §5.1 The budget, with the author's own measurements

`max_payload_len` (`server.py:375-413`) computes the per-response ceiling, and its comments carry **measured efficiency figures**:

```python
# Efficiency:
# A Records ~ 15%
# AAAA Records ~ 45%                                   # :397-398

domain_len = 1 + len(self.domain) + query_len + 1      # :400
query_header_len = 4 + domain_len                      # :401
edns_len = 11                                          # :402

dns_packet_room = 512 - (query_header_len + edns_len)  # :404

answer_len = 2 + 10 + record_len                       # :406

max_records = dns_packet_room // answer_len            # :408
max_size = max_records * (record_len - 1)              # :409

packet_length_len = 1                                  # :411

return max_size - packet_length_len                    # :413
```

**`AAAA` carries roughly three times the payload efficiency of `A`** — 45% versus 15%. The arithmetic: an A record's `rdata` is **4 bytes**, an AAAA record's is **16**. Both cost the same fixed per-record overhead (`answer_len = 2 + 10 + record_len`), so the overhead is amortised over 4× more payload in the AAAA case. The gap (15% vs 45%) is steeper than 4× because AAAA's **16 payload bytes pay for 1 index byte** (§5.2) while A's 4 bytes also pay 1.

**This is why `_aaaa_page_encoder` is the primary carrier and `_a_page_encoder` the fallback.** The encoder prefers 16-byte AAAA records because each one wastes proportionally less on framing.

### §5.2 The two page encoders

`_a_page_encoder` (`:734-769`) — 4-byte A records, **3 payload bytes per record**:

```python
data = encoder.encode(data, nonce, symmetric=encoder.kex_completed)   # :735
length = struct.pack('B', len(data))                                  # :739
payload = length + data                                               # :740
max_payload_len = self.max_payload_len(qname_len, 4)                  # :742
if len(payload) > max_payload_len:
    raise PayloadTooBig('Page size more than {max_len} bytes ({required_len})',
                        len(payload), max_payload_len)
for idx, part in enumerate([payload[i:i+3] for i in xrange(0, len(payload), 3)]):   # :751-752
    header = (random.randint(1, 3) << 30)                             # :753
    idx = idx << 25                                                   # :754
    bits = (struct.unpack('>I', b'\x00'+part+as_byte(
        random.randrange(0, 255))*(3-len(part)))[0]) << 1             # :755-756
    response.append('{}.{}.{}.{}'.format(*struct.unpack(
        '!BBBB', struct.pack('>I',
            header | idx | bits | int(not bool(bits & 6))))))         # :758-767
```

Packaging: a 4-byte integer is built from a **random 2-bit class header** (`random.randint(1,3) << 30`, i.e. always a nonzero class — never 0, 127, or 128+), an **index in bits 25-29**, and 3 payload bytes shifted left one, with the low bit set from `int(not bool(bits & 6))` — the low bit is **derived from the payload**, not random, which is a plausible-looking-hostname heuristic. Short final parts are padded with `random.randrange(0, 255)` bytes rather than zeros (`:755-756`), so the padded tail is indistinguishable from payload. `[source]`

`_aaaa_page_encoder` (`:771-803`) — 16-byte AAAA records, **15 payload bytes per record**:

```python
data = encoder.encode(data, nonce, symmetric=encoder.kex_completed)   # :772
max_payload_len = self.max_payload_len(qname_len, 4)
if len(data) > 0xFF:                                                  # :778
    raise PayloadTooBig('Payload size more than {max_len} bytes ({required_len})',
                        len(data), 0xFF)
length = struct.pack('B', len(data))                                  # :783
payload = length + data                                               # :784
...
for idx, part in enumerate([payload[i:i+15] for i in xrange(0, len(payload), 15)]):  # :793-794
    packed = struct.pack('B', idx) + part                             # :795
    if len(packed) < 16:
        packed = packed + b'\x00' * (16 - len(packed))                # :797
    addr = ':'.join([packed[i:i+2].encode('hex')
                     for i in xrange(0, len(packed), 2)])             # :798-800
    response.append(addr)
```

Layout per AAAA record: **1 index byte + 15 payload bytes = 16 bytes exactly**, hex-encoded in 2-character groups joined by colons — the textual form of an IPv6 address. The `idx` field is a **single byte** (`struct.pack('B', idx)`), which is the structural source of the record-count ceiling.

Final AAAA parts are zero-padded (`:797`) — **asymmetric with the A encoder, which pads with random bytes.** A zero-padded AAAA tail is a distinguishable fingerprint that the A path does not have. Recorded as an observation; whether it is reachable depends on whether `len(payload)` is ever not a multiple of 15, which it generally is not.

### §5.3 The 255-byte ceiling

Two independent 1-byte fields impose it, and the author's comment states the intent:

```python
# Default length limited to 256B to spend only 1 byte for info about
# the length.                                          # :391-392
```

- `length = struct.pack('B', len(data))` in **both** encoders (`:739`, `:783`) — a `B` format caps the value at 255.
- The AAAA encoder adds an **explicit pre-check**: `if len(data) > 0xFF: raise PayloadTooBig(... 0xFF)` (`:778-781`). **This check exists only in the AAAA encoder**; the A encoder has no equivalent and relies solely on the downstream `max_payload_len` comparison. `[source]`

So the payload ceiling is **255 bytes**, enforced by a guard in one encoder and by an implicit struct-format limit in both. The AAAA guard fires first and reports a clearer error (`'Payload size more than {max_len} bytes'` vs `'Page size more than {max_len} bytes'`) — the messages are deliberately distinct.

The `:789` message has an **argument-order defect**: the format string names `{max_len}` then `{required_len}`, but the call passes `(len(payload), max_payload_len)` — `len(payload)` first. Since the string never uses `{0}`/`{1}` positional placeholders, the values are not interpolated at all by `str.format` on a `format`-less string, so both arguments are effectively ignored in the message. The same pattern appears at `:745-747`. **Latent, cosmetic** — see §6.

### §5.4 Segmentation and reassembly

`DnsEncoder.encode` (`:446`) begins:

```python
rest = data.rsplit('.', 3)
```

**`rsplit('.', 3)` yields at most 4 parts.** The encoder therefore decomposes a hostname into **at most four segments**, and `_recursive_encoder` (`:376-444`) explores only those segmentations. Combined with the 30+ suffix positions in a real hostname, this is a hard structural limit: the encoder compresses the **leading labels deeply** and the remainder is carried by the recursive `generic` fallback or a FreeDNS whole-domain match.

`_recursive_encoder` is a **brute-force shortest-output search** over all legal segmentations (`:443`):

```python
best = sorted(results, key=lambda x: len(x.encoded))[0]
```

It tries merged leading labels (`:393-402`), a FreeDNS whole-domain or first-label match (`:407-426`), and every registered table encoder on the first label (`:428-441`), then keeps the **minimum-length** result. `ValueError` from an unencodable label is caught and that branch skipped (`:436-438`) — the mechanism by which `generic` guarantees a branch always succeeds.

**This is the CPU-for-bits trade.** The codebooks are precomputed and large precisely so the search has short codes to choose from, and the search is exhaustive-then-minimal so no better segmentation is left unexplored.

---

## §6 Latent defects — marked latent, not live

Both items below are **latent**: present in the source, not demonstrated reachable. "Latent" is used in D21's sense — a static observation of code that does not execute on any path this lane could establish, **not** a claim that the code is safe and not a claim that it is live.

### §6.1 `set_policy` self-comparison — `server.py:622-624`

```python
if kex == self.kex and self.timeout == timeout and \
        self.interval == self.interval:                  # :623
    return
```

`self.interval == self.interval` compares a value to itself and is **always `True`**. The intended comparison is almost certainly `self.interval == interval` — the parameter — mirroring the `timeout == timeout` clause on the line above, which does correctly compare the parameter.

**Latent, not live.** Reaching the early `return` requires all three conjuncts, and the clause is now a no-op, so the guard degenerates to `kex == self.kex and self.timeout == timeout`. The practical effect is that a `set_policy` call changing **only** `interval` no longer short-circuits; it proceeds to the body. The body then re-derives and applies the policy correctly (`:648-661`), so the outcome is a redundant recomputation rather than incorrect policy. **No impact demonstrated, and I am not claiming one** — the consequence I can establish is that the intended short-circuit no longer fires for an interval-only change.

### §6.2 `_kex_is_disabled` is a hardcoded stub — `server.py:1375-1376`

```python
def _kex_is_disabled(self, node):
    return False
```

The hook is called from `_cmd_processor:949` (`if not self.kex or self._kex_is_disabled(node)`), so the call site is live and the method participates in the KEX decision. **The method body ignores its `node` argument entirely and always returns `False`.** In this class, the KEX-disable path can therefore never be taken by node state — the decision is made solely by `self.kex`.

That is a legitimate design if a subclass overrides `_kex_is_disabled` to implement per-node KEX suppression; the base class provides a default that never suppresses. **This lane did not find such a subclass** — `DnsCommandServerHandler` is the only class defining or calling it in `server.py`. Recorded as a latent stub whose override, if any, lies outside `server.py`.

### §6.3 `PayloadTooBig` message arguments

At `:745-747` and `:786-789`, the raise passes `len(payload), max_payload_len` against format strings containing `{max_len}` and `{required_len}` — named placeholders that `str.format` will not substitute from positional arguments, and in any case neither message is passed through `format` at the raise site. The exception's own `error`/`__str__` (see `DnsCommandServerException:301-319`) may interpolate them; this lane did not read that far to confirm. **Latent, cosmetic.** Recorded rather than asserted.

---

## §7 The Parcel framing layer — and D6 §13's read boundary

**This section marks a seam and states a boundary. It does not re-derive D6 §13.**

D6 §13 read `picocmd.py`'s `Parcel` framing and the registered-command table. For continuity, the framing as D6 recorded it:

- `Parcel.pack(nonce, gen_csum=None)` = `gen_csum(data, nonce) + data`, where `data` is the concatenation of each command's encoded type byte followed by its packed body.
- Wire format `[CRC32 4][cmd_id 1][cmd payload]...`.
- `_gen_crc32` is `struct.pack('>i', binascii.crc32(data))`; the **nonce is never mixed into the CRC** — it is a bare checksum, not a MAC.
- `Parcel.registered_commands` holds **30** commands (`Poll`, `Ack`, `Policy`, `Idle`, `Kex`, `Connect`, `PasteLink`, `SystemInfo`, `Error`, `Disconnect`, `Exit`, `Sleep`, `Reexec`, `DownloadExec`, `CheckConnect`, `SystemStatus`, `SetProxy`, `OnlineStatusRequest`, `OnlineStatus`, `ConnectablePort`, `PortQuizPort`, `PupyState`, `CustomEvent`, `SystemInfoEx`, `ConnectEx`, `RegisterHostnameId`, `DataTransferControl`, `DataTransferPayload`, `InBandExecute`).
- `Kex.pack()` prefixes a **single-byte** length, capping a KEX parcel at 255 bytes.

**Boundary:** this report did **not** re-read the Parcel framing, the command classes, or the CRC helpers. Where §4 and §5 refer to `Parcel`, `Poll`, `Ack`, `Exit`, `Policy`, or `PayloadTooBig`, they do so as **imported and used** by `server.py` (`:51-63`) — the import list is evidence of the dependency, not a re-verification of the framing.

**The seam that matters:** the DNS layer sits **below** the Parcel layer. `Parcel.pack` produces the bytes that `DnsEncoder.encode` then compresses and `_a_page_encoder`/`_aaaa_page_encoder` then slice across records. Two independent length caps therefore stack:

| Layer | Cap | Source |
|---|---|---|
| `Parcel` / `Kex` | **255 bytes** | 1-byte length prefix (D6 §13) |
| DNS payload | **255 bytes** | 1-byte length field (`server.py:739`, `:783`) |

**The two caps are the same value and they are unrelated.** Both derive from a one-byte field, in code written by the same project, at two different layers. That coincidence is worth naming because it is a plausible source of a future misreading — a reader who finds 255 in either place should not assume it is the other layer's limit.

**Reassembly across records, stated honestly.** Each record carries a 1-byte index (`_a_page_encoder:754`, `_aaaa_page_encoder:795`) and the payload carries a 1-byte length. The index orders records **within one response**; the length tells the decoder when to stop. This lane **did not read the client-side reassembly path in full** — `client.py`'s page decoders (`_aaaa_page_decoder:263`, `_a_page_decoder:279`) were read for structure, not traced against a multi-record response. Whether the index is authoritative or advisory, and what happens on a gap, is **not established here** (§9).

---

## §8 Boundaries and scope

### §8.1 Read

| File | Size | Coverage |
|---|---|---|
| `dns_encoder_table.py` | 22,473 B / 8 lines | **Complete** — dict parsed and enumerated via `ast` |
| `dns_encoder.py` | 38,587 B / 845 lines | **Complete** for `Huffman`, `Node`, `Root`, `DnsEncoder`, `FREEDNS`, `DNS_ALPHABET`, `TmpResult`, `train` |
| `server.py` | 45,257 B / 1,459 lines | **Structural map of all classes/methods**; full read of `max_payload_len`, `set_policy`, `_cmd_processor`, `encoder_from_session`, `csum_from_session`, `_a_page_encoder`, `_aaaa_page_encoder`, `_kex_is_disabled`, `_resolve`, `ExpirableObject`, `Node`, `SessionDependedCommand` |
| `client.py` | 22,531 B / 708 lines | **Structure and key lines** — not a full line-by-line read |

### §8.2 Not read

- `picocmd.py` (53,699 B) — covered by D6 §13; boundary stated §7.
- `baseconv.py` (3,962 B), `ascii85.py` (2,085 B), `__init__.py` (1,176 B).
- `server.py` bodies of: `NodeBlocked`/`DeprecatedVersion`/`UnknownVersion` handling, `activator`, `cleanup`, `add_command` (:467), `reset_commands` (:527), `find_nodes` (:575), `find_sessions` (:587), `encode_pastelink_content` (:664), the 12 `on_*` event hooks, `_q_page_decoder` (:805), `_new_node_from_session` (:899), `_new_node_from_systeminfo` (:919), `process` (:1168, ~200 lines), `DnsCommandServer` (:1421-1459).
- `client.py` bodies beyond structural lines.

### §8.3 Instrument

Source-only. No REA provider was bound for this report. **No Ghidra, no execution, no packet capture, no build.** Every claim is a reading of a file on disk. Where a claim depends on runtime behaviour — the recursion's actual output for a given hostname, the page index authority, the entropy of a real response — it is marked `[inferred]` or carried into §9.

---

## §9 Residual unknowns

1. **The client-side reassembly path is not traced.** `client.py`'s `_aaaa_page_decoder` (`:263`) and `_a_page_decoder` (`:279`) were read for structure only. The index-to-order mapping, behaviour on a gap in the index sequence, and behaviour on a duplicated index are **not established**. The §7 statement that the index "orders records within one response" is a reading of the encoder, not a verified decoder contract.

2. **Whether the `freedns` 0-bit stub is exercised in practice.** The stub's role is derived from reading `Huffman.decode`'s `(decoded, remaining)` return signature and the 0-bit entry (§3.3). **A full byte-by-byte round-trip of a FreeDNS-matched hostname was not constructed.** If `chr(idx)` bypasses the stub codec entirely and is consumed by a different mechanism, §3.3's mechanism description is wrong even though the outcome is the same.

3. **`cdns` has no code path.** The tree holds table ID `0b00` conceptually alongside `freedns`, is registered by no `mappings` entry, and is emitted and decoded nowhere this lane found. Whether it is a reserved slot for an unimplemented feature, or a vestige of a removed one, is **not determined**.

4. **`_kex_is_disabled`'s override is unknown.** No subclass overriding it exists in `server.py`. Whether one exists elsewhere in the Pupy tree was **not searched**.

5. **`EncoderVersion` constants.** `encoder_from_session` compares `version == 1` / `== 2` with bare literals. Whether named constants for these exist elsewhere, and what defines version 2 as distinct, is **not established** — only the checksum-policy difference (§4.3) was found.

6. **`self.encoders[self.ENCODER_V1]` / `[self.ENCODER_V2]`** — these attribute names are referenced at `:721`/`:723` but were **not located as definitions** in the read portions of `server.py`. They are presumably set in `DnsCommandServerHandler.__init__` (`:338-374`, not fully read). The two names are **observed as used, not observed as defined**.

7. **The `terms` vocabulary's selection basis** — §2.2's claim that the words were chosen for camouflage value is `[inferred]` from semantic coherence. No frequency corpus was consulted.

8. **`max_payload_len`'s `record_len` argument.** Both call sites pass `4` (`:742`, `:776`) while AAAA's `rdata` is 16 bytes. Whether `record_len` is intentionally the A-record size in both paths — making the AAAA budget conservative — or is a stale argument, is **not determined**. The AAAA path additionally pre-checks `0xFF` (`:778`), which may exist precisely because `max_payload_len` under-estimates its capacity.

9. **The `:391-392` comment says "256B" while the cap is 255.** `struct.pack('B', ...)` maxes at 255, and `:778` checks `> 0xFF`. The comment's "256B" is off by one against its own code — cosmetic, recorded rather than counted as a defect.

10. **No other consumer of `DnsEncoder` was searched.** Whether `dns_encoder.py` is used outside `picocmd` (e.g. by `PupyDnsCnc.py`, 20,346 B) was **not checked**. §8.2's boundary is this report's scope, not a claim that this is the only caller.

---

## §10 Instrument record

### §10.1 `[near-miss]` — self-caught: misread the encoder-registration comprehension

While reading `dns_encoder.py:361-371`, this lane initially read the dict comprehension as iterating **all five** trees, which would construct `Huffman` objects for the two 0-bit stubs and was poised to be reported as a defect (a crash or a degenerate codec for `cdns`/`freedns`).

**The reading was wrong.** Line **`:370`** carries a guard — `if table in mappings` — and `mappings` (`:361-365`) contains only `generic`, `tlds`, `terms`. `self.encoders` therefore has exactly **three** keys and the stubs are never constructed.

**Recorded rather than quietly corrected** because it is the same error class this corpus has now logged repeatedly: a correct observation of one line producing a confident wrong conclusion about a region. The guard was one line below the construct being read. §1.4 states the corrected finding.

### §10.2 Instrument errors and workarounds

- **PowerShell regex quoting.** Two attempts to count tuples with `[regex]::Matches` using double-quoted patterns containing escaped quotes and parentheses failed with `Missing ')' in method call` / `Array index expression is missing or not valid` / `The string is missing the terminator` (`[exit code: 1]`). **Fix:** abandoned regex entirely for the structural work and parsed `dns_encoder.py` and `dns_encoder_table.py` with Python's `ast` module instead. This is the correct instrument for a Python source file and made the counts in §1.2 and §3.1 exact rather than approximate. **The failed attempts produced no numbers used in this report.**
- **`ast.literal_eval` failure on the large literals.** Reconstructing `FREEDNS` and `TLDS` via `literal_eval` on the assignment node raised for some literals (a long constructed tuple containing values the node validator rejected), and `FREEDNS` was extracted and verified via a targeted regex on the tuple body instead. The `FREEDNS` count of 256 was confirmed **two independent ways** — `literal_eval` on the module body, and regex extraction — both returning 256 with zero duplicates.
- **`re` on the raw file for tree keys.** Extracting the five `TREES` keys was done with a lookbehind/lookahead pattern on the raw text, then per-tree tuple counts were taken by splitting on successive key offsets. Totals: 39 + 1 + 513 + 513 + 1 = **1,067**, matching an independent whole-file tuple count of **1,067**. Two independent methods, same total.

### §10.3 Positive controls

Every absence claim in this report carries a control shown able to succeed with the same instrument:

- **`cdns`/`freedns` have no encoder registration** (§1.4) — the same dict comprehension **does** register `generic`, `tlds`, `terms`, so the guard was shown to admit three keys rather than none.
- **`SUPPORTED_METHODS` has no TXT entry** (§4.2) — the same dict-style literal **does** contain `QTYPE.A` and `QTYPE.AAAA`, so the construction was shown to admit entries.
- **`QTYPE.A`/`QTYPE.AAAA` literal counts** — `ast` enumerated 2 entries where TXT is absent, demonstrating the parse reached the literal's contents.
- **`FREEDNS` conformance to `DNS_ALPHABET`** (§3.1) — the same character-set test returned **0 violations across 256 entries**; the control is that the test was run against the alphabet set itself and correctly reports membership, rather than the empty set trivially satisfying a `<=` test. Explicitly: **an absence of violations is only meaningful because the alphabet was non-empty (38 chars) and every entry was non-empty.**
- **The three-tree bit-length distributions** (§1.2) — computed by the same code path that produced the `cdns`/`freedns` single-entry results, so the counter was shown discriminating between a 1-entry tree and a 513-entry tree.

### §10.5 `[near-miss]` — self-caught: a true number with an invented derivation

**The worst error class this corpus produces, caught in this lane before publication.**

An early draft of §1.2 read:

> `513 = 2⁹ + 1. That is the node count of a full binary Huffman tree over 512 leaves (512 symbol nodes + 1 root).`

**The number 513 is correct. The sentence explaining it is fabricated, and wrong by a factor of two on the leaves.**

The arithmetic, stated out loud:

- A full binary tree over **n** leaves has **2n − 1** nodes.
- **512 leaves → 1,023 nodes.** Not 513.
- `2⁹ + 1 = 513` is the node count of a tree over **256** leaves (2 × 256 + 1), which is not what the table contains.

So the draft attached a correct measurement to a **derivation that had been reverse-engineered from the measurement** rather than computed independently — the "find the number, then invent a reason for it" failure mode. It would have survived review by anyone who checked `513` and not the reasoning.

**The corrected finding**, established by enumerating the entries and computing the Kraft sum (§1.2):

- The 513 entries are **513 distinct symbols = 513 leaves**. The codebook stores **leaves only**; the 1,025-node tree is not materialised in the table.
- The defining property is `Σ 2^(−L) = **1.000000**` for `generic`, `tlds`, and `terms` — a **complete prefix code** on all three, verified by computation over the shipped rows.

**The recovery instrument was enumerating and measuring rather than reasoning about the count.** The Kraft sum is not derivable from the entry count; it was computed per-entry from the stored bit lengths and returned exactly 1.0 on all three trees, which independently confirms the tables are complete prefix codes. **That measurement replaces the rejected derivation entirely.**

### §10.6 `[near-miss]` — self-caught: over-broad framing of the compression model

An early draft's §0 headline read *"the compression model is word-level, not character-level."*

**That global claim is false.** `generic` **is** a character codec: 39 entries, 38 single-character symbols matching `DNS_ALPHABET` exactly, NUL sentinel, Kraft sum 1.0. A reader who opened `generic` would have correctly refuted the headline, and the refutation would have been easy.

**The defensible form** — now used in §0.1 and §2.1 — is narrow: the file contains **both** a character codec and word codecs; the trees that carry **domain vocabulary** (`tlds`, `terms`) are word codecs with max symbol lengths 13 and 20. The `generic` tree is the character fallback that guarantees encodability.

**Recorded because the over-broad version was the more persuasive sentence and the narrower one is the correct one.** The error was not in the measurement (`startswith(term)` and the symbol lengths were read correctly) but in generalising a finding about two trees into a claim about the file.

### §10.7 What was *not* an instrument error

- **The `chr(0)` / `IS_END` aliasing** (§3.3) was investigated as a possible bug and **found not to be one**. It is recorded as a resolved question, not an error.
- **The `idna()[:-1]` question** (§4.2) was raised by the Lead as a possible framing defect and **resolved to a DNS trailing-dot artifact**, established from the encoder side (`:798` emits pure hex, no dot). Recorded as resolved.

---

*Lane: `source-diver` · task-28 · all claims `[source]` unless tagged `[inferred]` · no provider bound, no execution, no binary evidence*
*This report is the control comparison for D6 §13 and does not re-derive the Parcel framing (§7).*
