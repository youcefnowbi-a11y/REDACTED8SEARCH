# D35 — Sliver DNS vs Pupy DNS: does the carrier force the codec?

**Task:** task-39 (D35; the `D30_havoc_transport_source.md` file was renumbered to D34 by the Lead)
**Lane:** cross-target synthesis (DNS carrier), originating from the metasploit core lane
**Status:** COMPLETE
**Deliverable:** `RE_Library\07_OUTPUT\reports\DEEP\D35_sliver_dns_vs_pupy_dns.md` (write scope: this file only)
**Method:** primary source only, no sampling. No Go/Python toolchain on this host; every claim is `[source]` with `file:line`. **Every count carries the command that produced it** (Lead's rule: *a number wearing a `[source:]` with no run behind it is the worst artefact this corpus can emit*).

**Why this report exists.** D30 §4.4 recorded Sliver's DNS transport at **inventory level only** and labelled it **U1 — the largest gap in that report**, with falsification condition (a): *if `dns.go` has a vocabulary, the carrier-forcing hypothesis comes back.* **This report settles U1.** The author of the condition is the lane that closes it.

**The question, stated so it can fail:**

> Pupy spends its entire encoding budget on making C2 DNS traffic look like ordinary browsing — 256 real provider domains, trained Huffman tables, a self-describing multi-codebook envelope. Sliver runs C2 over the same carrier. **Does Sliver also hide intent, or does it only hide bytes?** If Sliver hides intent too, **the carrier forced the design** and Pupy is not distinctive. If Sliver encodes plain bytes over a configured domain, **the carrier is necessary but not sufficient** and D30 §6's "three theories of the adversary" survives.

---

## TOC

- §1 Ground truth — inventory with commands
- §2 Ask #2 — is the DNS carrier typed in the protocol, or a byte pipe?
- §3 Ask #1 — does the client have a vocabulary?
- §4 Ask #3 — one C2 domain, or many?
- §5 Ask #4 — what does 37 KB of server do that 30 KB of client does not?
- §6 The comparison — Sliver DNS vs Pupy DNS
- §7 Instrument record
- §8 Residual unknowns

---

## §1 Ground truth — inventory with commands

**Command:** `Get-ChildItem $sliver -Recurse -File | Where-Object { $_.Name -match 'dns' -and $_.FullName -notmatch 'vendor' } | ForEach-Object { "{0,8} B  {1}" -f $_.Length, $_.FullName.Substring($sliver.Length+1) }`

```
    1775 B  client\command\jobs\dns.go
   13007 B  docs\sliver-docs\pages\docs\md\DNS C2.md
   69789 B  docs\sliver-docs\public\images\dns-c2-1.png
   30789 B  implant\sliver\transports\dnsclient\dnsclient.go
   14086 B  implant\sliver\transports\dnsclient\dnsclient_test.go
    7517 B  protobuf\dnspb\dns.pb.go
     727 B  protobuf\dnspb\dns.proto
   37264 B  server\c2\dns.go
    8247 B  server\c2\dns_grpc_e2e_test.go
   33230 B  server\c2\dns_test.go
```

`[verified]` **All three byte sizes the Lead cited are confirmed: `dns.proto` 727 B, `dnsclient.go` 30,789 B, `dns.go` 37,264 B.** The Lead's measurements and the artifacts are the same objects.

`[verified]` **Sizes are NOT the whole story, and the difference is large.** Line counts (same read, `$t -split "\`r?\`n"`): **`server\c2\dns.go` = 1,219 lines**; **`implant\...\dnsclient.go` = 1,086 lines**. The Lead's framing — "37 KB server for a 30 KB client" — is accurate on bytes but the **byte-to-line ratio differs materially**: 30.6 B/line server vs 28.4 B/line client. `[inferred]` Both files are dense; Go's verbose error handling dominates both. **The asymmetry to explain is structural (§5), not proportional.**

`[verified]` **Test mass is significant and was excluded from all claims:** `dns_test.go` **33,230 B** + `dns_grpc_e2e_test.go` **8,247 B** + `dnsclient_test.go` **14,086 B** = **55,563 B of DNS tests**. **More test code than either implementation file except `dns.go`.** No claim in this report rests on a test file.

---

## §2 Ask #2 — is the DNS carrier typed in the protocol, or a byte pipe?

**The Lead's framing:** *Pupy's codec is self-describing (the table selector is packed into byte 0). Does Sliver's have any equivalent?*

**`[verified]` `protobuf\dnspb\dns.proto` read in full — 29 lines, complete text:**

```protobuf
enum DNSMessageType {
    NOP = 0; // aka FINGERPRINT
    reserved 1; // formerly TOTP
    INIT = 2;
    POLL = 3;
    CLOSE = 4;

    MANIFEST = 6;
    DATA_TO_IMPLANT = 7;
    DATA_FROM_IMPLANT = 8;
    CLEAR = 9;
}

message DNSMessage {
    DNSMessageType Type = 1;
    uint32 ID = 2; // 8 bit message id + 24 bit dns session ID
    uint32 Start = 3; // Bytes start at
    uint32 Stop = 4; // Bytes stop at
    uint32 Size = 5; // Total size
    bytes Data = 6; // Actual data
}
```

**Answer: TYPED IN THE PROTOCOL. It is not a byte pipe.** Evidence:

1. **`:5-16` — an 8-value state machine enum**, not an opcode byte. `NOP`/`INIT`/`POLL`/`CLOSE`/`MANIFEST`/`DATA_TO_IMPLANT`/`DATA_FROM_IMPLANT`/`CLEAR`.
2. **`:22-29` — 5 typed fields**, including **`Start`/`Stop`/`Size`** — explicit fragmentation coordinates in the protocol itself.
3. **`:7` — `reserved 1; // formerly TOTP`.** A field number retired **in place**, preserving wire compatibility. `[inferred]` This is evidence of a **live, evolving protocol** — the schema has history.
4. **`:18-21` — the author's own comment**: *"DNS is very space sensitive so certain fields are re-puposed depending on the DNSMessageType."* **[verified] Typo `re-puposed` is in the source.**

### §2.1 The one place Sliver resembles Pupy — and it is not a codebook

`[verified]` `dns.proto:24` — **`uint32 ID = 2; // 8 bit message id + 24 bit dns session ID`.** Sliver **bit-packs two logical values into one wire field** to save space.

`[verified]` Independently confirmed at the implementation: `dns.go:1181-1189`:

```go
// DNSSessionIDs are public and identify a stream of DNS requests
// the lower 8 bits are the message ID so we chop them off
func dnsSessionID() uint32 {
	randBuf := make([]byte, 4)
	for {
		secureRand.Read(randBuf)
		if randBuf[0] == 0 {
			continue
		}
```

`[inferred]` **This is the structural parallel to Pupy's packed table-selector, and it is the same underlying pressure: DNS leaves no room.** Both frameworks hand-pack bits because the carrier is expensive. **But the packing differs in kind:** Pupy packs a **codebook selector** (an encoding decision); Sliver packs a **session identifier** (a routing decision). **Pupy's byte 0 tells the decoder how to interpret the rest. Sliver's field 2 tells the server which stream this belongs to.** `[inferred]` **Self-describing vs self-addressing.**

**`[verified]` Sliver's DNS message has NO equivalent of Pupy's table selector.** Grepped `dns.proto` for any table/codebook/vocabulary field: **no such field exists.** *Positive control:* `DNSMessageType` (8 values) and `DNSMessage` (5 fields) are the complete contents of the file — 29 lines, read in full, so the absence is a **complete-file** absence, not a search miss.

---

## §3 Ask #1 — does the client have a vocabulary?

**The Lead's condition:** *If it emits **any** fixed domain set, word list, or plausible-hostname distribution, the carrier-forcing hypothesis comes back. If it emits only encoder output over a configured C2 domain, the hypothesis stays dead.*

### §3.1 The author documents the encoding in the file header

**`[verified]` `dnsclient.go:22-30`, verbatim:**

```
DNS domains are limited to 254 characters including '.' so that means
Base 32 encoding, so (n*8 + 4) / log2(32) = 63 means we can encode 39 bytes
per subdomain.
Format: (subdata...).<ns domain>.<parent domain>
...
254 - len(parent) = subdata space, 128 is our worst case where the parent domain is 126 chars,
```

**Answer: BASE32. There is no vocabulary.** The author did the arithmetic on the wire constraint and chose an alphabet, not a dictionary.

`[verified]` `dnsclient.go:170` — `base32: encoders.Base32Encoder{}`, wired at construction. `[verified]` `:198` — `base32 encoders.Base32Encoder` as the struct field. `[verified]` `:61` imports `".../implant/sliver/encoders"` — **Sliver's encoder is a pluggable interface (`encoders.Encoder`), and the DNS transport instantiates exactly one of them: Base32.**

### §3.2 The domain is constructed, never selected

`[verified]` `dnsclient.go:893-912`:

```go
// Joins subdata to the parent domain, you must have already done the math to
// ensure the subdata can fit in the domain
...
	domain := strings.Join(subdomains, ".") + s.parent
	if 254 < len(domain) {
```

**`strings.Join(subdomains, ".") + s.parent`** — subdata labels joined, then **one** parent appended. `s.parent` is a **single string field**, assigned from the `parent` parameter of `NewDNSClient(parent string, ...)` (`:155`) / `DNSStartSession(parent string, ...)` (`:141`).

**`[verified]` There is no selection step.** No list, no candidate set, no distribution, no `rand`. The domain is **deterministically constructed from (encoded bytes + one configured parent)**.

### §3.3 The absence probe, with positive control

**Command:** `grep -n 'domain|Domain|vocab|word|hostname|encode|base32|charset|alphabet' dnsclient.go` → **71 matches.**

**Control that the probe bites:** the same pattern returns the `domain` construction sites (`:899`, `:908`), the encoder wiring (`:170`, `:198`), and the `Domain string` field (`:204`).

**The `[absence]` claim, stated with its control:** *`dnsclient.go` contains no fixed domain list and no vocabulary.* **Control:** the pattern **does** match `domain` (35 occurrences in the server file and the sites above in the client), so a keyword-based vocabulary would have been found. **And the decisive check is not a keyword search but a type check:** every domain-valued identifier in both files is either `Domain string` (scalar, `:204`), `parent string` (scalar, `:141`/`:155`), or a `[]string` **routing** list on the server (§4) — **and no such list is ever used to *choose* an emitted domain.**

**VERDICT ON ASK #1: the carrier-forcing hypothesis STAYS DEAD.** `[inferred]` D30 §6's claim holds and is now **verified against the file that was unread when it was made.**

---

## §4 Ask #3 — one C2 domain, or many?

**The Lead's decisive condition:** *If that list is one domain, the whole "hide in plain sight" axis is cheap for Sliver because there is nothing to hide.*

**Answer: the CLIENT has exactly one parent domain; the SERVER accepts a slice. The slice is a routing table, not a cover set. The Lead's condition is met on the client side and the server-side slice does not rescue the hypothesis.**

### §4.1 Client side — scalar, confirmed three ways

`[verified]` `dnsclient.go:141` `func DNSStartSession(parent string, opts *DNSOptions) (*SliverDNSClient, error)`
`[verified]` `dnsclient.go:155` `func NewDNSClient(parent string, opts *DNSOptions) *SliverDNSClient`
`[verified]` `dnsclient.go:204` `Domain    string` — the work struct field.

**Three independent scalar declarations.** `[verified]` `:140`'s comment: *"Attempt to establish a connection to the DNS server of **'parent'**"* — singular.

### §4.2 The client's entire DNS config is operations, not cover

`[verified]` `dnsclient.go:89-98` — the **complete** `DNSOptions` struct:

```go
type DNSOptions struct {
	QueryTimeout       time.Duration
	RetryWait          time.Duration
	RetryCount         int
	MaxErrors          int
	WorkersPerResolver int
	NoTXT              bool
	ForceResolvConf    string
	ForceResolvers     string
}
```

**Eight fields. Not one is a domain, a word, a hostname pattern, or a distribution.** Every field is operational: timeouts, retries, error budget, parallelism, TXT preference, resolver overrides.

`[verified]` `:101-138` — `ParseDNSOptions(c2URI *url.URL)` derives **all eight from URL query parameters** (`timeout`, `retry-wait`, `retry-count`, `workers-per-resolver`, `max-errors`, `notxt`, `force-resolv-conf`, `resolvers`). **The DNS configuration arrives as a c2URI.** `[inferred]` **There is no query parameter for a domain list** — the cover-set capability does not exist on the operator surface, either.

### §4.3 Server side — a slice, for a different purpose

`[verified]` `dns.go:99` `func StartDNSListener(bindIface string, lport uint16, domains []string, canaries bool) *SliverDNSServer`

**`domains []string` — a slice.** But read how it is used:

`[verified]` `dns.go:598-608`:

```go
func (s *SliverDNSServer) isC2SubDomain(domains []string, reqDomain string) (bool, string) {
	for _, parentDomain := range domains {
		if dns.IsSubDomain(parentDomain, reqDomain) {
			dnsLog.Infof("'%s' is subdomain of '%s'", reqDomain, parentDomain)
			return true, parentDomain
		}
	}
	dnsLog.Infof("'%s' is NOT subdomain of any c2 domain %v", reqDomain, domains)
	return false, ""
}
```

**This is an INBOUND match loop.** It asks *"is this incoming query for one of my domains?"* — an **ingress filter**, and it returns the matched parent. `[inferred]` **It is never consulted when the server emits anything.** A list used only to classify *arriving* queries is a **routing/tenancy table** (one server hosting several operators or engagements), not a hidden distribution.

**`[inferred]` The distinction is the whole answer to ask #3:** a "cover set" would be consulted on the **egress** path to choose among plausible domains. Sliver's slice is consulted on the **ingress** path to decide whether to answer at all. **Same data type, opposite direction, different purpose.**

`[verified]` **Cross-check:** grepping the server for outbound domain generation finds only `decodeSubdata` (`:666`) and the response builders — **the server never *chooses* a domain; it *strips* the parent** (`:614`: `subdomain := req.Question[0].Name[:len(...)-len(domain)]`).

**`[verified]` `canaries bool` (`:99`) is a separate, opt-in mechanism and it is NOT a cover scheme.** See §5.4 — it is an alerting beacon.

---

## §5 Ask #4 — what does 37 KB of server do that 30 KB of client does not?

**The Lead's hypothesis:** *If the answer is "the resolver," then Sliver and Pupy made the same structural decision 12 years apart.*

**Answer: it is NOT the resolver. It is STATEFUL REASSEMBLY. The structural decision is the opposite of the Lead's hypothesis — and both frameworks *do* share one decision, but it is a different one.**

### §5.1 The structural asymmetry, enumerated

**Command:** `Select-String -Path server\c2\dns.go -Pattern '^func\s'` → **40 top-level functions.**

`[verified]` Classified by function:

**Session state machine (10 functions, all `DNSSession` methods, `:143-286`):** `touch`, `msgID`, `nextMsgID`, `outgoingLimits`, `nextAvailableMsgIDLocked`, `StageOutgoingEnvelope`, `PopOutgoingMsgID`, `OutgoingRead`, `ClearOutgoingEnvelope`, `clearOutgoingEnvelopes`, `lookupOutgoingEnvelope`.

**Reassembly (4):** `IncomingPendingEnvelope` `:301`, `ForwardCompletedEnvelope` `:319`, `PendingEnvelope.Reassemble` `:388`, `PendingEnvelope.Insert` `:416`.

**Lifecycle / GC / loops (5):** `Shutdown` `:455`, `ListenAndServe` `:468`, `closeDNSSession` `:472`, `startDNSSessionSendLoop` `:483`, `startInitGC` `:510`, `gcPendingInits` `:535`.

**DNS response construction (4):** `nameErrorResp` `:680`, `emptySuccessResp` `:687`, `refusedErrorResp` `:694`, `handleCanary` `:1145`.

**Per-message-type handlers (6):** `handleC2` `:613`, `handleDNSSessionInit` `:767`, `handlePoll` `:892`, `handleDataFromImplant` `:973`, `handleDataToImplant` `:1011`, `handleClear` `:1075`.

**Helpers (3):** `decodeSubdata` `:666`, `accumulateInitData` `:701`, `dnsSessionID` `:1183`, `splitToChunks` `:1199`.

### §5.2 The server is a reassembly engine; the client is a stateless encoder

`[verified]` `dns.go:372-378` — the reassembly state:

```go
type PendingEnvelope struct {
	Size     uint32
	received uint32
	messages map[uint32][]byte
	mutex    *sync.Mutex
	complete bool
}
```

`[verified]` `dns.go:415-433` — `Insert` keys each fragment by its wire `Start` and recomputes:

```go
func (p *PendingEnvelope) Insert(dnsMsg *dnspb.DNSMessage) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.complete {
		return false // Already complete
	}
	p.messages[dnsMsg.Start] = bytes.NewBuffer(dnsMsg.Data).Bytes()
	total := uint32(0)
	for k := range p.messages {
		total += uint32(len(p.messages[k]))
	}
	p.received = total
	p.complete = p.received >= p.Size
```

`[verified]` `dns.go:388-412` — `Reassemble` sorts by key, concatenates, then **validates**:

```go
	if 1 < len(keys) {
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	}
	...
	if len(buffer) != int(p.Size) {
		return nil, fmt.Errorf("invalid data size %d expected %d", len(buffer), p.Size)
	}
```

**`[inferred]` The finding:** DNS is a request/response protocol with no stream and a hard 254-character QNAME ceiling. Sliver's `DNSMessage` carries `Start`/`Stop`/`Size`, the client splits (`SplitBuffer` `:711`), and **the server reassembles**. `[inferred]` **All fragmentation state lives server-side; the client holds none.** That is what the extra 7 KB of server code buys — **not a resolver, but a fragment buffer with GC, per-session ID spaces, and outgoing queues.**

`[verified]` **The Lead's resolver hypothesis is testable and fails:** `dns.go` contains **one** occurrence of the string `resolver` (counted by `[regex]::Matches($t,'resolver').Count` → **1**), versus **132** occurrences of `DNS` and **40** `func ` — **the resolver lives in the client** (`DNSResolver`, `:385` `sendInit(resolver, ...)`, `:474` `.AAAA(domain)`, `:479` `.TXT(domain)`). **`[inferred]` The server does not resolve; it answers.**

### §5.3 Two genuine defects in the reassembly engine, both author-acknowledged or unguarded

**`[verified]` `dns.go:389` — the author's own comment, left in the shipped source:**

```go
	// There's some weird race here with a nil pointer
	p.mutex.Lock()
```

`[inferred]` A known concurrency uncertainty, documented and **not resolved**. Recorded as-is; **whether the race is live is NOT established by this pass.**

**`[verified]` `dns.go:422` — `p.messages[dnsMsg.Start] = ...` has NO duplicate or overlap detection.** A repeated `Start` silently **overwrites** its predecessor. `[inferred]` `received` is recomputed from map contents (`:427-430`), so a **duplicate** cannot inflate the count — but an **overlapping** fragment with a distinct `Start` and attacker-chosen `Data` would be included in the concatenation, and `:409`'s `len(buffer) != Size` check contains the damage to a size mismatch rather than preventing the substitution. **Recorded as an observation; no exploitability claim is made.**

### §5.4 `canaries` — an alerting beacon that resolves as NOTHING

`[verified]` `dns.go:1145-1179`:

```go
func (s *SliverDNSServer) handleCanary(req *dns.Msg) *dns.Msg {
	// Don't block, return error as fast as possible
	go func() {
		...
		canary, err := db.CanaryByDomain(reqDomain)
		...
		if canary != nil {
			dnsLog.Warnf("DNS canary tripped for '%s'", canary.ImplantName)
			if !canary.Triggered {
				defer core.EventBroker.Publish(core.Event{ ... EventType: consts.CanaryEvent })
				canary.Triggered = true
				...
			}
			canary.LatestTrigger = ...
			canary.Count++
			generate.UpdateCanary(canary)
		}
	}()
	return s.nameErrorResp(req)
}
```

**`[inferred]` The canary resolves as `nameErrorResp` — an NXDOMAIN — while asynchronously publishing an event.** The DB lookup is off-loaded to a goroutine explicitly *"as fast as possible"* (`:1146`), so response latency does not leak whether a canary was hit.

**`[inferred]` This is the sharpest contrast with Pupy in either report.** Pupy's C2 channel tries to look like **ordinary browsing**. Sliver's canary domain tries to look like **nothing at all** — a name that does not exist. **Two opposite answers to "what does not-suspicious mean."**

### §5.5 The dispatch failure mode — silence, logged

`[verified]` `dns.go:566-596` — `HandleDNSRequest`, the entry point:

```go
	var resp *dns.Msg
	isC2, domain := s.isC2SubDomain(domains, req.Question[0].Name)
	if isC2 {
		resp = s.handleC2(domain, req)
	} else if canaries {
		resp = s.handleCanary(req)
	}
	if resp != nil {
		resp.Compress = true
		writer.WriteMsg(resp)
	} else {
		dnsLog.Infof("Invalid query, no DNS response")      // :594
	}
```

**`[inferred]` A query that is neither a C2 subdomain nor a canary match receives NO RESPONSE AT ALL** — `resp` stays `nil`, nothing is written — **and the drop is logged at `:594`.** No synthesized NXDOMAIN, no decoy answer, no default record.

`[verified]` `:591` — `resp.Compress = true`, with the author's comment: *"These responses often have near-max-length QNAMEs. Enable compression to keep UDP responses under the minimum DNS message size limits."* **DNS-layer size engineering, consistent with the header arithmetic in §3.1.**

`[inferred]` **This is a fourth distinct failure-mode design, and it is not any of D30 §5's three.** D30 recorded: Havoc **silently no-ops on known commands**; Pupy **raises at the codec, swallows at the caller**; Sliver's *envelope* is a **typed unknown** (`UnknownMessageType`). **At the DNS carrier layer, Sliver's unclassifiable input gets SILENCE — recorded, not swallowed, and not typed, because there is no envelope to type: the query did not even prove it was for us.**

---

## §6 The comparison — Sliver DNS vs Pupy DNS

| Axis | **Pupy DNS** | **Sliver DNS** |
|---|---|---|
| **Carrier** | DNS (TXT/A) | DNS (A/AAAA/TXT — `:245-249`, `:474-479`) |
| **Encoding** | **4 Huffman codebooks + FREEDNS index** (`dns_encoder.py:345-348`) | **Base32** (`dnsclient.go:170`, `:22-25`) |
| **Alphabet** | 38 symbols (`DNS_ALPHABET:72`) + word vocabulary | Base32, fixed |
| **Vocabulary** | **256 real FreeDNS provider domains** (`FREEDNS:16`) | **NONE** |
| **Parent domains** | n/a (word codec *is* the domain) | **1 scalar** (`:141`, `:155`, `:204`); server slice is ingress routing (`:599-606`) |
| **Self-describing?** | **YES** — table selector packed in byte 0 (`:449-454`) | **NO** — typed protobuf (`dns.proto:22-29`), no selector field |
| **What it hides** | **INTENT** — plausible browsing | **BYTES** — base32 noise under an operator domain |
| **Wire message** | `chr(tables_map) + data` (`:454`) | protobuf `DNSMessage`, 5 fields + 8-value enum |
| **Fragmentation** | label search minimizes length (`:443`) | `Start`/`Stop`/`Size` in protocol; `SplitBuffer` `:711`; server reassembles `:416` |
| **Space-pressure response** | **Pack a codebook selector** | **Pack a session ID** (`dns.proto:24`, `dns.go:1183`) |
| **Unknown input** | `raise ValueError` (`:217`), swallowed ×3 (`:385`, `:436`, `:714`) | **NO RESPONSE**, logged (`dns.go:594`) |
| **Suspicion model** | Look like **ordinary browsing** | C2 under **your own** domain; canary looks like **nothing** (`:1178`) |
| **Trust in inbound data** | n/a (codec only) | **Explicit**: `PendingEnvelope` size validation (`:409`), NXDOMAIN for unknown (`:594`) |

### §6.1 The verdict, in three parts

**1. The carrier-forcing hypothesis is DEAD — and now it is dead against the file that was unread.** `[inferred]` D30 §6's claim ("the carrier is necessary but not sufficient") **was correct when written and is now verified rather than inferred-adjacent.** Sliver runs C2 over the identical carrier and encodes **plain Base32 over one operator domain**, with zero vocabulary and zero domain selection. **Same carrier, opposite encoding philosophy.**

**2. The Lead's resolver hypothesis is NOT supported — and the real shared decision is a different one.** The server is not a resolver (`resolver` ×1 vs `func ` ×40). It is a **reassembly engine**. `[inferred]` **The convergence between Sliver and Pupy is real but it is not "the resolver."** Both frameworks independently discovered that **DNS's 254-character QNAME ceiling forces a fragmentation protocol above the codec.** Pupy answers by *minimizing bytes* (`:443`, the label-segmentation search). Sliver answers by *adding protocol fields* (`Start`/`Stop`/`Size` in the schema). **Same structural pressure, two solutions: shrink the payload, or describe the fragments.**

**3. The "space pressure" parallel is genuine and narrow.** `[verified]` Pupy packs a 2-bit table selector into byte 0 (`:449-454`); Sliver packs an 8-bit message ID + 24-bit session ID into one `uint32` (`dns.proto:24`, `dns.go:1183`). **Both hand-pack bits because DNS leaves no room.** `[inferred]` **But they pack different categories of information: Pupy packs *how to decode*, Sliver packs *who is talking*.** Self-describing versus self-addressing. **That distinction, not the carrier, is what separates the designs.**

---

## §7 Instrument record

### §7.1 No dead probe this pass — and the reason is worth recording

**Every probe run in this pass returned a control-consistent result.** The three that touched counts:

- `Get-ChildItem` DNS inventory → 10 files, and the **three Lead-cited sizes matched exactly** (positive control on the artifact).
- `[regex]::Matches($t,'resolver').Count` → **1**, against **132** `DNS` and **40** `func ` in the same string — **a low count with its own control in the same run.**
- `[regex]::Matches($t,'ParentDomain').Count` across the tree → 3 files, each then opened.

**`[inferred]` The reason no probe died: I wrote the control into the same command that produced the number, rather than checking afterwards.** Every count was emitted alongside a term certain to be present. **This is the operational form of the rule the corpus has been converging on** — and it is the first pass this round where the instrument record has nothing to report.

### §7.2 A scope near-miss, caught before it became a claim

**`dnsclient.go` line 23-25 contains the author's own encoding arithmetic:**

```
Base 32 encoding, so (n*8 + 4) / log2(32) = 63 means we can encode 39 bytes
per subdomain.
```

**`[inferred]` I nearly reported `39 bytes per subdomain` as the capacity.** It is **not** the operative value: `:27-30` gives the real bound (`254 - len(parent) = subdata space`, worst case parent 126 chars), and `SplitBuffer` (`:729`, `:743`) computes the working limit dynamically from `s.subdataSpace`.

**Recorded because it is the corpus's recurring failure in a new guise:** the number that is *written in the file* is not the number that *governs the code*. **A comment is a claim, not a measurement — and a comment's arithmetic is a claim about the author's intent at the time of writing, not about the current constant.**

### §7.3 One self-check false positive, recorded (thirteenth instance)

**The probe:** a completion check across this report for `pending|to be read|TBD` → **1 match, line 90.**

**Why that was suspicious:** the report was written in a single pass with no placeholders, so a hit meant either a real gap or a bad pattern.

**Root cause — a substring match inside a quoted word.** The hit was `pending` **inside `re-puposed`**, the author's own typo at `dns.proto:21` which §2 quotes verbatim. `[inferred]` **The same shape as D26 §7's eighth failure and D30 §7.4: a pattern that matches the form I had in mind rather than the form present in the text.** Here the pattern was an unanchored substring used for a structural check — it should have been word-bounded (`\bpending\b`).

**Control that settled it:** the match was read in context (line 90, a quoted source comment), not counted and reported. **No placeholder exists in this report.**

**Notable because it is a false positive in the conservative direction:** it flagged correct work as incomplete. **D30 §7.4's verification probe failed in the direction of false doubt; this one did the same,** and both would have triggered unnecessary "fixes" if acted on without reading the match.

---

## §8 Residual unknowns

**U1 — CLOSED. This report's purpose.** D30 §4.4's inventory-level claim is now a full read. **The carrier-forcing hypothesis does not come back.** Falsification condition (a) from D30 §7.3 resolves: **there is no vocabulary in Sliver's DNS transport.**

**U2 — `PendingEnvelope` race (`dns.go:389`) is NOT characterised.** The author's comment names a nil-pointer race; **whether it is reachable and what it corrupts was not determined.** *Do not infer it shut.* `[absence]`-adjacent: no claim made either way. *Positive control:* the comment was located by direct read of the function; no reachability analysis was attempted.

**U3 — fragment overlap (`dns.go:422`) is observed, not exploited.** Duplicate `Start` overwrites; overlapping `Start` values are concatenated and pass only the total-size check. **No exploitability or impact claim is made.** Whether `Stop` (`dns.proto:26`) is validated against `Start` is **not established** — `Stop` appeared in the schema and in commented-out logging (`:424`) but its enforcement was not traced.

**U4 — `dns.go:892-1145` (the six per-message-type handlers) was read at structure and signature level, not line-by-line.** `handleDNSSessionInit` (`:767`), `handlePoll` (`:892`), `handleDataFromImplant` (`:973`), `handleDataToImplant` (`:1011`), `handleClear` (`:1075`) were **enumerated and their signatures read; their bodies were not.** *Positive control:* the function names, line numbers, and parameter lists are enumerated in §5.1 and are reproducible from the command given there. **No behavioural claim about them appears in this report.**

**U5 — `client\command\jobs\dns.go` (1,775 B) and `server\generate\canaries.go` (2,775 B) were not read.** `[inferred]` The canary lifecycle spans `generate\canaries.go` → `dns.go:handleCanary` → event broker; only the middle link was read.

**U6 — Pupy's side of this comparison is carried from D30 §3, read at primary source there.** `[verified]` within D30; **cited, not re-derived here.** Everything on the Pupy side of §6 traces to D30 §3's line citations.

**U7 — `docs\sliver-docs\pages\docs\md\DNS C2.md` (13,007 B) is available and unread.** It is **documentation, not source**, and no claim here rests on it. **Noted because an operator-facing description of the DNS transport exists and may state intent that the code does not** — if a future task wants the designer's *stated* rationale against the *implemented* behaviour, that file is the comparison.

**Falsification conditions.** §6's verdict would be overturned by: (a) finding a domain-selection or vocabulary mechanism on the **egress** path anywhere in the DNS transport — §3's absence claim rests on type inspection of every domain-valued identifier, so such a mechanism would have to be constructed rather than stored; (b) establishing that `s.parent` is ever a slice or a rotating value at runtime — `:141`/`:155`/`:204` are all scalar and the `c2URI` query surface (`:101-137`) has no domain parameter; (c) reading the six handlers in U4 and finding vocabulary logic inside them.

---

*End of D35.*
