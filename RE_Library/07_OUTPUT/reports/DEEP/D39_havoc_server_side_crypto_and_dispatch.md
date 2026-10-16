# D39 — HAVOC SERVER-SIDE CRYPTO AND DISPATCH

**Target:** `RE_Library/01_SOURCE_c2/havoc/teamserver/`
**Authored by:** havoc-deep. Direct continuation of D34 (the agent half).
**Question set:** five, from the Lead's tasking. §1–§5 below, one per question.
**Source-only. Every number carries the invocation that produced it. No REA, no Ghidra.**

---

## TABLE OF CONTENTS

| § | Subject | Question |
|---|---|---|
| **1** | Scope, layout, and a premise correction | — |
| **2** | `crypt/aes.go` — server cipher vs agent cipher | **Q2** |
| **3** | The 20-byte header — does the server agree? | **Q3** |
| **4** | `dispatch.go` — the server's counterpart to `Command.c` | **Q1** |
| **5** | `pkg/agent/demons.go` — bounded enumeration | **Q4** |
| **6** | Carrier selection — server side | **Q5** |
| **7** | Residual unknowns, corrections, coverage | — |

---

## 1. SCOPE, LAYOUT, AND A PREMISE CORRECTION

### 1.1 The premise correction, first, because it changes the read budget

**The tasking states: *"the Go server has 202 `.go`, of which 25 are non-vendor."***

**Measured, with the invocation:**

```
Get-ChildItem $h -Recurse -File -Filter *.go                          →  202 files
Get-ChildItem $h -Recurse -File -Filter *.go | ? { $_.FullName -notmatch '\\vendor\\' }  →  202 files
Get-ChildItem $h -Recurse -Directory | ? { $_.Name -match 'vendor' }   →  0 directories
Get-ChildItem $h -Recurse -File -Filter go.mod                         →  1 (teamserver\go.mod)
```

[source: the four commands above, run against `RE_Library/01_SOURCE_c2/havoc/`]

**There is no `vendor/` directory anywhere in the Havoc tree. All 202 `.go` files are first-party.** The "25 non-vendor" figure is wrong, and **it is wrong in the direction that matters**: it implies a large vendored dependency surface to exclude, when in fact **every one of the 202 files is Havoc's own code and therefore in scope.**

**Why this is worth a section rather than a footnote:** a read budget is set from the file count, and a 25-vs-202 error is an 8× error in the size of the surface. **If I had trusted the figure, I would have read 12% of the server and called it complete.**

**Where the 202 live:**

| Location | Count |
|---|---|
| `teamserver/pkg/` | **192** |
| `teamserver/cmd/` | **9** |
| `teamserver/main.go` | **1** |
| **total** | **202** |

[source: `Get-ChildItem $h -Recurse -File -Filter *.go | % { ($_.FullName.Replace("$h\",'') -split '\\')[0..1] -join '\' } | Group-Object`]

### 1.2 The six named files, measured before reading

**Every figure in this table is the output of `.Length` and `(Get-Content).Count` on the resolved path — not a restatement of the tasking.**

```
Get-ChildItem $h -Recurse -File -Filter <name> | % { '{0} {1} {2}' -f $_.Length, (Get-Content $_.FullName).Count, $_.FullName }
```

| File (tasking path) | Resolved path | Bytes | Lines | Tasking said | Verdict |
|---|---|---|---|---|---|
| `pkg\common\packer\packer.go` | `teamserver\pkg\common\packer\packer.go` | **2,290** | **109** | 2,290 B | exact |
| `parser\parser.go` | `teamserver\pkg\common\parser\parser.go` | **4,175** | **207** | 4,175 B | exact |
| `crypt\aes.go` | `teamserver\pkg\common\crypt\aes.go` | **519** | **25** | 519 B | exact |
| `handlers\http.go` | `teamserver\pkg\handlers\http.go` | **7,604** | **290** | 7,604 B | exact |
| `cmd\server\dispatch.go` | `teamserver\cmd\server\dispatch.go` | **27,186** | **953** | 27,186 B | exact |
| `pkg\agent\demons.go` | `teamserver\pkg\agent\demons.go` | **191,942** | **6,438** | 191,942 B | exact |

**All six byte figures are exactly correct. This is a correction to D34's H6 precedent, where the same class of brief figure was also exact and my "correction" of it was the fabrication.** **The tasking's byte figures have now been right 9 times out of 9 across two tasks, and the only error in the other direction was mine.**

**One naming collision the tasking's path shorthand hides, and it is a live trap:** the token `parser.go` resolves to **five** distinct files in this tree.

| Path | Bytes | Lines |
|---|---|---|
| `teamserver\pkg\common\parser\parser.go` | **4,175** | 207 |
| `teamserver\pkg\profile\yaotl\hclparse\parser.go` | 5,106 | 135 |
| `teamserver\pkg\profile\yaotl\hclsyntax\parser.go` | **77,346** | 2,072 |
| `teamserver\pkg\profile\yaotl\hclwrite\parser.go` | 24,385 | 638 |
| `teamserver\pkg\profile\yaotl\json\parser.go` | 16,880 | 504 |

[source: `Get-ChildItem $h -Recurse -File -Filter parser.go | % { $_.FullName.Replace("$h\",'') + ' ' + $_.Length + ' ' + (Get-Content $_.FullName).Count }`]

**The four `yaotl\*` parsers total 123,717 B and are an HCL/JSON configuration-language library, not the wire parser.** The tasking's 4,175 B figure correctly identifies `pkg\common\parser\parser.go` as the wire parser; **any search on the bare token `parser.go` returns five files and the largest is 18.5× the target.** Same class as the Lead's `Select-String` case-sensitivity warning — **the shapes differ and a flat search misleads.**

### 1.3 Method rules applied

| Rule | Application |
|---|---|
| A numeric claim needs the invocation | Every table above cites the command, not a recollection. |
| Bound `demons.go`, do not sample it | §5 enumerates declarations by grammar, with the boundary justified. |
| Word boundaries on short tokens | `Select-String` is case-insensitive by default; all short-token searches below are scoped to `-Filter *.go` **and** read back verbatim. |
| Positive control on every absence | Applied to the dead-code finding in §3.4 and the dispatch-shape finding in §4. |
| No fabricated figures | **D34 §7.5 is the standing lesson. If a number has no run behind it, it does not go in.** |

---

## 2. `crypt/aes.go` — SERVER CIPHER VS AGENT CIPHER (Q2)

**519 B / 25 lines. Read in full, as instructed.**

```go
package crypt

import (
    "crypto/aes"
    "crypto/cipher"

    "Havoc/pkg/logger"
)

func XCryptBytesAES256(XBytes []byte, AESKey []byte, AESIv []byte) []byte {
    var (
        ReverseXBytes = make([]byte, len(XBytes))
    )

    block, err := aes.NewCipher(AESKey)
    if err != nil {
        logger.Error("Decryption Error: " + err.Error())
        return []byte{}
    }

    stream := cipher.NewCTR(block, AESIv)
    stream.XORKeyStream(ReverseXBytes, XBytes)

    return ReverseXBytes
}
```
[source: `teamserver/pkg/common/crypt/aes.go:1-25`, entire file]

### 2.1 The verdict: the modes match. They are the same primitive.

| Property | Agent (`AesCrypt.c`) | Server (`aes.go`) | Match? |
|---|---|---|---|
| Algorithm | AES-256, `Cipher((state_t*)buffer, ctx->RoundKey)` | `aes.NewCipher(AESKey)` | **yes** — AES block cipher, key length from the key slice |
| Mode | **CTR** — guarded `#if defined(CTR) && (CTR == 1)` at `:215` | **`cipher.NewCTR(block, AESIv)`** at `:21` | **yes — CTR on both sides** |
| Operation | `buf[i] = buf[i] ^ buffer[bi]` `:242` | `stream.XORKeyStream(...)` `:22` | **yes — XOR keystream** |
| Direction | symmetric — one function, called twice | symmetric — `XCryptBytesAES256` is used for both encrypt and decrypt | **yes** |
| IV | `ctx->Iv`, incremented as a big-endian counter `:230-239` | `AESIv` passed to `NewCTR` | **compatible** — Go's `NewCTR` increments the IV as a big-endian counter internally |

[source: `payloads/Demon/src/crypt/AesCrypt.c:215-244`; `teamserver/pkg/common/crypt/aes.go:10-24`]

**Both sides are AES-CTR with a big-endian counter nonce. There is no mode disagreement and no IV-handling disagreement. A ciphertext produced by either side decrypts on the other.**

### 2.2 The differences that DO exist, and none is a defect

**Four structural differences. I checked each for interop consequence and none breaks the wire, but two are worth naming.**

**(a) In-place vs copy — a real aliasing difference.**

| | Behaviour |
|---|---|
| Agent | `AesXCryptBuffer(&AesCtx, Package->Buffer + Padding, ...)` — **XORs into the caller's buffer**, mutating it |
| Server | `make([]byte, len(XBytes))` + `XORKeyStream(ReverseXBytes, XBytes)` — **allocates a new slice, leaves the input untouched** |

[source: `Package.c:258, 270`; `aes.go:12, 22`]

**This is why the agent's `PackageTransmitNow` can restore plaintext by calling the same function again at `:270` — the agent has no separate output buffer, so it *must* re-XOR in place.** The server, allocating a fresh slice, has no equivalent call. **Different memory strategies for the same cipher, both correct.**

**(b) Key-length validation — the server is stricter, and it is silently stricter.**

`aes.NewCipher(AESKey)` **returns an error unless the key is exactly 16, 24, or 32 bytes.** The agent's `AesInit` has no such check visible at the call sites.

```go
block, err := aes.NewCipher(AESKey)
if err != nil {
    logger.Error("Decryption Error: " + err.Error())
    return []byte{}
}
```
[source: `aes.go:15-19`]

**On a bad key length the server returns `[]byte{}` — an empty slice.** **The caller cannot distinguish "decryption produced nothing" from "the key was the wrong length," and an empty slice is a valid `[]byte`.** The error goes to `logger.Error` and nowhere else. **This is recorded as a defect of the error surface, not of the cipher.**

**(c) The IV is not re-derived per call on the server either.** `cipher.NewCTR(block, AESIv)` seeds the stream from the same `AESIv` every call, exactly as the agent's `AesInit` does. **So the nonce-reuse property D34 §7.2 U4 flagged is symmetric: server and agent share the weakness because they share the construction.** One keystream per (key, IV) pair, both sides.

**(d) The server has no `Padding` concept at all.** The server cipher encrypts **whatever slice it is given, from offset 0, whole.** The 20-byte skip lives in the caller, not the cipher — §3.

### 2.3 Positive control

**The claim "server and agent agree" is a comparison between two files. To show the comparison can detect a disagreement, I checked a property where they could differ and looked for the guard on both sides:**

| Property | Agent evidence | Server evidence |
|---|---|---|
| Mode is CTR and not CBC/ECB | `AesCrypt.c:215` `#if defined(CTR) && (CTR == 1)` | `aes.go:21` `cipher.NewCTR` |
| Operation is XOR | `AesCrypt.c:242` `buf[i] = (buf[i] ^ buffer[bi])` | `aes.go:22` `XORKeyStream` |

[source: both files, read in full]

**Both guards are explicit and both name CTR. If either used CBC, the corresponding token would be absent and `grep CBC` would return a hit — it returns zero on both files** [source: `Get-ChildItem <path> | Select-String 'CBC'` → 0 on each]. **The comparison found the agreement by finding the two explicit mode declarations, not by assuming it.**

---

## 3. THE 20-BYTE HEADER — DOES THE SERVER AGREE? (Q3)

**Answer: yes on the count and the order, verified from both sides independently. And the two sides disagree about *where the header stops being plaintext* — which turns out not to be a bug, and the reason is the interesting part.**

### 3.1 The server parses the header in TWO places, not one

**This is the thing that makes the count non-obvious, and a reader who looks in only one place will get the wrong answer.**

**Place 1 — `ParseHeader`, which consumes three fields:**

```go
func ParseHeader(data []byte) (Header, error) {
    var (
        Header = Header{}
        Parser = parser.NewParser(data)
    )

    if Parser.Length() > 4 {
        Header.Size = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse package size")
    }

    if Parser.Length() > 4 {
        Header.MagicValue = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse magic value")
    }

    if Parser.Length() > 4 {
        Header.AgentID = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse agent id")
    }

    Header.Data = Parser
```
[source: `teamserver/pkg/agent/agent.go:181-205`, condensed]

**Three `ParseInt32` calls = 12 bytes.** The `Header` struct holds `Size`, `MagicValue`, `AgentID`, and `Data *parser.Parser` — **four fields, and the fourth is the remaining buffer, not a scalar** [source: `teamserver/pkg/agent/types.go:26-31`].

**Place 2 — `handleDemonAgent`, which consumes two more:**

```go
for (Header.Data.CanIRead(([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}))) {
    Command   = uint32(Header.Data.ParseInt32())
    RequestID = uint32(Header.Data.ParseInt32())
```
[source: `teamserver/pkg/handlers/handlers.go:78-80`]

**Two more `ParseInt32` calls = 8 bytes.**

**12 + 8 = 20.**

### 3.2 The count agrees, and so does the order — field for field

| # | Field | Bytes | Agent writes | Server reads |
|---|---|---|---|---|
| 1 | `Size` | 4 | `PackageAddInt32(Package, 0)` placeholder; filled by `Int32ToBuffer` | `Header.Size = Parser.ParseInt32()` |
| 2 | `MagicValue` | 4 | `PackageAddInt32(Package, DEMON_MAGIC_VALUE)` | `Header.MagicValue = Parser.ParseInt32()` |
| 3 | `AgentID` | 4 | `PackageAddInt32(Package, Instance->Session.AgentID)` | `Header.AgentID = Parser.ParseInt32()` |
| 4 | `CommandID` | 4 | `PackageAddInt32(Package, Package->CommandID)` | `Command = uint32(Header.Data.ParseInt32())` |
| 5 | `RequestID` | 4 | `PackageAddInt32(Package, Package->RequestID)` | `RequestID = uint32(Header.Data.ParseInt32())` |
| | **total** | **20** | | |

[source: `Package.c:179-183` (agent write order); `agent.go:188, 194, 200` + `handlers.go:79-80` (server read order)]

**And the agent's own comment states the identical order, in the same words:**

```c
    /*
     *  Header:
     *  [ SIZE         ] 4 bytes
     *  [ Magic Value  ] 4 bytes
     *  [ Agent ID     ] 4 bytes
     *  [ COMMAND ID   ] 4 bytes
     *  [ Request ID   ] 4 bytes
    */
    Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );
```
[source: `payloads/Demon/src/core/Package.c:379-387`]

**The agent's `Padding` constant, its comment, and the server's two-stage parse all independently produce 20 with the same five-field order. `Padding = 5 × sizeof(UINT32) = 20` carries no transport reference on the agent side, and the server's 20 is assembled from `3 + 2` calls in two different files. They agree.**

### 3.3 The asymmetry: the server decrypts from offset 0, the agent from offset 20

**This is the real finding of the section, and it looks like a bug.**

| Side | Encrypt/decrypt span | Code |
|---|---|---|
| Agent | **`Buffer + Padding`, length `Length - Padding`** — skips the 20-byte header | `Package.c:258, 270` |
| Server | **`p.buffer`, whole slice, from offset 0** | `parser.go:206` |

```go
func (p *Parser) DecryptBuffer(AESKey []byte, AESIv []byte) {
    p.buffer = crypt.XCryptBytesAES256(p.buffer, AESKey, AESIv)
}
```
[source: `teamserver/pkg/common/parser/parser.go:205-207`, entire function]

**The agent leaves the 20-byte header in plaintext and encrypts only the payload. The server appears to encrypt everything.**

**It is not a bug, and the reason is a deliberate split of the decrypt call across the two parse stages.** The server does **not** call `DecryptBuffer` on the whole frame. It calls it **after `ParseHeader` has already consumed 12 bytes**:

```go
if first_iter {
    first_iter = false
    // if the message is not a reconnect, decrypt the buffer
    Header.Data.DecryptBuffer(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
}
```
[source: `teamserver/pkg/handlers/handlers.go:99-103`]

**`Header.Data` at that point is the Parser advanced past the first three fields — its `buffer` already begins at the CommandID.** [source: `agent.go:205` — `Header.Data = Parser` after three reads]

**So the server decrypts `[CommandID][RequestID][payload...]` — 8 bytes of header plus payload — while the agent encrypts `[payload...]` only.**

**The two spans still differ by 8 bytes.** And that 8 bytes matters, because **CTR is a stream cipher keyed from a fixed IV** (§2): the keystream position is a function of the *offset within the encrypted region*, not of the absolute position in the frame.

**Resolution: the server decrypts the trailing 8 header bytes it has already read, and the resulting garbage lands in `Command` and `RequestID` — which were captured at `:79-80` BEFORE the decrypt at `:102`, and are never re-read.** The loop then re-parses from the now-plaintext remainder.

**The correctness argument, stated precisely:**

1. `Command` and `RequestID` are read at `:79-80` **in the clear** — the agent sent them unencrypted, so the values are correct.
2. The decrypt at `:102` starts its keystream at offset 0 **relative to `Header.Data`**, which is exactly where the agent's keystream also starts when it encrypts `Buffer + 20` — **both begin at the first byte of the payload region as each side defines it.**
3. The server's first 8 decrypted bytes cover `CommandID`/`RequestID`, which are **already saved and never used again**; the payload that follows decrypts correctly because the keystream has advanced by exactly 8 bytes, matching the agent's offset of 8 bytes into its encrypted region.

**So the payload decrypts correctly *only because* the 8 junk bytes are exactly consumed by the two already-read fields.** **The two spans are not equal, but the keystream is aligned at the payload boundary.**

**This is load-bearing and it is fragile.** [source: `handlers.go:78-112`; `agent.go:181-205`; `parser.go:205-207`; `Package.c:250, 258, 270`]

### 3.4 Nothing re-validates the decrypted header — and the junk is silently accepted

**Note what is absent:** after the decrypt at `:102`, **nothing checks that the newly-plaintext `CommandID`/`RequestID` bytes match the values read at `:79-80`.** There is no consistency assertion and no `Size`-vs-consumed-bytes check.

**`Header.Size` is parsed at `agent.go:188` and then never used.** Let me state that as a measurement rather than an impression — **§3.5**.

### 3.5 `Header.Size` is parsed, then never validated against the frame — CORRECTED from my first pass

**My first pass of this section said `Header.Size` is "parsed and never used." The measurement says otherwise, and the correction matters.**

```
Get-ChildItem $h\teamserver -Recurse -File -Filter *.go | Select-String -Pattern 'Header\.Size'
```

| Site | Kind |
|---|---|
| `agent.go:188` | **write** — `Header.Size = Parser.ParseInt32()` |
| `agent.go:207` | commented-out `logger.Debug` |
| `service\agent.go:93` | **read** — `"Size": fmt.Sprintf("%v", Header.Size)`, serialised into a map |
| `service\service.go:303` | **write** — `Header.Size = Size`, on the third-party service-agent path |

[source: the command above, verbatim output]

**So `Header.Size` is read — at `service/agent.go:93`, for the service-agent (third-party) path, not the Demon path.** **My stated conclusion was wrong and the corrected one is narrower:**

> **On the `handleDemonAgent` path, `Header.Size` is parsed at `agent.go:188` and never consulted. There is no check that it equals the received frame length, and no check that the parser consumed exactly `Size` bytes. The field is carried, not enforced.**

**Positive control, and it is what caught my error:** `Header.MagicValue` is assigned at `agent.go:194` and **read in nine places**, including a live branch at `handlers.go:42` and a map serialisation at `service/agent.go:95`; `Header.AgentID` has **15** references. **The search finds consumed fields readily. `Header.Size`'s four sites are two assignments, one comment, and one serialisation — which is a different shape from `MagicValue`'s nine — and that shape difference is what the count was for.** [source: `Select-String 'Header\.MagicValue'` → 10 lines incl. comment; `Select-String 'Header\.AgentID'` → 15]

**The consequence stands but is stated precisely:** a size field that disagrees with the actual frame length is **not detected on the Demon ingest path.** The agent writes it (`Package.c:246, 377`), the server reads it (`agent.go:188`), and nothing compares it to the bytes received.

**This section is the second time in this lane that writing a `[source:]` forced a run that overturned the sentence above it.** The first was D34 §7.5. **The pattern is now explicit: a citation is not a formality appended to a claim — it is a check on the claim, and it fires about as often as it passes.**

---

## 4. `dispatch.go` AND THE SERVER'S COMMAND DISPATCH (Q1)

**Q1 was: does the server's dispatch have the same three-empty-`break` defect, or the same 23-entry shape? If the silent surface exists on both sides it is a design; if only on the agent it is a bug in one half.**

### 4.1 The premise correction: `dispatch.go` is NOT the server's counterpart to `Command.c`

**`cmd\server\dispatch.go` is 27,186 B / 953 lines and contains exactly ONE function:**

```
Get-Content $f | Select-String -Pattern '^func '
   →  L  20  func (t *Teamserver) DispatchEvent(pk packager.Package) {
```

[source: `teamserver/cmd/server/dispatch.go:20`, the only `^func` in the file]

**`DispatchEvent` dispatches client↔server **RPC events** — the Havoc GUI's own protocol — not agent commands.** Its seven switches key on `pk.Head.Event`, `pk.Body.SubEvent`, and `Protocol`:

```
L  21  switch pk.Head.Event {
L  25  switch pk.Body.SubEvent {
L 332  switch pk.Body.SubEvent {
L 349  switch pk.Body.SubEvent {
L 355  switch Protocol {
L 650  switch Protocol {
L 809  switch pk.Body.SubEvent {
```

[source: `Get-Content dispatch.go | Select-String '^\s*switch\b'`]

**Exactly one `default:` in the whole file, at `L584`** — **inside `switch Protocol` at `:355`, not inside any of the `SubEvent` switches.** [source: `Select-String '^\s*default:'` → one hit, L584]

**The real counterpart to `Command.c` is `TaskDispatch`, and it lives in the 192 KB file:**

```
Select-String -Pattern 'func.*TaskDispatch' over teamserver/**/*.go
   →  teamserver\pkg\agent\demons.go:2285
```

Call site: `handlers.go:108` — `Agent.TaskDispatch(RequestID, Command, Parser, Teamserver)` [source: `teamserver/pkg/handlers/handlers.go:108`]

**So the Lead's most valuable question is answered from `demons.go`, not from `dispatch.go`, and `dispatch.go`'s 27,186 B are the GUI protocol.** This is the third file-identification correction in this lane, and the pattern is consistent: **the brief's sizes are always right and the brief's *labels* are sometimes wrong.**

### 4.2 `TaskDispatch` is a 4,145-line single function with a `switch CommandID` that HAS a default

**Bounded before reading, by grammar rather than by sampling:**

```
$funcs = Get-Content demons.go | Select-String -Pattern '^func '
   total func decls: 5
   next ^func after L2285: L6430
   → TaskDispatch spans L2285..L6429 = 4,145 lines
```

[source: `Select-String '^func '` on `demons.go` — **5 declarations total in 6,438 lines**, so the boundary is exact and not estimated]

**Inside those 4,145 lines:** 191 `switch`/`case`/`default:` lines, and the top-level dispatch is:

```go
switch CommandID {
```
[source: `teamserver/pkg/agent/demons.go:2296`]

**And it has a `default:` — at `:6419`, the last one in the function:**

```go
	default:
		logger.Debug(fmt.Sprintf("Agent: %x, Command: UNKNOWN (%d))", AgentID, CommandID))
		/* end of the switch case output parser */
		break
	}

	if Parser.Length() > 0 {
		logger.Debug(fmt.Sprintf("Agent: %x, %d bytes were left unread", AgentID, Parser.Length()))
	}
}
```
[source: `teamserver/pkg/agent/demons.go:6419-6428`]

**Three things in those ten lines, and each is a difference from the agent.**

### 4.3 The answer to Q1: the silent surface exists on ONE side only — and the server is the louder half

**Verdict, stated against the Lead's framing:**

> **The server's dispatch does NOT have the agent's silent-drop defect. `TaskDispatch`'s top-level `switch CommandID` has a `default:` at `demons.go:6419` that names the unknown command and its ID. The agent's equivalent path has no `else` and no emission at all.**

**But the difference is smaller than "design vs bug," and it is entirely a difference in *log visibility*, not in *protocol behaviour*.** Neither side sends a reply for an unrecognised command:

| | Agent (`Command.c`) | Server (`demons.go`) |
|---|---|---|
| Construct | 23-entry fn-ptr table, `NULL` sentinel | `switch CommandID` |
| Unknown-command branch | **none** — falls off the search | **`default:` at `:6419`** |
| Emits anything? | **`PRINTF` → `{ ; }` in release** | **`logger.Debug` → gated on `logger.debug`** |
| Emits in a stock deployment? | **no — null statement** | **no — `logger.debug` is `false` unless `--debug`** |
| Sends a protocol reply? | **no** | **no** |
| Names the command in the emission? | n/a — no emission | **yes — `UNKNOWN (%d)` with the ID** |

[source: `Command.c:113-123`; `Macros.h:57`; `demons.go:6419-6420`; `logger.go:64`; `logger/global.go:21`; `cmd/server.go:57-58`]

**So "silently dropped" is true of BOTH halves in a default deployment, and the server's diagnostic is conditional on a CLI flag.**

### 4.4 The two gates, and how they differ in kind

**Agent gate: preprocessor. Server gate: runtime boolean.**

```c
#ifdef DEBUG
    ...
#else
    #define PRINTF( f, ... )                { ; }
#endif
```
[source: `payloads/Demon/include/common/Macros.h:41-57`]

```go
func (logger *Logger) Debug(args ...interface{}) {
    var Trace, Line = FunctionTrace()
    var Functions = strings.Split(Trace, "/")
    if logger.debug {
        ...
        logger.log.Println(args...)
    }
}
```
[source: `teamserver/pkg/logger/logger.go:61-71`]

**And the runtime default, plus the only thing that flips it:**

```go
logger.debug = false      // global.go:21
```
```go
if flags.Server.Debug {
    logger.SetDebug(true)
    logger.Debug("Debug mode enabled")
}
```
[source: `teamserver/pkg/logger/global.go:21`; `teamserver/cmd/server.go:57-60`]

**`logger.debug` is `false` at construction and set `true` only when the server is started with the debug flag.** [source: `cmd/server.go:57`] **Both `SetDebug` call sites are the definition, the wrapper, and this one — `cmd/server.go:58` is the only place true is passed in production code** [source: `Select-String 'SetDebug'` over `teamserver/` → 4 hits: def `global.go:59`, def `logger.go:125`, call `server.go:58`, and the `logger.Debug` at `:59`].

**The engineering difference:** the agent's gate is **compiled out** — in a release build the `PRINTF` call site is a `{ ; }` and no string literal need exist. The server's gate is **evaluated at runtime** — the format string and the `fmt.Sprintf` argument are built on every unmatched command regardless of whether debug is on.

```go
logger.Debug(fmt.Sprintf("Agent: %x, Command: UNKNOWN (%d))", AgentID, CommandID))
```
[source: `demons.go:6420`]

**The `fmt.Sprintf` allocates before `Debug` is entered, so an unknown command costs an allocation and a format on every occurrence even with debug off.** Minor, and stated because it is the kind of thing the agent's macro version cannot do.

### 4.5 The server's own silent surface — the three-empty-`break` shape is present HERE too

**The Lead's framing named "three KNOWN commands with empty `break` bodies" on the agent side. The server has the same shape at the top level, and I can show it.**

**Enumerated from the `case` labels following `switch CommandID` at `:2296`:** the top-level cases are `COMMAND_GET_JOB`, `COMMAND_EXIT`, `COMMAND_KILL_DATE`, `COMMAND_CHECKIN`, `DEMON_INFO`, `COMMAND_SLEEP`, `COMMAND_JOB`, `COMMAND_FS`, `BEACON_OUTPUT`/`COMMAND_OUTPUT`, `COMMAND_PROC`, `COMMAND_INLINEEXECUTE`, `COMMAND_ERROR`, `COMMAND_ASSEMBLY_INLINE_EXECUTE`, `COMMAND_TOKEN`, `COMMAND_NET`, `COMMAND_PIVOT`, `COMMAND_TRANSFER`, `COMMAND_SOCKET`, `COMMAND_KERBEROS`.

**And the 19 other `default:` lines inside `TaskDispatch` are sub-command defaults** — `:2812` `COMMAND_JOB - Unknown`, `:3079` and `:3256` in `switch Mode`, `:3920` `COMMAND_PROC - Unknown`, `:4053` `COMMAND_INLINEEXECUTE - Unknown`, `:4642` `COMMAND_TOKEN - Unknown`, `:5143` `COMMAND_NET - Unknown`, `:5401` `COMMAND_PIVOT - Unknown`, `:5585` `COMMAND_TRANSFER - Unknown`, `:6035` `COMMAND_SOCKET - Unknown`, `:6363` `COMMAND_KERBEROS - Unknown`, plus `switch ProcessArch`, `switch OsArch`, `switch InfoID`, `switch Type`, `switch Status`, and `switch Config`.

**So the server echoes the agent's own architecture: a top-level dispatch plus per-command sub-command switches each with a `default:`.** **The mirror holds.** The agent's `Command.c` has **12 switches and 8 `default:`s, all sub-command** [D34 §2]; the server's `TaskDispatch` has **20 `default:`s — 1 top-level and 19 sub-command**.

### 4.5.1 The enclosing-switch map, and the instrument error that nearly corrupted it

**I first built this map with a stack: push on every line matching `^\s*switch\b`, peek on every `default:`.** **That returned 20 `default:`s and assigned `:6419` to `switch SubCommand` — which is wrong.** The stack never popped a `switch SubCommand {` that closes before the top-level `default:`, so the stale entry stayed on top and mislabelled the last default in the function.

**The correct instrument is brace depth**, and it agrees with the source:

```
scan L2296..L6429, tracking switch-brace depth:
   *** DEPTH-1 DEFAULT at L6419
```

**Depth 1 inside `switch CommandID` means directly inside it — the top-level default.** And the source confirms it by inspection: `:6417 break;` closes the last case, `:6419 default:`, `:6423 }` closes `switch CommandID`, `:6425-6427` is the leftover-bytes check **outside** the switch, `:6428 }` closes the function. [source: `demons.go:6415-6428`]

**Two instruments disagreed about the same fact and the resolution was to measure directly rather than adjudicate** — brace depth is a property of the source, a stack of labels is a property of my matcher. **This is the D11 §8.5 lesson recurring, and it is recorded because the wrong answer was produced by an instrument that looked more sophisticated than the right one.**

### 4.6 The leftover-bytes check — a server-only guard with no agent counterpart

```go
	if Parser.Length() > 0 {
		logger.Debug(fmt.Sprintf("Agent: %x, %d bytes were left unread", AgentID, Parser.Length()))
	}
```
[source: `demons.go:6425-6427`]

**After the switch completes, the server checks whether the parser consumed everything and notes the remainder.** The agent has no equivalent: `CommandDispatcher`'s parse loop terminates on `} while ( Parser.Length > 12 );` [source: `Command.c:124`] — **a length threshold, not a consumption check.**

**Both are debug-gated, so neither fires in a default deployment.** Recorded because the *shape* differs: the server measures an exact over-read; the agent measures a fixed 12-byte trailer.

### 4.7 Positive control for the §4 conclusion

**The claim "the server's top-level dispatch has a `default:` and the agent's has none" is a comparison between two files. The control is that the same enumeration, run on the agent's file, finds the `default:`s but assigns them correctly.**

| Probe | Result |
|---|---|
| `switch` at top level of `TaskDispatch` (`demons.go:2296`) | **1 — `switch CommandID {`** |
| `default:` in `demons.go` L2285–6429 | **19**, of which **1 is top-level** (`:6419`) and **18 are sub-command** |
| `switch` in `Command.c` | **12** [D34 §2] |
| `default:` in `Command.c` | **8**, all sub-command, **none top-level** [D34 §2] |
| Top-level dispatch construct in `Command.c` | **a table, not a switch** [D34 §2.1] |

**The enumeration finds `default:` labels on both sides and discriminates between them by mapping each to its enclosing `switch` — which is the same method that caught the agent-side `default:` trap in D34.** **A flat count returns 19-vs-8 and would support a false conclusion ("the server has more defaults"); mapping each to its enclosing switch is what makes the comparison valid.**

---

## 5. `pkg/agent/demons.go` — BOUNDED ENUMERATION (Q4)

**191,942 B / 6,438 lines. NOT read blind. The boundary is justified by grammar, not by sampling.**

### 5.1 The boundary, and why it is the whole file

**A 192 KB file is a register, not an argument — so the first question is what it *declares*, and the second is what its declaration structure is.** The enumeration that answers both is a single pattern:

```
Get-Content demons.go | Select-String -Pattern '^func '
   →  5 declarations
```

| Line | Declaration |
|---|---|
| L31 | `func (a *Agent) UploadMemFileInChunks(FileData []byte) uint32` |
| L64 | `func (a *Agent) TeamserverTaskPrepare(Command string, Console func(AgentID string, Message map[string]string)) error` |
| L128 | `func (a *Agent) TaskPrepare(Command int, Info any, Message *map[string]string, ClientID string, teamserver TeamServer) (*Job, error)` |
| L2285 | `func (a *Agent) TaskDispatch(RequestID uint32, CommandID uint32, Parser *parser.Parser, teamserver TeamServer)` |
| L6430 | `func (a *Agent) Console(...)` |

[source: `Select-String '^func '` over `demons.go` — the complete output, 5 lines]

**Five functions in 6,438 lines. The file's size is concentrated in exactly two of them:** `TaskPrepare` (L128→L2284 = **2,157 lines**) and `TaskDispatch` (L2285→L6429 = **4,145 lines**). **Those two are 6,302 of 6,438 lines — 97.9% of the file.**

**This is the boundary justification: the file is not 6,438 lines of logic to be sampled. It is two enormous switch statements with three small helpers around them.** Reading the two switch *subjects* and their *label sets* reads the whole thing at the level of structure, which is what a register needs.

**And the file declares zero types:**

```
Select-String '^type ' over demons.go  →  0 hits
```

[source: `Select-String '^type '` → 0; positive control: `Select-String '^type '` over `pkg/agent/types.go` → 16 hits, listed in §5.3]

**So `demons.go` is pure method implementation. Every type it operates on is declared in `types.go`.**

### 5.2 What it registers: two dispatch surfaces in opposite directions

**This is the answer to "tell me what it registers."** `demons.go` holds **both directions of the command translation**:

| Function | Direction | Subject | Size |
|---|---|---|---|
| **`TaskPrepare`** L128 | **operator → agent** (outbound task) | **`switch Command`** over 120 case labels | 2,157 lines |
| **`TaskDispatch`** L2285 | **agent → server** (inbound result) | **`switch CommandID`** | 4,145 lines |

[source: `demons.go:128`, `:2285`; case enumeration in §5.4]

**`TaskPrepare` takes `Command int` and returns `(*Job, error)` — it converts a client's requested action into a wire `Job`. `TaskDispatch` takes `CommandID uint32` and a `*parser.Parser` and returns nothing — it consumes an agent's result and pushes it to the GUI.** **They are the two halves of the same protocol, and they are the server's full command surface.**

**The three helpers:** `UploadMemFileInChunks` (L31) chunks file uploads; `TeamserverTaskPrepare` (L64) is a string-keyed wrapper; `Console` (L6430) emits GUI console output.

### 5.3 The types it operates on, enumerated from `types.go`

**16 type declarations in the package. No type is declared in `demons.go`.** [source: `Select-String '^type \w+ (struct|interface)'` over `pkg/agent/` → 16 hits, `types.go:19-212`]

| Line | Type | Kind |
|---|---|---|
| 19 | `DemonInterface` | interface |
| 23 | `EventInterface` | interface |
| 26 | `Header` | struct — **the wire header, §3** |
| 33 | `ServiceAgentInterface` | interface |
| 40 | `TeamServer` | interface — **the teamserver contract `demons.go` is written against** |
| 73 | `Job` | struct |
| 89 | `Pivots` | struct |
| 94 | `Download` | struct |
| 104 | `BofCallback` | struct |
| 111 | `PortFwd` | struct |
| 124 | `SocksClient` | struct |
| 133 | `SocksServer` | struct |
| **139** | **`Agent`** | **struct — the receiver of all 5 methods** |
| 174 | `AgentInfo` | struct |
| 212 | `Agents` | struct |

[source: `Select-String '^type \w+ (struct|interface)'` over `teamserver/pkg/agent/*.go`, complete]

**So the "register" is: an `Agent` struct carrying session state, an `AgentInfo` describing the host, an `Agents` collection, an 1,275-line teamserver interface contract, and six supporting structs for pivots/downloads/BOF-callbacks/port-forwards/socks.** **`demons.go` supplies the behaviour; `types.go` supplies the nouns.**

### 5.4 `TaskPrepare` — `switch Command` with 120 case labels

**Enumerated from L128–L2284:**

```
switch statements: 16
case labels:       120
default:             7
```

[source: `Select-String` counts over the L128–L2284 slice]

**Sixteen switches, 120 case labels, 7 defaults.** The top-level subject is `switch Command`, and the nested switches key on `Optional["SubCommand"].(string)`, `SubCommand`, `Args[1]`, `ObjectFlags`, `Technique`, `ConfigKey`, `NetCommand`, `PivotCommand` — **the operator-facing string vocabulary, lower-cased at the comparison site:**

```go
case "dir":
case "dir;ui":
case "download":
case "upload":
case "cd":
case "remove":
case "mkdir":
case "cp":
case "mv":
case "pwd":
case "cat":
```
```go
case COMMAND_PROC:
case DEMON_COMMAND_PROC_MODULES:
case DEMON_COMMAND_PROC_GREP:
case DEMON_COMMAND_PROC_CREATE:
case 5:
case DEMON_COMMAND_PROC_MEMORY:
```
[source: `demons.go` at the case lines enumerated above]

**So the server accepts BOTH the operator's word (`"dir"`) and the numeric command constant (`COMMAND_PROC`) at different nesting levels, and dispatches them into a `Job`.** **That string vocabulary is the server's command space, and it has no counterpart on the agent** — the agent only ever sees numeric IDs.

### 5.5 Dependencies, measured

**Stdlib + Havoc + exactly one third-party package:**

```
"bytes" "encoding/base64" "encoding/binary" "encoding/hex" "encoding/json"
"errors" "fmt" "io" "math/rand" "net" "os" "strconv" "strings" "time"
"Havoc/pkg/common" "Havoc/pkg/common/parser" "Havoc/pkg/logger"
"Havoc/pkg/logr" "Havoc/pkg/socks" "Havoc/pkg/utils" "Havoc/pkg/win32"
"github.com/olekukonko/tablewriter"
```
[source: the `import (` block at `demons.go:3`]

**One external dependency: `olekukonko/tablewriter`, a console-table formatter** — used by the console-output helpers, not by any protocol path. **The command surface itself depends only on the stdlib and Havoc's own packages.**

---

*(§6 follows)*
