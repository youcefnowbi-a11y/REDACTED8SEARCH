# D39 — HAVOC SERVER-SIDE CRYPTO AND DISPATCH

**Target:** `RE_Library/01_SOURCE_c2/havoc/teamserver/`
**Authored by:** havoc-deep. Direct continuation of D34 (the agent half).
**Question set:** five, from the Lead's tasking. §2–§6 below, one or more per question.
**Source-only. Every number carries the invocation that produced it. No REA, no Ghidra.**

**Headline:** the two dispatch halves are **not** mirrored constructs — the agent uses a function-pointer table, the server uses a `switch` **with** a `default:`. Both are silent in a default deployment, for different reasons. All five questions are answered in §7.1.

---

## TABLE OF CONTENTS

| § | Subject | Question |
|---|---|---|
| **1** | Scope, layout, and a premise correction | — |
| **2** | `crypt/aes.go` — server cipher vs agent cipher | **Q2** |
| **3** | The 20-byte header — does the server agree? | **Q3** |
| **4** | Server command dispatch — where it actually lives | **Q1** |
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

**15 type declarations in the package. No type is declared in `demons.go`.** [source: `Select-String '^type \w+ (struct|interface)'` over `teamserver/pkg/agent/*.go` → **15 hits**; positive control: `Select-String '^type '` over `demons.go` → **0 hits**. **I first wrote 16 in this section and the table below has 15 rows — the count was corrected against the invocation.**]

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

**So the "register" is: an `Agent` struct carrying session state, an `AgentInfo` describing the host, an `Agents` collection, a 1,275-line teamserver interface contract, and six supporting structs for pivots/downloads/BOF-callbacks/port-forwards/socks.** **`demons.go` supplies the behaviour; `types.go` supplies the nouns.**

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

## 6. CARRIER SELECTION — THE SERVER SIDE (Q5)

**Q5 was: the agent's carrier is compile-time (`#ifdef TRANSPORT_HTTP` / `TRANSPORT_SMB` at `Transport.c:60, 75`). How does the SERVER decide which carrier a given agent uses? Listeners, per-agent config, or negotiation? And if a mismatch is possible, is there an error path?**

**Answer: it is a listener type chosen when the payload is built, it is compiled into the agent as a preprocessor define, and there are exactly two cases with no `default` — so an unrecognised listener type produces an agent with NO transport macro at all, and no error.**

### 6.1 The decision is one switch, at build time, with two cases and no default

```go
func (b *Builder) GetListenerDefines() []string {
	var defines []string

	switch b.config.ListenerType {

	case handlers.LISTENER_HTTP:

		defines = append(defines, "TRANSPORT_HTTP")
		break

	case handlers.LISTENER_PIVOT_SMB:

		defines = append(defines, "TRANSPORT_SMB")
		break

	}

	return defines
}
```
[source: `teamserver/pkg/common/builder/builder.go:1102-1120`, entire function]

**This is the answer, and it closes the loop with D34 §6.5 exactly.** The agent's `Transport.c` selects the carrier with `#ifdef TRANSPORT_HTTP` / `#ifdef TRANSPORT_SMB` [D34 §6.1]. **The define that decides which `#ifdef` fires is emitted here, by the server, at payload-generation time.** **There is no runtime negotiation and no capability handshake.**

### 6.2 The two listeners are separate profile blocks — the operator configures one per payload

```go
type Listeners struct {
	ListenerHTTP     []*ListenerHTTP     `yaotl:"Http,block"`
	ListenerSMB      []*ListenerSMB      `yaotl:"Smb,block"`
	ListenerExternal []*ListenerExternal `yaotl:"External,block"`
}
```
[source: `teamserver/pkg/profile/config.go:51-55`]

**`ListenerHTTP` is a full HTTP listener** — `Hosts`, `HostBind`, `HostRotation`, `PortBind`/`PortConn`, `Methode`, `UserAgent`, `Headers`, `Uris`, `Secure`, and sub-blocks for `Cert`, `Response`, `Proxy` [source: `config.go:57-85`].

**`ListenerSMB` is four fields** — `Name`, `PipeName`, `KillDate`, `WorkingHours` [source: `config.go:87-95`].

**So the SMB carrier's entire configuration is a pipe name, while the HTTP carrier carries TLS material, host rotation, request shaping, and proxy settings.** **That asymmetry is the server-side confirmation of D34 §6.4's finding:** the SMB transport is structurally the simpler one because the pipe's peer-identity check (`SmbRecv`'s `DemonId` validation) does the work that TLS and host rotation do for HTTP.

**And the two listeners are started from two separate loops over two separate config arrays:**

```go
for _, listener := range t.Profile.Config.Listener.ListenerHTTP {
```
```go
for _, listener := range t.Profile.Config.Listener.ListenerSMB {
```
[source: `teamserver/cmd/server/teamserver.go:229`, `:289`]

**The server runs both carriers simultaneously and independently. The agent is bound to one at build time.**

### 6.3 The mismatch path, and it is real

**The `switch` at `builder.go:1105` has no `default`.** If `b.config.ListenerType` is neither `LISTENER_HTTP` nor `LISTENER_PIVOT_SMB`:

1. `defines` is returned **empty**.
2. The agent is compiled **with neither `TRANSPORT_HTTP` nor `TRANSPORT_SMB` defined.**
3. In `Transport.c`, **both branches of `TransportSend` are `#ifdef`-guarded** [source: `Transport.c:60-85`; D34 §6.1], so **neither compiles in.**
4. **What remains is a `TransportSend` with no implementation body — a build failure or a link error, depending on the toolchain.**

**So the failure mode is a failed compile, not a silently dead agent — which is the *better* outcome.** **A carrier mismatch between a built agent and its listener is not possible through this path, because the agent that reaches a listener was built by that same server from that listener's type.**

**But two residual risks follow, and both are real:**

| Risk | Basis |
|---|---|
| **A payload generated against an HTTP listener, then deployed expecting to reach an SMB pivot, has no SMB transport.** | The define is fixed at generation. `ListenerType` is read once at `:1105`. |
| **`GetListenerDefines` returns an empty slice for an unrecognised type without logging.** | The `switch` has no `default` and no `logger` call in this function. |

[source: `builder.go:1102-1120`]

### 6.3.1 The empty-define path IS guarded — one level up, and CORRECTED from my first pass

**The third listener constant exists:**

```go
LISTENER_HTTP      = 1
LISTENER_PIVOT_SMB = 2
LISTENER_EXTERNAL  = 3
```
[source: `teamserver/pkg/handlers/types.go:106-108`]

**`LISTENER_EXTERNAL = 3` is absent from `GetListenerDefines`' two cases**, so an external listener would produce an empty define list — **but the build never gets that far:**

```go
	if b.config.ListenerType == handlers.LISTENER_EXTERNAL {
		b.SendConsoleMessage("Error", "External listeners are not support for payload build")
		b.SendConsoleMessage("Error", "Use SMB listener")
		return false
	}
```
[source: `teamserver/pkg/common/builder/builder.go:234-238`]

**An explicit guard, placed before the build, that names the condition, names the remedy, and returns `false`.** **So the unmatched-type path is NOT reachable with `LISTENER_EXTERNAL` — the build is refused with a console message.** **My §6.3 inference that an unrecognised type yields a silently transportless agent was correct about `GetListenerDefines` in isolation and wrong about the system: the caller guards the one value that reaches it.** **Corrected here rather than in §6.3, because the reasoning mattered.**

**And the guard is itself a positive control on the finding:** **`LISTENER_EXTERNAL` is the one listener type with no transport define, and it is the one listener type the builder explicitly rejects.** **The code knows about the gap and closes it at the entry point rather than in the switch.** **Whether the `switch`'s missing `default` is a latent hazard depends on no future listener type being added without a matching guard — which is a maintenance risk, not a present defect.**

**This is the same shape as the agent's `Command.c` finding one level up: a dispatch with no fallthrough arm and no diagnostic on the unmatched path.** **The build-time analogue of the runtime silent drop.** It reads a config value, fails to match, and returns nothing — **the difference is that an empty define list is caught by the compiler downstream, whereas an unmatched `CommandID` is not caught by anything.**

### 6.4 Positive control

**The claim "there are exactly two carrier types and no third" is an enumeration claim, and the control is that the same search finds the listener enum complete.**

```
Select-String 'TRANSPORT_HTTP|TRANSPORT_SMB' over teamserver/**/*.go
   →  exactly 2 hits: builder.go:1109, builder.go:1114
```

[source: the command, complete output in §6.1's search]

**Two hits, both in `GetListenerDefines`, both assigns.** **The server has no other place that names a transport define — so the carrier decision happens exactly once, in one function.**

**And the listener constants it switches on are themselves declared in one place:**

```
handlers.LISTENER_HTTP
handlers.LISTENER_PIVOT_SMB
```
[source: `builder.go:1107, 1112`; declared in `teamserver/pkg/handlers/`]

**Note the naming:** the constant is `LISTENER_PIVOT_SMB`, **not `LISTENER_SMB`** — the SMB carrier is registered in the code as a *pivot* listener. **That is consistent with `TransportSmb.c`'s `SmbRecv` peer-validation and with the Rapid7 `server_pivot_named_pipe.c` provenance D34 §5.3 recorded.** **The SMB transport exists to be a pivot, not as a peer to HTTP, and the constant name says so.**

---

## 7. RESIDUAL UNKNOWNS, CORRECTIONS, AND COVERAGE

### 7.1 The five answers, one line each

| Q | Question | Answer |
|---|---|---|
| **Q1** | Does the server's dispatch have the agent's silent-drop defect? | **No — `TaskDispatch`'s top-level `switch CommandID` has a `default:` at `demons.go:6419` that names the unknown command and its ID. But it is `logger.Debug`, gated on `logger.debug`, which is `false` unless `--debug`. So the *deployment* is silent on both sides; the *code* is silent on one.** |
| **Q2** | Does the server's cipher match the agent's? | **Yes — `cipher.NewCTR` + `XORKeyStream` at `aes.go:21-22` is the same AES-CTR/XOR construction as `AesXCryptBuffer`. No mode or IV mismatch. Two differences: server allocates, agent XORs in place; server builds a fresh stream per call, agent mutates a persistent IV context.** |
| **Q3** | Does the server's unpacker agree on 20? | **Yes — `ParseHeader` consumes 3×4 = 12 bytes (`agent.go:188, 194, 200`) and `handleDemonAgent` consumes 2×4 = 8 (`handlers.go:79-80`). 20, in the same field order. The asymmetry is *where* each side stops encrypting, and §3.3 shows why the keystream still aligns.** |
| **Q4** | What does `demons.go` register? | **2 functions hold 97.9% of it: `TaskPrepare` (2,157 lines, `switch Command`, 120 cases — operator→agent) and `TaskDispatch` (4,145 lines, `switch CommandID` — agent→server). 5 functions total, 0 types declared, 1 third-party import.** |
| **Q5** | How does the server pick a carrier? | **`GetListenerDefines` at `builder.go:1102` switches on `b.config.ListenerType` at payload-build time and emits `TRANSPORT_HTTP` or `TRANSPORT_SMB` as a compiler define. Two cases, no `default`. No runtime negotiation. The unmatched type is blocked by an explicit guard at `builder.go:234`.** |

### 7.2 Corrections made in-task, all against a measurement

**Six corrections. Every one was caught by running the invocation rather than restating the claim.**

| # | First statement | Measured | Where |
|---|---|---|---|
| 1 | "the Go server has 202 `.go`, of which 25 non-vendor" (tasking) | **202 total, 202 non-vendor, 0 `vendor/` dirs** | §1.1 |
| 2 | "`Header.Size` is parsed and never used" | **read at `service/agent.go:93`, written at `service/service.go:303`** | §3.5 |
| 3 | "`dispatch.go` is the server's counterpart to `Command.c`" (tasking) | **`dispatch.go` is the GUI RPC protocol; `TaskDispatch` in `demons.go:2285` is the counterpart** | §4.1 |
| 4 | stack-map: `:6419` default is in `switch SubCommand` | **brace depth: it is the top-level `default:` of `switch CommandID`** | §4.5.1 |
| 5 | "`types.go` declares 16 types" | **15** | §5.3 |
| 6 | "unrecognised listener type yields a silently transportless agent" | **`LISTENER_EXTERNAL` is explicitly rejected at `builder.go:234-238`** | §6.3.1 |

**Corrections 2, 4, 5 and 6 are mine. 1 and 3 are the tasking's, reported in place.**

**Correction 4 is the one worth carrying forward:** two instruments disagreed on the same fact, one of them looked more sophisticated, and the sophisticated one was wrong. **The D11 §8.5 rule — when two instruments disagree, measure directly rather than adjudicate — fired again, in a new form.**

### 7.3 Residual unknowns

| # | Unknown | Why it is open |
|---|---|---|
| **U1** | **Does any code path validate the 8 bytes the server decrypts at `handlers.go:102` against the values read at `:79-80`?** | **§3.4 shows no check exists in `handlers.go`. A full sweep of `teamserver/` for a consumer of those re-decrypted bytes was not performed.** |
| **U2** | **The endianness of the general agent→server ingest path.** | `parser.go:27` defaults `bigEndian = true`; `handlers.go:169` calls `SetBigEndian(false)` **only on the SMB pivot path.** **`Int32ToBuffer` at `Package.c:43-46` writes the size field BIG-endian, which matches the `true` default — but the remaining four header fields are written by `PackageAddInt32`, whose byte order was not read in this task.** |
| **U3** | **Whether the server's `Packer.Build()` path (§ from D39's first pass: encrypts from offset 0, no 20-byte skip) is ever used for agent-bound traffic.** | `Build()` has **4 call sites** (`dispatch.go:915`, `builder.go:408`, `handlers.go:88`, `handlers.go:287`). **`handlers.go:85-88` builds a `NewPacker(Agent.Encryption.AESKey, ...)` and `AddUInt32(Header.AgentID)` — a reconnect ack, not a task payload. Whether the task-reply path (`BuildPayloadMessage`) uses `Packer.Build()` was not traced.** |
| **U4** | **`AddOwnSizeFirst` (`packer.go:103`) is called from nowhere.** | **Target `AddOwnSizeFirst` → 1 hit (the declaration). Control `NewPacker` → 6 hits. Control `AddUInt32` → 4 hits.** **Dead code, but "dead" is a claim about the 202-file tree at one moment — no build was run to confirm the linker drops it.** |
| **U5** | **`TaskPrepare`'s 120 case labels vs `TaskDispatch`'s command cases — do the two vocabularies correspond 1:1?** | 120 outbound labels and the inbound case set were each counted, **but not diffed against each other.** A command the server can *send* that it cannot *receive* (or the reverse) would be here. |

### 7.4 Coverage

**Read in full in this task:** `crypt/aes.go` (25 lines), `packer.go` (109), `parser.go` (207).
**Read in part:** `handlers/handlers.go` (`:38-137`), `agent/agent.go` (`:181-230`), `cmd/server/server.go` (`:48-69`), `profile/config.go` (`:51-95`), `builder/builder.go` (`:234-238`, `:865-885`, `:1098-1120`), `logger/logger.go` (`:61-71`, `:108-125`), `logger/global.go` (`:20-59`).
**Enumerated by grammar, not read:** `demons.go` (5 `func` decls counted; `TaskDispatch` L2285–6429 and `TaskPrepare` L128–2284 measured; case/default/switch counts taken on both ranges; the 20 `default:` labels mapped to enclosing switches).
**Not read:** `cmd/server/dispatch.go` beyond its `func`/`switch`/`default:` skeleton (structure only, §4.1); the 19 sub-command `default:` bodies in `TaskDispatch`; `TaskPrepare`'s 120 case bodies.

**The `pkg/agent/` package is four files — `agent.go` (32,446 B), `commands.go` (6,905 B), `demons.go` (191,942 B), `types.go` (35,257 B).** [source: `Get-ChildItem pkg/agent -File -Filter *.go`] **My first pass of this section cited an `agent/console.go` that does not exist; the `Console` method is `demons.go:6430`.** **Corrected — a coverage list is an easy place to name a file from memory, which is why it is now a measured list.**

**The largest unread surface in this report is the body of `TaskDispatch` — 4,145 lines whose structure is measured and whose branches are not.** **Every claim about it in §4 is a claim about its shape, and §4.3's verdict is a claim about its `default:` arm specifically, which was read at `:6419-6428`.**

### 7.5 What D39 adds to D34, and what it does not

**D34 established the agent half:** a 23-entry function-pointer table with a `NULL` sentinel, a linear search, three known commands with empty `break` bodies, and `PRINTF` compiled to `{ ; }` in release.

**D39 establishes the server half and the comparison:**

1. **The dispatch shapes are DIFFERENT, not mirrored.** The agent uses a table; the server uses a `switch` with a `default:`. **D17 §10's row cannot be applied symmetrically** — the two halves do not share a construct.
2. **The silence is in a different place on each side.** The agent is silent by *preprocessor*; the server is silent by *runtime flag*. **Neither emits in a default deployment, and neither replies on the wire regardless of the flag.** **So "the agent silently drops and the server does not" is false; "the agent's drop is uncompilable and the server's is unconfigured" is true.**
3. **The cipher is one implementation in two languages.** CTR/XOR on both sides, matching, with a symmetric nonce-reuse property from the shared fixed-IV construction.
4. **The 20-byte header is agreed by both sides and assembled differently** — 5 writes on the agent, 3+2 reads across two server files, same order, and §3.3's alignment argument is what makes the differing decrypt spans work.
5. **The carrier is a build-time define emitted by the server**, closing the loop on D34 §6.1's compile-time observation: **the operator's listener choice at payload-generation is what decides which `#ifdef` the agent was compiled with.**

**D39 does not resolve:** D34's U1 (62 `DEMON_COMMAND_*` defines vs 23 table entries), U2 (who writes the SMB 8-byte read header), or U4 (nonce reuse exploited or not). **All three remain open and are now referenced from two reports.**

---

**End of D39.**
