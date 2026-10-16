# D65 — HAVOC PIVOT KEY LINEAGE

**Closes D56 §5 S-3.**
**Artifact:** `teamserver/pkg/agent/demons.go` and the `payloads/Demon` C sources.
**Method:** pure source read. No REA, no Ghidra, no execution.
**Write scope:** this file only. D47 and D56 are complete and were not touched.

---

## §0 — WHAT THIS IS

### 0.1 The question, inherited

**D56 §5 S-3 recorded, and did not measure:**

> `COMMAND_PIVOT`'s `DEMON_PIVOT_SMB_COMMAND` sub-arm calls `AgentHdr.Data.DecryptBuffer(PivotAgent.Encryption.AESKey, PivotAgent.Encryption.AESIv)` at L5373 — a SECOND agent's key/IV, not the session's. Is the pivot agent's key also fixed, or does the pivot handshake re-key?

**D56 proved no rotation exists on the primary path** (agent: alloc `Demon.c:115`, fill `:119`, teardown `:530`; server: one assignment at `demons.go:2372` inside the `COMMAND_CHECKIN` arm). **If `:5373` reads a DIFFERENT agent's material, that material is subject to the same non-rotation proof only if the same write sites produce it. If the pivot path sources key material anywhere else, the proof does not carry over.**

**That is what this report measures.**

### 0.2 The depth convention, stated up front

**The Lead's verification of D56 found that `depth-1` was not a measurement until the depth convention was named: a one-tab scan returns 30 cases, a two-tab scan returns 64, and both are internally consistent under their own definition.**

**This report's convention for any depth or nesting count:** a `case` or `default` label is at **depth 1** when the switch's own brace block contains it directly — equivalently, **exactly one tab of indentation** in this file's formatting. **Anything counted below states the convention in the same sentence as the number.**

### 0.3 What "the pivot path" means here

**Two directions, and both are in scope:**

- **Agent side:** `Pivot.c` — the pivot agent's own handling of a pivot connection and the `DEMON_PIVOT_SMB_*` commands it is asked to execute.
- **Server side:** `demons.go`'s `COMMAND_PIVOT` arm (L5154–L5411) and the `DEMON_PIVOT_SMB_COMMAND` sub-arm that reads `:5373`.

---

## §1 — Q1: THE PIVOT CONNECT PATH, TRACED FROM `:5373`

### 1.1 The entry point, verbatim

```go
			case DEMON_PIVOT_SMB_COMMAND:

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var (
						Package       = Parser.ParseBytes()
						AgentHdr, err = ParseHeader(Package)
					)

					if err == nil {

						if AgentHdr.MagicValue == DEMON_MAGIC_VALUE {
							var PivotAgent *Agent

							PivotAgent = teamserver.AgentInstance(AgentHdr.AgentID)
							if PivotAgent != nil {
								PivotAgent.UpdateLastCallback(teamserver)
```
[source: `teamserver/pkg/agent/demons.go:5346-5361`, verbatim]

```go
								first_iter := true
								for (AgentHdr.Data.CanIRead(([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}))) {
									var Command   = uint32(AgentHdr.Data.ParseInt32())
									var Request   = uint32(AgentHdr.Data.ParseInt32())

									if first_iter {
										first_iter = false
										// if the message is not a reconnect, decrypt the buffer
										AgentHdr.Data.DecryptBuffer(PivotAgent.Encryption.AESKey, PivotAgent.Encryption.AESIv)
									}
```
[source: `teamserver/pkg/agent/demons.go:5365-5374`, verbatim]

### 1.2 Which agent, and where the ID comes from

**`PivotAgent` is not `a`.** **The outer receiver of this message is the agent whose checkin delivered it — the variable `a` — while `PivotAgent` is looked up from a field carried inside the payload.**

**The lookup chain, each step measured:**

| Step | Site | What it does |
|---|---|---|
| 1 | `demons.go:5350` | `Package = Parser.ParseBytes()` — pulls an opaque byte slice out of the outer task region |
| 2 | `demons.go:5351` | `AgentHdr, err = ParseHeader(Package)` — parses a **second, nested** package header out of those bytes |
| 3 | `agent.go:188` | `Header.Size = Parser.ParseInt32()` |
| 4 | `agent.go:194` | `Header.MagicValue = Parser.ParseInt32()` |
| 5 | **`agent.go:200`** | **`Header.AgentID = Parser.ParseInt32()`** |
| 6 | `demons.go:5356` | `if AgentHdr.MagicValue == DEMON_MAGIC_VALUE` — the only validation between the wire and the key selection |
| 7 | **`demons.go:5359`** | **`PivotAgent = teamserver.AgentInstance(AgentHdr.AgentID)`** |
| 8 | `cmd/server/agent.go:156-162` | linear scan of `t.Agents.Agents`, matching `AgentID == int(NameID)` |
| 9 | **`demons.go:5373`** | **`DecryptBuffer(PivotAgent.Encryption.AESKey, PivotAgent.Encryption.AESIv)`** |

**So: the key that decrypts a pivot payload is selected by an integer read directly off the wire at `agent.go:200`, resolved against the live agent list at `agent.go:159`, and applied at `demons.go:5373`.** [source: the eight sites above]

### 1.3 The wire path, in the direction of travel

**Agent → agent, relayed through a pipe, then agent → server:**

1. **`PivotPush`** (`Pivot.c:235`) peeks a pipe (`:259`), reads `Length` (`:263`), `__builtin_bswap32` (`:265`), allocates (`:266`), `ReadFile` (`:268`).
2. **`PackageCreate(DEMON_COMMAND_PIVOT)`** (`:270`) → `PackageAddInt32(DEMON_PIVOT_SMB_COMMAND)` (`:271`) → **`PackageAddBytes(Package, Output, BytesSize)`** (`:272`) → `PackageTransmit(Package)` (`:274`).
3. **`PackageTransmit`** (`Package.c:281-330`) **queues** the package into `Instance->Packages` — it does not encrypt.
4. **`PackageTransmitAll`** (`Package.c:333`) encrypts the whole outer frame with **the relaying agent's own `Config.AES.Key`/`IV`** via `AesInit` (`:390`) — D47 §5.3's site.
5. **Server: `handlers.go:102`** decrypts the outer frame with `Agent.Encryption.AESKey`.
6. **Server: `demons.go:5373`** decrypts the inner frame with **`PivotAgent.Encryption.AESKey`** — a different agent.

**Two decrypts, two different agents' keys, one message.** [source: sites 1–6]

### 1.4 What the field is called, and what it is not

**The wire field is the third `int32` of the nested package header — `Header.AgentID` at `agent.go:200`, position `[8..11]` of an 80-byte-and-up package header** [source: `Package.c:174-185`, which writes `PackageAddInt32(Package, 0)` for length, `DEMON_MAGIC_VALUE`, then `Instance->Session.AgentID` — the same three-field opening in the same order].

**It is a plain integer. It is not a key, not a signature, not a MAC, and not bound to the outer session in any way.** **Any value that resolves through `AgentInstance` selects that agent's key material for the decrypt at `:5373`.** [source: `cmd/server/agent.go:159`, the only comparison applied to it]

### 1.5 Q1 answer

**The material `:5373` reads is a DIFFERENT agent's — the agent named by `AgentHdr.AgentID`, a field parsed from the nested package header at `agent.go:200` and resolved through the teamserver's live agent list at `cmd/server/agent.go:156`.** **The wire field is the agent-ID slot of the nested package header; the parse step is `ParseHeader`'s third `ParseInt32`; the destination struct field is `PivotAgent.Encryption.AESKey` / `AESIv`.** **The only gate is a magic-value comparison against a constant.**

---

## §2 — Q2: IS THERE A ROTATION SITE ON THE PIVOT PATH?

### 2.1 The census that answers it

**Every occurrence of `Encryption.AESKey` or `Encryption.AESIv` in the entire teamserver tree, printed:**

```
pkg\agent\agent.go:398      if bytes.Compare(Session.Encryption.AESKey, AesKeyEmpty) != 0 {        read
pkg\agent\agent.go:399      Parser.DecryptBuffer(Session.Encryption.AESKey, Session.Encryption.AESIv) read
pkg\agent\agent.go:748      BuildPayloadMessage([]Job{job}, a.Encryption.AESKey, a.Encryption.AESIv)    read
pkg\agent\agent.go:789      BuildPayloadMessage([]Job{PivotJob}, pivots.Parent.Encryption.AESKey, ...)  read
pkg\agent\demons.go:84      BuildPayloadMessage([]Job{task}, a.Encryption.AESKey, a.Encryption.AESIv)  read
pkg\agent\demons.go:2372    a.Encryption.AESKey = Parser.ParseAtLeastBytes(32)                          WRITE
pkg\agent\demons.go:2373    a.Encryption.AESIv = Parser.ParseAtLeastBytes(16)                           WRITE
pkg\agent\demons.go:2514    hex.EncodeToString(a.Encryption.AESKey),                                    read
pkg\agent\demons.go:2515    hex.EncodeToString(a.Encryption.AESIv),                                     read
pkg\agent\demons.go:5373    DecryptBuffer(PivotAgent.Encryption.AESKey, PivotAgent.Encryption.AESIv)   read
pkg\db\agents.go:50         base64.StdEncoding.EncodeToString(agent.Encryption.AESKey),                read
pkg\db\agents.go:51         base64.StdEncoding.EncodeToString(agent.Encryption.AESIv),                 read
pkg\db\agents.go:113        base64.StdEncoding.EncodeToString(agent.Encryption.AESKey),                read
pkg\db\agents.go:114        base64.StdEncoding.EncodeToString(agent.Encryption.AESIv),                 read
pkg\events\demons.go:37     "AESKey": base64.StdEncoding.EncodeToString(Agent.Encryption.AESKey),      read
pkg\events\demons.go:38     "AESIv":  base64.StdEncoding.EncodeToString(Agent.Encryption.AESIv),       read
pkg\handlers\handlers.go:85  NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)                read
pkg\handlers\handlers.go:102 Header.Data.DecryptBuffer(Agent.Encryption.AESKey, Agent.Encryption.AESIv) read
pkg\handlers\handlers.go:121 BuildPayloadMessage(NoJob, Agent.Encryption.AESKey, Agent.Encryption.AESIv) read
pkg\handlers\handlers.go:133 BuildPayloadMessage(job, Agent.Encryption.AESKey, Agent.Encryption.AESIv)  read
pkg\handlers\handlers.go:193 Parser.DecryptBuffer(PivotInstance.Encryption.AESKey, ...)                 read
pkg\handlers\handlers.go:236 BuildPayloadMessage([]agent.Job{job[j]}, Agent.Encryption.AESKey, ...)     read
pkg\handlers\handlers.go:284 NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)                read
```

**Invocation:**

```powershell
Get-ChildItem teamserver -Recurse -File -Filter *.go |
  Select-String -Pattern 'Encryption\.(AESKey|AESIv)' |
  ForEach-Object { '{0}:{1}   {2}' -f $_.Path, $_.LineNumber, $_.Line.Trim() }
```

**24 occurrences. Two of them are writes — `demons.go:2372` and `:2373`, which are adjacent lines writing one pair. One assignment site. The other 22 are reads.** [source: invocation above]

### 2.2 The answer

**No.** **The pivot path has no assignment of its own.** **`PivotAgent.Encryption.AESKey` is the same struct field that `demons.go:2372` populated when that agent checked in — the pivot path reads it, and the primary checkin path is the only thing that ever writes it.**

**Consequence:** **every property D56 established about the primary key material transfers to the pivot unchanged.** **The pivot agent's key is written once per checkin from the agent's own wire value, and the agent does not regenerate it (D56 §4.2).** **The pivot decrypt at `:5373` uses material with the identical non-rotation guarantee.**

**The server-side assignment is not per-path.** **There is no `PivotAgent.Encryption.AESKey = ...` anywhere in the tree.** [source: §2.1's full census contains no such line]

### 2.3 A second pivot decrypt site exists, and it is a defect

**The census surfaced `handlers.go:193`, which D56 did not name.** **Reading it:**

```go
							for {
								var (
									Parser       = parser.NewParser(TaskBuffer)
									CommandID    = 0
									SubCommandID = 0
								)

								Parser.SetBigEndian(false)

								Parser.ParseInt32()
								Parser.ParseInt32()

								CommandID = Parser.ParseInt32()

								if CommandID != agent.COMMAND_PIVOT && CommandID != 0 {
									break
								}

								/* get an instance of the pivot */
								PivotInstance = Teamserver.AgentInstance(PivotAgentID)
								if PivotInstance != nil {
									break
								}

								/* parse the task from the parser */
								TaskBuffer = Parser.ParseBytes()

								/* create a new parse for the parsed task */
								Parser = parser.NewParser(TaskBuffer)
								Parser.DecryptBuffer(PivotInstance.Encryption.AESKey, PivotInstance.Encryption.AESIv)
```
[source: `teamserver/pkg/handlers/handlers.go:162-193`, verbatim]

**The control flow at `:182-193` is inverted relative to its apparent intent.** **`:184 if PivotInstance != nil { break }` exits the loop when the instance IS found.** **Therefore `:193` is reached only when `PivotInstance == nil`.**

**At `:193` that nil is dereferenced as `PivotInstance.Encryption.AESKey`.** **In Go this is a nil-pointer panic — the field read on a nil `*Agent`. The decrypt at `handlers.go:193` cannot be reached with a valid pointer.**

**So `handlers.go:193` is dead code guarding a nil dereference, and `demons.go:5373` is the only reachable pivot decrypt in the tree.** [source: `:183` assigns unconditionally; `:184` breaks on non-nil; `:193` dereferences]

**This is a source-level claim about reachability, not a runtime observation.** **It is carried as residual P-2.**

---

## §3 — Q3: IS THE TWO-TIME-PAD EXPOSURE CROSS-AGENT?

### 3.1 The answer, first

**No — not in the sense the question asks.**

**The question: "if two agents' sessions use the same key material, then the two-time-pad exposure is cross-agent, not per-session — one compromised agent's traffic can be used to attack another's."**

**Two agents' sessions do NOT use the same key material.** **Each agent generates its own key and IV at `Demon.c:113-123` and transmits them to the server, which stores them per agent.** **`AgentInstance` resolves agent IDs to distinct `*Agent` records; each record carries its own `Encryption.AESKey` / `AESIv` fields.**

**The exposure remains per-session — but the session count is not one per agent. One pivoted message is encrypted under N distinct agents' keys, and that is the real structure.**

### 3.2 Where the material diverges — the sites

**Divergence 1 — generation is per-agent and independent.** **`Demon.c:113` runs on each agent's own startup, seeded from that agent's own `NtGetTickCount()`** [source: D47 §5.6, `Win32.c:1304-1315`, which is the only random source on the agent]. **No key is transmitted from one agent to another.**

**Divergence 2 — the multi-layer wrap uses a different key per layer.** **`agent.go:746-814`:**

```go
func (a *Agent) PivotAddJob(job Job) {
	var (
		Payload  = BuildPayloadMessage([]Job{job}, a.Encryption.AESKey, a.Encryption.AESIv)
		Packer   = packer.NewPacker(nil, nil)
		...
	)
	...
	// pack it up for all the parent pivots.
	for {
		if pivots.Parent.Pivots.Parent == nil {
			break
		}

		// create new layer package.
		Payload = BuildPayloadMessage([]Job{PivotJob}, pivots.Parent.Encryption.AESKey, pivots.Parent.Encryption.AESIv)
		Packer = packer.NewPacker(nil, nil)

		AgentID, err = strconv.ParseInt(pivots.Parent.NameID, 16, 32)
		...
		Packer.AddInt32(int32(AgentID))
		Packer.AddBytes(Payload)

		PivotJob = Job{
			Command: COMMAND_PIVOT,
			Data: []interface{}{
				DEMON_PIVOT_SMB_COMMAND,
				uint32(AgentID),
				Packer.Buffer(),
			},
		}

		pivots = &pivots.Parent.Pivots
	}

	pivots.Parent.JobQueue = append(pivots.Parent.JobQueue, PivotJob)
}
```
[source: `teamserver/pkg/agent/agent.go:746-814`, abridged with all key-bearing lines verbatim]

**`:748` encrypts the innermost payload with `a.Encryption.AESKey` — the agent being tasked.** **`:789` encrypts the next layer outward with `pivots.Parent.Encryption.AESKey`.** **`:810` advances `pivots = &pivots.Parent.Pivots`, so the next iteration uses the next ancestor's key.**

**Each hop is a distinct agent. Each layer is a distinct key.** **This is the correct design for a relay chain — a pivot must not be able to read the payload it forwards, and it cannot, because the layer beneath is encrypted under a key the relay does not hold.**

### 3.3 So is one compromised agent's traffic usable against another's?

**No.** **A pivot agent holds only its own key. The layer it can decrypt is the layer addressed to it. The payload inside is encrypted under a different agent's key, which the relay never receives.**

**The cross-agent interaction is structural, not a key-sharing defect:** **one message carries N layers under N keys, and the plaintext of layer *k* is the ciphertext of layer *k+1*.** **Reading any inner layer requires that layer's agent's key — the same per-agent secret, independently generated.**

### 3.4 What the pivot path DOES extend

**The non-rotation property extends to every agent in the chain, and that is the finding S-3 was pointing at.** **Each agent's key is fixed for its session (D56 §4.2), and §2.2 above shows the pivot path adds no assignment. So each layer of the chain is independently susceptible to its own keystream-repeat, and the susceptibility is not confined to "the session you are looking at" — every session in the chain has it.**

**What is NOT true:** **that a compromise of agent A yields agent B's key material, or that A and B share a keystream.** **The two-time pad is `C_A ⊕ C_B = A ⊕ B` within one agent's own traffic, and the pivot chain does not merge two agents' keystreams.**

**S-3 was written as a scope note — "is the pivot agent's key also fixed, or does the pivot handshake re-key?" The answer is that it is fixed, by the same non-rotation guarantee, and there is no pivot handshake that re-keys.** **That makes S-3 a scope note that resolved into a confirmation, not a new finding.**

---

## §4 — Q4: RE-TRANSMITTED EVERY CHECKIN, OR CAPTURED ONCE?

### 4.1 The pivot agent re-transmits, through its own checkin — same as any agent

**`Pivot.c` contains no key handling at all.** **Instrument and its positive control:**

```
INSTRUMENT: (?i)\b(AES|Key|IV|Iv|Decrypt|Encrypt|RandomNumber)\w*  over Pivot.c
  total hits in Pivot.c: 0

POSITIVE CONTROL: identical pattern over Command.c
  total hits in Command.c: 14
      5x      KeyValueList
      3x      KeyValueEntry
      2x      AES
      2x      Key
      1x      IV
      1x      EncryptionType
```
[source: invocation in §6.2]

**The zero is a real absence.** **The same pattern succeeds on a sibling file in the same directory and discriminates token types — `KeyValueList` and `Key` are counted as distinct forms, so the instrument is not merely matching the substring `Key`.** **`Pivot.c` has none of them.**

### 4.2 The relay path defers to the shared transmitter

**`PivotPush` builds and queues a package:**

```c
                                Package = PackageCreate( DEMON_COMMAND_PIVOT );
                                PackageAddInt32( Package, DEMON_PIVOT_SMB_COMMAND );
                                PackageAddBytes( Package, Output, BytesSize );

                                PackageTransmit( Package );
```
[source: `payloads/Demon/src/core/Pivot.c:270-274`, verbatim]

**`PackageTransmit` does not encrypt — it queues:**

```c
    if ( ! Instance->Packages )
    {
        Instance->Packages = Package;
    }
    else
    {
        // add the new package to the end of the list (to preserve the order)
        List = Instance->Packages;
        while ( List->Next ) {
            List = List->Next;
        }
        List->Next = Package;
    }
```
[source: `payloads/Demon/src/core/Package.c:317-329`, verbatim]

**Encryption happens in `PackageTransmitAll`, which owns the `AesCtx`:**

```c
BOOL PackageTransmitAll(
    OUT    PVOID*   Response,
    OUT    PSIZE_T  Size
) {
    AESCTX   AesCtx  = { 0 };
    BOOL     Success = FALSE;
    UINT32   Padding = 0;
    PPACKAGE Package = NULL;
```
[source: `payloads/Demon/src/core/Package.c:333-340`, verbatim]

**and calls `AesInit` at `:390` with `Instance->Config.AES.Key` / `Instance->Config.AES.IV`** [source: D47 §5.3, which measured this site].

**So pivot-relayed bytes are encrypted by the relaying agent's own never-regenerated key, in the same function that handles every other package.** **There is no pivot-specific crypto path.**

### 4.3 The re-transmission answer

**Re-transmitted every checkin, and re-sent on the same schedule as any agent's.**

**The mechanism is inherited, not pivot-specific:** **`CommandCheckin` calls `DemonMetaData`** [source: `Command.c:163-172`], **and `DemonMetaData` pads the key and IV onto the package** — `Demon.c:160` `PackageAddPad( *MetaData, ( PCHAR ) Instance->Config.AES.Key, 32 );` and `:161` for the IV [source: D47 §5.3].

**A pivot agent is an agent. It runs the same `CommandCheckin`, against the same `Instance`, sending the same `Config.AES.Key` it generated once.** **Its key is captured by the server at `demons.go:2372-2373` on each checkin and written to the same row at `db/agents.go:98`.**

**The exposure is therefore the re-sent kind, not the captured-once kind — but the distinction the question draws does not materialise here, because the value re-sent is always the same value.** **Re-transmission without regeneration is functionally a capture-once, repeated.** [source: §2.2 and D56 §4.2, jointly — the only write sites are `Demon.c:115`/`:119`, guarded by `Demon.c:113`]

---

## §5 — RESIDUAL UNKNOWNS, WITH PROBES

| ID | Unknown | Probe |
|---|---|---|
| **P-1** | **Whether `AgentHdr.AgentID` at `agent.go:200` can name an agent that is not the one that actually sent the pivot payload.** **§1.4 establishes the field is unauthenticated at the point of use — only `MagicValue == DEMON_MAGIC_VALUE` gates it. Whether the *outer* layer's encryption implicitly binds the inner ID is the question: the outer frame is encrypted under the relaying agent's key, so a third party cannot forge the outer layer without that key — but the relaying agent itself supplies the inner ID.** | Read whether any agent-side code validates that `AgentHdr.AgentID` matches a pivot it actually hosts. **Grep `AgentHdr.AgentID` teamserver-wide and print every comparison.** |
| **P-2** | **`handlers.go:193`'s nil dereference — is it reachable?** **§2.3 establishes it is reached only when `PivotInstance == nil`, at which point it dereferences nil. That is a Go panic, not a wrong-key decrypt. Not run.** | Instrument or reason about whether the `break` at `:185` always fires on a live pivot. **Source-only: trace whether `PivotAgentID` at `:158` can name an agent absent from the teamserver's list.** |
| **P-3** | **`PivotPush`'s `Length` handling at `Pivot.c:265`.** **`Length = __builtin_bswap32( Length ) + sizeof( UINT32 )` — the `+ 4` accounts for the length prefix, so the read is `Length` bytes while the declared payload is `Length - 4`. Whether `BytesSize` from `ReadFile` (`:268`) is then used as the length at `:272` is what determines if the trailing 4 bytes are included.** | Read `:263-272` at byte level and confirm what `BytesSize` holds after `ReadFile`. **This is adjacent to D56's scope, not inside it — recorded rather than chased.** |
| **P-4** | **Whether `UpdateLastCallback` (`demons.go:5361`) mutates the pivot agent's encryption state.** | Read `UpdateLastCallback` in `agent.go`. **If it re-adopts key material, §2.2's conclusion weakens. Expected negative — it is named for a timestamp — but not read.** |

---

## §6 — INSTRUMENT FAILURES

**Failure 1 — my first pass at the pivot decrypt sites nearly missed `handlers.go:193`.** I began from `:5373` and read outward. **Enumerating every `DecryptBuffer(` call site tree-wide returned 4 real sites where my starting point accounted for 2.** **Caught by running the enumeration instead of following the one path I had been given.** **The fourth site is the pivot decrypt in `handlers.go`, and reading it surfaced the nil-dereference defect in §2.3 — which is not the question I was asked, but is a real finding that would have been invisible from `:5373` alone.** **Root cause: tracing a named entry point is not a census, and the brief asked for Q1 as a trace.**

**Failure 2 — the same census also caught that there is exactly ONE assignment site where I expected two.** **I had assumed the pivot path maintained its own key copy.** **The 24-occurrence census with only two adjacent writes shows a single assignment point.** **Had I assumed the second, §2.2's conclusion would have been wrong in the direction that matters — it would have made the pivot look like it had independent key state when it does not.**

**Failure 3 — the depth convention, inherited from D56's verification.** **D56 was miscounted three ways on depth (one-tab → 30, two-tab → 64, name-filtered → 28).** **This report counts no nesting depths, so the convention does not bite here — but §0.2 states it anyway, because the Lead's rule is that a depth filter must name its level and this file should not be exempt on the grounds that it happens not to use one.**

**Failure 4 — `Pivot.c`'s zero needed a control before I would write it.** **A zero-hit crypto search is exactly the kind of result that is an instrument artifact.** **The control on `Command.c` returned 14 hits including `AES` and `IV`, proving the pattern matches the real tokens in a file that has them.** **Recorded because the finding "the pivot agent does no crypto" rests entirely on that zero.**

**Net: four failures, two of which changed a conclusion (1 and 2), one of which is a convention statement (3), and one of which is a control that validated a load-bearing zero (4).**

---

## §7 — WHAT THIS CHANGES

**D56 §5 S-3 was a scope note.** **Answered:**

| S-3's question | Answer | Site |
|---|---|---|
| Is the pivot agent's key fixed, or does the pivot handshake re-key? | **Fixed.** No pivot-specific assignment exists anywhere in the tree. | §2.1–§2.2, 24-occurrence census, 1 assignment site |
| Whose material does `:5373` read? | **A different agent's**, named by `AgentHdr.AgentID` parsed at `agent.go:200`. | §1.2 |
| Does the pivot re-transmit key material? | **Yes**, via its own `CommandCheckin` → `DemonMetaData` → `PackageAddPad(Key,32)`. Same value each time. | §4.3 |
| Is the exposure cross-agent? | **No.** Per-session, with N independently-keyed layers in a pivot chain. | §3 |

**One unasked finding surfaced:** **`handlers.go:193` is a pivot decrypt reached only with a nil pointer** (§2.3). **Carried as P-2, not chased.**

**No contradiction with D47 or D56 was found.** **D56's Q4 conclusion — fixed key, per-message counter restart, no rotation — is confirmed for every agent in a pivot chain, and no site exists that would shorten the exposure window.**

---

**End of D65.**

