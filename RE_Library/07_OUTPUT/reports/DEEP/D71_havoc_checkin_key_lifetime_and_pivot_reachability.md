# D71 — HAVOC CHECKIN KEY LIFETIME AND PIVOT REACHABILITY

**Closes D65 P-1, P-2, P-3, P-4.**
**Artifact:** `teamserver/` Go sources and `payloads/Demon` C sources.
**Method:** pure source read. No REA, no Ghidra, no execution.
**Write scope:** this file only. D47 and D56 were not touched.

---

## §0 — WHAT THIS IS, AND TWO CORRECTIONS

### 0.1 What was open

| D65 residual | Question | Section |
|---|---|---|
| **P-2** | Is `handlers.go:193` genuinely dead, and is its inverted guard a bug or a broken guard? | §1 |
| **P-4** | Does `UpdateLastCallback` mutate key state? | §2 |
| **P-1** | Is the inner `AgentHdr.AgentID` bound to the outer session — can a pivot **address** another agent's key material? | §3 |
| **P-3** | Is `PivotPush`'s length field validated before allocation? | §4 |

### 0.2 Correction 1 — read-access and addressability were conflated in D65

**D65 §3 answered "is the exposure cross-agent?" with NO, and the proof was that the pivot chain is sound: each layer is encrypted under a distinct agent's key, so a relay cannot read the payload inside the layer addressed to it.**

**That is a proof about READ-ACCESS. It says nothing about ADDRESSABILITY.**

**Addressability is a different property:** **can a pivot cause the server to select a *different* agent's key material for a decrypt, by naming that agent in the inner header?** **D65's chain argument does not touch this question, and this report answers it separately (§3).**

**The distinction matters because the gate at `demons.go:5356` is `AgentHdr.MagicValue == DEMON_MAGIC_VALUE` — a constant.** **A constant cannot authenticate anything. It establishes the header is *well-formed*, not that it is *authorized*.** [source: `demons.go:5356`, verbatim in D65 §1.1]

### 0.3 Correction 2 — P-3's premise was wrong, and I caught it mid-investigation

**D65's P-3 asked whether `PivotPush`'s length is "validated against the actual payload before allocation," on the assumption that the reader might be consuming a prefix the writer never wrote.**

**That assumption was wrong.** **The writer does write a length prefix — at the package layer, not in `PipeWrite`.** **`Package.c:246` back-patches it:**

```c
    Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );
```
[source: `payloads/Demon/src/core/Package.c:246`, and the identical statement at `:377` in `PackageTransmitAll`]

**So `Pivot.c:265`'s `+ sizeof( UINT32 )` is *correct* — it accounts for the 4 bytes it just consumed.** **The reader and writer agree. This is the opposite of D47 §3's `SmbRecv` defect, where the reader's field names were exchanged.**

**The answer to P-3 was therefore "no, the length is not validated" — but for a different reason than the residual anticipated, and §4 states it precisely.**

### 0.4 The depth convention

**Carried forward per the Lead's standing rule.** **This report counts no nesting depths.** **It is stated anyway because the convention must be declared in anything that counts, and a file should not be exempt on the grounds that its counts happen not to be depth-based.**

---

## §1 — Q1: IS `handlers.go:193` DEAD?

### 1.1 The containing function and its callers

**`handlers.go:193` is inside `handleDemonAgent`:**

```go
func handleDemonAgent(Teamserver agent.TeamServer, Header agent.Header, ExternalIP string) (bytes.Buffer, bool) {
```
[source: `teamserver/pkg/handlers/handlers.go:56`]

**Its callers, enumerated:**

```
pkg\handlers\handlers.go:43   return handleDemonAgent(Teamserver, Header, ExternalIP)
pkg\handlers\handlers.go:56   func handleDemonAgent(...)
```
[source: `Get-ChildItem teamserver -Recurse -File -Filter *.go | Select-String 'handleDemonAgent'` — 3 hits, one of which is a comment at `:50` and one the definition]

**One real call site, `:43`.** **The function is not dead by declaration.**

### 1.2 Every exit from the loop containing `:193`

**The loop is `handlers.go:162-215`. Its exits:**

| Line | Exit | Condition |
|---|---|---|
| `:179` | `break` | `CommandID != agent.COMMAND_PIVOT && CommandID != 0` |
| `:185` | `break` | `PivotInstance != nil` |
| `:205` | `continue` | `SubCommandID == agent.DEMON_PIVOT_SMB_COMMAND` |
| `:210` | `break` | `SubCommandID != DEMON_PIVOT_SMB_COMMAND` |
| `:215` | loop back | none of the above |

**`:193` is between `:185` and `:205`.** **The only way to reach it is `:184` evaluating false.** [source: `handlers.go:162-215`, read in full at D65 §2.3]

### 1.3 The verdict: dead-by-structure, with a live crash path

**`:184 if PivotInstance != nil { break }` exits when the instance IS found.** **`PivotInstance` was assigned unconditionally at `:183`.** **Therefore `:193` executes if and only if `:183` returned nil — and at that moment `:193` dereferences nil.**

**This is dead-by-structure, not dead-by-observation.** **The function has a live caller (§1.1); the guard is what makes `:193` unreachable with a valid pointer.** **D65 P-2 was right, and Q1's framing corrects one thing about it: it is not "dead code" in the harmless sense. `:193` is an unreachable *decrypt* wrapped around a *reachable* panic.**

**The reason `:193` can be reached at all is that nil is possible.** **`PivotAgentID` at `:158` is read from `job[j].Data[1].(uint32)` — a server-internal value the teamserver itself put there when queueing the pivot job:**

```go
	AgentID, err = strconv.ParseInt(a.NameID, 16, 32)
	...
	PivotJob = Job{
		Command: COMMAND_PIVOT,
		Data: []interface{}{
			DEMON_PIVOT_SMB_COMMAND,
			uint32(AgentID),
			Packer.Buffer(),
		},
	}
```
[source: `teamserver/pkg/agent/agent.go:757-778`]

**`PivotAgentID` names an agent that existed when the job was queued.** **It becomes nil at the lookup if that agent was removed in the interval — `PivotRemove` at `Pivot.c:139` and the disconnect path null the record.** **So the panic is reachable whenever a pivot agent is unlinked between job queueing and this handler running.** [source: `handlers.go:183` assigns, `:184` breaks on non-nil, `:193` dereferences]

### 1.4 Is the inverted guard a bug or a deliberate-but-broken guard?

**Deliberate-but-broken, and the shape is diagnostic.** **The two statements read:**

```go
								/* get an instance of the pivot */
								PivotInstance = Teamserver.AgentInstance(PivotAgentID)
								if PivotInstance != nil {
									break
								}
```
[source: `handlers.go:182-186`, verbatim]

**The pattern — assign, then test, then `break` — is what a *guard* looks like.** **A guard against a nil instance would be `if PivotInstance == nil { break }`, after which the code below can safely dereference.** **The author wrote the opposite operator.**

**Reading the surrounding intent: `:188 /* parse the task from the parser */` and `:191 /* create a new parse for the parsed task */` and `:193`'s decrypt all assume a valid `PivotInstance`.** **The decrypt at `:193` is written as if the pointer is guaranteed non-nil.** **So the code below the guard was written for the `!= nil` branch while the guard exits on `!= nil`.** **The guard is broken, not vestigial: the author intended `== nil`.**

**This makes it a latent crash, not dead code.** **The decrypt never runs; the dereference can.** [source: `:182-193` read in full]

---

## §2 — Q2: DOES `UpdateLastCallback` TOUCH KEY STATE?

### 2.1 The function, in full — it is four lines

```go
func (a *Agent) UpdateLastCallback(Teamserver TeamServer) {
	a.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")
	Teamserver.AgentUpdate(a)

	Teamserver.AgentLastTimeCalled(a.NameID, a.Info.LastCallIn, a.Info.SleepDelay, a.Info.SleepJitter, a.Info.KillDate, a.Info.WorkingHours)
}
```
[source: `teamserver/pkg/agent/agent.go:739-744`, verbatim]

### 2.2 The answer

**No. It touches no key state.**

**Every field written is a timestamp or a sleep parameter:** **`a.Info.LastCallIn` at `:740`; then `AgentLastTimeCalled` at `:743` receives `LastCallIn`, `SleepDelay`, `SleepJitter`, `KillDate`, `WorkingHours`.**

**Zero occurrences of `Encryption` in the function body.** **The single mutation of agent state is the `LastCallIn` string assignment.** [source: `agent.go:739-744`, the function is 6 lines including signature and closing brace and was read in full]

### 2.3 What it does downstream, for completeness

**`Teamserver.AgentUpdate(a)` at `:741` persists the record — and that is the path that reaches `db/agents.go:98`'s 25-column `UPDATE`, which includes `AESKey = ?, AESIv = ?`.** **That write re-persists the same value the field already holds.** **It is not a rotation: the DB write takes `agent.Encryption.AESKey` as an input, it does not produce one.** [source: D56 §4.1, `db/agents.go:113-114`, which base64-encodes the struct field for the write]

### 2.4 Effect on the census

**The one-assignment-site census stands.** **D65 §2.1 enumerated 24 occurrences of `Encryption.(AESKey|AESIv)` with exactly two adjacent writes (`demons.go:2372-2373`).** **`UpdateLastCallback` — read in full here — is not a 25th occurrence and not a third write.** [source: `agent.go:739-744`, no `Encryption` token present]

---

## §3 — Q3: ADDRESSABILITY, STATED SEPARATELY FROM READ-ACCESS

### 3.1 The two properties, named

**Read-access:** *can a pivot obtain the plaintext protected by another agent's key?*
**D65 answered NO.** **The chain is sound: each layer is encrypted under a distinct agent's key, and a relay holds only its own.** [source: D65 §3.3, resting on `agent.go:748` / `:789` / `:810`]

**Addressability:** *can a pivot cause the server to select another agent's key material for a decrypt, by naming that agent?*

**The answer to the second is also no — and the reason is a check that exists, which is stronger than the "no check exists" answer the question anticipated.**

### 3.2 Every use of the inner ID, enumerated

**The inner header's ID is `AgentHdr.AgentID`, parsed at `agent.go:200`. Every occurrence tree-wide:**

```
pkg\agent\demons.go:5225  if teamserver.AgentExist(AgentHdr.AgentID) {
pkg\agent\demons.go:5227  DemonInfo = teamserver.AgentInstance(AgentHdr.AgentID)
pkg\agent\demons.go:5229  Message["MiscData"] = fmt.Sprintf("%v;%x", a.NameID, AgentHdr.AgentID)
pkg\agent\demons.go:5233  if DemonInfo.Pivots.Parent.Pivots.Links[i].NameID == fmt.Sprintf("%08x", AgentHdr.AgentID) {
pkg\agent\demons.go:5253  DemonInfo = ParseDemonRegisterRequest(AgentHdr.AgentID, AgentHdr.Data, "")
pkg\agent\demons.go:5359  PivotAgent = teamserver.AgentInstance(AgentHdr.AgentID)
pkg\agent\demons.go:5384  Message["Message"] = fmt.Sprintf("Can't process output for %x: Agent not found", AgentHdr.AgentID)
```
[source: `Get-ChildItem teamserver -Recurse -File -Filter *.go | Select-String 'AgentHdr\.AgentID'` — 7 hits; `:5229` and `:5384` are strings]

### 3.3 The relationship check that exists — `:5233`

**One site performs a real binding test, and it is the pivot CONNECT path (`DEMON_PIVOT_SMB_CONNECT`), not the command path:**

```go
									// if agent exist then just retrieve the instance by agent id
									if teamserver.AgentExist(AgentHdr.AgentID) {

										DemonInfo = teamserver.AgentInstance(AgentHdr.AgentID)
										Message["MiscType"] = "reconnect"
										Message["MiscData"] = fmt.Sprintf("%v;%x", a.NameID, AgentHdr.AgentID)

										if DemonInfo.Pivots.Parent != nil {
											for i := range DemonInfo.Pivots.Parent.Pivots.Links {
												if DemonInfo.Pivots.Parent.Pivots.Links[i].NameID == fmt.Sprintf("%08x", AgentHdr.AgentID) {
													DemonInfo.Pivots.Parent.Pivots.Links = append(DemonInfo.Pivots.Parent.Pivots.Links[:i], DemonInfo.Pivots.Parent.Pivots.Links[i+1:]...)
													break
												}
											}
										}

										DemonInfo.Active = true
										DemonInfo.Reason = ""
										DemonInfo.Pivots.Parent = a

										a.Pivots.Links = append(a.Pivots.Links, DemonInfo)
										teamserver.LinkAdd(a, DemonInfo)
```
[source: `teamserver/pkg/agent/demons.go:5224-5245`, verbatim]

**`:5233` compares a link's `NameID` to the inner ID's hex form.** **And `:5242` `DemonInfo.Pivots.Parent = a` is the operation that *establishes* the parent relationship — `a` being the outer agent.** **So the connect path, when it runs, sets up `DemonInfo.Pivots.Parent` pointing at the outer agent.**

### 3.4 Why the command path at `:5359` is nonetheless safe — the LinkAdd argument

**`:5359` calls `AgentInstance(AgentHdr.AgentID)` with no comparison against the outer agent.** **The safety comes from a different place: `PivotAddJob` queues the job on a specific parent, and the server only accepts the result through a chain it established.**

**`agent.go:813` `pivots.Parent.JobQueue = append(pivots.Parent.JobQueue, PivotJob)` — the job is queued on the *outermost parent*, and that parent is the agent that will relay it back.** **`LinkAdd` at `:5245`/`:5257` is the only thing that creates a link, and it is driven by the connect path.** [source: `agent.go:746-814` and `demons.go:5231-5245`]

**So the addressability question resolves as: the inner ID names which agent's record is used for the decrypt, and that record's link to the outer agent was established at connect time by `:5242` — not re-verified at `:5359`.**

### 3.5 The answer

**Addressability: NO — but the reason is a trust chain established at connect, not a check at the command site.**

**The precise statement:** **`:5359` performs no comparison between `AgentHdr.AgentID` and the outer session.** **The relationship that makes the decrypt correct is `DemonInfo.Pivots.Parent = a`, set once at `demons.go:5242` during `DEMON_PIVOT_SMB_CONNECT`.** **The command path relies on that prior state and does not re-establish or re-verify it.**

**This is a real gap in defence-in-depth, and it is not a live read-access defect.** **A pivot cannot read another agent's payload (D65 §3).** **A pivot also cannot *usefully* address another agent's key material, because the bytes it forwards are encrypted under that agent's key, which it does not possess — so mis-addressing yields a decryption failure, not disclosure.**

**The residual is therefore:** **`:5359` trusts `:5242`'s prior state without restating the invariant.** **If the link topology can change between connect and command — `Pivot.c:302` `PivotRemove` removes links — then the decrypt at `:5373` uses whatever `AgentHdr.AgentID` names, validated only by the link state that `:5242` last set.** **Carried as residual A-1.** [source: `demons.go:5359` has no comparison; `:5242` sets the parent; `Pivot.c:302` removes]

---

## §4 — Q4: IS `PivotPush`'s LENGTH VALIDATED BEFORE ALLOCATION?

### 4.1 The reader, verbatim

```c
                if ( Instance->Win32.PeekNamedPipe( TempList->Handle, NULL, 0, NULL, &BytesSize, NULL ) )
                {
                    if ( BytesSize >= sizeof( UINT32 ) )
                    {
                        if ( Instance->Win32.PeekNamedPipe( TempList->Handle, &Length, sizeof( UINT32 ), NULL, &BytesSize, NULL ) )
                        {
                            Length = __builtin_bswap32( Length ) + sizeof( UINT32 );
                            Output = Instance->Win32.LocalAlloc( LPTR, Length );

                            if ( Instance->Win32.ReadFile( TempList->Handle, Output, Length, &BytesSize, NULL ) )
                            {
                                Package = PackageCreate( DEMON_COMMAND_PIVOT );
                                PackageAddInt32( Package, DEMON_PIVOT_SMB_COMMAND );
                                PackageAddBytes( Package, Output, BytesSize );
```
[source: `payloads/Demon/src/core/Pivot.c:259-272`, verbatim]

### 4.2 The writer, and why there IS a prefix

**`PipeWrite` writes from offset 0 and prepends nothing:**

```c
BOOL PipeWrite(
    IN  HANDLE   Handle,
    OUT PBUFFER Buffer
) {
    DWORD Written = 0;
    DWORD Total   = 0;

    do {
        if ( ! Instance->Win32.WriteFile( Handle, Buffer->Buffer + Total, MIN( ( Buffer->Length - Total ), PIPE_BUFFER_MAX ), &Written , NULL ) ) {
            return FALSE;
        }

        Total += Written;
    } while ( Total < Buffer->Length );

    return TRUE;
}
```
[source: `payloads/Demon/src/core/Win32.c:1202-1218`, verbatim]

**But the length is written one layer up, into offset 0 of the buffer:**

```c
    Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );
```
[source: `payloads/Demon/src/core/Package.c:246`, and identically at `:377`]

**`Int32ToBuffer` writes a big-endian `UINT32` at `Package->Buffer` — offset 0.** **So the package on the pipe starts with its own length.** **`Pivot.c:265`'s `+ sizeof( UINT32 )` is correct: it consumed a 4-byte length and adds it back to size the full frame.** [source: `Package.c:39 Int32ToBuffer` definition, `:246` the call, `Pivot.c:265` the read]

**`PIPE_BUFFER_MAX` is `0x10000`** [source: `payloads/Demon/include/core/Transport.h:8`], **which bounds `PipeWrite`'s per-call chunk, not the declared length.**

### 4.3 The answer

**The length is not validated. It is *derived* from the wire and trusted.**

**`Length` at `:263` is a `PeekNamedPipe` read of the pipe's first 4 bytes — i.e. the sender's declared package length.** **`:265` byte-swaps it and adds 4.** **`:266` allocates exactly that many bytes.** **Nothing compares the declared length to `BytesSize` — the total actually available, which the first `PeekNamedPipe` at `:259` populated.**

**The one check that exists is at `:261`: `BytesSize >= sizeof( UINT32 )`.** **That guarantees at least 4 bytes are readable, so the second peek cannot over-read.** **It does not bound `Length`.** [source: `:259-266`]

**Caveat that limits severity, stated because it is measured:** **the throughput here is a pipe between cooperating agent processes, and the declared length is produced by `Package.c:246` from a real `Package->Length`.** **A malformed length requires a non-conforming writer on the pipe — which `Pivot.c:298`'s `ERROR_BROKEN_PIPE` path and `Pivot.c:87`'s `PivotParseDemonID` both contemplate, so the pipe is not treated as fully trusted by the surrounding code.** [source: `Pivot.c:87`, `:298`]

**So: no length validation, and the surrounding code does not assume the peer is well-formed.** **Carried as residual A-2 — severity is a runtime question this report does not answer.**

---

## §5 — RESIDUAL UNKNOWNS, WITH PROBES

| ID | Unknown | Probe |
|---|---|---|
| **A-1** | **Can the link topology change between `DEMON_PIVOT_SMB_CONNECT` (which sets `DemonInfo.Pivots.Parent = a` at `:5242`) and a later `:5359` lookup, such that `AgentHdr.AgentID` names an agent not linked to the outer session?** §3.5 states `:5359` re-verifies nothing. | Read `PivotRemove` (`Pivot.c:139-205`) and `LinkAdd` side-by-side, and check whether a `Pivots.Parent` can be reassigned without a new connect. **Enumerate every write to `.Pivots.Parent`.** |
| **A-2** | **Can `Pivot.c:263`'s peek be driven to a `Length` exceeding available bytes, and what does `LocalAlloc` do with it?** | Reconstruct a conforming writer and compute the achievable `Length`. **Source-only achievable: state which writer site could emit a mismatched `[0..3]`.** |
| **A-3** | **Whether `handlers.go:193`'s panic has ever fired** — §1.3 establishes reachability given a removal race, not its probability. | No source probe. **Requires runtime observation; out of this report's reach.** |
| **A-4** | **`Command.c:2586`'s `PipeWrite` call writes `Data.Length` bytes, while a package-shaped writer writes `Package->Length`. Whether these two writer populations produce the same `[0..3]` field.** §4.2 shows the package path sets it at `:246`; the `Command.c` path writes a raw `BUFFER`. | Read `BUFFER` construction at `Command.c:2560-2563` and determine whether `Data.Buffer` was ever given a length prefix. **Adjacent to D65's P-3, newly visible.** |

---

## §6 — INSTRUMENT FAILURES

**Failure 1 — P-3's premise was wrong, and I caught it only by reading the writer.** D65's P-3 hypothesised that `Pivot.c:265`'s `+ sizeof(UINT32)` might be reading a prefix the writer never wrote — the D47 §3 shape. **Enumerating every `__builtin_bswap32` and `Int32ToBuffer` call tree-wide found `Package.c:246` back-patching the length at offset 0.** **The reader is correct and the two agree.** **Had I written the report from the residual's premise I would have published a false defect.** **Root cause: a residual is a hypothesis, and this one was inherited rather than re-tested.**

**Failure 2 — Q1's "dead code" framing would have been wrong.** **`:193` is not dead code; it is an unreachable decrypt wrapped around a reachable dereference.** **The distinction only appeared when I checked whether `PivotAgentID` could be nil, which required reading `agent.go:757-778` to learn it is server-internal rather than wire-supplied.** **The Lead's dead-by-structure / dead-by-observation split is what forced the check.**

**Failure 3 — I nearly answered Q3 with the wrong argument.** **My first instinct was the D65 chain argument — "each layer has its own key, so a pivot can't read another's payload."** **That answers read-access. Addressability asks whether the *selection* of key material can be influenced.** **Caught by the Lead's framing in the task description, which named the two properties separately.** **The correct answer turned out to have a different shape than either expectation: a real check exists, at `:5233`, but on the connect path rather than the command path.**

**Failure 4 — the depth convention is stated in §0.4 for a report that counts no depths.** **This is intentional repetition of a rule that is now corpus-wide, not an oversight.** **Recorded so the pattern is visible: the convention is stated every time, including where it has no effect.**

**Net: four failures. Failure 1 would have produced a false defect; Failure 3 would have produced a wrong answer to the report's primary question; Failure 2 would have misdescribed the report's own finding.**

---

## §7 — WHAT THIS CHANGES

**All four D65 residuals are closed.**

| Residual | Answer | Basis |
|---|---|---|
| **P-2** | **Dead-by-structure**, not dead-by-observation — `handleDemonAgent` has a live caller (`:43`), and `:184`'s inverted guard is what makes `:193` unreachable with a valid pointer. **The guard is a deliberate-but-broken check: the author intended `== nil`.** **A latent crash, not dead code.** | §1 |
| **P-4** | **No key mutation.** `UpdateLastCallback` (`agent.go:739-744`) writes only `LastCallIn` and calls `AgentLastTimeCalled`. **The one-assignment-site census stands.** | §2 |
| **P-1** | **Addressability: NO — but via a trust chain, not a check at the site.** `:5359` compares nothing; the relationship is set once at `:5242` during connect. **Read-access was already refuted by D65 §3. The two properties are now stated separately.** | §3 |
| **P-3** | **The length is not validated — it is derived from the wire and trusted.** `Pivot.c:266` allocates the declared value with only a `>= 4` lower bound at `:261`. **But the reader is correct, not buggy: `Package.c:246` writes the prefix it consumes.** | §4 |

**No contradiction with D47, D56, or D65 was found.** **D65 §3's read-access conclusion is unmodified; §3 of this report adds the addressability property it did not test.**

---

**End of D71.**
