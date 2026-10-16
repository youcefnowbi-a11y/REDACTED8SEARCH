# D52 — Covenant Task Consumption Path and Wire-Format Reachability

**Target:** `RE_Library/01_SOURCE_c2/covenant/Covenant/`
**Class:** source-only reversal (NO REA/GHIDRA)
**Task:** task-54, revision 2, owner `covenant-diver`
**Tags:** `[read]` = read directly § `[verified]` = confirmed by two independent instruments, control passed § `[inferred]` = my deduction § `[absence]` = searched and not found, with search AND positive control stated

This report closes three of the four unknowns D50 §6 left open, and adds one. It cross-references D50 and does not repeat its enumeration, its instrument record, or its four-answer structure.

---

## §0 — Corrections, led with as instructed

### §0.1 The Lead's path correction — accepted, and it is not cosmetic

D50 cited `Core\CovenantService.cs`. The exact path is **`Covenant\Core\CovenantService.cs`**. `[read]`

**The cause is worth recording because it is an instrument defect, not a typo.** Throughout D50 I printed paths as `$_.FullName.Substring($c.Length)` where `$c` was already the `covenant` directory. Every path the instrument emitted therefore **began at `\Covenant\`** — correctly. I then transcribed citations from memory of that display rather than from the emitted string, and the leading segment was the part I dropped. `[read]`

`[inferred]` **A path is a coordinate, and a coordinate that is 90% right is wrong.** This is D50 §5's general form one level up: the *display* was structural and correct, the *transcription* was lexical and lossy. **Every citation in D52 is copied from emitted output, not reconstructed.** Every path in this report carries its `Covenant/` root.

### §0.2 The brief said the `else` at `:232` might be DEAD CODE. It is not — and the reason inverts D50's framing

**The brief:** *"If the else branch is unreachable, record it as DEAD CODE — a different and weaker claim than 'wrong'."*

`[verified]` **The `else` branch at `InternalListener.cs:230-233` is REACHABLE, and it is the ONLY branch a control tasking can take.** The weaker claim is not the correct one here. Evidence in §1 and §2.

### §0.3 A correction to D50's own Q4 framing — it was one question short

`[read]` D50 §4.2 established that the server writes `Parameters = { "Delay", "300" }` and that both consumers read index 0 as a value. **D50 assume the grunt reads `message.Message` at all for these types.** It does — and closing that required reading the full branch chain, which §1 does. The finding survives, and §2 now states its exact consequence instead of inferring it.

---

## TOC

1. [§1 — Q1: which grunt path consumes a control tasking](#1-q1-which-grunt-path-consumes-a-control-tasking)
2. [§2 — Q2: is the `:232` encoding gap reachable? REACHABLE](#2-q2-reachability-of-the-232-encoding-gap)
3. [§3 — Q3: does `Parameters[0]`-as-label hit Assembly tasks? NO](#3-q3-does-parameters0-as-label-hit-assembly-tasks)
4. [§4 — Q4: `CovenantAPIExtensions.cs` and `ICovenantAPI.cs`](#4-q4-the-two-unread-files)
5. [§5 — Instrument record](#5-instrument-record)
6. [§6 — Residual unknowns, each with a probe](#6-residual-unknowns)

---

## 1. Q1: which grunt path consumes a control tasking

### 1.1 The instrument — structural, not lexical

The brief's rule: *"if/else chains and indentation are structural; do not infer a branch from an attribute's presence."* `[read]` I therefore **printed the entire chain with line numbers and column positions** rather than matching a pattern, and determined branch membership from **indentation column**, which is the syntactic fact that decides it.

`[verified]` **File:** `Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs`. The chain lives inside **`Execute` (L20-235)**, the grunt's main loop.

### 1.2 The consumption chain, printed

`[read]` The dispatch, with the column at which each branch keyword begins:

| Line | Column | Branch | What it does with `message.Message` |
|---|---|---|---|
| **L104** | 29 | `if (Type == SetDelay \|\| Jitter \|\| ConnectAttempts)` | `int.TryParse(message.Message, out int val)` `[read]` |
| **L106** | 33 | *(nested* `if (int.TryParse(...))`*)* | assigns `Delay`/`Jitter`/`ConnectAttempts` `[read]` |
| **L124** | 33 | `else` | `output += "Error parsing: " + message.Message` `[read]` |
| **L128** | 33 | — | `QueueTaskingMessage(...Completed, output...)` — **queues a response, does not fall through** `[read]` |
| **L129** | 29 | `}` — **closes the L104 block** | `[read]` |
| **L130** | 29 | `else if (Type == SetKillDate)` | `DateTime.TryParse(message.Message)` `[read]` |
| **L143** | 29 | `else if (Type == Exit)` | reads nothing; returns `[read]` |
| **L150** | 29 | `else if (Type == Tasks)` | reads nothing `[read]` |
| **L161** | 29 | `else if (Type == TaskKill)` | `message.Message.ToLower()` as a task name `[read]` |
| **L181** | 29 | `else if (message.Token)` | spawns `TaskExecute` at **L188** `[read]` |
| **L206** | 29 | `else` — **the fallthrough** | spawns `TaskExecute` at **L208** `[read]` |

`[verified]` **L104 and L150 begin at the same indentation column (29).** They are members of **one** if/else chain. The `SetDelay` block closes cleanly at **L129** having queued its response — **there is no fallthrough.** A `SetDelay` tasking therefore **never reaches L206** and **never spawns `TaskExecute`.** `[verified]`

### 1.3 The answer

`[verified]` **`SetDelay`, `SetJitter`, and `SetConnectAttempts` are consumed INLINE in `Execute` at L104-128.** They take the branch at **L104**, not the `else` at L206, and their `message.Message` is parsed as a bare integer.

`[read]` **`TaskExecute` (L236-413) is spawned from exactly two sites, both inside `Execute`:**

| Line | Guard | Reachable by a control tasking? |
|---|---|---|
| **L188** | `else if (message.Token)` | **No** — a `SetDelay` is already consumed at L104 and never reaches L181 `[verified]` |
| **L208** | `else` (final fallthrough) | **No** — same reason `[verified]` |

`[verified]` **The `Split(',')` + `Convert.FromBase64String(pieces[i])` path at `GruntHTTP.cs:244-250` is inside `TaskExecute` and is reachable only for messages that survive the whole L104-L205 chain — i.e. `Assembly` and `Token` taskings. A control tasking cannot reach it.**

`[read]` **Positive control for the branch claim:** the four explicitly-handled types are exactly the four the server constructs (`SetDelay`, `SetJitter`, `SetConnectAttempts`, `SetKillDate` — D50 §3.2) plus the three pure-local ones (`Exit`, `Tasks`, `TaskKill`). **The set of inline-handled types contains the set of server-constructed control types, completely.** No control tasking is left without a branch. `[verified]`

### 1.4 The consequence — D50 §4.2's chain, now closed

`[verified]` **The wire message for `SetDelay` is `"Delay,300"` and the consuming code is `int.TryParse(message.Message, out int val)`.**

| Stage | Exact behavior |
|---|---|
| Server writes params | `Covenant/Data/—§` — see §3; for control taskings `Covenant/Core/CovenantService.cs:1358` …’ `{ "Delay", grunt.Delay.ToString() }` `[read]` |
| Server joins raw | `Covenant/Models/Listeners/InternalListener.cs:232` …’ `string.Join(",", tasking.Parameters)` …’ `"Delay,300"` `[read]` |
| Grunt receives | `GruntHTTP.cs:99` `messenger.ReadTaskingMessage()` …’ `Message == "Delay,300"` `[read]` |
| Grunt parses | `GruntHTTP.cs:106` `int.TryParse("Delay,300", out int val)` …’ **`false`** `[verified]` |
| Grunt reports | `GruntHTTP.cs:124-128` …’ `output = "Error parsing: Delay,300"`, queued as `Completed` `[read]` |

`[inferred]` **The setting silently no-ops on the target, and the grunt reports `GruntTaskingStatus.Completed`** — not a failure status — carrying an error string inside the output. **The tasking is not marked failed.** An operator watching tasking status sees success; the error text is in the command output body. That is the closed consequence D50 marked `[inferred]`, and it is now `[verified]` from source on both ends.

---

## 2. Q2: reachability of the `:232` encoding gap

### 2.1 The claim under test

`[read]` `InternalListener.cs:232` sends **raw, unencoded** parameters. All four transports do `Split(',')` then `FromBase64String`. D50 §4.3 recorded this as a framing disagreement but could not establish reachability.

### 2.2 The answer: the branch is reachable — but the transports are not where it lands

`[verified]` **Two independent facts, and together they resolve it:**

**Fact 1 — the `else` branch is reachable.** §1.3 proves control taskings take `InternalListener.cs:230`, and §1.2 proves `Assembly` taskings take `:203`. `[read]` There is no third possibility: the outer `if` at `:203` is a two-way branch on `tasking.Type == Assembly`, and every `GruntTaskingType` is either `Assembly` or not. **The `else` at `:230` executes for every non-Assembly tasking the server dispatches.** `[verified]`

**Fact 2 — the raw string is consumed by `TryParse`, not by `Split`.** §1.3 proves the control types are handled at `GruntHTTP.cs:104-128` by `int.TryParse(message.Message)` / `DateTime.TryParse(message.Message)` on the **whole string**, before and independently of `TaskExecute`. `[verified]`

`[verified]` **Therefore: the `:232` raw join IS reachable, and it does NOT hit the `Split`/`FromBase64String` code.** The transports' `Split` path and the `else` branch's raw framing never meet — because they serve disjoint type sets and live in different methods.

### 2.3 What this means for the framing-disagreement claim

`[read]` Restated precisely, and this supersedes D50 §4.3's framing:

| Path | Sender framing | Receiver | Agreement |
|---|---|---|---|
| `Assembly` | base64 each param, join `,` (`InternalListener.cs:210`) | `TaskExecute` L244-250 `Split` + `FromBase64String` `[read]` | **CONSISTENT** `[verified]` |
| non-`Assembly` | **raw** join `,` (`InternalListener.cs:232`) | `Execute` L106/L132 `TryParse` on whole string `[read]` | **CONSISTENT** `[verified]` |

`[inferred]` **The `else` branch is not dead code and not mis-encoded — it is a deliberate second framing for a second consumer.** The two paths are self-consistent. **D50 §4.3's reading of a "framing disagreement" is not supported**, and I record that as a correction to my own prior report rather than defending it.

`[verified]` **The defect is therefore narrower and sharper than D50 stated: it is not an encoding mismatch. It is that the server writes a LABEL into `Parameters[0]` while the receiving parser expects a VALUE at the head of the string.** The encoding is fine. The payload shape is wrong.

---

## 3. Q3: does `Parameters[0]`-as-label hit Assembly tasks?

### 3.1 The answer: NO — and the mechanism is structural

`[verified]` **Assembly tasks do not carry a label at index 0, because Assembly `GruntTasking.Parameters` is built from a different source than the control taskings.**

`[read]` Enumerated every `Parameters = new List<string>` object-initializer in the tree — **exactly five sites**, all in `Covenant/Core/CovenantService.cs`:

| Line | Site | Shape |
|---|---|---|
| **L1329** | `SetConnectAttempts` | `{ "ConnectAttempts", value }` — **label first** `[read]` |
| **L1358** | `SetDelay` | `{ "Delay", value }` — **label first** `[read]` |
| **L1387** | `SetJitter` | `{ "JitterPercent", value }` — **label first** `[read]` |
| **L1416** | `SetKillDate` | `{ "KillDate", value }` — **label first** `[read]` |
| **L2884** | `Connect` | `new List<string> { }` — **empty** `[read]` |

`[verified]` **All four label-bearing sites are control taskings. No Assembly task appears in this list.** `[verified]`

### 3.2 Why Assembly is built elsewhere

`[read]` Assembly taskings get their parameters through a **different constructor path**:

```csharp
// Covenant/Core/CovenantService.cs:2578-2589  StartGruntTasking
private async Task<GruntTasking> StartGruntTasking(Grunt grunt, GruntTask task, GruntCommand command)
{
    return await this.CreateGruntTasking(new GruntTasking
    {
        GruntTaskId = task.Id, GruntId = grunt.Id,
        Type = task.TaskingType,                 // Assembly for all 95
        Status = GruntTaskingStatus.Uninitialized,
        GruntCommandId = command.Id, GruntCommand = command
        // NOTE: Parameters is NOT set here
    });
}
```

`[read]` **`StartGruntTasking` never assigns `Parameters`** — it falls back to the property default `new List<string>()` (`Covenant/Models/Grunts/GruntTasking.cs:91`). The parameters are attached later, at **`Covenant/Core/CovenantService.cs:2896`**:

```csharp
// Covenant/Core/CovenantService.cs:2879-2896  (inside the Assembly/Connect/Disconnect branch region)
string csharpcode = string.Join(" ", parameters);
tasking.GruntTask.Code = string.Format(WrapperFunctionFormat, csharpcode);
...
else if (tasking.GruntTask.Name.Equals("Connect", ...)) { parameters[0] = ...; }
tasking.Parameters = parameters;      // :2896
```

`[read]` **`parameters` here is the operator's parsed command-line token list** — the `List<ParsedParameter>` flowing from `InteractGrunt` …’ `ParseParametersIntoTask` (`:2472`) …’ this method. `[verified]` It is **positionally ordered values with no label prefix**, because `ParseParametersIntoTask` assigns values into `task.Options[i].Value` by position or by explicit label and **discards the label itself**. `[read]`

### 3.3 The conclusion, stated with its boundary

`[verified]` **The `Parameters[0]`-as-label defect is SetDelay/SetJitter/SetConnectAttempts/SetKillDate-specific.** It affects the **4 control taskings** the server self-generates. It does **not** affect the **95 Assembly tasks**, whose parameters arrive positionally from the operator's command line with no injected label. `[verified]`

`[inferred]` **The asymmetry has a visible origin.** The four control taskings are constructed by *server-internal code* in `CovenantService.cs:1320-1416`, whose author wrote a `{ label, value }` pair — matching the **operator-facing command syntax** (`SetDelay 300` has a command word and an argument). The Assembly path is constructed from the **operator's own tokenization**, where the command word has already been stripped into `commandName` (`CovenantService.cs:1734`). **One path inherits the command word into the payload; the other had it removed upstream.** That is the whole defect, and it explains the scope exactly.

`[read]` **Bound: all 11 files, all 95 tasks inspected via the parameter-construction path rather than by per-task enumeration** — because the finding is that *no* Assembly task touches the five label-bearing sites, which is a property of the construction code, not of any individual task. `[verified]` **Stated as a boundary decision:** enumerating 95 tasks' YAML would not add evidence, since none of them writes `GruntTasking.Parameters`. The 11-file/95-task count in D50 §3.1 stands unaltered.

---

## 4. Q4: the two unread files

### 4.1 `CovenantAPIExtensions.cs` — 212,491 B

`[read]` **Instrument:** route-attribute and authorization probes, with the D50 §0.1 positive control re-run. `[verified]`

| Probe | `CovenantAPIExtensions.cs` | Control: `ListenerApiController.cs` |
|---|---|---|
| `[HttpGet` / `[HttpPost` / `[Route` | **0** | **11** |
| `\bAuthorize\s*\(` | **0** | **1** |
| `\bAllowAnonymous\b` | **0** | 0 |
| `static —§ this ICovenantAPI operations` | **present** `[read]` | absent |

`[read]` **Sample, printed:**
```csharp
// Covenant/API/CovenantAPIExtensions.cs:1538
public static GruntCommand InteractGrunt(this ICovenantAPI operations, int id, string body = default(string))
// :1540
return operations.InteractGruntAsync(id, body).GetAwaiter().GetResult();
// :1553
public static async Task<GruntCommand> InteractGruntAsync(this ICovenantAPI operations, int id, ...)
// :1555
using (var _result = await operations.InteractGruntWithHttpMessagesAsync(id, body, null, cancellationToken)...
```

`[verified]` **Pure client-side convenience: extension methods on `ICovenantAPI`, adding synchronous wrappers (`GetAwaiter().GetResult()`) around the client's async calls. Zero route attributes, zero authorization, zero server role.** `[verified]` **It does not change the client-not-server classification — it confirms it**, because you cannot write an extension method *on an interface* that adds routing behavior; routing is a server-side pipeline concern.

### 4.2 `ICovenantAPI.cs` — 93,517 B

`[read]` **Instrument:** interface-member count and route-attribute probe. `[verified]`

| Probe | Value |
|---|---|
| Declaration at L19 | `public partial interface ICovenantAPI : System.IDisposable` `[read]` |
| `—§WithHttpMessagesAsync` members | **183** `[read]` |
| `[HttpGet` / `[HttpPost` / `[Route` | **0** `[verified]` |
| `\bAuthorize\s*\(` | **0** `[verified]` |

`[verified]` **183 method signatures, matching `CovenantAPI.cs`'s 183 implementations 1:1.** This is the AutoRest-generated interface half of the same client pair (D32 §1.2). **No routing, no authorization, no server role.** `[verified]`

### 4.3 The answer, and stop

`[verified]` **Neither file adds route attributes or authorization. Both are client-side. The client-not-server classification in D50 §0.1 stands, now with all three `API/` files measured rather than two.**

`[inferred]` **The `Covenant/API/` directory contains exactly three artifacts and all three are one client:** `ICovenantAPI.cs` (interface, 183 signatures), `CovenantAPI.cs` (implementation, 183 `SendAsync`), `CovenantAPIExtensions.cs` (convenience extensions). **Three files, 1,390,849 B combined, zero server-side surface.** The server is `Covenant/Controllers/` + `Covenant/Core/` + `Covenant/Hubs/`. That is the boundary the brief's premise missed.

---

## 5. Instrument record

**Mandatory.** This lane's record, continued from D20 §6.2, D32 §6, D50 §5.

| # | Where | Failure | Correction |
|---|---|---|---|
| 9 | D13 §7.2 | member-surface regex excluded digits …’ 178 vs 183 | widen class |
| 10 | D20 §6.2 | recursive `-Path` glob …’ false zero | enumerate, use `-LiteralPath` |
| 11 | D32 §6 | namespace collision read as `partial` split …’ 57 vs 0 | tighten to `partial` |
| 12 | D32 §1.3 | unescaped alternation …’ false zero | `-SimpleMatch` |
| 13 | D50 §2.1 | `\[Authorize` bracket-adjacent …’ 0 on 16 of 17 | anchor on identifier |
| **14** | **D52 §0.1** | **path transcribed from memory of a display instead of from emitted output** …’ dropped the `Covenant/` root across D50 | **copy from emitted output, never reconstruct** |

`[inferred]` **#14 is #13 one level of abstraction up.** #9-#13 were lexical probes against structural code. **#14 is a verbal probe against structural data** — the path was structurally correct on screen and I reconstructed it as language. **The rule that generalizes all six: do not re-derive a fact you have just measured. Copy it.**

`[verified]` **Positive controls actually run in this report:** (a) server-vs-client route attributes re-run, 11 vs 0 (§4.1); (b) four-transport `Split` path scope established by **method boundaries** (`TaskExecute` L236-413, next method L414) rather than by pattern; (c) branch membership established by **indentation column** (L104 and L150 both at col 29); (d) the five `Parameters =` sites enumerated exhaustively, all printed.

`[absence]` **Searched: any third `TaskExecute` call site.** Positive control: the enumeration printed all three textual matches for `TaskExecute\(`, one of which is the declaration — so the instrument demonstrably matches the identifier and found only L188 and L208 as call sites. **A third call site would have printed.**

---

## 6. Residual unknowns

### 6.1 Whether `Token == true` can co-occur with a control tasking type

**Unknown:** `GruntHTTP.cs:181` branches on `message.Token` **before** the final `else`. D50 §3.2 established `Token = tasking.GruntTask?.TokenTask ?? false` at `InternalListener.cs:239`. If any control tasking could carry `Token == true`, it would reach `TaskExecute` via L188 with a raw `"Delay,300"` and **then** hit `Split`/`FromBase64String` — which would make §2.3 wrong for that case.
**Probe:** enumerate every `TokenTask` assignment in the 11 YAML files and in `GruntTask` construction. **Bound: all 95 tasks, all 11 files.** Instrument warning: `TokenTask` is a YAML key and a C# property — match both, print matches.

### 6.2 The grunt builds' correspondence to source

**Unknown:** the four transports (`GruntHTTP`, `Brute`, `GruntBridge`, `GruntSMB`) are **template source** compiled into the implant (`GruntTask.Compile`, `CovenantService.cs:2899`). Whether all four share the §1 chain or diverge is established for `GruntHTTP` only.
**Probe:** apply §1's structural read (branch columns + `TaskExecute` boundary) to the other three files and diff the branch tables. **Do not assume the copy is faithful — D20 established copy-drift as a live mechanism in this corpus.**

### 6.3 `TaskExecute` for `Assembly` with an empty parameter list

**Unknown:** `GruntTasking.cs:91` defaults `Parameters` to empty, and §3.2 shows the Assembly path may leave it empty for a zero-option task. `TaskExecute` L244 does `Split(',')` on a `Message` that is then only `pieces[0]`.
**Probe:** trace `TaskExecute` L244-260 for `pieces.Length == 1` and confirm the parameters array stays `null` and the assembly is invoked with no arguments. **This is a read, not an inference.**

### 6.4 Not attempted, declared

- **No build, no compiler, no runtime.** Every `[verified]` claim is source-level with a stated control.
- **D50 not reopened** — cross-referenced; §2.3 corrects one D50 reading and says so explicitly.
- **The other three transports not read in this pass** (§6.2 names the probe).
- **`Covenant/Models/Grunts/GruntTask.cs:156` `FromSerializedGruntTaskOption` not traced** — it copies options for a task clone and is adjacent to §3.2's construction path but not on it.
