# D50 — Covenant API Surface and Task Library

**Target:** `RE_Library/01_SOURCE_c2/covenant/Covenant/`
**Class:** source-only reversal (NO REA/GHIDRA)
**Task:** task-39 filename `D50_covenant_api_and_task_library.md`
**Tags:** `[read]` = read directly · `[verified]` = confirmed by two independent instruments, control passed · `[inferred]` = my deduction · `[absence]` = searched and not found, with search AND positive control stated

---

## §0 — What this is, and two corrections to the brief

This report answers four questions about the Covenant server's API surface and task library. It is source-only. It builds on D13 (API control plane), D24 (client transport), D28/D40 (task library and `getsystem`) without redoing them.

**Two corrections to the brief, led with because the brief asked me to lead with them.**

### §0.1 CORRECTION 1 — `CovenantAPI.cs` is a CLIENT, not the server-side counterpart

**The brief states: *"`CovenantHubService`'s 233 public methods are client-side RPC stubs, not endpoints. `CovenantAPI.cs` is the SERVER-side counterpart and has not had that test applied."***

**That is the same substitution error D32 caught, one file over.** `CovenantAPI.cs` is a **client**. Applying the brief's own test to it: `[verified]`

| Probe | `CovenantAPI.cs` | Control: `ListenerApiController.cs` (known server) |
|---|---|---|
| `[HttpGet` / `[HttpPost` / `[Route` | **0** | **11** |
| `SendAsync` | **183** | 0 |
| `ServiceClient` | **1,293** | 0 |
| `BaseUri` property | **present** (L25, 205 refs) | absent |

`[read]` **Positive control passed**: the instrument returns 11 route attributes on a known server controller and 0 on the client. It distinguishes the two. `[verified]`

**Decisive evidence at L20-25:**
```csharp
// API/CovenantAPI.cs:20
public partial class CovenantAPI : ServiceClient<CovenantAPI>, ICovenantAPI
{
    public System.Uri BaseUri { get; set; }   // L25 — the host it calls
```
`[read]` A `ServiceClient<T>` with a `BaseUri` is a **client**. A server controller derives `Controller` and carries `[Route]`. **`CovenantAPI.cs` is the client half of the same generated pair as `ICovenantAPI.cs`; `CovenantHubService.cs` is the SignalR client; `CovenantAPIService.cs` wraps `CovenantAPI` as a client.** All three are clients. `[verified]`

**Consequence for Q1:** the question *"how many of `CovenantAPI.cs`'s methods are reachable from an HTTP route?"* **has no referent** — a client does not serve routes. The correct count of its methods is **183, all of them outbound calls**, and the correct answer to "how many are unguarded" is **zero, because guarding is not a client property.** §1 gives the enumeration anyway.

### §0.2 CORRECTION 2 — my own first measurement of Q2 was a FALSE ZERO, and it nearly became a headline

**My first authorization count reported `[Authorize]` = 0 on 16 of 17 controllers, total 3.** `[read]` **That was wrong.** The attribute is written **mid-line in a combined attribute list**:

```csharp
// Controllers/ApiControllers/ListenerApiController.cs:16
[ApiController, Route("api/listeners"), Authorize(Policy = "RequireJwtBearer")]
```

`[read]` My pattern `\[Authorize` required a literal `[` **immediately before** `Authorize`. Here the `[` opens the list and `Authorize` sits after a comma. **The detector could not match the form the codebase actually uses.** Corrected pattern `\bAuthorize\s*\(` returns **1 per controller, 17 of 17.** `[verified]`

**This is instrument failure #13 for this lane** (§5). It is the **D20 §6.2 shape exactly** — a broken detector returns a clean zero, and the zero looks like a finding. It was caught by the brief's own rule: **print your matches.** I printed the controller headers and saw the attribute sitting in the line my regex had just declared empty. `[read]`

**Had I not printed them, §2 of this report would have claimed "16 unguarded controllers."** That claim would have been **larger and more alarming than the truth**, exactly as flagged in D32 §6.

---

## TOC

1. [§1 — Q1: `CovenantAPI.cs`, enumerated and classified](#1-q1-covenantapics-enumerated-and-classified)
2. [§2 — Q2: the authorization surface, measured independently of D40](#2-q2-the-authorization-surface)
3. [§3 — Q3: the task library, counted and bounded](#3-q3-the-task-library)
4. [§4 — Q4: what runs where, and the cross-boundary defect](#4-q4-what-runs-where)
5. [§5 — Instrument record](#5-instrument-record)
6. [§6 — Residual unknowns, each with a probe](#6-residual-unknowns)

---

## 1. Q1: `CovenantAPI.cs`, enumerated and classified

### 1.1 The enumeration

**Instrument:** comment-stripped line classification, then matched with `Select-String`, then printed. `[verified]`

| Measurement | Value |
|---|---|
| File size | **1,084,841 B** |
| Lines | **23,549** |
| Type declarations | **exactly 1** — `public partial class CovenantAPI` at L20 |
| `public Task…` members | **183** |
| `…WithHttpMessagesAsync` | **183** |
| `return` statements | **183** |
| Non-comment public Task members | **183** |
| Comment / blank lines | **5,571** |

`[read]` **All 183 public methods are `…WithHttpMessagesAsync` and all return `HttpOperationResponse<T>`.** Printed samples:

```csharp
// :326
public async Task<HttpOperationResponse<IList<CommandOutput>>> GetCommandOutputsWithHttpMessagesAsync(...)
// :451
public async Task<HttpOperationResponse<CommandOutput>> CreateCommandOutputWithHttpMessagesAsync(CommandOutput body = default(CommandOutput), ...)
// :587
public async Task<HttpOperationResponse<CommandOutput>> EditCommandOutputWithHttpMessagesAsync(CommandOutput body = default(CommandOutput), ...)
```

`[verified]` **183 methods, 1 type, 0 route attributes, 183 `SendAsync`.** Every public member is an outbound HTTP call. Confirmed by D13's independent boilerplate enumeration: 19 non-generic + 164 generic `HttpOperationResponse` = 183, and 16 boilerplate markers each occurring exactly 183×. `[verified]`

### 1.2 The classification the brief asked for — with the denominator species stated

The brief warns about **denominator species 6**: *"a correct count of the wrong thing, filed under a heading that makes it read as a different thing."* Here is the classification with the species named explicitly.

| Category | Count | Species of the count |
|---|---|---|
| Reachable from an HTTP **route** | **0** | *n/a — a client serves no routes.* Measuring "outbound methods" and filing them under "endpoints" would be species 6. `[verified]` |
| Reachable from the **hub** | **0** | Same: the client is not a hub endpoint. `[verified]` |
| Reachable only from **internal code** | **183** | Every method is an outbound call made by the server acting as a client. `[read]` |
| **Unguarded** | **0** | Not a property a client possesses. `[inferred]` |

**`[verified]` The honest answer to Q1 is that the question does not apply, and the reason it does not apply is the same reason D32's premise failed: two similarly-named artifacts, one in `API/`, one in `Core/`, were treated as one thing.**

### 1.3 Where the brief's concern *does* apply

The brief's underlying worry — *"if the count is large, be explicit about which ones are unguarded"* — is **correctly aimed and mis-addressed.** The large unguarded surface in Covenant is **not** in `CovenantAPI.cs`. It is:

- **`Core/CovenantService.cs`** — 255,768 B / 5,138 lines, **zero** authorization decisions of its own (D13 §8.1, enumerated; D32 §5 re-confirmed the size and single-file structure). `[verified]`
- **`Hubs/CovenantHub.cs`** — 36,205 B / 1,153 lines, **no `[Authorize]`**, exactly **one** live method (D13 §4.0). `[read]`

`[inferred]` **Both are real, both are already documented, and neither is `CovenantAPI.cs`.** I flag this rather than restate it so the corpus does not acquire a third variant of this claim.

---

## 2. Q2: the authorization surface

### 2.1 The corrected measurement — 17 of 17

**Instrument:** `\bAuthorize\s*\(` and `\bAllowAnonymous\b` per file, `\b`-bounded, printed. `[verified]` **Positive control:** the same instrument returns 11 route attributes and the class-level policy on a known server controller, and the `verbs` column totals **183**, matching Q1's independent count of 183 client methods — **two instruments, two directions, same 183.** `[verified]`

| Controller | `Authorize` | `AllowAnonymous` | HTTP verbs |
|---|---|---|---|
| CommandOutputApiController.cs | 1 | 0 | 6 |
| CovenantUserApiController.cs | **4** | **2** | 15 |
| CredentialApiController.cs | 1 | 0 | 15 |
| EmbeddedResourceApiController.cs | 1 | 0 | 5 |
| EventApiController.cs | 1 | 0 | 9 |
| GruntApiController.cs | 1 | 0 | 12 |
| GruntCommandApiController.cs | 1 | 0 | 5 |
| GruntTaskApiController.cs | 1 | 0 | 5 |
| GruntTaskingApiController.cs | 1 | 0 | 10 |
| ImplantTemplateApiController.cs | 1 | 0 | 6 |
| IndicatorApiController.cs | 1 | 0 | 12 |
| LauncherApiController.cs | 1 | 0 | **41** |
| ListenerApiController.cs | 1 | 0 | 17 |
| ProfileApiController.cs | 1 | 0 | 10 |
| ReferenceAssemblyApiController.cs | 1 | 0 | 5 |
| ReferenceSourceLibraryApiController.cs | 1 | 0 | 5 |
| ThemeApiController.cs | 1 | 0 | 5 |
| **TOTAL** | **21** | **2** | **183** |

`[verified]` **17 of 17 controllers carry a class-level `Authorize(Policy = "RequireJwtBearer")`.** All 17 class-level lines printed:

```
CommandOutputApiController.cs:16:  [ApiController, Route("api/commandoutputs"), Authorize(Policy = "RequireJwtBearer")]
CovenantUserApiController.cs:17:   [ApiController, Route("api"), Authorize(Policy = "RequireJwtBearer")]
CredentialApiController.cs:18:     [ApiController, Route("api/credentials"), Authorize(Policy = "RequireJwtBearer")]
EmbeddedResourceApiController.cs:19:[ApiController, Route("api/embeddedresources"), Authorize(Policy = "RequireJwtBearer")]
EventApiController.cs:16:          [ApiController, Route("api/events"), Authorize(Policy = "RequireJwtBearer")]
GruntApiController.cs:17:          [ApiController, Route("api/grunts"), Authorize(Policy = "RequireJwtBearer")]
GruntCommandApiController.cs:16:    [ApiController, Route("api/commands"), Authorize(Policy = "RequireJwtBearer")]
GruntTaskApiController.cs:15:       [ApiController, Route("api/grunttasks"), Authorize(Policy = "RequireJwtBearer")]
GruntTaskingApiController.cs:17:    [ApiController, Route("api"), Authorize(Policy = "RequireJwtBearer")]
ImplantTemplateApiController.cs:16:[ApiController, Route("api/implanttemplates"), Authorize(Policy = "RequireJwtBearer")]
IndicatorApiController.cs:16:      [ApiController, Route("api/indicators"), Authorize(Policy = "RequireJwtBearer")]
LauncherApiController.cs:17:       [ApiController, Route("api/launchers"), Authorize(Policy = "RequireJwtBearer")]
ListenerApiController.cs:16:       [ApiController, Route("api/listeners"), Authorize(Policy = "RequireJwtBearer")]
ProfileApiController.cs:17:        [ApiController, Route("api/profiles"), Authorize(Policy = "RequireJwtBearer")]
ReferenceAssemblyApiController.cs:16:     [ApiController, Route("api/referenceassemblies"), Authorize(Policy = "RequireJwtBearer")]
ReferenceSourceLibraryApiController.cs:16:[ApiController, Route("api/referencesourcelibraries"), Authorize(Policy = "RequireJwtBearer")]
ThemeApiController.cs:16:          [ApiController, Route("api/themes"), Authorize(Policy = "RequireJwtBearer")]
```

`[read]` **This confirms D13 and refutes my first pass.**

### 2.2 Does the REST API repeat the hub's shape, or differ? — IT DIFFERS

**The brief asks exactly this: *"D40 found the hub presents a token at `CovenantHubService.cs:38` and that nothing REQUIRES one. Does the REST API repeat that shape, or does it differ?"***

`[verified]` **It differs, and the difference is the whole answer.**

| | Hub path | REST path |
|---|---|---|
| Where the control lives | **nowhere** — `CovenantHub.cs` has no `[Authorize]` (D13 §4.0) | **class-level `Authorize(Policy="RequireJwtBearer")`, 17 of 17** |
| Is a token *presented*? | Yes — `CovenantHubService.cs:38` `AccessTokenProvider` `[read]` | Yes — `JwtBearerEvents.OnMessageReceived` `[read]` |
| Is a token *required*? | **No** `[verified]` | **Yes, by attribute, at the controller** `[verified]` |
| Shape | **present-and-not-required** | **required** |

`[inferred]` **The hub's shape is NOT repeated on the REST side.** The REST controllers require authentication structurally — the attribute is on the class, so every action inherits it unless explicitly overridden. **The two paths disagree with each other**, which is precisely the D17 §4b asymmetry D13 documented: `POST api/listeners` requires `RequireJwtBearer`; `POST /covenanthub` — which can do the same thing via `CreateHttpListener` — requires nothing.

### 2.3 Is there exactly one unguarded controller method?

`[verified]` **No — and this is worth stating precisely, because the brief flags it as a candidate headline.** The two `[AllowAnonymous]` sites are both in `CovenantUserApiController.cs`:

| Line | Route | Why it is there |
|---|---|---|
| **L107** | `POST api/users/login` | Login must be pre-authentication. `[read]` |
| **L131** | `POST api/users` | Registration. `[read]` |

`[read]` **Both are overrides of the class-level policy, in the one controller whose `Route` is bare `api`.** The registration one is guarded **inside the method body**, not by attribute — D13 established `CreateUserVerify` (`Core/CovenantService.cs:481`) has two guards (`!_userManager.Users.Any()` gated on both `IsAuthenticated` and `IsInRole("Administrator")`), making it **first-user-bootstrap-only**. `[read]`

`[inferred]` **So: 2 anonymous *routes*, 0 anonymous *operations* that lack a secondary control, and the REST side does NOT reproduce the hub's defect.** The finding the brief hypothesised is not present. **I am reporting the negative rather than manufacturing the finding** — the hub asymmetry in D13 is already the stronger version of this claim.

`[read]` D40's 233-count is **not repeated here.** §2.1 is a fresh, independent measurement of a different surface (controllers, not hub classes), and it agrees with D13 on 17 controllers / 183 actions. Cross-reference only.

---

## 3. Q3: the task library

### 3.1 The count, and the boundary that justifies it

**The brief asks for the boundary, not the count.** The boundary is: **a task definition is a YAML sequence entry at indentation level 0 whose first key is `Name`.** `[read]`

**Why that is the right boundary — the discriminating evidence:**

```yaml
# Data/Tasks/DefaultGruntTasks.yaml — boundary witness
L1:  - Name: Help                    ← task definition begins (indent 0)
L2:    Aliases: []
L9:    Language: CSharp
L18:   Options:                      ← nested list begins
L19:   - Name: TaskName              ← indent 2 — an OPTION, not a task
L22:     Description: ...
L30: - Name: PowerShellImport        ← next task definition (indent 0)
```

`[verified]` **The negative control proves the boundary discriminates:** in `DefaultGruntTasks.yaml`, `^-\s*Name:` matches **23** (tasks) and `^\s+-\s*Name:` matches **115** (options). **Same lexical token, two different species, separated only by leading whitespace.** A detector that counted `- Name:` without anchoring indentation would return **138** for this one file and be wrong by 6×. `[read]`

| File | Task definitions (indent-0 `- Name:`) |
|---|---|
| DefaultGruntTasks.yaml | 23 |
| DotNetCore.yaml | 13 |
| GhostPack.yaml | 6 |
| SharpSC.yaml | 1 |
| SharpSploit.Credentials.yaml | 15 |
| SharpSploit.Enumeration.yaml | 16 |
| SharpSploit.Evasion.yaml | 1 |
| SharpSploit.Execution.yaml | 9 |
| SharpSploit.LateralMovement.yaml | 6 |
| SharpSploit.Persistence.yaml | 4 |
| SharpSploit.PrivilegeEscalation.yaml | 1 |
| **TOTAL (11 files)** | **95** |

`[verified]` **95 task definitions across 11 YAML files.** Second instrument: 11 files confirmed by directory listing of `Data/Tasks/` with `-Filter *.yaml`. `[verified]`

### 3.2 The task-type axis — 10 types, one of them 95% of the library

`[read]` `Models/Grunts/GruntTasking.cs:63-75`:

```csharp
public enum GruntTaskingType
{
    Assembly, SetDelay, SetJitter, SetConnectAttempts, SetKillDate,
    Exit, Connect, Disconnect, Tasks, TaskKill
}
```

`[read]` **10 tasking types. `GruntTask.TaskingType` defaults to `Assembly`** (`Models/Grunts/GruntTask.cs:39` and `:413`). `[read]` Enumerating the 11 YAML files for an explicit `TaskingType:` key finds **none** — every task in the library is `Assembly` by default. `[verified]` **So 95 task definitions → 95 `Assembly` taskings; the other 9 types are control-plane messages the server generates itself, not library tasks.**

`[read]` Enumerating where the server **sets** a non-Assembly type returns exactly four sites, all in `Core/CovenantService.cs`:

| Line | Type | Parameters |
|---|---|---|
| **L1328-1329** | `SetConnectAttempts` | `new List<string> { "ConnectAttempts", grunt.ConnectAttempts.ToString() }` |
| **L1357-1358** | `SetDelay` | `new List<string> { "Delay", grunt.Delay.ToString() }` |
| **L1386-1387** | `SetJitter` | `new List<string> { "JitterPercent", grunt.JitterPercent.ToString() }` |
| **L1415-1416** | `SetKillDate` | `new List<string> { "KillDate", grunt.KillDate.ToString() }` |

`[verified]` **Four sites, four types. `Exit`, `Connect`, `Disconnect`, `Tasks`, `TaskKill` are constructed elsewhere or by string — see §6. `Assembly` is every YAML task.**

### 3.3 Does the server validate parameters before dispatch? — presence yes, type no

`[read]` The gate is **`Core/CovenantService.cs:2472 ParseParametersIntoTask(GruntTask task, List<ParsedParameter> parameters)`**, called from `InteractGrunt` at **`CovenantService.cs:1746`**. `[read]` Full body read; it performs **four** checks and nothing else:

| Check | Line | What it validates |
|---|---|---|
| Parameter count ≥ required-option count | L2475 | **presence** (`!O.Optional`) |
| Labeled parameter matches an option name (case-insensitive) | L2487 | **presence of a name** |
| Unlabeled parameters fill unassigned non-file slots in order | L2498-2512 | **positional assignment** |
| No required option left unassigned | L2517-2527 | **presence** |

`[read]` **Returns `null` on success, a usage string on failure.** `[verified]`

`[read]` **What it does NOT do: no type check, no range check, no format check, no regex, no length bound, no allow-list.** Every value is assigned as a **raw `string`** at `L2490 nextOption.Value = parameters[i].Value;` and `L2490 option.Value = parameters[i].Value;`. `[verified]` **The only typed value in the function is the count comparison at L2475.**

`[inferred]` **The server validates that the operator supplied the right NUMBER of things. It does not validate that any of them is the right KIND of thing.** A `SetDelay`-style numeric option accepts `"banana"` at this gate. Whether that matters depends on §4 — and there, it does.

---

## 4. Q4: what runs where

### 4.1 The split, per the source

| Stage | Artifact | What happens |
|---|---|---|
| **SERVER — validation** | `CovenantService.cs:2472` | presence/position only (§3.3) `[read]` |
| **SERVER — state apply** | `CovenantService.cs:2954`, `:2971` | `int.TryParse(Parameters[0])` / `DateTime.TryParse(Parameters[0])` `[read]` |
| **SERVER — serialization** | `InternalListener.cs:200 GetGruntTaskingMessage` | base64 each parameter, join with `,` (Assembly); **raw join, NO base64** (else) `[read]` |
| **WIRE** | `InternalListener.cs:386` → `CreateMessageForGrunt` | encrypted `GruntEncryptedMessage` wrapping `GruntTaskingMessage` `[read]` |
| **TARGET — decode** | `GruntHTTP.cs` / `Brute.cs` / `GruntBridge.cs` / `GruntSMB.cs` | `message.Message.Split(',')`, then per-piece handling `[read]` |
| **TARGET — apply** | same files, ~L104-152 | `int.TryParse(message.Message)` / `DateTime.TryParse(message.Message)` `[read]` |

`[read]` **The serialization at `InternalListener.cs:203-233`, verbatim:**

```csharp
if (tasking.Type == APIModels.GruntTaskingType.Assembly)
{
    // :210 — EACH parameter base64'd INDIVIDUALLY, then joined with ','
    Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(
        Common.CovenantEncoding.GetBytes(P))));
}
else
{
    // :232 — RAW join, no encoding at all
    Message = string.Join(",", tasking.Parameters);
}
```

### 4.2 THE CROSS-BOUNDARY DEFECT

**The brief asks: *"is there a task whose server-side and target-side assumptions disagree — a parameter the server validates as one type and the grunt consumes as another, or a server-side precondition the grunt does not check."***

`[verified]` **Yes. It is the four control taskings, and the disagreement is a LABEL at index 0 that no consumer skips.**

**Build the message for `SetDelay`.** `CovenantService.cs:1358` constructs `Parameters = new List<string> { "Delay", grunt.Delay.ToString() }`. `[read]` That list flows to `GetGruntTaskingMessage`, takes the **`else` branch at `:232`** (because `Type != Assembly`), and produces:

```
Message = "Delay,300"
```

**Now both consumers read index 0 as the value:** `[verified]`

| Consumer | Code | Result |
|---|---|---|
| **Client-side (operator console)** `CovenantService.cs:2954` | `tasking.Parameters.Count >= 1 && int.TryParse(tasking.Parameters[0], out int n)` → parses **`"Delay"`** | **FAILS.** No assignment. Silent. `[read]` |
| **Target-side (implant)** `GruntHTTP.cs:106` | `int.TryParse(message.Message, out int val)` → parses **`"Delay,300"`** | **FAILS.** Outputs `"Error parsing: Delay,300"`. `[read]` |

`[read]` **Neither consumer strips the label.** Enumerated every `Parameters.Skip` / `Parameters.RemoveAt` / `Parameters[0]` site in the tree: the only `Skip(1)` calls are at `CovenantService.cs:1740` (grunt note) and `:2474` (`ParseParametersIntoTask`, which operates on the operator's *typed command line*, not this list). **Nothing skips index 0 for a control tasking.** `[verified]`

`[inferred]` **The server writes a label into a positional slot and every reader treats the slot as a value.** Both sides fail, both fail **silently**, and they fail **for the same reason** — so the bug is invisible from either end alone. The operator sees the command "succeed" (the tasking is created, dispatched, and the tasking row is written); the grunt reports a parse error the operator may never read.

### 4.3 The secondary defect — the `else` branch has no encoding contract

`[read]` `InternalListener.cs:232` sends **raw, unencoded** parameters, while every grunt transport decodes positionally:

```csharp
// Data/Grunt/GruntHTTP/GruntHTTP.cs (and Brute/GruntBridge/GruntSMB identically)
string[] pieces = message.Message.Split(',');
for (int i = 1; i < pieces.Length; i++) { parameters[i-1] = Encoding.UTF8.GetString(Convert.FromBase64String(pieces[i])); }
byte[] compressedBytes = Convert.FromBase64String(pieces[0]);
```

`[read]` **All four transports assume `pieces[0]` is a base64 *assembly* and `pieces[i>0]` are base64 *parameters*.** `[verified]` **That assumption is true only on the `Assembly` branch.** On the `else` branch the message is `"Delay,300"` — `pieces[0]` = `"Delay"` is not base64, and `pieces[1]` = `"300"` is not base64.

`[inferred]` **The transports and the control taskings disagree about the wire format itself.** The `else` branch at `:232` appears to expect a *different* framing than the transports implement. `[inferred]` This is consistent with the control taskings being read by a **separate, earlier code path** in the grunt — `int.TryParse(message.Message)` on the whole string, before any split. §4.4 records what I could and could not establish about which path wins.

### 4.4 What I could NOT establish, stated honestly

`[read]` The grunt's `GruntHTTP.cs:104-152` handles control types by parsing **`message.Message` as a whole**. The transports' `Split(',')` + `FromBase64String` path is a different region of the same file. **Both are present.** Which executes for a given `message.Type` depends on the branch taken at `:104`, and I did not trace the full control flow to a single entry point for all four transports. `[absence]` — **searched: the four transport files' type branches; positive control NOT established for the control-flow claim.** **I therefore assert the two mismatches in §4.2 as read facts (`[read]`/`[verified]` — the code says what it says) and mark the *consequence* chain as `[inferred]`.** See §6.1 for the probe that would close it.

---

## 5. Instrument record

**Mandatory. This lane's record, continued from D20 §6.2 and D32 §6.** Four failures now, one root cause: **a probe whose shape does not match the evidence's shape.**

| # | Where | Failure | Correction | Rule |
|---|---|---|---|---|
| **9** | D13 §7.2 | member-surface regex character class **excluded digits** → reported **178** for a **183**-member surface | class widened to `[A-Za-z0-9_]` | *A count is a measurement only if you enumerate it.* |
| **10** | D20 §6.2 | `Select-String -Path "$m\**\*.go"` → **false zero** on a control that must return 6 | per-file `-LiteralPath` over an enumerated 399-file list → exactly 6 | *A recursive glob in that form does not recurse the way the syntax suggests; a zero from it is a tooling artifact, not a finding.* |
| **11** | D32 §6 | name collision across namespaces read as a `partial` split → **57** apparent splits vs a true **0** | tightened to `partial` declarations only | *Same identifier in two files is not one type in two files.* |
| **12** | D32 §1.3 / §2 | `\|` unescaped in a `Select-String` alternation pattern → **false zero** while printing the matches | use `-SimpleMatch` for literals or escape properly | *Print the matches; a count without a printed match is a number you have not looked at.* |
| **13** | **This report, §2.1** | `\[Authorize` requires a literal `[` **immediately** before `Authorize`; the codebase writes it **mid-line in a combined attribute list** (`[ApiController, Route(...), Authorize(Policy=...)]`) → **reported 0 on 16 of 17 controllers** | `\bAuthorize\s*\(` → **17 of 17** | *An attribute in a combined attribute list is still an attribute. Anchor on the identifier, not on the bracket.* |

`[verified]` **#13 nearly became this report's headline.** A false zero on a security control reads as *"16 controllers are unguarded"* — a find far larger and more alarming than the truth. **It was caught only because the brief required printing the matches** and I printed the controller headers, where the attribute sat in the very line my regex had just called empty.

`[inferred]` **The general form, and I would index this one: the failures cluster around *structural* patterns — brackets, indentation, namespace scope, glob depth — while the numbers counted are lexical.** The instrument matches tokens; the code organizes them structurally. **Every one of #7–#13 was a lexical probe against a structural question.**

`[read]` **Positive controls actually run in this report:** (a) server-vs-client route-attribute control, 11 vs 0 (§0.1); (b) YAML indent-level control, 23 vs 115 (§3.1); (c) verbs cross-check, 183 client methods vs 183 route attributes, two instruments in two directions (§2.1); (d) comment-stripped method count, 183 live vs 5,571 comment/blank (§1.1). `[verified]`

---

## 6. Residual unknowns

Each with a concrete probe, per the brief.

### 6.1 Which grunt code path consumes a control tasking — the §4.4 gap

**Unknown:** whether `int.TryParse(message.Message)` on the whole string (`GruntHTTP.cs:104-128`) or the `Split(',')` + base64 path runs for `SetDelay`/`SetJitter`/`SetConnectAttempts`/`SetKillDate`. §4.2's two mismatches are read facts either way; only the *consequence* (does the setting silently no-op, or does the grunt report a parse error) depends on this.
**Probe:** trace `GruntHTTP.MessageLoop` (or equivalent) from the transport's receive point to the `message.Type` dispatch at `:104`, and determine whether an `Assembly`-framed message ever reaches the `else` branch at `InternalListener.cs:232` for a non-Assembly type. Instrument: read the full receive function, print the branch, do not infer from proximity.

### 6.2 The five tasking types not built in `CovenantService.cs`

**Unknown:** `Exit`, `Connect`, `Disconnect`, `Tasks`, `TaskKill` — enumerating `Type = GruntTaskingType.X` in the server found only the four in §3.2. The other five are plausibly constructed by string, by the hub, or on the grunt side.
**Probe:** search for `GruntTaskingType.Exit` etc. as **object-initializer assignments** across the whole tree (not just `Type =` form), and separately in `Hubs/`. **Instrument warning:** a `Type =` pattern is a *shape*, and this corpus has now three times produced a false zero from a shape assumption. Use a bare-identifier search plus a printed match set.

### 6.3 Whether `Parameters[0]`-as-label affects Assembly taskings too

**Unknown:** §4.2 is established for the four control taskings. Whether any `Assembly` tasking has the same label-in-slot-0 shape is **not** established.
**Probe:** for each of the 95 YAML tasks, print the `Options:` list and compare index order against what the grunt's `parameters[i-1]` loop expects. **Bounded, not sampled: all 95, all 11 files.**

### 6.4 Whether the `else`-branch `:232` encoding gap is reachable at all

**Unknown:** §4.3's framing disagreement is a read fact; reachability depends on §6.1.
**Probe:** same as §6.1. **If the `else` branch is unreachable, §4.3 is dead code and should be recorded as such** — the distinction between "wrong" and "unreachable" matters and I did not resolve it.

### 6.5 Not attempted, declared

- **No build, no compiler, no runtime.** All `[verified]` claims are source-level with controls, not execution.
- **`API/CovenantAPIExtensions.cs` (212,491 B) and `API/ICovenantAPI.cs` (93,517 B) were not read.** Their method counts are inferred from the client's 183-method surface, not enumerated. `[inferred]`
- **D40 not reopened** — cross-referenced only, per the brief.


