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
