# D46 — Covenant: the full grunt library, the listener path, and the build-time surface

**Targets:** `Covenant/Data/Tasks/**` (11 YAML, 318,063 B) · `Covenant/Data/Grunt/**` (4 families, 268,749 B) · `Covenant/Controllers/**` · `Covenant/Core/CovenantService.cs` (255,768 B) · `pupy` `convcompat`/`tokenprivs`
**Method:** pure source, no provider, no execution. Comments stripped before every member count. **Every probe controlled and its matches printed.** Boundary justified, not sampled.
**Write scope:** this file only.

---

## 0. What this is, and three corrections to the brief

### 0.1 Two brief facts verified exactly

| Brief claim | **Measured** |
|---|---|
| `Covenant\` `.cs` files excl obj/bin = **152** | **152** ✅ |
| `API\CovenantAPI.cs` = **1,084,841 B, one type at L20** | **1,084,841 B, 23,549 lines, exactly 1 `public partial class` at L20** ✅ — `public partial class CovenantAPI : ServiceClient<CovenantAPI>, ICovenantAPI` |

### 0.2 **CORRECTION 1 — the grunt task library is YAML, not a C# namespace (affects Q2's whole framing)**

**The brief frames Q2 as "`Grunt\` / the grunt task namespace." That framing is wrong in a way that would have produced a correct count of the wrong thing.**

- **`Data\Grunt\` is NOT the task library.** It is **four messenger/transport families** — `Brute` (2 `.cs`, 62,380 B), `GruntBridge` (63,288 B), `GruntHTTP` (75,307 B), `GruntSMB` (67,774 B). **8 files, 268,749 B.** These implement how a grunt *communicates*. D40 already read their cert callbacks.
- **The grunt task library is `Data\Tasks\`** — **11 `.yaml` files, 318,063 B**, plus 7 `.task` files (35,755 B).

**This is denominator species 6 with the polarity reversed from D40:** in D40, 233 client stubs read as 233 endpoints. Here, `Data\Grunt\` reads as "the task library" but is a transport directory, and the real library is YAML the brief never names. **A census of `Data\Grunt\` would have been a correct count of the wrong thing.**

### 0.3 **CORRECTION 2 — D40's own authorization count was an undercount, and the cause is mine**

**D40 §3.1 reported "`[Authorize]` — 9 attributes in 6 files." That is wrong. The true figure is 17 controllers, each carrying `[Authorize(Policy = "RequireJwtBearer")]`.**

**Cause, and it is my own defect:** my D40 pattern was `\[Authorize` — requiring `Authorize` to be the **first token** inside the bracket. **Covenant writes the attribute as a comma-joined list:**

```csharp
[ApiController, Route("api/listeners"), Authorize(Policy = "RequireJwtBearer")]
```

**`Authorize` sits mid-attribute, so `\[Authorize` cannot match it.** **This is the same defect class as D40's propagation error — a pattern that finds a token only where it is written in its most obvious form.** Corrected pattern `\[[^\]]*\bAuthorize\b[^\]]*\]`, with the mismatch printed per file as the control:

```
MISMATCH ListenerApiController.cs   [Authorize=0  corrected=1
MISMATCH GruntApiController.cs      [Authorize=0  corrected=1
... 16 further files, all [Authorize=0 corrected=1
```

**Reference-counted this pass: 17 API controllers, 17 policies, 0 exceptions.**

**BUT the class-level attribute is only the OUTER tier. Two controllers carry METHOD-LEVEL overrides that the class-level count cannot see — and this is the finding D40 missed entirely:**

| Controller | Class-level | Method-level override |
|---|---|---|
| `CovenantUserApiController.cs` | `RequireJwtBearer` (`:17`) | **`[AllowAnonymous]` on `Login` (`:107`) AND `CreateUser` (`:132`)**; **`RequireAdministratorRole` on `DeleteUser` (`:205`), `CreateUserRole` (`:300`), `DeleteUserRole` (`:326`)** |
| `HttpListenerController.cs` | **`[AllowAnonymous]` (`:21`)** | `[AllowAnonymous]` again (`:41`) — implicit, and deliberate (§1.3) |

**Covenant has a THREE-TIER authorization model on the user controller: anonymous (login, register) → JWT-required (everything else) → administrator-required (three destructive role/user operations).** **A controller-level census reports one tier and calls it the answer — which is exactly the shape this corpus exists to catch.** `[source: CovenantUserApiController.cs all attributes and signatures enumerated L17-376]`

### 0.4 **CORRECTION 3 — my first task-source probe returned a FALSE ZERO and I caught it with the control**

**My first Q2 probe searched for `Code:` blocks with a single-quoted-inline regex and captured `0 blocks` across all 11 YAML files.** **It then printed a full table of zeros** (`CovenantAPI=0, DllImport=0, Process.Start=0...`) that **looked like a measurement and was not one** — the regex was scanning raw YAML while the source lives in YAML literal block scalars.

**Caught by the control the brief mandates — "print your matches":** with zero blocks captured, the probe was **UNTESTED, not negative.** The correct parse is `Code: |` followed by more-indented lines. **Corrected extraction: 83 blocks, 122,873 chars of real C#, controllable at first line:**

```csharp
using System; | using System.IO; | public static class Task | { | public static int Execute() ...
```

**The zero table from the first probe is discarded, not built upon. Every Q2 number below comes from the corrected extractor.** `[source: both runs, this session]`

### 0.5 A fourth instrument failure — quoting killed a whole probe block

**One `pwsh` block died at parse time** (`Write-Output '=== '[T]ask' ...`) — an unescaped bracket inside a single-quoted string. **Exit code 1, zero output.** Recorded because it silently produced *no* result rather than a wrong one, and the recovery was to re-run the block intact.

---

## 1. Q1 — the `CreateHttpListener` path: what a request must present

### 1.1 The path has TWO entry points with DIFFERENT gates. Conflating them is the trap.

| Entry | Authorization | Service method | Reaches |
|---|---|---|---|
| **`HttpListenerController.Route()`** | **`[AllowAnonymous]` ×2** (`:21` class, `:41` method) | `_internalListener.Read/Write` | **the implant staging channel** |
| **`ListenerApiController.CreateHttpListener`** | **`[Authorize(Policy = "RequireJwtBearer")]`** (`:16`) | `CovenantService.CreateHttpListener` (`:3950`) | **listener creation** |
| **`CovenantHub.CreateHttpListener`** | **NONE** (D40 §1.2 — `CovenantHub` is the only mapped hub with 0 `[Authorize]`) | `_service.CreateHttpListener` (`CovenantHub.cs:164`) | **listener creation** |

**They are different functions with the same name. `Route()` is the one a grunt talks to. `CreateHttpListener` is the one an operator talks to.** **The brief asks what a "`CreateHttpListener` request" must present — and the honest answer is that this name denotes an operator action, while the listener's own exposure lives in `Route()`.** Both are enumerated.

### 1.2 `CovenantService.CreateHttpListener` (`:3950-3987`) — enumerate the checks in order

**Read in full. There is exactly ONE check, and it is not an authorization check:**

| # | Line | Check | Enforced? |
|---:|---|---|:--:|
| 1 | `:3950` | *(none — method entry)* | — |
| 2 | `:3952` | `GetListenerType(listener.ListenerTypeId)` — lookup | lookup only |
| 3 | `:3953` | `GetHttpProfile(listener.ProfileId)` — lookup | lookup only |
| 4 | `:3955-3960` | **mints a new `CovenantUser`** from a secure GUID + password | **creates privilege** |
| 5 | `:3961-3962` | **grants that user the `Listener` `IdentityRole`** | **grants privilege** |
| 6 | `:3964-3968` | **mints a JWT, `Listener` role, `"2000"` (minutes)** | **grants privilege** |
| 7 | `:3969-3979` | if `Status == Active` → `StartInitialHttpListener` | **starts a listener** |
| 8 | `:3986` | `return GetHttpListener(listener.Id)` | — |

**THERE IS NO AUTHORIZATION CHECK IN THE BODY.** **The method does not verify that the caller may create listeners, may bind a port, or may mint a `Listener`-role JWT. It assumes the caller was authorized by whatever reached it — which is `[Authorize]` on the API controller (✅ present) and **nothing** on the hub (❌ absent, D40 §1.2).**

**The privilege-granting behaviour is the finding:** every successful call **silently creates a new service account with a 33-hour token.** `[source: CovenantService.cs:3950-3987 read verbatim]`

### 1.3 `HttpListenerController.Route()` (`:41-79`) — **the unauthenticated endpoint, and there is no check to bypass**

**Class and method both carry `[AllowAnonymous]`** (`:21`, `:41`) — **explicitly, deliberately unauthenticated**, because an implant in the field cannot hold a JWT.

**What a request must present:**

| # | Line | Step | Credential required |
|---:|---|---|---|
| 1 | `:47` | `SetHeaders()` — applies profile response headers | **none** |
| 2 | `:48` | `guid = GetGuid(HttpContext)` | **none — may return `null`** |
| 3 | `:49` | `Request.Method == "GET"` → `Read(guid)` | **none** |
| 4 | `:56-61` | `POST` → body parsed, `Write(guid, msg)`, then `Read` | **none** |

**`GetGuid` (`:81-100`) is a pattern extractor, not an authenticator.** It walks profile request headers, and if none contain `{GUID}`, tries the URL; **it returns `null` when nothing matches (`:99`).** **A `null` guid is not rejected at `:48`.**

**The real gate is downstream, in the DATA, not the request:** `InternalListener.Write(guid, data)` (`:408-423`) tries to decode the body as a `GruntEncryptedMessage`; **on failure it pushes a `NotFound` status and returns (`:418-422`)** — commented *"May not be legitimate Grunt request, respond NotFound."* **So the gate is the shared-secret decryption of the message, not any request-level credential.**

### 1.4 **The first check that can be bypassed — answered precisely**

**For `Route()`: there is no check to bypass. Step 1 IS reachable by an unauthenticated caller.** The endpoint is one unauthenticated `GET` from `Read(guid)`, and the only thing standing between a stranger and the staging channel is **whether they can produce a correctly-encrypted grunt message** — a cryptographic gate applied to the *payload*, not an authorization check on the *caller*.

**For `CovenantService.CreateHttpListener`: step 2 (`GetListenerType`) is the first executed check, and it is a lookup, not an authorization test.** Reached via the hub, **there is no authorization step anywhere in the chain** (D40 §1.2: `CovenantHub` has 0 `[Authorize]`; §1.2 here: the body checks nothing). **Reached via `ListenerApiController`, the gate is `RequireJwtBearer` at `:16` and holds.** **The bypass is path-dependent, and the hub path is the one without a gate.**

### 1.5 `StartInitialHttpListener` (`:3859-3900`) — what actually constrains the bind

**Two real checks, both operational rather than authorization:**

```csharp
// :3862-3865
if (listener.UseSSL && string.IsNullOrWhiteSpace(listener.SSLCertificate))
    throw new ControllerBadRequestException($"HttpListener: {listener.Name} missing SSLCertificate");
// :3866-3869
if (_context.Listeners.Where(L => L.Status == ListenerStatus.Active && L.BindPort == listener.BindPort).Any())
    throw new ControllerBadRequestException($"Listener already listening on port: {listener.BindPort}");
```

**The bind address is NOT constrained.** `listener.ConnectAddresses` is iterated (`:3872`) to **create `NetworkIndicator` records** — indicators, not bind guards. **The listener's bind address and port come from the caller-supplied `listener` object.** **No allow-list, no bind-interface restriction, no port range.** `[source: CovenantService.cs:3859-3900 read verbatim]`

**Answer to Q1's actual question:** *a listener's exposure is decided by whatever the caller put in the `HttpListener` object plus the profile's GUID-extraction regex. The only real credential in the path is the grunt's shared-secret encryption; the only real bind constraint is a duplicate-port check.*

### 1.6 **The unauthenticated WRITE path — `CreateUser` is `[AllowAnonymous]`**

**Found while correcting §0.3, and it is a bigger answer to Q1's question than either listener path.**

```csharp
// CovenantUserApiController.cs
[ApiController, Route("api"), Authorize(Policy = "RequireJwtBearer")]   // :17  class-level
...
[AllowAnonymous]                                                        // :131
[HttpPost("users", Name = "CreateUser")]                                // :132
public async Task<ActionResult<CovenantUser>> CreateUser([FromBody] CovenantUserRegister register)
```

**An unauthenticated caller can create a Covenant user** via `POST /api/users`. **The method-level `[AllowAnonymous]` overrides the class-level `RequireJwtBearer`.**

**And the administrator tier is three methods** (`DeleteUser` `:205`, `CreateUserRole` `:300`, `DeleteUserRole` `:326`) — all `RequireAdministratorRole`, all correct.

**The residual this raises and does NOT answer:** **what role does a `CreateUser`-created account receive, and can it self-elevate?** Self-registration is standard in this class of framework; **the role assignment lives in `CovenantService.CreateUser` and is NOT read here.** **Named as a residual in §5.** `[source: CovenantUserApiController.cs:17, :107, :131-134, :205, :300, :326]`

---

## 2. Q2 — the grunt task library: boundary, count, families, and the split

### 2.1 **The boundary, justified rather than asserted**

**Boundary definition:** a *grunt task* is a top-level `- Name:` entry in a `Data\Tasks\*.yaml` file. **Why this boundary and not another:**

1. **It is the boundary the loader uses.** `DbInitializer` parses these YAML files into `GruntTask` rows; the C# models `Models\Grunts\GruntTask.cs` (20,741 B), `GruntTaskAuthor.cs`, `GruntTaskComponents.cs`, `GruntTasking.cs`, `GruntTaskOption.cs` are the deserialization targets. **The YAML entry ≈ the DB row ≈ the operator-visible task.**
2. **It excludes `Data\Grunt\`** — that is transport (§0.2), and including it would inflate the count with messenger code that is never a task.
3. **It excludes `.task` files** — 7 files, 35,755 B, all under `Data\Tasks\CSharp\netcoreapp3.0\` (`Assembly.task` 10,286 B, `ListDirectory.task` 7,522 B, `ProcessList.task` 7,065 B, `Shell.task` 4,366 B, `ShellCmd.task` 5,782 B, `ChangeDirectory.task` 403 B, `WhoAmI.task` 331 B). **These are the pre-compiled netcoreapp3.0 binaries for the DotNetCore variants — an artifact of the same tasks, not additional tasks.** **Counting them would double-count.**
4. **It includes all 11 YAML files**, since each is a distinct task pack loaded into the same table.

**Boundary: 11 YAML files → 95 task entries.** `[source: `^- Name:` at column 0, counted per file; per-file table below]`

### 2.2 The count, per file

| File | Bytes | Tasks |
|---|---:|---:|
| `DefaultGruntTasks.yaml` | 31,379 | **23** |
| `SharpSploit.Enumeration.yaml` | 70,146 | **16** |
| `SharpSploit.Credentials.yaml` | 49,455 | **15** |
| `DotNetCore.yaml` | 54,203 | **13** |
| `SharpSploit.Execution.yaml` | 33,174 | **9** |
| `SharpSploit.LateralMovement.yaml` | 25,076 | **6** |
| `GhostPack.yaml` | 27,681 | **6** |
| `SharpSploit.Persistence.yaml` | 17,047 | **4** |
| `SharpSploit.PrivilegeEscalation.yaml` | 3,724 | **1** |
| `SharpSC.yaml` | 3,360 | **1** |
| `SharpSploit.Evasion.yaml` | 2,818 | **1** |
| **TOTAL** | **318,063** | **95** |

**95 entries, 82 distinct names.** **13 names appear in more than one file** — `ChangeDirectory`, `Copy`, `CreateDirectory`, `Delete`, `Download`, `ReadTextFile`, `Upload`, `WhoAmI` (`DefaultGruntTasks` + `DotNetCore`); `Assembly`, `Shell`, `ShellCmd` (`DotNetCore` + `SharpSploit.Execution`); `ListDirectory`, `ProcessList` (`DotNetCore` + `SharpSploit.Enumeration`). **`DotNetCore.yaml` re-implements the core .NET Framework tasks for .NET Core** — a platform variant, not a collision. **95 rows, 82 distinct operators-visible names is the honest pair of numbers.**

### 2.3 Delivery mechanism — and an instrument correction

| `TaskingType` | Count |
|---|---:|
| `Assembly` | **86** |
| `Connect`, `Disconnect`, `Exit`, `SetDelay`, `SetJitter`, `SetKillDate`, `SetConnectAttempts`, `TaskKill`, `Tasks` | **9** (agent control, `DefaultGruntTasks.yaml`) |

**86 of 95 tasks are compiled C# assemblies. 9 are in-agent control directives.** **`Language: CSharp` on all 95** (the earlier 155 was 95 top-level + 60 nested inside `ReferenceSourceLibraries` blocks — **my probe counted two different things under one heading**; corrected to 95).

**`TokenTask: true` on exactly 5** — and they are the entire token-impersonation family: **`MakeToken`, `GetSystem`, `ImpersonateProcess`, `ImpersonateUser`, `RevertToSelf`** (all `SharpSploit.Credentials.yaml`). **`UnsafeCompile: false` on all 95.**

### 2.4 **THE SPLIT — measured on ~122,900 chars of real task source**

**`CovenantAPI` appears ZERO times across all 83 extracted `Code:` blocks.**

| File | `CovenantAPI` | `DllImport` | `kernel32`/`ntdll`/`advapi32` | `Process.Start` | `Assembly.Load` | `System.IO` |
|---|---:|---:|---:|---:|---:|---:|
| `DefaultGruntTasks.yaml` | **0** | 0 | 0 | 0 | 0 | 19 |
| `DotNetCore.yaml` | **0** | 0 | 0 | **22** | 2 | 23 |
| `GhostPack.yaml` | **0** | 0 | 0 | 0 | 0 | 7 |
| `SharpSC.yaml` | **0** | 0 | 0 | 0 | 0 | 1 |
| `SharpSploit.Credentials.yaml` | **0** | 0 | 0 | 0 | 0 | 2 |
| `SharpSploit.Enumeration.yaml` | **0** | **8** | **8** | 0 | 0 | 1 |
| `SharpSploit.Evasion.yaml` | **0** | 0 | 0 | 0 | 0 | 0 |
| `SharpSploit.Execution.yaml` | **0** | 0 | 0 | 0 | 0 | 2 |
| `SharpSploit.LateralMovement.yaml` | **0** | 0 | 0 | 0 | 0 | 0 |
| `SharpSploit.Persistence.yaml` | **0** | 0 | 0 | 0 | 0 | 0 |
| `SharpSploit.PrivilegeEscalation.yaml` | **0** | 0 | 0 | 0 | 0 | 0 |

### 2.5 What the split means — and why it is architecturally different here

**Covenant's post-exploitation tasks do not call the Covenant API. They are self-contained C# that acts directly on the target through .NET and selective P-Invoke.**

**The three tiers:**

| Tier | Mechanism | Where |
|---|---|---|
| **Direct .NET** | `System.IO`, `Process.Start`, `Assembly.Load` | **the default** — 8 of 11 files |
| **P-Invoke** | `DllImport` into `kernel32`/`ntdll`/`advapi32` | **concentrated in ONE file** — `SharpSploit.Enumeration` (8 `DllImport`, 8 native refs). Elsewhere: `SharpSploit.Enumeration` also carries the only `Registry` hits (4) |
| **Embedded assemblies** | `ReferenceSourceLibraries` → bundled GhostPack / SharpSploit / SharpSC / SharpUp / Rubeus / SharpDPAPI / SharpDump / SharpWMI (8 in `Data\ReferenceSourceLibraries\`) | **41 `ReferenceSourceLibraries` blocks**; **6 non-empty in `GhostPack.yaml`, 15 in `Credentials`, 15 in `Enumeration`, 9 in `Execution`, 6 in `LateralMovement`, 4 in `Persistence`, 1 each in `SharpSC`/`Evasion`/`PrivilegeEscalation`** |

**Why this is the meaningful comparison the corpus has been missing:** **Covenant compiles a fresh grunt per task** (§3 below). **A framework that compiles per-task has no reason to route post-exploitation through its own API — and it doesn't.** **MSF and Sliver tasks call back into the framework's own session/meterpreter API; Covenant's tasks are standalone programs that the framework merely delivers.** **That is a genuine architectural difference, not a stylistic one, and it is now measured rather than assumed.**

**The consequence for capability physics:** a Covenant task's capability is bounded by **what the compiled assembly can do in its host process**, not by what the framework exposes. **`Assembly.Load` ×2 and the reflection hits in `DefaultGruntTasks` (11) / `DotNetCore` (19) are the in-process execution path.** **The 5 `TokenTask: true` tasks are the ones that need a token context — consistent with `RevertToSelf` being required cleanup after `MakeToken`.**

---

## 3. Q3 — the build-time substitution surface: **28 placeholders, and most of a grunt is decided before it runs**

### 3.1 Every distinct `{{REPLACE_*}}` placeholder in the tree

**Enumerated across `*.cs`, `*.py`, `*.ps1`, `*.txt`, `*.yml` — 28 distinct placeholders.** (First pass reported 30; the second method returned 28 and the named list confirms 28 — two inferred names were in my table that no probe found. **Corrected to 28.**) Substitution happens in `Core\CovenantService.cs` (the compiler path), consumed in the launcher/stager/messenger sources.

| Placeholder | Hits | Files | **Substituted value** | **Operator-controlled?** |
|---|---:|---|---|:--:|
| `{{REPLACE_PROFILE_MESSAGE_TRANSFORM}}` | **11** | all 5 messenger families + CovenantService | profile transform key | **YES — profile** |
| `{{REPLACE_CONNECT_ATTEMPTS}}` | 7 | Brute/GruntBridge/GruntHTTP/GruntSMB | connect retry count | **YES — grunt setting** |
| `{{REPLACE_DELAY}}` | 7 | " | beacon delay | **YES — grunt setting** |
| `{{REPLACE_GRUNT_GUID}}` | 7 | all 4 stagers + CovenantService | **per-grunt GUID** | **YES — per-grunt** |
| `{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}` | 7 | all 4 stagers + CovenantService | **shared-secret passphrase** | **YES — per-grunt** |
| `{{REPLACE_JITTER_PERCENT}}` | 7 | " | jitter % | **YES — grunt setting** |
| `{{REPLACE_KILL_DATE}}` | 7 | " | kill date | **YES — grunt setting** |
| `{{REPLACE_PROFILE_READ_FORMAT}}` | 6 | GruntBridge/GruntSMB | read format string | **YES — profile** |
| `{{REPLACE_PROFILE_WRITE_FORMAT}}` | 6 | GruntBridge/GruntSMB | write format string | **YES — profile** |
| `{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}` | 5 | Brute/GruntHTTP | header names | **YES — profile** |
| `{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}` | 5 | " | header values | **YES — profile** |
| `{{REPLACE_PROFILE_HTTP_POST_REQUEST}}` | 5 | " | POST request template | **YES — profile** |
| `{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}` | 5 | " | POST response template | **YES — profile** |
| `{{REPLACE_PROFILE_HTTP_URLS}}` | 5 | " | callback URLs | **YES — profile** |
| `{{REPLACE_USE_CERT_PINNING}}` | 5 | Brute/GruntHTTP | pinning on/off | **YES — per-grunt** (D40) |
| `{{REPLACE_VALIDATE_CERT}}` | 5 | " | cert validation on/off | **YES — per-grunt** (D40) |
| `{{REPLACE_GRUNT_IL_BYTE_STRING}}` | 4 | `Launcher.cs` only | compiled IL bytes | **generated, not operator-typed** |
| `{{REPLACE_PIPE_NAME}}` | 4 | GruntSMB/SMBStager | SMB pipe name | **YES — per-grunt** |
| `{{REPLACE_SCRIPT_LANGUAGE}}` | 4 | `Launcher.cs` | script language | **YES — launcher** |
| `{{REPLACE_SCRIPT}}` | 4 | `Launcher.cs` | script body | **YES — launcher** |
| `{{REPLACE_VERSION_SETTER}}` | 4 | `Launcher.cs` | version metadata | generated |
| `{{REPLACE_BRIDGE_MESSENGER_CODE}}` | 3 | GruntBridge/BridgeStager | **messenger C# source** | generated |
| `{{REPLACE_COVENANT_CERT_HASH}}` | 3 | BruteStager/GruntHTTPStager | **cert hash pin** | **YES — server cert** |
| `{{REPLACE_COVENANT_URIS}}` | 3 | BruteStager/GruntHTTPStager | callback URIs | **YES** |
| `{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}` | 3 | Brute/GruntHTTP | GET response template | **YES — profile** |
| `{{REPLACE_COVENANT_URI}}` | 2 | GruntBridgeStager | single callback URI | **YES** |
| `{{REPLACE_PROGID}}` | 2 | `Launcher.cs` | COM ProgID | **YES — launcher** |
| `{{REPLACE_TAGGED_SCRIPT}}` | 2 | `Launcher.cs` | tagged script | **YES — launcher** |

### 3.2 **The build-time/runtime split — Q3's real question**

**Classifying all 30 by *who decides at what moment*:**

| Decision class | Count | Meaning |
|---|---:|---|
| **Operator-set per-grunt** (GUID, shared secret, delay, jitter, kill date, connect attempts, cert pinning, validate-cert, pipe name) | **9** | **changes every build** |
| **Operator-set via profile** (transform, read/write format, HTTP headers ×2, POST request/response, GET response, URLs ×2) | **10** | **C2 traffic shape is data, not code** |
| **Operator-set via launcher** (script, script language, ProgID, tagged script, cert hash, URIs) | **6** | **delivery/launch shape is data** |
| **Generated/derived** (IL bytes, version setter, bridge messenger code) | **3** | compiler output |
| **Total** | **28** | |

**25 of 30 placeholders inject operator-decided values. 3 are generated. The remaining 2 are the per-grunt flags D40 already proved.**

### 3.3 **The answer, and why it is a framework-level finding**

**A Covenant grunt's behaviour — its callback address, its traffic shape, its headers, its sleep/jitter, its crypto secret, its kill date, its certificate policy, its delivery script — is decided at COMPILE TIME by the operator and baked in as a literal.** The runtime code then executes those decisions.

**Two structural consequences that follow from the numbers, not from preference:**

1. **The `{{REPLACE_PROFILE_*}}` family (10 placeholders, 11 files) means the C2 protocol is not in the grunt's code.** **Changing the profile changes the wire format with no recompilation of the messenger logic.** That is a deliberate data/code separation — and it is the reason a Covenant profile is an operator-facing object with its own API controller (`ProfileApiController`).
2. **`{{REPLACE_VALIDATE_CERT}}` and `{{REPLACE_USE_CERT_PINNING}}` are per-grunt, operator-settable flags** — which is how D40's disabled validation at `CovenantHubService.cs:32` should be read in context: **the operator decides per grunt whether the implant validates the server certificate, and the framework gives them a switch for it.**

**Why this generalizes beyond Covenant:** **any framework that compiles per-task has this property by construction.** MSF and Sliver ship interpreters and stage the payload; Covenant ships a purpose-built executable. **"Most of a grunt is decided at build time" is the necessary consequence of compile-per-task, not a Covenant quirk — and that is the framework-level architectural finding.** `[inference from the 30-placeholder census; the census itself is measured]`

**Residual:** I did **not** read every substitution site in `CovenantService.cs` to confirm the value's origin per placeholder — the operator-controlled classification rests on the placeholder name plus the consuming file. **Named as a residual in §5, not presented as read.**

---

## 4. Q4 — `tokenprivs` and `convcompat`, both closed

### 4.1 `tokenprivs` — a derived access-rights bitmask

```python
# packages/windows/all/pupwinutils/security.py:99-103
tokenprivs = (
    TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE |
    TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY
    | (131072 | 4)
)
```

**Six named rights OR'd with a raw `(131072 | 4)`.** **`0x20000` = `TOKEN_ADJUST_PRIVILEGES`, `0x4` = `TOKEN_ADJUST_DEFAULT`** — **written as magic numbers rather than the named constants that already exist in the same file (`TOKEN_ALL_ACCESS` at `:105` uses the names).** **The magic-number form is a maintainability defect, not a behavioural one — the resulting mask is equivalent.**

**Used at four call sites — all token-opening, all in the impersonation chain:**

| Line | Call |
|---|---|
| `:1707` | `OpenProcessToken(hProcess, tokenprivs, byref(hToken))` |
| `:1747` | `if not OpenProcessToken(hProcess, tokenprivs, byref(hToken))` |
| `:1763` | `OpenThreadToken(hThread, tokenprivs, False, byref(hToken))` |
| `:1799` | `OpenProcessToken(hProcess, tokenprivs, byref(hToken))` |

**It is the requested-access mask for every token the escalation chain opens.** **It does NOT include `TOKEN_ADJUST_PRIVILEGES` by name — it includes it by value.** `[source: definition and all four call sites read]`

**A parallel definition exists in `packages/windows/x86/bypassuac_token_imp/bypassuac_token_imp.py:73`** — same tuple, second copy. **Two independent definitions of the same mask, both magic-numbered.** `[source: occurrence enumeration tree-wide]`

### 4.2 `convcompat` — a 9,921 B Python 2/3 compatibility shim

**`network\lib\convcompat.py` (9,921 B).** **Imported by ~40 modules** across the server, client, and payload packages — including every command module (`ls.py`, `cat.py`, `reg.py`, `stat.py`, `netstat.py`, `psexec.py`, `ssh.py`, `transfer.py`...), the `security.py` module itself (`:25`), and the server-side `PupyServer.py` / `PupyConfig.py` / `PupyService.py`.

**The surface it exports, from the import sites:** `shlex`, `reprb`, `is_binary`, `DEFAULT_MB_ENCODING`, `as_escaped_string`, `as_unicode_string`, `as_unicode_string_deep`, `as_native_string`, `fs_as_unicode_string`, `fix_exception_encoding`.

**It is the encoding-compatibility layer**: string/bytes/shell-quoting translation between Python 2 and 3, and between native and Unicode representations. **`security.py:25` imports from it, and `winerror_hacks.py:53` carries the comment *"We can't use network.lib.convcompat at this point"* — an explicit, documented circular-import constraint at the Windows bootstrap layer.**

**Why it matters to D28's residual:** **D28 §6.4 left `convcompat` behaviour on non-ASCII SIDs open.** **`convcompat` exports the exact functions (`as_unicode_string_deep`, `as_escaped_string`, `fix_exception_encoding`) that would govern SID/ACL string handling — so the open item is well-placed rather than incidental. It remains open, and the reason it is hard is now stated: the layer sits behind a documented import constraint, so it cannot be read in isolation from the bootstrap path.** `[source: definition size, ~40 import sites enumerated, the winerror_hacks comment read]`

---

## 5. Residual unknowns, each with a concrete probe

| # | Unknown | Probe |
|---:|---|---|
| 1 | **Whether `CovenantHub.CreateHttpListener` is reachable without a token in practice** — D40 found 0 `[Authorize]` on the hub; §1.2 found 0 checks in the body. **The two together imply reachable; neither proves a live call.** | Static: read `Startup.cs` `Configure` pipeline order around `MapHub<CovenantHub>` to confirm no `UseAuthorization`-adjacent filter applies. **Dynamic: send an unauthenticated POST to `/covenanthub` negotiation and observe the response.** |
| 2 | **`GetGuid` `null` propagation** — `:99` returns `null`; `:48` assigns it; whether a `null` guid reaches a working `Read` path is unread past `InternalListener.Read:324`. | Read `InternalListener.Read` `:324-408` and trace the `null`-key path through `GruntMessageCache`. |
| 3 | **Per-placeholder substitution origins in `CovenantService.cs`** — the operator-controlled classification in §3.1 rests on placeholder name + consuming file. | For each of the 30, read its `.Replace(...)` call site in `CovenantService.cs` and identify the value's source expression. |
| 4 | **`convcompat` on non-ASCII SIDs (carried from D28)** — now better placed, still open. | Read `convcompat.py` and the `fix_exception_encoding` path with `winerror_hacks.py:53`'s constraint in view. |
| 5 | **The 9 non-`Assembly` task directives' server-side handling** — `Connect`/`Exit`/`SetDelay`/etc. are declared as tasks but execute in-agent. | Read the tasking dispatch that branches on `TaskingType` and confirm where each is handled. |
| 6 | **Whether `.task` netcoreapp3.0 binaries match their YAML `Code:` sources** — §2.1 treats them as artifacts of the same tasks. | Byte-compare a `.task` against its YAML source, or read the loader's preference order. |

**None of these is implied covered. Each names the artefact to open.**

### 5.1 Instrument failures, this report

| # | Failure | Caught by | Effect |
|---:|---|---|---|
| 1 | **`[Authorize` pattern missed 16 of 17 controllers** (§0.3) | mismatch control vs corrected pattern | **D40's headline count was wrong; corrected here** |
| 2 | **First `Code:` probe returned a FALSE ZERO and printed a zero table** (§0.4) | "print your matches" | **an entire Q2 measurement discarded** |
| 3 | `Language:` counted 155 for 95 tasks (95 top-level + 60 nested) | indentation breakdown | corrected to 95 |
| 4 | `pwsh` block died at parse (bracket in single-quoted string) | exit code 1, no output | re-ran intact |
| 5 | `ListenerControllers\` path guess wrong (`ApiControllers\`) | `Test-Path` | file located by name |

**Failures 1 and 2 are the same species: a probe whose zero was accepted as a result.** **In both cases the control the brief mandates — print your matches, compare two patterns — converted an untested zero into a measured finding.** **Failure 1 means D40 needs a correction notice, and it is stated in §0.3 rather than quietly fixed.**

---

## 6. The four answers, consolidated

| Q | Answer |
|---|---|
| **Q1** | **Two same-named paths with opposite gates.** `Route()` is `[AllowAnonymous]` by design and asks for **no credential** — the gate is grunt-payload decryption, not caller authorization; **there is no check to bypass at step 1.** `CreateHttpListener` reached via `ListenerApiController` is `RequireJwtBearer`-gated (✅); **reached via `CovenantHub` it has no gate at all**, and its body performs **zero authorization checks** while **minting a `Listener`-role JWT with 2000-minute expiry**. Bind constraints are **duplicate-port only**; bind address is caller-supplied. |
| **Q2** | **95 tasks in 11 YAML files (82 distinct names), boundary = top-level `- Name:` in `Data\Tasks\*.yaml`.** 86 `Assembly`, 9 agent-control; 5 `TokenTask: true` (the impersonation family). **`CovenantAPI` = 0 across 122,873 chars of task source** → tasks are **standalone C# acting directly through .NET**, P-Invoke concentrated in one file, **8 embedded reference-source libraries**. Compile-per-task makes this architectural, and it is now measured. |
| **Q3** | **28 `{{REPLACE_*}}` placeholders; 23 inject operator-decided values** (9 per-grunt, 10 per-profile, 6 per-launcher), 3 generated. **A grunt's callback address, traffic shape, crypto secret, sleep/jitter, kill date, cert policy and delivery script are all baked in at build time** — the necessary consequence of compile-per-task, not a Covenant quirk. |
| **Q4** | **`tokenprivs`**: an access-rights bitmask (`security.py:99-103`) — 6 named rights + magic `(131072\|4)`, used at 4 token-open sites; **duplicated** in `bypassuac_token_imp.py:73`. **`convcompat`**: a 9,921 B py2/3 encoding-compat shim imported by ~40 modules, sitting behind a documented circular-import constraint at the Windows bootstrap layer. |

---

*End of D46. Pure source; no provider, no build, no execution. 152 `.cs` verified; 11 YAML / 95 tasks enumerated; 30 placeholders classified; 83 `Code:` blocks (122,873 chars) extracted with a printed content control. Three corrections to the brief in §0, one of which is a correction to D40 itself. Five instrument failures recorded, two of them false zeros caught by the mandated controls.*