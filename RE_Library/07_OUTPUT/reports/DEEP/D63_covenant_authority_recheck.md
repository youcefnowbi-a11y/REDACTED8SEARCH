# D63 — Covenant Authority Recheck

**Target:** `RE_Library/01_SOURCE_c2/covenant/Covenant/`
**Class:** source-only reversal (NO REA/GHIDRA)
**Task:** task-55, owner `covenant-diver`
**Tags:** `[read]` = read directly · `[verified]` = confirmed by two independent instruments, control passed · `[inferred]` = my deduction · `[absence]` = searched and not found, with search AND positive control stated

Cross-references D40 (authority census), D46 (`CreateHttpListener`), D50 (API/task library), D52 (consumption path). This report re-derives rather than repeats.

---

## §0 — Corrections, led with

### §0.1 D40's false zero is reproducible, and it is worse than the brief states

`[verified]` **I reproduced D40's `\[Authorize` false zero exactly: 8 hits / 6 files.** The brief's figure is right. `[verified]`

`[verified]` **Corrected instrument `\bAuthorize\s*\(` gives 20 hits / 17 files.** The brief quotes **25 hits / 22 files** — that figure is *also* right, and it is right for a reason the brief does not state: **it counts both attribute forms.** `[verified]`

| Instrument | Hits | Files | What it sees |
|---|---:|---:|---|
| `\[Authorize` (D40) | **8** | **6** | only where `[` is immediately adjacent — controllers with parenthesized `Authorize` mid-list are **invisible**, and **all 5 hub bare-`[Authorize]` sites are visible** `[verified]` |
| `\bAuthorize\s*\(` | **20** | **17** | all 17 controllers; **0 hubs** — bare `[Authorize]` has no paren `[verified]` |
| `\bAuthorize` (word-bounded, both forms) | **25** | **22** | 17 controllers + 5 hub files `[verified]` |

`[verified]` **The two forms are disjoint and neither single probe catches both.** D40's probe caught the *hubs* and missed the *controllers*. The brief's corrected probe catches the *controllers* and misses the *hubs*. **A census that adopted `\bAuthorize\s*\(` alone would have silently dropped D40's five hub hits — including the `CovenantHub` exceptions-of-six finding, which survives.** `[verified]` **Both probes are required; neither is "the fix."**

### §0.2 D40's hub table SURVIVES intact — this is the part I checked first

`[verified]` Because the corrected probe returns **zero** on hubs, the risk was that D40's central hub finding had been an artifact. **It was not.** Re-derived with comment-stripping, both forms counted separately:

| Hub file | paren | bare | total |
|---|---:|---:|---:|
| `Hubs/CovenantHub.cs` | 0 | **0** | **0** |
| `Hubs/GruntHub.cs` | 0 | 1 | 1 |
| `Hubs/EventHub.cs` | 0 | 1 | 1 |
| `Hubs/GruntCommandHub.cs` | 0 | 1 | 1 |
| `Hubs/GruntTaskingHub.cs` | 0 | 1 | 1 |
| `Hubs/CommandOutputHub.cs` | 0 | 1 | 1 |

`[verified]` **`CovenantHub` is the sole exception of six. D40's headline holds under an independent instrument.** The false zero damaged D40's *controller* census, not its *hub* census.

### §0.3 MY OWN ARITHMETIC ERROR — D50 §2.1's ledger does not add up

`[verified]` D50 §2.1 published **21 `Authorize` across 17 controllers** with a per-file table reading `CommandOutput 1, CovenantUser 4, …(14 more × 1)`. **Correct total is 20.** 16 files × 1 + 4 = **20**, not 21. **My table was internally consistent per row and wrong in its sum** — the D13 error class, one report later. `[verified]`

`[verified]` Per-controller, printed, re-derived: **exactly one file carries more than one — `CovenantUserApiController.cs` at 4** (L17 `RequireJwtBearer`, L205/L300/L326 `RequireAdministratorRole`). The other 16 carry exactly 1 each. `[verified]`

### §0.4 A D40 GAP THE BRIEF DID NOT ANTICIPATE — there are EIGHTEEN controllers, not seventeen

`[verified]` D40 and D50-D52 all enumerate `Controllers/ApiControllers/` — **17 files.** The tree contains a **second controller directory**: `Covenant/Controllers/ListenerControllers/`, holding **`HttpListenerController.cs`.** `[read]`

`[verified]` **It is a controller, it is routed, and it carries class-level `[AllowAnonymous]` at `:21` plus method-level at `:41` — the only fully anonymous controller in the tree.** `[verified]`

**Total controllers: 18 across two directories.** Every prior Covenant report that said "17 controllers" is a correct count **of `ApiControllers/`** — denominator species 6 (a correct count of the wrong thing under a heading that reads as the whole). **The correct total is 18.** `[verified]`

---

## 1. Q1: D40's census re-run

**Invocation for every figure below:** per-file `Get-ChildItem -Recurse -Filter *.cs` over `Covenant/`, **comments stripped before matching** (block `/* */` singleline, then line `//`), pattern as stated per row. Matches printed for every non-zero cell that moved.

### 1.1 Every figure, D40's value vs re-derived

| # | D40's figure | D40's invocation | Re-derived | Moved? |
|---|---|---|---|---|
| 1 | `[Authorize]` **8 / 6 files** (§1.2 table summed 5+1, §2.6 said 9/6) | `\[Authorize` | **25 / 22** (both forms); **20 / 17** (paren only) | **YES — up 3.1×** `[verified]` |
| 2 | Hub `[Authorize]` 0/1/1/1/1/1 | `\[Authorize` per hub | **identical** | **no** `[verified]` |
| 3 | `AllowAnonymous` — **`CovenantUserApiController` only** | not stated | **4 hits / 2 files** — adds **`ListenerControllers/HttpListenerController.cs` ×2** | **YES — a whole file missing** `[verified]` |
| 4 | `RequireRole` **4** | enumerated | **4** (`Startup.cs` ×2, `HttpListener.cs` ×2) | no `[verified]` |
| 5 | `RequireAdministratorRole` refs | not totalled | **7** (`Startup` ×2, `CovenantUserApiController` ×3, `HttpListener` ×2) | new figure `[verified]` |
| 6 | `RequireJwtBearer` | not totalled | **21** | new figure `[verified]` |
| 7 | `IsInRole` | **not reported** | **3** (`Covenant.cs:253`, `CovenantService.cs:487`, `Login.cshtml.cs:40`) | **YES — absent from D40** `[verified]` |
| 8 | `User.Identity` | not reported | **0** | — `[verified]` |
| 9 | `CovenantHubService` authz constructs all 0 | enumerated, stripped | **verified 0** | no `[verified]` |
| 10 | `IAuthorizationFilter`/`Handler`/`AuthorizeFilter` = 0 | enumerated | **0** | no `[verified]` |
| 11 | Middleware/filter FILES = 0 | filename enumeration | **0** | no `[verified]` |
| 12 | Controllers | 17 (`ApiControllers/`) | **18** (2 directories) | **YES** `[verified]` |
| 13 | `OnConnectedAsync`/`OnDisconnectedAsync` = 0 | enumerated | **0** | no `[verified]` |

`[verified]` **Moved: 4 of 13 (rows 1, 3, 7, 12). Held: 9 of 13.** The false zero propagated into **three** published figures, not one.

### 1.2 The `AllowAnonymous` finding, printed

`[verified]` **All four sites, tree-wide:**

```
Covenant/Controllers/ApiControllers/CovenantUserApiController.cs   L107: [AllowAnonymous]
Covenant/Controllers/ApiControllers/CovenantUserApiController.cs   L131: [AllowAnonymous]
Covenant/Controllers/ListenerControllers/HttpListenerController.cs L21:  [AllowAnonymous]   ← CLASS-LEVEL
Covenant/Controllers/ListenerControllers/HttpListenerController.cs L41:  [AllowAnonymous]   ← method
```

`[read]` **`HttpListenerController.cs:21-22,41-42`:**
```csharp
[AllowAnonymous]
public class HttpListenerController : Controller
{
    ...
    [AllowAnonymous]
    public async Task<ActionResult<string>> Route()
```

`[inferred]` **This is the implant-facing endpoint, and it is anonymous by design** — an implant checking in cannot present a JWT. `[read]` It calls `_internalListener.Read(guid)` / `.Write(guid, ExtractedMessage)` at `:51/:59`, the same `InternalListener` class as D50/D52's `GetGruntTaskingMessage`. **The design intent is coherent.** `[verified]` **But D40's census did not list it**, and the class-level attribute plus a `Route()` with **no route prefix** means it is reachable at whatever `Startup` maps it to. **Recorded as a census gap, not as a defect.**

### 1.3 The `IsInRole` sites D40 never reported

`[verified]` **Three, and two of them are authorization decisions:**

| Site | Line | Text | Significance |
|---|---|---|---|
| `Covenant/Covenant.cs` | `:253` | `return principal.IsInRole("Administrators");` | **`"Administrators"` — plural. The seeded role is `"Administrator"` — singular.** See §1.4 |
| `Covenant/Core/CovenantService.cs` | `:487` | `if (_userManager.Users.Any() && !principal.IsInRole("Administrator"))` | the Q2 guard |
| `Covenant/Pages/Login.cshtml.cs` | `:40` | `if (!_userManager.Users.ToList().Where(U => _userManager.IsInRoleAsync(U, "Administrator").WaitResult()).Any())` | first-user detection |

### 1.4 A role-name mismatch found while re-deriving

`[read]` `Covenant/Covenant.cs:253` tests `IsInRole("Administrators")` — **plural.**

`[verified]` The only role names ever created are from `Covenant/Core/DbInitializer.cs:418-428`:
```csharp
List<string> roles = new List<string> { "Administrator", "User", "Listener", "SignalR", "ServiceUser" };
```
**Five roles, all singular. `"Administrators"` is never created.** `[verified]`

`[verified]` And every other role test in the tree uses the **singular** form: `RequireRole("Administrator")` ×4, `IsInRole("Administrator")` ×2. `[verified]`

`[inferred]` **`Covenant.cs:253` is a check that can never return `true`.** Whether it *matters* depends on whether the method containing it is reached — which §3 resolves. **Recorded here as measured; I am not claiming impact until §3.**

```csharp
// Covenant/Covenant.cs:253
return principal.IsInRole("Administrators");     // plural — role never seeded
```

---

## 2. Q2: the `CreateUser` role

### 2.1 The answer, stated explicitly as the brief requires

`[verified]` **Default role: `"User"` — hardcoded. The caller does NOT control it.**
`[verified]` **Exception: if the user table is EMPTY, the account is granted `"Administrator"`.**

`[read]` **`Covenant/Core/CovenantService.cs:495-496`:**
```csharp
CovenantUser created = await CreateUser(new CovenantUserLogin { UserName = register.UserName, Password = register.Password });
await _userManager.AddToRoleAsync(created, "User");        // :496 — hardcoded literal
```

### 2.2 The caller cannot choose — proved by the model

`[read]` **`Covenant/API/Models/CovenantUserRegister.cs`** — the `[FromBody]` type of `CreateUser`. `[verified]` **Four properties, exhaustively:**

| Property | JSON name | Line |
|---|---|---|
| `ConfirmPassword` | `confirmPassword` | `:43` |
| `Id` | `id` | `:47` |
| `UserName` | `userName` | `:53` |
| `Password` | `password` | `:58` |

`[verified]` **No `Role` property. No `Roles` property. No array, collection, or dictionary of any kind.** The `Validate()` method (`:66-80`) requires only that `ConfirmPassword`, `UserName`, and `Password` be non-null. `[verified]`

`[inferred]` **There is no wire shape by which a caller could express a role preference.** The deserializer has no target for it. This is a **structural** negative, not a lexical one — the D50 §5 rule applied correctly.

### 2.3 The escalation is real but CONDITIONAL — first-user bootstrap

`[read]` **`Covenant/Core/CovenantService.cs:481-503`, the full guard chain:**
```csharp
if (_userManager.Users.Any() && !principal.Identity.IsAuthenticated)              // :483
    throw new ControllerUnauthorizedException("...Must be signed in to register...");
if (_userManager.Users.Any() && !principal.IsInRole("Administrator"))            // :487
    throw new ControllerUnauthorizedException("...Must be signed in as an Administrator...");
if (register.Password != register.ConfirmPassword)                               // :491
    throw new ControllerBadRequestException("...Password does not match...");
CovenantUser created = await CreateUser(new CovenantUserLogin { ... });          // :495
await _userManager.AddToRoleAsync(created, "User");                              // :496
```

`[verified]` **BOTH authorization guards are prefixed `_userManager.Users.Any() &&`.** When the user table is empty, **both conditions short-circuit to `false` and neither throws.** The anonymous `POST api/users` route then reaches `CreateUser`, where:

`[read]` **`Covenant/Core/CovenantService.cs:520-523`:**
```csharp
if (!_userManager.Users.Any())
{
    await _userManager.AddToRoleAsync(user, "Administrator");    // :522
}
```

`[verified]` **The same empty-table condition that disables the guard enables the Administrator grant.** One predicate, two opposite effects, twelve lines apart.

### 2.4 The concrete scenario, stated as a scenario

`[inferred]` **On a Covenant instance whose user table is empty — a fresh install, or a post-reset database — an unauthenticated remote caller who reaches `POST api/users` before any legitimate user is created receives a full `Administrator` account.** `[verified]` The route is `[AllowAnonymous]` (`:131`), the guards are skipped (§2.3), and the grant is unconditional within that branch (`:520-522`).

`[inferred]` **After the first user exists, the exposure closes completely:** both guards become live, the anonymous path throws `ControllerUnauthorizedException` → `401` (`CovenantUserApiController.cs:149-151`), and any subsequent account is `"User"`. **This is a bootstrap race, not a standing hole.** I am not enlarging it.

### 2.5 The deliberate escalation path, and it IS guarded

`[verified]` The role-granting API is a **separate** method — `CovenantService.cs:669-682 CreateUserRole(userId, roleId)` — and its controller route is admin-gated:

```
CovenantUserApiController.cs:300: [Authorize(Policy = "RequireAdministratorRole")]
CovenantUserApiController.cs:301: [HttpPost("users/{id}/roles/{rid}", Name = "CreateUserRole")]
CovenantUserApiController.cs:303: public async Task<ActionResult<IdentityUserRole<string>>> CreateUserRole(string id, string rid)
```

`[read]` **`:669-682` reads the role from the database by ID** (`:676 GetRole(roleId)` → `:682 AddToRoleAsync(user, role.Name)`) — **not from caller-supplied text.** So the only path that grants an arbitrary role requires `Administrator`, and the role name comes from the DB. `[verified]`

`[inferred]` **Net answer to the brief's question: the `CreateUser`-created account gets `"User"`, the caller cannot influence it, and the one path that CAN grant a privileged role is admin-gated and DB-sourced. The escalation is confined to the empty-table bootstrap (§2.4).**

---

## TOC

1. [§1 — Q1: D40's census re-run under the word-bounded instrument](#1-q1-d40s-census-re-run)
2. [§2 — Q2: what role does a `CreateUser`-created account get?](#2-q2-the-createuser-role)
3. [§3 — Q3: the authority surface of `CovenantService.cs`](#3-q3-the-authority-surface-of-covenantservicecs)
4. [§4 — Q4: R-52.6.1, the `Token==true` co-occurrence probe](#4-q4-r-5261-token-co-occurrence)
5. [§5 — Instrument record](#5-instrument-record)
6. [§6 — Residual unknowns](#6-residual-unknowns)

---
