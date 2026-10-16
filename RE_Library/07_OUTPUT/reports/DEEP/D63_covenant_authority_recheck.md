# D63 — Covenant Authority Recheck

**Target:** `RE_Library/01_SOURCE_c2/covenant/Covenant/`
**Class:** source-only reversal (NO REA/GHIDRA)
**Task:** task-55, owner `covenant-diver`
**Tags:** `[read]` = read directly · `[verified]` = confirmed by two independent instruments, control passed · `[inferred]` = my deduction · `[absence]` = searched and not found, with search AND positive control stated

Cross-references D40 (authority census), D46 (`CreateHttpListener`), D50 (API/task library), D52 (consumption path). This report re-derives rather than repeats.

---

## TOC

- **§0 — Corrections, led with** · §0.1 D40's false zero, reproduced · §0.2 D40's hub table survives · §0.3 **my own arithmetic error** · §0.4 **18 controllers, not 17**
- **§1 — Q1: D40's census re-run** · 13 figures compared · 4 moved · `AllowAnonymous` (+1 file) · `IsInRole` (never reported) · §1.4 **retracted**
- **§2 — Q2: the `CreateUser` role** · **§2.1 the answer** · caller cannot choose · first-user bootstrap · §2.6 retraction
- **§3 — Q3: `CovenantService.cs` authority surface** · 179 reachable methods · **only 2 can see a principal** · `CreateHttpListener` **has a twin**
- **§4 — Q4: R-52.6.1 closed** · `Token==true` = 5, all `Assembly` · **clean negative, D52 §2.3 stands**
- **§5 — Instrument record** · failures #15/#16/#17 · species ledger
- **§6 — Residuals** · R-63.1 … R-63.6

**Headline:** D40's `[Authorize]` figure is wrong in **both** dimensions (8/6 → **25/22**), the error propagated into **four** published figures across two reports, and **D40 contradicts itself** between its line 103 (five files) and line 270 (9/6) — the disagreement is the only surviving trace. Separately: **`CreateUser` grants the caller no role choice; the default is `"User"`; the escalation is confined to an empty user table.**

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

### 2.6 A thread from D52 §1.4 — retracted

`[read]` I flagged `Covenant.cs:253` in §1.4 as a possible dead role check, since it tests `IsInRole("Administrators")` (plural) while only `"Administrator"` is ever seeded. **Reading the containing method resolves it against my lead, and I am withdrawing the implication.**

`[read]` **`Covenant/Covenant.cs:247-256`:**
```csharp
private static bool IsElevated()
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole("Administrators");       // :253
    }
    return Environment.UserName.Equals("root", StringComparison.CurrentCultureIgnoreCase);
}
```

`[verified]` **`"Administrators"` is the correct Windows LOCAL GROUP name — plural is right.** The principal is a `WindowsPrincipal` built from `WindowsIdentity.GetCurrent()`, not a `ClaimsPrincipal` from a JWT. The method asks "is this Covenant process elevated on the host?" — an OS question. `[read]`

`[inferred]` **My §1.4 flag was a lexical match on a shared token across two unrelated domains** — ASP.NET Identity roles and Windows local groups. **That is instrument failure #13's shape again, in a new costume: I matched on a string where the question was about which *system* the string addresses.** `[verified]` **No defect. Recorded because I raised it.**

---

## 3. Q3: the authority surface of `CovenantService.cs`

### 3.1 The enumeration key — built from the class body, not by prefix

`[read]` `CovenantService` is registered `AddTransient<ICovenantService, CovenantService>()` at **`Covenant/Startup.cs:195`**, and controllers hold it as **`_service`**. So the reachable set is every `_service.X(...)` call site in a controller body — **enumerated by scanning controller method bodies for the call expression, not by filtering method names.** `[verified]` This is the D56 trap avoided: a name-prefix filter on `Create*` would have dropped `GetCurrentUser`, `InteractGrunt`, and `Login`; a filter on `*HttpListener` would have merged two different methods.

`[verified]` **179 distinct service methods are invoked from controllers.** Full list derived; the classification follows.

### 3.2 The gate structure — one attribute per controller, at class level

`[read]` Mapped every `[Http*]` action to its class-level and method-level attributes. `[verified]` **The result is unusually uniform:**

| Controller | Class attribute | Action-level overrides |
|---|---|---|
| `ApiControllers/*` — **16 of 17** | `[ApiController, Route(...), Authorize(Policy = "RequireJwtBearer")]` | **none** `[verified]` |
| `ApiControllers/CovenantUserApiController.cs` | `[ApiController, Route("api"), Authorize(Policy = "RequireJwtBearer")]` | **5**: `:107` `[AllowAnonymous]`, `:131` `[AllowAnonymous]`, `:205`/`:300`/`:326` `[Authorize(Policy = "RequireAdministratorRole")]` `[verified]` |
| `ListenerControllers/HttpListenerController.cs` | **`[AllowAnonymous]`** — no `Authorize` anywhere in the file | class-level *and* `:41` `[AllowAnonymous]` `[verified]` |

`[verified]` **`RequireAdministratorRole` appears at action level in exactly THREE places, all in `CovenantUserApiController.cs`** — matching §1.1 row 1's `RequireAdministratorRole` count of 7 (2 in `Startup.cs` as a policy definition, 2 in `HttpListener.cs` as a policy definition, **3 as actual controller annotations**). `[verified]`

### 3.3 The structural answer: only TWO methods in the file can even SEE a principal

`[read]` Exhaustive `ClaimsPrincipal` enumeration across the whole tree. `[verified]` **In `CovenantService.cs` — 255,768 B, 5,138 lines, 179 controller-reachable methods — exactly two methods accept a `ClaimsPrincipal`:**

| Method | Interface | Impl | Site |
|---|---:|---:|---|
| `GetCurrentUser(ClaimsPrincipal principal)` | `:36` | `:446` | `CovenantUserApiController.cs:82,162` `[read]` |
| `CreateUserVerify(ClaimsPrincipal principal, CovenantUserRegister register)` | `:38` | `:481` | `CovenantUserApiController.cs:138` `[read]` |

`[verified]` **The other 177 controller-reachable methods have no principal parameter, therefore contain no role decision, therefore are guarded entirely by the controller's class-level attribute.** `[verified]`

`[inferred]` **This is the single most important structural fact about Covenant's authority model: authorization is ONE attribute per controller class, enforced by ASP.NET's middleware, and the service layer is structurally incapable of a second check.** There is no defense in depth because there is no second place to put one. **D40 §3.1's "authorization is attribute-only" finding is correct, and this is *why*.**

### 3.4 The `CreateHttpListener` siblings — D46's finding has a verbatim twin

**The brief asks: "Are there siblings?"** `[verified]` **Yes — exactly one, and it is a structural clone.**

`[read]` **Exhaustive account-minting census in `CovenantService.cs`** — every `GenerateJwtToken` site, every `CreateUserRole(` call, every `new CovenantUserLogin`:

| Line | Site | Role granted | JWT lifetime | Principal? |
|---|---|---|---:|---|
| `:473` | `Login` | caller's own | per config | n/a — this is the login path `[read]` |
| **`:3964`** | **`CreateHttpListener`** | **`Listener`** | **`2000`** | **NONE** `[verified]` |
| **`:4002`** | **`CreateBridgeListener`** | **`Listener`** | **`2000`** | **NONE** `[verified]` |

`[read]` **The two are line-for-line equivalents** (`:3950-3987` vs `:3989-…`):
```csharp
string password = Utilities.CreateSecureGuid().ToString() + "A";          // :3955 / :3993
CovenantUser listenerUser = await this.CreateUser(new CovenantUserLogin
{
    UserName = Utilities.CreateSecureGuid().ToString(),
    Password = password
});                                                                        // :3956 / :3994
IdentityRole listenerRole = await this.GetRoleByName("Listener");          // :3961
IdentityUserRole<string> userrole = await this.CreateUserRole(listenerUser.Id, listenerRole.Id);  // :3962 / :4000
listener.CovenantToken = Utilities.GenerateJwtToken(
    listenerUser.UserName, listenerUser.Id, new[] { listenerRole.Name },
    _configuration["JwtKey"], _configuration["JwtIssuer"],
    _configuration["JwtAudience"], "2000"                                  // :3967 / :4005
);
```

`[verified]` **D46's `CreateHttpListener` characterization is exactly right — zero authorization checks, a `Listener`-role account, a 2000-minute JWT — and `CreateBridgeListener` reproduces it verbatim.** The only differences are the profile getter (`GetHttpProfile` vs `GetBridgeProfile`, `:3953` vs `:3991`) and the role lookup idiom (`GetRoleByName("Listener")` at `:3961` vs `_context.Roles.FirstOrDefaultAsync(R => R.Name == "Listener")` at `:3999`). `[verified]`

### 3.5 The guard on the siblings, and where the asymmetry actually is

`[verified]` **Both service methods are reachable from TWO controller routes with DIFFERENT guards:**

| Route | Controller site | Guard | Service method |
|---|---|---|---|
| `POST api/listeners/http` | `ListenerApiController.cs:156-161` | **`RequireJwtBearer`** (class, `:16`) `[read]` | `CreateHttpListener` `[read]` |
| `POST api/listeners/bridge` | `ListenerApiController.cs:219-…` | **`RequireJwtBearer`** (class, `:16`) `[read]` | `CreateBridgeListener` `[read]` |
| hub `CreateHttpListener` | **`CovenantHub.cs:162-165`** | **NONE — no `[Authorize]`** (§0.2) `[verified]` | `CreateHttpListener` `[read]` |

`[inferred]` **The asymmetry D46 found is not in the service method — it is in the ROUTE.** The REST route is `RequireJwtBearer`-guarded; the hub route is unguarded. **The same service method, two entry points, one gate.** D46's finding stands; **§3.4 shows it is a two-instance class of finding, not one**, because `CreateBridgeListener` sits behind the identical service-level absence and the hub would expose it the same way if a hub method forwarded to it.

`[read]` **`CovenantHub.cs:162-165` is live, not comment-enclosed** — `[verified]` the enclosing block comment ends at `:161` (`*/`) and the next `/*` opens at `:166`, so **`:162-165` is between two comment blocks, which is exactly how D32 §2 described this class's structure.** `[verified]` This is D32's **block-commenting** hidden-boundary mechanism, and it is what makes `CreateHttpListener` the only live method of 222 apparent ones (D40 §1.1). `[verified]`

### 3.6 The class-level classification, stated as the brief requires

`[verified]` **Guarded / unguarded, for every controller-reachable surface:**

| Class | Controller-reachable methods | Guard | Verdict |
|---|---:|---|---|
| 15 `ApiControllers/*` (single-purpose) | 15 cont. / 15 svc methods | class `RequireJwtBearer` | **guarded** (no principal seen by service) `[verified]` |
| `CovenantUserApiController` | 17 actions | class `RequireJwtBearer`; 2 `AllowAnonymous`; 3 `RequireAdministratorRole` | **mixed — see table** `[verified]` |
| `HttpListenerController` (ListenerControllers) | 1 action | **`AllowAnonymous` (class)** | **UNGUARDED — implant-facing by design** `[verified]` |
| `CovenantHub` (`/covenanthub`) | **1 live method** (`CreateHttpListener`) | **NONE** | **UNGUARDED — D46's finding** `[verified]` |

`[read]` **`CovenantUserApiController` broken out — all 17 actions:**

| Guard | Count | Actions |
|---|---:|---|
| `AllowAnonymous` | **2** | `:108` `POST users/login` → `Login`; `:132` `POST users` → `CreateUserVerify` `[verified]` |
| `RequireAdministratorRole` (method-level) | **3** | `:206` `DELETE users/{id}` → `DeleteUser`; `:301` `POST users/{id}/roles/{rid}` → `CreateUserRole`; `:327` `DELETE users/{id}/roles/{rid}` → `DeleteUserRole` `[verified]` |
| class `RequireJwtBearer` only | **12** | the remainder `[verified]` |

`[verified]` **Bound: 18 controllers, 2 directories, every `[Http*]` action in each enumerated from the class body, every service call resolved to an `ICovenantService` member.** The two `AllowAnonymous` routes are the complete set of unauthenticated REST surface; `HttpListenerController.Route()` is the third unauthenticated endpoint and the only one that is *entirely* unauthenticated. `[verified]`

---

## 4. Q4: R-52.6.1, the `Token==true` co-occurrence

### 4.1 The probe, run as stated

`[read]` **Invocation:** every `TokenTask` occurrence across `Covenant/Data/Tasks/*.yaml` (the YAML key) **and** every `TokenTask` in `*.cs` (the C# property), enumerated with `Get-ChildItem -Recurse` + per-file `Select-String`, matches printed. `[verified]`

### 4.2 The answer

`[verified]` **`Token == true` CAN occur — 5 tasks set it. It CANNOT co-occur with a control tasking type. R-52.6.1 resolves as a clean negative, and D52 §2.3 stands.**

`[verified]` **Counts, both species, over `Covenant/Data/Tasks/` (11 files):**

| Value | Count |
|---|---:|
| `TokenTask: true` | **5** |
| `TokenTask: false` | **90** |
| **`TokenTask:` any** | **95** |

`[verified]` **95 total reconciles exactly with D50's 95-task figure and D40's boundary** — every task definition declares the key, so the key count IS the task count.

### 4.3 The five `true` tasks, named

`[read]` All five are in **`SharpSploit.Credentials.yaml`:**

| Line | Task | `TaskingType` at | Type |
|---|---:|---|---|
| `L51` | `MakeToken` | `L49` | **`Assembly`** `[verified]` |
| `L178` | `GetSystem` | `L176` | **`Assembly`** `[verified]` |
| `L272` | `ImpersonateProcess` | `L270` | **`Assembly`** `[verified]` |
| `L373` | `ImpersonateUser` | `L371` | **`Assembly`** `[verified]` |
| `L701` | `RevertToSelf` | `L699` | **`Assembly`** `[verified]` |

`[inferred]` **The semantic is coherent and instructive: all five are token-manipulation tasks** — make a token, steal SYSTEM, impersonate, revert. `TokenTask: true` means *"this task manipulates the grunt's process token,"* which is precisely why only these five carry it. `[verified]` **The key is task-semantic, not tasking-type-semantic.**

### 4.4 The co-occurrence hinge, resolved

`[verified]` **`TaskingType` is set in all 95 task definitions** — no task omits it. The 12 distinct values are the 10 enum members of `GruntTaskingType` (`GruntTasking.cs:63-75`) plus repeats, and **the 4 control-typed `Set` variants plus `Connect`/`Disconnect`/`Exit`/`Tasks`/`TaskKill` all declare `TokenTask: false`.** `[verified]`

`[read]` **`GruntTasking.cs:90-91` — the tasking model has NO `TokenTask` property at all:**
```csharp
public GruntTaskingType Type { get; set; } = GruntTaskingType.Assembly;
public List<string> Parameters { get; set; } = new List<string>();
```

`[verified]` **The `Token` on the wire is not a tasking field — it is read through the task FK** at `InternalListener.cs:239`:
```csharp
Token = tasking.GruntTask == null ? false : tasking.GruntTask.TokenTask
```

`[inferred]` **So the co-occurrence requires a control-typed TASK DEFINITION carrying `TokenTask: true` — and none exists.** The five `true` tasks are all `Assembly`; every control-typed task is `false`; and `TaskingType` is never omitted, so there is no default-resolution path that could silently produce a control type on a `true` task. `[verified]`

`[verified]` **The server-constructed control taskings corroborate independently.** Reading the four object initializers at `CovenantService.cs:1320-1361` (and their siblings through `:1416`), each sets exactly: `Id, GruntId, Grunt, GruntTaskId, GruntTask, Status, Type, Parameters, GruntCommand, GruntCommandId`. **`TokenTask` is never assigned** — consistent with §4.4's finding that the field does not exist on the tasking type. `[verified]`

`[inferred]` **R-52.6.1 closes: D52 §2.3's claim — that a control tasking reaching `TaskExecute` via `:188` would mis-parse raw `"Delay,300"` — is not reachable via the bundled corpus.** D52 §2.3 stands as written. **The residual was well-founded and is now discharged rather than carried.**

### 4.5 What would falsify this, stated as a probe

`[inferred]` **The negative is bounded by the bundled corpus.** It fails if any of the following becomes true: **(a)** a user-authored task definition sets `TokenTask: true` **and** a control `TaskingType` — the YAML is data, and Covenant's task-import path accepts it; **(b)** a control tasking is constructed by a path other than the four initializers at `:1320-1416`; **(c)** `GruntTasking` gains a `TokenTask` property in a later revision. `[inferred]` **Probe for (a):** re-run §4.2's counts after any task-set change; the invariant to assert is **`TokenTask:true` ⊆ `TaskingType:Assembly`**. `[inferred]` **(a) is the live one** — the invariant holds for the shipped corpus but is not enforced by any validator, per D50's `ParseParametersIntoTask` finding.

---

## 5. Instrument record

### 5.1 Failure #15 — the bracket-adjacent attribute, now with its blast radius measured

`[verified]` **Failure #13 (`\[Authorize` against combined attribute lists) was reported by D50 as a single-table error. D63 §1.1 measures its actual propagation: it corrupted FOUR published figures across TWO reports** — D40's `[Authorize]` count, D40's file count, D40's `AllowAnonymous` file list, and D50's controller total. `[verified]`

`[inferred]` **The generalizable lesson is not "use word boundaries." It is that a false zero does not stay local** — it is absorbed into every downstream figure that shares its denominator, and the downstream figures then corroborate each other. **D40 line 103 and line 270 disagree, and that disagreement was the only surviving trace of the error.** `[verified]`

### 5.2 Failure #16 (new, self-caught this round) — table rows correct, sum wrong

`[verified]` D50 §2.1's per-controller table was **individually correct on every row** and **wrong in its total** (21 vs 20). `[verified]`

`[inferred]` **This is a distinct failure mode from every prior entry in the ledger:** the instrument was sound, the matches printed, and the arithmetic was not re-derived from the rows. **The rule: a total must be computed from the emitted rows, never carried alongside them.** `[verified]` §1.1's table and §4.2's counts above were both produced by summing the enumerated matches, not by restating a remembered figure.

### 5.3 Failure #17 (new, self-caught and RETRACTED) — cross-domain token match

`[read]` §1.4 and §2.6: I matched `IsInRole("Administrators")` against the seeded role `"Administrator"` and implied a dead check. **The containing method (`Covenant.cs:247-256 IsElevated`) addresses the Windows local group, not ASP.NET Identity roles.** `[verified]` **Retracted — no defect.**

`[inferred]` **The rule: a shared string across two authorization domains is not evidence.** The question is never "does this token appear elsewhere?" but **"which system does this call resolve against?"** `[verified]` **Instrument failure #13's shape, third costume.**

### 5.4 Instrument discipline applied this round

`[verified]` **Every figure in §1–§4 was produced with a printed match list**, all numbers summed from those matches (§5.2), **comments stripped before classification** (block then line, in that order), **controller action names read from class bodies** rather than prefix-filtered (§3.1), **and `[absence]` claims given a positive control** — §4.4's `TaskingType` census first proved the YAML probe could fire (it returned 95 hits on a key that exists) before §4.2 trusted its 0 on `TaskingType` omission. `[verified]`

### 5.5 Species ledger for this report

`[inferred]` **Six species were counted and each needed its own instrument:**

| Species | Count | Instrument |
|---|---:|---|
| bare `[Authorize]` | **5** | `\bAuthorize\b` minus `\bAuthorize\s*\(` |
| `Authorize(Policy=…)` in a combined list | **20** | `\bAuthorize\s*\(` |
| `[AllowAnonymous]` | **4** | `\bAllowAnonymous\b`, stripped |
| controllers | **18** | two directories, not one |
| `TaskingType` keys | **95** | `^\s*TaskingType:` in YAML |
| `ClaimsPrincipal`-taking service methods | **2** | `ClaimsPrincipal` in the service file |

`[inferred]` **Five of the six would have been silently wrong under a single-instrument pass.** That is the report's methodological result.

---

## 6. Residuals

### R-63.1 `[verified]` — `TokenTask:true` ⊆ `Assembly` is unenforced

`[inferred]` §4.5(a): the invariant holds for the shipped corpus; **nothing validates it on import.** A user-authored task with a control `TaskingType` and `TokenTask: true` would reach `TaskExecute` with raw `"Delay,300"` — D52 §2.3's scenario — but only for control types **other than the four label-first ones D52 already showed are consumed inline.** `[inferred]` **Probe:** trace `CovenantService` task-import (`ParseParametersIntoTask` at `L2472` and its callers) for any type check on `TokenTask`.

### R-63.2 `[read]` — `HttpListenerController` has no route prefix and was absent from every prior census

`[verified]` §0.4/§1.2: class `[AllowAnonymous]`, one `Route()` action, **no `Route` attribute on the class.** Its actual URL depends on `Startup`'s endpoint mapping, which I did **not** resolve this round. `[inferred]` **Probe:** read `Startup.cs` `UseEndpoints`/conventional-route configuration and resolve `Route()`'s concrete path, then confirm whether it is reachable without any listener-token gate.

### R-63.3 `[verified]` — the empty-table `Administrator` bootstrap is real but its reachability is untested

`[inferred]` §2.4 describes the scenario structurally; **I did not run Covenant**, so I have not observed the exploit. `[inferred]` **Probe:** confirm `POST api/users` resolves on a fresh database with the user table empty, and that no `Startup` filter or seeding step guarantees a user exists before the endpoint is served.

### R-63.4 `[read]` — three unauthenticated endpoints, one of them entirely unguarded

`[verified]` §3.6: `POST users/login` and `POST users` (method `[AllowAnonymous]`), plus `HttpListenerController.Route()` (class `[AllowAnonymous]`). **The third is a whole controller; the first two are overrides on a gated class.** `[inferred]` **Probe:** whether any of the three is rate-limited or lockout-protected — `Startup` configures lockout flags but I did not trace them.

### R-63.5 `[read]` — D40's other non-`Authorize` counts were spot-checked, not exhaustively re-derived

`[verified]` §1.1 re-derived 13 figures. **D40 contains more.** `[verified]` **The four that moved are the four that used the corrupted denominator;** the remainder were re-derived and held, but I did not re-run every count in a 487-line report. `[inferred]` **Probe:** any D40 figure whose denominator involves "files containing an attribute" is suspect and should be re-run under §5.5's species ledger.

### R-63.6 `[inferred]` — `CovenantHub`'s live-method count should be re-verified by a parser

`[verified]` §3.5 relies on `CovenantHub.cs:162-165` sitting between two block comments (`*/` at `:161`, `/*` at `:166`) to call it live while 221 siblings are commented out. `[inferred]` **This is D32's finding reused, and I read it from source rather than from D32's text.** `[inferred]` **Probe:** run a comment-aware parser over `CovenantHub.cs` and confirm the live-method set has exactly one member.

### R-63.7 `[read]` — the mojibake alarm in §5 was itself an instrument artifact

`[verified]` While verifying D63's own encoding I found `pwsh`'s `Get-Content` rendering `# D63 — …` as `# D63 â€" …`, which reads exactly like the D52 double-encoding defect. **Byte-level inspection disproved it:** `U+00A7` is encoded `C2 A7` (§'s correct form), and every double-encoding signature (`C3A2E28094`, `C382`, `E2809D`, `E280A0`) counts **0**. `[verified]`

`[inferred]` **The files were never damaged; the console was decoding UTF-8 as cp1252.** §5.3's rule applies to itself: **the question is which system the bytes are being read through.** `[inferred]` **Probe:** none — the byte-level check is authoritative and this residual exists only to prevent the false alarm being re-raised.

---

*D63 — task-55 — `covenant-diver` — source-only, no REA/GHIDRA. Every figure above was produced by an invocation whose matches are printed in-line.*
