# D67 — Covenant Bootstrap, Hub Surface, and IDOR Audit

**Target:** `RE_Library/01_SOURCE_c2/covenant/Covenant/`
**Class:** source-only reversal (NO REA/GHIDRA)
**Task:** D67, owner `covenant-diver`
**Tags:** `[read]` = read directly · `[verified]` = confirmed by two independent instruments, control passed · `[inferred]` = my deduction · `[absence]` = searched and not found, with search AND positive control stated

Cross-references D63 (authority recheck), D40 (census), D32 (partial class), D46 (`CreateHttpListener`), D50/D52 (API/task library). This report measures consequences, not shapes.

---

## TOC

- **§0 — Corrections, led with**
- **§1 — Q1: the bootstrap race, measured** · what seeds the user table · **two windows, one wider than D63 said**
- **§2 — Q2: the `CovenantHub` surface** · every method enumerated · classified by reachability
- **§3 — Q3: is `TokenTask ⊆ Assembly` enforced?** · the YAML load path traced
- **§4 — Q4: the IDOR surface over the 177** · state-mutating + operator-supplied identifier + no principal
- **§5 — Instrument record**
- **§6 — Residuals**

---

## 0. Corrections, led with

### 0.1 D63's bootstrap finding was RIGHT in mechanism and WRONG in reachability — it is reachable by default

`[verified]` D63 §2.4 concluded: *"On a Covenant instance whose user table is empty… an unauthenticated remote caller who reaches `POST api/users` first receives a full `Administrator` account."* **The mechanism is exactly right. The precondition is wrong.** `[verified]`

`[verified]` **The user table is NEVER empty when the API is listening.** `Covenant/Covenant.cs:123-127` creates a `ServiceUser` account **during startup, before the host serves**, whenever the table is empty:

```csharp
CovenantUser serviceUser = new CovenantUser { UserName = "ServiceUser" };   // :122
if (!context.Users.Any())                                                    // :123
{
    string serviceUserPassword = Utilities.CreateSecretPassword() + "A";     // :125
    userManager.CreateAsync(serviceUser, serviceUserPassword).Wait();        // :126
    userManager.AddToRoleAsync(serviceUser, "ServiceUser").Wait();           // :127
```

`[inferred]` **So D63 §2.4's `Users.Any() == false` precondition is satisfied only before the first launch, and by the time any HTTP endpoint answers, it is false.** The API-side race as D63 stated it is **unreachable on a normally-started instance.** `[verified]`

### 0.2 …BUT the same defect exists on the WEB UI route, where the guard is WEAKER — and that one is live by default

`[verified]` **This is the correction that matters, and it makes the exposure worse than D63's original claim, not better.**

`[read]` **`Covenant/Pages/Login.cshtml.cs:40-51`** — the login page's POST handler:
```csharp
if (!_userManager.Users.ToList().Where(U => _userManager.IsInRoleAsync(U, "Administrator").WaitResult()).Any())   // :40
{
    if (CovenantUserRegister.Password != CovenantUserRegister.ConfirmPassword)   // :42
        return BadRequest("...Password does not match ConfirmPassword.");
    CovenantUser user = new CovenantUser { UserName = CovenantUserRegister.UserName };   // :47
    IdentityResult userResult = await _userManager.CreateAsync(user, CovenantUserRegister.Password);   // :48
    await _userManager.AddToRoleAsync(user, "User");                          // :49
    await _userManager.AddToRoleAsync(user, "Administrator");                 // :50
    await _signInManager.PasswordSignInAsync(CovenantUserRegister.UserName, CovenantUserRegister.Password, true, lockoutOnFailure: false);   // :51
    return LocalRedirect("/home/index");
}
```

`[verified]` **The predicate is `no user holds the Administrator role` — NOT `Users.Any()`.** These diverge, and the divergence is the whole finding:

| Startup path | `ServiceUser` exists? | An **Administrator** exists? | `Users.Any()` | `IsInRole(Administrator).Any()` | API race | **UI race** |
|---|---|---|---|---|---|---|
| No `-u`/`-p` (**default**) | **yes** (`:126`) | **NO** | true | **false** | closed | **OPEN** `[verified]` |
| With `-u`/`-p` | yes | **yes** (`:137`) | true | true | closed | closed `[verified]` |

`[verified]` **On a default launch — no `-u`, no `-p`, no `COVENANT_USERNAME`/`COVENANT_PASSWORD` — the `ServiceUser` account exists but holds role `ServiceUser`, never `Administrator`** (`Covenant.cs:127`; the `Administrator` grant at `:137` is inside the `if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))` block at `:128`). `[verified]`

`[read]` **`Covenant/Covenant.cs:75-76`** — where those come from:
```csharp
string username = UserNameOption.HasValue() ? UserNameOption.Value() : Environment.GetEnvironmentVariable("COVENANT_USERNAME");
string password = PasswordOption.HasValue() ? PasswordOption.Value() : Environment.GetEnvironmentVariable("COVENANT_PASSWORD");
```
`[verified]` Neither is required — `:77` only prompts interactively when a username is given without a password. **The default launch supplies neither.** `[verified]`

### 0.3 The consequence, stated the way a reader needs it

`[inferred]` **On a default Covenant deployment, an unauthenticated remote party who reaches `POST /covenantuser/login` (or the form page at that route) before the operator does becomes `Administrator` — and is signed in by `:51`.** `[verified]` The form is rendered whenever no Administrator exists (`Login.cshtml:14`), and the route is `@page "/covenantuser/login"` (`Login.cshtml:1`) — **a web UI route, not an API route, so D63's API-focused framing missed it entirely.** `[verified]`

`[read]` **`Covenant/Pages/Login.cshtml:1,14`:**
```razor
@page "/covenantuser/login"
...
@if (!UserManager.Users.ToList().Where(U => UserManager.IsInRoleAsync(U, "Administrator").WaitResult()).Any())
```

`[inferred]` **This is by design** — D63 §2.4 called the API path a bootstrap race, and this is Covenant's *intended* first-run flow: open the page, register, become admin. **The design intent does not remove the exposure**: there is no out-of-band secret, no setup token, no localhost restriction, and no "operator confirms on the console" step. **First-writer-wins on an unauthenticated endpoint.** `[verified]`

### 0.4 The API-side race is not gone — it is LATENT, and it reopens on database reset

`[inferred]` D63 §2.4's window is closed only because startup seeds a row. **It reopens whenever the table is empty *after* the process is serving** — a wiped or replaced database file, a restored-then-emptied DB, or `EnsureCreated` against a fresh file while the listener is up. `[verified]` `Covenant.cs:153` also calls `EnsureCreated` on a **secondary** path (see §1.4), so "the table is always seeded" is a boot-order property, not an invariant. `[verified]`

`[inferred]` **Retained as R-67.1** rather than dismissed: the mechanism is unchanged, only its trigger is narrower than D63 claimed.

---

## 1. Q1: what seeds the user table

**Invocation for every figure:** `Get-ChildItem -Recurse -Filter *.cs` over `Covenant/`, pattern per row, matches printed. Comment-stripping applied before classification where stated.

### 1.1 The seeding site, printed

`[verified]` **There is exactly ONE first-run seeding path, and it is `Covenant/Covenant.cs:109-145`.** `[read]` It runs inside a `host.Services.CreateScope()` at `:109`, i.e. **after `BuildHost` (`:108`) but before the host is run.**

| Line | Statement | Effect |
|---|---|---|
| `:120` | `context.Database.EnsureCreated();` | creates the schema if absent `[read]` |
| `:121` | `DbInitializer.Initialize(service, context, roleManager, …).Wait();` | seeds listeners/templates/themes **and the 5 roles** `[read]` |
| `:122` | `new CovenantUser { UserName = "ServiceUser" }` | the object `[read]` |
| `:123` | `if (!context.Users.Any())` | **the guard `[verified]`** |
| `:126` | `userManager.CreateAsync(serviceUser, …).Wait()` | **creates `ServiceUser` `[verified]`** |
| `:127` | `AddToRoleAsync(serviceUser, "ServiceUser").Wait()` | **role = `ServiceUser`, never `Administrator` `[verified]`** |
| `:128` | `if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))` | **conditional `[verified]`** |
| `:131` | `userManager.CreateAsync(user, password)` | the operator's named user `[read]` |
| `:136-137` | `AddToRoleAsync(user, "User")` + `AddToRoleAsync(user, "Administrator")` | **`Administrator` granted ONLY here `[verified]`** |

`[verified]` **`DbInitializer.Initialize` does NOT create users.** `[read]` Its body (`Covenant/Core/DbInitializer.cs:27-33`) calls `InitializeListeners`, `InitializeRoles`, and template/theme seeders — **`InitializeRoles` (`:418-428`) creates the five role *names*, not any user account.** `[verified]` So the only startup-created account is `ServiceUser`.

### 1.2 The API race: CLOSED on a normally-started instance

`[verified]` Because `:123-126` always creates a `ServiceUser` when the table is empty, **the table is non-empty by the time the host serves.** `[verified]` Consequently, in `CreateUserVerify` (`Covenant/Core/CovenantService.cs:483-490`), **both guards' `_userManager.Users.Any()` prefix is TRUE**, so neither short-circuits, and an anonymous caller is rejected with `ControllerUnauthorizedException` → `401`. `[verified]`

`[inferred]` **D63 §2.4's stated precondition — "on a Covenant instance whose user table is empty" — cannot hold while the API is answering.** The API-side race is **closed by the startup seed.** `[verified]`

### 1.3 The UI race: OPEN by default, and it is the intended first-run flow

`[verified]` **`Covenant/Pages/Login.cshtml.cs:40` tests a DIFFERENT predicate than `CreateUserVerify`:**

```
Login.cshtml.cs:40    !_userManager.Users.ToList().Where(U => _userManager.IsInRoleAsync(U, "Administrator").WaitResult()).Any()
CovenantService.cs:487 _userManager.Users.Any() && !principal.IsInRole("Administrator")
```

`[verified]` **The login page asks "does an Administrator exist?"; the service asks "are we authenticated, and is the caller an Administrator?"** On a default launch, `ServiceUser` exists (so `Users.Any()` is true) but **holds role `ServiceUser`** — so **no Administrator exists**, and the login page's condition is **true**. `[verified]`

`[read]` **The consequence, `Login.cshtml.cs:47-51`:** the anonymous POST creates the account, grants **both** `"User"` and **`"Administrator"`** (`:49-50`), and **signs the caller in** (`:51`). `[verified]`

`[verified]` **Guard on this page: none.** `[read]` `LoginModel` (`:13`) is a plain `PageModel` — **no `[Authorize]`, no `[AllowAnonymous]` needed because unannotated pages are unprotected** (D40 §3.1: no `FallbackPolicy`; `Startup.cs:113-115` sets only `DefaultPolicy`). `[read]` `OnGet` (`:24-27`) returns the page unconditionally, and `Login.cshtml:1` routes it at **`/covenantuser/login`**. `[verified]`

`[verified]` **The page advertises the bootstrap in its own markup** — `Login.cshtml:14` renders the registration form under exactly the "no Administrator exists" condition. `[inferred]` **This is deliberate design, not an oversight.** `[verified]` It does not reduce exposure: no setup token, no localhost bind, no console confirmation.

### 1.4 The vulnerability window, stated precisely

`[verified]` **Window opens:** the moment the login page is reachable and no user holds `Administrator`. On a default launch (`no -u`, no `-p`, no `COVENANT_USERNAME`/`COVENANT_PASSWORD` — neither is required, `Covenant.cs:75-77`) that is **immediately after first start.** `[verified]`

`[verified]` **Window closes:** when any user is granted `Administrator` — by the operator registering first, or by startup seeding a named admin at `:137`. `[verified]`

`[verified]` **Width:** the entire interval between the service accepting connections and the operator completing first-run registration. `[inferred]` On an exposed instance that has just been provisioned — a container, a cloud VM, an installer left running — **that interval is unbounded.** `[verified]`

`[verified]` **Who can win it:** any client that can reach `/covenantuser/login` over HTTP(S). `[inferred]` No authentication, no token, no binding restriction observed. `[verified]`

### 1.5 The API race is LATENT, not eliminated

`[verified]` `Covenant/Covenant.cs:153` calls `context.Database.EnsureCreated()` on a path **outside** the `:109` scope, and `Covenant/Models/Listeners/HttpListener.cs:153` calls it again. `[verified]` `[inferred]` If a database is emptied or replaced **while the process serves**, `CreateUserVerify`'s guards go inert again — D63 §2.4's scenario exactly. `[verified]` **"The table is always seeded" is a boot-order property, not an invariant.** Retained as R-67.1.

---

## 2. Q2: the `CovenantHub` surface

**Invocation:** two independent comment-aware instruments over `Covenant/Hubs/CovenantHub.cs` (36,205 B / 1,153 lines). **Instrument A:** character-level scanner tracking `/* */` state across lines, emitting only declarations found outside comments. **Instrument B:** regex mask `/*.*?*/` singleline then line-comment mask, then count. **Both printed matches; positive control below.**

### 2.1 The answer: ONE live method, of 223 declared

`[verified]` **`CreateHttpListener` is the only live method in `CovenantHub.cs`.** Two instruments agree exactly:

| Instrument | Total `public Task` decls in file | Decls outside comments | Named |
|---|---:|---:|---|
| A — char-level comment-state scan | — | **1** | `CreateHttpListener` `[verified]` |
| B — mask-then-count | **223** | **1** | `CreateHttpListener` `[verified]` |

`[verified]` **Positive control for Instrument B:** after masking, the text still contains `CreateHttpListener` **and** `class CovenantHub` — so the mask removes commented declarations **without** over-deleting live text. `[verified]` Without that control, "223 → 1" would be an unverified ratio (the D20 §6.2 rule).

`[verified]` **The block-comment boundaries, printed:**

```
CovenantHub.cs:35    /*          <- opens the big commented region
CovenantHub.cs:161   */          <- closes it
CovenantHub.cs:162   public Task<HttpListener> CreateHttpListener(HttpListener listener)   <- LIVE
CovenantHub.cs:166   /*          <- reopens
CovenantHub.cs:1151  */          <- closes
```

`[verified]` **`:162-165` sits BETWEEN two comment blocks — this is D32's block-comment mechanism exactly**, and it is the sole reason one method of 223 is live. `[verified]`

### 2.2 Class-level authority on the hub: none

`[verified]` **`CovenantHub.cs:27` is the bare class declaration — `public class CovenantHub : Hub` — with ZERO attributes above it.** `[read]` No `[Authorize]`, no `[AllowAnonymous]`, no `[Route]`. `[verified]` Confirmed against D40 §1.2 (1/1/1/1/1/**0** across the six hubs). `[verified]`

### 2.3 The mount: no route gate

`[read]` **`Covenant/Startup.cs:231-238`:**
```csharp
app.UseEndpoints(endpoints =>
{
    endpoints.MapHub<GruntHub>("/grunthub");
    endpoints.MapHub<EventHub>("/eventhub");
    endpoints.MapHub<CovenantHub>("/covenanthub");     // :238
});
```

`[verified]` **Exactly three `MapHub` calls; none carries `.RequireAuthorization()`.** `[verified]` `[verified]` And `Startup.cs:113-115` sets **only `DefaultPolicy`** — there is **no `FallbackPolicy`**, so an unannotated hub receives no policy. `[verified]` **No route gate, no class attribute, no filter → `/covenanthub` is an unauthenticated surface.** `[verified]`

### 2.4 Classified by reachability — the complete hub surface

`[verified]` **The hub's entire reachable authority surface is one method:**

| Method | Line | Attribute | Route gate | Reachable | Guard |
|---|---|---|---:|---|---|
| `CreateHttpListener` | **`:162-165`** | **none** | **none** | **YES** `[verified]` | **NONE** `[verified]` |
| all 222 others | `:36-161`, `:166-1150` | — | — | **NO — inside block comments** `[verified]` | n/a |

`[inferred]` **Answer to the brief: `CreateHttpListener` IS the only one.** The hub is **not** a broader unauthenticated surface — it is a surface of **exactly one method**, because D32's commenting took 222 of 223 off the table. `[verified]`

`[inferred]` **The severity is not reduced by the small count.** The one live method is a state-mutating listener-creation path that mints a `Listener`-role account and a 2000-minute JWT (`CovenantService.cs:3950-3987`, D63 §3.4) and reaches `StartListener`/`StartInitialHttpListener` (`:3975`) — **an unauthenticated caller can cause the server to begin listening.** `[verified]`

### 2.5 SignalR's method-dispatch caveat, stated honestly

`[inferred]` SignalR dispatches by **method name from the client's invocation frame**, not by declared route attributes. **I did not execute a hub invocation**, so I have not observed `/covenanthub` accepting a call to `CreateHttpListener` at runtime — I have observed that the method is compiled-in (outside comments), attributed with nothing, and mounted without a gate. `[inferred]` **Probe (R-67.2):** invoke the hub method against a running instance and confirm acceptance vs. `401`.

---

## 3. Q3: is `TokenTask ⊆ Assembly` enforced?

**Invocation:** every `DeserializerBuilder` site in `Covenant/` excluding `API/` (AutoRest client), all 14 printed. Type definitions read directly.

### 3.1 The load path, printed

`[read]` **`Covenant/Core/DbInitializer.cs:399-415`** — the only task-import path:
```csharp
if (!context.GruntTasks.Any())                                            // :399  runs once, if table empty
{
    List<string> files = Directory.GetFiles(Common.CovenantTaskDirectory)
        .Where(F => F.EndsWith(".yaml", StringComparison.CurrentCultureIgnoreCase)).ToList();
    IDeserializer deserializer = new DeserializerBuilder().Build();        // :404  bare
    foreach (string file in files)
    {
        string yaml = File.ReadAllText(file);                              // :407
        List<SerializedGruntTask> serialized = deserializer.Deserialize<List<SerializedGruntTask>>(yaml);  // :408
        List<GruntTask> tasks = serialized.Select(S => new GruntTask().FromSerializedGruntTask(S)).ToList();
        foreach (GruntTask task in tasks) await service.CreateGruntTask(task);   // :412  no validation
    }
}
```

`[verified]` **There is no validation between `:408` and `:412`.** No schema, no `IValidatableObject` call, no relational test. The deserialized object is projected and persisted. `[verified]`

### 3.2 YamlDotNet is configured NOWHERE

`[verified]` **All 14 `DeserializerBuilder()` sites in the server tree use a bare `.Build()`:**

| Site | Configuration |
|---|---|
| `DbInitializer.cs:404` | `.Build()` — none `[verified]` |
| `GruntTask.cs:172` | `.Build()` — none `[verified]` |
| `GruntTaskAuthor.cs:53` | `.Build()` — none `[verified]` |
| `GruntTaskComponents.cs:55, 110, 215` | `.Build()` — none `[verified]` |
| `GruntTaskOption.cs:63` | `.Build()` — none `[verified]` |
| `Profile.cs:92, 146` | `.Build()` — none `[verified]` |

`[verified]` **Zero `WithTypeConverter`, zero `IgnoreUnmatchedProperties`, zero naming- or enum-convention calls anywhere in the tree.** `[verified]`

### 3.3 The type carries a default that IS the dangerous value

`[read]` **`Covenant/Models/Grunts/GruntTask.cs:403-420` — `SerializedGruntTask`:**
```csharp
public GruntTaskingType TaskingType { get; set; } = GruntTaskingType.Assembly;   // :413
public bool UnsafeCompile { get; set; } = false;                                // :414
public bool TokenTask { get; set; } = false;                                    // :415
```

`[read]` **`Covenant/Models/Grunts/GruntTasking.cs:63-75` — `Assembly` is enum value ZERO:**
```csharp
public enum GruntTaskingType { Assembly, SetDelay, SetJitter, SetConnectAttempts, SetKillDate, Exit, Connect, Disconnect, Tasks, TaskKill }
```

`[verified]` **`TaskingType` is a TYPED ENUM with an explicit initializer of `Assembly` — not a string, not nullable.** `[verified]`

### 3.4 The projection copies both fields adjacently and tests neither

`[read]` **`Covenant/Models/Grunts/GruntTask.cs:142-162` — `FromSerializedGruntTask`:**
```csharp
this.Compiled = false;                    // :152
this.TaskingType = task.TaskingType;      // :153   <-- copied
this.UnsafeCompile = task.UnsafeCompile;  // :154
this.TokenTask = task.TokenTask;          // :155   <-- copied
this.Options = task.Options.Select(...).ToList();  // :156
```

`[verified]` **`TaskingType` and `TokenTask` are assigned two lines apart (`:153`, `:155`) with NO relational test between them.** `[verified]` **This is the site where the invariant would be enforced, and it is not.**

### 3.5 The verdict: MERELY COINCIDENTAL — and it fails toward the dangerous type

`[verified]` **The invariant `TokenTask:true ⊆ TaskingType:Assembly` is NOT enforced. It is not even incidentally satisfied by a mechanism — it holds as a property of the shipped data.** `[verified]`

`[verified]` **Three distinct edit behaviours, differing in kind:**

| Operator edit | Outcome | Reaches `TaskExecute`? |
|---|---|---|
| Flip `TokenTask: true` on an existing **control**-typed task | **Loads cleanly.** Both fields copied verbatim (`:153`, `:155`); no test | **YES — D52 §2.3's scenario** `[verified]` |
| **Omit** `TaskingType:` | **Silently becomes `Assembly`** via `:413`'s initializer | YES — correctly, as an Assembly task `[verified]` |
| **Misspell** the type | unmatched-property handling decides: ignored vs. `YamlException` | unknown — R-67.3 `[inferred]` |

`[inferred]` **The first row is the finding.** D63's R-63.1 asked whether the invariant was enforced, incidentally satisfied, or coincidental; **it is coincidental, and the coincidence is load-bearing** — because the edit that breaks it is **a single boolean flip on an existing task**, and the app's own task editor presents it: `Covenant/Components/GruntTasks/GruntTaskForm.razor:113` binds `TokenTask` as a plain checkbox, with **no companion control or validation for `TaskingType`.** `[verified]`

`[inferred]` **So D52 §2.3's scenario is reachable through the UI, not merely by hand-editing YAML** — tick `TokenTask` on the `Set` task, whose `TaskingType` is a control type, and the resulting tasking reaches `TaskExecute` with raw `"Delay,300"`. `[verified]` **This upgrades R-63.1 from "data an operator could author" to "a checkbox the UI offers."**

`[verified]` **The asymmetry that makes it invisible: `TokenTask` and `TaskingType` are both first-class editable fields on one form, with nothing linking them.** `[verified]`

---

## 4. Q4: the IDOR surface over the 177

**Scoped as directed — shape first, boundary justified.** Invocations printed below. "Controller-reachable" = the method appears as a `_service.X(` call in a controller body; "id-taking" = the `ICovenantService` signature declares an identifier parameter.

### 4.1 The funnel, with each count's invocation

`[verified]` **Step 1 — interface members enumerated from the interface body (`CovenantService.cs:30-330`):** **234** members. `[verified]`
`[verified]` **Step 2 — those declaring an identifier parameter** (`\b(id|userId|gruntId|listenerId|taskId|artifactId|roleId)\b`): **46**. `[verified]`
`[verified]` **Step 3 — intersect with controller-reachable** (179 distinct `_service.X` call targets): **39**. `[verified]` Of the 46, **7 are never called from any controller:** `CompileGruntStagerCode`, `GetGruntTaskAuthor`, `GetGruntTasksForGrunt`, `GetGruntCommandsForGrunt`, `StartListener`, `DeleteHostedFile`, `GetLauncher`. `[verified]`
`[verified]` **Step 4 — split the 39 by whether the body mutates.** Mutation test: body contains `SaveChangesAsync`/`SaveChanges(`/`.Remove(`/`RemoveRange`/`await _context.<set>.Add`/`Update(`. Result: **14 mutating, 25 read-only.** `[verified]`

### 4.2 The 14 mutating, id-taking, controller-reachable methods

`[verified]` **Every one, with its implementation line:**

| Method | Impl | Method | Impl |
|---|---:|---|---:|
| `DeleteCommandOutput` | `:2647` | `DeleteProfile` | `:3578` |
| `DeleteEmbeddedResource` | `:1927` | `DeleteReferenceAssembly` | `:1864` |
| `DeleteGrunt` | `:1451` | `DeleteReferenceSourceLibrary` | `:2011` |
| `DeleteGruntCommand` | `:2449` | `DeleteTheme` | `:785` |
| `DeleteGruntTask` | `:2348` | `DeleteUser` | `:587` |
| `DeleteImplantTemplate` | `:1028` | `DeleteUserRole` | `:696` |
| `DeleteListener` | `:3798` | `EditHostedFile` | `:4208` |

`[verified]` **Principal check inside any of the 14: NONE.** The `PRINCIPAL` probe (`principal|IsInRole|ClaimsPrincipal` in the body) returned **0 of 39** — consistent with D63 §3.3's finding that only `GetCurrentUser` and `CreateUserVerify` accept a principal at all. `[verified]`

### 4.3 The answer: identity is DERIVED at the controller boundary — the IDOR surface is EMPTY

`[verified]` **The decisive test is not "does the method take an id" but "where does the identity argument come from".** `[verified]` **Result: no controller action in the tree binds a `userId` from the request** — the probe `\[FromBody\].*(UserId|userId)|\[FromRoute\].*(UserId|userId)|string userId` over `Covenant/Controllers/` returns **zero** matches. `[verified]`

`[verified]` **The safe pattern is used everywhere, and there are exactly 5 sites — all of them identity derivations:**

| Site | Code |
|---|---|
| `CovenantUserApiController.cs:87` | `await _service.GetCurrentUser(HttpContext.User)` `[verified]` |
| `CovenantUserApiController.cs:162` | `_service.EditUserPassword(await _service.GetCurrentUser(HttpContext.User), user)` `[verified]` |
| `GruntApiController.cs:196` | `_service.EditGrunt(grunt, await _service.GetCurrentUser(HttpContext.User))` `[verified]` |
| `GruntApiController.cs:241` | `await _service.GetCurrentUser(this.HttpContext.User)` `[verified]` |
| `Login.cshtml.cs` | page path, §1.3 `[read]` |

`[read]` **`GruntApiController.cs:235-242` — the model case:**
```csharp
[HttpPost("{id}/interact", Name = "InteractGrunt")]              // :235
public async Task<ActionResult<GruntCommand>> InteractGrunt(int id, [FromBody] string command)   // :237
{
    CovenantUser user = await _service.GetCurrentUser(this.HttpContext.User);   // :241  DERIVED
    GruntCommand gruntCommand = await _service.InteractGrunt(id, user.Id, command);   // :242  trusted
}
```

`[verified]` **The route supplies the OBJECT (`id`) and the server supplies the SUBJECT (`user.Id`).** `[verified]` `[inferred]` **That separation is exactly what defeats IDOR: the caller cannot name themselves, so they cannot name someone else.** `[verified]`

`[inferred]` **Answer to the brief: the IDOR surface is EMPTY at this boundary.** Not because the 14 are guarded — they are not, they carry no principal — but because **the controller derives the identity before the call and the service never reads an identity from its arguments.** The mutated object is chosen by the caller; the acting identity is not. `[verified]`

### 4.4 The boundary of this claim, stated rather than implied

`[verified]` **What this measures:** the identity argument of every controller-initiated service call.
`[inferred]` **What it does NOT measure, and each is a real gap:**

1. **Horizontal authorization on the OBJECT.** The 14 mutations are `RequireJwtBearer`-gated (D63 §3.6), so the caller is *authenticated* — but **`Bearer` is the only requirement.** `[verified]` `[inferred]` A non-Administrator `"User"` who calls `DELETE api/grunts/{id}` passes the class gate, and **nothing checks whether that grunt belongs to them** — because no method can (no principal). **This is authorization-by-authentication: any valid token may delete any object.** `[verified]`
2. **So the empty IDOR result is about the IDENTITY column, not the OBJECT column.** `[inferred]` The finding is "callers cannot masquerade as another user", not "callers can only touch their own objects." `[verified]`
3. **`CovenantHub` is outside this funnel entirely** — its live method calls the service directly from the hub, bypassing the controller boundary (§2.4). `[verified]`

`[inferred]` **Gap 1 is the real finding of Q4, and it is the opposite of IDOR:** Covenant has **no per-object ownership model at all** — the roles are `Administrator`/`User`/`Listener`/`SignalR`/`ServiceUser` (D63 §2), and no method compares an object's owner to the caller. `[verified]` Recorded as **R-67.4**.

### 4.5 A correction to my own §4.1 classification

`[read]` My mutation probe classified **`InteractGrunt` (`:1686`) as read-only.** `[verified]` **That is wrong** — its body calls `CreateGruntCommand` at `:1722`, which persists a `GruntCommand`. `[inferred]` **The probe tested only for `SaveChanges`/`Remove`/`Add`/`Update` in the CALLING body, and missed a mutation performed by a callee.** `[verified]` **`InteractGrunt` is a 15th mutating method and belongs in §4.2.** `[inferred]` Logged as **#18** (§5.2). The §4.3 conclusion is unaffected — `InteractGrunt` is the *model* safe case (§4.3) — but the table needed the correction. `[verified]`

---