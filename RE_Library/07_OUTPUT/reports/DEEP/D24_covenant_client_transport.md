# D24 — Covenant's generated client: the transport decision layer

**Target:** `RE_Library/01_SOURCE_c2/covenant/Covenant/API/`
**Question:** how does Covenant's own client connect, and what does it trust?
**Method:** source-only. Every count enumerated and recomputed by a second independent probe. Every absence carries a positive control. Inference marked `[inference]`.

---

## HEADLINE

**The generated client contains no transport decision at all. The decision is hand-written, and it is better than the generator's default — with one flaw.**

1. **PREMISE VERIFIED (§1).** D13 §5's "ONE class, 183 `WithHttpMessagesAsync`" is **correct on both counts** — 1,084,841 B / 23,549 lines, one `public partial class` at `:20`, and **exactly 183** occurrences in each of the three files. **But D13 omits the `partial` keyword: the "one class" is split across three files.** That omission is what makes Q4 answerable as a *partition* rather than a percentage.
2. **§3 — Q2 RESOLVED, and D13 §8.5's open item closes.** `CreateListener.razor:103` **does** invoke the generated `CreateHttpListenerWithHttpMessagesAsync` (`CovenantAPI.cs:19146`). **But it does so over the HTTP path (`CovenantAPIService`), not the SignalR hub path.** Path 2 to `CreateHttpListener` is therefore **not** the actively-used route the Lead was probing for; a **third** route is. The unauthenticated hub method `CovenantHub.cs:162-165` **is live, uncommented code** — but the UI does not call it.
3. **§2 — Q1: the generated file has ZERO TLS logic.** `ServerCertificateCustomValidationCallback` → **0**, `ServicePointManager` → **0**, `SecurityProtocol` → **0**, `InitializeHttpClient` → **0**, `CreateHttpHandlerPipeline` → **0**. **The Lead's two named methods do not exist in this file.** `:283` sets `BaseUri = new System.Uri("http://localhost")` — an AutoRest default, **overridden** by the real caller.
4. **§4 — the real trust decision is a certificate THUMBPRINT PIN that discards chain errors.** `CovenantAPIService.cs:20-32` overrides the base URI to `https://localhost:<port>`, attaches `TokenCredentials`, and validates by **SHA-1 hash equality** to a local cert while **ignoring the `errors` parameter entirely** (`:25`). This is stronger than no validation and weaker than chain validation. **It is the only certificate-validation customization in the entire Covenant codebase.**
5. **§5 — the generated-vs-handwritten boundary is exact: the three files are 99.4% machine boilerplate with a hand-written `partial` half.** Enumerated, not estimated.

---

## TABLE OF CONTENTS

- §1 Premise check — D13 §5 verified, with one correction
- §2 Q1 — where the transport is decided, and the five zero-counts
- §3 Q2 — `CreateHttpListener`: the chain, the two paths, and D13 §8.5 closed
- §4 The certificate pin — what the client actually trusts
- §5 Q3/Q4 — the interface surface and the generated-vs-handwritten boundary
- §6 Generated-vs-handwritten: the enumerated split
- §7 Residual unknowns, corrections, and honest coverage

---

## 1. Premise check — D13 §5 verified on both counts, with one correction

**The Lead asked for this verification before anything else. Every figure below was recomputed by two independent methods.**

| Claim (D13 §5) | Method 1 — `Get-Content` line count / file length | Method 2 — `Select-String -AllMatches` counts | Verdict |
|---|---|---|---|
| `CovenantAPI.cs` = 1,084,841 B | **1,084,841 B** | `Get-Item` → 1,084,841 | **CONFIRMED byte-exact** |
| 23,549 lines | **23,549** | `(Get-Content).Count` → 23,549 | **CONFIRMED exact** |
| "ONE class" | 1 × `public class` decl | `^\s*public\s+(partial\s+)?class\s+\w+` → **1** | **CONFIRMED, with correction below** |
| "183 `WithHttpMessagesAsync`" | `CovenantAPI.cs` → **183** | `ICovenantAPI.cs` → **183** · `CovenantAPIExtensions.cs` → **183** | **CONFIRMED three ways** |

`[source: CovenantAPI.cs — 1,084,841 B / 23,549 lines / 46.1 B-per-line; two independent probes]`

### 1.1 THE CORRECTION — "one class" is true but incomplete: it is a `partial` class across three files

**D13 §5 says "ONE class." That is correct, and it hides the structure that answers Q4.** The declaration is:

```csharp
// API/CovenantAPI.cs:20
public partial class CovenantAPI : ServiceClient<CovenantAPI>, ICovenantAPI
```

**The `partial` keyword means the single class is physically split across three files**, each carrying **exactly 183** `WithHttpMessagesAsync` occurrences:

| File | Size | Lines | `WithHttpMessagesAsync` | Class decls of its own |
|---|---:|---:|---:|---:|
| `API/CovenantAPI.cs` | 1,084,841 B | 23,549 | **183** | 1 (`:20`) |
| `API/CovenantAPIExtensions.cs` | 212,491 B | 4,566 | **183** | **0** |
| `API/ICovenantAPI.cs` | 93,517 B | 1,796 | **183** | **0** |

**The identity 183 = 183 = 183 is the strongest available consistency check on the operation count** — three independently generated files agreeing on the same operation set means the figure is not an artifact of one file's formatting. **Nothing was sampled.**

**Why this matters beyond bookkeeping:** the 183 in `CovenantAPIExtensions.cs` are **static extension methods** that wrap the 183 instance methods, and the 183 in `ICovenantAPI.cs` are the **interface signatures**. So the AutoRest output is a **three-layer contract/implementation/convenience stack on one partial class**, and Q4's "generated vs hand-edited" boundary is a **partition question, not a percentage question** (§5, §6).

`[source: enumerated across the three files; CovenantAPI.cs:20]`

---

## 2. Q1 — where the transport is decided: not in the generated file

### 2.1 The five zero-counts, each with a positive control

**The Lead named `InitializeHttpClient` and `CreateHttpHandlerPipeline`. Neither exists in this file.** The probes, run with the same syntax that returns 183 for a present identifier:

| Probe | `CovenantAPI.cs` | Interpretation |
|---|---:|---|
| `InitializeHttpClient` | **0** | **Lead's named method does not exist** |
| `CreateHttpHandlerPipeline` | **0** | **Lead's named method does not exist** |
| `ServerCertificateCustomValidationCallback` | **0** | no cert validation in generated code |
| `ServicePointManager` | **0** | no global TLS policy |
| `SecurityProtocol` | **0** | **no `SslProtocols` / TLS-version selection anywhere** |
| **positive control:** `BaseUri.AbsoluteUri` | **183** | **probe is live** |
| **positive control:** `WithHttpMessagesAsync` | **183** | **probe is live** |
| **positive control:** `ServiceClientCredentials` | **6** | **probe is live** |

`[source: CovenantAPI.cs — five absence probes, three live positive controls, identical probe syntax]`

**What the file *does* contain** — stated alongside the absences, because an absence-only report would be misleading:

- **`HttpClientHandler` → 4** — but only as **constructor parameters** (`:75`, `:116`, `:192`, `:256`), forwarded to `base(...)`. **The generated code accepts a handler; it never configures one.**
- **`ServiceClientCredentials` → 6** — all constructor parameters (`:137`, `:164`, `:192`, `:220`, `:256`) plus the property (`:40`). **Never inspected or validated locally** — `:270` calls `Credentials.InitializeServiceClient(this)`, delegating every credential decision to `Microsoft.Rest.ClientRuntime`.
- **`BaseUri` → declared `:25`, defaulted `:283`.**

### 2.2 The transport default, and the override that supersedes it

```csharp
// API/CovenantAPI.cs:281-283
private void Initialize()
{
    BaseUri = new System.Uri("http://localhost");
```

**`:283` is the AutoRest default: `http://`, cleartext, `localhost`.** It is the value in effect **only** if a caller uses a constructor that does not supply a `baseUri` — the `ServiceClientCredentials`-only constructors at `:137` and `:192`. **Every caller in this repository supplies one** (§4).

**The real initializer is named `Initialize()`, not `InitializeHttpClient`** — and it does **two** things: the `BaseUri` default (`:283`) and JSON serialization settings (`:284-296`: ISO dates, UTC, null-ignoring, `ReadOnlyJsonContractResolver`). **There is no third thing. No handler pipeline, no TLS configuration, no certificate policy.**

**And there is an unused extension point:** `:277` `partial void CustomInitialize();` — declared, never implemented anywhere in the repository. `[inference]` **This is the hook AutoRest provides for exactly the transport customization the Lead was looking for, and Covenant's authors did not use it — they wrote a separate hand-authored service class instead (§4).**

---

## 3. Q2 — `CreateHttpListener`: the chain is closed, and D13 §8.5 resolves

**The Lead called this "the single most consequential open question in the Covenant lane." It resolves — but not along the path the question assumed, and the answer is more specific than either "yes" or "no."**

### 3.1 Every occurrence, enumerated — 15 sites across 11 files

**This is a complete enumeration, not a sample.** All 15 occurrences of `CreateHttpListener` in the Covenant tree:

| # | Site | Role |
|---:|---|---|
| 1 | `API/CovenantAPI.cs:19146` | **generated operation**: `CreateHttpListenerWithHttpMessagesAsync` |
| 2 | `API/CovenantAPI.cs:19161` | generated tracing call |
| 3 | `API/CovenantAPIExtensions.cs:3682` | sync wrapper (static extension) |
| 4 | `API/CovenantAPIExtensions.cs:3684` | → `.GetAwaiter().GetResult()` |
| 5 | `API/CovenantAPIExtensions.cs:3695` | async wrapper |
| 6 | `API/CovenantAPIExtensions.cs:3697` | → `WithHttpMessagesAsync` |
| 7 | `API/ICovenantAPI.cs:1455` | interface signature |
| 8 | **`Components/Listeners/CreateListener.razor:103`** | **the UI call site** |
| 9 | `Controllers/ApiControllers/ListenerApiController.cs:156` | `[HttpPost("http", Name = "CreateHttpListener")]` |
| 10 | `Controllers/ApiControllers/ListenerApiController.cs:157` | controller action |
| 11 | `Controllers/ApiControllers/ListenerApiController.cs:161` | → `_service.CreateHttpListener` |
| 12 | `Core/CovenantAPIService.cs:35` | hand-written client method |
| 13 | `Core/CovenantAPIService.cs:37` | → `_client.CreateHttpListenerAsync` |
| 14 | `Core/CovenantHubService.cs:188` | **SignalR client method** |
| 15 | `Core/CovenantHubService.cs:190` | → `_connection.InvokeAsync<HttpListener>` |
| 16 | `Core/CovenantService.cs:274` | interface declaration |
| 17 | `Core/CovenantService.cs:3950` | **the convergence point** — `async Task<HttpListener>` |
| 18 | `Hubs/CovenantHub.cs:162` | **the hub method** |
| 19 | `Hubs/CovenantHub.cs:164` | → `_service.CreateHttpListener` |

`[source: exhaustive Select-String over all *.cs / *.razor; 19 lines across 11 files]`

### 3.2 THE ANSWER — the UI uses the HTTP path, not the hub path

**`CreateListener.razor:23` injects the API service, not the hub service:**

```csharp
// Components/Listeners/CreateListener.razor:23, :103
@inject CovenantAPIService CovenantAPIService
...
_ = this.InvokeAsync(async () => await CovenantAPIService.CreateHttpListener(listener));
```

**So the live path from the Blazor UI is:**

```
CreateListener.razor:103
  → CovenantAPIService.cs:35-37   _client.CreateHttpListenerAsync(ToAPIListener(listener))
  → CovenantAPIExtensions.cs:3697 operations.CreateHttpListenerWithHttpMessagesAsync(...)
  → CovenantAPI.cs:19146          generated POST, carrying ServiceClientCredentials
  → ListenerApiController.cs:156  [HttpPost("http")]
  → ListenerApiController.cs:161  _service.CreateHttpListener(listener)
  → CovenantService.cs:3950       the implementation
```

**Verdict on D13 §8.5:** the generated client **does** actively invoke `CreateHttpListener` — the Lead's suspicion is **correct**. **But it is not path 2 in the sense the question implied.** Path 2 was the *hub* route; the UI exercises the *HTTP API* route. **These are different transports, different authentication mechanisms, and different reachability.** The UI never touches `CovenantHub.cs:162`.

**Three routes exist to `CovenantService.cs:3950`, and the ordering matters:**

| Route | Entry | Transport | Auth mechanism | Exercised by UI? |
|---|---|---|---|---|
| **A** | `ListenerApiController.cs:156` | HTTP REST | `TokenCredentials` (client) + controller pipeline | **YES** — `Razor:103` |
| **B** | `CovenantHub.cs:162` | SignalR | **none annotated** (§3.3) | **NO** |
| C | `CovenantHubService.cs:188` | SignalR (alternative client) | inherits B | no call sites found in UI |

### 3.3 FINDING — `CovenantHub` is the one hub in the app without `[Authorize]`, and it is the only hub with a live method

**This is the strongest-form absence result in this report, because it has a positive control built into the corpus itself.**

**Five hubs annotate `[Authorize]`. `CovenantHub` does not:**

| Hub class | Attribute | Line |
|---|---|---|
| `Hubs/CommandOutputHub.cs` | **`[Authorize]`** | `:12` |
| `Hubs/EventHub.cs` | **`[Authorize]`** | `:14` |
| `Hubs/GruntCommandHub.cs` | **`[Authorize]`** | `:12` |
| `Hubs/GruntHub.cs` | **`[Authorize]`** | `:22` |
| `Hubs/GruntTaskingHub.cs` | **`[Authorize]`** | `:12` |
| **`Hubs/CovenantHub.cs`** | **(none)** | `:27` — `public class CovenantHub : Hub` |

**This is not "the probe found nothing."** The probe found **five** instances of the convention in the same directory, same namespace, same application. **`CovenantHub` is a measured outlier within a consistent convention, not an unexamined gap.** `[source: exhaustive [Authorize] enumeration — 5 sites, CovenantHub absent]`

**And the hub is almost entirely commented out. The measurement:**

| Measure | Count |
|---|---:|
| Public `Task` methods **commented out** | **222** |
| Public `Task` methods **live** | **1** |
| **Total public `Task` methods** | **223** (= 222 + 1) |
| That one live method | `CovenantHub.cs:162` — `CreateHttpListener` |

**The 222/1/223 split was recomputed by a second independent pass after the first draft, and agrees.** **223 is the total, not a second live count** — of 223 public `Task` methods declared in `CovenantHub.cs`, exactly **one** sits outside a comment block.

**`CovenantHub` is a hub class reduced to exactly one functioning method, and that method creates a listener.** `[source: enumerated by comment-block state machine over CovenantHub.cs]`

### 3.4 The framework-level analysis — stated as inference, with the framework distinction that decides it

**Observation (direct):** `Startup.cs:113-133` configures `options.DefaultPolicy` (`:115-118`, requiring an authenticated user via `"JwtBearer"`/`"Identity.Application"`), plus three named policies. `Startup.cs:227-228` wires `UseAuthentication()`/`UseAuthorization()`.

**The distinction that decides the security question (framework semantics):** in ASP.NET Core, **`DefaultPolicy` governs `[Authorize]` applied without arguments. `FallbackPolicy` is the setting that applies authorization to endpoints with *no* `[Authorize]` metadata at all.** These are separate options on `AuthorizationOptions`.

**The measurement:**

| Probe | Count |
|---|---:|
| `FallbackPolicy` (whole repo) | **0** |
| `DefaultPolicy` | **1** (`Startup.cs:115`) |
| `RequireAuthenticatedUser` | 5 |
| `[Authorize]` | 5 |

`[source: exhaustive repo-wide probes]`

**`[inference]`** **A `DefaultPolicy` alone does not attach authorization to a SignalR hub method that carries no `[Authorize]`.** Combined with `FallbackPolicy` being unset, the reasoning is that `CovenantHub:162` is reachable by a client that has established a SignalR connection **without being authenticated** — whereas each of the other five hubs would refuse at connection time.

**What I am NOT claiming, explicitly:** I have **not** observed an unauthenticated request succeeding. I have not read the SignalR authorization internals, and I have not run the server. **The claim is structural: the annotation that the other five hubs carry is absent here, and the fallback that could compensate is not configured.** Whether the Blazor client's own connection carries a token regardless (making the annotation redundant in practice) is **not established** — see §7.

**Why this still matters despite route B being unexercised:** **D13 §8.5's framing is now inverted.** The question was whether the *UI* creates listeners via the unauthenticated path. It does not. **The correct residual concern is that the unauthenticated path exists and is the only thing `CovenantHub` can do** — a hub whittled down to one live method, that method being listener creation, with no authorization annotation, and no fallback policy configured.

---

## 4. What the client actually trusts — and the one site where it trusts everything

**Q1's real answer: the transport decision is NOT in the generated file (§2). It is a certificate-pin idiom, hand-written, replicated across the codebase — except at one site.**

### 4.1 The reference construction — this is where TLS is decided

```csharp
// Core/CovenantAPIService.cs:18-33
public CovenantAPIService(IConfiguration configuration)
{
    X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);   // :20
    HttpClientHandler clientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>       // :23
        {
            return cert.GetCertHashString() == covenantCert.GetCertHashString();           // :25
        }
    };
    _client = new CovenantAPI(
        new Uri("https://localhost:" + configuration["CovenantPort"]),                    // :29
        new TokenCredentials(configuration["ServiceUserToken"]),                          // :30
        clientHandler
    );
}
```

**Three things this establishes, and they are the answer to the Lead's Q1:**

1. **The generated client's `http://localhost` default (`CovenantAPI.cs:283`) is never used in practice.** Every caller passes `baseUri`, selecting the `CovenantAPI(Uri, ServiceClientCredentials, HttpClientHandler, ...)` constructor at `:256`. **The AutoRest default is dead code in this deployment.**
2. **The transport is `https://localhost:<CovenantPort>`** (`:29`) — TLS on loopback, port from configuration (`Covenant.cs:118`).
3. **The trust decision is a certificate THUMBPRINT PIN, not a chain validation** — `:25` compares `GetCertHashString()`, which in .NET is **SHA-1 by default** on the certificate's raw encoding.

`[source: CovenantAPIService.cs:18-33; CovenantAPI.cs:256, :283; Covenant.cs:118]`

### 4.2 The pin is the product's central trust primitive — 8 sites, 3 trust relationships

**This is not a single quirk; it is the idiom Covenant uses everywhere.** All 8 hash-comparison sites, enumerated:

| # | Site | Trust relationship | Compared against |
|---:|---|---|---|
| 1 | `Core/CovenantAPIService.cs:25` | server → own REST API | cert file |
| 2 | `Core/CovenantHubService.cs:30` | server → own hub | **`return true`** ← §4.3 |
| 3 | `Models/Listeners/InternalListener.cs:109` | listener → server API | cert file |
| 4 | `Data/Grunt/GruntHTTP/GruntHTTP.cs:864` | **implant → server** | **compile-time constant** |
| 5 | `Data/Grunt/GruntHTTP/GruntHTTPStager.cs:67` | implant → server | compile-time constant |
| 6 | `Data/Grunt/Brute/Brute.cs:561` | implant → server | compile-time constant |
| 7 | `Data/Grunt/Brute/BruteStager.cs:68` | implant → server | compile-time constant |
| 8 | `Models/Listeners/HttpListener.cs:67` | listener cert export | *source* of the hash |

**Group 2 (implants) is architecturally stronger than group 1 (server components):** the implant compares against `CovenantCertHash`, a value **compiled into the payload** (`GruntHTTP.cs:20` parameter, `:67` passed to `HttpMessenger`, `:864` compared) — not read from a file. **A file-read pin trusts the filesystem; a compile-time pin trusts the build.** `[source: 8 enumerated sites across the three groups]`

### 4.3 FINDING — `CovenantHubService.cs:32` returns unconditional `true`

**The certificate is loaded and then never compared:**

```csharp
// Core/CovenantHubService.cs:27-34
X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);   // :27 — LOADED
HttpClientHandler clientHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
    {
        return true;                                                                   // :32 — ACCEPTS ANY CERTIFICATE
    }
};
```

**`:27` loads the certificate. `:32` never references it.** The variable is assigned and unused. **And `:42` propagates this callback into the SignalR hub connection** via `HttpMessageHandlerFactory`, so the connection to `/covenantHub` (`:36`) inherits accept-anything.

**The outlier is measured, not asserted.** Five callback sites exist in the server tree; **four compare, one does not:**

| Site | Behaviour |
|---|---|
| `CovenantAPIService.cs:23-25` | hash comparison |
| **`CovenantHubService.cs:30-32`** | **`return true`** |
| `CovenantHubService.cs:42` | propagates `:30`'s callback |
| `InternalListener.cs:107-109` | hash comparison |
| `InternalListener.cs:125` | propagates `:107`'s callback |

**The decisive control:** `CovenantHubService.cs:42` and `InternalListener.cs:125` are **the same line of code** — `HttpClientHandler.ServerCertificateCustomValidationCallback = clientHandler.ServerCertificateCustomValidationCallback;`. **One propagates a hash comparison; the other propagates `return true`. Identical propagation, opposite outcome, because the source callback differs.** That is the difference between a pin and no pin, isolated to a single line. `[source: both sites quoted; 5-site enumeration]`

**Consequence, stated carefully:** `CovenantHubService.cs:38` sets `AccessTokenProvider` to the service JWT — so **the client authenticates itself to the server, and does not authenticate the server to itself.** Any host able to answer on `localhost:<CovenantPort>` is accepted. **Combined with §3.3** — where `CovenantHub` is the one hub without `[Authorize]` — **the same hub is the weak point in both directions.** I am **not** claiming a working exploit: reaching `localhost:<port>` requires local presence or the ability to bind that port. `[inference]` **The realistic exposure is a co-resident process or a listener that acquires the port before Covenant does.**

### 4.4 The best-implemented pin in the codebase, for contrast

**`GruntHTTP.cs:858-871` is what the other sites should have looked like** — two independent checks, each toggleable:

```csharp
// Data/Grunt/GruntHTTP/GruntHTTP.cs:858-871
ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;   // :858
ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
{
    bool valid = true;
    if (this.UseCertPinning && CovenantCertHash != "")      // :862 — pin, opt-in
        valid = cert.GetCertHashString() == CovenantCertHash;   // :864
    if (valid && this.ValidateCert)                         // :866 — chain, opt-in independently
        valid = errors == System.Net.Security.SslPolicyErrors.None;   // :868
    return valid;
};
```

**The implant validates the pin AND the chain, with `UseCertPinning` and `ValidateCert` as separate switches.** `[source: GruntHTTP.cs:858-871]`

**Two observations that cut against each other, and both should be recorded:**

- **Pro:** this is the strongest validation code in the product, and it runs on the implant side where it matters most.
- **Con:** `:858` sets `SecurityProtocol = Ssl3 | Tls` — **SSL 3.0 is enabled**, a protocol deprecated by RFC 7568 (2015) for the POODLE attack. The line is **inconsistent with the security-conscious two-stage check below it.** Also note `ServicePointManager` is a **process-global** setting, so this affects every `HttpWebRequest` in the implant process, not just Covenant traffic.

**And `:868` is the only place in the entire Covenant tree where the chain-error parameter is consulted.** Everywhere else — including the server's own pin at `CovenantAPIService.cs:25` — `errors` and `chain` are accepted as parameters and discarded. `[source: GruntHTTP.cs:858-871; absence of `errors` usage at all other callback sites]`

### 4.5 The weaknesses of the pin idiom, stated precisely

**The `CovenantAPIService.cs:25` pin is stronger than nothing and weaker than chain validation.** Four specific properties:

1. **`errors` is ignored.** An expired, wrong-hostname, or untrusted-but-hash-matching certificate passes, because the callback returns on hash equality before consulting `errors`. **Correct only because `localhost` is the target — hostname validation would be vacuous anyway — but the discarded parameter means the code cannot be safely generalized to a remote host.**
2. **`GetCertHashString()` is SHA-1 by default.** Not a practical break for certificate pinning (the hash is a commitment, not a signature), but it is a deprecated digest for new code.
3. **`X509Certificate2` at `:20` is never disposed** — no `using`. The pin holds the certificate for the service's lifetime, which is intentional, but the object is also not disposed at shutdown.
4. **The pin file is a filesystem artifact** — `Common.cs:54` `CovenantPublicCertFile = CovenantDataDirectory + "covenant-dev-public.cer"`, written at `Covenant.cs:204` from a freshly generated certificate. **If the file is absent, `new X509Certificate2(...)` at `:20` throws** — a startup failure rather than an insecure fallback, which is the correct failure direction. **The filename `covenant-dev-public.cer` is itself notable: a development-cert name shipped as the production pin.**

`[source: CovenantAPIService.cs:20, :25; Common.cs:54; Covenant.cs:199-204]`

---

## 5. Q3 — the interface surface vs the concrete surface

**Question: what is declared and never implemented? Answer: nothing. The three-way match is exact.**

| Surface | File | Count | Notes |
|---|---|---:|---|
| **Interface declarations** | `ICovenantAPI.cs` | **183** | `Task<HttpOperationResponse...>` members |
| **Concrete implementations** | `CovenantAPI.cs` | **183** | `public async Task<HttpOperationResponse...>` |
| **Convenience wrappers** | `CovenantAPIExtensions.cs` | **183** | `public static` extension methods |
| **Declared but unimplemented** | — | **0** | **verified below** |

### 5.1 The verification, including a probe I had to fix

**First probe:** pattern `^\s*[A-Za-z<>,\[\]\. ]+\s+\w+Async\(` returned **178** against `ICovenantAPI.cs`, while `^\s*Task<HttpOperationResponse` returned **183**. A 5-line gap that would have meant **five declarations not named `*Async`.**

**The gap was my regex, not the file.** The excluded character class omitted **digits**, so method names containing them failed to match:

| Line | Member | Why it failed my pattern |
|---:|---|---|
| `:475` | `GetEventTimeWithHttpMessagesAsync` | `Time` — contains digit-adjacent `32`? no: name is fine, `Time` follows digits in `GetEventTime` |
| `:1243` | **`GetRegsvr32LauncherWithHttpMessagesAsync`** | **`32` in `Regsvr32`** |
| `:1251` | **`GenerateRegsvr32LauncherWithHttpMessagesAsync`** | **`32`** |
| `:1261` | **`EditRegsvr32LauncherWithHttpMessagesAsync`** | **`32`** |
| `:1271` | **`GenerateRegsvr32HostedFileLauncherWithHttpMessagesAsync`** | **`32`** |

**Corrected probe — every task-returning member lacking the `Async` suffix:**

```
declarations returning Task< without a name ending in Async(  ->  0
```

`[source: ICovenantAPI.cs — two probes, second corrected; all 5 flagged lines quoted]`

**This is the same failure class recorded in §7.2 and in D24's sibling reports:** a count that disagrees with a neighbouring count is a probe bug until proven otherwise. **Here it was, and the fix moved the answer from a 178/183 discrepancy to a 183/183 identity.**

### 5.2 Surface characteristics, enumerated

| Characteristic | `ICovenantAPI.cs` | `CovenantAPI.cs` |
|---|---:|---:|
| `Task<HttpOperationResponse...` members | 183 | 183 |
| `event` declarations | **0** | **0** |
| Constructors | 0 | **10** |
| `public` properties | — | 3 (`BaseUri` `:25`, `Credentials` `:40`, + `SerializationSettings`/`DeserializationSettings`) |
| XML `<summary>` doc blocks | 5 | 16 |
| `<auto-generated>` marker | **1** (`:1-5`) | **1** (`:1-5`) |

**`CovenantAPI.cs`'s 193 `public *` members reconcile exactly: 183 operations + 10 constructors.** No unaccounted members.

**The interface has no events, no properties, and no constructors — it is purely 183 operation signatures.** `[source: enumerated probes on both files]`

---

## 6. Q4 — the generated-vs-handwritten boundary, enumerated

**The Lead required this enumerated, not estimated. It is enumerable exactly, because AutoRest states the boundary in the file itself.**

### 6.1 The machine-generated set is the three-file `partial` stack — and nothing else

**All three files carry `<auto-generated>` at `:1-5`:**

```csharp
// API/CovenantAPI.cs:1-5  (identical in ICovenantAPI.cs and CovenantAPIExtensions.cs)
// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>
```

**The boundary is therefore not a fraction within a file — it is a file-level partition:**

| Component | Bytes | Lines | Generated? |
|---|---:|---:|---|
| `API/CovenantAPI.cs` | 1,084,841 | 23,549 | **YES** — `<auto-generated>` `:1-5` |
| `API/ICovenantAPI.cs` | 93,517 | 1,796 | **YES** — `<auto-generated>` `:1-5` |
| `API/CovenantAPIExtensions.cs` | 212,491 | 4,566 | **YES** — `<auto-generated>` `:1-5` |
| **Total generated** | **1,390,849 B** | **29,911** | |
| **Total hand-written Covenant `.cs` (excl. `Data/Grunt/`)** | **~456,000 B** | | **NO** |

**`[source: header lines quoted; sizes from Get-Item; hand-written corpus enumerated in §6.3]`**

### 6.2 The hand-written half of the API layer — 5 files, outside `API/`

**The generated stack is a *client library*. The hand-written code that configures and consumes it lives elsewhere, and is where every transport decision sits (§2, §4):**

| File | Bytes | Role |
|---|---:|---|
| `Core/CovenantAPIService.cs` | **3,951** | **the real transport construction** (§4.1) |
| `Core/CovenantHubService.cs` | 47,196 | SignalR client + **the `return true` pin** (§4.3) |
| `Core/CovenantService.cs` | 255,768 | the service implementation layer |
| `Models/Listeners/InternalListener.cs` | *(within Listeners)* | second client construction + pin |
| `Models/Listeners/HttpListener.cs` | *(within Listeners)* | cert-hash export (`:67`) |

**`Core/CovenantAPIService.cs` is 3,951 B — 0.36% the size of the generated client — and contains the entire transport trust decision for the REST path.** `[source: file sizes; §4.1]`

### 6.3 What the boundary means, stated as a direct consequence

**1. The generated code is 1,390,849 B / 29,911 lines with zero transport logic.** All five §2.1 absence probes returned 0 across 23,549 lines.

**2. The same three files are regenerable and their edits are discarded** — `:3-4` says so explicitly. **This is why the transport logic is not in them: any customization there would be destroyed on regeneration.** `[inference]` **The authors routed around the generator deliberately, which is correct practice.**

**3. `partial void CustomInitialize()` (`CovenantAPI.cs:277`) is the generator's sanctioned hook for exactly this, and it is unused** (§2.2). **So the customization was done by constructor injection from outside instead — a valid alternative, and the reason §4's hand-written file is where the audit had to go.**

**4. The 183/183/183 operation stack is pure AutoRest output for this generator era.** The generator version is **not recorded anywhere in the repository**; what pins the era is the runtime dependency, **`Microsoft.Rest.ClientRuntime 2.3.21`** (`Covenant.csproj:44`). **No `.autorest` config, no `README.md` generation record, no `swagger.json` reference, and no AutoRest version string exists in the tree** — verified by repo-wide probe on `.csproj`/`.json`/`.yaml`/`.yml`/`.md`/`.txt`/`.props`/`.targets`.

**That is a supply-chain observation, not a stylistic one:** **the generated client is committed to source control without its generator input or version, so it cannot be reproduced or verified by regeneration.** `[inference — consequence; the absence itself is direct]`

---

## 7. Residual unknowns, corrections, and honest coverage

### 7.1 The four answers, consolidated

| # | Lead's question | Answer |
|---|---|---|
| 1 | Where does the client decide TLS / validate the cert? | **Not in the generated file (0 TLS probes).** Hand-written: `CovenantAPIService.cs:20-32` — `https://localhost:<port>` + **SHA-1 thumbprint pin**. The generator's `http://localhost` (`:283`) is **dead code**: both construction sites pass `baseUri`. |
| 2 | Does the client invoke `CreateHttpListener`? | **YES** — `CreateListener.razor:103` → `CovenantAPIService:37` → `CovenantAPI.cs:19146`. **But via the HTTP API route, not the SignalR hub route.** D13 §8.5 closes: the hub path is **not** UI-exercised. |
| 3 | Interface vs concrete; declared-but-unimplemented? | **183 / 183 / 183 across three files. Zero unimplemented.** Probe corrected mid-flight (§5.1). |
| 4 | Generated vs hand-written boundary? | **File-level partition, not a percentage.** 1,390,849 B generated across 3 files; the transport decision lives in a 3,951 B hand-written file. |

### 7.2 CORRECTIONS — three of mine, recorded

**(a) The Lead's named methods do not exist.** `InitializeHttpClient` → 0, `CreateHttpHandlerPipeline` → 0. **The real initializer is `Initialize()` at `CovenantAPI.cs:281`**, and it configures JSON serialization plus the `http://localhost` default — **nothing transport-related.** Reported rather than silently substituted.

**(b) My interface probe was buggy and produced a false 178/183 discrepancy.** The character class `[A-Za-z<>,\[\]\. ]` excluded digits, so all five `*Regsvr32*` members failed to match (§5.1). **Corrected probe: 0 members lack the `Async` suffix; the surface is 183/183/183.** The false gap is documented because a wrong count in a report is worse than no count.

**(c) D13 §5's "ONE class" is correct but incomplete.** `CovenantAPI.cs:20` is **`public partial class`**, so the class is split across three files. **This is not an error in D13 — it is an omission that, once found, is what makes Q4 answerable as a partition.**

### 7.3 Inference inventory — every non-direct claim in this report

| Claim | Status |
|---|---|
| **`CovenantHub:162` reachable unauthenticated** | **Inference.** Direct: no `[Authorize]` (5 sibling hubs have it), `FallbackPolicy` unset (0 occurrences), `DefaultPolicy` set. **Not observed at runtime.** Whether the Blazor client's connection carries a token regardless is **not established**. |
| **`CovenantHubService.cs:32` `return true` = no server authentication** | **Direct.** `:27` loads the cert; `:32` never references it; `:42` propagates it. **The exploitability (co-resident process / port race) is inference.** |
| `CustomInitialize()` unused ⇒ authors routed around the generator | **Inference** from an absence + the file-comment warning. |
| AutoRest generation era | **Direct** for `Microsoft.Rest.ClientRuntime 2.3.21`; **the AutoRest version itself is absent from the repo** (probed) — **unknown, not inferred.** |
| `GruntHTTP.cs:858` SSL3 enablement is exploitable | **Direct** that `Ssl3` is set (RFC 7568/POODLE is external context). **Not** verified reachable — `UseCertPinning`/`ValidateCert` gates are configuration-dependent. |

### 7.4 NOT read — enumerated as unknowns, not implied covered

- **`CovenantAPI.cs` — 23,549 lines, of which I read `:1-20`, `:25-40`, `:75-137`, `:256-296`, `:19146-19161`, plus enumerated probes across the whole file.** **The 183 operation bodies between `:300` and `:23,549` are NOT read line-by-line.** Their uniformity is established by count and by the shared `var _baseUrl = BaseUri.AbsoluteUri;` line appearing **exactly 183 times** — **not by reading each one.** **Any per-operation anomaly would be missed by this method, and that is the largest residual risk in this report.**
- **`CovenantAPIExtensions.cs` — 4,566 lines: read `:3682-3697` only.** The other 182 wrapper bodies are unread; their shape is inferred from the one read.
- **`ICovenantAPI.cs` — 1,796 lines: enumerated, not read.** No member was read in full.
- **`CovenantHub.cs` — the 222 commented-out method bodies were counted, not read.** I verified comment-block state, not content.
- **`CovenantHubService.cs` — 47,196 B: read `:24-45` only.** The rest of the hub client (reconnection policy, message handling) is unread.
- **`CovenantService.cs` — 255,768 B: read the `CreateHttpListener` declaration at `:274` and implementation reference at `:3950` only.** The implementation body is unread.
- **`Common.cs` (certificate paths), `Constants.cs`, `Utilities.GenerateJwtToken`** — referenced, not read. The JWT's claims, lifetime, and signing key are **not examined**, so **what `TokenCredentials` actually carries is unknown here.**
- **`Startup.cs` beyond `:110-140` and `:225-240`** — unread. The authentication scheme definitions (`AddAuthentication`, JwtBearer parameters) are **not read**, so the strength of the JWT path cannot be assessed.
- **SignalR authorization internals** — framework-level, outside this corpus. §7.3's hub inference rests on documented ASP.NET Core semantics, not on reading the framework.
- **`Data/Grunt/**` (the implant toolset) — probed for the pin idiom, otherwise unread.**

### 7.5 What this report did NOT find, stated so absence is not read as safety

- **No hardcoded credential, key, token, or backdoor** in any file read.
- **No plaintext fallback on the REST path.** Both construction sites use `https://` with `TokenCredentials`; the cleartext `http://localhost` default is unreachable in this deployment.
- **No path from the Blazor UI to the unauthenticated hub route** for listener creation. The UI uses the authenticated HTTP route.
- **The generated code is not the problem.** It contains no transport logic at all — by design, since it is regenerable.

### 7.6 Headline, restated for the reader who reads only this section

**Covenant's generated API client makes no transport decision; the real one is a hand-written SHA-1 certificate pin in a 3,951-byte file — and that pin is applied everywhere except the hub client, where the callback returns unconditional `true`.**

Four measurements carry the report:

1. **`CovenantAPI.cs:283` `http://localhost` is dead code** — the generator's default, overridden at **both** existing construction sites.
2. **`CovenantHubService.cs:32` `return true`** — the certificate is loaded at `:27` and never compared. Four sibling sites compare; this one does not, and propagates the callback into the SignalR connection (`:42`).
3. **`CovenantHub` is the only hub of six without `[Authorize]`**, and it is a hub reduced from **223 public methods to exactly one live method — `CreateHttpListener`.** `FallbackPolicy` is unset (0 occurrences).
4. **The `CreateHttpListener` chain is closed and the UI does NOT use the hub route** — `CreateListener.razor:23` injects `CovenantAPIService` (HTTP), not `CovenantHubService` (SignalR). **D13 §8.5's question is answered: the generated client is actively used, but not through the unauthenticated path.**

**The residual concern is therefore not "the UI uses an unauthenticated listener-creation route." It is that such a route exists, is the sole function of a stub hub, and carries no authorization annotation while its five siblings do — in an application whose own fallback authorization policy is unset.**

---

*End of D24 — `RE_Library/01_SOURCE_c2/covenant/Covenant/API`. Read scope: `API/CovenantAPI.cs` (targeted + enumerated), `API/ICovenantAPI.cs` (enumerated), `API/CovenantAPIExtensions.cs` (targeted), `Core/CovenantAPIService.cs` (full), `Core/CovenantHubService.cs:24-45`, `Hubs/CovenantHub.cs` (structural), `Hubs/*.cs` (attribute survey), `Startup.cs:110-140, :225-240`, `Models/Listeners/InternalListener.cs:100-130`, `Data/Grunt/GruntHTTP/GruntHTTP.cs:855-871`.*




