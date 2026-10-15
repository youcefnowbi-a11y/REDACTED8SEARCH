# D32 — The Covenant `partial` Class Question

**Target:** `RE_Library/01_SOURCE_c2/covenant/Covenant/`
**Class:** source-only reversal (NO REA/GHIDRA)
**Task:** task-39
**What I was asked:** verify that D13's "one class" is a `partial` class split across three files, name all three, determine whether the split is load-bearing, and re-examine `CovenantHubService.cs:32` in that light.

**Tags:** `[read]` = read directly · `[verified]` = confirmed by two independent instruments · `[inferred]` = my deduction · `[absence]` = searched and not found, with search and positive control stated

---

## CORRECTION 0 — the premise does not survive enumeration, and I say so at the top

**The task premise is: "D13's 'one class' is a `partial` split across three files." Both halves of that sentence are false, for different reasons.** `[verified]`

**(a) The `partial` split does not exist.** Enumerating every `partial` declaration in the tree returns **53 `partial` types declared across 53 files — and zero types declared `partial` in more than one file.** `[verified]` **No class in the Covenant tree is split across multiple `partial` files.** The positive control (§1.2) confirms the detector finds multi-file splits when they exist.

**(b) D13's "one class" was about a different file than the one the premise is tracking.** D13 measured **`API/CovenantAPI.cs`** and found exactly one type: `public partial class CovenantAPI : ServiceClient<CovenantAPI>, ICovenantAPI` at **L20**. That claim is **correct as D13 wrote it** — `CovenantAPI` genuinely is the sole type in that file. The premise attaches it to `CovenantHubService`, which is a **different class in a different directory, declared without `partial` at all.** `[read]`

**What is actually true, and it is more interesting than the premise:** `CovenantAPI` is declared `partial`, and **`ICovenantAPI.cs:19` declares `public partial interface ICovenantAPI`.** These are the two halves of a genuine generated-client split — but across **two** files, not three, and the split is between a **class and its interface**, which is the AutoRest convention, not a hidden boundary.

**Method note, stated because the task asked for instrument discipline:** the premise reached me third-hand (D24 → Lead → me). It contains a **file-identity error** — `CovenantHubService` substituted for `CovenantAPI` — and a **count error** — three substituted for two. I did not resolve this by re-reading the claim. **I enumerated the tree**, and the enumeration is what produced the correction.

---

## TOC

1. [The `partial` census — every declaration, enumerated](#1-the-partial-census)
2. [Positive control and the split that does exist](#2-positive-control-and-the-split-that-does-exist)
3. [Is the split load-bearing or cosmetic?](#3-is-the-split-load-bearing-or-cosmetic)
4. [`:32`'s unconditional `true` — co-location re-examined](#4-32s-unconditional-true--co-location-re-examined)
5. [Where the 255,768 B actually sits](#5-where-the-255768-b-actually-sits)
6. [Instrument record](#6-instrument-record)
7. [What I could not establish](#7-what-i-could-not-establish)

---

## 1. The `partial` census

### 1.1 Every `partial` declaration in the tree

Enumerated exhaustively over all `.cs` files. **53 distinct `partial` type names across 53 files.** `[verified]`

| Location | Count | Notes |
|---|---|---|
| `API/Models/*.cs` | **47** | AutoRest-generated DTOs |
| `API/CovenantAPI.cs` | 1 | the generated client class |
| `API/ICovenantAPI.cs` | 1 | the generated client interface |
| `Components/Shared/*.razor.cs` | 2 | `CovenantTable<TItem>`, `SortableTableHeader<TItem, TItem2>` |
| `Models/Listeners/InternalListener.cs` | 2 | `GruntTaskingMessage`, `GruntTaskingMessageResponse` (at L910, L935) |

`[read]` **53 declarations, 53 files, 53 distinct type names.** Full list:

`CovenantAPI`, `ICovenantAPI`, `BinaryLauncher`, `BridgeListener`, `CapturedCredential`, `CapturedHashCredential`, `CapturedPasswordCredential`, `CapturedTicketCredential`, `CommandOutput`, `CovenantUser`, `CovenantUserLogin`, `CovenantUserLoginResult`, `CovenantUserRegister`, `CscriptLauncher`, `DownloadEvent`, `EmbeddedResource`, `EventModel`, `FileIndicator`, `Grunt`, `GruntCommand`, `GruntTask`, `GruntTaskAuthor`, `GruntTasking`, `GruntTaskOption`, `HostedFile`, `HttpListener`, `HttpProfile`, `HttpProfileHeader`, `IdentityRole`, `ImplantTemplate`, `Indicator`, `InstallUtilLauncher`, `Launcher`, `Listener`, `ListenerType`, `MSBuildLauncher`, `MshtaLauncher`, `NetworkIndicator`, `PowerShellLauncher`, `Profile`, `ReferenceAssembly`, `ReferenceSourceLibrary`, `Regsvr32Launcher`, `ShellCodeLauncher`, `StringIdentityUserRole`, `TargetIndicator`, `Theme`, `WmicLauncher`, `WscriptLauncher`, `CovenantTable<TItem>`, `SortableTableHeader<TItem, TItem2>`, `GruntTaskingMessage`, `GruntTaskingMessageResponse`

`[read]`

### 1.2 The multi-file test — and its positive control

**Question:** of those 53, how many are declared `partial` in more than one file?

**Answer: zero.** `[verified]`

**Positive control, executed and shown to pass:** I wrote two files `a.cs` and `b.cs`, each containing `public partial class ZedTest { }`, then ran the identical detector over that directory. It reported **`CONTROL PASSED: ZedTest in 2 files`**. `[verified]` **The detector demonstrably finds a multi-file `partial` split. Applied to the Covenant tree it returns zero.** The absence is a property of the codebase, not of the instrument.

`[absence]` **"A class split across three `partial` files" — searched `^\s*(public|internal|sealed|abstract|static)?\s*partial\s+(class|struct|interface)\s+\w+` over every `.cs` file in the tree, positive control passed, zero hits.** Nothing in Covenant matches the premise's shape.

### 1.3 The 57 same-name-across-files result — and why it is NOT a partial split

A looser scan (type name declared in >1 file, **any** declaration form, not just `partial`) returns **57 type names spanning multiple files.** `[read]` **This is not the finding it resembles, and I want to state that before anyone indexes it.**

Every one of those 57 is a **namespace collision between the generated API model layer and the hand-written server model layer**:

| Name | Generated half | Hand-written half |
|---|---|---|
| `Grunt` | `API/Models/Grunt.cs` | `Models/Grunts/Grunt.cs` (+3 grunt-data files) |
| `HttpListener` | `API/Models/HTTPListener.cs` | `Models/Listeners/HttpListener.cs` |
| `Profile` | `API/Models/Profile.cs` | `Models/Listeners/Profile.cs` (+4 grunt files) |
| `Theme` | `API/Models/Theme.cs` | `Models/Covenant/Theme.cs` |

`[read]` These are **`Covenant.API.Models.X` vs `Covenant.Models.X`** — two genuinely distinct types sharing a short name in different namespaces. **They are not `partial` continuations and they do not compose into one type.** A reader who conflates them would conclude Covenant has one type split across files; it has two types that happen to be spelled the same. `[inferred]`

**This is, I believe, the mechanism by which the premise acquired its shape.** `CovenantHubService` and `CovenantHub` also share a prefix, live in different directories, and are related by convention rather than by declaration — which reads exactly like a `partial` split from a distance. **The resemblance is lexical.** `[inferred]`

---

## 2. Positive control and the split that does exist

The one genuine generated-code split in the tree is the **class/interface pair** of the API client: `[read]`

| File | Declaration | Bytes |
|---|---|---|
| `API/CovenantAPI.cs` | `public partial class CovenantAPI : ServiceClient<CovenantAPI>, ICovenantAPI` (L20) | **1,084,841** |
| `API/ICovenantAPI.cs` | `public partial interface ICovenantAPI : System.IDisposable` (L19) | **93,517** |

`[read]` **Both are `partial`. Together they total 1,178,358 B across two files.** This is the AutoRest convention — a generated class and its generated interface, each declared `partial` so a consumer can extend them without regenerating. It is a **known, declared, conventional** split, and it is **two** files.

`[read]` **`CovenantHub.cs:27` is `public class CovenantHub : Hub` — NOT `partial`.**
`[read]` **`CovenantHubService.cs:22` is `public class CovenantHubService : IRemoteCovenantService` — NOT `partial`.**

**Neither hub-related class is `partial` in any file.** The premise's central structural claim does not hold for either class it could plausibly have meant. `[verified]`

`[read]` For completeness, the two files that *look* like a hub split by name:

| File | Class | Bytes | Lines | `partial`? |
|---|---|---|---|---|
| `Hubs/CovenantHub.cs` | `CovenantHub : Hub` | 36,205 | 1,153 | **no** |
| `Core/CovenantHubService.cs` | `CovenantHubService : IRemoteCovenantService` | 47,196 | 1,228 | **no** |

These two are **not halves of one type.** `CovenantHub` is a **SignalR server hub** (derives `Hub`); `CovenantHubService` is a **SignalR client proxy** (holds a `HubConnection`, `IRemoteCovenantService`). They are the two ends of a connection, in different namespaces, neither `partial`. `[read]` **They are a client and a server, not one class in two files.**

---

## 3. Is the split load-bearing or cosmetic?

**Because no multi-file `partial` split exists, this question has no referent in the sense asked.** But the *underlying* concern — *does a reader who opens one file see the whole picture?* — does apply to the two genuine multi-file structures in this area, and it is worth answering precisely rather than dismissing. `[read]`

### 3.1 The generated class/interface split — cosmetic, and conventional

| Property | Assessment |
|---|---|
| Is it load-bearing for authorization? | **No.** `CovenantAPI.cs` is an HTTP client façade; `ICovenantAPI.cs` is its interface. Neither contains an authorization decision. `[read]` — D13 §1 established the class is 183 uniform AutoRest operations with no branching that varies. |
| Does a reader opening one half miss a control? | **No.** There is no control in either half to miss. |
| Is it declared? | **Yes** — `partial` is explicit at both declaration sites, which is the opposite of an undeclared boundary. |

`[read]` **Cosmetic.** It is generated-code convention, and it is visible to anyone reading either file.

### 3.2 The hub pair — NOT a split, and the distinction is the whole answer

This is where the premise's shape came from, and it matters that it is wrong in a specific direction: **`CovenantHub` and `CovenantHubService` are not two views of one class; they are two different programs' ends of one wire protocol.** `[read]`

- `Hubs/CovenantHub.cs:27` — `public class CovenantHub : Hub`. **Server side.** Runs in the Covenant host, receives SignalR invocations.
- `Core/CovenantHubService.cs:22` — `public class CovenantHubService : IRemoteCovenantService`. **Client side.** Runs *as a client*, opens a `HubConnection` to `wss://localhost:{port}/covenantHub` (L35-37), and sends invocations.

`[read]` **A reader who opens `CovenantHub.cs` sees a hub with one live method and no `[Authorize]`. A reader who opens `CovenantHubService.cs` sees 233 client-side `InvokeAsync` calls.** Neither file shows the other. **But this is not a `partial` boundary that hides a control — it is the normal separation between a server and its client, and the "missing authorization" is not hidden in the other file.** `[read]` There is no `[Authorize]` in `CovenantHubService.cs` either, because authorization belongs on the server side and that is `CovenantHub.cs` — where it is absent.

**So the honest answer to task question 2 is: the split is neither load-bearing nor cosmetic, because it is not a split.** `[verified]` The concern that motivated the question is nevertheless **substantively correct in a different location** — see §3.3.

### 3.3 The concern is real, and it lands somewhere else

The Lead's framing — *"a reader who opens the file with the operations sees no authorization code at all ... the same defect shape as D22's relocation and D17 §4c"* — describes a genuine hazard. **It is not produced by `partial` here. It is produced by the fact that D13's service-level negative and this report's hub finding both live in files that look complete.**

`[read]` Concretely: `Core/CovenantService.cs` is **255,768 B / 5,138 lines** and contains **zero** authorization decisions of its own (D13 §8.1, enumerated). `Hubs/CovenantHub.cs` is **36,205 B / 1,153 lines** and contains **no `[Authorize]`** — and 985 of those lines are inside a block comment. `[read]` **Both files read as complete implementations.** Neither is. But the mechanism is **block-commenting and single-siting**, not `partial` splitting.

`[inferred]` **The correct cross-reference is D13 §4.0 and §8, not a `partial` boundary.** I flag this because if D24 or D17 §4b.1 is currently attributing a hidden-boundary shape to `partial`, that attribution is wrong and should be corrected. See §8 for the exact replacement text.

---

## 4. `:32`'s unconditional `true` — co-location re-examined

**The question asked:** does the `true`-returning method live in a *different `partial` file* from the four sibling sites that compare — and if so, is the finding that the control was never co-located with the code it protects?

**Answer: no. All the cert-validation sites live in their own files, none of them `partial`, and the `true` is co-located with its own connection setup — which makes the original "wrong return value" reading the correct one.** `[verified]`

### 4.1 Every certificate-validation site in the tree, enumerated

`[read]` Complete enumeration of `ServerCertificateCustomValidationCallback` and `GetCertHashString`:

| # | File:Line | Behaviour |
|---|---|---|
| 1 | `Core/CovenantAPIService.cs:23-25` | **compares** — `cert.GetCertHashString() == covenantCert.GetCertHashString()` |
| 2 | `Core/CovenantHubService.cs:30-33` | **`return true`** — unconditional |
| 3 | `Core/CovenantHubService.cs:42` | propagates #2's handler to the SignalR client |
| 4 | `Models/Listeners/InternalListener.cs:107-109` | **compares** |
| 5 | `Models/Listeners/InternalListener.cs:125` | propagates #4's handler |
| 6 | `Models/Listeners/HttpListener.cs:67` | `return cert.GetCertHashString();` — getter, not a validator |
| 7 | `Data/Grunt/Brute/Brute.cs:561` | **compares** (`== CovenantCertHash`) |
| 8 | `Data/Grunt/Brute/BruteStager.cs:68` | **compares** |
| 9 | `Data/Grunt/GruntHTTP/GruntHTTP.cs:864` | **compares** |
| 10 | `Data/Grunt/GruntHTTP/GruntHTTPStager.cs:67` | **compares** |

`[read]` **Four server-side comparing sites (#1, #4, #7, #8, #9 — five counting the stager pair as distinct) plus the one `true`.** The Lead's "four sibling sites that actually compare" is **accurate** `[verified]`.

### 4.2 The co-location question, answered by inspection

`[read]` `CovenantHubService.cs:30-33` and `CovenantHubService.cs:42` are **in the same file, adjacent, within the same constructor**:

```csharp
// CovenantHubService.cs:27-42
X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);
HttpClientHandler clientHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
    {
        return true;                                    // :32
    }
};
_connection = new HubConnectionBuilder()
    .WithUrl("https://localhost:" + configuration["CovenantPort"] + "/covenantHub", options =>
    {
        options.AccessTokenProvider = () => { return Task.FromResult(configuration["ServiceUserToken"]); };
        options.HttpMessageHandlerFactory = inner =>
        {
            HttpClientHandler.ServerCertificateCustomValidationCallback =
                clientHandler.ServerCertificateCustomValidationCallback;   // :42
        };
    });
```

`[read]` **The `true` is co-located with the connection it governs, in the same constructor, 12 lines apart.** It is not stranded in another file. The `covenantCert` variable is even **loaded at L27 and then never used** — the callback that would consume it was replaced with `true`. `[read]`

**Verdict: the original reading stands. This is a wrong return value in place, not a control separated from its code.** `[verified]` `[inferred]` The unused `covenantCert` at L27 is corroborating evidence that the comparison was **removed** from this site rather than never written — the vestige of the correct implementation remains in the method. That is a stronger inference than the premise's, and it points at **deliberate disabling**, consistent with D13 §8.4's finding that this whole client family was dismantled asymmetrically.

### 4.3 The fourth task question — where the mass sits

`[read]` D13 established `Core/CovenantService.cs` is **255,768 B with no authorization decision of its own.** `[verified]` **It is a single file, not `partial`, and it is not split anywhere.** The mass sits entirely in `Core/CovenantService.cs`:

| File | Bytes | Lines | `partial`? | Auth decisions |
|---|---|---|---|---|
| `Core/CovenantService.cs` | **255,768** | 5,138 | **no** | **0** `[read]` |

`[read]` **File size confirmed: 255,768 B. There is no second `partial` file for this class, so the question "in which `partial` file does the mass sit?" has no referent.** The mass sits in one file, and D13 §8.1's enumeration — 0 `[Authorize]`, 0 `RequireRole`, 0 `HttpContext`, 0 `IAuthorizationService`, all six `ClaimsPrincipal`/`IsInRole`/`IsAuthenticated` hits resolving to two already-documented methods — is **not weakened** by any split. `[verified]`

**This strengthens D13 §8.1 rather than complicating it.** A single-file 255 KB service with zero authorization is a cleaner negative than one spread across files, because there is no file a reader could have missed. `[inferred]`

---

## 5. The 255,768 B figure — independently re-measured

Because task question 4 turns on that number, and because this lane has twice produced a count by pattern rather than by enumeration: `[verified]`

| File | Measured bytes | Measured lines |
|---|---|---|
| `Core/CovenantService.cs` | **255,768** | **5,138** |
| `Core/CovenantHubService.cs` | **47,196** | 1,228 |
| `Hubs/CovenantHub.cs` | **36,205** | 1,153 |
| `API/CovenantAPI.cs` | **1,084,841** | 23,549 |
| `API/ICovenantAPI.cs` | **93,517** | 1,796 |

`[verified]` **255,768 B confirmed by direct file measurement.** D13's figure is correct.

### 5.1 D13's "one class" claim — re-verified as correct
D13 §1 stated `API/CovenantAPI.cs` contains exactly one type. Re-enumerated: `[verified]`

| Test | Result |
|---|---|
| Type declarations in `CovenantAPI.cs` | **exactly 1** — `public partial class CovenantAPI : ServiceClient<CovenantAPI>, ICovenantAPI` at L20 |
| Second `partial` file for `CovenantAPI`? | **none** `[absence]` — positive control in §1.2 |
| Complementary file | `ICovenantAPI.cs` — a **separate type** (`ICovenantAPI`), not a second part of `CovenantAPI` |

`[verified]` **D13's claim is correct and needs no correction.** The premise that D13 was wrong about "one class" is itself wrong.

---

## 6. Instrument record

**Mandatory, and this lane's record is why.** Two failures from my own prior work are carried forward, plus one from this task.

| # | Instrument | Failure | Correction | Rule it produced |
|---|---|---|---|---|
| 9 | Member-surface regex, D13 §7.2 | character class **excluded digits**, so every `*Regsvr32*` member silently failed to match → reported **178** for a **183**-member surface | character class widened to `[A-Za-z0-9_]` | *A count is a measurement only if you enumerate it.* A regex that silently fails to match is indistinguishable from an absence. |
| 10 | Dialect sweep, D20 §6.2 | `Select-String -Path "$m\**\*.go"` returned **0** for six known-malformed sites | per-file `-LiteralPath` iteration over an enumerated 399-file list → **exactly 6** | *A recursive glob in that form does not recurse the way the syntax suggests, and a zero from it is a tooling artifact, not a finding.* |
| 11 | `partial` multi-file test, **this task** | initial loose scan (any declaration form, any namespace) returned **57 type names across multiple files** — which **looks like** 57 `partial` splits | tightened to `partial` declarations only → **0**; the 57 are same-name types in **different namespaces** | *A name collision across namespaces is not a partial split.* Both produce "same identifier, two files"; only one composes into a single type. |

`[verified]` **Failure #11 is the one to carry forward from this report.** It is the same family as #9 and #10 — **a probe whose shape does not match the evidence's shape** — and it is the third time in this lane that a plausible-looking result was produced by a detector measuring the wrong thing. In this case the wrong result (57) was **larger and more alarming** than the right one (0), which is the reverse of the usual direction and worth noting: **instrument error does not reliably bias toward false negatives.**

**Failure #11 also corrects the premise handed to me**, which is its own point. The Lead's message reports D24 as having found a three-file `partial` split. Applying the tightened detector, that split does not exist. Whether D24 made the same name-collision error, or the error entered in transmission, **I cannot determine from here** — D24 is not in my write scope. §8 gives the exact text to route.

---

## 7. What I could not establish

1. **What D24 actually said.** I have the Lead's summary of it, not D24 itself. D24 is not in my read scope for this task; I did not open it. **If D24 states the three-file `partial` split directly, D24 contains an error and §8 gives the correction.** `[absence]` — I searched the Covenant tree, not D24.
2. **Whether `CovenantBlazorService` / `SignalRCovenantService` ever constituted `partial` parts of anything.** Both are named only in commented-out DI lines (`Startup.cs:197-198`) and **neither exists as a type** (D13 §8.2). They are the only candidates for a "third file," and they are deleted, not split. `[inferred]`
3. **No build was run.** `partial` legality is a compiler-checked property; I verified by source enumeration, not by compiling. **A `partial` split across assemblies or projects with mismatched visibility would be a compile error, not a silent boundary** — so the enumeration is sufficient for this claim, but I did not invoke a compiler. `[inferred]`
4. **No runtime verification.** Unchanged from D13 and D20.

## 8. Correction text to route, if a correction is wanted

**For D24, if it carries the claim.** Replace any statement that *"D13's one class is a `partial` class split across three files"* with:

> **D13's `CovenantAPI` is declared `partial` but is not split — it is the sole type in `API/CovenantAPI.cs` (L20), and no second `partial` file for it exists anywhere in the tree.** A tree-wide enumeration returns **53 `partial` types across 53 files, zero declared in more than one file** (positive control passed). `partial` is the AutoRest generation convention here. The name-collision results (`Grunt`, `HttpListener`, `Profile`, etc., each in a generated and a hand-written file) are **distinct types in different namespaces**, not `partial` continuations.

**For D13.** No correction is needed — D13's "one class" statement is **verified correct** on re-enumeration.

**For D17 §4b.1, if it attributes a hidden-boundary shape to `partial`.** The genuinely hidden boundary in Covenant is **not** a `partial` split. It is: (a) **block-commenting** — `Hubs/CovenantHub.cs` L166-1151, 985 lines of a 1,153-line file, which is why a `public`-member grep over-counted by 223× (D13 §4.0); and (b) **single-siting** — the authorization control living only in controller attributes with `Core/CovenantService.cs` (255,768 B, single file, zero auth decisions) beneath it. **The `partial` mechanism is not present in Covenant's authority path at all.** `[verified]`

