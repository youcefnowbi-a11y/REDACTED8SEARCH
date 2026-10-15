# D17 — Cross-target synthesis: eight frameworks, measured against each other

This is the only report in the corpus that could not have been written by a single lane. Every other
document here is one target read closely. This one exists because nineteen of those documents now
exist and can be compared.

**Scope note, stated first because it bounds everything below:** this synthesis is written from the
lane reports as committed, not from a fresh read of all 739 MB. Where this document asserts a
mechanism it cites the report that measured it. Where a lane's report is incomplete, the row says so
rather than implying coverage. **No new measurements were taken for this document** except where
marked `[re-verified]`.

---

## 0. The headline, before the tables

Six frameworks were each reversed exhaustively and independently. Read side by side, they do not
diverge the way six independent codebases would. **They diverge on exactly one axis and agree on
almost everything else.**

The axis is **what the framework does when the Windows evasion layer fails.** Two frameworks —
Sliver and Havoc, the two most capable in this corpus — made **opposite** choices on the most-watched
evasion question in the field, and **neither choice was made deliberately at the architectural level.**
Both fell out of smaller decisions. This is §4.

Everything else — crypto primitives, jitter formulas, wire framing — converges to within noise. The
differences that look large in a feature comparison are mostly **the same mechanism at a different
layer.**

---

## 1. Cryptographic perimeter, per framework

| target | key exchange | transport crypto | message crypto | signing | source |
|---|---|---|---|---|---|
| **Sliver** | age/X25519 | ChaCha20-Poly1305, nonce-prepended | same primitive, one codec | **Ed25519 (minisign), server→implant only** | D1 §1, §4, §23.1 |
| **Sliver (implant↔server)** | — | — | — | **asymmetric by design, and correct** | D1 §23.2 |
| **Covenant** | RSA | AES (grunt session key) | AES + RSA wrap | — | D2 §3 |
| **Mythic** | per-payload (container is agnostic) | per-payload | per-payload | — | D4 |
| **Havoc** | — | AES (Demon) | AES | — | D5 §11 |
| **Pupy** | RSA-4096 → AES-256 | **four distinct crypto systems** | AES-CBC | *none* | D11_pupy §4, §9 |
| **Merlin** | — | HTTP/2 + HTTP/3, TLS | — | — | D10 |
| **Metasploit** | RSA | AES | TLV + AES | — | D7, D9 |
| **AhMyth / AndroRAT** | none / none | **plaintext — no TLS layer at all** | none | none | D3 §3.4, §6.1, §7.1 |

**What converges.** Every framework that has transport crypto at all uses **AES or ChaCha20 with a
symmetric session key derived from an asymmetric exchange.** There is no framework here inventing a
primitive. That is not a finding about the frameworks; it is a finding about the field.

**What does not converge, and matters:**

**Sliver is the only framework in the corpus with a verified signed server→implant path**
(`implant/sliver/cryptography/crypto.go:185-206`, `minisignRawSigSize = 74`, D1 §23). Every other
framework in this corpus has **unauthenticated or unverified server→implant messages**, which means
every one of them trusts whatever is on the other end of the socket to be the real server.

**Pupy has four independent crypto systems in one framework** (D11_pupy §9): `rsa_aes` (RSA-4096 +
AES-256-CBC, real), `obfs3` (UniformDH + AES-CTR + 4 KB handshake padding + three chained layers),
`ec4`/`ecm`/`kc4` (elliptic curve + RC4), and `ssl` (mutual TLS with a four-property hardening
profile). **The default transport, `ssl`, explicitly excludes RC4 — while three of the four
alternatives are built on it** (`ssl/conf.py:25`). That is not a defect; it is a framework whose
transport layer grew four times and never converged.

### 1.0 The Android floor — verified independently, and it is an absence, not a weakness

Reported by android-diver (D3 lane), **independently reproduced by the Lead this round.**

D3 already establishes the transport story in three places: §3.4 (`:268`) AhMyth socket.io 0.8.3 on
`http://<ip>:42474`, "plaintext, no TLS"; §6.1 (`:282`) AndroRAT raw TCP, port 8000,
attacker-listens/victim-dials; §7.1 (`:498`) the AhMyth handshake sending four device fields in the
clear. **A brief claiming Android's transport was unclaimed was wrong, and it was the Lead's.**

The TLS/pinning probe across both first-party trees, 16 markers, **all 16 initially returned zero.**
android-diver ran the control before reporting and found the path filter was excluding the tree.
Unfiltered, reproduced by the Lead over 2,925 files:

```
HostnameVerifier    : 81        SSLContext          : 44
TrustManager        : 71        CertificatePinner   : 134
CONTROLS: Socket 5,247 | Base64 64 | equals 982
```

**All of it lives under `ahmyth\AhMyth-Server\app\app\Factory\` and is `okhttp3` + `io.socket`
smali** — the decompiled transitive dependency closure of the socket.io client, which D3 §10.1
already excludes from the first-party denominator. Not one line is AhMyth's or AndroRAT's.

> **AhMyth and AndroRAT do not have a weak transport layer — they have no transport security layer at
> all.** There is no `TrustManager` to be misconfigured, no `HostnameVerifier` to be bypassed, no pin
> to be wrong.

**That is categorically different from Pupy**, where D11 found three endian conventions and an
unauthenticated handshake *beneath* `CERT_NONE` — Pupy has four crypto systems and misuses one.
**Android has zero.** The corpus axis is real and **Android is the floor of it, not an instance of
it.**

**This is the sixth instrument in the corpus whose zero needed its control, and the first where the
control was the only thing between a lane and shipping a wrong finding.** The probe was capable; the
*path filter* was the defect. Same shape as instance 3 (non-recursive glob reads a nested tree as
flat) and instance 5 (root-anchored `.gitignore` rules match nothing): **a scoping error presenting as
an absence, where the scope is the thing that silently failed.**

### 1.0.1 The denominator defect — the same failure at the third level, and it was found by asking

android-diver then turned the same probe on **its own delivered report**, and D3 §10.1 was wrong.
**Lead-verified independently this round:**

| ahmyth subtree | files | bytes |
|---|---:|---:|
| `AhMyth-Server\app\node_modules` | **7,911** | **124,076,770** |
| everything else | 526 | 21,241,085 |
| **total as published in D3 §10.1** | **8,437** | **145,317,855** |

**`node_modules` is 93.8% of the file count and 85.4% of the bytes** of the number D3 §10.1 presents
as the AhMyth denominator for a first-party/vendored split. **The real first-party client is
`AhMyth-Client`, 41 files / 139,112 B.** AndroRAT is affected differently: **2,479 of 4,008 files
(61.9%) / 27,388,229 B (50.4%) are decompiled `.smali`**, not AndroRAT's Java.

**So a report that names a split "first-party vs vendored" counted three separate vendored
dependency closures into its own denominator** — `node_modules` (7,911), `okhttp3`+`io.socket` smali
(385), and AndroRAT's smali (2,479). The §10.2/§10.3 first-party *counts* (12 Java / 19 Java) are
separately enumerated and hold; **it is the framing denominator and the §10.5 ratios resting on it
that were wrong.**

**This is the same failure as §1.0, one level up, and the progression is worth stating plainly:**

| level | what failed | what it looked like |
|---|---|---|
| 1 | **the probe**: a path filter excluded the tree | 16 clean zeros |
| 2 | **the attribution**: 385 smali files called vendored | correct, once asked where they lived |
| 3 | **the denominator**: 7,911 `node_modules` files counted as first-party-adjacent | **93.8% of a headline number** |

**At level 3 there was no probe to control and no zero to doubt.** The number was produced correctly,
by a working instrument, from the right tree — and it was the wrong number because **the boundary it
measured was drawn wrong.** A positive control on an extractor cannot catch this. **The only thing
that caught it was a lane asking whether its own split was complete.**

**Recorded here because it is the generalisable part:** the instrument rule (§6) covers tools that
return nothing. This covers **a tool that returns exactly the right answer to the wrong question**,
which is undetectable from the output and is why "enumerate your denominator" is a separate discipline
from "control your probe."

### 1.1 The Pupy finding worth carrying forward

`rsa_aes.py` is real crypto — RSA-4096 wrapping a fresh 32-byte AES-256 key at `:204`/`:207`. **Its
own docstring at `:12` calls it "a simple xor transport."** Copy-paste, never updated. A reader who
trusts the docstring over the code records the opposite of the truth.

And `ssl_rsa` sets `CERT_NONE` at `:23`, materialises a CA bundle at `:42`, and **hands it to a
wrapper that will not consult it** — then stacks `rsa_aes`'s unauthenticated handshake underneath.
That is a two-layer construction where each layer's weakness is masked by the other's *appearance* of
strength. D11_pupy §4 marks the sufficiency of the pre-auth decryption oracle `[inference]` because
it depends on the `rsa` library's internals, which are not in this corpus. **Correct posture.**

---

## 2. Wire format and dispatch, per framework

| target | framing | length prefix | integrity | dispatch | source |
|---|---|---|---|---|---|
| **Sliver** | protobuf envelope | protobuf | ChaCha20-Poly1305 tag | **135-entry message-ID table** | D1 §4, §6 |
| **Havoc** | custom | — | AES | **bidirectional handler; command ID parsed from operator GUI string** | D12 §2 |
| **Pupy (picocmd)** | `[CRC32 4B BE][cmd_id 1B][payload]` | **none between records** | **UNKEYED CRC32** | **29 positional IDs** | D6 §13 |
| **Mythic** | JSON / Go structs | — | — | per-container | D4 |
| **Merlin** | JSON module descriptors | — | **no hash or signature field exists** | — | D10 |
| **Metasploit** | TLV | TLV length field | — | 24 handlers | D7, D9 |
| **AndroRAT/AhMyth** | custom text/binary | — | none | — | D3 |

### 2.1 The single most important row in this table

**Havoc has no closed set of dispatchable commands.** `TaskPrepare(Command int, …)` at
`demons.go:128` is called from one place, and the command ID is **parsed from a string the operator's
GUI sent** — `strconv.Atoi(val.(string))` at `dispatch.go:168`, forwarded `:188` (D12 §2).

This means **a static "teamserver sends X, agent drops X" list is not well-defined in Havoc.** Not
unfound — undefined. Any integer the client can express reaches the agent. Compare Sliver's 135-entry
table and Pupy's 29 positional IDs: **three frameworks, three completely different answers to "what
can be dispatched," and Havoc's answer is "whatever the GUI types."**

### 2.2 The unguarded dispatch, Havoc agent side

`Command.c:114-123` — the handler lookup is a **struct array of 22 entries scanned linearly to a
`NULL` sentinel, with no `default` branch.** An unknown command runs to the sentinel, breaks,
returns. **No error emit, no log to the operator, no response packet** (D12 §6).

**Measured cross-reference (D12 §4):** agent handlers **22** | teamserver constants **36** (35
distinct values, one collision) | matched **22** | unmatched **13 values / 14 constants** |
agent-only **0**. The 14-vs-13 split is the `COMMAND_GET_JOB` / `COMMAND_INLINEEXECUTE_EXCEPTION`
collision at value `1` — see STATUS.md round 14 for why that number was misreported once.

### 2.3 The Pupy framing defect, and its amplification

Pupy's picocmd has **no length prefix between records** and a **CRC32 that is unkeyed** — D6 §13.2
verified at `picocmd.py:1780` that a `nonce` is accepted and never referenced. So the integrity check
is a plain checksum any party can recompute.

D11_pupy §6 found the amplification: **`kc4` is not a separate transport.** `kc4/conf.py:16-17`
reuses `EC4TransportClient`/`ServerBody` verbatim over UDP — **where a desynced length prefix is
strictly worse because UDP has no stream resynchronization.** The corpus's endianness census (74 call
sites across picocmd, ecm, ec4, rsa_aes) found **exactly one module using native byte order, and it is
a length prefix** (`ec4`). That single anomaly propagates into the UDP variant.

---

## 3. Evasion, per framework — and this is where they actually differ

| target | direct syscalls | syscall stubs | AMSI | module stomping | source |
|---|---|---|---|---|---|
| **Sliver** | **NO — verified seven ways** | none | **crude 1-byte `0xC3` patch** | none | D1 §7 |
| **Havoc** | **YES** — Hell's Gate + Halo's Gate | 4 `.asm`, 34 `SysNt*` wrappers | **broken on x86** | — | D5 §3, D11 §4 |
| **Pupy** | memfd on Linux only | — | **severed at preprocessor** | — | D6 §14 |
| **Covenant** | no | — | — | — | D2 |
| **Merlin** | no | — | — | — | D10 |

**Sliver's §7 is a negative finding verified seven independent ways.** No direct syscalls, no module
stomping, no `PssCaptureSnapshot`, and an AMSI bypass that writes a single `0xC3` byte over the
function prologue. It is the least sophisticated evasion layer of the two leading frameworks in this
corpus, and it is in the framework with the more disciplined crypto.

**Havoc has the sophisticated version and a broken instance of it.** §3.1 below.

### 3.1 Havoc's x86 degradation — four independent instances

D5 §3 documented four separate places where the 32-bit build loses a property the 64-bit build has.
The fourth is decisive:

**`asm/Syscall.x86.asm` uses `call` where the x64 version uses `jmp`.** An indirect syscall stub
exists to make the syscall instruction appear to originate inside `ntdll`. A `call` from the stub
returns to the stub — the return address points at Havoc's own code, which is exactly the artifact the
technique exists to avoid. **The x86 indirect syscall cannot preserve the property that makes indirect
syscalls useful.**

Corroborating: `asm/Spoof.x86.asm` is literally `_Spoof: ret`.

### 3.2 The CAPSTONE — armed and unreachable, at two layers

**`SYS_EXTRACT( NtSetEvent )` resolves at `Syscalls.c:75`** (Lead-re-verified four independent ways
after havoc-deep's own recheck introduced an off-by-one; D11 §8.5 records that **the verification pass
was the error, not the catch**).

Tree-wide measurements (Lead-verified):
```
SysNtSetEvent      : 0
NtCreateEvent      : 25   <- positive control, same file family
SysNtCreateEvent   : 5    <- positive control
distinct SysNt*    : 34 wrappers / 268 occurrences
```

**35 syscalls resolved, 34 fully wired, one not.** The SSN is extracted, the indirect-call address is
armed — and **no wrapper exists**, so `NtSetEvent` runs through a **direct import at `Win32.c:1296`**,
bypassing the indirect-syscall evasion entirely.

**Non-dead code: the capability runs and its evasion doesn't.**

### 3.3 The same shape one layer up — and it is NOT the same finding

D12 tested whether the dispatch layer mirrors the syscall layer. **It does not, and the reason is
structural.** `COMMAND_PS_IMPORT` = `0x1011` has zero references anywhere (control: neighbour
`COMMAND_PROC` = `0x1010`, dispatched at `demons.go:481` and `:3650`). But **nothing dispatches it, so
nothing is armed and no live target is at risk.**

> `NtSetEvent` armed an evasion and left it unreachable. `PS_IMPORT` arms nothing.
> **One severed link in the syscall layer, zero in the protocol layer.**

havoc-deep was explicitly invited to promote this into a symmetry and refused. **That refusal is the
reason the finding is trustworthy.**

---

## 4. The one axis where the frameworks genuinely disagree, and neither chose it

Sliver and Havoc made **opposite** choices on Windows evasion. The interesting part is **why**, and it
is not architectural intent in either case.

**Sliver:** the implant is a **Go binary, `CGO_ENABLED=0`, `GOOS=windows GOARCH=amd64`.** A pure-Go
Windows binary cannot easily emit hand-written syscall stubs — there is no assembler in the build,
and Go's own runtime makes the calling convention hostile to it. **The absence of direct syscalls is a
consequence of the language choice.** Sliver then writes the AMSI patch in Go, and a Go string write
gets one byte.

**Havoc:** the Demon agent is **C++**, so hand-written `.asm` is available and the team used it — four
files' worth. The x86 breakage is a consequence of **writing the 64-bit technique first and porting it
second**, which is visible in the file (`call` where `jmp` belongs).

**Neither framework decided to be sophisticated or unsophisticated at the evasion layer.** Sliver's
restraint and Havoc's effort both fall out of **what language the implant is written in.** The
evasion axis in this corpus is a proxy for the language axis.

That is the most transferable claim in this document, and it is a claim about *how to read a
capability comparison*, not about either framework.

---

## 4b. THE PATTERN THAT CONVERGED INDEPENDENTLY — three lanes, one finding, no coordination

This section did not exist in the first draft of D17. It was added because **three lanes working
separately, on three frameworks, with no knowledge of each other's results, arrived at the same
structural finding.** That is the strongest class of result this corpus can produce: not a claim one
lane made, but a claim three lanes *could not avoid making.*

| framework | primary capability path | gated? | **alternate path to the SAME capability** | gated? | source |
|---|---|---|---|---|---|
| **Sliver** | the 201-RPC gRPC operator API | **yes** — transport allowlist + interceptors | **`aitools` in-process executor** — `*rpc.Server` passed directly as `Backend` | **NO — no interceptor runs at all** | D12 §1 |
| **Covenant** | `POST api/listeners` | **yes** — `RequireJwtBearer` on 17/17 controllers | **`CovenantHub.CreateHttpListener`** on `/covenanthub`, mapped bare | **NO — zero attribute lines in the file** | D13 §4 |
| **Havoc** | indirect syscall stubs (`SysNt*`) | **yes** — 34 wrappers wired | **direct import of `NtSetEvent` at `Win32.c:1296`** | **NO — no `SysNtSetEvent` wrapper exists** | D11 §4 |

**The pattern:**

> **A security control holds on the primary path and lapses on the alternate path to the same
> capability.** The control is not wrong. **The alternate path was never in its scope.**

Three independent instances, three different mechanisms, three different frameworks:

- **Sliver** — the control is a **gRPC interceptor**, and the alternate path is a **direct Go method
  call**, which cannot pass an interceptor by construction of the middleware pattern.
- **Covenant** — the control is an **attribute on a controller**, and the alternate path is a
  **SignalR hub method**, which no controller attribute can reach.
- **Havoc** — the control is a **wrapper function**, and the alternate path is a **raw import**, which
  need not go through the wrapper.

**What makes this a finding rather than a coincidence.** In all three cases the *same operation* is
reachable two ways, and the gated way is the documented or obvious one. In all three, the alternate
path exists for a **legitimate, unrelated reason** — Sliver's for an LLM tool layer, Covenant's for a
SignalR hub, Havoc's because `Win32.c` is the plain-Win32 path and had no reason to know the syscall
layer existed.

**In none of the three was the alternate path created to bypass the control.** Each was created for
its own purpose and simply landed outside a fence drawn elsewhere. **That is why a code review looking
for bypasses would miss all three.**

### 4b.1 The Covenant instance, in detail, because it is the cleanest — and now service-level

Five of six SignalR hubs carry class-level `[Authorize]`. **`CovenantHub.cs` carries none** — zero
attribute lines in the file — and `Startup.cs:238` maps it bare at `/covenanthub` with no
`.RequireAuthorization()` (D13 §4).

**It exposes exactly one live method:** `CreateHttpListener` at `CovenantHub.cs:162-165`. That method
provisions a 2000-day Identity user, stores the JWT, and can bind a listener
(`CovenantService.cs:3953-3970`).

> **The same operation via `POST api/listeners` requires `RequireJwtBearer`. Via `/covenanthub` it
> does not.** Two channels, same capability, one gated.

**THE CONTROL LIVES IN EXACTLY ONE PLACE — service-level evidence, D13 §8.1.** covenant-diver
enumerated `CovenantService.cs` (255,768 B / 5,138 lines) for the full negative set and found
**zero** `[Authorize]`, `[AllowAnonymous]`, `RequireRole`, `HasPermission`, `HttpContext`,
`RequireJwtBearer`, `IAuthorizationService`, or policy literals. **All six token hits resolve to two
methods D13 already documents** — and `GetCurrentUser` (L446-454) was **read, not counted**: it does
`_userManager.GetUserAsync(principal)`, throws `ControllerNotFoundException` if null, and returns the
record. **No role test, no ownership test. It is a lookup, not a check.**

**Controls calibrated both directions:** `CovenantUserApiController.cs` = **8**, `Startup.cs` = **4**,
`CovenantService.cs` = **0**, `CovenantHub.cs` = **0** (independently re-confirming the
zero-attribute claim).

> **The service implementing all 183 operations contains no authorization decision of its own. The
> control lives entirely in the controller attributes — which is exactly why the hub path has nothing.
> There is no second layer to catch it. The alternate path lapsed because the control was only ever in
> one place, and the hub is not that place.**

**That sentence is the general mechanism for §4b**, not just this instance: Sliver's control lives in
the transport interceptor, so the in-process executor has nothing; Havoc's lives in the wrapper, so the
raw import has nothing. **In all three, the control existed in exactly one place and the alternate
path was never that place.**

### 4b.1a The REVERSE shape — and why it took a second detector to find

covenant-diver then ran the probe I asked for (enumerate commented-out `services.Add*` and
block-commented classes) and got a **clean negative**: `CovenantHub.cs` is the **only** file in the
entire Covenant tree with a multi-line block comment, detector calibrated against both known spans
before being run tree-wide. Three commented-out `services.Add*` lines at `Startup.cs:196-198`, all one
abandoned architecture, **two of the three naming types that do not exist** (`CovenantBlazorService`,
`SignalRCovenantService`) — tombstones for deleted classes.

**The fifth artifact appeared from a different detector**, which is the methodological point:

> **An enumeration is only as complete as the detector's shape.** The comment-detector could not see
> it, and no amount of calibrating that detector would have found it.

`Core/CovenantAPIService.cs` — 3,951 B / 95 lines — is **live in DI** at `Startup.cs:194`, the line
**immediately above** the three commented-out ones. It authenticates with
`configuration["ServiceUserToken"]`, implements **real certificate pinning**
(`cert.GetCertHashString() == covenantCert.GetCertHashString()`) — better built than
`CovenantHubService`'s `return true` stub — and **has zero consumers: three references total, all
declaration or registration, zero constructor injections, zero field refs, zero call sites.**

> **It is the REVERSE of §4b's shape.** `CovenantHub.CreateHttpListener` is **reachable but ungated**.
> `CovenantAPIService.CreateHttpListener` is **gated but unreachable**.

**Marked `[inference]`, deliberately not promoted — capability present, reachability absent.** D13 §8.3
tabulates all four paths to `CreateHttpListener`; **path 2 (the hub) is the only one of the four with no
gate.**

> **RULED OUT (round 16, D24 §3).** The open question this section left — *"whether Covenant's own client
> invokes `CovenantHub.CreateHttpListener`, which would make path 2 an actively-used unauthenticated
> route"* — **is answered NO, and the framing was wrong.** Lead-verified:
> `CreateListener.razor:23` injects **`CovenantAPIService`**, not `CovenantHubService`, and `:103` calls
> **`CovenantAPIService.CreateHttpListener`** over the HTTP path. **A third, *authenticated* route is the
> one in use.** Path 2 remains **live-but-uncalled** — present on disk, reachable in principle, not
> exercised by the shipped UI.
>
> **A distinction this forces, which the REVERSE-shape framing did not previously hold:** D13 §8.5 and
> this section both treated §4b.1a as a property of the *codebase*. **It is not — it is a property of
> the codebase plus its callers, and the callers changed the answer.** The reverse shape was
> **constructed** (the two `CreateHttpListener` entry points differ in gate) but the *reachability half
> of it was inferred from absence*, and D24 read the call sites and found the absent consumer.
> **"Gated but unreachable" survived; "reachable but ungated" lost its practical half.** The structural
> defect stands; the exploitation story does not.
>
> **Consequence for how §4b.1a should be cited: the reverse shape is a property of the artifact, and
> reachability is a property of the deployment.** Any future instance of this pattern needs **both**
> halves measured, not one measured and the other inferred from a grep that returned nothing.

### 4b.1c The hub is the only one of six without `[Authorize]` — measured against siblings

**D24 §6 supplies the in-corpus control this section was missing. Lead-verified, all six hub `.cs`
files enumerated:**

| hub file | `[Authorize]` | bytes |
|---|---:|---:|
| `CovenantHub.cs` | **0** | 36,205 |
| `CommandOutputHub.cs` | 1 | 487 |
| `EventHub.cs` | 1 | 503 |
| `GruntCommandHub.cs` | 1 | 486 |
| `GruntHub.cs` | 1 | 4,262 |
| `GruntTaskingHub.cs` | 1 | 486 |

**Five of six carry the attribute; `CovenantHub` does not** — and it is the one whittled from 223 public
methods down to exactly one live method, and that method is `CreateHttpListener`. **The control is what
makes this a finding rather than an observation:** the annotation is present in the same tree, on the
sibling types, written by the same authoring convention. **This is absent-by-omission, not
absent-by-convention.**

**And the compensating setting is unconfigured:** `FallbackPolicy` → **0 occurrences**, while
`DefaultPolicy` is set. That distinction matters and is easy to invert: **a default policy governs
`[Authorize]`-without-arguments, not unannotated endpoints.** So the one setting that could have caught
an unannotated hub is the one that is unset. `[source: D24 §6; `[inference]` — no server was run and no
unauthenticated request was observed]`

### 4b.1d The certificate control that returns `true`

**Also D24, and it is the same shape one layer down.** `CovenantHubService.cs:27` loads the certificate —
and **`:32` is literally `return true;`**. The certificate is **loaded and never compared**. Lead-verified
from source; the decisive control is that **`:42` and `InternalListener.cs:125` are the same line of
code** — one propagating a real hash comparison, the other propagating `true`.

**Five callback sites exist in the server tree; four compare, this one does not.** And `:42` propagates it
into the SignalR connection while `:38` sets `AccessTokenProvider` to `ServiceUserToken` — so **the client
authenticates itself to the server and never authenticates the server to itself.**

> **This is §4b's shape expressed as a *value* rather than a *path*: the control exists at four of five
> sites and is replaced by a constant at the fifth.** The fourth instance of the alternate-path lapse, and
> the only one where the alternate path is a **one-token edit** rather than a structurally different
> route.

### 4c The fourth disappearance: the transport decision is in a gem that is not in the tree

**This is a grader's finding, not a defect in a target, and it belongs in the synthesis because it
changes what "reversing Metasploit's transport layer" can mean.**

D9 read `lib/rex/proto/` and reported the protocol layer. **D22 §4 established that `lib/rex/proto/` does
not decide transport at all — and could not have, because the deciding code is not in the checkout.**
Lead-verified from disk:

**`01_SOURCE_c2\metasploit\lib\rex\socket.rb` DOES NOT EXIST.** The `lib\rex\` directory has no `socket.rb`
and no `socket\` subdirectory. **Rex was externalized into gems, and the Metasploit source tree is not
self-contained for transport.**

The decision lives in **`04_TOOLS\gems\rex-socket-0.1.71\src\lib\rex\`, and it is one line:**

```
socket.rb:44-46   def self.create(opts = {})
                    return create_param(Rex::Socket::Parameters.from_hash(opts))
socket.rb:51-53   def self.create_param(param)
                    return param.comm.create(param)        <- THE ONLY DISPATCH
comm.rb:48-50     def self.create(param)
                    raise NotImplementedError               <- base REFUSES to decide
```

- **`proxies.rb` is 1,518 B and parses only** — exactly five types at `:7-11` (`sapni`, `http`, `socks4`,
  `socks5`, `socks5h`). It never connects. **A comma-separated chain is parsed and handed on.**
- **`parameters.rb` (13,250 B) parses the decision inputs** — `'SSL'`:116, `'SSLVersion'`:128,
  `'Proxies'`:175-176, `'Proto'`:180-181, `'Comm'`:188 — and **passes all four through**.
- **Proof it is pass-through, from the other direction:** `http/client.rb:165-191` takes
  `ssl`/`ssl_version`/`proxies`/`comm` as constructor parameters and forwards all four to
  `Rex::Socket::Tcp.create`. **The protocol knows HTTP; the socket layer knows transport.**
- **Verified across all 302 protocol files: 27 call `Rex::Socket`, ZERO decide locally.**

> **THE SHAPE: five socket files (~78 KB) answer the question that 302 protocol files appear to be needed
> for.** D9 measured the right tree for the question it was asked and the question was the wrong one —
> **the boundary was drawn at `lib/rex/proto/` because that is where the files are, not because that is
> where the decision is.**

**And the gem inventory is the second half: `rex-socket` IS unpacked, but the other twelve `rex-*` gems
are ABSENT — none vendored.** Lead-verified: `04_TOOLS\gems\` holds **six** unpacked trees
(`rex-arch`, `rex-core`, `rex-encoder`, `rex-powershell`, `rex-socket`, `rex-text`). **`rex-exploitation`
— D22's measured rank-1 gap at 13 call sites (cmd_stager, egghunter, jsobfu, omelet, rop_db, seh,
vbsobfuscate, browser/http exploit servers) — is not among them.**

**Consequence for this corpus's coverage claims:** any statement of the form *"Metasploit's transport /
TLS / proxy handling was reversed"* is **false as a statement about the checkout**, not because the work
was skipped but because **the code is not there.** The honest form is: **the *dispatcher* was reversed
(`rex-socket`, one line), the *decision inputs* were reversed (`parameters.rb`), and the *deciders*
(`ssl.rb`, `ssl_tcp.rb`, `comm/local.rb`) are now reversed — D26 read `comm/local.rb` in full.** Twelve
gems remain outside the tree entirely.

> **~~`comm/local.rb` at 23,093 B unexamined~~ — CLOSED by D26.** The gap this section named as its
> largest single hole is now read, and **the answer went against this section's own prediction.**
>
> **D26 was pre-authorized for three outcomes, and predicted the third — "the consumer is not in the
> corpus." It was branch one.** `Local` **does** consult `param.proxies` and **does** walk the chain:
> `:350-352` rewrites the connect target to `proxies.first` so `peerhost` is never resolved directly;
> `:418-424` walks with `each_cons(2)` — proxy→proxy for intermediate hops, last-proxy→target at the
> end, **real multi-hop, not one CONNECT**; `:439-567` implements **all five** declared types
> (SAPNI `:441`, HTTP `:510`, SOCKS4 `:534`, SOCKS5 `:550`, SOCKS5H `:567`, plus `proxy_socks4a` `:594`
> and `proxy_socks5h` `:615`). Lead-verified on disk.
>
> **`proxies.rb` is not an orphan and the gem gap is not a confound for this question.** Enumeration two
> independent ways: **5 files include `Rex::Socket::Comm`, exactly 1 defines `self.create` — `local.rb`.**
> The other four are listener/observer mixins hooking `notify_before_socket_create` /
> `notify_socket_created`; none defines `create`. **The proxy walk needs no second `Comm`; it lives
> inside `Local`.** D22 §4.4's speculation that an absent gem might hold a proxy-walking `Comm` is
> retired. **The citation is now earned.**
>
> **A pre-authorization that goes unused is itself data.** This section armed a prediction with a
> section number and a vocabulary for the answer it expected. **The corpus gave the opposite answer, and
> the correct form of the record is to say so in the section that made the prediction.** An armistice
> with one's own hypothesis is not a result; **reporting that the hypothesis lost is.**

> **§4c's shape DID appear — one layer over from where this section aimed it.**
> `local.rb:161-168` is a fail-fast guard whose comment refers to *"the proxy comm"* as **a distinct
> object that handles its own socket creation** — and **no such class exists anywhere in the corpus.**
> **The corpus contains evidence of a design component that is absent from the corpus.** Two readings,
> neither chosen, both `[inferred]`, recorded open at D26 §6/U3: **(A)** the comment is stale —
> proxying was once delegated to a separate comm, later folded into `Local`; better supported, since
> `Local` demonstrably does the work the comment attributes elsewhere. **(B)** the comment anticipates
> an out-of-corpus comm; better supported by present tense and by the fact that the guard only makes
> sense if such a comm could silently ignore `interface`.
>
> **That is genuinely unsettleable from source, and it is the §4c shape in its purest form: the
> evidence of an absence is itself *inside* the corpus.** Not "the artifact is not here" but **"the
> artifact here refers to something that is not here."** That is a fifth species, and unlike the fourth
> it cannot be closed by acquiring the missing file — **because the missing thing is a class, and the
> corpus proves it once existed.**

> **And the transport layer fails CLOSED.** The same guard at `:165-167` raises `Rex::BindFailed` with
> reason *"Interface option is incompatible with proxy use"* — **refused loudly with reason text,
> explicitly *"rather than silently binding to the wrong interface."*** Every proxy branch raises
> `Rex::ConnectionProxyError` with host/port/type and a specific message (`"blocked by ACL"`,
> `"returned a non-OK response"`, `"SOCKS4 target host must be an IPv4 address or a hostname"`).
> **This is the opposite of the bare-rescue swallow pattern D9 §17 recorded for `lib/msf/core/`: the
> same toolkit fails loudly at the transport layer and silently at the session layer.**

**Load-bearing ordering fact, new from D26: TLS is applied AFTER the proxy walk** (`:426-430`,
*"Now extend the socket with SSL and perform the handshake"*). **Proxy negotiation completes first,
then TLS wraps the resulting tunnel end-to-end** — which is why C2-over-HTTPS-through-SOCKS5 works: the
TLS session is established *through* the tunnel to the real target, so **the proxy never sees
plaintext.** `[source: D26 §5]`

> **This is a third species of the denominator defect.** §1.0.1 gives three levels: the probe, the
> attribution, the boundary. **This is a fourth: the artifact is not in the corpus.** A lane can be
> perfectly instrumented, correctly scoped, and still unable to answer — **because the answer was
> elsewhere the whole time and no count of the tree could ever have revealed that.**

### 4b.1b One abandoned topology, not five incidents

**This revises D13 §4.4, and the revision is covenant-diver's own, on its own earlier conclusion.**
`CovenantHubService` is literally `IRemoteCovenantService` — the **remote** implementation of the
operator service, the local one being `CovenantService`. **The hub was the server half of a deliberate
two-process split** (Blazor front end → SignalR proxy → service) that was abandoned and dismantled
**asymmetrically**: hub methods block-commented but the class left mapped with one method live; the
proxy disabled at DI but left in the tree.

> **`CovenantHub` is the surviving half of an abandoned architecture, and the one method left live in
> it is a listener-creation entry point the abandonment never gated.** The live/comment boundary at
> `L161/162` is the exact line where the author stopped commenting.

**That is a better result than "unprotected hub," and it is why the counting exercise was worth
running.** A report that stopped at "the hub has no `[Authorize]`" would have been correct and would
have described a *mistake*. **What is actually there is the remains of a design.**

### 4b.2 What does NOT generalize, stated so it is not over-claimed

**This pattern is not "these frameworks skip authorization."** Covenant enforces it on **all 183
AutoRest operations across 17 of 17 controllers** with zero state-changing endpoints unannotated
(D13 §2). Sliver enforces it across its entire RPC surface. Havoc wires 34 of 35 syscalls correctly.

The claim is narrower and more useful: **enforcement is comprehensive on the path it was designed
for, and the alternate path to the same capability was never in its scope.** A comparison that
reported "Covenant gates its API" or "Sliver gates its RPC" would be *correct and would miss this
entirely.*

---

## 5. Persistence, process manipulation, and privilege

| capability | Sliver | Havoc | Pupy | source |
|---|---|---|---|---|
| persistence mechanism | service layer, `service_windows.go` (257 lines) | — | **missing entirely** | D1 §14, D6 §14 |
| PPID spoofing | — | — | **REAL** (`create_new_process_from_ppid` `:2692`) | D6 U-5 |
| token impersonation | priv/ (22 KB) `[now task-27]` | Token.c (45.1 KB) | **works** — `getsystem()` `:2015` → `create_proc_as_sid` → `impersonate_token` | D6 U-5 |
| process injection | — | own inject/ | `MemoryModule.c` (1,641 lines) | D5, D6 |
| screenshots | screen/ | — | **`vidcap.pyd` ×2 — prebuilt binary** | task-26 |

**Lead-verified negatives in Pupy (grep returns 0, with controls):** `lsass`,
`MiniDumpWriteDump`, `ReadProcessMemory`, `Samr`. **Pupy does not do credential dumping.** That is a
real absence and it is the cleanest one in the corpus — the framework has the token machinery to do
it and does not.

### 5.1 Pupy's severance pattern — the corpus's cleanest structural finding

Seven features, eight mechanisms, all severed by something **outside** the feature's own code:

1. persistence — **the file is missing**
2. JVM module — commented out, severed at three levels
3. Android — placeholder (`client/android_sources/pp.py`, 138 B)
4. **ETW suppression — severed at the PREPROCESSOR.** `_PUPY_PRIVATE_WS2_32` is defined **nowhere**
   (8 `#ifdef`, 0 `#define`). **Control: `_PUPY_PRIVATE_NT` IS defined at `Makefile:87`.** The
   pattern is real and one instance is live.
5. crash-artefact generator — severed by an unset build variable
6. `actctx.h:35` declares `void _MyLoadActCtxPointers();` — tree-wide grep returns **exactly one
   match**, the declaration
7. Linux-only `FEATURE_INJECTOR` — **`L73: FEATURE_INJECTOR :=`** (empty), gated at `L145`

**The control that works is `FEATURE_PATHMAP`, live at `Makefile:119-129`.** Without it, "seven
severed features" would be an untestable claim about a codebase that might just be broken.

### 5.2 The one live crash defect, and it is mutual-exclusion

`MyLoadLibrary.c:761-787` — `MySetUnhandledExceptionFilter`: `:772-777` logs and **falls through**,
then `lib->ehFilter = handler;` at `:779` **with `lib == NULL`**. D6 §24.6.

And the framework's own safety net has a mutual exclusion: **minidump is `#ifdef DEBUG` (`:863-872`);
header decommit is `#ifndef DEBUG`.** Release build decommits the PE headers and produces no minidump.
Debug build retains headers and can dump. **You cannot have both**, and release is the shipping
configuration. `FEATURE_POSTMORTEM` appears **exactly twice repo-wide, both commented out.**

---

## 6. Integrity of the analysis layer itself

Every framework above is software that trusts its own inputs. This corpus is also software, and it
had the same class of problem. **Five independent measuring instruments failed during this work and
the failures are recorded per-lane rather than hidden.** The full ledger is in `STATUS.md` rounds 13
and 14. The shape:

> **An instrument that returns nothing or nearly-nothing is more suspicious than one that returns
> something wrong. Absence is the one result you cannot distinguish from a dead tool by looking at
> it. A wrong number at least came from a live process; a zero might have come from nowhere.**

And the figure-level variant, from D12 §9:

> **A number that arrived by a route other than the one it appears to have arrived by.**

Both are worth carrying into any future comparison, because **a capability comparison is exactly the
kind of artifact where a clean zero is most likely to be believed.** "Framework X has no feature Y" is
a legitimate finding and it is indistinguishable, on the page, from a probe that never ran.

---

## 6.5 A duplicated-defect pattern, found by checking the smallest claim first

> **FRAMING CORRECTED (round 16, by covenant-diver's D20). Two errors in this section as first written.**
>
> **1. MYTHIC IS POSTGRESQL, NOT MySQL.** This section invited "a MySQL question." **Measured:**
> `sqlx.Connect("postgres", …)` at `database/initialize.go:169`; `migrate.ExecVersion(DB.DB, "postgres", …)`
> at `:128`; schema ends `-- PostgreSQL database dump complete` (`schema.go:4851`); config keys
> `postgres_host` / `postgres_sslmode`, default port 5432. **Lead-verified.**
> **This invalidated an entire defect class before it was published:** **231 sites** of
> `::text` (113), `RETURNING` (73), `ILIKE` (35), `ON CONFLICT` (9) are **all valid PostgreSQL, zero
> defects.** Read as MySQL, those would have been the headline finding. **The control caught the lane
> hunting a bug that does not exist — and it would have been a large, plausible, wrong finding.** This
> is the instrument rule applied to *dialect assumptions* rather than to probes.
>
> **2. THERE ARE FIVE CORRECT SIBLINGS, NOT FOUR.** The fifth is
> `webserver/controllers/user_delete_apitoken_webhook.go:78` — `SET deleted=:deleted, active=:active`
> (named-parameter form). **The trigger I wrote searched for the positional comma form and structurally
> could not find it.** covenant-diver found it by switching from *pattern-first* to **population-first**:
> enumerate all **15** `UPDATE apitokens` sites, then classify. **2-state subset = 6 malformed / 5
> correct.** Lead-verified at `:78`.
>
> **The generalization this section asked for did NOT replicate, and that is a negative result worth
> stating:** Covenant (EF Core LINQ) has **0** raw SQL `SET` sites; Havoc's GORM query builder composes
> `SET` programmatically and **cannot emit `AND`**; Pupy 0; PHP absent; Metasploit uses ActiveRecord.
> **The class is possible in exactly ONE framework, in ONE subsystem (`src/rabbitmq/`), on ONE table
> (`apitokens`).** See D20 §5.

**This is not a framework difference — it is a defect class that spans the corpus, and it reached six
files in one directory.** Placed here rather than in §2 because it is an artifact of *how the code was
written and copied*, not of any framework's protocol design.

`recv_pt_task_opsec_post_response.go:46` contains:

```sql
UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1
```

**`SET a=true AND b=false` is not two assignments.** SQL requires a comma between assignments, so this
parses as `deleted = (true AND active=false)` — **`active` is never set.** The correct form is
`SET deleted=true, active=false`.

**android-diver wrote it up as an isolated typo in one file, then ran one `Select-String` across the
directory. It is six files. Lead-verified:**

| file | line |
|---|---|
| `recv_pt_task_opsec_post_response.go` | 46 |
| `recv_pt_task_opsec_pre_response.go` | 41 |
| `recv_pt_task_create_response.go` | 46 |
| `recv_pt_task_process_response.go` | 27 |
| `recv_pt_payload_build_response.go` | 92 |
| `utils.go` | 796 |

> **RETRACTED (round 16, by android-diver's D25). A key mismatch was flagged here as a possible
> copy-paste slip: `payload_build_response.go:92` filters on `WHERE payload_id=$1` while the other five
> use `task_id=$1`. THAT IS NOT A DEFECT AND THIS REPORT NO LONGER CARRIES IT.**
>
> **`apitokens` carries BOTH keys as independent foreign keys** — Lead-verified in
> `003003000_3.3.0.sql`: `payload_id integer` at **`:153`**, `task_id integer` at **`:155`**, with
> separate constraints `apitokens_payload_id_fkey` (`:299`) and `apitokens_task_id_fkey` (`:304`)
> referencing **different tables**. The handler at `:92` is **payload-scoped end to end** — it selects
> `FROM payload`, updates `filemeta` and `payload`, and emits `TriggerPayloadBuildFinish` carrying
> `PayloadID`. **`payload_id` is the consistent key for that file.**
>
> **So the six sites are one statement in one family with a correctly-varying WHERE key.** Reporting the
> mismatch as drift would have been a **false finding** — a defect added to the corpus by pattern-matching
> on form without checking the schema. **The defect is the `SET` clause and the swallowed error, nothing
> else.** android-diver wrote the verdict as a *removal*, which is why it is recorded as one.

**And the correct form is in use in FIVE sibling files for the identical statement — `eventing.go:747`
and `:1595`, `check_container_status.go:219`, `initialize.go:177`** all write
`SET deleted=true, active=false`, and **`webserver/controllers/user_delete_apitoken_webhook.go:78`**
writes the named-parameter form `SET deleted=:deleted, active=:active`. Note `eventing.go:747` is
**twelve lines** from the class of code that gets this right.

> **So the finding is not "someone didn't know SQL." It is a wrong idiom duplicated while the right one
> sits in a neighbouring file.** That is a *searchable pattern*, not a line to patch — and had it
> shipped as isolated, the corpus would carry a one-file defect where a six-file pattern exists.

**CLASSIFICATION: COPY-DRIFT, on four independent evidence lines (D20 §4):**

1. **All six share the VERBATIM error string** `"Failed to update the apitokens to set to deleted"`. A
   corpus-wide search for that exact string returns **exactly 6**, one per malformed site, **1:1**. The
   five correct sites use different, better messages (`"Failed to mark apitoken as deleted"`).
2. **5 of 6 statements are byte-identical** (`WHERE task_id=$1`); the sixth is the same block adapted to
   `payload_id=$1`.
3. **The ratio is 39:6 corpus-wide** for multi-assignment `SET` — the correct form is the codebase norm
   **6.5× over**, with five correct siblings in the **same subsystem**.
4. **A second, CORRECT copied lineage exists** — `eventing.go:747` and `:1595` are textually identical
   **including the trailing space** after `active=false`. **Copying is the normal authoring behaviour
   here, and it produced one correct lineage and one corrupted one.**

> **The defect is a copy operation applied to a snippet that was already wrong — not a knowledge gap.
> All six satisfy the copy-drift criterion; none satisfies the ignorance criterion.**

**Verification status, stated precisely:** the six sites and the five correct-form controls are
**verified**. Whether **PostgreSQL accepts the malformed `SET deleted=true AND active=false` or errors**
is **NOT verified** — no database was started, no statement parsed or executed. **That distinction
decides the impact: if it errors, the token is never invalidated; if it is accepted, `active` silently
keeps its old value.** Both are worse than intended, and they are not the same defect. Recorded as an
open unknown, not asserted.

**But one fact stands on source alone, independent of the database answer:** all six sites
**log-and-continue** — `if err != nil { logging.LogError(...) }` with **no return, no counter, no caller
notice**. **So the failure is SILENT under either branch.** That is precisely why closing the dialect
question matters: the error path swallows whatever the answer turns out to be. `[source: D20 §6.1]`

**The log strings are byte-identical across all six — hash-verified, not eyeballed:** sha16
`55E9F2DE880D7F8C`, including `utils.go`, which was previously only *string-matched*. The set is
therefore **five read for logic + one confirmed identical by hash** — stated precisely rather than
claimed as six reads. `[source: D25 §1]`

**The contrast case that makes the template claim airtight:** `opsec_pre_response.go:65-77` —
**same author, same package, same handler shape — DOES return on its write failure.** The template had a
correct form available in its own file. `[source: D25 §3]`

---

### 6.5.1 A second, independent defect: the shared-`err` overwrite

**Found by android-diver while reading the same four siblings (D25 §4). It is NOT part of the copied
template — same authoring habit, different mechanism — so it gets its own line rather than folding
into §6.5.**

`recv_pt_task_create_response.go:187-199`:

```go
187:  _, err = database.DB.NamedExec(`UPDATE task SET status=:status, stderr=:stderr, completed=:completed ...`)
191:  _, err = database.DB.Exec(`INSERT INTO response (task_id, operation_id, response) VALUES ($1,$2,$3)`, ...)
193:  if err != nil { logging.LogError(err, "failed to add error to responses") }
196:  if err != nil { logging.LogError(err, "Failed to update task status"); return }
```

**Two consecutive writes assign the same `err`; `:191` overwrites `:187` before either `if` inspects
it.** Three consequences:

1. **The `UPDATE task` error is discarded entirely** — if the status write fails, nothing reports it.
2. **`:196`'s message is wrong** — it says *"Failed to update task status"* but prints the error from
   the `INSERT INTO response` at `:191`.
3. **The task can be left with `Completed=false` and a stale status *after* `TriggerTaskFinish` was
   already emitted with `ActionSuccess: false` at `:200`** — the finish signal fires on state the
   handler failed to write.

**Reachability: `:184-199` is the only one of the four siblings where the swallowed-`SET` error is
compounded by a second swallowed write on the same path.** `[source: D25 §4]`

> **This is the class D17 §1.0.1 predicts but does not itself catch.** The first defect was found by
> asking *"is this SQL right?"* The second was found by reading the **error path** of code that had
> already been classified and closed. **A pattern search finds the pattern it was built for; it does not
> find the second defect sitting six lines away in the same function.**

**This is §1.0.1's pattern again, one layer over: the first measurement was correct and the scope was
wrong.** android-diver's own words: *"had I written it up as isolated, the corpus would carry a one-file
defect where a six-file pattern exists."*

### 6.5.1 The refinement android-diver made to the denominator rule, and it is better than mine

I wrote §1.0.1's rule as **"enumerate your denominator."** android-diver's correction, from having
actually run it:

> **"Enumerate your denominator" isn't the rule that would have caught me. I did enumerate it —
> correctly, from disk. What was wrong was the BOUNDARY of the set I chose to enumerate: I enumerated
> under a path that contained dependencies. The rule that catches this is "justify the boundary, not
> the count" — state why each subtree is IN scope before totalling.**

**Accepted, and it supersedes my phrasing.** A correct count of a wrongly-bounded set is still wrong,
and the count will look healthy. **The denominator is a boundary decision; the enumeration is just
arithmetic performed inside it.** Stating the exclusion classes *with sizes* — which is what the
corrected D3 §10.1 does — makes the boundary auditable in a way a total never is.

## 7. What REDACTED gains at the composition layer

REDACTED is a Python orchestrator plus LLM: MCTS over a 65-action world model, parallel swarms
sharing a Living Graph, an adversarial verification lane, 141 GRIMOIRE techniques across 12 domains,
142 learned plays, AES-GCM entitlement gating, and Ed25519 offline license verification.

Read against the six frameworks above, the composition layer is not a bigger C2. **It is a different
kind of object, and the six frameworks do not contain the thing it is made of.**

**What REDACTED would have to build from scratch, because no target in this corpus has it:**

1. **Search over action sequences.** Every framework here is a **dispatch table**: Sliver has 135
   message IDs, Pupy has 29 positional IDs, Havoc parses an integer from a GUI. **A dispatch table
   is a menu, not a planner.** Not one framework in this corpus contains a search procedure, a
   heuristic evaluator, or a rollout. MCTS over a world model has no counterpart here.
2. **A world model.** Each framework models the *wire*, not the *host*. Sliver's `handlers/` (332 KB)
   implements operations; nothing predicts what an operation will do to a target's state.
3. **Adversarial verification as a first-class lane.** The closest analogues in the corpus are
   Havoc's `Syscalls.c` resolving an SSN it cannot use, Sliver's `c2/http.go:209-212` unguarded map
   write, and Pupy's `MySetUnhandledExceptionFilter` falling through with `lib == NULL` — **all three
   are defects a verification lane would have caught, and not one framework here has one.** The
   evidence is direct: every instance in §4b was found by an *external* reviewer reading the code
   against a second path. **No framework in this corpus contains any mechanism that would have found
   its own §4b instance.**
4. **Learning across engagements.** `142 learned plays` implies state that persists and updates. **No
   framework here persists anything between operations except loot and credentials.** D1 §23.3 found
   Sliver's outbound replay cache is a pure unbounded `sync.Map` memory leak with *zero* replay
   protection — a framework that cannot even remember a nonce across a restart is not remembering a
   play.

**What REDACTED legitimately inherits from this corpus — the mechanisms, not the architecture:**

| layer | take | from |
|---|---|---|
| transport crypto | X25519 + ChaCha20-Poly1305 with a verified signed server→implant path | D1 §1/§4/§23 |
| wire integrity | **a KEYED MAC, not a CRC32** — Pupy's unkeyed CRC at `picocmd.py:1780` is the anti-pattern | D6 §13.2 |
| framing | **explicit length prefix, and consistent byte order** — Pupy's single native-order offender propagating into UDP is the anti-pattern | D11_pupy §6 |
| evasion | pick the technique that matches the implementation language, and **verify the stub actually emits what it claims** — both Sliver and Havoc got this wrong in opposite directions | D1 §7, D5 §3 |
| dispatch | **closed enumerated set with a `default` branch that errors** — Havoc's sentinel-scan with no `default` is silent failure by construction | D12 §6 |
| privilege | Pupy's token chain is real and small: `getsystem()` → `create_proc_as_sid` → `impersonate_token` → `CreateProcessAsUser` | D6 U-5 |
| capability surface | **replay cache with bounded growth** — Sliver gets concurrency right and growth wrong; the encoder map at `c2/http.go:209-212` gets both wrong | D1 §23.3, §21.2 |

**The honest composition-layer conclusion.** Every mechanism in this corpus is available to
REDACTED by reading these reports, and none of the architecture is. The frameworks here are
**toolkits**; REDACTED's claim is to be a **decision-maker**. The gap between those two is not
something this corpus can close, and nothing in the 1.8 MB of analysis above narrows it — which is
itself the useful result: **the six most capable open C2 frameworks in existence contain no
planning, no prediction, and no learning, and their absence is measurable rather than asserted.**

---

## 8. Residual unknowns in this synthesis

Stated rather than smoothed:

1. **D1 has no capability section.** `implant/sliver/handlers/` (44 `.go`, 332 KB) is unread — now
   task-27. Rows in §5 for Sliver are therefore **structure-inferred, not capability-measured.**
2. **Pupy's DNS C2 tables are unread** — task-28. §2.3 covers the Parcel framing and not the DNS
   encoding. `dns_encoder_table.py` (22,473 B) is an uncharacterised 22 KB.
3. **Covenant's control plane is DELIVERED** (D13, 79,666 B, task-25 complete). But covenant-diver
   states the boundary plainly: **`CovenantService.cs` (255,768 B) was read at ~5%, auth-critical
   regions only.** A permission check implemented inside a service method with no controller
   attribute **would be invisible to D13.** `CovenantAPIExtensions.cs` (212 KB),
   `ICovenantAPI.cs` (93 KB), and `CovenantHubService.cs` (47 KB) were **not read at all.** §4b.1's
   Covenant instance rests on an attribute-level scan, which is the right level for that finding but
   is not a full read of the service layer.
4. **Mythic's `recv_pt_task_opsec_post_response.go` — RETIRED, read in full. CORRECTED, and this
   claim was originally false here.** The first draft of this document stated the file "is in no
   report." **That was wrong — a false claim about the corpus's own coverage.** It **is** cited at
   `T4_mythic.md:559`, as the `PT_TASK_OPSEC_POST_CHECK` consumer. The accurate statement was
   narrower: T4 **named it once, as a `[source:]` citation for a queue name** — a *naming*, not a
   *reading*.
   **android-diver has since read all 187 / 187 lines. Full note at `D18_mythic_opsec_post_response.md`.**
   Three findings, and the first is a corpus pattern promoted to §6.5:
   - **The malformed `SET deleted=true AND active=false` is in SIX files, not one**, with the correct
     comma form in use in four sibling files (§6.5, Lead-verified).
   - **`checkForTaskInterception` (`:162-187`) runs OUTSIDE the OPSEC gate and can reverse a
     `SUBMITTED` verdict** — an operator event group can stop a task the gate already approved, so
     **the gate is not the final authority on execution.**
   - **`:87`'s script-only path makes the `addTaskById` at `:132` unreachable for that class.**
   **Error class, recorded because it recurs: a claim about what the corpus knows about itself, made
   without checking the corpus.** Same shape as the retracted citation-count pattern — **the failure is
   not in the target, it is in the index.**
5. **Metasploit's 2,715 exploit modules are counted, not enumerated** (D9). Every MSF row above is
   from the core library and the handler layer, not from the exploit side.
6. **Android's transport is covered in D3** (§1.0 above); the 146 unread lines of
   `tcpConnection.java` are **command handlers** (`getSMS`, `getLocation`, `startAudio`,
   `getCallLogs`, `getMACAddress`), which is capability inventory rather than transport.
   **Enumerated and declined deliberately by the D3 lane**, not overlooked.
7. **No framework was executed.** Every row is static. §3's evasion rows in particular describe what
   the code emits, not what a defender's sensor would see.
8. **`D11` is used five times as a document number** (`D11_havoc_native_win32`, `D11_merlin_binaries`,
   `D11_mythic_crypto_postresponse`, `D11_pupy_transport_crypto`, `D11_sliver_rpc_core`). Cross-file
   `D11 §n` references are **ambiguous without the filename**, and task-22's CROSSREF_AUDIT recorded
   this as failure mode C. **Any citation to `D11` in this document names the file.**

## 9. Document-numbering collision, recorded because this report cites across the whole corpus

Task-22 (CROSSREF_AUDIT, closed) measured 1,648 edges: **1,626 OK / 16 PARENT-OK-SUB-MISSING /
6 DANGLING**. Four failure modes; two bear on reading *this* document:

- **Mode B — a reference written against an intended structure that later moved. 16 instances, 2.7×
  the hard dangles, and it FAILS SILENTLY because the parent section always resolves.** A reader
  following `D5 §12` gets a real section that is not the one meant, and nothing errors.
- **Mode C — a doc number covering multiple files.** `D11` is five files. `D3`'s bare `§3.7` means
  `D8`'s. `§23.3` was claimed by both D1 and D6; `D3`'s bare `§23.3` means `D6`'s.

**Resolution order used throughout D17: the nearest preceding proper noun or backticked token wins,
before falling back to the containing file.** Where this document cites `D11 §n`, the filename is
given. Where it cites `§n` bare inside a target's row, it means that target's own report.

---

## 10. What an encoder is FOR, read off three frameworks — and the one that does not encode content

**Three targets in this corpus carry an encoder, and each was built against a different threat model.**
They look similar in a file listing and are not similar in purpose.

### 10.1 Pupy's DNS codec is a WORD codec wearing a character codec's clothes

**This corrects a premise in the D16 brief, which described `dns_encoder_table.py` as a character-level
compression table.** Lead-verified from source:

- **`dns_encoder_table.py` is 8 lines / 22,473 bytes** — one single `dict` literal named `TREES`.
- It holds **five** codebooks, not one, and **two are deliberate empty stubs**: `cdns` and `freedns` are
  1-entry, 0-bit, single-NUL. `generic` (39 entries) is exactly `DNS_ALPHABET`. `tlds` and `terms` are
  each **513 entries** — 2⁹+1, the node count of a full Huffman tree over 512 symbols.
- **`:194` is `if phrase.startswith(term):` — the matcher works on WHOLE MULTI-CHARACTER TERMS**, sorted
  longest-match-first at `:135`/`:168`. This is not character-level.
- **And the vocabulary is the finding.** The `terms` symbols are real internet words: `cloud`, `cdn2`,
  `webdav`, `nextcloud`, `payment`, `member`, `temp`, `correo`, `cloudfunctions`.

> **The codec is a domain-vocabulary word codec, statistically shaped to look like cloud / CDN / payment
> DNS traffic.** Compression ratio is not the only design goal; **the symbol distribution is a cover
> story.** A DNS sensor sees words it expects to see in a corporate network, because those are the
> words the codebook was built from.

**The largest single win is a 256-entry provider list** (`dns_encoder.py:16-70`): `chickenkiller.com`,
`mooo.com`, `ignorelist.com`, `h4ck.me`, `privatedns.org`, `dyn.mk` — **exactly 256 entries, zero
duplicates, every one conforming to `DNS_ALPHABET`.** `chr(idx)` costs **8 bits regardless of domain
length**, so `chickenkiller.com` (17 characters) collapses to **one byte**. **The list is exactly 256
because the index is a byte** — the size is a boundary artifact of the encoding, not a catalog.

**Two more, both Lead-verified:**

- **A documentation defect: code right, comment wrong.** `dns_encoder.py:351` comments
  *"3 bits - AMOUNT OF PARTS"*; the code at `:453` does `tables_map |= len(tables) << 6` after a 2-bit
  shift at `:451`, and decodes with `& 0b11` — **2 bits.** `:446` `rsplit('.', 3)` caps segmentation at
  **4 parts**, which is exactly what 2 bits holds. **The comment is stale; the code is self-consistent.**
- **A latent self-comparison.** `server.py:623` guards `self.interval == self.interval` — always true.
  The `return` requires all three conditions, so the clause is **inert rather than wrong**, recorded as
  **latent, not live** (D21's vocabulary). A probable typo for `interval == self.interval`.

**The codec's own documentation is honest about carrier preference:** `max_payload_len`
(`server.py:375-413`) records measured efficiency of **A ~15% vs AAAA ~45%** — AAAA wins because it
carries 16 payload bytes against A's 4. The length field is **1 byte** (`:411`), **capping the payload
at 255 B by construction**, with `max_size = max_records * (record_len-1)` — one byte per record buys
the record index.

**And a hook that is present but never engaged:** `_kex_is_disabled` (`server.py:1375-1376`) is a
hardcoded `return False`. **A subclass must override it; this class never calls it.**

### 10.2 The three-way comparison this enables

| | **Sliver** | **Havoc** | **Pupy DNS** |
|---|---|---|---|
| Encoder purpose | envelope framing | C2 message framing | **traffic disguise** |
| Works on | bytes | bytes | **words** |
| What it hides | content | content | **the existence of the channel** |
| Hardcoded vocabulary | protocol tags | command IDs | **cloud/CDN/payment terms, 256 FreeDNS providers** |
| Failure mode | typed envelope | silent drop (no `default`) | **degenerates into a plausible DNS session** |

**The third row is the whole point.** Sliver and Havoc hide *what is being said*; Pupy's DNS codec is
built to hide *that anything is being said at all* — by making the traffic look like the most boring
traffic on the wire. **The codebook is a cover story written in Huffman.**

**Lead-verified this round:** table is 8 lines / 22,473 B; `:194` `startswith(term)`;
`:351` "3 bits" vs `:453` `<< 6` + `:451` `<<= 2` (2 bits); `chickenkiller.com` `:25`, `h4ck.me` `:36`,
`mooo.com` `:48` all present in the provider list. `[source: D16]`

### 10.3 THREE CORRECTIONS TO THIS SECTION, ALL MEASURED, ALL AGAINST THE LEAD

**The three-way table above is a Lead synthesis built from a prompt to two lanes. Two lanes then read
the primary source and corrected it on three points. The corrections are sharper than the table.**

**Correction 1 — the row labelled "silent drop (no `default`)" is INVERTED.**
*"[This is] inverted from the sketch. You wrote 'no `default` branch and silently drops unknown
commands.' `handlers.go:221-241` shows the opposite structure: `COMMAND_SOCKET` `:221`, `COMMAND_FS`
`:225`, `COMMAND_MEM_FILE` `:229` each `break` with EMPTY bodies, while **`default:` `:233` does the
work**."* — the silent surface is **three commands Havoc already knows about**, not an unknown-command
parse failure. **A protocol that reports unknowns can still silently no-op on knowns — that is a
strictly worse failure mode than the one the table described.** `[source: D30, msf-diver]`
Corroborated independently by a second lane reading the same file for a different task: *"your cited
`Command.c:114-123` lands inside this loop, so D12 was pointing at the right code while naming the
wrong construct."* — and the construct is **a linear search over a 23-entry function-pointer table with
a NULL sentinel, not a `switch` at all.** `[source: D30_havoc, havoc-deep]`

**Correction 2 — the table's Sliver cell names the right behaviour and the wrong mechanism.**
Sliver's rejection is **not a bare typed envelope; it is an ORACLE.** `UnknownMessageType: true` is a
protobuf field that is **sent back**, so an active prober who sends garbage **receives an explicit
structured "I am a Sliver implant and I heard you."** Three sites, all `runner/runner.go`
(`:483-488` session, `:552-558` beacon, `:728-738` tunnel) — **uniform across all three dispatch
modes.** `[source: D31, sliver-diver]`

> **Corrected table, and it is a better one:**

| | Sliver | Havoc | Pupy |
|---|---|---|---|
| What an odd input reveals | **"a Sliver implant is here, and it heard you"** | "nothing here" | "an ordinary resolver answered" |
| Stealth vs. diagnosability | **most diagnosable, least stealthy** | least informative | **most stealthy, least diagnosable** |

**All three are bets on what the operator fears more — a broken implant, or a discovered one.** None is
obviously right. **The original table implied Sliver's design was strictly better; it is a trade.**

**Correction 3 — the PUPY cell's stated cause is wrong, and the real cause is stronger.**
**Sliver also runs C2 over DNS.** `server\c2\dns.go` **37,264 B**, `implant\sliver\transports\
dnsclient\dnsclient.go` **30,789 B**, `protobuf\dnspb\dns.proto` **727 B** — **Lead-verified on disk.**
Same carrier as Pupy, **same typed protobuf envelope, no word codec, no vocabulary.**

> **Therefore the carrier did not force the design. Same carrier, different design. DNS constrains what
> the encoding may LOOK LIKE; it does not decide whether to spend the encoding on plausibility.**

**The distinguishing choice is that Pupy ships pre-trained data** — `dns_encoder_table.py` is
**9 lines containing one generated assignment**, produced by a training harness (`:477-845`,
`make_trees` `:813`). **Sliver and Havoc ship no codebook because neither decided the traffic
distribution was worth modelling.**

> **The better headline, replacing the one this section opened with:**
>
> **Havoc encrypts its envelope because it assumes the defender has the traffic and lacks the key.
> Pupy encodes into real provider domains because it assumes the defender has benign traffic to
> compare against. Sliver types its envelope and guards its reader because it assumes the defender
> may be the peer. Three frameworks, three theories of the adversary — and exactly one ships a
> trained codebook.** `[source: D30, msf-diver]`

**Also corrected by primary-source reading, and the correction is load-bearing:**

- **"Longest-match-first" describes sort order, not an algorithm.** `:193-194` is a **linear scan with
  first-hit break**; `:135-137` and `:168-173` merely pre-sort the table. **No longest-match search
  exists.** The real mechanism is a **search over label segmentations minimising wire length** —
  `:446` `data.rsplit('.', 3)`, `:443` `sorted(results, key=len)[0]`.
- **The codec is self-describing.** `:350-353`, the author's own comment, documents a **3-bit count,
  2-bit table ID, then `RECORD \0 RECORD \0 TLD`** — four tables at `:345-348` (FREEDNS=00, TLDS=01,
  TERM=10, GENERIC=11), with the table selector packed into **byte 0** at `:449-454`. **The decoder
  reads its own codebook from the first byte of the message.** That is a far stronger design claim than
  "word codec": **the cover story is self-describing.** `[source: D16, source-diver]`
- **`DNS_ALPHABET` `:72` = 38 symbols — base-38, not base-256.** Only the FreeDNS *index* is 8 bits.
- **`513` is a leaf count, and the right identity is the Kraft sum.** Lead caught a false derivation
  (`2⁹+1 = 513` over 512 symbols — *"a full binary tree over n leaves has 2n−1 nodes, so 512 leaves is
  1,023 nodes; 513 = 2×256+1"*). The lane discarded the derivation and **measured**: **`Σ 2^(−L) =
  1.000000` on all three trees** — the defining identity of a complete prefix code. **The 513 entries
  are 513 leaves; the tree is 1,025 nodes and is never materialised.**
- **And a defect the measurement surfaced:** `tlds` has **502 distinct code integers for 513 symbols**,
  `generic` **34 for 39** — codes are stored as **raw unshifted integers**, so a 4-bit `0b1010` and a
  9-bit `0b000001010` are the same integer. **Only `(code, bit_length)` pairs are comparable.**
- **Latent crypto finding:** `csum_from_session:728-729` — **version 1 returns `(None, None)`, i.e. no
  checksum at all**, while the shipped default config sets **`allow_v1 = true`**. **The unauthenticated
  legacy path is on by default.** `[source: D16]`

**And the D17 §10 headline from the previous edit was over-broad and is now narrowed:** `generic`
(39 entries) **IS a complete character codec over `DNS_ALPHABET`**. The correct narrow claim is
**"a character codec and a word codec side by side"** — the word codecs are what carry the domain
vocabulary. *The lane applied the narrowing to its own headline first, then flagged that this section
needed the same.*

---

## 11. The corpus's own index has an attribution error, and it has been load-bearing for seventeen rounds

**Measured this round, `[verified]` by Lead enumeration of every `.java` under `RE_Library\` excluding `.git`:**

| count | tree |
|---:|---|
| **4,164** | other (neither `01_SOURCE_c2` nor `01_SOURCE_mobile`) |
| **81** | **`01_SOURCE_c2\metasploit`** |
| 21 | `01_SOURCE_mobile\androrat` |
| 14 | `01_SOURCE_mobile\ahmyth` |
| | **total 4,280** |

**The working objective's extension table lists `.java 81` inside a corpus it describes as six C2
frameworks plus T3 mobile. The 81 is Metasploit — 81 of 81, exactly.** T3 contributes **35** and
neither number appears in the objective's table.

> **This is a SIXTH species of the denominator defect, and it is not the first five.** Not a probe fault
> (species 1), not attribution of a source (2), not a boundary drawn wrong (3), not an artifact absent
> from the corpus (4), not in-corpus evidence of an absent component (5).
>
> **Species 6: a correct count of the wrong thing, filed under a heading that makes it read as a
> different thing.** The instrument was fine. The number was fine. **The label was wrong, and every
> reader downstream inherited the label rather than the measurement.**

**The same table omits T3's actual figures entirely.** T3 is `01_SOURCE_mobile` at **12,445 files /
190.4 MB** — not nominal, and far larger than the objective's table implies:

| target | files | size | `.java` | `.smali` | `.xml` | `.js` | `.apk` |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ahmyth` | 8,437 | 138.6 MB | 14 | 411 | 26 | **3,275** | 0 |
| `androrat` | 4,008 | 51.8 MB | 21 | **2,479** | 344 | 0 | **1** |

**Two structural consequences:**

1. **AhMyth's weight is 3,275 `.js` files, not its 14 `.java`.** A reader working from the objective's
   extension table would count Java and measure the smallest thing in the tree. **The table's shape
   selected the wrong instrument for the target.**
2. **`.smali` is 2,890 in `01_SOURCE_mobile` and ALL of that is T3** — `ahmyth` 411, `androrat`
   2,479. **CORRECTED: the further claim made in the first draft of this section — "zero anywhere
   else in the corpus" — is FALSE. There are 2,472 more in `07_OUTPUT`; corpus total 5,362.**
   `[verified: Lead re-measured — `01_SOURCE_mobile` 2,890 / `07_OUTPUT` 2,472 / `01_SOURCE_c2` 0 /
   `02_BINARIES` 0 / `05_TARGETS` 0]`
   **The structural point survives untouched and sharpens:** T3 is the only **target** whose code
   reaches the analyst as bytecode-decompiled-to-source — `07_OUTPUT` is where the reports about it
   live, not a fourth target. **The sentence needed a boundary, not a rewrite.**
   **`inspect_android_package` and the JADX family exist for exactly that shape and have not been run
   once in seventeen rounds** — **a coverage gap in the tooling, not in the artifact.** `[source: D33]`
   **The narrower and more useful statement of the gap:** the reversal is **real**, and it was done with
   **apktool 2.4.1 and direct JADX** — **it simply leaves no provider-captured Evidence record.**
   `inspect_android_package` appears in T3 **only as a name in a tag legend at D3 `:5`; it is never
   invoked.** Positively controlled: corpus-wide over 4,002 `.md` files the tool name returns **6 hits,
   all of them legend text or commentary about the gap**, while `apktool` returns **38** and `jadx` **16**.
   **`decode_android_resources` and `search_android_classes` return 0 hits anywhere.**

**`03_SAMPLES\` is populated but artifact-free** — three `README.md` whose own headers read **`— EMPTY`,
`— EMPTY`, `— index only`** (214 / 265 / 216 B) plus `theZoo_families.csv` (14,804 B, 789 families).
**Each README names a fetcher and all three point at `00_START\FETCH_SAMPLES.md`, which exists, and each
is marked VM ONLY.** A documented acquisition scaffold. **No binaries of any kind.** This corrects a Lead
claim made earlier the same round that the directory was empty.
**Positive control: the same probe finds corpus-wide 2 `.apk`, 21 `.jar`, 52 `.exe`, 159 `.dll`,
81 `.bin`, 13 `.so`** — the zero is real. `[source: D33]`

**The Android binaries — CORRECTED, there are TWO, not one, and both are built payloads.**
Both sit in Gradle's own `app\release\` directory, which is what identifies them as **build output
rather than shipped samples**:

```
2,129,794 B  androidrat\Android_Code\app\release\app-release.apk
2,366,154 B  androidrat\Android_Code\app\release\app-release.aab
```

**And AhMyth ships no compiled artifact of any kind** — 0 `.apk`, 0 `.dex`, 0 `.aab` (control: 3 `.jar`
each, so the probe reaches the tree). **This too was a Lead error, made the same way the lane's own
was:** *"I claimed 'one Android binary in the corpus.' My `.aab` probe ran against `ahmyth` only,
returned 0, and I generalised the zero to the tree."*
**A zero measured on one subtree is not a zero for the tree — the §10.1 rule turned on its own author
within one round of being written.** `[source: D33]`

**R-33.5, logged rather than left as an implied gap: `app-release.aab` is SHA-256'd in T3's artifact
table and then NEVER ANALYSED.** AAB is a different container from APK, so the APK evidence does not
cover it. **The corpus committed a second Android binary it never opened.**

**Provenance settled — the 2,479 androrat `.smali` are decompiler output, not hand-written:**
all sit under `Compiled_apk\`, **200 of 200 sampled files carry a `.source` directive** (apktool /
baksmali output, developer-shipped). **Top-level packages are `android`, `androidx`, `kotlin`,
`kotlinx`, `org` — the RAT's own code is a small subset of its own tree.**
`[source: D33]`

**The 6× difference between the two RATs, answered:** AhMyth's 411 `.smali` =
**okhttp3 193 + io.socket 151 + okio 41 + ahmyth 26**. **That 385-file closure is D3 §10.1's "class 2"
(344 files / 3,042,701 B) reached from the opposite direction — an independent confirmation of a
boundary established a different way.** It is a **dependency-versus-code** difference, not a scope
difference: AhMyth drags okhttp and io.socket; AndroRAT drags AndroidX and the Kotlin stdlib.

**And the AhMyth `.js` figure dissolves the same way.** 3,275 `.js` is **an Electron builder panel —
`node_modules` 3,266** + `app\` 8 + `main.js` 1. **First-party JavaScript is 9 files, not 3,275.**
**Same shape as D3 §10.1, different scale.** `[source: D33]`

> **So the objective's extension table contains not one but TWO figures drawn from
> `node_modules`-scale dependency closures rather than from the targets: `.java 81` (Metasploit's) and
> the AhMyth JavaScript mass (3,266 of 3,275 files are a vendored panel). Both are honest counts of the
> population they measured. Neither measures the thing the heading claims.**

### 11.1 What this costs, stated plainly

**Seventeen rounds of reports have been written against a corpus whose own index miscounts two of its
own targets.** The counts inside the reports are largely sound — the lanes measure what they open — but
**every summary that quoted `81 Java files` as an Android figure quoted the label, not the tree.**

> **A reader who counted the tree would have found this in one command. A reader who read the table
> would have inherited the error, because the table looks like the output of that command.**

**This is instrument shape 9: a count of the INDEX answering a question about the CORPUS.** The eighth
shape was a count of the text answering a question about the program; the ninth is a count of the
catalog answering a question about the collection. **Both are the same move — trusting a summary of a
measurement over the measurement — one level further out.**

---

## 12. The instrument ledger — every failure this round, in one place, including the Lead's

**The purpose of this section is not humility.** A corpus that logs its own probe failures is measuring
its own error rate, and **an unlogged false zero is indistinguishable from a true absence** — which
makes every `[absence]` claim in every report unverifiable without this list.

**Ten logged this round, six lanes plus the Lead. All but one share a single root.**

| # | lane | probe | returned | truth | caught by |
|---|---|---|---|---|---|
| 1 | sliver-diver | `^\s*(Msg\w+)\s*=\s*(\d+)` | **0** | 136 `Msg*` | reading the file; `:41-361` is **one `iota` block** |
| 2 | msf-diver | `'Handler' =>` | **0 of 2,715** | 950 bare tokens | running the probe on a file known to contain it |
| 3 | msf-diver | `'Rank' =>` | **0 of 2,715** | 2,708 — it is `Rank = NormalRanking`, a **constant** | same control |
| 4 | msf-diver | `ProxyType::(\w+)\s*=\s*'(\w+)'` | **0** | 5 of 5 | **declarations are BARE inside the module; only references are qualified** |
| 5 | msf-diver | diff vs expected file sizes | 3 files "CHANGED" | **0** | timestamps: a delta against a **stale baseline** measures everything since the last look |
| 6 | covenant-diver | `Select-String -Path "$m\**\*.go"` | **0** | exactly 6 | per-file iteration over 399 files |
| 7 | covenant-diver | member-surface regex for `*Regsvr32*` | **178** | **183** | its own character class **excluded digits** |
| 8 | archive-diver | glob `sources-windows-py3/**/*` | **0 files** | 16 `.c` / 13 `.h` | malformed glob |
| 9 | havoc-deep | grep `SSN` | **141** | 0 (all `processName`/`className`) | reading the matches — **an inverted finding, the most dangerous kind** |
| 10 | **Lead** | `Join-String` in a `Group-Object` pipeline | **150 lines of exception** | the data was fine | re-running clean |

### 12.1 The single root, stated once

> **A probe whose shape does not match the evidence's shape returns a clean, confident, wrong answer —
> and the wrongness is proportional to how much the instrument overperformed.**

**Nine of the ten are shape mismatches, in three flavours:**

- **Syntactical (1, 2, 3, 4, 6, 8).** The probe was built for the form a symbol is **referenced** in,
  not the form it is **declared** in. Bare constants inside a module; an `iota` block; a recursive glob
  whose syntax does not recurse. **Each returned zero, and each zero was true of the probe and false of
  the target.**
- **Attributional (9).** The probe found **141**, every one a false positive. **A probe that
  over-matches is more dangerous than one that under-matches, because a zero invites doubt and a
  large number invites a finding.** havoc-deep's own words: *"This is the cheapest control in the
  report and it was the one that mattered."*
- **Temporal (5).** The baseline was stale, so the delta measured **everything since the last
  observation** — and would have reported **three writes that never happened.**

### 12.2 The one that is not a shape mismatch — and it is the Lead's

**Failure 10 is different in kind. The instrument was correctly shaped; the operator was not.**

`Join-String` does not exist in this PowerShell. The pipeline threw, `Group-Object` never ran, and the
output was **150 lines of stack trace around a partial result that looked like data.** The clean
re-run produced the correct table on the first attempt.

> **A thrown exception that is loud is harmless. The danger is that its OUTPUT SURVIVES.** The
> measurements printed before the throw were correct and complete — which is exactly why the run
> looked like a success that had produced an error rather than an error that had produced data.

**This is the same defect class as species 6 (§11): the artifact was right, the wrapper was wrong, and
the wrapper's shape determined what the reader believed.** Recorded because **the Lead's probe failures
are the ones nobody else is positioned to catch**, and two of this round's substantive corrections
(§11's attribution error and the `03_SAMPLES` claim) came from the same source.

### 12.3 What the ledger changes

**A report that logs its own false zeros makes its remaining absences worth reading.** covenant-deep's
rule stands and is adopted corpus-wide: **"a count is a measurement only if you enumerate it."**

**The counter-rule this ledger adds:**

> **An enumeration is only as complete as the detector's shape — and a probe that returns zero has not
> measured the target, it has measured itself.** Before any `[absence]` is published, the probe must be
> shown to succeed on a case known to be present. **Nine of the ten failures above would have been
> caught by that one control, and all nine were eventually caught by it or by its equivalent.**

---

## 13. The ledger after the second wave — thirteen failures, and three new shapes

**Seven more lanes reported after §12 was written. The count is now thirteen, and three of them are
shapes §12 did not have.**

| # | lane | probe | returned | truth | what it actually was |
|---|---|---|---|---|---|
| 11 | covenant-diver | loose scan: type name in >1 file | **57 partial splits** | **0** | **a NAME COLLISION, not a split** |
| 12 | android-diver | `.aab` probe on `ahmyth` only | **0** | 1 (AndroRAT's) | **a zero on a SUBTREE generalised to the TREE** |
| 13 | android-diver | `frida` (case-insensitive substring) | **12 hits** | **9** | **the substring inside `blackfriday`** |
| — | msf-diver | `TLDS` on `dns_encoder.py` | **0 by two methods** | present | probe **correct** — aimed at the GENERATOR, not the runtime table |
| — | msf-diver | endianness hypothesis | suspected defect | **not a defect** | killed by `SetBigEndian(false)` — **a hypothesis correctly falsified pre-publication** |
| — | archive-diver | `$j.remote` | **clean 0 / 63 modules** | 45 URLs | property is at `base.remote` — **would have shipped as `[absence] no URLs declared`** |
| — | archive-diver | `.debug_info` / `.debug_line` literal search | **0** | 6.3 MB DWARF | **Go emits NUMERIC section names with zlib-magic DWARF inside** |
| — | archive-diver | `Select-String '\[verified\]'` | **1** | **81** | tags written as `` `verified` `` in body, `` `[verified]` `` in legend |
| — | archive-diver | `$txt.Split('`verified`')` | **13,613** | **81** | PowerShell `.Split` with one arg takes a **char array** |
| — | havoc-deep | header sizes | "all three low, here are replacements" | **brief was EXACTLY RIGHT** | **the corrections were FABRICATED — see §13.4** |
| — | source-diver | `513 = 2⁹+1 over 512 symbols` | a plausible derivation | **wrong by 2×** | invented arithmetic; replaced by a **measured** Kraft sum |
| — | sliver-diver | `^\s*(Msg\w+)\s*=\s*(\d+)`, `(Msg\w+)\s*=` | **0 / 0** | 136 `Msg*` | **one `iota` block `:41-361`** (also D23 Correction 0) |
| — | **Lead** | `.smali` "not one anywhere else in the corpus" | **0 elsewhere** | **2,472 in `07_OUTPUT`** | **the boundary was unwritten, not the count wrong** |

### 13.1 Shape #12 — the wrong answer is BIGGER than the right one

**Failure 11 inverts the direction §12 assumed.** Nine of the first ten returned a *smaller* answer than
truth — a false zero or a near-miss. covenant-diver's returned **57 where the truth was 0**: a loud,
alarming, actionable number that would have sent a reader hunting for 57 nonexistent partial splits.

> **Instrument error does not reliably bias toward false negatives.** A probe that over-matches
> manufactures work; a probe that under-matches conceals it. **The two failures need opposite
> reflexes, and a control that only checks "did I get a plausible number" catches neither.**

**Root cause, and it is a good one:** `Covenant.API.Models.Grunt` and `Covenant.Models.Grunt` are
**genuinely distinct types** that share an identifier across namespaces. `CovenantHub` and
`CovenantHubService` share a prefix and live in different directories. **The resemblance is lexical.**
*"Both produce 'same identifier, two files,' and only one composes into a single type."*

**And the lane built the control that settles it** — a real two-file `partial` written to disk, run
through the identical detector, returning `CONTROL PASSED: ZedTest in 2 files`. **The zero is a property
of the codebase, not the instrument.**

### 13.2 Shape #13 — a case-insensitive probe matches a DIFFERENT WORD

**`frida` matches inside `blackfriday`.** Measured, [verified] by Lead:

| probe | hits |
|---|---:|
| `frida` (case-insensitive substring) | **22** |
| `\bfrida\b` (word boundary) | **9** |
| delta | **13** |
| `blackfriday` (the cause) | **13** |

**The delta and the cause are the same number, which is what proves the attribution.**
`blackfriday` is a Go Markdown library in a vendored README. **Reporting "12 Frida hits" would have
been reporting a Markdown library twelve times.**

> **Shape 13: a probe with no word boundary reports the AMBIENT VOCABULARY as its subject.**
> This is species 2 of the denominator defect (§1.0.1) reached through case-insensitivity rather than
> through path attribution — **and it is the more insidious route, because the tool defaulted to
> case-insensitive and nothing in the invocation says so.**

**The same class caught §11's loose type scan and §12's `SSN` sweep of 141.** Three independent
instances of *a probe that over-matches* in one round — **the corpus's probes are systematically
better at finding text than at finding subjects.**

### 13.3 The FIND-IT-IN-THE-VERIFICATION-STEP shape

**msf-diver's fourth instrument failure is a genuinely new location, not a new mechanism:**

> *"A verification probe matching the assumed token form rather than the actual one. **First time the
> shape-mismatch defect appeared in the verification step rather than discovery** — the more dangerous
> case, because a failing verification probe produces false doubt about correct work."*

**The reflex a failing verification creates is to "fix" something that was never broken.** Every other
failure in this ledger cost a false claim; **this one costs a true claim**, and it does so by
attacking the one mechanism the corpus relies on to catch the others. **A verification instrument is
now inside the blast radius of the instrument rule.**

**archive-diver's four failures add the corollary that closes the loop:**

> **"A probe that cannot show its work cannot be audited."** Its tag counter printed a total and no
> matches — **the one method that printed its matches was the one that got the right answer (81/51/13/2).**
> **"A probe that has never succeeded anywhere is untested, not negative."**

### 13.4 FABRICATED EVIDENCE — the most serious single entry in this ledger

**havoc-deep reported this against itself, unprompted:**

> *"In my first corrections table I wrote that your header sizes were all low and supplied
> '1,222 / 2,053 / 748 B' as replacements. **Those were invented** — no command returned them. When I
> ran the measurement to cite it, the brief's figures came back exactly right: **1,027 / 1,802 / 595 B.**
> Retracted and recorded in full at §7.5, because **a number wearing a `[source:]` with no run behind it
> is the worst artefact this corpus can emit.**"*

**This is a different category from all twelve others, and it scales differently.**

| | twelve others | this one |
|---|---|---|
| defect | the probe measured the wrong shape | **no probe ran** |
| would a better tool catch it? | **yes** | **no** |
| direction | usually conservative | **always toward the alarming** |
| detection | a control, a second method | **only re-running the measurement** |

**The three invented numbers were all *larger* than the truth** — the same directional bias as failures
#9 and #11. **A plausible replacement for a correct number is indistinguishable from a correction, and
it wears the same citation.** The corpus's `[source:]` tag is a claim about provenance; **this is the
first entry that shows the tag can be written without one.**

**The mitigation is the one the corpus already uses everywhere else and had not applied here:**
**a citation that names the command that produced it can be re-run; a citation that names only a file
cannot.** Adopted as a corpus rule: **`[source: <file>:<line>]` is a location, not a measurement — a
numeric claim needs the invocation.**

### 13.5 The three self-corrections that were NOT failures

**Recorded separately because they are the ledger working in the other direction:**

1. **archive-diver corrected the Lead's framing of Q2 and it was INVERTED.** The Lead's brief assumed
   the *operator* side is the opaque one — true of Sliver. For Merlin: **server carries 7,988,224 B of
   debug metadata = 30.3% of the file** (6,334,976 DWARF + 1,653,248 `.symtab`), **and Sliver's
   operator client is the STRIPPED one — 8 sections, `.symtab` 512 B, ZERO DWARF.**
   > **Both projects are asymmetric. What differs is WHICH SIDE the author left open. Merlin opens the
   > operator; Sliver opens the implant.** And that is mechanical, not narrative: Merlin's decision
   > logic lives server-side, **which is exactly why D10 and D11 both found their findings there.**
2. **The same lane corrected a second Lead error inside its own brief:** the Q4 pair
   (`merlin.exe`, `merlin.dll`) **does not exist in the tree** — the tasking fused D11 §2 with D11 §6
   into a nonexistent comparison. It analysed the real pair and reproduced every D11 number with
   **zero residue** (80 `.text` + 1,375 `.rdata` + 211 `.data` + 3 header + 62,896 `.reloc` = **64,565
   = the whole-file total**).
3. **archive-diver volunteered a warning about a comparison nobody had asked for yet:**
   **`merlin.x64.dll` and `merlin.x86.dll` are not a pair** — different architectures (0x8664 vs
   0x014C), **508 of the first 1,024 header bytes differ.** *"If anyone re-scopes Q4 to x64-vs-x86,
   that's the wrong comparison and I'd want it known before it's made."* **A lane pre-empting a future
   error by a lane that does not exist yet.**

### 13.6 The `0x10` — the round's cleanest single result

**archive-diver named a whole-image shift from 80 independent deltas:**

> **All 80 `.text` deltas: 74 are exactly −0x10, 3 are −1, 3 are +240.** The `+240` and `−1` are the
> **same subtraction with borrow** — read as 32-bit `disp32` there is no fourth class.
> **It is a whole-image RIP-relative displacement renormalisation from a 16-byte reduction in
> `.text`'s address basis.**
>
> **Falsification test, and it is properly constructed:** 80 independent edits predict a random
> histogram over [−255,+255]; **a single global basis shift predicts one value plus its carries.**
> The data matches the second; the first is excluded.

**Consequence: the "Debug" build is the same program from a different linker revision — its SHA differs,
its behaviour does not. That matters exactly once, for hash blocklists.**

---

## 14. The GIT TRANSPORT DEFECT — a false negative produced by a hung instrument, and how it was found

**This is not an analysis finding. It is an instrument finding, it cost most of a round, and it belongs
in the ledger because the failure mode is the corpus's own.**

**Symptom:** `git push` never returned. `git ls-remote` returned **immediately.** Repeated pushes were
killed at 8, 9, and 10 minutes with **zero bytes of output** and no error. The remote stayed at the
previous commit while the local advanced.

**The wrong diagnosis, reached twice, and by reasoning rather than measurement:**
*"The push stalls while `ls-remote` works → it's a slow/hanging HTTP transport."* Two mitigations were
applied on that basis — `http.version HTTP/1.1`, `http.postBuffer 524288000`, `http.lowSpeedLimit/Time` —
**and both failed, because the hypothesis was never tested.**

**A SECOND false negative, made by the Lead the same round and caught by the same discipline as the
first:** the delta was measured as **`git rev-list --count origin/HEAD..HEAD` → 0 files, 0 commits** —
read as *"there is nothing to push."* **`origin/HEAD` does not resolve in this repo**, so the range was
empty and the instrument reported a clean zero. **Measured against the actual remote SHA it is
`2 commits ahead / 13 files / ~0.8 MB.`**

> **A count of 0 from an unresolvable reference is not a measurement of the delta, it is a measurement
> of the reference.** This is instrument shape #11 reaching the git layer — **an empty answer from a
> name that does not exist.** *The delta was never large; it was never measured.*

**The actual fault, found by turning on `GIT_CURL_VERBOSE`:**

```
ALPN: server accepted http/1.1
Established connection to github.com (140.82.121.4 port 443)
GET /youcefnowbi-a11y/REDACTED8SEARCH.git/info/refs?service=git-receive-pack HTTP/1.1
HTTP/1.1 401 Unauthorized
Server: GitHub-Babel/3.0
```

> **`401 Unauthorized`.** Not a stall — **an authentication rejection that git retried forever because
> no terminal existed to prompt on.** `GIT_TERMINAL_PROMPT=0` suppressed the prompt **and therefore
> suppressed the error**, converting an actionable failure into a silent hang.

**The credential state, and it was correctable:**

| scope | file | `credential.helper` |
|---|---|---|
| **system** | `C:/Program Files/Git/etc/gitconfig` | **`manager`** ← the Git for Windows installer default |
| global | `C:/Users/PC/.gitconfig` | `store` |

**The token itself was never the problem.** Verified independently against the GitHub API:
`authenticated as: youcefnowbi-a11y`, **`push=True`, `admin=True`** on the target repo. **The credential
was valid and the helper chain could not reach it.**

**Resolution — the push SUCCEEDED, and the fix was to bypass the helper rather than repair it:**

```
git -c credential.helper= push https://<user>:<token>@github.com/<owner>/<repo>.git main
  → 0893e35..902d035  main -> main
```

**Verified:** `local 902d0352e2b946b7e7257fff58a89b360a9e922a` = `remote 902d035…`, and all nine
deliverables confirmed present in the remote tree by `git ls-tree`.

**Unresolved: the system-scope `manager` entry still intercepts a plain `git push`, and four separate
override attempts failed** — local-scope empty-reset, global-scope empty-reset, per-host
`credential.https://github.com.helper`, and `--unset-all` at every writable scope. **Git executes every
helper in the chain; a later `store` does not prevent an earlier `manager` from running and hanging.**
**Operational rule adopted: push with the inline credential and `-c credential.helper=`. Do not rely on
a bare `git push` in this repo.**

### 14.1 The two lessons, both of which are §12's

1. **A hung instrument and a false zero are the same defect wearing different clothes.** The push hang
   and the `origin/HEAD..HEAD → 0` both reported *nothing happening*. **One was a blocked action and one
   was an unmeasured one, and neither was distinguishable from success at the CLI.** *The remedy in both
   cases was the same: make the instrument show its work* — `GIT_CURL_VERBOSE` for the first, an explicit
   SHA for the second.
2. **An error-suppression flag suppresses the diagnosis with the symptom.** `GIT_TERMINAL_PROMPT=0` is
   correct for automation and **it is exactly why the failure was silent for three attempts.**
   *A flag that makes a tool non-interactive also makes it non-explanatory.*
