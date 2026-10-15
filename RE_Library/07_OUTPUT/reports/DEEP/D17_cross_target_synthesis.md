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
control was the only thing standing between a lane and shipping a wrong finding.** The probe was
capable; the *path filter* was the defect. Same shape as instance 3 (non-recursive glob reads a
nested tree as flat) and instance 5 (root-anchored `.gitignore` rules match nothing): **a scoping
error presenting as an absence, where the scope is the thing that silently failed.**

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

### 4b.1 The Covenant instance, in detail, because it is the cleanest

Five of six SignalR hubs carry class-level `[Authorize]`. **`CovenantHub.cs` carries none** — zero
attribute lines in the file — and `Startup.cs:238` maps it bare at `/covenanthub` with no
`.RequireAuthorization()` (D13 §4).

**It exposes exactly one live method:** `CreateHttpListener` at `CovenantHub.cs:162-165`. That method
provisions a 2000-day Identity user, stores the JWT, and can bind a listener
(`CovenantService.cs:3953-3970`).

> **The same operation via `POST api/listeners` requires `RequireJwtBearer`. Via `/covenanthub` it
> does not.** Two channels, same capability, one gated.

**An honest correction made in-flight, and it is the sixth instrument:** covenant-diver's first pass
reported `CovenantHub` as **~230 unauthenticated methods.** It has **one.** The other 222 are inside
**two block comments** (`L35-161`, `L166-1151`) — a textual `public` grep counts dead code. **Off by
223×.** Corrected in-report at §4.0 rather than quietly patched.

**A textual count is not a reachability count.** That is the same lesson as the `TaskDispatch` premise
(D12 §2) and the `COMMAND_` prefix (D12 §9 F1), arriving a third time from a third lane: **the count
was of the text, and the question was about the program.**

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
4. **Mythic's post-response siblings are partially covered.** D4 §13.3 flagged one file
   (`util_agent_message_actions_post_response.go`, 142,962 B); a second exists
   (`recv_pt_task_opsec_post_response.go`, 7,270 B) and is in no report. D11_mythic covers
   post_response crypto; the second sibling is not established as covered.
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
