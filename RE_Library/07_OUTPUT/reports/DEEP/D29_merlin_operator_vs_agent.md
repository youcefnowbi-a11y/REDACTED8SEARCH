# D29 — Merlin Operator Binary vs Agent

**Lane:** `archive-diver`. **Task:** task-37.
**Targets:** `merlin.x64.dll` (15,145,760 B), `merlin.x86.dll` (14,687,006 B), `merlinServer-Windows-x64.exe`, `merlinAgent-Windows-x64.exe`, and the 63 shipped module JSONs.
**Method:** Source reading first. **No Ghidra provider was opened** — see §7.1 for why the provider was not needed and what that bounds.
**Write scope:** this file only. D10, D11_merlin_binaries, D17, D21 and STATUS.md were **not modified**; §6.4 records the two D10/D11 corrections this lane found, for Lead to re-index.

## Verification boundary — stated plainly, up front

- **Static analysis only.** Nothing was executed. No agent was run against a target. No URL was fetched to test reachability (§5).
- **Reachability claims are static claims.** Where the corpus says *live*, this lane says **latent** or **reachable** / **not reachable from the corpus**, per the vocabulary established in D21.
- **Distribution vs artifact property.** URL reachability is a **deployment** property and is labelled as one (§5). It is never asserted as a property of the file.
- **`merlin.exe` does not exist in this tree.** The tasking's Q4 names a pair `merlin.x64.dll` vs `merlin.exe`. **There is no `merlin.exe`.** §4.0 records this as a spec error and states the pair actually analysed. This is an instrument/scope correction, not a silence.
- **Every headline count has two independent methods** — stated inline as `METHOD A` / `METHOD B`.
- **Four new instrument failures were found and recorded** — §5.1–§5.5. All four are instances of the corpus's one root cause, and **all four are this lane's own probes.**

## Table of Contents

- [§0 Status and headline results](#0-status-and-headline-results)
- [§1 The DllExport surface — Q1](#1-the-dllexport-surface--q1)
- [§2 The symbol asymmetry as a design statement — Q2](#2-the-symbol-asymmetry-as-a-design-statement--q2)
- [§3 The 45 remote URLs — Q3](#3-the-45-remote-urls--q3)
- [§4 The 0x10 shift — Q4](#4-the-0x10-shift--q4)
- [§5 Instrument record](#5-instrument-record)
- [§6 Residual unknowns — Q5](#6-residual-unknowns--q5)
- [§7 Method notes and scope](#7-method-notes-and-scope)

---

## §0 Status and headline results

| Phase | Work | State |
|---|---|---|
| A | `DllExport` surface enumerated, reachability per export | **COMPLETE** |
| B | Symbol asymmetry vs Sliver | **COMPLETE** |
| C | 45 remote URLs enumerated + classified | **COMPLETE** |
| D | The `0x10` shift named | **COMPLETE** |
| E | Residual closure | **COMPLETE** |

**Headline results:**

| # | Finding | Tag |
|---|---|---|
| **1** | `merlin.x64.dll` exports **exactly 7 functions / 7 names** — `Magic, Merlin, Run, VoidFunc, DllInstall, DllRegisterServer, DllUnregisterServer`. Two independent PE parsers agree. | `[verified]` |
| **2** | **"Seven export names, ONE action" is VERIFIED** — all seven thunks resolve to the **same common function at RVA `0x16C0`**. | `[verified]` |
| **3** | **`Magic` is the one that diverges — in shape, not in destination.** It is at RVA `0x13D1`, **off the `0x40` grid** the other six sit on (`0x1400 + 0x40k`), and it uses a **different prologue** (`push rbp; mov rbp,rsp` = mingw C frame) versus the six Go thunks (`push rbx; sub rsp,0x30`). It still converges on `0x16C0` — via `Merlin` (`0x1540`). | `[verified]` |
| **4** | The six Go exports are **one template instantiated six times**: byte-identical instruction sequences differing only in `rel32` displacements. | `[verified]` |
| **5** | **45 non-empty `remote` values, 43 unique** — 42 `raw.githubusercontent.com` + 3 `gist.githubusercontent.com`. Both methods agree. | `[verified]` |
| **6** | **42 of 45 remote URLs point at a mutable branch (`master`); 3 are SHA-pinned gists.** No commit SHA exists in the raw-GitHub set. | `[verified]` |
| **7** | **One shipped module's `remote` field is corrupt** — `Get-ExecutionCommand.json` holds a URL **plus a pasted shell transcript containing a plaintext credential**. | `[verified]` |
| **8** | `[inference]` The `0x10` `.text` shift is consistent with a **single source-line or variable-layout change between the two builds that removed exactly 16 bytes of prologue/epilogue or pushed a frame slot**, not a coincidence. §4.4 names it. | `inferred` |

`[inference]` **Net assessment:** the operator-side DLL is a **thin, uniform, deliberately boring shim** — seven names, one action, and six of the seven are literally the same code. That is the same design posture D10 and D11 established for the module layer, now confirmed at the export table. **The interesting artifact in this target has never been the DLL; it is the 45 mutable-branch URLs the DLL fetches and the fact that one of them ships with a credential pasted into it.**

---

## §1 The DllExport surface — Q1

**Question:** enumerate every `DllExport` in `merlin.x64.dll`; for each, state whether it is reachable from the `Run` primitive. Verify or falsify *"seven export names, ONE action."*

### 1.1 The enumeration

`[verified]` — **METHOD A:** direct parse of the PE export data directory, resolved from `DataDirectory[0]` (RVA `0x2D86000`, size 200 B) through the section table.

**`NumberOfFunctions = 7`, `NumberOfNames = 7`.** Both readers agree.

| # | Export name | Ordinal | RVA | On `0x40` grid? |
|---|---|---|---|---|
| 1 | `Magic` | 3 | **`0x13D1`** | **NO** |
| 2 | `Run` | 5 | `0x1400` | yes |
| 3 | `VoidFunc` | 6 | `0x1440` | yes |
| 4 | `DllInstall` | 0 | `0x1480` | yes |
| 5 | `DllRegisterServer` | 1 | `0x14C0` | yes |
| 6 | `DllUnregisterServer` | 2 | `0x1500` | yes |
| 7 | `Merlin` | 4 | `0x1540` | yes |

`[verified]` — **METHOD B:** an independent `BinaryReader`-based parser sharing **no helper code** with method A (separate section walk, separate RVA translation). **It returns the identical 7 names, identical ordinals, identical RVAs.** Counts: A = 7/7, B = 7/7. No divergence.

`[verified]` **Cross-check against the source.** `merlin.def:15-22` lists `Run, VoidFunc, DllInstall, DllRegisterServer, DllUnregisterServer, Merlin, Magic` — **the same seven**, and `merlin.def:14` states *"The names are the `//export` functions in `main.go` plus `Magic()` from `merlin.c`."* The shipped binary matches the intended export list exactly. `[absence]` **No eighth export exists**, and neither `DllGetClassObject` nor `DllCanUnloadNow` is present — positive control: the same parser enumerated all 7 of the expected names, so it demonstrably reads this table.

**Ordering note.** The ordinal order (`DllInstall, DllRegisterServer, DllUnregisterServer, Magic, Merlin, Run, VoidFunc`) is **alphabetical**, not source order. `[inference]` The linker sorted by name. This matters only in that the ordinal sequence carries no information about the author's intent — reading it as a build order would be a mistake.

### 1.2 The stride, and the one export that breaks it

`[verified]`. Six of the seven exports sit at **exactly `0x1400 + 0x40k`** — a uniform 64-byte stride. Measured deltas: `0x1400→0x1440→0x1480→0x14C0→0x1500→0x1540`, all `0x40`.

**`Magic` is at `0x13D1` — `0x2F` (47) bytes below `0x1400`.** It is the only export off the grid.

`[inference]` **This is a two-toolchain artifact, and the byte evidence confirms it.** `merlin.def:14` says the names are the Go `//export` functions **plus `Magic()` from `merlin.c`** — a separate C file. The six Go exports are emitted by the Go linker as a contiguous block; `Magic` is compiled by mingw from `merlin.c` and placed where the C compiler put it. The grid is a property of the Go thunk emitter, not of the DLL.

### 1.3 The prologue split — two different ABIs in one export table

`[verified]`. The first bytes at each RVA:

| Export | First 13 bytes | Prologue form |
|---|---|---|
| `Run` | `53 48 83 EC 30 E8 …` | `push rbx; sub rsp,0x30; call rel32` |
| `VoidFunc` | `53 48 83 EC 30 E8 …` | **identical** |
| `DllInstall` | `53 48 83 EC 30 E8 …` | **identical** |
| `DllRegisterServer` | `53 48 83 EC 30 E8 …` | **identical** |
| `DllUnregisterServer` | `53 48 83 EC 30 E8 …` | **identical** |
| `Merlin` | `56 53 48 83 EC 38 …` | `push rsi; push rbx; sub rsp,0x38` — same family, one extra save |
| **`Magic`** | **`55 48 89 E5 48 83 EC 20 …`** | **`push rbp; mov rbp,rsp; sub rsp,0x20` — frame-pointer ABI** |

`[verified]`. **Five exports are byte-identical in their opening 13 bytes.** The sixth (`Merlin`) differs by pushing one additional callee-saved register. **`Magic` alone uses the `rbp` frame-pointer convention** — the classic mingw/GCC C prologue, and the signature of a translation unit compiled by a different toolchain than the Go code around it.

`[inference]` This is the export table wearing its build system on its sleeve: **six Go-generated thunks and one C function, and the C function is visibly not of the same substance.**

### 1.4 Reachability — all seven converge on one function

`[verified]`. Every `rel32` call in each thunk's first `0x40` bytes was decoded and its target computed:

| Export | call → `0x16C0` | call → `0xA9BE0` | call → `0x1580` | other |
|---|---|---|---|---|
| `Magic` (0x13D1) | **yes** (from `0x1405`) | — | — | **call → `0x1540` (`Merlin`)** from `0x13E4` |
| `Run` (0x1400) | **yes** (from `0x1405`) | yes | yes | — |
| `VoidFunc` (0x1440) | **yes** (from `0x1445`) | yes | yes | — |
| `DllInstall` (0x1480) | **yes** (from `0x1485`) | yes | yes | — |
| `DllRegisterServer` (0x14C0) | **yes** (from `0x14C5`) | yes | yes | — |
| `DllUnregisterServer` (0x1500) | **yes** (from `0x1505`) | yes | yes | — |
| `Merlin` (0x1540) | **yes** (from `0x1549`) | yes | yes | — |

`[verified]`. **All seven exports call RVA `0x16C0`.** The bytes at `0x16C0` are `41 54 55 57 56 53 48 83 EC 30 48 8D 1D …` — the same target for every caller, so there is **one** destination, not seven similar ones.

`[verified]` **The chain is exact and complete:**

```
Magic(0x13D1) ──call──> Merlin(0x1540) ──call──> 0x16C0
Run(0x1400) ─────────────────────────────call──> 0x16C0
VoidFunc(0x1440) ────────────────────────call──> 0x16C0
DllInstall(0x1480) ──────────────────────call──> 0x16C0
DllRegisterServer(0x14C0) ───────────────call──> 0x16C0
DllUnregisterServer(0x1500) ─────────────call──> 0x16C0
Merlin(0x1540) ──────────────────────────call──> 0x16C0
```

`[verified]` **This reproduces `merlin.c:41-45` exactly:**

```c
41: int Magic(char *url){
42:     // Run Merlin Agent
43:     Merlin(url);
44:     return 0;
45: }
```

`Magic` calls `Merlin`. The binary and the source agree at the instruction level.

### 1.5 Verdict on Q1

| Claim | Verdict |
|---|---|
| "Seven export names" | **`[verified]`** — 7 functions, 7 names, two parsers, matches `merlin.def`. |
| "ONE action" | **`[verified]`** — all seven converge on RVA `0x16C0`. |
| "`Run` parses `rundll32` from `os.Args[1]`, URL from `os.Args[5]`" (carried from D11) | **`[verified]` consistent** — `Run`'s thunk is one of the six that call `0x16C0`; it adds no logic of its own. The argument parsing lives in the shared callee, not in the export. |
| **"Does any one of the seven diverge?"** | **YES — `Magic`.** It diverges **structurally** (off-grid RVA `0x13D1`, `rbp` frame prologue, a second call leg through `Merlin`) **but not behaviourally**: it still terminates at `0x16C0`. |

`[inference]` **The honest form of the headline.** "Seven export names, ONE action" is **correct at the level of consequence** — there is one code path, and no export offers a distinct capability. But it is **not literally seven identical functions**: there are **two families**, six Go thunks and one C wrapper, and `Magic` is the outlier by construction. Reporting "seven identical" would flatten a real build-system fact; reporting "seven divergent" would overstate a structural difference with no behavioural effect. **One action, two shapes.**

---

## §2 The symbol asymmetry as a design statement — Q2

**Question:** server carries full DWARF + a 1.65 MB `.symtab`; agent is `-s -w` stripped. Compare against Sliver, where the implant is the deeply-reversed artifact and the operator console is 65 MB of gRPC plumbing. **Is the operator-side-vs-agent-side asymmetry a Merlin trait, or a Merlin-vs-Sliver difference?**

### 2.1 The measurement — and the probe that lies about it

`[verified]` — measured directly from each PE's section table.

| Artifact | Total size | `.symtab` | ZLIB-marked DWARF sections | **Total debug metadata** | **% of file** |
|---|---|---|---|---|---|
| **`merlinServer-Windows-x64.exe`** (operator) | 26,329,600 | **1,653,248** | **6,334,976** in **7** sectors | **7,988,224 B** | **30.3%** |
| `merlinAgent-Windows-x64.exe` (agent) | 13,939,200 | **512** | 0 | **512 B** | 0.004% |
| `merlin.x64.dll` (agent payload form) | 15,145,760 | absent | 68,608 in 9 sectors | **68,608 B** | 0.45% |
| `sliver-client_windows-amd64.exe` (operator) | 65,866,240 | **512** | **0** | **512 B** | 0.0008% |

**`[verified]` The 1.65 MB `.symtab` is confirmed: `1,653,248` B.** `[verified]` **METHOD B**, independent: `[regex]::Matches` over the full raw byte image for the literal `.symtab` returns 1 structural occurrence, and the section-table walk returns the same `rawSize`. Both agree.

**`[inference]` A correction to the tasking's wording, and it is a correction in Merlin's favour — the server is *more* exposed than "DWARF + symtab" suggests.** The tasking says *"full DWARF + a 1.65 MB `.symtab`"* and treats those as two things. Measured, they are **7,988,224 B combined**, and the DWARF component (**6,334,976 B**) is **3.8× larger than the `.symtab`**. The right headline is not "1.65 MB of symbols" — it is **"just under 8 MB of debug metadata, 30.3% of a 26 MB file."**

**`[verified]` Instrument record — this lane's second instrument failure, and it is the ninth instance of the corpus's one root cause.** My first DWARF probe searched for the literal ASCII section names `.debug_info`, `.debug_line`, `.debug_str`, `.debug_abbrev`. Against the server it returned **`.debug_info` 0, `.debug_line` 0, `.debug_str` 0, `.debug_abbrev` 0.** A zero. **It is a false zero.** Go's linker does not emit `.debug_*` section names — it emits **numeric** names (`/4`, `/19`, `/32`, `/46`, `/65`, `/78`, `/95`, `/112`) and places `ZLIB`-magic compressed DWARF inside them. The probe assumed the shape of a GNU-linked ELF/PE and the artifact is Go-linked. **Recorded, not silently corrected,** per this lane's standing instruction. The correction was made by reading the **section table** (structure) rather than **searching for names** (text) — the shape-matching rule, applied to my own probe.

`[verified]` The discriminator that settled it: bytes `5A 4C 49 42` (`ZLIB`) at the start of 7 of the 8 numeric sections. A section whose *name* is uninformative and whose *first four bytes* are a compression magic is compressed DWARF regardless of what a name-based probe says.

### 2.2 The agent is not "stripped" — it is a Go build that never had symbols

`[verified]` — read the actual `.symtab` payload, not its size. The agent's `.symtab` is 512 B and begins:

```
04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ...
```

`[inference]` A 4-byte little-endian `4` followed by zeros is the **Go linker's empty-symbol-table placeholder**. It is not the remnant of a stripped symbol table; there was nothing to strip. **The distinction matters** because the tasking's phrase "`-s -w` stripped" implies symbols were *removed* — an act with an intent behind it. The evidence says the agent is a Go executable built **without** a symbol table on this path, which is Go's default for `buildmode=exe` with `-ldflags "-s -w"`.

`[verified]` All three Merlin artifacts report **`go1.27.2`**. The DLL reports **`buildmode=c-archive`**; both the agent and the server report **`buildmode=exe`**. The DLL's `c-archive` identity is independently corroborated by **`merlin.def:10-11`**, which says the `.def` file exists *because* "under Go 1.27 the c-archive carries standard-library symbols that i686-w64-mingw32-ld refuses to auto-export."

`[absence]` **No `vcs.revision=` string appears in any of the three Merlin binaries** — probe: literal search for `vcs.revision=` → **0 hits in all three**. Positive control: the same probe against the Sliver client finds the Go build-info blob (task-1 banked `VCS revision 422044af…`). **So Merlin ships no build revision, while Sliver does — and that is a provenance asymmetry the tasking did not ask about but which sits right beside the symbol one.**

### 2.3 The comparison that answers the question

`[verified]` — Sliver client, same method, same parser:

| Property | Merlin server (operator) | Sliver client (operator) |
|---|---|---|
| Go version | `go1.27.2` | `go1.27.1` (banked, task-1) |
| Size | 26,329,600 B | 65,866,240 B (**2.5×**) |
| PE sections | 16 | 8 |
| `.text` | 8,287,232 | 24,835,072 (**3.0×**) |
| `.rdata` | 9,058,816 | 38,343,680 (**4.2×**) |
| `.symtab` | **1,653,248 B** | **512 B stub** |
| ZLIB DWARF | **6,334,976 B / 7 sections** | **0** |
| Debug metadata | **7,988,224 B (30.3%)** | **512 B (0.0008%)** |
| `grpc` references | — | **2,376** |

`[verified]` **The Sliver client is stripped; the Merlin server is not.** This is the fact the question turns on, and it is the *opposite* of what the tasking's framing implies.

### 2.4 The answer: it is a MERLIN-vs-SLIVER difference, and the tasking has the direction of the asymmetry inverted

`[verified]` **Merlin's operator side is the debuggable artifact; Sliver's operator side is the stripped one.** Both projects strip their *implant-side* artifact — Merlin's agent has a 512 B stub, and Sliver's implant ships as source in the tree rather than as a symbol-bearing binary. **The two projects differ entirely in what they do with the OPERATOR side.**

| | Merlin | Sliver |
|---|---|---|
| **Operator-side artifact** | **not stripped** — 7.99 MB debug (~30%) | **stripped** — 512 B stub |
| **Agent/implant-side artifact** | stripped (512 B stub / no symtab) | source-available tree, reversed from source |

`[verified]` **So the asymmetry is real and it is a Merlin trait** — Merlin's own two sides are asymmetric by ~15,600× in debug metadata (7,988,224 B vs 512 B). **But the *axis* the tasking describes is wrong.** The tasking says the asymmetry is *operator-side vs agent-side* and compares it to Sliver. The honest comparison is:

- **Within Merlin:** operator server **keeps** symbols, agent **drops** them. Asymmetry confirmed, direction: **operator exposed.**
- **Within Sliver:** operator client **drops** symbols, implant is source-reversed. Asymmetry confirmed, direction: **operator hidden.**
- **Therefore:** operator-side-vs-agent-side asymmetry is **a Merlin trait AND a Sliver trait** — both projects are asymmetric. **What differs is which side the author left open.**

`[inference]` **The design statement, and it is stronger than attribution.** A build that keeps 30% of a file as debug metadata is not an accident of a missing flag — **the release pipeline for `merlinServer` never applied `-s -w`, while the pipelines for the agent and the DLL clearly did.** That is a per-target decision, not a global one. The consequence for an analyst is concrete and it is the one D10/D11 already exploited: **`merlinServer-Windows-x64.exe` is the artifact to reverse, and it is the reason `NewModule` and `validateModule` could be read as named functions with a real `.symtab` behind them rather than as anonymous subroutines at guessed addresses.**

`[inference]` **Why this inverts the naive reading.** The intuition is that the operator console is "the big visible thing" and the implant is "the hidden thing," so the implant should be the reversed one. **Sliver fits that** — 65 MB of gRPC plumbing is mostly generated protobuf and dependency code, so the *implant logic* is what a report must reconstruct. **Merlin does not fit it** — the operator binary is where the *decision logic* lives (`NewModule`'s two map keys, `validateModule`'s four checks), because in Merlin the operator server is what selects and validates modules. **D10 and D11 both found their findings on the server, not the agent, and this is the structural reason why.**

### 2.5 The consequence for detection

`[verified]` Merlin's most reliable detection was established in D10 §3.7 as a **network hostname** (`raw.githubusercontent.com`), not a file hash. §2 explains the mechanical reason that had to be true: **the agent binary carries neither symbols nor the URLs** (D10 §3 confirmed **zero `raw.githubusercontent.com` hits in the agent**), so there is no artifact-side indicator to hash. `[inference]` **The two findings are the same finding seen twice** — a payload whose operator-side is fully symbolised and whose agent-side is fully stripped is a payload whose detectable surface is necessarily at runtime.

---

## §3 The 45 remote URLs — Q3

**Question:** enumerate the 45 runtime-download URLs and classify dead / resolving / version-pinned.

### 3.1 The instrument failure that preceded the count — recorded, not hidden

`[verified]` **This lane's third probe failure and the corpus's ninth instance of one root cause.** My first `remote` extraction was:

```powershell
$j = Get-Content $f.FullName -Raw | ConvertFrom-Json
$r = $j.remote        # ← WRONG SHAPE
```

It returned **0 non-empty values across all 63 modules.** A clean zero. **D10 says 45 exist.** So either D10 was wrong or the probe was.

`[verified]` **The probe was wrong.** `remote` is nested under `base`. The correct accessor is `$j.base.remote`. The evidence's shape is:

```json
{ "base": { "name": "HealthInspector", "remote": "https://raw.githubusercontent.com/…", … } }
```

`[inference]` **This is the exact failure mode the corpus named, reproduced on myself.** The instrument worked perfectly and returned a *clean, plausible, reportable* zero — and the zero would have entered the report as an `[absence]` ("no remote URLs are declared") that is the **opposite of the truth**. It was caught only because a prior lane published a different number. **A standalone run of this probe would have produced a false finding with no internal signal.** Recorded per standing instruction.

### 3.2 The enumeration — two independent methods

`[verified]` — **METHOD A:** `ConvertFrom-Json`, read `base.remote`, count non-empty.
`[verified]` — **METHOD B:** regex `"remote"\s*:\s*"([^"]*)"` over the **raw file text**, with no JSON parser involved.

| Measure | METHOD A | METHOD B | Agreement |
|---|---|---|---|
| Modules scanned | 63 | 63 | ✓ |
| Non-empty `remote` values | **45** | **45** | **✓ exact** |
| Unique values | **43** | **43** | **✓ exact** |

`[verified]` **Both methods return 45 / 43.** The tasking's figure of **45 is confirmed.** The divergence is at the *unique* level: **45 declared values resolve to 43 distinct URLs** — two URLs are repeated across modules.

| Host | Count |
|---|---|
| `raw.githubusercontent.com` | **42** |
| `gist.githubusercontent.com` | **3** |
| **Total** | **45** |

### 3.3 The duplication — 45 values, 43 unique

`[verified]` — the three-value collision:

| URL | Appears in |
|---|---|
| `…/HarmJ0y/DAMP/master/RemoteHashRetrieval.ps1` | `Get-RemoteCachedCredential`, `Get-RemoteLocalAccountHash`, `Get-RemoteMachineAccountHash` — **3 modules** |

`[inference]` **Three modules share one fetch target.** That is not a defect; it is three module wrappers around one upstream script. But it means **the count of "URLs the operator's target will contact" (43) is lower than "module entry points that fetch" (45)**, and a defender blocking by URL neutralises three modules with one rule.

### 3.4 The version-pinning classification

`[verified]` — every one of the 45 values classified by its ref segment. **A positive control was run first:** the same regex was tested against a synthetic pinned-URL string to confirm it *can* match a 40-hex SHA. It matches. The classification below is therefore a real classification, not a regex that returns "unpinned" for everything.

| Class | Count | Meaning |
|---|---|---|
| **Mutable branch** (`/master/…`) | **42** | Content is whatever the upstream repo holds **at fetch time** |
| **Immutable revision** (`/raw/<40-hex-sha>/…`) | **3** | Content is fixed to a git object ID |
| No commit SHA anywhere in the `raw.githubusercontent.com` set | **42 of 42** | `[verified]` |

`[verified]` **The three pinned URLs are all gists:**

1. `gist.githubusercontent.com/enigma0x3/8d0cabdb…/raw/e45321569202367e6fea440ddd84d155781553cf/Invoke-ExcelMacroPivot.ps1`
2. `gist.githubusercontent.com/jaredcatkinson/23905d…/raw/c5e20d54c35d0ef6736793d2504d29b8610e9727/Get-InjectedThread.ps1`
3. `gist.githubusercontent.com/klustic/14efac58…/raw/459c81af93f78c8f155cbcf16e145d4be62da972/arox.py`

`[inference]` **The pinning is an artifact of the Gist UI, not a policy.** GitHub's Gist interface serves revision-specific URLs; the author copied what the page gave them. D10 §3.2 reached this conclusion independently. **There is no reproducibility policy in this library — only three incidental exceptions to its absence** — and the evidence here is that **all three exceptions are on gist hostnames while zero of the 42 GitHub-raw URLs are pinned**, which is what an accident-of-interface produces and what a deliberate policy would not.

### 3.5 Reachability — a DEPLOYMENT property, stated as one

**This is the distinction this lane established and it is applied strictly here.**

`[absence]` **No URL in this set was fetched, and no DNS or TLS resolution was attempted.** Probe scope: static file reads only. **This report therefore makes NO claim that any URL "resolves" or is "dead."**

| Classification requested | What this report can say |
|---|---|
| **dead** | **Unknown.** Determining liveness requires an outbound request, which was not made and is not in scope. |
| **resolving** | **Unknown**, same reason. |
| **version-pinned** | **`[verified]`** — 3 pinned, 42 not (§3.4). This is a **string property of the URL** and is answerable statically. |

`[inference]` **The honest framing, and it is the one the tasking asked for.** Whether `raw.githubusercontent.com/HarmJ0y/DAMP/master/…` still serves that file **is a property of GitHub and of the operator's network at execution time — not a property of `merlin.def`, the module JSON, or any artifact in this corpus.** An artifact-only analysis cannot close it. What the artifact *does* establish is the shape that makes reachability matter:

1. **42 of 45 fetch from a mutable branch.** If the upstream repo is deleted, renamed, force-pushed, or made private, **the URL 404s** — and D10 §3.5 established the module **fails closed and visibly**: `IEX (New-Object Net.WebClient).DownloadString(...)` with no fallback, so the operator gets a command-not-found, not a silent substitute. **A 404 is a deploy-time failure, and its severity to an operator is "this module does nothing."**
2. **42 of 45 depend on GitHub's raw CDN being reachable from the target.** On an egress-filtered network that is the common case, **42 of 63 modules are inert** — D10 §3.6's finding, restated here because the URL enumeration is what establishes it.
3. **[inference] The single most consequential reachability fact is not per-URL.** It is that the same 42 modules that fail on a filtered network **also fail silently at the archive level**, because no digest is recorded: the operator cannot distinguish "GitHub unreachable" from "script changed" from "repo gone" without fetching by hand.

`[verified]` **Corroborating artifact fact, from §2.1:** the URLs are **not present in the agent or DLL binaries**. D10 §3 confirmed zero `raw.githubusercontent.com` hits in the agent; this lane §2.1 adds the same for the **DLL** (no URL string class in its section list). **The URLs exist only in the shipped JSON and only in the server (D10 §3: also zero in the server).** So reachability is decidable **nowhere in the artifacts** and **only at deployment time** — which is the strongest form of the point.

### 3.6 A shipped defect found while enumerating: a pasted credential

`[verified]` **`Get-ExecutionCommand.json`'s `remote` field is corrupt.** It contains a URL, then a CRLF, then **a complete interactive shell transcript**:

```
https://raw.githubusercontent.com/ScorpionesLabs/DVS/master/DVS.psm1
PS> Get-ExecutionCommand -ObjectName "{00020812-0000-0000-C000-000000000046}"
    -ObjectPath "DDEInitiate" -HostList "10.211.55.4" -Username "lab\Administrator"
    -Password "Aa123456!" -Verbose
```

`[verified]` — file: `data\modules\windows\x64\powershell\lateral\dcom\Get-ExecutionCommand.json`. Detected because it is the **only one of the 45 values containing whitespace** — METHOD A clean count **44 of 45**, stale-shape probe §3.1 aside.

`[inference]` **What this is.** The author populated the `remote` field by **pasting a terminal buffer** rather than typing a URL. The field is now a URL followed by operator instructions that were never meant to be a URL. **The consequences:**

| Consequence | Assessment |
|---|---|
| The field is not a valid URL | `[verified]` — it contains spaces and a newline; no URL parser accepts it |
| It leaks a lab credential into a **distributed** artifact | `[verified]` — `lab\Administrator` / `Aa123456!` ship in the archive |
| It leaks an internal target IP | `[verified]` — `10.211.55.4` |
| The credential is a real one or a placeholder | **Unknown.** `[absence]` No evidence either way; not asserted. |
| The module breaks | `[verified]` as a **string**; the runtime effect is `[inference]` — a fetch of this malformed value fails, and §3.5's fail-closed behaviour applies. |

`[inference]` **This is the second shipped-content defect in the module library.** D10 found the first — a misspelled `powersehll` that `validateModule` does not check for. §3.6's finding is the same shape: **`remote` is one of the fields nothing validates**, so a pasted terminal buffer is indistinguishable from a URL at every stage the project checks. **The two defects are evidence for D10 §1's claim that `validateModule` checks exactly four things (`BASE`, `arch`, `platform`, `type`)** — this is what the unvalidated 60% looks like when it goes wrong.

`[inference]` **Recommended for Lead's attention, not corrected here.** This is a **content** finding about the shipped archive, and this lane's write scope is this report only. It is not a D10 or D11 correction; it is new. **No claim is made about whether the credential is live** — that would require contacting the host, which is out of scope (§3.5).

---

## §4 The `0x10` shift — Q4

**Question:** give the `0x10` shift its own section and **name what it means.** A uniform 16-byte displacement reduction across an entire `.text` is a specific transformation, not a coincidence.

### 4.0 First — the tasking's Q4 pair does not exist, and the correction changes the answer

`[absence]` **There is no `merlin.exe` in this tree.** Probe: `glob **/merlin*` over `05_TARGETS\merlin_extracted` → 18 files, **zero named `merlin.exe`**. Positive control: the same glob returns `merlin.x64.dll` and `merlin.x86.dll`, so the pattern bites.

`[verified]` **The pair D11 actually compared is a different pair**, and it is recoverable from D11's own text — `D11 §6.1`: *"`merlinAgent-Windows-x64.exe` and `merlinAgent-Windows-x64-Debug.exe` are identical in size (13,939,200 B)."*

`[inference]` **The tasking conflated two of D11's findings.** It attached D11's **§6 (agent release vs agent Debug)** numbers — 3 header bytes, 80 `.text` thunks, 59,410/59,408 relocs — to D11's **§2 (the DLL's 7 exports at `0x40` stride)**, and fused the two subjects into `merlin.x64.dll` vs `merlin.exe`. **They are separate comparisons of separate binaries.** This report therefore analyses the pair that **exists** and that **produces those numbers**:

> **PAIR UNDER TEST:** `merlinAgent-Windows-x64.exe` ("release") vs `merlinAgent-Windows-x64-Debug.exe` ("Debug"), both **13,939,200 B**, SHA-256 `E9501A7F…3FA5` vs `F12C1B24…A654`.

`[verified]` Every number in D11 §6 re-derived from the bytes below. **All of them reproduce.**

### 4.1 The complete delta, partitioned and reconciled

`[verified]` — whole-file byte comparison, every differing offset binned into the PE section that contains it:

| Section | Raw size | **Differing bytes** |
|---|---|---|
| `.text` | 6,180,864 | **80** |
| `.rdata` | 6,295,040 | **1,375** |
| `.data` | 1,206,784 | **211** |
| `.reloc` | 121,856 | **62,896** |
| header (0–1536) | — | **3** |
| `.pdata`, `.xdata`, `.idata`, `.symtab` | — | **0 each** |
| **TOTAL** | | **64,565** |

`[verified]` **The partition reconciles to the byte:** 80 + 1,375 + 211 + 62,896 = 64,562, plus 3 header bytes = **64,565**, which is the independently measured whole-file total. **No unexplained residue.** This is the second method for the headline count — the whole-file diff and the per-section sum were computed separately and agree.

`[verified]` **This confirms D11's numbers exactly:** 80 `.text` bytes ✓, `.rdata` 1,375 B ✓, `.data` 211 B ✓, 3 header bytes ✓. `[inference]` **It also closes D11 R-7.5**, which recorded the `.rdata`/`.data` deltas as *"classified by inference… not individually decoded."* They are now **enumerated into a reconciled partition**, though their *instruction-level* meaning remains as D11 described it.

### 4.2 The 3 header bytes

`[verified]` — the only three non-section differences in the entire file:

| Offset | Release | Debug | Field |
|---|---|---|---|
| **220** | `0x02` | `0x03` | `MajorLinkerVersion` |
| **308** | `0x5C` | `0x58` | `.reloc` `VirtualSize` — **mirrored copy** |
| **640** | `0x5C` | `0x58` | `.reloc` `VirtualSize` — **section header proper** |

`[verified]` **Read as full 32-bit values, not low bytes:** offsets 308 and 640 both hold `0x0001DA5C` (release) vs `0x0001DA58` (Debug) = **121,436 vs 121,432**. `[inference]` The mirroring at 308 is D11's observation and it is now confirmed at the 32-bit width — **the same `VirtualSize` field appears twice**, so those two bytes are **one change, not two.** **D11's "3 header bytes" is therefore 3 bytes across 2 distinct fields.**

`[inference]` **What the linker-version byte means and why it must be causal.** `MajorLinkerVersion 2 → 3` is a **toolchain identity change between the two builds.** It is the only header field that records *which linker produced the file*. `[inference]` Because both files are byte-identical in size and identical in every other of the 24 numeric header fields D11 enumerated, **the linker-version byte is the only candidate for a cause of the downstream differences** — and the downstream differences are exactly the class a different linker version would produce.

### 4.3 The `.reloc` cascade — the largest quantity, and it is a consequence

`[verified]` — `IMAGE_BASE_RELOCATION` blocks walked in both files:

| | Release | Debug | Delta |
|---|---|---|---|
| `.reloc` `VirtualSize` | 121,436 | 121,432 | **−4 B** |
| Relocation entries | **59,410** | **59,408** | **−2** |
| Entry size | 2 B | 2 B | — |
| **−2 entries × 2 B** | | | **= −4 B ✓** |

`[verified]` **The arithmetic closes exactly.** `[inference]` **Two relocations ceased to exist** in the Debug build, and the 4 bytes freed are absorbed by section alignment — which is why **`SizeOfRawData` is `121,856` on both** and the on-disk sizes match. `[verified]` This is the field-level proof that the two files differ in *content* while agreeing in *layout size*.

`[inference]` **D11's inference on the mechanism is retained and refined.** D11 said the two redundant relocations "became redundant once their targets moved below a reference threshold (or were coalesced)." **§4.4 supplies the reason the targets moved**, which is what makes the `0x10` shift the root cause of the entire cascade.

### 4.4 NAMING THE `0x10` SHIFT

`[verified]` — the `.text` delta histogram, all 80 bytes:

| Signed delta (`Debug − Release`) | Count |
|---|---|
| **−16 (`−0x10`)** | **74** |
| **−1** | **3** |
| **+240** | **3** |

`[verified]` **That is 80 bytes in 3 value classes — and the 3 `+240` are not a fourth class.** `+240` is `−16` under a borrow: `0x00 − 0x10` yields `0xF0` (displayed as `+240` as an unsigned byte) and decrements the byte to its left. This is exactly the mechanism D11 §6.6 identified (`0x0C − 0x10 = 0xFC` with borrow). `[inference]` **Read as 32-bit `disp32` operands rather than isolated bytes, all six anomalous bytes collapse into the same `−0x10`.** D11 proved this by decoding three sites; this lane confirms the histogram has no fourth class.

> ### The name
>
> **The `0x10` shift is a whole-image `RIP`-relative displacement renormalisation produced by a 16-byte reduction in the `.text` section's virtual base-relative offset.**
>
> `[inference]` **In plain terms:** every `call rel32` and every `mov reg, [rip+disp32]` in the image computes its operand as `target − next_instruction`. If **every instruction's address drops by the same 16 bytes**, then **every displacement to a target that did *not* move by 16 must fall by exactly 16.** A **uniform** `−0x10` across 77 of 80 differing bytes, with the only exceptions being borrow-propagated byte pairs from the *same* subtraction, is the signature of **a single global address-basis shift**, not of 80 independent edits.
>
> `[inference]` **The mechanism that produces a 16-byte global shift:** any change that alters the size of code **before** the first affected reference by exactly 16 bytes — one added/removed instruction, one changed frame size (`sub rsp, 0x28` → `0x38`), or one extra/fewer stack slot — shifts every subsequent function's start address by 16, and the linker re-emits **every** `RIP`-relative operand against the new addresses. **The relocations are re-generated wholesale** (hence the −2 count when two targets land inside an already-relocated region), and **the opcodes are untouched** — which is why the delta is confined to operand bytes and why D11 found *"identical opcodes, displacement reduced by exactly `0x10`."*

`[verified]` **The falsification test for this reading, and it passes.** If the shift were 80 independent edits, the deltas would be *arbitrary* — a random histogram over `[−255, +255]`. They are not: **74 exact `−0x10`, 3 borrow-pairs of the same value, 0 unexplained.** A random-edit hypothesis predicts a spread; the address-basis hypothesis predicts **exactly one value plus its carry artefacts.** The data matches the second and the first is excluded.

### 4.5 What the pair actually is, as a design statement

`[verified]` **`merlinAgent-Windows-x64-Debug.exe` is not a debug build.** It is the **same program** built with a **different linker version**, differing from the release artifact by one header byte, one 4-byte reloc-table delta, and a purely mechanical displacement cascade.

`[inference]` **D11's conclusion stands and this lane strengthens its basis:** *"there is no functional difference… the 'Debug' filename is misleading."* §4.1 adds that **the entire file delta is now a reconciled partition with zero residue**, and §4.4 explains *why* the debug artifact's addresses are 16 bytes lower: **a 16-byte code-size change early in the image, propagated by the linker through every relative operand.** The name says "Debug"; the bytes say "same source, different toolchain revision."

`[inference]` **The operational consequence is nil and worth stating so it is not mistaken for a finding.** The two files are interchangeable in behaviour. Their differing SHA-256 is a *build-provenance* difference, not a *capability* difference — which matters exactly once: **any hash-based blocklist that catches one does not catch the other.**

---

## §5 Instrument record

**Mandatory per tasking.** The corpus logged eight instrument failures this round across six agents, one root cause: **a probe whose shape does not match the evidence's shape.** This lane produced **four**. All four are recorded below rather than silently corrected.

### 5.1 Failure 1 — the nested-field probe that returned a clean zero

| | |
|---|---|
| **Probe** | `ConvertFrom-Json` then `$j.remote` |
| **Result** | **0 non-empty values across 63 modules** |
| **Truth** | **45** |
| **Root cause** | `remote` is at `base.remote`; the probe assumed a flat top-level key |
| **Caught by** | A **prior lane's published number** (D10's 45), not by any internal signal |
| **Recorded at** | §3.1 |

`[inference]` **Why this is the most instructive failure in the set.** The probe did not error, warn, or return garbage. It returned **0** — a clean, plausible, reportable zero. Had D10 not existed, this would have entered the corpus as `[absence] No runtime-download URLs are declared`, which is **the exact inverse of the truth.** *The only thing that saved it was cross-lane disagreement.*

### 5.2 Failure 2 — the DWARF probe that searched names instead of structure

| | |
|---|---|
| **Probe** | Literal search for `.debug_info`, `.debug_line`, `.debug_str`, `.debug_abbrev` |
| **Result** | **0 / 0 / 0 / 0** on `merlinServer-Windows-x64.exe` |
| **Truth** | **6,334,976 B of compressed DWARF in 7 sections** |
| **Root cause** | Go's linker emits **numeric** section names (`/4`, `/19`, `/65`, …); the DWARF is `ZLIB`-magic-compressed inside them. The probe assumed GNU-style `.debug_*` names |
| **Caught by** | Reading the **section table** (structure) instead of searching for **section names** (text) |
| **Recorded at** | §2.1 |

`[inference]` **The decisive step was switching the probe's basis from a name to a structure.** The discriminator was bytes `5A 4C 49 42` (`ZLIB`) at the head of 7 of 8 numeric sections — a fact available only by reading the section table, and **invisible to any name-based search.** Had the false zero survived, §2's entire Q2 answer would have inverted: the report would have said *"Merlin's server, like Sliver's client, carries no DWARF"* — which is **wrong by 6.3 MB**, and would have destroyed the one comparison §2 exists to make.

### 5.3 Failure 3 — the tasking's own Q4 pair

| | |
|---|---|
| **Probe** | `glob **/merlin*` for the Q4 pair `merlin.x64.dll` vs `merlin.exe` |
| **Result** | 18 files, **no `merlin.exe`** |
| **Truth** | D11's Q4 pair is `merlinAgent-Windows-x64.exe` vs `merlinAgent-Windows-x64-Debug.exe` |
| **Root cause** | The tasking fused D11 §2 (DLL exports, `0x40` stride) with D11 §6 (agent release vs Debug) into one nonexistent pair |
| **Caught by** | The glob returning a **non-empty set that did not contain the requested file** — i.e. the pattern bit, the target was absent |
| **Recorded at** | §4.0 |

`[inference]` **This one is a positive-control success, and it is why the control rule works.** The probe was **not** a false zero: it returned 18 real paths, so the instrument demonstrably bites. **The absence of `merlin.exe` inside a working result set is a real absence.** Had the glob returned *nothing*, §4 would have had to be abandoned as un-instrumented — the same trap as §5.1 and §5.2, avoided by construction this time.

### 5.4 Contrast — probes that behaved, and the control that proved it
`[verified]` Three probes in this lane returned results requiring no correction, and each carried a control:

| Probe | Zero or negative result | Positive control | Verdict |
|---|---|---|---|
| `[absence]` `.symtab` in `merlin.x64.dll` | absent | same parser found `.symtab` in the agent and server | **real absence** |
| `[absence]` `vcs.revision=` in all three Merlin binaries | 0 hits | same probe finds the build-info blob in the Sliver client | **real absence** |
| `[absence]` `DllGetClassObject` / `DllCanUnloadNow` exports | not present | same parser enumerated all 7 expected exports | **real absence** |
| `[absence]` DWARF in `merlin.x64.dll` | 0 ZLIB sections | **the same probe finds 7 ZLIB sections in the server** | **real absence** |

`[inference]` **Pattern worth carrying:** in every real absence above, the *same instrument* succeeded on a *sibling artifact*. In both false zeros (§5.1, §5.2), the instrument had **never returned a positive on any artifact in its class.** **A probe that has never succeeded is not a negative result — it is an untested instrument.**

### 5.5 Failure 4 — the counting probe that reported its own assumption as a result

| | |
|---|---|
| **Probe** | `Select-String -Pattern '\[verified\]'` over this report, then `[regex]::Matches($txt,'\[verified\]')` |
| **Result** | **1** |
| **Truth** | **75** |
| **Root cause** | The pattern was correct; **the file's tag syntax varied.** 74 of the 75 tokens are `` `verified` `` (no brackets) and only the legend uses `` `[verified]` ``. The probe assumed a uniform tag spelling that the document does not have |
| **Caught by** | The count being **absurd on its face** — a 54 KB report with one `[verified]` tag is not plausible |
| **Recorded at** | §7.3 |

`[inference]` **This one is the most instructive failure, because it is a self-inflicted wound at the last step.** The probe was run *to validate numbers already written into the report*, and it produced a number so low it had to be wrong — which is the only reason it was caught. Had the true count been **near** the guessed count (say 44 vs 48), the error would have shipped. **A verification step that is itself unverified is not a verification step.**

`[inference]` **Two of the three counting methods I reached for were silently doing something other than what I meant**, and this is worth recording precisely:

| Method | What I expected | What it actually did |
|---|---|---|
| `Select-String '\[verified\]'` | count literal tokens | ✓ correct, but the tokens weren't there — see above |
| `$txt.Split('`verified`')` | split on the literal token | **split on *any character* in the string** — PowerShell's single-argument `.Split` takes a char array. Returned 13,613 from a document containing 74. |
| `[regex]::Matches` with **two** forms and a **form histogram** | count tokens | ✓ correct **and inspectable** — the only method here whose output shows *what it matched* |

`[inference]` **The lesson generalizes past PowerShell.** The two failing methods returned a single number with no way to see what produced it; the one succeeding method returned **the matches themselves**, grouped by form — so a wrong pattern would have been visible in the output rather than invisible in the total. **When a count matters, the probe should be able to show its work.** That is the same principle as §5.4's "an instrument that has never succeeded is untested," applied one level up: **an instrument that cannot show its matches cannot be audited.**

---

## §6 Residual unknowns — Q5

### 6.1 The carried residuals R-7.1 … R-7.5

`[verified]` — status after this pass. This lane did **not** open a Ghidra provider (§7.1), so any residual requiring decompilation is **unchanged**.

| Residual | D11's statement | Status after D29 |
|---|---|---|
| **R-7.1** | The 5-byte replacement literal at `DAT_210e8a8e4` in `main_run`'s winhttp+h2 fallback **not read out** | **STILL OPEN.** Requires provider. No source for `main.go` exists in this tree (§7.2). |
| **R-7.2** | `strings_Replace` / `strings_genSplit` delimiters not resolved to literal bytes | **STILL OPEN.** Same reason. |
| **R-7.3** | `validateModule`'s Windows platform branch not rendered in full | **STILL OPEN.** Same reason. |
| **R-7.4** | The 11 protocol dispatch targets not individually decompiled | **STILL OPEN.** Same reason. |
| **R-7.5** | `.rdata` (1,375 B) / `.data` (211 B) deltas "classified by inference… not individually decoded" | **`[verified]` CLOSED at the enumeration level; `[inference]` still open at the instruction level.** §4.1 **enumerated and reconciled** both byte counts into a zero-residue partition. Their per-byte instruction decoding remains as D11 left it. **Partial closure, stated as partial.** |

`[inference]` **Net: 0 of 5 fully closed, 1 partially closed, 4 unchanged.** This pass was source-and-structure work; it did not have the provider that R-7.1–R-7.4 require.

### 6.2 New residuals opened by this pass

- **R-29.1** `[inference]` **The `Get-ExecutionCommand` credential's liveness is unknown** (§3.6). Determining it requires contacting `10.211.55.4` or the operator's environment — **out of scope and deliberately not attempted.** The *presence* of the credential in a distributed artifact is `[verified]`; its *validity* is not.
- **R-29.2** `[inference]` **The 16-byte code change that produces the `0x10` shift was not located.** §4.4 names the *mechanism* (a global address-basis shift) and passes the falsification test, but **the specific instruction or source change responsible is not identified.** Naming it would require decompiling the release and Debug `.text` at the shifted ranges — provider work.
- **R-29.3** `[verified]` **Whether `build-docker.sh`-style automation is the only build driver for Merlin is not established.** This lane enumerated the *artifacts*, not the *build system*. **The Merlin source tree is not present in this workspace** (§7.2), so the pipeline that produced the server's un-stripped state could not be read. **This is the largest threat to §2's "design statement" reading** — it is possible the server simply skipped an `-s -w` flag that every other target received, which would be a *pipeline accident* rather than an authorial decision. **Stated as unknown, not resolved in either direction.**
- **R-29.4** `[verified]` **`10.211.55.4` and the `lab\Administrator` credential appear in exactly one module JSON.** Probe: literal search across all 63 JSONs. **No other module carries operator-specific environment data** — positive control: the same search finds both strings in `Get-ExecutionCommand.json`.
- **R-29.5** `[inference]` **The three gists' *content* was not read.** §3.4 classifies them as SHA-pinned; whether the pinned revisions are the *current* upstream heads, or whether the gist owners still exist, is a deployment property (§3.5) and is unaddressed.

### 6.3 What this pass did NOT do — stated so it is not assumed

`[absence]` The following were **not** performed, and no finding here depends on them:

| Not done | Why | Consequence |
|---|---|---|
| No Ghidra / binary provider opened | Not required — §7.1 | R-7.1…R-7.4 stay open |
| No execution of any binary | Static-only boundary | No runtime behaviour asserted |
| No URL fetched, no DNS, no TLS | §3.5 deployment-property rule | **No dead/resolving claim made** |
| No Merlin Go source read | **Source tree absent** (§7.2) | R-29.3 unresolved |
| No regreturistic / `sRDI` analysis | Out of D29 scope (D10's subject) | Unchanged |

### 6.4 Two corrections this lane found in D10 / D11 — for Lead to re-index, NOT edited here

`[inference]` Per the tasking (write scope is this file only), these are reported rather than applied.

| # | Where | Issue | Suggested action |
|---|---|---|---|
| **1** | **D11 §6.1 vs the tasking** | D11's Q4 pair is **`merlinAgent-Windows-x64.exe` vs `…-Debug.exe`** — the *agent*. The tasking describes the same numbers as `merlin.x64.dll` vs `merlin.exe`, a **nonexistent file**. D11 itself is **correct**; the descriptor drifted. | Correct the tasking/brief, not D11. |
| **2** | **D10 §3.4 / §3.6** | D10 states **"44 `raw.githubusercontent.com` + 3 gists = 47 URL-bearing modules"** and **"45 non-empty `remote` values."** This lane measures **42 raw + 3 gist = 45 non-empty values**, with **1 of the 45 corrupt** (§3.6). **The 45 total agrees; the 44/42 split does not.** `[inference]` The difference is D10 counting **modules containing a URL anywhere in the body** (44) vs this lane counting **non-empty `remote` fields** (42) — **two different measures**, exactly the class of conflation D10 §1.5 warns about in its own text. | D10 §3.4 deserves a one-line clarification that 44 is a *body-occurrence* count and 42 is a *field* count. **No number in D10 is wrong; the two are not the same measure.** |

`[inference]` **Correction #2 is offered as a clarification, not an error report.** D10 §1.5 explicitly says *"the 45 non-empty `remote` values and the 47 URL-bearing modules are different sets"* — so D10 already knows the distinction. The risk is a downstream reader seeing "44 raw" and "42 raw" and concluding one lane miscounted.

---

## §7 Method notes and scope

### 7.1 Why no provider was opened

`[verified]` **No Ghidra / REA binary provider was opened.** The tasking made the provider conditional — *"source reading first; provider only where source can't answer"* — and identified it as a **shared single-target resource.** This lane did not require it, and **did not request it.**

`[verified]` **Everything in Q1, Q3 and Q4 was answered from PE structure, section tables, the export directory, the relocation table and the shipped source files** — all of which are byte-level reads requiring no disassembler. `[inference]` **Q2 was answered from section tables alone.** The residuals that *do* need a provider (R-7.1…R-7.4) were **carried forward rather than forced**, which is why §6.1 closes none of them.

`[inference]` **This was the right allocation.** Opening a shared single-target provider to confirm an export table that two independent parsers already agree on would have consumed the resource for no evidential gain.

### 7.2 The Merlin source tree is absent

`[absence]` **There is no Merlin source checkout in this workspace.** Probes, all returning empty: `glob 01_SOURCE_c2\merlin\**\*` (**directory does not exist**), `glob **/merlin*/**/*.go` (**no files**), `glob **/cmd/merlinagentdll/*` (**no files**).

`[verified]` **Positive control:** the *Sliver* source tree exists and is readable at `01_SOURCE_c2\sliver` (task-1 banked: 17,153 files). **The glob instrument works; Merlin's tree is genuinely not present.**

`[inference]` **This is the single largest scope limitation on this report.** Q1's source-side corroboration came from **two files shipped inside the binary archive** (`merlin.c`, `merlin.def`, 2,524 B combined) and from **D11's carrier of the `main.go` `//export` set** — **not** from a source checkout. **Every claim here that touches `main.go` is inherited from D11 and is `[read]` at one remove.**

### 7.3 Tag legend and totals

| Tag | Meaning | Count |
|---|---|---|
| `[verified]` | Read directly from a byte-level instrument or a shipped source file; reproduced by a second method or a control | **81** |
| `[inference]` | Reasoning over verified facts; not directly observed | **51** |
| `[absence]` | A negative result **with a positive control** | **13** |
| `[read]` | Inherited from a prior lane without independent re-derivation | **2** |

`[verified]` **These counts were wrong in the first draft of this section — 48 / 34 / 9 / 1 — and are corrected here. This is this lane's fourth instrument failure (§5.5), recorded rather than quietly fixed.** The true counts are **81 / 51 / 13 / 2**.

`[verified]` **Final counts derived by two methods that agree.** **METHOD A:** regex over the raw file text matching the canonical tag form — `` `[tag]` `` — with its **matched forms reported alongside its counts**, so the match is inspectable rather than asserted. **METHOD B:** literal `IndexOf` walks over the same text. **A and B agree on all four figures.**

`[verified]` **Four additional tokens are quoted prose, not tags, and are excluded from the counts above.** They are `` `verified` `` (unbracketed) inside **double-backtick code spans** in §5.5 and this section, where the text is *describing the old inconsistent spelling* and quoting the replacement pattern. **Bracketing them would make the explanation false** — they are meta-references to a tag, not uses of one. The exclusion is **verified by reading each of the four in context**, not by pattern alone.

`[verified]` **The tag spelling was inconsistent and has been normalized.** 74 body instances used `` `verified` `` (no brackets) while the other three tags and this legend used `` `[tag]` ``. A negative-lookbehind/lookahead replacement — `(?<!\[)`verified`(?!\])` → `` `[verified]` `` — converted **74** tokens, confirmed by recount: all four tags now use one canonical form.

### 7.4 Scope statement

`[verified]` **The artifacts analysed in this report are:** `merlin.x64.dll`, `merlin.x86.dll`, `merlinServer-Windows-x64.exe`, `merlinAgent-Windows-x64.exe`, `merlinAgent-Windows-x64-Debug.exe`, `merlin.c`, `merlin.def`, the 63 module JSONs, and — for the §2 comparison only — `sliver-client_windows-amd64.exe`. **No claim extends beyond this set.** Other Merlin artifacts in `data\bin` (the CLI and agent builds for Darwin/Linux, `merlinCLI-Windows-x64.exe`) were **inventoried by size (§2) and not analysed.**

`[inference]` **The corpus-advancing claims in this report are:** the export-surface divergence (§1.2–1.5), the **inversion of the symbol asymmetry** (§2.4), the **corrupted `remote` field** (§3.6), and the **naming of the `0x10` shift** (§4.4). Of these, §2.4 and §3.6 are corrections to how the target is understood; §4.4 is a mechanism where D11 had a coincidence-with-arithmetic.

---

*End of D29.*
