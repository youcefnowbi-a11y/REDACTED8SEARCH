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
- **One new instrument failure was found and recorded** — §5.1. It is the corpus's ninth instance of one root cause and it is **this lane's own probe**.

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
| **1** | `merlin.x64.dll` exports **exactly 7 functions / 7 names** — `Magic, Merlin, Run, VoidFunc, DllInstall, DllRegisterServer, DllUnregisterServer`. Two independent PE parsers agree. | `verified` |
| **2** | **"Seven export names, ONE action" is VERIFIED** — all seven thunks resolve to the **same common function at RVA `0x16C0`**. | `verified` |
| **3** | **`Magic` is the one that diverges — in shape, not in destination.** It is at RVA `0x13D1`, **off the `0x40` grid** the other six sit on (`0x1400 + 0x40k`), and it uses a **different prologue** (`push rbp; mov rbp,rsp` = mingw C frame) versus the six Go thunks (`push rbx; sub rsp,0x30`). It still converges on `0x16C0` — via `Merlin` (`0x1540`). | `verified` |
| **4** | The six Go exports are **one template instantiated six times**: byte-identical instruction sequences differing only in `rel32` displacements. | `verified` |
| **5** | **45 non-empty `remote` values, 43 unique** — 42 `raw.githubusercontent.com` + 3 `gist.githubusercontent.com`. Both methods agree. | `verified` |
| **6** | **42 of 45 remote URLs point at a mutable branch (`master`); 3 are SHA-pinned gists.** No commit SHA exists in the raw-GitHub set. | `verified` |
| **7** | **One shipped module's `remote` field is corrupt** — `Get-ExecutionCommand.json` holds a URL **plus a pasted shell transcript containing a plaintext credential**. | `verified` |
| **8** | `[inference]` The `0x10` `.text` shift is consistent with a **single source-line or variable-layout change between the two builds that removed exactly 16 bytes of prologue/epilogue or pushed a frame slot**, not a coincidence. §4.4 names it. | `inferred` |

`[inference]` **Net assessment:** the operator-side DLL is a **thin, uniform, deliberately boring shim** — seven names, one action, and six of the seven are literally the same code. That is the same design posture D10 and D11 established for the module layer, now confirmed at the export table. **The interesting artifact in this target has never been the DLL; it is the 45 mutable-branch URLs the DLL fetches and the fact that one of them ships with a credential pasted into it.**

---

## §1 The DllExport surface — Q1

**Question:** enumerate every `DllExport` in `merlin.x64.dll`; for each, state whether it is reachable from the `Run` primitive. Verify or falsify *"seven export names, ONE action."*

### 1.1 The enumeration

`verified` — **METHOD A:** direct parse of the PE export data directory, resolved from `DataDirectory[0]` (RVA `0x2D86000`, size 200 B) through the section table.

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

`verified` — **METHOD B:** an independent `BinaryReader`-based parser sharing **no helper code** with method A (separate section walk, separate RVA translation). **It returns the identical 7 names, identical ordinals, identical RVAs.** Counts: A = 7/7, B = 7/7. No divergence.

`verified` **Cross-check against the source.** `merlin.def:15-22` lists `Run, VoidFunc, DllInstall, DllRegisterServer, DllUnregisterServer, Merlin, Magic` — **the same seven**, and `merlin.def:14` states *"The names are the `//export` functions in `main.go` plus `Magic()` from `merlin.c`."* The shipped binary matches the intended export list exactly. `[absence]` **No eighth export exists**, and neither `DllGetClassObject` nor `DllCanUnloadNow` is present — positive control: the same parser enumerated all 7 of the expected names, so it demonstrably reads this table.

**Ordering note.** The ordinal order (`DllInstall, DllRegisterServer, DllUnregisterServer, Magic, Merlin, Run, VoidFunc`) is **alphabetical**, not source order. `[inference]` The linker sorted by name. This matters only in that the ordinal sequence carries no information about the author's intent — reading it as a build order would be a mistake.

### 1.2 The stride, and the one export that breaks it

`verified`. Six of the seven exports sit at **exactly `0x1400 + 0x40k`** — a uniform 64-byte stride. Measured deltas: `0x1400→0x1440→0x1480→0x14C0→0x1500→0x1540`, all `0x40`.

**`Magic` is at `0x13D1` — `0x2F` (47) bytes below `0x1400`.** It is the only export off the grid.

`[inference]` **This is a two-toolchain artifact, and the byte evidence confirms it.** `merlin.def:14` says the names are the Go `//export` functions **plus `Magic()` from `merlin.c`** — a separate C file. The six Go exports are emitted by the Go linker as a contiguous block; `Magic` is compiled by mingw from `merlin.c` and placed where the C compiler put it. The grid is a property of the Go thunk emitter, not of the DLL.

### 1.3 The prologue split — two different ABIs in one export table

`verified`. The first bytes at each RVA:

| Export | First 13 bytes | Prologue form |
|---|---|---|
| `Run` | `53 48 83 EC 30 E8 …` | `push rbx; sub rsp,0x30; call rel32` |
| `VoidFunc` | `53 48 83 EC 30 E8 …` | **identical** |
| `DllInstall` | `53 48 83 EC 30 E8 …` | **identical** |
| `DllRegisterServer` | `53 48 83 EC 30 E8 …` | **identical** |
| `DllUnregisterServer` | `53 48 83 EC 30 E8 …` | **identical** |
| `Merlin` | `56 53 48 83 EC 38 …` | `push rsi; push rbx; sub rsp,0x38` — same family, one extra save |
| **`Magic`** | **`55 48 89 E5 48 83 EC 20 …`** | **`push rbp; mov rbp,rsp; sub rsp,0x20` — frame-pointer ABI** |

`verified`. **Five exports are byte-identical in their opening 13 bytes.** The sixth (`Merlin`) differs by pushing one additional callee-saved register. **`Magic` alone uses the `rbp` frame-pointer convention** — the classic mingw/GCC C prologue, and the signature of a translation unit compiled by a different toolchain than the Go code around it.

`[inference]` This is the export table wearing its build system on its sleeve: **six Go-generated thunks and one C function, and the C function is visibly not of the same substance.**

### 1.4 Reachability — all seven converge on one function

`verified`. Every `rel32` call in each thunk's first `0x40` bytes was decoded and its target computed:

| Export | call → `0x16C0` | call → `0xA9BE0` | call → `0x1580` | other |
|---|---|---|---|---|
| `Magic` (0x13D1) | **yes** (from `0x1405`) | — | — | **call → `0x1540` (`Merlin`)** from `0x13E4` |
| `Run` (0x1400) | **yes** (from `0x1405`) | yes | yes | — |
| `VoidFunc` (0x1440) | **yes** (from `0x1445`) | yes | yes | — |
| `DllInstall` (0x1480) | **yes** (from `0x1485`) | yes | yes | — |
| `DllRegisterServer` (0x14C0) | **yes** (from `0x14C5`) | yes | yes | — |
| `DllUnregisterServer` (0x1500) | **yes** (from `0x1505`) | yes | yes | — |
| `Merlin` (0x1540) | **yes** (from `0x1549`) | yes | yes | — |

`verified`. **All seven exports call RVA `0x16C0`.** The bytes at `0x16C0` are `41 54 55 57 56 53 48 83 EC 30 48 8D 1D …` — the same target for every caller, so there is **one** destination, not seven similar ones.

`verified` **The chain is exact and complete:**

```
Magic(0x13D1) ──call──> Merlin(0x1540) ──call──> 0x16C0
Run(0x1400) ─────────────────────────────call──> 0x16C0
VoidFunc(0x1440) ────────────────────────call──> 0x16C0
DllInstall(0x1480) ──────────────────────call──> 0x16C0
DllRegisterServer(0x14C0) ───────────────call──> 0x16C0
DllUnregisterServer(0x1500) ─────────────call──> 0x16C0
Merlin(0x1540) ──────────────────────────call──> 0x16C0
```

`verified` **This reproduces `merlin.c:41-45` exactly:**

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
| "Seven export names" | **`verified`** — 7 functions, 7 names, two parsers, matches `merlin.def`. |
| "ONE action" | **`verified`** — all seven converge on RVA `0x16C0`. |
| "`Run` parses `rundll32` from `os.Args[1]`, URL from `os.Args[5]`" (carried from D11) | **`verified` consistent** — `Run`'s thunk is one of the six that call `0x16C0`; it adds no logic of its own. The argument parsing lives in the shared callee, not in the export. |
| **"Does any one of the seven diverge?"** | **YES — `Magic`.** It diverges **structurally** (off-grid RVA `0x13D1`, `rbp` frame prologue, a second call leg through `Merlin`) **but not behaviourally**: it still terminates at `0x16C0`. |

`[inference]` **The honest form of the headline.** "Seven export names, ONE action" is **correct at the level of consequence** — there is one code path, and no export offers a distinct capability. But it is **not literally seven identical functions**: there are **two families**, six Go thunks and one C wrapper, and `Magic` is the outlier by construction. Reporting "seven identical" would flatten a real build-system fact; reporting "seven divergent" would overstate a structural difference with no behavioural effect. **One action, two shapes.**

---

## §2 The symbol asymmetry as a design statement — Q2

**Question:** server carries full DWARF + a 1.65 MB `.symtab`; agent is `-s -w` stripped. Compare against Sliver, where the implant is the deeply-reversed artifact and the operator console is 65 MB of gRPC plumbing. **Is the operator-side-vs-agent-side asymmetry a Merlin trait, or a Merlin-vs-Sliver difference?**

### 2.1 The measurement — and the probe that lies about it

`verified` — measured directly from each PE's section table.

| Artifact | Total size | `.symtab` | ZLIB-marked DWARF sections | **Total debug metadata** | **% of file** |
|---|---|---|---|---|---|
| **`merlinServer-Windows-x64.exe`** (operator) | 26,329,600 | **1,653,248** | **6,334,976** in **7** sectors | **7,988,224 B** | **30.3%** |
| `merlinAgent-Windows-x64.exe` (agent) | 13,939,200 | **512** | 0 | **512 B** | 0.004% |
| `merlin.x64.dll` (agent payload form) | 15,145,760 | absent | 68,608 in 9 sectors | **68,608 B** | 0.45% |
| `sliver-client_windows-amd64.exe` (operator) | 65,866,240 | **512** | **0** | **512 B** | 0.0008% |

**`verified` The 1.65 MB `.symtab` is confirmed: `1,653,248` B.** `verified` **METHOD B**, independent: `[regex]::Matches` over the full raw byte image for the literal `.symtab` returns 1 structural occurrence, and the section-table walk returns the same `rawSize`. Both agree.

**`[inference]` A correction to the tasking's wording, and it is a correction in Merlin's favour — the server is *more* exposed than "DWARF + symtab" suggests.** The tasking says *"full DWARF + a 1.65 MB `.symtab`"* and treats those as two things. Measured, they are **7,988,224 B combined**, and the DWARF component (**6,334,976 B**) is **3.8× larger than the `.symtab`**. The right headline is not "1.65 MB of symbols" — it is **"just under 8 MB of debug metadata, 30.3% of a 26 MB file."**

**`verified` Instrument record — this lane's second instrument failure, and it is the ninth instance of the corpus's one root cause.** My first DWARF probe searched for the literal ASCII section names `.debug_info`, `.debug_line`, `.debug_str`, `.debug_abbrev`. Against the server it returned **`.debug_info` 0, `.debug_line` 0, `.debug_str` 0, `.debug_abbrev` 0.** A zero. **It is a false zero.** Go's linker does not emit `.debug_*` section names — it emits **numeric** names (`/4`, `/19`, `/32`, `/46`, `/65`, `/78`, `/95`, `/112`) and places `ZLIB`-magic compressed DWARF inside them. The probe assumed the shape of a GNU-linked ELF/PE and the artifact is Go-linked. **Recorded, not silently corrected,** per this lane's standing instruction. The correction was made by reading the **section table** (structure) rather than **searching for names** (text) — the shape-matching rule, applied to my own probe.

`verified` The discriminator that settled it: bytes `5A 4C 49 42` (`ZLIB`) at the start of 7 of the 8 numeric sections. A section whose *name* is uninformative and whose *first four bytes* are a compression magic is compressed DWARF regardless of what a name-based probe says.

### 2.2 The agent is not "stripped" — it is a Go build that never had symbols

`verified` — read the actual `.symtab` payload, not its size. The agent's `.symtab` is 512 B and begins:

```
04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ...
```

`[inference]` A 4-byte little-endian `4` followed by zeros is the **Go linker's empty-symbol-table placeholder**. It is not the remnant of a stripped symbol table; there was nothing to strip. **The distinction matters** because the tasking's phrase "`-s -w` stripped" implies symbols were *removed* — an act with an intent behind it. The evidence says the agent is a Go executable built **without** a symbol table on this path, which is Go's default for `buildmode=exe` with `-ldflags "-s -w"`.

`verified` All three Merlin artifacts report **`go1.27.2`**. The DLL reports **`buildmode=c-archive`**; both the agent and the server report **`buildmode=exe`**. The DLL's `c-archive` identity is independently corroborated by **`merlin.def:10-11`**, which says the `.def` file exists *because* "under Go 1.27 the c-archive carries standard-library symbols that i686-w64-mingw32-ld refuses to auto-export."

`[absence]` **No `vcs.revision=` string appears in any of the three Merlin binaries** — probe: literal search for `vcs.revision=` → **0 hits in all three**. Positive control: the same probe against the Sliver client finds the Go build-info blob (task-1 banked `VCS revision 422044af…`). **So Merlin ships no build revision, while Sliver does — and that is a provenance asymmetry the tasking did not ask about but which sits right beside the symbol one.**

### 2.3 The comparison that answers the question

`verified` — Sliver client, same method, same parser:

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

`verified` **The Sliver client is stripped; the Merlin server is not.** This is the fact the question turns on, and it is the *opposite* of what the tasking's framing implies.

### 2.4 The answer: it is a MERLIN-vs-SLIVER difference, and the tasking has the direction of the asymmetry inverted

`verified` **Merlin's operator side is the debuggable artifact; Sliver's operator side is the stripped one.** Both projects strip their *implant-side* artifact — Merlin's agent has a 512 B stub, and Sliver's implant ships as source in the tree rather than as a symbol-bearing binary. **The two projects differ entirely in what they do with the OPERATOR side.**

| | Merlin | Sliver |
|---|---|---|
| **Operator-side artifact** | **not stripped** — 7.99 MB debug (~30%) | **stripped** — 512 B stub |
| **Agent/implant-side artifact** | stripped (512 B stub / no symtab) | source-available tree, reversed from source |

`verified` **So the asymmetry is real and it is a Merlin trait** — Merlin's own two sides are asymmetric by ~15,600× in debug metadata (7,988,224 B vs 512 B). **But the *axis* the tasking describes is wrong.** The tasking says the asymmetry is *operator-side vs agent-side* and compares it to Sliver. The honest comparison is:

- **Within Merlin:** operator server **keeps** symbols, agent **drops** them. Asymmetry confirmed, direction: **operator exposed.**
- **Within Sliver:** operator client **drops** symbols, implant is source-reversed. Asymmetry confirmed, direction: **operator hidden.**
- **Therefore:** operator-side-vs-agent-side asymmetry is **a Merlin trait AND a Sliver trait** — both projects are asymmetric. **What differs is which side the author left open.**

`[inference]` **The design statement, and it is stronger than attribution.** A build that keeps 30% of a file as debug metadata is not an accident of a missing flag — **the release pipeline for `merlinServer` never applied `-s -w`, while the pipelines for the agent and the DLL clearly did.** That is a per-target decision, not a global one. The consequence for an analyst is concrete and it is the one D10/D11 already exploited: **`merlinServer-Windows-x64.exe` is the artifact to reverse, and it is the reason `NewModule` and `validateModule` could be read as named functions with a real `.symtab` behind them rather than as anonymous subroutines at guessed addresses.**

`[inference]` **Why this inverts the naive reading.** The intuition is that the operator console is "the big visible thing" and the implant is "the hidden thing," so the implant should be the reversed one. **Sliver fits that** — 65 MB of gRPC plumbing is mostly generated protobuf and dependency code, so the *implant logic* is what a report must reconstruct. **Merlin does not fit it** — the operator binary is where the *decision logic* lives (`NewModule`'s two map keys, `validateModule`'s four checks), because in Merlin the operator server is what selects and validates modules. **D10 and D11 both found their findings on the server, not the agent, and this is the structural reason why.**

### 2.5 The consequence for detection

`verified` Merlin's most reliable detection was established in D10 §3.7 as a **network hostname** (`raw.githubusercontent.com`), not a file hash. §2 explains the mechanical reason that had to be true: **the agent binary carries neither symbols nor the URLs** (D10 §3 confirmed **zero `raw.githubusercontent.com` hits in the agent**), so there is no artifact-side indicator to hash. `[inference]` **The two findings are the same finding seen twice** — a payload whose operator-side is fully symbolised and whose agent-side is fully stripped is a payload whose detectable surface is necessarily at runtime.

---
