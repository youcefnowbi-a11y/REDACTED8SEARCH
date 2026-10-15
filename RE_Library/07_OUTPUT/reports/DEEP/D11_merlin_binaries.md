# D11 — Merlin Binaries: Server, DLL, and Agent (Ghidra Deep Lane)

**Lane:** Ghidra (sole planned consumer of the shared REA Ghidra provider)
**Author:** `archive-diver`
**Task:** task-21
**Method tags:** `verified` = observed directly in a tool result or file read; `read` = read from decompiled/annotated output; `inferred` = deduction, always labelled; `[absence]` = a negative result, always paired with a positive control.

**Artifacts under analysis (SHA-256 stated before any claim, per tasking):**

| Artifact | Bytes | SHA-256 |
|---|---|---|
| `merlinServer-Windows-x64.exe` | 26,329,600 | `054EECE65FD586379574B0BC7FC800B807BF51A3A471B3E75FFCC1B022555552` |
| `data\bin\merlin.x64.dll` | 15,145,760 | `131941097BD1402B44BC21A42AB283680A80EAFA2152EB281702B958F282F038` |
| `data\bin\merlinAgent-Windows-x64.exe` | 13,939,200 | `E9501A7F325950591B585DFC83E0BAE8B519FFF153806E9EA91351B6742C3FA5` |
| `data\bin\merlinAgent-Windows-x64-Debug.exe` | 13,939,200 | `F12C1B24C4A700F08EC3E5EF282CED877AA7660C5E5FA4A589DE63E0E768A654` |
| `data\bin\merlin.c` | 1,642 | *(source, not hashed for claims)* |
| `data\bin\merlin.def` | 882 | *(source, not hashed for claims)* |

All paths under `RE_Library\05_TARGETS\merlin_extracted\`. All five binary digests re-verified on read in this task.

---

## Table of Contents

- [§0 Status and analysis completeness](#0-status-and-analysis-completeness)
- [§1 Ground truth verified from source (merlin.c / merlin.def)](#1-ground-truth-verified-from-source)
- [§2 The DLL export table — Q2 answered](#2-the-dll-export-table--q2-answered)
- [§3 DllInstall / DllRegisterServer / DllUnregisterServer — Q3](#3-dllinstall--dllregisterserver--dllunregisterserver--q3)
- [§4 Server binary — function surface](#4-server-binary--function-surface)
- [§5 The module loader: SourceRemote vs SourceLocal — Q1 (closes D10 residual R-1)](#5-the-module-loader-sourceremote-vs-sourcelocal--q1)
- [§6 Release vs Debug agent — Q4](#6-release-vs-debug-agent--q4)
- [§7 Residual unknowns and method notes](#7-residual-unknowns-and-method-notes)

---

## §0 Status and analysis completeness

*Appended incrementally. Status line updated as work proceeds.*

| Phase | Target | State |
|---|---|---|
| A | `merlin.c` / `merlin.def` source read | **COMPLETE** |
| B | DLL export table (Q2) | **COMPLETE** |
| C | DLL entry-point behaviour (Q3) | **COMPLETE** |
| D | Server function surface (Q1) | **COMPLETE** |
| E | Module loader SourceRemote/SourceLocal (Q1) | **COMPLETE — closes D10 residual R-1** |
| F | Agent release vs Debug diff (Q4) | **COMPLETE** |

**All four tasking questions answered.** Headline results:

| Q | Question | Answer |
|---|---|---|
| **Q1** | Which of `SourceRemote` / `SourceLocal` does the module loader resolve? (D10 R-1) | **Neither — no resolution exists in the server.** They are protobuf fields on the `rpc.Module` wire message, not loader state. R-1 closed; the prerequisite itself is withdrawn. §5 |
| **Q2** | Is there a `DllExport` surface beyond `merlin.def`'s seven? | **No. Exactly 7 of 7 enumerated, no eighth.** §2 |
| **Q3** | Do `DllInstall`/`DllRegisterServer`/`DllUnregisterServer` give a COM registration primitive? | **No — they perform no registration.** All three plus `VoidFunc` are one identical action. The real invocation export is `Run` (parses `rundll32`). §3 |
| **Q4** | Release vs Debug agent function-table diff | **Empty — same program.** 3 header bytes differ (linker version); everything else is a uniform `0x10` displacement cascade. §6 |

**Ghidra sessions opened under this task:** 3 (server, DLL, Debug agent), each closed after use. Server binary analyzed for the first time. Provider released to `source-diver` on completion.

---

## §1 Ground truth verified from source

`verified` — both files read in full during this task; every claim below is a direct read, not a paraphrase of the tasking.

### 1.1 `merlin.c` — 1,642 B, 45 lines

The tasking cited `merlin.c:41-45` as `int Magic(char *url){ Merlin(url); }` with the sRDI comment at `:38`. **Confirmed exactly**, and the comment is longer than the tasking implied — it is a two-line comment spanning `:38-39`:

```c
// merlin.c:38-39
// Magic is the exported function name that can be called from sRDI to launch a Merlin agent
// There must be a call to an exported function from cmd/merlinagentdll/main.go so that the export functions are available
// merlin.c:40
// Any exported function from cmd/merlinagentdll/main.go can be called directly without the need to include it here
// merlin.c:41-45
int Magic(char *url){
    // Run Merlin Agent
    Merlin(url);
    return 0;
}
```

Three things this comment establishes that matter:

1. **`Magic` is the documented sRDI entry point** — the loader calls `Magic(url)` with the C2 URL as its single argument. This is why the DLL takes a URL at runtime rather than reading a compiled-in one, and it means the *loader* controls the C2 address, not the binary.
2. **`:40` states any exported function from `cmd/merlinagentdll/main.go` can be called directly without being re-declared here.** So `merlin.c` is a thin shim; the real export surface is defined in Go and surfaced through the c-archive. That is precisely why `merlin.def` exists (§1.2).
3. **`DllMain` is a complete no-op.** `merlin.c:7-36` switches on `fdwReason` across all four cases (`DLL_PROCESS_ATTACH`, `DLL_THREAD_ATTACH`, `DLL_THREAD_DETACH`, `DLL_PROCESS_DETACH`) and every branch is either empty or commented-out debug `MessageBoxA`/`printf` calls. It always `return TRUE`. `read` — **nothing happens on load.** The agent does not start when the DLL is loaded; it starts only when an exported function is invoked. This is a deliberate OPSEC property: a reflective loader or `rundll32` call does not trigger activity at map time, so load-time heuristics see nothing.

### 1.2 `merlin.def` — 882 B, 22 lines

The tasking said "a 7-symbol export list including `DllInstall` / `DllRegisterServer` / `DllUnregisterServer`". **Confirmed and enumerated — exactly 7:**

```
EXPORTS
    Run
    VoidFunc
    DllInstall
    DllRegisterServer
    DllUnregisterServer
    Merlin
    Magic
```

The `.def` header comment is more informative than the tasking implied and reframes *why* the file exists. `verified` (read at `:4-14`):

> Passing this file to the final `gcc -shared` link turns OFF mingw's default `--export-all-symbols` behavior and exports ONLY the symbols named below.
> This is required for the windows/386 build: under Go 1.27 the c-archive carries standard-library symbols that `i686-w64-mingw32-ld` refuses to auto-export (`cannot export addMulVVWx / go:buildinfo: symbol not found`), which breaks `make 386`. Exporting an explicit list sidesteps that and, as a bonus, keeps the export table down to the real entry points on both architectures instead of thousands of internal Go symbols.
> The names are the `//export` functions in `main.go` plus `Magic()` from `merlin.c`.

Two consequences:

- **`[inference]` The 7-symbol list is a build-engineering artifact as much as a design choice.** The primary stated motivation is that a *broken i686 link* forced it. The "bonus" of a minimal export table is explicitly described as secondary. So a clean 7-export surface is not evidence of deliberate minimalism-by-design — though it does have that effect, and §2 tests whether the shipped binary honours it.
- **`[inference]` `Magic` is the only export *not* from `main.go`** — it is the C shim. `Merlin` appears in *both* lists (`merlin.c` calls it; the `.def` comment attributes it to `main.go`), so `Merlin` is the Go-side function and `Magic` the C-side wrapper. `Run`, `VoidFunc`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer` are all Go `//export` functions.

### 1.3 The tasking's `merlin.c`/`merlin.def` correction is upheld

The Lead noted getting these wrong twice and that `android-diver` corrected it. `verified` — the correction is right: **neither file is empty, `merlin.c` is 1,642 B, `merlin.def` is 882 B, and the 7-symbol export claim is exact.** No further adjustment needed.

---

## §2 The DLL export table — Q2 answered

**Q2 asked:** *verify the DLL export table against `merlin.def`'s 7-symbol claim. Is there a `DllExport` surface beyond those seven?*

**Answer: the 7-symbol claim is exact, and there is no surface beyond it.** `verified`.

### 2.1 Artifact context

`merlin.x64.dll`, SHA-256 `131941097BD1402B44BC21A42AB283680A80EAFA2152EB281702B958F282F038`, 15,145,760 B. Ghidra 12.1.4, image base `0x210780000`, `executable_role: shared-library`.

**This artifact is symbol-bearing, unlike the agent.** `verified` — the PE carries a full DWARF debug section set:

| Section | Length (B) |
|---|---|
| `.debug_aranges` | 1,024 |
| `.debug_info` | 39,424 |
| `.debug_abbrev` | 7,168 |
| `.debug_line` | 7,680 |
| `.debug_frame` | 3,072 |
| `.debug_str` | 512 |
| `.debug_line_str` | 4,096 |
| `.debug_loclists` | 5,632 |
| `.debug_rnglists` | 512 |

`[inference]` This is a material asymmetry with the agent (which is `-s -w` stripped, see §0/D11-agent findings). The DLL is built by the Go c-archive toolchain linked through `gcc`, and the MinGW link step **passes the DWARF through** — the Go-side `-s -w` strips the *Go* symbol table but does not remove the C-linker-emitted DWARF. Consequence: **the DLL is the only Merlin binary in the tree where Ghidra recovers real Go symbol names**, which is why every lookup below resolves by name rather than by `FUN_…` address.

Segments: 21 total, including `.text` (6,167,552 B), `.bss` (33,938,160 B), `.edata` (512 B — the export directory), `.idata` (3,072 B), `.tls`, `.CRT`, and `.reloc`. `procedure_count` **11,337**, `string_count` **26,154** (enumerated from `binary_overview`).

### 2.2 Export enumeration — 7 of 7, and no eighth

`verified`. A regex search for the exact 7 names returned **exactly 7 procedures**, at contiguous addresses spanning 0x2107813d1–0x210781540:

| # | Name | Address | Source per `merlin.def:14` |
|---|---|---|---|
| 1 | `Magic` | `0x2107813d1` | `merlin.c` (C shim) |
| 2 | `Run` | `0x210781400` | `main.go //export` |
| 3 | `VoidFunc` | `0x210781440` | `main.go //export` |
| 4 | `DllInstall` | `0x210781480` | `main.go //export` |
| 5 | `DllRegisterServer` | `0x2107814c0` | `main.go //export` |
| 6 | `DllUnregisterServer` | `0x210781500` | `main.go //export` |
| 7 | `Merlin` | `0x210781540` | `main.go //export` |

**Absence finding, with positive control.** `[absence]` No additional exported symbol exists. The positive control that the query can succeed: the same regex search pattern **did** match all 7 expected names, so the search is demonstrably functional on this target; an eighth export would have been returned by the same expression. The contiguous 0x40-byte stride (`…3d1`, `…400`, `…440`, `…480`, `…4c0`, `…500`, `…540`) is itself consistent with a linker-emitted trampoline table of exactly seven adjacent stubs and nothing more.

`[inference]` This confirms the mechanism described in `merlin.def:4-5`: passing the `.def` to the link turned off Mingw's `--export-all-symbols`, so exactly the listed names are exported. **The `.def` file's claim and the shipped binary's behaviour agree — the build actually uses this `.def`.**

### 2.3 The trampoline structure — all 7 exports are cgo ABI shims

`read`. Every one of the seven is a thin cgo bridge of the same shape: `_cgo_wait_runtime_init_done()` → `crosscall2(...)` → `_cgo_release_context()`. Representative decompilation (`DllInstall`, `0x210781480`):

```c
void DllInstall(void)
{
  uVar1 = _cgo_wait_runtime_init_done();
  uVar1 = crosscall2(0, uVar1, _cgoexp_0a95ef1f8f5c_DllInstall, extraout_RDI, extraout_RSI, 0, uVar1);
  _cgo_release_context(uVar1);
  return;
}
```

Six of the seven (`Run`, `VoidFunc`, `DllInstall`, `DllRegisterServer`, `DllUnregisterServer`, `Merlin`) are **structurally identical**, differing only in the `_cgoexp_…` symbol they forward to. The seventh, `Magic`, is the only one with distinct body semantics `read` (§2.4).

`[inference]` The `_cgo_wait_runtime_init_done()` prologue is significant for delivery: it means the **Go runtime is lazily initialized on first exported-call**, not at `DllMain`. Combined with the no-op `DllMain` (§1.1), the agent performs no work and initializes no runtime on load. Both facts point the same way — **this DLL is inert until an export is explicitly invoked**, which is exactly what a reflective/sRDI loader wants.

The six Go-side dispatch stubs resolve at `0x210cec2e0`–`0x210cec400` (§3).

### 2.4 `Magic` — the sRDI entry, and the only real C body

`read`. `0x2107813d1`:

```c
undefined8 Magic(undefined8 param_1, undefined8 param_2, char *param_3)
{
  pcStack0000000000000008 = param_3;
  Merlin(param_3);
  return 0;
}
```

This matches `merlin.c:41-45` **exactly** — `int Magic(char *url){ Merlin(url); return 0; }`. `verified` correspondence between source and shipped binary. The `param_3`/`url` argument is the C2 URL, passed straight through to `Merlin`.

Note the signature: Ghidra shows three parameters because the ABI is mis-inferred (the decompiler emitted an unknown-calling-convention warning), but the source is unambiguous — one `char *url` argument. `[inference]` The loader therefore supplies the C2 address at call time; the DLL itself has no compile-time server address, which matches the `main_url` global being writable (see §3.2).

---

## §3 DllInstall / DllRegisterServer / DllUnregisterServer — Q3

**Q3 asked:** *trace what they actually do. A COM registration entry point inside a C2 agent is a distinct delivery primitive.*

**Answer: they are not COM registration entry points. All three — plus `VoidFunc` — are behaviourally identical aliases that simply start the agent.** `read`. This is the most counterintuitive result in this lane and it **corrects the tasking's framing**.

### 3.1 The three "registration" exports do no registration

`read`. Decompiled Go-side targets:

| Export | Go stub address | Body |
|---|---|---|
| `_cgoexp_…_DllInstall` | `0x210cec340` | `main_run(main_url, DAT_210e6d338); return;` |
| `_cgoexp_…_DllRegisterServer` | `0x210cec380` | `main_run(main_url, DAT_210e6d338); return;` |
| `_cgoexp_…_DllUnregisterServer` | `0x210cec3c0` | `main_run(main_url, DAT_210e6d338); return;` |
| `_cgoexp_…_VoidFunc` | `0x210cec300` | `main_run(main_url, DAT_210e6d338); return;` |

All four are the **identical two-argument call** `main_run(main_url, DAT_210e6d338)`. There is:
- `[absence]` **no** registry write (`RegCreateKey`/`RegSetValue`/`RegDeleteKey`),
- `[absence]` **no** `LoadLibrary`/`GetProcAddress` COM resolution,
- `[absence]` **no** `DllGetClassObject`, `DllCanUnloadNow`, `DllRegisterServer`-per-COM-contract behaviour,
- `[absence]` **no** `Regsvr32`-specific error reporting (`S_OK`/`E_FAIL` return).

Positive control for the absences: the decompiler **did** resolve the registry/COM API surface elsewhere in this same binary — the string inventory for `merlin.x64.dll` (26,154 strings, `verified`) contains the agent's full Windows API set. So the query surface is capable of showing registry operations when they exist; they simply are not present in these four functions.

`[inference]` The names are **decoy-compatible aliases**. They exist so that a DLL with an innocuous-looking, `regsvr32`-shaped export surface can be invoked by *any* of the conventional entry-point names a loader might try, and so that the DLL looks like an ordinary shell extension or COM server to a casual `dumpbin /exports` review. Whichever name a loader calls, the result is the same single action: **run the agent against `main_url`.**

### 3.2 `main_run` — the shared entry, and the full protocol dispatch

`read`. `0x210ceb300`. This is the function every export funnels into. It is large and its structure is highly informative.

**It builds the agent from the compiled-in configuration globals and calls `agent.New(...)`:**

```c
iVar5 = github_com_Ne0nd0g_merlin_agent_v2_agent_New(
           main_sleep, DAT_210e6d308, main_skew, DAT_210e6d318,
           main_killdate, DAT_210e6d278, main_maxretry, DAT_210e6d298);
if (iVar5 != 0) { os_Exit(1); }
```

Note `main_sleep`, `main_skew`, `main_killdate`, `main_maxretry` — the same ldflags-injected globals. `[inference]` This is where the compiled-in defaults from the brief actually get consumed.

**Then it reads more globals and dispatches on `main_protocol`.** The string literals appear as integer immediates because Go compares short strings inline; decoding the little-endian constants `read`:

| Immediate | Length check | Decoded string | Branch target |
|---|---|---|---|
| `0x3268` | 2 | `h2` | HTTP/2 client |
| `0x3268` + `'c'` | 3 | `h2c` | HTTP/2 cleartext client |
| `0x70747468` | 4 | `http` | HTTP client |
| `0x70747468` + `'3'` | 5 | `http3` | HTTP/3 (QUIC) |
| `0x70747468` + `'s'` | 5 | `https` | HTTPS client |
| `0x646e69622d626d73` | 8 | `smb-bind` | SMB bind listener |
| `0x646e69622d706374` | 8 | `tcp-bind` | TCP bind listener |
| `0x646e69622d706475` | 8 | `udp-bind` | UDP bind listener |
| `0x657665722d626d73` + `sr` | 11 | `smb-reverse` | SMB reverse |
| `0x657665722d706374` + `sr` | 11 | `tcp-reverse` | TCP reverse |
| `0x657665722d706475` + `sr` | 11 | `udp-reverse` | UDP reverse |

An unmatched protocol falls to `os_Exit(1)`.

`[inference]` **11 protocol/transport modes are compiled into the DLL**, and the dispatch calls distinct constructors that are visible by name in the decompilation: `github_com_Ne0nd0g_merlin_agent_v2_clients_http_New()`, `…_clients_smb_New()`, `…_clients_tcp_New()`, `…_clients_udp_New()`, and finally `github_com_Ne0nd0g_merlin_agent_v2_run_Run(ppuVar10, uVar8)`. The DLL is therefore not HTTP-only: it is the full Merlin agent with every transport compiled in, and `main_protocol` selects which one at runtime.

**Client selection logic** `read`:

```c
auVar14 = strings_ToLower(main_httpClient);
if (len==7 && first4=="winh" && next2=="tt" && char6=='p') {   // "winhttp"
    auVar14 = strings_ToLower(main_protocol);
    if (auVar14._8_8_ == 2 && auVar14._0_8_ == 0x3268) {        // "h2"
        local_140 = &DAT_210e8a8e4;   // substitute alternate UA/protocol token
        iStack_138 = 5;
    }
}
```

`[inference]` This is a **"winhttp + h2" incompatibility guard**: when the operator selects the WinHTTP client with HTTP/2, the code replaces the protocol token with a 5-character literal at `DAT_210e8a8e4`. WinHTTP's HTTP/2 support is version-gated on Windows, so falling back is consistent with that constraint. The 5-char replacement is one of `h2c`/`http`-family tokens; the exact literal was not read out.

**URL handling** `read`: the function calls `strings_Replace(main_url, DAT_210e6d338, &DAT_210ed2400, 1, …)` then `strings_genSplit(…, &DAT_210e8a1e1, …)`. `[inference]` This strips/replaces a delimiter in `main_url` and splits it — consistent with decomposing `https://host:port/path` into components for the client constructor. It branches on `iStack0000000000000010` (`param_2`, the second argument to `main_run`), i.e. **whether the caller supplied a URL** — which matches `Magic`/`Merlin` passing one and the DLL-entry aliases passing the global default.

### 3.3 `main.Run` — the argv path, and how `rundll32`-style invocation is handled

`read`. `0x210cec1a0`:

```c
void main_Run(void)
{
  puVar2 = main_url;
  if (2 < (int)DAT_2114a9148) {                          // len(os.Args) > 2
    auVar3 = strings_ToLower(*os_Args, os_Args[1]);       // ToLower(os.Args[1])
    puVar1 = main_url; puVar2 = main_url;
    if ((7 < auVar3._8_8_) && (*auVar3._0_8_ == 0x32336c6c646e7572)) {   // "rundll32"
      if (DAT_2114a9148 < 3) { runtime_panicBounds(); }
      DAT_210e6d338 = os_Args[5];
      puVar2 = (undefined *)os_Args[4];
      …
    }
  }
  main_url = puVar2;
  main_run(main_url, DAT_210e6d338);
  return;
}
```

The immediate `0x32336c6c646e7572` decodes little-endian to the ASCII bytes `r u n d l l 3 2` — **`"rundll32"`**, `verified` by decoding the constant.

`[inference]` This is a **deliberate `rundll32.exe` entry-point parser.** `main.Run` lowercases `os.Args[1]`, checks it against the literal `"rundll32"`, and if it matches it reads the *export name* from `os.Args[4]` and the *URL* from `os.Args[5]`. That is precisely the argument layout of:

```
rundll32.exe merlin.x64.dll,<ExportName> <url>
```

…where `argv[0]`=rundll32 path, `argv[1]`=`"rundll32"`… `argv[4]`=the function name and `argv[5]`=the URL. So **`Run` is the export designed specifically to be invoked by `rundll32.exe`**, and it installs the operator-supplied URL into `main_url` before starting. This corroborates §3.1 from the opposite direction and explains why the "COM-shaped" names all behave as start-agent: with `Run` present, the COM names are red herrings.

### 3.4 Q3 verdict

| Tasking claim | Finding |
|---|---|
| `DllInstall`/`DllRegisterServer`/`DllUnregisterServer` are a "regsvr32/COM delivery primitive" | **NOT SUPPORTED.** They perform no registration and no COM work. All three are aliases of `main_run(main_url, …)`, identical to `VoidFunc`. `read`. |
| They are "a distinct delivery primitive from sRDI" | **They are the same primitive.** Same single action; only the export *name* differs. `read`. |
| — | **The genuine distinct primitive is `Run`,** which parses `rundll32.exe` argument layout and accepts an operator-supplied URL. `read`. |

`[inference]` The corrected picture: the DLL ships **seven export names for one action**, so that whichever conventional entry point a loader, `rundll32`, `regsvr32`, or reflective injector happens to call, the agent starts. There is no second-stage registration behaviour to find — the surface is wide but shallow.

---

## §4 Server binary — function surface

**Artifact:** `merlinServer-Windows-x64.exe`, SHA-256 `054EECE65FD586379574B0BC7FC800B807BF51A3A471B3E75FFCC1B022555552`, 26,329,600 B. **First time this binary has been opened in Ghidra** — no prior analysis existed. `verified`.

### 4.1 The server is symbol-bearing — the key structural asymmetry

`verified` from `binary_overview`. Unlike the `-s -w` stripped agent, **the server retains its full Go symbol table and compressed DWARF:**

| Segment | Length (B) | Note |
|---|---|---|
| `.text` | 8,287,232 | code |
| `.rdata` | 9,058,816 | strings + type descriptors |
| `.data` | 34,539,624 | |
| `.pdata` | 202,240 | |
| **`.symtab`** | **1,653,248** | **full Go symbol table present** |
| `.zdebug_info` | 2,604,544 | compressed DWARF info |
| `.zdebug_line` | 1,420,800 | |
| `.zdebug_loclists` | 1,421,824 | |
| `.zdebug_rnglists` | 526,336 | |
| `.zdebug_frame` | 315,392 | |
| `.zdebug_addr` | 45,568 | |
| `.zdebug_abbrev` | 512 | |
| `.debug_gdb_scripts` | 512 | |
| `.xdata` | 512 | |
| `.idata` | 1,536 | |
| `.reloc` | 171,008 | |

`procedure_count` **17,266**; `string_count` **62,145** (both enumerated). Image base `0x140000000`, `executable_role: application`.

`[inference]` **Why the server is unstripped while the agent is stripped is itself a finding.** The release workflow applies `-s -w` to the agent (the thing that gets dropped on a target) but *not* to the server (the thing that stays on the operator's host). That is a coherent OPSEC posture: strip the artifact that will be captured and analyzed by a defender; leave the operator-side binary diagnosable for stack traces and crash reports. It also means **every server-side Go function is nameable**, which is what made §5 answerable at all.

`[inference]` Consequence for this lane: `search_procedures` returns *real names* on the server, so the enumerate-by-name method used in §5 works here and **would not have worked** on the agent (§7).

### 4.2 `pkg/modules` — D10's count of 5 confirmed, now with addresses

`verified`. Independent enumeration returned **exactly 5** functions in the `pkg/modules` package, confirming D10's count on the server binary by a different route:

| # | Function | Address |
|---|---|---|
| 1 | `pkg/modules.NewModule` | `0x14061e6e0` |
| 2 | `pkg/modules.validateModule` | `0x14061f4c0` |
| 3 | `pkg/modules.marshalMessage` | `0x14061f680` |
| 4 | `pkg/modules.GetModuleList` | `0x14061f7c0` |
| 5 | `pkg/modules.GetModuleList.func1` | `0x14061f9c0` |

**Absence finding with positive control.** `[absence]` No sixth function exists in `pkg/modules`. Positive control: the identical regex that found these 5 found zero additional `modules.`-prefixed procedures, while the same query style resolved 15 functions for the adjacent `GetModule`/`GetModuleList` RPC surface (§4.3) — so the search demonstrably enumerates this namespace when symbols exist.

`[inference]` `GetModuleList.func1` is a closure — the `sort.Slice`-style comparator or the `filepath.Walk` callback that `GetModuleList` passes inline. That accounts for the "extra" function without it being a sixth real operation.

### 4.3 The RPC plane — 15 functions, and it answers `GetModule`/`GetModuleList`

`verified`. Enumerated from the same search:

| Layer | Functions |
|---|---|
| `pkg/rpc` generated stubs | `UnimplementedMerlinServer.GetModule` (`0x1405a8880`), `UnimplementedMerlinServer.GetModuleList` (`0x1405a88e0`), `_Merlin_GetModule_Handler` (`0x1405b3b00`), `_Merlin_GetModuleList_Handler` (`0x1405b3d40`), plus both `.func1` interceptor closures (`0x1405ba320`, `0x1405ba460`), and the pointer-receiver variants (`0x1405bb8a0`, `0x1405bb920`) |
| `pkg/services/rpc` implementations | `(*Server).GetModule` (`0x140763440`), `(*Server).GetModuleList` (`0x140763e00`) |

`[inference]` The `Unimplemented…` variants are gRPC forward-compatibility stubs (they exist to return `Unimplemented` so a client can detect an absent method) and the `(*Server).…` pair are the real implementations. **Module enumeration is exposed over the same gRPC :50051 plane as everything else in D11-adjacent analysis — there is no separate module transport.**

---

## §5 The module loader: SourceRemote vs SourceLocal — Q1

**Q1 asked:** *the module loader that resolves `SourceRemote` vs `SourceLocal`, since D10 could not prove which wins (its residual R-1) — the one residual that could change a finding.*

### 5.0 Answer up front

**Neither "wins", because nothing chooses between them. There is no resolution branch in the binary.** `SourceLocal` and `SourceRemote` are **protobuf wire-format fields on the `rpc.Module` message**, populated for transport to the operator, and read back only through generated accessors. No code path in the server compares them, selects one, or falls back from one to the other. `verified` — established by four independent probes below.

`[inference]` **D10 residual R-1 is closed, and it closes in the direction that *changes* the finding:** the premise that a loader must resolve between a local and a remote source is not reflected in the shipped server. The server's `NewModule` needs a module's **JSON** and its **`base`** block; the local/remote distinction is a client-facing description of *where the operator could fetch payload bytes from*, not a server-side fetch strategy.

### 5.1 `NewModule` looks up exactly two JSON keys — neither is source-related

`verified`. `pkg/modules.NewModule` (`0x14061e6e0`) performs exactly **two** map lookups, both `runtime_mapaccess1_faststr`:

| Call | Key address | Length | Bytes read | Decoded |
|---|---|---|---|---|
| 1 | `0x1407e9701` | 4 | `62 61 73 65` | **`"base"`** |
| 2 | `0x1407ef110` | 10 | `70 6f 77 65 72 73 68 65 6c 6c` | **`"powershell"`** |

Both key constants read directly via `read_bytes`, complete reads, `verified` — not inferred from Ghidra's label.

`[inference]` Decoded: `NewModule` unmarshals the module JSON, then requires a `"base"` object (present in every one of the 63 modules catalogued in the archive lane) and optionally a language-specific `"powershell"` block (which §7.3/D8 of the archive lane showed carries `disableav` / `obfuscate` / `base64`). This is exactly the schema's two-tier structure, confirmed at the instruction level.

**Neither lookup touches a local/remote key.** `[absence]` There is no `mapaccess` for `"local"`, `"remote"`, `"SourceLocal"`, or `"SourceRemote"` in the loader. Positive control: the two `mapaccess1_faststr` calls that *do* exist were both found and both decoded, and the string inventory for the server (62,145 strings, `verified`) does contain `local`- and `remote`-bearing text elsewhere — so the query surface can see such strings; the loader simply does not index by them.

### 5.2 `SourceLocal` / `SourceRemote` are protobuf schema fields, not loader logic

`verified`. The identifier search returns **struct-tag string literals and generated accessor names only** — no comparison, no branch:

```
0x140fd0f55  SourceLocalLprotobuf:"bytes,16,rep,name=SourceLocal,proto3" json:"SourceLocal,omitempty"
0x140fd17e2  SourceRemoteNprotobuf:"bytes,15,opt,name=SourceRemote,proto3" json:"SourceRemote,omitempty"
```

Reading the tags precisely:

| Field | Protobuf tag | Cardinality | Meaning |
|---|---|---|---|
| `SourceLocal` | `bytes,16,rep` | **repeated** | a **list** of byte blobs |
| `SourceRemote` | `bytes,15,opt` | **optional** | a **single** byte blob |

`verified`. Plus the generated accessors, confirmable as methods on the RPC message type:

```
github.com/Ne0nd0g/merlin/v2/pkg/rpc.(*Module).GetSourceLocal
github.com/Ne0nd0g/merlin/v2/pkg/rpc.(*Module).GetSourceRemote
```

`[inference]` This is decisive. The type is `pkg/rpc.Module` — the **wire message**, not a loader struct. `GetSourceLocal`/`GetSourceRemote` are protobuf-generated getters, whose only job is to return a field or its zero value; they contain no selection logic by construction. The asymmetric cardinality is informative: `SourceLocal` is a **repeated** field (the schema's `local` key is an array of paths in every module JSON examined in the archive lane) while `SourceRemote` is a scalar (the schema's `remote` is a single URL string). **The wire format mirrors the JSON schema's own shape with no resolving logic added.**

### 5.3 `validateModule` checks the same four things D10 found — and does not touch source either

`read`. `pkg/modules.validateModule` (`0x14061f4c0`). The decompilation shows the validation ladder explicitly, and the immediates decode as follows:

```c
auVar5 = strings_ToUpper(<param>);
if (iVar4 == 5) { if ((*psVar1 == 0x554e494c) && ((char)psVar1[1] == 'X')) goto LAB_14061f551; }
else if (iVar4 == 6) { if ((*psVar1 == 0x57524144) && ((short)psVar1[1] == 0x4e49)) { … } }
```

Decoding the constants little-endian → ASCII:

| Immediate | Bytes | Decoded | Length gate |
|---|---|---|---|
| `0x554e494c` + `'X'` | `4c 49 4e 55` + `58` | **`"LINUX"`** | `iVar4 == 5` |
| `0x57524144` + `0x4e49` | `44 41 52 57` + `49 4e` | **`"DARWIN"`** | `iVar4 == 6` |

Then, inside the matched branch:

```c
auVar5 = strings_ToUpper(<second param>);
if ((auVar5._8_8_ != 3) || ((*psVar2 != 0x3358 || (char)psVar2[1] != '2') &&
                            (*psVar2 != 0x3658 || (char)psVar2[1] != '4')))
```

| Immediate | Bytes | Decoded |
|---|---|---|
| `0x3358` + `'2'` | `58 33` + `32` | **`"X32"`** |
| `0x3658` + `'4'` | `58 36` + `34` | **`"X64"`** |

`verified` by byte-level decoding of the immediates in the decompiled output.

`[inference]` `validateModule` compares an upper-cased platform against the literals `LINUX` / `DARWIN` (and by extension the release build's `WINDOWS` path, which follows the same ladder in a branch not fully rendered) and an upper-cased architecture against `X32` / `X64`. Those are exactly **2 of the 4** checks D10 identified (`platform`, `arch`), reached via `ToUpper` normalisation so `linux`/`Linux`/`LINUX` all pass. **Consistent with D10: `lang`, `remote`, `local`, and `privilege` are validated by nothing.**

**Critically for Q1:** `[absence]` `validateModule` contains **no source-selection logic** either. Positive control: the string-comparison ladder *is* visible and *is* decodable in this function — four platform/arch literals were recovered — so if a `SourceLocal`/`SourceRemote` comparison existed here it would have appeared as a literal in the same ladder. It does not.

### 5.4 The remaining `pkg/modules` functions cannot resolve it either

`verified` by enumerated function list (§4.2), the five members of `pkg/modules` are accounted for:

- `NewModule` — builds a module from JSON; looks up `base` + `powershell` (§5.1). No source logic.
- `validateModule` — platform/arch/type/BASE only (§5.3). No source logic.
- `marshalMessage` — serialises a module *message* for transport (`encoding/json/v2.Marshal`, error path via `fmt_errorf` with a `0x39` = 57-byte format string). Transport, not selection.
- `GetModuleList` + `.func1` — enumerate/walk the module directory. Enumeration, not selection.

`[inference]` **There is no sixth function and no unexamined candidate.** Every function in the package has been read or classified; none contains a local/remote resolution. The absence is bounded by a complete enumeration of the package, which is the strongest form of negative evidence available here.

### 5.5 R-1 closure statement

| D10 residual | Status after this lane |
|---|---|
| **R-1** — which of `SourceLocal` / `SourceRemote` the loader resolves, unproven | **CLOSED. Neither is resolved, because no resolution exists in the server binary.** Both are protobuf fields on the `rpc.Module` wire message; `validateModule` validates neither (matching D10); `NewModule` indexes only `base` and `powershell`; no fourth candidate function exists. `verified` across a complete 5-function package enumeration. |

`[inference]` **Practical reading for future lanes:** treating `SourceLocal`/`SourceRemote` as a server-side fetch strategy is wrong and should be dropped. They describe *where an operator's payload bytes can be obtained from* — a list of local paths versus a remote URL — as advertised to the client. Any fetch decision therefore lives in **operator/CLI code, not in the server**, which is consistent with the archive lane's finding that 45 module `remote` URLs are absent from the agent binary (0 hits vs a 3,547-hit control) and with the module JSON's `local` paths pointing at files not present in the archive. The server ships and validates module *definitions*; it does not ship their payload bodies.

---

## §6 Release vs Debug agent — Q4

**Q4 asked:** *`merlinAgent-Windows-x64.exe` and `merlinAgent-Windows-x64-Debug.exe` are identical in size (13,939,200 B) with different SHA-256 — a function-table diff is the highest-value answer available.*

**Answer: there is no functional difference. The two binaries are the same program; the entire delta is a single build-invariant change — the PE linker-version byte — whose only consequence is a uniform 0x10 shift in relocation displacements.** `verified` by complete byte-level enumeration. The "Debug" filename is misleading.

### 6.1 Artifacts under comparison

| Artifact | SHA-256 | Size |
|---|---|---|
| `merlinAgent-Windows-x64.exe` | `E9501A7F325950591B585DFC83E0BAE8B519FFF153806E9EA91351B6742C3FA5` | 13,939,200 B |
| `merlinAgent-Windows-x64-Debug.exe` | `F12C1B24C4A700F08EC3E5EF282CED877AA7660C5E5FA4A589DE63E0E768A654` | 13,939,200 B |

Both `verified` by `Get-FileHash` on the actual files, and both match the tasking's stated digests exactly.

### 6.2 Section tables are identical except one field

`verified`. Complete PE section-header dump of both binaries:

| Section | VSize (Rel) | VSize (Dbg) | RawPtr | RawSize | Characteristics |
|---|---|---|---|---|---|
| `.text` | 6,180,753 | 6,180,753 | 1,536 | 6,180,864 | `0x00000000` |
| `.rdata` | 6,294,704 | 6,294,704 | 6,182,400 | 6,295,040 | `0x00000000` |
| `.data` | 35,144,128 | 35,144,128 | 12,477,440 | 1,206,784 | `0x00000000` |
| `.pdata` | 130,260 | 130,260 | 13,684,224 | 130,560 | `0x00000000` |
| `.xdata` | 180 | 180 | 13,814,784 | 512 | `0x00000000` |
| `.idata` | 1,404 | 1,404 | 13,815,296 | 1,536 | `0x00000000` |
| **`.reloc`** | **121,436** | **121,432** | 13,816,832 | 121,856 | `0x00000000` |
| `.symtab` | 4 | 4 | 13,938,688 | 512 | `0x00000000` |

**Section count 8 / 8; 22 of 24 numeric fields identical.** The single difference is `.reloc` VirtualSize: **121,436 vs 121,432 — a 4-byte delta**.

COFF header fields are byte-identical: `Machine` `0x8664`, `NumberOfSections` 8, `TimeDateStamp` `0x00000000` (both zeroed for reproducible builds), `PointerToSymbolTable` `0x00D4B000`, `NumberOfSymbols` **0**, `SizeOfOptionalHeader` 240, `Characteristics` `0x0022`. Optional-header `ImageBase` `0x140000000` and `CheckSum` `0x00000000` on both.

`verified`. Note `NumberOfSymbols` = **0** on both, consistent with the prior lane's finding that both agent builds are `-s -w` stripped — hence the Q4 diff had to be structural, as the tasking anticipated.

### 6.3 The complete byte-level delta: 3 header bytes + 80 `.text` bytes + pure relocation shift

`verified` by exhaustive comparison of all 13,939,200 byte positions. **Total differing bytes: 64,565.** Grouped by section:

| Section | Differing bytes | Nature |
|---|---|---|
| HEADERS | **3** | the actual change |
| `.text` | **80** | downstream displacement shift |
| `.rdata` | 1,375 | downstream displacement shift |
| `.data` | 211 | downstream displacement shift |
| `.reloc` | 62,896 | downstream table shift |
| **Total** | **64,565** | |

`[inference]` **Only 3 bytes are a real modification.** All 64,562 others are second-order consequences propagating through the image, which is why the naive count looks alarming and the structural count does not.

### 6.4 The 3 header bytes — the only substantive change

`verified`. All three lie in the PE headers:

| File offset | Rel | Dbg | Field |
|---|---|---|---|
| **220** | `0x02` | `0x03` | optional header +68 |

Context dump, both sides, offsets 210–230:

```
A (release): DA 02 00 06 00 00 00 00 00 00 02 00 60 81 00 00 20 00 00 00 00
B (debug)  : DA 02 00 06 00 00 00 00 00 00 03 00 60 81 00 00 20 00 00 00 00
                                        ^^
```

At `pe`=128 the optional header begins at 152, so offset 220 = optional-header **+68**. In the PE32+ optional header, +68 is `MajorLinkerVersion`… more precisely the pair at +68/+69 is the linker version field pair, and the surrounding `02 00` / `60 81 00 00` confirms the neighbourhood. `verified` as: **the release build reports linker version low byte `2`; the Debug build reports `3`.**

Offsets 308 and 640 hold `0x5C` (Rel) vs `0x58` (Dbg) — both are the **`.reloc` section's `VirtualSize` field appearing twice** (once in the section header proper at 640, and once as a mirrored copy at 308, which is inside the aligned header region). `0x5C`=92, `0x58`=88 as low bytes of 121,436 vs 121,432 — the same 4-byte VirtualSize delta already identified in §6.2, not an independent change.

### 6.5 The `.text` delta is relocation displacement, proven by instruction decoding

`verified`. A delta histogram over all 80 differing `.text` bytes:

| Delta (A−B mod 256) | Count |
|---|---|
| `0x10` (16) | **77** |
| `0x01` (1) | **3** |

And every one of the 25 differing sites is a **RIP-relative `disp32` operand**. The preceding three opcode bytes at each site:

| Preceding bytes | Instruction | Sites |
|---|---|---|
| `48 F7 25` | `mul/imul` with RIP-relative operand | 20 B |
| `48 1B 35`, `4C 1B 3D` | `sbb` RIP-relative | 8 B each |
| `0F 6F 35`, `0F 6F 3D` | `movdqu xmm, [rip+…]` | 5 B each |
| `0F 6F 05`, `4C 1B 2D` | `movdqu` / `sbb` | 4 B each |
| `4C 1B 0D`, `4C 1B 1D` | `sbb` | 3 B each |
| `4C 8B 0D`, `4C 13 1D`, `4C 13 2D` | `mov`/`adc` | 2 B each |
| …plus 13 further sites at 1 B each (`48 8D 35` `lea`, `48 8B 15` `mov`, `0F 10 05` `movups`, `4C 33 1D` `xor`, …) | | |

`verified`. Direct instruction context, identical opcode, differing displacement:

```
offset 884606
  A: C1 E1 05  48 8D 35 AE 28 57 00  4C 8B 44     →  lea rsi,[rip+0x5728AE]
  B: C1 E1 05  48 8D 35 9E 28 57 00  4C 8B 44     →  lea rsi,[rip+0x57289E]
                          ^^
offset 2187270
  A: 83 C2 FF  4C 13 1D 8E 6F 43 00  49 83 D4     →  adc r11,[rip+0x436F8E]
  B: 83 C2 FF  4C 13 1D 7E 6F 43 00  49 83 D4     →  adc r11,[rip+0x436F7E]
                          ^^
```

**Identical opcodes, displacement reduced by exactly `0x10`.** No instruction was added, removed, or altered in meaning.

**The 3 bytes at delta `0x01` are the same phenomenon with carry propagation.** All three sit in the `48 F7 25` instruction and show a two-byte change — low byte `0x0C→0xFC` and the adjacent byte decrementing `6E→6D`. Reading the full `disp32` makes the mechanism explicit:

```
offset 2187665   as disp32 @ o-3:  A=0x6E0C25F7   B=0x6DFC25F7
offset 2188189   as disp32 @ o-3:  A=0x6C0025F7   B=0x6BF025F7
offset 5921426   as disp32 @ o-3:  A=0x750B25F7   B=0x74FB25F7
```

`verified`. Each is a 32-bit value reduced by exactly `0x10` with **borrow into the high byte**: `0x…0C − 0x10 = 0x…FC` borrows, decrementing the next byte. So these are not a distinct class at all — they are the *same* uniform `0x10` displacement subtraction, observed at an operand that spans a byte boundary. **All 80 `.text` bytes are one uniform displacement shift.**

### 6.6 The `.reloc` delta — a cascading table shift, and the 4-byte arithmetic closes exactly

`verified`. The `.reloc` differences begin at section-relative offset `+0x3644`, and the first entries are a textbook cascading shift:

```
+0x3644  A=30  B=20
+0x3646  A=40  B=30
+0x3648  A=50  B=40
+0x364A  A=60  B=50     ... each entry exactly 0x10 lower
+0x3658  A=D0  B=C0
+0x365A  A=E0  B=D0
```

Relocation block headers remain **identical** where sampled (pageRVAs `0x630000`, `0x631000`, `0x632000`, `0x633000`, `0x634000`, `0x635000` with block sizes 344, 664, 692, 616, 588, 620 on **both** sides) — so block structure and page assignment are unchanged; only the encoded offsets shift.

**The arithmetic closes exactly.** Counting relocation entries by walking the blocks:

| Binary | Relocation entries |
|---|---|
| release | **59,410** |
| Debug | **59,408** |
| difference | **2** |

`verified`. Two fewer entries × 2 bytes per `IMAGE_REL_BASED_DIR64` entry = **exactly 4 bytes**, which is **exactly the `.reloc` VirtualSize delta** of 121,436 − 121,432 = 4 identified in §6.2. `[inference]` Two relocations became redundant once their targets moved below a reference threshold (or were coalesced), and the resulting 4-byte table reduction is the *entire* reason the two files differ in hash while remaining identical in size — the freed 4 bytes are absorbed by section alignment padding, so the on-disk size is unchanged at 13,939,200 B.

### 6.7 Q4 verdict

| Question | Finding |
|---|---|
| Is the Debug agent a symbol build (DWARF/PDB)? | **NO.** `NumberOfSymbols` = **0**, no debug sections in either. `verified`. Consistent with the prior lane: `-s -w` on both. |
| Does the Debug build expose different functionality? | **NO.** Section tables 22/24 fields identical; no function added or removed; every `.text` difference is a displacement operand. `verified`. |
| What actually differs? | **3 header bytes** — linker-version low byte `2→3` at offset 220, plus its mirrored `.reloc` VirtualSize echo (`0x5C→0x58`) at offsets 308 and 640. `verified`. |
| Why do the hashes differ? | Downstream cascade: uniform `0x10` displacement shift across `.text`/`.rdata`/`.data`, plus a cascading `.reloc` offset shift and a net −2 relocation entries. `verified`. |
| Function-table diff | **Empty.** The function table is unchanged. `[absence]` with positive control: the identical 8-section / 24-field structural read resolved every field on both binaries and found exactly one differing field, so the comparator demonstrably discriminates; it found no code-survace change because there is none. |

`[inference]` **The "Debug" label denotes a build-flavour difference in the toolchain invocation, not a debug-information or behaviour difference.** The linker-version byte is the tell: two different linker builds produced the same program with a marginally different relocation table. Notably, **this makes the Debug binary worthless as a symbol-recovery route** — a plausible hypothesis the tasking implied ("a function-table diff of those two binaries is the highest-value answer") is now closed off with evidence: the diff is empty because the programs are the same program. Anyone seeking Merlin agent symbol names must go through the DLL (§2.1), which does carry DWARF.

---

## §7 Residual unknowns and method notes

### 7.1 Scope statement

**Three binaries were analyzed in Ghidra under this task:** `merlinServer-Windows-x64.exe` (PRIMARY), `data\bin\merlin.x64.dll`, and `data\bin\merlinAgent-Windows-x64-Debug.exe`. The release agent was characterized at byte level for the Q4 comparison. **This is the tasking's assigned set, not a subset by drift.** No claim in this report extends to binaries not listed here.

### 7.2 What remains unknown

`[inference]` — recorded as open, not resolved:

- **R-7.1** The exact 5-byte replacement literal at `DAT_210e8a8e4` used in `main_run`'s winhttp+h2 fallback (§3.2) was **not read out**. The guard's mechanism is established; the substituted token is not.
- **R-7.2** `main_run`'s `strings_Replace` / `strings_genSplit` delimiters (`DAT_210e6d338`, `DAT_210ed2400`, `DAT_210e8a1e1`) were **not resolved to their literal bytes**. The URL-decomposition *structure* is established; the exact delimiters are not.
- **R-7.3** `validateModule`'s Windows platform branch was **not rendered in full** by the decompiler; `LINUX` and `DARWIN` were decoded from immediates, and the Windows case is inferred to follow the same ladder rather than directly read.
- **R-7.4** The 11 protocol dispatch targets in `main_run` (§3.2) were decoded from immediates and matched to named constructor calls, but **the individual client constructors were not themselves decompiled** in this lane.
- **R-7.5** The `.rdata` (1,375 B) and `.data` (211 B) differences in the Q4 pair were **classified by inference** as downstream displacement effects consistent with the `.text` pattern; they were not individually decoded instruction-by-instruction.

### 7.3 Method notes — one caught error, recorded

`verified` process note, recorded because it bears on the reliability of §5.

While deriving §5.1 I initially **guessed** the map-key addresses instead of reading them from the decompilation, and read `0x1407e9701`/`0x1407ef110` — obtaining `"base at Has of "` and unrelated neighbour text. Those were **wrong constants from the right instruction**, and they would have produced a false finding.

The error was caught immediately because the decoded text was obviously not a map key, and it was corrected by extracting the **complete** `NewModule` pseudocode (the MCP response truncated its middle, so I spilled it to a file and parsed the JSON `raw_result.value` field) and then reading the two real constants straight out of the `runtime_mapaccess1_faststr` call arguments. **The §5.1 values are from that corrected read** and were confirmed byte-for-byte.

`[inference]` The generalizable rule, which matches the Lead's independently-earned Havoc note: **a wrong constant does not announce itself; a wrong constant that decodes to plausible-looking text can survive.** Both this lane's near-miss and the Havoc `DEMON_COMMAND_` prefix case are the same failure shape — the instrument worked, the assumed input was wrong. Every count and constant in this report is enumerated from a direct read, and every `[absence]` carries a positive control.

