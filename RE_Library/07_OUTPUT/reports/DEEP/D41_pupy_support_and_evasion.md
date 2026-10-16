# D41 — Pupy support and evasion: `hookfuncs` vs `security`, in-memory PE loading, the pyd ABI, and the KEX

**Lane:** `source-diver` · **Task:** task-45 · **Instrument:** source-only. **No REA provider held or needed. No Ghidra. No execution.**
**Tag legend:** `[source]` = read from a file on disk, cited by line. `[measured]` = a number produced by a shipped invocation, printed in this report. `[inferred]` = deduction, labelled. `[absence]` = negative result with a positive control shown able to succeed. `[instrument]` = one of my own probe failures, recorded.

---

## Table of Contents

- [§0 What this is, and three corrections to the brief](#0-what-this-is-and-three-corrections-to-the-brief)
- [§1 T1 — `hookfuncs.py` vs `security.py`: the contrast does not exist](#1-t1--hookfuncspy-vs-securitypy-the-contrast-does-not-exist)
- [§2 T4 — the `ecpv` KEX: fail-CLOSED, three layers deep](#2-t4--the-ecpv-kex-fail-closed-three-layers-deep)
- [§3 T2 — `MemoryModule.c` and `jni_on_load.c`](#3-t2--memorymodulec-and-jni_on_loadc)
- [§4 T3 — the `_pupy_pyd_args_t` ABI](#4-t3--the-_pupy_pyd_args_t-abi)
- [§5 Residual unknowns, each with a concrete probe](#5-residual-unknowns-each-with-a-concrete-probe)
- [§6 Instrument record](#6-instrument-record)

---

## §0 What this is, and three corrections to the brief

This report covers Pupy's remaining unread mechanisms: the `pupwinutils` support layer, the in-memory PE loader, the Android JNI bridge, the `_pupy.pyd` ABI contract, and the `ecpv` key exchange.

### §0.1 `hookfuncs.py` does NOT resolve functions dynamically — the contrast is an artifact

**The brief's T1 is built on a premise that does not survive measurement.**

The brief states: *"`hookfuncs.py` builds a `CFUNCTYPE` dispatch table at `:60-79` while `security.py` resolves nothing dynamically"* and asks why the directory-mate differs.

Three separate defects in that premise, all measured:

1. **`:60-79` is not a `CFUNCTYPE` dispatch table.** Lines 60–79 of `hookfuncs.py` are **`VK_`-prefixed virtual-key constants** (`VK_CAPITAL 0x14`, `VK_SHIFT 0x10`, …), the `LPMSG = POINTER(MSG)` typedef, and the `LOWORD` helper. There is **no `CFUNCTYPE` on any line in 60–79.** `[measured]` — every `FUNCTYPE` line in the file, printed:

```
L13       CFUNCTYPE, cast,                                    <- import
L20       WINFUNCTYPE                                         <- import
L81   HOOKPROC = WINFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)
L82   LOWLEVELKEYBOARDPROC = CFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)
L83   MONITORENUMPROC = WINFUNCTYPE(INT, DWORD, DWORD, ...
```

**The file has five `FUNCTYPE`-family occurrences: 2 imports, 3 typedefs.** Nothing resembling a name-string dispatch table.

2. **The "5 `CFUNCTYPE` hits" figure conflates two different callables.** Measured separately on comment-stripped source: **`CFUNCTYPE` = 2, `WINFUNCTYPE` = 3.** The 5 is their sum. `WINFUNCTYPE` and `CFUNCTYPE` are distinct `ctypes` callables with different calling-convention behaviour on Win32 (`WINFUNCTYPE` uses the `stdcall` convention, `CFUNCTYPE` the default/cdecl), and treating them as one instrument is the **substring-class** error — a probe whose shape does not match the evidence's shape.

3. **`hookfuncs.py` resolves nothing dynamically, exactly like `security.py`.** Both files reach Win32 through **static attribute access on a `WinDLL` object**. Measured, raw and comment-stripped, identical on both:

| Probe | `hookfuncs.py` | `security.py` |
|---|---|---|
| `GetProcAddress` | **0** | **0** |
| `LoadLibrary*` | **0** | **0** |
| `getattr(` | **0** | **0** |
| `cdll` | **0** | **0** |
| `WinDLL(` | **4** | **7** |
| `argtypes` | **27** | **63** |
| `restype` | **16** | **60** |

`[measured]` — raw and code-stripped counts were **identical on every row**, so no hit is a comment or a string. The invocation is in §6.1.

**Conclusion for the brief: there is no contrast to explain.** The two files are the **same design at two scales** — `security.py` is 9.5× larger (78,800 B vs 8,249 B) and declares 2.3× more `argtypes`, but both are statically-bound `WinDLL` wrappers. *"One design applied inconsistently"* is itself wrong; it is **one design applied at two sizes.**

**The directory-mate question is therefore answered and closed, and the answer is that the question rests on a false premise.** What follows in §1 is the real finding about what `hookfuncs.py`'s typedefs are for.

---

## §1 (T1) — `hookfuncs.py` vs `security.py`: the contrast does not exist

### §1.1 What `hookfuncs.py` actually is

The file's own header comment states its purpose (`hookfuncs.py:3-4`):

```python
# Place to store various bindings, wrappers, etc
# Reason: to avoid duplication of prototypes
```

**A comment is a claim, not a measurement.** The claim is testable, and it is **correct**: the file is a shared prototype store, and it is consumed by exactly the consumers the comment implies.

### §1.2 The three typedefs and their real consumers

The brief asks whether the table *"creates a call path that `security.py`'s static approach cannot express."* **It does — but not a dynamic-resolution path.** What the typedefs express is a **callback** — a native function that calls *back into Python*.

Corpus-wide consumers of the three typedefs, enumerated by name with `Get-ChildItem -Recurse` over all `.py` in the Pupy tree:

| Typedef | Defined | Consumed by |
|---|---|---|
| `HOOKPROC` (`WINFUNCTYPE`, `:81`) | `hookfuncs.py:81` | `hookfuncs.py:173` (`SetWindowsHookEx.argtypes`), **`keylogger.py:135`** (`HOOKPROC(self.hook_proc)`), **`mouselogger.py:116`** (`HOOKPROC(self.hook_proc)`) |
| `LOWLEVELKEYBOARDPROC` (`CFUNCTYPE`, `:82`) | `hookfuncs.py:82` | **nothing** — defined and never referenced anywhere in the tree |
| `MONITORENUMPROC` (`WINFUNCTYPE`, `:83`) | `hookfuncs.py:83` | `hookfuncs.py:217` (`EnumDisplayMonitors.argtypes`) |

`[measured]` — full result printed in §6.2.

**The load-bearing consumer is `HOOKPROC`, and it instantiates a Python callable as a native callback:**

```python
# keylogger.py:135
self.hook_proc_ptr = HOOKPROC(self.hook_proc)
```

```python
# mouselogger.py:116
self.pointer = HOOKPROC(self.hook_proc)
```

**This is the call path `security.py`'s static approach cannot express** — and the distinction is not static-vs-dynamic resolution. It is **direction of control flow**:

- `security.py` wraps **callee-side** APIs. Every binding is `WinDLL(...)` then `fn.argtypes`/`fn.restype` — Python calls out to Windows and receives a value. Data flows **one way, out**.
- `hookfuncs.py` declares **callback prototypes**. `HOOKPROC(self.hook_proc)` wraps a bound Python method as a C function pointer that **Windows will invoke from its own context**, on the thread that pumps the hook messages. Control flows **back in**, asynchronously, on a foreign thread.

**A callback requires a type declaration to exist at module scope and be shared**, because the function pointer must be alive and correctly prototyped at the moment `SetWindowsHookEx` is called. That is precisely what a shared "place to store various bindings" is for, and it is why the typedefs live here rather than beside their users. `security.py` needs no such shared store because **it never hands a Python callable to the OS.**

**So the correct answer to T1's final question is:** yes, the typedefs express a call path the static-wrapping file does not — **inbound native callbacks**, not dynamic symbol resolution. And the two files coexist without contradiction because they serve the two halves of the `ctypes` boundary.

### §1.3 `HOOKPROC` is a `WINFUNCTYPE`, `LOWLEVELKEYBOARDPROC` is a `CFUNCTYPE` — and the `CFUNCTYPE` one is dead

`HOOKPROC` and `LOWLEVELKEYBOARDPROC` have **identical signatures** — `(LRESULT, c_int, WPARAM, LPARAM)` at `:81` and `:82` — but differ in **calling convention**: `HOOKPROC` is `WINFUNCTYPE` (`stdcall`), `LOWLEVELKEYBOARDPROC` is `CFUNCTYPE` (cdecl). On 32-bit Windows that difference is load-bearing: a hook procedure invoked by USER32 with the wrong convention corrupts the stack.

**`LOWLEVELKEYBOARDPROC` is referenced nowhere in the tree.** `[measured]` — the corpus-wide walk returned exactly one hit: its own definition line. It is a **dead typedef**, and it is the one carrying the *wrong* convention for the same signature as the live one.

**Marked `latent`, not `live`, in D21's sense.** It is not called, so it cannot currently cause a stack fault. Its hazard is that it is a plausible-looking name (`LOWLEVELKEYBOARD` matches `WH_KEYBOARD_LL`'s semantics) sitting in a shared prototype store where a future author would naturally reach for it — and reaching for it instead of `HOOKPROC` would produce a calling-convention mismatch on x86 that manifests as a crash inside USER32, arbitrarily far from the mistake.

**`hookfuncs.py` also retains two provenance comments naming borrowed code** — `:255` `#credit: Black Hat Python` and `:276` a `nullege.com` URL for the `get_clipboard` snippet. Recorded as provenance, not as a defect.

### §1.4 `security.py`'s zero is real, and it is the *correct* pattern

`security.py`'s dynamic-resolution counts are all zero, and this report's stripping probe confirms the zeros are **code-level, not an artifact of comments or strings**. `security.py` is 2,842 lines of statically-declared `WinDLL` bindings: 7 `WinDLL(` constructors, 63 `argtypes`, 60 `restype`. **A file that reaches Windows through 123 explicit prototype declarations and no runtime lookup is a file that has been deliberately bound at import time.**

That is the single most defensible way to call Win32 from `ctypes`: a missing symbol raises `AttributeError` at **import**, not at the call site inside a hook. `security.py`'s design is not the anomaly; it is the stricter of the two, and `hookfuncs.py` follows it with only the minimum deviation required to hand out callbacks.

### §1.5 THE CORRECTION — the dispatch table exists, in `winpty.py`, and the brief transposed the file

The brief attributes a **function-name-string → prototype dispatch table at `:60-79`** to `hookfuncs.py`. **That table exists — in `winpty.py:59-80` — and the line numbers match exactly.** The file attribution was wrong; the line citation was right.

`winpty.py:59-80` is a dict literal with **19 string keys** mapping to `CFUNCTYPE` prototypes:

```python
_functions = {
    'winpty_error_code':              CFUNCTYPE(DWORD, c_void_p),
    'winpty_error_msg':               CFUNCTYPE(LPCWSTR, c_void_p),
    ...
    'winpty_conerr_name':             CFUNCTYPE(LPCWSTR, c_void_p)
}
```

`[measured]` — 19 keys, and **19/19 `CFUNCTYPE`, 0 `WINFUNCTYPE`**, which is why the per-file classification in §6.4 shows `winpty.py CFUNCTYPE=20` (19 table entries + 1 import at `:17`) against `WINFUNCTYPE=0`.

**And it is consumed as a genuine dynamic resolver** (`winpty.py:82-91`):

```python
_new_api = set(['winpty_config_set_htoken'])

for funcname, definition in _functions.items():
    funcaddr = pupy.find_function_address(DLLNAME, funcname)     # :85  RESOLUTION
    if not funcaddr and funcname not in _new_api:
        raise ImportError(
            "Couldn't find function {} at winpty.dll".format(
                funcname))                                        # :87-89  FAIL-CLOSED
    setattr(self, funcname[len('winpty_'):], definition(funcaddr))  # :91  BIND
```

**This is the only dynamic symbol resolution in the entire Pupy Python tree.** `[measured]` — a corpus-wide scan for `GetProcAddress` returned **zero across all files** (positive control: the scan succeeded on `winpty.py`, finding its `find_function_address` call — so the instrument works and the absence of `GetProcAddress` is real). `getattr(` appears 60+ times tree-wide but **almost entirely on `self`-attribute accessors, not on DLL handles**; the complete classified list is in §6.4.

### §1.6 Why `winpty.py` differs — the threat-model answer, and it is not author or era

**The distinguishing variable is not authorship and not era. It is whether the target symbol's existence is guaranteed at import time.**

- `security.py`, `hookfuncs.py` and the other statically-bound files reach **Windows system DLLs** — `user32`, `kernel32`, `gdi32`, `psapi`, `advapi32`. These are present on every Windows host Pupy can run on. A missing symbol means a broken system or a bitness mismatch, and **failing loudly at import is correct**.
- `winpty.py` binds **`WINPTY.DLL`** (`winpty.py:55`, `DLLNAME = 'WINPTY.DLL'`) — a **third-party DLL that Pupy ships and loads**, not a system component. Its exports are **version-dependent**, and the code says so explicitly: `_new_api = set(['winpty_config_set_htoken'])` at `:82` marks one symbol that **older `WINPTY.DLL` builds do not export**, and `:86` allows that specific absence to pass.

**So the design is consistent, and it is the same design everywhere:** *bind statically where the ABI is guaranteed; resolve dynamically where the dependency's version is not.* `winpty.py` is not a different design executed by a different author — it is the **same fail-closed principle applied to a dependency with different guarantees.** The dynamic path still fails closed (`:87-89` raises `ImportError` by default) and relaxes only for the one symbol the code has explicitly declared as legitimately optional.

**This answers T1's final question.** The table expresses a call path the static approach cannot: **binding an export whose presence cannot be known until the DLL is loaded, with a per-symbol policy for the ones that are permitted to be absent.** `security.py` cannot express that, and correctly does not need to.

**Contract downstream, for the reader who follows this:** `find_function_address` is **not a Python-level function.** It is imported from the native extension `_pupy` under a `hasattr` guard (`agent\__init__.py:139-142`), and **falls back to `_stub`, not to a working resolver, when the extension is absent** (`:158`, in the `except ImportError` branch). So `winpty.py`'s resolution capability is **provided by the C extension and is absent on non-native Pupy decodes.** That is a fact about where the capability actually lives — the same "the artifact is elsewhere" shape D22 and D17 §4c recorded — and it is the reason a source-only read of `winpty.py` overstates what the module can do.

---

## §2 (T2) — `MemoryModule.c` and `jni_on_load.c`

### §2.0 Boundary, justified

`MemoryModule.c` — `client\sources-windows-py3\MemoryModule.c`, **51,876 B on disk, 1,641 lines**, 50,236 bytes decoded as UTF-8.

**The boundary is `MemoryLoadLibraryEx` (`:971-1206`, 236 lines), and it is justified because that single function is the loader's control flow.** Every mechanism the brief asks about is a direct call inside it, in a fixed order. The other 1,405 lines are the stage bodies, the resource API (`:1359-1641`), and `_MemoryGetProcAddress`/`MemoryFreeLibrary`. **I read the control flow in full plus the bodies of the five staged mechanisms; I did not read the resource-manager functions `_MemoryFindResourceW`/`_MemoryLoadString` (`:1359-1641`), which are not on the load path.**

**Line/byte note:** the decoded byte count differs from the on-disk size by 1,640 bytes. **`[instrument]`** — the file carries **CRLF line endings**, so every one of the 1,641 line splits consumes 2 bytes on disk but 1 in the decoded string. `1,641 × 1 = 1,641 ≈ 1,640` (final line unterminated). **Not a discrepancy, and I checked rather than assumed it.**

### §2.1 The loader pipeline — seven stages, in order, with failure paths

`MemoryLoadLibraryEx` (`:971`) runs a fixed sequence. **Six of the seven stages `goto error` on failure; the seventh cannot fail.**

| # | Stage | Call site | Failure behaviour |
|---|---|---|---|
| 0 | Input validation | `:993-1038` | `return NULL` directly (pre-`result`), `SetLastError` set |
| 1 | Allocate image + `MEMORYMODULE` | `:1050-1070` | `goto cleanup` / `goto cleanup` — **`VirtualFree` first at `:1067`** |
| 2 | Copy headers | `:1089-1099` | **unchecked** — `VirtualAlloc` return not tested |
| 3 | `CopySections` | `:1102` | `goto error` |
| 4 | `PerformBaseRelocation` | `:1107-1112` | records `result->isRelocated`, **does not `goto error`** |
| 5 | `BuildResourceTables` | `:1115` | `goto error` |
| 6 | `BuildImportTable` | `:1121` | `goto error` |
| 7 | `FinalizeSections` | `:1128` | `goto error` |
| 8 | `ExecuteTLS` | `:1133-1137` | `goto error` |
| 9 | `RegisterExceptionTable` | `:1140-1145` | `goto error` (**x64 only**) |
| 10 | `BuildExportTable` | `:1150` | **`void` — cannot fail** |
| 11 | Entry point | `:1153-1174` | `goto error` on `DLL_PROCESS_ATTACH` returning FALSE |

**The two failure exits are different and both are correct:**

- **`cleanup:` (`:1185-1192`)** — reached by validation failures and the allocation failures. Unmaps the view and closes the mapping, then **returns `result`**, which is `NULL` on the validation paths and **non-NULL on the successful path**. This is the normal exit.
- **`error:` (`:1194-1205`)** — reached by any stage failure. **Calls `MemoryFreeLibrary(result)` (`:1197`) to unwind, then unmaps and closes, then `return NULL`.**

**This is fail-closed and it unwinds.** `MemoryFreeLibrary` (`:1310`) is the inverse of the load: it runs `DLL_PROCESS_DETACH` if `result->initialized` is set, frees the import table, and releases the code pages. **Because `result->initialized = TRUE` is set only at `:1173` after a successful entry-point call, a failure before that point frees memory without delivering a `DETACH` to a DLL that never received `ATTACH`** — the correct pairing.

### §2.2 The five mechanisms, each with its API and its failure path

**1. Section mapping — `CopySections` (`:154`).**
Copies each `IMAGE_SECTION_HEADER` from the file image to `codeBase + VirtualAddress`, and **commits** the destination range. **Failure → `FALSE` → `goto error` (`:1103`).** The loader maps sections at their **declared virtual addresses**, which is why the image must be allocated at the preferred base or relocated — the two are coupled, and stage 2's comment (`:1041-1043`) documents the coupling.

**2. Relocation — `PerformBaseRelocation` (`:368`).**
Walks `IMAGE_DIRECTORY_ENTRY_BASERELOC`, and per block computes `type = *relInfo >> 12` and `offset = *relInfo & 0xfff` (`:391-393`) — **the standard 4-bit-type/12-bit-offset split.** `IMAGE_REL_BASED_ABSOLUTE` is skipped (`:397-399`); `IMAGE_REL_BASED_HIGHLOW` adds `delta` to a 32-bit location (`:401-405`); `IMAGE_REL_BASED_DIR64` handles 64-bit (`:408-409`, `_WIN64` only).

**This is the one stage that does NOT `goto error`, and the reason is a design choice worth naming.** `:374-376`:

```c
if (directory->Size == 0) {
    return (delta == 0);
}
```

and at the call site `:1107-1112`, the result is **recorded, not tested**:

```c
locationDelta = (SIZE_T)(code - old_header->OptionalHeader.ImageBase);
if (locationDelta != 0) {
    result->isRelocated = PerformBaseRelocation(result, locationDelta);
} else {
    result->isRelocated = TRUE;
}
```

**A `FALSE` return means the image has a relocation directory but could not be applied at a non-zero delta** — an image that is **now silently broken at every relocated address**, and the loader **continues**. `isRelocated` is stored on the module (`:1109`) and **never tested on the load path.** `[measured]` — the flag is written at `:1109`/`:1111` and read nowhere in this file.

**This is the strongest defect candidate in `MemoryModule.c`, and it is marked `latent`, not `live`:** the outcome is a load that *appears* to succeed while returning a module whose absolute addresses are wrong, which would fault on first call rather than at load. **Liveness depends on whether a real payload is ever loaded at a non-preferred base with relocations present** — not established here, and not demonstrable from source alone. Carried as residual §5.4.

**3. Import resolution — `BuildImportTable` (`:520`).**
For each import descriptor, loads the named DLL and resolves each `IMAGE_IMPORT_BY_NAME` to an address, writing the IAT in place. The hook surface is `GetHooks` (`:505`) and `ImportHooks`, and the export-name policy is `isAllowedSymbol` (`:749`) — both part of this repo's additions to the upstream library.

**Failure → `FALSE` → `goto error` (`:1122`).** **This is the one stage where the process's real DLL loader is engaged** — the in-memory module's imports resolve against genuine system DLLs, so an import of a DLL absent from the host fails the load. Fail-closed.

**4. TLS callbacks — `ExecuteTLS` (`:340`).**
Reads `IMAGE_DIRECTORY_ENTRY_TLS`; if `VirtualAddress == 0` returns `TRUE` immediately (`:348-351`, with the `"No TLS callbacks.."` trace). Otherwise walks `tls->AddressOfCallBacks` and **invokes each callback directly**, `DLL_PROCESS_ATTACH`, `NULL` reserved (`:358-362`). Returns `TRUE` unconditionally after the walk.

**This stage CANNOT report failure.** `:364` returns `TRUE` on every path, and the call site `:1133-1137` does `goto error` on a return that is never `FALSE`. **A TLS callback that faults takes the process down inside its own entry; there is no error return to observe.** The only control is the flag test `_ISSET(flags, MEMORY_LOAD_NO_TLS_CALLBACKS)` at `:1133`, which skips the stage entirely. **The comment at `:1132` — "TLS callbacks are executed BEFORE the main loading" — is the author's claim, and the code confirms the ordering: `ExecuteTLS` at `:1134` precedes the entry point at `:1164`.** `[source]` — verified by call order, not by the comment.

**5. Entry-point dispatch — `:1153-1174`.**
Gated by three conditions: `!_ISSET(flags, MEMORY_LOAD_NO_EP)` **and** `result->isDLL` **and** `result->pcDllEntry` non-null. `isDLL` comes from `IMAGE_FILE_DLL` in the file header at load (`:1074`), so **an EXE payload never receives an entry-point call through this path** — its entry is reached by whatever calls it after `MemoryGetProcAddress`. The call is `pcDllEntry((HINSTANCE)code, DLL_PROCESS_ATTACH, reserved)` with `reserved` **forced to `NULL` under `MEMORY_LOAD_ALIASED`** (`:1166`). **Failure (`FALSE`) → `SetLastError(ERROR_DLL_INIT_FAILED)` → `goto error` (`:1169-1172`).** Only on success is `result->initialized = TRUE` set (`:1173`).

### §2.3 Two more behaviours on the load path

**Headers are wiped on the success path only.** `:1178-1183`, guarded by `#ifndef DEBUG`, calls `CleanupHeaders(result)` (`:891`) **after** the entry point runs and **before** `cleanup:`. **A failed load retains its headers** — consistent with the `error:` path running `MemoryFreeLibrary` instead.

**Header memory is committed, not reserved.** `:1089-1095` allocates `SizeOfHeaders` at `code` with `MEM_COMMIT, PAGE_READWRITE` and `memcpy`s the headers there. Combined with `CleanupHeaders` on success, this is the standard pe-to-mem pattern: **headers exist during load and are removed after.** `[inferred]` — the intent is read from the ordering, not from a comment stating it.

### §2.4 The x64-vs-x86 asymmetry, and a `#if DEBUG` allocation that nobody ships

**Machine-type validation is compile-time-selected** (`:1025-1032`): `_WIN64` requires `IMAGE_FILE_MACHINE_AMD64`, else `IMAGE_FILE_MACHINE_I386`. **A 64-bit build cannot load a 32-bit payload and vice versa — the loader fails closed with `ERROR_BAD_EXE_FORMAT` at `:1030`.** This is the same architecture-pinning the corpus recorded in D5 §3 and D14, appearing here as a **hard reject** rather than a degradation.

**`:1040-1048` is the interesting one.** The preferred-base allocation is wrapped in `#if DEBUG`:

```c
#if DEBUG
    code = (unsigned char *)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase),
        old_header->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#endif

    if (code == NULL) {
        // try to allocate memory at arbitrary position
        code = (unsigned char *)VirtualAlloc(NULL, ...);
```

**In a release build `code` is still `NULL` at `:1050`, so the preferred-base attempt is compiled out and every release load takes the arbitrary-position branch.** That means **`locationDelta != 0` is the normal case in a release build** (`:1107`), which is precisely the condition under which stage 4's untested `PerformBaseRelocation` return matters. **The `#if DEBUG` guard converts "try preferred base, fall back" into "always relocate" for every shipped binary.** `[source]` for the guard; `[inferred]` for the consequence, which follows from `code == NULL` at `:1050` in a non-`DEBUG` build.

**This is why §3.2's latent defect is worth carrying rather than dismissing.** The relocation path is not an edge case in release builds; it is the only path.

### §2.5 `jni_on_load.c` — not read in this pass

**`jni_on_load.c` (30,294 B) and the `_pupy_pyd_args_t` ABI were NOT read.** Both are within **task-16 (D6 §14)**, which is `in_progress` under this same owner, and writing them here as well would duplicate that lane. **The scope question is with the Lead.** Stated plainly rather than silently omitted: **T2's `MemoryModule.c` half is complete; T2's Android half and all of T3 are open.**

---

## §3 (T3) — the `_pupy_pyd_args_t` ABI

### §3.0 Boundary and method

**Method note, per the Lead's D56 warning:** every claim below comes from an **enumeration**, not a name filter. The type name was searched whole-tree (**5 sites**, §6.6), the `pupy.c` switch was **enumerated case-by-case** rather than filtered (**one switch, five cases, all five printed, no `default`** — §6.7), and the preprocessor census is a **per-file count of `#ifdef`/`#else`/`#endif`** (§6.8). A name-driven filter over a switch body silently dropped 2 of 30 cases in D56; this section does not use one.

**Scope note:** the Lead confirmed T3 belongs to D41 and retired task-16 as **superseded** (not complete). `D6_pupy_code.md` has **not** been touched. This section is the single home for this material.

### §3.1 The struct — three fields, compile-time gated

**Defined in `pupy_load.h:10-14`, and the entire definition sits inside a preprocessor branch:**

```c
typedef VOID (*on_exit_session_t)(VOID);          // :6

#ifdef _PUPY_DYNLOAD                              // :8

typedef struct _pupy_pyd_args {                   // :10
    PVOID *pvMemoryLibraries;                     // :11
    on_exit_session_t cbExit;                     // :12
    BOOL blInitialized;                           // :13
} _pupy_pyd_args_t;                               // :14
#else                                             // :15
void on_exit_session(void);                       // :16
#endif                                            // :17
```

**Three fields. One in, one out, one handshake:**

| Field | Type | Direction | Purpose |
|---|---|---|---|
| `pvMemoryLibraries` | `PVOID *` | **caller → pyd** | array of already-loaded memory-module handles |
| `cbExit` | `on_exit_session_t` | **pyd → caller** | exit callback the pyd installs |
| `blInitialized` | `BOOL` | **pyd → caller** | success handshake |

**The struct does not exist in a non-`_PUPY_DYNLOAD` build.** `:15-17` provides only an `on_exit_session` *function declaration* instead. So the ABI is **either binary-present or entirely absent by compile flag** — there is no partially-populated runtime variant to reason about. `[source]` — `pupy_load.h:8-17`.

### §3.2 The writer — `pupy_load.c`, all three fields set, one read back

`initialize()` declares the struct **under the same flag** (`pupy_load.c:230-232`), then at `:378-395`:

```c
#ifdef _PUPY_DYNLOAD
    dprint("_pupy built with dynload\n");

    args.pvMemoryLibraries = MyGetLibraries();     // :381  populate
    args.cbExit = NULL;                            // :382  CLEARED before the call
    args.blInitialized = FALSE;                    // :383  CLEARED before the call

    dprint("Load _pupy\n");
    HMODULE pupyhMod = xz_dynload(
        "_pupy.pyd",
        _pupy_pyd_c_start, _pupy_pyd_c_size,
        &args                                      // :389  BY REFERENCE
    );

    if (args.blInitialized != TRUE) {              // :392  HANDSHAKE CHECK
        dprint("_pupy.pyd initialization failed\n");
        return;                                    // :394  BAIL OUT
    }
```

**Four properties, each load-bearing:**

1. **`&args` is passed by reference** (`:389`) — the pyd mutates the caller's struct. This is an **out-parameter ABI**, not a value copy.
2. **All three fields are explicitly initialised before the call** (`:381-383`), including **`cbExit = NULL` and `blInitialized = FALSE`**. Both pyd-written fields are **cleared to a known-failed state first**, so an untouched struct reads as *"not initialised"* — the safe default.
3. **`blInitialized` is the sole success discriminator** (`:392`), and on failure `initialize()` **`return`s early** (`:394`) — **the `PyInit__pupy` call at `:403` is never reached.**
4. **`xz_dynload`'s return is used without a null check.** `pupyhMod` is assigned at `:386` and passed to `MyGetProcAddress` at `:399` **with no test on `pupyhMod`**. `[source]` — the binding is unconditional; whether `MyGetProcAddress` validates internally is a residual (§5.5).

### §3.3 The reader — `pupy.c` DllMain, and the pointer-range guard

The pyd reads the struct in `DllMain` (`pupy.c:493-524`), at `DLL_PROCESS_ATTACH`:

```c
case DLL_PROCESS_ATTACH:                           // :503
    hAppInstance = hinstDLL;                       // :504
    if (lpReserved > 0xFFFF) {                     // :505  RANGE GUARD
        _pupy_pyd_args_t *args =
                (_pupy_pyd_args_t*) lpReserved;    // :506-507  CAST

        if (args->pvMemoryLibraries) {             // :509  NULL-CHECKED
                MySetLibraries(args->pvMemoryLibraries);   // :510
        }

        args->cbExit = on_exit_session;            // :513  WRITE BACK
        args->blInitialized = TRUE;                // :514  HANDSHAKE
    }
    return TRUE;                                   // :516
```

**`:505` `if (lpReserved > 0xFFFF)` is the most interesting line in this ABI, and it is a discriminator, not a validity check.**

`lpReserved` is `DllMain`'s third parameter, whose documented meaning varies by load mechanism. Under a **normal `LoadLibrary`** it is `NULL` for a dynamic load and non-`NULL` for a static load. Under a **reflective/manual mapper** it is whatever the mapper passes — here, **the caller's `&args` pointer** (`pupy_load.c:389`).

**`0xFFFF` is a heuristic boundary between "a small integer Windows might pass" and "an address in user space."** On 32-bit Windows any legitimate user-mode address exceeds `0xFFFF`. The guard therefore reads as: *"treat `lpReserved` as our struct only if it is plausibly a pointer."*

**This is fail-safe, and the two ends agree.** A non-null `lpReserved` that is a small integer is skipped, and the pyd **still returns `TRUE`** (`:516`) **without setting `blInitialized`** — so the caller sees the handshake fail and bails at `pupy_load.c:392`. **An unrecognised `lpReserved` produces a clean failure at the caller rather than a misinterpreted struct.** Good design, recorded as such.

**The residual is the false-positive direction:** an `lpReserved` above `0xFFFF` that is **not** our struct — e.g. a legitimate large non-null `lpReserved` from a static load — **would be cast and dereferenced at `:509`, then written at `:513-514`.** `[inferred]` — this requires `_pupy.pyd` to be loaded by a mechanism passing a large non-null `lpReserved` while `_PUPY_DYNLOAD` is in effect. Carried as residual §5.6. **Not claimed as exploitable:** it needs a load path not observed here, and the shipped path (`xz_dynload`, `:386`) passes a genuine struct.

### §3.4 Size-mismatch behaviour — the structural answer

The brief asks what happens on a size mismatch. **There is no version field, no size field, and no magic value** (`pupy_load.h:10-14`), so a mismatch cannot be detected by the ABI itself. What happens is decided by the **compile flag**, and the flag is the real contract:

- **Both sides `_PUPY_DYNLOAD`** — struct exists on both sides, matching layout. **Correct.**
- **Caller without, pyd with** — `pupy_load.c` never declares `args` (gated at `:230-232`) and takes the `#else` branch, calling `PyInit_pupy()` directly (`:421`). The pyd has the type but is never handed one, so `DllMain` sees a normal `lpReserved` and **skips `:505`**, returning `TRUE` with `blInitialized` untouched and never read. **Degraded but not miscompiled.**
- **Caller with, pyd without** — `initialize()` populates all three fields, passes `&args`, then **waits for `args.blInitialized != TRUE`** (`:392`). A pyd without the reader never sets it, so **`initialize()` returns early at `:394` and the interpreter never initialises.** **Fail-closed.**

**So the mismatch story is: the ABI is all-or-nothing by compile flag, and every mixed combination fails closed rather than corrupting.** That is why the `blInitialized` handshake exists at all — **without it, the third case would silently proceed to call `PyInit__pupy` on a pyd that never received its libraries.**

**Layout-identity caveat, stated not assumed:** the struct crosses **two separately-compiled binaries by pointer**, so its layout is fixed by their ABIs and not by any wire encoding. Both are built from this tree by `build-docker.sh`, so layouts agree **by construction, not by negotiation**. `[inferred]` — I did not verify build flags for both artifacts; the `.pyd` is not in this tree (§6.9).

### §3.5 The exit callback — one name, two directions, and why `cbExit = NULL` is not redundant

The pyd writes `cbExit` as `on_exit_session` (`pupy.c:513`), and the caller immediately stores it (`pupy_load.c:418` `on_exit_session_cb = args.cbExit;`). That static then runs from **two independent triggers**:

- **`OnThreadCrash`** (`pupy_load.c:202-206`) — guarded `if (on_exit_session_cb && !on_exit_session_called)`, sets `on_exit_session_called = TRUE` (`:205`), calls it (`:206`).
- **The window procedure's exit message** (`:468-471`) — same guard, same single-shot flag.

**The `on_exit_session_called` flag (`:33`) makes the callback idempotent across both paths** — a crash and a clean exit cannot both fire it. Correct and deliberate.

**And `args.cbExit = NULL` at `:382` is not redundant with `blInitialized = FALSE`.** It initialises the field that becomes `on_exit_session_cb` (`:418`) to null, so that **if the pyd returns without writing it, the stored callback is null and both guarded call sites skip** (`:202`, `:469` each test for non-null). **The clearing at `:382` is what makes those guards reachable in the failure case** — a caller that skipped it would store an uninitialised value and a guard could pass on garbage.

### §3.6 What the Python layer sees of this ABI

`_pupy` supplies eight capabilities to Python — `find_function_address`, `reflective_inject_dll`, `ld_preload_inject_dll`, `mexec`, `set_exit_session_callback`, `_import_module`, `_load_dll`, `get_arch` — and **every one is bound under a `hasattr` guard with a `_stub` fallback** (`agent\__init__.py:120-160`). **The ABI struct itself is never visible to Python**: it is consumed entirely inside `DllMain` during load, and Python only ever sees the resulting module attributes. So the struct's contract is **native-to-native only**, and the Python-side `hasattr` pattern is a *separate, later* capability-negotiation layer.

**Worth stating because it corrects a natural assumption:** the eight optional capabilities are **not** fields in `_pupy_pyd_args_t`. The struct carries three things (libraries in, callback out, handshake); the capability set is discovered afterwards by `hasattr` on the imported module. **Two different negotiation mechanisms at two different times**, and conflating them would misread the ABI's size.

---

## §4 (T4) — the `ecpv` KEX: fail-CLOSED, three layers deep

**The brief's highest-severity question: is there a path where the peer is not authenticated?**

**Answer: no such path exists in this code, and the reason is structural rather than a check that could fail open.** The expected finding — the expected fail-open — is **not present**. This is the same shape as msf-diver's D54 result: the bug that was expected is not there, and the correct report says so.

### §4.1 Layer 1 — the peer key is a CONSTRUCTOR ARGUMENT, never a wire field

The decisive structural property. Every one of the **five** `ECPV` construction sites in the tree supplies key material at object-construction time:

| Site | Construction | What it supplies |
|---|---|---|
| `picocmd\client.py:153` | `ECPV(public_key=key, curve='brainpoolP224r1')` | **peer public key** |
| `picocmd\server.py:347` | `ECPV(private_key=key[0])` | **own private key** (v1) |
| `picocmd\server.py:348` | `ECPV(private_key=key[1], curve='brainpoolP224r1')` | **own private key** (v2) |
| `transports\ec4.py:37,43` | `ECPV(public_key=...)` / `ECPV(private_key=...)` | one or the other |
| `transports\ecm.py:42,48` | `ECPV(public_key=...)` / `ECPV(private_key=...)` | one or the other |

`[measured]` — full corpus-wide enumeration in §6.3.

**The public key is never read off the wire.** It arrives as a keyword argument from a caller that already possesses it. So there is no code path in which a remote peer **selects its own key material** and has it accepted: to reach `unpack`/`decrypt`, the object must already have been constructed with a key the local side chose.

**And construction fails closed when neither is supplied.** `ec4.py:33-34` and `ecm.py:38-39` both open `__init__` with:

```python
if not self.pubkey and not self.privkey:
    raise ValueError('Public or Private key required for EC4')
```

**A missing key raises at construction, before any transport state exists.** That is fail-closed by exception at the earliest possible point — not a later predicate that could be skipped.

### §4.2 Layer 2 — the KEX is authenticated by a Schnorr-style commitment

The exchange is EC-ElGamal (ECIES) over a Brainpool curve, with a commitment binding the sender to its ephemeral key.

**Outbound, `pack` (`ecpv.py:196-225`):**

```python
while not (t and s):
    k = self._gen_random()
    R = self._curve.g * k
    key = self._mgf2(ec2osp(R), 16)
    r = self.encrypt(message, nonce, key=key)
    hash = self._hash.new()
    hash.update(r + (struct.pack('>I', nonce) if nonce else b'')
                   + struct.pack('>I', len(r)))
    u = hash.digest()[:self._curve.bytes]
    t = from_bytes(u)
    if not (t > 1 and t < self._curve.field.n):
        continue
    s = (k - self._private_key * t) % self._curve.field.n
```

**Inbound, `unpack` (`ecpv.py:227-245`):**

```python
s = from_bytes(message[:self._curve.bytes])
r = message[self._curve.bytes:]
...
t = from_bytes(u)
if not (t >= 0 and t < self._curve.field.n):
    return None
R = self._curve.g * s + self._public_key * t
if R.inf:
    return None
key = self._mgf2(ec2osp(R), 16)
return self.decrypt(r, nonce, key=key)
```

`s = k - priv*t (mod n)` and recovery `R = g*s + pub*t` — the Schnorr commitment identity, because `g*s + pub*t = g*(k - priv*t) + g*priv*t = g*k = R`. **The recovered `R` seeds the MGF, so the AES key is a function of the commitment.** An attacker who cannot produce a valid `(s, r)` pair cannot produce the key that decrypts `r`.

**Both failure paths return `None` rather than raising:** `unpack:239` on `t` out of range, and `unpack:242` on the point-at-infinity check. **A failed verification yields `None`, which downstream must handle** — and `decrypt` at `:355` layers a further `None` return on a padding mismatch. *"Returns None on failure"* is a fail-closed contract, though it shifts the burden to the caller: a caller that does not test for `None` will raise `TypeError` rather than silently accept. See §5.1 for the residual.

### §4.3 Layer 3 — the response is verified before the shared key is set

`process_kex_response` (`ecpv.py:264-274`):

```python
if decrypt:
    response = self.unpack(response, nonce)

P1 = osp2ec(self._curve, response)
if not P1:
    raise ValueError('Invalid ECDH PK response')

key = self._mgf2(ec2osp(P1 * self._kex_private_key), key_size)
self._kex_shared_key = (key, _reversed_bytes(key))
```

**`self._kex_shared_key` is assigned only after `unpack` has returned a non-`None` value AND `osp2ec` has produced a valid curve point.** A malformed or unauthenticated response raises `ValueError` **before** any shared key is installed. **The key is not set to a degraded value on failure — it is not set at all.**

The two directions use the **same bytes in reverse order** (`:273`), so `_kex_shared_key[0]` keys one direction and `[1]` the other. This is confirmed by the module's own shipped self-test at `:407-411`, which runs the full round trip and asserts the reversal:

```python
req = verifier.generate_kex_request()
resp, key = signer.process_kex_request(req, 0)
key2 = verifier.process_kex_response(resp, 0)
if not list(key) == list(reversed(key2)):
    print("KEX FAILED", key, key2)
    break
```

**This is a verification harness, not a claim.** `[source]` — `ecpv.py:370-412` is an `if __name__ == '__main__':` self-test exercising `generate_key`, `pack`/`unpack`, `encrypt`/`decrypt`, `encode`/`decode` byte-precise, plus the KEX round trip. It is strong evidence the KEX is live and exercised, though **the harness was not executed in this lane** (no execution, §6.5) — so it is evidence of intent and coverage, not a passing test run.

### §4.4 The `process_kex_request` caching path — and why it is not a bypass

`process_kex_request` (`:252-262`) short-circuits:

```python
if request == self._cached_kex_request and self._kex_shared_key:
    return self._cached_kex_response, self._kex_shared_key
```

**An identical repeated request returns the cached response and key without recomputation.** Examined as a potential replay/downgrade path and **found not to be one**: the cache is keyed on the **exact request bytes**, and the cached value is returned only when `self._kex_shared_key` is already set. An attacker replaying a captured request therefore gets back a **response to a key exchange they already saw**, for a session whose key they still do not possess — the response is not new key material. A *downgrade* would require the cache to return a weaker key on a second request; it returns the same key.

**Marked `latent`, not `live`.** The cache is an idempotence optimisation whose security depends on the request being unpredictable (`_gen_random()` at `:204`, `:248`). Not currently exploitable on the evidence read here. Recorded as a **residual with a probe** (§5.2), because establishing non-exploitability would require tracking the client's request-generation path, which is outside the files read in full.

### §4.5 Two asymmetries worth naming

**`check_csum`/`gen_csum` disagree on key index — correctly.** `gen_csum` (`:292-297`) selects `self._kex_shared_key[0]`; `check_csum` (`:276-281`) selects `self._kex_shared_key[1]`. Since `[1]` is `_reversed_bytes([0])`, that is **intentional** — each direction keys with its own half. **Not a defect.** Recorded because it reads as an inconsistency at a glance and the next reader will otherwise stop on it.

**The pre-KEX fallback is keyed by a PUBLIC value.** Both functions fall back to `self._public_key_digest` when no KEX has occurred (`:281`, `:297`), as do `encrypt` (`:313`) and `decrypt` (`:336`). `_public_key_digest` is `_mgf2(ec2osp(public_key), AES_BLOCK_SIZE)` (`:187-189`) — **derived from the public key alone, therefore public.** Pre-KEX traffic is encrypted under a key an observer can compute. This is the **Pupy-wide design** already recorded in D11_pupy_transport_crypto and is not a new finding here; noted so §2 does not read as though the KEX is the only path. **The KEX is authenticated; the pre-KEX bootstrap is not, by construction.** Whether that matters depends on what is transmitted before KEX completes — a **residual with a probe** (§5.3).

---

---
