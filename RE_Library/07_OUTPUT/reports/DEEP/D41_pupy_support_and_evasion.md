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

## §1 T1 — `hookfuncs.py` vs `security.py`: the contrast does not exist

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

---

