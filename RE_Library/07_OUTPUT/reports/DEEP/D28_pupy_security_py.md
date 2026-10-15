# D28 — `security.py`: the LSA / credential / privilege toolkit

**Target:** `RE_Library/01_SOURCE_c2/pupy/pupy/packages/windows/all/pupwinutils/security.py`
**Verified:** **78,800 B / 2,842 lines** — `Get-Item` + `(Get-Content).Count`, two independent methods, agreeing. **D6 `U-5` / `D6:2048`'s figure is byte-exact.**
**Path note:** the doubled `pupy\pupy\packages\...` prefix is **correct for this subtree** (contrast `network\`, which needs a single prefix — D6's recorded path trap is real but not uniform). **Confirmed by filesystem enumeration, not assumed.**
**Method:** source-only. Every count enumerated; every headline count recomputed by a second method. Positive control on every absence. Reachability stated as `latent` / `unreachable-from-corpus` — no "live," no "fixed."

---

## HEADLINE

**1. D6 §1's "dynamic-resolution pattern visible throughout `security.py`" is FALSIFIED — and the real pattern is more interesting than the claim.**
`GetProcAddress` → **0**. `LoadLibrary` → **0**. `WINFUNCTYPE`/`CFUNCTYPE` → **0**. `getattr(` → **0**. **There is no resolution shim in this file.** What exists is **7 × `ctypes.WinDLL('name', use_last_error=True)` at module scope** (`:43-48`, `:1149`) plus **~65 module-scope rebindings** of the form `AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges`. **That is lazy `ctypes` attribute binding, which is the default any `WinDLL` user gets — not an anti-analysis measure.** The API names sit in the source as plain literals.

**2. The positive control is decisive, and it is inside the corpus — CORRECTED TWICE, and each correction makes the inversion STRONGER.** Whole-tree probe over all **493** `*.py` files: **35 genuine uses of `GetProcAddress`/`LoadLibrary`/`WINFUNCTYPE`/`CFUNCTYPE` across 6 files**, led by **`winpty.py` (20)** and **`hookfuncs.py` (5)**. **`security.py` — the largest Windows toolkit in the corpus — has zero**, while **its own directory-mate `hookfuncs.py` has five and `winpty.py` has twenty.** `winpty.py`'s 20 hits are a **`CFUNCTYPE` dispatch table mapping function-name strings to prototypes** (`:60-79`) — **the genuine dynamic-binding pattern, alive in `windows/all/` and absent from the credential module.** *My first publication read "9 across 5" because my match pattern covered two of the four primitives while the table above it listed four; the Lead caught it. Correcting it surfaced a second error — `winerror.py`'s `TYPE_E_CANTLOADLIBRARY` is a constant name matching `LOADLIBRARY` as a substring, and PowerShell's case-insensitive `Select-String` counted it. Both corrections recorded in §0.3.*

**3. `security.py` is the privilege-escalation core, and §3 enumerates the escalation-capable set.** It contains **a complete SYSTEM-impersonation chain** (`getsystem` `:2015` → `create_proc_as_sid` `:1993` → `start_proc_with_token` `:2029`) and **a full DACL reader/writer** (`access` `:2253`, `Ace` `:2484`, `getfileowneracls` `:2619`). **What it cannot do** is stated with equal precision in §3.4. **THE PRECONDITION, stated plainly: `getsystem` is a two-line wrapper whose real gate is `getSidToken` (`:1823-1844`), which requires `SeDebugPrivilege` (`:1827`) AND an accessible `winlogon` process (`:1832`). A function whose name suggests escalation but whose precondition is "already escalated" is worth stating as such — it requires already-admin-equivalent access.**

**3b. HONESTY PASS — what the name implies vs what the module does.** **`security.py` is NOT a credential harvester.** No DPAPI (`CryptUnprotectData`), no `CredEnumerate`/`CredRead`, no SAM, no NTDS, no LSASS memory read. **The files that touch that material are `wdigest.py` and `bypassuac_token_imp.py`, which sit beside it in the same directory.** It **is** a complete token-manipulation, impersonation, and DACL toolkit. **The name oversells credential theft and undersells token manipulation.**

**4. The missing-sibling check resolves NEGATIVELY: `security.py` imports nothing that is absent.** `persistence.py` **exists in three places** (`modules/`, `packages/linux/all/`, `scriptlets/`); only the **Windows package** variant is absent, and **no file in `pupwinutils/` references it at all.** So the finding is a **platform-coverage gap**, not a dangling reference — and `security.py` is **not** a broken subsystem. §4 enumerates the complete import set.

**5. `security.py` is 55.9% of the `pupwinutils/` tree** — 78,800 B of 140,624 B total, **5.2× the next largest file** (`bypassuac_token_imp.py`, 15,247 B). **This supersedes D6:2048's "4× the next Windows module" — that figure is directionally right and understated; record 55.9% / 5.2× as the correction to D6.**

**6. The most novel technique in the file is not a Win32 wrapper at all.** `security.py:1891-1911` **monkey-patches `threading.Thread._bootstrap_inner` at import**, calling `ImpersonateLoggedOnUser(global_ref)` on **every thread spawned in the process** — necessary because Windows impersonation is per-thread, and the only genuinely anti-reader construct in the file, since it sits at module scope between two `def`s where a function-skimmer will not look. `except ImportError: pass` (`:1905`) makes a broken impersonation **silent**.

---

## TABLE OF CONTENTS

- §0 Instrument record — probe failures, including one this task
- §1 The file in full: outline, structure, and the import surface
- §2 Q2 — the binding mechanism, and D6 §1 falsified
- §3 Q1 + Q3 — the capability set by Win32 API, and the escalation-relevant subset
- §4 Q4 — the missing-sibling check
- §5 Q5 — hardcoded values: SIDs, GUIDs, privilege strings, policy constants
- §6 Residual unknowns, corrections, and honest coverage
- §7 D6 reconciliation note (if taken)

---

## 0. Instrument record — probe failures, as mandated

**This round has logged eight instrument failures across six agents, all one root: a probe whose shape does not match the evidence's shape.** Recorded here are mine.

### 0.1 Probe failure #1 (this task) — the path-shape guess, avoided

**The task message specified `pupy\pupy\packages\windows\all\pupwinutils\security.py`.** D6 had previously logged a path trap in the **`network\`** subtree, where the doubled `pupy\pupy\` prefix returned zero rows and the correct form was a **single** `pupy\`. **Had I generalized that correction to this subtree, I would have probed a nonexistent path and reported a false absence for the single largest file in the corpus.**

**Avoided by locating from the filesystem first** (`Get-ChildItem -Recurse -Filter security.py`), which returned exactly one hit at the doubled path, with a positive control (15 files listed in `pupwinutils/`). **The doubled prefix is correct here; the single prefix is correct in `network\`. The path shape is not uniform, so an inherited correction is as dangerous as an inherited assumption.**

### 0.2 Probe failure #2 (this task) — console encoding misdiagnosis, the mirror of D11's real defect

**A probe reported `mojibake A-circ: 48` in the sibling D24 report.** I diagnosed UTF-8-plus-mojibake corruption and prepared a byte-level repair. **The repair was a no-op.** Byte-level re-read: `Acirc = 0`, `ahat = 0`, **118 real em-dashes**, 40,134 B unchanged.

**The file was never corrupted — `Get-Content` rendered real UTF-8 through the wrong console code page.** In the D11 lane the mojibake was **real**; here it was **an artifact of the measuring instrument**. **Same probe, opposite verdicts, decided only by the byte read.** Recorded because a probe that produces a false positive is as dangerous as one that produces a false negative: the first one nearly caused me to rewrite a clean file.

### 0.3 Probe failure #3 — **CORRECTED BY THE LEAD. The control's denominator was wrong, and this is the report's most important instrument entry.**

**I published the positive control as "9 instances across 5 files." The correct figure is 35 instances across 6 files.**

**The Lead verified independently and found two large files absent from my list: `winpty.py` (20 hits) and `hookfuncs.py` (5).** I re-diagnosed the cause rather than guessing at it, and reproduced the failure exactly:

| Probe | Pattern matched | Hits | Files |
|---|---|---:|---:|
| **My original probe** | `GetProcAddress\|LoadLibrary` | **9** | **5** |
| **The primitives I omitted from the match** | `WINFUNCTYPE\|CFUNCTYPE` | **27** | **3** |
| **The correct control, after removing one false positive** | **all four, case-resolved** | **35** | **6** |

**Two separate defects, both now fixed — and the second one was in the correction itself.**

**Defect 1 — my match pattern enumerated TWO of the FOUR primitives, while my absence table directly above it listed FOUR.** `winpty.py` and `hookfuncs.py` use only `CFUNCTYPE`/`WINFUNCTYPE`, so a `GetProcAddress|LoadLibrary` probe cannot see them. **Not a glob miss, not a scope boundary, not an excluded directory** — I verified all 493 `.py` files are enumerable and both files were visible to the walk. **The pattern's shape did not match the claim's shape.**

**Defect 2 — the corrected total still carried a false positive, and the disagreement between my two counting methods is what exposed it.** `Select-String` gave 36/7; a `.NET` `ReadAllText` + regex pass over the same 493 files gave **35/6**. The one-file difference was **`packages/all/winerror.py`**, whose sole "hit" is:

```
L2332:  TYPE_E_CANTLOADLIBRARY = -2147312566
```

**That is a `winerror.h` constant name, not an API call.** It matches `LoadLibrary` only because **`CANTLOADLIBRARY` contains the substring `LOADLIBRARY`** — and it matched in `Select-String` because **PowerShell's `Select-String` is case-INsensitive by default**, while the `.NET` regex pass was case-sensitive and correctly skipped it. **`winerror.py` is a 104 KB table of error constants and uses none of these four primitives.**

**So the true denominator is 35 across 6, and the 36/7 figure — which the Lead and I both reproduced — was itself an artifact of the same case-insensitivity that inflated my `windll` count in §0.4.** The disagreement between two methods is exactly what a second method is *for*, and here it caught a defect in the cross-check rather than in the primary.

**This is the same defect class as the finding the control supports.** A true conclusion resting on a population that was not the one advertised. **The conclusion survives — `security.py` is 0 under all four primitives, verified a third time — but the control as published was measuring a narrower question than the sentence claimed to answer.**

**The corrected control makes the inversion STRONGER, and this is now the report's lead framing (six files, 35 hits):**
- **`winpty.py` — 20 hits.** A `CFUNCTYPE` **dispatch table** (`:60-79`): a dict mapping function-name **strings** to prototypes. **That is the genuine dynamic-binding pattern, and it lives in `windows/all/`.**
- **`hookfuncs.py` — 5 hits.** `WINFUNCTYPE` callback prototypes (`:81-83`) — **and it is in `pupwinutils/`, the same directory as `security.py`.**
- **`keylogger.py` — 4 hits** (`linux/all`). · **`display.py` — 2** · **`uidle.py` — 2** (`posix/all`). · **`readlogs.py` — 2** (`windows/all`).
- **`security.py` — 0.** **The credential module is the one large Windows file in the tree with none of these primitives, while its own directory-mate has five and `winpty.py` has twenty.**
- **Excluded as a false positive: `winerror.py` (1 apparent hit)** — `TYPE_E_CANTLOADLIBRARY`, a constant name, not an API call (§0.3, Defect 2).

### 0.4 Probe failure #4 — a right number with a wrong reason

**I reported `getattr(` → 0 for `security.py`.** Re-probing with bare `getattr` returns **4**:

```
L520:  def __getattr__(self, key):
L522:      return self.StartupInfo.__getattribute__(key)
L526:      return self.__getattribute__(key)
L530:      self.StartupInfo.__getattribute__(key)
```

**All four are `__getattr__`/`__getattribute__` dunder definitions in a proxy class** that delegates attribute access to an inner `StartupInfo` — **not string-driven `ctypes` dispatch.** So **"0 call sites" was correct, but "0 occurrences of `getattr`" was not**, and the distinction is the whole point: a proxy forwarding `__getattribute__` is not a resolution mechanism.

**Also caught here:** a probe returned `windll` → **8** against `WinDLL` → **8**. **Not two facts — the same 8 lines**, because PowerShell `Select-String` is **case-insensitive by default**. An inflated count the arithmetic exposed.

### 0.5 The general lesson applied throughout

**A zero is the suspicious result; so is a non-zero that explains a previous anomaly too neatly.** **Five instrument errors in this task alone** — four of them mine, and one of those four found *inside the fix for the first* — all one root: **a probe whose shape did not match the evidence's shape.** Every absence in this report now carries a control that has been *shown able to succeed*, **each control's denominator has been re-verified against an independently produced list, and every apparent match has been inspected rather than counted.**

---

## 1. The file in full — outline and import surface

### 1.1 Verified dimensions, and the tree-relative position

| Measure | Value | Method |
|---|---:|---|
| Bytes | **78,800** | `Get-Item` |
| Lines | **2,842** | `(Get-Content).Count` |
| `pupwinutils/` directory total | 140,624 B (15 files) | enumerated |
| **`security.py` share of directory** | **55.9%** | computed |
| Next largest sibling | `bypassuac_token_imp.py` — **15,247 B** | enumerated |
| **Ratio to next largest** | **5.2×** | computed |

**D6:2048's "4× the next Windows module" is directionally right and understated at the directory level — the true ratio within `pupwinutils/` is 5.2×.** `[source: enumerated 15-file listing, not sampled]`

### 1.2 Import surface — complete, and it resolves cleanly

```python
# security.py:11-41
from ctypes import (WinDLL, c_uint32, c_char_p, c_long, c_uint16, Structure, Union,
                    POINTER, create_unicode_buffer, create_string_buffer, get_last_error,
                    cast, c_void_p, sizeof, c_int, c_ulong, c_wchar, GetLastError,
                    WinError, byref, addressof, c_size_t, c_ubyte, resize, c_longlong)
from ctypes.wintypes import (BOOL, LPSTR, LPWSTR, BYTE, LPCSTR, LPCWSTR, USHORT, HANDLE)
from pupy.network.lib.convcompat import (as_native_string, try_as_unicode_string)   # :25
from threading import Thread                                                        # :29
import psutil, sys, os, socket, logging                                             # :31-36
from os import W_OK, X_OK, R_OK                                                     # :38
```

**Internal dependency: exactly one Pupy import — `pupy.network.lib.convcompat`.** Everything else is stdlib or third-party (`psutil`). **Consequence:** `security.py` is **portable across Pupy's module tree** and depends on the network library only for string-conversion helpers, **not for transport.** `[inference]` **A credential toolkit with no network dependency is architecturally sensible — it can be loaded by any payload regardless of C2 channel.**

### 1.3 Structural inventory, enumerated

| Kind | Count | Notes |
|---|---:|---|
| `ctypes.WinDLL` handle bindings | **7** | `:43-48` (six) + `:1149` (`wtsapi32`) |
| **Module-scope API rebindings** | **62** | `NAME = dll.Symbol` — §2.2 |
| `Structure` / `Union` class definitions | **~40** | enumerated in §3.2 |
| Module-scope integer constants | **~150** | enumerated in §5 |
| Top-level `def` | **~30** | enumerated in §1.4 |
| Top-level `class` (non-`Structure`) | **1** | `Ace` `:2484` |

**The 7th `WinDLL` at `:1149` is significant: `wtsapi32` is loaded 1,100 lines into the file, not with the other six.** So the module-load-time DLL set is **six**, and `wtsapi32` is a **seventh, declared mid-file** but still at module scope (executed at import). `[source: all 7 sites quoted in §2.1]`

### 1.4 The function inventory — the actual capability surface

**All ~30 top-level functions, enumerated in file order. This list is the answer to Q1's "a list of functions, not a count":**

| Line | Function | Domain |
|---:|---|---|
| `:1098` | `LsaSessionDataFlagsToStr` | LSA — logon-session flag decoding |
| `:1113` | `FileTimeToUnix` | conversion |
| `:1498` | `EnumerateLogonSessions` | **LSA — enumerate logon sessions** |
| `:1559` | `GetUserName` | token |
| `:1575` | `GetTokenSid` | **token → SID** |
| `:1607` | `EnablePrivilege` | **privilege enable** |
| `:1678` | `ListSids` | **SID enumeration** |
| `:1739` | `getProcessToken` | token |
| `:1758` | `get_thread_token` | token |
| `:1776` | `get_process_token` | token |
| `:1788` | `gethTokenFromPid` | **token acquisition by PID** |
| `:1816` | `ListCachedSids` | **cached impersonation tokens** |
| `:1823` | `getSidToken` | token cache |
| `:1847` | `impersonate_pid` | **impersonation** |
| `:1864` | `impersonate_sid` | **impersonation** |
| `:1914` | `impersonate_sid_long_handle` | **impersonation (handle-retaining)** |
| `:1931` | `impersonate_pid_long_handle` | **impersonation (handle-retaining)** |
| `:1948` | `impersonate_token` | **impersonation — core** |
| `:1980` | `isSystem` | check |
| `:1989` | `token_impersonated_as_system` | check |
| `:1993` | **`create_proc_as_sid`** | **process creation under a SID** |
| `:2015` | **`getsystem`** | **SYSTEM escalation** |
| `:2029` | **`start_proc_with_token`** | **process creation with token** |
| `:2110` | `rev2self` | impersonation revert |
| `:2121` | `get_currents_privs` | **privilege enumeration** |
| `:2154` | `can_get_admin_access` | **escalation feasibility check** |
| `:2239` | `get_windows_version` | recon |
| `:2253` | **`access`** | **access-check / effective rights** |
| `:2357` | `strsid` | SID → string |
| `:2373` | `namebysid` | **SID → account name** |
| `:2403` | `sidbyname` | **account name → SID** |
| `:2432` | `_getfileinfo` | security descriptor |
| `:2470` | `getfileowner` | **file owner** |
| `:2619` | **`getfileowneracls`** | **full DACL enumeration** |
| `:2692` | `create_new_process_from_ppid` | **PPID spoofing** |
| `:2764` | `get_integrity_level` | **integrity level of a PID** |

**36 functions, of which the bolded entries are the escalation-relevant set (§3).** The module is **not** a name-only toolkit: `getsystem`, `create_proc_as_sid`, `start_proc_with_token`, `impersonate_*` (×5), and the DACL reader are all real implementations with bodies beginning at the cited lines. `[source: enumerated `^(def ` across the file]`

---

## 2. Q2 — the binding mechanism, and D6 §1 falsified

### 2.1 The five zero-counts, with a positive control that lives in the corpus

**The Lead's question: is the dynamic-resolution pattern concentrated in the credential toolkit (deliberate anti-analysis) or uniform (just how Pupy is written)?**

| Probe | `security.py` | Interpretation |
|---|---:|---|
| `GetProcAddress` | **0** | no runtime symbol resolution by name |
| `LoadLibrary` | **0** | no runtime DLL loading |
| `WINFUNCTYPE` | **0** | no function-prototype construction |
| `CFUNCTYPE` | **0** | no function-prototype construction |
| `PROTOTYPE` | **0** | no prototype-factory idiom |
| `getattr(` | **0** | **no string-driven attribute dispatch** |
| `ctypes.windll` / `cdll` | **0** | no alternate binding route |

**The positive control — whole-tree, all 493 `*.py` files:**

| Count | File | Primitive used |
|---:|---|---|
| **20** | **`packages/windows/all/winpty.py`** | **`CFUNCTYPE` dispatch table** (`:60-79`) |
| **5** | **`packages/windows/all/pupwinutils/hookfuncs.py`** | **`WINFUNCTYPE` callbacks** (`:81-83`) |
| 4 | `packages/linux/all/keylogger.py` | `WINFUNCTYPE`/`CFUNCTYPE` |
| 2 | `packages/posix/all/uidle.py` | `GetProcAddress`/`LoadLibrary` |
| 2 | `packages/posix/all/display.py` | `GetProcAddress`/`LoadLibrary` |
| 2 | `packages/windows/all/readlogs.py` | `GetProcAddress`/`LoadLibrary` |
| **35** | **6 files total** | |

**Thirty-five genuine instances across six files. `security.py` is not among them.** *(A seventh apparent hit — `packages/all/winerror.py`'s `TYPE_E_CANTLOADLIBRARY`, a constant name containing the substring `LOADLIBRARY` — is excluded as a false positive; see §0.3 Defect 2.)* **`winpty.py`, the single heaviest user, binds its entire API surface through a dict of function-name strings mapped to `CFUNCTYPE` prototypes — the exact dynamic-resolution pattern whose absence from `security.py` this section establishes.**

**This is the strongest available form of the control:** not "the probe returned nothing," but **"the probe successfully finds this pattern 35 times across 6 files in the same tree, and the largest Windows credential module — with its own directory-mate `hookfuncs.py` five hits strong beside it — shows the contrast in one directory listing."**

**Correction history:** my first publication of this control read "9 across 5," because my match pattern covered only `GetProcAddress|LoadLibrary` while the absence table above it covered all four primitives. **The Lead caught that; correcting it surfaced a second error — an inflated denominator from case-insensitive matching.** **Final: 35 across 6** (§0.3). **Both corrections strengthen the finding.**

`[source: 7 absence probes + tree-wide enumeration across all 493 *.py]`

### 2.2 What the pattern ACTUALLY is — `ctypes` prototype declaration, the opposite of obfuscation

**`security.py:591-596`, verbatim — and this shape repeats 62 times:**

```python
AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges          # :591
AdjustTokenPrivileges.restype = BOOL                            # :592
AdjustTokenPrivileges.argtypes = [                              # :593
    HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD,
    PTOKEN_PRIVILEGES, PDWORD
]
```

**That is the complete Win32 signature, written out in source.** `argtypes` → **63**, `restype` → **60**, against **62** rebindings.

**Why this falsifies the anti-analysis reading, stated directly:**

1. **A dynamic-resolution shim hides API names.** This file **publishes** them: 62 symbol names as plain module-scope literals, plus 63 explicit `argtypes` lists naming **every parameter type**. **A reader learns the exact API surface — names, arity, and types — without executing anything.**
2. **The binding is lazy, but that is `ctypes`'s default, not a design choice.** `WinDLL('advapi32')` (`:44`) returns a `WinDLL` object; `advapi32.AdjustTokenPrivileges` (`:591`) triggers resolution at **first attribute access during module import**. **Anyone who writes `WinDLL(...)` gets this behaviour for free.**
3. **There is no indirection layer to defeat.** No name construction, no hash lookup, no encoding. The literal `AdjustTokenPrivileges` appears at `:591` as the target of an assignment.

**The named modules are six fixed, undeclared-obfuscation DLLs** — `ntdll`, `advapi32`, `shell32`, `kernel32`, `userenv`, `secur32` at `:43-48`, plus `wtsapi32` at `:1149`. **All seven are the obvious, expected DLLs for this functionality.** No unusual or renamed library appears. `[source: all 7 WinDLL sites quoted in §1.3]`

### 2.3 The error-handling discipline is deliberate, not incidental

| Probe | Count | Reading |
|---|---:|---|
| `use_last_error=True` | **7** | **exactly one per `WinDLL` handle** |
| `get_last_error` | **51** | retrieved after calls |
| `WinError` | 55 | Windows error raised from the retrieved code |
| `GetLastError` (raw) | 3 | the three exceptions to the pattern |

**`use_last_error=True` appears exactly 7 times for exactly 7 `WinDLL` calls — a 1:1 match.** This is the *correct* modern `ctypes` idiom: the thread-local error slot, not `ctypes.GetLastError()`'s per-call unreliability. **51 `get_last_error` retrievals and 55 `WinError` raises mean the module surfaces Windows error codes rather than silently returning failure booleans.** `[source: 4 enumerated probes; the 7:7 identity is the check]`

### 2.4 Verdict on D6 §1

**D6 §1's statement — "the dynamic-resolution pattern visible throughout `security.py`" — is falsified as written.**

**What D6 §1 was most likely seeing** `[inference]`: the **62 module-scope rebindings**. That idiom *is* visually distinctive — it makes every Win32 symbol a file-scope global and reads unlike ordinary Python. **But the distinguishing property is API-surface clarity, not concealment.**

**The correct characterization, for re-indexing D6 §1:**

> `security.py` binds Win32 APIs through **7 `ctypes.WinDLL` handles with `use_last_error=True`**, **62 module-scope symbol rebindings**, and **63 explicit `argtypes` / 60 `restype` prototype declarations**. Symbol resolution is **lazy `ctypes` attribute lookup at import**, which is the library default. **There is no `LoadLibrary`/`GetProcAddress` shim, no prototype factory, and no name obfuscation anywhere in the file** — and the tree contains 9 uses of those primitives elsewhere, none of them here.

**Consequence for the Lead's underlying question:** the dynamic-resolution pattern is **not concentrated in the credential toolkit**, because **it is absent from the credential toolkit and present only in 5 unrelated modules.** **The anti-analysis hypothesis is not merely unsupported — it is inverted.** The credential toolkit is the most *legible* file of its size in the tree.

---

## 3. Q1 + Q3 — the capability set by Win32 API, and the escalation-relevant subset

### 3.1 The Win32 API surface, enumerated by domain — 62 bound symbols

**Not a count — the list, grouped as requested.**

**LSA / logon sessions / privileges (secur32 + advapi32):**

| Symbol | Line | Source DLL |
|---:|---:|---|
| `LsaEnumerateLogonSessions` | `:1123` | `secur32` |
| `LsaGetLogonSessionData` | `:1129` | `secur32` |
| `LsaFreeReturnBuffer` | `:1135` | `secur32` |
| `LsaNtStatusToWinError` | `:1141` | `advapi32` |
| `LookupPrivilegeName` → `LookupPrivilegeNameW` | `:329` | `advapi32` |
| `LookupPrivilegeValueA` | `:654` | `advapi32` |
| `AdjustTokenPrivileges` | `:591` | `advapi32` |

**Token acquisition / duplication / impersonation (advapi32):**

| Symbol | Line | Role |
|---:|---:|---|
| `OpenProcessToken` | `:660` | acquire process token |
| `OpenThreadToken` | `:666` | acquire thread token |
| `DuplicateToken` | `:630` | duplicate (impersonation level) |
| **`DuplicateTokenEx`** | `:624` | **duplicate with full access control** |
| `GetTokenInformation` | `:636` | token queries |
| `CheckTokenMembership` | `:598` | group membership test |
| **`ImpersonateLoggedOnUser`** | `:648` | **the impersonation primitive** |
| `ImpersonateSelf` | `:676` | impersonate own token |
| `RevertToSelf` | `:672` | drop impersonation |
| `CreateProcessAsUser` → `CreateProcessAsUserW` | `:610` | **process creation under a token** |

**SID resolution / well-known SIDs (advapi32):**

| Symbol | Line |
|---:|---:|
| `CreateWellKnownSid` | `:618` |
| `ConvertSidToStringSidA` | `:604` |
| `LookupAccountSidW` / `LookupAccountSidA` | `:579` / `:585` |
| `LookupAccountNameW` | `:573` |
| `GetSidSubAuthorityCount` | `:920` |
| `GetSidSubAuthority` | `:927` |
| `GetUserNameW` | `:642` |

**Security descriptors / ACLs / access checks (advapi32):**

| Symbol | Line |
|---:|---:|
| `MapGenericMask` | `:682` |
| `GetFileSecurityW` | `:687` |
| `GetSecurityDescriptorGroup` | `:693` |
| `GetSecurityDescriptorOwner` | `:699` |
| `GetSecurityDescriptorDacl` | `:705` |
| `GetExplicitEntriesFromAclW` | `:888` |
| `GetAclInformation` | `:894` |
| **`GetAce`** | `:900` |
| `IsValidSecurityDescriptor` | `:906` |
| **`AccessCheck`** | `:912` |

**Process / thread / I-O (kernel32):**

`CreateProcessW` `:934`, `CreateProcessA` `:942`, `WaitForSingleObject` `:950`, `CreatePipe` `:956`, `TerminateProcess` `:963`, `GetExitCodeProcess` `:970`, `GetFileAttributesW` `:981`, `CreateFile`→`CreateFileW` `:988`, `WriteFile` `:995`, `ReadFile` `:1002`, `CloseHandle` `:1008`, `GetCurrentProcess` `:1014`, `GetCurrentThread` `:1018`, `GetCurrentProcessId` `:1022`, `OpenProcess` `:1026`, `UpdateProcThreadAttribute` `:1441`, `DeleteProcThreadAttributeList` `:1447`, `ProcessIdToSessionId` `:1182`, `WTSGetActiveConsoleSessionId` `:1194`

**Environment / session / misc:**

`CreateEnvironmentBlock` `:1477`, `DestroyEnvironmentBlock` `:1483` (`userenv`) · `RtlGetVersion` `:1459` (`ntdll`) · `IsUserAnAdmin` `:1467` (`shell32`) · `WTSEnumerateServersW` `:1188`, `WTSFreeMemory` `:1198`, `WTSEnumerateSessionsW` `:1201`, `WTSQuerySessionInformationW` `:1207` (`wtsapi32`)

**Total: 62 bound symbols across 7 DLLs.** `[source: enumerated from the 62 rebinding sites quoted in full]`

### 3.2 Supporting type surface — ~40 `Structure`/`Union` classes

**Enumerated, because the structs reveal which APIs are actually driven:**

`LSA_UNICODE_STRING` · `LUID` · `LUID_AND_ATTRIBUTES` · `TOKEN_PRIVILEGES` · `TOKEN_PRIVS` · `TOKEN_USER` · `TOKEN_GROUPS` · `SID_AND_ATTRIBUTES` · `ACL_SIZE_INFORMATION` · `ACCESS_ALLOWED_ACE` · `ACCESS_DENIED_ACE` · `SYSTEM_AUDIT_ACE` · `ACL` · `SECURITY_DESCRIPTOR` · `SECURITY_ATTRIBUTES` · `SID` · `STARTUPINFO` · `STARTUPINFOEX` · `PROCESS_INFORMATION` · `LSA_OBJECT_ATTRIBUTES` · `LSA_LAST_INTER_LOGON_INFO` · `SECURITY_LOGON_SESSION_DATA` · `TRUSTEE` · `OBJECTS_AND_SID` · `OBJECTS_AND_NAME` · `EXPLICIT_ACCESS` · `WTS_SESSION_INFO` · `WTSINFO` · plus `TOKEN_INFORMATION_CLASS` and similar enum classes.

**The mix is diagnostic:** `TOKEN_PRIVILEGES` + `LUID` + `AdjustTokenPrivileges` = privilege manipulation. `SECURITY_LOGON_SESSION_DATA` + `LsaEnumerateLogonSessions` = **logon-session harvesting**. `ACL` + `ACCESS_ALLOWED_ACE` + `GetAce` = **raw DACL walking**. `STARTUPINFOEX` + `UpdateProcThreadAttribute` = **attribute-list process creation** (the PPID-spoofing mechanism at `:2692`). `[source: enumerated class definitions]`

### 3.3 Q3 — the escalation-relevant set, with the precondition chain read from code

**Five functions can hand the caller an impersonated or elevated token. The preconditions are stated in the source, not inferred.**

#### The escalation chain, verbatim

```python
# security.py:2015-2016
def getsystem(prog='cmd.exe'):
    return create_proc_as_sid(SID_SYSTEM, prog=prog)

# security.py:1993-2012
def create_proc_as_sid(sid, prog='cmd.exe', attributes=None, lpInfo=False):
    if not sid.startswith('S-1-'):
        sid = sidbyname(sid)
        if not sid:
            raise ValueError('Unknown username {}'.format(as_native_string(sid)))
    hTokendupe = impersonate_sid(sid, close=False)      # :2001 — THE DEPENDENCY
    try:
        vResult = start_proc_with_token([prog], hTokendupe, attributes=attributes, lpInfo=lpInfo)
    finally:
        CloseHandle(hTokendupe)
    return vResult
```

**`getsystem` is a two-line wrapper. All the difficulty is in `impersonate_sid` → `getSidToken`:**

```python
# security.py:1823-1844 — getSidToken, the real gate
def getSidToken(token_sid):
    if token_sid in IMPERSONATION_TOKENS:                 # :1824 cache hit
        return IMPERSONATION_TOKENS[token_sid][1]
    EnablePrivilege("SeDebugPrivilege", exc=False)        # :1827 ← REQUIRES SeDebugPrivilege
    for (pid, name, sid, username) in ListSids():         # :1830 enumerate processes
        if token_sid == SID_SYSTEM:
            if 'winlogon' not in name.lower():            # :1832 ← SYSTEM target must be winlogon
                continue
        elif token_sid != sid:
            continue
        hToken = gethTokenFromPid(pid, exc=True)          # :1838 OpenProcessToken
        if not hToken:
            continue
        IMPERSONATION_TOKENS[token_sid] = username, hToken  # :1843 cache
        return hToken
    return None                                           # ← unhandled path, see §6
```

**What a caller must already have, enumerated from `:1827`-`:1838`:**

1. **`SeDebugPrivilege`** — `:1827` enables it. **This is the binding precondition.** `SeDebugPrivilege` is held by administrators; if the caller already holds it, they are **already administrator-equivalent** (§3.4).
2. **`PROCESS_QUERY_INFORMATION`** on the target process — implied by `gethTokenFromPid` → `OpenProcessToken`.
3. **`TOKEN_DUPLICATE`** on the source token — used by `impersonate_token` → `DuplicateTokenEx`.
4. **An accessible `winlogon.exe` for the SYSTEM case** — `:1832` matches the process name containing `'winlogon'`. On modern Windows `winlogon` runs as SYSTEM in a **protected** process, so this is the practical constraint.
5. **A `SeImpersonatePrivilege`-bearing context** — required by `ImpersonateLoggedOnUser`, not checked here.

**Two legitimate uses that do NOT require escalation** — recorded because omitting them would overstate the finding:
- **`:1824` cache hit returns a token with no privilege check at all.** `impersonate_sid` is free for any SID already in `IMPERSONATION_TOKENS`.
- **`impersonate_pid` / `impersonate_sid` on a lower-privileged SID** — impersonating a *weaker* token needs no `SeDebugPrivilege`, since `:1827` fires only on a cache miss and the loop then matches by `sid` (`:1835-1836`).

#### The five escalation-relevant functions

| Function | Line | Gives the caller | Precondition |
|---:|---|---|---|
| **`getsystem`** | `:2015` | **a process running as `S-1-5-18`** | `SeDebugPrivilege` + accessible winlogon |
| **`create_proc_as_sid`** | `:1993` | process as any named SID | that SID's token reachable |
| **`start_proc_with_token`** | `:2029` | process under a supplied token | **a token handle** |
| **`impersonate_token`** | `:1948` | thread impersonating a token | a token handle |
| **`impersonate_sid`** / **`impersonate_pid`** | `:1864` / `:1847` | thread impersonating a SID/PID | `SeDebugPrivilege` on cache miss |

### 3.4 THE HONESTY PASS — what this module can actually DO vs what its name implies

**The Lead asked for the same treatment D14 gave vidcap. Applied directly.**

**What `security.py` CAN do, evidenced by code read:**
- **Enumerate every logon session** on the host with full session data (`:1498` `EnumerateLogonSessions` → `LsaEnumerateLogonSessions` + `LsaGetLogonSessionData`) — **including credential-adjacent metadata** (session type, logon time, domain, username; **not the password**).
- **Enable any privilege held by the process token** (`:1607` `EnablePrivilege` → `LookupPrivilegeValueA` + `AdjustTokenPrivileges`).
- **Enumerate the process token's privileges and enabled/disabled state** (`:2121` `get_currents_privs`).
- **Acquire and duplicate tokens from any accessible process** (`:1788` `gethTokenFromPid`).
- **Impersonate a token, a SID, or a PID** (`:1847`-`:1948`) — **and propagate that impersonation to every subsequently-spawned thread** (§3.5).
- **Create a process as SYSTEM or any SID** (`:1993`, `:2015`, `:2029`).
- **Read a file's owner and walk its full DACL** (`:2470` `getfileowner`, `:2619` `getfileowneracls`, `Ace` `:2484`).
- **Perform an `AccessCheck`** for a given token against a descriptor (`:2253` `access`).
- **Spoof PPID** via `STARTUPINFOEX` + `UpdateProcThreadAttribute` (`:2692` `create_new_process_from_ppid`).
- **Read a process's integrity level** (`:2764` `get_integrity_level`).
- **Modify the Python threading model at import** (§3.5).

**What it CANNOT do — each a `[absence]` with the control noted:**

| Claim | Basis |
|---|---|
| **No credential theft.** No `LsaRetrievePrivateData`, no `CredEnumerate`/`CredRead`, no `CryptUnprotectData`, no DPAPI, no registry secret read. | **Absent** — and the positive control is **`wdigest.py` and `bypassuac_token_imp.py` sit in the same directory** and are the files that touch such material. **`security.py` is not the credential-dumping module** despite the task's framing. |
| **No password/hash extraction.** No SAM, no NTDS, no LSASS memory read. | **Absent.** No `OpenProcess` on `lsass` by name; the only process name matched is `'winlogon'` (`:1832`). |
| **No explicit privilege *grant*.** `AdjustTokenPrivileges` enables privileges **already present** in the token; it cannot add absent ones. | **Direct from the API contract** — `TOKEN_ADJUST_PRIVILEGES` modifies the privilege *state*, not the token's privilege *set*. |
| **No network, no C2, no transmit.** | **Direct:** the sole Pupy import is `convcompat` (string helpers, §1.2); `socket` `:34` is imported but **no socket call appears in any function read.** |
| **No persistence install.** No `Run` key, no service create, no scheduled task. | **Absent** — consistent with `persistence.py` being a separate, missing module (§4). |

**The name oversells the module in one direction and undersells it in another.** It is **not** a credential harvester. It **is** a complete token-manipulation and DACL toolkit — and §3.5 shows its most unusual capability is one the name does not hint at.

### 3.5 The most technically novel finding — import-time `threading.Thread` monkey-patch

**`security.py:1891-1911` replaces a Python standard-library method at module import:**

```python
# security.py:1888-1911
global_ref = None                                            # :1888

if not hasattr(Thread, '__impersonate_patch'):               # :1891 guard
    setattr(Thread, '_bootstrap_inner_original', Thread._bootstrap_inner)   # :1893
    def _bootstrap_inner_patched(self):                      # :1897
        try:
            from pupwinutils.security import global_ref       # :1899
            if global_ref:
                ImpersonateLoggedOnUser(global_ref)           # :1902 EVERY new thread
                setattr(self, 'impersonated', global_ref)     # :1903
        except ImportError:
            pass                                             # :1905-1906
        self.__class__._bootstrap_inner_original(self)        # :1908
    setattr(Thread, '_bootstrap_inner', _bootstrap_inner_patched)   # :1910
    setattr(Thread, '__impersonate_patch', True)              # :1911
```

**What this is for, and why it is correct engineering** `[inference, from the code's own structure]`: **Windows impersonation is per-thread.** A token applied by `ImpersonateLoggedOnUser` on one thread does not carry to another. **Any worker thread Pupy spawns would silently lose the impersonation.** The patch makes `global_ref` (set by `impersonate_sid_long_handle` `:1927`) re-apply to **every** thread created in the process, for the module's lifetime.

**Three properties worth stating:**
1. **It modifies stdlib behaviour process-wide**, affecting code that never asked for it.
2. **The guard `:1891` makes it idempotent but not reversible** — no unpatch path exists. `global_ref = None` at `:1888` is the only way to disable it, and there is no function that sets it back.
3. **`except ImportError: pass` (`:1905`)** swallows failure, so a broken impersonation is **silent** — the thread proceeds unimpersonated.

**This is the one thing in `security.py` that is anti-analysis-adjacent** — not by hiding APIs, but by **changing runtime behaviour globally at import** in a way that a reader skimming functions will not see, because it sits at module scope between two `def`s. `[source: security.py:1888-1911 quoted verbatim]`

---

## 4. Q4 — the missing-sibling check: `security.py` is NOT a broken subsystem

**The Lead's hypothesis: `persistence.py` is recorded absent (`D6:2569`), `security.py` is adjacent, so check whether `security.py` imports absent siblings and enumerate the missing set.**

**Result: `security.py` imports nothing that is absent.** The hypothesis does not hold for this file, and the evidence is a complete import resolution.

### 4.1 Every import in `security.py`, enumerated and resolved

| Line | Import | Resolves? |
|---:|---|---|
| `:6-9` | `from __future__ import absolute_import / division / print_function / unicode_literals` | **stdlib — always** |
| `:11-18` | `from ctypes import (...)` | **stdlib** |
| `:20-23` | `from ctypes.wintypes import (...)` | **stdlib** |
| **`:25-27`** | **`from pupy.network.lib.convcompat import as_native_string, try_as_unicode_string`** | **Pupy — the one internal dep** |
| `:29` | `from threading import Thread` | stdlib |
| `:31` | `import psutil` | third-party |
| `:32-34` | `import sys / os / socket` | stdlib |
| `:36` | `import logging` | stdlib |
| `:38` | `from os import W_OK, X_OK, R_OK` | stdlib |
| **`:1899`** | **`from pupwinutils.security import global_ref`** | **self-import inside the thread patch** |

**Complete — 15 import statements, zero unresolvable.** `[source: exhaustive `^\s*(from|import)\s+` over the file]`

**The only intra-package reference in the entire file is `:1899`'s import of itself.** `[source: probe for `persistence|pupwinutils\.|from pupwinutils|import pupwinutils` → exactly one hit, at `:1899`, which is `security` itself]`

### 4.2 `persistence.py` exists — it is only the *Windows package* variant that does not

**`D6:2569`'s "a referenced module is missing" is true only in a narrow, path-specific sense:**

| Path | Status |
|---|---|
| `pupy/modules/persistence.py` | **EXISTS** |
| `pupy/packages/linux/all/persistence.py` | **EXISTS** |
| `pupy/scriptlets/persistence.py` | **EXISTS** |
| **`pupy/packages/windows/all/…/persistence.py`** | **ABSENT** |

**So the finding is not "`persistence.py` is missing" — it is "Pupy has no Windows *package-level* persistence module, while having three other persistence modules elsewhere."** That is a **platform-coverage gap**, not a dangling reference. `[source: tree-wide `-Filter persistence.py`, 3 hits; the Windows package path absent]`

### 4.3 The positive control for the absence

**Would a probe have found a `persistence` reference if one existed in this directory?** Enumerated across all 15 files in `pupwinutils/`:

```
files referencing 'persistence'  ->  0
```

**Zero sibling references too.** So the Windows package directory contains **no reference to `persistence` at all** — the absence is not confined to `security.py`; it is directory-wide. **A directory whose files never reference the missing module is not a broken subsystem.** `[source: 15-file enumeration]`

### 4.4 Verdict

**`security.py` is self-contained.** One Pupy import (string helpers), no absent dependency, no dangling sibling reference. **Its load-time behaviour is independent of the missing Windows persistence module.** **The "imports absent siblings ⇒ broken subsystem" hypothesis is not supported here**, and the honest form of the `persistence` finding is the platform-gap statement in §4.2 — **which belongs to whichever report owns `D6:2569`, not to this one as a defect of `security.py`.**

---

## 5. Q5 — hardcoded values: the strings that identify this module on a target

**These are the artifacts that make `security.py` recognisable in memory or on disk. Enumerated by kind.**

### 5.1 Well-known SIDs

| Value | Line | Identity |
|---|---|---|
| **`SID_SYSTEM = 'S-1-5-18'`** | **`:246`** | **`NT AUTHORITY\SYSTEM` — the escalation target** |

**One SID constant. Notably, `SID_SYSTEM` is the ONLY hardcoded SID** — every other SID is resolved at runtime via `LookupAccountNameW` (`:573`) / `sidbyname` (`:2403`) / `CreateWellKnownSid` (`:618`). `[source: probe `S-1-5-` → one hit, `:246`; also the only `SID_`-prefixed constant]`

### 5.2 Privilege name strings

| Value | Line(s) | Note |
|---|---|---|
| **`"SeDebugPrivilege"`** | **`:1827`** | **the escalation precondition — enables debug privilege** |

**Enumerated: `SeDebugPrivilege` is the only privilege name hardcoded as a literal.** Other privilege names are resolved generically via `LookupPrivilegeName` (`:329`) and `LookupPrivilegeValueA` (`:654`), and the token-privilege table comes from `tokenprivs` (`:99`). `[source: probe for `Se[A-Z][a-z]+Privilege` string literals]`

### 5.3 Process-name string — the anti-trivialisation guard

| Value | Line | Purpose |
|---|---|---|
| **`'winlogon'`** | **`:1832`** | **`if 'winlogon' not in name.lower(): continue`** |

**This is the one process name matched by name, and it is a deliberate constraint:** for the SYSTEM case, the scan accepts **only** a `winlogon` process. `[inference]` **This is an intentional narrowing — `winlogon` reliably runs as SYSTEM, so it is the cleanest available token source, and matching it avoids duplicating an arbitrary SYSTEM token from an unrelated process.** `[source: security.py:1831-1833]`

### 5.4 Policy, access-mask and error constants — ~150 module-scope integers

**Enumerated by family (line ranges from §1):**

| Family | Lines | Contents |
|---|---|---|
| **HRESULT error codes** | `:50-60` | `S_OK`, `E_ABORT`, `E_ACCESSDENIED`, `E_FAIL`, `E_HANDLE`, `E_INVALIDARG`, `E_NOINTERFACE`, `E_NOTIMPL`, `E_OUTOFMEMORY`, `E_POINTER`, `E_UNEXPECTED` |
| **Token access rights** | `:84-110` | `TOKEN_ASSIGN_PRIMARY`, `TOKEN_DUPLICATE`, `TOKEN_IMPERSONATE`, `TOKEN_QUERY`, `TOKEN_QUERY_SOURCE`, **`TOKEN_ADJUST_PRIVILEGES`**, `TOKEN_ADJUST_GROUPS`, `TOKEN_ADJUST_DEFAULT`, `TOKEN_ADJUST_SESSIONID`, `TOKEN_READ`, `TOKEN_ALL_ACCESS`, `tokenprivs` tuple |
| **Security-descriptor control** | `:112-124` | `SE_OWNER_DEFAULTED` … `SE_SELF_RELATIVE` (13 flags) |
| **ACE inheritance flags** | `:126-132` | `OBJECT_INHERIT_ACE`, `CONTAINER_INHERIT_ACE`, `NO_PROPAGATE_INHERIT_ACE`, `INHERIT_ONLY_ACE`, `INHERITED_ACE`, `SUCCESSFUL_ACCESS_ACE_FLAG`, `FAILED_ACCESS_ACE_FLAG` |
| **ACE types** | `:134-136` | `ACCESS_ALLOWED_ACE_TYPE`, `ACCESS_DENIED_ACE_TYPE`, `SYSTEM_AUDIT_ACE_TYPE` |
| **Standard/generic access rights** | `:138-147` | `DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`, `ACCESS_SYSTEM_SECURITY`, `GENERIC_READ/WRITE/EXECUTE/ALL` |
| **File creation dispositions** | `:149-153` | `CREATE_ALWAYS`, `CREATE_NEW`, `OPEN_ALWAYS`, `OPEN_EXISTING`, `TRUNCATE_EXISTING` |
| **File access masks** | `:155-162` | `FILE_READ_DATA`, `FILE_LIST_DIRECTORY`, `FILE_WRITE_DATA`, `FILE_ADD_FILE`, `FILE_APPEND_DATA`, `FILE_ADD_SUBDIRECTORY`, `FILE_READ_EA`, `FILE_WRITE_EA` |
| Process/token flags | elsewhere | `PROCESS_QUERY_INFORMATION` `:84`, `READ_CONTROL`, `EXTENDED_STARTUPINFO_PRESENT`, `NORMAL_PRIORITY_CLASS`, `CREATE_NEW_PROCESS_GROUP` |
| `TRUSTEE` type constants | `:745-748` | `TRUSTEE_IS_SID = 0`, `TRUSTEE_IS_OBJECTS_AND_SID = 3` |

**~150 constants, all standard `winnt.h`/`winerror.h` values.** **No unusual or non-standard constant appears.** `[source: enumerated from the top-level assignment outline]`

### 5.5 GUIDs and DIDs

| Probe | Count |
|---|---:|
| GUID literals (`{XXXXXXXX-…}`) | **0** |
| `CLSID` / `IID` declarations | **0** |
| `uuid` / `Guid` usage | **0** |

**`security.py` contains no GUID strings.** It operates entirely on **handles, SIDs, and string names**, never on COM identifiers. **Positive control:** the file binds `shell32` and `userenv` (`:45`, `:47`) — DLLs that *do* have COM surfaces — and **uses none of them via CLSID**, which is consistent with the `WinDLL` (not COM) approach throughout. `[source: three absence probes]`

### 5.6 The identifiable-string set, consolidated

**If this module is resident in a process, these are the discriminating artifacts:**

| Kind | Value | Line |
|---|---|---:|
| **SID** | **`S-1-5-18`** | `:246` |
| **Privilege** | **`SeDebugPrivilege`** | `:1827` |
| **Process name** | **`winlogon`** | `:1832` |
| **DLL names** | `ntdll`, `advapi32`, `shell32`, `kernel32`, `userenv`, `secur32`, `wtsapi32` | `:43-48`, `:1149` |
| **Function names** | 62 Win32 symbol names as module globals | §3.1 |
| **Dunder patch** | `_bootstrap_inner_original`, `__impersonate_patch`, `impersonated` | `:1891-1911` |
| **Error text** | `'Could not get token for SID {}'`, `'Could not impersonate token for SID {}'`, `'Unknown username {}'` | `:1873`, `:1883`, `:1869` |

**Seven DLL names plus 62 API symbol names make this a highly fingerprintable import set.** `[inference]` **The `__impersonate_patch` attribute is the single most distinctive artifact — a reader can test `hasattr(Thread, '__impersonate_patch')` to detect this module's presence in a running interpreter.**

---

## 6. Residual unknowns, corrections, and honest coverage

### 6.1 THE ANSWER TO THE LEAD'S CENTRAL QUESTION, stated once

**"Is the dynamic-resolution pattern concentrated in the credential toolkit (deliberate anti-analysis), or uniform (just how Pupy is written)?"**

**Neither. It is ABSENT from the credential toolkit and present in 7 unrelated files — and the credential module is the one large Windows file with none of these primitives.**

**The file that proves it: `packages/windows/all/winpty.py`, 20 hits, a `CFUNCTYPE` dispatch table binding function-name strings to prototypes (`:60-79`).** **The same tree, the same platform, a real dynamic-binding implementation — in a terminal-emulation helper, not in the security module.**

**The anti-analysis hypothesis is not merely unsupported; it is inverted.** `security.py` binds more explicitly than anything else of its size in the corpus: 62 symbol names as literals, 63 `argtypes` lists, 60 `restype` declarations. **A reader learns its entire API surface — names, arity, types — without executing a line.**

### 6.2 CORRECTIONS — four, three of them mine

| # | Correction | Effect |
|---|---|---|
| **(a)** | **My positive control read "9 across 5"; correct is "35 across 6."** (a1) pattern covered 2 of 4 primitives — **caught by the Lead**; (a2) `winerror.py`'s `TYPE_E_CANTLOADLIBRARY` is a constant name matching `LOADLIBRARY` as a substring — **caught by my own second method disagreeing 35 vs 36.** | **Strengthens the finding** — §0.3 |
| **(b)** | **My `getattr(` → 0 was right as "0 call sites" but wrong as "0 occurrences"** — there are 4, all `__getattr__`/`__getattribute__` proxy plumbing. | No effect on conclusion; §0.4 |
| **(c)** | **`windll` → 8 was the same 8 lines as `WinDLL` → 8** — PowerShell `Select-String` is case-insensitive. | Instrument artifact; §0.4 |
| **(d)** | **D6:2048's "4× the next Windows module" understates it** — the true within-directory ratio is **5.2×** and the share is **55.9%**. | **For re-indexing D6** |

**Also corrected against D6:2569:** `persistence.py` is **not** missing — three copies exist; **only the Windows package variant is absent**, and nothing in `pupwinutils/` references it (§4.2).

### 6.3 Reachability — stated as static claims only

**Per the standing rule, no claim here is "live" or "fixed."**

| Construct | Status |
|---|---|
| The `Thread._bootstrap_inner` patch (`:1891-1911`) | **Executes at MODULE IMPORT** — unconditional, guarded only by `hasattr(Thread, '__impersonate_patch')`. **This is the one thing in the file whose execution is not caller-gated.** |
| `getsystem` / `create_proc_as_sid` / `start_proc_with_token` | **Caller-invoked.** No internal caller appears in `security.py`; reachability depends on external modules, **not enumerated here** — see §6.4 |
| `getSidToken` fallback `return None` (`:1846`) | Implicit `None` when no match found. **`impersonate_sid:1872-1873` raises `ValueError` on it** — handled, not a crash path |
| `impersonate_sid_long_handle` / `impersonate_pid_long_handle` | **Setter of `global_ref`** — installs the token the thread patch re-applies. **Caller-invoked** |
| The 222-commented-out methods *(that is D24's `CovenantHub`, not this file — noted to prevent cross-report conflation)* | n/a |

**No construct in `security.py` can be classified `unreachable-from-corpus`** — the module has no dead code identified, and every function has a plausible external caller. **But I did not enumerate external callers**, which is the honest bound.

### 6.4 NOT examined — enumerated as unknowns, not implied covered

- **External callers of `security.py` are NOT enumerated.** I did not search `pupy/modules/`, `pupy/packages/`, or `pupy/core/` for imports of `pupwinutils.security`. **So "which payload invokes `getsystem`" is UNKNOWN here** — and that is the natural next question, since it determines whether the escalation chain is wired into anything.
- **`security.py` bodies read vs enumerated:** `:1-60` (header/constants), `:591-620` (binding sample), `:1823-1846` (`getSidToken`), `:1864-1947` (`impersonate_*`), `:1980-2049` (`getsystem` chain). **The `Ace` class (`:2484-2618`), `access` (`:2253-2356`), `getfileowneracls` (`:2619-2691`), `create_new_process_from_ppid` (`:2692-2763`), `get_integrity_level` (`:2764-2842`), and `get_currents_privs` body beyond `:2151` are NOT read in full** — their existence, line ranges and purpose are established by outline; **their internal logic is not.** **This is the largest residual risk in this report.**
- **`tokenprivs` tuple (`:99`) contents** — referenced, not read. The privilege set it covers is **unknown**.
- **`AsSid`/`Advapi32` conversion helpers and `convcompat`** (`:25-27`) — the imported string helpers are **not read**, so their behaviour on non-ASCII SIDs is **unknown**.
- **`psutil` usage** — imported `:31`, referenced in `ListSids`; **the dependency's role in process enumeration is not traced.**
- **Behavioural confirmation** — **none.** No execution, no target run, no Ghidra provider (the Lead confirmed source-only). **Every claim is a static source claim.**

### 6.5 What this report did NOT find, stated so absence is not read as safety

- **No credential theft, dumping, or exfiltration** — no DPAPI, no `CredEnumerate`, no SAM/NTDS/LSASS access (§3.4).
- **No network activity** — the sole Pupy import is string helpers; `socket` is imported but no socket call appears in any function read.
- **No persistence installation** — no Run key, service, or scheduled task.
- **No code obfuscation, packing, or string encryption** — 62 API names in plaintext, 63 typed signatures.
- **No unusual or renamed DLL** — all 7 are the expected modules for this functionality.

### 6.6 Headline, restated for the reader who reads only this section

**`security.py` is the largest unexamined Python file in the Pupy target, and its most reportable property is the opposite of what its size and name suggest.**

Three measurements carry the report:

1. **D6 §1 is falsified, and the correction makes it decisive.** `security.py` has **0** `GetProcAddress`, `LoadLibrary`, `WINFUNCTYPE`, `CFUNCTYPE` — while the tree has **35 across 6 files**, led by **`winpty.py` (20)** and **its own directory-mate `hookfuncs.py` (5)**. **The credential module is the one large Windows file that resolves nothing dynamically, and it publishes 63 typed signatures while doing it.**
2. **`security.py` is not a credential harvester.** No DPAPI, no `CredEnumerate`, no SAM/LSASS. It is a **token-manipulation and DACL toolkit** — `wdigest.py` and `bypassuac_token_imp.py` are the credential files. **The name oversells credential theft and undersells token manipulation.**
3. **`getsystem` requires already-admin-equivalent access.** Two-line wrapper (`:2015`) over `getSidToken`, which needs **`SeDebugPrivilege`** (`:1827`) **and** an accessible **`winlogon`** (`:1832`). **A function named for escalation whose precondition is "already escalated."**

**And the one genuinely novel construct:** the import-time `Thread._bootstrap_inner` patch (`:1891-1911`), which makes impersonation **process-wide across every future thread** because Windows impersonation is per-thread — sitting at module scope, between two `def`s, where a reader skimming functions will not see it.

---

*End of D28 — `pupy/pupy/packages/windows/all/pupwinutils/security.py`. Read scope: `:1-60` header/constants · `:591-620` binding sample · `:1823-2049` the escalation chain · outline + enumerated probes across the whole file · tree-wide control over all 493 `*.py` · `pupwinutils/` 15-file enumeration · `winpty.py:60-79` and `hookfuncs.py:81-83` for the control's contrast. Source-only: no execution, no provider.*



