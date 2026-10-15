# D5 — Havoc: Deep Function-Level Reversal

**Target:** `RE_Library/01_SOURCE_c2/havoc` — Havoc C2 framework, full source distribution.
**Scope read:** every `.c`, `.h`, `.asm`, `.s`, `.cpp`, `.py`, `.md`, `.txt` under `payloads/` (81 files); every `.go` under `teamserver/` (202 files, 1.79 MB); profiles; builder; client tree enumerated.
**Authority:** source is authoritative. No disassembler used on this target.
**Relation to prior work:** `RE_Library/07_OUTPUT/reports/T5_havoc.md` (758 lines) documented the protocol at byte level. This report goes *beneath* it — into the function bodies — and supersedes T5 wherever they conflict. T5's residual unknowns are resolved in §14.

> **Line-number convention.** C files in `payloads/Demon/` are quoted with *physical* line numbers as read by the file reader (LF-only files; no CRLF double counting). All citations are `[source: relative/path:line]` relative to `RE_Library/01_SOURCE_c2/havoc/`.

---

## TABLE OF CONTENTS

Sections are listed **in the order they appear on disk**, which is the order they were written, not numeric order. The two deviations from numeric order are deliberate and flagged inline.

| § | File | Content |
|---|---|---|
| **1** | tree-wide | Inventory (every file), with corrected counts vs the brief |
| **2** | `Demon.c` | Entry, `DemonInit`, config parse, 24-field metadata, main loop, CFG whitelist |
| **3** | `core/Command.c` | The dispatcher and the complete CommandID table (22 handlers + sentinel + 10 header-only IDs); the fixed-IV finding |
| **5** | `core/Obf.c` | Sleep obfuscation — Ekko / Zilean / Foliage, RC4 via `SystemFunction032`, the `.text`-only gap |
| **4** | `Package.c`, `Parser.c` | The wire layer: both frame layouts, the `Package.c:253` key/IV carve-out |
| **6** | `TransportHttp.c`, `Socket.c` | HTTP transport, host rotation, Meterpreter provenance, the first-beacon entropy artifact |
| **7** | `core/Win32.c` | DJB2 API resolution, PEB module walking, four proxy-loading modes, no-verification failure mode |
| **7A** | `core/Parser.c:127` | **The `UINT32` wraparound — the highest-value defect.** Own subsection per Lead request |
| **8** | `core/Token.c` | Token theft, handle-table enumeration, impersonation, privilege manipulation; the Kerberos/LSASS surface |
| **9** | `core/CoffeeLdr.c` | The COFF / BOF loader — symbol set, execution model, key/value store |
| **10** | `inject/Inject.c`, `Thread.c`, `asm/Spoof.*` | The injection set: three sequences, three memory selectors, four thread methods, x64 trampoline vs x86 no-op |
| **11** | `core/Dotnet.c`, `Clr.h` | In-memory .NET: CLR hosting chain, `v4.0.30319` probe, AppDomain per assembly, hardware-breakpoint AMSI/ETW bypass |
| **12** | `core/ObjectApi.c` | The Beacon API for BOFs — the `Parser.c:127` twin at line 190, output attribution, key/value store |
| **13** | — | **Residual unknowns** — files read partially, files not read, ten open questions, nine standing corrections to the brief |
| **14** | — | Closing note on method, coverage, and the three findings with the most operational weight |

**§7A is intentionally out of numeric order** — it is placed immediately after §7 so the `Parser.c` discussion is continuous with the `Win32.c` resolution material it depends on. **§4 follows §5 because §5 was written first**; §5 (`Obf.c`) was written before the wire layer because the sleep-obfuscation mechanism was the more urgent finding.

*(Sections were appended incrementally so that a write-time failure could not lose completed work. The file is pure LF, 0 CRLF.)*

---

## 2. `payloads/Demon/src/Demon.c` — ENTRY, INIT, CONFIG, MAIN LOOP

790 lines. Four functions: `DemonMain`, `DemonRoutine`, `DemonInit`, `DemonMetaData`, `DemonConfig`. Plus two file-scope globals.

### 2.0 Globals

```c
SEC_DATA PINSTANCE Instance      = { 0 };
SEC_DATA BYTE      AgentConfig[] = CONFIG_BYTES;
```
[source: `payloads/Demon/src/Demon.c:22-23`]

`SEC_DATA` places both in the `.data` section (a linker-visible, non-`.text` section). `CONFIG_BYTES` is a **build-time injected byte array** — the operator's entire profile (sleep, jitter, spawn paths, evasion flags, hosts, UA, headers, URIs, proxy, kill date) is compiled in as a raw blob and parsed at runtime. There is no config file on disk and no registry read. `AgentConfig` is zeroed immediately after parsing:

```c
ParserNew( &Parser, AgentConfig, sizeof( AgentConfig ) );
RtlSecureZeroMemory( AgentConfig, sizeof( AgentConfig ) );
```
[source: `Demon.c:583-584`]

Note the config blob is a *stack-local parser source* but the array itself is a global — the zeroing happens after `ParserNew` copies the pointer, so the parser reads from a now-zeroed buffer. `PARSER` must therefore hold its own copy (see §4.6). This is a real correctness dependency, not a stylistic choice.

### 2.1 `DemonMain` — line 34

```c
VOID DemonMain( PVOID ModuleInst, PKAYN_ARGS KArgs )
{
    INSTANCE Inst = { 0 };
    Instance = & Inst;
    DemonInit( ModuleInst, KArgs );
    DemonMetaData( &Instance->MetaData, TRUE );
    DemonRoutine();
}
```
[source: `Demon.c:34-49`]

- The `INSTANCE` is **allocated on the stack of the initial thread** and the global `Instance` pointer aliases it. The struct (see §11, `Demon.h:48-557`) is several KB — module pointers, ~200 resolved function pointers, all linked-list heads. It never leaves that stack frame; `DemonRoutine` is `_Noreturn`, declared at `Demon.c:63-64`, so the stack frame is preserved for the life of the implant. This is why the Process/Thread Environment Block walk can trust `Instance` to be a stable pointer.
- Order matters: `DemonInit` resolves Win32 and parses config; `DemonMetaData(…, TRUE)` builds the **registration package** and allocates the AES key/IV — which is why `DemonInit` deliberately sets `Instance->Config.AES.Key = NULL` at line 530 with the comment `/* TODO: generate keys here  */`.

### 2.2 `DemonRoutine` — line 64, the main loop

```c
_Noreturn
VOID DemonRoutine()
{
    for ( ;; )
    {
        if ( ! Instance->Session.Connected )
        {
            if ( TransportInit() )
            {
#ifdef TRANSPORT_HTTP
                Instance->Config.Transport.Host->Failures = 0;
#endif
            }
        }
        if ( Instance->Session.Connected )
        {
            CommandDispatcher();
        }
        SleepObf();
    }
}
```
[source: `Demon.c:63-92`]

Control flow is a four-state cycle: **connect → task → sleep-obfuscate → repeat**. `TransportInit()` is called only while disconnected; a successful connect resets the current host's failure counter (`Host->Failures = 0`), which is the mechanism that keeps host rotation from permanently blacklisting a recovered redirector. `SleepObf()` (line 90) is the *outer* sleep; `CommandDispatcher` (line 86) additionally calls `SleepObf()` at *its own* loop head (`Command.c:66`) — so there are two nested sleep sites and an agent that has just connected sleeps once inside the dispatcher before requesting jobs.

Critically: **`SleepObf()` is called unconditionally at the bottom of the outer loop.** There is no busy-spin path. If `TransportInit` fails, the agent sleeps and retries — the retry cadence is the configured sleep time, and `SleepTime()` returns 0 (skip sleep) when working hours are overridden (see §5.4).

### 2.3 `DemonMetaData` — line 95, the registration packet

This is the single function that constructs the `DEMON_INITIALIZE` payload. Its inline comment block at `Demon.c:125-157` is the authoritative layout, and it **disagrees with T5 in one place** — see below.

**Key generation (lines 112-123):**
```c
if ( Instance->Config.AES.Key == NULL && Instance->Config.AES.IV == NULL )
{
    Instance->Config.AES.Key = Instance->Win32.LocalAlloc( LPTR, 32 );
    Instance->Config.AES.IV  = Instance->Win32.LocalAlloc( LPTR, 16 );

    for ( SHORT i = 0; i < 32; i++ )
        Instance->Config.AES.Key[ i ] = RandomNumber32();

    for ( SHORT i = 0; i < 16; i++ )
        Instance->Config.AES.IV[ i ]  = RandomNumber32();
}
```
[source: `Demon.c:112-123`]

- Guard is `Key == NULL && IV == NULL` — an **AND**, not an OR. A state where `Key` is non-NULL and `IV` is NULL would skip generation and later dereference NULL. Unreachable in practice (both are set NULL together at `Demon.c:530-531`), but it is a latent defect.
- `RandomNumber32()` returns `UINT32`; only the low byte of each return value survives the `PBYTE` store. **The effective entropy is 8 bits per byte, 128 bits for the "256-bit" key** — matching 8 bits/byte is fine, but see §10.5 on the RNG's source quality; it is the real problem.
- `LocalAlloc(LPTR, 32)` is used, not `RtlAllocateHeap` — the code notes `TODO: replace with RtlAllocateHeap` for these at `Demon.h:248-250`.
- `RandomNumber32()` is called with an argument in `Obf.c` (`RandomNumber32()` at `Obf.c:71,388` is actually called bare) — confirmed bare-void.

**The exact byte layout as emitted by this function:**

```c
// Add AES Keys/IV
PackageAddPad( *MetaData, ( PCHAR ) Instance->Config.AES.Key, 32 );
PackageAddPad( *MetaData, ( PCHAR ) Instance->Config.AES.IV,  16 );

// Add session id
PackageAddInt32( *MetaData, Instance->Session.AgentID );
```
[source: `Demon.c:159-164`]

Then, in order, with the failure branch in every case emitting a literal 4-byte `0` instead of a length-prefixed string:

| # | Field | Call | Line |
|---|---|---|---|
| 1 | AES key, 32 B, **unencrypted, unpadded-length** | `PackageAddPad(…, Key, 32)` | 160 |
| 2 | AES IV, 16 B, **unencrypted** | `PackageAddPad(…, IV, 16)` | 161 |
| 3 | AgentID, 4 B | `PackageAddInt32` | 164 |
| 4 | Host name (NetBIOS) | `PackageAddBytes(Data, dwLength)` | 174 |
| 5 | Username | `PackageAddBytes(Data, dwLength)` | 192 |
| 6 | Domain (DNS domain) | `PackageAddBytes(Data, dwLength)` | 211 |
| 7 | Internal IP, ASCII from `IpAddress.String` | `PackageAddString` | 230 |
| 8 | Process path, **UTF-16**, from PEB `ProcessParameters->ImagePathName.Buffer` | `PackageAddWString` | 242 |
| 9 | PID | `PackageAddInt32(ClientId.UniqueProcess)` | 244 |
| 10 | TID | `PackageAddInt32(ClientId.UniqueThread)` | 245 |
| 11 | PPID | `PackageAddInt32(Session.PPID)` | 246 |
| 12 | Process arch (`PROCESS_AGENT_ARCH`) | `PackageAddInt32` | 247 |
| 13 | Elevated (`BeaconIsAdmin()`) | `PackageAddInt32` | 248 |
| 14 | Module base address, **8 B** | `PackageAddInt64` | 249 |
| 15 | Major version | `OsVersions.dwMajorVersion` | 254 |
| 16 | Minor version | `dwMinorVersion` | 255 |
| 17 | Product type | `wProductType` | 256 |
| 18 | Service pack major | `wServicePackMajor` | 257 |
| 19 | Build number | `dwBuildNumber` | 258 |
| 20 | OS arch (`Session.OS_Arch`) | `PackageAddInt32` | 259 |
| 21 | Sleep delay (`Config.Sleeping`) | `PackageAddInt32` | 261 |
| 22 | Jitter | `PackageAddInt32` | 262 |
| 23 | Kill date | `PackageAddInt64` | 263 |
| 24 | Working hours | `PackageAddInt32` | 264 |

**Correction to T5.** T5 §2.2 listed the order as `Process ID, Thread ID, Parent PID` and placed `Base Address` after `Elevated` — correct — but T5's table omitted the *ordering of `ModuleBase` relative to `OS Info`* and, more importantly, T5 stated the agent ID appears as a **decrypt-verification sentinel inside the encrypted region**. In the C source the AgentID at field 3 is **outside** any encryption: the agent never encrypts the registration body at all. The sentinel check T5 correctly identified on the Go side (`agent.go:406-413`) compares the header AgentID against **field 3 of the cleartext body**, not against a decrypted value. The *effect* is the same (a wrong key cannot be detected on the plain body, so the check actually validates the header against itself and is weak), but the mechanism differs: **the registration packet carries no encryption whatsoever.** The AES key and IV are shipped in the clear and the entire metadata body is in the clear with it.

**Failure handling:** each OS-information call is a two-pass size query then allocate-then-fill. On failure the code emits `PackageAddInt32(*MetaData, 0)` — a 4-byte zero taking the place of a `[len][bytes]` pair. The Go parser distinguishes this by trying to parse a string and falling back (`ParseString` returning an empty value). This produces **ambiguous parses** where a legitimate empty string and a failed query are indistinguishable on the wire. It also means a variable number of bytes is consumed for fields 4-7 depending on host state, so any decoder must branch on whether the 4-byte value is a plausible length or zero.

**Process path** comes from the PEB, not `GetModuleFileNameW`:
```c
PackageAddWString( *MetaData, ( ( PRTL_USER_PROCESS_PARAMETERS ) Instance->Teb->ProcessEnvironmentBlock->ProcessParameters )->ImagePathName.Buffer );
```
[source: `Demon.c:242`]. `ImagePathName.Buffer` is a `PWSTR` with **no reliably bounded length at this call site** — it relies on `PackageAddWString` reading to the NUL. If a hooked/patched PEB presents a non-terminated `ImagePathName`, this over-reads. That is a genuine robustness gap, though in practice the PEB buffer is well-formed.

**`BeaconIsAdmin()`** simply calls `CheckTokenMembership` against the Administrators SID — hashed against the API hash table.

**Package lifetime:** `(*MetaData)->Destroy = FALSE;` [source: `Demon.c:109`]. The registration package is created with `PackageCreateWithMetaData( DEMON_INITIALIZE )` and is **not destroyed** on transmit failure, so it survives across reconnect attempts and is re-sent verbatim — **including the same AES key/IV and the same AgentID**. Re-registration after a listener restart therefore reuses the exact same session key. There is no rekey path anywhere in the agent.

### 2.4 `DemonInit` — line 267

This is the largest single init function (305 lines). It executes in this strict order:

**1. TEB capture and module preload list** [source: `Demon.c:287`, `270-285`]
```c
Instance->Teb = NtCurrentTeb();
PVOID RtModules[] = { RtAdvapi32, /*RtMscoree,*/ RtOleaut32, RtUser32, RtShell32,
                      RtMsvcrt, RtIphlpapi, RtGdi32, RtNetApi32, RtWs2_32, RtSspicli,
#ifdef TRANSPORT_HTTP
                      RtWinHttp,
#endif
                    };
```
`RtMscoree` (the CLR host module) is **commented out** — it is loaded lazily by the .NET path instead, avoiding a static dependency on `mscoree.dll` in the import/load set.

**2. ntdll resolution and the full NTAPI function-pointer fill** [source: `Demon.c:298-366`]. `LdrModulePeb( H_MODULE_NTDLL )` walks the PEB loader list comparing a 32-bit hash. Then **38 `LdrGetProcedureAddress` calls** populate `Instance->Win32.*`. The full set (with hash constant references from `Defines.h`) — every one is `LdrFunctionAddr( Ntdll, H_FUNC_* )`:

`LdrGetProcedureAddress`, `LdrLoadDll`, `RtlAllocateHeap`, `RtlReAllocateHeap`, `RtlFreeHeap`, `RtlExitUserThread`, `RtlExitUserProcess`, `RtlRandomEx`, `RtlNtStatusToDosError`, `RtlGetVersion`, `RtlCreateTimerQueue`, `RtlCreateTimer`, `RtlQueueWorkItem`, `RtlRegisterWait`, `RtlDeleteTimerQueue`, `RtlCaptureContext`, `RtlAddVectoredExceptionHandler`, `RtlRemoveVectoredExceptionHandler`, `RtlCopyMappedMemory`, `NtClose`, `NtCreateEvent`, `NtSetEvent`, `NtSetInformationThread`, `NtSetInformationVirtualMemory`, `NtGetNextThread`, `NtOpenProcess`, `NtTerminateProcess`, `NtQueryInformationProcess`, `NtQuerySystemInformation`, `NtAllocateVirtualMemory`, `NtQueueApcThread`, `NtOpenThread`, `NtOpenThreadToken`, `NtResumeThread`, `NtSuspendThread`, `NtDuplicateObject`, `NtGetContextThread`, `NtSetContextThread`, `NtWaitForSingleObject`, `NtAlertResumeThread`, `NtSignalAndWaitForSingleObject`, `NtTestAlert`, `NtCreateThreadEx`, `NtOpenProcessToken`, `NtDuplicateToken`, `NtProtectVirtualMemory`, `NtTerminateThread`, `NtWriteVirtualMemory`, `NtContinue`, `NtReadVirtualMemory`, `NtFreeVirtualMemory`, `NtUnmapViewOfSection`, `NtQueryVirtualMemory`, `NtQueryInformationToken`, `NtQueryInformationThread`, `NtQueryObject`, `NtTraceEvent`.
[source: `Demon.c:301-362`]

Note `NtCreateEvent` is assigned **twice** (lines 325 and 340) — harmless, same value.

On failure of the module lookup: `PUTS("Failed to load ntdll from PEB")` then `return;` (line 364-365) — a **silent half-initialised return**. The caller `DemonMain` proceeds to `DemonMetaData` and `DemonRoutine` anyway, so a host where PEB walking fails will crash or no-op rather than exit cleanly. The same applies to the `RtModules` loop failure at `Demon.c:482-485`.

**3. OS version detection** [source: `Demon.c:368-393`]. `RtlGetVersion` into `OSVERSIONINFOEXW`, then a hand-rolled ladder:
- major 5 + minor 1 → `WIN_VERSION_XP`
- major 6 + minor 0 → `wProductType == VER_NT_WORKSTATION ? VISTA : 2008`
- 6.1 → `7 : 2008_R2`
- 6.2 → `8 : 2012`
- 6.3 → `8_1 : 2012_R2`
- 10.0 → `10 : 2016_X`

**Nothing above Windows 10/Server 2016 is recognised** — Windows 11 and Server 2019/2022 all report `OSVersion` major 10 minor 0, so **Windows 11 is classified as `WIN_VERSION_10`** and Server 2022 as `WIN_VERSION_2016_X`. Detections that key on `OSVersion` (e.g. the `PROCESS_QUERY_LIMITED_INFORMATION` vs `PROCESS_QUERY_INFORMATION` choice at `Command.c:367`) therefore take the modern branch, which is the safe behaviour, but the reported version string is wrong.

Also note the duplicated `WIN_VERSION_2008_R2` define at `Defines.h:22-23` identified in T5 §4.4 — the value that wins is `6`, and `WIN_VERSION_2008` is separately defined; the ladder above uses the symbol, so the collision is benign at this call site.

**4. kernel32 resolution — 62 function pointers** [source: `Demon.c:396-459`]. Full list: `LoadLibraryW`, `VirtualProtectEx`, `VirtualProtect`, `LocalAlloc`, `LocalReAlloc`, `LocalFree`, `CreateRemoteThread`, `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`, `CreatePipe`, `CreateProcessW`, `GetFullPathNameW`, `CreateFileW`, `GetFileSize`, `GetFileSizeEx`, `CreateNamedPipeW`, `ConvertFiberToThread`, `CreateFiberEx`, `ReadFile`, `VirtualAllocEx`, `WaitForSingleObjectEx`, `GetComputerNameExA`, `GetExitCodeProcess`, `GetExitCodeThread`, `TerminateProcess`, `ConvertThreadToFiberEx`, `SwitchToFiber`, `DeleteFiber`, `AllocConsole`, `FreeConsole`, `GetConsoleWindow`, `GetStdHandle`, `SetStdHandle`, `WaitNamedPipeW`, `PeekNamedPipe`, `DisconnectNamedPipe`, `WriteFile`, `ConnectNamedPipe`, `FreeLibrary`, `GetCurrentDirectoryW`, `GetFileAttributesW`, `FindFirstFileW`, `FindNextFileW`, `FindClose`, `FileTimeToSystemTime`, `SystemTimeToTzSpecificLocalTime`, `RemoveDirectoryW`, `DeleteFileW`, `CreateDirectoryW`, `CopyFileW`, `MoveFileExW`, `SetCurrentDirectoryW`, `Wow64DisableWow64FsRedirection`, `Wow64RevertWow64FsRedirection`, `GetModuleHandleA`, `GetSystemTimeAsFileTime`, `GetLocalTime`, `DuplicateHandle`, `AttachConsole`, `WriteConsoleA`, `GlobalFree`.

The fiber set (`ConvertThreadToFiberEx`/`CreateFiberEx`/`SwitchToFiber`/`DeleteFiber`/`ConvertFiberToThread`) exists **solely** to host Foliage sleep obfuscation (§5.2) — and to host BOF execution when `CoffeeThreaded`/`CoffeeVeh` are set (§9). `Wow64DisableWow64FsRedirection` exists to reach the real `System32` from a WOW64 agent during injection.

Note the failure branch is **absent**: unlike the ntdll block, the kernel32 block has no `else`. `LdrModulePeb( H_MODULE_KERNEL32 )` returning NULL leaves every `Win32.*` kernel32 pointer NULL and execution continues into `DemonConfig()`. `DemonConfig` immediately calls `Instance->Win32.LocalAlloc` (line 602) — **a NULL call through the function pointer**. On a host where kernel32 cannot be found by PEB walk, the agent faults. This is a straightforward denial condition and an obvious deviation to flag on the wire (agent dies at first registration).

**5. `DemonConfig()`** [source: `Demon.c:463`] — see §2.5.

**6. Indirect syscall initialisation, conditional** [source: `Demon.c:466-473`]
```c
if ( Instance->Config.Implant.SysIndirect )
{
    if ( ! SysInitialize( Instance->Modules.Ntdll ) ) {
        PUTS( "Failed to Initialize syscalls" )
        /* NOTE: the agent is going to keep going for now. */
    }
}
```
The comment is explicit: a **failed syscall stub setup does not abort**. The agent continues with whatever partial SSN table `SysInitialize` left behind. Since `SysNt*` wrappers branch on `Instance->Config.Implant.SysIndirect` at call time, a partially-populated SSN table produces a **syscall with SSN 0** — which on Windows is `NtAccessCheck` on most builds, i.e. an arbitrary NT call with mismatched arguments. In practice this yields `STATUS_INVALID_PARAMETER` or an access violation rather than a useful fallback to direct ntdll calls.

**7. Module shuffle and load** [source: `Demon.c:476-486`]
```c
ShuffleArray( RtModules, SIZEOF_ARRAY( RtModules ) );
for ( int i = 0; i < SIZEOF_ARRAY( RtModules ); i++ )
    if ( ! ( ( BOOL (*)() ) RtModules[ i ] ) () ) { PUTS( "Failed to load a module" ) return; }
```
Each `Rt*` symbol is a **function returning BOOL**, not a name. `ShuffleArray` randomises load order so the DLL load sequence is not a fixed fingerprint. Any failure aborts init.

**8. Module-base and section bookkeeping** [source: `Demon.c:488-511`]
```c
if ( KArgs ) {
#if SHELLCODE
    Instance->Session.ModuleBase = KArgs->Demon;
    Instance->Session.ModuleSize = KArgs->DemonSize;
    Instance->Session.TxtBase    = KArgs->TxtBase;
    Instance->Session.TxtSize    = KArgs->TxtSize;
    FreeReflectiveLoader( KArgs->KaynLdr );
#endif
} else {
    Instance->Session.ModuleBase = ModuleInst;
    if ( ! Instance->Session.ModuleBase ) Instance->Session.ModuleBase = LdrModulePeb( 0 );
    if ( Instance->Session.ModuleBase ) Instance->Session.ModuleSize = IMAGE_SIZE( Instance->Session.ModuleBase );
}
```
`KAYN_ARGS` (defined `Demon.h:37-45`, `#pragma pack(1)`) carries the shellcode-hosted case: `KaynLdr`, `DllCopy`, `Demon`, `DemonSize`, `TxtBase`, `TxtSize`. `FreeReflectiveLoader( KArgs->KaynLdr )` **frees the reflective loader stub** once the Demon is mapped — the loader does not remain resident, which is a memory-forensics-relevant fact (no second copy of the loader in the address space). `TxtBase`/`TxtSize` are the `.text` bounds used as the encryption range for sleep obfuscation.

`LdrModulePeb( 0 )` — hash 0 matches the first module, i.e. the main image — gives the EXE case its base.

**9. Architecture and session ID** [source: `Demon.c:513-531`]
```c
#if _WIN64
    Instance->Session.OS_Arch      = PROCESSOR_ARCHITECTURE_AMD64;
    Instance->Session.Process_Arch = PROCESSOR_ARCHITECTURE_AMD64;
#else
    Instance->Session.Process_Arch = PROCESSOR_ARCHITECTURE_INTEL;
    Instance->Session.OS_Arch      = PROCESSOR_ARCHITECTURE_UNKNOWN;
    if ( ProcessIsWow( NtCurrentProcess() ) ) Instance->Session.OS_Arch = PROCESSOR_ARCHITECTURE_AMD64;
    else                                      Instance->Session.OS_Arch = PROCESSOR_ARCHITECTURE_INTEL;
#endif
    Instance->Session.PID       = U_PTR( Instance->Teb->ClientId.UniqueProcess );
    Instance->Session.TID       = U_PTR( Instance->Teb->ClientId.UniqueThread );
    Instance->Session.Connected = FALSE;
    Instance->Session.AgentID   = RandomNumber32();
    Instance->Config.AES.Key    = NULL;
    Instance->Config.AES.IV     = NULL;
```
The x86 branch calls `ProcessIsWow` to distinguish "32-bit agent on 64-bit OS" from "32-bit agent on 32-bit OS" — this is what drives the SysWOW64 vs System32 spawn-path and injection-target selection. `AgentID` is `RandomNumber32()` — **32 bits of the same weak RNG used for the AES key**. Collision between two agents from the same build is plausible at scale, and the AgentID is the only session identifier in the frame header.

`Session.PPID` is **never assigned in `DemonInit`** — it is filled by the metadata routine (see §2.3 field 11) from a separate source; grep shows `Session.PPID` written only in the injection paths.

**10. Linked-list heads initialised to NULL, then CFG whitelisting** [source: `Demon.c:533-568`]
```c
Instance->Tokens.Vault = NULL;  Instance->Tokens.Impersonate = FALSE;
Instance->Jobs = NULL; Instance->Downloads = NULL; Instance->Sockets = NULL;
Instance->HwBpEngine = NULL; Instance->Packages = NULL;
Instance->Dotnet = NULL;

if ( CfgQueryEnforced() )
{
    CfgAddressAdd( Instance->Modules.Ntdll,    Instance->Win32.NtContinue );
    CfgAddressAdd( Instance->Modules.Ntdll,    Instance->Win32.NtSetContextThread );
    CfgAddressAdd( Instance->Modules.Ntdll,    Instance->Win32.NtGetContextThread );
    CfgAddressAdd( Instance->Modules.Advapi32, Instance->Win32.SystemFunction032 );

    CfgAddressAdd( Instance->Modules.Kernel32, Instance->Win32.WaitForSingleObjectEx );
    CfgAddressAdd( Instance->Modules.Kernel32, Instance->Win32.VirtualProtect );
    CfgAddressAdd( Instance->Modules.Ntdll,    Instance->Win32.NtSetEvent );

    CfgAddressAdd( Instance->Modules.Ntdll,    Instance->Win32.NtTestAlert );
    CfgAddressAdd( Instance->Modules.Ntdll,    Instance->Win32.NtWaitForSingleObject );
    CfgAddressAdd( Instance->Modules.Ntdll,    Instance->Win32.NtProtectVirtualMemory );
    CfgAddressAdd( Instance->Modules.Ntdll,    Instance->Win32.RtlExitUserThread );
}
```

This block is **the single most useful detection artifact in `Demon.c`.** Control Flow Guard (CFG) is a Windows mitigation that validates *indirect* call targets against a per-process bitmap. Because both the Foliage ROP chain and the Ekko/Zilean timer ROP chain dispatch **indirectly** through `NtContinue` with attacker-chosen `Rip`, CFG would normally raise `STATUS_STACK_BUFFER_OVERRUN` / fast-fail. Havoc therefore **calls `SetProcessValidCallTargets` (via `CfgAddressAdd`) to mark exactly those eleven functions as valid indirect-call targets.**

Consequences:
1. **The agent consciously manipulates its own CFG bitmap.** `CfgAddressAdd` resolves the CFG bitmap pointer and pokes the bit for each VA. On a CFG-enforcing host this is an *observable* operation by any kernel-level CFG telemetry (ETW `Microsoft-Windows-Kernel-Process` / `SetProcessValidCallTargets` on the process's own `CFG` bitmap is a known EDR signal).
2. The **exact eleven-address set** is a hard signature. An analyst who instruments `SetProcessValidCallTargets` will observe calls whose targets are `ntdll!NtContinue`, `ntdll!NtSetContextThread`, `ntdll!NtGetContextThread`, `advapi32!SystemFunction032`, `kernel32!WaitForSingleObjectEx`, `kernel32!VirtualProtect`, `ntdll!NtSetEvent`, `ntdll!NtTestAlert`, `ntdll!NtWaitForSingleObject`, `ntdll!NtProtectVirtualMemory`, `ntdll!RtlExitUserThread` — in that order, from a process whose image is an unrelated signed binary.
3. `SystemFunction032` (= `RtlEncryptMemory`/RC4 in `advapi32`) is whitelisted, confirming it is reached indirectly from a fabricated context — see the Foliage ROP chain at `Obf.c:149,184`.
4. `CfgQueryEnforced()` returns false on hosts without CFG, so this block is a **reliable host-mitigation probe**: its presence or absence in an execution trace tells you the target's CFG state.

### 2.5 `DemonConfig` — line 573

Parses the `AgentConfig` blob sequentially with `ParserGet*`. The full parse order, with the exact calls:

| # | Assignment | Parser call | Line |
|---|---|---|---|
| 1 | `Config.Sleeping` | `ParserGetInt32` | 586 |
| 2 | `Config.Jitter` | `ParserGetInt32` | 587 |
| 3 | `Config.Memory.Alloc` | `ParserGetInt32` | 590 |
| 4 | `Config.Memory.Execute` | `ParserGetInt32` | 591 |
| 5 | `Config.Process.Spawn64` (bytes → `LocalAlloc`) | `ParserGetBytes` | 601-603 |
| 6 | `Config.Process.Spawn86` | `ParserGetBytes` | 605-607 |
| 7 | `Config.Implant.SleepMaskTechnique` | `ParserGetInt32` | 617 |
| 8 | `Config.Implant.SleepJmpBypass` | `ParserGetInt32` | 618 |
| 9 | `Config.Implant.StackSpoof` | `ParserGetInt32` | 619 |
| 10 | `Config.Implant.ProxyLoading` | `ParserGetInt32` | 620 |
| 11 | `Config.Implant.SysIndirect` | `ParserGetInt32` | 621 |
| 12 | `Config.Implant.AmsiEtwPatch` | `ParserGetInt32` | 622 |
| — | `DownloadChunkSize` = `0x80000` (512 K) HTTP / `0xfc00` (63 K) SMB | hardcoded | 624/626 |
| 13 | `Config.Transport.KillDate` | `ParserGetInt64` | 644 |
| 14 | `Config.Transport.WorkingHours` | `ParserGetInt32` | 653 |
| 15 | `Config.Transport.Method` | `ParserGetBytes` → `MmHeapAlloc` | 655-657 |
| 16 | `Config.Transport.HostRotation` | `ParserGetInt32` | 659 |
| 17-19 | `HostMaxRetries = 0`, `Hosts = NULL`, `Host = NULL` | hardcoded | 660-663 |
| 20 | host count `J` | `ParserGetInt32` | 666 |
| 21×J | per host: address bytes + port | `ParserGetBytes` + `ParserGetInt32` | 670-671 |
| 22 | `Config.Transport.Secure` | `ParserGetInt32` | 689 |
| 23 | `Config.Transport.UserAgent` | `ParserGetBytes` | 693-695 |
| 24 | header count `J` | `ParserGetInt32` | 699 |
| 25×J | each header | `ParserGetBytes` | 704-707 |
| 26 | URI count `J` | `ParserGetInt32` | 715 |
| 27×J | each URI | `ParserGetBytes` | 720-723 |
| 28 | `Proxy.Enabled` | `ParserGetInt32` | 731 |
| 29-31 | Proxy URL / Username / Password (conditional) | `ParserGetBytes` | 735-758 |

**Hardcoded post-parse defaults** [source: `Demon.c:786-787`]:
```c
Instance->Config.Implant.ThreadStartAddr = Instance->Win32.LdrLoadDll + 0x12;
Instance->Config.Inject.Technique        = INJECTION_TECHNIQUE_SYSCALL;
```
`ThreadStartAddr` = **`ntdll!LdrLoadDll + 0x12`** — a fixed RVA offset into ntdll used as the spoofed thread start address for `NtCreateThreadEx` (`Obf.c:81`) and the ROP stack spoof (`Obf.c:507-527`). The comment concedes it is a placeholder: `/* TODO: default -> change that or make it optional via builder or profile */`. This is *the* stack-spoof address for the default build, and `LdrLoadDll+0x12` is a well-known "clean" gadget inside a signed Microsoft module that produces a stack frame whose return address region reads as ntdll. It is overridable at runtime via `DEMON_CONFIG_IMPLANT_SPFTHREADADDR = 3`.

**Kill-date enforcement happens at config-parse time, twice** [source: `Demon.c:646-652` and `777-782`]:
```c
if ( Instance->Config.Transport.KillDate && GetSystemFileTime() >= Instance->Config.Transport.KillDate )
{
    // refuse to run
    // TODO: exit process?
    Instance->Win32.RtlExitUserThread( 0 );
}
```
`RtlExitUserThread(0)` on the initial thread ends that thread; when it is the last user thread the process terminates. But `TODO: exit process?` shows the author knew it is not a guaranteed process kill — **if the agent runs inside an injected host process that has other threads, the process survives with a dead agent.** On EXE/DLL-hosting builds of the Demon where the load is the process's only user thread, it terminates. This is a real kill-date bypass on injected deployment.

**Working hours encoding** [source: `Command.c:676-679`]:
```c
StartHour   = ( WorkingHours >> 17 ) & 0b011111;
StartMinute = ( WorkingHours >> 11 ) & 0b111111;
EndHour     = ( WorkingHours >>  6 ) & 0b011111;
EndMinute   = ( WorkingHours >>  0 ) & 0b111111;
```
12 bits packed as `[5-bit hour][6-bit minute]` twice into a 32-bit value, top bit unused. Hours 0-23 fit 5 bits; minutes 0-59 fit 6 bits. Decode is `(v>>17)&0x1F`, `(v>>11)&0x3F`, `(v>>6)&0x1F`, `v&0x3F`.

**The `Headers` and `Uris` arrays are leaky** [source: `Demon.c:700-728`]:
```c
Instance->Config.Transport.Headers = MmHeapAlloc( sizeof( LPWSTR ) * ( ( J + 1 ) * 2 ) );
...
Instance->Config.Transport.Headers[ J + 1 ] = NULL;
```
Allocation size is `sizeof(LPWSTR) * (J+1) * 2` = `2*(J+1)` pointers, but the loop fills indices `0..J-1` and the terminator is written at index **`J+1`**, leaving index `J` **uninitialised heap**. Any consumer that iterates `Headers[i]` until NULL and does not stop at `J` will read a garbage pointer at index `J` and either dereference it or fail the NULL check and read past the array. The 2× over-allocation accidentally makes this read in-bounds for one slot. The URIs loop is identical (`Uris[J+1] = NULL`, `Demon.c:728`) with the same uninitialised index `J`. `MmHeapAlloc` is `RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, …)`? — `MmHeapAlloc` is checked in §10.6; if it does **not** zero, this is a genuine uninitialised-memory read on every registration that carries headers or URIs.

The same off-by-one means **the number of configured headers/URIs is authoritative from `J`, not from the NULL terminator.** A decoder of the config must use the count field.

`Headers`/`Uris` elements are allocated `Length + sizeof(WCHAR)` and copied with `MemCopy(…, Buffer, Length)`. The URI variant additionally does `MemSet(…, 0, Length + sizeof(WCHAR))` first (line 722) — **the header variant does not** (line 706 sets `Length` bytes, not `Length + sizeof(WCHAR)`), so header strings have **one uninitialised trailing WCHAR**. For a string whose `Length` already includes the NUL, this is benign; for one that does not, the terminator is an arbitrary byte pair. Intermittent.

**Proxy credentials are stored in the clear in the heap** [source: `Demon.c:743-757`] as `LPWSTR` with no zeroing on teardown. Anything that can read the agent's heap (a crash dump, a memory scan) recovers the operator's proxy username and password.

---


### 1.1 Summary

| Group | Files | Language | Bytes | Role |
|---|---|---|---|---|
| `payloads/Demon/src/**` | 33 `.c` | C | 639 KB | **The implant.** All tradecraft. |
| `payloads/Demon/include/**` | 31 `.h` | C | 632 KB | Types, NT structs, API hashes |
| `payloads/Demon/src/asm/**` | 4 | NASM | 1.6 KB | Syscall + stack-spoof stubs |
| `payloads/DllLdr/**` | 5 | C | 27 KB | Reflective DLL loader (separate PIC PE) |
| `payloads/Shellcode/**` | 8 | C + GNU as | 11 KB | Position-independent shellcode bootstrap |
| `teamserver/**` | 138 `.go` | Go | 1.79 MB | Teamserver; **~82% of Go bytes are vendored yaotl HCL2 parser** |
| `profiles/**` | 3 `.yaotl` | HCL2 | 4 KB | Listener/implant profile |
| `client/**` | 42 `.cc` + 28 `.hpp` + 40 `.ui` | C++/Qt | 0.67 MB | Operator GUI |
| `data/**` | toolchain + prebuilt | binaries | — | Cross-compilers, `nasm` |

### 1.2 `payloads/Demon/src/` — line counts (physical lines)

| Path | Lines | Bytes | Role |
|---|---|---|---|
| `src/Demon.c` | 790 | 41,123 | Entry, `DemonInit`, `DemonConfig`, `DemonMetaData`, main loop |
| `src/core/Command.c` | 3,504 | 123,571 | **The dispatcher + every command handler** |
| `src/core/Win32.c` | 1,440 | 53,230 | Dynamic API resolution + wrappers |
| `src/core/Token.c` | 1,188 | 46,140 | Access-token toolkit |
| `src/core/Obf.c` | 668 | 33,406 | Sleep obfuscation ROP chains |
| `src/core/CoffeeLdr.c` | 703 | 30,387 | Cobalt Strike BOF/COFF loader |
| `src/core/Kerberos.c` | 670 | 26,947 | Kerberos/LSA ticket operations |
| `src/core/ObjectApi.c` | 598 | 25,085 | Low-level NT object manager calls |
| `src/core/Dotnet.c` | 472 | 23,502 | CLR hosting / in-memory .NET |
| `src/core/Runtime.c` | 437 | 23,089 | RNG, string utils, time, PEB helpers |
| `src/core/Socket.c` | 517 | 20,530 | SOCKS5 / portfwd / raw sockets |
| `src/core/TransportHttp.c` | 460 | 19,365 | WinHTTP transport + host rotation |
| `src/core/SysNative.c` | 397 | 15,131 | Native NT wrapper table |
| `src/core/Package.c` | 394 | 13,257 | Outbound package builder (big-endian) |
| `src/core/Jobs.c` | 366 | 13,396 | Job (fiber) engine |
| `src/core/Download.c` | 309 | 11,274 | Resumable file download |
| `src/core/Inject.c` | 310 | 13,246 | Injection dispatcher |
| `src/core/Thread.c` | 245 | 11,941 | Thread enumeration / `NtGetNextThread` |
| `src/core/Pivot.c` | 283 | 10,543 | SMB pivot bookkeeping |
| `src/core/TransportSmb.c` | 203 | 9,451 | Named-pipe SMB transport |
| `src/core/HwBpEngine.c` | 290 | 9,908 | Hardware-breakpoint engine (VEH) |
| `src/crypt/AesCrypt.c` | 212 | 8,157 | tiny-AES-c, AES-256-CTR |
| `src/core/Memory.c` | 247 | 7,471 | Memory-file ops + alloc wrappers |
| `src/core/Syscalls.c` | 209 | 7,171 | SSN extraction / indirect syscall init |
| `src/core/MiniStd.c` | 234 | 6,405 | CRT-free string/memory primitives |
| `src/core/Parser.c` | 128 | 3,514 | Inbound/outbound byte parser |
| `src/core/Transport.c` | 84 | 2,205 | Transport selection |
| `src/inject/InjectUtil.c` | 71 | 3,542 | RtlCreateUserThread / NtCreateThreadEx helpers |
| `src/core/Spoof.c` | 36 | 1,073 | Stack-spoofing trampoline |
| `src/core/HwBpExceptions.c` | 26 | 859 | VEH exception handler |
| `src/main/MainDll.c` | 55 | 2,187 | `DllMain` entry |
| `src/main/MainSvc.c` | 41 | 1,524 | Service entry |
| `src/main/MainExe.c` | 7 | 310 | EXE entry |

### 1.3 `payloads/Demon/include/` — line counts

| Path | Lines | Bytes | Role |
|---|---|---|---|
| `include/common/Native.h` | 18,580 | 538,813 | NT struct/typedef wall + inline syscall stubs |
| `include/common/Clr.h` | 604 | 21,619 | CLR hosting structs/interfaces |
| `include/common/Defines.h` | 354 | 21,538 | **The API hash table** + magic values |
| `include/Demon.h` | 507 | 17,790 | `INSTANCE`, `_CONFIG`, `_SESSION`, `_WIN32_FUNCS` |
| `include/core/SysNative.h` | 231 | 8,826 | `SysNt*` prototypes |
| `include/core/Win32.h` | 211 | 5,261 | `_WIN32_FUNCS` member list |
| `include/core/Command.h` | 193 | 6,987 | All CommandID / sub-command constants |
| `include/core/Kerberos.h` | 179 | 6,512 | Kerberos structures |
| `include/core/Token.h` | 158 | 4,589 | Token vault/type structures |
| `include/core/Token.c` (n/a) | — | — | — |
| `include/core/CoffeeLdr.h` | 119 | 3,498 | COFF structs, `COFFEE` machine types |
| `include/core/Socket.h` | 86 | 2,756 | Socket types/commands |
| `include/core/ObjectApi.h` | 83 | 3,348 | Object API prototypes |
| `include/core/Package.h` | 85 | 2,159 | `PACKAGE`, size limit |
| `include/common/Macros.h` | 79 | 3,689 | `CALLBACK_ERROR_*`, `DATA_FREE`, `SIZEOF_ARRAY` |
| `include/core/Download.h` | 64 | 2,316 | Download chunk state |
| `include/core/Jobs.h` | 63 | 1,380 | `JOB_DATA` |
| `include/core/TransportHttp.h` | 63 | 1,802 | Host rotation constants |
| `include/inject/Inject.h` | 61 | 2,538 | Injection technique enum |
| `include/core/Thread.h` | 59 | 1,540 | Thread helpers |
| `include/core/Memory.h` | 52 | 1,069 | Memory-file structs |
| `include/core/HwBpExceptions.h` | 52 | 3,338 | VEH prototypes |
| `include/core/Syscalls.h` | 51 | 1,762 | **SSN constants** (T5 unknown #8) |
| `include/core/Runtime.h` | 45 | 538 | RNG/time prototypes |
| `include/core/HwBpEngine.h` | 42 | 1,026 | HWBP engine |
| `include/core/Spoof.h` | 39 | 2,271 | Spoof constants |
| `include/core/SleepObf.h` | 32 | 926 | Sleep-obf technique enum + `OBF_JMP` |
| `include/core/Transport.h` | 28 | 1,027 | Transport struct |
| `include/core/MiniStd.h` | 26 | 1,274 | CRT-free prototypes |
| `include/core/Parser.h` | 23 | 816 | `PARSER` struct |
| `include/inject/InjectUtil.h` | 24 | 1,155 | InjectUtil prototypes |
| `include/core/TransportSmb.h` | 20 | 595 | SMB transport |
| `include/core/Pivot.h` | 18 | 555 | `PIVOT_DATA` |
| `include/crypt/AesCrypt.h` | 18 | 516 | AES constants |
| `include/core/Dotnet.h` | 4 | 124 | thin |
| `include/core/Process.h` | 3 | 82 | thin |

### 1.4 `payloads/DllLdr/` and `payloads/Shellcode/`

| Path | Lines | Bytes | Role |
|---|---|---|---|
| `DllLdr/Source/Entry.c` | 346 | 16,523 | Reflective loader entry |
| `DllLdr/Include/Core.h` | 77 | 3,001 | Loader types |
| `DllLdr/Include/Native.h` | 185 | 5,305 | Loader NT decls |
| `DllLdr/Include/Macro.h` | 12 | 505 | Macros |
| `DllLdr/Scripts/extract.py` | 31 | 1,583 | Extract loader binary |
| `Shellcode/Source/Entry.c` | 103 | 5,999 | Shellcode entry |
| `Shellcode/Source/Win32.c` | 34 | 1,863 | PEB resolution |
| `Shellcode/Source/Utils.c` | 25 | 620 | Utils |
| `Shellcode/Source/Asm/x64/Asm.s` | 40 | 834 | x64 PIC prologue |
| `Shellcode/Source/Asm/x86/Asm.s` | 41 | 849 | x86 PIC prologue |
| `Shellcode/Include/Core.h` | 61 | 1,834 | |
| `Shellcode/Scripts/extract.py` | 21 | 907 | |
| `Shellcode/Scripts/Hasher.c` | 26 | 536 | API-hash generator |
| `Shellcode/Scripts/Linker.ld` | — | — | Custom linker script |
| `payloads/DllLdr.x64.bin` | — | 6,656 b | **Prebuilt reflective loader** |
| `payloads/Shellcode.x64.bin` | — | 3,072 b | **Prebuilt x64 shellcode stub** |
| `payloads/Shellcode.x86.bin` | — | 2,048 b | **Prebuilt x86 shellcode stub** |

### 1.5 `payloads/Demon/src/asm/` — the assembly stubs (complete)

All four files are quoted in full in §8.3.

| Path | Lines | Bytes |
|---|---|---|
| `src/asm/Syscall.x64.asm` | 14 | 423 |
| `src/asm/Syscall.x86.asm` | 26 | 702 |
| `src/asm/Spoof.x64.asm` | 22 | 450 |
| `src/asm/Spoof.x86.asm` | 6 | 80 |

### 1.6 Teamserver (Go) — actual line counts

| Path | Lines | Bytes | Vendor? |
|---|---|---|---|
| `teamserver/pkg/agent/demons.go` | 5,149 | 191,942 | Havoc |
| `teamserver/pkg/agent/types.go` | 1,046 | 35,257 | Havoc |
| `teamserver/pkg/agent/agent.go` | 990 | 32,446 | Havoc |
| `teamserver/pkg/win32/types.go` | 994 | 58,752 | Havoc (Win32 type mirrors) |
| `teamserver/pkg/common/builder/builder.go` | 945 | 30,730 | Havoc |
| `teamserver/cmd/server/dispatch.go` | 778 | 27,186 | Havoc |
| `teamserver/cmd/server/teamserver.go` | 784 | 25,510 | Havoc |
| `teamserver/pkg/service/service.go` | 607 | 19,463 | Havoc |
| `teamserver/pkg/agent/commands.go` | 216 | 6,905 | Havoc |
| `teamserver/cmd/server/agent.go` | 201 | 6,633 | Havoc |
| `teamserver/cmd/server/listener.go` | 352 | 11,161 | Havoc |
| `teamserver/pkg/common/util.go` | 249 | 7,815 | Havoc |
| `teamserver/pkg/socks/util.go` | 253 | 7,178 | Havoc |
| `teamserver/pkg/handlers/handlers.go` | 271 | 9,298 | Havoc |
| `teamserver/pkg/handlers/http.go` | 244 | 7,604 | Havoc |
| `teamserver/pkg/logr/demon.go` | 182 | 6,431 | Havoc |
| `teamserver/pkg/common/certs/https.go` | 278 | 9,663 | Havoc |
| `teamserver/pkg/common/parser/parser.go` | 176 | 4,175 | Havoc |
| `teamserver/pkg/common/packer/packer.go` | 83 | 2,290 | Havoc |
| `teamserver/pkg/db/*.go` | 557 | 15,319 | Havoc |
| `teamserver/pkg/events/*.go` | 497 | 19,402 | Havoc |
| `teamserver/pkg/profile/{config,profile}.go` | 167 | 5,671 | Havoc |
| `teamserver/pkg/webhook/*.go` | 146 | 4,737 | Havoc |
| `teamserver/pkg/service/*.go` | 228 | 6,960 | Havoc |
| `teamserver/pkg/socks/socks.go` | 49 | 981 | Havoc |
| `teamserver/pkg/logger/*.go` | 164 | 5,302 | Havoc |
| `teamserver/pkg/colors/colors.go` | 19 | 1,032 | Havoc |
| `teamserver/pkg/packager/*.go` | 234 | 4,159 | Havoc |
| `teamserver/cmd/*.go` | 144 | 4,977 | Havoc |
| `teamserver/main.go` | 10 | 190 | Havoc |
| **`teamserver/pkg/profile/yaotl/**`** | **~34,000** | **~1.20 MB** | **VENDORED — HCL2 parser (OpenTofu/Terraform ancestor)** |
| `teamserver/pkg/profile/yaotl/hclsyntax/scan_tokens.go` | 5,198 | 207,326 | VENDORED (generated scanner) |
| `teamserver/pkg/profile/yaotl/hclsyntax/parser.go` | 1,818 | 77,346 | VENDORED |
| `teamserver/pkg/profile/yaotl/hclsyntax/expression.go` | 1,425 | 57,017 | VENDORED |
| `teamserver/pkg/profile/yaotl/hcldec/spec.go` | 1,412 | 56,331 | VENDORED |
| `teamserver/pkg/profile/yaotl/json/*.go` | ~5,000 | ~180 KB | VENDORED |
| `teamserver/pkg/profile/yaotl/hclwrite/*.go` | ~4,600 | ~200 KB | VENDORED |
| `teamserver/pkg/profile/yaotl/ext/*` (dynblock, tryfunc, typeexpr, transform, userfunc, customdecode) | ~2,600 | ~90 KB | VENDORED |
| `teamserver/pkg/profile/yaotl/hcltest/*.go` | ~700 | ~24 KB | VENDORED |
| `teamserver/pkg/profile/yaotl/*_test.go` (all tests) | ~14,000 | ~440 KB | VENDORED |

**VENDORED-DEPENDENCY MARKER.** `teamserver/pkg/profile/yaotl/` is an **HCL2 configuration-language parser**, a fork of HashiCorp HCL / OpenTofu's `hcl` package. It is **not Havoc-authored**. It accounts for roughly **82% of all Go bytes** and **~93% of all Go lines** in the teamserver, and about **31% of the entire repository's Go+C source bytes**. Its `hclsyntax`, `hcldec`, `hclwrite`, `json`, `gohcl`, `ext/*` subtrees are inherited verbatim. **No Havoc tradecraft lives there.** It is enumerated in §13.9 for completeness only, at directory granularity, because the user asked for everything; a line-by-line reversal of a generic HCL parser is not Havoc analysis.

### 1.7 Profiles and client

| Path | Role |
|---|---|
| `profiles/havoc.yaotl` | Default teamserver profile: operator credentials, ports, toolchain paths |
| `profiles/http_smb.yaotl` | HTTP+SMB listener example: URIs, UA, headers, `demon_pipe`, `Werfault.exe` spawn |
| `profiles/webhook_example.yaotl` | Discord webhook config |
| `client/` | Qt GUI: 42 `.cc`, 28 `.hpp`, 40 `.ui`, 11 `.qss`, 13 `.h`, `.qrc` resources, 85 `.png` |
| `data/` | Bundled `x86_64-w64-mingw32` / `i686-w64-mingw32` cross toolchains, `nasm`, Go runtime |
| `assets/` | Screenshots, icons |

### 1.8 Extension census (whole tree, `.git` excluded)

```
.go    202   1.79 MB
.png    85   3.69 MB
.h      54   0.67 MB
.hcl   51   ~0
.cc     42   0.60 MB
.ui     40   0.17 MB
.c      38   0.61 MB
.hpp    28   0.07 MB
.MD     19   0.08 MB
```

Note the C/H file *count* is far lower than the task brief's estimate (420 `.c`, 481 `.h`, 408 `.s`, 190 `.asm`). The real tree has **38 `.c`**, **54 `.h`**, **4 `.asm`**, **2 `.s`**. The inflated counts in the brief almost certainly counted files inside `data/` (the bundled mingw toolchain ships thousands of headers) and/or `.git`. Every `.c`/`.h`/`.asm`/`.s` file **outside** `data/` is enumerated above and read in this report. The toolchain headers under `data/*-w64-mingw32-cross/` are upstream GCC/MinGW — not Havoc code — and are excluded.

---

## 3. `core/Command.c` — THE DISPATCHER AND THE COMPLETE COMMANDID TABLE

3,504 lines, 26 top-level functions. The largest and most important file in the target.

### 3.1 THE COMMAND TABLE — `DemonCommands[]`

Declared `SEC_DATA` at `Command.c:16-42`, so the array of `{INT ID; VOID(*Function)(PPARSER);}` pairs lives in `.data` rather than `.text` — a flat, fully-addressable structure, 16 bytes per entry on x64. **Terminated by a sentinel `{ .ID = 0, .Function = NULL }` at index 22** (`Command.c:41`), which is what the linear-scan dispatch loop breaks on.

```c
SEC_DATA DEMON_COMMAND DemonCommands[] = {
        { .ID = DEMON_COMMAND_SLEEP,                    .Function = CommandSleep                    },
        { .ID = DEMON_COMMAND_CHECKIN,                  .Function = CommandCheckin                  },
        { .ID = DEMON_COMMAND_JOB,                      .Function = CommandJob                      },
        { .ID = DEMON_COMMAND_PROC,                     .Function = CommandProc                     },
        { .ID = DEMON_COMMAND_PROC_LIST,                .Function = CommandProcList                 },
        { .ID = DEMON_COMMAND_FS,                       .Function = CommandFS                       },
        { .ID = DEMON_COMMAND_INLINE_EXECUTE,           .Function = CommandInlineExecute            },
        { .ID = DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE,  .Function = CommandAssemblyInlineExecute    },
        { .ID = DEMON_COMMAND_ASSEMBLY_VERSIONS,        .Function = CommandAssemblyListVersion      },
        { .ID = DEMON_COMMAND_CONFIG,                   .Function = CommandConfig                   },
        { .ID = DEMON_COMMAND_SCREENSHOT,               .Function = CommandScreenshot               },
        { .ID = DEMON_COMMAND_PIVOT,                    .Function = CommandPivot                    },
        { .ID = DEMON_COMMAND_NET,                      .Function = CommandNet                      },
        { .ID = DEMON_COMMAND_INJECT_DLL,               .Function = CommandInjectDLL                },
        { .ID = DEMON_COMMAND_INJECT_SHELLCODE,         .Function = CommandInjectShellcode          },
        { .ID = DEMON_COMMAND_SPAWN_DLL,                .Function = CommandSpawnDLL                 },
        { .ID = DEMON_COMMAND_TOKEN,                    .Function = CommandToken                    },
        { .ID = DEMON_COMMAND_TRANSFER,                 .Function = CommandTransfer                 },
        { .ID = DEMON_COMMAND_SOCKET,                   .Function = CommandSocket                   },
        { .ID = DEMON_COMMAND_KERBEROS,                 .Function = CommandKerberos                 },
        { .ID = DEMON_COMMAND_MEM_FILE,                 .Function = CommandMemFile                  },
        { .ID = DEMON_EXIT,                             .Function = CommandExit                     },
        { .ID = 0, .Function = NULL }
};
```
[source: `payloads/Demon/src/core/Command.c:16-42`]

**Resolved CommandID → handler table.** Numeric values from `include/core/Command.h`.

| # | CommandID hex | dec | Symbol | C handler | Handler line | Sub-commands |
|---|---|---|---|---|---|---|
| 0 | `0x0B` | 11 | `DEMON_COMMAND_SLEEP` | `CommandSleep` | 174 | — |
| 1 | `0x64` | 100 | `DEMON_COMMAND_CHECKIN` | `CommandCheckin` | 163 | — |
| 2 | `0x15` | 21 | `DEMON_COMMAND_JOB` | `CommandJob` | 188 | LIST=1, SUSPEND=2, RESUME=3, KILL_REMOVE=4, (DIED=5 emitted only by agent) |
| 3 | `0x1010` | 4112 | `DEMON_COMMAND_PROC` | `CommandProc` | 263 | MODULES=2, GREP=3, CREATE=4, MEMORY=6, KILL=7 |
| 4 | `0x0C` | 12 | `DEMON_COMMAND_PROC_LIST` | `CommandProcList` | 562 | — |
| 5 | `0x0F` | 15 | `DEMON_COMMAND_FS` | `CommandFS` | 675 | DIR=1, DOWNLOAD=2, UPLOAD=3, CD=4, REMOVE=5, MKDIR=6, COPY=7, MOVE=8, GET_PWD=9, CAT=10 |
| 6 | `0x14` | 20 | `DEMON_COMMAND_INLINE_EXECUTE` | `CommandInlineExecute` | 1114 | — |
| 7 | `0x2001` | 8193 | `DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE` | `CommandAssemblyInlineExecute` | 1708 | — |
| 8 | `0x2003` | 8195 | `DEMON_COMMAND_ASSEMBLY_VERSIONS` | `CommandAssemblyListVersion` | 1792 | — |
| 9 | `0x09C4` | 2500 | `DEMON_COMMAND_CONFIG` | `CommandConfig` | 1865 | 15 options, §3.11 |
| 10 | `0x09CE` | 2510 | `DEMON_COMMAND_SCREENSHOT` | `CommandScreenshot` | 2084 | — |
| 11 | `0x09D8` | 2520 | `DEMON_COMMAND_PIVOT` | `CommandPivot` | 2463 | LIST=1, SMB_CONNECT=10, SMB_DISCONNECT=11, SMB_COMMAND=12 |
| 12 | `0x0834` | 2100 | `DEMON_COMMAND_NET` | `CommandNet` | 2109 | DOMAIN=1, LOGONS=2, SESSIONS=3, COMPUTER=4, DCLIST=5, SHARE=6, LOCALGROUP=7, GROUP=8, USER=9 |
| 13 | `0x16` | 22 | `DEMON_COMMAND_INJECT_DLL` | `CommandInjectDLL` | 1203 | — |
| 14 | `0x18` | 24 | `DEMON_COMMAND_INJECT_SHELLCODE` | `CommandInjectShellcode` | 1266 | — |
| 15 | `0x1A` | 26 | `DEMON_COMMAND_SPAWN_DLL` | `CommandSpawnDLL` | 1247 | — |
| 16 | `0x28` | 40 | `DEMON_COMMAND_TOKEN` | `CommandToken` | 1373 | IMPERSONATE=1, STEAL=2, LIST=3, PRIVSGET_OR_LIST=4, MAKE=5, GET_UID=6, REVERT=7, REMOVE=8, CLEAR=9, FIND_TOKENS=10 |
| 17 | `0x09E2` | 2530 | `DEMON_COMMAND_TRANSFER` | `CommandTransfer` | 2608 | LIST=0, STOP=1, RESUME=2, REMOVE=3 |
| 18 | `0x09EC` | 2540 | `DEMON_COMMAND_SOCKET` | `CommandSocket` | 2739 | create/connect/read/write/close + SOCKS, §3.15 |
| 19 | `0x09F6` | 2550 | `DEMON_COMMAND_KERBEROS` | `CommandKerberos` | 3077 | §10.1 |
| 20 | `0x0A00` | 2560 | `DEMON_COMMAND_MEM_FILE` | `CommandMemFile` | 3237 | §10.7 |
| 21 | `0x005C` | 92 | `DEMON_EXIT` | `CommandExit` | 3315 | — |

**CommandIDs with NO dispatch entry** — present in the header, never routed to a handler, because they are agent→server or control-only IDs:

| ID | Symbol | Handled where | Note |
|---|---|---|---|
| 1 | `DEMON_COMMAND_GET_JOB` | not handled | Server's request-for-work marker |
| 10 | `DEMON_COMMAND_NO_JOB` | `Command.c:106` guard | Sentinel the server injects when the queue is empty; the dispatcher skips handler lookup entirely |
| 89 | `DEMON_INFO` | agent→server | Informational package |
| 90 | `DEMON_OUTPUT` | agent→server | Command output |
| 91 | `DEMON_ERROR` | agent→server | Error |
| 92 | `DEMON_EXIT` | **both directions** | Agent→server on self-exit *and* a real server→agent task mapped to `CommandExit`. The only ID that appears on both directions. |
| 93 | `DEMON_KILL_DATE` | agent→server | Sent immediately before the agent dies |
| 94 | `BEACON_OUTPUT` | legacy CS alias | |
| 99 | `DEMON_INITIALIZE` | agent→server | Registration package built by `DemonMetaData` |
| 2570 | `DEMON_PACKAGE_DROPPED` | agent→server | Memory-file drop notice |

**This is the single most important structural fact about the dispatcher: it is a linear scan, not a switch.**

```c
for ( UINT32 FunctionCounter = 0 ;; FunctionCounter++ ) {
    if ( DemonCommands[ FunctionCounter ].Function == NULL ) {
        break;
    }
    if ( DemonCommands[ FunctionCounter ].ID == CommandID ) {
        DemonCommands[ FunctionCounter ].Function( &TaskParser );
        break;
    }
}
```
[source: `Command.c:113-122`]

- **O(n) linear search per task, in table order** — average 11 comparisons. No jump table, no binary search, no ordering assumption: the table is **not sorted by ID** (order is SLEEP, CHECKIN, JOB, PROC…). A `switch` would have compiled to a jump table and made static recovery trivial; the author left `// TODO: rewrite this part` at `Command.c:44-47`.
- **Unknown CommandID = silent no-op.** No match → loop hits the sentinel → break → return. **No error package is emitted.** There is no "unknown command" path anywhere in `Command.c`.
- **Duplicate IDs resolve first-match-wins** and cannot be detected at runtime. The table has no duplicates today.
- The handler is called with `&TaskParser` **even when the task body is empty** (`TaskBufferSize == 0` skips `ParserNew`/`ParserDecrypt`, lines 108-111). `TaskParser` is then the zero-initialised struct from line 53, so `ParserGetInt32` on a zero-size task yields `0` rather than faulting — *provided* the parser bounds-checks (§4.6).
- Handler return type is `VOID` — **a handler cannot report failure to the dispatcher.** All error reporting is out-of-band via `PackageTransmit`.

### 3.2 `CommandDispatcher` — line 48

```c
VOID CommandDispatcher( VOID )
{
    PARSER   Parser = { 0 };  LPVOID DataBuffer = { 0 };  SIZE_T DataBufferSize = { 0 };
    PARSER   TaskParser = { 0 };  ...
    PRINTF( "Session ID => %x\n", Instance->Session.AgentID );

    do {
        if ( ! Instance->Session.Connected ) { break; }
        SleepObf();
        if ( ReachedKillDate() ) { KillDate(); }
        if ( ! InWorkingHours() ) { continue; }
```
[source: `Command.c:48-75`]

**The sleep is at the top of the dispatcher loop (line 66) and every iteration sleeps.** `DemonRoutine` *also* calls `SleepObf()` after the dispatcher returns (`Demon.c:90`). Because the dispatcher is `do{…}while(TRUE)` and exits only via `break` when disconnected, `DemonRoutine`'s sleep executes **only once per disconnect** — the dispatcher owns the sleep cadence.

`continue` on `! InWorkingHours()` **skips `PackageTransmitAll` as well as the task fetch**, so outside working hours the agent is fully silent and `Session.Connected` is never re-evaluated inside the loop. A host that drops the connection at 17:00 stays `Connected == TRUE` (stale) until working hours resume and **no reconnect is attempted during the off-hours window.** Intended as silence, but it means the `Connected` flag is not a liveness indicator off-hours.

**Task fetch, HTTP branch:**
```c
if ( ! PackageTransmitAll( &DataBuffer, &DataBufferSize ) && ! HostCheckup() )
{
    CommandExit( NULL );
}
```
[source: `Command.c:79-82`]

`PackageTransmitAll` both flushes queued outbound packages and retrieves the server's reply in one request/response. If it returns FALSE *and* `HostCheckup()` also returns FALSE, the agent calls `CommandExit( NULL )` with a NULL parser — safe because `CommandExit` guards for NULL (§3.19). `HostCheckup()` is the host-rotation decision: **a transport failure only kills the agent when the host list is exhausted.**

**SMB branch:**
```c
PackageTransmitAll( NULL, NULL );
if ( ! SMBGetJob( &DataBuffer, &DataBufferSize ) ) { PUTS( "SMBGetJob failed" ) continue; }
```
[source: `Command.c:85-94`]
The SMB path ignores `PackageTransmitAll`'s status and `continue`s on a pipe read failure — looping back to `SleepObf()` at line 66. An SMB pivot whose parent has died **spins through sleep-obfuscation forever** rather than exiting. `HostCheckup` is `#ifdef TRANSPORT_HTTP`, so there is no SMB-side rotation and no SMB-side timeout. A dead SMB parent leaves an orphan that keeps sleeping and re-encrypting its own memory indefinitely.

**Task framing parse — the inner loop:**
```c
if ( DataBuffer && DataBufferSize > 0 ) {
    ParserNew( &Parser, DataBuffer, DataBufferSize );
    do {
        CommandID  = ParserGetInt32( &Parser );
        RequestID  = ParserGetInt32( &Parser );
        TaskBuffer = ParserGetBytes( &Parser, &TaskBufferSize );
        Instance->CurrentRequestID = RequestID;
        if ( CommandID != DEMON_COMMAND_NO_JOB ) {
            PRINTF( "Task => RequestID:[%d : %x] CommandID:[%d : %x] TaskBuffer:[%x : %d]\n", ... )
            if ( TaskBufferSize != 0 ) {
                ParserNew( &TaskParser, TaskBuffer, TaskBufferSize );
                ParserDecrypt( &TaskParser, Instance->Config.AES.Key, Instance->Config.AES.IV );
            }
            for ( UINT32 FunctionCounter = 0 ;; FunctionCounter++ ) { ...dispatch... }
        }
    } while ( Parser.Length > 12 );
```
[source: `Command.c:97-124`]

Each task record is `[CommandID 4][RequestID 4][len 4][data len]` = **12 bytes of header minimum**. The loop continues while **more than** 12 bytes remain, so a trailing record consisting of exactly a 12-byte header with a zero-length body is **silently dropped**. In practice the server always sends a body or a `NO_JOB` marker, but a bodyless task appended last is lost with no error.

**`TaskBufferSize` is never reset between iterations.** It is declared once (line 55) and `ParserGetBytes` writes through the pointer. If a record's `ParserGetBytes` takes a failure path that does not write `*Length`, **the previous record's size persists and is reused** — a malformed record can cause the *next* record's task to be decrypted using the wrong length. Cross-task state leak in the hot loop.

**Decrypt is conditional on `TaskBufferSize != 0`** and uses the key/IV allocated once at registration and **never rotated**. See §3.3.

**Per-iteration cleanup:**
```c
MemSet( DataBuffer, 0, DataBufferSize );
Instance->Win32.LocalFree( DataBuffer );   DataBuffer = NULL;
ParserDestroy( &Parser );   ParserDestroy( &TaskParser );
```
[source: `Command.c:126-131`]
The inbound buffer is zeroed before free. `TaskBuffer` points *into* `DataBuffer`, so the whole-buffer zeroing covers the decrypted body. `TaskParser` is destroyed after the buffer it points into is freed — safe only because `ParserDestroy` does not touch the buffer.

**Post-loop hooks — the outbound work queue:**
```c
JobCheckList();  PivotPush();  DownloadPush();  DotnetPush();  SocketPush();
```
[source: `Command.c:142-154`]

Five push functions drain per-subsystem outbound queues: job output, SMB pivot pipe output, download chunks, .NET output, socket data. They run **once per dispatcher iteration, unconditionally, after task execution and before the next sleep.**

- **Output latency is floored by the sleep time.** A 60-second sleep means 60-second-granularity interactive output.
- Each push writes into the global `Instance->Packages` list (`Demon.h:520+`), which `PackageTransmitAll` flushes at the top of the *next* iteration — so output produced this iteration travels one full sleep-cycle later.
- A handler that calls `PackageTransmit` directly bypasses this queue and emits immediately. Most do.

**Loop exit:**
```c
    } while ( TRUE );
    Instance->Session.Connected = FALSE;
    PUTS( "Out of while loop" )
}
```
[source: `Command.c:156-161`]
The two clean exits are `break` at line 63 (disconnected at loop top) and `break` at line 137 (HTTP transport failure with an empty `DataBuffer`). The second is `#ifdef TRANSPORT_HTTP`-guarded — **the SMB build has no exit path from that `else` at all**; it falls through to `JobCheckList()` and loops.

### 3.3 THE HANDSHAKE AND THE FRAME — at statement level

**Frame construction (agent → server).** Every outbound package is built by `PackageCreate( CommandID )` then wrapped by `PackageTransmit` (§4.5):

```
[ SIZE        : 4 bytes, big-endian ]     <- size of everything after this field
[ MagicValue  : 4 bytes, 0xDEADBEEF ]     <- DEMON_MAGIC_VALUE, Defines.h:15
[ AgentID     : 4 bytes, big-endian ]     <- Instance->Session.AgentID
[ CommandID   : 4 bytes, big-endian ]     <- the command being answered
[ RequestID   : 4 bytes, big-endian ]     <- Instance->CurrentRequestID
[ AES-256-CTR encrypted body            ]
```

**Registration (`DEMON_INITIALIZE`) is the one frame whose body is NOT encrypted.** `DemonMetaData` builds it with `PackageCreateWithMetaData( DEMON_INITIALIZE )` (`Demon.c:106`) and `PackageTransmit` sends it as-is. Its body is the 24-field metadata block from §2.3, whose **first 48 bytes are the AES key (32) and IV (16) in cleartext.**

**The AES key exchange, as implemented:**

1. Agent allocates 32-byte key + 16-byte IV, fills both from `RandomNumber32()` — `Demon.c:112-123`.
2. Agent writes both into the **cleartext** `DEMON_INITIALIZE` body — `Demon.c:159-161` via `PackageAddPad`.
3. Agent transmits. The teamserver reads key+IV from the plaintext body and stores them on the agent record (`teamserver/pkg/agent/agent.go`, `Encryption{Key, IV, Enabled}`).
4. **Every subsequent frame in both directions uses AES-256-CTR with that key and that IV.** The agent never rotates. `ParserDecrypt(&TaskParser, Key, IV)` at `Command.c:110` is the only inbound decrypt call site.
5. **The IV is reused for every message.** AES-CTR with fixed key+IV is a **many-time pad**: `C1 = P1 ⊕ KS`, `C2 = P2 ⊕ KS` under the same keystream `KS`, so `C1 ⊕ C2 = P1 ⊕ P2`, and any single known plaintext recovers `KS` and decrypts every other frame.

The attacker does not even have to guess. **`DEMON_INITIALIZE` is itself unencrypted and its structure is highly predictable** — 24 fields, mostly lengths whose low bytes are ASCII digits, a UTF-16 image path starting `C:\`, an ASCII IP address. A passive interceptor who sees the registration frame (which *also contains the key and IV in the clear*) can recover the keystream directly and decrypt the entire session. **The registration frame is the known plaintext.**

And the oracle is re-armed on demand: `CommandCheckin` (§3.4) **re-emits the exact same 24-field metadata block**, encrypted under the session key with the fixed IV. Running the operator's own `checkin` command hands an interceptor a fresh known plaintext at any point in the session.

This is not theoretical. It is a **direct consequence of the design and it is reachable by the operator's own command set.**

**The AgentID sentinel.** The agent writes `Instance->Session.AgentID` at metadata field 3 (`Demon.c:164`) **outside** the encrypted region, in the clear. The server-side check compares the parsed body's AgentID against the frame header's AgentID — both values it just read from the same undisputed body. **It is a consistency assertion, not authentication.** There is **no key confirmation, no MAC, no HMAC, no nonce, and no replay protection** anywhere in the frame format.

**Frame parsing (server → agent).** The agent's inbound buffer is not parsed as a wrapped frame — the transport layer has already stripped the frame header. Confirmed by `Command.c:97-124`: the first thing read is `CommandID` (4), then `RequestID` (4), then a length-prefixed body. **The server→agent direction is `[CommandID][RequestID][len][AES-CTR body]` repeated — no size field, no magic value, no AgentID.** The agent cannot verify a task was intended for it and cannot detect a truncated or oversized reply; `DataBufferSize` comes from the HTTP layer.

**Decrypt applies to the body only, after the length is read in the clear.** So the `[ID][REQ][len]` header of every task is unencrypted on the wire — the command being run and the request ID are exposed to any interceptor even without breaking the CTR. **The command taxonomy is not protected.**

### 3.4 `CommandCheckin` — line 163
```c
VOID CommandCheckin( PPARSER Parser )
{
    PUTS( "Checkin" )
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_CHECKIN );
    DemonMetaData( &Package, FALSE );
    PackageTransmit( Package );
}
```
[source: `Command.c:163-172`]. Creates the package *without* the metadata header (`PackageCreate`, not `PackageCreateWithMetaData`) because `DemonMetaData(&Package, FALSE)` skips the `DEMON_INITIALIZE` header write when `Header == FALSE` (`Demon.c:104`). The body is the full 24-field metadata block, **including the AES key and IV, re-sent in the clear.** Both the re-registration path and the known-plaintext oracle. `Parser` is unused.

### 3.5 `CommandSleep` — line 174
```c
Instance->Config.Sleeping = ParserGetInt32( Parser );
Instance->Config.Jitter   = ParserGetInt32( Parser );
PackageAddInt32( Package, Instance->Config.Sleeping );
PackageAddInt32( Package, Instance->Config.Jitter );
```
[source: `Command.c:174-186`]. **No validation whatsoever.** A `Sleeping` of 0 produces a full-speed beacon loop (the sleep path still runs `SleepObf()`, which with a 0 timeout returns immediately). A negative value read as `DWORD` parks the agent for ~49 days. Jitter greater than the sleep interval is accepted. No floor, no ceiling, no bound check.

### 3.6 `CommandJob` — line 188
Switches on `ParserGetInt32` (line 192) with the sub-command echoed back first (line 194) for client correlation.
- **`JOB_LIST` (=1)**, 198-219: walks `Instance->Jobs` emitting `[JobID][Type][State]` triples. `do { if (JobList) {…; JobList = JobList->Next;} else break; } while (TRUE)` — terminates correctly on an empty list. Ignores the rest of the task body.
- **`SUSPEND` (=2)**, 221-233: `JobSuspend(JobID)` → `[JobID][Success]`.
- **`RESUME` (=3)**, 235-245: `JobResume(JobID)` → `[JobID][Success]`.
- **`KILL_REMOVE` (=4)**, 247-257: `JobKill(JobID)` → `[JobID][Success]`.
- **`JOB_DIED` (=5)** is defined (`Command.h:103`) but has **no case here** — it is agent→server only, emitted by `Jobs.c` when a fiber terminates.

Any other sub-command falls through with **no error emitted**, producing a package containing only the echoed `Command` int.

### 3.7 `CommandProc` — line 263
Sub-commands `MODULES`=2, `GREP`=3, `CREATE`=4, `MEMORY`=6, `KILL`=7. **`PROC`=5 does not exist** — the gap is real; the client never sends 5.

**`PROC_MODULES` (272-334)** — walks the target's PEB loader list over the wire:
- `ProcessID` parsed only `if (Parser->Length > 0)` (line 279); a bodyless command defaults to `NtCurrentProcess()` (line 276). This direct `Parser->Length` read is the only bounds check here (§4.6).
- `SysNtQueryInformationProcess(ProcessBasicInformation)` → `PebBaseAddress` (288)
- `SysNtReadVirtualMemory(hProcess, &PebBaseAddress->Ldr, …)` — **reads the remote PEB pointer, not the local one** (300)
- Iterates `InMemoryOrderModuleList`, reading each `LDR_DATA_TABLE_ENTRY` and its `FullDllName.Buffer` out of the target (302-325)
- Emits `[ProcessID]` once, then per module `[FullDllName ASCII][DllBase as 8-byte pointer]` (316-317)

**Bug at line 311 — a remotely triggerable stack buffer overflow.**
```c
WCHAR ModuleNameW[ MAX_PATH ] = { 0 };            // 520 bytes, line 295
...
SysNtReadVirtualMemory( hProcess, CurrentModule.FullDllName.Buffer,
                        &ModuleNameW, CurrentModule.FullDllName.Length, &Size );
```
The destination is a 520-byte stack array; the length is `CurrentModule.FullDllName.Length` **read out of the remote process** with no upper bound. The only check afterwards is `if (CurrentModule.FullDllName.Length > 0)` (line 313) — a *lower*-bound check. A target process reporting a module path longer than 520 bytes smashes the agent's stack. **A hostile or corrupted target process can overflow the agent via `PROC_MODULES`.** This is the most serious memory-safety defect in `Command.c`.

**`PROC_GREP` (337-421)** — `ParserGetWString` search term, `ProcessSnapShot` (`NtQuerySystemInformation` `SystemProcessInformation`), `WcsIStr` (case-insensitive substring) against each `ImageName.Buffer`. Per match: opens with `PROCESS_QUERY_LIMITED_INFORMATION` when `Session.OSVersion > WIN_VERSION_XP` else `PROCESS_QUERY_INFORMATION` (367) — the only functional consumer of the OS-version ladder, and correct for Vista+. Emits `[ImageName W][PID][PPID][UserDomain bytes][86|64]`.

**Bug at line 369 — an infinite loop in the agent's task handler.**
```c
hProcess = ProcessOpen( ..., PROCESS_QUERY_LIMITED_INFORMATION );
if ( ! hProcess )
    continue;                       // <-- line 368-369
...
if ( SysProcessInfo->NextEntryOffset == 0 ) break;               // line 400
SysProcessInfo = C_PTR( U_PTR( SysProcessInfo ) + SysProcessInfo->NextEntryOffset );  // line 403
```
The `continue` jumps to `while (TRUE)` at line 358 **without advancing `SysProcessInfo` or testing the terminator.** Every subsequent iteration re-tests the *same* entry, fails `ProcessOpen` again, and continues again. The entry is reached only because its `ImageName` matched the search pattern, so this triggers **whenever the grep pattern matches a process the agent cannot open** — any protected/PPL process (`MsMpEng`, `Services.exe` on a hardened host, EDR processes, or simply a higher-integrity process). **`PROC_GREP` on such a pattern hangs the agent thread permanently**, which from the operator's side looks like the agent dying (the dispatcher never returns, so no further beacons). The trigger is not exotic.

**`PROC_CREATE` (423-466)** — parses `[ProcessState][Process W][Args W][Piped][Verbose]`, maps empty strings to NULL (435-439), calls `ProcessCreate(TRUE, Process, ProcessArgs, ProcessState, &ProcessInfo, ProcessPiped, NULL)`. Returns `[Process W][PID or 0][Success][Piped][Verbose]`. On success always closes `hThread`, and `hProcess` **only when not piped** (458-460) — in the piped case the handle is retained for reading and stored in `JOB_DATA`, closed by `JobCheckList` when the job ends.

**`PROC_MEMORY` (468-526)** — `NtQueryVirtualMemory` walk. `QueryProtec == 0` emits every committed region `[BaseAddress][RegionSize][AllocationProtect][State][Type]`; nonzero emits only regions whose **`AllocationProtect`** equals it exactly. Filtering on `AllocationProtect` rather than `Protect` means a region allocated RW and later `VirtualProtect`ed to RX is reported under its *allocation* protection, so a query for `PAGE_EXECUTE_READ` misses every JIT region. Visibility filters: `MemInfo.Type != MEM_FREE` and `MemInfo.AllocationBase != 0`.

**`PROC_KILL` (528-547)** — `ProcessOpen(PID, PROCESS_TERMINATE)` then `TerminateProcess(hProcess, 0)`; exit code hardcoded 0. Returns `[hProcess ? TRUE : FALSE][PID]`. **It reports success from the handle open, not from `TerminateProcess`'s return**, so a handle acquired but with termination denied still reports TRUE — the operator's UI shows a kill that did not happen.

### 3.8 `CommandProcList` — line 562
Its own CommandID (12), no sub-command. `ProcessSnapShot` → per process: `ProcessOpen(QUERY_LIMITED_INFORMATION|QUERY_INFORMATION)` → `SysNtOpenProcessToken(TOKEN_QUERY)` → `TokenQueryOwner(TOKEN_OWNER_FLAG_DEFAULT)` → `ProcessIsWow`.

Emit per process: `[ImageName bytes][PID][x86 BOOL][PPID][SessionId][NumberOfThreads][UserDomain bytes]`, prefixed once by `[ProcessUI]` (589); package is `DEMON_COMMAND_PROC_LIST`.

**Bug — `x86` is not reset per iteration.** `BOOL x86 = FALSE;` is declared at line 573 **outside** the loop and assigned only when `Process` is non-NULL (614). For a process whose handle open failed, `x86` retains the **previous process's** value and is emitted (620). The client sees a stale architecture for every process the agent cannot open. Same class as the uninitialised-`Headers` read in §2.5.

The `#ifdef DEBUG` branch (626-632) deliberately leaks the handle to the agent's own process so `PRINTF` keeps working; release builds close all handles (634-637). `SysProcessPtr` is zeroed before free (665).

### 3.9 `CommandFS` — line 675 — ten sub-commands

**`FS_DIR` (684-792)** parses `[FileExplorer][TargetFolder W][SubDirs][FilesOnly][DirsOnly][ListOnly][Starts W][Contains W][Ends W]`. `Starts[0] ? Starts : NULL` (712-714) — filters are enabled only when non-empty, so the client encodes "no filter" as an empty string rather than an absent field.

`TargetFolder[0] == L'.'` builds the wildcard from the current directory (`GetCurrentDirectoryW` + append `\*`); **else:**
```c
MemCopy( Path, TargetFolder, MAX_PATH * sizeof( WCHAR ) );
```
[source: `Command.c:735`]

`Path` is a `LocalAlloc`'d 520-byte buffer, but `TargetFolder` is the `ParserGetWString` result — a heap buffer sized to the actual string. **An unconditional 520-byte copy from a shorter source is a heap over-read.** A 20-character path (40 bytes + NUL) over-reads ~478 bytes of adjacent heap, and that data becomes the operator-visible path string (and is passed to `listDir`). It over-reads the source, not overflows the destination, so it is not a write primitive — but on a page boundary it faults, and the leaked bytes reach the operator. **A short directory name is the common case, so this is the normal path, not the edge case.**

`listDir(Path, SubDirs, FilesOnly, DirsOnly, Starts, Contains, Ends, 10)` — the trailing `10` is the recursion depth cap. The inline `TODO` (740-745) acknowledges the function "is known to crash if the search space is too vast." A hard depth limit of 10 is the only bound.

Emit: `[FileExplorer][ListOnly][Path W][RootDirExists BOOL]`, then per directory `[Path W][NumFiles][NumFolders]` (+`[TotalFileSize]` unless `ListOnly`), then per file `[FileName W]` (+`[IsDir][Size][wDay][wMonth][wYear][wMinute][wHour]` unless `ListOnly`). **Timestamp fields are inconsistent** — `wDay/wMonth/wYear` come from `DirOrFile->FileTime` while `wMinute/wHour` come from `DirOrFile->SystemTime`, two different struct members for one logical timestamp, and **seconds are never transmitted**.

**`FS_DOWNLOAD` (794-…)** parses a `ParserGetBytes` filename, `CreateFileW(GENERIC_READ)`, `GetFullPathNameW`, `GetFileSizeEx`, `DownloadAdd(hFile, size)`. On any failure `PACKAGE_ERROR_WIN32` then `goto CleanupDownload` with `Success = FALSE`. Header layout per the inline comment (839-847): `[Mode: Open(0)|Write(1)|Close(2)][File ID]`, with `[File Size][File Name]` on Open. The file handle and full path are retained for the transfer's lifetime in `DOWNLOAD_DATA`.

*(`FS_UPLOAD`, `CD`, `REMOVE`, `MKDIR`, `COPY`, `MOVE`, `GET_PWD`, `CAT` occupy lines 848-1113; each case follows the same parse-act-emit shape with `PACKAGE_ERROR_WIN32` on failure.)*

### 3.10 `CommandInlineExecute` — line 1114
Runs a raw shellcode blob in-process or in a spawned process per the body flags. Emits one of the four status codes from `Command.h:40-43`:

| Code | Symbol | Meaning |
|---|---|---|
| 1 | `DEMON_COMMAND_INLINE_EXECUTE_EXCEPTION` | An exception (e.g. `0xC0000005`, a BOF/COFF crash) escaped the executed code |
| 2 | `DEMON_COMMAND_INLINE_EXECUTE_SYMBOL_NOT_FOUND` | A required symbol could not be resolved |
| 3 | `DEMON_COMMAND_INLINE_EXECUTE_RAN_OK` | Executed to completion |
| 4 | `DEMON_COMMAND_INLINE_EXECUTE_COULD_NO_RUN` | Never started |

The exception path is driven by the VEH installed via `HwBpExceptions.c` / `RtlAddVectoredExceptionHandler` — the inline-execute and COFF engines share that harness, which is why `…_EXCEPTION` exists as a first-class result. Recovering the four-code taxonomy at source level resolves part of T5 §11.

### 3.11 `CommandConfig` — line 1865 — the option surface
`DEMON_CONFIG_SHOW_ALL` = 0 dumps everything; individual options are `set`.

| Option | Symbol | Effect |
|---|---|---|
| 0 | `DEMON_CONFIG_SHOW_ALL` | Emits the entire current config |
| 1 | `DEMON_CONFIG_IMPLANT_SLEEPMASK` | Toggle sleep masking |
| 3 | `DEMON_CONFIG_IMPLANT_SPFTHREADADDR` | **Set `ThreadStartAddr`** — the stack-spoof gadget |
| 4 | `DEMON_CONFIG_IMPLANT_VERBOSE` | Toggle debug prints |
| 5 | `DEMON_CONFIG_IMPLANT_SLEEP_TECHNIQUE` | `SLEEPOBF_NO_OBF/EKKO/ZILEAN/FOLIAGE` |
| 6 | `DEMON_CONFIG_IMPLANT_COFFEE_THREADED` | BOF execution threaded |
| 7 | `DEMON_CONFIG_IMPLANT_COFFEE_VEH` | BOF exception forwarding |
| 101 | `DEMON_CONFIG_MEMORY_ALLOC` | Memory allocation technique |
| 102 | `DEMON_CONFIG_MEMORY_EXECUTE` | Memory execute technique |
| 150 | `DEMON_CONFIG_INJECTION_TECHNIQUE` | `INJECTION_TECHNIQUE_*` (§8.1) |
| 151 | `DEMON_CONFIG_INJECTION_SPOOFADDR` | Injection stack-spoof address |
| 152 | `DEMON_CONFIG_INJECTION_SPAWN64` | Spawn-to path (x64) |
| 153 | `DEMON_CONFIG_INJECTION_SPAWN32` | Spawn-to path (x86) |
| 154 | `DEMON_CONFIG_KILLDATE` | Kill date |
| 155 | `DEMON_CONFIG_WORKINGHOURS` | Working-hours bitfield |

**Option 3 is the interesting one.** It sets `ThreadStartAddr` at runtime — the address `NtCreateThreadEx` is told to begin executing at (`Obf.c:81`) and the address the fake stack frames are built around (`Obf.c:507-527`). Setting it to a bespoke gadget in an already-mapped module is how a Havoc user defeats the `LdrLoadDll+0x12` default that is otherwise identical across every Havoc implant in existence. **An unmodified Havoc installation uses the same stack-spoof gadget address worldwide**, a reliable memory/file signature.

### 3.12 `CommandScreenshot` — line 2084
`2510`. GDI32 screen capture → encodes to BMP → returns as a package body. Uses the `RtGdi32` / kernel32 sets resolved in `DemonInit`.

### 3.13 `CommandNet` — line 2109 — nine sub-commands
`DOMAIN`=1, `LOGONS`=2, `SESSIONS`=3, `COMPUTER`=4, `DCLIST`=5, `SHARE`=6, `LOCALGROUP`=7, `GROUP`=8, `USER`=9 (`Command.h:76-84`). Implemented against `NetApi32` (the `RtNetApi32` module loaded in `DemonInit`). `LOGONS`/`SESSIONS` are the `NetSessionEnum`/`NetWkstaUserEnum` paths yielding logged-on-user telemetry — the lateral-movement reconnaissance pair. Emits `[SubCommand]` echo then the enumerated records.

### 3.14 `CommandPivot`, `CommandTransfer` — lines 2463, 2608
**`PIVOT` (2520)** — `LIST`=1, `SMB_CONNECT`=10, `SMB_DISCONNECT`=11, `SMB_COMMAND`=12. Manages `Instance->SmbPivots` (`PIVOT_DATA`). `SMB_CONNECT` names a pipe and target; `SMB_COMMAND` routes an inner Demon frame down an established pivot — how a second agent is reached without a route to the teamserver. `MAX_SMB_PACKETS_PER_LOOP = 30` (`Pivot.h`) bounds the drain per iteration.

**`TRANSFER` (2530)** — `LIST`=0, `STOP`=1, `RESUME`=2, `REMOVE`=3 (`Command.h:105-108`). Operates on `Instance->Downloads` and the `MEM_FILE` upload list; `STOP`/`RESUME` manipulate per-transfer state consumed by `DownloadPush`.

### 3.15 `CommandSocket` — line 2739
`2540`. Creates/connects/reads/writes/closes sockets via `Instance->Sockets`, and with the SOCKS variant proxies operator traffic through the agent. `SocketPush()` (line 154) drains pending socket data each iteration.

### 3.16 `CommandKerberos` — line 3077
`2550`. Full LSA/Kerberos toolkit — see §10.1.

### 3.17 `CommandMemFile` — line 3237
`2560`. Creates, lists, reads/writes and clears **memory-only files** backed by `MEM_FILE` structures in `Instance->MemFiles`. Nothing touches disk. `DEMON_PACKAGE_DROPPED` (2570) is emitted when a memory file is dropped into a process.

### 3.18 Working-hours and kill-date helpers — lines 3263-3314
```c
BOOL InWorkingHours( )
{
    SYSTEMTIME SystemTime;
    Instance->Win32.GetLocalTime( &SystemTime );
    if ( Instance->Config.Transport.WorkingHours == 0 ) return TRUE;
    StartHour   = ( WorkingHours >> 17 ) & 0b011111;
    StartMinute = ( WorkingHours >> 11 ) & 0b111111;
    EndHour     = ( WorkingHours >>  6 ) & 0b011111;
    EndMinute   = ( WorkingHours >>  0 ) & 0b111111;
    ...
}
```
[source: `Command.c:3263-3294`]. Reads **local** time (`GetLocalTime`, not UTC), so working hours are expressed in *the victim's* timezone; an operator setting 09:00-17:00 gets that window on the host's clock. The bitfield is two 12-bit `[5-bit hour][6-bit minute]` pairs packed into 32 bits.
```c
VOID KillDate( )
{
    PUTS( "KillDate" )
    PPACKAGE Package = PackageCreate( DEMON_KILL_DATE );
    PackageTransmit( Package );
    Instance->Win32.RtlExitUserThread( 0 );
}
```
[source: `Command.c:3300-3313`]. **Sends `DEMON_KILL_DATE` before dying** — a deliberate final notification so the UI removes the agent. Then `RtlExitUserThread(0)`: same caveat as §2.5 — ends the *thread*, not guaranteed the *process*. In an injected host with other threads the process survives with a dead agent.

### 3.19 `CommandExit` — line 3315
```c
VOID CommandExit( PPARSER Parser )
{
    BOOL Threaded = FALSE;
    if ( Parser && Parser->Length > 0 ) Threaded = ParserGetInt32( Parser );
    PPACKAGE Package = PackageCreate( DEMON_EXIT );
    PackageAddInt32( Package, Threaded );
    PackageTransmit( Package );
    if ( ! Threaded ) Instance->Win32.RtlExitUserProcess( 0 );
    else              Instance->Win32.RtlExitUserThread( 0 );
}
```
The `Parser && Parser->Length > 0` guard is what makes `CommandExit( NULL )` at `Command.c:81` safe: the NULL case yields `Threaded = FALSE` → `RtlExitUserProcess(0)`, killing the whole process. The threaded case exits only the agent's own thread — used when the Demon is a BOF/fibre inside an operator-spawned process.

### 3.20 Control-flow notes for `Command.c` as a whole
- **Every handler is `VOID`-returning and reports via `PackageTransmit`.** No error channel to the dispatcher.
- **`PACKAGE_ERROR_WIN32` / `PACKAGE_ERROR_NTSTATUS` / `CALLBACK_ERROR_*` are macros** (`Macros.h`) that build and transmit an error package inline. Roughly a third of failure branches use them; the rest silently `break`.
- **Eight sub-command switches, none with a `default` that emits an error** — an out-of-range sub-command yields a package containing only the echoed value. `CommandProc`, `CommandFS`, `CommandJob`, `CommandToken`, `CommandNet`, `CommandPivot`, `CommandTransfer`, `CommandSocket` all share this shape.
- **Handlers mutate global `Instance->…` directly; there is no locking.** The dispatcher is single-threaded and the jobs are cooperative fibres, but `SocketPush` and the injected-process paths are not.

---

## 5. `core/Obf.c` — SLEEP OBFUSCATION: EKKO, ZILEAN, FOLIAGE

668 lines (778 reported by the reader with the in-file comment block), `#if _WIN64`-guarded for the whole file: **the x86 build has no sleep obfuscation at all** — `Obf.c:770-776` is a bare `#else` that calls `WaitForSingleObjectEx` directly with the comment `// TODO: add support for sleep obf and spoofing`.

Three techniques plus a no-op, selected by `Instance->Config.Implant.SleepMaskTechnique`:

| Value | Symbol | Mechanism | API |
|---|---|---|---|
| `0x0` | `SLEEPOBF_NO_OBF` | plain wait (with optional stack spoof) | `WaitForSingleObjectEx` |
| `0x1` | `SLEEPOBF_EKKO` | ROP chain on the **timer queue** thread | `RtlCreateTimerQueue`/`RtlCreateTimer` |
| `0x2` | `SLEEPOBF_ZILEAN` | ROP chain on the **wait** thread | `RtlRegisterWait` |
| `0x3` | `SLEEPOBF_FOLIAGE` | ROP chain from an **APC** on a new fibre thread | `NtCreateThreadEx` + `NtQueueApcThread` |
[source: `include/core/SleepObf.h`, `Obf.c:748-768`]

Plus jump-bypass sub-modes on EKKO/ZILEAN:

| Value | Symbol | Byte patched |
|---|---|---|
| `0x0` | `SLEEPOBF_BYPASS_NONE` | — |
| `0x1` | `SLEEPOBF_BYPASS_JMPRAX` | `JmpPad[1] = 0x20` (`jmp rax`) |
| `0x2` | `SLEEPOBF_BYPASS_JMPRBX` | `JmpPad[1] = 0x23` (`jmp rbx`) |
[source: `Obf.c:462-464`]

### 5.1 The common encryption core — RC4, not AES

**Sleep obfuscation encrypts with RC4 via `SystemFunction032`, not with the agent's AES.**

```c
USTRING Key = { 0 };
USTRING Rc4 = { 0 };
UCHAR   Random[16] = { 0 };
...
for ( SHORT i = 0; i < 16; i++ )
    Random[ i ] = RandomNumber32( );

Key.Buffer = &Random;
Key.Length = Key.MaximumLength = 0x10;      // 16-byte RC4 key

Rc4.Buffer = ImageBase;
Rc4.Length = Rc4.MaximumLength = ImageSize; // the whole image, or .text
```
[source: `Obf.c:69-77` (Foliage) and the equivalent block in `TimerObf`]

`SystemFunction032` is `advapi32!SystemFunction032` — the undocumented `RtlEncryptMemory`-family RC4 primitive (cryptoapi `USTRING`-based). **RC4 is used because it is a stream cipher operating in place with no block padding** — the image can be re-encrypted and re-decrypted in place without any buffer growth, and the same call serves both directions.

**Range selection:**
```c
ImageBase = Instance->Session.ModuleBase;
ImageSize = Instance->Session.ModuleSize;

if ( Instance->Session.TxtBase != 0 && Instance->Session.TxtSize != 0 ) {
    TxtBase    = Instance->Session.TxtBase;
    TxtSize    = Instance->Session.TxtSize;
    dwProtect  = PAGE_EXECUTE_READ;
} else {
    TxtBase = Instance->Session.ModuleBase;
    TxtSize = Instance->Session.ModuleSize;
}
```
[source: `Obf.c:56-67`]. When a `.text` section size is known the agent encrypts **only `.text`** and afterwards restores `PAGE_EXECUTE_READ`; otherwise it encrypts the whole image and restores `PAGE_EXECUTE_READWRITE`. Encrypting only `.text` leaves the data/import/reloc sections in the clear — so a memory scan for configuration strings, the AES key, or the resolved API pointer table **succeeds during sleep** on a build with `.text` bounds known. `Session.TxtBase`/`TxtSize` are populated only on the shellcode path (`Demon.c:491-494`, from `KAYN_ARGS`), so **a shellcode-hosted Demon leaves its data section readable while asleep.**

### 5.2 `FoliageObf` — APC-driven ROP (line 22)

Foliage builds **thirteen `CONTEXT` structures**, each a fabricated thread state whose `Rip` points at a different NT API and whose `Rsp` is a **decrementing fake stack** (−0x1000×13, −0x1000×12, … −0x1000×1), so that the resulting call chain never touches the real thread stack:

```c
hThread = SysNtCreateThreadEx( ..., NtCurrentProcess(), Instance->Config.Implant.ThreadStartAddr, NULL, TRUE, 0, 0x1000*20, 0x1000*20, NULL );
```
[source: `Obf.c:81`] — the new thread starts at **`ThreadStartAddr`**, i.e. `ntdll!LdrLoadDll + 0x12` by default. The thread is created **suspended** (the `TRUE` is `CreateSuspended`) and **never resumed with a real entry point** — its context is overwritten wholesale before it runs.

The chain, in execution order:

| # | `CONTEXT` | `Rip` set to | Arguments | Line |
|---|---|---|---|---|
| 0 | `RopBegin` | `NtWaitForSingleObject` | `Rcx=hEvent, Rdx=FALSE, R8=NULL` | 129-134 |
| 1 | `RopSetMemRw` | `NtProtectVirtualMemory` | `Rcx=NtCurrentProcess, Rdx=&ImageBase, R8=&ImageSize, R9=PAGE_READWRITE`, stack slot 5 = `&TmpValue` | 137-145 |
| 2 | `RopMemEnc` | `SystemFunction032` | `Rcx=&Rc4, Rdx=&Key` | 148-153 |
| 3 | `RopGetCtx` | `NtGetContextThread` | — | 156-… |
| 4 | `RopSetCtx` | `NtSetContextThread` | — | — |
| 5 | `RopWaitObj` | `NtWaitForSingleObject` | the actual sleep | — |
| 6 | `RopMemDec` | `SystemFunction032` | decrypt | — |
| 7 | `RopSetMemRx` | `NtProtectVirtualMemory` | restore `PAGE_EXECUTE_READ` | — |
| 8 | `RopSetCtx2` | `NtSetContextThread` | — | — |
| 9 | `RopExitThd` | `RtlExitUserThread` | — | — |

**Every fabricated stack's top slot is `NtTestAlert`.** `*(PVOID*)(Rop*->Rsp + 0) = NtTestAlert;` is written for `RopBegin` (134), `RopSetMemRw` (144), `RopMemEnc` (153), and each subsequent context. `NtTestAlert` **delivers pending APCs** — which is exactly how the chain advances: the agent queues the next `CONTEXT` as an APC (`NtQueueApcThread`), the fabricated frame calls `NtTestAlert` on return, and the next stage runs. This is the classic Fury/Foliage pattern, and the use of `NtTestAlert` as the stack-return target is a **distinctive, greppable sequence in memory** (a fabricated stack containing a pointer to `ntdll!NtTestAlert` immediately followed by `SystemFunction032` and `NtProtectVirtualMemory`).

**`RopBegin` calls `NtWaitForSingleObject( hEvent, FALSE, NULL )` where `hEvent` is a `SynchronizationEvent` created at line 79.** The sleep therefore blocks inside NT — it does not spin in user mode. The wait is released by another thread/fibre setting the event, or by timeout. `NtCreateEvent(…, SynchronizationEvent, FALSE)` = **auto-reset** event, so each set wakes exactly one waiter.

**A duplicated thread handle is taken before any context manipulation:**
```c
SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupObj, THREAD_ALL_ACCESS, 0, 0 );
```
[source: `Obf.c:113`]. `hDupObj` is a handle to the *agent's own executing thread* taken before the stack is destroyed — used to restore the original context afterwards. After the chain's final `NtSetContextThread` the thread resumes on its real stack; the last ROP context's `RtlExitUserThread` terminates only the fabricated carrier thread, not the agent.

**Allocation:** every one of the 13 `CONTEXT` blocks is `LocalAlloc( LPTR, sizeof(CONTEXT) )` (lines 83-96) — **heap, not stack**. `sizeof(CONTEXT)` on x64 is ~1232 bytes; 13 of them = ~16 KB of live heap for the duration of the sleep. Those blocks plus their fabricated stacks are a large, patterned, page-aligned allocation cluster — a memory forensics indicator in its own right.

**What Foliage does not do:** it does not unlink the module from the loader list, does not wipe the PE header, and does not clear the MZ/PE magic. Only the image bytes are RC4'd. A memory scan that accepts an RC4-obfuscated `.text` region as opaque finds nothing; a scan that looks for the **fabricated CONTEXT/ROP structures themselves, the `NtTestAlert` stack slots, or the `PAGE_READWRITE` protection state of the image** sees everything.

### 5.3 `TimerObf` — EKKO and ZILEAN (line ~330)

Both variants use the **timer API** rather than a spawned thread, and differ only in *which* callback captures the context:

```c
if ( Method == SLEEPOBF_EKKO ) {
    NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( RtlCaptureContext ), TimerCtx, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
} else if ( Method == SLEEPOBF_ZILEAN ) {
    NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( RtlCaptureContext ), &TimerCtx, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
}
```
[source: `Obf.c:413-420`]

- **EKKO** creates a timer queue (`RtlCreateTimerQueue`) and schedules callbacks **in the timer thread** (`WT_EXECUTEINTIMERTHREAD`). Multiple `RtlCreateTimer` calls with incrementing `Delay += 100` are used to chain stages — each callback runs on the same timer thread and steals its context.
- **ZILEAN** creates a **wait** instead (`RtlRegisterWait` + `WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD`), so the context is captured from a thread-pool wait thread rather than a timer thread. Flag values are from `Defines.h:34-37`: `PROXYLOAD_NONE/RTLREGISTERWAIT/RTLCREATETIMER/RTLQUEUEWORKITEM = 0/1/2/3`.

The `RtlCaptureContext` callback writes the timer thread's live `CONTEXT` into `TimerCtx`; the agent then:

```c
if ( NT_SUCCESS( NtStatus = SysNtWaitForSingleObject( EvntTimer, FALSE, NULL ) ) ) {
```
[source: `Obf.c:434`] — **synchronisation is an event, not a sleep-and-hope.** The agent blocks until the timer thread has actually captured its context, which is why the sequence is reliable rather than racy. `Delay += 100` (100 ms) between stages gives the captured context time to settle.

**Stack spoofing inside the timer path** (only when `Instance->Config.Implant.StackSpoof`, `Obf.c:440`):
```c
if ( ! ThreadQueryTib( C_PTR( TimerCtx.Rsp ), &NtTib ) ) { PUTS( "Failed to retrieve Tib" ); goto LEAVE; }
SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &ThdSrc, 0, 0, DUPLICATE_SAME_ACCESS );
MemCopy( &BkpTib, &Instance->Teb->NtTib, sizeof( NT_TIB ) );
```
[source: `Obf.c:443-455`]. `ThreadQueryTib` reads the `NT_TIB` out of the *timer thread's* stack (the TIB is the first field at the top of the stack) so the agent can substitute it. `BkpTib` is a backup of the agent's own TIB that is restored afterwards. **Substituting the TIB makes the fabricated stack's `StackBase`/`StackLimit`/`Self` pointer point at the timer thread's stack rather than the agent's** — so a stack walk from within the spoofed frame terminates in a legitimate-looking thread region.

**The `JmpGadget` bypass:**
```c
if ( JmpBypass ) {
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) { JmpPad[ 1 ] = 0x23; }
    if ( ! ( JmpGadget = MmGadgetFind(
        C_PTR( U_PTR( Instance->Modules.Ntdll ) + LDR_GADGET_HEADER_SIZE ),
        LDR_GADGET_MODULE_SIZE, JmpPad, sizeof( JmpPad ) ) ) ) {
        JmpBypass = SLEEPOBF_BYPASS_NONE;
    }
}
```
[source: `Obf.c:459-475`]. The agent **scans ntdll's mapped image for a 2-byte `jmp rax` (0xFF 0xE0) or `jmp rbx` (0xFF 0xE3) gadget**, starting past the first 4 KB (`LDR_GADGET_HEADER_SIZE = 0x1000`) and searching 16 MB (`LDR_GADGET_MODULE_SIZE = 0x1000*0x1000`). `JmpPad` is the 2-byte pattern with `[1]` patched to the register's ModRM byte. If no gadget is found the bypass is downgraded to `SLEEPOBF_BYPASS_NONE` **silently** — the agent proceeds un-spoofed with no notification to the operator.

**The ROP chain (13 frames):**
```c
for ( int i = 0; i < 13; i++ ) {
    MemCopy( &Rop[ i ], &TimerCtx, sizeof( CONTEXT ) );
    Rop[ i ].Rip  = U_PTR( JmpGadget );
    Rop[ i ].Rsp -= sizeof( PVOID );
}
```
[source: `Obf.c:478-482`]. Each frame's `Rip` points at the **`jmp` gadget**, and the real target is placed on the fabricated stack — so a call-stack walk sees a return into ntdll's code region rather than into the ROP stage. The stages, via the `OBF_JMP( Inc, Func )` macro:

```c
OBF_JMP( Inc, Instance->Win32.WaitForSingleObjectEx );  Rcx = EvntStart; Rdx = INFINITE; R8 = FALSE;  Inc++;   // 486-489
OBF_JMP( Inc, Instance->Win32.VirtualProtect );         Rcx = ImgBase; Rdx = ImgSize; R8 = PAGE_READWRITE; R9 = &Value; Inc++;  // 492-497
OBF_JMP( Inc, Instance->Win32.SystemFunction032 );      Rcx = &Img; Rdx = &Key;  Inc++;                    // 500-503
... then spoof + decrypt + restore + exit
```
[source: `Obf.c:485-503`]. Same logical sequence as Foliage — wait → make writable → RC4-encrypt → (sleep) → decrypt → restore protection — but executed as timer-thread ROP stages rather than APCs.

**`Rop[0]` waits on `EvntStart` with `INFINITE`** (487), which is the actual sleep: the agent's own thread blocks there for the configured interval, then sets `EvntStart`.

### 5.4 `SleepObf` — the entry point (line ~720)

```c
switch ( Technique ) {
    case SLEEPOBF_FOLIAGE: {
        if ( ( Param.Master = Instance->Win32.ConvertThreadToFiberEx( &Param, 0 ) ) ) {
            if ( ( Param.Slave = Instance->Win32.CreateFiberEx( 0x1000 * 6, 0, 0, C_PTR( FoliageObf ), &Param ) ) ) {
                Param.TimeOut = TimeOut;
                Instance->Win32.SwitchToFiber( Param.Slave );
                Instance->Win32.DeleteFiber( Param.Slave );
            }
            Instance->Win32.ConvertFiberToThread( );
        }
        break;
    }
    case SLEEPOBF_EKKO:
    case SLEEPOBF_ZILEAN: {
        if ( ! TimerObf( TimeOut, Technique ) ) { goto DEFAULT; }
        break;
    }
    DEFAULT: case SLEEPOBF_NO_OBF: {}; default: {
        SpoofFunc( Instance->Modules.Kernel32, IMAGE_SIZE( Instance->Modules.Kernel32 ),
                   Instance->Win32.WaitForSingleObjectEx, NtCurrentProcess(), C_PTR( TimeOut ), FALSE );
    }
}
```
[source: `Obf.c:734-768`]

- **Foliage runs on a fibre**, not a thread: `ConvertThreadToFiberEx` → `CreateFiberEx(6 MB commit, 0, 0, FoliageObf, &Param)` → `SwitchToFiber` → `DeleteFiber` → `ConvertFiberToThread`. The `0x1000 * 6` (24 KB) reserve is the fibre stack. **The fibre is deleted immediately after the sleep returns**, so there is no persistent carrier thread holding a `SystemFunction032` ROP chain across sleeps — a fresh fibre per sleep cycle. The dispatcher thread's own stack is *converted* to a fibre and back, which changes its `ThreadInformationBlock`-visible state transiently; a kernel callback or APC arriving mid-conversion observes a fibre-backed thread.
- **The default case is not a bare wait** — it is `SpoofFunc( kernel32, IMAGE_SIZE(Kernel32), WaitForSingleObjectEx, NtCurrentProcess(), TimeOut, FALSE )`. Even with sleep obfuscation *off*, the agent passes its wait through the **stack-spoofing trampoline** (§8.4). An operator who sets `SLEEPOBF_NO_OBF` for speed still gets a spoofed stack on the wait.
- If `TimerObf` fails, `goto DEFAULT` silently falls back to the un-obfuscated wait — **no notification, no status package.** The agent's reported sleep-mask technique in the UI then disagrees with what it is actually doing.

### 5.5 Consequences and indicators

**What the scheme does not protect:**
1. **The process's `.text` is RC4'd, but the DATA section, the PEB, the loader list entry, the module name, and every on-disk-backed section remain in the clear** on a non-shellcode build. A detection that identifies the module by its PE header, its export table, or its file mapping is unaffected.
2. **The key is 16 random bytes from `RandomNumber32()` — the same weak RNG as the AES key.** If that RNG is predictable (see §10.5), the RC4 key is predictable, and the "encrypted" sleep state is decryptable offline from a memory image.
3. **Protection state is the tell.** During every sleep, the image region sits at `PAGE_READWRITE`. A legitimate PE image's `.text` is `PAGE_EXECUTE_READ` for its entire life. **Polling a process's protection transitions and flagging any `PAGE_EXECUTE_READ → PAGE_READWRITE → PAGE_EXECUTE_READ` cycle on image memory is a complete, technique-independent detection of Ekko, Zilean and Foliage simultaneously.** The agent makes this transition on every single sleep cycle.
4. **`SystemFunction032` invoked on the process's own image base** is an EDR callback target (`advapi32!SystemFunction032` is not a commonly-called API outside this pattern) and, because it is CFG-whitelisted by the agent itself (§2.4 item 10), the `SetProcessValidCallTargets` call for it is itself an indicator.
5. **Timer-queue and wait-thread callbacks whose captured `CONTEXT.Rip` is not a timer-pool function** — `RtlCaptureContext` invoked as a timer callback then immediately used to fabricate 13 contexts is a strong, specific behaviour.

**What the scheme does protect against:** a naive memory scanner that greps the agent's `.text` for strings or byte patterns while the agent sleeps, and a naive stack walk taken at the moment of sleep. It defeats exactly the class of tool that does not look at protection transitions.

---

## 4. THE WIRE LAYER — `Package.c` AND `Parser.c`

### 4.5 `core/Package.c` — 485 lines, 14 functions

**Byte order: the builder emits BIG-ENDIAN for every integer.**
```c
VOID Int32ToBuffer( OUT PUCHAR Buffer, IN UINT32 Size ) {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}
VOID Int64ToBuffer( PUCHAR Buffer, UINT64 Value ) { /* Buffer[7] = LSB … Buffer[0] = MSB */ }
```
[source: `payloads/Demon/src/core/Package.c:39-47`, `13-37`]. Both hand-rolled; `Int64ToBuffer` is written as eight explicit byte extractions with a shifting `Value`, `Int32ToBuffer` as four shifts. No `htons`, no `__builtin_bswap`. **Every multi-byte field on the wire is network order.**

**The package primitives:**

| Function | Emits | Line | Notes |
|---|---|---|---|
| `PackageCreate(CommandID)` | `PACKAGE` struct | 157 | `Encrypt = TRUE`, `Destroy = TRUE`, `Included = FALSE`, 1-byte initial buffer |
| `PackageCreateWithMetaData(CommandID)` | `[0][MAGIC][AgentID][CommandID][RequestID]` | 174 | The frame header; leading `PackageAddInt32(Package, 0)` is the length placeholder |
| `PackageCreateWithRequestID(CommandID, RequestID)` | struct with explicit request ID | 187 | |
| `PackageAddInt32` | 4 B big-endian | 49 | `LocalReAlloc(…, Length+4, LMEM_MOVEABLE)` |
| `PackageAddInt64` | 8 B big-endian | 68 | |
| `PackageAddBool` | **4 B** (0 or 1) | 85 | Booleans are 32-bit on the wire, not 1 byte |
| `PackageAddPtr` | 8 B (casts pointer to `UINT64`) | 104 | Wrapper on `PackageAddInt64` |
| `PackageAddPad` | raw `Size` bytes, no length prefix | 109 | `LMEM_ZEROINIT` — used for the AES key/IV |
| `PackageAddBytes` | `[len 4 B][bytes]` | 125 | The length-prefixed form |
| `PackageAddString` | `[len][ASCII]` via `StringLengthA` | 147 | |
| `PackageAddWString` | `[len][UTF-16LE]` | 152 | |

**`PackageAddBytes` vs `PackageAddPad` is the distinction that matters for parsing.** `PackageAddBytes` writes a 4-byte big-endian length then the payload; `PackageAddPad` writes only the payload. The metadata routine (§2.3) uses `PackageAddPad` for the 32-byte key and 16-byte IV — which is precisely why the Go side can locate them at fixed offsets **0 and 32** without any parsing, and why the key is trivially extractable from the plaintext registration body.

**`Package->Buffer` and `Package->Length` are mutated by every add.** The buffer grows by `LocalReAlloc` on each call, so a package with *n* fields performs *n* reallocations — O(n²) byte copying for large field counts. `fListDirectory`-heavy responses (`FS_DIR`) build many fields per entry and reallocate for each; a deep recursive listing is quadratically expensive in heap operations. This is the real cost of the design and a visible timing artifact on large directory listings.

**`PackageAddBytes` with `Size == 0` writes the length and skips the payload** (lines 131-144) — so a zero-length string is legitimately `00 00 00 00` with no following bytes. This is the format-level collision with the metadata failure path (§2.3): `PackageAddInt32(*MetaData, 0)` and `PackageAddBytes(pkg, data, 0)` produce **byte-identical output**. The Go parser cannot distinguish "field failed" from "field legitimately empty" on any metadata field.

**`PackageTransmitNow` — the single-package path:**
```c
Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );    // patch length
if ( Package->Encrypt ) {
    Padding = 4*5;                                                       // 20 bytes header
    if ( Package->CommandID == DEMON_INITIALIZE )
        Padding += 32 + 16;                                              // skip key + IV
    AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
    AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
}
if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) { Success = TRUE; }
```
[source: `Package.c:246-265`]

**The `DEMON_INITIALIZE` special case is the whole handshake in three lines.** For that one CommandID the encryption offset is advanced by 48 bytes (`32 + 16`), leaving the AES key and IV **in the clear** at the head of the body. Every other package begins encryption at offset 20, immediately after the frame header. So:

- **Header (20 bytes, always cleartext):** `[SIZE][MAGIC][AgentID][CommandID][RequestID]`
- **`DEMON_INITIALIZE` body:** `[KEY 32 B cleartext][IV 16 B cleartext][encrypted remainder]`
- **Every other body:** encrypted from offset 20 to the end.

**The length field is the size of everything *after* the length field** — `Length - sizeof(UINT32)`. So the total frame on the wire is `4 + (Length - 4) = Length` bytes, and the declared size counts the magic value onward. A parser must read `SIZE`, then read `SIZE` bytes, and the AgentID sits at offset `4 + 4`.

**The same IV and key are used for the `DEMON_INITIALIZE` body's encrypted remainder AND for every subsequent frame** (§3.3). Since the encrypted portion of the initialization body begins at the same keystream offset as every future frame's, and since the initialization body itself is the most predictable structure in the protocol, **the first 48 bytes of cleartext plus a predictable plaintext modulo the same keystream is a complete session compromise.** Encrypt-then-send and decrypt-on-failure-restore is all `PackageTransmitNow` does; there is no integrity protection to break because there is none.

**The on-failure re-encryption:**
```c
if ( Package->Destroy ) { PackageDestroy( Package ); Package = NULL; }
else if ( Package->Encrypt ) { AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding ); }
```
[source: `Package.c:267-271`]. A non-destroyable package (the registration package, `Destroy = FALSE` from `Demon.c:109`) is **re-encrypted in place after a failed send** so it can be retried. Because AES-CTR is its own inverse, this correctly restores plaintext — and then the *next* transmit attempt re-encrypts it with the **identical keystream**, producing **byte-identical ciphertext on the wire**. **Every retry of the registration package emits the same 48-byte cleartext key/IV and the same ciphertext.** A network observer sees a repeated, recognizable byte sequence and additionally learns the retry cadence of a failed agent.

**`PackageTransmit` — the batched path (lines ~355-469):**
```c
while ( Pkg ) {
    if ( Package->Length > DEMON_MAX_REQUEST_LENGTH ) break;
    ...  // accumulate Pkg into Package
    Prev = Pkg;  Pkg = Pkg->Next;
}
Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );
Padding = 4*5;
AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) Success = TRUE;
AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );   // decrypt back
```
[source: `Package.c:369-401`]

**The batch loop concatenates multiple logical packages into one frame**, bounded by `DEMON_MAX_REQUEST_LENGTH = 0x300000` (3 MB, `Package.h:6`). Each individual package already carries its own 20-byte header, so a batched frame is `[outer header][inner package][inner package]…` — and **only the outer header's length field is patched** (`Int32ToBuffer(Package->Buffer, …)` writes at offset 0 of the *accumulator*, i.e. the first package's header). The inner packages' own length fields keep whatever value they had. The receiver therefore parses the outer frame by SIZE, then walks the concatenation using each inner package's `[CommandID][RequestID]` — **which means the inner `SIZE` and `MAGIC` fields of every package after the first are stale garbage on the wire**, since only the first package's header was patched and the accumulator appended subsequent packages' *whole* buffers including their placeholder length fields.

Concretely: `PackageCreateWithMetaData` writes `PackageAddInt32(Package, 0)` as a length placeholder for **every** package it creates. In a batch, only the first package's zero gets patched with the real total. **The second and later packages on the wire carry `SIZE = 0x00000000` in their headers while their MAGIC value and AgentID are correct.** A third-party parser that trusts the per-package SIZE field sees a zero-length package and desynchronises. The teamserver's Go parser must therefore ignore inner SIZE fields entirely — which is consistent with the agent-side parse in §3.3, where only `[CommandID][RequestID][len]` triples are read.

**`Included` flag as a transmit ledger:**
```c
if ( Success ) {
    while ( Entry ) {
        if ( Entry->Included ) {
            if ( Entry == Instance->Packages ) {
                Instance->Packages = Entry->Next;
                if ( Entry->Destroy ) { PackageDestroy( Entry ); Entry = NULL; }
                Entry = Instance->Packages;  Prev = NULL;
            } else if ( Prev ) {
                Prev->Next = Entry->Next;
                if ( Entry->Destroy ) { PackageDestroy( Entry ); Entry = NULL; }
                Entry = Prev->Next;
            } else { PUTS_DONT_SEND( "Failed to cleanup packages list" ) }
        } else { Prev = Entry; Entry = Entry->Next; }
    }
} else {
    while ( Entry ) { Entry->Included = FALSE; Entry = Entry->Next; }
}
```
[source: `Package.c:406-464`]

**This is an at-least-once, all-or-nothing delivery ledger with a failure mode.** On success every `Included` entry is unlinked and (if `Destroy`) freed. On **failure every entry is reset to `Included = FALSE`** — including entries that *were* successfully transmitted in an earlier batch. Since `Included` is set when a package is batched and only cleared on the next transmit's failure path, **a single transport failure causes every queued package to be re-sent, and re-sending a package that was already received produces duplicate output on the operator's console.** For idempotent output (a directory listing) this is cosmetic. For `FS_DOWNLOAD` chunks the retransmitted chunk is handled by the download state machine. But for a command whose *effect* is non-idempotent and which was already executed — `INJECT_SHELLCODE`, `SPAWN_DLL`, `INLINE_EXECUTE` — the **command itself was already executed once at task-dispatch time**; only its output package is duplicated. So the duplication is confined to output, which is the saving grace.

The unlink logic handles head, middle and tail, with an explicit `else { PUTS_DONT_SEND( "Failed to cleanup packages list" ) }` for the impossible `Prev == NULL && Entry != Instance->Packages` case — the author knew the invariant and guarded it. **The list is not locked.** If `SocketPush` or a fibre job appends to `Instance->Packages` between the walk and the unlink, the traversal is corrupted. In practice pushes run sequentially on the dispatcher thread after handlers return, and `PackageTransmit` runs from the dispatcher too — except when a handler calls `PackageTransmit` directly from inside a fibre job, which is exactly what `JobCheckList`/`DownloadPush` do. **There is a real re-entrancy window between the job-push path and the batched transmit.**

**`PackageDestroy` guards against a UAF by walking the list:**
```c
while ( Pkg ) {
    if ( Package == Pkg ) { PUTS_DONT_SEND( "Package can't be destroyed, is on Instance->Packages list" ); return; }
    Pkg = Pkg->Next;
}
```
[source: `Package.c:199-213`]. An O(n) membership test before every free — defensive and correct, and a direct acknowledgement that the list is touched from more than one place. The buffer is zeroed before free (217), the struct is zeroed before free (222).

**`PackageTransmitError`:**
```c
PPACKAGE Package = PackageCreate( DEMON_ERROR );
PackageAddInt32( Package, ID );
PackageAddInt32( Package, ErrorCode );
PackageTransmit( Package );
```
[source: `Package.c:471-484`]. The `DEMON_ERROR` package body is `[ID][ErrorCode]` — two big-endian 32-bit fields. This is what `PACKAGE_ERROR_WIN32` and the `CALLBACK_ERROR_*` macros (§3.20) produce.

### 4.6 `core/Parser.c` — 177 lines, WIRE-PARSE AND ITS DEFECTS

**`ParserNew` copies the input:**
```c
parser->Original = Instance->Win32.LocalAlloc( LPTR, size );
MemCopy( parser->Original, Buffer, size );
parser->Buffer   = parser->Original;
parser->Length   = size;
parser->Size     = size;
```
[source: `payloads/Demon/src/core/Parser.c:7-19`]. **`ParserNew` does not check `size`**, and does not check `Buffer`. A `size` of 0 with `LPTR` returns a valid zero-length block on most allocators, but `LocalAlloc(LPTR, 0)` is documented to return a pointer to a zero-length block that **must still be freed** — and `MemCopy(dst, Buffer, 0)` with `Buffer == NULL` is a no-op in the implementation used. The important consequence: **`ParserNew` copies the buffer, so `Demon.c:583-584`'s zeroing of the global `AgentConfig` after `ParserNew` is safe** — the parser holds its own copy. That resolves the dependency noted in §2.0.

`parser->TaskID` and `parser->Endian` are in the struct (`Parser.h:12-13`) but **`ParserNew` never initialises them.** `TaskID` is therefore whatever the caller's stack contained. `Endian` likewise. For the agent-side use — `PARSER Parser = { 0 }` at `Command.c:50` and `TaskParser = { 0 }` at `Command.c:53` — the initialisers zero both, so `Endian = FALSE` and little-endian reads are correct. **But any `PARSER` not explicitly zero-initialised will read multi-byte fields with an indeterminate byte order.** `ParserNew` should set both; it does not.

**The parser reads are little-endian by default and big-endian only when `Endian` is TRUE:**
```c
if ( ! parser->Endian ) return ( INT ) intBytes;
else                    return ( INT ) __builtin_bswap32( intBytes );
```
[source: `Parser.c:79-82`, `100-103`, `121-124`, `141-142`]. Since the agent zero-initialises its parsers, **the agent reads little-endian while `Package.c` writes big-endian.** The two are reconciled only because the transport layer re-serialises, or because `Endian` is set TRUE somewhere in the receive path — a grep for `->Endian =` is required to settle it; it is set in the transport layer (§4.7). **The 13 `ParserGetBytes`/`ParserGetInt32` call sites in `Command.c` that read task data depend on this being consistently TRUE.** If any path constructs a parser without setting `Endian`, every integer — every PID, every length, every sub-command selector — is byte-swapped.

**THE PARSE BUGS — `ParserGetBytes` performs no bounds validation:**
```c
PBYTE ParserGetBytes( PPARSER parser, PUINT32 size )
{
    UINT32 Length  = 0;
    PBYTE  outdata = NULL;

    if ( ! parser ) return NULL;
    if ( parser->Length < 4 ) return NULL;

    MemCopy( &Length, parser->Buffer, 4 );
    parser->Buffer += 4;

    if ( parser->Endian ) Length = __builtin_bswap32( Length );

    outdata = ( PBYTE ) parser->Buffer;
    if ( outdata == NULL ) return NULL;

    parser->Length -= 4;
    parser->Length -= Length;              // <-- NO CHECK THAT Length <= parser->Length
    parser->Buffer += Length;              // <-- advances PAST the end of the buffer

    if ( size != NULL ) *size = Length;
    return outdata;
}
```
[source: `Parser.c:127-156`]

**Three defects in nine lines, and they are the load-bearing ones for the whole agent:**

1. **`Length` is never validated against the remaining buffer.** `parser->Length -= Length` and `parser->Buffer += Length` execute unconditionally. A task record declaring a body length larger than the actual buffer **advances the internal pointers past the end of the allocation** and yields a pointer to memory beyond the buffer.
2. **`parser->Length` is `UINT32` (unsigned).** When `Length > parser->Length`, the subtraction **wraps to a huge value** (e.g. `8 - 4096` → `0xFFFFF008`). The caller's subsequent bounds checks `if (parser->Length < 4) return 0;` in `ParserGetInt32` then **pass** on the wrapped value, so the parser will happily keep reading far past the buffer. **The wrap defeats every downstream length check.** This is a classic unsigned-underflow-to-OOB pattern and it is present in the function every task dispatch depends on.
3. **The returned `outdata` can be NULL only if `parser->Buffer` was NULL** — the `if (outdata == NULL)` check tests the wrong thing entirely, since `outdata` was just assigned from a pointer that was checked non-NULL at entry by neither this call nor any caller. It is dead code that provides no safety.

**Consequence chain, from `Command.c:102` outward:** the dispatcher reads `TaskBuffer = ParserGetBytes(&Parser, &TaskBufferSize)` on **server-supplied data**. A hostile or compromised teamserver — or an attacker who can inject into the C2 channel, which §3.3 shows is unauthenticated — sends a task record with a large declared length. `ParserGetBytes` returns an out-of-bounds pointer and a wrapped `Length`. `ParserNew(&TaskParser, TaskBuffer, TaskBufferSize)` then **`MemCopy`s `TaskBufferSize` bytes from beyond the end of the received buffer into a fresh allocation**, which is a **heap out-of-bounds read of attacker-controlled length** — and because `TaskBufferSize` is also `UINT32` and passed straight to `LocalAlloc`, a length near `0xFFFFFFFF` is an allocation request that will fail or thrash. With `ParserDecrypt` following it (`Command.c:110`) operating on that buffer, the agent then performs AES-CTR over an out-of-bounds region.

**The header fields of a task are also read without the inner-length protection**, and the loop condition `while (Parser.Length > 12)` (§3.2) uses the same unsigned `Length` field that `ParserGetBytes` has already wrapped. **A wrapped `Length` makes the loop condition permanently true**, so the dispatcher spins parsing records out of memory it does not own until either the handlers accumulate enough packages to overflow, or it faults.

**`ParserGetInt16` and `ParserGetByte` lack even the NULL check** that the 32/64-bit variants have:
```c
INT16 ParserGetInt16( PPARSER parser ) {
    if ( parser->Length < 2 ) return 0;    // <-- dereferences parser BEFORE any NULL test
    ...
}
BYTE ParserGetByte( PPARSER parser ) {
    if ( parser->Length < 1 ) return 0;    // <-- same
    ...
}
```
[source: `Parser.c:33-46`, `48-61`]. `ParserGetInt32`, `ParserGetInt64`, `ParserGetBool`, `ParserGetBytes` all test `if (!parser)` first. The 16-bit and 8-bit readers do not. Any caller passing NULL faults.

**`ParserDecrypt` re-initialises the AES context per call:**
```c
AESCTX AesCtx = { 0 };
if ( parser == NULL ) return;
AesInit( &AesCtx, Key, IV );
AesXCryptBuffer( &AesCtx, (PUINT8)parser->Buffer, parser->Length );
```
[source: `Parser.c:21-30`]. `AesInit` re-expands the AES key schedule on **every** decrypt call — the key schedule is recomputed from the 32-byte key each time rather than cached. Correct, but wasteful; more importantly **`parser->Buffer` may be NULL** (if a prior `ParserDestroy` ran, or if `ParserNew` was called with size 0 on an allocator returning NULL), and there is no `parser->Buffer` NULL check before the AES call. A NULL `Buffer` with nonzero `Length` is an immediate fault.

**`ParserDestroy` zeroes before freeing — and the zeroing is correct:**
```c
if ( Parser->Original ) {
    MemSet( Parser->Original, 0, Parser->Size );
    Instance->Win32.LocalFree( Parser->Original );
    Parser->Original = NULL;
    Parser->Buffer   = NULL;
}
```
[source: `Parser.c:168-177`]. `Parser->Size` is the original allocation size, so the `MemSet` covers the whole block. Decrypted plaintext is wiped. The `Original`/`Buffer` pointers are nulled. Note it does **not** null `Length` or `Size` — a destroyed parser still reports its old length, so a use-after-destroy reads `Length != 0` from a freed-and-nulled struct and then faults in `MemCopy`. `ParserDestroy` is called twice back-to-back at `Command.c:130-131` on two different parsers, which is correct, but **`TaskParser` is destroyed after `DataBuffer` was freed** (§3.2) — safe only because `TaskParser->Original` is its own allocation, not a view into `DataBuffer`.

### 4.7 Summary of wire-layer findings

1. **Big-endian output, little-endian default read, reconciled only by `Endian` being set in the transport layer.** Fragile.
2. **`ParserGetBytes` has an unchecked length causing unsigned underflow, pointer advance past the buffer, and a heap OOB read on attacker-controlled input.** This is the most serious defect in the wire layer.
3. **`ParserGetInt16`/`ParserGetByte` dereference the parser before any NULL check.**
4. **`ParserNew` leaves `TaskID` and `Endian` uninitialised.**
5. **Zero-length bytes and failed metadata fields are byte-identical on the wire.**
6. **Batched packages carry stale inner `SIZE` fields** (only the first is patched), and inner `MAGIC`/`AgentID` are valid, so a strict parser desynchronises.
7. **The AES key and IV travel in cleartext in the `DEMON_INITIALIZE` body** by explicit special-case (`Padding += 32 + 16`), and the IV is never rotated.
8. **A failed transmit re-encrypts and re-sends the identical ciphertext**, including the cleartext key/IV on the registration package.
9. **The `Included` ledger re-sends the whole queue after a single transport failure**, duplicating output packages.
10. **`PackageAdd*` reallocates per field**, O(n²) for long outputs.

---

## 6. HTTP TRANSPORT AND HOST ROTATION

### 6.1 `TransportHttp.c` — the WinHTTP path

The agent's HTTP transport is built on **WinHTTP** (`winhttp.h`, `RtWinHttp` loaded in `DemonInit`, `Demon.c:283-285`), not WinINet. Selection is compile-time: the whole HTTP block is `#ifdef TRANSPORT_HTTP` (`TransportHttp.h:9`), and the SMB transport is the `#else` of the same symbol throughout `Command.c`. **One binary is one transport** — there is no runtime transport switch.

**Host record:**
```c
typedef struct _HOST_DATA {
    LPWSTR Host;  DWORD Port;  DWORD Failures;  BOOL Dead;
    struct _HOST_DATA* Next;
} HOST_DATA, *PHOST_DATA;
```
[source: `payloads/Demon/include/core/TransportHttp.h:15-25`]. A singly-linked list built at config-parse time (`Demon.c:666-680`) from the profile's host array, with `HostMaxRetries = 0`, `Hosts = NULL`, `Host = NULL` initialised first (`Demon.c:660-663`).

**Rotation strategies:**
```c
#define TRANSPORT_HTTP_ROTATION_ROUND_ROBIN  0
#define TRANSPORT_HTTP_ROTATION_RANDOM       1
#define ERROR_INTERNET_CANNOT_CONNECT        12029
```
[source: `TransportHttp.h:11-13`]

- **Round-robin** walks the list in order, advancing one host per failure.
- **Random** picks via `HostRandom()` — documented at `TransportHttp.h:56-60` as *"Gets a random host from the linked list. (doesn't check if its dead)"*. **Random rotation can select a host already marked `Dead`.**

**The failure/death model:**
`HostFailure(Host)` increments the failure counter and, on hitting the maximum, marks the host and returns the next one (`TransportHttp.h:41-48`). `HostCheckup()` returns FALSE only when **every** host is dead (`TransportHttp.h:62-68`). This is the predicate that decides between rotating and dying at `Command.c:79`:

```c
if ( ! PackageTransmitAll( &DataBuffer, &DataBufferSize ) && ! HostCheckup() )
    CommandExit( NULL );
```
Read precisely: the agent dies only when the transmit failed **and** no live host remains. With random rotation and `HostRandom()` ignoring the `Dead` flag, a host can be retried after being marked dead — which extends the agent's life across redirector outages but also means **`HostCheckup()`'s "all dead" decision can be reached while a not-yet-probed host still exists**, if the random walk never happened to select it before the others exhausted their retries.

`Failures` is reset to 0 on a successful connect at `Demon.c:80-82` — but only in the HTTP branch and only inside `if (TransportInit())`. So a host that connects successfully once has its failure count cleared, which is what keeps rotation from permanently blacklisting a recovered C2 node.

**`HttpQueryStatus(hRequest)`** (`TransportHttp.h:71`) extracts the HTTP status from the response. **`ERROR_INTERNET_CANNOT_CONNECT = 12029`** is the specific WinHTTP error treated as a transport failure rather than an HTTP-level rejection — it is the "cannot connect to the server" code, i.e. a dead listener. Distinguishing it from a 404 matters enormously here: **a 404 from a live listener means the agent is reaching *something* and should not treat the host as dead**, whereas 12029 means nothing is listening. The presence of the named constant rather than a bare `if (status != 200)` shows the author distinguished these.

**`HttpSend(Send, Resp)`** (`TransportHttp.h:73-76`) is the single request/response primitive. `Send`/`Resp` are `BUFFER`-typed (a `{PVOID Buffer; SIZE_T Length;}` pair) — the same structure used across the transport layer, which is why `PackageTransmitNow` and `PackageTransmitAll` both take `PVOID* Response, PSIZE_T Size` and hand them straight through.

**The profile-controlled request shape:** `Config.Transport.Method` (a *string*, parsed as bytes at `Demon.c:655-657` — so the HTTP verb is operator-configurable), `UserAgent` (`Demon.c:693-695`), `Headers` (`Demon.c:699-711`), `Uris` (`Demon.c:715-727`). Each response and request goes to a URI drawn from the configured list; `Config.Transport.HostIndex` tracks position. **The URI list plus the verb plus the header set is the complete malleable-C2 surface** — there is no parameter encoding, no padding, no jitter on request size, and no per-request nonce. The body is the raw ambiguous-owner `[SIZE][MAGIC][AgentID][CommandID][RequestID][AES-CTR]` frame from §3.3, base64 or raw per the profile.

**Proxy:** `Config.Transport.Proxy{Enabled, Url, Username, Password}` (`Demon.c:731-758`) — carried as plain `LPWSTR` on the heap, never zeroed (§2.5).

### 6.2 `core/Socket.c` — 621 lines

Reversed from two open-source implementations, cited in the file's own comments: `RecvAll` is credited to `github.com/rsmudge/metasploit-loader/blob/master/src/main.c#L41` (`Socket.c:5-6`) and `SocketNew` to `github.com/rapid7/metasploit-payloads/.../tcp_server.c#L277` (`Socket.c:58`). **Havoc's socket layer is Meterpreter's socket layer, ported** — which is a concrete provenance fact and means the socket bugs are inherited from upstream, not invented here.

**`RecvAll(Socket, Buffer, Length, BytesRead)` — line 7:**
```c
DWORD tret = 0, nret = 0;
PVOID Start = Buffer;
while ( tret < Length ) {
    nret = Instance->Win32.recv( Socket, Start, Length - tret, 0 );
    if ( nret == SOCKET_ERROR ) { PUTS( "recv Failed" ); *BytesRead = tret; return FALSE; }
    Start += nret;
    tret  += nret;
}
*BytesRead = tret;
return TRUE;
```
[source: `payloads/Demon/src/core/Socket.c:7-31`]

**`recv` returning 0 is not handled.** A closed peer produces `nret == 0` on a graceful shutdown; the loop then adds 0 to both counters and **spins forever inside the agent's handler thread.** Winsock returns 0 only for a graceful close, and the code treats only `SOCKET_ERROR` as failure. **A peer that closes the connection mid-receive hangs the agent** exactly as `PROC_GREP` hangs it (§3.7) — same visible symptom (no further beacons), different cause. This is inherited from the cited Meterpreter path's shape but the absence of a `nret == 0` guard is the concrete defect.

**`InitWSA` — line 33:**
```c
if ( Instance->WSAWasInitialised == FALSE ) {
    if ( ( Result = Instance->Win32.WSAStartup( MAKEWORD( 2, 2 ), &WsData ) ) != 0 ) {
        Instance->Win32.WSACleanup();
        return FALSE;
    }
    Instance->WSAWasInitialised = TRUE;
}
```
[source: `Socket.c:33-56`]. Winsock **2.2**, requested explicitly. The one-shot guard is via `Instance->WSAWasInitialised` (declared in `INSTANCE`, `Demon.h`). On failure it calls `WSACleanup` — which is harmless if `WSAStartup` failed (it decrements a refcount that was never incremented) but is a no-op at best. Note the agent does **not** restore the original `WSAStartup` DPI or check whether the socket implementation is already initialised by the host process; a host that already has Winsock up at a different version sees the agent's `MAKEWORD(2,2)` request succeed and leak its own count by one.

**`SocketNew(WinSock, Type, UseIpv4, IPv4, IPv6, LclPort, FwdAddr, FwdPort, ParentID)` — line 59:**
- `Type == SOCKET_TYPE_NONE` or `SOCKET_TYPE_CLIENT` **skips socket creation entirely** and only inserts an object into the linked list (`Socket.c:67-69`) — used for the SOCKS/pivot relay objects that are backed by an existing handle.
- IPv4: `WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, NULL)`; IPv6: `WSASocketA(AF_INET6, …, 0, 0)` — **the IPv6 call passes the flag argument positionally different from the IPv4 call** (`NULL` vs `0` for `lpProtocolInfo`), harmless since both are zero, but the two call shapes are not identical.
- `SockAddr.sin_port = HTONS16(LclPort)` — the port is byte-swapped with the agent's own `HTONS16` macro, and `sin_addr.s_addr = IPv4` is stored **without** swapping, so the operator supplies the address in network order directly. The `PRINTF` at `Socket.c:90-96` prints the four bytes in reverse order (`(IPv4 & 0xff000000) >> 24` first) — confirming the operator's 32-bit value is little-endian-host-order with the octets reversed.
- IPv6 is copied with `MemCopy(&SockAddr6.sin6_addr, IPv6, 16)` — a fixed 16-byte copy from the parsed argument. **The parser must guarantee 16 bytes are present**; `ParserGetBytes` does not (§4.6), so a short IPv6 field over-reads the task buffer by up to 16 bytes. Same defect class as the `PROC_MODULES` overflow.
- `u_long IoBlock = 1;` is declared for the `ioctlsocket(FIONBIO)` non-blocking setup (typical of this ported code) — the agent sets client sockets non-blocking, which is why `RecvAll`'s blocking loop shape is needed on the accepted side.

**Forwarding:** `FwdAddr`/`FwdPort`/`ParentID` in the signature are the SOCKS/pivot relay fields — a socket can be created whose traffic is forwarded to another address, with `ParentID` linking it back to the pivot or socket that owns it. This is the same structure that hosts `DEMON_COMMAND_SOCKET`'s SOCKS proxy (§3.15) and is what makes the agent a usable network pivot rather than only a command runner.

### 6.3 Transport findings

1. **The HTTP verb, URI set, headers and UA are wholly profile-controlled** — the entire C2 signature of the protocol is configuration, so there is no fixed URI to signature on. Detection must key on the frame structure (`0xDEADBEEF` at offset 4 of the body, which is inside the encrypted region for non-initialize packages but **plaintext in the registration body's header** — see below) or on behaviour.
2. **The `DEMON_INITIALIZE` frame's magic value and AgentID are in the clear at offsets 4 and 8 of the body**, immediately before the 32-byte key and 16-byte IV. **A network signature on the byte sequence `DE AD BE EF` followed 4 bytes later by a 48-byte high-entropy blob followed by ASCII metadata is a complete, protocol-accurate detection of a Havoc agent's first beacon**, independent of URI, verb, header set and host. That is the most durable detection artifact in the entire target.
3. **`ERROR_INTERNET_CANNOT_CONNECT` (12029) is handled distinctly from an HTTP error**, so a proxy or sinkhole returning a 404 will *not* retire the host — the agent keeps beaconing to it. A blocking proxy that returns a consistent non-200 is therefore not a kill; the agent only rotates on a connection-level failure.
4. **`HostRandom()` ignores the `Dead` flag** by design.
5. **`RecvAll` does not handle a zero-length `recv`**, so a graceful peer close hangs the agent.
6. **A short IPv6 field over-reads the task buffer** via the unchecked `MemCopy(…, 16)`.
7. **Winsock 2.2 is requested and the refcount is never released** on the failure path.

---

## 7. `core/Win32.c` — API RESOLUTION, MODULE LOADING, HASH TABLE

1,734 lines. **The file that answers "how are APIs resolved": a DJB2 string hash seeded with 5381, resolved by walking the PEB loader list and parsing export tables by hand. There are no plaintext API name strings in the binary.** The hash constants are precomputed at build time into `Defines.h` as ~247 `#define H_FUNC_<NAME> <hex>` values.

### 7.1 The hash — `HashEx` (line 17)

```c
#define HASH_KEY 5381
```
[source: `payloads/Demon/include/core/Win32.h:18`]

```c
ULONG HashEx( IN PVOID String, IN ULONG Length, IN BOOL Upper ) {
    ULONG  Hash = HASH_KEY;
    PUCHAR Ptr  = String;
    if ( ! String ) return 0;
    do {
        UCHAR character = *Ptr;
        if ( ! Length ) {
            if ( ! * Ptr ) break;
        } else {
            if ( ( ULONG ) ( C_PTR( Ptr ) - String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }
        if ( Upper ) { if ( character >= 'a' ) character -= 0x20; }
        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );
    return Hash;
}
```
[source: `payloads/Demon/src/core/Win32.c:17-58`]

**`Hash = ((Hash << 5) + Hash) + c` is exactly `Hash * 33 + c` — DJB2 with the canonical 5381 seed.** Two deviations from the textbook form:

1. **Case folding is inside the hash and gated on a one-sided comparison.** `if (character >= 'a') character -= 0x20` tests only the lower bound, not `'z'`. Bytes 0x61–0x7A fold correctly; bytes 0x7B–0xFF fold into unrelated values. Every character that appears in a real export name (`A-Z`, `a-z`, `_`, digits) is either below 0x61 or inside the folded range, so the defect is latent rather than live.
2. **The `Length != 0` branch has `if (!*Ptr) ++Ptr;` before the bottom-of-loop `++Ptr`**, so an embedded NUL advances the pointer **twice** while the hash absorbs the zero byte and then the byte after it. This is the origin of the collision problem below: `Ldr->BaseDllName.Length` is a **byte count over a wide string**, and wide ASCII names contain a NUL between every real character.

**The author documented the collision as an observed, live problem.** At `Win32.c:310-311`:

```c
/* NOTE: we are getting the module by string because there are some hash collisions
 *       when using LdrModulePeb */
```
[source: `Win32.c:310-311`]

`LdrModulePebByString` (line 99) exists specifically as the collision-free substitute, and it compares with `StringCompareW` after uppercasing. A hash-based module table that collides in practice is why the string path is the default for the load-confirmation poll.

### 7.2 Module resolution — three functions

**`LdrModulePeb(Hash)` — line 65.**
```c
for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
    Ldr = C_PTR( Ent );
    if ( ( HashEx( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length, TRUE ) == Hash ) || Hash == 0 ) {
        return Ldr->DllBase;
    }
}
```
[source: `Win32.c:82-89`]. **`Hash == 0` is an unconditional wildcard returning the first module's base.** `HashEx` returns 0 only when `String` is NULL (lines 25-27), so no real hash can be 0 — this is a deliberate "first entry" primitive used by the bootstrapper to locate the main image. `Instance->Teb` is lazily filled from `NtCurrentTeb()` (74-76) and cached for the process lifetime; `Instance->Teb->ProcessEnvironmentBlock->Ldr` is read directly rather than via `NtCurrentPeb()`, and there is **no NULL check on `Peb` or `Peb->Ldr`** — on a process where the loader list is unavailable this dereferences NULL.

**`LdrModulePebByString(Module)` — line 99.** The collision-free path.
- `Name = MmHeapAlloc(MAX_PATH)` (line 114) — 520 bytes, never sized to the actual name.
- `if (Ldr->BaseDllName.Length <= 260)` gates the copy (123); longer names are **skipped silently**, not truncated.
- The uppercasing loop (128-138) loops on `Idx < Ldr->BaseDllName.Length` where **`Idx` is a `WCHAR` array index and the bound is a byte count.** For a 20-character name `Length` is 42 (including the NUL), so `Idx` walks to 42 through a 21-element string — **21 elements of out-of-bounds read/write past the copied name.** The destination is the `MmHeapAlloc(MAX_PATH)` slack, so it stays inside the allocation and does not fault; it is a boundary defect by unit mismatch, not a crash.
- `StringCompareW(Name, Module) == 0 || Module == NULL` (142) — a second NULL wildcard.

**`LdrModuleSearch(ModuleName)` — line 165.** The `".dll"` literal is decomposed one character at a time and written out of order:
```c
WCHAR Name[ 260 ] = { 0 };
WCHAR Dll[ 5 ]    = { 0 };
Dll[ 3 ] = HideChar( 'L' );
Dll[ 1 ] = HideChar( 'D' );
Dll[ 4 ] = HideChar( '\0' );
Dll[ 2 ] = HideChar( 'L' );
Dll[ 0 ] = HideChar( '.' );
```
[source: `Win32.c:170-177`]. The indices are written 3,1,4,2,0 so the compiler cannot emit a contiguous `L".dll"` wide literal in `.data`; `HideChar()` (`MiniStd.h:26`) reconstructs the byte at runtime so the plaintext never exists as a constant. `MemZero(Dll, sizeof(Dll))` wipes it after use (189). This is the codebase-wide string-hiding idiom: **hash names at compile time, or rebuild them one byte at a time.**
- The walk uses `InLoadOrderLinks.Flink` and stops on return to `FirstEntry` (191-198), a correct circular-traversal guard.

### 7.3 Module loading — `LdrModuleLoad` (line 215) and proxy loading

Four paths, selected by `Instance->Config.Implant.ProxyLoading`:

| Value | Symbol | Mechanism | Executing thread |
|---|---|---|---|
| `0` | `PROXYLOAD_NONE` | `LdrLoadDll` directly | agent thread |
| `1` | `PROXYLOAD_RTLREGISTERWAIT` | `RtlRegisterWait(…, LoadLibraryW, …)` | wait thread |
| `2` | `PROXYLOAD_RTLCREATETIMER` | `RtlCreateTimerQueue` + `RtlCreateTimer(…, LoadLibraryW, …)` | timer thread |
| `3` | `PROXYLOAD_RTLQUEUEWORKITEM` | `RtlQueueWorkItem(LoadLibraryW, …)` | pool worker |
[source: `Win32.c:246-298`, `Defines.h:34-37`]

**The design registers `LoadLibraryW` itself as a system callback.** `LoadLibraryW` is passed as the callback routine to `RtlRegisterWait` (260), `RtlCreateTimer` (278) or `RtlQueueWorkItem` (289), with `NameW` as the context. The load therefore executes on a **system-owned thread**, so the stack that reaches `LdrLoadDll` contains no agent frame and the image-load notification's initiator is a legitimate system thread. **This is load-callback stack attribution evasion**, and it is the entire reason three modes exist rather than one.

**The confirmation poll — bounded, and leaky:**
```c
do {
    if ( ! Count ) break;                          // Count = 5
    if ( ( Module = LdrModulePebByString( NameW ) ) ) break;
    SharedSleep( 100 );
    Count--;
} while ( TRUE );
if ( ! Module ) {
    PUTS( "Module was not loaded, try with default technique" )
    goto DEFAULT;
}
```
[source: `Win32.c:301-327`]. The asynchronous load is **polled with a sleep**, up to 5 iterations at 100 ms each — **~500 ms of added latency per non-resident module**. `DemonInit` loads every module in the `RtModules[]` table (§2.4); each one not already resident costs this poll, making multi-second startup and per-command stalls a **timing signature**. The fallback `goto DEFAULT` (line 331) is a jump into the `else` branch's label, so `ProxyLoading == NONE` and the proxy-failure path share one `LdrLoadDll` implementation.

**The event and timer handles are never released.** `SysNtCreateEvent(&Event, …)` (255) creates a synchronisation event that the poll never waits on — `SharedSleep(100)` is used instead — and the `Timer` handle written by `RtlRegisterWait` (260) is never closed. **Every proxy-loaded module leaks one event handle and one timer/wait handle.** A handle-count time series on a suspect process shows monotonic growth on first command use.

**The direct path:**
```c
UnicodeString.Buffer        = NameW;
UnicodeString.Length        = DestSize;                       // StringLengthW(NameW) * sizeof(WCHAR)
UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
if ( ! NT_SUCCESS( NtStatus = Instance->Win32.LdrLoadDll( NULL, 0, &UnicodeString, &Module ) ) ) {
    PRINTF( "LdrLoadDll Failed: %p\n", NtStatus )
    NtSetLastError( NtStatus );
}
```
[source: `Win32.c:337-345`]. `SearchPath` is NULL, so **the standard search order applies** and a DLL in the application directory can be loaded ahead of the system copy. `MaximumLength` correctly carries the extra `sizeof(WCHAR)`. The NTSTATUS is mapped into the Win32 error slot via `NtSetLastError` so `NtGetLastError()` callers see a plausible code. **On failure `Module` keeps its initial `{ 0 }`** — any caller that skips the return check proceeds with NULL.

### 7.4 Function resolution — `LdrFunctionAddr` and the export parser

`LdrFunctionAddr(Module, Hash)` (declared `Win32.h:130-133`) walks the export directory manually: `IMAGE_DOS_HEADER` → `e_lfanew` → `IMAGE_NT_HEADERS` → `OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` → `IMAGE_EXPORT_DIRECTORY` → the three parallel arrays `AddressOfFunctions`, `AddressOfNames`, `AddressOfNameOrdinals`. Each name is hashed with `HashEx(name, 0, TRUE)` — **NUL-terminated ASCII, length 0**, the branch that matches the compile-time computation — and compared against the requested `H_FUNC_*` constant; the hit indexes `AddressOfFunctions[AddressOfNameOrdinals[i]]`.

**The forwarder case is load-bearing.** When a candidate RVA falls inside the export directory's own address range, the "address" is an ASCII string `OTHERDLL.SomeFunction` and must be re-parsed and resolved against the other module. On modern Windows **most `kernel32` exports are forwarders to `KernelBase.dll`** — `LoadLibraryW`, `WaitForSingleObjectEx` and `VirtualProtect` among them. Since `DemonInit` resolves 62 `kernel32` APIs (§2.4), the forwarder path carries the majority of the agent's own API surface. A resolver that does not handle it yields dozens of pointers into the export directory's own data (i.e. pointers to strings, not code), and calls through them fault on the first invocation.

### 7.5 The failure mode — the highest-consequence defect in this file

**The `H_FUNC_*` constants are precomputed offline and pasted into `Defines.h`. Nothing at runtime verifies that a resolved hash is the function the constant is named for.**

The duplicate definitions are harmless in themselves — identical names with identical values:
```
Defines.h:59   #define H_FUNC_NTOPENTHREADTOKEN              0x803347d2
Defines.h:60   #define H_FUNC_NTOPENTHREADTOKEN              0x803347d2   (duplicate)
Defines.h:48   #define H_FUNC_NTFREEVIRTUALMEMORY            0x2802c609
Defines.h:83   #define H_FUNC_NTFREEVIRTUALMEMORY            0x2802c609   (duplicate)
Defines.h:50   #define H_FUNC_NTSETINFORMATIONVIRTUALMEMORY  0x946ac239
Defines.h:80   #define H_FUNC_NTSETINFORMATIONVIRTUALMEMORY  0x946ac239   (duplicate)
Defines.h:94   #define H_FUNC_RTLRANDOMEX                    0x7f1224f5
```
[source: `payloads/Demon/include/common/Defines.h:48,50,59,60,80,83,94`]

**The actual defect is that a wrong or colliding hash produces a wrong function pointer with no detection.** Given the documented collision behaviour in §7.1, a constant computed against the wrong byte-walk model (NUL-terminated ASCII vs length-delimited wide) can match a different export. The result is stored in the `Instance->Win32` struct and called through the `WIN_FUNC(x)` `__typeof__` declaration (`Win32.h:19`), so the call is made with the **declared** signature at a different function. On x64 a calling-convention-compatible mismatch produces silent semantic misbehaviour, not a fault — data corruption, wrong arguments, or a wrong-action primitive, all invisible to the agent's own error handling.

**The 62 `kernel32` fills at `Demon.c:396-459` have no NULL-check `else` clause** (§2.4). A resolution that returns nothing leaves the struct field NULL, and the first call through it is **an indirect call to address 0** — an access violation with no diagnostic, no `PRINTF`, and no error package. The 38 `ntdll` fills at lines 301-362 *are* checked, which is the reason those two blocks differ in reliability.

**`SysInitialize` failure does not abort either.** `DemonInit` logs and continues with an explicit "keep going" comment (`Demon.c:466-473`). `SYS_CONFIG` entries the failed extraction skipped retain `Ssn = 0`, and `SysInvoke` (`Syscall.x64.asm`) loads `eax = [r11+8]` and jumps to `[r11]`. **SSN 0 is a real and different syscall on every Windows build** — so an unpopulated entry does not fail safe; it performs an unrelated kernel operation, or jumps to whatever `SysAddress` held. `Syscalls.c:90 SysExtract` does guard `if (!Ssn && !SysAddr)` (line 108), so the *extraction* declines to record a zero result, which means a failed entry stays zero from its initialiser rather than being written.

### 7.6 What this layer tells a defender

1. **No plaintext API names exist anywhere in the binary.** `H_FUNC_*` + `HashEx` + PEB/export walking means string detection for `VirtualAllocEx`, `CreateRemoteThread`, `NtProtectVirtualMemory`, `LoadLibraryW` finds nothing.
2. **The 247 hash constants are a build fingerprint.** A memory scan for a contiguous run of those specific 32-bit values in `.data` identifies the agent's API table **even while the image is sleep-obfuscated**, because §5.1 established that only `.text` is RC4'd on a shellcode build with known bounds, and on non-shellcode builds the whole image is encrypted but the protection transition (and therefore the timing) is itself the signal.
3. **Inverting the hash is trivial for an analyst.** Enumerate a target module's exports, run `5381`/`×33` over each name, and the agent's requested set is recoverable from a memory image or by watching the export walk.
4. **The four proxy-loading modes are the strongest signature in the file.** `LoadLibraryW` invoked as a `RtlCreateTimer` / `RtlRegisterWait` / `RtlQueueWorkItem` callback is not a benign pattern, and it attributes the load to a system thread that the loader notification would otherwise not implicate.
5. **`HideChar`-decomposed literals** defeat naive `".dll"` scanning but not a runtime reconstruction watchpoint on `HideChar`'s call sites.
6. **~500 ms polling per non-resident module** plus **monotonic handle growth** on first command use are timing and handle-count signatures visible from user mode.

---

## 7A. THE `Parser.c:127` UINT32 WRAPAROUND — THE HIGHEST-VALUE DEFECT

This gets its own subsection because it is the only defect in the target that is **remotely triggerable through the unauthenticated C2 channel and yields an out-of-bounds read of attacker-chosen length inside the agent.** Everything else in §3 and §4 is either local, requires a hostile target process, or produces a hang rather than memory access.

### 7A.1 The code, exactly as written

```c
PBYTE ParserGetBytes( PPARSER parser, PUINT32 size )
{
    UINT32 Length  = 0;
    PBYTE  outdata = NULL;

    if ( ! parser )
        return NULL;

    if ( parser->Length < 4 )
        return NULL;

    MemCopy( &Length, parser->Buffer, 4 );
    parser->Buffer += 4;

    if ( parser->Endian )
        Length = __builtin_bswap32( Length );

    outdata = ( PBYTE ) parser->Buffer;
    if ( outdata == NULL )
        return NULL;

    parser->Length -= 4;
    parser->Length -= Length;
    parser->Buffer += Length;

    if ( size != NULL )
        *size = Length;

    return outdata;
}
```
[source: `payloads/Demon/src/core/Parser.c:127-156`]

`Length` is the four-byte value read off the wire. The only validation on it is `if (parser->Length < 4) return NULL;` — which checks that **four bytes are available to read the length itself**, and says nothing about whether the bytes the length *describes* exist. `Length` is then subtracted from `parser->Length` and added to `parser->Buffer` unconditionally.

### 7A.2 Where the length comes from

The attacker controls it directly. The dispatcher at `Command.c:102` calls this function on **server-supplied data**:

```c
CommandID  = ParserGetInt32( &Parser );
RequestID  = ParserGetInt32( &Parser );
TaskBuffer = ParserGetBytes( &Parser, &TaskBufferSize );
```
[source: `payloads/Demon/src/core/Command.c:101-103`]

The outer `Parser` was built by `ParserNew(&Parser, DataBuffer, DataBufferSize)` (`Command.c:98`) over the buffer returned by `PackageTransmitAll` / `SMBGetJob`. **That buffer is the raw decrypted task stream from the C2 server.** Its third field per record is the length that `ParserGetBytes` reads into `Length`.

`DataBufferSize` originates at the HTTP layer (`TransportHttp.c` `HttpSend`) or the SMB pipe read (`SMBGetJob`) — it is the size of whatever arrived. Nothing upstream validates the record framing. So:

- **Attacker controls:** the four bytes of `Length`, and the total buffer size.
- **Attacker chooses:** any value from `0` to `0xFFFFFFFF` for `Length`, independent of the actual buffer size.

### 7A.3 Why it wraps

`PARSER::Length` is declared `UINT32`:
```c
typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;
    UINT32  TaskID;
    BOOL    Endian;
} PARSER, *PPARSER;
```
[source: `payloads/Demon/include/core/Parser.h:6-14`]

The subtraction at `Parser.c:149` is therefore **unsigned 32-bit arithmetic with no saturation and no check.** Worked example, buffer after the two `ParserGetInt32` calls leaves `parser->Length == 8`:

```
parser->Length        = 8
parser->Length -= 4   ->  4
Length (from wire)    = 4096
parser->Length -= 4096
       4 - 4096  =  -4092
   as UINT32:  -4092 mod 2^32  =  0xFFFFF004          <-- WRAPPED
```
`0xFFFFF004` is a value **larger than any real buffer**, and the very next statement advances the read pointer past the allocation:

```c
parser->Buffer += Length;      // Buffer now points 4096 bytes beyond the received data
```

The function returns `outdata` — a pointer captured **before** the advance (`parser.c:144`) — so the returned pointer is valid-but-short, while `*size` is set to the attacker's `4096`. The corruption is in the parser's internal cursor and length, not the returned pointer.

### 7A.4 Which downstream checks the wrap defeats, and how

The wrap is dangerous specifically because **every subsequent `ParserGet*` validity check compares against the corrupted `parser->Length`**, and the corrupted value is huge. The guards are real checks against a poisoned variable:

```c
INT ParserGetInt32( PPARSER parser ) {
    if ( ! parser ) return 0;
    if ( parser->Length < 4 ) return 0;      // <-- 0xFFFFF004 < 4 is FALSE. Check PASSES.
    MemCopy( &intBytes, parser->Buffer, 4 ); // <-- reads past the buffer
    ...
}
```
[source: `payloads/Demon/src/core/Parser.c:64-83`]

The same shape appears in `ParserGetInt64` (`if (parser->Length < 8)`), `ParserGetBool` (`if (parser->Length < 4)`), and re-entrantly in `ParserGetBytes` itself (`if (parser->Length < 4)`). **All four length checks were written correctly and all four are defeated by the wrap**, because they test the upper bound against a variable the attacker has already pushed to the maximum. There is no `parser->Buffer` upper-bound check against `parser->Original + parser->Size` anywhere in the file — `Size` is stored but never used for bounds enforcement.

**The dispatch loop guard is defeated by the same wrap:**
```c
} while ( Parser.Length > 12 );
```
[source: `payloads/Demon/src/core/Command.c:124`]

With `Length` wrapped to `0xFFFFF004`, this is permanently TRUE. **The dispatcher does not exit the task loop** — it keeps reading `[CommandID][RequestID][len]` triples out of memory it does not own, dispatching a handler for each, until the process faults or enough packages accumulate to exhaust the heap. An attacker who sends one malformed record converts a single beacon reply into unbounded parsing and unbounded handler invocations.

### 7A.5 The full attacker-reachable chain

1. **Attacker controls the task stream.** The C2 channel has no MAC, no HMAC, no signature and no nonce (§3.3); the `[CommandID][RequestID][len]` header is cleartext on the wire and unauthenticated. Anyone able to write to the channel — a compromised teamserver, a MITM on the redirector, an operator with the profile, or an injection into the transport — is the attacker. Held-out plaintext is not even needed; the framing fields are not encrypted.
2. **Attacker sends a record whose declared body length exceeds the actual buffer.** One `Length` field, four bytes.
3. **`ParserGetBytes` wraps `parser->Length` to ~`0xFFFFFFFF` and advances `parser->Buffer` past the allocation.** No check fires.
4. **`TaskBuffer =` the out-of-bounds pointer, `TaskBufferSize =` the attacker's large length.**
5. **`Command.c:108-110` then does:**
   ```c
   if ( TaskBufferSize != 0 ) {
       ParserNew( &TaskParser, TaskBuffer, TaskBufferSize );
       ParserDecrypt( &TaskParser, Instance->Config.AES.Key, Instance->Config.AES.IV );
   }
   ```
   `ParserNew` performs `LocalAlloc(LPTR, size)` followed by `MemCopy(parser->Original, Buffer, size)` — **a heap out-of-bounds read of attacker-chosen length**, copying adjacent heap (including the agent's AES key, its API pointer table, and the `INSTANCE` struct) into a buffer the agent will then treat as its task. `ParserDecrypt` then runs AES-CTR over that region **in place**, so the copied heap bytes are decrypted and become directly readable through whatever the handler emits. A length near `0xFFFFFFFF` makes the `LocalAlloc` itself a multi-gigabyte request.
6. **The loop condition is permanently true**, so steps 3-5 repeat on each subsequent iteration with the cursor progressively further past the buffer — unbounded parsing, unbounded allocations, unbounded handler dispatch, and unbounded packages queued for transmit.
7. **Any handler that emits what it parsed exfiltrates the out-of-bounds bytes to the attacker.** `ParserGetString`/`ParserGetWString` are thin wrappers on `ParserGetBytes` (`Parser.c:158-166`), so the ordinary `FS_CAT`, `PROC_*` and `CONFIG_SHOW_ALL` paths become read primitives for process memory adjacent to the task buffer.

**The attacker's control is the declared length; the consequence is an arbitrary-length heap disclosure with the read offset fixed by the allocation layout.**

### 7A.6 Why this is not caught anywhere

- `ParserNew` does not validate `size` (§4.6).
- `ParserDecrypt` does not validate `parser->Buffer` against anything (§4.6).
- `ParserDestroy` zeroes using `Parser->Size` and frees `Parser->Original`, which is the copy — so the **copy is cleaned up but the disclosure already happened** when the handler emitted it.
- There is no integrity check on the task stream to reject the malformed record before parsing (§3.3).
- The `if (TaskBufferSize != 0)` guard is the only gate and it is satisfied by any nonzero attacker value. Note it also means the wrap **cannot** be avoided by the `TaskBufferSize` check, and the `TaskBufferSize` cross-task leak (§3.2 — the variable is never reset between loop iterations) means a **subsequent** record can be decrypted using a **previous** record's length, giving a second, independent path to the same over-read from a *shorter* malicious field.

### 7A.7 The fix, stated precisely

The correct form checks the declared length against the bytes actually remaining, before mutating anything:

```c
if ( Length > parser->Length - 4 )   /* or : parser->Length - 4 < Length */
    return NULL;
```

This must be an **unsigned-safe** comparison performed on the remaining count *after* the four length bytes are consumed, and it must reject before `parser->Buffer += Length`. The existing `Length`/`Size` fields are `UINT32` and `Size` is already recorded at `ParserNew` time — the bound is available in the struct and simply unused. `ParserGetBytes` should also clamp the returned pointer to `parser->Original + parser->Size`. Fixing all four getters to compare against a recomputed `Size - consumed` instead of the mutated `Length` would close the class rather than the instance.

---

## 8. `core/Token.c` — TOKEN THEFT, IMPERSONATION, PRIVILEGE MANIPULATION

1,410 lines, 30 functions. The full token-manipulation surface: duplicate, steal across processes, impersonate from a vault, logon with credentials, and enumerate every token on the host via the **handle table**.

### 8.1 The vault — `Instance->Tokens`

```c
typedef struct _INSTANCE {
    ...
    struct {
        PTOKEN_LIST_DATA Vault;         /* linked list of held tokens */
        HANDLE           Token;         /* currently impersonating */
        BOOL             Impersonate;
    } Tokens;
```
[source: `payloads/Demon/include/Demon.h`]. Three fields: the vault list, the active impersonation handle, and the flag.

**`TokenAdd` (line 323) appends to the tail:**
```c
TokenEntry              = Instance->Win32.LocalAlloc( LPTR, sizeof( TOKEN_LIST_DATA ) );
TokenEntry->Handle      = hToken;
TokenEntry->DomainUser  = DomainUser;
TokenEntry->dwProcessID = dwProcessID;
TokenEntry->Type        = Type;
TokenEntry->lpUser      = User;
TokenEntry->lpDomain    = Domain;
TokenEntry->lpPassword  = Password;
TokenEntry->NextToken   = NULL;
if ( Instance->Tokens.Vault == NULL ) { Instance->Tokens.Vault = TokenEntry; return TokenIndex; }
TokenList = Instance->Tokens.Vault;
while ( TokenList->NextToken != NULL ) { TokenList = TokenList->NextToken; TokenIndex++; }
TokenList->NextToken = TokenEntry;
TokenIndex++;
return TokenIndex;
```
[source: `payloads/Demon/src/core/Token.c:336-362`]. The **return value is the token's index in the vault** — the operator-facing handle. `TokenIndex` is a position, not a stable ID: removing an entry (line 474 `TokenRemove`) renumbers everything after it. **The vault stores plaintext credentials.** `TokenEntry->lpPassword = Password;` keeps the **cleartext password for a `make` token in the agent's heap for the agent's entire lifetime** — there is no expiry, no wipe on `TokenRemove` for the string fields, and no `MemZero` of the password anywhere in this path. The file's own header comment (`Token.c:12-24`) is a design note acknowledging the list order is arbitrary.

**Tokens are never closed on the success path of the vault.** `TokenAdd` takes ownership of `hToken`; nothing in the vault free path (`TokenRemove`, `TokenClear`) closes the *handle* — only the list node. **Each stolen token leaks a kernel handle and an unreleased token object**, which is both a resource signature and a forensic trail: the stolen token remains referenced after it is "removed" from the vault.

### 8.2 `TokenSteal` — line 414

Opens the target process, opens its token, and duplicates it with impersonation rights:
```c
HANDLE TokenSteal( IN DWORD ProcessID, IN HANDLE TargetHandle ) {
    HANDLE            hProcess  = NULL;
    HANDLE            hTokenDup = NULL;
    CLIENT_ID         ProcID    = { 0 };
    OBJECT_ATTRIBUTES TokenAttr = { 0 };
    ...
```
[source: `Token.c:414-422`]. The `TargetHandle` parameter allows passing an already-open process handle; when it is NULL the function opens by `ProcessID` via a `CLIENT_ID{UniqueProcess = (HANDLE)ProcessID}` and `SysNtOpenProcess`, then `SysNtOpenProcessToken`/`NtOpenProcessTokenEx`, then `TokenDuplicate` (line 37) into a primary or impersonation token at the requested `SEC_IMP_LEVEL`.

**This is the classic token-steal primitive and it requires `SeDebugPrivilege` for cross-privilege targets.** That is why the two privilege helpers exist immediately above it. Note the ordering in the file: `TokenSetPrivilege` (203), `TokenSetSeDebugPriv` (240), `TokenSetSeImpersonatePriv` (271), then `TokenAdd` (323), then `TokenSteal` (414) — the code is laid out in the order the operator needs it: enable the two privileges, then steal.

**`TokenSteal` does not enable the privileges itself.** The operator must issue `token privs-get` (steal 4 / `DEMON_COMMAND_TOKEN_PRIVSGET`) first. A steal against a higher-privilege process without it fails at `NtOpenProcessToken` with `STATUS_ACCESS_DENIED` — an error the client surfaces, so this is a workflow step rather than a silent defect.

### 8.3 Privilege manipulation — and the string obfuscation

**`TokenSetPrivilege(Privilege, Enable)` — line 203.** `LookupPrivilegeValueA(NULL, Privilege, &TokenLUID)`, build a one-element `TOKEN_PRIVILEGES` with `SE_PRIVILEGE_ENABLED` or `0`, `SysNtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)`, `AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, 0, NULL, NULL)`.

**`AdjustTokenPrivileges` returns TRUE even when the privilege could not be assigned.** The documented API contract requires checking `GetLastError() == ERROR_NOT_ALL_ASSIGNED` after a successful call; **this code does not check it** (line 227-230). `TokenSetPrivilege` therefore **returns TRUE when the privilege was not enabled** — the agent reports success and the subsequent operation fails with access denied. For a token running as a filtered/standard user this is the common path, and it produces a misleading success in the operator UI.

**`TOKEN_ALL_ACCESS` is requested for privilege adjustment** (line 226) — `TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY` would suffice. Requesting `TOKEN_ALL_ACCESS` on the current process token is an unnecessary access mask, and it is one of the request patterns that access-mask-aware telemetry keys on.

**Two privileges are reconstructed one character at a time:**
```c
CHAR PrivName[ 17 ] = { 0 };
// SeDebugPrivilege
PrivName[ 2  ] = HideChar('D');
PrivName[ 9  ] = HideChar('i');
PrivName[ 16 ] = HideChar('\0');
PrivName[ 0  ] = HideChar('S');
PrivName[ 3  ] = HideChar('e');
PrivName[ 6  ] = HideChar('g');
PrivName[ 7  ] = HideChar('P');
PrivName[ 11 ] = HideChar('i');
PrivName[ 4  ] = HideChar('b');
PrivName[ 5  ] = HideChar('u');
PrivName[ 10 ] = HideChar('v');
PrivName[ 15 ] = HideChar('e');
PrivName[ 1  ] = HideChar('e');
PrivName[ 13 ] = HideChar('e');
PrivName[ 14 ] = HideChar('g');
PrivName[ 12 ] = HideChar('l');
PrivName[ 8  ] = HideChar('r');
Success = TokenSetPrivilege(PrivName, Enable);
MemZero( PrivName, sizeof( PrivName ) );
```
[source: `Token.c:243-268`]. Length 17 = `"SeDebugPrivilege"` (16) + NUL. The indices are written in an order that has nothing to do with the string (2, 9, 16, 0, 3, 6, 7, 11, 4, 5, 10, 15, 1, 13, 14, 12, 8) specifically to prevent the compiler from coalescing the stores into a single contiguous wide/ASCII literal. **`PrivName` is zeroed after use** (line 266) — this one *is* cleaned up, unlike the password in the vault.

**`TokenSetSeImpersonatePriv` (line 271)** is the same technique for `"SeImpersonatePrivilege"` — a 23-byte buffer (22 + NUL), indices written 7, 5, 4, 8, 3, 0, 11, 12, 17, 19, 22, 6, 16, 21, 10, 15, 9, 1, 13, 14, 2, 18, 20, zeroed at line 303.

**A defender's note:** the *names* never appear in the binary, but `SeImpersonatePrivilege` + `SeDebugPrivilege` are exactly the two privileges a potato-style escalation or a token-steal chain needs, and `AdjustTokenPrivileges` called with those privileges enabled on a process that then opens another process's token is the behavioural signature. `HideChar` also means a static string scan for `"SeDebugPrivilege"` finds nothing in `Token.c` — the strings are *reconstructed*, so the detection has to be on the `LookupPrivilegeValueA` argument at runtime.

### 8.4 The handle-table token hunt — `ListTokens` (line 1130)

This is the most capable part of the file: enumerating **every token on the system** by walking the kernel handle table rather than by process.

Supporting functions:
| Function | Line | Role |
|---|---|---|
| `QueryObjectTypesInfo` | 878 | `NtQueryObject(ObjectTypesInformation)` → list of kernel object types |
| `GetTypeIndexToken` | 910 | Finds the index whose type name is `"Token"` |
| `GetTokenInfo` | 949 | Per-handle `NtQueryObject(ObjectTypeInformation)` — reads the type index of a single handle |
| `ProcessIsIncluded` | 1029 | PID membership test against an exclusion list |
| `GetProcessesFromHandleTable` | 1040 | Maps handle-table PIDs into a process list |
| `GetAllHandles` | 1076 | `NtQuerySystemInformation(SystemHandleInformation)` — **the whole kernel handle table** |
| `IsNotCurrentUser` | 1122 | Dedup: compares two `BUFFER` users |
| `ListTokens` | 1130 | The enumeration, with impersonation-level and user-identity filters |

The shape: `GetAllHandles` reads `SystemHandleInformation`, `GetTypeIndexToken` locates the Token object-type index by name, then for every handle whose `ObjectTypeIndex` matches it, `SysNtDuplicateHandle` into the agent and query it. `CanTokenBeImpersonated` (802) and `IsImpersonationToken` (771) filter for usable tokens, and `ProcessUserToken` (830) / `AddUserToken` (733) fold results into the vault.

**`GetTypeIndexToken` matching on the type name `"Token"` is a string comparison against a kernel-reported name** — meaning this path *does* contain a plaintext `"Token"` comparison unless it is also `HideChar`-decomposed, which is inconsistent with the rest of the file's discipline. A static scan finds the object-type name here even though the privilege names are hidden.

**This is the `steal-token` / `find-tokens` implementation behind `DEMON_COMMAND_TOKEN_STEAL` (2) and `DEMON_COMMAND_TOKEN_FIND_TOKENS` (10)** (`Command.h:86-95`). It is materially stronger than the per-PID `TokenSteal` path: it finds tokens belonging to processes the agent cannot open, and tokens held by **services and other sessions** that would never appear in a per-process sweep. `TOKEN_QUERY | TOKEN_DUPLICATE` on a handle from the system handle table is the access path, and it is exactly the primitive that makes `SeImpersonatePrivilege` dangerous.

### 8.5 Impersonation

| Function | Line | Mechanism |
|---|---|---|
| `TokenImpersonate` | 707 | `SysNtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(HANDLE))` |
| `TokenRevSelf` | 74 | Same call with a **NULL token** — reverts to the process token |
| `ImpersonateTokenFromVault` | 1257 | Selects by vault index, then impersonates |
| `ImpersonateTokenInStore` | 1361 | Selects by user identity, then impersonates |
| `SysImpersonateLoggedOnUser` | 1281 | `NtSetInformationThread` on the current thread |
| `TokenCurrentHandle` | 624 | `NtOpenThreadToken`/`NtOpenProcessToken` for the active token |
| `TokenElevated` | 650 | Reads `TokenElevation` — used to pick between filtered and full |

**`TokenRevSelf` is the revert:**
```c
if ( ! NT_SUCCESS( NtStatus = SysNtSetInformationThread( NtCurrentThread(), ThreadImpersonationToken, &Token, sizeof( HANDLE ) ) ) )
```
[source: `Token.c:80`] — with `HANDLE Token = NULL;` (line 77). Setting `ThreadImpersonationToken` to a NULL handle pointer is the documented revert-to-self, so `DEMON_COMMAND_TOKEN_REVERT` (7) is correctly implemented.

**Impersonation is per-thread and the agent's dispatcher is one thread.** Setting `ThreadImpersonationToken` on `NtCurrentThread()` means the impersonation applies only to the agent's dispatcher thread — which is exactly what is wanted for the subsequent command, and exactly why a job executed on a *fibre* or a spawned thread **does not inherit the impersonation**. `Instance->Tokens.Impersonate` (the flag) then diverges from the actual thread state, and an operator who impersonates and then runs a threaded command gets the wrong identity with the UI still showing the impersonated one.

### 8.6 `TokenMake` — line 598, and the logon surface

`TokenMake(User, Password, Domain, LogonType)` performs a fresh logon via `LsaLogonUser` with the supplied credentials and returns the resulting token. The `LogonType` is operator-controlled — `LOGON32_LOGON_INTERACTIVE`, `NETWORK`, `NEW_CREDENTIALS`, `BATCH`, `SERVICE` are all reachable through the client's `token make` sub-command. **The credentials arrive as cleartext in the task body** (which is AES-CTR encrypted under the session key with the fixed IV of §3.3), then are **retained in the vault in cleartext** (line 343).

`LsaLogonUser` requires `SeTcbPrivilege` for most logon types; the file does not appear to enable it, so this path depends on the agent already running with sufficient privilege. The `Lsass`-adjacent API set resolved in `Defines.h` (`H_FUNC_LSALOOKUPAUTHENTICATIONPACKAGE 0x876cc00b`, `H_FUNC_LSACALLAUTHENTICATIONPACKAGE 0x6d1a042d`, `H_FUNC_LSADEREGISTERLOGONPROCESS 0x8aba5ef1`, `H_FUNC_LSACONNECTUNTRUSTED 0x1da98b7d`, `H_FUNC_LSAGETLOGONSESSIONDATA 0x1c698f42`, `H_FUNC_LSAENUMERATELOGONSESSIONS 0xbca01141`, `H_FUNC_LSAFREERETURNBUFFER 0x916b1321`) is the `advapi32`/`secur32` LSA binding used by both this path and `Kerberos.c` (§8.7).

### 8.7 The Kerberos surface — `core/Kerberos.c`

`Kerberos.c` (26.3 KB) is the `DEMON_COMMAND_KERBEROS` (2550) implementation dispatched at `Command.c:3077`. It uses the LSA authentication-package functions above plus the `secur32` SSPI binding:
- `LsaRegisterLogonProcess` / `LsaConnectUntrusted` to obtain an `LSA_HANDLE` — the untrusted path needs no privilege, which is why it is present.
- `LsaLookupAuthenticationPackage` with package name `"Kerberos"` (and `"Negotiate"`) to get the package ID.
- `LsaCallAuthenticationPackage` with the **`KerbQueryTicketCacheEx`/`KerbRetrieveEncodedTicket`** message types to pull cached TGTs and service tickets out of LSASS **without touching disk**.
- `LsaEnumerateLogonSessions` + `LsaGetLogonSessionData` for session enumeration.

**The well-known operation this implements is cache extraction** — pulling `.kirbi`/ccache-format ticket material straight from the LSA cache of the logon session the agent is running in. Because `LsaConnectUntrusted` + `LsaLookupAuthenticationPackage` + `LsaCallAuthenticationPackage` require **no special privilege** for the *calling* session's own cache, an unprivileged agent in an authenticated user's context can extract that user's TGT and every service ticket that user has. **This is the head of the delegation/`S4U2Self`-to-`ServicesTicket`-flags deviation chain that ends in domain admin, and it needs no elevation to start.** That makes the unprivileged cache-read the highest-impact capability in the token/Kerberos block.

**A ticket's validity is time-bounded by its own `EndTime`.** Because the agent is a long-lived process, a ticket extracted at hour 0 can be used hours later; the only agent-side constraint is the kill date (§3.18) and the working-hours window.

### 8.8 Defects in this file

1. **`TokenSetPrivilege` returns TRUE when `AdjustTokenPrivileges` succeeded but `ERROR_NOT_ALL_ASSIGNED` was set** (line 227-230) — silent privilege-assignment failure reported as success.
2. **`TokenAdd` stores the cleartext password with no wipe** (line 343), for the agent's lifetime. `TokenRemove`/`TokenClear` do not wipe `lpUser`/`lpDomain`/`lpPassword`/`DomainUser`.
3. **Token handles are never closed on vault removal** — kernel handle and token-object leak per stolen token.
4. **`TOKEN_ALL_ACCESS` on the current process token** for a privilege-only operation (line 226) — over-broad access request.
5. **`TokenIndex` is positional, not stable** — `TokenRemove` renumbers the vault, so an index captured by the operator before a removal refers to a different token afterwards. An operator who removes token 1 and then acts on token 2 acts on what was token 3.
6. **Impersonation is thread-scoped but tracked process-globally** via `Instance->Tokens.Impersonate`, so the flag and the actual thread state can disagree once threaded/forb-jobs are used (§8.5).
7. **`GetTypeIndexToken` compares the kernel object-type name `"Token"` as a literal** — inconsistent with the file's otherwise complete string hiding (§8.4).
8. **`TokenQueryOwner` allocates `MmHeapAlloc(UserSize)` on the *failure* branch** of a deliberately-failing size query (line 124-126) — the call is expected to return `STATUS_BUFFER_TOO_SMALL`, and the code relies on `UserSize` being populated in that case. If the API fails for a different reason, `UserSize` is 0 and `MmHeapAlloc(0)` is used before the second query is attempted.

---

## 9. `core/CoffeeLdr.c` — THE COFF / BOF LOADER

29.7 KB. This is the in-memory COFF object loader behind `DEMON_COMMAND_INLINE_EXECUTE` (20), dispatched at `Command.c:1114`. It executes Beacon Object Files — unlinked `.o` COFF objects compiled with `cl.exe /c` or `gcc -c` — entirely in the agent's address space, with no file written and no disk artifact.

### 9.1 What a BOF actually is, mechanically

A BOF is a COFF object file, not a PE. It has no header, no section alignment, no imports table in the PE sense, and — critically — **unresolved symbols**. The `.o` was compiled but never linked, so calls to `BeaconPrintf`, `LoadLibraryA`, `GetProcAddress`, `Nt*` and anything else the author used appear as COFF `IMAGE_SYMBOL` records with `Value == 0` and `SectionNumber == 0` (external, unresolved). **The loader's whole job is to satisfy those symbols at runtime and then run the one section containing code.**

The three things the loader must do:
1. **Allocate** a region for every section's raw data.
2. **Relocate** — apply the `IMAGE_RELOCATION` records that describe every site referencing a symbol or a different section, because the sections were placed at different addresses than the linker assumed.
3. **Bind** unresolved external symbols to real addresses, which for a BOF means the Beacon API set supplied by the host.

### 9.2 Symbol resolution — the Beacon API

The loader installs a symbol table mapping BOF-facing names to agent functions. The canonical Beacon set, and what Havoc maps each to:

| BOF symbol | Havoc implementation | Purpose |
|---|---|---|
| `BeaconPrintf` | `PutOutput` wrapper on `PackageAddString` | formatted output back to the operator |
| `BeaconOutput` | direct `PackageAddBytes` | raw output |
| `BeaconDataParse` / `BeaconDataExtract` / `BeaconDataInt` / `BeaconDataShort` / `BeaconDataLength` | `parser`-shaped accessors over the packed argument blob | the `datap` argument BOFs receive |
| `BeaconDataPtr` / `BeaconDataString` / `BeaconDataPtr` | offset-returning accessors | |
| `BeaconFormatAlloc` / `BeaconFormatAppend` / `BeaconFormatPrintf` / `BeaconFormatToString` / `BeaconFormatFree` / `BeaconFormatReset` | `MmHeapAlloc`-backed growable buffer | the `formatp` capture buffer |
| `BeaconUseToken` / `BeaconRevertToken` / `BeaconIsAdmin` | `TokenImpersonate` / `TokenRevSelf` / elevation check (§8.5) | token control from inside a BOF |
| `BeaconGetSpawnTo` | returns configured spawn path | |
| `BeaconSpawnTemporaryProcess` / `BeaconInjectProcess` / `BeaconInjectTemporaryProcess` | `Inject.c` paths (§10) | BOF-driven injection |
| `BeaconGetOutputData` | returns accumulated output | |
| `BeaconAddValue` / `BeaconGetValue` / `BeaconRemoveValue` | `Instance->CoffeKeyValueStore` | the BOF key/value store |
| `toWideChar` | `CharStringToWCharString` | |
| `LoadLibraryA` / `GetProcAddress` / `GetModuleHandleA` / `FreeLibrary` | `Instance->Win32.*` | forwarded so the BOF never calls a real import |

**The key/value store is exactly the `CoffeKeyValueStore` linked list declared in `INSTANCE`** (`Demon.h`). BOFs use `BeaconAddValue`/`BeaconGetValue` to pass state between invocations — a BOF that caches a handle, a PID, or a credential in the store keeps it for the agent's lifetime across separate `inline-execute` commands. **This is a persistence mechanism inside the agent that the operator never explicitly configured**, and nothing in the loader expires or clears it.

### 9.3 The execution model — and `CoffeeThreaded` / `CoffeeVeh`

Two `Config.Implant` flags control how the BOF body runs (`Demon.h`, and `Command.c:1114` onward):

- **`CoffeeThreaded`** — the BOF is executed on a **new thread** rather than on the dispatcher thread. This matters because BOFs are allowed to block, and a blocking BOF on the dispatcher thread stalls the entire agent (§3). With the flag off, a BOF that sleeps or waits for I/O hangs every subsequent command.
- **`CoffeeVeh`** — the BOF runs with a **Vectored Exception Handler installed**. `BeaconPrintf`-heavy BOFs and BOFs that deliberately fault (a common anti-analysis trick, and used by some BOFs to detect a debugger) rely on a VEH being present. `HwBpEngine.c`/`HwBpExceptions.c` (§11) provide the hardware-breakpoint VEH that intercepts `EXCEPTION_SINGLE_STEP` for the AMSI/ETW patching path; the same mechanism serves the BOF.

Because the loader executes on a thread or fibre under the agent's own process, **a BOF has full access to the agent's memory** — the AES key, the API pointer table, the token vault, the key/value store. There is no sandbox between a BOF and the agent. That is by design in every C2 BOF loader, and it means an operator who inline-executes a BOF they did not write is trusting it with the session.

### 9.4 The argument blob — `datap`

`inline-execute` takes two arguments: the BOF path (read from disk or from the memory-only file system, §3.16) and an **argument string**. The string is packed into the BOF's expected ABI: a 4-byte big-endian total length, then a sequence of `[length][bytes]` entries, matching `BeaconDataParse`'s expectation of a length-prefixed sequence. `BeaconDataExtract` pops entries in order.

**The packing uses the same `PackageAddBytes` length-prefix convention as the wire** (§4.5), and `BeaconDataExtract` in the loader reads it with the same pattern as `ParserGetBytes`. **That means the loader's data extractor inherits the identical class of defect** — a length-prefixed read with no bound against the remaining blob. Since the argument blob here originates from the *operator* rather than the wire, the exposure is lower than §7A, but a BOF that calls `BeaconDataExtract` on a malformed `datap` reads past the blob into agent heap. The blob lives in the same allocation space as the token vault.

### 9.5 What this file means for detection

1. **The BOF symbol set is a fingerprint.** An agent process whose memory contains the strings `BeaconPrintf`, `BeaconDataParse`, `BeaconAddValue` (or their hashes, if hidden) is hosting a COFF loader. The symbol names must exist **in cleartext in the loaded object** — a COFF's symbol table is not obfuscated — and the loader compares against them, so the comparison strings are in the *loader* too unless hash-compared like `Win32.c`.
2. **A COFF object materialised in executable memory is unusual.** The loader must copy section raw data into memory it has made executable. A page that was `PAGE_READWRITE` and becomes `PAGE_EXECUTE_READ` *without* a `LoadLibrary`/image-map event in the same window is the BOF-loading signature, and it is the same protection-transition signal as §5's sleep obfuscation — one detector covers both.
3. **`MMF`/`IMAGE_SCN_MEM_EXECUTE` sections with no corresponding module on the module list** is directly observable from a scanning tool.
4. **The key/value store is persistent state that survives command boundaries**, so an incident responder who finds a stale handle or path cached in an agent's heap has found a BOF cache.
5. **The `CoffeeVeh` path installs a VEH** — `AddVectoredExceptionHandler` with a non-module handler address is itself notable, and it is shared with the hardware-breakpoint AMSI patch (§11.3), so the two features produce one artifact.

### 9.6 Residual unknowns for this file

The precise COFF relocation arithmetic beyond the standard `IMAGE_REL_AMD64_ADDR64`/`ADDR32`/`REL32` triple, whether the loader honours section characteristics other than execute/read/write, and whether it supports COFF objects with more than one code section are **not** settled here — those specific branches were not read. The loader exists and executes BOFs; the depth of its COFF conformance is unresolved.

---

## 10. THE INJECTION SET — `inject/Inject.c`, `inject/InjectUtil.c`, `core/Thread.c`, `src/asm/Spoof.*`

The injection code lives under `payloads/Demon/src/inject/`, **not** under `src/core/` — a layout note, since the source tree's own organisation does not match the brief's assumption.

### 10.1 The technique enumeration

```c
#define INJECTION_TECHNIQUE_WIN32           1
#define INJECTION_TECHNIQUE_SYSCALL         2
#define INJECTION_TECHNIQUE_APC             3
#define INJECTION_TECHNIQUE_DEFAULT         INJECTION_TECHNIQUE_SYSCALL
```
[source: `payloads/Demon/include/inject/Inject.h:10-19`]

**There is no `LIBRARY_TECHNIQUE_*` set of four to enumerate — the memory-access technique selector is the separate three-valued enum below, and the thread-creation method is a third independent selector.** The three axes are independent and configured separately:

| Axis | Header | Values | Set by |
|---|---|---|---|
| **Memory operations** | `core/Memory.h:8-10` | `DX_MEM_DEFAULT = 0`, `DX_MEM_WIN32 = 1`, `DX_MEM_SYSCALL = 2` | per call, hardcoded at each call site |
| **Thread creation** | `core/Thread.h` | `THREAD_METHOD_DEFAULT`, `THREAD_METHOD_CREATEREMOTETHREAD`, `THREAD_METHOD_NTCREATEHREADEX`, `THREAD_METHOD_NTQUEUEAPCTHREAD` | `Config.Implant` / per-call `Method` |
| **Injection sequence** | `inject/Inject.h` | `WIN32 = 1`, `SYSCALL = 2`, `APC = 3`, default `SYSCALL` | `Config.Injection.Technique` |

**The default is `INJECTION_TECHNIQUE_SYSCALL`**, and `Demon.c:787` sets `Instance->Config.Injection.Technique = INJECTION_TECHNIQUE_SYSCALL` as the post-parse default (§2). So **out of the box, every injection allocates, writes and protects through direct `Nt*` stubs rather than the Win32 API.**

### 10.2 The memory-operation selector — `DX_MEM_*` used at each call site

`Inject()` (line 27) does **not** honour a single technique flag. It hardcodes the memory technique per operation, and the choices are inconsistent:

```c
/* allocate: DX_MEM_DEFAULT (= 0 = WIN32 path) */
if ( ! ( Memory = MmVirtualAlloc( DX_MEM_DEFAULT, Process, Size, PAGE_READWRITE ) ) ) { ... }

/* write: the wrapper takes no technique argument */
if ( ! ( MmVirtualWrite( Process, Memory, Payload, Size ) ) ) { ... }

/* protect: DX_MEM_SYSCALL (= 2) */
if ( ! ( MmVirtualProtect( DX_MEM_SYSCALL, Process, Memory, Size, PAGE_EXECUTE_READ ) ) ) { ... }

/* argument allocate: DX_MEM_DEFAULT again */
if ( ! ( Param = MmVirtualAlloc( DX_MEM_DEFAULT, Process, Argc, PAGE_READWRITE ) ) ) { ... }
```
[source: `payloads/Demon/src/inject/Inject.c:87`, `95`, `103`, `114`]

**The technique names appear to denote a per-operation choice, not a per-injection profile, and the code mixes them within one injection.** Allocation goes through the default (Win32 `VirtualAllocEx`) path, protection goes through the syscall path. `MmVirtualWrite` takes no selector at all, so writes are whatever that wrapper does internally.

**The configuration option `DEMON_CONFIG_INJECTION_TECHNIQUE 150` (`Command.h:68`)** is the operator-facing knob for `Config.Injection.Technique`, i.e. the *thread creation* method selected in `ThreadCreate` below — not the `DX_MEM_*` memory axis. An operator who sets the injection technique to "syscall" changes how threads are created; it does **not** change how memory is allocated or written, which remain as hardcoded above. **The config option's name overstates its reach**, and that is a real operational surprise: selecting syscall injection still produces Win32 `VirtualAllocEx` calls for the payload allocation.

### 10.3 `Inject()` — the sequence, line by line

```c
DWORD Inject( IN BYTE Method, IN HANDLE Handle, IN DWORD Pid, IN BOOL x64,
              IN PVOID Payload, IN SIZE_T Size, IN UINT64 Offset,
              IN PVOID Argv, IN SIZE_T Argc )
```
[source: `Inject.c:27-37`]

1. **Parameter validation (47-49):** rejects only if both `Handle` and `Pid` are absent, or both `Payload` and `Size` are absent. **`Size` is never checked against an upper bound**, and `Payload`/`Size` are used as a unit — a caller passing a valid `Payload` with a huge `Size` causes an out-of-bounds read of the agent's own memory into the remote process.
2. **Process acquisition (52-65):** uses the supplied `Handle` if present, else `ProcessOpen(Pid, PROCESS_ALL_ACCESS)`. **`PROCESS_ALL_ACCESS` is requested unconditionally** — a maximal access mask for an operation that needs `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION`. This is the single most reliable cross-process injection detection in existence and the code does not minimise the mask.
3. **Architecture validation (68-84):** three checks against `Instance->Session.OS_Arch` and `ProcessIsWow(Process)`. The `IsWow64` probe distinguishes a WOW64 target; the checks correctly reject x64-payload-into-x86-process and x86-payload-into-native-x64-process. **A WOW64 (x86) agent can inject x64 into an x64 target via `ThreadCreateWoW64` (line 118)** — the cross-architecture case that requires the 64-bit thread-creation stub.
4. **Allocate (87):** `MmVirtualAlloc(DX_MEM_DEFAULT, Process, Size, PAGE_READWRITE)`.
5. **Write (95):** `MmVirtualWrite(Process, Memory, Payload, Size)`.
6. **Protect (103):** `MmVirtualProtect(DX_MEM_SYSCALL, Process, Memory, Size, PAGE_EXECUTE_READ)` — **`RW → RX`, never `RWX`.** The staged-transition discipline is correct and is what a sophisticated injector does; it is also the signature §10.6 notes.
7. **Optional argument block (111-128):** a second `MmVirtualAlloc`/`MmVirtualWrite` pair for `Argv`/`Argc`, left `PAGE_READWRITE`.
8. **Execute (131):** `ThreadCreate(Method, Process, x64, C_PTR(Memory + Offset), Param, &Tid)`.
9. **Cleanup (138-167):** on `Status == INJECT_ERROR_FAILED` only, `MmVirtualFree` both regions. The process handle is closed only when it was opened here (`if (Process && !Handle)`); the thread handle is always closed.

**The failure-cleanup gate is the defect:** `if (Status == INJECT_ERROR_FAILED)` (line 142) tests for the *initial* sentinel value. Any status set to something other than `INJECT_ERROR_FAILED` — and the architecture-mismatch paths set `INJECT_ERROR_PROCESS_ARCH_MISMATCH` (70, 78, 82) — **skips the free entirely.** So an architecture mismatch after the payload has been written leaves the remote allocation resident forever, with the payload in it. The remote process keeps a `PAGE_READWRITE` buffer containing the injected DLL/shellcode and nothing references it. That is a **residue artifact in the target process** produced by a path the operator sees as a clean "arch mismatch" error.

### 10.4 Thread creation — `core/Thread.c` `ThreadCreate` (line 217)

```c
switch ( Method )
{
    case THREAD_METHOD_DEFAULT: {
        return ThreadCreate( THREAD_METHOD_NTCREATEHREADEX, Process, x64, Entry, Arg, ThreadId );
    }
    case THREAD_METHOD_CREATEREMOTETHREAD: {
        Thread = Instance->Win32.CreateRemoteThread( Process, NULL, 0, Entry, Arg, 0, ThreadId );
        break;
    }
    case THREAD_METHOD_NTCREATEHREADEX: {
        NTSTATUS      NtStatus   = STATUS_SUCCESS;
        THD_ATTR_LIST ThreadAttr = { 0 };
        CLIENT_ID     Client     = { 0 };
        ThreadAttr.Entry.Attribute = ProcThreadAttributeValue( PsAttributeClientId, TRUE, FALSE, FALSE );
        ThreadAttr.Entry.Size      = sizeof( CLIENT_ID );
        ThreadAttr.Entry.pValue    = C_PTR( &Client );
        ThreadAttr.Length          = sizeof( PROC_THREAD_ATTRIBUTE_LIST );
        NtStatus = SysNtCreateThreadEx( &Thread, THREAD_ALL_ACCESS, NULL, Process, Entry, Arg, FALSE, 0, 0, 0, &ThreadAttr );
        if ( NT_SUCCESS( NtStatus ) ) { if ( ThreadId ) *ThreadId = U_PTR( Client.UniqueThread ); }
        else { PRINTF( "Failed to create new thread => NtStatus:[%x]\n", NtStatus ); NtSetLastError( ... ); }
        break;
    }
    case THREAD_METHOD_NTQUEUEAPCTHREAD: {
        /* TODO: finish implementing it */
        break;
    }
    default: { PRINTF( "Technique not found => %d", Method ) break; }
}
```
[source: `payloads/Demon/src/core/Thread.c:234-279`]

- **`THREAD_METHOD_DEFAULT` recurses into `THREAD_METHOD_NTCREATEHREADEX`** — a self-call with a rewritten selector rather than a fallthrough, so the default resolves to `NtCreateThreadEx`.
- **`THREAD_METHOD_NTQUEUEAPCTHREAD` is an empty `TODO`** (270-273). The `INJECTION_TECHNIQUE_APC = 3` value and the thread-method `APC` label both exist and both do nothing — **selecting APC injection in the client silently creates no thread**, the `switch` falls out with `Thread == NULL`, `Inject` logs "Failed to create a new thread", and the cleanup gate (above) does not free the allocation, so an APC injection attempt leaves the payload resident in the target and running nothing. This is the single most misleading capability in the injection set.
- **`NtCreateThreadEx` is called with `CreateSuspended = FALSE`** (the 7th argument). The thread starts executing immediately. There is no suspended-create-then-modify window, which is the more common evasion (create suspended, queue an APC or set the context, then resume).
- **`THREAD_ALL_ACCESS` on the created thread** — again maximal, and the handle is immediately closed by `Inject`'s cleanup (164-167).
- **The `ProcThreadAttributeValue(PsAttributeClientId, …)` attribute list is used purely to learn the new thread's ID**, because `NtCreateThreadEx` does not return a TID directly. `ThreadAttr.Length = sizeof(PROC_THREAD_ATTRIBUTE_LIST)` and the struct is a **single-entry fixed array**, not the variable-length `InitializeProcThreadAttributeList`-allocated form — so it relies on the kernel accepting a minimal one-entry list, and `CLIENT_ID Client` on the stack being written by the kernel. A malformed/short attribute list here is a plausible cause of an `NtCreateThreadEx` failure that the code reports only as an NTSTATUS.
- **`ThreadCreateWoW64` (line 118)** is the x86→x64 path, guarded by `#if _M_IX86` (227). It is the only cross-bitness mechanism in the file and requires the 64-bit thread stub.

**`CreateRemoteThread`** (241) is the Win32 path: `CreateRemoteThread(Process, NULL, 0, Entry, Arg, 0, ThreadId)` — `dwCreationFlags = 0`, so not suspended. It is the loudest possible injection primitive and is present as a selectable technique.

### 10.5 The assembly stubs — `src/asm/Syscall.*` and `src/asm/Spoof.*`

**Syscall dispatch x64** (`Syscall.x64.asm`, 17 lines):
```asm
SysSetConfig:  mov r11, rcx          ; stash pointer to SYS_CONFIG in r11
               ret
SysInvoke:     mov r10, rcx          ; r10 = first syscall arg (Windows x64 ABI for syscalls)
               mov eax, [r11+0x8]    ; eax = SSN  (SYS_CONFIG {PVOID Adr; WORD Ssn})
               jmp QWORD [r11]       ; jump to the resolved ntdll syscall instruction
               ret
```
**`jmp QWORD [r11]` is the indirect-syscall technique**: control transfers to a `syscall` instruction **that lives inside `ntdll`, not in the agent's own memory**. Call-stack and instruction-pointer inspection therefore show the syscall originating from `ntdll`'s address range, which is what defeats the "syscall instruction outside a known module" heuristic. The `r11` stash is what makes the address and SSN available without stack arguments.

**Syscall dispatch x86** (`Syscall.x86.asm`, 30 lines):
```asm
_SysSetConfig: mov edx, [esp+4]
_SysInvoke:    mov ebx, [edx]        ; address
               mov eax, [edx+4]      ; SSN
               mov edx, esp
               sub edx, 4
               call DWORD ebx        ; call the ntdll stub
_IsWoW64:      mov eax, [fs:0xc0]    ; WoW64 TEB check
```
The x86 form uses `call` rather than `jmp` (so the syscall instruction is reached via a return-address frame) and reads the WoW64 flag from `fs:[0xC0]`, matching `Syscalls.c:39`'s `__readfsdword(0xC0)`.

**Stack spoofing x64** (`Spoof.x64.asm`, 26 lines) — this is the real one:
```asm
Spoof:   pop r11
         add rsp, 8
         mov rax, [rsp+24]
         ; rewrite the return slot
         ; stash r11 / rbx
         mov [rax], <fixup>
         jmp r10
fixup:   sub rsp, 16
         ; restore rbx
         jmp QWORD [rcx+8]
```
It pops the call's return address, rewrites the fabricated frame's return address to a `fixup` label inside the agent, jumps to the target (`r10`), and on return repairs the stack and resumes. The observable effect: **a call stack that appears to return into a legitimate caller rather than into the agent**, and a return address on the stack that does not point at the agent's code. Combined with the `SleepFunc`/`WaitForSingleObjectEx` spoofing in `Obf.c` (§5), this is what makes the sleeping agent's stack look benign.

**Stack spoofing x86** (`Spoof.x86.asm`, 9 lines):
```asm
_Spoof: ret
```
**A bare `ret` — the x86 stack-spoofing path is a no-op stub.** It matches the `#else` comment in `Obf.c` (`// TODO: add support for sleep obf and spoofing`). A 32-bit agent therefore gains **no stack spoofing at all** while the client's `stack-spoof` configuration option appears settable: an operator running an x86 Demon with stack spoofing enabled gets a silent no-op. On x64 the mechanism is genuine.

**This asymmetry is the clearest example in the whole target of a security feature that is configuration-visible but architecture-conditional, with no warning emitted.**

### 10.6 The reflective loader — `InjectUtil.c` and `DllInjectReflective`

**`InjectUtil.c` (3 functions, ~90 lines)** is the PE arithmetic the reflective load depends on:
| Function | Line | Role |
|---|---|---|
| `Rva2Offset(dwRva, uiBaseAddress)` | 12 | Maps an RVA to a file offset by walking section headers — the core of reflective loading |
| `GetReflectiveLoaderOffset(ReflectiveLdrAddr)` | 36 | Locates the `ReflectiveLoader` export inside the injected DLL image |
| `GetPeArch(PeBytes)` | 72 | Reads the PE header to classify x86/x64 |

`GetReflectiveLoaderOffset` is what makes `DllInjectReflective` (line 172) work: the DllLdr is injected with its PE headers intact so the `ReflectiveLoader` entry can be found in the mapped image. **The injected blob is a PE, not shellcode**, so the section headers and export directory are present in the remote process — the artifact a scanner looks for.

**`DllInjectReflective(hTargetProcess, DllLdr, DllLdrSize, DllBuffer, DllLength, Parameter, ParamSize, ctx)` (line 172)** injects the loader (`DllLdr`) and the payload DLL (`DllBuffer`) and passes a parameter block. The `PINJECTION_CTX ctx` carries the injection parameters across the call. **`DllSpawnReflective` (line 322)** is the spawn-to-self variant used by `SPAWN_DLL` (26) — it creates a new process of the configured spawn image (`Werfault.exe` per the hardcoded values) and reflectively loads into it, giving a **legitimate signed host process executing the payload** with no injection into an existing process at all.

### 10.7 What the injection set produces forensically

1. **`PROCESS_ALL_ACCESS` and `THREAD_ALL_ACCESS` are requested unconditionally.** These are the two loudest access masks in Windows and the code never minimises them. An `OpenProcess` audit entry with `0x1F0FFF` is the highest-signal single event this agent generates.
2. **The staged `RW → RX` transition on a non-image, non-mapped region** is the artifact. The allocation is `MEM_PRIVATE` (not `MEM_IMAGE`, not `MEM_MAPPED`), it is written then made executable, and it appears on no module list.
3. **`NtCreateThreadEx` with a start address in a `MEM_PRIVATE` region** is directly observable by EDR thread-creation callbacks with the start address — the target region is identifiable at creation time.
4. **The injected PE retains its headers**, so a memory scan for `MZ`/`PE\0\0` in `MEM_PRIVATE` executable regions finds the payload.
5. **The arch-mismatch residue path (§10.3 point 9) leaves a written payload in a target process with no thread**, which is a *stable* memory artifact that a scanner can find long after the failed operation.
6. **The x86 `_Spoof: ret` no-op** means a 32-bit agent's stacks are fully visible — an x86 Havoc session has no stack obfuscation whatsoever despite the configuration surface.
7. **`DllSpawnReflective` + `Werfault.exe`** produces a Microsoft-signed host process executing non-Microsoft code, which is the hardest of these to triage by signature alone; the discriminator is again the private executable region inside a signed process.

### 10.8 Residual unknowns for this file

`MmVirtualAlloc`/`MmVirtualWrite`/`MmVirtualProtect`'s internal handling of `DX_MEM_DEFAULT` vs `DX_MEM_SYSCALL` vs `DX_MEM_WIN32` (i.e. exactly which `Nt*` stub each selects) was not read in `Memory.c`; the functional intent is clear from the call sites but the internal routing is unresolved. `ThreadCreateWoW64`'s 64-bit stub mechanism was identified but not read line-by-line. The `INJECTION_CTX` structure's fields are not enumerated here.

---

## 11. `core/Dotnet.c` + `common/Clr.h` — IN-MEMORY .NET EXECUTION

573 lines. This is `DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE` (0x2001), dispatched at `Command.c:1708`: execute a .NET assembly **from memory, with no file on disk**, inside the agent's own process, and capture its `Console.WriteLine` output back to the operator.

### 11.1 The five hardcoded GUIDs

```c
GUID xCLSID_CLRMetaHost     = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
GUID xCLSID_CorRuntimeHost  = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
GUID xIID_AppDomain         = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };
GUID xIID_ICLRMetaHost      = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
GUID xIID_ICLRRuntimeInfo   = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
GUID xIID_ICorRuntimeHost   = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
```
[source: `payloads/Demon/src/core/Dotnet.c:10-15`]

These are the standard CLR hosting CLSIDs/IIDs, declared in the agent rather than linked from `mscoree.h` (the header is included at `Win32.h:6` but the agent defines its own copies so the vtable layout is under its control). **They are stored as plain `.data` — a memory scan for `{ 0x9280188d, 0x0e8e, 0x4867, … }` or for `CLSID_CorRuntimeHost`'s `0xcb2f6723, 0xab3a, 0x11d2` locates the CLR-hosting capability in an agent image even while `.text` is sleep-obfuscated** (§5.1 — data sections are not encrypted on the shellcode build path).

### 11.2 The CLR load chain — `ClrCreateInstance` (line 524)

```c
if ( RtMscoree() ) {
    if ( Instance->Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost ) == S_OK ) {
        if ( ( *ppClrMetaHost )->lpVtbl->GetRuntime( *ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo ) == S_OK ) {
            if ( ( ( *ppClrRuntimeInfo )->lpVtbl->IsLoadable( *ppClrRuntimeInfo, &fLoadable ) == S_OK ) && fLoadable ) {
                if ( ( *ppClrRuntimeInfo )->lpVtbl->GetInterface( *ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost ) == S_OK ) {
                    ( *ppICorRuntimeHost )->lpVtbl->Start( *ppICorRuntimeHost );
                }
```
[source: `Dotnet.c:528-541`]

The chain is `mscoree!CLRCreateInstance` → `ICLRMetaHost::GetRuntime(version)` → `ICLRRuntimeInfo::IsLoadable` → `ICLRRuntimeInfo::GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost)` → `ICorRuntimeHost::Start()`. **Every step is checked and produces a distinct diagnostic string** (544, 550, 556, 562) — this is the best error handling in the file, and the messages are operator-visible.

**The comments are self-aware about the deprecation and the evasion tradeoff:**
```c
//Load the CLR into the current process and return a runtime interface pointer.
//   -> CLR changed to ICor which is deprecated but works
//Start it. This is okay to call even if the CLR is already running
```
[source: `Dotnet.c:536`, `539`]. `ICorRuntimeHost` is the .NET Framework 2.0-era interface; `ICLRRuntimeHost` is the modern one. The author chose the deprecated interface deliberately — it exposes `CreateDomain`, which is required for the AppDomain-based load used below and is **not** available on `ICLRRuntimeHost`. `DefaultAppDomain` on the modern interface would avoid creating a new domain; the chosen path deliberately creates one.

**The version string comes from `Instance->Dotnet->NetVersion.Buffer`** and is reported to the operator **before** the assembly runs (lines 137-142). So the operator knows which CLR was selected — and can see the selection fail, since the diagnostics above are printed.

### 11.3 The version probe — `FindVersion` (line 501) and the `v4.0.30319` literal

```c
BOOL FindVersion( PVOID Assembly, DWORD length )
{
    char* assembly_c = (char*)Assembly;
    char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

    for (int i = 0; i < length; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            if (v4[j] != assembly_c[i + j])
                break;
            else { if (j == (9)) return 1; }
        }
    }
    return 0;
}
```
[source: `Dotnet.c:501-522`]

**The ten bytes `76 34 2E 30 2E 33 30 33 31 39` are ASCII `"v4.0.30319"`** — the .NET Framework 4.x CLR version string. `FindVersion` scans the **supplied assembly bytes** for that literal, which appears in a .NET assembly's metadata as the runtime version it was compiled against. The function answers "does this assembly target .NET 4.x?" by string search rather than by parsing the metadata's `IMAGE_COR20_HEADER` / `#~` stream.

**Two defects:**
1. **The scan over-reads by 9 bytes.** The inner loop indexes `assembly_c[i + j]` for `j` up to 9 while the outer loop runs `i` up to `length - 1`. At `i == length - 1` it reads `assembly_c[length + 8]` — **9 bytes past the end of the assembly buffer.** The buffer is agent heap holding the operator-supplied assembly, so the read is in-agent and typically inside the allocation's slack, but it is an out-of-bounds read driven by the assembly length.
2. **The literal is byte-obfuscated by being a `char` array initialiser rather than a string literal** (505) — consistent with the codebase's string discipline, though the compiler is free to coalesce it into `.rdata` anyway since it is a static initialiser with constant elements. Unlike `HideChar`-decomposed strings, **this one can still appear in the binary**; the decomposition here is stylistic, not effective.

`FindVersion` is used to pick between the CLR versions the profile can offer: if the assembly declares 4.x, the agent requests the 4.x runtime; otherwise it falls back through the configured version list. **This is why an assembly built for .NET 5/6/7/8 in this corpus cannot be run by Havoc's loader** — the version probe and the `GetRuntime` call are `ICorRuntimeHost`-based .NET Framework paths, and `dotnet`-hosted (CoreCLR) assemblies simply are not loadable that way. Havoc's CLR hosting is **.NET Framework only**, and that is a hard functional boundary, not a configuration choice.

### 11.4 The output capture — a named pipe and a console swap

This is the mechanism that makes `Console.WriteLine` from an assembly appear in the operator's UI:

```c
#define PIPE_BUFFER 0x10000 * 5        /* 327680 */
Instance->Dotnet->Pipe = Instance->Win32.CreateNamedPipeW(
    Instance->Dotnet->PipeName.Buffer,
    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES,
    PIPE_BUFFER, PIPE_BUFFER,
    0,
    NULL
);
if ( ! ( Instance->Dotnet->File = Instance->Win32.CreateFileW( Instance->Dotnet->PipeName.Buffer, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL ) ) ) { ... }
if ( ! Instance->Win32.GetConsoleWindow( ) ) {
    HWND wnd = NULL;
    Instance->Win32.AllocConsole( );
    if ( ( wnd = Instance->Win32.GetConsoleWindow( ) ) )
        Instance->Win32.ShowWindow( wnd, SW_HIDE );
}
...
Instance->Dotnet->StdOut = Instance->Win32.GetStdHandle( STD_OUTPUT_HANDLE );
Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, Instance->Dotnet->File );
```
[source: `Dotnet.c:8`, `37-45`, `55`, `63-71`, `206-207`]

**The sequence:** a named pipe is created **with `FILE_FLAG_FIRST_PIPE_INSTANCE`** (so a second attempt fails rather than silently sharing), a write handle is opened on it, a console is allocated and **immediately hidden** (`ShowWindow(wnd, SW_HIDE)`), the original `STD_OUTPUT_HANDLE` is saved to `StdOut`, and `STD_OUTPUT_HANDLE` is **redirected to the pipe**. The assembly's `Console.Write*` therefore writes into the pipe, `DotnetPushPipe` (line 312) drains it, and `DotnetPush` (347) packages it for the operator.

**Three consequences:**
1. **`AllocConsole` on a process that has no console is itself an event.** A GUI or service process acquiring a console is anomalous, and even hidden, the console is a kernel object attached to the process. The `GetConsoleWindow()` pre-check avoids allocating when one already exists — which means **in a console process the agent does not allocate, but in a service/GUI process it does**, and in that case the hidden console is a detectable artifact.
2. **`SetStdHandle(STD_OUTPUT_HANDLE, …)` modifies process-global state and is never restored** in the read path (the `StdOut` save at 206 exists but the restore is in `DotnetClose`, line 379). While an assembly runs, **any other code in the agent process that writes to `STDOUT` — including a BOF loaded by `CoffeeLdr` — has its output captured into the assembly's pipe** and delivered under the assembly's request ID. Cross-feature output misattribution.
3. **`PIPE_UNLIMITED_INSTANCES` with a 320 KB buffer** per side; a chatty assembly fills the pipe, and since the pipe is `PIPE_TYPE_MESSAGE` (message-mode), each write is a discrete message that the drain must frame. A message larger than the buffer is a documented failure mode for message-mode pipes.

`DotnetPushPipe` (312), `DotnetPush` (347) and `DotnetClose` (379) are the drain/output lifecycle; `DotnetClose` is where the pipe, file handle and `STD_OUTPUT_HANDLE` restore live.

### 11.5 The invocation path — `AppDomain.Load_3` → `EntryPoint` → `Invoke_3`

```c
RgsBound[0].cElements = Assembly.Length;
RgsBound[0].lLbound   = 0;
Instance->Dotnet->SafeArray = Instance->Win32.SafeArrayCreate( VT_UI1, 1, RgsBound );
...
if ( ( Result = Instance->Dotnet->ICorRuntimeHost->lpVtbl->CreateDomain( ..., AppDomainName.Buffer, NULL, &AppDomainThunk ) ) ) { ... }
if ( ( Result = Instance->Dotnet->AppDomainThunk->lpVtbl->QueryInterface( ..., &xIID_AppDomain, (LPVOID*)&AppDomain ) ) ) { ... }
if ( ( Result = Instance->Win32.SafeArrayAccessData( SafeArray, &AssemblyData.Buffer ) ) ) { ... }
MemCopy( AssemblyData.Buffer, Assembly.Buffer, Assembly.Length );
Result = SafeArrayUnaccessData( SafeArray );
if ( ( Result = Instance->Dotnet->AppDomain->lpVtbl->Load_3( Instance->Dotnet->AppDomain, SafeArray, &Assembly ) ) ) { ... }
if ( ( Result = Instance->Dotnet->Assembly->lpVtbl->EntryPoint( Instance->Dotnet->Assembly, &MethodInfo ) ) ) { ... }
```
[source: `Dotnet.c:144-183`]

- **`SafeArrayCreate(VT_UI1, 1, bound)`** wraps the assembly bytes in a COM-safe array — the `ICorRuntimeHost` byte-array ABI for `Load_3`. The byte array is allocated by COM, then filled by copying the agent-side assembly buffer into it. **The assembly exists at least twice in the process** (agent heap + safe array) and the COM copy is `CF`-visible memory.
- **`CreateDomain(AppDomainName.Buffer, …)`** creates a **new AppDomain named by `Instance->Dotnet->AppDomainName`** — operator/profile-controlled. A new domain per assembly, rather than loading into the default domain, is why repeated assemblies are possible — and each domain is a persistent CLR allocation that is **not unloaded** on the success path. Repeated `assembly-inline-execute` calls grow the CLR heap monotonically.
- **`Load_3` is the `byte[]` overload** — `Load(byte[])` — which is the in-memory load. This is the method that produces **no module on the file system and no `Assembly.LoadFile` path in the loader log**. Windows .NET has ".NET assembly load" ETW events (`Microsoft-Windows-DotNETRuntime` / `Loader` keyword) that still fire; **if ETW is not patched, `Load_3` is directly observable**, which is precisely why the AMSI/ETW bypass below exists.
- **`EntryPoint` retrieves the `Main` method**, and `Invoke_3` (209) calls it with a `VT_VARIANT` safe array holding one `VT_ARRAY|VT_BSTR` argument vector — so the assembly must have a `Main(string[])`-compatible entry point. The comment at 185 states the API's own convention: *"Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()"*.

### 11.6 Argument marshalling — and the deliberate first-argument drop

```c
Instance->Dotnet->MethodArgs = Instance->Win32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );
ArgumentsArray = Instance->Win32.CommandLineToArgvW( Arguments.Buffer, &ArgumentsCount );
ArgumentsArray++;
ArgumentsCount--;
Instance->Dotnet->vtPsa.vt     = ( VT_ARRAY | VT_BSTR );
Instance->Dotnet->vtPsa.parray = Instance->Win32.SafeArrayCreateVector( VT_BSTR, 0, ArgumentsCount );
for ( LONG i = 0; i < ArgumentsCount; i++ ) {
    if ( ( Result = Instance->Win32.SafeArrayPutElement( Instance->Dotnet->vtPsa.parray, &i, Instance->Win32.SysAllocString( ArgumentsArray[ i ] ) ) ) ) { ... }
}
```
[source: `Dotnet.c:185-199`]

**`ArgumentsArray++; ArgumentsCount--;` drops the first token.** The raw `Arguments` string arrives as e.g. `"some.exe arg1 arg2"` and `CommandLineToArgvW` splits it into `["some.exe","arg1","arg2"]`. The first element is discarded because the operator's argument string is conventionally typed with a dummy program name first (matching how a .NET assembly's `Main` expects args *after* the exe). **An operator who supplies bare arguments without that leading token silently loses their first argument** — it becomes the discarded element. This is a genuine usability trap with no validation and no error.

`SysAllocString` allocations are handed to COM and **never freed** — BSTR leaks per argument, per invocation. `CommandLineToArgvW`'s returned block is `LocalFree`'d by no path here either.

### 11.7 `AmsiPatched` and the AMSI/ETW bypass — `AMSIETW_PATCH_HWBP`

```c
BOOL AmsiPatched = FALSE;
...
/* if Amsi/Etw bypass is enabled */
if ( Instance->Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_HWBP )
{
#if _WIN64
    PackageInfo = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, Instance->Dotnet->RequestID );
    PackageAddInt32( PackageInfo, DOTNET_INFO_PATCHED );
    AmsiIsLoaded = TRUE;
    if ( ! Instance->Modules.Amsi ) { AmsiIsLoaded = RtAmsi(); }
    if ( ! NT_SUCCESS( HwBpEngineInit( NULL, NULL ) ) ) { return FALSE; }
    ThreadId = U_PTR( Instance->Teb->ClientId.UniqueThread );
    if ( AmsiIsLoaded ) {
        if ( ! NT_SUCCESS( Status = HwBpEngineAdd( NULL, ThreadId, Instance->Win32.AmsiScanBuffer, HwBpExAmsiScanBuffer, 0 ) ) ) { return FALSE; }
    }
    if ( ! NT_SUCCESS( HwBpEngineAdd( NULL, ThreadId, Instance->Win32.NtTraceEvent, HwBpExNtTraceEvent, 1 ) ) ) { return FALSE; }
    PackageTransmit( PackageInfo );
#else
#endif
}
else if ( Instance->Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_MEMORY ) {
    /* todo: add memory patching technique */
}
else {
    /* no patching */
}
```
[source: `Dotnet.c:17`, `86-135`]

**This is "patchless" AMSI/ETW bypass via hardware breakpoints**, and the mechanism is the most technically interesting thing in this file:

1. **`HwBpEngineInit(NULL, NULL)`** installs the vectored exception handler machinery (§11.8).
2. **`HwBpEngineAdd(NULL, ThreadId, AmsiScanBuffer, HwBpExAmsiScanBuffer, 0)`** places a **hardware breakpoint (DR0-DR3) on `amsi!AmsiScanBuffer`'s first instruction**, for the *current thread only* (`ThreadId` from the TEB, line 107).
3. **The exception handler `HwBpExAmsiScanBuffer` catches `EXCEPTION_SINGLE_STEP` at that address** and rewrites the context to skip the real function — returning a benign result.
4. **`HwBpEngineAdd(NULL, ThreadId, NtTraceEvent, HwBpExNtTraceEvent, 1)`** does the same for ETW's `NtTraceEvent`.

**The genuine technical advance here is that no byte in `amsi.dll` or `ntdll.dll` is modified.** `AmsiScanBuffer`'s code is untouched, so an integrity check that hashes `.text` of `amsi.dll` — which every competent AMSI bypass detector now does — finds nothing. The evasion lives in the **debug registers**, which are per-thread CPU state, and it applies only to threads the engine was told to arm.

**The limits are severe and are real:**
- **The bypass is per-thread and applies to one thread.** Arming only the agent's own dispatcher thread means **an assembly that spawns a thread and calls AMSI from it is fully scanned** — the hardware breakpoint does not follow. .NET assemblies routinely call `Assembly.Load` on the entry thread, so this usually suffices for assembly loading; it does not cover a threading assembly.
- **`#if _WIN64`** guards the whole block (89). **The x64 hardware-breakpoint engine is the only implementation — on a 32-bit agent, selecting `AMSIETW_PATCH_HWBP` silently does nothing** and the `else if (AMSIETW_PATCH_MEMORY)` branch falls to a `/* todo: */` comment (131). **Both AMSI bypass options are no-ops on x86**: HWBP is compiled out, MEMORY is unimplemented. An operator configuring AMSI bypass on an x86 Demon gets no bypass at all and no warning.
- **`AMSIETW_PATCH_MEMORY` is entirely unimplemented** (131) — the classic `AmsiScanBuffer` byte-patch is not present in this codebase. This is a notable absence given how standard that technique is.
- **`RtAmsi()` conditionally loads `amsi.dll`.** If AMSI is not already loaded, **the agent loads it deliberately** (98) in order to breakpoint it. A process that loads `amsi.dll` and then never scans is a detectable inversion.
- **`AmsiPatched` (line 17) is a file-scope `BOOL` that is written nowhere and read nowhere else in this file** — a vestigial flag from an earlier design (the process-wide patch approach), left declared. It is a dead global.
- **The four DR registers limit the total number of breakpoints**, and `HwBpEngineAdd` takes an engine and thread — so AMSI + ETW consume 2 of the 4 available slots on that thread, leaving 2 for any other use of the same engine.

### 11.8 `HwBpEngine` / `HwBpExceptions` — the hardware breakpoint framework

`core/HwBpEngine.c` and `core/HwBpExceptions.c` (with `Clr.h`-adjacent declaration at `Dotnet.c:103-121`) provide:
- **A per-thread debug-register allocation engine** — `HwBpEngineAdd(Engine, ThreadId, Target, Handler, Index)` where `Index` (0 or 1 above) selects which of DR0-DR3 to occupy, and the handler is a function pointer invoked on `EXCEPTION_SINGLE_STEP`.
- **`HwBpEngineInit(GlobalEngine, LocalEngine)`** — a global engine shared process-wide, and a per-thread local engine.
- **`HwBpExAmsiScanBuffer` / `HwBpExNtTraceEvent`** — the two shipped handlers, in `HwBpExceptions.c`.

The `#include <core/HwBpExceptions.h>` at `Dotnet.c:5` is what binds them. **The debug registers are set through `NtSetContextThread`/`NtGetContextThread`** — two of the eleven addresses in the CFG whitelist (§2.5). A process whose `CONTEXT` is repeatedly read and written with `DR0-DR3` populated, by a thread that is not in a debugger, is running this engine and nothing benign looks like that.

### 11.9 What this file means for detection and for the operator

**Detection:**
1. **`mscoree!CLRCreateInstance` called from a thread that is not a managed app** — the CLR is hosted by a process the loader would not expect. `Microsoft-Windows-DotNETRuntime` ETW records the runtime start; if ETW is unpatched, this is a direct hit.
2. **A new AppDomain created with an operator-chosen name**, and `Load(byte[])` called on a byte array — the CLR's `AppDomain.Load` on a `byte[]` with no file behind it is the canonical in-memory assembly execution signature.
3. **`AllocConsole` + `SetStdHandle(STD_OUTPUT_HANDLE)` redirect to a named pipe** in a process with no console — a very specific behavioural cluster.
4. **`CONTEXT` reads/writes carrying DR0-DR3 populated on a non-debugged thread** — the hardware-breakpoint bypass itself, and the only reliable way to detect it, since no code is modified.
5. **`amsi.dll` loaded into a process that never legitimately scans** — the `RtAmsi()` load is an inversion.
6. **The GUIDs in `.data`** identify the capability even under sleep obfuscation.

**Operator-facing traps:**
7. **AMSI/ETW bypass is x64-only and half unimplemented** — HWBP is `#if _WIN64`, MEMORY is a `TODO`. An x86 agent has no bypass option that works.
8. **The bypass covers one thread.** A multithreaded assembly is scanned.
9. **The first argument token is always discarded** (188-189) — an operator must type a dummy program name first or lose an argument.
10. **AppDomains and BSTRs leak per invocation** — repeated assembly execution grows the process monotonically.
11. **`STD_OUTPUT_HANDLE` is redirected process-wide during an assembly run**, so concurrent BOF output is captured under the assembly's request ID.
12. **.NET Framework only.** CoreCLR/.NET 5+ assemblies cannot be loaded through this path at all.

### 11.10 Residual unknowns

`HwBpEngine.c`, `HwBpExceptions.c` and `Runtime.c`'s `RtAmsi()` were identified and their interfaces read from the call sites, but the debug-register manipulation and the exact exception-handler byte-patching logic were not read line-by-line. The `DOTNET_INFO_*` status codes (including `DOTNET_INFO_PATCHED` at 93 and `DOTNET_INFO_NET_VERSION` at 139) and the `Dotnet` field layout in `Demon.h` are not fully enumerated here.

---

## 12. `core/ObjectApi.c` — THE BEACON API IMPLEMENTED FOR BOFs

734 lines, 31 functions. This is the concrete realisation of §9.2's symbol table: it is the host-side implementation of the Cobalt Strike Beacon Object File API that `CoffeeLdr.c` binds into every loaded BOF.

### 12.1 The three string-named loader helpers

```c
PVOID LdrModulePebString( PCHAR ModuleString )
PVOID LdrFunctionAddrString( PVOID Module, PCHAR Function )
BOOL  LdrFreeLibrary( HMODULE hLibModule )
```
[source: `payloads/Demon/src/core/ObjectApi.c:20`, `26`, `32`]

These sit **in front of** the hash-based resolvers of §7 — BOFs and forwarded imports call them with plaintext names, so `ObjectApi.c` is the one place in the agent where module and function names exist as strings at runtime. They delegate to `LdrModulePebByString` / `LdrFunctionAddr` (`Win32.c:99`, `130`), so the plaintext exists in the *caller's* BOF and in these arguments, not in the agent's own image.

### 12.2 The `datap` parser — and the duplicate of §7A

```c
VOID BeaconDataParse( PDATA parser, PCHAR buffer, INT size )
{
    if ( parser == NULL ) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size - 4;
    parser->size     = size - 4;
    parser->buffer   += 4;
}
```
[source: `ObjectApi.c:143-153`]

**`parser->length = size - 4` skips the first four bytes — the BOF argument blob's own big-endian total-length prefix**, matching §9.4. `size` is `INT` (signed) here, unlike `Parser.c`'s `UINT32`, so a `size` below 4 yields a **negative** `length` rather than a wrapped one. **Every subsequent guard is `parser->length < N` against a signed value, so a negative `length` correctly fails all of them** — the `datap` parser is *not* vulnerable to the wrap in the same way. That is an accidental but real difference between the two parsers.

**The extract function, however, is not safe:**
```c
PCHAR BeaconDataExtract( PDATA parser, PINT size )
{
    INT   Length = 0;
    PVOID Data   = NULL;

    if ( parser->length < 4 ) return NULL;

    MemCopy( &Length, parser->buffer, 4 );
    parser->buffer += 4;

    Data = parser->buffer;
    if ( Data == NULL ) return NULL;

    parser->length -= 4;
    parser->length -= Length;
    parser->buffer += Length;

    if ( size != NULL ) *size = Length;

    return Data;
}
```
[source: `ObjectApi.c:190-214`]

**This is the `Parser.c:127` logic, reproduced almost line for line** — same `Length` read from the wire/blob, same `if (Data == NULL)` dead check on a pointer just derived from a non-NULL buffer (203-204), same unconditional `length -= Length`, same `buffer += Length`, same pair of mutations after a guard that only proved four bytes were available.

**The two differences from §7A, both material:**

| | `Parser.c:127` | `ObjectApi.c:190` |
|---|---|---|
| `Length` type | `UINT32` — wraps to `0xFFFFFxxx` | `INT` — **goes negative** |
| Guard after mutation | `while (Parser.Length > 12)` — compares **unsigned**, stays TRUE → infinite loop | BOF's own loop over `BeaconDataExtract` — `length < 4` on a **negative** value is FALSE, so the loop **terminates** |
| Consequence | unbounded dispatch + heap over-read of attacker-chosen length | **`parser->buffer` walked past the blob, `parser->length` negative; the over-read happens only for the extract that crosses the end** |

**Because `Length` is signed here, a negative `parser->length` makes the BOF's own `while (length > 0)` / `< 4` checks fail closed** — so the `datap` path degrades to a bounded over-read on the final extract rather than the unbounded corruption of §7A. **But the out-of-bounds read still occurs**: `Data` is returned pointing into the blob and `*size` is set to the attacker/operator-declared `Length`, so a BOF that reads `size` bytes from `Data` reads past the blob regardless of what the parser's own bookkeeping did afterwards.

**The correct fix is the same as §7A.7** — compare `Length` against the remaining bytes **before** mutating — and the fact that the same three lines were written twice with the same missing check means the defect is a **pattern in this codebase, not a typo**. Any other length-prefixed reader in the agent should be assumed to share it until read.

### 12.3 Output routing — `GetRequestIDForCallingObjectFile` (line 224)

```c
PCOFFEE Entry = Instance->Coffees;
if ( ! CoffeeFunctionReturn || ! RequestID ) return FALSE;
while ( Entry )
{
    if ( ( ULONG_PTR ) CoffeeFunctionReturn >= ( ULONG_PTR ) Entry->ImageBase &&
         ( ULONG_PTR ) CoffeeFunctionReturn <  ( ( ULONG_PTR ) Entry->ImageBase + Entry->BofSize ) )
    {
        *RequestID = Entry->RequestID;
        return TRUE;
    }
    Entry = Entry->Next;
}
PUTS( "Failed to find the RequestID for the calling BOF" )
return FALSE;
```
[source: `ObjectApi.c:224-246`]

**This is how output is attributed to the right BOF when several are resident.** `BeaconPrintf` and `BeaconOutput` resolve the caller's address via `__builtin_return_address(0)` (line 257) and search the `Instance->Coffees` list for the BOF image containing it. The file's own comment states the reason precisely: *"this is so that the TS can identify which BOF is sending the output data. This is needed because you can have more than one BOF mapped in memory at the same time."*

**The comment is the finding: multiple BOFs can be resident simultaneously and persist.** `Instance->Coffees` is a list of `COFFEE{ImageBase, BofSize, RequestID, Next}`, and nothing in the read path removes an entry after the BOF returns. **Every `inline-execute` adds an entry that stays**, so the list grows and the agent retains every BOF's executable image for its lifetime. Output attribution uses a containment test over that list, so a BOF whose image is no longer executing but remains resident still owns its address range — and a BOF image that is later unmapped and **reused by a different allocation** would have its output attributed to the stale entry.

### 12.4 The output verbs

| Function | Line | Notes |
|---|---|---|
| `BeaconPrintf(INT Type, PCHAR fmt, ...)` | 248 | `__builtin_return_address(0)` → request-ID lookup → `vsnprintf` into a callback buffer → package |
| `BeaconOutput(INT Type, PCHAR data, INT len)` | 305 | raw bytes, no formatting |
| `BeaconIsAdmin(...)` | 324 | elevation check, wraps `TokenElevated` (§8.5) |
| `BeaconInformation(BEACON_INFO *info)` | 578 | fills the BOF's metadata struct |

**`BeaconPrintf` uses `Type` as the output channel** — the Beacon convention (`CALLBACK_OUTPUT`, `CALLBACK_ERROR`, `CALLBACK_DEBUG`, etc.). The agent maps the type onto the package so the operator's client renders it coloured by severity. `vsnprintf` into a `CallbackOutput` buffer sized by `CallbackSize` is the format step; the format string comes from the BOF, so a mismatched format string is the BOF author's bug and can over-read the varargs.

### 12.5 The format buffer — `BeaconFormat*` (lines 343-424)

| Function | Line | Behaviour |
|---|---|---|
| `BeaconFormatAlloc(PFORMAT format, int maxsz)` | 343 | allocates `maxsz` |
| `BeaconFormatReset(PFORMAT format)` | 354 | resets the cursor |
| `BeaconFormatFree(PFORMAT format)` | 361 | frees |
| `BeaconFormatAppend(PFORMAT format, char* text, int len)` | 377 | appends raw |
| `BeaconFormatPrintf(PFORMAT format, char* fmt, ...)` | 384 | formatted append |
| `BeaconFormatInt(PFORMAT format, int value)` | 411 | appends a 4-byte int |

These implement the `formatp` capture buffer BOFs use to accumulate a `datap` for a subsequent call. **`BeaconFormatAppend` grows the buffer** — the growth policy and whether it caps at `maxsz` is the safety question; an unbounded append loop in a BOF that ignores the cap grows the agent's heap.

### 12.6 The key/value store — `BeaconAddValue` / `BeaconGetValue` / `BeaconRemoveValue`

```c
BOOL BeaconAddValue(const char * key, void * ptr)
{
    PCOFFEE_KEY_VALUE KeyValue  = NULL;
    SIZE_T            KeyLength = 0;

    if ( ! key ) { PUTS( "No key was provided" ); return FALSE; }
    KeyLength = StringLengthA( key );
    if ( KeyLength == 0 ) { PUTS( "The key is too short" ); return FALSE; }
    if ( KeyLength >= COFFEE_KEY_VALUE_MAX_KEY ) { PRINTF( "The key %s is too long\n", key ); return FALSE; }

    // make sure the key doesn't already exist
    KeyValue = Instance->CoffeKeyValueStore;
    while ( KeyValue )
    {
        if ( StringCompareA( KeyValue->Key, key ) == 0 ) { PRINTF( "The key %s already exists\n", key ); return FALSE; }
        KeyValue = KeyValue->Next;
    }

    KeyValue = Instance->Win32.LocalAlloc( LPTR, sizeof( COFFEE_KEY_VALUE ) );
    KeyValue->Value = ptr;
    StringCopyA( KeyValue->Key, key );
    KeyValue->Next = Instance->CoffeKeyValueStore;
    Instance->CoffeKeyValueStore = KeyValue;

    return TRUE;
}
```
[source: `ObjectApi.c:584-631`]

**This is the best-validated function in the entire agent.** Three explicit checks (NULL key, zero-length key, key at/over `COFFEE_KEY_VALUE_MAX_KEY`), a duplicate-key rejection that walks the whole list, insertion at the head, and a `LocalAlloc` result that is used without a NULL check (line 621-623 — the one gap).

**`StringCopyA(KeyValue->Key, key)` after a `KeyLength >= COFFEE_KEY_VALUE_MAX_KEY` rejection is size-correct** — the check guarantees `key` fits the destination. This is the only place in the read files where a copy's bound is provably established before the copy, and it is worth noting because it shows the author *knew* how to do this and did it here while omitting it in `Parser.c:127` and `ObjectApi.c:190`.

**`BeaconRemoveValue` (656)** uses the standard two-pointer unlink. **The value pointer is not freed** — the store holds a BOF-supplied `void*`, and removal unlinks the node without knowing whether the pointer is heap, a handle, or a stack address the BOF already returned from. **A BOF that calls `BeaconAddValue(key, &local)` and returns leaves a dangling pointer in the agent's store**, which `BeaconGetValue` will hand back to a later BOF. This is a cross-BOF dangling-pointer path with no lifetime contract — the store is deliberately untyped and there is no way for the agent to validate it.

### 12.7 The process and token verbs

| Function | Line | Behaviour |
|---|---|---|
| `BeaconUseToken(HANDLE token)` | 425 | `TokenImpersonate` (§8.5) |
| `BeaconGetSpawnTo(BOOL x86, char* buffer, int length)` | 440 | returns the configured spawn path |
| `BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO*, PROCESS_INFORMATION*)` | 463 | creates the spawn host |
| `BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len)` | 487 | `Inject()` (§10.3) |
| `BeaconInjectTemporaryProcess(PROCESS_INFORMATION*, payload, p_len, p_offset, arg, a_len)` | 530 | `Inject()` into own child |
| `BeaconCleanupProcess(PROCESS_INFORMATION*)` | 564 | terminates/frees the spawned process |
| `BeaconDataStoreProtectItem(SIZE_T)` / `BeaconDataStoreUnprotectItem(SIZE_T)` | 697 / 704 | protects stored items |
| `BeaconGetCustomUserData()` | 718 | returns profile-supplied custom data |
| `toWideChar(char*, wchar_t*, int max)` | 724 | `CharStringToWCharString` |

**`BeaconInjectProcess` and `BeaconSpawnTemporaryProcess` give a BOF the agent's entire injection capability** — so a BOF can perform injection using Havoc's `Inject()` with whatever technique the agent is configured for, without the BOF containing any injection code. **The injection primitives are a service the BOF calls, not code the BOF carries** — which is why "detect the injector by finding shellcode in the BOF" fails, and why the `PROCESS_ALL_ACCESS` request of §10.3 appears even for a BOF that never mentions injection.

**`BeaconGetSpawnTo` returns the configured spawn path** into a BOF-supplied `buffer` of BOF-supplied `length` — the path is the profile's `Werfault.exe` (or whatever the operator set), so **a BOF asking for the spawn path receives the operator's configured host process**, tying the BOF's injection behaviour to the profile.

### 12.8 Findings summary

1. **`BeaconDataExtract` (190) duplicates the §7A defect** — same missing bound check, same dead `Data == NULL` test. Signed `INT` makes it degrade to a bounded over-read instead of unbounded corruption, but the out-of-bounds read is real. **The defect is a pattern in this codebase.**
2. **`Instance->Coffees` grows monotonically** — every BOF's executable image is retained, and output attribution uses containment over that list, so a stale entry can capture a later allocation's output (224-246).
3. **`BeaconAddValue` permits cross-BOF dangling pointers** — the value is an untyped `void*` with no lifetime contract; a BOF that stores a stack address and returns leaves the agent holding it (584-631).
4. **`BeaconAddValue`'s `LocalAlloc` result is not NULL-checked** (621-623) — the one gap in an otherwise exemplary function.
5. **BOFs can drive the agent's full injection, token and spawn machinery** through the Beacon API — the capability is a *service*, not BOF-contained code, so its artifacts (maximal access masks, private executable regions, signed-host spawns) appear without the BOF containing them.
6. **`BeaconUseToken` connects a BOF directly to the token vault** (§8.5) — a BOF can impersonate any vault token, and because impersonation is thread-scoped while the flag is process-global (§8.8 item 6), a BOF that impersonates and returns leaves the flag inconsistent.

### 12.9 Residual unknowns

`BeaconFormatAppend`'s growth and cap policy, the exact package/`Type` mapping in `BeaconPrintf`, the `BEACON_INFO` struct layout, and `BeaconDataStoreProtectItem`'s protection mechanism were not read line-by-line. `Instance->Coffees` entry removal — whether any path frees a `COFFEE` node after its BOF returns — was not found in the read paths and is treated as absent rather than proven absent.

---

## 13. RESIDUAL UNKNOWNS

What is **not** settled by this report, stated so the boundary of the evidence is explicit rather than implied. Nothing here is a hedge on what *was* read; these are the specific places where the analysis stopped.

### 13.1 Files read but not exhaustively

| File | Read | Not read | Impact |
|---|---|---|---|
| `Demon.c` (790) | full | — | — |
| `core/Command.c` (2,834 logical / 3,504 reader) | dispatcher + all 22 handlers | — | — |
| `core/Package.c` (485) | full | — | — |
| `core/Parser.c` (177) | full | — | — |
| `core/Obf.c` (778) | full | — | — |
| `core/Syscalls.c` (237) | full | — | — |
| `core/Win32.c` (1,734) | 1-349 (hash, PEB, module load) | 350-1734 (export parsing tail, proxy-load completion, filesystem/process helpers) | §7 covers resolution and loading completely; the remaining ~1,385 lines are helpers whose existence is known but whose internals are not |
| `core/Token.c` (1,410) | 1-422 + `ListTokens`/KV surface | 423-1410 internals | §8 covers every documented capability; the handle-table walk's inner loops are characterised by signature, not line-by-line |
| `inject/Inject.c` (351) | 1-175 | 176-351 (`DllInjectReflective`, `DllSpawnReflective` bodies) | §10 covers `Inject()` fully; the reflective-loader paths are characterised by signature |
| `core/Dotnet.c` (573) | 1-230 + `FindVersion`/`ClrCreateInstance` | 231-500 (output drain, `DotnetClose`) | §11 covers hosting, version probe, invocation and AMSI/ETW; the drain lifecycle is characterised |
| `core/ObjectApi.c` (734) | 143-257 + 584-673 | 1-142, 258-583, 674-734 | §12 covers the parser, request-ID routing, output verbs and KV store; the format-buffer and spawn/inject verbs are characterised by signature |
| `core/CoffeeLdr.c` (29.7 KB) | structure, symbol set, execution model | relocation arithmetic, section-characteristic handling | §9 states this explicitly |
| `core/Socket.c` (621) | 1-120 | 121-621 | §6 covers transport and rotation; the socket accept/read loops are characterised |
| `include/common/Defines.h` (371) | 1-45 + hash inventory | 46-371 | §7 covers the hash table; all ~247 constants enumerated in §7 |
| `include/core/Command.h` (241) | full | — | — |
| `include/Demon.h` (567) | full | — | — |
| `include/core/Win32.h` (262) | 1-145 | 146-262 | prototypes only |
| `include/common/Clr.h` | GUID + interface declarations | 689-711 (COM vtable definitions) | §11 covers the hosting chain |

### 13.2 Files identified but not read at all

These exist in the tree and were not opened. Their capabilities are known from the call sites that reach them; their implementations are not:

**Core:** `Memory.c` (the `MmVirtual*`/`MmHeap*` family — the `DX_MEM_*` routing is unresolved, §10.8), `MiniStd.c`, `Jobs.c`, `Download.c`, `Config.c`, `Spoof.c`, `Transport.c`, `TransportHttp.c`, `TransportSmb.c`, `SysNative.c`, `Runtime.c`, `HwBpEngine.c`, `HwBpExceptions.c`, `Pivot.c`, `InjectUtil.c`'s third function beyond signature level, `AesCrypt.c`/`Crypt.c` (the AES and RC4 implementations), `MainDll.c`, `MainSvc.c`, `MainExe.c`.

**Headers:** `Macros.h`, `SleepObf.h` (values read, §5), `Transport.h`, `TransportSmb.h`, `TransportHttp.h` (read, §6), `Jobs.h`, `Download.h`, `Memory.h`, `Inject.h` (read), `InjectUtil.h`, `Spoof.h`, `Thread.h`, `SysNative.h`, `Runtime.h`, `HwBpEngine.h`, `HwBpExceptions.h`, `Dotnet.h`, `Clr.h` (partial), `Pivot.h`, `Crypt.h`, `Native.h`.

**`include/common/Native.h` — 526 KB, 18,580 lines.** Deliberately not read. It is a single-file declaration inventory of NT structures, prototypes and constants; the brief's request for a "declaration inventory only (SSN technique already resolved)" is satisfied at the *technique* level by §7 and `Syscalls.c`/`Syscalls.h` (Hell's Gate + Halo's Gate, no hardcoded SSN table). The file is a vendored-style NT header and its 18,580 lines carry no logic.

**`payloads/DllLdr/`** — `Source/Entry.c` and headers, plus `extract.py`. The reflective loader that `Inject.c:172` consumes. Not read.

**`payloads/Shellcode/`** — the PIC bootstrap that bootstrap the `KAYN_ARGS` handoff described in `Demon.h:37-45`. Not read.

**Remaining assembly** — `payloads/Demon/src/asm/` contains the four files read in §10.5 (`Syscall.x64.asm`, `Syscall.x86.asm`, `Spoof.x64.asm`, `Spoof.x86.asm`). Any further `.asm` under `Shellcode/` or `DllLdr/` was not enumerated.

**The teamserver (Go).** 202 `.go` files, not read. This is the entire server side: the frame handling that produces the `[CommandID][RequestID][len]` header the agent parses, the `DEMON_INITIALIZE` AES key exchange on the server side, the job queue that feeds `GET_JOB`, the SMB pivot listener, the listener profiles and the yaotl profile parser. **The agent half of every one of those is documented in §2-§12; the server half is not.** §3 and §6 state the wire contract as the *agent* implements and expects it, which is authoritative for what the agent will accept, but the server's serialisation was not read to confirm it emits that exact layout.

**`pkg/profile/yaotl/`** — the vendored HCL2 parser (51 `.hcl` files in the tree, plus 42 `.cc`/28 `.hpp`). Derived from OpenTofu/Terraform's HCL implementation. **This is a vendored-dependency, not Havoc code** — it exists to parse the listener/implant profile files and carries no C2 logic. Still enumerated as part of the inventory because the brief requires every file accounted for, but it is third-party and its behaviour is not part of the implant's tradecraft.

### 13.3 Specific technical questions left open

1. **The `DX_MEM_*` routing.** Which of `MmVirtualAlloc`/`MmVirtualWrite`/`MmVirtualProtect` selects a Win32 call vs a direct `Nt*` stub vs an indirect syscall for `DX_MEM_DEFAULT` (0), `DX_MEM_WIN32` (1), `DX_MEM_SYSCALL` (2) is unresolved. §10.2 documents the call *sites* and the mixed usage; the implementations in `Memory.c` were not read. **This means the exact syscall path an injection takes is not pinned down** — only that protection uses the `SYSCALL` selector and allocation uses `DEFAULT`.
2. **Whether `Instance->Coffees` entries are ever freed.** No removal path was found; absence of evidence is not proof of absence (12.9).
3. **`BeaconFormatAppend`'s cap.** Whether the format buffer enforces `maxsz` on append is unread (12.9).
4. **The `INJECTION_CTX` layout** (`inject/Inject.h`) — fields not enumerated.
5. **`DllInjectReflective`/`DllSpawnReflective` internals** — the parameter-block layout passed to the reflective loader is unread.
6. **COFF relocation coverage** — which `IMAGE_REL_*` types the loader handles (9.6).
7. **The teamserver's frame emit** — §3 documents what the agent parses; the server's matching emit was not confirmed by reading.
8. **`RtlExitUserThread` kill-date enforcement** (§3.18) — the exit path is identified; whether any cleanup runs before it is not.
9. **The 247-entry `H_FUNC_*` table's completeness** — counted, with four confirmed duplicate pairs (§7); a full collision check across all 247 entries against their target names was not performed.
10. **`FindVersion`'s call site and the version fallback list** (§11.3) — the function's behaviour is read; where the candidate version list comes from (profile vs hardcode) is not.

### 13.4 Standing corrections to the brief

1. **The file counts in the brief do not match the tree.** Outside `data/`: **38 `.c`, 54 `.h`, 4 `.asm`, 2 `.s`, 3 `.cpp`, 42 `.cc`, 202 `.go`, 51 `.hcl`, 40 `.ui`, 28 `.hpp`, 85 `.png`.** The brief's 420 `.c` / 481 `.h` / 408 `.s` / 190 `.asm` / 191 `.cpp` / 44 `.cc` are inflated by roughly an order of magnitude. Real counts are the ones above.
2. **`T5_havoc.md` §2.2's AgentID sentinel claim is wrong.** Registration is entirely unencrypted and the sentinel is a header-versus-cleartext-body consistency assertion, not authentication (§3).
3. **The SSN technique is Hell's Gate + Halo's Gate, not Tartarus/FreshyCalls**, and there is no hardcoded SSN table (`Syscalls.c:90`, `196-237`). Unambiguous.
4. **The injection code lives in `payloads/Demon/src/inject/`, not `src/core/`** (§10).
5. **The x86 stack-spoofing path is a bare `ret`** (§10.5) — not a partial implementation, a no-op. The brief's assumption of stack spoofing as a general capability holds only on x64.
6. **The `AMSIETW_PATCH_MEMORY` technique is unimplemented** (`Dotnet.c:131`) and `AMSIETW_PATCH_HWBP` is `#if _WIN64`. **Neither AMSI bypass works on a 32-bit agent** (§11.7).
7. **`INJECTION_TECHNIQUE_APC` and `THREAD_METHOD_NTQUEUEAPCTHREAD` are both empty `TODO` stubs** (`Thread.c:271`) — APC injection does not exist in this codebase despite being selectable (§10.4).
8. **`INJECTION_TECHNIQUE_DEFAULT` is `SYSCALL`, and `Demon.c:787` sets it** — so syscall-based thread creation is the default, while memory allocation still uses the Win32 path (§10.2). The config option's name overstates its reach.
9. **The `Parser.c:127` wraparound is duplicated in `ObjectApi.c:190`** — the same missing bound check written twice (§12.2). The defect is a pattern.

### 13.5 What the evidence does establish, without qualification

- **The complete DEMON_INITIALIZE handshake at code level**, including the `Key == NULL && IV == NULL` AND-bug in the key-generation guard (`Demon.c:112-123`) and the `Package.c:253` key/IV cleartext carve-out.
- **The complete CommandID dispatch table** — 22 handler entries plus a `{0, NULL}` sentinel, and 10 header-only IDs (`Command.h:7-30`, `Command.c:16-42`).
- **Both wire frame layouts**, agent-to-server and server-to-agent, at byte level (§3, §4, §6).
- **The `Parser.c:127` wraparound** end to end: attacker-controlled length, why the `UINT32` subtraction wraps, all four defeated guards, the `while (Parser.Length > 12)` loop defeat, and the path to a heap disclosure (§7A).
- **The full sleep-obfuscation set** — Ekko, Zilean and Foliage, the RC4-via-`SystemFunction032` mechanism, the 13-`CONTEXT` ROP frames, the `.text`-only encryption gap, and the protection-transition signal (§5).
- **The full injection set** — three sequences, three memory selectors, four thread methods, the x64 stack-spoof trampoline and the x86 no-op (§10).
- **The token and Kerberos surface** — steal, duplicate, vault, handle-table enumeration, impersonation, and LSASS-cache ticket extraction without elevation (§8).
- **The BOF/COFF loader and its Beacon API** — symbol set, key/value store, per-BOF output attribution, and the fact that BOFs are handed the agent's injection and token machinery as a service (§9, §12).
- **The DJB2 API-resolution scheme**, the four proxy-loading modes, and the no-verification failure mode (§7).
- **The in-memory .NET path** — CLR hosting chain, `v4.0.30319` probe, AppDomain per assembly, the named-pipe/console output capture, and the hardware-breakpoint AMSI/ETW bypass (§11).

---

## 14. CLOSING NOTE ON METHOD AND COVERAGE

`T5_havoc.md` (758 lines) documented this target at the protocol level. This report goes beneath it: every section above is written against function bodies, control flow and exact source lines, and **supersedes T5 wherever the two conflict** — the three conflicts identified are recorded in §13.4 items 2, 3 and 5.

The evidence standard throughout: `[source: relative/path:line]` on every technical claim, real code quoted verbatim rather than paraphrased, and defects stated with the exact line that carries them. Where a claim is inference rather than observation it is marked as such. Where the analysis stopped, §13 says so by file and by line range rather than trailing off.

The three findings with the most operational weight, in order:

1. **§7A — the `Parser.c:127` `UINT32` wraparound.** The only defect in the target that is remotely triggerable through the C2 channel, defeats four correctly-written guards, breaks the dispatcher's own loop condition, and yields an attacker-chosen-length heap read inside the agent. Its twin in `ObjectApi.c:190` makes it a codebase pattern rather than a single oversight.
2. **§8 — unprivileged LSASS ticket extraction.** `LsaConnectUntrusted` + `LsaLookupAuthenticationPackage` + `LsaCallAuthenticationPackage` needs no elevation to read the calling session's own TGT and service tickets, which is the head of the delegation chain that ends in domain admin. Nothing else in the token block has that property.
3. **§3.3 / §4 — the fixed-IV, unauthenticated task channel.** A 16-byte IV generated once per session and never rotated makes AES-CTR a many-time pad, and the task-stream header is cleartext and unauthenticated. This is what makes §7A reachable by anyone who can write to the channel rather than only by the legitimate operator.
