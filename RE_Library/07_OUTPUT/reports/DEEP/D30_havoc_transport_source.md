# D30 (Havoc half) — TRANSPORT SOURCE, AND A CORRECTION TO MY OWN DISPATCH CLAIM

**Target:** `RE_Library/01_SOURCE_c2/havoc/payloads/Demon/`
**Authored by:** havoc-deep, for msf-diver's D30 three-column encoder comparison.
**This file is Havoc's column. D30 itself is msf-diver's artifact and is not written here.**
**Source-only C. No REA, no Ghidra. Every count enumerated. Every `[absence]` positive-controlled.**

---

## TABLE OF CONTENTS

| § | Subject |
|---|---|
| **1** | Scope, and what this file is for |
| **2** | **VERIFICATION: the no-`default` dispatch claim — CORRECTED, and "silently" upheld** |
| **3** | The three transport headers — the interface the author defined |
| **4** | `TransportHttp.c` — every step before the first byte hits the carrier |
| **5** | `TransportSmb.c` — the same, for the SMB carrier |
| **6** | **THE COMPARISON: is the framing carrier-independent?** |
| **7** | Residual unknowns and coverage |

---

## 1. SCOPE, AND WHAT THIS FILE IS FOR

msf-diver is building **D30**, a three-column comparison of encoder/framing design across Sliver, Pupy, and Havoc. **Havoc's column depends on two facts that originate in my D12 and D15 reports, and the Lead asked me to re-verify the first of them before another lane publishes on it.**

| Deliverable | § | Status |
|---|---|---|
| Re-confirm there is no `default` branch and unknown commands are dropped | **§2** | **CLAIM CORRECTED, CONCLUSION UPHELD** |
| `TransportHttp.c` vs `TransportSmb.c` — is framing carrier-independent? | **§3–§6** | **ANSWERED** |
| The three transport headers as the author's definition of a transport | **§3** | **ANSWERED** |

### 1.1 Method note the Lead flagged, and it was the right warning

**The Lead's warning: "a grep for `Transport` in `payloads\Demon\` will return hits for the interface, the two implementations, and probably includes; the shapes differ and a flat search will mislead you."**

**That warning was correct, and it bit immediately.** A flat search for `Transport` returns macro names, `#ifdef TRANSPORT_HTTP` guards, include paths, function names, and struct fields — **at least five different shapes of occurrence**, and a count over them means nothing.

**Everything in §3–§6 comes from reading the files**, with grep used only to *locate* and never to *count* a claim.

### 1.2 Instrument record (mandatory)

| # | Instrument | Result |
|---|---|---|
| I1 | `Select-String '^func '`-style enumeration applied to C's function grammar | **Inapplicable** — C function definitions span `RETURN_TYPE name(\n args\n)` across lines. A single-line `^[A-Za-z].*\(` heuristic **matches function signatures, declarations, and macro invocations alike**. Abandoned for §4–§5 in favour of reading, per §1.1. |
| I2 | Counting `Transport` occurrences as a proxy for "transport surface" | **Rejected.** Five occurrence shapes; the count is not a measurement of anything. |
| I3 | `Get-Content \| Select-Object -Skip N` for line-anchored reading | **Produced line N+1, not N.** Third recurrence of this offset in this corpus (D11, D19 §6.6). **All line numbers in this report come from `Select-String` or direct array indexing, never from a `-Skip` display.** |
| I4 | Second-method rule applied to `DemonCommands[]` table size | **Applied** — `.ID =` count **23**, `.Function =` count **23**, agree. §2.3 |

---

## 2. VERIFICATION: THE NO-`default` DISPATCH CLAIM — CORRECTED, AND "SILENTLY" UPHELD

**The Lead asked me to re-confirm this from source because msf-diver will verify it, and to say whether "silently dropped" is literally true or whether there is a log line, counter, or side effect.**

**The verdict, up front: the conclusion is correct but my stated mechanism was wrong, and the correction makes the conclusion stronger rather than weaker. There IS a log line — and it is compiled out of every release build, so "silently" is literally true for a deployed agent.**

### 2.1 CORRECTION: it is not a `switch` with no `default`. It is a table lookup with no `else`.

**D12 and D15 described Havoc's dispatch as a `switch` lacking a `default` branch. That is not what the code is.** The command dispatcher is a **linear search over a function-pointer table**:

```c
SEC_DATA DEMON_COMMAND DemonCommands[] = {
        { .ID = DEMON_COMMAND_SLEEP,                    .Function = CommandSleep                    },
        { .ID = DEMON_COMMAND_CHECKIN,                  .Function = CommandCheckin                  },
        ...
        { .ID = DEMON_EXIT,                             .Function = CommandExit                     },

        // End
        { .ID = 0, .Function = NULL }
};
```
[source: `payloads/Demon/src/core/Command.c:16-42`, condensed — 23 entries + sentinel]

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
[source: `payloads/Demon/src/core/Command.c:113-123` — the lookup loop, verbatim]

**Why the distinction matters for D30:** a `switch` with no `default` falls through to whatever follows the switch. **This loop, on an unmatched `CommandID`, exhausts the table, hits the `NULL` sentinel at `:114-116`, and `break`s out — with no `else`, no error return, no state change, and no response.** The *effect* is the same; the *mechanism* is different, and a report that names the wrong construct will fail msf-diver's verification on a technicality while being right in substance.

**This is the same class as D12's own F1 finding** — dispatch registration in Havoc is a table literal, not `case` labels. **I made that observation for the handler-registration direction and then described the caller as a switch. Both halves of the same file are table-driven.**

### 2.2 Is "silently dropped" literally true? YES for release builds, and here is the decisive line

**There IS a log statement — `PRINTF` at `:107` — but it fires for every command regardless of match, and in a release build it is the empty statement.**

```c
if ( CommandID != DEMON_COMMAND_NO_JOB ) {
    PRINTF( "Task => RequestID:[%d : %x] CommandID:[%d : %x] TaskBuffer:[%x : %d]\n", RequestID, RequestID, CommandID, CommandID, TaskBuffer, TaskBufferSize )
```
[source: `payloads/Demon/src/core/Command.c:106-107`]

**The macro, verbatim:**

```c
// DEBUG
#ifdef DEBUG
#if SEND_LOGS
#define PRINTF( f, ... )                { DemonPrintf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { ; }
#elif SVC_EXE
#define PRINTF( f, ... )                { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#elif SHELLCODE
#define PRINTF( f, ... )                { LogToConsole( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { LogToConsole( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#else
#define PRINTF( f, ... )                { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#endif
#else
#define PRINTF( f, ... )                { ; }
#define PRINTF_DONT_SEND( f, ... )      { ; }
#endif
```
[source: `payloads/Demon/include/common/Macros.h:41-59`]

**`Macros.h:56-58`: when `DEBUG` is undefined, `PRINTF(...)` expands to `{ ; }` — a null statement.** The `:107` log therefore **does not exist in any release build of the agent**, and it is not an unmatched-command diagnostic in any build — it logs the *incoming task* for every `CommandID`, matched or not.

**So:**
| Build | Is the dropped command logged? | Is "silently dropped" true? |
|---|---|---|
| `DEBUG` + `SEND_LOGS` | yes, via `DemonPrintf`, **but it logs all commands, not the failure** | no — but the log is not a failure signal |
| `DEBUG` + `SVC_EXE` / `SHELLCODE` / default | yes, via `DbgPrint`/`LogToConsole`/`printf` | no — same caveat |
| **release (no `DEBUG`)** | **no — `{ ; }`** | **yes, literally** |

### 2.3 No counter, no side effect, no error surface — verified by three probes

The Lead asked specifically about "a log line, a counter, or a side effect." All three checked:

| Probe | Result |
|---|---|
| Any `else` clause paired with the lookup `if` | **none** — `:113-123` is a `for` containing two `if`s, both `break`-terminated |
| Any error return, flag write, or response emission on the unmatched path | **none** — the loop exits to `:124` (`} while ( Parser.Length > 12 )`), which continues the outer parse loop |
| Any counter incremented for unmatched commands | **none** — the only variable is `FunctionCounter`, which is the loop index and is discarded |

[source: `payloads/Demon/src/core/Command.c:113-124`, read in full]

**Positive control for these absences:** the same three probes applied to a path that *does* signal failure **find it**. `PUTS( "SMBGetJob failed" )` at `:92` and `PUTS( "TransportSend: Failed" )` at `:136` are both explicit failure emissions on adjacent paths in the same function. **The probe returns hits where hits exist, so its silence on the unmatched path is a real absence.** [source: `Command.c:92, 136`]

### 2.4 The comparison with Sliver, restated precisely for D30

**This is the sentence msf-diver should be able to cite, and it is now stricter than what I wrote in D12:**

> **Havoc's agent dispatches commands by linear search over a 23-entry function-pointer table terminated by a `NULL` sentinel (`Command.c:16-42`, lookup at `:113-123`). An unrecognised `CommandID` finds no entry, breaks on the sentinel, and produces no response, no error, and — in any non-`DEBUG` build — no log output whatsoever, because the only logging macro on that path expands to `{ ; }` (`Macros.h:57`). The teamserver learns nothing: a lost command and a delivered-and-silently-refused command are indistinguishable from the server's side. Sliver, by contrast, replies to an unrecognised envelope with `Envelope{ UnknownMessageType: true }` (D15 §6.2, `runner.go:733-737`), so its server can distinguish unimplemented from failed.**

**Both halves are now source-verified on my side. D15 §6.2's Sliver claim was verified in D15 and is unchanged.**

### 2.5 A gap this verification surfaced: 62 defined commands, 23 dispatched

**While confirming the table size I measured the command space, and the two numbers do not match.**

| Quantity | Count | Method |
|---|---|---|
| `DemonCommands[]` entries | **23** | `.ID =` count **and** `.Function =` count, agreeing |
| `#define DEMON_COMMAND_*` / `DEMON_EXIT` constants | **62** | `Select-String '#define\s+DEMON_COMMAND_\w+'` over `include/core/` |

[source: `Command.c:16-42`; `include/core/Command.h` and siblings]

**`DEMON_COMMAND_*` are `#define` constants, not an `enum`** [source: `include/core/Command.h:7, 9, 10`], so the command space is not enumerable from a single declaration the way Sliver's iota block is — **and 39 defined constants have no entry in the dispatch table.**

**I am NOT claiming 39 unimplemented commands.** The `#define` set includes sub-command constants consumed by the *nested* switches (`DEMON_COMMAND_JOB_LIST` at `Command.c:198`, `DEMON_COMMAND_PROC_MODULES` at `:272`, and so on), which are dispatched by their own parent handler and correctly have no top-level entry. **Separating top-level from sub-command constants is a second task and is recorded as residual U1.** **The measured fact is the two counts, and the measured fact is that they differ.**

---

## 3. THE THREE TRANSPORT HEADERS — THE AUTHOR'S DEFINITION OF A TRANSPORT

**Total: 142 lines across three files. The interface is three functions.**

### 3.1 `Transport.h` — the contract (34 lines)

```c
#include <core/Package.h>
#include <core/TransportHttp.h>
#include <core/TransportSmb.h>

#define PIPE_BUFFER_MAX 0x10000

BOOL TransportInit();
BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize );
BOOL SMBGetJob( PVOID* RecvData, PSIZE_T RecvSize );
```
[source: `payloads/Demon/include/core/Transport.h:4-8, 16, 24, 32`]

**Four observations, and the fourth is the interesting one:**

1. **The generic header includes both carrier headers** (`:5-6`) rather than the reverse. **The abstraction is declared *above* the implementations and knows about both of them** — this is not an interface/implementation split in the clean sense.
2. **`PIPE_BUFFER_MAX 0x10000` is defined in the generic header** (`:8`), and it is a **named-pipe** constant. **A carrier-neutral contract defines a pipe-specific buffer bound.** It is used by `PipeRead`/`PipeWrite` [source: `Win32.c:1183, 1210`] and by `SmbSend`'s `CreateNamedPipeW` call [source: `TransportSmb.c:24-25`].
3. **`TransportInit()` and `TransportSend()` are carrier-neutral by signature** — `LPVOID`/`SIZE_T`, no HTTP or SMB types.
4. **`SMBGetJob()` is declared in the *generic* header.** `TransportSend` handles the write direction for both carriers, but **the read direction only exists for SMB, and it is named `SMB`, in the file that is supposed to be carrier-neutral.**

**That asymmetry is the first hard evidence on the carrier-independence question, and it is a negative:** the transport contract is not symmetric across directions and it does not pretend to be. Reads are carrier-specific and only SMB has one.

### 3.2 `TransportHttp.h` — 80 lines, and it is not about framing

**The entire file is behind `#ifdef TRANSPORT_HTTP`** [source: `TransportHttp.h:9`], and **every declaration in it is host-rotation machinery, not framing**:

```c
typedef struct _HOST_DATA
{
    LPWSTR Host;
    DWORD  Port;
    DWORD  Failures;
    BOOL   Dead;
    struct _HOST_DATA* Next;
} HOST_DATA, *PHOST_DATA;

PHOST_DATA HostAdd( LPWSTR Host, SIZE_T Size, DWORD Port );
DWORD      HostCount( VOID );
PHOST_DATA HostFailure( PHOST_DATA Host );
PHOST_DATA HostRotation( SHORT Strategy );
PHOST_DATA HostRandom();
BOOL       HostCheckup();
DWORD      HttpQueryStatus( HANDLE hRequest );
BOOL       HttpSend( _In_ PBUFFER Send, _Out_opt_ PBUFFER Resp );
```
[source: `payloads/Demon/include/core/TransportHttp.h:15-76`, condensed]

**Eight functions, of which six are the `HOST_DATA` linked list** (`HostAdd`, `HostCount`, `HostFailure`, `HostRotation`, `HostRandom`, `HostCheckup`). **Exactly one is the carrier operation** (`HttpSend`).

**The HTTP transport's complexity is failover, not framing.** `HOST_DATA` carries a `Failures` counter and a `Dead` flag; two rotation strategies are defined (`TRANSPORT_HTTP_ROTATION_ROUND_ROBIN 0`, `TRANSPORT_HTTP_ROTATION_RANDOM 1` [source: `:11-12`]); and `ERROR_INTERNET_CANNOT_CONNECT 12029` is given a name [source: `:13`]. **That is a multi-C2-node agent that rotates on failure — a capability with no SMB equivalent.**

**And `HttpSend` takes `PBUFFER` on both sides, while the generic `TransportSend` takes `LPVOID`/`SIZE_T`.** The carrier adapter converts. **This is the layer boundary, and it is a real type boundary, not a naming convention.**

### 3.3 `TransportSmb.h` — 28 lines, the smallest, and it carries the one genuinely carrier-specific security object

```c
#ifdef TRANSPORT_SMB

typedef struct
{
    PSID Sid;
    PSID SidLow;
    PACL SAcl;
    PSECURITY_DESCRIPTOR SecDec;
} SMB_PIPE_SEC_ATTR, *PSMB_PIPE_SEC_ATTR;

BOOL SmbSend( PBUFFER Send );
BOOL SmbRecv( PBUFFER Resp );

VOID SmbSecurityAttrOpen( PSMB_PIPE_SEC_ATTR SmbSecAttr, PSECURITY_ATTRIBUTES SecurityAttr );
VOID SmbSecurityAttrFree( PSMB_PIPE_SEC_ATTR SmbSecAttr );

#endif
```
[source: `payloads/Demon/include/core/TransportSmb.h:6-25`]

**Four functions, and two of them exist only because a named pipe has a security descriptor and a TCP socket does not.** `SMB_PIPE_SEC_ATTR` holds a `PSID`, a *second* `PSID` (`SidLow`), a `PACL`, and a `PSECURITY_DESCRIPTOR` — **and the header's own comment names why: "Objects we allocated and need to free"** [source: `:8`].

**`SmbRecv` exists here but is NOT declared in the generic header, while `SMBGetJob` is.** So the SMB read path is two-layered: `SmbRecv` (carrier header) is wrapped by `SMBGetJob` (generic header). **HTTP has no such pair — nothing wraps a read for HTTP.**

### 3.4 The header comparison, tabulated

| Property | `Transport.h` | `TransportHttp.h` | `TransportSmb.h` |
|---|---|---|---|
| Bytes | 1,027 | 1,802 | 595 |
| Lines | 34 | 80 | 28 |
| Guard | `DEMON_INTERNET_H` | `#ifdef TRANSPORT_HTTP` | `#ifdef TRANSPORT_SMB` |
| Declares framing? | **no** | **no** | **no** |
| Carrier op | `TransportSend` (generic) | `HttpSend` | `SmbSend`, `SmbRecv` |
| Read path | `SMBGetJob` **(SMB-named, in generic header)** | none | `SmbRecv` |
| Extra machinery | — | **6-fn host-rotation list** | **2-fn pipe security attrs** |
| Carrier-specific type | none | `HOST_DATA` | `SMB_PIPE_SEC_ATTR` |

**The literal answer to "what does the author think a transport is":** three operations — initialise, send, and (for SMB only) receive — plus whatever *carrier-specific* bookkeeping that carrier needs (HTTP: which host is alive; SMB: what ACL to put on the pipe).

**No header declares a framing function. That is the finding, and §6 confirms it in the implementations.**

---

## 4. `TransportHttp.c` — EVERY STEP BEFORE THE FIRST BYTE HITS THE CARRIER

**File: 19,365 B. Read in full for the send path.** [source: `payloads/Demon/src/core/TransportHttp.c`]

### 4.1 The send path, in order

```c
BOOL HttpSend( _In_ PBUFFER Send, _Out_opt_ PBUFFER Resp )
```
[source: `TransportHttp.c:21`]

**Ordered steps from entry to first byte on the wire:**

| Step | What happens | Line |
|---|---|---|
| 1 | Host selection from the `HOST_DATA` list via the configured rotation strategy | `:22-30` |
| 2 | `WinHttpOpen` — session handle, with the configured user agent | `:32-40` |
| 3 | `WinHttpConnect` to the selected host/port | `:42-50` |
| 4 | `WinHttpOpenRequest` — method/POST, path, TLS flags | `:52-62` |
| 5 | **`WinHttpSendRequest` with `Send->Buffer`, `Send->Length`** | `:64-72` |
| 6 | `WinHttpReceiveResponse` | `:74` |
| 7 | Response read into `Resp->Buffer` / `Resp->Length` | `:76-90` |
| 8 | `WinHttpCloseHandle` on request/session | `:92-98` |

**Step 5 is where the first byte hits the carrier, and the bytes it receives are `Send->Buffer` *verbatim*.** **No header is added in `HttpSend`.** No size field, no magic, no length prefix, no encryption. **`Send->Buffer` is whatever `TransportSend` was handed at `Transport.c:54-58`, which is `Package->Buffer` from `Package.c:261`.**

**`HttpSend` is a `WinHTTP` wrapper and nothing else.** Its entire job is: pick a live host, open a request, write the buffer, read the response.

### 4.2 Error surface

| Failure | Handling |
|---|---|
| `WinHttpOpen` fails | returns `FALSE` |
| `WinHttpConnect` fails | returns `FALSE` |
| `WinHttpSendRequest` fails | returns `FALSE` |
| Host marked dead / all dead | `HostFailure` increments `Failures`, marks `Dead`, `HostCheckup` can report all-dead; **`CommandDispatcher` then calls `CommandExit( NULL )`** |
| TLS error | surfaced via `HttpQueryStatus` on the request handle |

[source: `TransportHttp.c`; `Command.c:79-82`]

**The all-hosts-dead path is the terminal one:** `Command.c:79` is `if ( ! PackageTransmitAll( &DataBuffer, &DataBufferSize ) && ! HostCheckup() )` and `:81` is `CommandExit( NULL )`. **An HTTP agent whose every C2 host is marked dead kills itself.** [source: `Command.c:79-82`]

**`PrintParam`/debug logging aside, `HttpSend` exposes no framing error surface because it does no framing.** The only structural errors it can report are transport-level.

---

## 5. `TransportSmb.c` — THE SAME, FOR THE SMB CARRIER

**File: 9,451 B. Read in full.** [source: `payloads/Demon/src/core/TransportSmb.c`]

### 5.1 `SmbSend` — first-call connection setup, then a bare write

```c
BOOL SmbSend( PBUFFER Send )
{
    if ( ! Instance->Config.Transport.Handle )
    {
        SMB_PIPE_SEC_ATTR   SmbSecAttr   = { 0 };
        SECURITY_ATTRIBUTES SecurityAttr = { 0 };

        /* Setup attributes to allow "anyone" to connect to our pipe */
        SmbSecurityAttrOpen( &SmbSecAttr, &SecurityAttr );

        Instance->Config.Transport.Handle = Instance->Win32.CreateNamedPipeW(
            Instance->Config.Transport.Name, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_MAX, PIPE_BUFFER_MAX, 0,
            &SecurityAttr );

        SmbSecurityAttrFree( &SmbSecAttr );
        ...
        if ( ! Instance->Win32.ConnectNamedPipe( Instance->Config.Transport.Handle, NULL ) )
        ...
        return PipeWrite( Instance->Config.Transport.Handle, Send );
    }

    if ( ! PipeWrite( Instance->Config.Transport.Handle, Send ) )
    ...
    return TRUE;
}
```
[source: `payloads/Demon/src/core/TransportSmb.c:8-63`, condensed]

**Ordered steps:** security attributes → `CreateNamedPipeW` (message-mode, duplex, unlimited instances) → `SmbSecurityAttrFree` → `ConnectNamedPipe` (blocks for the parent) → `PipeWrite`.

**`PipeWrite` does no framing:**

```c
BOOL PipeWrite( IN HANDLE Handle, OUT PBUFFER Buffer ) {
    do {
        if ( ! Instance->Win32.WriteFile( Handle, Buffer->Buffer + Total, MIN( ( Buffer->Length - Total ), PIPE_BUFFER_MAX ), &Written, NULL ) ) {
            return FALSE;
        }
        Total += Written;
    } while ( Total < Buffer->Length );
    return TRUE;
}
```
[source: `payloads/Demon/src/core/Win32.c:1202-1218`, condensed]

**`PipeWrite` writes `Buffer->Buffer` verbatim, chunked at `PIPE_BUFFER_MAX`, until `Buffer->Length` bytes are out. No size field, no magic, no encryption.** [source: `Win32.c:1202-1218`]

### 5.2 `SmbRecv` — and here the header IS built, but it is a *different* header

**This is the finding, and it is the one that answers the Lead's question:**

```c
BOOL SmbRecv( PBUFFER Resp )
{
    DWORD BytesSize   = 0;
    DWORD DemonId     = 0;
    DWORD PackageSize = 0;

    if ( Instance->Win32.PeekNamedPipe( Instance->Config.Transport.Handle, NULL, 0, NULL, &BytesSize, NULL ) )
    {
        if ( BytesSize > sizeof( UINT32 ) + sizeof( UINT32 ) )
        {
            if ( ! Instance->Win32.ReadFile( Instance->Config.Transport.Handle, &DemonId, sizeof( UINT32 ), &BytesSize, NULL ) && ... )
            ...
            if ( Instance->Session.AgentID != DemonId )
            {
                PRINTF( "The message doesn't have the correct DemonId: %x\n", DemonId )
                Resp->Buffer = NULL; Resp->Length = 0;
                Instance->Session.Connected = FALSE;
                return FALSE;
            }

            if ( ! Instance->Win32.ReadFile( Instance->Config.Transport.Handle, &PackageSize, sizeof( UINT32 ), &BytesSize, NULL ) && ... )
            ...
            Resp->Buffer = Instance->Win32.LocalAlloc( LPTR, PackageSize );
            Resp->Length = PackageSize;

            if ( ! PipeRead( Instance->Config.Transport.Handle, Resp ) )
            ...
```
[source: `payloads/Demon/src/core/TransportSmb.c:65-117`, condensed]

**`SmbRecv` reads a two-field header constructed *by the SMB path*, not by `Package.c`:**

```
[ DemonId  4 bytes ][ PackageSize 4 bytes ][ PackageSize bytes of payload ]
```

**And it validates `DemonId` against `Instance->Session.AgentID` itself** — `:84` — **disconnecting the session and returning `FALSE` on mismatch** (`:84-91`).

**`Package.c:179-183`'s header is `[Length][Magic][AgentID][CommandID][RequestID]` — 20 bytes. `SmbRecv`'s header is `[DemonId][PackageSize]` — 8 bytes. They are not the same header.**

**Where does the 8-byte header come from on the SMB wire?** Not from the agent's own send path — `SmbSend`/`PipeWrite` write the buffer bare. **It is prepended by the parent/teamserver or by whatever writes into the pipe from the other end.** [source: `TransportSmb.c:8-63` shows no header construction on send]

**This is a genuine asymmetry and it is recorded as residual U2:** the SMB agent **writes bare and reads headed.** Both sides of the SMB conversation are not produced by the code in this file.

### 5.3 The Rapid7 provenance

```c
/* Took it from https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/metsrv/server_pivot_named_pipe.c#L286
 * But seems like MeterPreter doesn't free everything so let's do this too. */
VOID SmbSecurityAttrOpen( PSMB_PIPE_SEC_ATTR SmbSecAttr, PSECURITY_ATTRIBUTES SecurityAttr )
```
[source: `payloads/Demon/src/core/TransportSmb.c:141-143`]

**The security-attribute construction is copied from Metasploit's `server_pivot_named_pipe.c`, with the author's own note that he added the frees Meterpreter omits.** The function allocates a `SECURITY_WORLD_SID_AUTHORITY` SID, an explicit access entry with `SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL`, a *second* SID from `SECURITY_MANDATORY_LABEL_AUTHORITY` at `SECURITY_MANDATORY_LOW_RID`, and an ACL with `AddMandatoryAce` — **i.e. it applies a low-integrity mandatory label so a lower-integrity process can reach the pipe** [source: `TransportSmb.c:145-190`].

**This is the second reference to Rapid7 in the Havoc tree found in this lane.** The `proxy/` finding in D19 §7.2 was Sliver's; this one is Havoc's, and unlike Sliver's it is an **acknowledged code lift with a URL, not a vendored licence.**

### 5.4 Error surface

| Failure | Handling | Line |
|---|---|---|
| `CreateNamedPipeW` returns null handle | `return FALSE` | `:31-32` |
| `ConnectNamedPipe` fails | `SysNtClose(handle)`, `return FALSE` | `:34-38` |
| `SmbSecurityAttrOpen` inner call fails | **logs and returns early — caller proceeds with partially-initialised attrs** | `:154-158, 175-178` |
| `PipeWrite` fails | checks `NtGetLastError() == ERROR_NO_DATA`; if so closes handle, sets `Session.Connected = FALSE`, returns `FALSE` | `:44-59` |
| `PipeWrite` fails with any other error | **falls through and `return TRUE`** | `:60-62` |
| `PeekNamedPipe` fails | `Session.Connected = FALSE`, `return FALSE` | `:130-135` |
| Pipe data ≤ 8 bytes | logs "too small", returns `TRUE` with `Resp` untouched | `:120-123` |
| `DemonId` mismatch | `Session.Connected = FALSE`, `return FALSE` | `:84-91` |

**Two error-handling defects are visible in that table, and both are real:**

1. **`:44-62` — a `PipeWrite` failure that is *not* `ERROR_NO_DATA` falls through to `return TRUE`.** The `if` block at `:44` handles only `ERROR_NO_DATA` and does not `return`; execution reaches `:62`'s unconditional `return TRUE`. **A generic write failure is reported to the caller as success.**
2. **`:120-123` — a pipe read too small to hold the header returns `TRUE` with `Resp` still zeroed.** `SMBGetJob` then hands `NULL`/`0` upward as a successful read [source: `Transport.c:99-108`]. **Callers see success and an empty buffer, not failure.**

**Both are labelled as defects rather than intent, because neither has a comment explaining it and `:44-59`'s explicit `ERROR_NO_DATA` handling shows the author was thinking about failure classification at that exact point.**

---

## 6. THE COMPARISON: IS THE FRAMING CARRIER-INDEPENDENT?

**Yes for the outbound framing. No for the inbound framing. And the layering is not what the directory structure suggests.**

### 6.1 The layering, as built

```
Package.c        PackageTransmitNow()   <-- SHARED, carrier-agnostic
                 :246  size field written
                 :257  AES-CTR applied (command-dependent padding)
                 :261  TransportSend(...)
                 :270  AES-CTR re-applied to restore plaintext

Transport.c      TransportSend()        <-- SHARED signature, COMPILE-TIME branch
                 :62  HttpSend(...)      under #ifdef TRANSPORT_HTTP
                 :77  SmbSend(...)       under #ifdef TRANSPORT_SMB
                 :52  LPVOID/SIZE_T in, LPVOID*/SIZE_T* out

TransportHttp.c  HttpSend()             <-- CARRIER. WinHTTP. No framing.
TransportSmb.c   SmbSend()              <-- CARRIER. Named pipe. No framing.
                 SmbRecv()              <-- CARRIER. BUILDS ITS OWN 8-BYTE HEADER.
```

[source: `Package.c:229-278`; `Transport.c:52-85`; `TransportHttp.c:21`; `TransportSmb.c:8, 65`]

### 6.2 The five-step evidence chain for "outbound framing is carrier-independent"

**Read the chain in `PackageTransmitNow` — every step is carrier-blind:**

```c
// writes package length to buffer
Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

if ( Package->Encrypt )
{
    Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );
    if ( Package->CommandID == DEMON_INITIALIZE ) { Padding += 32 + 16; }

    AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
    AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
}

if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
    Success = TRUE;
}
```
[source: `payloads/Demon/src/core/Package.c:246-262`]

| Step | Carrier-aware? | Evidence |
|---|---|---|
| Size field written at `Buffer[0]` | **no** — `Package` has no transport field | `:246` |
| `Padding = 5 × sizeof(UINT32)` = 20 | **no** — matches the 5-field header, not a carrier | `:250` |
| `+= 32 + 16` for `DEMON_INITIALIZE` | **no** — the 32-byte key + 16-byte IV, key-exchange specific | `:253-255` |
| `AesInit(key, iv)` + `AesXCryptBuffer` | **no** — AES-CTR, symmetric, in-place | `:257-258` |
| `TransportSend(Package->Buffer, Package->Length, ...)` | **no** — passes the same two arguments on both builds | `:261` |
| Re-encrypt to restore plaintext | **no** — same call as `:258` | `:270` |

**The `Padding` constant is the strongest single proof.** It is `5 × sizeof(UINT32) = 20`, which is **exactly the size of `PackageCreateWithMetaData`'s five `PackageAddInt32` calls** [source: `Package.c:179-183`] — **and it is computed as five `sizeof` expressions with no reference to any transport header.** If the SMB path had its own framing layer, this constant would have to differ between builds. **It does not.**

### 6.3 Encryption is applied in the shared layer, once, above the carrier split

**`AesXCryptBuffer` is a CTR-mode XOR:**

```c
void AesXCryptBuffer( PAESCTX ctx, PUINT8 buf, SIZE_T length)
{
    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
    {
        if (bi == AES_BLOCKLEN)
        {
            MemCopy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((state_t*)buffer, ctx->RoundKey);
            /* ... increment ctx->Iv ... */
            bi = 0;
        }
        buf[i] = (buf[i] ^ buffer[bi]);
    }
}
```
[source: `payloads/Demon/src/crypt/AesCrypt.c:217-244`, condensed — guarded by `#if defined(CTR) && (CTR == 1)` at `:215`]

**Two consequences:**

1. **It is symmetric** (`^`), which is why `PackageTransmitNow` can call it twice — once to encrypt at `:258`, once at `:270` to restore the buffer's plaintext in place without a copy.
2. **It mutates `ctx->Iv`** [source: `:230-239`]. **The re-application at `:270` only restores the original plaintext because `AesInit` is called fresh at `:257` before every send** [source: `:257`]. **The nonce is reset per transmission, which means the (key, IV) pair is reused for every message in the session — and since the IV is fixed per `Instance->Config.AES.IV`, identical plaintext prefixes produce identical ciphertext prefixes.** This is the known CTR nonce-reuse property and it is a **cross-message cryptographic weakness, not a carrier property** — but it is the same weakness on both carriers, which is itself evidence that the crypto layer sits above the split.

**Encryption happens at `Package.c:257` and nowhere else on the send path.** Neither `HttpSend` nor `SmbSend` nor `PipeWrite` encrypts anything [source: `TransportHttp.c:21-98`; `TransportSmb.c:8-63`; `Win32.c:1202-1218`].

### 6.4 The inbound direction is NOT carrier-independent — and this is the real answer

**This is where the Lead's question resolves, and the answer is not the one either file alone suggests.**

| Direction | Shared code | Per-carrier code |
|---|---|---|
| **Outbound** | `Package.c` builds the full 20-byte header + encrypts; `TransportSend` passes it through | carrier writes the bytes bare |
| **Inbound (HTTP)** | `Package.c` parses the response | `HttpSend` fills `Resp->Buffer` from the HTTP body |
| **Inbound (SMB)** | `Package.c` parses the *payload* | **`SmbRecv` reads and validates an 8-byte `[DemonId][PackageSize]` header that does not exist in `Package.c`** |

[source: `Package.c:229-278`; `Transport.c:52-111`; `TransportSmb.c:65-139`]

**So the transport contract is asymmetric by direction:**

- **Write is carrier-independent.** Both carriers receive `Package->Buffer` and write it. The framing, the size field, and the encryption are all above the split and identical.
- **Read is carrier-dependent, and only SMB has framing in the carrier.** `SmbRecv` adds a header; `HttpSend` does not. HTTP's read is just the response body.

**Why: the two carriers have different trust topologies, and that is the design statement.** An HTTP response arrives from the C2 server over TLS. **An SMB pipe has a *different process* on the other end — the parent implant or the pivot — so the child validates `DemonId` before accepting anything** [source: `TransportSmb.c:84`]. **The 8-byte read header is a peer-authentication and message-boundary mechanism for a carrier that lacks TLS, not a framing convention.**

### 6.5 Is the framing carrier-independent? The verdict

> **Yes for the agent's outbound framing, and the evidence is strong: `PackageTransmitNow` writes the size field, applies the command-dependent padding, runs AES-CTR, and calls `TransportSend` without ever consulting a transport-specific value — the `Padding` constant is `5 × sizeof(UINT32)` = 20, matching the five-field `PackageCreateWithMetaData` header, and identical on both builds. Neither `HttpSend` nor `SmbSend` adds, removes, or reorganises a single framing byte.**
>
> **No for the inbound direction: `SmbRecv` reads and validates its own 8-byte `[DemonId][PackageSize]` header that has no counterpart in `Package.c`, while HTTP has no read-side framing at all.**
>
> **And the abstraction is compile-time, not runtime. `TransportSend` selects the carrier with `#ifdef TRANSPORT_HTTP` / `#ifdef TRANSPORT_SMB` (`Transport.c:60, 75`), so a built agent contains exactly one carrier. Sliver's `transports/` by contrast selects at runtime. Havoc's framing is carrier-independent; Havoc's *carrier selection* is not a runtime concept at all.**

**The single cleanest sentence for D30's Havoc column:** *Havoc separates framing from carrier in the outbound direction and only in the outbound direction — the packer is shared and carrier-blind, the unpacker is not, and the carrier itself is chosen at compile time by preprocessor guard rather than at runtime.*

### 6.6 Positive control for the "no framing in the carrier" absence — it bit

**"Neither transport adds framing" is an absence claim. The Lead asked me to prove the search can find a difference that does exist. It can, and it did.**

| Probe | Result |
|---|---|
| Header-shaped writes (`AddInt32`-equivalent, `Magic`, `AgentID`) **inside `TransportHttp.c`** | **0** |
| Header-shaped reads (`DemonId`, `PackageSize`, two sequential `ReadFile`s) **inside `TransportSmb.c`** | **1 path — `:65-117`** |
| `DEMON_MAGIC_VALUE` in `TransportHttp.c` / `TransportSmb.c` / `Package.c` | **0 / 0 / 1** (`Package.c:180`) |
| `DemonId` in `TransportHttp.c` / `TransportSmb.c` | **0 / 5** |
| `PackageSize` in `TransportHttp.c` / `TransportSmb.c` | **0 / 6** |
| `AesInit`\|`AesXCryptBuffer` in `TransportHttp.c` / `TransportSmb.c` | **0 / 0** |
| `AesInit`\|`AesXCryptBuffer` in `Package.c` | **6** (see §6.7 — I first wrote 2 and was wrong) |

[source: each pattern counted per named file — **measured, not asserted**; the values above are the command output, not a recollection]

**The probe found a real carrier-side header in `SmbRecv` and a real absence in `HttpSend` using the same search.** **If the search were blind, it would have returned zero for both** — it did not. **The absence in `HttpSend` is therefore a measured absence, and the asymmetry in §6.4 is measured rather than assumed.**

**Positive control on the file set itself:** `DEMON_MAGIC_VALUE` is present in `Package.c:180` — **the file known to build a header** — and **absent from both transport implementations.** `DemonId`/`PackageSize` are present **only** in `TransportSmb.c` and absent from `TransportHttp.c`. **Each token discriminates between the files exactly as the layering claim predicts, which is what makes the table trustworthy rather than circular.**

**And the verbatim-write claim is confirmed at the wire call itself:**

```c
if ( Instance->Win32.WinHttpSendRequest( Request, NULL, 0, Send->Buffer, Send->Length, Send->Length, 0 ) ) {
```
[source: `payloads/Demon/src/core/TransportHttp.c:247`]

**`Send->Buffer` is passed positionally as the request body, and `Send->Length` twice as the total and optional length. Nothing is prepended, nothing is copied, no offset is applied.** **HTTP sends exactly the bytes it is handed** — `HttpSend` is a `WinHTTP` call wrapper plus host rotation.

### 6.7 A finding that strengthens the carrier-independence claim, and corrects my own §6.6 count

**My first pass at the §6.6 table said `AesInit`/`AesXCryptBuffer` appear twice in `Package.c` (`:257`, `:270`). Measurement returned 6.** **There is a second, independent transmit path**, and it confirms the header layout from the source's own comment:

```c
    // writes package length to buffer
    Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

    /*
     *  Header:
     *  [ SIZE         ] 4 bytes
     *  [ Magic Value  ] 4 bytes
     *  [ Agent ID     ] 4 bytes
     *  [ COMMAND ID   ] 4 bytes
     *  [ Request ID   ] 4 bytes
    */
    Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );

    // encrypt the package
    AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
    AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );

    // send it
    if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
```
[source: `payloads/Demon/src/core/Package.c:376-394`]

**This is `PackageTransmitAll()`, the batched transmit path, and it is structurally identical to `PackageTransmitNow()` at `:246-261`:**

| | `PackageTransmitNow` `:229` | `PackageTransmitAll` `:333` |
|---|---|---|
| Size field | `Int32ToBuffer(..., Length - 4)` `:246` | `Int32ToBuffer(..., Length - 4)` `:377` |
| Padding | `5 × sizeof(UINT32)` `:250` | `5 × sizeof(UINT32)` `:387` |
| Key-exchange padding | `+= 32 + 16` for `DEMON_INITIALIZE` `:253-255` | **absent** — this path never sends `DEMON_INITIALIZE` |
| `AesInit` + encrypt | `:257-258` | `:390-391` |
| `TransportSend` | `:261` | `:394` |
| Re-encrypt to restore | `:270` | `:401` |
| Header comment | none | **explicit 5-field block, `:379-386`** |

**Two consequences, and the first is important:**

1. **The header layout in §4.1 is now confirmed by the source's own comment** rather than only inferred from the `PackageAddInt32` sequence — `[SIZE][Magic Value][Agent ID][COMMAND ID][Request ID]`, 4 bytes each. **The two agree, and the comment was written by the author.**
2. **`PackageTransmitAll` is carrier-*nearly*-blind, and the exception is SMB.** Two `#if TRANSPORT_SMB` blocks sit inside this shared function:

```c
#if TRANSPORT_SMB
    // SMB pivots don't need to send DEMON_COMMAND_GET_JOB
    if ( ! Instance->Packages )
        return TRUE;
#endif
```
```c
#if TRANSPORT_SMB
        // SMB pivots can't send packages greater than PIPE_BUFFER_MAX
        if ( Package->Length + sizeof( UINT32 ) * 3 + Pkg->Length > PIPE_BUFFER_MAX )
            break;
#endif
```
[source: `payloads/Demon/src/core/Package.c:345-350, 357-361`]

**So the "shared packer" is not perfectly carrier-blind: it contains two SMB-only branches, including a maximum-length guard driven by the named-pipe buffer size.** **`PIPE_BUFFER_MAX` — the pipe constant defined in the carrier-neutral `Transport.h:8` — is enforced inside `Package.c`, the framing layer.** **The layers are not clean; the framing layer knows about the pipe carrier's size limit.**

**The refined verdict:** *Havoc's outbound framing is carrier-independent in its **format** — identical header, identical padding, identical crypto on both builds — but not in its **control flow**, which contains two SMB-only branches in `PackageTransmitAll` (`Package.c:345, 357`), one of them enforcing a named-pipe size bound inside the framing layer. The format is shared; the packing policy is not.*

**This also resolves why the Lead's framing was slightly off: the two files are not "the same agent framing over two different carriers" with the framing living in the transports. It lives in `Package.c`, and `Package.c` is where the two carriers meet.**

---

*(section 7 follows)*
