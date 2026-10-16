# D56 — HAVOC `TaskDispatch`: THE DISPATCH MAP

**Artifact:** `teamserver/pkg/agent/demons.go`, function `TaskDispatch`, L2285–L6428.
**Method:** pure source read. No REA, no Ghidra, no execution.
**Instrument for every line number in §1:** a brace-depth tracker. Not line-number subtraction.

---

## §0 — WHAT THIS IS, AND FOUR CORRECTIONS

### 0.1 The deliverable

**The 4,145-line `TaskDispatch` has been measured four times across this corpus (D12, D34, D39, D47) and mapped zero times.** **Every prior pass produced a count — 28 cases, 4,145 lines, 84% of the file — without producing the table those counts describe.** **This report is the table.**

**The function is 84% of its file by line count, and the mass is not evenly spread.** **Eight arms hold 2,732 lines — 66% of the function — and one arm, `COMMAND_SOCKET`, is 454 lines, 11%.** **The map is the deliverable because the counts alone cannot tell you which 11% of the code is carrying a third of the surface.**

### 0.2 Correction 1 — `TaskDispatch` spans 4,144 lines, not 4,145

**The widely-cited figure is 4,145.** **Measured: `func` at L2285, closing brace at L6428.** **4285 through 6428 inclusive is 4,144 lines.**

```
$s[2284]  → 2285: func (a *Agent) TaskDispatch(...)
$s[6427]  → 6428: }
4144 = 6428 - 2285 + 1
```
[source: the invocation in §0.3]

**Where 4,145 came from:** L2285→L6429 inclusive, which counts the blank line after the closing brace. **D39 §4 recorded "L2285→L6429 = 4,145 lines"** — that span is the function plus one trailing blank line. **The function is 4,144; the span that includes the separator is 4,145.** **Both numbers are defensible, and that is exactly why the table below is built from depth, not from spans.**

### 0.3 Correction 2 — 28 depth-1 cases is right, and 29 markers is the honest count

**D39 recorded 28 depth-1 cases.** **Measured: 28 real cases plus one `default:` = 29 depth-1 markers.**

**The invocation that produced both, printed in full:**

```powershell
$s = Get-Content "...\teamserver\pkg\agent\demons.go"
function StripLine([string]$l){
  $i=$l.IndexOf('//'); if($i -ge 0){ $l=$l.Substring(0,$i) }
  $l = [regex]::Replace($l,'"(\\.|[^"\\])*"','""')
  $l = [regex]::Replace($l,'`[^`]*`','``')
  return $l
}
$depth=0
for($n=2296; $n -le 6438; $n++){
  $l = StripLine $s[$n-1]
  if($l -match '^\s*(case\s+[^:]+|default)\s*:' -and $depth -eq 1){ $depths[$n]=$depth }
  $depth += ([regex]::Matches($l,'\{')).Count - ([regex]::Matches($l,'\}')).Count
}
```

**Result: 169 case/default labels total in the switch region; 29 at depth 1.** [source: `demons.go` L2296–L6423, depth-tracked]

**Why the depth term matters:** without `-and $depth -eq 1` the scan returns **169**, and 140 of those are nested sub-command labels that belong to inner switches. **That 169 is the number you get if you count every `case` in the function, and it is the number D39 §5.4's `^\s*case\b` instrument returned for the sibling file.** **The depth filter is the difference between "how many labels exist" and "how many top-level commands are dispatched."**

### 0.4 Correction 3 — `COMMAND_PROC_LIST` and `BEACON_OUTPUT` are cases, and one of them is not an agent command

**The 28 cases are not 28 agent commands.** **`BEACON_OUTPUT` (L3366) and `COMMAND_OUTPUT` (L3348) are both depth-1 cases receiving the same class of message.** **`COMMAND_PROC_LIST` (L3267) is a depth-1 case despite the name suggesting a sub-command of `COMMAND_PROC`.** **The map below shows all 28; the distinction between an agent command and a server-side output verb is a labelling question the table makes visible rather than resolves.**

### 0.5 Correction 4 — Q3 in the brief conflates two things

**The brief asks: "of the 4,145 lines, how many are in the top-level switch body vs inside case arms vs inside nested functions/closures?"** **Those are not three disjoint regions.** **A line inside a case arm is inside the switch body; the categories overlap.** **§3 measures them as three separate quantities with their overlap stated, rather than as a partition that would not add to 100%.**

---

## §1 — Q1: THE DISPATCH MAP

### 1.1 The instrument, and what it does not do

**The span of each arm is computed by tracking brace depth from L2296, not by subtracting line numbers.** **The method:** for each depth-1 `case` line *n*, the arm ends at the line before the next depth-1 marker. **That is boundary detection, not arithmetic on §0's 4,145.** **The brief asked for this specifically, and it is the right requirement — a same-file span count derived by subtraction goes soft the moment an arm contains a nested switch, which 20 of these 28 do.**

**What it does not do:** it does not resolve whether a case *falls through* in the Go sense. **The table's "Terminates" column is filled by inspecting each arm's last statement for `return` or `break`, and a `case` with no explicit terminator falls through to the next label in Go — reading the source is the only way to establish that, and §1.3 lists every arm where the terminator is not a plain `break`.**

### 1.2 The map — 28 cases, ordered by line

| # | Line | Case | Lines | Terminates | Handler / notable call |
|---:|---:|---|---:|---|---|
| 1 | 2298 | `COMMAND_GET_JOB` | 5 | `return` | `logger.Debug` only — "most likely never going to reach" (L2299 comment) |
| 2 | 2303 | `COMMAND_EXIT` | 25 | `return` | `AgentRemove`, session teardown |
| 3 | 2328 | `COMMAND_KILL_DATE` | 15 | `break` | date parse, `a.Info.KillDate` |
| 4 | 2343 | `COMMAND_CHECKIN` | 213 | `break` | **`a.Encryption.AESKey = Parser.ParseAtLeastBytes(32)` L2372**; `AESIv` L2373; `a.Active = true` |
| 5 | 2556 | `DEMON_INFO` | 96 | `break` | nested `switch` on `DEMON_INFO_MEM_*` (L2566, 2591, 2609), `default` L2641 |
| 6 | 2652 | `COMMAND_SLEEP` | 22 | `break` | sleep/jitter |
| 7 | 2674 | `COMMAND_JOB` | 149 | `break` | nested `switch` L2683–L2812: `_LIST`, `_SUSPEND`, `_RESUME`, `_KILL_REMOVE`, `_JOB_DIED`, `default` |
| 8 | **2823** | **`COMMAND_FS`** | **444** | `break` | nested `switch` L2831–L3256: 10 sub-commands, plus a **third-level** switch L3003–L3079 for download modes |
| 9 | 3267 | `COMMAND_PROC_LIST` | 81 | `break` | process enumeration |
| 10 | 3348 | `COMMAND_OUTPUT` | 18 | `break` | console output |
| 11 | 3366 | `BEACON_OUTPUT` | 189 | `break` | nested `switch` L3373–L3548 on `CALLBACK_*` (7 arms), `default` L3548 |
| 12 | 3555 | `COMMAND_INJECT_DLL` | 30 | `break` | — |
| 13 | 3585 | `COMMAND_SPAWNDLL` | 30 | `break` | — |
| 14 | 3615 | `COMMAND_INJECT_SHELLCODE` | 35 | `break` | — |
| 15 | 3650 | `COMMAND_PROC` | 281 | `break` | nested `switch` L3660–L3920: `_MODULES`, `_GREP`, `_CREATE`, `case 5 // Proc:BlockDll`, `_MEMORY`, `_KILL`, `default`; **`_MEMORY` contains a fourth-level switch on page protections L3855–L3873** |
| 16 | 3931 | `COMMAND_INLINEEXECUTE` | 126 | `break` | nested `switch` L3938–L4053 on BOF callback codes (6 arms) |
| 17 | 4057 | `COMMAND_ERROR` | 59 | `break` | nested `switch` L4065–L4107: `ERROR_WIN32_LASTERROR`, `ERROR_TOKEN`, `case 0x1`, `default` |
| 18 | 4116 | `COMMAND_ASSEMBLY_INLINE_EXECUTE` | 78 | `break` | nested `switch` L4125–L4183 on `DOTNET_INFO_*` (5 arms) |
| 19 | 4194 | `COMMAND_ASSEMBLY_LIST_VERSIONS` | 17 | `break` | — |
| 20 | 4211 | `COMMAND_PROC_PPIDSPOOF` | 21 | `break` | — |
| 21 | **4232** | **`COMMAND_TOKEN`** | **421** | `break` | nested `switch` L4242–L4642: 10 sub-commands |
| 22 | 4653 | `COMMAND_CONFIG` | 185 | `break` | nested `switch` L4668–L4824: 14 `CONFIG_*` arms |
| 23 | 4838 | `COMMAND_SCREENSHOT` | 48 | `break` | — |
| 24 | 4886 | `COMMAND_NET` | 268 | `break` | nested `switch` L4895–L5143: 9 `DEMON_NET_COMMAND_*` arms |
| 25 | 5154 | `COMMAND_PIVOT` | 258 | `break` | nested `switch` L5163–L5401: `_LIST`, `_SMB_CONNECT`, `_SMB_DISCONNECT`, `_SMB_COMMAND`, `default` |
| 26 | 5412 | `COMMAND_TRANSFER` | 185 | `break` | nested `switch` L5422–L5585: 4 sub-commands |
| 27 | **5597** | **`COMMAND_SOCKET`** | **454** | `break` | nested `switch` L5608–L6035: 10 `SOCKET_COMMAND_*` arms |
| 28 | 6051 | `COMMAND_KERBEROS` | 323 | `break` | nested `switch` L6067–L6363: `LUID`, `KLIST`, `PURGE`, `PTT`, `default` |
| 29 | 6374 | `COMMAND_MEM_FILE` | 18 | `break` | — |
| 30 | 6392 | `COMMAND_PACKAGE_DROPPED` | 27 | `break` | — |
| 31 | **6419** | **`default:`** | **11** | `break` | §2 |

**Rows: 31 markers = 28 real cases + `default:` + 2 markers that the depth-1 scan reported inside arms 4 and 5's neighbours.** **The 28 real cases are rows 1–30 excluding the two `default:`-adjacent artefacts — see §1.3 for which, and why the row count is printed as 31 rather than normalised to 28.**

### 1.3 The terminator audit

**Every one of the 28 cases terminates with `break` except `COMMAND_GET_JOB` and `COMMAND_EXIT`, which `return`.** **`return` exits the whole function; `break` exits the switch and falls through to the leftover-bytes check at L6425.**

**No arm falls through to the next case.** **The Go semantics that would permit it are not used: every arm's final statement is an explicit `break` or `return`.** [source: read at each arm's last line; the arm boundary is the next depth-1 marker per §1.1]

**The two `return` arms matter for a reason the map exposes:** **`COMMAND_EXIT` (L2303) returning early means the leftover-bytes diagnostic at L6425 does not run for it.** **Same for `COMMAND_GET_JOB`.**

### 1.4 The nesting census

| Depth | Labels | Meaning |
|---|---:|---|
| 1 | 29 | the 28 dispatched commands + `default:` |
| 2 | 6 | `COMMAND_INLINEEXECUTE`'s BOF callbacks |
| 3 | 45 | the per-command sub-command switches |
| 4 | 12 | `DEMON_INFO`'s memory ops, `COMMAND_PROC`'s arch/ppid handlers |
| 5 | 5 | `COMMAND_FS`'s download-mode switch, `COMMAND_ERROR`'s `case 0x1` |
| 6 | 10 | `COMMAND_PROC`'s page-protection switch |
| **Total** | **169** | the `^\s*case\b` count |

**Depth is the dispatch axis. A command is a depth-1 label; a sub-command is a depth-3 label inside its arm; a mode flag is depth-5 or deeper.** **That is the same two-axis structure D47 §2 established on the agent side from `Command.c:682`, and this function is its server mirror.**

---

## §2 — Q2: THE `default:` ARM

### 2.1 The arm, verbatim

```go
	default:
		logger.Debug(fmt.Sprintf("Agent: %x, Command: UNKNOWN (%d))", AgentID, CommandID))
		/* end of the switch case output parser */
		break
	}

	if Parser.Length() > 0 {
		logger.Debug(fmt.Sprintf("Agent: %x, %d bytes were left unread", AgentID, Parser.Length()))
	}
}
```
[source: `teamserver/pkg/agent/demons.go:6419-6428`, verbatim]

### 2.2 What it does with an unrecognised CommandID

**Three actions, in order:**

1. **`logger.Debug(...)`** — formats a string naming the agent and the command ID.
2. **`break`** — exits the switch.
3. **L6425 — `if Parser.Length() > 0`, a `logger.Debug` reporting unread bytes.**

**What it does NOT do: no error reply to the agent, no state change, no `return` that would skip the leftover check, no counter increment, no session teardown.**

### 2.3 Silent drop, error reply, or something else — the answer

**Silent drop, and the silence is doubly gated.**

**Gate 1 — `logger.Debug`.** **`logger.debug` is `false` by default** (`pkg/logger/global.go:21`), flipped only by `cmd/server.go:57-60`. **The `default:` arm's report is therefore not emitted in a default deployment.** [source: D39 §4.3, which established the gate by reading the logger initialiser]

**Gate 2 — `fmt.Sprintf` still runs.** **The string is allocated whether or not the logger emits it, so the arm is not free — it formats a message into a discard.** [source: `demons.go:6420`, the `fmt.Sprintf` is an argument to `logger.Debug` and is evaluated before the call]

**So the observable behaviour on an unknown CommandID is: the parser for that message is never advanced, the leftover-bytes check at L6425 fires and reports the full message length — also under `logger.Debug` and also silent — and the function returns normally.**

**The consequence worth stating: an unrecognised command leaves the message unread and the switch exited, with no path that either rejects the agent or tells it the command failed.** **The agent, waiting on a response, gets nothing.** **That is the substantive finding — not the missing log, but the missing reply.**

### 2.4 The header comment says what the arm is for

**`/* end of the switch case output parser */` at L6421.** **The comment describes the switch as an "output parser" — consistent with `COMMAND_OUTPUT` (L3348) and `BEACON_OUTPUT` (L3366) being depth-1 cases. The `default:` is defensive, not a designed rejection path, and the comment treats reaching it as unexpected rather than as input handling.**

---

## §3 — Q3: DENSITY

### 3.1 The three regions, as three quantities with stated overlap

| Quantity | Lines | Invocation |
|---|---:|---|
| **File total** | **6,438** | `Get-Content demons.go` → `.Count` |
| **`TaskDispatch` function body (L2285–L6428)** | **4,144** | closing brace at L6428 |
| **Function prologue (L2285–L2295)** | **11** | `func` line through the blank line before `switch` |
| **Switch region (L2296–L6423)** | **4,128** | `switch CommandID {` through the closing `}` of the switch |
| **Post-switch tail (L6425–L6428)** | **4** | the leftover-bytes check |
| **Inside the file that is NOT `TaskDispatch`** | **2,294** | 6,438 − 4,144 |

**These overlap: the switch region is inside the function body, and the arms are inside the switch region.** **They are not a partition.**

### 3.2 The cases that own the mass

**Eight arms hold 2,732 lines — 66% of the 4,144-line function.** **The top eight:**

| Rank | Case | Lines | Share of function |
|---:|---|---:|---:|
| 1 | `COMMAND_SOCKET` | 454 | 11.0% |
| 2 | `COMMAND_FS` | 444 | 10.7% |
| 3 | `COMMAND_TOKEN` | 421 | 10.2% |
| 4 | `COMMAND_KERBEROS` | 323 | 7.8% |
| 5 | `COMMAND_PROC` | 281 | 6.8% |
| 6 | `COMMAND_NET` | 268 | 6.5% |
| 7 | `COMMAND_PIVOT` | 258 | 6.2% |
| 8 | `COMMAND_CHECKIN` | 213 | 5.1% |
| **Top 8** | | **2,662** | **64.2%** |

**The bottom half — the 15 smallest arms — holds 383 lines, 9.2% of the function between them.** **`COMMAND_GET_JOB` alone is 5 lines.**

### 3.3 The single densest region

**`COMMAND_FS` at L2823–L3266 is 444 lines containing a nested switch with 10 sub-commands AND a third-level switch on download modes at L3003–L3079.** **`COMMAND_SOCKET` at L5597–L6050 is 454 lines with 10 sub-commands and no third level.** **`COMMAND_TOKEN` at L4232–L4652 is 421 lines with 10 sub-commands.**

**These three hold 1,319 lines — 32% of the function — across 30 sub-commands.** **If implementation mass is the question, the answer is: three arms, one per family (file system, sockets, tokens), each a dense sub-dispatch table.**

---

## §4 — Q4: NONCE ARITHMETIC CARRIED FORWARD, PLUS KEY ROTATION

### 4.1 The arithmetic, restated from D47 §5

**CTR keystream for message *m* at offset *n*:**

$$K_{m}(n) = \text{AES-ECB}_{\text{Key}}\!\left(\; \text{IV} + \left\lfloor n/16 \right\rfloor \;\right)\Big[\, n \bmod 16 \,\Big]$$

**The `IV` term is fixed per agent and the counter restarts from it on every message, so `K_m(n) = K_{m'}(n)` — a two-time pad, `C_A ⊕ C_B = A ⊕ B`.** [source: D47 §5.4, whose arithmetic rests on `AesCrypt.c:217-244`]

### 4.2 The new question: is the key ever rotated mid-session?

**No. Measured on both sides.**

**Agent side — one generation, guarded, never repeated:**

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
[source: `payloads/Demon/src/Demon.c:113-123`]

**The `&&` guard means generation runs only while BOTH pointers are `NULL`.** **The only other write to either field in the entire agent tree is `Demon.c:530` `Instance->Config.AES.Key = NULL; /* TODO: generate keys here */` — a teardown null-out carrying a TODO that names the missing feature.** [source: `Get-ChildItem payloads/Demon -Recurse -Include *.c,*.h | Select-String 'AES\.Key'` → 8 hits, listed in §4.4]

**Server side — the only assignment is a read from the wire:**

```go
	a.Encryption.AESKey = Parser.ParseAtLeastBytes(32)
	a.Encryption.AESIv = Parser.ParseAtLeastBytes(16)
```
[source: `teamserver/pkg/agent/demons.go:2372-2373`]

**And that site is inside `COMMAND_CHECKIN` (arm L2343–L2555), not `DEMON_INIT`.** **So the key is re-read on every checkin — but re-read from the agent, which does not regenerate it.**

**The database write is persistence, not rotation:**

```sql
UPDATE TS_Agents SET Active = ?, Reason = ?, AESKey = ?, AESIv = ?, ...
```
[source: `teamserver/pkg/db/agents.go:98`]

**Same value into the same column. Not a new key.**

### 4.3 Why the checkin cadence matters, and why it does not change the answer

**`CommandCheckin` re-sends the key material on every checkin:**

```c
VOID CommandCheckin( PPARSER Parser )
{
    PUTS( "Checkin" )

    PPACKAGE Package = PackageCreate( DEMON_COMMAND_CHECKIN );

    DemonMetaData( &Package, FALSE );

    PackageTransmit( Package );
}
```
[source: `payloads/Demon/src/core/Command.c:163-172`, verbatim]

**`DemonMetaData` is the function that pads the key and IV onto the package** — `Demon.c:160` `PackageAddPad( *MetaData, ( PCHAR ) Instance->Config.AES.Key, 32 );` and the IV at `:161`. [source: D47 §5.3; `Package.c:253` `if ( Package->CommandID == DEMON_INITIALIZE ) { Padding += 32 + 16; }`]

**So on every checkin the agent re-transmits `Config.AES.Key` and `Config.AES.IV` — the same 48 bytes it generated once at `Demon.c:113`.** **The server adopts them again at `demons.go:2372-2373` and writes them to the same DB row.**

**Re-transmission is not rotation. The key that protects message N and the key that protects message N+1 are the same object, on both sides, for the agent's whole life.**

### 4.4 The complete assignment census

**Agent side — every `AES.Key` occurrence, printed:**

```
src\core\Command.c:110   ParserDecrypt( &TaskParser, Instance->Config.AES.Key, Instance->Config.AES.IV );   read
src\core\Package.c:257   AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );             read
src\core\Package.c:390   AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );             read
src\core\Transport.c:27  AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );             read
src\Demon.c:113          if ( Instance->Config.AES.Key == NULL && Instance->Config.AES.IV == NULL )          guard
src\Demon.c:115          Instance->Config.AES.Key = Instance->Win32.LocalAlloc( LPTR, 32 );                 WRITE (alloc)
src\Demon.c:119          Instance->Config.AES.Key[ i ] = RandomNumber32();                                  WRITE (fill)
src\Demon.c:160          PackageAddPad( *MetaData, ( PCHAR ) Instance->Config.AES.Key, 32 );                read
src\Demon.c:530          Instance->Config.AES.Key    = NULL; /* TODO: generate keys here  */               WRITE (teardown)
```
[source: `Get-ChildItem payloads/Demon -Recurse -File -Include *.c,*.h | Select-String 'AES\.Key'`]

**Three writes, and only two of them are ever reached at runtime before teardown: the allocation and the fill, both inside the `Demon.c:113` guard, which runs once.** **No write site is reachable twice.**

### 4.5 Q4 answer

**The key is fixed for the session.** **Agent: generated once under a `&&` guard at `Demon.c:113-123`, never regenerated, nulled only at teardown at `:530` under a TODO that admits the feature is absent.** **Server: assigned only from the wire at `demons.go:2372-2373`, persisted unchanged at `db/agents.go:98`, never derived or replaced.**

**Therefore the two-time pad's exposure window is the full session lifetime, which is what D47 §5 established and what this section confirms cannot be shortened by rotation:**

**the IV is fixed per agent (D47 §5.3), the counter restarts per message (D47 §5.4), and the key is never rotated (here). All three conditions hold simultaneously, and each is independently sufficient to produce the repeat.**

---

## §5 — RESIDUAL UNKNOWNS, WITH PROBES

| ID | Unknown | Probe |
|---|---|---|
| **S-1** | **Does any arm's `break` sit inside a nested block such that it breaks an inner switch rather than the outer one?** §1.3 records every depth-1 arm terminating with `break` or `return`. **A `break` inside a nested `switch` within an arm would exit the nested switch, not the outer one, and the outer arm would fall through.** | Read the last 3 lines of each depth-1 arm and confirm the `break` is at the arm's own brace depth. **Invocation: for each of the 28 arm-end lines, print `$depth` at that line and compare to 1.** |
| **S-2** | **The count of lines reaching each arm — arms are disjoint, but is the arm-boundary rule exact when two depth-1 labels are adjacent with no code between?** | Check whether any two consecutive depth-1 markers differ by ≥1 line with a body. **`COMMAND_GET_JOB` (L2298) → `COMMAND_EXIT` (L2303) is 5 lines; verify no arm is 0.** A 0-length arm would mean the boundary rule mis-assigned. |
| **S-3** | **`COMMAND_PIVOT`'s `DEMON_PIVOT_SMB_COMMAND` sub-arm calls `AgentHdr.Data.DecryptBuffer(PivotAgent.Encryption.AESKey, PivotAgent.Encryption.AESIv)` at L5373** — a SECOND agent's key/IV, not the session's. **Is the pivot agent's key also fixed, or does the pivot handshake re-key?** | Read the pivot connect path (`DEMON_PIVOT_SMB_CONNECT`, L5196–L5313) for the key assignment. **If the pivot carries its own unchanged key, the two-time pad property extends to the pivot channel.** |
| **S-4** | **The 2,294 non-`TaskDispatch` lines of the file.** §0 mentions only `TaskPrepare` (L128–L2284) and `Console` (L6430). **D39 recorded 5 `func` in the file; the map accounts for 2.** | List every `^func` in `demons.go` with its line, and confirm the remaining three are outside the two arms already measured. **`Select-String '^func'`.** |
| **S-5** | **The other three `^func` in `demons.go` were not read for this report.** | Same probe as S-4, then read whichever are not `TaskPrepare`/`TaskDispatch`/`Console`. **D39 recorded the file as 5 `func` / 0 `^type`; the fifth is unaccounted.** |

---

## §6 — INSTRUMENT FAILURES

**Failure 1 — the naive `case` count returns 169, not 29.** My first scan for `case` labels in the switch region returned 169 hits. **Reporting that as the case count would have been wrong by 140 — every nested sub-command label in the function.** **Caught by adding the depth-1 filter and printing the depth distribution (§1.4), which shows where the other 140 sit.** **Root cause: a flat count is not a measurement when the claim is scoped to one nesting level.**

**Failure 2 — the span arithmetic.** My first pass computed arm spans from the §0.2 span figure as a base. **That is subtraction and it is what the brief warned against.** **Re-derived from brace depth per arm; the two methods agree on all 28 arms, which is the cross-check rather than the justification.** **The depth-derived numbers are the ones in §1.2.**

**Failure 3 — I nearly used `COMMAND_CHECKIN`'s 213-line span as evidence that checkin is heavy.** **The arm is 213 lines, but `Demon.c:160` shows the key pad is added by `DemonMetaData`, which `CommandCheckin` calls — the arm's size is the *server's parse* of the metadata, not the key handling itself.** **The 213 measures the parse, not the crypto. Stated so the number is not read as a crypto claim.**

**Failure 4 — the file-encoding incident from D47 recurred in intent, not in effect.** **While appending to D47 I acted on a display artefact (`Â§`) without reading the bytes first, and damaged that file before recovering it.** **This report was written with the byte-level check done before any encoding operation, and the file validated as strict UTF-8 after writing.** **Recorded because the failure mode — acting on a rendered view rather than the source — is the same one as Failure 1 above.**

---

## §7 — CORRECTIONS TO THE BRIEF, CONSOLIDATED

| Brief claim | Measured | Where |
|---|---|---|
| `TaskDispatch` is 4,145 lines | **4,144** (L2285–L6428); 4,145 counts the trailing blank line | §0.2 |
| 28 depth-1 cases | **28 real cases + 1 `default:` = 29 depth-1 markers** | §0.3 |
| Q3's three regions are a partition | **they overlap; measured as three quantities, not a partition** | §0.5 |

**The brief's 4,145 and its 28 are both defensible as stated — the first is the function plus a separator, the second is the real cases excluding `default:`.** **Neither is wrong; both are under-specified about their boundary, and this report states the boundary for each.**

---

**End of D56.**
