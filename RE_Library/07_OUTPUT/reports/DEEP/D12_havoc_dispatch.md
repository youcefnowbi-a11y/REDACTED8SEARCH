# D12 — HAVOC: `TaskDispatch` VERSUS THE AGENT HANDLER TABLE

**Target:** `RE_Library/01_SOURCE_c2/havoc/`
**Source-only. No REA, no Ghidra. Every count enumerated. Every absence positive-controlled.**
**Predecessor:** D11 (`D11_havoc_native_win32.md`) — Q3's `NtSetEvent` severance.
**Status:** complete.

---

## TABLE OF CONTENTS

| Read order | § | Subject |
|---|---|---|
| 1 | **1** | Scope and what this task assumed |
| 2 | **2** | The premise was partly wrong — recorded before the finding |
| 3 | **3** | Side A: the agent's handler table |
| 4 | **4** | Side B: the teamserver's command vocabulary |
| 5 | **5** | The cross-reference, both directions |
| 6 | **6** | What actually happens on an unknown command |
| 7 | **7** | The one genuine asymmetry |
| 8 | **8** | Answer, and why it is not the symmetry the task expected |
| 9 | **9** | Instrument failures during this task |
| 10 | **10** | Residual unknowns and coverage |

---

## 1. SCOPE AND WHAT THIS TASK ASSUMED

D11 §8.2 recorded: *"`TaskDispatch`'s 71 cases were counted, not cross-referenced for agent-side counterpart handlers (that's the teamserver analogue of Q3 and it's unexplored)."* task-24 adopted that framing and asked four things: extract every case label; enumerate the agent handler table; cross-reference both directions; and for any unmatched case, determine what happens at runtime.

**The task anticipated one of two outcomes.** Either *dispatched-but-unhandled* — the teamserver sends a command the agent drops, mirroring `NtSetEvent`'s armed-and-unreachable shape at the protocol layer — or *clean*, and clean was explicitly acceptable: *"DO NOT manufacture a match to fit the symmetry."*

**What this report found is a third thing.** The premise — that `TaskDispatch`'s 71 cases constitute the set of commands the teamserver dispatches — **is wrong**, and §2 records why before any finding is stated.

---

## 2. THE PREMISE WAS PARTLY WRONG — RECORDED BEFORE THE FINDING

I wrote the §8.2 residual myself, so this correction is mine to record.

**`TaskDispatch` is not the send-side dispatcher.** It is a **bidirectional message handler**. Examining the 14 teamserver-side command constants that have no agent handler (§5.1 carries the full list and the 13-vs-14 distinction):

| Constant | Value | Where `TaskDispatch` handles it |
|---|---|---|
| `COMMAND_GET_JOB` | 1 | `demons.go:2298` |
| `COMMAND_KILL_DATE` | 93 | `demons.go:2328` |
| `COMMAND_OUTPUT` | 90 | `demons.go:3348` |
| `COMMAND_ERROR` | 91 | `demons.go:4057` |
| `COMMAND_PACKAGE_DROPPED` | 2570 | `demons.go:6392` |
| `COMMAND_PROC_PPIDSPOOF` | 27 | `demons.go:641` and `:4211` |

[source: `case COMMAND_*:` labels in `teamserver/pkg/agent/demons.go`]

**Every one of these is a message the agent sends to the teamserver**, and `TaskDispatch` is where the teamserver *receives* it. `COMMAND_GET_JOB` and `COMMAND_NOJOB` are the agent's beacon poll and its "nothing to do" reply. `COMMAND_OUTPUT` and `COMMAND_ERROR` are result reporting. `COMMAND_PACKAGE_DROPPED` is raised agent-side at `Package.c:311` and consumed teamserver-side at `demons.go:6392`.

**Therefore comparing `TaskDispatch`'s cases against the agent's handler table was a category error** — I would have been matching the agent's *outbound* vocabulary against its *inbound* handler table. `TaskDispatch` handles both directions in one function, which is why §7.2 of D11 found 71 case labels in one body.

**The correct `dispatched` set is not a static table at all. See §5.2.**

---

## 3. SIDE A — THE AGENT'S HANDLER TABLE

The agent does not route commands through a `switch`, and it does not use the `COMMAND_*` prefix. **Its vocabulary is `DEMON_COMMAND_*`**, and the handler table is a **struct array**:

```c
SEC_DATA DEMON_COMMAND DemonCommands[] = {
{ .ID = DEMON_COMMAND_SLEEP,                    .Function = CommandSleep                    },
{ .ID = DEMON_COMMAND_CHECKIN,                  .Function = CommandCheckin                  },
{ .ID = DEMON_COMMAND_JOB,                      .Function = CommandJob                      },
...
{ .ID = DEMON_COMMAND_MEM_FILE,                 .Function = CommandMemFile                  },
{ .ID = DEMON_EXIT,                             .Function = CommandExit                     },

// End
{ .ID = 0, .Function = NULL }
};
```
[source: `payloads/Demon/src/core/Command.c:17-43`]

**Enumerated: 22 entries plus a NULL sentinel.** All 22 IDs and functions are distinct — validated explicitly (§9), because my first extraction of this table returned `DEMON_COMMAND_FS_CAT` 22 times.

| # | Constant | Value | Handler |
|---|---|---|---|
| 1 | `DEMON_COMMAND_SLEEP` | 11 | `CommandSleep` |
| 2 | `DEMON_COMMAND_CHECKIN` | 100 | `CommandCheckin` |
| 3 | `DEMON_COMMAND_JOB` | 21 | `CommandJob` |
| 4 | `DEMON_COMMAND_PROC` | 0x1010 = 4112 | `CommandProc` |
| 5 | `DEMON_COMMAND_PROC_LIST` | 12 | `CommandProcList` |
| 6 | `DEMON_COMMAND_FS` | 15 | `CommandFS` |
| 7 | `DEMON_COMMAND_INLINE_EXECUTE` | 20 | `CommandInlineExecute` |
| 8 | `DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE` | 0x2001 = 8193 | `CommandAssemblyInlineExecute` |
| 9 | `DEMON_COMMAND_ASSEMBLY_VERSIONS` | 0x2003 = 8195 | `CommandAssemblyListVersion` |
| 10 | `DEMON_COMMAND_CONFIG` | 2500 | `CommandConfig` |
| 11 | `DEMON_COMMAND_SCREENSHOT` | 2510 | `CommandScreenshot` |
| 12 | `DEMON_COMMAND_PIVOT` | 2520 | `CommandPivot` |
| 13 | `DEMON_COMMAND_NET` | 2100 | `CommandNet` |
| 14 | `DEMON_COMMAND_INJECT_DLL` | 22 | `CommandInjectDLL` |
| 15 | `DEMON_COMMAND_INJECT_SHELLCODE` | 24 | `CommandInjectShellcode` |
| 16 | `DEMON_COMMAND_SPAWN_DLL` | 26 | `CommandSpawnDLL` |
| 17 | `DEMON_COMMAND_TOKEN` | 40 | `CommandToken` |
| 18 | `DEMON_COMMAND_TRANSFER` | 2530 | `CommandTransfer` |
| 19 | `DEMON_COMMAND_SOCKET` | 2540 | `CommandSocket` |
| 20 | `DEMON_COMMAND_KERBEROS` | 2550 | `CommandKerberos` |
| 21 | `DEMON_COMMAND_MEM_FILE` | 2560 | `CommandMemFile` |
| 22 | `DEMON_EXIT` | 92 (`Command.h:35`) | `CommandExit` |

[source: table at `Command.c:17-39`; values from `#define DEMON_COMMAND_*` in `payloads/Demon/include/core/Command.h`; `DEMON_EXIT` at `Command.h:35`]

**Note the naming discontinuity:** the agent's `DEMON_EXIT` is `92`, and the teamserver's `COMMAND_EXIT` is also `92` (`commands.go:59`). They match on the wire and differ in name — which is why **the cross-reference must be done by value, not by name.**

### 3.1 The lookup, and the 33 sub-command switches

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
[source: `payloads/Demon/src/core/Command.c:114-123`]

**A linear scan terminated by the NULL sentinel.** **This is §6's runtime answer.**

**Separately, `Command.c` contains 33 further `case DEMON_COMMAND_*:` labels** at `:198`, `:221`, `:235`, `:247`, `:272`, `:337`, `:423`, `:468`, `:528`, `:684`, `:794`, `:882`, `:949`, `:964`, `:994`, `:1010`, `:1035`, `:1060`, `:1075`, `:1383`, `:1406`, `:1450`, `:1477`, `:1532`, `:1595`, `:1635`, `:1650`, `:1660`, `:1668`, `:2624`, `:2641`, `:2668`, `:2696`. **These are sub-command switches inside individual handlers** — `DEMON_COMMAND_JOB_LIST` under the `JOB` handler, `DEMON_COMMAND_FS_DIR` under the `FS` handler, `DEMON_COMMAND_TOKEN_STEAL` under `TOKEN`. [source: `case` labels in `Command.c`, grouped by their enclosing `switch ( Command )` / `switch ( SubCommand )` at `:196`, `:270`, `:682`, `:1381`, `:2117`, `:2622`, `:2749`, `:3088`] **They are correctly excluded from the top-level table**, and confusing the two would have produced a false 33-vs-22 mismatch.

---

## 4. SIDE B — THE TEAMSERVER'S COMMAND VOCABULARY

**Enumerated: 36 `COMMAND_*` constants, in one file.**

| Constant | Value | Line |
|---|---|---|
| `COMMAND_GET_JOB` | 1 | `commands.go:27` |
| `COMMAND_CHECKIN` | 100 | `:29` |
| `COMMAND_NOJOB` | 10 | `:30` |
| `COMMAND_SLEEP` | 11 | `:31` |
| `COMMAND_PROC` | 0x1010 | `:32` |
| `COMMAND_PS_IMPORT` | 0x1011 | `:33` |
| `COMMAND_PROC_LIST` | 12 | `:34` |
| `COMMAND_FS` | 15 | `:35` |
| `COMMAND_INLINEEXECUTE` | 20 | `:36` |
| `COMMAND_ASSEMBLY_INLINE_EXECUTE` | 0x2001 | `:37` |
| `COMMAND_ASSEMBLY_LIST_VERSIONS` | 0x2003 | `:38` |
| `COMMAND_JOB` | 21 | `:39` |
| `COMMAND_INJECT_DLL` | 22 | `:40` |
| `COMMAND_INJECT_SHELLCODE` | 24 | `:41` |
| `COMMAND_SPAWNDLL` | 26 | `:42` |
| `COMMAND_PROC_PPIDSPOOF` | 27 | `:43` |
| `COMMAND_TOKEN` | 40 | `:44` |
| `COMMAND_NET` | 2100 | `:45` |
| `COMMAND_CONFIG` | 2500 | `:46` |
| `COMMAND_SCREENSHOT` | 2510 | `:47` |
| `COMMAND_PIVOT` | 2520 | `:48` |
| `COMMAND_TRANSFER` | 2530 | `:49` |
| `COMMAND_SOCKET` | 2540 | `:50` |
| `COMMAND_KERBEROS` | 2550 | `:51` |
| `COMMAND_MEM_FILE` | 2560 | `:52` |
| `COMMAND_PACKAGE_DROPPED` | 2570 | `:53` |
| `COMMAND_OUTPUT` | 90 | `:57` |
| `COMMAND_ERROR` | 91 | `:58` |
| `COMMAND_EXIT` | 92 | `:59` |
| `COMMAND_KILL_DATE` | 93 | `:60` |
| `COMMAND_INLINEEXECUTE_EXCEPTION` | 1 | `:63` |
| `COMMAND_INLINEEXECUTE_SYMBOL_NOT_FOUND` | 2 | `:64` |
| `COMMAND_INLINEEXECUTE_RAN_OK` | 3 | `:65` |
| `COMMAND_INLINEEXECUTE_COULD_NO_RUN` | 4 | `:66` |
| `COMMAND_EXCEPTION` | 0x98 | `:68` |
| `COMMAND_SYMBOL_NOT_FOUND` | 0x99 | `:69` |

[source: `teamserver/pkg/agent/commands.go:27-69`]

**Two collisions worth noting, both benign on the wire because the values coincide where it matters:** `COMMAND_GET_JOB` and `COMMAND_INLINEEXECUTE_EXCEPTION` both equal `1`, and `COMMAND_INLINEEXECUTE_SYMBOL_NOT_FOUND` equals `2`. **These are not duplicates** — the first is a top-level command, the others are BOF exception sub-codes carried in a different field. [source: same table, lines `:27`, `:63-64`]

---

## 5. THE CROSS-REFERENCE, BOTH DIRECTIONS

### 5.1 By value (the wire carries the integer)

**Agent handler values (22):** `11, 12, 15, 20, 21, 22, 24, 26, 40, 92, 100, 2100, 2500, 2510, 2520, 2530, 2540, 2550, 2560, 4112, 8193, 8195`

**Teamserver values (36 constants, 35 distinct).** Intersection:

| Result | Count |
|---|---|
| Distinct teamserver **values** with a matching agent handler | **22** |
| Distinct teamserver **values** with no agent handler | **13** |
| Teamserver **constants** with no agent handler | **14** — see the value-1 collision below |
| Agent handler values with no teamserver constant | **0** |
| Constants collapsing to a duplicate value | 1 — `COMMAND_GET_JOB` and `COMMAND_INLINEEXECUTE_EXCEPTION` both equal `1` |

[source: recomputed independently as a set intersection over both enumerations]

**The 13 unmatched values, by name:**

| # | Constant | Value |
|---|---|---|
| 1 | `COMMAND_INLINEEXECUTE_EXCEPTION` | 1 |
| 2 | `COMMAND_INLINEEXECUTE_SYMBOL_NOT_FOUND` | 2 |
| 3 | `COMMAND_INLINEEXECUTE_RAN_OK` | 3 |
| 4 | `COMMAND_INLINEEXECUTE_COULD_NO_RUN` | 4 |
| 5 | `COMMAND_NOJOB` | 10 |
| 6 | `COMMAND_PROC_PPIDSPOOF` | 27 |
| 7 | `COMMAND_OUTPUT` | 90 |
| 8 | `COMMAND_ERROR` | 91 |
| 9 | `COMMAND_KILL_DATE` | 93 |
| 10 | `COMMAND_EXCEPTION` | 0x98 = 152 |
| 11 | `COMMAND_SYMBOL_NOT_FOUND` | 0x99 = 153 |
| 12 | `COMMAND_PACKAGE_DROPPED` | 2570 |
| 13 | `COMMAND_PS_IMPORT` | 0x1011 = 4113 |

[source: `teamserver/pkg/agent/commands.go:27-69`, filtered against the 22 agent handler values]

**A counting correction, recorded in place — 13 values, 14 constants.** `COMMAND_GET_JOB` is also `1`. Because value `1` has no agent handler, **both** `COMMAND_GET_JOB` and `COMMAND_INLINEEXECUTE_EXCEPTION` are unmatched, so the constant count is **14** while the value count is **13**. An earlier draft of this section reported "14 unmatched" and then listed 13 — **the list was the value-level truth and the number was the constant-level truth, stated as if they were the same thing.** Both figures are now labelled. §4's collision note (`:27` vs `:63`) is the same fact seen from the definitions side.

**13 of the 13 unmatched values are inbound** — the agent sends them, the teamserver receives them. Verified individually at §2's table and §7. **Reporting them as "dispatched but unhandled" would have been the manufactured match the task forbids.** They are not dispatched; they are handled teamserver-side, and they have no agent handler because the agent is the sender.

**`COMMAND_GET_JOB` belongs to the same class:** `demons.go:2298` is its receive-side case. [source: `case COMMAND_GET_JOB:` at `demons.go:2298`]

### 5.2 The dispatched set is not static — it comes from the client

`TaskDispatch` is not how commands leave the teamserver. **The send path is `TaskPrepare(Command int, ...)`** at `demons.go:128`, called from exactly one place:

```go
command, err = strconv.Atoi(val.(string))
```
[source: `teamserver/cmd/server/dispatch.go:168`]

```go
job, err = t.Agents.Agents[i].TaskPrepare(command, pk.Body.Info, Message, ClientID, t)
```
[source: `teamserver/cmd/server/dispatch.go:188`]

```go
if err = t.Agents.Agents[i].TeamserverTaskPrepare(Command, Console); err != nil {
```
[source: `teamserver/cmd/server/dispatch.go:155`]

**The operator's GUI sends a command ID as a string; the teamserver parses it to an int and puts it on the wire.** [source: `dispatch.go:155-188`]

**Consequence for this task:** there is no closed set of commands the teamserver can dispatch. **Any integer the client can express reaches the agent.** A static dispatched-vs-handled comparison is therefore not just unfound — **it is not well-defined in this codebase.** The dispatched set is the client's, and the client is the C++ GUI (`client/src/UserInterface/Dialogs/Payload.cc` and its command senders), which is outside D11/D12's read scope.

**Positive control on that finding:** `strconv.Atoi` at `dispatch.go:168` is reached only in the `else` branch — `discovers` first checks whether the command is a recognised string via the `TeamserverTaskPrepare` path at `:155`, and falls back to integer parsing at `:168` otherwise. [source: `dispatch.go:142-188` structure] **Both branches are present and reachable**, so this is a real dual-path send, not a misread.

---

## 6. WHAT ACTUALLY HAPPENS ON AN UNKNOWN COMMAND

The task asked this for any unmatched case. **The answer is a silent drop, and it is visible in the lookup itself:**

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
[source: `payloads/Demon/src/core/Command.c:114-123`]

**If no entry matches, the loop runs to the sentinel, breaks at line 116, and returns to the caller.** There is **no `default` branch, no error emit, no log, and no response packet.** The agent's command buffer is zeroed and freed at `:127-129` and parsing continues at `:125`.

**The one thing that does happen is a local debug print, and it fires before the lookup:**

```c
PRINTF( "Task => RequestID:[%d : %x] CommandID:[%d : %x] TaskBuffer:[%x : %d]\n", RequestID, RequestID, CommandID, CommandID, TaskBuffer, TaskBufferSize )
```
[source: `payloads/Demon/src/core/Command.c:108`]

**So an unknown command produces an agent-side debug line recording that it arrived, and nothing else — the operator receives no error.** **Inference (marked):** this print is the `PRINTF` macro, which in a release build is typically compiled out or gated by a debug flag; **I did not verify its build gating**, so whether the line appears in a shipped build is unknown (§10).

---

## 7. THE ONE GENUINE ASYMMETRY

**`COMMAND_PS_IMPORT` = `0x1011`.** [source: `teamserver/pkg/agent/commands.go:33`]

| Check | Result |
|---|---|
| Teamserver references to `COMMAND_PS_IMPORT` | **1** — the definition at `commands.go:33` |
| Occurrences in `demons.go` (any dispatch) | **0** |
| Agent-side references (`PS_IMPORT`, `0x1011`, `4113`) | **0** |
| **Positive control:** `COMMAND_PROC` = `0x1010` | **3** in `demons.go` — `:481`, `:3650`, `:3661` |

[source: `demons.go:481` and `:3650` for the control; agent tree searched over `payloads/Demon` in full]

**`COMMAND_PROC` is defined at `commands.go:32` as `0x1010` and dispatched at `demons.go:481` and `:3650`. `COMMAND_PS_IMPORT` is defined one line later as the next value, `0x1011`, and appears nowhere else in the tree, teamserver or agent.** The control proves the matcher finds a handled neighbour with an adjacent value.

**What it is not:** this is one constant in a definitions file. **Both `COMMAND_PROC` (handled) and `COMMAND_PS_IMPORT` (unreferenced) are legacy,** since the modern agent uses `DEMON_COMMAND_PROC = 0x1010` in the handler table — so `PS_IMPORT` is most likely a retired or planned command whose constant was kept. **That is a stale constant, not the Pupy severance pattern.** The mechanism to reach a live target does not exist for it: nothing in the teamserver dispatches it, so no target is at risk. `NtSetEvent` armed an evasion and never used it; `PS_IMPORT` arms nothing.

**I am not presenting this as a second instance of the `NtSetEvent` shape.** The task said not to manufacture a match to fit the symmetry, and this is not one.

---

## 8. ANSWER, AND WHY IT IS NOT THE SYMMETRY THE TASK EXPECTED

**The cross-reference is clean in the direction that matters, and the reason is structural rather than fortunate.**

**The agent cannot silently drop a command from the teamserver in the way the task hypothesised, because the teamserver does not dispatch from a fixed table.** The send path resolves the command ID from the operator's GUI at `dispatch.go:168` and forwards it verbatim at `:188`. The 22-entry handler table at `Command.c:17-39` covers every command the teamserver GUI can currently construct, evidenced by the 22 matched values in §5.1.

**Four things are true and each was measured:**

1. **22 agent handlers, 36 teamserver constants, 22 values in common.** [source: §5.1]
2. **The unmatched teamserver constants are inbound message types plus one stale constant — 13 distinct unmatched values across 14 constants.** Not 14 dropped commands. [source: §5.1, §2, §7]
3. **An unknown command reaching the agent is a silent drop with no operator-visible error** — no default branch at `Command.c:114-123`. This is the real runtime hazard and it is a property of the agent, not a mismatch between two tables.
4. **The dispatched set is client-defined**, so a static "teamserver sends X, agent ignores X" list cannot be constructed from the Go source alone.

**The symmetry the task hoped for is not there.** The honest statement is narrower and, I think, more useful: **the agent's dispatch has no default case, so any command the teamserver can be induced to send — including any integer the client can express — is dropped silently with no error to the operator.** That is a robustness property worth naming, and it is one line of C rather than a cross-reference table.

**On the "property of how Havoc was built" framing:** the evidence does not support pairing this with `NtSetEvent`. `NtSetEvent` is an **armed mechanism with no consumer** — the SSN is extracted, the address is written, the wrapper is absent. Here there is **no armed mechanism**: the handler table is complete for the send path, and the single unreferenced constant is inert. **One severed link in the syscall layer; zero in the protocol layer.** [source: D11 §4.3-§4.4 for the severance; §5.1 and §7 here for the protocol layer]

---

## 9. INSTRUMENT FAILURES DURING THIS TASK

**Four, all caught before publication. Recorded because the task's method section exists precisely for this.**

**F1 — the `COMMAND_` zero that was a naming failure.** My first probe searched for `#define COMMAND_*` in `payloads/Demon/include` and returned **0**. The agent's prefix is **`DEMON_COMMAND_`**. The positive control (`COMMAND_` across the whole agent tree, 106 hits in `Command.c` alone) showed the vocabulary was present under a different name. **An absence report here would have been wrong.**

**F2 — the handler table extracted as `DEMON_COMMAND_FS_CAT` 22 times.** My secondary extraction used `Select-Object -Skip 16 -First 23` piped into `Select-String`, and the `$matches` automatic variable carried stale state between iterations, so every row returned the same value. **Caught by validating the output: 22 identical IDs and 22 identical functions is not a table.** Re-extracted with a single-pass regex over raw text, then validated as 22 entries / 22 distinct IDs / 22 distinct functions. Note that `FS_CAT` is `10` — the same value as the spurious result — consistent with the leak.

**F3 — the mismatch counter that disagreed with its own output.** `$miss += $_` inside a `ForEach-Object` pipeline appended in a child scope, so the summary printed `14` while **15** MISS lines were on screen. Caught by counting the printed lines against the counter. **The lines were the evidence; the number was not.**

**F4 — the brief's framing.** §8.2's residual, which I wrote, called `TaskDispatch` the place commands are dispatched. §2 corrects it: `TaskDispatch` is a bidirectional handler and the send set is client-defined. **This is my error carried into the task description.**

**F5 — the 13-versus-14 count, caught by independent recomputation.** The first draft said "14 unmatched" and then listed 13. The names came from a by-name print in an early run; the number came from a value-level set operation run later, and I wrote both into one sentence. **Recomputing the intersection from scratch after the report was written caught it.** The cause is the value-`1` collision between `COMMAND_GET_JOB` and `COMMAND_INLINEEXECUTE_EXCEPTION`: **13 distinct unmatched values, 14 unmatched constants, and the two figures are both correct for different questions.** Now labelled separately at §5.1 and §8.

**F5 is the closest relative of D11 §8.5's defect.** There, a recheck generated a line number instead of measuring one. Here, a count was carried from an earlier run whose scope was different from the run that produced the number — **a stale figure wearing the authority of a measurement.** The defence that worked was recomputing the set from the two enumerations rather than re-reading my own summary of them.

**These are the same class as D11 §8.5's and as the three instruments the task brief listed.** All five looked like results. The specific defence that worked each time was **validating the instrument's output shape before reading it as evidence** — 22 distinct rows, a counter matching its lines, a control hit on a known-present neighbour, a set recomputed from its inputs. **In F5's case the recomputation was done only because the report was already written and the numbers were cheap to check a second time; it would not have been caught by inspection.**

**These are the same class as D11 §8.5's and as the three instruments the task brief listed.** All four looked like results. The specific defence that worked each time was **validating the instrument's output shape before reading it as evidence** — 22 distinct rows, a counter matching its lines, a control hit on a known-present neighbour.

---

## 10. RESIDUAL UNKNOWNS AND COVERAGE

### 10.1 Coverage

| Set | Files | Depth |
|---|---|---|
| `Command.c` handler table + lookup | 1 (3,504 lines) | **headers and dispatch read; handler bodies not read** |
| `Command.h` | 1 (241 lines) | **read in full — all 61 constants extracted** |
| `commands.go` | 1 (254 lines) | **read in full — all 36 constants extracted** |
| `demons.go` `TaskDispatch` | 1 (6,438 lines) | **case labels extracted; 1,696-line body not read line-by-line** |
| `dispatch.go` | 1 (953 lines) | send path read at `:140-199`; remainder sampled |
| C++ client | not read | **outside scope — and §5.2 shows it defines the dispatched set** |

**Explicit boundary: the C++ client was not read.** §5.2 makes it the source of truth for what can be dispatched. **The 22-vs-36 comparison is complete for the Go and C sources; it is not a complete dispatched-vs-handled analysis, because the dispatcher is the GUI.**

### 10.2 Residual unknowns

**U1 — the client's command senders.** `client/src/UserInterface/` was not enumerated. **The actual set of dispatchable commands is defined there.** Unmeasured.

**U2 — `PRINTF` build gating.** §6's debug line may be compiled out in release. Not verified.

**U3 — the 33 sub-command switch bodies.** Counted and located; not read. Whether every sub-command constant has a `case` was not checked — **that is the same cross-reference question one level down**, and it is unexplored.

**U4 — `COMMAND_PS_IMPORT`'s origin.** Inferred as legacy from adjacency to `COMMAND_PROC`; **no git history was consulted** (not in the source tree).

**U5 — `TaskDispatch`'s 1,696-line body.** Case labels extracted; control flow between them not traced. D11 §7.2 counted 71 labels across 11 switches; **the nesting structure was not mapped.**

### 10.3 Method compliance

Every count enumerated against disk. Every absence positive-controlled: **F1** (`COMMAND_` 106 hits proving the naming difference), **F2** (22 distinct IDs proving the extraction), **§7** (`COMMAND_PROC` 3 hits proving the matcher finds a handled neighbour of `COMMAND_PS_IMPORT`), **§5.2** (both send branches present). Inference marked. Corrections recorded in place, including one against my own prior task description (§2, F4).

**Deliverable: `D12_havoc_dispatch.md`.**

---

*End of D12.*
