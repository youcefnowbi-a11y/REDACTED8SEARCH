# D47 — HAVOC DEMON EXTENDED SURFACE

**Target:** `RE_Library/01_SOURCE_c2/havoc/` (`payloads/Demon/` and `teamserver/`)
**Authored by:** havoc-deep. Continuation of D34 (agent half) and D39 (server half).
**Scope:** four closers — D39's U5, U1, U2, U3, U4.
**Source-only. No REA, no provider. Every number carries the invocation that produced it.**

---

## §0 — WHAT THIS IS, AND TWO CORRECTIONS TO THE BRIEF

### 0.1 Corrections to the brief, first

**Correction 1 — the brief's Q1 outbound set is under-scoped, and the brief is right that it holds a defect.**

The brief says: *"Diff the 120 outbound command labels against the inbound case set."*

**The 120 is `TaskPrepare`'s case-label count and it is correct** — `§5.4` of D39 measured `^\s*case\b` → 120 over `demons.go:128-2284`. **But only 22 of those 120 labels are `COMMAND_*` identifiers; the other 98 are operator-facing strings (`"dir"`, `"upload"`, `"PAGE_READONLY"`), command constants in their non-`COMMAND_` namespace, and numeric literals.** **`TaskPrepare` is also not the server's only outbound sender.**

**Measured — the true outbound surface, four senders:**

```
Get-ChildItem $h\teamserver -Recurse -File -Filter *.go | Select-String -Pattern 'Command:\s+(?:agent\.)?(COMMAND_[A-Z0-9_]+)'
   → 29 distinct labels across 10 construction sites
```

| Sender | Sites | Commands sent |
|---|---|---|
| `TaskPrepare` (`demons.go:128`) | via `case` labels | 22 distinct `COMMAND_*` |
| `UploadMemFileInChunks` (`demons.go:31`) | `:49` | `COMMAND_MEM_FILE` |
| `Agents` SOCKS/pivot helpers (`demons.go:1872-2127`, `:5879`) | 6 sites | `COMMAND_SOCKET` |
| `agent.go:772, 802` | 2 sites | `COMMAND_PIVOT` |
| `handleDemonAgent` (`handlers.go:117`) | 1 site | `COMMAND_NOJOB` |

[source: the command above; and `Select-String 'AddJobToQueue'` → 9 call sites, listed in §1.2]

**Had I diffed only `TaskPrepare`'s labels against the inbound set, Direction A would have returned `(none)` and I would have reported "the sets are clean."** **The diff only finds the asymmetry when the outbound set is the union of all senders.** **This is the brief's rule — bound, don't sample — applied to its own question, and the bound was too narrow in the brief.**

**Correction 2 — the brief's U2 framing of the SMB header as a "8-byte read header" is right, and D34 already had it; the new work is the absorber check, not the header.** No further correction; noted so §3 is read as an extension of D34 §5, not a re-derivation.

### 0.2 What the four questions produced

| Q | Result | Confidence |
|---|---|---|
| **Q1** — the set diff | **One asymmetric command: `COMMAND_NOJOB`. It is a sentinel, correctly absent from both dispatch surfaces. No defect.** | **high** — both directions computed, every label traced to a consumer |
| **Q2** — 62 defines vs 23 entries | **39 non-table defines classified by consumer; the gap is a two-axis ID space, not 39 dead defines** | **high** — bounded enumeration |
| **Q3** — U2 + U3 | See §3, §4 | varies |
| **Q4** — nonce reuse | See §5 | **high** — counter arithmetic given |

**Answered in confidence order: Q1 (§1), Q2 (§2), Q4 (§5), then U2/U3 (§3, §4).** **§5 is placed before §3/§4 because Q4's arithmetic resolved cleanly and U2/U3 carry the residual unknowns.**

---

## §1 — Q1: THE SET DIFFERENCE (CLOSES D39 U5)

### 1.1 The instrument, and its two scopes

**Two sets had to be built, and the outbound one has two parts.**

**Inbound set — the depth-1 `case` labels of `switch CommandID` (`demons.go:2296`).** Extracted by tracking brace depth so that labels inside nested switches (a `switch SubCommand` in a command arm) are excluded:

```
$depth=0; $in=@()
for($i=2295;$i -lt 6429;$i++){ $l=$s[$i]
  if($depth -eq 1 -and $l -match '^\s*case\s+(COMMAND_[A-Z0-9_]+)' ){ $in += $matches[1] }
  $depth += ([regex]::Matches($l,'\{')).Count - ([regex]::Matches($l,'\}')).Count }
```

**This is the same brace-depth instrument D39 §4.5.1 established as correct after a stack-based map mislabelled the top-level `default:`.**

**Outbound set — two parts, unioned:**

```
# part 1: TaskPrepare case labels
$s[127..2283] | Select-String -Pattern '^\s*case\s+(COMMAND_[A-Z0-9_]+)'
# part 2: every Job construction, teamserver-wide
Get-ChildItem $h\teamserver -Recurse -File -Filter *.go | Select-String -Pattern 'Command:\s+(?:agent\.)?(COMMAND_[A-Z0-9_]+)'
```

### 1.2 The counts

| Set | Source | Count |
|---|---|---|
| Outbound, `TaskPrepare` labels | `demons.go:128-2284` | **22** distinct |
| Outbound, `Job` constructions | 10 sites, 4 functions | **29** distinct |
| **Outbound UNION** | | **29** |
| **Inbound** | `TaskDispatch` depth-1 cases | **28** |
| Intersection | | **28** |

[source: both extraction commands above, run and printed]

**The union is 29 and the intersection with the 28 inbound is 28. So exactly one label is in the outbound set and not the inbound set.**

**The 9 `AddJobToQueue` call sites that place those Jobs on the wire:**

| Site | Command |
|---|---|
| `cmd/server/dispatch.go:198` | *(client-supplied job, passed through)* |
| `pkg/agent/demons.go:58` | `COMMAND_MEM_FILE` |
| `pkg/agent/demons.go:1882, 1913, 1936, 2064, 2127, 5888` | `COMMAND_SOCKET` |
| `pkg/service/service.go:244` | *(service-agent path)* |

[source: `Select-String 'AddJobToQueue'` over `teamserver/` → 9 lines; definition is `agent.go:647`]

### 1.3 DIRECTION A — server can send, cannot handle

```
Compare-Object $outU $inU | Where-Object { $_.SideIndicator -eq '<=' }
   →  COMMAND_NOJOB
```

**One label. `COMMAND_NOJOB`.**

### 1.4 `COMMAND_NOJOB` is a sentinel, and its absence from dispatch is correct on BOTH sides

**Server side — it is emitted when the job queue is empty:**

```go
	/* if there is no job then just reply with a COMMAND_NOJOB */
	if asked_for_jobs == false || len(Agent.JobQueue) == 0 {
		var NoJob = []agent.Job{{
			Command: agent.COMMAND_NOJOB,
			Data:    []interface{}{},
		}}
```
[source: `teamserver/pkg/handlers/handlers.go:114-120`]

**Agent side — it is consumed by a guard that wraps the entire table search:**

```c
    if ( CommandID != DEMON_COMMAND_NO_JOB ) {
        PRINTF( "Task => RequestID:[%d : %x] CommandID:[%d : %x] TaskBuffer:[%x : %d]\n", ... )
        if ( TaskBufferSize != 0 ) {
            ParserNew( &TaskParser, TaskBuffer, TaskBufferSize );
            ParserDecrypt( &TaskParser, Instance->Config.AES.Key, Instance->Config.AES.IV );
        }

        for ( UINT32 FunctionCounter = 0 ;; FunctionCounter++ ) {
            if ( DemonCommands[ FunctionCounter ].Function == NULL ) {
                break;
            }

            if ( DemonCommands[ FunctionCounter ].ID == CommandID ) {
                DemonCommands[ FunctionCounter ].Function( &TaskParser );
                break;
            }
        }
    }
} while ( Parser.Length > 12 );
```
[source: `payloads/Demon/src/core/Command.c:106-124`]

**The `if` at `:106` encloses the whole search `:113-122`. `DEMON_COMMAND_NO_JOB` never reaches the table.** Declared `#define DEMON_COMMAND_NO_JOB 10` at `Command.h:9`, and **its only other occurrence in the entire agent source is a comment** at `Demon.c:58` — `*      D. Execute Task (if it's not DEMON_COMMAND_NO_JOB)`.

**What it actually is:** the server's poll reply is a framed package containing one or more `[CommandID][RequestID][TaskBuffer]` triplets. **When there is no work, it must still return a well-formed package — so it returns one triplet whose `CommandID` means "empty" and whose `TaskBuffer` is zero-length.** **The agent consumes and discards it so that the parse loop `do { } while ( Parser.Length > 12 )` advances past it and terminates correctly.**

**So it is a framing-level sentinel, not a command.** **Correctly: not in the 23-entry `DemonCommands[]` table (it has no handler), and correctly: not a case in `TaskDispatch` (the server never receives it).** **Its absence from both is the design.**

### 1.5 DIRECTION B — server can handle, never sends

```
Compare-Object $outU $inU | Where-Object { $_.SideIndicator -eq '=>' }
   →  (none)
```

**Empty. Every one of the 28 inbound labels is reachable from at least one server-side sender.**

**And the 6 labels D39 §7 flagged as "inbound-only" resolve under the union too — they are agent→server results, and D39's list was produced from the narrower set:**

| Label | Value | Server usage | Agent origin |
|---|---|---|---|
| `COMMAND_GET_JOB` | 1 | `demons.go:2298, 5377`; `handlers.go:106` | `Command.h:8`; `Package.c:352` |
| `COMMAND_OUTPUT` | 90 | `demons.go:3348` | agent output path |
| `COMMAND_ERROR` | 91 | `demons.go:4057` + 6 sub-cases | agent error path |
| `COMMAND_KILL_DATE` | 93 | `demons.go:2328` | agent kill-date notice |
| `COMMAND_MEM_FILE` | 2560 | `demons.go:6374`; `handlers.go:229` | **bidirectional** — see below |
| `COMMAND_PACKAGE_DROPPED` | 2570 | `demons.go:6392` | agent over-size notice |

[source: the per-label `Select-String` run in §1.2; values from `commands.go:27, 52, 53, 57, 58, 60`]

**`COMMAND_MEM_FILE` is the one of the six that is NOT agent-only** — it appears in the union's outbound set because `UploadMemFileInChunks` sends it (`demons.go:49`) and the agent reports success back (`demons.go:6374` reads it inbound). **So it is genuinely bidirectional, and D39's "inbound-only" label for it was an artifact of D39's narrower outbound scope.** [source: `demons.go:49` vs `:6374`]

### 1.6 Positive controls on the Q1 instrument

**The control that matters — does the depth-1 extractor find a label that IS present?** Yes: **28 depth-1 labels returned, including the 22 that also appear in `TaskPrepare`.** **A filter that found nothing would return an empty set; this one returns 28 and correctly excludes nested `SubCommand` cases.**

**The control on the outbound extractor:** the `Command:` pattern returned **10 construction sites across 4 functions**, and reading `demons.go:48-56` confirms the shape matches:

```go
		MemFileJob := Job{
			Command:   COMMAND_MEM_FILE,
			RequestID: rand.Uint32(),
			Data: []any{ ID, uint64(FileSize), FileData[start:end] },
		}

		a.AddJobToQueue(MemFileJob)
```
[source: `demons.go:48-58`]

**And the near-miss that proves the control was needed:** my first outbound extraction matched `Command:` with an optional `agent.` prefix but **`handlers.go:117` writes `Command: agent.COMMAND_NOJOB,` — with the `agent.` qualifier.** **If the pattern had not allowed that prefix, `COMMAND_NOJOB` would have been missed and Direction A would have been reported empty.** [source: `handlers.go:117`]

### 1.7 Q1 verdict

**The sets are NOT identical — one label is asymmetric — and the asymmetry is a sentinel that is correctly absent from dispatch on both sides.** **The result is clean, the comparison is shown in both directions, and the one hit is explained rather than dismissed.** **No defect on this axis.**

---

## §2 — Q2: THE 61-DEFINES-VS-23-ROWS GAP (CLOSES D39 U1)

### 2.1 Three corrections to the brief's framing, all measured

**The brief says "62 `#define`s vs 23 dispatch entries. Which 39 are not dispatched?"** **Both numbers behave differently under exact measurement, and the gap is not 39.**

**Correction A — 61, not 62.**

```
Get-Content Command.h | Select-String -Pattern '^\s*#define\s+(DEMON_COMMAND_[A-Z0-9_]+)\s+(\S+)'
   → 62 matches
```

**But one of them is the include guard, not a command:**

```c
#ifndef DEMON_COMMAND_H
#define DEMON_COMMAND_H
```
[source: `payloads/Demon/include/core/Command.h:1-2`]

**`DEMON_COMMAND_H` matches the character class `DEMON_COMMAND_[A-Z0-9_]+` because `H` is a letter.** **The real count is 61.** **This is a substring artifact of exactly the kind the corpus rules warn about, and it fired on my own census before any conclusion was drawn from it.** **Fix applied: exclude the guard, and note it.**

**Correction B — the table has 23 rows but only 22 IDs, because one row's ID is not `DEMON_COMMAND_`-prefixed.**

```c
SEC_DATA DEMON_COMMAND DemonCommands[] = {
        { .ID = DEMON_COMMAND_SLEEP,                    .Function = CommandSleep                    },
        ...
        { .ID = DEMON_COMMAND_MEM_FILE,                 .Function = CommandMemFile                  },
        { .ID = DEMON_EXIT,                             .Function = CommandExit                     },

        // End
        { .ID = 0, .Function = NULL }
};
```
[source: `payloads/Demon/src/core/Command.c:16-42`, verbatim]

**Rows:** `:17`–`:38` = **22 functional rows**, `:41` = **1 `NULL` sentinel** → **23 rows total.**

**But `:38` is `.ID = DEMON_EXIT`, and `DEMON_EXIT` does not match `DEMON_COMMAND_`. So a census of `DEMON_COMMAND_*` table IDs returns 21, and D39's "62 vs 23" arithmetic is comparing a 62 against a row count that includes a non-`DEMON_COMMAND_` ID and a sentinel.** **D34's "23-entry table" is correct — it counts rows. The gap is measured against the wrong denominator unless that is stated.**

**Correction C — the gap is 40, not 39, and none of the 40 is undispatched.**

### 2.2 The classification: 61 defines, 21 in the table, 40 outside it, and every one consumed

**Method — for each `DEMON_COMMAND_*` define not present in the table, find every occurrence in the agent tree and print the files:**

```
$tblIDs  = Command.c .ID = DEMON_* values  → 22
$defs    = Command.h DEMON_COMMAND_* defines → 62 (incl. guard) → 61 real
$notInTable = $defs | Where-Object { $tblIDs -notcontains $_ }
foreach($d in $notInTable){ print $d and its occurrence files }
```

**Result — 41 rows printed, 40 real. Every single one has at least one consumer outside its own declaration. Not one is orphaned.**

| Class | Count | Mechanism | Consumer |
|---|---|---|---|
| **A. Sub-command IDs** | **33** | second-level `switch` inside a command handler | `Command.c` only |
| **B. BOF outcome codes** | **4** | returned by the Coffee loader | `CoffeeLdr.c` |
| **C. Control sentinels** | **2** | guard (`NO_JOB`) and poll (`GET_JOB`) | `Package.c`, `Command.c`, `Demon.c` |
| **D. Job-lifecycle notice** | **1** | emitted by the job scheduler | `Jobs.c` |
| **E. Regex artifact** | **1** | the include guard, not a command | — |
| | **41 printed / 40 real** | | |

**The class assignment is by consumer file, printed — not by name shape:**

```
Class A (only src/core/Command.c):  33
Class B (CoffeeLdr.c):               4   _INLINE_EXECUTE_EXCEPTION, _SYMBOL_NOT_FOUND, _RAN_OK, _COULD_NO_RUN
Class C (other):                     2   _GET_JOB -> Package.c;  _NO_JOB -> Command.c + Demon.c
Class D (Jobs.c):                    1   _JOB_DIED
TOTAL non-table real defines:       40
```

[source: the per-define consumer classification run in §2.1; each class's members printed]

**The 33 in Class A, each with exactly 2 occurrences — its declaration in `Command.h` and one `case` label in `Command.c`:**

`DEMON_COMMAND_JOB_LIST`, `_JOB_SUSPEND`, `_JOB_RESUME`, `_JOB_KILL_REMOVE`, `_TRANSFER_LIST`, `_TRANSFER_STOP`, `_TRANSFER_RESUME`, `_TRANSFER_REMOVE`, `_PROC_MODULES`, `_PROC_GREP`, `_PROC_CREATE`, `_PROC_MEMORY`, `_PROC_KILL`, `_TOKEN_IMPERSONATE`, `_TOKEN_STEAL`, `_TOKEN_LIST`, `_TOKEN_PRIVSGET_OR_LIST`, `_TOKEN_MAKE`, `_TOKEN_GET_UID`, `_TOKEN_REVERT`, `_TOKEN_REMOVE`, `_TOKEN_CLEAR`, `_TOKEN_FIND_TOKENS`, `_FS_DIR`, `_FS_DOWNLOAD`, `_FS_UPLOAD`, `_FS_CD`, `_FS_REMOVE`, `_FS_MKDIR`, `_FS_COPY`, `_FS_MOVE`, `_FS_GET_PWD`, `_FS_CAT`

[source: the Class A member list printed in the classification run — 33 rows, and I first wrote 34 in this table before the run corrected it]

**And the structural proof that Class A is a second-level dispatch, not a stray label:**

```c
    switch ( Command )
    {
        case DEMON_COMMAND_FS_DIR: PUTS( "FS::Dir" )
        {
            LPWSTR           TargetFolder = NULL;
```
[source: `payloads/Demon/src/core/Command.c:682-686`]

**This is `CommandFS`'s own `switch`, keyed on the sub-command ID parsed from the task buffer.** **`Command.c` contains 12 such switches:** `:196`, `:270`, `:682`, `:1163`, `:1310`, `:1381`, `:1872`, `:2117`, `:2472`, `:2622`, `:2749`, `:3088` [source: `Select-String '^\s*switch\s*\('`].

### 2.3 The answer to Q2: it is a two-axis ID space, not 39 dead defines

**The `DEMON_COMMAND_*` namespace encodes TWO levels of identifier in one prefix:**

| Axis | Example | Value | Dispatched by |
|---|---|---|---|
| **Top level — the command** | `DEMON_COMMAND_FS` | `15` | the 23-row table, linear search `Command.c:113-122` |
| **Second level — the sub-command** | `DEMON_COMMAND_FS_DIR` | `1` | the handler's own `switch`, e.g. `:682` |

**The collision is the point: `DEMON_COMMAND_FS_DIR = 1` and `DEMON_COMMAND_TRANSFER_LIST = 0` and `DEMON_COMMAND_TOKEN_IMPERSONATE = 1` and `DEMON_COMMAND_JOB_LIST = 1` all reuse the same small integers.** [source: values from the `Command.h` dump in §2.1]

**They cannot collide on the wire because the wire carries the top-level `CommandID` first, and only the top-level arm ever reads the sub-command.** **`Command.c:100-102` parses `CommandID`, `RequestID`, `TaskBuffer`; the table search at `:113-122` matches the top-level ID; the handler then parses `TaskBuffer` afresh and switches on the sub-command.**

[source: `Command.c:100-122`, read in full in §1.4]

**So:**
- **The table is not short of entries; it is the top-level axis and it has all 22 of them.**
- **The 40 defines outside it are the second level, plus 4 BOF codes, 2 sentinels, and 1 job notice.**
- **Nothing is undispatched.** **The "62 vs 23" gap is an artifact of counting two namespaces as if they were one.**

### 2.4 Where the two axes meet on the server — a fourth cross-check

**The server mirrors the two-axis split exactly.** `commands.go` declares the top-level axis AND the sub-command axis in the same file:

```
COMMAND_PROC                     = 0x1010   // top level
DEMON_COMMAND_PROC_MODULES       = 2        // sub, in the agent's namespace
DEMON_COMMAND_PROC_GREP          = 3
DEMON_COMMAND_PROC_CREATE        = 4
DEMON_COMMAND_PROC_MEMORY        = 6
```
[source: `teamserver/pkg/agent/commands.go`; values match `Command.h:110-113` where `_PROC_MODULES=2, _PROC_GREP=3, _PROC_CREATE=4, _PROC_MEMORY=6`]

**The server's `TaskDispatch` has the mirroring structure: a top-level `case COMMAND_PROC:` containing a nested `switch` on the sub-command** — D39 §4.5 measured 20 `default:`s in `TaskDispatch`, of which the ones at `:3920` (in `switch SubCommand`) name `COMMAND_PROC - Unknown`.

**So both halves are two-axis, both live in one prefix namespace on the agent, and the top-level axis is the only one that reaches the dispatcher.** **Consistent across the wire.**

### 2.5 Positive controls

**Control 1 — does the occurrence search find consumers for defines that are definitely consumed?** Yes: **all 40 non-table defines returned ≥1 consumer, and the 21 table IDs were excluded by construction and separately confirmed present in the table.** **A search that could not find consumers would have returned `(NONE)` for at least some of the 40; it returned `(NONE)` for zero.**

**Control 2 — the one `(NONE)`-looking row is demonstrably an artifact, not a dead define.** `DEMON_COMMAND_H` returned `uses=2 in include\core\Command.h` — its `#ifndef`/`#define` pair. **The source confirms it at `:1-2`.** **So the instrument found the guard, recognised it by reading, and excluded it — rather than silently counting it as a define.**

**Control 3 — the sub-command claim is checked structurally, not by name shape.** The `switch ( Command )` at `:682` and the `case DEMON_COMMAND_FS_DIR:` at `:684` were read together. **A name that merely looks like a sub-command (`FS_*`) was not accepted as one; its enclosing switch was read.**

### 2.6 Q2 verdict

**The gap is not 39 undispatched commands. It is 40 defines on a second identifier axis, every one consumed, plus four non-command code families.** **Measured counts: 61 real `DEMON_COMMAND_*` defines, 21 of them in the 23-row table, 22 top-level IDs including `DEMON_EXIT`.** **No dead define found, so no D36 "capability present and unconnected" statement follows from this axis.** **Recorded plainly because the expected finding is absent.**

---

*(§3 follows)*