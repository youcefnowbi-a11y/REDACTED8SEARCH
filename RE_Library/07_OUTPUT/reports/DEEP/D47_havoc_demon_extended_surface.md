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

*(§2 follows)*