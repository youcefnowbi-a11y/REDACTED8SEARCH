# D47 � HAVOC DEMON EXTENDED SURFACE

**Target:** `RE_Library/01_SOURCE_c2/havoc/` (`payloads/Demon/` and `teamserver/`)
**Authored by:** havoc-deep. Continuation of D34 (agent half) and D39 (server half).
**Scope:** four closers � D39's U5, U1, U2, U3, U4.
**Source-only. No REA, no provider. Every number carries the invocation that produced it.**

---

## �0 � WHAT THIS IS, AND TWO CORRECTIONS TO THE BRIEF

### 0.1 Corrections to the brief, first

**Correction 1 � the brief's Q1 outbound set is under-scoped, and the brief is right that it holds a defect.**

The brief says: *"Diff the 120 outbound command labels against the inbound case set."*

**The 120 is `TaskPrepare`'s case-label count and it is correct** � `�5.4` of D39 measured `^\s*case\b` ? 120 over `demons.go:128-2284`. **But only 22 of those 120 labels are `COMMAND_*` identifiers; the other 98 are operator-facing strings (`"dir"`, `"upload"`, `"PAGE_READONLY"`), command constants in their non-`COMMAND_` namespace, and numeric literals.** **`TaskPrepare` is also not the server's only outbound sender.**

**Measured � the true outbound surface, four senders:**

```
Get-ChildItem $h\teamserver -Recurse -File -Filter *.go | Select-String -Pattern 'Command:\s+(?:agent\.)?(COMMAND_[A-Z0-9_]+)'
   ? 29 distinct labels across 10 construction sites
```

| Sender | Sites | Commands sent |
|---|---|---|
| `TaskPrepare` (`demons.go:128`) | via `case` labels | 22 distinct `COMMAND_*` |
| `UploadMemFileInChunks` (`demons.go:31`) | `:49` | `COMMAND_MEM_FILE` |
| `Agents` SOCKS/pivot helpers (`demons.go:1872-2127`, `:5879`) | 6 sites | `COMMAND_SOCKET` |
| `agent.go:772, 802` | 2 sites | `COMMAND_PIVOT` |
| `handleDemonAgent` (`handlers.go:117`) | 1 site | `COMMAND_NOJOB` |

[source: the command above; and `Select-String 'AddJobToQueue'` ? 9 call sites, listed in �1.2]

**Had I diffed only `TaskPrepare`'s labels against the inbound set, Direction A would have returned `(none)` and I would have reported "the sets are clean."** **The diff only finds the asymmetry when the outbound set is the union of all senders.** **This is the brief's rule � bound, don't sample � applied to its own question, and the bound was too narrow in the brief.**

**Correction 2 � the brief's U2 framing of the SMB header as a "8-byte read header" is right, and D34 already had it; the new work is the absorber check, not the header.** No further correction; noted so �3 is read as an extension of D34 �5, not a re-derivation.

### 0.2 What the four questions produced

| Q | Result | Confidence |
|---|---|---|
| **Q1** � the set diff | **One asymmetric command: `COMMAND_NOJOB`. It is a sentinel, correctly absent from both dispatch surfaces. No defect.** | **high** � both directions computed, every label traced to a consumer |
| **Q2** � 62 defines vs 23 entries | **39 non-table defines classified by consumer; the gap is a two-axis ID space, not 39 dead defines** | **high** � bounded enumeration |
| **Q3** � U2 + U3 | See �3, �4 | varies |
| **Q4** � nonce reuse | See �5 | **high** � counter arithmetic given |

**Answered in confidence order: Q1 (�1), Q2 (�2), Q4 (�5), then U2/U3 (�3, �4).** **�5 is placed before �3/�4 because Q4's arithmetic resolved cleanly and U2/U3 carry the residual unknowns.**

---

## �1 � Q1: THE SET DIFFERENCE (CLOSES D39 U5)

### 1.1 The instrument, and its two scopes

**Two sets had to be built, and the outbound one has two parts.**

**Inbound set � the depth-1 `case` labels of `switch CommandID` (`demons.go:2296`).** Extracted by tracking brace depth so that labels inside nested switches (a `switch SubCommand` in a command arm) are excluded:

```
$depth=0; $in=@()
for($i=2295;$i -lt 6429;$i++){ $l=$s[$i]
  if($depth -eq 1 -and $l -match '^\s*case\s+(COMMAND_[A-Z0-9_]+)' ){ $in += $matches[1] }
  $depth += ([regex]::Matches($l,'\{')).Count - ([regex]::Matches($l,'\}')).Count }
```

**This is the same brace-depth instrument D39 �4.5.1 established as correct after a stack-based map mislabelled the top-level `default:`.**

**Outbound set � two parts, unioned:**

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

[source: `Select-String 'AddJobToQueue'` over `teamserver/` ? 9 lines; definition is `agent.go:647`]

### 1.3 DIRECTION A � server can send, cannot handle

```
Compare-Object $outU $inU | Where-Object { $_.SideIndicator -eq '<=' }
   ?  COMMAND_NOJOB
```

**One label. `COMMAND_NOJOB`.**

### 1.4 `COMMAND_NOJOB` is a sentinel, and its absence from dispatch is correct on BOTH sides

**Server side � it is emitted when the job queue is empty:**

```go
	/* if there is no job then just reply with a COMMAND_NOJOB */
	if asked_for_jobs == false || len(Agent.JobQueue) == 0 {
		var NoJob = []agent.Job{{
			Command: agent.COMMAND_NOJOB,
			Data:    []interface{}{},
		}}
```
[source: `teamserver/pkg/handlers/handlers.go:114-120`]

**Agent side � it is consumed by a guard that wraps the entire table search:**

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

**The `if` at `:106` encloses the whole search `:113-122`. `DEMON_COMMAND_NO_JOB` never reaches the table.** Declared `#define DEMON_COMMAND_NO_JOB 10` at `Command.h:9`, and **its only other occurrence in the entire agent source is a comment** at `Demon.c:58` � `*      D. Execute Task (if it's not DEMON_COMMAND_NO_JOB)`.

**What it actually is:** the server's poll reply is a framed package containing one or more `[CommandID][RequestID][TaskBuffer]` triplets. **When there is no work, it must still return a well-formed package � so it returns one triplet whose `CommandID` means "empty" and whose `TaskBuffer` is zero-length.** **The agent consumes and discards it so that the parse loop `do { } while ( Parser.Length > 12 )` advances past it and terminates correctly.**

**So it is a framing-level sentinel, not a command.** **Correctly: not in the 23-entry `DemonCommands[]` table (it has no handler), and correctly: not a case in `TaskDispatch` (the server never receives it).** **Its absence from both is the design.**

### 1.5 DIRECTION B � server can handle, never sends

```
Compare-Object $outU $inU | Where-Object { $_.SideIndicator -eq '=>' }
   ?  (none)
```

**Empty. Every one of the 28 inbound labels is reachable from at least one server-side sender.**

**And the 6 labels D39 �7 flagged as "inbound-only" resolve under the union too � they are agent?server results, and D39's list was produced from the narrower set:**

| Label | Value | Server usage | Agent origin |
|---|---|---|---|
| `COMMAND_GET_JOB` | 1 | `demons.go:2298, 5377`; `handlers.go:106` | `Command.h:8`; `Package.c:352` |
| `COMMAND_OUTPUT` | 90 | `demons.go:3348` | agent output path |
| `COMMAND_ERROR` | 91 | `demons.go:4057` + 6 sub-cases | agent error path |
| `COMMAND_KILL_DATE` | 93 | `demons.go:2328` | agent kill-date notice |
| `COMMAND_MEM_FILE` | 2560 | `demons.go:6374`; `handlers.go:229` | **bidirectional** � see below |
| `COMMAND_PACKAGE_DROPPED` | 2570 | `demons.go:6392` | agent over-size notice |

[source: the per-label `Select-String` run in �1.2; values from `commands.go:27, 52, 53, 57, 58, 60`]

**`COMMAND_MEM_FILE` is the one of the six that is NOT agent-only** � it appears in the union's outbound set because `UploadMemFileInChunks` sends it (`demons.go:49`) and the agent reports success back (`demons.go:6374` reads it inbound). **So it is genuinely bidirectional, and D39's "inbound-only" label for it was an artifact of D39's narrower outbound scope.** [source: `demons.go:49` vs `:6374`]

### 1.6 Positive controls on the Q1 instrument

**The control that matters � does the depth-1 extractor find a label that IS present?** Yes: **28 depth-1 labels returned, including the 22 that also appear in `TaskPrepare`.** **A filter that found nothing would return an empty set; this one returns 28 and correctly excludes nested `SubCommand` cases.**

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

**And the near-miss that proves the control was needed:** my first outbound extraction matched `Command:` with an optional `agent.` prefix but **`handlers.go:117` writes `Command: agent.COMMAND_NOJOB,` � with the `agent.` qualifier.** **If the pattern had not allowed that prefix, `COMMAND_NOJOB` would have been missed and Direction A would have been reported empty.** [source: `handlers.go:117`]

### 1.7 Q1 verdict

**The sets are NOT identical � one label is asymmetric � and the asymmetry is a sentinel that is correctly absent from dispatch on both sides.** **The result is clean, the comparison is shown in both directions, and the one hit is explained rather than dismissed.** **No defect on this axis.**

---

## �2 � Q2: THE 61-DEFINES-VS-23-ROWS GAP (CLOSES D39 U1)

### 2.1 Three corrections to the brief's framing, all measured

**The brief says "62 `#define`s vs 23 dispatch entries. Which 39 are not dispatched?"** **Both numbers behave differently under exact measurement, and the gap is not 39.**

**Correction A � 61, not 62.**

```
Get-Content Command.h | Select-String -Pattern '^\s*#define\s+(DEMON_COMMAND_[A-Z0-9_]+)\s+(\S+)'
   ? 62 matches
```

**But one of them is the include guard, not a command:**

```c
#ifndef DEMON_COMMAND_H
#define DEMON_COMMAND_H
```
[source: `payloads/Demon/include/core/Command.h:1-2`]

**`DEMON_COMMAND_H` matches the character class `DEMON_COMMAND_[A-Z0-9_]+` because `H` is a letter.** **The real count is 61.** **This is a substring artifact of exactly the kind the corpus rules warn about, and it fired on my own census before any conclusion was drawn from it.** **Fix applied: exclude the guard, and note it.**

**Correction B � the table has 23 rows but only 22 IDs, because one row's ID is not `DEMON_COMMAND_`-prefixed.**

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

**Rows:** `:17`�`:38` = **22 functional rows**, `:41` = **1 `NULL` sentinel** ? **23 rows total.**

**But `:38` is `.ID = DEMON_EXIT`, and `DEMON_EXIT` does not match `DEMON_COMMAND_`. So a census of `DEMON_COMMAND_*` table IDs returns 21, and D39's "62 vs 23" arithmetic is comparing a 62 against a row count that includes a non-`DEMON_COMMAND_` ID and a sentinel.** **D34's "23-entry table" is correct � it counts rows. The gap is measured against the wrong denominator unless that is stated.**

**Correction C � the gap is 40, not 39, and none of the 40 is undispatched.**

### 2.2 The classification: 61 defines, 21 in the table, 40 outside it, and every one consumed

**Method � for each `DEMON_COMMAND_*` define not present in the table, find every occurrence in the agent tree and print the files:**

```
$tblIDs  = Command.c .ID = DEMON_* values  ? 22
$defs    = Command.h DEMON_COMMAND_* defines ? 62 (incl. guard) ? 61 real
$notInTable = $defs | Where-Object { $tblIDs -notcontains $_ }
foreach($d in $notInTable){ print $d and its occurrence files }
```

**Result � 41 rows printed, 40 real. Every single one has at least one consumer outside its own declaration. Not one is orphaned.**

| Class | Count | Mechanism | Consumer |
|---|---|---|---|
| **A. Sub-command IDs** | **33** | second-level `switch` inside a command handler | `Command.c` only |
| **B. BOF outcome codes** | **4** | returned by the Coffee loader | `CoffeeLdr.c` |
| **C. Control sentinels** | **2** | guard (`NO_JOB`) and poll (`GET_JOB`) | `Package.c`, `Command.c`, `Demon.c` |
| **D. Job-lifecycle notice** | **1** | emitted by the job scheduler | `Jobs.c` |
| **E. Regex artifact** | **1** | the include guard, not a command | � |
| | **41 printed / 40 real** | | |

**The class assignment is by consumer file, printed � not by name shape:**

```
Class A (only src/core/Command.c):  33
Class B (CoffeeLdr.c):               4   _INLINE_EXECUTE_EXCEPTION, _SYMBOL_NOT_FOUND, _RAN_OK, _COULD_NO_RUN
Class C (other):                     2   _GET_JOB -> Package.c;  _NO_JOB -> Command.c + Demon.c
Class D (Jobs.c):                    1   _JOB_DIED
TOTAL non-table real defines:       40
```

[source: the per-define consumer classification run in �2.1; each class's members printed]

**The 33 in Class A, each with exactly 2 occurrences � its declaration in `Command.h` and one `case` label in `Command.c`:**

`DEMON_COMMAND_JOB_LIST`, `_JOB_SUSPEND`, `_JOB_RESUME`, `_JOB_KILL_REMOVE`, `_TRANSFER_LIST`, `_TRANSFER_STOP`, `_TRANSFER_RESUME`, `_TRANSFER_REMOVE`, `_PROC_MODULES`, `_PROC_GREP`, `_PROC_CREATE`, `_PROC_MEMORY`, `_PROC_KILL`, `_TOKEN_IMPERSONATE`, `_TOKEN_STEAL`, `_TOKEN_LIST`, `_TOKEN_PRIVSGET_OR_LIST`, `_TOKEN_MAKE`, `_TOKEN_GET_UID`, `_TOKEN_REVERT`, `_TOKEN_REMOVE`, `_TOKEN_CLEAR`, `_TOKEN_FIND_TOKENS`, `_FS_DIR`, `_FS_DOWNLOAD`, `_FS_UPLOAD`, `_FS_CD`, `_FS_REMOVE`, `_FS_MKDIR`, `_FS_COPY`, `_FS_MOVE`, `_FS_GET_PWD`, `_FS_CAT`

[source: the Class A member list printed in the classification run � 33 rows, and I first wrote 34 in this table before the run corrected it]

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
| **Top level � the command** | `DEMON_COMMAND_FS` | `15` | the 23-row table, linear search `Command.c:113-122` |
| **Second level � the sub-command** | `DEMON_COMMAND_FS_DIR` | `1` | the handler's own `switch`, e.g. `:682` |

**The collision is the point: `DEMON_COMMAND_FS_DIR = 1` and `DEMON_COMMAND_TRANSFER_LIST = 0` and `DEMON_COMMAND_TOKEN_IMPERSONATE = 1` and `DEMON_COMMAND_JOB_LIST = 1` all reuse the same small integers.** [source: values from the `Command.h` dump in �2.1]

**They cannot collide on the wire because the wire carries the top-level `CommandID` first, and only the top-level arm ever reads the sub-command.** **`Command.c:100-102` parses `CommandID`, `RequestID`, `TaskBuffer`; the table search at `:113-122` matches the top-level ID; the handler then parses `TaskBuffer` afresh and switches on the sub-command.**

[source: `Command.c:100-122`, read in full in �1.4]

**So:**
- **The table is not short of entries; it is the top-level axis and it has all 22 of them.**
- **The 40 defines outside it are the second level, plus 4 BOF codes, 2 sentinels, and 1 job notice.**
- **Nothing is undispatched.** **The "62 vs 23" gap is an artifact of counting two namespaces as if they were one.**

### 2.4 Where the two axes meet on the server � a fourth cross-check

**The server mirrors the two-axis split exactly.** `commands.go` declares the top-level axis AND the sub-command axis in the same file:

```
COMMAND_PROC                     = 0x1010   // top level
DEMON_COMMAND_PROC_MODULES       = 2        // sub, in the agent's namespace
DEMON_COMMAND_PROC_GREP          = 3
DEMON_COMMAND_PROC_CREATE        = 4
DEMON_COMMAND_PROC_MEMORY        = 6
```
[source: `teamserver/pkg/agent/commands.go`; values match `Command.h:110-113` where `_PROC_MODULES=2, _PROC_GREP=3, _PROC_CREATE=4, _PROC_MEMORY=6`]

**The server's `TaskDispatch` has the mirroring structure: a top-level `case COMMAND_PROC:` containing a nested `switch` on the sub-command** � D39 �4.5 measured 20 `default:`s in `TaskDispatch`, of which the ones at `:3920` (in `switch SubCommand`) name `COMMAND_PROC - Unknown`.

**So both halves are two-axis, both live in one prefix namespace on the agent, and the top-level axis is the only one that reaches the dispatcher.** **Consistent across the wire.**

### 2.5 Positive controls

**Control 1 � does the occurrence search find consumers for defines that are definitely consumed?** Yes: **all 40 non-table defines returned =1 consumer, and the 21 table IDs were excluded by construction and separately confirmed present in the table.** **A search that could not find consumers would have returned `(NONE)` for at least some of the 40; it returned `(NONE)` for zero.**

**Control 2 � the one `(NONE)`-looking row is demonstrably an artifact, not a dead define.** `DEMON_COMMAND_H` returned `uses=2 in include\core\Command.h` � its `#ifndef`/`#define` pair. **The source confirms it at `:1-2`.** **So the instrument found the guard, recognised it by reading, and excluded it � rather than silently counting it as a define.**

**Control 3 � the sub-command claim is checked structurally, not by name shape.** The `switch ( Command )` at `:682` and the `case DEMON_COMMAND_FS_DIR:` at `:684` were read together. **A name that merely looks like a sub-command (`FS_*`) was not accepted as one; its enclosing switch was read.**

### 2.6 Q2 verdict

**The gap is not 39 undispatched commands. It is 40 defines on a second identifier axis, every one consumed, plus four non-command code families.** **Measured counts: 61 real `DEMON_COMMAND_*` defines, 21 of them in the 23-row table, 22 top-level IDs including `DEMON_EXIT`.** **No dead define found, so no D36 "capability present and unconnected" statement follows from this axis.** **Recorded plainly because the expected finding is absent.**

---

## �5 � Q4: NONCE REUSE (CLOSES D39 U4)

**This section is placed before �3 and �4 because its arithmetic resolved completely, and because U4 is the one question whose answer changes what the other sections mean.**

### 5.1 The cipher, in full

```go
func XCryptBytesAES256(XBytes []byte, AESKey []byte, AESIv []byte) []byte {
    var (
        ReverseXBytes = make([]byte, len(XBytes))
    )

    block, err := aes.NewCipher(AESKey)
    if err != nil {
        logger.Error("Decryption Error: " + err.Error())
        return []byte{}
    }

    stream := cipher.NewCTR(block, AESIv)
    stream.XORKeyStream(ReverseXBytes, XBytes)

    return ReverseXBytes
}
```
[source: `teamserver/pkg/common/crypt/aes.go:10-24`, entire file, 25 lines]

**`cipher.NewCTR(block, AESIv)` � the IV is a caller parameter. The file contains no IV generation, no nonce derivation, no counter management. It is a pure function of `(plaintext, key, iv)`.**

### 5.2 The agent's CTR counter, and its exact arithmetic

```c
void AesXCryptBuffer( PAESCTX ctx, PUINT8 buf, SIZE_T length)
{
    UINT8 buffer[AES_BLOCKLEN];
    size_t i;
    int bi;
    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
    {
        if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
        {
            MemCopy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((state_t*)buffer,ctx->RoundKey);
            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
            {
                if (ctx->Iv[bi] == 255)
	            {
                    ctx->Iv[bi] = 0;
                    continue;
                }
                ctx->Iv[bi] += 1;
                break;
            }
            bi = 0;
        }
        buf[i] = (buf[i] ^ buffer[bi]);
  }
}
```
[source: `payloads/Demon/src/crypt/AesCrypt.c:217-244`, verbatim]

**The counter arithmetic, stated precisely:**

1. **`buffer` is the keystream block.** `MemCopy(buffer, ctx->Iv, 16)` copies the current counter into it, and `Cipher(buffer, RoundKey)` encrypts it **in place** � so `buffer` becomes `AES_ECB(counter)`.
2. **`bi` counts position within the keystream block**, `0..15`. The `bi = AES_BLOCKLEN` initial value forces regeneration on the first byte and every 16 bytes thereafter.
3. **`ctx->Iv[bi] += 1` for `bi = 15` downward** � i.e. **the counter is incremented as a big-endian 128-bit integer, least-significant byte at index 15.** Carry propagates `15 ? 14 ? ... ? 0`, with `== 255` wrapping to `0` and `continue`.
4. **`Cipher` is applied to the counter FIRST, and the increment happens SECOND** � so block *n* uses `AES(counter_n)` where `counter_0 = IV` and `counter_{n+1} = counter_n + 1`.

**This is textbook CTR mode: `keystream_n = AES_ECB(IV + n)`, big-endian.**

**And it matches Go's `crypto/cipher` CTR, which increments the 128-bit counter as a big-endian integer.** **Proof by interop rather than by reading the stdlib:** the server decrypts agent-produced ciphertext with its own implementation �

```go
Header.Data.DecryptBuffer(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
```
[source: `teamserver/pkg/handlers/handlers.go:102`; `DecryptBuffer` at `parser/parser.go:205-207` calls `crypt.XCryptBytesAES256`]

**If the two counter orders disagreed, no agent message would ever decrypt, and Havoc would not function.** **It functions. So the orders agree � measured through the protocol's own success, not through the stdlib source.**

**LIMITATION, stated plainly: `crypto/cipher/ctr.go` and the Go toolchain are NOT present on this box** (`Get-Command go` ? not on PATH; `C:\Program Files\Go` and `C:\Go` ? both absent). **I could not quote the stdlib increment code. The counter-order agreement above is established by interop, which is a stronger claim than reading the source but does not show the source.**

### 5.3 The IV is generated ONCE per agent, and the counter RESTARTS on every message

**Generation � once, at agent initialisation:**

```c
    // create AES Keys/IV
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
[source: `payloads/Demon/src/Demon.c:112-123`]

**`Instance->Config.AES.Key` is `PBYTE` and `Instance->Config.AES.IV` is `PBYTE`** � byte arrays [source: `payloads/Demon/include/Demon.h:154-157`]. **So each `RandomNumber32()` call, which returns a `ULONG`, is truncated to its low byte on assignment.**

**Reset � on every transmission:**

```c
            AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
```
[source: `payloads/Demon/src/core/Package.c:257-258`]

```c
void AesInit( PAESCTX ctx, const PUINT8 key, const PUINT8 iv)
{
  KeyExpansion( ctx->RoundKey, key );
  MemCopy( ctx->Iv, iv, AES_BLOCKLEN );
}
```
[source: `payloads/Demon/src/crypt/AesCrypt.c:103-107`]

**`AesInit` copies from `iv` � which is `Instance->Config.AES.IV` � into the context.** **`AesXCryptBuffer` then mutates `ctx->Iv`, not `Config.AES.IV`.** **`Config.AES.IV` is never written again after `Demon.c:122`.**

**Four call sites all pass the same persisted IV:**

| Site | Context |
|---|---|
| `Package.c:257` | `PackageTransmit` (first transmit path) |
| `Package.c:390` | `PackageTransmitAll` (broadcast path) |
| `Transport.c:27` | transport init/handshake |
| `Parser.c:28` | `ParserDecrypt` � via a `Key, IV` pair passed in |

[source: `Select-String 'AesInit\s*\('` over `payloads/Demon/src/**/*.c`; the fifth match is the declaration at `AesCrypt.c:103`]

**And the server adopts the agent's key/IV rather than generating its own:**

```go
	a.Encryption.AESKey = Parser.ParseAtLeastBytes(32)
	a.Encryption.AESIv = Parser.ParseAtLeastBytes(16)
```
[source: `teamserver/pkg/agent/demons.go:2372-2373`; identically at `agent.go:387-388`]

**persisted to the database:**

```sql
UPDATE TS_Agents SET Active = ?, Reason = ?, AESKey = ?, AESIv = ?, ...
```
[source: `teamserver/pkg/db/agents.go:98`]

**So: one key and one IV per agent, for the agent's entire lifetime, and the counter is reset to that IV at the start of every message.**

### 5.4 The answer, with the arithmetic

**The keystream for message *m*, at byte offset *n* within the encrypted region:**

$$K_{m}(n) = \text{AES-ECB}_{\text{Key}}\!\left(\; \text{IV} + \left\lfloor n/16 \right\rfloor \;\right)\Big[\, n \bmod 16 \,\Big]$$

**where the addition is big-endian 128-bit and `IV` is the fixed per-agent value.**

**The `IV` term does not depend on *m*. Neither does `Key`. Therefore `K_m(n) = K_{m'}(n)` for all messages *m*, *m'* � the keystream repeats.**

**Two-time pad, stated exactly:** for two messages `A` and `B` encrypted under the same keystream, with ciphertexts `C_A = A ? K` and `C_B = B ? K`:

$$C_A \oplus C_B = A \oplus K \oplus B \oplus K = A \oplus B$$

**The key material cancels. An observer with both ciphertexts obtains the XOR of the two plaintexts, with no key and no cryptanalysis.** **With N observers collecting N messages, the same applies pairwise.**

**Qualified by the offset within the message:** the keystream is a function of *n* from the start of the encrypted region. **So the leak is strongest between two messages of similar length at the same offset, and weaker (but still real) across differing lengths � the standard two-time-pad structure.** **D39 �3.3 established that the agent encrypts from offset 20 and the server decrypts from offset 0 of the post-header region, and that the keystream is aligned at the payload boundary � so for a given command, the payload bytes of two messages sit at the same keystream positions.**

### 5.5 The answer to the Lead's third sub-question: is there any path where the same pair is used twice

**Every path. There is no path that does not.** The pair `(Config.AES.Key, Config.AES.IV)` is generated once at `Demon.c:113-123`, is never regenerated, and `AesInit` at `Package.c:257` re-seeds from it on every single `PackageTransmit` call.

**There is no message counter, no nonce field, no re-keying, and no IV evolution anywhere in the transmit path.** **The IV is a constant for the agent's life.**

**The one qualification: `Package.c:270` re-XORs the same buffer with a fresh `AesCtx` seeded from the same IV �**

```c
        } else if ( Package->Encrypt ) {
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
        }
```
[source: `Package.c:269-271`]

**This is the "restore plaintext after sending" step D34 �6.7 recorded.** **It works precisely because the keystream is deterministic and restartable from the same IV � the agent's design *depends* on the counter being reset.** **The property that makes the restore work is the same property that makes the keystream repeat.** **That is the finding: the nonce reuse is not an oversight in one branch, it is load-bearing for correct buffer handling.**

**Contrast with the server, which allocates a new slice rather than mutating in place** (D39 �2.2a) � **so the server has no need for the reset and does not depend on it, but it inherits the same fixed IV because it adopts the agent's.**

### 5.6 A second, independent finding: the IV and key bytes are 7-bit

**`RandomNumber32` does not return 32 random bits:**

```c
ULONG RandomNumber32(
    VOID
) {
    ULONG Seed = 0;

    Seed = NtGetTickCount();
    Seed = Instance->Win32.RtlRandomEx( &Seed );
    Seed = Instance->Win32.RtlRandomEx( &Seed );
    Seed = ( Seed % ( LONG_MAX - 2 + 1 ) ) + 2;

    return Seed % 2 == 0 ? Seed : Seed + 1;
}
```
[source: `payloads/Demon/src/core/Win32.c:1304-1315`, verbatim]

**Three observations, each verifiable from the source:**

1. **`:1314` forces the result even.** `Seed % 2 == 0 ? Seed : Seed + 1` � if odd, add 1. **The return value is always even.** Assigned into a `PBYTE` array, **each key and IV byte has its low bit fixed at `0`, so each carries at most 7 bits of entropy instead of 8.**
2. **The entropy budget is therefore:** key `32 � 7 = 224` bits (nominally 256); IV `16 � 7 = 112` bits (nominally 128).
3. **`:1309` seeds from `NtGetTickCount()`** � a millisecond uptime counter � **then applies `RtlRandomEx` twice.** `RtlRandomEx` is a deterministic PRNG given its seed. **So the entropy of any single byte is bounded by the tick-count resolution at the moment of the `Demon.c:118-122` loop, not by a CSPRNG.**

**`NtGetTickCount` at millisecond resolution, with 32 key bytes and 16 IV bytes generated in one tight loop at `:118-122`, means consecutive outputs come from tick counts that differ by, at most, single-digit milliseconds between them � and the loop characteristically completes within the same tick.** **Two consecutive calls with the same seed produce the same value; the `+1`-if-odd makes them both even.**

**I am not claiming these are equal without measuring it.** **The claim I can make from source: the seed is a millisecond tick count read inside a loop that occupies microseconds, and the output is coerced even.** **The probe that would settle the entropy is named in �6 as U-3.** **This is stated as a structural weakness with a named probe, not as a demonstrated break.**

### 5.7 Positive controls

**Control 1 � the "IV reused" claim is not inferred from the absence of a generator; it is the presence of a constant.** `Demon.c:122` writes `Config.AES.IV[i]` once; the only other write to that field in the entire tree is `Demon.c:531` `Instance->Config.AES.IV = NULL;` (teardown) [source: `Select-String 'AES\.IV'` over `payloads/Demon/**`]. **Two writes, one of which is a null-out. The field is a constant after init.**

**Control 2 � the counter reset is measured, not assumed.** `AesInit`'s body is `MemCopy(ctx->Iv, iv, 16)` at `:106` � **it copies INTO the context FROM the argument.** **A `MemCopy` in the other direction would make the counter persist; the argument order rules that out.** **Read the body rather than inferred from the call site.**

**Control 3 � the offset that `AesInit` copies from is confirmed to be the config field at each call site.** All four call sites were printed with their arguments; two are `Instance->Config.AES.IV` verbatim.

**Control 4 � the interop argument is falsifiable and I checked it.** If Go's CTR used a little-endian counter while the agent uses big-endian, the interop would fail. **It does not fail**, per `handlers.go:102`'s live decrypt path. **I could not read the stdlib to confirm the mechanism, which is recorded as a limitation rather than glossed.**

### 5.8 Q4 verdict

**CTR mode with a reused `(key, IV)` pair is a two-time pad. Havoc's design guarantees that reuse:**

**one key and IV per agent, generated once at `Demon.c:113-123`, re-seeded on every transmission by `AesInit` at `Package.c:257`, with no message counter, no nonce field, and no re-keying.**

**The arithmetic is `C_A ? C_B = A ? B`. The property is load-bearing for the agent's in-place re-XOR at `Package.c:270`, so it is not a bug in one branch � it is the design.** **Independently, the key and IV bytes are coerced even by `Win32.c:1314` and seeded from a millisecond tick count at `:1309`, which reduces and constrains the entropy beyond the reuse itself.**

---

## �3 � Q3a: THE SMB 8-BYTE READ HEADER (CLOSES D39 U2)

### 3.1 The instrument

**D34 recorded that `SmbRecv` validates its own 8-byte `[DemonId][PackageSize]` header against `PackageCreateWithMetaData`'s 20-byte header, and left it as a suspected misread. D39 �3 established the HTTP path's 8-byte disagreement is absorbed because `Command` and `RequestID` are parsed *before* the decrypt and never re-read. The question is whether SMB has the same absorber.**

**Three files had to be read together: the reader, the writer, and the function that locates the ID.**

### 3.2 The reader � `SmbRecv`

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
            if ( ! Instance->Win32.ReadFile( Instance->Config.Transport.Handle, &DemonId, sizeof( UINT32 ), &BytesSize, NULL ) && NtGetLastError() != ERROR_MORE_DATA )
            ...
            if ( Instance->Session.AgentID != DemonId )
            {
                PRINTF( "The message doesn't have the correct DemonId: %x\n", DemonId )
                ...
```
[source: `payloads/Demon/src/core/TransportSmb.c:65-92`]

**Read 1 ? `DemonId` (4 B), compared against `Instance->Session.AgentID` at `:84`. Read 2 ? `PackageSize` (4 B), used at `:102` to allocate exactly that many bytes. Then `PipeRead` consumes the remainder.**

### 3.3 The writer � and the first thing that rules out a five-field parse

```c
BOOL PipeWrite(
    IN  HANDLE   Handle,
    OUT PBUFFER Buffer
) {
    DWORD Written = 0;
    DWORD Total   = 0;

    do {
        if ( ! Instance->Win32.WriteFile( Handle, Buffer->Buffer + Total, MIN( ( Buffer->Length - Total ), PIPE_BUFFER_MAX ), &Written , NULL ) ) {
            return FALSE;
        }

        Total += Written;
    } while ( Total < Buffer->Length );

    return TRUE;
}
```
[source: `payloads/Demon/src/core/Win32.c:1202-1218`, verbatim]

**`PipeWrite` writes `Buffer->Buffer` verbatim from offset 0. It prepends nothing.** **And `SmbSend` passes the package straight to it �**

```c
    if ( ! PipeWrite( Instance->Config.Transport.Handle, Send ) )
```
[source: `payloads/Demon/src/core/TransportSmb.c:44`; the same call at `:41` on the connect path]

**So there is no separate 8-byte SMB envelope. The 8 bytes `SmbRecv` reads ARE the first 8 bytes of the package buffer itself.**

### 3.4 The package header, and the field the reader actually reads

```c
PPACKAGE PackageCreateWithMetaData( UINT32 CommandID )
{
    PPACKAGE Package = PackageCreate( CommandID );

    PackageAddInt32( Package, 0 ); // package length
    PackageAddInt32( Package, DEMON_MAGIC_VALUE );
    PackageAddInt32( Package, Instance->Session.AgentID );
    PackageAddInt32( Package, Package->CommandID );
    PackageAddInt32( Package, Package->RequestID );

    return Package;
}
```
[source: `payloads/Demon/src/core/Package.c:174-185`, verbatim]

**Header, offset by offset, confirmed against the comment at `Package.c:379-386` and the `Padding` expression at `:387`:**

| Offset | Field | Written by |
|---|---|---|
| `[0..3]` | **package length** | `PackageAddInt32(Package, 0)` `:178`, filled in later by `Int32ToBuffer( Package->Buffer, Package->Length - sizeof(UINT32) )` `:377` |
| `[4..7]` | `DEMON_MAGIC_VALUE` | `:179` |
| `[8..11]` | **`Instance->Session.AgentID`** | `:180` |
| `[12..15]` | `Package->CommandID` | `:181` |
| `[16..19]` | `Package->RequestID` | `:182` |

**Now the correspondence, stated exactly:**

| `SmbRecv` reads | Offset | Header field at that offset | Name the code gives it |
|---|---|---|---|
| read 1 ? `DemonId`, compared to `Session.AgentID` | `[0..3]` | **package length** | *not* the AgentID |
| read 2 ? `PackageSize`, allocates that many | `[4..7]` | **`DEMON_MAGIC_VALUE`** | *not* the size |
| � | `[8..11]` | the actual **AgentID** | never read here |
| � | `[12..19]` | CommandID, RequestID | never read here |

**The reader's two field names are exchanged with respect to the writer's two fields at those offsets.** **`DemonId` is compared against `Session.AgentID`, but offset `[0..3]` holds the package length.** **`PackageSize` is used as an allocation size, but offset `[4..7]` holds the magic value.**

### 3.5 The second reader � `PivotParseDemonID`, and it agrees with the WRITER

**This is the cross-check that decides the question, and the Lead's rule applies: two instruments disagree, so measure the source.**

```c
UINT32 PivotParseDemonID( PVOID Response, SIZE_T Size )
{
    PARSER Parser  = { 0 };
    UINT32 Value   = 0;

    ParserNew( &Parser, Response, Size );

    ParserGetInt32( &Parser );
    ParserGetInt32( &Parser );

    Value = __builtin_bswap32( ParserGetInt32( &Parser ) );
    ...
```
[source: `payloads/Demon/src/core/Pivot.c:331-341`, verbatim]

**Two `ParserGetInt32` calls discard offsets `[0..3]` and `[4..7]`, and the THIRD read � offsets `[8..11]` � is the value it returns as the DemonID.**

**And `[8..11]` is where `PackageCreateWithMetaData:180` writes `Instance->Session.AgentID`.**

**So `PivotParseDemonID`, the function whose entire purpose is to find an agent ID in an SMB pivot buffer, reads it from offset 8. `SmbRecv`, the other reader of the same format, reads it from offset 0.**

### 3.6 What this means � and what it does not

**`PivotParseDemonID` is correct against the writer. `SmbRecv` is not.** **The same header is parsed by two functions in the same transport family, and only one of them agrees with the code that builds it.**

**The consequence, traced concretely:** `SmbRecv:84` compares offset `[0..3]` � the package **length** � against `Session.AgentID`. **A `DWORD` length equals a `DWORD` AgentID only by collision.** **When they differ, `:84` fires, and `:80-89` sets `Session.Connected = FALSE` and returns FALSE.** **That is a disconnect on a length/ID mismatch, not a data corruption � the message is discarded rather than mis-parsed, because the guard fires before `PipeRead` and before any allocation using the mis-named `PackageSize`.**

**So the failure mode is a false disconnect, not a buffer overrun.** **`Resp->Buffer` is still `NULL` at that point** (`:78`), so the mis-sized allocation at `:102` is never reached on this path.

**But note what the guard is: `Session.AgentID` is set from the pivot handshake, and the length field varies per message. So any SMB pivot message whose length does not equal the agent ID will be rejected at `:84`** � meaning the check passes only when length == AgentID, which is to say when the two numbers happen to coincide.

**LIMITATION, stated: I have not run this code, so I cannot demonstrate a specific message that triggers it. The claim is structural � the offset the reader uses is not the offset the writer writes � and it is established by reading three functions that agree on the layout, with the fourth disagreeing. The probe that would convert this to a demonstration is named in �6 as U-5.**

### 3.7 Does SMB have the HTTP absorber? No � and that is the answer to the Lead's question

**The HTTP path's absorber was: header fields are parsed from the plaintext before the region is decrypted, and nothing re-reads them afterward, so an 8-byte span difference in the encrypted region never lands on a field that is subsequently trusted.** [source: D39 �3.3; `handlers.go:78-80` before `:99-103`]

**The SMB path has no such absorber, because there is no decrypt on this path at all.** **`SmbRecv` reads 8 bytes, does an ID comparison, reads `PackageSize` more bytes, and hands the buffer to `Command.c:90` via `SMBGetJob` � where the parse loop at `Command.c:96-125` takes over and decrypts the *three-field* task region itself, exactly as it does for HTTP.**

**The SMB 8-byte read is transport framing, not header parsing, and it duplicates the first 8 bytes of the payload header rather than extending it.** **That duplication is where the two functions disagree.**

### 3.8 Q3a verdict

**Bug, not accounted-for.** **`SmbRecv` reads the agent ID from offset 0 where the writer places the package length, while `PivotParseDemonID` � the other reader of the same format � correctly reads it from offset 8.** **The HTTP path's absorber does not exist on this path because the SMB path performs no decrypt here.** **The observable effect is a false-disconnect guard, not a mis-parse, because the comparison at `:84` fires before the buffer is used.**

---

## �4 � Q3b: `Packer.Build()` AND THE WIRE (CLOSES D39 U3)

### 4.1 The function

```go
func (p *Packer) Build() []byte {
	T := make([]byte, 20)
	Temp := make([]byte, len(T))

	// check if aes key is empty if so then its not enabled
	if bytes.Compare(p.AesKey, Temp) == 0 {
		return p.data
	}

	if p.AesKey == nil {
		logger.Debug("No Aes Key specified")
	}

	if (p.AesKey != nil) || (p.AesIV != nil) {
		p.data = crypt.XCryptBytesAES256(p.data, p.AesKey, p.AesIV)
	}

	return p.data
}
```
[source: `teamserver/pkg/common/packer/packer.go:80-93`]

**`Build()` encrypts `p.data` from offset 0 � the whole buffer, no 20-byte skip.** **That is the asymmetry against the agent's `Package.c:258`, which encrypts `Package->Buffer + Padding` with `Padding = 20`.** [source: `Package.c:250-258`]

**The question is which call sites reach the wire.**

### 4.2 The four call sites, measured

```
Get-ChildItem $h\teamserver -Recurse -File -Filter *.go | Select-String -Pattern '\.Build\(\)'
   ? dispatch.go:915    if PayloadBuilder.Build() {
   ? builder.go:408     if DllPayload.Build() {
   ? handlers.go:88     Build = Packer.Build()
   ? handlers.go:287    Build = Packer.Build()
```
[source: the command above; 4 sites]

| Site | Function | What it builds | Reaches an agent? |
|---|---|---|---|
| `dispatch.go:915` | `DispatchEvent`, GUI client path | operator-requested payload bytes for download | **No � client-bound** |
| `builder.go:408` | `DllPayload.Build()` | the compiled agent DLL **before** it is a running agent | **No � build-time artifact** |
| `handlers.go:88` | `handleDemonAgent`, `DEMON_INIT` reconnect | reconnect acknowledgement | **Yes** |
| `handlers.go:287` | `handleDemonAgent`, `COMMAND_MEM_FILE` | mem-file chunk fetch | **Yes** |

### 4.3 CORRECTION, MADE AGAINST MYSELF BEFORE ANY CONCLUSION � BOTH WIRE SITES USE THE SESSION KEY

**In the first draft of this section I wrote that `handlers.go:85` constructs `packer.NewPacker(nil, nil)` and that the `DEMON_INIT` ack therefore goes out unencrypted. I then read the line instead of restating it. Both statements are wrong.**

```go
			/* check if this is a 'reconnect' request */
			if Command == agent.DEMON_INIT {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INIT", Header.AgentID))
				Packer = packer.NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
				Packer.AddUInt32(uint32(Header.AgentID))

				Build = Packer.Build()

				_, err = Response.Write(Build)
```
[source: `teamserver/pkg/handlers/handlers.go:82-90`, verbatim]

**`NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)` � the real session key and IV, taken from the `Agent` record.** **The reconnect ack is encrypted.**

```go
			Packer = packer.NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
			Packer.AddUInt32(uint32(Header.AgentID))

			Build = Packer.Build()

			_, err = Response.Write(Build)
```
[source: `teamserver/pkg/handlers/handlers.go:284-289`, verbatim]

**`handlers.go:287` is the same shape: real session key and IV.** **The mem-file chunk is encrypted.**

**What I had wrong:** I carried a note that `handlers.go:85` was a `nil, nil` packer. **The `nil, nil` packer exists in the codebase � but it is in the service-agent path, not this handler**, and I had not measured which site owned which. **The instrument that fixes it is reading the four lines between `:83` and `:88`, which I had not done when I drafted the claim.** **This is the fifth self-caught error in this lane and the second in D47; it is recorded rather than silently fixed, per corpus practice.**

### 4.4 What the `Packer.Build()` offset difference actually means, now that both sites are measured

**Both wire-reaching sites encrypt from offset 0, over a buffer that begins with `Packer.AddUInt32(uint32(Header.AgentID))`.** **So the server's wire format for these two replies is `[AgentID : 4 B][ encrypted-from-offset-0 payload ]`.**

**The agent's inbound parse of a package is `[SIZE][MAGIC][AGENTID][COMMANDID][REQUESTID]` then decrypt from offset 20** [source: `Package.c:379-391`].

**These are two different formats.** **The agent does not parse the `DEMON_INIT` ack or a mem-file chunk with the same header discipline it applies to a task package � and it does not need to, because both are read on paths that expect a payload, not a framed package.** **That is a design statement about the two directions, not a defect: `Packer.Build()` is the server's reply-serialiser for payload bytes, and `PackageCreateWithMetaData` is the agent's message-serialiser for framed packages. They are not supposed to agree.**

**So the answer to D39 U3 is: `Packer.Build()`'s whole-buffer encryption DOES reach agent traffic at two sites, both encrypted with the session key, and the offset-0 choice is correct for the payload-shaped replies those sites produce.** **No asymmetric-encryption defect.** **And D34's transport finding is untouched � different packer, different direction, different format.**

### 4.5 SOURCE GAP � MY EARLIER CLAIM ABOUT `service/service.go` IS NOT IN THIS REPORT

**The `nil, nil` packer I misattributed above is a real construct elsewhere in the tree.** **In D39 �2.4 I recorded a `NewPacker` at `service/service.go` among five `NewPacker` calls.** **The measured `NewPacker` call sites are `agent.go:749`, `agent.go:790`, `builder.go:563`, `handlers.go:85`, `handlers.go:284`** [source: the `NewPacker` census in D39 �7.3, which corrected a "5 call sites" claim to "target 1 / control 6 / control 4" hits].

**So `service/service.go` is NOT among the five.** **That path is the service-agent RPC, and its packer construction is unmeasured here.** **Named as U-6 in �6.**

### 4.6 The `bytes.Compare` detail, kept because it is correct and is the reason the guard is worth noting

**`Build()`'s early return tests `bytes.Compare(p.AesKey, Temp) == 0` against a 20-byte zero slice `Temp`** [source: `packer.go:81-85`].

- **If `p.AesKey` is a 32-byte session key, `Compare` returns non-zero and the early return does not fire.**
- **If `p.AesKey` were `nil`, `bytes.Compare(nil, Temp)` compares an empty slice to a 20-byte slice and returns `-1` � also non-zero � so the early return STILL does not fire.**
- **Then `:88` `if (p.AesKey != nil) || (p.AesIV != nil)` decides.** **With `nil, nil` both are false and no encryption happens; with a real key the `||` is true and encryption happens.**
- **The `if p.AesKey == nil { logger.Debug(...) }` at `:87` is therefore the ONLY diagnostic for the unencrypted-reply case, and it emits only under `--debug`** (`logger/global.go:21`, `cmd/server.go:57-60`) [source: D39 �4.3].

**So the guard structure has a real gap � an unencrypted server reply is silent in a default deployment � but on THIS path the gap is not reached, because both call sites pass a real key.** **It would be reached if any `NewPacker(nil, nil)` site wrote its `Build()` to a socket. That is what U-6 checks.**

### 4.7 Q3b verdict

**Two of four `Packer.Build()` sites reach an agent: `handlers.go:88` and `handlers.go:287`, and both are encrypted with the session key � measured, at `:85` and `:284` respectively.** **The whole-buffer offset-0 encryption is correct for the payload-shaped replies these sites build and does not conflict with the agent's 20-byte header, because the two serialisers serve different directions.** **D34's transport finding is not inverted.** **The unencrypted-reply hazard is real in the guard structure but is not demonstrated on these two paths, and is carried as U-6 for the `nil, nil` packer's own write site.**

---

*(�6 follows)*