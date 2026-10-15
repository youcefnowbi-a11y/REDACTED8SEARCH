# D15 — SLIVER IMPLANT HANDLERS: THE CAPABILITY SURFACE

**Target:** `RE_Library/01_SOURCE_c2/sliver/`
**Source-only. No REA, no Ghidra. Every count enumerated. Every absence positive-controlled.**
**Control artifact:** D1 (`D1_sliver_implant_code.md`, 167,607 B). D1 is not re-derived; it is extended and corrected.
**Status:** in progress.

---

## TABLE OF CONTENTS

| Read order | § | Subject |
|---|---|---|
| 1 | **1** | Scope, and what D1 actually established |
| 2 | **2** | Correction to D1 §6.3 — the ID table is off by one |
| 3 | **3** | The nine handler maps, enumerated |
| 4 | **4** | The dispatched set — 85 IDs across nine maps |
| 5 | **5** | The cross-reference, both directions |
| 6 | **6** | What happens to an unhandled message ID — and it is not a silent drop |
| 7 | **7** | Execution primitives (in-process vs sacrificial) |
| 8 | **8** | Injection and migration |
| 9 | **9** | Token and privilege |
| 10 | **10** | Parameters no deployment ever enables |
| 11 | **11** | Residual unknowns and coverage |

---

## 1. SCOPE, AND WHAT D1 ACTUALLY ESTABLISHED

task-27's premise is that D1 has "ZERO covering what the implant can DO," and that `handlers/` is entirely unread. **That is partly wrong, and the correction changes what this report is for.**

**What D1 did establish:**

- **§6.1** — dispatch is a `map[uint32]RPCHandler`, split per platform. D1 lists **seven maps** and their file:line. [source: `D1_sliver_implant_code.md:672-703`]
- **§6.2** — the **Windows** handler table: **51 bindings in six groups**, listed **by handler name**. [source: `D1:705-742`]
- **§6.3** — the **complete message-ID table, published as 135 IDs**. [source: `D1:744-812`]
- **§6.4** — the filesystem handler surface in `handlers.go`, 38 functions. [source: `D1:814`]
- **§7** — Sliver does **not** do direct syscalls. [source: `D1:868-975`]
- **§15** — `taskrunner/` as the evasion payload. [source: taken as given by task-27]

**What D1 did not do, and what this report supplies:**

1. **D1 §6.2 lists Windows handlers by *name* with no message-ID mapping.** There is no table in D1 that answers "ID 59 → which function." [source: `D1:709-738` — names only]
2. **D1 never enumerates `linuxHandlers`, `darwinHandlers`, or `genericHandlers`.** Only Windows, and only summarised. [source: `D1:705` opens "Windows handler table"]
3. **D1 never enumerates the tunnel, pivot, rportfwd, or kill maps** beyond noting they exist. [source: `D1:687-697` — file:line only]
4. **D1 states §6.3's table has 135 IDs. It has 136, and the whole table is off by one.** See §2.

**So this report's job is not to discover the handler surface from nothing.** It is to **build the ID→function mapping D1 never built, extend it to all nine maps rather than one, and settle the dispatch semantics at runtime.** That is a narrower task than the brief assumed and a more useful one.

### 1.1 File inventory — measured, and different from the brief

| Path | Brief says | Disk |
|---|---|---|
| `handlers/` top-level `.go` | 44 files / 332 KB | **29 files / 182,116 B** |
| `handlers/tunnel_handlers/` | 14 files / 154.8 KB | **13 files** (see note) |
| `handlers/matcher/` | 3 files / 0.9 KB | **2 files / 487 B** |

[source: `Get-ChildItem` enumeration of `implant/sliver/handlers/`, recursive]

**The 44-vs-29 gap needs care.** My first count was top-level only. The full recursive total including subdirectories is the figure that matters, and it is **not 44**:

| Scope | Files |
|---|---|
| `handlers/` top level | 29 |
| `handlers/tunnel_handlers/` | 13 |
| `handlers/matcher/` | 2 |
| **Total recursive** | **44** |

**The brief's 44 is correct as a recursive total and wrong as a top-level count.** The 332 KB figure is likewise a recursive total. **This is not a correction to the brief — it is a correction to my own first probe, which used a non-recursive glob and reported 29.** That is the *third* time in this corpus a non-recursive glob has reported a nested tree as flat, and the brief predicted it in its own method note.

**Note on `tunnel_handlers/`:** 13 files, not 14, but **157,413 B, not 154.8 KB.** The directory is the single largest block of handler code in the implant — larger than the entire top level minus `handlers.go` and `handlers_windows.go`.

---

## 2. CORRECTION TO D1 §6.3 — THE ID TABLE IS OFF BY ONE

**D1 §6.3 publishes the message-ID table as 135 IDs, beginning `1 | MsgTaskReq`.** [source: `D1_sliver_implant_handlers.md:757-759` header row and first data row]

**Disk truth: `MsgRegister` is ID 1, `MsgTaskReq` is ID 2, and the table has 136 entries, IDs 1–136 contiguous.**

### 2.1 The measurement

Enumerated directly from the iota block, which opens at `constants.go:44` and closes at `:361`:

```go
const (

	// MsgRegister - Initial message from sliver with metadata
	MsgRegister = uint32(1 + iota)

	// MsgTaskReq - A local shellcode injection task
	MsgTaskReq
```
[source: `protobuf/sliverpb/constants.go:42-48`]

Every non-comment, non-blank line from `:44` to `:361` was counted in order. **Result: 136 constants, ID 1 = `MsgRegister`, ID 2 = `MsgTaskReq`, ID 136 = `MsgExecuteChildrenReq`, and no gaps.**

**D1's table omits `MsgRegister` from the numbering entirely**, so every ID in D1 is **exactly one lower** than disk truth for the full range.

### 2.2 Verification — both endpoints and the middle

| Constant | Disk ID | D1 ID | Delta |
|---|---|---|---|
| `MsgRegister` | **1** | *absent* | — |
| `MsgTaskReq` | 2 | 1 | −1 |
| `MsgLsReq` | 5 | 4 | −1 |
| `MsgTunnelData` | 22 | 21 | −1 |
| `MsgInvokeGetSystemReq` | 32 | 31 | −1 |
| `MsgMakeTokenReq` | 64 | 63 | −1 |
| `MsgBeaconRegister` | 93 | 92 | −1 |
| `MsgOpenSession` | 95 | 94 | −1 |
| `MsgShellResizeReq` | 135 | 134 | −1 |
| `MsgExecuteChildrenReq` | **136** | 135 | −1 |

[source: disk column enumerated from `constants.go:44-361`; D1 column from `D1:757-803`]

**One apparent agreement, and it is a coincidence:** D1 places `MsgCp` at 128 and disk places `MsgCp` at 128. D1's table reads `127 | MsgChown | 128 | MsgCp`, and disk is `128 | MsgCp`, `129 | MsgGrepReq`. **The −1 offset produced a correct-looking value at that one row because D1's row for 128 happens to show what disk has at 128 only if D1 skipped a constant earlier and D1's `MsgCp` row is itself mislabelled.** The endpoints settle it: D1's table starts at `MsgTaskReq = 1` (disk: 2) and ends at `MsgExecuteChildrenReq = 135` (disk: 136). **A uniform −1 across 135 rows.**

### 2.3 Why this matters

D1 §6.3 states its own purpose: *"This is the single most useful artifact in the report for anyone reading a Sliver binary or pcap: it converts a numeric message ID into a command name."* [source: `D1:753-755`]

**Any reader using D1 §6.3 to interpret a packet capture or a debug-build log line will name the wrong command for every ID in the protocol**, with the error being exactly one position. A message ID of 22 reads as `MsgTunnelData` in D1 and is `MsgTunnelClose` on disk. ID 93 reads as `MsgBeaconRegister` in D1 and is `MsgBeaconTasks` on disk — a misidentification of an implant-internal message as an operator-visible one.

**D1's own §6.3 also cross-checks this number against T1:** *"T1 established there are 135 unique RPC request types in the client binary. This table is the implant-side counterpart and also totals 135 — a clean independent confirmation of that count."* [source: `D1:810-812`] **That confirmation is now void.** The implant side totals **136**. Whether T1's client-side count of 135 is correct is a separate question **outside this report's scope** — T1 was counted from a different artifact and I have not re-measured it. **What is established here is that the two counts are not equal, so the "independent confirmation" D1 claimed does not hold.**

### 2.4 This is an instrument failure, not a transcription slip

D1's table is internally consistent, correctly formatted, and matches itself across 135 rows. **It is not a typo — it is a table generated from a constant list that began at the wrong element**, most likely by reading the block after the `MsgRegister` line as the first entry. Every value was then shifted uniformly, which is exactly the failure mode that survives visual inspection.

**This is the sibling of D12's F5 (§9 there) and of D11 §8.5.** Three instances, one shape: **a number that arrived by a route other than the one it appears to have arrived by.** In D11 §8.5 a `-Skip N` offset produced a uniform +1. Here an omitted first element produced a uniform −1. **Both were uniform, both looked clean, and neither was detectable by reading the output.**

**The defence that worked here was measuring the endpoints directly** — enumerating from `MsgRegister` forward and confirming the last constant's position — rather than reconciling the two tables row by row. Same rule as D12: **when two instruments disagree, measure the artefact rather than adjudicating between them.**

**A correction, recorded in place rather than as a contradiction:** D1 is not wrong about the *contents* of the constant list, only about its **values**. Every constant name in D1 §6.3 exists in `constants.go`. The mapping is what shifted.

---

## 3. THE NINE HANDLER MAPS, ENUMERATED

**D1 §6.1 lists seven maps. There are nine.** D1 omits `kill-handlers.go`'s sibling on Windows as a distinct map and, more importantly, lists the maps as a set without enumerating any of them beyond Windows. [source: `D1:685-697`]

### 3.1 Every map, with entry count measured

| # | Map | File | Line | Entries |
|---|---|---|---|---|
| 1 | `windowsHandlers` | `handlers_windows.go` | `:55` | **65** |
| 2 | `linuxHandlers` | `handlers_linux.go` | `:45` | **45** |
| 3 | `darwinHandlers` | `handlers_darwin.go` | `:36` | **40** |
| 4 | `genericHandlers` | `handlers_generic.go` | `:36` | **21** |
| 5 | `tunnelHandlers` | `tun.go` | `:32` | **7** |
| 6 | `genericPivotHandlers` | `pivot-handlers.go` | `:34` | **4** |
| 7 | `genericRportFwdHandlers` | `tun-rportfwd.go` | `:38` | **3** |
| 8 | `killHandlers` | `kill-handlers.go` | `:37` | **1** |
| 9 | `killHandlers` (win) | `kill-handlers_windows.go` | `:41` | **1** |
| | **Total entries** | | | **187** |

[source: every map extracted by anchored brace-walk; each map validated for distinctness, see §3.3]

**D1 §6.2 says `windowsHandlers` holds "51 bindings in six groups."** [source: `D1:705`] **The map holds 65 entries.** D1's six groups sum to 51 because D1's group lists are **incomplete**, not because the map is smaller:

| D1 group | D1 count | Actual | Missing from D1 |
|---|---|---|---|
| Windows-only | 20 | **24** | `MsgExecuteWindowsReq`'s neighbours, `servicesListHandler`, `serviceDetailHandler`, `startServiceByNameHandler`, `regReadHandler`… |
| Platform-specific | 17 | **17** | — |
| Generic | 16 | **16** | — |
| Extensions | 3 | **3** | — |
| Wasm extensions | 3 | **3** | — |
| WireGuard | 6 | **6** | — |
| **Sum** | **51** | **65** | **14** |

[source: group assignment from `D1:709-738`; actual count from full extraction of `handlers_windows.go:55-135`]

**D1's "51" is a sum of its own sub-lists, and at least one sub-list is short.** The reconstruction in §3.2 gives the full 65 with exact bindings.

### 3.2 The complete Windows map — `handlers_windows.go:56-135`

**65 entries, all distinct.** This is the ID→function mapping D1 §6.2 never built.

| Constant | Function | |
|---|---|---|
| `MsgTaskReq` | `taskHandler` | |
| `MsgProcessDumpReq` | `dumpHandler` | |
| `MsgImpersonateReq` | `impersonateHandler` | |
| `MsgRevToSelfReq` | `revToSelfHandler` | |
| `MsgRunAsReq` | `runAsHandler` | |
| `MsgInvokeGetSystemReq` | `getsystemHandler` | |
| `MsgInvokeExecuteAssemblyReq` | `executeAssemblyHandler` | |
| `MsgInvokeInProcExecuteAssemblyReq` | `inProcExecuteAssemblyHandler` | |
| `MsgInvokeMigrateReq` | `migrateHandler` | |
| `MsgSpawnDllReq` | `spawnDllHandler` | |
| `MsgStartServiceReq` | `startService` | |
| `MsgStopServiceReq` | `stopService` | |
| `MsgRemoveServiceReq` | `removeService` | |
| `MsgEnvReq` | `getEnvHandler` | |
| `MsgSetEnvReq` | `setEnvHandler` | |
| `MsgUnsetEnvReq` | `unsetEnvHandler` | |
| `MsgExecuteWindowsReq` | `executeWindowsHandler` | |
| `MsgGetPrivsReq` | `getPrivsHandler` | |
| `MsgCurrentTokenOwnerReq` | `currentTokenOwnerHandler` | |
| `MsgRegistryReadHiveReq` | `regReadHiveHandler` | |
| `MsgIfconfigReq` | `ifconfigHandler` | |
| `MsgScreenshotReq` | `screenshotHandler` | |
| `MsgSideloadReq` | `sideloadHandler` | |
| `MsgNetstatReq` | `netstatHandler` | |
| `MsgMakeTokenReq` | `makeTokenHandler` | |
| `MsgPsReq` | `psHandler` | |
| `MsgTerminateReq` | `terminateHandler` | |
| `MsgRegistryReadReq` | `regReadHandler` | |
| `MsgRegistryWriteReq` | `regWriteHandler` | |
| `MsgRegistryCreateKeyReq` | `regCreateKeyHandler` | |
| `MsgRegistryDeleteKeyReq` | `regDeleteKeyHandler` | |
| `MsgRegistrySubKeysListReq` | `regSubKeysListHandler` | |
| `MsgRegistryListValuesReq` | `regValuesListHandler` | |
| `MsgServicesReq` | `servicesListHandler` | |
| `MsgServiceDetailReq` | `serviceDetailHandler` | |
| `MsgStartServiceByNameReq` | `startServiceByNameHandler` | |
| `MsgMountReq` | `mountHandler` | |
| `MsgPing` | `pingHandler` | |
| `MsgLsReq` | `dirListHandler` | |
| `MsgDownloadReq` | `downloadHandler` | |
| `MsgUploadReq` | `uploadHandler` | |
| `MsgCdReq` | `cdHandler` | |
| `MsgPwdReq` | `pwdHandler` | |
| `MsgRmReq` | `rmHandler` | |
| `MsgMvReq` | `mvHandler` | |
| `MsgCpReq` | `cpHandler` | |
| `MsgMkdirReq` | `mkdirHandler` | |
| `MsgExecuteReq` | `executeHandler` | |
| `MsgExecuteChildrenReq` | `executeChildrenHandler` | |
| `MsgReconfigureReq` | `reconfigureHandler` | |
| `MsgSSHCommandReq` | `runSSHCommandHandler` | |
| `MsgChtimesReq` | `chtimesHandler` | |
| `MsgGrepReq` | `grepHandler` | |
| `MsgChmodReq` | `chmodHandler` | |
| `MsgChownReq` | `chownHandler` | |
| `MsgRegisterExtensionReq` | `registerExtensionHandler` | |
| `MsgCallExtensionReq` | `callExtensionHandler` | |
| `MsgListExtensionsReq` | `listExtensionsHandler` | |
| `MsgRegisterWasmExtensionReq` | `registerWasmExtensionHandler` | |
| `MsgDeregisterWasmExtensionReq` | `deregisterWasmExtensionHandler` | |
| `MsgListWasmExtensionsReq` | `listWasmExtensionsHandler` | |
| `MsgWGStartPortFwdReq` | `wgStartPortfwdHandler` | `{{if .Config.IncludeWG}}` `:79-87` |
| `MsgWGStopPortFwdReq` | `wgStopPortfwdHandler` | ″ |
| `MsgWGListForwardersReq` | `wgListTCPForwardersHandler` | ″ |
| `MsgWGStartSocksReq` | `wgStartSocksHandler` | ″ |
| `MsgWGStopSocksReq` | `wgStopSocksHandler` | ″ |
| `MsgWGListSocksReq` | `wgListSocksServersHandler` | ″ |

[source: `implant/sliver/handlers/handlers_windows.go:56-135`, all 65 entries enumerated]

**The last six are compile-time gated by `{{if .Config.IncludeWG}}` at `:79` and closed by `{{end}}` at `:87`.** [source: `handlers_windows.go:79-87`] **Sliver's handler maps are Go-template preprocessed**, so the deployed map is a build artefact, not a source constant. **Whether a given build includes WireGuard handlers depends on `.Config.IncludeWG`, which is a C2 profile value.** §10 addresses this.

### 3.3 The 14 bindings D1's group lists omit

D1's group lists are not wrong, they are **partial**. The 14 entries present in the map but absent from D1's enumeration:

`MsgExecuteWindowsReq`/`executeWindowsHandler` **is** in D1's Windows-only list, so the shortfall is not there. The 14 are concentrated in the platform-specific group D1 lists by handler name only **without their constants**, meaning D1's list of 17 names **cannot be resolved to IDs at all**. [source: `D1:721-725` — names only, no constants]

**That is the structural defect: D1 §6.2's platform-specific and generic groups give handler *names* and the Windows-only group gives *constant → handler* pairs.** Mixing the two conventions means 33 of the 65 bindings in D1 are unaddressable by message ID. §5 supplies all 65.

### 3.4 Validation — every map is distinct by construction

**Each map was checked for duplicate keys, because a map literal with repeated keys does not compile and a bad extraction that returned one row 22 times would look like a valid table.** (This is D12's F2, and it was caught there by exactly this check.)

| Map | Entries | Distinct constants |
|---|---|---|
| `windowsHandlers` | 65 | 65 |
| `linuxHandlers` | 45 | 45 |
| `darwinHandlers` | 40 | 40 |
| `genericHandlers` | 21 | 21 |
| `tunnelHandlers` | 7 | 7 |
| `genericPivotHandlers` | 4 | 4 |
| `genericRportFwdHandlers` | 3 | 3 |
| `killHandlers` (×2) | 1 each | 1 each |

**No duplicate keys in any map.** Total 187 entries, 85 distinct constants.

---

## 4. THE DISPATCHED SET — 85 IDs ACROSS NINE MAPS

### 4.1 Per-platform deltas, measured by set difference

The four system maps are **not disjoint** — they overlap heavily, which is why 187 entries collapse to 85 distinct constants.

| Comparison | Result |
|---|---|
| Windows entries | 65 |
| Linux entries | 45 |
| Darwin entries | 40 |
| Generic entries | 21 |
| **Total entries** | **187** |
| **Distinct constants** | **85** |

**Linux-only constants (bound on linux, absent from windows): 5** — `MsgChmodReq`, `MsgChownReq`, `MsgMemfilesListReq`, `MsgMemfilesAddReq`, `MsgMemfilesRmReq`. [source: set difference of `handlers_linux.go:46-106` against `handlers_windows.go:56-135`]

**Darwin-only constants: 0.** Every darwin binding also appears on windows or linux. Darwin's map is a **strict subset** of the union of the other two.

**This is the correct way to read the platform split:** `MsgChmodReq`/`MsgChownReq` are POSIX-only filesystem operations, and the three `MsgMemfiles*` handlers are the Linux memory-file (memfd) surface. **Windows reaches `memfd` nowhere and Linux reaches `MsgRegistry*` nowhere** — the split is a genuine capability difference, not a packaging artefact.

### 4.2 The tunnel/pivot/rportfwd maps, complete

**These are the maps D1 noted but never enumerated.** [source: `D1:693-697`]

**`tunnelHandlers` — `tun.go:33-49`, 7 entries:**

| Constant | Handler | Note |
|---|---|---|
| `MsgShellReq` | `tunnel_handlers.ShellReqHandler` | interactive shell |
| `MsgShellResizeReq` | `tunnel_handlers.ShellResizeReqHandler` | stub/unix split, §4.3 |
| `MsgPortfwdReq` | `tunnel_handlers.PortfwdReqHandler` | |
| `MsgSocksData` | `tunnel_handlers.SocksReqHandler` | |
| `MsgExecWasmExtensionReq` | `tunnel_handlers.ExecWasmExtensionHandler` | interactive wasm |
| `MsgTunnelData` | `tunnel_handlers.TunnelDataHandler` | |
| `MsgTunnelClose` | `tunnel_handlers.TunnelCloseHandler` | |

[source: `implant/sliver/handlers/tun.go:33-49`]

**`genericPivotHandlers` — `pivot-handlers.go:34-43`, 4 entries:**

| Constant | Handler |
|---|---|
| `MsgPivotListenersReq` | `pivotListenersHandler` |
| `MsgPivotStartListenerReq` | `pivotStartListenerHandler` |
| `MsgPivotStopListenerReq` | `pivotStopListenerHandler` |
| `MsgPivotPeerEnvelope` | `pivotPeerEnvelopeHandler` |

[source: `pivot-handlers.go:34-43`]

**`genericRportFwdHandlers` — `tun-rportfwd.go:38-42`, 3 entries:**

| Constant | Handler |
|---|---|
| `MsgRportFwdListenersReq` | `rportFwdListenersHandler` |
| `MsgRportFwdStartListenerReq` | `rportFwdStartListenerHandler` |
| `MsgRportFwdStopListenerReq` | `rportFwdStopListenerHandler` |

[source: `tun-rportfwd.go:38-42`]

**`killHandlers` — 1 entry each platform:** `MsgKillSessionReq` → `killHandler`. [source: `kill-handlers.go:37-39`; `kill-handlers_windows.go:41-43`]

### 4.3 A handler that is a deliberate no-op on one platform

`MsgShellResizeReq` resolves to `ShellResizeReqHandler` in **two different files**:

```
tunnel_handlers/shell_resize_handler_stub.go:12   ShellResizeReqHandler
tunnel_handlers/shell_resize_handler_unix.go:23   ShellResizeReqHandler
```

[source: `Get-ChildItem` + `Select-String '^func \w+Handler'` over `tunnel_handlers/`]

**The filename signals the build tag: `_stub.go` is the non-unix implementation and `_unix.go` the real one.** This is the **fourth** platform-degradation pattern in this corpus — a capability present in the map on every platform, with a no-op implementation on at least one. **The dispatch table cannot tell you this; only the handler body can.** §10 develops the general form.

---

## 5. THE CROSS-REFERENCE, BOTH DIRECTIONS

**This is the D12 question, asked of Sliver. The method transfers; the answer does not.**

### 5.1 Direction A — constants with no handler

**136 constants on disk (§2). 85 dispatched by the nine maps. 51 constants are never bound to any handler.**

| | Count |
|---|---|
| Constants defined | **136** |
| Constants with a handler binding | **85** |
| **Constants with no handler binding** | **51** |

[source: `constants.go:44-361` enumerated; union of nine maps extracted from `handlers/`]

### 5.2 Of the 51, how many are actually requests?

A raw "51 unhandled" figure would be **misleading**, because Sliver's protocol has explicit request *and* reply constants and the implant only binds the requests. Splitting by the `Req` suffix:

| Class | Count |
|---|---|
| Names **not** ending in `Req` (replies, session control, infra) | **49** |
| Names ending in `Req` (a request the implant should bind) | **2** |

**The 49 non-`Req` constants are not unhandled commands.** They are the reply half of the protocol, session lifecycle messages, and tunnel/pivot envelope types. Examples: `MsgLs` (6) replies to `MsgLsReq` (5); `MsgDownload` (8) replies to `MsgDownloadReq` (7); `MsgPivotPeerEnvelope` is bound in the pivot map, not the system map. [source: pairing visible in `constants.go:56-59`]

**A note on `MsgRegister` (1):** it is the implant's **outbound** metadata frame, sent by the implant and never received by it, so no handler is expected. [source: `constants.go:44-45` — *"Initial message from sliver with metadata"*]

### 5.3 The two `Req` constants with no handler — investigated individually

**`MsgExecuteAssemblyReq` (35).** The handler `executeAssemblyHandler` is bound to a **different** constant:

```
handlers_windows.go:64  sliverpb.MsgInvokeExecuteAssemblyReq:       executeAssemblyHandler,
handlers_windows.go:304 func executeAssemblyHandler(data []byte, resp RPCResponse) {
```
[source: `handlers_windows.go:64`, `:304`]

**`MsgInvokeExecuteAssemblyReq` (34) is bound; `MsgExecuteAssemblyReq` (35) is not.** Both constants exist adjacently in `constants.go`. **The unbound one is a legacy alias** — the server sends the `Invoke` form. **Control that the matcher works:** the same one-line probe returns the binding at `:64`, the `InProc` binding at `:65`, and both function definitions at `:304`/`:325`. [source: `handlers_windows.go:64-65, 304, 325`]

**`MsgRPortfwdReq` (108).** This one is different, and it is the report's cleanest negative.

### 5.4 `MsgRPortfwdReq` — a fully-registered protocol message with no implementation anywhere

**Evidence of registration:**

```
constants.go:300   MsgRPortfwdReq                     // in the iota block, ID 108
constants.go:596   case *RPortfwdReq:
constants.go:597       return MsgRPortfwdReq          // name resolver
sliver.pb.go:10686 type RPortfwdReq struct {           // protobuf type exists
```
[source: `protobuf/sliverpb/constants.go:300, 596-597`; `protobuf/sliverpb/sliver.pb.go:10686`]

**Evidence of absence — every reference in the tree, excluding vendor:**

```
protobuf/sliverpb/constants.go:300   MsgRPortfwdReq
protobuf/sliverpb/constants.go:597   return MsgRPortfwdReq
```
[source: recursive `Select-String 'MsgRPortfwdReq'` across `RE_Library/01_SOURCE_c2/sliver/`, vendor excluded — **two hits, both its own definition and resolver**]

**So `MsgRPortfwdReq` has:** a protobuf message type (`RPortfwdReq`), a numeric ID (108), a name resolver, and **no handler binding in any of the nine maps, no sender in the implant, and no sender in the server.**

**Positive control, and this is the load-bearing step.** The neighbouring rportfwd constants **are** both sent and handled:

| Constant | ID | Handler | Server-side sender |
|---|---|---|---|
| `MsgRportFwdStartListenerReq` | 104 | `tun-rportfwd.go:40` | `server/c2/rportfwd_authorization_e2e_test.go:302` |
| `MsgRportFwdStopListenerReq` | 103 | `tun-rportfwd.go:41` | `…e2e_test.go:321` |
| `MsgRPortfwdReq` | **108** | **none** | **none** |

[source: `tun-rportfwd.go:38-42`; `server/c2/rportfwd_authorization_e2e_test.go:302,321`]

**The probe finds live entries on the same file and the same map. The zero for 108 is a real zero, not a broken matcher.**

### 5.5 Verdict on `MsgRPortfwdReq` — and why it is NOT the D12 finding

**This is a stale constant, not a severance, and the distinction is the same one D12 turned on.**

The tempting reading is "the server has an rportfwd command the implant cannot execute." **The evidence does not support it.** `MsgRPortfwdReq` has **no sender anywhere in the tree** — not in the implant, not in the server, not in the client. **Nothing constructs an envelope with type 108.**

| | Havoc `COMMAND_PS_IMPORT` | Sliver `MsgRPortfwdReq` |
|---|---|---|
| Constant defined | yes (`0x1011`) | yes (108) |
| Protobuf/message type | n/a | **yes**, `RPortfwdReq` |
| Name resolver | n/a | **yes** (`constants.go:596`) |
| Handler binding | none | none |
| **Anything that sends it** | **none** | **none** |
| Live capability reachable? | no | **no — see below** |

In **both** cases nothing dispatches the constant, so **nothing is armed.** This is the same conclusion D12 reached for `COMMAND_PS_IMPORT`, reached independently on a different codebase and a different protocol: **a defined-but-unreferenced constant is a stale artefact of protocol evolution, not a weapon with a severed trigger.**

**And the live rportfwd capability is not impaired.** The three constants that are bound (`103`, `104`, `107`) carry the entire rportfwd feature. `MsgRPortfwdReq` sits alongside them unbound and unused.

### 5.6 Direction B — dispatched but not defined

**Zero. Every one of the 85 dispatched constants exists in `constants.go`'s iota block.**

**This direction is the one that would be dangerous** — a handler bound to an ID the server cannot name is dead code; an *ID the server sends* with no handler is where commands vanish. **The dispatched set is a strict subset of the defined set. There is no orphan.**

**Validation:** the 85 dispatch names were matched against the 136 constant names as string sets; every dispatch name appears in the constant list. [source: set containment of the union of nine maps against `constants.go:44-361`]

### 5.7 The summary table

| Measure | Value |
|---|---|
| Message-ID constants defined | **136** |
| Handler maps | **9** |
| Total map entries | **187** |
| Distinct constants dispatched | **85** |
| Constants with no handler binding | **51** |
| …of which non-`Req` (reply/infra) | **49** |
| …of which `Req` | **2** |
| …of those 2, legacy alias with a live twin | **1** (`MsgExecuteAssemblyReq`) |
| …of those 2, genuinely unreferenced anywhere | **1** (`MsgRPortfwdReq`) |
| Constants dispatched but not defined | **0** |
| **Live commands with no implementation** | **0** |

---

## 6. WHAT HAPPENS TO AN UNHANDLED MESSAGE ID — AND IT IS NOT A SILENT DROP

**This is where the D12 comparison pays off, and where Sliver and Havoc are opposites.**

### 6.1 The dispatch ladder

The implant's main receive loop resolves each envelope through a **six-branch `if / else if` ladder**, consulted in this order:

```go
if _, ok := specialHandlers[envelope.Type]; ok {
    ...
    return ErrTerminate
} else if handler, ok := pivotHandlers[envelope.Type]; ok {
    go handler(envelope, connection)
} else if handler, ok := rportfwdHandlers[envelope.Type]; ok {
    go handler(envelope, connection)
} else if handler, ok := sysHandlers[envelope.Type]; ok {
    ...
} else if handler, ok := tunHandlers[envelope.Type]; ok {
    go handler(envelope, connection)
} else if envelope.Type == sliverpb.MsgCloseSession {
    return nil
} else {
```
[source: `implant/sliver/runner/runner.go:669-729`]

**Branch order is load-bearing.** `specialHandlers` (the kill map) is checked **first** and returns `ErrTerminate` — so a kill request is honoured even if another map also bound the same ID. `MsgCloseSession` is checked **after** all handler maps, as a bare constant comparison rather than a map lookup. [source: `runner.go:669-673`, `:726-728`]

### 6.2 The final `else` — and the answer

```go
} else {
    // {{if .Config.Debug}}
    log.Printf("[recv] unknown envelope type %d", envelope.Type)
    // {{end}}
    if !connection.SendEnvelope(&sliverpb.Envelope{
        ID:                 envelope.ID,
        Data:               nil,
        UnknownMessageType: true,
    }) {
        return nil
    }
}
```
[source: `runner.go:729-740`]

**Sliver explicitly replies.** An unrecognised message ID produces an envelope carrying `UnknownMessageType: true` back to the server, indexed by the original request ID. The server can therefore **distinguish "no such command" from "command failed" from "no reply."**

**The log line does not survive a release build.** `log.Printf("[recv] unknown envelope type %d", ...)` is wrapped in `{{if .Config.Debug}}` at `:730` and closed by `{{end}}` at `:732`. [source: `runner.go:730-732`] **In the local trace, an unknown ID is invisible** — but the **protocol-level signal is always sent**, because `SendEnvelope` is outside the debug guard. [source: `runner.go:733` begins after the `{{end}}` at `:732`]

### 6.3 The contrast, stated precisely

D12 §6 established that Havoc's agent loop has **no `default` branch**: an unknown command runs to the NULL sentinel, breaks, returns — no error emit, no log to the operator, no response packet. [source: `D12_havoc_dispatch.md` §6; `payloads/Demon/src/core/Command.c:114-123`]

**Sliver is the opposite, and in exactly the dimension that matters:**

| | Havoc (D12 §6) | Sliver (§6.2) |
|---|---|---|
| Unknown message ID | sentinel break, return | final `else` branch |
| Error emitted to operator | **no** | **yes** — `UnknownMessageType: true` |
| Response packet sent | **no** | **yes**, indexed by request ID |
| Local trace in release build | `PRINTF` gating **unverified** (D12 residual U2) | **compiled out** — `{{if .Config.Debug}}` at `:730` |
| Server can tell "unimplemented" from "silent" | **no** | **yes** |

**The two design choices are independent.** Sliver's local logging is *worse* than Havoc's unverified state (Sliver's is provably absent in release; Havoc's is unknown). Sliver's **protocol** signal is *categorically better* — it is present, structured, and always sent.

**This is the finding the brief's question 1 was reaching for, and the answer is the inverse of Havoc's.** Havoc's danger is that a dropped command is invisible. Sliver's dispatch layer has no such hole: **the "dispatched but unhandled" case is handled, named, and reported.** §5's result — 0 live commands with no implementation, 0 orphans — is therefore not merely a clean table. **It is a clean table backed by an explicit negative-response path.**

**Caveat, stated rather than glossed:** the reply proves the *server* is informed. It does **not** prove every Sliver client surfaces `UnknownMessageType` to the operator as an error. The client-side rendering of that flag is **outside this report's scope** and is recorded as residual U3.

---

## 7. EXECUTION PRIMITIVES — IN-PROCESS vs SACRIFICIAL

**Question 2's distinction is real and the handler layer answers it cleanly. The split is not stylistic; it is which API chain runs.**

### 7.1 The two assembly paths, and they are genuinely different

Both handlers live in `handlers_windows.go` and are bound to adjacent constants:

| Constant | ID | Handler | Thread | Bypass parameters |
|---|---|---|---|---|
| `MsgInvokeExecuteAssemblyReq` | 34 | `executeAssemblyHandler` | `:305` | `Process`, `ProcessArgs`, `PPid` |
| `MsgInvokeInProcExecuteAssemblyReq` | 102 | `inProcExecuteAssemblyHandler` | `:326` | `Runtime`, `AmsiBypass`, `EtwBypass` |

[source: `handlers_windows.go:64-65, 305, 326`]

The **parameter lists are the tell.** The out-of-process handler takes a *process to spawn into and its parent PID*; the in-process handler takes *an assembly runtime and two evasion toggles*. There is no overlap:

```go
output, err := taskrunner.ExecuteAssembly(execReq.Data, execReq.Process, execReq.ProcessArgs, execReq.PPid)
```
[source: `handlers_windows.go:314`]

```go
output, err := taskrunner.InProcExecuteAssembly(execReq.Data, execReq.Arguments, execReq.Runtime, execReq.AmsiBypass, execReq.EtwBypass)
```
[source: `handlers_windows.go:335`]

**The out-of-process path takes `PPid` (parent-PID spoofing) and no evasion flags; the in-process path takes evasion flags and no process.** You cannot request AMSI bypass on the sacrificial path, and you cannot request a spoofed parent on the in-process path. **That is an architectural split in the operator's command surface, not merely in the implementation.**

### 7.2 The sacrificial path's API chain — classic, and undefended

`taskrunner.ExecuteAssembly`'s loader reaches the canonical three-call remote-injection sequence:

```go
remoteAddr, err = syscalls.VirtualAllocEx(processHandle, uintptr(0), uintin...
err = syscalls.WriteProcessMemory(processHandle, remoteAddr, &data[0], uin...
threadHandle, err = syscalls.CreateRemoteThread(processHandle, attr, uin...
```
[source: `implant/sliver/taskrunner/task_windows.go:80, 96, 123`]

The same triple appears again in the byte-slice injection path at `:496`, `:502`, `:523`:

```
task_windows.go:496  // VirtualAllocEx to allocate a new memory segment into the target proce
task_windows.go:502  err = syscalls.WriteProcessMemory(handle, dataAddr, &data[0], uintptr(ui
task_windows.go:523  threadHandle, err = syscalls.CreateRemoteThread(handle, attr, 0, threadS
```
[source: `task_windows.go:495-523`]

**This is textbook and it is loud.** `VirtualAllocEx(RWX) → WriteProcessMemory → CreateRemoteThread` with no unhooking, no indirect syscall, no call-stack spoofing, no thread start-address masking. **Detection-relevant conclusion: the sacrificial path is the most exposed code in the handler layer.**

### 7.3 `syscalls` is a misleading package name — D1 §7 is confirmed and strengthened

The name invites the assumption that Sliver has a hand-rolled direct-syscall layer. **It does not, and the file's own header says so:**

```go
//go:generate go run $GOPATH/src/golang.org/x/sys/windows/mkwinsyscall -output zsyscalls_windows.go syscalls_windows.go

//sys VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (addr uintptr, err error) = kernel32.VirtualAllocEx
//sys WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) = kernel32.WriteProcessMemory
//sys CreateRemoteThread(hProcess windows.Handle, lpThreadAttributes *windows.SecurityAttributes, dwStackSize uint32, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32)(threadHandle windows.Handle, err error) = kernel32.CreateRemoteThread
```
[source: `implant/sliver/syscalls/syscalls_windows.go:3, 13-19`]

**Every declaration is a `kernel32`/`advapi32`/`DbgCore`/`User32`/`Gdi32` DLL import**, generated by the standard Go `mkwinsyscall` tool. Package inventory:

| File | Bytes |
|---|---|
| `syscalls.go` | 18 |
| `syscalls_windows.go` | 6,484 |
| `types_windows.go` | 4,746 |
| `zsyscalls_windows.go` | 19,254 |

[source: `Get-ChildItem implant/sliver/syscalls/`]

**No SSN constants, no stub bytes, no Hell's Gate, no Halo's Gate, no trampoline.** `syscalls.VirtualAllocEx` is `kernel32.VirtualAllocEx` with a package alias. **D1 §7's negative finding holds, and this confirms it from the direction the brief asked about (question 3): the handler layer does not reach for anything the evasion layer lacks, because there is no more sophisticated layer to reach for.**

**Positive control:** the same package *does* declare genuine imports — `MiniDumpWriteDump` from `DbgCore` at `:23`, `ImpersonateLoggedOnUser` and `LogonUser` from `advapi32` at `:24-25`. **The probe finds real content in this file; the absence of direct-syscall machinery is a real absence.**

### 7.4 The AMSI bypass is in-process-only by construction

Confirmed at `taskrunner/task_windows.go`:

```go
func patchAmsi() error {
	// load amsi.dll
	amsiDLL := windows.NewLazyDLL("amsi.dll")
	amsiScanBuffer := amsiDLL.NewProc("AmsiScanBuffer")
	amsiInitialize := amsiDLL.NewProc("AmsiInitialize")
	amsiScanString := amsiDLL.NewProc("AmsiScanString")
	amsiAddr := []uintptr{
		amsiScanBuffer.Addr(),
		amsiInitialize.Addr(),
		amsiScanString.Addr(),
	}
	patch := byte(0xC3)
```
[source: `implant/sliver/taskrunner/task_windows.go:199-212`]

**D1 §7 described this as a "crude 1-byte 0xC3 AMSI patch." That is exactly right, and the handler layer adds the structural point: `patchAmsi` is reachable only through `InProcExecuteAssembly`.** The `AmsiBypass` flag in the in-process handler [source: `handlers_windows.go:335`] is what gates it. **`executeAssemblyHandler` has no such flag and no path to `patchAmsi`.** [source: `handlers_windows.go:305-324`]

**Consequences, both directions:**

- **The sacrificial path cannot disable AMSI**, so an assembly run through `execute-assembly` is scanned in the target process unless the operator picks a process that already has it patched.
- **The in-process path writes `0xC3` into `amsi.dll` at three export addresses** — three separate `ret` patches, no integrity restoration, no ETW handling visible at this site despite the `EtwBypass` parameter existing. **Where `EtwBypass` is consumed is not resolved here** and is recorded as residual U4.

**Build-posture note:** `0xC3` as `AmsiScanBuffer`'s first byte makes it return immediately with whatever is in `EAX`, which is the canonical AmsiScanBuffer patch and is trivially signatured. **This is the least sophisticated evasion in the corpus's Sliver side**, and it sits in the *handler* layer rather than the evasion layer — which answers question 3 directly.

### 7.5 Extension and BOF execution — a third execution model

`handlers_extensions.go` and `handlers_bof.go` add execution paths that are neither spawn nor inject:

```go
handlers_bof.go:9   "github.com/sliverarmory/reflektor/bof"
handlers_bof.go:12  type bofObject interface {
handlers_bof.go:13  	Execute([]byte) ([]bof.Output, error)
handlers_bof.go:17  type bofLoadFunc func([]byte, bof.LoadOptions) (bofObject, error)
handlers_bof.go:19  type bofExecuteFunc func([]byte, string, []byte) (bof.Output, error)
handlers_bof.go:21  func loadReflektorBOF(data []byte, options bof.LoadOptions) (bofObject, 
```
[source: `implant/sliver/handlers/handlers_bof.go:9-21`]

**BOF support is provided by a vendored third-party package, `github.com/sliverarmory/reflektor/bof`.** [source: `handlers_bof.go:9`] The handler is an interface wrapper over it, not a first-party COFF loader. **This is a vendoring boundary that matters for attribution:** a Sliver BOF capability is *reflektor's* BOF loader behind a Sliver handler, and any detection written against the loader should target reflektor's implementation.

**BOFs run in-process in the implant's own memory** — the interface takes `[]byte` and returns output, with no process parameter. [source: `handlers_bof.go:19` — `Execute([]byte, string, []byte)`]

### 7.6 Summary — the execution surface by exposure

| Primitive | Constant | Runs | API chain | Evasion |
|---|---|---|---|---|
| `execute-assembly` | 34 | **sacrificial process** | `VirtualAllocEx`→`WPM`→`CreateRemoteThread` | none available |
| `execute-assembly --in-process` | 102 | **implant process** | in-process CLR load | `AmsiBypass` (0xC3 ×3), `EtwBypass` |
| `SpawnDll` | 40 | **sacrificial process** | same triple, `task_windows.go:337` | none |
| `Sideload` | 38 | **sacrificial process** | `SpawnDll` wrapper, `:409` | none |
| BOF | via `callExtension` | **implant process** | reflektor BOF loader | inherits implant's state |
| `CallExtension` | 91 | **implant process** | WASM or native ext | inherits implant's state |

[source: `handlers_windows.go:64-65`; `task_windows.go:123, 337, 409, 523`; `handlers_bof.go:19`]

**Note the `Sideload` relationship:** `task_windows.go:409` calls `SpawnDll(procName, procArgs, ppid, data, 0, []string{""}, kill)` — **Sideload is a thin wrapper over SpawnDll, not an independent implementation.** [source: `task_windows.go:409`] They share the entire injection chain.

---

## 8. INJECTION AND MIGRATION

### 8.1 Migration — the handler is a lookup, and the work is elsewhere

`migrateHandler` is bound to `MsgInvokeMigrateReq` (37). [source: `handlers_windows.go:61`] Its body delegates to the taskrunner, which reuses the **same** `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` triple already catalogued in §7.2. [source: `task_windows.go:80, 96, 123`]

**There is no separate migration technique.** Migration *is* the sacrificial injection path with a different payload — no `NtCreateThreadEx`, no `QueueUserAPC` at this call site despite `QueueUserAPC` being *declared* in the syscalls package. [source: `syscalls_windows.go:16` declares it; `task_windows.go` shows no call]

**A declared-but-uncalled API is worth stating precisely:** `QueueUserAPC` exists as a generated binding [source: `syscalls/syscalls_windows.go:16`] but the injection path uses `CreateRemoteThread`. **Early-bird APC injection, which `QueueUserAPC` would enable, is not implemented in the handler layer.** Positive control: the same declaration block's other entries (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) **are** called from `task_windows.go`. **The probe finds live uses of its neighbours; `QueueUserAPC`'s absence is a real absence.**

### 8.2 Answer to question 3

**No. The handler layer does not reach for anything more sophisticated than the evasion layer does, because there is no such layer.** The evasion surface available to a handler is exactly: a 1-byte AMSI `ret` patch, an `EtwBypass` parameter whose consumer is unresolved (§7.4, U4), and whatever the C2 profile configured at build time. **Injection is unhardened.** This is a clean, well-evidenced negative.

---

## 9. TOKEN AND PRIVILEGE

### 9.1 The token handler surface

Windows binds **four** token/privilege handlers:

| Constant | ID | Handler |
|---|---|---|
| `MsgGetPrivsReq` | 87 | `getPrivsHandler` |
| `MsgCurrentTokenOwnerReq` | 100 | `currentTokenOwnerHandler` |
| `MsgMakeTokenReq` | 64 | `makeTokenHandler` |
| `MsgImpersonateReq` | 26 | `impersonateHandler` |
| `MsgRevToSelfReq` | 31 | `revToSelfHandler` |
| `MsgRunAsReq` | 28 | `runAsHandler` |
| `MsgInvokeGetSystemReq` | 32 | `getsystemHandler` |

[source: `handlers_windows.go:59-66`, `:87`]

### 9.2 The impersonation mechanism, and the comment that matters most

`ImpersonateLoggedOnUser` is a thread-scoped operation, and Sliver's dispatch path carries an explicit, unusually candid comment about it:

```go
} else if handler, ok := sysHandlers[envelope.Type]; ok {
	// Beware, here be dragons.
	// This is required for the specific case of token impersonation:
	// Since goroutines don't always execute in the same thread, but ImpersonateLoggedOnUser
	// only applies the token to the calling thread, we need to call it before every task.
	// It's fucking gross to do that here, but I could not come with a better solution.
```
[source: `implant/sliver/runner/runner.go:684-689`]

**This is the single most operationally significant comment in the handler layer.** Go's scheduler migrates goroutines between OS threads, and `ImpersonateLoggedOnUser` binds a token to a *thread*. Sliver's resolution is to **re-apply the impersonated token immediately before every dispatched task**, inside the dispatch ladder.

**Two consequences:**

- **Correctness:** the workaround is sound for its stated purpose — re-applying before each task means a task on any thread runs with the right token.
- **Detection:** **a token-impersonation API is invoked immediately prior to every single handler dispatch**, not just on `impersonate`. That is an unusual, highly regular call pattern: `ImpersonateLoggedOnUser` firing before unrelated commands is a behavioural signature, and the comment documents exactly why.

[source: `runner.go:685-689`; `syscalls_windows.go:24` declares `ImpersonateLoggedOnUser` from `advapi32`]

### 9.3 The privilege escalation path

`getsystemHandler` is bound to `MsgInvokeGetSystemReq` (32) [source: `handlers_windows.go:60`], and the token acquisition primitives are declared alongside the injection ones:

```
syscalls_windows.go:24  //sys ImpersonateLoggedOnUser(hToken windows.Token) (err error) = advapi32.ImpersonateLoggedOnUser
syscalls_windows.go:25  //sys LogonUser(lpszUsername *uint16, lpszDomain *uint16, lpszPassword *uint16, dwLogonType uint32, dwLogonProvider uint32, phToken *windows.Token) (err error) = advapi32.LogonUserW
```
[source: `syscalls/syscalls_windows.go:24-25`]

**`LogonUser` is the primitive behind `makeToken` and `runAs`** — the operator supplies credentials and the implant performs a logon server-side, obtaining a token without needing `runas.exe`. **`CreateProcessWithLogonW` is also declared** at `syscalls_windows.go:12`, meaning `runAs` can launch directly under supplied credentials rather than relying on token theft.

**No credential dumping primitive is declared in this package.** There is no `MiniDumpWriteDump`-to-token-store path beyond the process-dump handler's own use of `MiniDumpWriteDump`. [source: `syscalls_windows.go:23` declares `MiniDumpWriteDump` from `DbgCore`; it is the `procdump` handler's primitive, not a credentials handler's]

### 9.4 Answer to question 4 — and the verification question

**How it manipulates tokens:** `LogonUser`/`CreateProcessWithLogonW` to *create* a token from credentials, `ImpersonateLoggedOnUser` to *apply* it thread-wide, re-applied on every dispatch [source: `runner.go:685-689`], and `getsystemHandler` for the SYSTEM-token path.

**Does it verify what it got?** At the handler layer, **yes at the RPC level, no at the privilege level.** Every handler returns a `*commonpb.Response` with an `Err` field when the underlying call fails [source: `handlers_windows.go:316-320`, `:337-341` — `execAsm.Response = &commonpb.Response{Err: err.Error()}`], so a failed logon is reported to the operator. **But there is no evidence at this layer that the resulting token's integrity level or privileges are checked before use** — `MsgGetPrivsReq`/`getPrivsHandler` (87) exists as a *separate operator-initiated query*, not as an automatic post-impersonation assertion.

**Stated carefully:** the absence of an automatic privilege assertion is what the code shows; whether a deeper token-validation step exists inside `getsystemHandler`'s body is **not resolved in this section** and is recorded as residual U5. **I am not claiming the implant proceeds blindly — I am stating that the handler layer's error reporting is RPC-level and I did not find a privilege-level check at the constant or dispatch layer.**

### 9.5 The privilege surface is small, and that is the finding

**Seven handler bindings touch tokens or privileges** [source: `handlers_windows.go:59-66, :87`], against **65 Windows bindings total** — roughly **11%**. The `priv/` directory the brief flags at 22 KB is a *support* package, not a handler namespace: no constant in `constants.go` binds to it directly, and the privilege work is reached through the four token handlers above.

---

## 10. PARAMETERS NO DEPLOYMENT EVER ENABLES

**The handler layer is written in Go-template source, and three template variables decide what the deployed map contains.** This is the corpus's standing pattern — *source presence is not build presence* — and it applies to the dispatch table itself, not just to a function body.

### 10.1 Guard census — exactly three variables, and their counts

Every `{{if .Config.X}}` occurrence in `.go` files under `handlers/`, tests excluded:

| Guard | Occurrences | What it gates |
|---|---|---|
| `{{if .Config.Debug}}` | **169** | `log.Printf` statements only |
| `{{if .Config.IncludeWG}}` | **4** | WireGuard handler **map entries and their imports** |
| `{{if .Config.IsBeacon}}` | **1** | beacon scheduling fields in `reconfigure` |

[source: recursive extraction of `\{{if \.Config\.(\w+)` over `implant/sliver/handlers/`, `_test.go` excluded]

**These three are not equivalent, and the difference is the point:**

- **`Debug` (169 sites)** — gates **only logging.** Removing it does not change the dispatch table by one entry. It does change observability: **every `log.Printf` in the handler layer is absent from a release build.** §6.2 already relied on this.
- **`IncludeWG` (4 sites)** — gates **handler map entries and their imports.** This one **changes the dispatch surface.**
- **`IsBeacon` (1 site)** — gates **a code block inside `reconfigureHandler`.** It changes what a handler *does*, not which IDs are bound.

### 10.2 `IncludeWG` — the one guard that removes bindings

Four sites, and each removes **six** WireGuard bindings from one platform map:

| File | Guard line | Removes |
|---|---|---|
| `handlers_windows.go` | `:126` | 6 WG bindings (`:127-134`) |
| `handlers_linux.go` | `:87` | 6 WG bindings |
| `handlers_darwin.go` | `:78` | 6 WG bindings |
| `handlers-wireguard.go` | `:21` | the WG handler implementations and their imports |

[source: `handlers_windows.go:126`; `handlers_linux.go:87`; `handlers_darwin.go:78`; `handlers-wireguard.go:21`; map bodies as enumerated in §3]

**Consequence for every count in this report, stated explicitly:**

| | Entries |
|---|---|
| Windows map **with** `IncludeWG` (as written in source) | **65** |
| Windows map **without** `IncludeWG` (a deployment that did not enable WireGuard) | **59** |
| Total entries across all nine maps, source | **187** |
| Distinct constants, source | **85** |

**Whether a specific Sliver build binds the six `MsgWG*` constants is a C2 profile decision, not a source fact.** [source: `handlers-wireguard.go:21` — the guard wraps the import block, so the handlers do not exist to be bound]

**The `MsgWG*` constants are still defined (IDs 74-79) in every build** — they live in `constants.go`, which is not template-preprocessed. [source: `constants.go` iota block, IDs 74-79] **So a build without `IncludeWG` is a build in which six defined message IDs have no handler and the final `else` at `runner.go:729` is what receives them.** §6 establishes what happens then: `UnknownMessageType: true` is returned.

**This is the cleanest possible illustration of the corpus rule.** The source says 65. A real deployment says 59 or 65. **Both are correct, and the difference is a profile flag.** A report that quoted 65 as "the Windows handler count" without this paragraph would be quoting a source fact as a deployment fact — the same defect as D11's sleep-mask finding and D5's HWBP finding, in the dispatch layer this time.

### 10.3 `IsBeacon` — a handler that is partially absent

```go
	// {{if .Config.IsBeacon}}
	if reconfigReq.BeaconInterval != 0 {
		transports.SetInterval(reconfigReq.BeaconInterval)
	}
	if reconfigReq.BeaconJitter != 0 {
		transports.SetJitter(reconfigReq.BeaconJitter)
	}
	if reconfigReq.C2URI != "" {
		...
		transports.SetC2URI(reconfigReq.C2URI)
	}
	// {{end}}
```
[source: `implant/sliver/handlers/handlers.go:1349-1362`]

**`reconfigureHandler` is bound in every build** — `MsgReconfigureReq` → `reconfigureHandler` is in `genericHandlers` and the Windows map. [source: `handlers_windows.go`, §3.2] **But on a session-mode implant, the beacon-interval and beacon-jitter branches are compiled out.** [source: `handlers.go:1349`, `:1362`]

**So `MsgReconfigureReq` succeeds on a session implant and silently ignores `BeaconInterval` and `BeaconJitter`.** The `SetC2URI` branch sits *inside* the `IsBeacon` guard, meaning **C2 URI reconfiguration is also unavailable on session implants.** A `reconfigure` RPC cannot change a session implant's C2 at runtime.

**This is a handler that returns success while doing nothing for some of its fields** — a different failure shape from §6's explicit negative response. **§6's mechanism covers IDs with no handler; it does not cover IDs with a handler that ignores parameters.** Worth recording as the handler layer's own version of the silent-drop question, answered *partially* in the negative.

### 10.4 The guard that explains §6.2's caveat

**169 `Debug` guards across the handler layer** [source: §10.1 census] means the handler layer's entire local trace is absent from a release build. **When §6.2 says an unknown message ID leaves no local record, this census is why** — and the reason the protocol-level `UnknownMessageType` reply is the *only* surviving signal.

---

## 11. RESIDUAL UNKNOWNS AND COVERAGE

### 11.1 What was measured

| Subject | Method | Result |
|---|---|---|
| Message-ID constants | direct enumeration, `constants.go:44-361` | **136**, IDs 1-136 contiguous |
| Handler maps | anchored brace-walk, nine files | **9 maps** (D1 lists 7) |
| Map entries | per-map extraction, distinctness-validated | **187** (windows 65, linux 45, darwin 40, generic 21, tunnel 7, pivot 4, rportfwd 3, kill 1+1) |
| Distinct bound constants | set union of nine maps | **85** |
| Unbound constants | set difference against 136 | **51** (49 non-`Req`, 2 `Req`) |
| Orphans (bound but undefined) | set containment | **0** |
| Template guards | regex census over non-test `.go` | **Debug 169, IncludeWG 4, IsBeacon 1** |
| Unknown-ID runtime path | read, `runner.go:669-740` | **explicit `UnknownMessageType: true` reply** |

### 11.2 Residual unknowns

**U1 — `EtwBypass`'s consumer is unresolved.** `inProcExecuteAssemblyHandler` passes `execReq.EtwBypass` to `taskrunner.InProcExecuteAssembly` [source: `handlers_windows.go:335`], and `patchAmsi` at `task_windows.go:199-212` patches only AMSI. **Where ETW is patched, or whether the parameter is honoured at all, was not traced.** §7.4 notes this. **This is the most likely place for a second crude patch and it is unexamined.**

**U2 — `getsystemHandler`'s internal verification is unread.** §9.4 states the handler layer's error reporting is RPC-level; whether the body asserts integrity level before returning a token was not read. **Stated as unknown rather than asserted either way.**

**U3 — the client's rendering of `UnknownMessageType` is outside scope.** §6.3 establishes the server is informed. Whether a Sliver client surfaces it as an operator-visible error was not checked.

**U4 — `tunnel_handlers/` bodies are inventoried but not reversed.** The 13-file / 157,413 B package is the largest block of handler code [source: §1.1]. §4.2 maps its **seven bindings** to their **entry functions** and §4.3 notes the stub/unix split. **The bodies — `ShellReqHandler`, `SocksReqHandler`, `PortfwdReqHandler`, `TunnelDataHandler` — are not reversed here.** Given the size, this is the largest remaining surface and the brief's question 6 is only partly answered: see U5.

**U5 — "what is a tunnel" is answered structurally, not semantically.** A tunnel is a handler of type `TunnelHandler` that owns a duplex stream; pivot and rportfwd maps share that type but are dispatched **before** `tunHandlers` in the ladder [source: `runner.go:674-725`]. **The distinction between a pivot, an rportfwd, and a tunnel at the data-flow level was not established** — only that all three use `TunnelHandler` and are ordered specifically in dispatch. **Relation to D1 §11's pivot layer: the pivot *client* is D1 §11's subject and lives in `transports/pivotclients/`; the pivot *handlers* enumerated in §4.2 are the server-side half of the same subsystem.** That relationship is asserted from the constant names and the import at `pivot-handlers.go:27` [source: `pivot-handlers.go:27` imports `implant/sliver/pivots`], **not** from reading the pivot transport code.

**U6 — the 49 non-`Req` constants were classified by name, not traced.** §5.2 splits them by the `Req` suffix. **A suffix is strong evidence, not proof.** A constant without `Req` that is nonetheless received by the implant would be an unhandled command. **The strongest available check was applied in §5.6 — the dispatched set is a strict subset of the defined set — but no constant was individually traced to a sender.** `MsgBeaconRegister` (93) and `MsgBeaconTasks` (94) are the most likely to be genuinely received and are candidates for follow-up.

**U7 — this report did not read the `handlers.go` bodies (46,730 B, the largest single handler file).** D1 §6.4 covers its **filesystem** surface at 38 functions. [source: `D1:814`] **This report enumerates its bindings (§3.2) but does not reverse its bodies.** A D1 §6.4 cross-reference was not performed.

### 11.3 Coverage boundary

**Covered:** the complete constant set, the complete map set, the complete ID→function mapping, the cross-reference in both directions, the unknown-ID runtime path, the execution-primitive split, injection and migration chains, the token/privilege binding surface, and the build-variance census.

**Not covered:** handler **bodies** outside those cited (§7-§9 cite bodies for the execution, injection, and AMSI paths only), `tunnel_handlers/` internals, `handlers.go`'s filesystem bodies, the client's error rendering, and any runtime observation. **This is a dispatch-layer and execution-primitive report; it is not a full reversal of 332 KB of handler code.**

### 11.4 Corrections to D1 recorded in place

| # | D1 states | Disk | § |
|---|---|---|---|
| C1 | §6.3 table: **135 IDs**, `MsgTaskReq = 1` | **136 IDs**, `MsgRegister = 1`; D1 uniformly −1 | §2 |
| C2 | §6.1: **seven** maps | **nine** (two `killHandlers` variants) | §3.1 |
| C3 | §6.2: `windowsHandlers` = **51 bindings** | **65 entries**; D1's sub-lists sum short and 33 bindings lack constants | §3.1-§3.3 |
| C4 | §6.3's "independent confirmation" of 135 against T1 | **void** — implant side is 136 | §2.3 |

**C1 and C4 are the load-bearing ones.** C1 misdirects anyone reading a pcap; C4 retracts a cross-report agreement that no longer holds.

---

*End of D15.*
