# D23 — Sliver message-ID count reconciliation: is T1's 135 the same defect as D1's 135?

**Task:** T1 correction (Lead-issued). **Lane:** sliver-diver. **Method:** source-only enumeration; no REA/Ghidra.
**Question:** D1 §6.3 published a 135-ID table beginning `MsgTaskReq = 1`; disk truth is **136 constants, IDs 1–136, ID 1 = `MsgRegister`**. D1 is corrected. **Does T1's client-side 135 share the defect?**

**Answer, up front: No. T1's 135 is not the same number as D1's 135, and it is not an off-by-one.** `[src]` T1's `135` is, on the evidence, **the row count of a protobuf *field-tag* CSV** — not a request-type count at all. It is a **category error**, not an arithmetic one. D1's was arithmetic. **They are two different defects that happen to print the same integer.** `[inference]`

**Citation convention:** inline `path/file.go:LINE`.

---

## 0. Correction 0 — my own first probe was broken, and it nearly produced a third false zero

**Recorded first because the corpus's central methodological rule is that an absence needs a positive control, and my opening probe failed that rule.** `[src]`

My first attempt to enumerate the constants used:

```
$pat = '^\s*(Msg\w+)\s*=\s*(\d+)'
```

**Result: `total Msg* matches: 0`.** `[src]`

Had I reported that, it would have been **the third instrument-induced false zero this session.** The cause: `protobuf/sliverpb/constants.go:41-361` is **not** a list of `Name = N` assignments. It is a single `iota` block — `MsgRegister = uint32(1 + iota)` at `:44`, followed by ~135 bare identifiers with **implicit values**. A regex looking for `= <digits>` finds exactly the one line that has them and misses the other 135. `[src]`

**This is the same class of error as the `db/` non-recursive glob (D11 §0) and D1's `Native.h` count: an instrument that reports a structure as flat when it is implicit.** Three instances, three different instruments, one root cause. `[inference]`

The corrected enumeration walks the `iota` block line-by-line, tracking implicit continuation and skipping comment-only lines. Result, and it confirms the Lead's disk truth exactly: **136 constants, IDs 1–136 contiguous, 136 distinct IDs, ID 1 = `MsgRegister` (`:44`), ID 136 = `MsgExecuteChildrenReq`.** `[src]`

**Full enumeration saved to `RE_Library\07_OUTPUT\_d23_msgids.csv`** (136 rows: `Name`, `Val`) for independent re-derivation. `[src]`

---

## TOC

1. What T1 actually says, and what it cites
2. The instrument T1 used — and why it cannot produce 135
3. What actually has 135 rows
4. Independent re-derivation of the client-side request-type count (three methods)
5. Why 136 was never reachable from T1's corpus
6. The real client/implant divergence — a naming split, not an off-by-one
7. Verdict
8. Residual unknowns
9. What this report does NOT establish

---

## 1. What T1 actually says, and what it cites

`reports/T1_sliver_client.md:236`:

> **135 unique request types** were enumerated across the extraction corpus.

The sentence sits at the end of **§3.2**, whose subject is the **RPC method-signature surface**: `:226-234` discusses three protobuf namespaces, the `...grpc.CallOption` variadic as a streaming discriminator, and methods whose input type does not end in `Req` (`CloseSession`, `CurrentTokenOwnerReq`, `MemfilesListReq`). `[src]`

**§3.2 is signature analysis. Its natural product is a count of input types, and its cited artifact for that analysis is `rpc_signatures.txt`.** `[inference]`

`T1:527` restates it: *"the full 135-entry ..."* — same number, no new derivation. `[src]`

**Neither sentence cites a file.** That is the defect that matters here and it is discussed in §7. `[src]`

---

## 2. The instrument T1 used — and why it cannot produce 135

The §3.2 evidence base is `extractions\T1\rpc_signatures.txt` — **154 lines** of Go method signatures. `[src]`

Reproducing §3.2's stated method (extract the first protobuf pointer type from the parameter list of each signature, deduplicate) gives: `[src]`

| Method | Result |
|---|---|
| `rpc_signatures.txt` lines | **154** |
| signatures with `...grpc.CallOption` | 79 |
| signatures without (streaming) | 75 |
| input types extracted (non-unique) | 79 |
| **unique input types (Method A)** | **81** |
| unique `*Req`-suffixed input types (Method B) | **76** |
| unique input types excluding `commonpb.Empty` (Method C) | **81** |

**None of these is 135, and none is 154.** `[src]` The remainder of the corpus:

| Artifact | Lines/rows |
|---|---|
| `sliverrpc_client_methods.txt` | **201** (201 unique) |
| `rpc_signatures.txt` | 154 |
| `proto_field_tags.csv` | **135** |

`[src]`

**Conclusion: T1's 135 is not reproducible from the signature surface by any method I can construct.** The number does not come from its own cited evidence. `[src]` + `[inference]`

---

## 3. What actually has 135 rows

`extractions\T1\proto_field_tags.csv` is **exactly 135 rows.** `[src]`

**And it is a field list, not a type list.** Enumerated: `[src]`

| Property | Value |
|---|---|
| rows | **135** |
| unique `addr` | **135** |
| unique `name` | **123** |
| names ending `Req` | **0** |
| names containing `Req` | **1** |
| columns | `addr, wire, field, label, name, json, enum` |

Sample rows, verbatim from the file: `field=4 Ack`, `field=2 address`, `field=9 AddressOfFunctions`, `field=14 AmsiBypass`, `field=8 Arch`, `field=8 BeaconID`, `field=7 Capabilities`, `field=2 ClientPrivateKey`. `[src]`

**Every one of the 135 rows is a *struct field* — a name like `Ack` or `Capabilities` with a field number and a wire type. Not one is a message type, not one is a request type.** `[src]`

**T1 itself labels this artifact correctly.** `T1:238-240`: *"### 3.3 Protobuf field tags"* and *"records protobuf struct tags with resolved wire types"* — the very next subsection. `[src]` So T1's §3.3 describes `proto_field_tags.csv` accurately as a **field-tag** table, while §3.2, four lines earlier, reports a **135** that matches that field-tag table's row count. `[src]`

**Assessment (`[inference]`, and I want the confidence marked honestly):** the most probable account is that a 135 row-count of `proto_field_tags.csv` migrated into the §3.2 sentence, where it was mislabelled as a count of *request types*. **I cannot prove the causal path** — the derivation step was not recorded, and that absence is itself the reason this cannot be closed by inspection. What I *can* state as `[src]`: §3.2's sentence is unsupported by its own evidence base, and the only 135 in the T1 corpus is a field-tag row count. **The coincidence of 135 with D1's defective 135 is exactly that — a coincidence, and a confusing one.**

**Independent re-derivation, requested by the Lead (§2 of the task): the client-side request-type count is 81 (broader reading) or 76 (strict `*Req` reading). It is not 135, and it is not 136.**

---

## 4. Independent re-derivation of the client-side request-type count

Three methods, each stated with its scope, as the task requires. `[src]`

**Method A — unique protobuf input types across all 154 signatures.**
Scope: every signature in `rpc_signatures.txt`; extract the first `*(clientpb|sliverpb|commonpb).X` in the parameter list; deduplicate on fully-qualified name.
**Result: 81.** Includes `commonpb.Empty` and three non-`Req` inputs (`clientpb.MSFReq` aside, the irregular ones named at `T1:233-234`).

**Method B — unique `*Req`-suffixed input types only.**
Scope: same corpus, restricted to inputs whose type name ends in `Req`.
**Result: 76.**

**Method C — as Method A, excluding `commonpb.Empty`.**
Scope: same as A, minus the one empty-message input.
**Result: 81** (`commonpb.Empty` does not appear as an input in this file — the three namespaces listed at `T1:226` notwithstanding).

**Method D — the constants table, for the implant side.**
Scope: `protobuf/sliverpb/constants.go` `iota` block, `:41-361`, walked with implicit-value continuation.
**Result: 136 constants, 136 distinct IDs, range 1–136.**

**Reconciliation:** the two figures measure **different things**, and conflating them is the error this report exists to prevent. `[src]`

| Instrument | Measures | Count |
|---|---|---|
| constants `iota` block | **wire message IDs** (the envelope's `MsgNumber`) | **136** |
| RPC signature input types | **operator-plane request messages** | **76 / 81** |
| `proto_field_tags.csv` rows | **protobuf struct fields** | **135** |

**These are three disjoint categories.** A message ID is not a request type; a request type is not a field. **The client-side "how many request types" and the implant-side "how many message IDs" were never the same measurement**, and D1 `:810-812`'s claim that one "independently confirmed" the other was comparing a measurement to a non-measurement. `[src]` + `[inference]`

---

## 5. Why 136 was never reachable from T1's corpus

**Positive control, run before reporting this absence.** `[src]`

Probe: search all 12 spill files in `extractions\T1\strings\` (2.9 MB total) for the constant names.

| Probe string | Hits |
|---|---|
| `MsgRegister` | **0** |
| `MsgTaskReq` | **0** |
| `MsgExecuteChildrenReq` | **0** |
| `MsgShellResizeReq` | **0** |
| `Msg` | **0** |
| `sliverpb.Msg` | **0** |
| `MsgNumber` | **0** |

`[src]`

**Control: the same probe shape returns non-zero elsewhere in the corpus** — `sliverrpc_client_methods.txt` yields 201 method names, and the spills are demonstrably populated (2.9 MB across 12 files, including a 1.07 MB and a 519 KB spill). `[src]` **So the spills are not empty and the probe is not broken; the `Msg*` identifiers are genuinely absent from them.**

**Interpretation (`[inference]`):** Go constant *names* are symbol-table entries, not string data — precisely the mechanism T1 §4.2 documented at `:326-327` when correcting the `search_strings` method error. The T1 string spills therefore could never contain the `Msg*` name list, which is why **T1 had no path to 136 by this route regardless of method.** The absence is structural, not incidental.

**Which is the cleanest statement of why the two 135s are unrelated: T1 could not have made D1's error, because T1 never looked at the constants table at all.**

---

## 6. The real client/implant divergence — a naming split, not an off-by-one

The Lead's question 2 asked: if 135, is there a client-only or implant-only request type? **The honest answer is that the comparison is not well-posed as asked — but diffing the two surfaces anyway is productive, because it exposes a genuine and unremarked convention split.** `[inference]`

Diffing the 82 `Msg*Req`-derived names against the 76 signature `*Req` names: `[src]`

**18 present in the constants table, with no matching signature (implant-side / wire-only):**
`DeregisterWasmExtensionReq`, `InvokeExecuteAssemblyReq`, `InvokeGetSystemReq`, `InvokeInProcExecuteAssemblyReq`, `InvokeMigrateReq`, `KillSessionReq`, `RegisterWasmExtensionReq`, `RegistrySubKeysListReq`, `RPortfwdReq`, `RportFwdStartListenerReq`, `ScreenshotReq`, `SpawnDllReq`, `WGListForwardersReq`, `WGListSocksReq`, `WGStartPortFwdReq`, `WGStartSocksReq`, `WGStopPortFwdReq`, `WGStopSocksReq`

**12 present in signatures, with no matching `Msg*Req` (operator-plane-only):**
`GetSystemReq`, `InvokeSpawnDllReq`, `KillReq`, `MigrateReq`, `MSFReq`, `RegistrySubKeyListReq`, `WGPortForwardStartReq`, `WGPortForwardStopReq`, `WGSocksServersReq`, `WGSocksStartReq`, `WGSocksStopReq`, `WGTCPForwardersReq`

`[src]`

**The pattern is not random, and it is the actual finding of this report.** Nearly every entry on both lists has a **near-twin on the other side with a different name for the same operation**: `[src]`

| Operator-plane (gRPC) | Implant wire | Same operation |
|---|---|---|
| `InvokeGetSystemReq` | `GetSystemReq` | ✓ |
| `InvokeSpawnDllReq` | `SpawnDllReq` | ✓ |
| `InvokeMigrateReq` | `MigrateReq` | ✓ |
| `InvokeExecuteAssemblyReq` / `InvokeInProcExecuteAssemblyReq` | — (no `Invoke` prefix) | ✓ |
| `RegistrySubKeyListReq` | `RegistrySubKeysListReq` | ✓ (plural) |
| `KillReq` | `KillSessionReq` | ✓ |
| `WGPortForwardStartReq` | `WGStartPortFwdReq` | ✓ (reordered words) |
| `WGPortForwardStopReq` | `WGStopPortFwdReq` | ✓ (reordered words) |
| `WGSocksStartReq` | `WGStartSocksReq` | ✓ (reordered words) |
| `WGSocksStopReq` | `WGStopSocksReq` | ✓ (reordered words) |
| `WGSocksServersReq` | `WGListSocksReq` | ✓ |
| `WGTCPForwardersReq` | `WGListForwardersReq` | ✓ |

**Two mechanisms produce the divergence, and neither is an off-by-one:** `[inference]`

1. **`Invoke` prefix.** The operator-plane names use an `Invoke`/no-`Invoke` convention (`InvokeGetSystemReq` vs `GetSystemReq`) — a *naming* difference on the same operation.
2. **Word-order and pluralisation drift** in the WireGuard family (`WGPortForwardStart` vs `WGStartPortFwd`; `RegistrySubKey` vs `RegistrySubKeys`).

**So the 18/12 split is almost entirely naming, not capability.** `[inference]` The counts differ (82 vs 76) because each surface adds a handful of genuine natives — `MSFReq` and `ScreenshotReq` are plausible single-side entries — but **the bulk of the divergence is the same operations wearing different names in the two namespaces.** `[inference]`

**This is unpublished and it is a real hazard:** anyone correlating operator RPCs to implant wire IDs by name-matching will silently miss ~16 operations. `[inference]` It belongs in the corpus as a companion to D15's ID→function mapping.

---

## 7. Verdict

| Question | Answer |
|---|---|
| Does T1's 135 share D1's defect? | **No.** `[src]` |
| Is T1's 135 an off-by-one? | **No — it is a category error.** 135 is the row count of a *field-tag* CSV, presented as a count of *request types*. `[src]` + `[inference]` |
| Why did both print 135? | **Coincidence.** D1's 135 was 136 depleted by one (a real off-by-one). T1's 135 is `proto_field_tags.csv`'s row count (an unsupported attribution). `[inference]` |
| What is the true client-side request-type count? | **81** (all unique input types) or **76** (strict `*Req`). Both reproduced in §4. `[src]` |
| Is the client/implant comparison 135 vs 136? | **Not well-posed.** 136 counts *wire message IDs*; 81/76 count *operator-plane request messages*. Disjoint categories (§4). `[src]` |
| Are the two surfaces meaningfully different? | **Yes — by name, not by count.** 18 implant-only + 12 operator-only entries, mostly the same operations under different names (§6). `[src]` |

**The corpus's root reference count problem is now bounded precisely:**

- **D1's 135** — wrong by one. Implant side is **136**. Lead corrected inline; D15 carries the full ID→function map. Arithmetic error. `[src]`(D1)
- **T1's 135** — **not a count of the thing it claims.** Citation defect: a figure with no cited artifact, matching the row count of an adjacent field-tag table. **Category error.** `[src]`
- **D1 `:810-812`'s "independent confirmation"** — void on two independent grounds: (i) same table checked against itself, already voided by the Lead; (ii) **the two figures were never the same measurement**, so no agreement between them could ever have been confirmation. `[src]` + `[inference]`

**Recommended T1 disposition:** §3.2's sentence should be replaced with the supported figure and its method — **"81 unique request input types (76 strict `*Req`), enumerated from `rpc_signatures.txt` (154 signatures) by extracting the first protobuf parameter type and deduplicating"** — with the delimitation that this is an *operator-plane request-type* count and is **not** comparable to the 136-entry wire-ID table. **I am not making that edit unprompted**, having just been instructed to append to T1 only if needed and to prefer D23 as the vehicle. Flagged for the Lead's call.

---

## 8. Residual unknowns

1. **The derivation step for T1's 135 was never recorded.** §3's identification of `proto_field_tags.csv` as the source is `[inference]` from row-count correspondence plus subject-adjacency, **not** proof. **Probe:** unrecoverable if no derivation log exists; if the Lead holds the T1 session notes, the answer is there.
2. **`proto_tags.csv` is 0 bytes.** `extractions\T1\proto_tags.csv` exists and is empty — plausibly the aborted precursor to `proto_field_tags.csv`. Whether it once held 135 rows is unverified. **Probe:** check filesystem timestamps against the T1 session.
3. **Method A's 81 vs Method B's 76 differ by 5** (`CloseSession`, `CurrentTokenOwnerReq`, `MemfilesListReq`, `Ping`, `Tunnel`-class inputs). I enumerated the list but did not individually adjudicate which are *requests* vs *responses* vs *streaming payloads*. The honest range for "request types" is **76–81**. `[src]`
4. **`commonpb.Empty` handling.** `T1:226-228` names `commonpb` as a third namespace with `Empty` as its type, but `rpc_signatures.txt` shows no `*commonpb.Empty` input in the 154 lines I parsed. Either the namespace claim rests on evidence outside this file, or `Empty` appears as an output. **Unresolved — I did not enumerate outputs.** `[src]`
5. **T1 §3.2's other claims were not re-audited.** Given one unsupported figure in the section, the namespace and streaming-discriminator claims at `:226-232` deserve the same treatment. I verified only the count. `[inference]`
6. **The 18/12 diff is name-level, not semantic.** §6's pairing table is `[inference]` from naming resemblance. Confirming it requires reading each `Msg*` constant's comment in `constants.go` against its RPC handler. I did not do that; **D15's ID→function mapping is the natural place**, and D15 is not mine to touch.

---

## 9. What this report does NOT establish

- **It does not claim T1's 135 was copied from D1.** Different instruments, different sources; §3's account is that it came from a field-tag table. Coincidence, not contamination. `[inference]`
- **It does not re-audit D1 or D15.** D1's correction is the Lead's and is cited, not re-derived.
- **It does not claim 76 or 81 is the "right" number in an absolute sense** — both are correct *for their stated scope* (§4). A different scope yields a different number.
- **It makes no claim about the deployed client binary.** Everything here is derived from source-tree artifacts; **the 135 was itself a claim about the client binary**, and whether the binary's symbol table would yield 76/81/135/136 is *not* established here and would require REA/Ghidra, which this task excludes.
- **It does not edit T1.** Recommended disposition only (§7).

---

## Summary

**D1's 135 was wrong by one. T1's 135 was not the same measurement.** The corpus's root reference count had **two** published 135s, and they fail for **different reasons** — one arithmetic, one categorical — which is worse than either failing twice for the same reason, because the agreement between them looked like corroboration. D1 `:810-812` treated that agreement as independent confirmation; it was two numbers in different units happening to round to the same figure.

The client-side operator-plane request-type count is **76 (strict) to 81 (broad)**, re-derived three ways in §4. The implant-side wire message-ID count is **136**, independently re-enumerated and matching the Lead's figure. **These are disjoint categories and should never be compared.** `[src]`

**One unremarked finding worth capturing (§6):** the operator-plane and implant wire namespaces diverge on ~16 operations by name alone — `Invoke` prefixes and WireGuard word-order drift — which will silently defeat name-based correlation between gRPC methods and wire IDs.
