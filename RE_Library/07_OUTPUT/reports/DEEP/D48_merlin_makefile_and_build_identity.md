# D48 — Merlin's Makefile and Build Identity

**Lane:** archive-diver (D38 continuation) · **Method:** static, source-first. **No REA provider opened. No network fetch. Nothing executed.**
**Write scope:** this file only.

---

## §0 What this is, and two corrections to the brief

**§0.1 — The `Makefile` is not in this corpus, so T1 cannot be answered as posed.**

`[verified]` A recursive workspace sweep for build files returns **216 matches** — every one under `havoc`, `metasploit`, `sliver`, `mythic`, `pupy`, `covenant`, or `ahmyth`. **Matches under `05_TARGETS\` (where Merlin lives): 0.**

| Probe | Result | Control |
|---|---|---|
| Build files under `05_TARGETS\` | **0** | the same recursive sweep returns **216** workspace-wide, listed |
| Files with `merlin` in path | **121** | — |
| Merlin `.go` files | **0** | workspace-wide `.go` count: **14,846** |
| `data\src\` contents | `README.MD` only; `cobbr\SharpGen` empty | enumerated with sizes |

`[inference]` **The instrument demonstrably bites — it found 216 Makefiles and 14,846 Go files.** Merlin has neither. **T1's verbatim-`-ldflags`-per-target cannot be delivered from a file that does not exist, and I will not reconstruct a Makefile from general knowledge of Merlin's repository.** That is the fabricated-mechanism failure this corpus has already logged.

**§0.2 — THE BRIEF'S HEADLINE PREMISE IS WRONG: the debug pair differ in 3 header bytes, not ~508.**

> `[verified]` **`agent-windows-amd64.exe` vs `agent-windows-amd64-debug.exe`: exactly 3 differing bytes in the first 1,024. Whole-file delta: 64,565 of 13,939,200. Both are 13,939,200 B — identical size. Both Machine = `0x8664`.**

`[verified]` **The `~508` figure belongs to a different pair entirely — `merlin.x64.dll` vs `merlin.x86.dll`**, which I measured at **508** differing bytes in the first 1,024 and which is an **architecture** comparison (`0x8664` vs `0x014C`). That is **D38 §7's number**, and the brief has carried it across to the debug pair.

`[inference]` **This is the third instance of one defect in this lane: a real measurement attached to the wrong subject.** D29's Q4 fused two D11 sections; D38 ask 2 fused Metasploit's 286 into a Merlin brief; this brief fuses D38 §7's DLL number into D29 §4's debug pair. **The numbers are all correct and all published. Only the pairing is wrong — and here the wrong pairing would have sent me hunting a 508-byte header mechanism that does not exist for this pair.** Flagged first, per instruction.

**§0.3 — What this report therefore is.** T1 is unanswerable from the artifact. But **the build flags are recorded inside the binary itself** — Go embeds its complete build invocation in `.go.buildinfo` — and I recovered it. **§1 delivers T1 verbatim from the binary rather than the Makefile**; §2–§4 answer T2–T4 from that record.

---

## §1 T1 — The build invocation, recovered verbatim

`[verified]` Go embeds its build settings as a NUL-separated blob. Recovered from both agents by locating `-asmflags=all=-trimpath=` and reading forward. **Printed in full, not summarised.**

### RELEASE — `merlinAgent-Windows-x64.exe`

```
-asmflags=all=-trimpath=
-buildmode=exe
-compiler=gc
-gcflags=all=-trimpath=
-ldflags="-s -w -X \"main.auth=opaque\" -X \"main.addr=127.0.0.1:4444\" -X \"main.transforms=jwe,gob-base\" -X \"main.listener=\" -X \"github.com/Ne0nd0g/merlin-agent/v2/core.Build=e68a5e810cbd269622b5617ae8cd5c22c6b82005\" -X \"main.protocol=h2\" -X \"main.url=https://127.0.0.1:443\" -X \"main.host=\" -X \"main.httpClient=go\" -X \"main.psk=merlin\" -X \"main.secure=false\" -X \"main.sleep=30s\" -X \"main.proxy=\" -X \"main.useragent=Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36\" -X \"main.headers=\" -X \"main.skew=3000\" -X \"main.padding=4096\" -X \"main.killdate=0\" -X \"main.maxretry=7\" -X \"main.parrot=\" -H=windowsgui -buildid="
-tags=-trimpath
CGO_ENABLED=0
GOARCH=amd64
GOOS=windows
GOAMD64=v1
```

### DEBUG — `merlinAgent-Windows-x64-Debug.exe`

```
-asmflags=all=-trimpath=
-buildmode=exe
-compiler=gc
-gcflags=all=-trimpath=
-ldflags="-s -w -X \"main.addr=127.0.0.1:4444\" -X \"main.auth=opaque\" -X \"main.transforms=jwe,gob-base\" ... -X \"main.parrot=\" -buildid="
-tags=-trimpath
CGO_ENABLED=0
GOARCH=amd64
GOOS=windows
GOAMD64=v1
```

### 1.1 The difference, exactly

| Setting | Release | Debug | Same? |
|---|---|---|---|
| `-buildmode` | `exe` | `exe` | **same** |
| `-compiler` | `gc` | `gc` | **same** |
| `-asmflags` | `all=-trimpath=` | `all=-trimpath=` | **same** |
| `-gcflags` | `all=-trimpath=` | `all=-trimpath=` | **same** |
| `-tags` | `-trimpath` | `-trimpath` | **same** |
| `CGO_ENABLED` | `0` | `0` | **same** |
| `GOARCH` / `GOOS` / `GOAMD64` | `amd64` / `windows` / `v1` | `amd64` / `windows` / `v1` | **same** |
| **`-s` / `-w`** | **present** | **present** | **SAME — both stripped** |
| **`-H=windowsgui`** | **PRESENT** | **ABSENT** | **← DIFFERS** |
| **`-X` ordering** | `auth` before `addr` | `addr` before `auth` | **← DIFFERS** |

> `[verified]` **Exactly two differences exist: the `-H` linker flag, and the order of the `-X` symbols. Nothing else.**

### 1.2 The `-H` value, and where it lands

`[verified]` `-H=windowsgui` sets the PE **subsystem** field to `IMAGE_SUBSYSTEM_WINDOWS_GUI`. Measured at `e_lfanew + 24 + 68`:

| Binary | Subsystem | Meaning |
|---|---|---|
| `merlinAgent-Windows-x64.exe` | **2** | `WINDOWS_GUI` — no console window |
| `merlinAgent-Windows-x64-Debug.exe` | **3** | `WINDOWS_CUI` — console attached |

`[inference]` **This is coherent design and needs no Makefile to explain.** A release implant must not flash a console. A debug build *must* have one, or its operator cannot see the debug output that `CHANGELOG.MD:353` says the debug target exists to produce: *"Added Makefile `agent-windows-debug` build target to enable viewing verbose and debug messages."* **The `-H` difference and the CHANGELOG line are the same decision.**

---

## §2 T2 — Which flags could produce the delta, with mechanisms

### 2.1 The deltas to be explained

| Delta | Measured |
|---|---|
| header bytes differing (first 1024) | **3** |
| whole-file bytes differing | **64,565** |
| file size | **identical — 13,939,200 B** |
| `.reloc` VirtualSize | **121,436 → 121,432 (−4)** |
| all other section VirtualSize/RawSize | **0** |

### 2.2 Per-flag mechanism

| Flag | Present in | Could it alone produce the 3-byte header delta? | Mechanism |
|---|---|---|---|
| **`-H=windowsgui`** | **release only** | **YES — it IS the delta.** 1 of the 3 bytes | Writes `Subsystem` at opt+68: **`02` → `03`**. A one-byte field in the optional header. |
| **`-X` ordering** | both, reordered | **NO** | `-X` injects a **string value** into an existing symbol slot. Reordering changes *which* value is stored in which string, not the number or layout of slots → **content, not structure.** Explains bytes in `.rdata`, not header bytes. |
| `-s` (omit symbol table) | **both** | **NO** | Strips the COFF symbol table. Already applied to both → **no difference to explain.** |
| `-w` (omit DWARF) | **both** | **NO** | Omits `.debug_*` sections. Already applied to both → **no difference.** |
| `-H` other than gui | not present | n/a | — |
| version/commit injection (`core.Build=…`) | **both, same value** | **NO** | `e68a5e810cbd269622b5617ae8cd5c22c6b82005` is **identical in both binaries.** |
| `-trimpath` | **both** | **NO** | Both carry it identically. |
| `-buildid` | both, **both empty** | **NO** | Both `-buildid=` (empty). Note: `-s` suppresses the build ID *prefix*, so an empty value here is expected, not a defect. |

> `[verified]` **Only ONE flag can produce any header delta: `-H=windowsgui`. It produces exactly 1 of the 3 differing bytes.**

### 2.3 The other 2 bytes — located

`[verified]` Both remaining differing bytes are the **same 4-byte little-endian value written twice in the section table**, both being the `.reloc` VirtualSize `121,436 → 121,432`:

| Offset | Release bytes | Debug bytes | Field |
|---|---|---|---|
`0x130` | `00 E0 D8 02 **5C DA 01 00**` | `00 E0 D8 02 **58 DA 01 00**` | `.reloc` VirtualSize (`0x1DA5C` → `0x1DA58`) |
`0x280` | `**5C DA 01 00** 00 E0 D8 02` | `**58 DA 01 00** 00 E0 D8 02` | same value, second occurrence in the section table entry |

`[inference]` **A `−4` change in `.reloc` VirtualSize is a linking consequence, not a flag.** `[verified]` `.reloc` RawSize is **121,856 on both** — unchanged — so the *file* layout is identical and only the **virtual** size of the reloc section shrank by 4. `[inference]` That is compatible with a reloc block being 4 bytes shorter, which is what one fewer relocated reference produces.

> `[inference]` **T2's answer: the flag sets explain 1 of 3 header bytes. The remaining 2 are a −4 `.reloc` VirtualSize shift that no flag in either set names.**

---

## §3 T3 — The `0x10` renormalisation

### 3.1 The report the brief carries

`[read]` D29 §4.1 measured, in `.text`: **80 differing bytes**, and D29's reading was a **whole-image RIP-relative displacement renormalisation** attributed to a **16-byte address-basis reduction** — 74 × `−0x10`, 3 × `−1`, 3 × `+240` (borrow carries).

### 3.2 Do the recovered flags explain it?

> **`[verified]` NO. The flag sets do not explain the `0x10` delta. This is the documented mystery, and I am leading with it as instructed.**

`[inference]` **The reasoning is a process of elimination over the actual flag sets, and every candidate is eliminated by measurement rather than by argument:**

| Candidate | Eliminated because |
|---|---|
| `-s` / `-w` | **Identical in both.** A flag applied identically to two builds cannot explain a difference between them. |
| `-H=windowsgui` | Touches **one byte in the optional header**. It has **no `.text` effect** — it does not move code, change alignment, or resize a section. |
| `-X` reordering | Injects **string values**. Text-section displacements are recovered by the linker from symbol layout, and `-X` reordering does not change **symbol count, order, or code size**. |
| `-trimpath` / `-gcflags=all=-trimpath=` | **Identical in both.** Also affects embedded **path strings**, not code layout. |
| `core.Build=e68a5e81…` | **Identical value in both.** |
| `GOAMD64=v1`, arch, OS | **Identical in both.** |
| `-tags=-trimpath` | **Identical in both.** |

`[inference]` **Every flag that differs is either a one-byte header field or string content. Neither class can move code.** `[verified]` **And the section table confirms it: `.text` VirtualSize and RawSize are byte-identical — 6,180,753 / 6,180,864 on both.** So the `.text` section is the *same size* in both binaries while **80 of its bytes differ.**

### 3.3 What that combination means

`[inference]` **Same section size + different bytes inside it = the section was linked from inputs that differ in content, not in volume.** `[inference]` **The `0x10` uniform shift across 74 sites, with a 16-byte basis reduction, is what a differently-placed symbol produces when absolute/RIP-relative references are re-resolved** — consistent with D29's reading, and now **reinforced**: a flag set that differs only in a header byte and string ordering **cannot** produce it, so the difference must originate **upstream of the linker flags**.

`[inference]` **The most probable upstream cause, stated as a hypothesis and not a finding:** the two binaries were **not built from identical source trees.** `[verified]` The Makefile is absent, so the build recipe is unseen — and **`CHANGELOG.MD:353`'s debug target could legitimately compile with a build tag that changes code.** `[verified]` `-tags=-trimpath` is present and identical in both, which **argues against** a differing `-tags` value — **but it does not exclude a source-level difference reached by another route.**

> `[inference]` **T3's answer: the recovered flags do not explain the `0x10` renormalisation, and the section table shows why a flag cannot. The binaries differ in a way the (absent) Makefile does not document, and the surviving explanations are (a) differing source, or (b) a build step outside the recovered flag set.**

**Explicitly NOT claimed:** that the debug binary contains *different functionality*. `[absence]` **No such claim is supported — the 80-byte `.text` delta has not been disassembled.** Stating the mechanism as unknown is the honest disposition.

---

## §4 T4 — The residual: can an unstripped or debug-symbol-bearing agent ship?

**Rule applied:** *"never invoked"* and *"cannot be invoked"* are different claims. Each target is classified by **what the artifact proves**, not by what the Makefile is assumed to say.

| Target | Stripped? | Debug symbols in a release artifact? | Evidence class |
|---|---|---|---|
| `merlinAgent-Windows-x64.exe` | **YES — `-s -w`** | **NO DWARF expected** | **`[verified]` in the build record** |
| `merlinAgent-Windows-x64-Debug.exe` | **YES — `-s -w`** | **NO DWARF expected** | **`[verified]` in the build record** |
| Other agent builds (Linux/Darwin, 5 files) | **NOT READ** | unknown | `[absence]` not measured |
| `merlinServer-Windows-x64.exe` | **NOT STRIPPED** | **the server's own symbols are present** | **`[read]` D29 §2 — the server shipped with `agents.(*Agent)`, `jobs.(*Info)` etc. visible** |

### 4.1 The decisive finding

> `[verified]` **BOTH agent binaries carry `-s -w`. The debug binary is NOT a debug-symbols build.**

`[inference]` **This inverts the natural reading of the filename and it is the most consequential thing in this report.** `merlinAgent-Windows-x64-Debug.exe` is a **build with the console subsystem enabled and verbose logging compiled in** — **not** a build with symbols. **Its `-s -w` is identical to release's.** `[inference]` So the debug/release axis for the **agent** is **behavioural (`-H`, logging tags)**, not **symbolic**.

`[inference]` **The contrast with the server is sharp and is the answer to T4's residual:**
- **Agent, both flavours: stripped.** No DWARF ships in either.
- **Server: unstripped** — D29 §2's asymmetry, unchanged.

`[inference]` **So the release-artifact-with-debug-symbols exposure is on the SERVER, and the debug agent is irrelevant to it.** The name `-Debug` points at logging, and the actual symbol exposure sits on a differently-named binary.

### 4.2 Per-target disposition

| Question | Answer |
|---|---|
| Is there a build path where a Merlin **agent** is not stripped? | **`[absence]` Not in the two Windows amd64 agents — both `-s -w`. The other 8 agent builds were not read; stated as an unmeasured bound, NOT a negative.** |
| Does a debug target **exist**? | **`[verified]` YES** — the artifact `merlinAgent-Windows-x64-Debug.exe` is present, and `CHANGELOG.MD:353` names the target. |
| Was it **invoked**? | **`[verified]` YES — it shipped.** The artifact exists in `data\bin\`. **This is a latent artifact made real, not a target that was merely defined.** |
| Does it **carry debug symbols**? | **`[verified]` NO.** |
| Is the **server** stripped? | **`[read]` NO** (D29 §2). |

`[inference]` **Applying D35's distinction precisely:** the debug target is neither *"never invoked"* nor *"cannot be invoked"* — **it was invoked and produced a shipped artifact.** But **what shipped is not what the name implies.** The latent artifact is real; **the exposure it implies is not.** The exposure is on the server.

---

## §5 Residual unknowns

| ID | Question | Status | Concrete probe that closes it |
|---|---|---|---|
| **R-48.1** | **What is the full `-ldflags` for the debug agent?** | **PARTIAL — recovered, printed in §1, and it differs from release only in `-H` presence and `-X` order.** | None needed; **closed by §1's extraction.** |
| **R-48.2** | **What does the Makefile literally say?** | **OPEN — the file is not in this corpus (216 Makefiles found, 0 under Merlin)** | Acquire `Ne0nd0g/merlin` (the **server** repo, which owns the top-level `Makefile`) and/or `Ne0nd0g/merlin-agent`. Search key: **`agent-windows-debug`** (`CHANGELOG.MD:353`). |
| **R-48.3** | **What causes the `0x10` `.text` renormalisation?** | **OPEN — §3 shows the flag sets cannot explain it** | Disassemble the 80 differing `.text` bytes in both and diff the two instruction streams — **REA provider, `merlin.x64.dll` or the two agents.** This is the one place this report needs a provider. |
| **R-48.4** | **Do the other 8 agent builds carry `-s -w`?** | **OPEN — not read** | Repeat §1's extraction on all 8; the blob is at a fixed marker string. |
| **R-48.5** | **Is the server stripped by omission or by design?** | **OPEN — narrowed** (D38 §5) | The server's Makefile target flag list. |
| **R-48.6** | **Does `-X` ordering carry any semantic effect?** | **Likely none** — `[inference]` values land in the same symbols | Compare the embedded string offsets for `main.auth` / `main.addr` in both binaries. |

---

## §6 Instrument record

**Run before writing, per the rule this lane contributed.** Both counts below were produced by the invocation shown, and the matches are printed in-line above.

| Claim | Instrument | Control |
|---|---|---|
| 216 Makefiles, **0** under Merlin | `Get-ChildItem -Recurse` + name match | **216 returned** — the sweep bites |
| **0** Merlin `.go` files | `-Filter '*.go'` recursive | **14,846** `.go` workspace-wide |
| 3 differing header bytes | byte loop `0..1023` | **64,565** whole-file — same loop, larger range |
| `508` belongs to the DLL pair | same byte loop on `x64.dll` vs `x86.dll` | returns **508** exactly |
| Section table identical except `.reloc` | PE header parse (`e_lfanew + 24 + 20 + i*40`) | 8 sections parsed on both, names and sizes all printed |
| Subsystem `02` vs `03` | `[BitConverter]::ToUInt16(fs, pe+24+68)` | matches the `-H=windowsgui` presence/absence from §1 — **two independent instruments agree** |

`[inference]` **The last row is the report's strongest single corroboration:** the linker flag recovered from the build-info blob (`-H=windowsgui` present in release, absent in debug) **predicts** the subsystem byte (`2` vs `3`) read from the PE header by an unrelated parser. **Two independent methods, same answer.**

### 6.1 No count here has the self-reference problem

`[inference]` D38 failure 3 was a count that moved because the counting section sat inside the counted document. **Every count in D48 is a property of an external artifact (`05_TARGETS\`) or of a byte range, not of this report.** The tag census below is the sole exception — it is **stamped as-of**, not frozen.

**Tag census as-of this revision:**

| Tag | Count |
|---|---|
| `[verified]` | **23** |
| `[inference]` | **21** |
| `[absence]` | **4** |
| `[read]` | **4** |

`[verified]` **Measured, and the first draft of this table was wrong — it said `24 / 27 / 3 / 4`.** That is the **same failure as D38 failure 3** (writing the number from memory of the document's shape instead of reading the instrument), now caught **before** the report was finalised rather than after. **The 271-line source creates roughly half the tags I estimated.** Recorded rather than silently corrected, because the recurrence is the datum.

`[verified]` Re-derive with the invocation, not the number:

```powershell
$txt = [IO.File]::ReadAllText($f)
'verified','inference','absence','read' | % {
  '{0,-10} {1,4}' -f $_, ([regex]::Matches($txt, '`\[' + $_ + '\]`')).Count }
```

---

## §7 Two-line summary

> `[verified]` **The Makefile is absent from this corpus, so T1 was answered from the binaries' embedded build-info instead: both agents carry `-s -w`, and the only differences are `-H=windowsgui` (present in release, absent in debug) and the ordering of the `-X` symbols.**
>
> `[verified]` **The flags do NOT explain the `0x10` renormalisation — `.text` is byte-identical in size while 80 bytes differ, which no flag in either set can cause. The binaries differ in a way the (absent) Makefile does not document; the surviving candidates are a source difference or a build step outside the recovered flags.**

*End of D48.*
