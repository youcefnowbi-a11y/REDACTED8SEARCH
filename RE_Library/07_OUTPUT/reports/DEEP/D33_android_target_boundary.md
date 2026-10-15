# D33 — The Android target as it actually exists on disk

**Scope owner:** android-diver (task-42)
**Question:** the objective names **T3 (Android: AhMyth + AndroRAT)**. This report measures what is actually on disk, and what part of it any report has actually reversed.
**Method:** every count enumerated from the filesystem. No provider, no execution, no network.

---

## 1. The boundary, stated before the count

**Boundary rule:** T3 = the two trees under `RE_Library\01_SOURCE_mobile\`. Nothing else. `03_SAMPLES\`, `07_OUTPUT\`, and `02_BINARIES\` are **outside** T3 even where they contain Android-shaped files, and §7 states what they hold separately.

**Justified, not assumed.** `01_SOURCE_mobile` contains exactly two entries — `ahmyth` and `androrat` — and no third. A count inside that boundary is meaningful only against the objective's claim that T3 exists on disk, so §2 tests the boundary against the objective's own numbers rather than against itself.

## 2. T3 as measured

| Tree | Files | Bytes |
|---|---:|---:|
| `01_SOURCE_mobile\ahmyth` | **8,466** | 201,897,313 |
| `01_SOURCE_mobile\androrat` | **4,036** | 81,957,423 |
| **T3 total** | **12,502** | **283,854,736** |

[source: `Get-ChildItem -Recurse -File` + `Measure-Object Length -Sum`, per tree]

**Whole-tree extension census, descending:**

| Ext | ahmyth | androrat | T3 | What it is |
|---|---:|---:|---:|---|
| `.js` | 3,275 | 0 | **3,275** | AhMyth builder — **3,266 of them `node_modules`** |
| `.smali` | 411 | 2,479 | **2,890** | decompiled bytecode, both targets |
| `.json` | 1,463 | — | 1,463 | npm manifests / package data |
| `.md` | 748 | — | 748 | vendored package docs |
| `.kotlin_metadata` | 550 | — | 550 | Kotlin stdlib metadata |
| `.xml` | 26 | 344 | 370 | manifests + resources |
| `.java` | 14 | 21 | **35** | **the only human-written code in T3** |
| `.apk` | **0** | **1** | **1** | one compiled artifact |

**The single most important line in this table is the last one.** T3's human-written source is **35 files**. Everything else is a dependency closure, decompiled bytecode, or documentation.

## 3. THE ATTRIBUTION ERROR IN THE OBJECTIVE'S INDEX

**The objective's extension table lists `.java 81` under a corpus described as six C2 frameworks + T3 mobile. That 81 is not T3, and it is not shared with T3.**

`.java` corpus-wide, by tree, enumerated:

| Count | Tree | What it is |
|---:|---|---|
| **81** | `01_SOURCE_c2\metasploit` | **the entire 81** |
| **21** | `01_SOURCE_mobile\androrat` | T3 |
| **14** | `01_SOURCE_mobile\ahmyth` | T3 |
| 4,164 | `07_OUTPUT` | generated/extracted output, not a target |
| **4,280** | **corpus total** | |

**Result: the objective's `.java 81` is Metasploit — 81 of 81, unanimously.** T3 contributes **35**, and **neither 81 nor 35 appears in the objective's own table under its own name.**

**This is a distinct failure species from the ones D17 §1.0.1 records, and it is worth naming.** It is not a wrong count (§ the count is exactly right), not a wrong boundary (§ the boundary is one real tree), and not a wrong probe (§ it was measured by a working instrument on the right files). **It is a correct count of the wrong thing, filed under a heading that makes it read as something else.** The number 81 is true about Metasploit and false about T3, and the table's context supplies the false reading.

**Consequence for seventeen rounds:** any reader asking "how much Java is in the Android target" from the objective's table gets **81**, when the answer is **35**, and inherits a 2.3× overstatement plus a misattribution. **The T3 reports never contradicted it because they never counted the corpus-wide total — they counted their own tree**, which is the correct local move and is exactly why the error survived.

## 4. THE `.smali` CORRECTION — the lead's figure is low by 2,472

**The lead measured `.smali` as "2,890 corpus-wide, ALL of it in `01_SOURCE_mobile`." The second half of that is wrong, and the error is instructive because the first half is exactly right.**

| Count | Tree |
|---:|---|
| **2,890** | `01_SOURCE_mobile` — ahmyth 411 + androrat 2,479 |
| **2,472** | `07_OUTPUT` |
| **5,362** | **corpus total** |

[source: `Get-ChildItem -Recurse -File -Filter *.smali` corpus-wide, grouped by top-level tree]

**2,472 `.smali` files exist in `07_OUTPUT` — the output tree.** The lead's tree scoping excluded output, which is defensible for a *target* census, and the sentence "not one `.smali` file exists anywhere else in the corpus" is nonetheless false as written.

**The structural point the lead drew from it survives intact and sharpens.** `.smali` in `01_SOURCE_mobile` is **2,890 files of bytecode-to-source in a source tree** — T3 is still the only *target* whose code arrives as decompiled bytecode rather than as source or a native binary. **The claim needed a boundary, not a rewrite: "all `.smali` in the target corpus" is true; "all `.smali` in the corpus" is not.** This is the `07_OUTPUT` denominator appearing again — the same boundary that produced D3's own first defect.

## 5. The 3,275 `.js` — answered

**The lead asked why AhMyth carries 3,275 JavaScript files. Enumerated by immediate parent under `AhMyth-Server\app`:**

| Count | Location |
|---:|---|
| **3,266** | `node_modules` |
| **8** | `app\` (first-party) |
| **1** | `main.js` (Electron entry) |

**So 99.7% is a dependency closure and AhMyth's own JavaScript is 9 files.** It is an **Electron builder** — an npm-packaged desktop panel whose `main.js` is the entry point — and it ships a **pre-built payload template** (§6.1). **It is not a Node payload builder in the sense of generating payloads at runtime from JS logic; the JS is the panel UI and its dependencies.**

**This is the same shape as D3 §10.1's defect, at a different scale.** A naive `.js` count of 3,275 describes the npm closure; the first-party count is **9**. **Justify the boundary, not the count.**

## 6. THE SINGLE COMPILED ARTIFACT

### 6.1 AndroRAT ships TWO compiled artifacts, not one — a correction to my first pass

**My first pass claimed one Android binary in the corpus. That was wrong: the corpus holds TWO, and this is the corrected count.**

```
2,129,794 B   01_SOURCE_mobile\androrat\Android_Code\app\release\app-release.apk
2,366,154 B   01_SOURCE_mobile\androrat\Android_Code\app\release\app-release.aab
```

**How I got it wrong, because the failure mode is worth recording.** My `.aab` probe in this pass ran against **`ahmyth` only**, returned 0, and I generalised the zero to the corpus without re-running it against `androrat`. **A zero measured on one subtree is not a zero for the tree.** The corpus-wide control returns **1** `.aab`, and it is AndroRAT's. This is D33's own subject matter turned on D33: the count was produced correctly by a working instrument **on a boundary I had drawn too small.**

- Both sit in `Android_Code\app\release\` — **Gradle's own release output directory**, inside the source repo. These are **build products committed to the tree**, not downloaded specimens.
- So `01_SOURCE_mobile` holds **2 `.apk` + 1 `.aab`**, and the corpus holds **3 `.apk`** total: AndroRAT's, the **tool-pipeline test fixture** (`07_OUTPUT\...\testapk\...\HelloActivity.apk`, 5,266 B, not a target), and `androrat`'s.
- **`ahmyth` has zero `.apk`, zero `.dex`, zero `.aab`** (control: 3 `.jar` in each tree, so the filter distinguishes artifact types). **AhMyth ships no compiled artifact of any kind.**

**Both artifacts are SHA-256'd in T3's artifact table** (`T3_android_mobile.md:14-15`): APK `98037b11…`, AAB `2251774a…`.

**Why this matters:** the APK is the **only Android binary in the corpus that can be reversed as a flat-dex binary** — and D3 §9 used it, establishing that its embedded constants (`192.168.43.113` / `8000`, no `icon`) **diverge from the source's** (`192.168.0.105` / `8888` / `icon=true`). **That divergence is only discoverable from the compiled artifact**, which is why D3's rule "the compiled artifact's constants win over the source's" depends on this file. **The `.aab` is not covered by that finding** (§9, R-33.5).

### 6.2 The `.smali` provenance — decompiler output, proven

**The lead asked whether androrat's 2,479 `.smali` files are decompiler output or hand-written.**

- **All 2,479 are under a directory literally named `Compiled_apk`** — `androrat\Compiled_apk\smali\`. [source: directory enumeration]
- **First lines of the first file:** `.class`, `.super`, **`.source "INotificationSideChannel.java"`** — a `.source` directive carrying the **original Java filename**, which is emitted by a decompiler and never written by hand.
- **Sampled 200 files: 200 of 200 carry a `.source` directive; 109 carry `.line` directives.** [source: `Get-Content -TotalCount 60` per file, 200-file sample]

**Verdict: `apktool`/baksmali output, committed into the repo. Not hand-written.** This is covered as a **binary-derived** claim in D3 terms, not a source claim.

**And it is mostly not the RAT's code.** Top-level packages under `Compiled_apk\smali\`: `android`, `androidx`, `com`, `eu`, `kotlin`, `kotlinx`, `org` — **standard AndroidX and Kotlin support libraries.** The RAT's own classes are the `com\example\reverseshell2\` subset, matching the 19 first-party `.java` files.

### 6.3 The 6× difference between the two targets — explained

| | ahmyth | androrat |
|---|---:|---:|
| `.smali` | 411 | **2,479** |
| of which **first-party** | **26** | *see below* |
| of which **dependency closure** | **385** | rest |

**AhMyth's 411 break down as: `okhttp3` 193, `io.socket` 151, `okio` 41, `ahmyth` 26.** The 385-file `okhttp3` + `io.socket` closure is **exactly the "class 2" exclusion in D3 §10.1/§10.5 (344 files / 3,042,701 B)** — this report arrives at the same boundary from a different direction, which is an independent confirmation of that call.

**AhMyth's own 26 `.smali` are 19 distinct classes** (7 are `R$*` resource stubs), under `AhMyth-Server\app\app\Factory\Ahmyth\smali\ahmyth\mine\king\ahmyth\`.

**So the 6× difference is a dependency-versus-code difference, not a scope difference.** AhMyth's `.smali` is a **pre-built payload template shipped inside the Electron builder** (`Factory\Ahmyth\`) — small because the builder ships a minimal payload and generates the rest at build time. AndroRAT's `.smali` is a **full decompile of an AndroidX-using app**, so it carries the entire modern support-library closure. **Two Android RATs of comparable *capability* have 6× different *file* counts because one drags AndroidX and Kotlin stdlib and the other drags okhttp.**

## 7. `03_SAMPLES\` — populated but artifact-free

**"Empty" is the wrong word, and the correction is specific.** The directory holds **7 entries / 4 files**:

| File | Bytes |
|---|---:|
| `malware-traffic-analysis\README.md` | 214 |
| `MalwareBazaar\README.md` | 265 |
| `theZoo\README.md` | 216 |
| `theZoo\theZoo_families.csv` | 14,804 |

**It is a documented scaffold, not an oversight.** Each README states its own status in its own header and names its fetcher:
- `malware-traffic-analysis` — **"# malware-traffic-analysis.net — EMPTY"** / "Not scriptable. Curated blog, per-post download links." / "binaries: VM ONLY."
- `MalwareBazaar` — **"# MalwareBazaar — EMPTY"** / needs an abuse.ch Auth-Key / "API never returns raw files" / "Fetcher: `..\..\00_START\FETCH_SAMPLES.md`" / "VM ONLY."
- `theZoo` — **"# theZoo — index only"** / "789 malware families, text catalog." / "No samples downloaded."

**All three point to `00_START\FETCH_SAMPLES.md`, which exists.** [source: `Get-ChildItem 00_START` → `BINARY_SOURCES.md, FETCH_SAMPLES.md, INDEX.md, LANDSCAPE.md, MANIFEST.md`]

**Conclusion: `03_SAMPLES\` is a deliberately unpopulated acquisition scaffold with a documented fetch path and an explicit VM-only posture. It contains no binaries of any kind, Android or otherwise.**

**Positive control — the probe bites.** The same recursive probe that returns 0 Android artifacts in `03_SAMPLES` finds, corpus-wide: **2 `.apk`**, 21 `.jar`, 52 `.exe`, 159 `.dll`, 81 `.bin`, 13 `.so`. **The filter is capable of success and returns a true zero here.** [source: per-extension recursive counts, whole `RE_Library`]

## 8. IS T3 NOMINAL? — **NO, and the reason is not the one the framing assumed**

**The lead asked whether T3 is the fourth-species case: "the objective names it, a report covers it, and the artifact the report describes may not be in the corpus." T3 is not that case.** The artifacts are present:

| Question | Answer |
|---|---|
| Does T3 exist on disk? | **Yes — 12,502 files / 283,854,736 B** |
| Does T3 have source? | **Yes — 35 `.java` files, 19 AhMyth classes + 19 AndroRAT classes** |
| Does T3 have a binary? | **Yes — AndroRAT's 2,129,794 B `app-release.apk`** |
| Does T3 have bytecode? | **Yes — 2,890 `.smali`, both targets** |
| Is a report covering it? | **Yes — D3/T3, source-level, with the APK used for §9's constant divergence** |
| Is the artifact absent? | **No** |

**What IS true is narrower and worth stating exactly: T3 is the only target whose code reaches a reader as decompiled bytecode in a source tree, and the corpus holds one Android binary.** That is the opposite of nominal — **it is the corpus's only bytecode-shaped target**, and §4 explains why that matters for tooling.

## 9. D3's claims — source or binary?

**The lead asked whether D3's claims are about source or about binaries. Measured: D3 is a source-level report that DID use binary-derived evidence, with a dedicated tag for it — my first pass understated this and the correction is below.**

**Corrected measurement:**

| Fact | Value |
|---|---|
| Tags in `D3_android_code.md` | **94 `[source:]`** |
| `[apk-binary]` tag defined and used in **T3** | **YES — 12 occurrences**, scheme defined at `T3_android_mobile.md:5` |
| JADX used | **YES — D3 `:594-595`** are JADX-decompiled `config.java` values |
| APK opened via REA's Android providers | **NO — 0 uses of `inspect_android_package` / `decode_android_resources` / `search_android_classes` in D3** |

**So the accurate statement is: T3 is not a source-only report.** It carries a formal `[apk-binary]` tag, records SHA-256s for both compiled artifacts (`:14-15`), documents the pre-decoded smali tree as `apktool 2.4.1 output, developer-shipped` (`:16`), and reports the APK's manifest diverging from source at `:244` and `:296`. **The compiled artifacts were used as evidence.**

**What remains a real gap, stated narrowly:** the reversal is **tool-level, not provider-level**. It used **apktool + JADX directly** — not REA's Android providers, which appear in T3 only as a name in the evidence-tag legend at `:5`, never as an invocation. **The distinction matters because a direct apktool/JADX run leaves no provider-captured Evidence record**, which is the thing the corpus can audit.

**One claim in T3 now needs flagging as unverifiable from the tree:** `:309` presents `config.java` **"decompiled from the shipped compiled APK"** via JADX. **The input APK is present and its SHA-256 is recorded, but the JADX run itself is not reproducible from the corpus** — no output tree, no provider Evidence. **The claim is plausible and consistent with `:14`; it is not independently re-derivable here.** Marked, not disputed.

**And the `app-release.aab` (2,366,154 B) is analysed in T3's artifact table but its contents are not reported** — the AAB is SHA-256'd and then unmentioned. AAB is a different container from APK (it holds a bundletool-format module set, not a flat dex), so it is not the same evidence as the APK.

## 10. Instrument record — MCP, Frida, hypervisor

**Status recorded as asked. Nothing was run. No capability is claimed.**

**My first pass got this table wrong via a bad probe, and the correction is the more useful content.** I searched a narrow file set, saw 0, and wrote "grep across all `.md` returns 0 hits." **The real corpus-wide counts over 4,002 `.md` files are 6 / 1 / 12 / 38** — so the zero was my probe's boundary, not the corpus's contents. **Corrected table:**

| Item | Status | Basis |
|---|---|---|
| `inspect_android_package` | **NAMED, NEVER INVOKED** | 6 `.md` hits — **all** are the tag legend at `T3:5`, the lead's own D17:1052 note, and this report; **no invocation, no output** |
| `inspect_adb_client` | **NEVER INVOKED** | 1 hit — this report's own table row; **the only mention in the corpus is D33 counting it** |
| `decode_android_resources` / `search_android_classes` | **NEVER INVOKED** | 0 hits anywhere incl. T3 |
| JADX | **USED DIRECTLY, not through REA** | D3 `:594-595`; T3 uses it in a direct CLI pipeline |
| apktool | **USED DIRECTLY** | 38 hits; T3 `:16` documents `apktool 2.4.1 output` |
| Frida 17.9.1 | **installed, NEVER ATTACHED** | `T1_sliver_client.md:607` — *"The binary was never executed. Frida 17.9.1 is installed on this host"* |
| Hypervisor | **NEVER CHOSEN OR CONFIRMED** | 38 hits, none an environment record |

**The false-positive class this exposed, worth naming for future probes.** Of the 12 `frida` hits, **the large majority are the substring inside `blackfriday` / `Blackfriday`** — a Go Markdown library in a vendored `README.md`/`CHANGELOG.md`. **A case-insensitive substring probe for `frida` matches `blackfriday`.** The two real signal lines are `T1:607` and this report. **If I had reported "12 Frida hits" I would have been reporting a Markdown library twelve times** — which is the same defect as D17 §1.0.1 level 2, where 385 smali files were called vendored without asking where they lived.

**The honest framing of the tooling gap.** The lead's sharper claim is right and this report confirms the facts behind it: **`inspect_android_package` and the JADX family exist in REA specifically for the bytecode shape T3 presents, T3 is the only target presenting that shape, and the provider has never been pointed at it.** But **a tool that cannot be pointed at an artifact is not a coverage gap closeable this round** — no confirmed hypervisor, Frida never attached, no attached device.

**The one thing that would change the picture, checked statically:** an Android artifact *is* present to point at — **`androrat\...\app-release.apk` (2,129,794 B) and `app-release.aab` (2,366,154 B)**, both on disk. **So this is not an artifact-absence blocker; it is a provider/device-environment blocker.** The distinction matters because one of those is closable with a hypervisor and the other would not be.

## 11. Corrections recorded

**This report corrects two of the lead's figures and records two of the lead's own self-reported errors.**

| Claim | Status |
|---|---|
| "`03_SAMPLES\` is empty" | **Wrong — 7 entries / 4 files: three README stubs + `theZoo_families.csv` (14,804 B). Populated but artifact-free.** |
| "`.java 81` may include Android" | **Inverted — the 81 is Metasploit's entirely; T3 contributes 35.** |
| "`.smali` = 2,890, all in `01_SOURCE_mobile`" | **First half right; second half wrong — 2,472 more in `07_OUTPUT`, corpus total 5,362.** |
| Lead's `Join-String` probe fault (150 error lines, no data failure) | **Recorded as reported. Same class as the lanes' regex faults: instrument mis-shaped, error was the instrument's, not the data's.** |

**My own error in this pass, recorded for symmetry:** my first `.smali` grouping run returned `2479 Compiled_apk` as a *single* bucket because my path-splitting logic collapsed every file to the same key. **The number was right and the grouping was wrong.** I re-ran it by enumerating the `smali` root's child directories directly, which is where §6.3's package list comes from. **Same lesson as the lead's `Join-String`: a correct total produced by a mis-shaped instrument is still a number I had to re-derive before trusting.**

## 12. Residual unknowns

- **R-33.1** — Whether the APK/AAB decompile cleanly through a provider, and what they hold beyond §9's constants. **Unresolved: no hypervisor, no device, provider never proven.**
- **R-33.2** — AhMyth's `Factory\Ahmyth\smali` template (19 classes) vs the shipped source (`AhMyth-Client\app\src`, 14 `.java`): **which is authoritative, and do they differ?** Not compared here; it is a D3 question.
- **R-33.3** — The 2,472 `.smali` in `07_OUTPUT` are **unexamined**. Not a target, but not accounted for either.
- **R-33.4** — `theZoo_families.csv`'s 789 families were not read; whether it names Android families is unchecked.
- **R-33.5** — **`app-release.aab` (2,366,154 B) is SHA-256'd in T3 but its contents are never reported.** AAB is a different container from APK, so the APK's evidence does not cover it. Unexamined.

## 13. Summary — the three questions answered

1. **Why 3,275 `.js`?** An Electron builder panel: **3,266 `node_modules` + 9 first-party.** First-party count is 9, not 3,275.
2. **Which `.apk`, and is it a payload or a sample?** **Two artifacts, not one** — `androrat\Android_Code\app\release\app-release.apk` (**2,129,794 B**) and `app-release.aab` (**2,366,154 B**), both committed Gradle release builds, i.e. **built payloads**. AhMyth ships no compiled artifact at all.
3. **D3 — source or binary?** **Both, tagged.** 94 `[source:]` plus a formal **`[apk-binary]` tag used 12 times** and JADX-derived values at D3 `:594-595` — **but via direct apktool/JADX, never through REA's providers**, so no provider-captured Evidence record exists.

**T3 is not nominal. It is the corpus's only bytecode-shaped target, holding 12,502 files, 35 first-party `.java` files, and two committed Android binaries — and REA's Android provider, built for exactly that shape, has never been pointed at it.**

**The largest single thing this report established is negative.** The objective's `.java 81` is Metasploit's 81 in full, filed under a heading where it reads as the mobile/corpus total. **T3's real Java footprint is 35.** That error has been load-bearing for seventeen rounds because it is a *correct count of the wrong thing* — the one failure mode no probe and no denominator check catches, because both the number and the boundary it was measured on are individually sound.
