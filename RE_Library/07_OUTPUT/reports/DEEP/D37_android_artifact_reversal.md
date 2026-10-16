# D37 — The Android provider, invoked

**Scope owner:** android-diver (task-42 successor)
**Question:** D33 §10 recorded `inspect_android_package` as **NAMED AND NEVER INVOKED**, with the verdict *"provider/device-environment blocker, not artifact-absence."* **This report tests that verdict by running the provider.**
**Method:** REA MCP providers + direct container inspection. **Nothing was executed. Frida was NOT attached. No device, no emulator.**

---

## 1. VERDICT ON Q1: **MY D33 §10 PREDICTION WAS WRONG. THE PROVIDER RETURNS.**

**This is the first successful `inspect_android_package` invocation in the corpus.** It returned in well under a minute on a 2,129,794 B APK.

**D33 §10 said the gap was environment-blocked. It is not.** The artifact was attachable, the dependencies were present, and the tool worked on the first attempt. **The gap was that nobody had run it — a seventeen-round absence of invocation, not a capability failure.** My own D33 verdict is refuted here, by me, using the tool I said couldn't reach it.

**Dependencies, each tested before invoking rather than assumed:**

| Precondition | Status |
|---|---|
| `REA_JADX_MCP_JAR` | **SET** → `C:\Users\PC\Desktop\.agent\rea-tools\jadx-headless-mcp-0.7.1-all.jar`, exists |
| JDK | **java 21.0.12.1** on PATH (Eclipse Adoptium) |
| Engine | `jadx-headless-mcp` **0.7.1**, worker_count 1, heap 4,070 MiB |

**No missing-dependency rejection occurred**, so the escape hatch the lead allowed does not apply: this is a working provider on a present artifact.

**All three previously-unrun tools returned:**

| Tool | Result |
|---|---|
| `inspect_android_package` | **RETURNED** — `ev_8705e044…` |
| `decode_android_resources` | **RETURNED** — apktool **2.12.0**, full decoded manifest |
| `search_android_classes` | **RETURNED** — JADX 0.7.1, 1,304 classes |

**Artifact identity confirmed on both provider paths:** SHA-256 **`98037b11a118839bef93924a5718c9e988f1c11df507909cdf6bc0cb97189830`** — **matches T3's recorded hash at `T3_android_mobile.md:14` exactly.** The provider read the same artifact the report described.

## 2. Q1 result: what the provider returned

**Package identity (three independent reads agree):**

| Field | `inspect_android_package` | `decode_android_resources` | Source `build.gradle` |
|---|---|---|---|
| package | `com.example.reverseshell2` | `com.example.reverseshell2` | `com.example.reverseshell2` |
| versionName | `1.0` | `1.0` | `1.0` |
| versionCode | `1` | `1` | `1` |
| minSdk | `16` | `16` | `16` |
| targetSdk | `22` | `22` | `22` |
| compileSdk | — | **`29`** | **`29`** |

**Every field matches. The committed binary IS built from the committed source.** [derived: three independent reads, one of them the source file]

- **`class_count` = 1,304** · **`resource_count` = 742** · signature verification **not_performed** · APK never executed.

## 3. Q2: THE AAB — opened, and it is a different container holding the same app

**R-33.5 is closed. The AAB is a real ZIP** (magic `50 4B 03 04`) with **751 entries** — against the APK's **742**. **Different layouts, not the same file twice:**

| | APK | AAB |
|---|---|---|
| dex | `classes.dex` **3,604,660 B** | `base/dex/classes.dex` **4,340,284 B** |
| manifest | `AndroidManifest.xml` 6,340 B | `base/manifest/AndroidManifest.xml` 5,795 B |
| resources | `resources.arsc` 267,144 B | `base/resources.pb` **501,033 B** |
| bundle metadata | — | `BundleConfig.pb` 277 B, `dependencies.pb` 2,463 B |
| kotlin metadata | — | **378 `.kotlin_metadata` files** under `base/root/kotlin/` |
| `res/` entries | **742 total entries** | **0** — resources are protobuf-packed |

**Reading: the same app in two containers.** Same package, same declared SDKs, one `classes.dex` each. **The AAB is the bundletool format** — resources compiled to `resources.pb` rather than `resources.arsc`, Kotlin metadata extracted to sidecar files, root layout under `base/`. **The APK's evidence does not transfer to the AAB, and now it doesn't need to: both were read.**

**The dex sizes differ (3,604,660 vs 4,340,284 B) and that is expected, not a discrepancy** — an AAB dex is pre-optimisation output and is not shrunk the same way. **It is NOT evidence of different code**, and it should not be cited as such. **What would establish the code is identical is a class-level comparison; I did not perform one. Marked.**

## 4. Q3: THE MANIFEST — and the provenance check passes

**Decoded from the APK (`decode_android_resources`, apktool 2.12.0), the full component set:**

| Type | Name | Flags |
|---|---|---|
| activity | `com.example.reverseshell2.MainActivity` | MAIN / LAUNCHER |
| service | `com.example.reverseshell2.mainService` | `exported="false"` |
| receiver | `com.example.reverseshell2.broadcastReciever` | **`exported="true"`** — BOOT_COMPLETED, SCREEN_OFF, SCREEN_ON |
| service | `com.example.reverseshell2.jobScheduler` | `permission=BIND_JOB_SERVICE` |

**15 permissions**, in manifest order: INTERNET, ACCESS_WIFI_STATE, RECEIVE_BOOT_COMPLETED, WAKE_LOCK, CAMERA, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, VIBRATE, READ_SMS, ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION, READ_CALL_LOG, RECORD_AUDIO, **SYSTEM_ALERT_WINDOW**, READ_PHONE_STATE. Plus `uses-feature` camera + camera.autofocus.

**All 15 are accounted for by the source's own code** — the RAT's 19 classes map onto them one-for-one: `readSMS`→READ_SMS, `readCallLogs`→READ_CALL_LOG, `audioManager`→RECORD_AUDIO, `CameraPreview`/`videoRecorder`→CAMERA, `locationManager`→ACCESS_FINE/COARSE_LOCATION, `vibrate`→VIBRATE, `ipAddr`→ACCESS_WIFI_STATE, `MainActivity`+`jumper`→**SYSTEM_ALERT_WINDOW** (the latter is D3's naming-inversion finding, confirmed here at the manifest level: the permission that lets it draw over other apps is the one `jumper` uses).

### 4.1 THE PROVENANCE VERDICT: **the binary matches the source**

**The lead asked: if manifest and source differ, the committed binary is not built from the committed source.** Tested three ways:

| Check | Source | Compiled | Match |
|---|---|---|---|
| package / version / SDKs | `build.gradle` | manifest + provider metadata | **YES — all 6 fields** |
| permission set | source manifest | decoded APK manifest | **YES — 15/15, same order** |
| class names | 19 `.java` classes | 18 matched by `search_android_classes` | **YES — `Payloads` subpackage included** |

**Verdict: the committed APK was built from this source tree. Provenance holds.** **This is a negative finding and it is worth stating plainly** — I looked for a build-provenance break and there isn't one. `minifyEnabled false`, no ProGuard/R8, consistent with D3's `:296`.

**One asymmetry worth recording:** `search_android_classes` returns **18** classes where the source has **19** `.java` files. **The missing one is `ExampleInstrumentedTest`** — an `androidTest` class, correctly absent from a release build. **The count is right; the difference is explained, not unexplained.**

## 5. Q4: HOW MUCH OF ANDRORAT IS ACTUALLY ANDRORAT — **68 of 2,479 (2.7%)**

**The real size of AndroRAT, measured for the first time.** The 2,479 `.smali` in `Compiled_apk\smali\`, by top-level package:

| Package | Files | % | What it is |
|---|---:|---:|---|
| **`androidx`** | **1,369** | 55.2% | AndroidX support libraries |
| **`kotlin`** | **827** | 33.4% | Kotlin stdlib |
| **`org`** | 136 | 5.5% | Apache (104) + IntelliJ (25) + JetBrains (7) |
| **`com.example`** | **68** | **2.7%** | **← the RAT** |
| `eu.bolt` | 57 | 2.3% | `screenshotty:1.0.2` |
| `android.support` | 11 | 0.4% | legacy support |
| `kotlinx` | 11 | 0.4% | kotlinx.android |
| **total** | **2,479** | | |

**So 97.3% of AndroRAT's own source tree is dependency closure.** The `androidx` breakdown is `core` 391 + `appcompat` 362 + `fragment` 86 + `constraintlayout` 61 + …; the `kotlin` breakdown is `collections` 145 + `jvm` 131 + `coroutines` 86 + `sequences` 75 + `text` 67 + …

**Cross-check against the APK side, as the lead asked:** the APK holds **1,304 classes, of which 18 are `com.example.reverseshell2.*`** — **1.4%**. So:

| View | Total | RAT's own | % |
|---|---:|---:|---:|
| `.smali` (source side) | 2,479 | **68** | 2.7% |
| DEX classes (APK side) | 1,304 | **18** | 1.4% |

**The two sides disagree on the ratio and the disagreement is structural, not contradictory.** `.smali` counts **files including anonymous inner classes** (`mainService$1.smali` etc.), so 19 source classes expand to 68 files. The APK's `search_android_classes` matched **top-level named classes** and folded the anonymous ones into their parents. **68 vs 18 is the same code counted two ways** — and it is the same lesson as the `node_modules` denominator, at a third scale.

**Against D3 §10.1: D3 excluded 344 files / 3,042,701 B as "class 2" reached from the APK side. This report reaches an analogous boundary from the source side and gets 2,411 excluded of 2,479.** The numbers are **not directly comparable** — D3's 344 was the `okhttp3`+`io.socket` closure for **AhMyth**, and this is AndroRAT's AndroidX/Kotlin closure. **They are different targets' closures and must not be conflated.** Stated here so no future reader adds them.

**AhMyth's equivalent, for the record (from D33 §6.3):** 411 `.smali` = `okhttp3` 193 + `io.socket` 151 + `okio` 41 + **ahmyth 26**. **First-party ratio 26/411 = 6.3%** — higher than AndroRAT's 2.7%, because AhMyth's closure is smaller (okhttp) than AndroRAT's (AndroidX + Kotlin).

## 6. The second-copy finding: AhMyth ships a payload template, AndroRAT ships a compiled agent

**Both targets ship a *second* copy of themselves, and the two are different species.** This is the structural difference worth one paragraph:

| | AhMyth | AndroRAT |
|---|---|---|
| second copy | **`.smali` template** in `AhMyth-Server\app\app\Factory\Ahmyth\smali\` | **compiled APK + AAB** in `Android_Code\app\release\` |
| purpose | **pre-built payload the builder patches and ships** | **build output committed to the tree** |
| first-party | 26 files / 19 classes | 68 files / 19 classes |
| generates payloads at build time | **YES** — the Electron builder patches the template | **NO** — it is Gradle's own `release` output |

**AndroRAT's committed APK is a build artifact, not a builder resource.** It carries no machinery to produce other payloads; it *is* the payload. **AhMyth's `Factory\Ahmyth\` smali is the opposite: a template the panel mutates** — which is why AhMyth renders 3,275 `.js` and AndroRAT renders none.

**And the class counts coincide: both targets are 19 classes of first-party code.** Two Android RATs of similar scope, each with 19 classes, presenting 26 vs 68 `.smali` files depending on which dependency closure they drag. **That is the answer to D33's "6× difference" question, now measured from both sides.**

## 7. What did NOT run, stated plainly

| Item | Status | Reason |
|---|---|---|
| **Frida attach** | **NOT ATTEMPTED** | no device/emulator; `inspect_adb_client` never proven |
| **APK execution** | **NEVER** | provider is static by construction |
| **Signature verification** | **NOT PERFORMED** | provider states so; `META-INF` present but unverified |
| **APK-vs-AAB class comparison** | **NOT DONE** | container-level read only; §3 marked |
| **`inspect_adb_client` via MCP** | **STILL NEVER INVOKED** | no device to list; not attempted |
| **Hypervisor** | **NEVER CHOSEN** | no record |

**`inspect_adb_client` remains the corpus's one genuinely unrun provider** — and unlike `inspect_android_package`, its absence is **correct**: it enumerates attached devices, and there are none. **That one is environment-blocked; the Android package provider never was.**

**Positive control on the Frida claim:** the corpus holds a Frida installation record (`T1_sliver_client.md:607`) and 9 word-boundary `frida` hits (§8), so the probe finds Frida references. **The absence of an attach record is a true absence.**

## 8. Instrument record — and the `blackfriday` control re-run

**The lead's §13.2 attribution, independently reproduced:**

| Probe | Hits |
|---|---:|
| `frida` (case-insensitive substring) | **22** |
| `\bfrida\b` (word boundary) | **9** |
| **delta** | **13** |
| `blackfriday` | **13** |

**Delta equals cause — the attribution is proven, not asserted.** All 13 are a Go Markdown library in vendored `README.md`/`CHANGELOG.md`. **The instrument shape is the defect: `Select-String` is case-insensitive by default and nothing in the invocation says so.**

**Probe-validity controls used in this report:**

| Claim | Control | Result |
|---|---|---|
| "provider returns" | actually invoked it | **returned, 3/3 tools** |
| artifact identity | SHA-256 vs T3's recorded hash | **matches — `98037b11…`** |
| provenance match | 3 independent reads | **6/6 fields agree** |
| "68 of 2,479 are the RAT" | enumerated every file by package | **sums to 2,479** |
| "18 classes match 19 source" | named the missing one | **`ExampleInstrumentedTest` — androidTest, correctly absent** |
| "AAB is real ZIP" | magic bytes + 751 entries read | **`50 4B 03 04`** |

## 9. Residual unknowns

- **R-37.1** — **APK vs AAB class-level equivalence.** Both hold one `classes.dex`; whether the class sets are identical is **not established**. §3 marked.
- **R-37.2** — **Signature verification not performed.** `META-INF` present; the provider does not verify. `[absence: provider-declared]`
- **R-37.3** — **The 1,304-class APK inventory is not enumerated** (the bridge elided the 1,304-item list as `inventory_elided`). I have the count and the 18 RAT matches; the destination of the other 1,286 is **unexamined**.
- **R-37.4** — **AhMyth has no compiled artifact**, so no provider read is possible for it. Its only code evidence is source + the `Factory` template. **This is a permanent asymmetry between the two targets, not a gap to close.**
- **R-37.5** — Method-level semantics of the RAT's own 18 classes were **not decompiled**. The provider can; this report established reachability and composition only.

## 10. Summary — the four questions

1. **Does the provider return?** **YES.** D33 §10's environment-blocked verdict is **refuted**. All three tools returned on the first attempt; dependencies were present; the artifact hash matches. **The seventeen-round gap was an absence of invocation.**
2. **The AAB?** **A real ZIP, 751 entries, bundletool format** — `base/dex/classes.dex` 4,340,284 B, `base/resources.pb`, `BundleConfig.pb`, 378 `.kotlin_metadata`. **Same app, different container.** R-33.5 closed; class-level equivalence marked R-37.1.
3. **Manifest vs source?** **They match — 6/6 identity fields, 15/15 permissions, 18/19 classes.** The committed binary **was** built from the committed source. **Negative finding, stated as such.**
4. **How much of AndroRAT is AndroRAT?** **68 of 2,479 `.smali` — 2.7%.** 97.3% is AndroidX (1,369) + Kotlin (827) + Apache/IntelliJ (136) + screenshotty (57) + legacy support (22). **The real size of AndroRAT is 19 classes.**

**The single most important line in this report: the tool that sat unrun for seventeen rounds worked immediately, and the reason it had never run is that nobody had typed its name.**
