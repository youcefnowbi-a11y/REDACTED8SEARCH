# D49 — The mobile boundary, and the two extraction models

**Scope owner:** android-diver
**Question:** what is the real size of the mobile target, how do the two targets differ architecturally, and are D37's residuals closable?
**Method:** enumerated filesystem measurement + first-party source reading. **REA providers were not required and were not invoked.** No execution, no network.

---

## §0 — What this is, and a correction to the brief

**The brief's own numbers are inconsistent and the brief does not flag it.** It gives `12,445 files / 190.4 MB` and `12,502 / 283,854,736 B` in the same paragraph, both attributed to D33. **Q2 resolves that (§2).** The short version: **both are correct measurements of different sets, and the difference is `.git`.**

**One correction to the brief's framing.** The brief says *"D33 gave 12,445 files / 190.4 MB."* D33 gave **12,502 / 283,854,736 B** as its headline **and** recorded 12,445 as the lead's figure. **The lead's figure was the one without `.git`.** I state this because Q2 asks which was "counting" what, and the honest answer is that the smaller number is the *cleaner* one — it excludes version-control internals — while the larger is the *complete* one. **Neither is an error. The error would be using either without its boundary.**

---

## §1 — Q1: AhMyth's dependency-vs-first-party ratio

**Invocation:**
```powershell
$a = Get-ChildItem "$M\ahmyth" -Recurse -File -Force |
     Where-Object { $_.FullName -notmatch '\\\.git\\' }
$nm = $a | Where-Object { $_.FullName -match '\\node_modules\\' }
```
**`-Recurse` + `-Force`, `.git` excluded — the brief's own warnings about `-Filter` arrays and `-Path` globs apply and are avoided here.**

### Result

| Measure | Files | Bytes | % files |
|---|---:|---:|---:|
| **AhMyth total (excl `.git`)** | **8,437** | 145,317,855 | 100% |
| `node_modules` | **7,911** | 124,076,770 | **93.8%** |
| **Non-dependency** | **526** | 21,241,085 | **6.2%** |

**AhMyth is 93.8% npm dependency closure.** The non-dependency 526 break down as `AhMyth-Server/app` **469** files, `AhMyth-Client/app` **30**, and ~27 loose config/readme files.

### The comparison the brief asked for

| | AndroRAT (D37) | **AhMyth (this report)** |
|---|---:|---:|
| total first-party-adjacent | 2,479 `.smali` | 8,437 files |
| dependency | 2,411 (97.3%) | 7,911 (93.8%) |
| **first-party** | **68 (2.7%)** | **526 (6.2%)** |
| **the RAT itself** | **19 classes** | **19 classes** |

**The two projects are the same size where it matters and wildly different everywhere else.** Both are **19 classes of agent**. AndroRAT's bloat is a **build closure** (AndroidX + Kotlin, pulled by Gradle). AhMyth's bloat is a **package manager closure** (less, semantic-ui, caniuse-db, inquirer, gulp-*, jquery).

### What the ratio implies about development models

**They are not two implementations of one design; they are two different kinds of artifact.**

- **AndroRAT is an Android app whose author used modern libraries.** Its dependency surface is whatever `build.gradle` resolves — `androidx.appcompat`, `constraintlayout`, `kotlin-stdlib`. **The bloat arrives because the app is written the ordinary way and the ordinary way is heavy.** Its first-party code is 19 classes because **the agent is simple relative to the platform it must live on.**
- **AhMyth is a *product* — an Electron desktop panel with a GUI, a victim list, and a build pipeline — and someone else's code dominates it.** `AhMyth-Server/app` is 8,380 files against `AhMyth-Client`'s **41**. **The panel is 200× the implant it delivers.** That is a distribution-platform development model: build the operator tooling, ship the payload at the end.

**The sharpest single number: AhMyth's entire implant source is 41 files / 62,484 B.** Everything else in an 8,437-file repository exists to let an operator build, configure, and drive it. **The ratio is not a code-quality signal — it is a statement about which half of the system the project invested in.**

---

## §2 — Q2: reconciling 12,445 and 12,502

**They differ by 57 files and 84,210,049 bytes, and the difference is exactly `.git`.**

**Invocation:**
```powershell
$M = "$R\01_SOURCE_mobile"
$a = Get-ChildItem $M -Recurse -File            # 12,445 files / 199,644,687 B
$b = Get-ChildItem $M -Recurse -File -Force     # 12,502 files / 283,854,736 B
```

| Boundary | Files | Bytes | MiB |
|---|---:|---:|---:|
| **Without `.git`** (no `-Force`) | **12,445** | **199,644,687** | **190.4** |
| **With `.git`** (`-Force`) | **12,502** | **283,854,736** | **270.7** |
| **delta** | **57** | **84,210,049** | 80.3 |

**Attribution, verified by enumerating the delta rather than assuming it:**
```
\ahmyth\.git    : 29 files / 56,579,458 B
\androrat\.git  : 28 files / 27,630,591 B
                 total 84,210,049 B  == the entire discrepancy
```

**So: neither number is wrong. They are two boundaries.** `12,445 / 190.4 MiB` is the **working tree**; `12,502 / 270.7 MiB` is the **working tree plus version-control object store**. `Get-ChildItem` without `-Force` silently omits dotfiles, and `.git` is a dotfile — **which is precisely instrument-shape defect territory: the omission is invisible in the invocation.**

**One unit note, since the brief renders 190.4 as "MB":** 199,644,687 B is **190.4 MiB** but **199.6 MB**. `Measure-Object -Sum` returns bytes; a 190.4 label on a byte count is a MiB reading. **Small, but this corpus has a standing rule that a number without its unit and its invocation is not a measurement.**

**The number to use, stated with its boundary:** *the mobile corpus is 12,445 files / 190.4 MiB of working tree, or 12,502 / 270.7 MiB including git internals.* **For every coverage claim in this report I use the working-tree boundary (12,445), because version-control object files are not target content.**

### Per-tree, at both boundaries

| Tree | Working tree | With `.git` | `.git` bytes |
|---|---:|---:|---:|
| `ahmyth` | **8,437** / 145,317,855 B | 8,466 / 201,897,313 B | 56,579,458 |
| `androrat` | **4,008** / 54,326,832 B | 4,036 / 81,957,423 B | 27,630,591 |
| **total** | **12,445** / 199,644,687 B | **12,502** / 283,854,736 B | 84,210,049 |

---

## §3 — Q3: D37's residuals

### R-37.1 — APK vs AAB class-level equivalence. **NOT CLOSED — and now better characterised.**

Both hold exactly one `classes.dex` (APK 3,604,660 B; AAB 4,340,284 B). **I did not compare class sets, and I state why rather than leaving it vague:** the AAB's dex is **not directly comparable** — an AAB is pre-optimisation bundletool output, so size difference is expected and is *not* evidence of different code. **Establishing equivalence requires running JADX against the AAB's extracted `base/dex/classes.dex`.** That is a concrete, bounded probe and I did not run it this round. **Probe: extract `base/dex/classes.dex` from the AAB, invoke `inspect_android_package` or JADX on it, compare the class list to the APK's 1,304.**

### R-37.2 — Signatures unverified. **NOT CLOSED. Correctly so.**

The provider declares `signature_verification: not_performed`. **`META-INF` is present in the APK** (72 hits for the string) and the template's `original/` holds a `CERT.RSA`. **Verification is `apksigner`/`jarsigner` work, not provider work**, and neither is confirmed present. **Probe: `apksigner verify --print-certs app-release.apk` if an SDK build-tools is present; else state as environment-absent.** `[absence: provider-declared + tooling-unconfirmed]`

### R-37.3 — The other 1,286 APK classes unenumerated. **NOT CLOSED — but the reason is now known.**

The JADX bridge returned `inventory_elided: true` for the 1,304-item list at `limit: 4096`. **The count is trustworthy; the enumeration was elided by the bridge, not by me.** I confirmed the 18 first-party classes via a *filtered* query (`"reverseshell2"`), which returned matches — **so the instrument works and the elision is a delivery limit.** **Probe: re-query `search_android_classes` with per-package filters (`androidx`, `kotlin`, `io.socket`) to enumerate in bounded slices.** Not attempted: beyond D49's scope and the brief said providers only if genuinely required.

### R-37.5 — The RAT's 18 classes not decompiled. **NOT CLOSED. Unchanged.**

Method-level decompilation of `com.example.reverseshell2.*` remains unperformed. **Probe: `inspect_android_method` per class, or `inspect_analysis_view` kind android on the retained parent evidence.** The parent evidence (`ev_8705e044…`) is retained and reusable without re-running the provider.

**Summary: none of the four is closable by a pure source/artifact pass, and each now carries a named probe rather than a vague "unresolved."**

---

## §4 — Q4: the template-vs-compiled axis

### 4.1 What the builder actually is

**Located:** `AhMyth-Server\app\app\Factory\Ahmyth\` — containing `smali/`, `res/`, `original/`, `AndroidManifest.xml`, `apktool.yml`.

**What patches it:** `AhMyth-Server\app\app\assets\js\controllers\AppCtrl.js` (421 lines), driven by `Constants.js`. **The pipeline is four shell-outs to bundled JARs:**

```
L338  java -jar apktool.jar  d  <victim.apk> -f -o <apkFolder>   # decompile
L313  data.replace(data.substring(data.indexOf("http://"),
                                  data.indexOf("?model=")), "http://" + ip + ":" + port)
L163  fs.copy(Factory/Ahmyth/smali → <apkFolder>/smali)          # inject agent
L129  java -jar apktool.jar  b  <apkFolder> -o Ahmyth.apk        # rebuild
L137  java -jar sign.jar <Ahmyth.apk>                            # sign
```

**The patch is a single string substitution.** `IOSocket.smali` ships with the developer's own LAN address:
```
L79: const-string v4, "http://192.168.8.100:42474?model="
```
**The operator's IP:port is spliced in by substring replacement between `http://` and `?model=`. There is no validation that either marker exists.** `indexOf` returns `-1` if absent, and `substring(0, -1)` returns `""` — **so a template lacking either marker yields `"http://" + ip + ":" + port` concatenated onto a string starting at -1**, silently. **[read]** This is a latent defect: the failure mode is a malformed URL, not an error.

### 4.2 What each model lets an operator do

| | **AhMyth (template)** | **AndroRAT (compiled)** |
|---|---|---|
| **produces** | a *new* APK binding the agent into **any third-party app** | itself, unchanged |
| **operator sets** | IP:port, bind method, target app | nothing post-build |
| **camouflage** | **YES** — the payload wears the victim app's identity | none |
| **on-disk residue** | **the template + every target app decompiled** | one release APK + AAB |
| **requires** | Java + bundled `apktool.jar` + `sign.jar` | nothing |
| **fails when** | markers absent; target uses non-standard launcher | n/a |

**AhMyth's model gives an operator something AndroRAT's cannot: disguise.** The agent is injected into a legitimate app so the installed package is the *original app's* package name, icon, and launcher activity — while `MainService` runs underneath. **`BindOnBoot` appends the service and receiver to the victim's manifest and copies 17 permissions in; `BindOnLauncher` additionally injects a `startService` call into the victim's launcher `onCreate`.** (`AppCtrl.js:199`, `:231`.)

**AndroRAT's model gives an operator something AhMyth's cannot: reproducibility.** A committed `app-release.apk` is a fixed artifact — its constants are knowable, its hash is stable, and it can be analysed once. **That is exactly why D37 could verify its provenance 6/6 fields.** **A template-patched APK cannot be pre-analysed at all**, because its defining content does not exist until an operator supplies an IP.

### 4.3 Does the patched output differ beyond the intended change? **YES — in four ways.**

This is the half the brief flagged as interesting, and the answer is affirmative.

**(a) The template is a STALE BUILD and the shipped manifest does not match the shipped source.**
```
AhMyth-Client\app\build.gradle :  minSdkVersion 11   targetSdkVersion 24   compileSdkVersion 24
Factory\Ahmyth\apktool.yml     :  minSdkVersion 10   targetSdkVersion 18   apkFileName: app.apk
```
**The template descends from a build that is not the client in this repository** — different SDK floors, and `apktool.yml` names its origin `app.apk`, not the client's artifact. **Whichever agent code the builder actually injects is 6 SDK levels below what the source declares.** An operator patching a modern app injects an agent declaring `targetSdk 18`; on Android 9+ that agent runs in a legacy compatibility path. **Provenance finding: source and shipped template are two different builds of "the same" project.**

**(b) `copyPermissions` matches on SUBSTRING, so a declared permission is skipped if any OTHER permission's text contains it.**
`AppCtrl.js:184` tests `firstPart.indexOf(permissionName) == -1`. `permissionName` is extracted as the *name value* only — e.g. `android.permission.CAMERA`. **`android.permission.CAMERA` is a substring of nothing problematic, but `...READ_EXTERNAL_STORAGE` cannot collide — however the check is against the whole manifest head, not a permission list.** The practical consequence: **a victim app declaring `WRITE_EXTERNAL_STORAGE` causes `READ_EXTERNAL_STORAGE`'s addition to be tested as present only if that exact string appears.** This is a fragile test, **[read] and I flag it as fragile rather than claiming a specific observed collision** — I did not construct a case.

**(c) The injected components are added UNCONDITIONALLY and duplicate on re-runs.**
`AppCtrl.js:210` splices `ahmythService + ahmythReciver` before `</application>` **without checking whether they are already present.** The template's **own** `AndroidManifest.xml` already contains `MainService` and `MyReceiver` (L27-28). **The builder does not patch the template's manifest — it patches the *victim's* — so the template manifest is dead weight pointing at the same namespace.** But **running the builder twice against the same decompiled folder yields duplicated `<service>`/`<receiver>` entries.** apktool will emit both. **[read]**

**(d) The agent is copied OVER the target's smali, and namespace collisions are not checked.**
`L163` `fs.copy(Factory/Ahmyth/smali → apkFolder/smali)` merges trees. **The agent's namespace is `ahmyth.mine.king.ahmyth`; `okhttp3`, `okio`, and `io.socket` are also copied.** A victim app already containing **`okhttp3`** or **`io.socket`** would have those trees overwritten. **This is not hypothetical housekeeping: `io.socket` and `okhttp3` are among the most common Android libraries in existence.** An operator binding into such an app silently replaces the host app's HTTP/socket stack with the template's older version. **[read, inferred consequence]**

### 4.4 AndroRAT's residue, for contrast

**AndroRAT leaves exactly two artifacts and no template:** `app-release.apk` (2,129,794 B) and `app-release.aab` (2,366,154 B), both in Gradle's `app\release\`. **Plus `Compiled_apk\` — 2,479 `.smali` that are apktool output committed into the tree**, which D33 established (200/200 carrying `.source`). **So AndroRAT's repository also contains a decompilation, of itself, checked in.** Neither project treats its build products as disposable.

---

## §5 — Residual unknowns

| ID | Unknown | Concrete probe |
|---|---|---|
| **R-49.1** | APK/AAB class equivalence (was R-37.1) | extract `base/dex/classes.dex`, run JADX, diff class list vs 1,304 |
| **R-49.2** | Signature verification (was R-37.2) | `apksigner verify --print-certs`; else record SDK absent |
| **R-49.3** | The other 1,286 APK classes (was R-37.3) | `search_android_classes` with per-package filters |
| **R-49.4** | RAT method semantics (was R-37.5) | `inspect_android_method` on retained `ev_8705e044…` |
| **R-49.5** | **Whether the template's smali equals a build of `AhMyth-Client` in-tree** — §4.3(a) shows the SDK floors differ, so **they are not the same build**; whether the *class bodies* differ is unmeasured | diff `Factory\Ahmyth\smali\ahmyth\mine\king\ahmyth\*` against the client's 14 `.java`; the smali is 19 classes + 8 `R$*` vs 14 `.java` — **the counts already disagree and I did not reconcile them** |
| **R-49.6** | Whether AhMyth's `Factory` closure is complete enough to build without network | it needs `apktool.jar` + `sign.jar`; **present in `Factory\`** — but neither was executed, and no build was attempted |

**None of these blocks the report's findings.** Each is a bounded invocation away.

---

## §6 — What the two models say together

**Both projects are 19 classes of agent. Neither is 8,000 files of agent.** AndroRAT's 8.5%-of-tree figure and AhMyth's 6.2% are the same story told by two different package managers: **the Android RAT is small, and the apparatus around it is large.**

**And the apparatus is the part with the defects.** Every live issue in this report — the unguarded substring patch, the unconditional manifest splice, the stale SDK floors, the blind `fs.copy` over `okhttp3` — **lives in the builder, not the implant.** The 19 classes work; the pipeline that distributes them is where the mistakes are.

**For the corpus: AndroRAT is analysable once, thoroughly, and its hash is stable. AhMyth is analysable only as a *family* of outputs, because each operator's build is a different artifact.** That is the real consequence of the template-vs-compiled axis, and it is why D37's provenance verification worked on one target and could never work on the other.
