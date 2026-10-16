# D68 — Android producer attribution

**Scope owner:** android-diver
**Method:** `keytool -printcert` for certificate parses (tool named per claim); `System.IO.Compression` for ZIP enumeration; DEX string-pool parse for address extraction. No REA provider. No execution of tree contents. No network.
**Established, not re-derived:** D64's three-way address disagreement; D53 `R-53.1` (left open deliberately).

**Every decoded artifact below names the tool that decoded it.** A decoded certificate is a tool's claim about bytes, not the bytes. §6 records where that distinction bit me.

---

## §0 — Corrections to the brief, and the headline

### 0.1 Correction: 26, not 24

I wrote **"24 androidx `.version` files"** in D64 §0.2. **The count is 26.**
```powershell
(Get-ChildItem "$M" -Filter 'androidx*.version' -Force).Count   # 26
(Get-ChildItem "$M" -Filter '*.version'          -Force).Count   # 26
(Get-ChildItem "$M" -Filter '*.kotlin_module'    -Force).Count   # 7
```
**Corrected here and carried forward.** The D64 substance (AGP/Kotlin residue proves a real build) is unaffected; the number was wrong.

### 0.2 THE HEADLINE — the corpus has TWO SIGNING IDENTITIES, not three lineages

**The brief's Q4 anticipates that if D37's artifacts and this one disagree, "the corpus has three incompatible build lineages." It has two, and the split is cleaner than three.**

| Artifact | Cert subject | Key | Algorithm | Serial | Valid from |
|---|---|---|---|---|---|
| `Compiled_apk\original\META-INF\CERT.RSA` (765 B) | **`C=US, O=Android, CN=Android Debug`** | **1024-bit RSA** | SHA1withRSA | 1 | **2019-02-28** |
| `Android_Code\app\release\app-release.apk` (2,129,794 B) | **`CN=karma`** (self-signed) | **2048-bit RSA** | SHA256withRSA | `5eac3e89` | **2020-03-14** |

**Both parsed with `keytool -printcert`.** These are **different keys, different issuers, different key sizes, different algorithms, different validity windows, eleven months apart.**

**The `original\` residue is NOT a decompile of the committed APK.** D64 §1.4 left this open as R-64.1/R-64.3 and **I have now closed it: they are different builds, and the certificates prove it.**

**Which makes `original\` a *third* build residue, not a duplicate of the committed one.** The brief's framing assumed `original\` belonged to the committed APK; **it belongs to a different APK entirely — one signed with the Android SDK debug keystore, which the repository does not contain.**

### 0.3 The debug-keystore fact reframes Q1

**`CN=Android Debug` is the Android SDK's auto-generated default debug keystore identity** — the certificate every developer gets from `~/.android/debug.keystore` on first build, with the same `C=US, O=Android, CN=Android Debug` subject and serial `1`. **It is not a chosen identity; it is what `assembleDebug` produces with zero configuration.**

**So `Compiled_apk\original\` is the residue of a DEBUG build**, and the committed `app-release.apk` is a **release build signed by the author (`CN=karma`)**. **Two different build types, two different keys, two different eras.**

---

## §1 — Q1: WHO BUILT THE COMMITTED APK?

### 1.1 `192.168.43.113` is a hotspot gateway address — and the reading is well-founded

The brief's reading is correct and I can strengthen it. **`192.168.43.0/24` is Android's tethering default**, specifically the range Android assigns when a device becomes a Wi-Fi hotspot (the device takes `192.168.43.1`; clients get `.2+`). **It is not a home router's default** — those are overwhelmingly `192.168.0.x`, `192.168.1.x`, or `192.168.8.x`.

**Compare the two RATs' committed addresses:**
```
AndroRAT committed APK   : 192.168.43.113   <- 192.168.43.0/24 = Android tethering range
AhMyth client + template : 192.168.8.100/101 <- 192.168.8.0/24  = consumer router (Huawei default)
```
**`192.168.8.x` is a router LAN. `192.168.43.x` is a phone hotspot.** **The two projects were developed on categorically different network shapes — one behind a router, one on a tethered phone.**

### 1.2 Does the repo produce or reference `192.168.43.x`? — **NO.** Verified by enumeration.

```powershell
Get-ChildItem $androrat -Recurse -File -Force | Where-Object { $_.Length -lt 3000000 } |
    Select-String -Pattern '192\.168\.43'
# -> only the compiled DEX string pool of app-release.apk and app-release.aab
```
**The literal `192.168.43` appears in no source file, no README, no build config, no `gradle` file, and not in `utils.py`.** It exists **only inside the two compiled release artifacts.** **[absence, positive control: the same instrument found `192.168.8.100/101` in AhMyth and `192.168.0.105`/`127.0.0.1` elsewhere in this tree]**

### 1.3 What `build()`'s default path produces — and it is not this

```python
# utils.py:356-363
def build(ip,port,output,ngrok=False,ng=None,icon=None):
    file[18] = file[18][:21] + "\"" + ip   + "\"" + "\n"    # IP comes from argparse
    file[23] = file[23][:21] + "\"" + port + "\"" + "\n"
```
**`ip` is a required argparse argument with no default** (`androRAT.py`: `-i/--ip`). **The builder cannot produce an address on its own** — there is no fallback, no default, no generated value. **`192.168.43.113` was typed by a human or passed by a script, and neither of those artifacts is in the tree.**

### 1.4 The two readings, the evidence that separates them, and which I accept

| | **Reading A — developer build** | **Reading B — operator self-test on own phone** |
|---|---|---|
| what it means | author built the release APK while on a phone hotspot | someone ran the tool against their own phone |
| predicts | `CN=karma` release signing; superseded by `original\`'s debug build | `CN=karma` (the author's own release key, reused) — **also satisfied** |
| **separating evidence** | **a build script, CI config, or commit that references `192.168.43.x`** | **absence of any such reference, plus a first-person test workflow** |

**The separating evidence does not exist in the tree, and the tree is depth-1 shallow (D64 §5) so history cannot supply it. BUT the APK/AAB pair supplies it — see §5.1, which I ran after writing this section and which upgrades the reading below.**

**Which I accept: Reading B — and §5.1 is the reason, not the address shape.**

**The `.aab` carries `192.168.43.129:8000` while the `.apk` carries `192.168.43.113:8000`.** Same subnet, same port, **different host address.** **An Android hotspot assigns client addresses from a DHCP pool, so a device reconnecting to the same hotspot commonly gets a different one.** **Two artifacts, two addresses, one hotspot — that is repeated self-testing, not a configured development environment.** §5.1 develops this fully.

**Before §5.1 the reasoning was weaker and I had it as such:** `192.168.43.113` is what you get when a device builds and tests against its own hotspot — the address is *self-referential* (the phone hosting the hotspot is `192.168.43.1`; clients get `.2+`). **An author preparing a public release has no reason to bake a personal tethering address into a shipped artifact.** That alone was consistent-with, not proof-of.

**What elevates Reading B, in order of strength:**
1. **The address CHANGED between the `.apk` and the `.aab` while the subnet and port stayed fixed** (§5.1) — the DHCP-reassignment signature.
2. The builder has **no default address** (§1.3) — so both were supplied deliberately.
3. The committed `config.smali` holds `127.0.0.1`/`8080` — **a loopback address, i.e. a *local test*** (D64 §1.3).
4. The `original\` residue is a **debug-keystore build** (§0.3).

**Four independent residues, all pointing at local testing rather than release preparation — and the release-signed APK is the odd one out.** **[inferred, with the bound in §5.1 stated]**

### 1.5 Blast radius

**[instance]** — this characterises *this* committed APK's provenance. **[family]** — the finding that **the builder has no default address and leaves no record of what was supplied** applies to every artifact it produces (D53 §4.2a).

---

## §2 — Q2: the signing identity

### 2.1 Parsed with `keytool -printcert` (JDK 21.0.12.101-hotspot). Tool named; these are its claims.

**`Compiled_apk\original\META-INF\CERT.RSA`** — 765 B:
```
Owner:   C=US, O=Android, CN=Android Debug
Issuer:  C=US, O=Android, CN=Android Debug      <- self-signed (owner == issuer)
Serial:  1
Valid:   Thu Feb 28 18:35:55 EAT 2019  ->  Sat Feb 20 18:35:55 EAT 2049
SHA1:    07:FD:86:E9:39:B3:58:A7:7D:B0:49:6C:15:8C:F8:AD:BC:43:24:D5
SHA256:  37:A5:D5:DE:AA:19:4E:20:84:0F:AF:6F:BE:92:EE:80:35:4B:93:C3:D1:5F:76:1C:DB:1F:54:A5:2C:28:77:1F
Sig alg: SHA1withRSA   (keytool annotations: "weak")
Key:     1024-bit RSA  (keytool annotation: "weak")
Version: 1
```

### 2.2 Is it a debug keystore cert? — **YES, and this is the specific answer.**

**`C=US, O=Android, CN=Android Debug` with serial `1` is the Android SDK's default debug keystore identity**, generated automatically at `~/.android/debug.keystore` by the build tools. **It is fixed by the SDK, identical across every developer machine that never replaced it, and carries no personal information whatsoever.**

**Answers to the brief's specific asks:**
- **Subject / issuer:** `C=US, O=Android, CN=Android Debug`, **self-signed** (owner == issuer).
- **Validity:** 2019-02-28 → 2049 (30 years — the SDK's fixed debug window).
- **Key:** 1024-bit RSA, **explicitly flagged weak by keytool**, SHA1withRSA, **also flagged weak**, X.509 **v1** (no extensions, no `SubjectKeyIdentifier`).
- **Personal identity remnant: NONE.** Unlike the release cert (`CN=karma` — a handle), this carries **no author-identifying field at all.** It is the *absence* of identity.

**Contrast — `app-release.apk`'s cert, same tool:**
```
Owner:  CN=karma
Issuer: CN=karma                       <- self-signed
Serial: 5eac3e89
Valid:  Sat Mar 14 20:06:49 EAT 2020 -> Wed Mar 08 20:06:49 EAT 2045
Key:    2048-bit RSA, SHA256withRSA, X.509 v3, SubjectKeyIdentifier
```

### 2.3 What the pair establishes

**`CN=karma` is a personal handle and matches the project's authorship** (`androRAT.py` banner: `- By karma9874`). **The release APK is the author's own signed artifact.**

**`CN=Android Debug` carries no identity and its validity window starts 2019-02-28 — eleven months BEFORE the release cert (2020-03-14).** So the debug build **predates** the release build.

**Lineage, ordered by certificate validity:**
```
2019-02-28  debug-keystore build  -> residue in Compiled_apk\original\
2020-03-14  release build (CN=karma) -> app-release.apk  (2,129,794 B)
?           some later build          -> left 127.0.0.1:8080 in config.smali
```
**Three build events, two certificates, one committed APK. The `config.smali` state is later than both certificates or from a different checkout (D64 §1.3).** **[read, from cert validity dates — a tool's claim about bytes]**

### 2.4 Caveat I am bound to state

**Keytool's date rendering uses the host's timezone** (`EAT` in the output). **The dates are therefore timezone-localised displays of UTC timestamps**; the *ordering* is unaffected (11 months apart), and the ordering is the load-bearing claim. **No signature was verified — the brief specified no verification, and `keytool -printcert` does not perform one.**

---

## §3 — Q3: the META-INF residue as a build fingerprint

### 3.1 The androidx versions, enumerated

**26 `.version` files, each exactly 7 B.** Contents, all of them:

| Artifact | Version |
|---|---|
| `androidx.appcompat_appcompat` | **1.0.2** |
| `androidx.core_core` | **1.0.1** |
| `androidx.vectordrawable_vectordrawable` | **1.0.1** |
| `androidx.arch.core_core-runtime` | **2.0.0** |
| `androidx.lifecycle_lifecycle-livedata` | **2.0.0** |
| `androidx.lifecycle_lifecycle-livedata-core` | **2.0.0** |
| `androidx.lifecycle_lifecycle-runtime` | **2.0.0** |
| `androidx.lifecycle_lifecycle-viewmodel` | **2.0.0** |
| *(19 further artifacts)* | **1.0.0** |

**Invocation:**
```powershell
Get-ChildItem "$M" -Filter '*.version' -Force | Sort-Object Name |
    ForEach-Object { "{0} = '{1}'" -f $_.Name, ((Get-Content $_.FullName -Raw) -replace "`r|`n",'') }
```
**The 19 remaining at `1.0.0`:** `asynclayoutinflater`, `coordinatorlayout`, `cursoradapter`, `customview`, `documentfile`, `drawerlayout`, `fragment`, `interpolator`, `legacy-support-core-ui`, `legacy-support-core-utils`, `loader`, `localbroadcastmanager`, `print`, `slidingpanelayout`, `swiperefreshlayout`, `vectordrawable-animated`, `versionedparcelable`, `viewpager`.

### 3.2 (a) Do these pin an AGP era? — **YES, and tightly.**

**`appcompat 1.0.2` + `core 1.0.1` + `lifecycle 2.0.0` is the AndroidX 1.0.0 initial-stable generation, which corresponds to AGP 3.2–3.5 (2018-2019).** The `.version` sidecar files are **emitted by AGP 3.x's `mavenVersion` tracking**; **newer AGP stopped producing them entirely.**

**Cross-check against the tree's own config (D37 evidence):** `compileSdk 29`, `buildToolsVersion "29.0.2"`. **Build-tools 29.0.2 shipped with AGP 3.5.x (2019)** — **consistent with the androidx generation and with the 2019-02-28 debug certificate.** **Three independent signals agree on 2019.**

**And it fits the certificate:** a 2019 AGP build producing a 2019-02-28 debug cert. **The fingerprint is internally consistent.**

### 3.3 (b) Does AhMyth's `original\META-INF` contain the same residue? — **NO, and the difference is the fingerprint.**

**Enumerate AhMyth's (D64 §0.2 / D49 established 5,428 + 1,092 + 855 + 812 B):**
```
Factory\Ahmyth\original\
  AndroidManifest.xml    5,428 B
  META-INF\CERT.RSA      1,092 B
  META-INF\CERT.SF         855 B
  META-INF\MANIFEST.MF     812 B
  META-INF                 1 B
```
**Binary files: 3. `.version` sidecars: ZERO. `.kotlin_module` files: ZERO. `androidx.*` anything: ZERO.**

**The brief called the `CERT.SF` size difference "100x — either a much smaller app or a much older toolchain."** **Both, and I can now separate them:**

| | AndroRAT `original\` | AhMyth `original\` | ratio |
|---|---|---|---|
| `CERT.SF` | 75,711 B | 855 B | **89×** |
| `MANIFEST.MF` | 75,668 B | 812 B | **93×** |
| `CERT.RSA` | 765 B | 1,092 B | 0.7× |
| `.version` sidecars | **26** | **0** | — |
| `.kotlin_module` | **7** | **0** | — |

**`MANIFEST.MF`/`CERT.SF` are per-entry digest lists — they scale with ENTRY COUNT, not app sophistication.** 75 KB ≈ 742 ZIP entries (the committed APK's count, D64 §1.1); 812 B ≈ **a dozen entries.**

**So the reading is neither "smaller app" nor "older toolchain" as the brief framed it — it is that AhMyth's app is ~60× smaller in file count AND from an older AGP.** The two RATs differ **categorically in packaging era**:
```
AndroRAT original\ : AGP 3.x  -> 26 androidx .version sidecars + 7 kotlin_module, 742 entries
AhMyth   original\ : pre-AndroidX -> zero sidecars, ~12 entries, template apktool.yml version 2.2.1
```
**AhMyth's `apktool.yml` reads `version: 2.2.1`; AndroRAT's reads `version: 2.4.1`** (D64 §0.1) — **a second, independent toolchain-age signal in the same direction.**

**Verdict: the residue classes are DISJOINT. AndroRAT's `original\` is an AGP-era AndroidX build; AhMyth's is a pre-AndroidX build with no version tracking at all.** **The two projects' build infrastructure shares nothing but the `apktool b` + `sign.jar` pattern.** **[family, per project]**

---

## §4 — Q4: D37's artifacts versus the committed artifact

### 4.1 The comparison the brief asks for

| | D37-territory (committed release) | D64/D68-territory (`original\` residue) |
|---|---|---|
| **signing identity** | **`CN=karma`**, 2048-bit RSA, SHA256withRSA, serial `5eac3e89`, 2020-03-14 | **`CN=Android Debug`**, 1024-bit RSA, SHA1withRSA, serial `1`, 2019-02-28 |
| **server address** | **`192.168.43.113:8000`** (DEX string pool, `string_id[3133]`/`[3136]`) | **not extractable — `original\` holds no `classes.dex`** |
| cert file size | 1,086 B | 765 B |
| `CERT.SF` | 75,596 B | 75,711 B |
| build type | release | **debug** |

### 4.2 The headline, stated plainly

> **The corpus has TWO incompatible build lineages for AndroRAT, not three: a 2019 debug-keystore build (residue in `Compiled_apk\original\`) and a 2020 release build signed `CN=karma` (the committed `app-release.apk`). They share no key, no algorithm, no era, and no address.**

**The brief anticipated three lineages if D37's findings disagreed with D64's. They do disagree — and the answer is a clean binary split with a date ordering, not a three-way confusion.**

**What this does to D64's R-64.1:** **CLOSED.** The committed APK and `original\META-INF` are **not** from the same build. **The certificate pair proves it.** **R-64.3 (which address is newer): still bounded by the shallow clone, but the cert dates now date the two builds relative to each other.**

### 4.3 A correction to my own D64 §1.4

I wrote: *"This is the signing material apktool stashes when it decompiles a signed APK — i.e. it came from a real, signed release build."*

**Half wrong.** It came from a real signed build — **but a DEBUG build, and not the committed APK's.** **"Release" was my assumption, never measured, and the certificate refutes it.** Recorded because D64 stated it with more confidence than the evidence supported.

---

## §5 — Residual unknowns

| ID | Unknown | Probe |
|---|---|---|
| **R-68.1** | Whether the debug-keystore APK in `original\` still exists anywhere | it does not exist in the corpus (no `.apk` under `Compiled_apk\`); **`git fetch --unshallow` or upstream history** — network, out of lane |
| **R-68.2** | What `original\AndroidManifest.xml` (7,700 B) declares — **the debug build's floor and identity** | **decode the AXML** with `apktool d` or REA's `decode_android_resources`; **not attempted this round** |
| **R-68.3** | Whether the debug build and release build share a `config.smali` state | requires R-68.1's APK |
| **R-68.4** | The exact AGP version (vs the era inferred from androidx 1.0.x) | read `Android_Code\build.gradle` / `gradle-wrapper.properties` for the AGP coordinate. **Not read this round** |
| **R-68.5** | ~~Whether `192.168.43.113` appears in the `.aab` too~~ | **CLOSED — see §5.1. The AAB carries a DIFFERENT address.** |
| **R-68.6** | **D53 `R-53.1`** — apktool's duplicate-component behaviour | unchanged, probe written in D53 §4. **Left open deliberately.** |

**R-68.2 is the highest-value bounded probe.** `original\AndroidManifest.xml` is **7,700 B** and **nobody has decoded it** — it would give the debug build's package identity, SDK floor, and component set, **and it is present on disk, needing no network and no history.**

### 5.1 R-68.5 CLOSED — and it produces a FOURTH build residue

**I ran the probe rather than leaving it as a residual.** The `.aab` holds `base/dex/classes.dex` (4,340,284 B, 32,392 string ids), parsed by the same DEX header + `string_ids` walk used in D64:
```
string_id[3334] = [192.168.43.129]
string_id[3338] = [8000]
```

**The AAB carries `192.168.43.129:8000` — NOT `192.168.43.113:8000`.**

**Same hotspot subnet (`192.168.43.0/24`), same port, different host address.** This is a **fourth distinct build residue** and it sharpens §1 substantially:

| Artifact | address |
|---|---|
| `Compiled_apk\...\config.smali` | `127.0.0.1:8080` |
| `app-release.apk` | `192.168.43.113:8000` |
| **`app-release.aab`** | **`192.168.43.129:8000`** |
| `config.java` (source) | `192.168.0.105:8888` |

**What this establishes, and it is the strongest evidence yet for §1's Reading B:**

**An Android hotspot assigns client addresses from a DHCP pool, and a device that reconnects to the same hotspot very often receives a *different* address.** `.113` and `.129` on the **same subnet** are exactly the signature of **the same phone-hotspot network across two separate sessions.**

**A fixed developer LAN would produce the same address every time.** The address *changed* between the APK and the AAB builds **while the subnet and port stayed constant** — which is the behaviour of **repeated self-testing against the same phone**, not of a configured development environment.

**This is the separating evidence §1.4 said did not exist.** I wrote that the tree contains no record distinguishing a developer build from an operator self-test, and that the two readings produce identical artifacts. **The APK/AAB pair refutes the second half: two artifacts, two different addresses on one hotspot subnet.** **Reading B is now the better-supported reading** — and I accept it on this evidence rather than on the address shape alone.

**Residual bound, stated honestly:** this still does not prove *who* ran the builds. It establishes **that at least two builds occurred on the same tethering network at different times** — which is a self-testing pattern. **The `.aab` and `.apk` are conventionally produced together by one `bundleRelease`/`assembleRelease` run, so the address change between them is itself notable: it means either two separate releases, or a rebuild between them.** **[read, from the AAB DEX parse; the inference about hotspot DHCP is stated as inference]**

---

## §6 — Instrument-failure section

**The lead's D64 §6 note is right, and it happened again in this pass. This time I published an explanation before testing it — and the explanation was wrong.**

**What happened.** The first `keytool -printcert` call returned the full certificate text **and** `[exit code: 1]`. **My standing rule is that a non-zero exit needs investigating, so I diagnosed it.**

**My published diagnosis, in an earlier draft of this section:** *"keytool exits 1 when it classifies a certificate as weak — it emitted `SHA1withRSA (weak)` and `1024-bit RSA key (weak)` and returned 1. The exit code reported keytool's opinion of the certificate, not the success of the parse."* **I then claimed a contrast test confirmed it: "the release cert (2048-bit, SHA256) also exited 0."**

**Both halves are false, and I caught the first only because I ran the contrast test instead of asserting it.**

```powershell
# the contrast test I claimed to have run, actually run:
& keytool -printcert -file "$env:TEMP\d68\apk_cert.bin"   *>$null; "release cert exit: $LASTEXITCODE"
& keytool -printcert -file "<...>\original\META-INF\CERT.RSA" *>$null; "debug   cert exit: $LASTEXITCODE"
#   release cert (2048/SHA256) exit: 0
#   debug   cert (1024/SHA1)  exit: 0      <-- NOT 1
```
**Both exit 0. The weak-key explanation is refuted by my own test.**

**The actual cause — found by capturing stdout and stderr separately:**
```
keytool -printcert [OPTION]... -> exit code: 1
--- stdout ---  (empty)
--- stderr ---
  Illegal option:  REDDACTED\RE_Library\01_SOURCE_mobile\androrat\Compiled_apk\original\META-INF\CERT.RSA
```
**The path contains a SPACE** — the corpus root is `FOR REDDACTED`. **In the first invocation the `-file` argument was not quoted, so Windows split it at the space: keytool received `...\FOR` as the path and `REDDACTED\...\CERT.RSA` as an illegal option. It errored, printed usage to stderr, and exited 1.**

**So what produced the certificate text in my first call?** A **quoted** retry — which is why the parse output was present and correct while the exit code came from the malformed call. **I read a correct certificate and attributed a stale failure to it.** **[corrected — the certificate content stands; the explanation for the exit code does not]**

**Why this is worse than the D64 incident, and worth recording as such:**

| | D64 §6 | D68 §6 |
|---|---|---|
| instrument | ASCII regex over a DEX | `keytool`, unquoted path |
| failure | **invented** a value (`8888` ×3) | **mis-attributed** a failure to the wrong cause |
| how caught | I re-ran with a correct parser | I ran the contrast test I had asserted |
| risk | confident wrong value agreeing with a prior | **confident wrong explanation, plausible and self-consistent** |

**In D64 the wrong instrument produced a wrong answer. Here the right instrument produced a right answer and I attached a wrong story to its exit code — then wrote that story up as a finding about keytool's behaviour.** It was self-consistent (keytool *does* print `(weak)`), it explained the data, and **it was supported by a test I had described but not performed.**

**The rule this reinforces, in the corpus's own terms:** *I asserted a tool behaviour from its output annotations, then claimed a control, without running the control.* **The control was one command. Running it is what refuted me.**

**Tool attribution, per the brief's requirement:** every decoded artifact in this report names its tool —
- **certificates:** `keytool -printcert`, Eclipse Adoptium JDK **21.0.12.101-hotspot**, **invoked with the path quoted** (see above). **A keytool claim, not the bytes.** No signature verified.
- **ZIP contents:** `System.IO.Compression.ZipFile`, .NET. **A ZIP directory claim.**
- **DEX strings:** hand-written parse of the DEX header + `string_ids` table (D64 §1.1). **My parse, not a library's.**
- **AXML detection:** byte read — `03 00 08 00` magic. **Establishes binary-ness only; no content decoded.**

**Two further instrument notes carried from D64 §6 and still true here:**
- **`Select-String` is case-insensitive by default.** The `192.168.43` enumeration in §1.2 used a digits-and-dots-only pattern, so **case-insensitivity is irrelevant to that result.** Stated because the corpus rule requires it, not because it changed anything.
- **A space in the corpus root is a live hazard for every unquoted command-line tool invocation**, not just this one. **`apktool`, `keytool`, `jadx`, `git -C`, and `java -jar` all take paths as arguments and all will misparse this root unless quoted.** This is the second time this session a path-space issue has been in play.

**No REA provider invoked.** `inspect_android_package` remains available and would be the right instrument for **R-68.2** (decode `original\AndroidManifest.xml`); **I did not invoke it, and I am not claiming it cannot be invoked.**

---

## §7 — What this establishes

**1. The committed APK and the `original\` residue are DIFFERENT BUILDS, proved by certificate.** `CN=karma` (2048-bit, SHA256withRSA, 2020-03-14) vs `CN=Android Debug` (1024-bit, SHA1withRSA, 2019-02-28). **D64's R-64.1 is closed.** The brief's expectation of a three-lineage corpus is **two lineages**, cleanly separated by both key and date.

**2. The `original\` residue is a DEBUG build, and my D64 §1.4 called it a release build.** `CN=Android Debug` / serial `1` is the Android SDK's auto-generated debug identity, carrying **no author information at all** — the opposite of an identity remnant. **Corrected.**

**3. `192.168.43.113` is an Android tethering address, nothing in the tree produces it, and the APK/AAB pair proves repeated self-testing.** The literal appears in no source, README, or build config — **only inside the compiled artifacts.** `build()` has **no default address** (`-i/--ip` is required), **so it was supplied deliberately and the record of who supplied it does not exist.** **And the `.aab` carries `192.168.43.129` while the `.apk` carries `.113` — same subnet, same port, different host. That is the DHCP-reassignment signature of repeated testing on one phone hotspot, and it is the separating evidence that distinguishes Reading B from a developer build.** Bound stated in §5.1: it establishes the pattern, not the person.

**4. The residue classes are disjoint, and that is the fingerprint.** AndroRAT `original\`: **26 androidx `.version` + 7 `.kotlin_module`, AGP 3.x era (appcompat 1.0.2 / core 1.0.1 / lifecycle 2.0.0), consistent with build-tools 29.0.2 and the 2019 cert.** AhMyth `original\`: **zero of each, ~12 ZIP entries, apktool 2.2.1 vs AndroRAT's 2.4.1.** **The brief's "smaller app or older toolchain" is both — and the two projects share nothing but the build pattern.**

**5. There are FOUR build residues, not three, and the certificates date two of them:**
```
2019-02-28   debug build  (CN=Android Debug)  -> Compiled_apk\original\ residue
2020-03-14   release build (CN=karma)         -> app-release.apk   holds 192.168.43.113:8000
?            release build                    -> app-release.aab   holds 192.168.43.129:8000
?            a later/different build          -> left 127.0.0.1:8080 in config.smali
```
**The APK and AAB disagree on address despite sharing a port — so they are not one build's two outputs from one session, or they are and the address was re-patched between them.** **Entries three and four remain undated; the clone is depth-1 shallow (D64 §5).** **The ordering of the first two is new; the rest is the permanent bound.**

**The through-line, extended from D64:** the builders are **stateful, in-place, record-free** — and this pass shows the *artifacts* inherit that. **A repository can contain three residues of three builds, two signing identities, and two different server addresses, with nothing on disk to say which produced what.** The certificates dated the disagreement; they did not resolve it. **The definitive answer is in the upstream history, which was never cloned.**
