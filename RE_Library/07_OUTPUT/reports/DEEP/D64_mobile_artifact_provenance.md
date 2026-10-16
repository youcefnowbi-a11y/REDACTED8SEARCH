# D64 — The artifacts the builders actually produce

**Scope owner:** android-diver
**Deliverable scope:** this file only.
**Method:** filesystem enumeration, binary XML decode, byte-level string extraction from committed artifacts, `Constants.js`/`AppCtrl.js` read. No REA provider. No execution. No network.

**Blast-radius convention (carried from D53):** **[instance]** = one artifact; **[family]** = every artifact the builder produces.

**Established, not re-derived:** AndroRAT first-party = **68 of 2,479 `.smali` = 2.7%** (D37); both RATs are **19 classes of agent**; `androrat\utils.py:63,67` `is_valid_ip`/`is_valid_port` defined-never-called; `AppCtrl.js:313` prepend-on-empty-replace (D53).

---

## §0 — Corrections to the brief

**Two, and the first changes what Q1 can answer.**

### 0.1 `Compiled_apk\` does NOT contain a committed APK

The brief states: *"AndroRAT ships a committed APK at `RE_Library\01_SOURCE_mobile\androrat\Compiled_apk\`."*

**It does not.** `Compiled_apk\` is the **decompiled working tree** — the builder's *input*, not its output:

```
Compiled_apk\
  AndroidManifest.xml   ← binary AXML (bytes 03 00 08 00), not text
  apktool.yml           ← apkFileName: Compiled_apk.apk ; version: 2.4.1
  resources.arsc
  build\  kotlin\  original\  res\  smali\
```

**Zero `.apk`, `.aab`, or `.jar` files under `Compiled_apk\`.** Verified by extension-filtered recursive enumeration.

**The committed APKs are elsewhere:**
```
Android_Code\app\release\app-release.apk    2,129,794 B   SHA-256 98037b11…9830
Android_Code\app\release\app-release.aab    2,366,154 B   SHA-256 2251774a…b410
```
**Both are the artifacts D37 already opened and the provider already read.** So Q1 as phrased — "the committed artifact nobody has opened" — **refers to a file that does not exist at that path, and the artifacts that do exist were opened in D37.**

**What IS unopened is more interesting, and 0.2 names it.**

### 0.2 `Compiled_apk\original\` holds the META-INF of a REAL SIGNED BUILD

**This is the genuinely unopened artifact, and the brief does not mention it.**

```
Compiled_apk\original\
  AndroidManifest.xml              7,700 B
  META-INF\CERT.RSA                  765 B   ← a real signing certificate
  META-INF\CERT.SF                75,711 B
  META-INF\MANIFEST.MF            75,668 B
  META-INF\androidx.appcompat_appcompat.version       7 B
  ... (24 androidx/fragment/lifecycle .version files)
  META-INF\kotlin-stdlib.kotlin_module              3,727 B
  META-INF\screenshotty-lib_release.kotlin_module      63 B
```

**`CERT.RSA` is a signing certificate from a build that actually ran.** The `.version` and `.kotlin_module` files are emitted by the Android Gradle Plugin and Kotlin compiler — **they are build residue that only exists in a real build output, never in hand-written source.**

**Consequence for Q1:** the committed APK in `Android_Code\app\release\` and the `META-INF` in `Compiled_apk\original\` are **two residues of the same build pipeline** — one the artifact, one the signing metadata apktool stashed when it decompiled that artifact. **§1 tests whether they agree.**

---

## §1 — Q1: the committed APK versus the source that supposedly built it

### 1.1 The comparison, with both sides extracted

| | server address | port | icon flag |
|---|---|---|---|
| **`Compiled_apk\smali\...\config.smali`** (builder INPUT, on disk now) | `127.0.0.1` | `8080` | `0x1` |
| **`Android_Code\app\release\app-release.apk`** (committed ARTIFACT) | **`192.168.43.113`** | **`8000`** | — |
| `01_SOURCE_mobile\androrat\...\config.java` (source of truth) | `192.168.0.105` | `8888` | `true` |

**They disagree. All three.**

**Invocation — the input side (`Select-String`, targets printed):**
```powershell
Select-String -Path "$androrat\Compiled_apk\smali\com\example\reverseshell2\config.smali" `
              -Pattern 'const-string|const/4'
#  L19: const-string v0, "127.0.0.1"
#  L24: const-string v0, "8080"
#  L29: const/4 v0, 0x1
```

**Invocation — the artifact side.** The APK is a ZIP; `classes.dex` is 3,604,660 B. **A DEX is not text, so I parsed its `string_ids` table rather than grepping bytes** (byte-grep finds substrings inside unrelated data — my own first pass returned three spurious `8888` hits from `ARGB_8888`, a dexmap entry, and binary noise):
```powershell
# read classes.dex from the ZIP, parse the DEX header, walk string_ids
string_ids_size : 26908
string_ids_off  : 112 (0x70)
# decoding all 26,908 strings and filtering to exact matches:
#   string_id[3133] @0x25FA93 = [192.168.43.113]
#   string_id[3136] @0x25FAB7 = [8000]
```

**These two are the ONLY dotted-quad and the only `8000` in the entire 26,908-string pool.** The three `8888` occurrences are accounted for and are not the config port. **The committed APK's server address is `192.168.43.113:8000`, extracted verbatim.**

### 1.2 Is the committed address a valid IP? — **YES.** The brief's hypothesis does not hold.

The brief asks: *"If the builder's column arithmetic is wrong, the committed artifact encodes a malformed address."*

**It does not.** Tested against `utils.py:63`'s own regex:
```
^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$
octets: 192, 168, 43, 113   all in 0..255  => is_valid_ip WOULD return TRUE
```
**The column arithmetic worked.** `file[18][:21]` correctly discards the old literal and writes the new one — I verified this mechanically in D53 and the artifact confirms it end-to-end. `192.168.43.113` is a well-formed **RFC1918 private address** (192.168.0.0/16). **Port `8000` passes `is_valid_port` (digits, length > 1).**

**Stated as a negative finding: the builder's fragile mechanism did not fail here.** It is fragile — positional indices, dead validators, no post-write check — **but on this artifact it produced a correct, parseable address.** A defect that does not fire is still a defect; it is not evidence.

### 1.3 What the disagreement means — and it is the real Q1 answer

**The committed APK was not built from the current `Compiled_apk\` tree.**

If it had been, `config.smali` would hold `192.168.43.113`/`8000` — because the builder **writes the template in place at `:365` and never restores it** (D53 §4.2(a)), so whatever the last build used would still be sitting there. It holds `127.0.0.1`/`8080` instead.

**Three candidate explanations, and the evidence ranks them:**

| # | Explanation | Verdict |
|---|---|---|
| 1 | The APK was built by this builder, then `config.smali` was later reset/reverted | **contradicted** — `build()` has no reset path; D53 established the mutation persists |
| 2 | The APK was built from a *different checkout* of `Compiled_apk\` | **consistent with all evidence** |
| 3 | The APK predates the current builder entirely | **consistent; not distinguishable from 2 without git history** |

**Explanation 2 or 3 — and 1 is ruled out by D53's finding.** The template's on-disk `127.0.0.1`/`8080` is **not** a developer default that the committed APK overrode; it is the residue of a **different, later or earlier** build. **Either way: the committed APK and the committed template are residues of two different builds.**

**Blast radius: [family].** This is the same defect class D53 §4.2(a) named, now confirmed at the artifact level: **because `build()` leaves no build record, the committed state of the template cannot be used to reconstruct which build produced the committed artifact.** The tree carries a template and an APK that do not agree, and **nothing in the repository says which is which.**

### 1.4 The `original\` META-INF — a third residue

`Compiled_apk\original\META-INF\` carries `CERT.RSA`, `CERT.SF` (75,711 B), `MANIFEST.MF` (75,668 B) and 24 androidx `.version` files. **`CERT.SF` and `MANIFEST.MF` at ~75 KB each are consistent with a large multi-package build** — the androidx/kotlin closure D37 counted (1,369 androidx + 827 kotlin `.smali`).

**This is the signing material apktool stashes when it decompiles a *signed* APK** — i.e. it came from a real, signed release build. **Whether it is the certificate of the same `app-release.apk` is a concrete probe (R-64.3), not an inference I will make**: comparing `CERT.SF`'s digest list against the APK's actual entries requires reading both, and **I have not.**

---

## §2 — Q2: AhMyth's `192.168.8.100` — the author's own network, and a second stale-build proof

### 2.1 (a) Default, placeholder, or the author's own network? — **the author's own network, and the evidence is strong**

**Invocation — every occurrence in the tree** (`Get-ChildItem -Recurse -File -Force`, `node_modules`/`.git` excluded, `Select-String` on two literals):

```
AhMyth-Client\...\IOSocket.java:28            "http://192.168.8.101:42474?model="
AhMyth-Server\...\Factory\Ahmyth\...\IOSocket.smali:79
                                              "http://192.168.8.100:42474?model="
AhMyth-Server\app\app\assets\js\Constants.js:15   exports.defaultPort = 42474;
AhMyth-Server\app\app\index.html:64           placeholder="Deafult is 42474"
AhMyth-Server\app\app\assets\js\Controllers...views\build.html:25
                                              placeholder="default is 42474"
```

**Both are RFC1918 `192.168.0.0/16` private addresses.** A placeholder would be `0.0.0.0`, `127.0.0.1`, or `YOUR_IP_HERE`. **`192.168.8.100` is a concrete host on a LAN — it is somebody's development machine, and given it appears in both the client source and the shipped template, it is the author's.**

**The finding the brief did not anticipate — and it is a second independent proof of D49 §4.3(a):**

```
template smali : 192.168.8.100
client .java   : 192.168.8.101
                 ^^^ differ by ONE in the last octet
```

**The template's hard-coded address and the client source it supposedly came from are not the same address.** Since `IOSocket.smali` is the compiled form of `IOSocket.java`, and nothing in the repository patches `IOSocket.java` (only `AppCtrl.js:313` rewrites the *smali*, at build time, on the *target's* copy), **the `.smali` was compiled from a different revision of `IOSocket.java` than the one committed.** **D49 §4.3(a) proved the SDK floors differ; this proves the source bodies differ too — two independent lines of evidence that the template is a foreign build.** **[family]**

### 2.2 (b) Does the builder overwrite it, and at which line? — **yes, at `:313`, and only on a copy**

**Invocation — the write site:**
```powershell
# AppCtrl.js:303  ipPortFile = path.join(CONSTANTS.ahmythApkFolderPath, CONSTANTS.IOSocketPath)
# Constants.js:7  ahmythApkFolderPath = .../Factory/Ahmyth   (.replace("app.asar","app.asar.unpacked"))
# Constants.js:16 IOSocketPath = 'smali/ahmyth/mine/king/ahmyth/IOSocket.smali'
# AppCtrl.js:305  fs.readFile(ipPortFile, 'utf8', ...)
# AppCtrl.js:313  data.replace(data.substring(indexOf("http://"), indexOf("?model=")), "http://"+ip+":"+port)
# AppCtrl.js:314  fs.writeFile(ipPortFile, result, 'utf8', ...)
```
**`ipPortFile` resolves to `Factory\Ahmyth\smali\ahmyth\mine\king\ahmyth\IOSocket.smali` — the TEMPLATE ITSELF.**

**This is the structural difference from AndroRAT, and it corrects my own D49 emphasis.** I wrote in D49 §4.2 that "AhMyth never patches its own template, only the target's copy." **That is wrong, and `:303`/`:313` prove it: the builder rewrites the template in place at `:313` before every build — exactly as AndroRAT's `build()` does at `utils.py:365`.**

**Both builders mutate their template in place and neither restores it.** The AndroRAT-specific defect D53 §4.2(a) identified — *"mutates the template before building, and does not restore it on failure"* — **is present in AhMyth too, at a different line.** D53 marked that finding `[family]` for AndroRAT; **it is now `[family]` for both, and it is the same defect shape in two codebases.** **[family]**

**Consequence for the shipped template:** `Factory\Ahmyth\...\IOSocket.smali:79` currently reads `192.168.8.100:42474`. **That is the residue of whatever build last ran against this checkout** — which is why it is not `192.168.8.101`, the value in the source it was compiled from. **The committed template's address is not the author's declaration; it is leftover state.**

### 2.3 (c) Is `42474` reachable through the builder, or template-only?

**Both — and the distinction matters.**

| Path | `42474` reachable? | Evidence |
|---|---|---|
| **template-only** | yes | `IOSocket.smali:79` contains it literally |
| **builder default** | **yes** | `Constants.js:15 defaultPort=42474`, consumed at `AppCtrl.js:295` |
| **operator-specified** | yes | `:296` accepts any port in `(1024, 65535]` |

**`AppCtrl.js:290-299`:**
```js
$appCtrl.Build = (ip, port) => {
    if (!ip) { ...return; }
    else if (!port) { port = CONSTANTS.defaultPort; }        // <- 42474
    else if (port > 65535 || port <= 1024) { ...return; }
```
**If the operator supplies an IP but no port, the port defaults to `42474` — the same value the template ships.** So the shipped default is *coherent*: the template's baked-in port and the builder's fallback agree. **An operator who leaves the port blank produces an artifact still pointing at `42474`, which is why the template's `:42474` is not a stale artefact in the way the IP is — it is a live default.**

**The URL *form* is also reachable and required:** `:313` searches for the literal `"http://"` and the literal `"?model="`. **Both must be present in the template for the substitution to work at all** — and `IOSocket.smali:79` supplies both. **So on the shipped template, `:313`'s prepend-on-empty-match defect (D53 §1.2a) does not fire.** It fires only if a template lacks `?model=` — which **the shipped template does not**. **Concrete probe R-64.5: confirm no operator-reachable path can hand `:313` a template without `?model=`; `ahmythApkFolderPath` is a fixed path, so this requires the template file itself to be missing or truncated — the `:306` read-error guard would then fire first.**

---

## §3 — Q3: the produced SDK floor

### 3.1 The brief's instruction was to find where the SDK floor is injected. **It is not injected anywhere.**

**Invocation — searched both files for every floor-related token:**
```powershell
foreach($f in "$A\assets\js\Constants.js", "$A\assets\js\controllers\AppCtrl.js") {
    Select-String -Path $f -Pattern 'minSdk|targetSdk|uses-sdk|sdkVersion|platformBuild|compileSdk|<application'
}
```
```
--- Constants.js ---   (NO SDK-floor match at all)
--- AppCtrl.js ---
  L177: var firstPart = manifest.substring(0, manifest.indexOf("<application"));
  L178: var lastPart  = manifest.substring(manifest.indexOf("<application"));
  (NO SDK-floor match at all)
```

**`Constants.js` contains no SDK token of any kind. `AppCtrl.js` references `<application>` only as a splice anchor.** **Neither the floor nor the ceiling is set, modified, or read by the builder.** The `copyPermissions` list (D49/D53) contains permissions and features — **no `<uses-sdk>`.**

### 3.2 So what floor does the produced artifact carry? **It depends entirely on which of the two paths ran.**

There are **two mutually exclusive build paths** (`AppCtrl.js:321`):

**Path A — `bindApk.enable == false` (the default, `:25`) → `GenerateApk(ahmythApkFolderPath)`.**
The template is built **as itself**. Its floor is whatever the template declares:
```
Factory\Ahmyth\apktool.yml:  minSdkVersion: '10'   targetSdkVersion: '18'
Factory\Ahmyth\AndroidManifest.xml:2
  <manifest ... package="ahmyth.mine.king.ahmyth" platformBuildVersionCode="24" platformBuildVersionName="7.0">
```
**Produced floor: `minSdk 10` / `targetSdk 18`.** **[read]**

**A mechanism detail that matters, verified:** the template's `AndroidManifest.xml` **contains no `<uses-sdk>` element at all** (`$m.Contains('<uses-sdk')` → `False`). **The floor lives in `apktool.yml`'s `sdkInfo` block, and apktool synthesises the `<uses-sdk>` into the output AXML at rebuild time.** So the floor is applied by **the tool**, not by the manifest text the builder edits — **which is why no amount of manifest patching by `AppCtrl.js` could change it.**

**Path B — `bindApk.enable == true` → decompile the victim, patch the *victim's* manifest.**
`:336` `apkFolder = filePath.substring(0, filePath.indexOf(".apk"))`; `:338` `apktool d <victim.apk> -f -o <apkFolder>`; `:200` reads **`path.join(apkFolder, "AndroidManifest.xml")`** — **the victim's manifest**, then `copyPermissions` + splice at `:210`, then `:163` copies **only the `smali` tree**, then `GenerateApk`.

**Produced floor: the VICTIM APP'S OWN floor.** **[read]**

### 3.3 The answer, stated plainly

> **The produced APK carries the TEMPLATE's floor (minSdk 10 / targetSdk 18) only when binding is disabled. When binding is enabled, it carries the VICTIM's floor and the template's manifest never enters the build — only its smali does.**

**The 6-level gap D49 identified is therefore not a gap in the produced artifact on the binding path.** It is a property of the **standalone** AhMyth APK (Path A). On Path B the agent runs under whatever `uses-sdk` the host app declared — **which is the point of the camouflage model, and it also means the agent's compiled `targetSdk 18` assumptions travel as code, while the manifest floor travels as the victim's.** **Two different SDK floors in one artifact: the manifest says the victim's, the agent's bytecode was compiled against 18.**

**That mismatch is the load-bearing consequence.** An agent compiled against `targetSdk 18` running under a manifest declaring `targetSdk 33` is subject to Android 13 behaviour changes it was never written for — **and `Constants.js`'s injection list (`:40-41` `android.hardware.camera` nested in the autofocus string, D53 §2) is the same file that would have carried a floor had anyone thought to write one.**

**The brief's "follow that same pattern: find where the SDK floor is injected" — the honest answer is that the pattern does not extend, because there is no floor injection to find.** The `uses-feature` collision in `Constants.js` exists because `Constants.js` *does* hold an injection list; **it holds no SDK entry, so there is no collision, no default, and nothing to trace.** **[absence — with the positive control that the same `Select-String` pattern DID match `<application>` in `AppCtrl.js`, so the probe bites.]**

---

## §4 — Q4: D53's R-53.1 — apktool's behaviour on duplicate components

**D53 R-53.1 asked:** when `AppCtrl.js:210` splices `MainService`/`MyReceiver` twice, does apktool **reject** the duplicate or **emit** it?

**I cannot close it from this corpus, and I will not guess.** What I can state:

**Established (D53, unchanged):** the *string* splice produces two identical `<service>` and `<receiver>` elements. **Simulated, 2× each on a second run.**

**Not established:** apktool's writer behaviour. **apktool 2.4.1 is the version in AndroRAT's tree** (`Compiled_apk\apktool.yml: version: 2.4.1`); AhMyth bundles `Factory\apktool.jar` (unopened this round). **Neither apktool source tree is present in the corpus**, and the flows here are **ZIP+resource-table writers**: `AndroidManifest.xml` is written as **binary AXML** (confirmed: AndroRAT's `Compiled_apk\AndroidManifest.xml` begins `03 00 08 00`), meaning apktool re-encodes the XML into the AXML format and rebuilds `resources.arsc`. **Whether its AXML encoder validates component-name uniqueness is a property of that encoder, not of XML.**

**The probe that would close it, precisely:**
1. Take a decompiled folder with a manifest containing two identical `<service android:name="X"/>` elements.
2. Run the bundled `apktool.jar b` against it.
3. Observe: non-zero exit, or a built APK.
4. If it builds, run `aapt2 dump xmltree` on the output manifest and count the `<service>` nodes.

**Why I did not run it:** step 2 executes a JAR **and produces an APK**, which is a build attempt — **outside this lane's constraints** (no build attempts, no execution of tree contents). **The right owner is whoever holds the build sandbox**, and the probe is now written down rather than left as "unverified." **R-53.1 remains open, correctly and deliberately.** **[absence: not-closable-here, not not-closable]**

---

## §5 — Residual unknowns

| ID | Unknown | Concrete probe |
|---|---|---|
| **R-64.1** | Whether the committed `app-release.apk` and `Compiled_apk\original\META-INF` come from the **same** build | compare `CERT.SF`'s digest list against the APK's actual ZIP entries; `CERT.RSA` is 765 B and unread this round |
| **R-64.2** | Which build produced the committed APK, given `config.smali` disagrees | **git CANNOT close this — clone is depth-1 shallow, 1 commit (verified).** Probe: `git fetch --unshallow` or upstream `karma9874/AndroRAT` history — **network, out of lane** |
| **R-64.3** | Whether `192.168.8.100` or `192.168.8.101` is the *newer* of the two | same bound as R-64.2 — **no local history exists** |
| **R-64.4** | apktool's writer behaviour on duplicate components (**= D53 R-53.1**) | §4 probe, 4 steps |
| **R-64.5** | Whether `:313`'s empty-match defect can fire on any operator-reachable state | `ahmythApkFolderPath` is fixed; requires template truncation, which `:306` guards first. **Probe: corrupt the template file in a scratch copy and observe which guard fires first** |
| **R-64.6** | Whether `original/AndroidManifest.xml` (7,700 B) matches the shipped APK's manifest | decode both, diff. **Not attempted** |
| **R-64.7** | The bundled apktool versions' identity | AhMyth `Factory\apktool.jar` **16,314,178 B** vs AndroRAT `Jar_utils\apktool.jar` **17,661,172 B** — **different jars**; read each JAR's `META-INF` for version. **Not opened** |

**One residual worth elevating: R-64.2 — and I checked whether git can close it. IT CANNOT.**

**I invoked git rather than assuming** (read-only, no network):
```powershell
git -C $androrat rev-list --all --count     # 1
git -C $androrat rev-parse HEAD             # 1516f5e6cad261db33f7f5bb074377de72cc6d94
Get-Content $androrat\.git\shallow          # 1516f5e6cad261db33f7f5bb074377de72cc6d94
```
**The clone is depth-1 shallow: HEAD *is* the shallow boundary, and the object store holds exactly one commit.**
```
1516f5e6cad261db33f7f5bb074377de72cc6d94
Neeraj Singh <33444666+karma9874@users.noreply.github.com>
Wed Jan 3 00:14:41 2024 +0530
Update auto_close.yml
```
**`ahmyth` is the same** — one commit, `97465b123d08f42c433c68d6a7b51acd36891ec3`, `.git\shallow` present.

**So R-64.2, R-64.3 and R-64.6 cannot be closed from this corpus by any local operation.** Every file in both trees has exactly one recorded version, and **that version is the one already on disk and already measured.** The "git history would settle it" instinct is correct in principle and **unavailable in fact** — which is itself worth recording, because it is the difference between *unread* and *not present*: **the history is not unread, it was never cloned.** **[absence, established by invocation rather than presumed]**

**The probe that would actually settle R-64.2:** `git fetch --unshallow` (a network operation) or reference to the upstream `karma9874/AndroRAT` history — **both outside this lane.** **Stated as the concrete bound, not as a gap in effort.**

---

## §6 — Instrument-failure section

**My first pass at extracting the DEX strings was WRONG, and I am recording it because the error is instructive.**

**What I did:** converted `classes.dex` to an ASCII string and regex-matched for `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` and for 4–5 digit numerics.

**What it returned for the port:** `8888` **3×** and `8000` **1×**. **I nearly reported `8888` as the port — which would have "confirmed" D3's source value and been wrong.**

**Why it was wrong:** a DEX string pool is **length-prefixed and sorted, not NUL-delimited text**. Byte-level regex matching finds numeric runs **inside compiled data, encoded values, and identifiers** — the three `8888` hits were `ARGB_8888` (a real constant), a dexmap type descriptor, and binary noise. **Only one of the four candidate hits was a genuine string-pool entry.**

**What I did instead:** parsed the DEX header (`string_ids_size=26908`, `string_ids_off=0x70`) and **decoded all 26,908 strings through the length-prefix**, then filtered to exact matches. **That returned `string_id[3133]="192.168.43.113"` and `string_id[3136]="8000"` — authoritative, one each.**

**The lesson, and it is the corpus's own instrument-shape defect in a new medium:** *a substring match against a binary returns whatever the binary's non-string regions happen to contain.* **The wrong instrument produced a confident, plausible, wrong answer that agreed with a prior expectation — the most dangerous kind of failure.** A `8888` in the source tree plus a `8888` match in the artifact would have looked like confirmation of provenance when it was an `ARGB` constant.

**Second instrument note: `Select-String` is case-insensitive by default** (standing corpus rule). Every pattern in this report that needed case-sensitivity used explicit alternation or exact matching; **the SDK-floor search (`minSdk|targetSdk|uses-sdk|sdkVersion`) would have matched `minSdkVersion` and `MINSDKVERSION` alike — which is correct here, since I wanted any case.**

**Third: no REA provider was invoked.** All findings are filesystem and byte-level. **The provider would have been relevant for R-64.1/R-64.6 (manifest decode) and I did not invoke it** — the binary-XML decode was done by reading the AXML magic (`03 00 08 00`) to establish *that* it is binary, **not by decoding it.** **Any manifest content claim in this report is attributed to its source; the only decoded manifest values come from D37's `decode_android_resources`/`inspect_android_package` evidence (`ev_8705e044…`, `ev_b0783ca4…`).**

---

## §7 — What this report establishes

**1. The brief's Q1 artifact does not exist at the stated path.** `Compiled_apk\` is a decompiled input tree, not an APK. The committed APKs are in `Android_Code\app\release\` and were opened in D37. **What was genuinely unopened is `Compiled_apk\original\META-INF\` — a real signed build's certificate material, now identified.**

**2. The committed APK's server address, extracted verbatim from its DEX string pool: `192.168.43.113:8000`.** It is a **valid** IPv4 by the builder's own regex. **The brief's hypothesis — that the column arithmetic produced a malformed address — does not hold.** The mechanism is fragile; on this artifact it worked.

**3. The committed APK was NOT built from the committed template.** `config.smali` holds `127.0.0.1:8080`; the APK holds `192.168.43.113:8000`; the source holds `192.168.0.105:8888`. **Three residues, three different builds.** And because `build()` writes in place with no restore, **the template's committed value is not a declaration — it is leftover state.** **[family]**

**4. AhMyth's `192.168.8.100` is the author's own LAN address, and the template disagrees with its own source by one octet** (`192.168.8.100` smali vs `192.168.8.101` java). **Second independent proof that the template is a foreign build** — D49 proved the SDK floors differ; this proves the source bodies differ. **[family]**

**5. Correction to my own D49:** I wrote that "AhMyth never patches its own template, only the target's copy." **Wrong.** `AppCtrl.js:303` + `:313` + `:314` **rewrite `Factory\Ahmyth\...\IOSocket.smali` in place before every build.** **Both builders mutate their template and neither restores it** — D53's AndroRAT finding is an instance of a defect present in both codebases. **[family, both]**

**6. The SDK floor is never injected by either builder.** `Constants.js` and `AppCtrl.js` contain **no SDK token at all**. The produced floor is the **template's** (`minSdk 10`/`targetSdk 18`, synthesised by apktool from `apktool.yml` — the template manifest has no `<uses-sdk>`) when binding is off, and **the victim's** when binding is on, because the builder patches the victim's manifest and copies only smali. **On the binding path the artifact carries two floors: the manifest's (victim) and the bytecode's (18).** **[absence, with positive control]**

**7. R-53.1 stays open, with a written probe and a named reason** — it needs a build, which is out of lane. **Not guessed.**

**The through-line:** both builders are **stateful, in-place, and record-free**. They overwrite their templates, they never restore them, they never write down what they did, and **the committed tree therefore contains artifacts and inputs that do not agree, with nothing on disk to say which came first.**

**And the obvious rescue — git history — is not merely unread, it is absent: both clones are depth-1 shallow with exactly one commit.** The disagreement between `config.smali` and the committed APK is **permanent within this corpus**: no local operation can order them, and the two candidate explanations (different checkout / earlier builder) **cannot be separated here.** That is a bound worth stating plainly rather than a loose end.

**Every finding above is a consequence of the builders' one shared design choice — mutate in place, record nothing — and the corpus's inability to resolve the resulting disagreement is a consequence of the clone method.**

