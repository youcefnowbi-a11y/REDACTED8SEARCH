# D53 — The mobile builder defects

**Scope owner:** android-diver
**Target:** the *builder* layer of both mobile RATs, not the implants.
**Method:** full source read of `AppCtrl.js` (421 L, complete) and `utils.py` `build()` (L356-402); collision cases constructed and executed as simulations. No REA provider. No execution of either builder. No network.

**Blast-radius framing, applied per finding:** a defect in a builder is a defect in **every artifact that builder produces**. Where a finding affects one committed binary it is marked **[instance]**; where it affects the whole output family it is marked **[family]**.

---

## §0 — Correction to the brief, lead with it

**The brief's Q4 premise is wrong, and the truth is more interesting.**

The brief asks: *"does a BUILDER exist in that tree at all, or is the committed APK hand-made? … If it does not, that asymmetry IS the answer to why D37 verified provenance 6/6 and you could not."*

**AndroRAT has a builder. It is `androRAT.py --build` → `utils.py:build()` (L356-402).** It is a full payload generator: patches a smali template, runs `apktool b`, signs with `sign.jar`. **The same five-stage design as AhMyth's.**

**So the asymmetry D49 named is not "builder vs no builder" — it is a different and sharper thing, and §4 states it.** The short version: **AndroRAT's builder patches a template that is *also the committed artifact*, and the template's current on-disk values are islandic defaults (`127.0.0.1`/`8080`) that match neither the source nor the shipped APK.** D37 verified the *APK*; the *builder* was never in question because it was never looked for.

**The brief's four questions remain answerable and three produce findings.** Q2 escalates with a constructed case (§2). Q3 confirms with an exact fragment (§3). Q1 yields a defect the brief did not anticipate (§1) — **the one in `utils.py`, not `AppCtrl.js`.**

---

## §1 — Q1: `AppCtrl.js` in full, step by step

**One packaging fact that governs the whole pipeline:** `AhMyth-Server\package.json` declares `"asarUnpack": "**/app/Factory/**/*"`. **The template is deliberately kept outside the Electron asar archive so it exists as real, writable files at runtime** — which is why `Constants.js` calls `.replace("app.asar", "app.asar.unpacked")` on all three template paths (`ahmythApkFolderPath`, `apktoolJar`, `signApkJar`). **The design requires the template to be mutable on disk**, and the bundled `apktool.jar` is a build input, not a library.

### 1.1 The pipeline, in execution order

| # | Line | Step | Failure mode | Handler |
|---|---|---|---|---|
| 1 | :290-299 | validate ip/port | empty ip; port out of range | **present** — explicit log + return |
| 2 | :305 | `fs.readFile` `IOSocket.smali` | file missing | **present** — logs, returns |
| 3 | **:313** | **the substitution** | **markers absent** | **ABSENT — silent malformation** |
| 4 | :314 | `fs.writeFile` | disk/permission | present — logs, returns |
| 5 | :322 *or* :338 | `GenerateApk` *or* `apktool d` | apktool fails | **partially present** — :341 logs, returns |
| 6 | :163 | `fs.copy` smali over target | copy fails / collides | **partial** — logs on error, **no collision check** |
| 7 | :129 | `apktool b` | build fails | present — :132 logs, returns |
| 8 | :137 | `sign.jar` | sign fails | present — :140 logs, returns |
| 9 | :145 | `fs.unlink` unsigned apk | unlink fails | **`throw err` — uncaught in callback** |

### 1.2 The silent-failure paths, named by line

The brief asks me to find "every OTHER silent-failure path of that shape" as :313. **There is exactly one more, and it is worse than :313.**

**(a) `:313` — the unguarded substitution** *[family]*

```js
var result = data.replace(data.substring(data.indexOf("http://"),
                                         data.indexOf("?model=")),
                          "http://" + ip + ":" + port);
```
If either marker is absent, `indexOf` returns `-1`. **`String.prototype.substring` clamps negative arguments to 0, so `substring(-1, -1)` returns the empty string** — and `replace("", ...)` **prepends the new URL to the front of the entire file.**

**Verified by execution, not assumed** (Node, this session):
```js
data.substring(-1, -1)                      // ""
data.replace(data.substring(-1,-1), "http://9.9.9.9:1234")
// => "http://9.9.9.9:1234.class public LX;\n.source \"X.java\"\n..."
```
**The result is a `.smali` file with a raw URL spliced before `.class`** — a parse error apktool will report at the next stage, **but the error message names the build, not the substitution.** The operator sees "Building Failed" plus a smali syntax error, with no indication that the IP patch corrupted the file. **The file was already overwritten on disk at :314.**

**(b) `:145` — `throw err` inside an async callback, with no `try`/`catch`** *[family]*

```js
fs.unlink(path.join(outputPath, CONSTANTS.apkName), (err) => {
    if (err) throw err;
```
Throwing inside a Node callback with no enclosing handler is an **uncaught exception** — it terminates the Electron main process rather than logging. **This is the inverse of :313: instead of a silent failure it is a loud process kill, and neither is a handled error.** The log at :149 that tells the operator the build succeeded is *inside this callback and after the unlink*, so a failed unlink means **the operator never sees the success message for a build that in fact succeeded.**

**(c) `:104` — the file dialog's undefined check is unreachable** *[instance]*

```js
dialog.showOpenDialog(function(fileNames) {
    if (fileNames === undefined) { $appCtrl.Log("No file selected"); }
```
Electron is pinned at **`^9.2.0`** (`AhMyth-Server\package.json`, devDependencies). **In the Electron 9 callback API, cancellation passes an empty array, not `undefined`.** The check never fires; the code proceeds to `fileNames[0]` → `undefined` → `readFile(undefined)` sets `$appCtrl.filePath = undefined`. **The wrong branch is guarded and the right one is not.** The consequence is bounded: `:330` catches it (`!filePath.includes(".apk")` would itself throw on `undefined`) — **so cancelling the dialog throws instead of logging "No file selected."** **[read; the Electron-9 callback shape is from the pinned version, not observed at runtime]**

**(d) `:96` — `$$phase` guard is a race, not a guard** *[instance]*

`if (!$appCtrl.$$phase) $appCtrl.$apply();` — `$$phase` is AngularJS-internal and unset outside a digest. In the callback contexts used here it is always falsy, so `$apply()` is always attempted. A log emitted *during* a digest throws `$digest already in progress`. **This is a known foul in this idiom and is worth stating as latent rather than observed — no run was performed.**

### 1.3 What :313 does NOT do

**It does not validate the result.** Even when both markers are present, there is no check that the written file still parses, that the URL is well-formed, or that `ip` is an address. **`:291` checks only that `ip` is non-empty.** A string like `"; rm -rf /` is accepted and spliced.

---

## §2 — Q2: the collision case, CONSTRUCTED

**The flag escalates. Here is the concrete string.**

`copyPermissions` (:176-191) extracts a name and tests it against the **entire manifest head, as a bare substring**:

```js
var permissionName = permArray[i].substring(permArray[i].indexOf('name="') + 6);
permissionName = permissionName.substring(0, permissionName.indexOf('"'));
if (firstPart.indexOf(permissionName) == -1) { firstPart = firstPart + "\n" + permArray[i]; }
```

**The injection list contains two entries where one is a substring of the other:**
```
android.hardware.camera            <-- + '+<uses-feature android:name="android.hardware.camera" />'
android.hardware.camera.autofocus  <-- <uses-feature android:name="android.hardware.camera.autofocus" />
```

**The collision, executed as a simulation.** A target app that declares the autofocus feature — any barcode scanner, camera app, or document scanner:

```xml
<manifest package="com.victim.app">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-feature android:name="android.hardware.camera.autofocus" android:required="true"/>
  ...
```
Result of running the real algorithm:
```
ADD    android.permission.WAKE_LOCK
ADD    android.permission.CAMERA
SKIP   android.hardware.camera              <-- indexOf found it inside ...camera.autofocus
SKIP   android.hardware.camera.autofocus
```
**The `android.hardware.camera` feature is silently NOT injected, because its name is a literal substring of a different feature the app already declared.** The test cannot distinguish "this exact feature is present" from "this string occurs somewhere."

### 2.1 Severity — bounded honestly

**I constructed the collision and I am not overstating it.** The affected entries are `uses-feature`, and `uses-feature` is an **install-time device filter**, not a runtime gate. The implant's camera use depends on `android.permission.CAMERA`, **which the simulation shows is still injected.**

**So: the defect is real, reproducible, and load-bearing for correctness — but it does not disable the implant.** I tested the permission namespace exhaustively against 32 real Android permissions and **found no permission-vs-permission prefix collision.** The affected surface is the two `uses-feature` entries, and the consequence is a payload that does not declare a camera capability it uses. **Stated as bounded, not inflated.**

**Blast radius: [family]** — every artifact built from a target declaring `camera.autofocus`.

---

## §3 — Q3: the unconditional splice at :210, CONFIRMED

```js
var newManifest = permManifest.substring(0, permManifest.indexOf("</application>"))
                + ahmythService + ahmythReciver
                + permManifest.substring(permManifest.indexOf("</application>"));
```
**No presence check. The splice is unconditional**, and it operates on the file already written at :211.

**What is added, read verbatim from `Constants.js`:**
```xml
<service android:enabled="true" android:exported="false" android:name="ahmyth.mine.king.ahmyth.MainService"/>
<receiver android:enabled="true" android:exported="true" android:name="ahmyth.mine.king.ahmyth.MyReceiver">
  <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
</receiver>
```

**Running the builder TWICE against the same decompiled folder — simulated with the real algorithm:**

```
RUN 1 →  MainService occurrences: 1    MyReceiver occurrences: 1
RUN 2 →  MainService occurrences: 2    MyReceiver occurrences: 2
```

**The duplicated fragment, exactly as produced:**
```xml
      <service android:enabled="true" android:exported="false" android:name="ahmyth.mine.king.ahmyth.MainService"/>
      <service android:enabled="true" android:exported="false" android:name="ahmyth.mine.king.ahmyth.MainService"/>   <!-- RUN 2 duplicate -->
      <receiver android:enabled="true" android:exported="true" android:name="ahmyth.mine.king.ahmyth.MyReceiver">
        <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
      </receiver>
      <receiver android:enabled="true" android:exported="true" android:name="ahmyth.mine.king.ahmyth.MyReceiver">     <!-- RUN 2 duplicate -->
        <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
      </receiver>
```

**Why the operator triggers this easily:** the decompiled folder is created at :338 with `-f` (force) into `<apk>.apk`-minus-extension, and the build is started by a button (:288). **A second click — because the first appeared to hang, or the operator changed the IP — re-runs :210 against the already-modified manifest.** The `-f` on `apktool d` means re-*decompiling* would refresh the folder, but that only happens on a fresh Browse-and-Build, not on a repeat of the Build step for an already-decompiled target.

**Manifest consequence:** duplicate `<service>`/`<receiver>` declarations for the same component name are a manifest-merger conflict; apktool will emit them and `aapt`/`aapt2` behaviour on the duplicate varies by build-tools version. **The `BOOT_COMPLETED` receiver declared twice means two receivers for one action — the agent starts twice on boot.** **[family]** — affects every build where the operator clicks Build more than once for one target.

---

## §4 — Q4: AndroRAT's builder — it exists, and it is the sharper asymmetry

### 4.1 The builder is `utils.py:build()` (L356-402)

```
L357  editor = "Compiled_apk/smali/com/example/reverseshell2/config.smali"
L361  file[18] = file[18][:21] + "\"" + ip   + "\"" + "\n"
L362  file[23] = file[23][:21] + "\"" + port + "\"" + "\n"
L363  file[28] = file[28][:15] + " 0x0"/" 0x1" + "\n"     # icon flag
L376  java -jar Jar_utils/apktool.jar b Compiled_apk -o <output>
L385  java -jar Jar_utils/sign.jar -a <output> --overwrite
```
**Read: `String.substring`/`.substring` slicing by a HARD-CODED column index.** The template's on-disk state confirms the targets:

```
 19:     const-string v0, "127.0.0.1"     <-- [:21] patch site
 24:     const-string v0, "8080"          <-- [:21] patch site
 29:     const/4 v0, 0x1                  <-- [:15] patch site
```
`"    const-string v0, "` is exactly 21 characters, so `[:21]` discards the old literal and the new one is written fresh. **[read, verified by executing the substring arithmetic]**

### 4.2 The defects, and one the brief did not anticipate

**(a) `build()` MUTATES THE TEMPLATE BEFORE IT BUILDS — and does not restore it on failure.** *[family]*

`L359` opens `config.smali`, `L365` writes it, and **only then** does `L376` attempt the build. If the build fails at L382, the code prints `"Building Failed"` and returns — **leaving `config.smali` holding the last operator's IP and port.** The next operator who builds inherits them as the starting point. **This is why the committed template reads `127.0.0.1`/`8080` and not the source's `192.168.0.105`/`8888` (D3 §9): the committed value is not the developer's intent, it is the residue of whatever build last ran in that checkout.** **The template is not a template; it is a mutable workspace that happens to be committed.**

**(b) `is_valid_ip` and `is_valid_port` are DEFINED AND NEVER CALLED.** *[family]*

```
utils.py:63  def is_valid_ip(ip):    ... regex + 0-255 range check
utils.py:67  def is_valid_port(port): ...
```
**Grep for both names across `utils.py` and `androRAT.py` returns only the definitions — zero call sites.** The validation exists, is correct, and is dead code. `build()` receives `ip` and `port` straight from `argparse` and writes them into smali with no check.

**(c) The column-index coupling is silent under template change.** *[family]*

`file[18]`, `file[23]`, `file[28]` are **positional**. If `config.java` gains a line, or the template is rebuilt and line numbers shift, **the patch lands on the wrong line** — writing `"\"" + ip + "\""` onto an arbitrary smali statement. There is no check that line 19 contains a `const-string`, or that the patch produced a parseable file. **The developer flags this in the source itself:**
```python
#Very much uncertaninity but cant think any other way to do it xD
```
**A comment admitting the mechanism is fragile is evidence, and it is the only place in either builder that anyone acknowledged the technique's weakness.**

### 4.3 The real asymmetry — and it corrects D49

**Both targets have a builder. The difference is what each builder's template IS.**

| | AhMyth | AndroRAT |
|---|---|---|
| builder | `AppCtrl.js` (421 L) | `utils.py:build()` (47 L) |
| template location | `Factory\Ahmyth\` — **a dedicated directory** | `Compiled_apk\` — **the committed output tree** |
| patch method | substring between markers | **hard-coded line/column index** |
| template vs shipped artifact | template ≠ any shipped APK | **template IS the tree the APK was built from** |
| committed state | template holds dev's own `192.168.8.100:42474` | holds `127.0.0.1:8080` — **last-run residue** |
| restore on failure | n/a (template only patched on success path) | **none — mutation persists** |

**The asymmetry relevant to D37's 6/6 provenance verification:** **AndroRAT's `Compiled_apk\` is the build input *and* the build record.** When D37 verified the shipped APK against the committed source and found 6/6 identity fields and 18/19 classes matching, **what it verified is that the APK corresponds to the source tree — and the builder's template is that same tree, sitting in the repository, un-run since the last commit.** `config.smali` on disk holds `127.0.0.1`/`8080`; the shipped APK holds `192.168.43.113`/`8000` (D3 §9). **Those disagree, and that disagreement is the residue: the committed `Compiled_apk` was last patched by a build that is not the build that produced the shipped release APK.**

**AhMyth cannot be checked this way at all**, because its template lives apart from any output and is patched per-operator. **That — not "builder vs no builder" — is why provenance verification worked on one and not the other.** *[family, both]*

---

## §5 — Findings ranked by blast radius

| # | Finding | Class | Scope |
|---|---|---|---|
| 1 | `build()` mutates template pre-build, no restore | **[family]** | every AndroRAT build after a failure |
| 2 | `:313` unguarded substitution → silent file corruption | **[family]** | every AhMyth build against a marker-less template |
| 3 | `:210` unconditional splice → duplicate components on re-run | **[family]** | every AhMyth build where Build is clicked twice |
| 4 | `is_valid_ip`/`is_valid_port` dead | **[family]** | every AndroRAT build |
| 5 | `uses-feature` substring collision | **[family]** | AhMyth builds into apps declaring `camera.autofocus` |
| 6 | hard-coded `file[18]/[23]/[28]` coupling | **[family]** | every AndroRAT build after a template change |
| 7 | `throw err` at `:145` kills the Electron process | **[family]** | AhMyth builds where the unlink fails |
| 8 | `:104` cancellation check unreachable | **[instance]** | operator UX only |
| 9 | `:96` `$$phase` guard | **[instance, latent]** | not observed |

**Six of nine are family-scoped. That is the finding of this report: the builder layer is where the defects concentrate, and they are systematic rather than incidental.**

---

## §6 — Residual unknowns

| ID | Unknown | Probe |
|---|---|---|
| **R-53.1** | Whether apktool's manifest writer rejects or emits the duplicated `<service>` from §3 — **I simulated the string splice, not apktool's build** | run apktool on a manifest with duplicate components; or read apktool's `AndroidManifestResourceParser` |
| **R-53.2** | Whether `substring(x, -1)` in the *bundled* JS engine behaves as standard JS (swap/empty) | the behaviour is spec'd for V8; Electron version not confirmed in-tree |
| **R-53.3** | The exact apktool/sign.jar versions bundled by AndroRAT vs AhMyth | read `apktool.jar` manifest (`Factory\` 17661172 B vs AhMyth's); **not opened** |
| **R-53.4** | Whether any *other* target-app declaration substring-collides with the 15 permission entries | my test covered 32 real permissions; **a corpus of real manifests would be the real test** |
| **R-53.5** | Whether the shipped AndroRAT APK's `config` values came from the same commit as `Compiled_apk` | D3 §9 has the three values; **the commit provenance is not recoverable from the tree** |

**No residual blocks a finding.** Each is bounded.

---

## §7 — The line worth keeping

**D49 said the defects live in the builder. This pass found nine of them, six of them family-scoped, and the sharpest one is not in the file the brief pointed at** — it is in `utils.py:build()`, where the payload template is overwritten before the build is attempted and never restored, which is why the committed template holds an address that matches neither its own source nor its own shipped artifact.

**And the asymmetry that mattered was not builder-vs-none. It was template-as-output versus template-as-workspace: AndroRAT committed the very tree it builds from, which is precisely what let D37 check its provenance — and precisely what AhMyth's separated template makes impossible.**
