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
