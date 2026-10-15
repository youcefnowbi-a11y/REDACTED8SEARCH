# D6 — Pupy IOC / hardcoded-value extraction

Extracted from `RE_Library/01_SOURCE_c2/pupy`. Every entry cites its defining source line.
Companion to `D6_pupy_code.md`. Source-only; no Ghidra/REA provider used.

---

## 1. Network fingerprints (highest detection value)

### 1.1 WebSocket path — deterministic, secret-derived, STATIC
```
^/ws/[0-9a-f]{8}$
```
Derivation: `/ws/` + `md5(PATH_GEN_SECRET + b"ws").hexdigest()[:8]`
- **Constant for a given `PATH_GEN_SECRET`, for all victims and all time. No per-session nonce.**
- Only 32 bits, fixed known suffix `b"ws"`.
- Applies to `ws` and `dfws` transports.
`[source: pupy/network/transports/ws/conf.py:46, :51]`

### 1.2 WebSocket User-Agent — exact string
```
Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36
```
2017 Chrome 60 claiming Windows 7. Emitted verbatim by `ws` and `dfws`.
`[source: pupy/network/transports/ws/conf.py:16-18]`

### 1.3 DNS channel character set
```
abcdefghijklmnopqrstuvwxyz0123456789-.
```
In-band terminator `\0`; 4-bit code `15` in the `generic` Huffman table.
Detect by label entropy/length and query volume, not character set.
`[source: pupy/network/lib/picocmd/dns_encoder.py:14, :72; dns_encoder_table.py:8]`

### 1.4 Traffic-analysis defeat
`obfs3` prepends random padding (`MAX_PADDING = 8194`) to defeat packet-length
fingerprinting. Present and layered **under** RSA/AES.
`[source: pupy/network/lib/transports/obfs3/obfs3.py:27, :231-232]`

---

## 2. Free-DNS rendezvous domains (`FREEDNS`, 247 entries)

Default fallback channel host list. Encoded as a **single byte index**, so the
first decoded byte identifies which provider was used.
Full tuple: `[source: pupy/network/lib/picocmd/dns_encoder.py:16-70]`

Selected (see §4.5 of `D6_pupy_code.md` for the full discussion):
```
chickenkiller.com  mooo.com  ignorelist.com  h4ck.me
pixelfucker.com  stfu-kthx.net  crabdance.com  farted.net
madhacker.biz  mindhackers.org  hackquest.com  inmotionhosting.com
now.im  my.to  us.to  uk.to  qc.to  d-n-s.name
info.gf  mine.bz  info.tm  home.kg  dyn.mk  z0d.eu
strangled.net  violated.me  possessed.us  enemyterritory.org
```

---

## 3. Credentials and key material (ALL shipped in-repo)

| Secret | Value | Location |
|---|---|---|
| Bind payload password | `PuPyD3f4ultP4sSw0rd` | `network/transports/__init__.py:27` |
| DNSCNC **private** key | `XqYoPdC5LR8Ct0givPQRBlKv41o=` | `:30` |
| DNSCNC public key | `v6iJnUBFI1qeQ9jrP2NZsTd4qwYB` | `:29` |
| TLS **private** key (plaintext PKCS#8) | `MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDcqttkD+a+YvSd...` | `:70-99` |
| TLS certificate | `MIIDczCCAlugAwIBAgIJAK4ksVkg9NIl...` — serial `AK4ksVkg9NIl` | `:47-69` |
| RSA public key (2048b) | `-----BEGIN RSA PUBLIC KEY-----` `MIICCgKCAgEA...` | `:32-46` |

**Two complete private keys ship in-repo** (TLS + DNSCNC). The RSA key is
public-only with **no matching private key** in the tree.

Certificate DN — author fingerprints, and it **expired 2019-04-11**:
```
C=FR  ST=POU  L=JAIUY  O=LOLITA  OU=S COMME ?
serial AK4ksVkg9NIl   notBefore 2016-07-15   notAfter 2019-04-11
```
`[source: network/transports/__init__.py:47-69]`

---

## 4. Cryptographic constants

| Value | Literal | Location |
|---|---|---|
| ECPV default curve | `brainpoolP160r1` → default hash **SHA1** | `ecpv.py:65` |
| ECPV checksum | SHA-1, `[:4]` → **32-bit tag, key-prepended, not HMAC** | `ecpv.py:283-289, 299-305` |
| ECPV cache | module-global `deque(maxlen=64)`, never cleared, holds private keys | `ecpv.py:35, :53` |
| EC4 curve / hash | `brainpoolP384r1` / explicit `SHA384` | `ec4.py:38-46` |
| EC4 KEX size | `key_size=128` (**128 bytes**) | `ec4.py:65, :74` |
| EC4 ciphers | `RC4(key[0])` encrypt / `RC4(key[1])` decrypt, halves = reversed | `ec4.py:78-79` |
| EC4 keystream discard | `b'\x00'*3072` + CIA NOD doc URL | `ec4.py:83-84` |
| EC4 length prefix | `struct.pack('H', ...)` — **native endianness** | `ec4.py:71, :116` |
| obfs3 padding / pubkey / key | `8194` / `192` / `16` (exact Tor obfs3 constants) | `obfs3.py:27, :29, :30` |
| obfs3 magic | `hmac_sha256_digest(shared_secret, magic_const)` — **correct HMAC** | `obfs3.py:227, :237` |
| RSA transports | `rsa_key_size=4096, aes_size=256` in 5 confs | `rsa/conf.py:35,39` etc. |

---

## 5. Protocol magic and control constants

| Value | Literal | Location |
|---|---|---|
| Ping control magic | `b'\x00CTRL\x00V1'` | `network/lib/connection.py:62` |
| Brine SC protocol version | `BRINE_VER_1 = 1` | `connection.py:61` |
| Control code NOP | `CONTROL_NOP = 0` | `connection.py:54` |
| Control code enable V1 | `CONTROL_ENABLE_BRINE_EXT_V1 = 1` | `connection.py:55` |
| DNS table selectors | `FREEDNS=0b00 TLDS=0b01 TERM=0b10 GENERIC=0b11` | `dns_encoder.py:345-348` |
| Reflective run-inline signal | `lpReserved == (LPVOID) 0x1` | `client/sources-windows-py3/main_reflective.c:55` |
| Reflective do-not-start | `lpReserved == (LPVOID) 0x2` | `main_reflective.c:64` |
| MemoryModule query | `DLL_QUERY_HMODULE` | `main_reflective.c:43-46` |
| Window class | `"DummyWindowClass"` | `pupy_load.c:30` |
| Unused constant | `#define REFLECTIVE_SPECIAL 5` — never referenced | `main_reflective.c:16` |

---

## 6. Persistence and privilege artefacts

```ini
# pupy/conf/pupy.conf.default:178-181
[persistence]
preferred_methods = 2,8,3,9
name = OneDriveUpdate
```
- Default persistence name masquerades as **OneDrive's updater**.
- Four ordered WinPwnage technique IDs.
- **Install-only; `# TODO persistence removal` at `modules/persistence.py:73`.**
- **Windows implementation `pupwinutils/persistence.py` IS ABSENT** — imported at
  `scriptlets/persistence.py:29` and listed as a dependency at `:9`, but the file
  does not exist. Windows persistence is non-functional as-shipped.
- Linux counterpart IS present: `packages/linux/all/persistence.py` (13,088 B).

```ini
# pupy.conf.default:174-176
[bypassuac]
preferred_methods = 1,2,3,4,8,9,10
```
`[source: pupy/conf/pupy.conf.default:174-181; pupy/scriptlets/persistence.py:9,29,66-67]`

---

## 7. Host and process artefacts

| Value | Literal | Location |
|---|---|---|
| Target interpreter | `python310.dll` (version-locked 3.10) | `client/common/Python-dynload.c:140` |
| PStore default root | `config.get('pstore', '~')` — user home | `agent/__init__.py:990` |
| Stdlib path marker | `VPATH_PREFIX`, `.pyo`, `/__init__.pyo` | `Python-dynload.c:634-733` |
| malloc'd payload scrub | `OSUnmapRegion(library_c_start, library_c_size)` | `Python-dynload.c:100` |

---

## 8. Notable absences (verified negatives)

- **No AMSI bypass code** — grep of `Python-dynload.c` for `AMSI|amsi|AmsiScan`
  returns zero matches. Inapplicable by architecture: no .NET, bytecode-only (no
  script text), `MemLoadLibrary` bypasses `LoadLibrary` hooks.
  `[source: §1.13]`
- **No transport-swap function** — grep of `connection.py` (33,937 B, 1,113 lines)
  for `def switch|swap|change|set_transport` returns nothing. Transport is fixed
  at `TransportConf.__init__`.
  `[source: connection.py; §10 U-2]`
- **No `allow_v1` config key** — tree-wide; mechanism is `ENCODER_V1 = 0` selected
  by `node.version == 1`, a CLI flag, and `_unpack_v1`.
  `[source: picocmd/server.py:335,1109; commands/dnscnc.py:98; §4.8]`
- **No `pupwinutils/persistence.py`** — see §6.

---

## 9. Counts (measured, correcting T6/brief)

| Item | Brief/T6 | Measured |
|---|---|---|
| `.py` files | 576 | **509** |
| Transports | 10 | **13** |
| Native C/H/Go omitted | — | **31 .c, 34 .h, 9 .go** |
| `picocmd/` stack | not mentioned | **8 files, 173,581 B** |
| `dns_encoder_table.py` | ~22 KB file | **8 lines, one 22,289-char literal** |

---

## 10. picocmd protocol constants (added — U-1 closure, §13)

### 10.1 Wire framing — exact struct
```
[ CRC32  4 B BE signed ][ cmd_id 1 B ][ payload … ][ cmd_id 1 B ][ payload … ] …
```
One CRC32 prefix over the **entire** remainder, then a **repeating** `[cmd_id][payload]` sequence to end-of-buffer. No length prefix; each command's `unpack` reports its own consumed byte count.
`[source: pupy/network/lib/picocmd/picocmd.py:1792-1796, :1812, :1818-1823]`

### 10.2 Checksum
- **`binascii.crc32(payload)` — UNKEYED.** The `nonce` parameter is accepted and **never referenced** by `_gen_crc32`/`_check_crc32`.
- Packed/unpacked as **`'>i'` (big-endian, SIGNED int32)** — latent hazard for CRCs with bit 31 set; correct form is `'>I'`.
- **Not** an HMAC. Zero adversarial resistance. Distinct from (and weaker than) the ECPV SHA-1 `gen_csum` in §2.
`[source: picocmd.py:1779-1787]`

### 10.3 Command ID dispatch table — positional ordinals
| ID | Command | ID | Command |
|---|---|---|---|
| 0 | `Poll` | 15 | `SystemStatus` |
| 1 | `Ack` | 16 | `SetProxy` |
| 2 | `Policy` | 17 | `OnlineStatusRequest` |
| 3 | `Idle` | 18 | `OnlineStatus` |
| 4 | `Kex` | 19 | `ConnectablePort` |
| 5 | `Connect` | 20 | `PortQuizPort` |
| 6 | `PasteLink` | 21 | `PupyState` |
| 7 | `SystemInfo` | 22 | `CustomEvent` |
| 8 | `Error` | **23** | **`SystemInfoEx` ← V2 begins** |
| 9 | `Disconnect` | 24 | `ConnectEx` |
| 10 | `Exit` | 25 | `RegisterHostnameId` |
| 11 | `Sleep` | 26 | `DataTransferControl` |
| 12 | `Reexec` | 27 | `DataTransferPayload` |
| 13 | `DownloadExec` | 28 | `InBandExecute` |
| 14 | `CheckConnect` | | |

IDs derive from **position in the constructor call**, not explicit numbering. Author comment: `"In other case make break something"`.
`[source: picocmd.py:1746-1757, :181-206]`

### 10.4 Version branch
- `SystemInfoEx.unpack` reads **`version = ord(data[0])`**; `version == 1` → `_unpack_v1`; **anything else → `NotImplementedError`**. V2 is not implemented at this point.
- `SystemInfoEx` uses a **flag bitfield with type-dependent widths**: IPv4 = 4 B, IPv6 = 16 B, selected by nested flag bits.
`[source: picocmd.py:1331-1345, :1351-1357]`

### 10.5 `DataTransferControl` field widths
- `action` 2 bits (0–3: START/CANCEL/FINISH/CORRUPTED); `transfer_id` 4 bits (≤ 0xF); `total_size` uint16; `crc` uint32.
- Wire order **`'>HI'` (big-endian)** — note this **contradicts EC4's native-order `'H'`** length prefix. Opposite endianness in two framing layers of the same product.
`[source: picocmd.py:1517-1537, :1570, :1584; lib/transports/ec4.py:57]`

---

## 11. Native build artefacts (added — U-4 closure, §14)

| Indicator | Value | Source |
|---|---|---|
| `_pupy` module name | `"_pupy"`, doc `"Builtins utilities for pupy"` | `pupy.c:24, :449` |
| Build revision string | `GIT_REVISION_HEAD` embedded as `_pupy.revision` | `pupy.c:471` |
| Dedicated exception | `_pupy.error` | `pupy.c:472` |
| `DllMain` args sentinel | `lpReserved > 0xFFFF` ⇒ cast to `_pupy_pyd_args_t*` | `pupy.c:505-507` |
| Injection order | remote thread → **APC fallback** | `base_inject.c:582-591` |
| Remote buffer protection | alloc `PAGE_READWRITE`, then loader pages → `PAGE_EXECUTE_READ`, 16 KiB from page-aligned base | `base_inject.c:566, :577-579` |
| Reflective imports | resolved by **hash** (`dwModuleHash`/`dwFunctionHash`) | `ReflectiveLoader.c:43-52` |
| Position independence | `caller()` via `_ReturnAddress()`, `__declspec(noinline)` | `ReflectiveLoader.c:38` |
| Instruction cache | `NtFlushInstructionCache` **commented out** | `ReflectiveLoader.c:68` |
| Core dumps | `RLIMIT_CORE` → 0/0 (disabled) | `sources-linux-py3/pupy_load.c:52-54` |
| FD limit | `RLIMIT_NOFILE` → hard max | `sources-linux-py3/pupy_load.c:46-50` |
| memfd camouflage | memfd **named `"libc.so.6"`** in release builds | `memfd.h:61` |
| memfd syscall numbers | **319 x86_64 / 356 i386 / 385 arm** — **no aarch64 branch** | `memfd.h:17-25` |
| Android `sys.executable` | rewritten to literal `'PythonService'` | `android_sources/main.py:15` |
| Android `platform.system` | monkey-patched to `lambda: 'android'` | `android_sources/main.py:9` |
| PyOxidizer bytecode | `bytecode_optimize_level_two = True` (**`-OO`**, assertions removed) | `pyoxidizer.bzl:34` |
| PyOxidizer loading | `allow_in_memory_shared_library_loading = True` | `pyoxidizer.bzl:28` |
| PE header cleanup | `CleanupHeaders` zeroes headers post-map | `MemoryModule.c:891` |
| Export filtering | `isAllowedSymbol` + `fnv1a` + `BuildExportTable` | `MemoryModule.c:738, :749, :814` |

**`memfd` named `libc.so.6`** and the **`-OO` assertion removal** (which silently disables `dns_encoder.py:277`'s `assert(found)`) are the two highest-value findings in this block.
`[sources as tabulated]`

---

## 12. Shipped-broken features (detection-relevant negatives)

Two advertised capabilities **do not exist in any shipped payload**. Both are worth recording because a detector or analyst who assumes them will mis-scope the threat.

### 12.1 Windows persistence — MISSING IMPLEMENTATION

- **`pupwinutils/persistence.py` does not exist.** Referenced at `scriptlets/persistence.py:9` (dependency list), `:29` (`from pupwinutils.persistence import add_registry_startup`), `:66` (call), `:67` (error log).
- **`pupwinutils.persistence` is the ONLY unresolved `pupwinutils.*` reference in the tree** — every sibling resolves.
- Config ships and is defaulted: `pupy.conf.default:178-181` (`name = OneDriveUpdate`, `preferred_methods = 2,8,3,9`).
- Net: `ImportError` at scriptlet load on Windows. Linux implementation **does** exist (`packages/linux/all/persistence.py`, 13,088 B).
- Removal unimplemented on all platforms (`# TODO persistence removal`, `modules/persistence.py:73`).
`[source: D6 §11.1, §13.7, §17]`

### 12.2 JVM introspection module — COMMENTED OUT

- **`setup_jvm_class()` prints `"NOT IMPLEMENTED: broken jvm setup"` and returns NULL**; its body and the `PyModuleDef` are inside `/* */`.
- **All 9 `JVM_Methods` are dead code** — the table is never passed to `PyModule_Create`.
- **Dead at 3 independent levels:** implementation gutted (`jni_on_load.c:899-911`); call sites commented (`Python-dynload.c:326`, `sources-linux-py3/pupy.c:539` — both `//setup_jvm_class();`); empty stubs defined (`sources-windows-py3/main_exe.c:41`, `sources-linux-py3/main_exe.c:22` — `void setup_jvm_class(void) {}`).
- **There is no `jvm` Python module at runtime.** `import jvm` fails.
- `JNI_OnLoad` IS live (`:923-1012`) — caches `__jvm`, attaches on `JNI_EDETACHED`, resolves `java.lang.Thread`. State is cached and never exposed.
- **Abandoned capability (recorded for completeness):** borrowing an app-visible **classloader** to load attacker Java classes — `__multi_FindClass` (`:783`), thread/classloader enumeration (`:153`, `:246`, `:566`), `__find_preferred_classloader` (`:306`, `:374`), `ClassLoader.findClass` cached as `__j_ClassLoader_findClass` (`:12`).
`[source: client/common/jni_on_load.c:6-16, :153, :246, :306, :374, :566, :783, :870-911, :923-1012]`

### 12.3 The pattern

| | Persistence | JVM module |
|---|---|---|
| Implementation | **missing file** | **present, commented out** |
| Tombstone | none | `"NOT IMPLEMENTED: broken jvm setup"` |
| Severed at | 1 level | **3 levels** |
| Style | oversight | deliberately disabled, self-labelled broken |

Both are advertised by their own interface; neither works. The second is self-documenting — the author knew and shipped it anyway.
`[source: D6 §18.5]`

### 12.4 THIRD instance — the Android payload is a placeholder

- **`android_sources/pp.py` (138 B) is a stub:** `def main(): print("pp.py is not replaced with working one!"); time.sleep(1)`.
- **`android_sources/main.py:19-25`** drives it in an **unbounded loop** (`while True` → `pp.main()` → on exception `traceback.print_exc()` + `time.sleep(10)`, no exit, no backoff).
- **A shipped Android build loops forever printing that string.** The real `pp.py` was meant to be substituted by the build pipeline and never was.
- **Most severe of the three** — unconditional: persistence and the JVM module are dead everywhere, but the Android payload is inert **by default build**.

| # | Feature | Defect class | Severity |
|---|---|---|---|
| 1 | Windows persistence | **missing file** | unreachable |
| 2 | JVM module | **commented out** ×3 levels | unreachable |
| 3 | **Android payload** | **placeholder file** | **inert by default build** |

`[source: D6 §20.3; android_sources/pp.py:5; main.py:19-25]`

---

## 13. Windows privilege surface — token theft IOCs (`pupwinutils/security.py`)

**Path:** `pupy\pupy\packages\windows\all\pupwinutils\security.py` — **78,800 B / 2,842 lines.** The largest file in Pupy. **Fully functional — NOT in the §12 defect class.** This is where Pupy's Windows privilege escalation actually lives.
`[source: D6 §21]`

### 13.1 Highest-value detections

| Artifact | Significance | Line |
|---|---|---|
| **Open process token of `winlogon.exe`** | The `getsystem` primitive; near-zero benign cause | `:1832` |
| **Child process with spoofed SYSTEM parent** | `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`; PPID spoof | `:2727-2729` |
| `SeDebugPrivilege` enabled by non-debugger | Prerequisite for all token theft here | `:1827`, `:1848`, `:1949`, `:2704` |
| `SeImpersonate` + `SeAssignPrimaryToken` together | Token dup for process creation | `:1950`, `:1963-1965` |
| `DuplicateTokenEx` with `TOKEN_ALL_ACCESS` | Over-broad duplication | `:1957-1959` |
| Repeated `OpenProcessToken` failures | `exc=False` → trail of swallowed attempts | `:1627-1641` |
| `LsaEnumerateLogonSessions` from non-system process | Unprivileged logon recon | `:1498`, `:1123-1139` |
| `RtlGetVersion` instead of `GetVersionEx` | Real OS version; defeats shim | `:1459` |

**The `winlogon` token open and the spoofed-parent child are the two near-unique signatures.** `[source: D6 §21.9]`

### 13.2 The `getsystem` chain

`getsystem()` (`:2015`) → `create_proc_as_sid('S-1-5-18')` (`:1993`) → `impersonate_sid` (`:1864`) → `getSidToken` (**hunts `winlogon` only**, `:1832`) → `impersonate_token` (`:1948`, `DuplicateTokenEx(TOKEN_ALL_ACCESS, SecurityImpersonation, TokenPrimary)`) → `ImpersonateLoggedOnUser` → `start_proc_with_token` → `CreateProcessAsUser` + `CreateEnvironmentBlock` (`:2083`).
`[source: D6 §21.4]`

**`SecurityImpersonation`(2) + `TokenPrimary`(1)** = a token usable for **both** thread impersonation and process creation. `SecurityDelegation`(~3) defined but unused — correct. `[source: security.py:1954-1959, :244]`

### 13.3 Credential access — precise negative

- **LSASS: NO.** No `lsass`, no `MiniDumpWriteDump`, no `ReadProcessMemory`. **Verified absent by grep.** `[source: grep]`
- **SAM: NO.** No hive access. `[source: grep]`
- **Logon sessions: YES**, unprivileged, via `LsaEnumerateLogonSessions` → usernames, SIDs, logon types, timestamps. Same unprivileged LSA surface as Havoc (D5). `[source: security.py:1049-1139, :1498]`
- **Arbitrary process tokens: YES** — the whole point of the file.

**An analyst hunting Pupy as a credential thief should look for `winlogon` token access, NOT LSASS reads.** `[source: D6 §21.6]`

### 13.4 Known defects in this file

- `IMPERSONATION_TOKENS` (`:1813`) is a **module-global dict caching privileged token handles**; the close is commented out (`:1879-1880`) → handles held for implant lifetime.
- `create_new_process_from_ppid` docstring says "Returns True" (`:2696`) but returns a PID (`:2761`) — stale docstring.
- `Se*` privileges enabled with **`exc=False`** at every call site → failures silently swallowed, execution continues.

### 13.5 Sliver / Havoc / Pupy placement

| | Sliver (D1 §15) | Havoc (D5) | **Pupy (§13)** |
|---|---|---|---|
| Elevation needed | yes | **NO** | **YES** (`SeDebug`) |
| Technique | 1-byte `0xC3` AMSI/ETW patch | LSA auth package | **token dup + impersonation + PPID spoof** |
| Fail mode | **fails closed** | — | **swallows, continues** |
| Granularity | one primitive | one call | **68 functions** |

**Sliver refuses; Pupy degrades. Havoc reads; Pupy takes.** Pupy is the most complete of the three at the privilege layer and the most dependent on prior elevation — noisy and broad, the opposite of Sliver's minimal fail-closed discipline.
`[source: D6 §21.8]`

---

## 14. In-memory PE loader — `MemoryModule.c` (U-4a)

**Path:** `client\sources-windows-py3\MemoryModule.c` — **51,876 B / 1,641 lines.** Largest native file. The reflective-loading core.
`[source: D6 §22]`

### 14.1 HEADLINE — PE headers are decommitted in every release build

```c
// MemoryModule.c:891-901
VOID CleanupHeaders(PMEMORYMODULE module) {
    ...
    if (!VirtualFree(module->headers, SizeOfPEHeader(module->headers), MEM_DECOMMIT)) { ... }
}
```
Called under **`#ifndef DEBUG`** at `:1178-1183`. **`DEBUG` reaches the compiler only via `Makefile:44-46` `ifdef DEBUG` → `/DDEBUG`** — so **release builds decommit the PE headers of every in-memory-loaded module; debug builds do not.**

**Analyst consequence: scanning committed memory for `MZ` / `PE\0\0` will NOT find a module loaded this way.** The pages are decommitted, not just altered. This is the concrete anti-forensics payoff of the reflective loader.
`[source: MemoryModule.c:891-904, :1178-1183; Makefile:44-46]`

### 14.2 Import mediation — a 21-symbol hook table

`BuildImportTable` (`:520-695`) replaces the loaded module's imports with **Pupy's own callbacks**, keyed by module + symbol name (`:529-556`, `:576-583`) — `LoadLibrary*`×4, `GetModuleHandle*`×4, `GetModuleFileName*`×2, `GetVersionExA/W`×2, `FindResource*`/`SizeofResource`/`LoadResource`×6, `CreateThread`, `GetProcAddress`, `FreeLibrary`.

| Finding | Detail |
|---|---|
| Effect | A reflected module calling these gets **Pupy's wrapper**, not the Win32 API |
| **Ordinal imports BYPASS the hooks** | `:652-658` calls `getProcAddress` directly — **the hook policy is name-keyed, therefore ordinal-blind** |
| No allowlist | `GetImportAddr` (`:426-447`) is **override, not restriction** — unmatched imports pass through |
| `GetVersionEx` → real version | `:541-542` redirect to local `RtlGetVersion` (`:61-73`, lazily resolves `ntdll!RtlGetVersion`) |

`[source: MemoryModule.c:426-447, :529-583, :649-683, :61-73]`

### 14.3 TLS callbacks — a load-time execution path

`ExecuteTLS` (`:340-365`) calls every `AddressOfCallBacks` entry with `DLL_PROCESS_ATTACH` **before the entry point** (`:1133` precedes `:1153`). Suppressible via `MEMORY_LOAD_NO_TLS_CALLBACKS`.

**A payload can live entirely in a TLS callback**, and with `MEMORY_LOAD_NO_EP` (`:1153`) a module can load with callbacks firing and **no entry point at all**. Works because relocations (`:1109`) run before TLS (`:1134`) — `AddressOfCallBacks` is an absolute VA, not an RVA.
`[source: MemoryModule.c:340-365, :1109, :1133-1153]`

### 14.4 FOURTH shipped-broken feature — ETW suppression never compiles

`MemoryModule.c:558-574` defines ETW-stub hook tables (`EtwEventWrite`/`EventWrite` → `systemEtwEventWrite` etc.) under `#ifdef _PUPY_PRIVATE_WS2_32`.

**`_PUPY_PRIVATE_WS2_32` is defined NOWHERE.** Verified: recursive scan of `sources-windows-py3/` finds the token **only** in `#ifdef`/`#ifndef` directives (`MemoryModule.c:558`,`:578`; `MemoryModule.h:76`,`:144`; `MyLoadLibrary.c:198`,`:275`; `pupy_load.c:238`,`:285`) — never a `#define` or `/D` flag. Makefile defines: `_WIN32`, `WIN_X64`/`_WIN64`/`WIN_X86`, `LIBCRYPTO`, `LIBSSL`, `LIBFFI`, `HAVE_WINDOW`, `_PUPY_DYNLOAD`, `_PUPY_PRIVATE_NT`, `POSTMORTEM`, `UNCOMPRESSED` (+`DEBUG`/`VERBOSE` debug-only). **Not present.**

**⇒ ETW suppression for reflected modules does not exist in any shipped build.** Eight `#ifdef` sites across four files, all inert.

| # | Feature | Severed at | Tombstone |
|---|---|---|---|
| 1 | Windows persistence | missing file | none |
| 2 | JVM module | commented out ×3 | `"NOT IMPLEMENTED: broken jvm setup"` |
| 3 | Android payload | placeholder file | `"pp.py is not replaced with working one!"` |
| 4 | **ETW suppression** | **preprocessor: the `-D` is absent** | **none — the absence is the tombstone** |

**The trap is a near-miss:** `_PUPY_PRIVATE_NT` **is** defined (`Makefile:87`), and `_PUPY_PRIVATE_WS2_32` sits one line away in source with the same prefix. **Source presence is not build presence.**
`[source: MemoryModule.c:558-583; Makefile:87; D6 §22.7]`

### 14.5 Second build-config split — preferred-base allocation is `#if DEBUG` only

`:1040-1048` is guarded `#if DEBUG`, so in release `code` is NULL at `:1050` and the **arbitrary-position allocation at `:1052` always runs**. The image **never lands at its declared `ImageBase`** ⇒ `locationDelta` (`:1107`) is always non-zero ⇒ **`PerformBaseRelocation` always runs** and the `else` at `:1110-1112` is dead. Preferred-base optimization forfeited in shipped builds.
`[source: MemoryModule.c:1040-1112; Makefile:44-46]`

### 14.6 Export-filter policy — `isAllowedSymbol` (`:749-812`)

| Mode | Match | Notes |
|---|---|---|
| No filter supplied (`:756`) | **allow everything** | filtering is **opt-in** |
| Ordinal import (`:752`) | **always allow** | `HIWORD(procname)==0` — no name to filter |
| `MEMORY_LOAD_DEFAULT` (`:763`) | `strcmp` | plaintext allowlist |
| `EXPORT_FILTER_FNV1A` (`:775`) | FNV-1a hash compare | **allowlist contains no readable names** |
| `EXPORT_FILTER_PREFIX` (`:788`) | `strncmp` | family match, `len > proclen` guarded |
| **unknown flags (`:806`)** | **DENY** | **fail-closed** |

`fnv1a` (`:738-746`): offset `2166136261`, prime `16777619` — same construction as `ReflectiveLoader.c`'s hash resolver.
`[source: MemoryModule.c:738-812]`

### 14.7 Relocations (`:368-424`)

`ABSOLUTE` skipped; `HIGHLOW` (32-bit) and `DIR64` (`_WIN64`) applied. **`default:` silently ignores unknown types with the diagnostic `printf` commented out** (`:414-416`) — a quiet fail-open in the relocation pass. Minor: the `directory->Size == 0` early return at `:375` returns `delta == 0`, so a relocation-less module at a non-zero delta reports failure (does not bite in practice).

**`UNHOOK` path:** `_CreateModuleMapping` (`:906-967`) maps the module's **on-disk file** read-only to reload pristine bytes; released on both exit paths (`:1186-1190`, `:1199-1203`).
`[source: MemoryModule.c:368-424, :906-967, :1186-1203]`

---

## 15. Crash-artefact generator (`postmortem.c`) — U-4c

**Path:** `client\sources-windows-py3\postmortem.c` — **25,642 B / 898 lines.** Read in full.
`[source: D6 §23]`

### 15.1 ON-DISK ARTEFACT — the headline IOC

An unhandled-exception filter writes a **comprehensive process forensic dump** to:

```
%LOCALAPPDATA%\Microsoft\postmortem\
```
(`POSTMORTEM_DEST_FOLDER`, `postmortem.h:7`; written via `SHGetFolderPathAndSubDirW` at `postmortem.c:849-851`.)

**Directory-name significance:** `Microsoft\postmortem` reads as a vendor component. Its presence on a host is a **high-confidence Pupy indicator** — the genuine Microsoft path is not `postmortem`.

**Contents written by `SaveExceptionInfo` (`:860`, body to `:814`):**

| Artefact | Line |
|---|---|
| Exception code / name / flags / address | `:726-763` |
| **Full register context** (RSP/RBP/RIP + RAX–R15, or 32-bit equivalents) | `:735-762` |
| **Loaded-module list** (`MyEnumerateLibraries` + `MyEnumerateLoadedLibraries`) | `:781`, `:784` |
| **DBGHELP stack trace** (`SaveContextStack`) | `:791` |
| Calling stack (`SaveCallingStack`) | `:802` |
| **Full CPython stack** (`Py_GetCurrentThreadStackTrace`) | `:808` |

**This is not a crash reporter — it is an on-host forensic evidence generator.** Recovering it yields the implant's native execution context **and its Python call stack**. The most analyst-useful artefact Pupy leaves on disk is one it writes for itself.
`[source: postmortem.c:726-814, :816-876]`

### 15.2 FIFTH severed feature — `POSTMORTEM` is never defined

`postmortem.c` is **not compiled as its own translation unit** — it is `#include`d into `pupy_load.c` under a guard:

```c
// pupy_load.c:15-17
#ifdef POSTMORTEM
#include "postmortem.h"
#include "postmortem.c"
```
And `POSTMORTEM` requires an external Makefile variable:
```make
# Makefile:98-100
ifneq ($(FEATURE_POSTMORTEM),)
CFLAGS += /DPOSTMORTEM
endif
```

**`FEATURE_POSTMORTEM` appears exactly twice repo-wide:** that guard, and **a commented-out line** in the build script — `build-docker.sh:149` `#make ... FEATURE_POSTMORTEM=1 ARCH=32`. **Every active invocation** (`:151-152`, `:155-156`, `:159-160`, `:163-164`) passes `DEBUG=1 FEATURE_DYNLOAD=1` and **never** `FEATURE_POSTMORTEM`.

**⇒ `POSTMORTEM` is defined by no active build line; the crash-artefact generator does not exist in any shipped build.**
`[source: pupy_load.c:15-17; Makefile:98-100; build-docker.sh:149-164]`

### 15.3 Minidump is `#ifdef DEBUG` only — and mutually exclusive with §14.1

```c
// postmortem.c:863-872
#ifdef DEBUG
  if (pExceptionPointers) {
    if (hDbgHelp) { CreateMiniDump(hDbgHelp, appdata_local, pExceptionPointers); }
    else { dprint("Failed to load DBGHELP\n"); }
  }
#endif
```

| Build | PE headers in memory | Minidump on crash |
|---|---|---|
| **Release** (`DEBUG` undefined) | **decommitted** (§14.1) | **not generated** |
| **Debug** (`/DDEBUG`) | retained | **generated** |

**Pupy cannot have both.** The config that wipes memory-resident PE headers is the config that forbids the minidump.
`[source: postmortem.c:863-872; MemoryModule.c:1178-1183; Makefile:44-46]`

### 15.4 Minor defect — decorative fallback

`postmortem.c:841-845`: if `SHGetFolderPathAndSubDirW` cannot be resolved, `GetTempPathW` fills `appdata_local` — then the code **returns `EXCEPTION_CONTINUE_SEARCH` unconditionally**, discarding the path either way. **The fallback never writes anywhere.** (`:875` also returns `EXCEPTION_CONTINUE_SEARCH` on success, so the filter never swallows the exception.)
`[source: postmortem.c:841-845, :875]`

### 15.5 Five severed features, five mechanisms

| # | Feature | Severance mechanism | Evidence |
|---|---|---|---|
| 1 | Windows persistence | **file absent** | `scriptlets/persistence.py:9` |
| 2 | JVM module | **source commented out ×3** | `"NOT IMPLEMENTED: broken jvm setup"` |
| 3 | Android payload | **placeholder file** | `"pp.py is not replaced with working one!"` |
| 4 | ETW suppression | **macro never passed** (`_PUPY_PRIVATE_WS2_32`) | 8 inert `#ifdef` sites, 4 files |
| 5 | **Crash-artefact generator** | **build variable never set** (`FEATURE_POSTMORTEM`); `.c` `#include`d, never compiled standalone | `Makefile:98-100`; `build-docker.sh:149` |

**Pupy's capability surface and its shipped capability set differ, and the difference is invisible from the source tree.**
`[source: D6 §17, §18, §20.3, §22.7, §23.5]`

### 15.6 METHODOLOGY RULE — source presence is not build presence

Proven three independent ways in this target:

| # | Case | Source shows | Build delivers |
|---|---|---|---|
| 1 | Optimizer deletion | `assert(found)` `dns_encoder.py:277` | stripped by `-OO` (`pyoxidizer.bzl:34`) |
| 2 | Declaration vs live symbol | `setup_jvm_class` declared in both headers | empty stubs; call sites commented |
| 3 | Missing `-D` / unset build var | full ETW stubs; entire `postmortem.c` | never compiled |

**Three questions before reporting a source-visible capability as present:**
1. **Is the enclosing guard satisfied in a real build?** (macro defined? by what? any active build line?)
2. **Is the file actually compiled?** (`postmortem.c` is `#include`d into another TU — a tree-wide file scan lists it as present.)
3. **Does the pipeline delete it downstream?** (`-OO`, linker GC, generated `#ifdef`.)

**Failure inverts capability assessment** — reporting capability the target lacks, missing capability it has. Sliver's fail-closed patch is *build-stable*; Pupy's build-dependence means **two analysts reading the same tree can correctly describe two different implants.**
`[source: D6 §23.6]`

---

## 16. Loader internals: thread seam, ETW suppression, SxS manifest (`MyLoadLibrary.c`, `actctx.c`, `resource_python_manifest.c`) — U-4d

`MyLoadLibrary.c` **27,034 B / 971 lines**; `actctx.c` **25 lines**; `resource_python_manifest.c` **35 lines**.
`[source: D6 §24]`

### 16.1 ON-DISK / IN-BINARY FINGERPRINT — hardcoded SxS manifest

`resource_python_manifest.c` embeds a Windows assembly manifest into the implant's PE resources:
```xml
<requestedExecutionLevel level="asInvoker" uiAccess="false"></requestedExecutionLevel>
<assemblyIdentity type="win32" name="Microsoft.VC90.CRT" version="9.0.21022.8"
                  processorArchitecture="amd64" publicKeyToken="1fc8b3b9a1e18e3b">
```
`[source: resource_python_manifest.c:8, :14 (amd64), :24, :30 (x86)]`

**Two huntable facts:**

1. **`asInvoker` = no elevation request.** The implant deliberately does **not** ask for administrator, so launching it produces **no UAC prompt** — it silently inherits the current token. A PE whose embedded manifest declares `asInvoker` while exhibiting implant behaviour is consistent, not anomalous; do not expect a UAC artefact.
2. **`Microsoft.VC90.CRT` version `9.0.21022.8` (VS2008) is a version fingerprint.** A PE on a modern host declaring a pinned SxS dependency on the **VS2008 CRT**, `publicKeyToken=1fc8b3b9a1e18e3b`, is anomalous — contemporary software does not request `VC90` at that version. **Huntable via PE resource inspection without any runtime behaviour.**

### 16.2 ETW suppression stubs — SIXTH inert capability, mechanism now readable

`MyLoadLibrary.c:198-254` (definitions) and `:275-278` (`callbacks` table entries) are guarded by `_PUPY_PRIVATE_WS2_32` — **defined nowhere** (§14.4). Dead. **But the stubs show how the suppression would work:**

- `MyEtwRegister` (`:200-220`) **never contacts ETW.** It keeps `static ULONGLONG dwFakeRegHandle = 0x80000000;` (`:206`) and returns `*RegHandle = dwFakeRegHandle++` (`:218`) — **synthetic, ever-incrementing handles.**
- `MyEtwEventWrite` (`:223-231`), `MyEtwEventWriteFull` (`:234-245`), `MyEtwUnregister` (`:248-253`) `dprint` and return `ERROR_SUCCESS` — **no event is ever emitted.**

A reflected module instrumented with ETW would believe registration succeeded and produce **zero telemetry**. `callbacks` (`:256-279`) is a **positional** initializer matching `DL_CALLBACKS`, and the struct is guarded by the same macro in `MyLoadLibrary.h:76`/`:144` — **both sides carry the guard, so the file compiles cleanly in either state.** The defect is invisible to compilation and visible only in the build flags.
`[source: MyLoadLibrary.c:198-279; MyLoadLibrary.h:76, :144]`

### 16.3 gated-but-real: the thread-hardening seam

`MyCreateThread` (`:881-914`) **redirects every thread created by a reflected module** through `WrappedThreadRoutine` (`:841-879`), stashing the original routine, parameter, and exception filter in an `ORIGINAL_THREAD_ARGS` (`:900-902`). The wrapper runs the routine inside `__try/__except` and dispatches faults to `ThreadUnhandledExceptionFilter` (`:793-839`), which resolves **which memory module the failing routine came from** (`MyFindMemoryModuleNameByAddr`, `:811`) and prefers **that module's own `ehFilter`** (`:818-819`). `EXCEPTION_BREAKPOINT` passes through untouched (`:802-809`).

**This is the seam the §15 crash-artefact generator plugs into** (`pupy_load.c:481` → `MyGetUnhandledExceptionFilter()`, `:789-791`). Plumbing real; only the `FEATURE_POSTMORTEM`-gated body missing.
`[source: MyLoadLibrary.c:793-839, :841-879, :881-914]`

### 16.4 SEVENTH severance mechanism — `actctx.c`, declared-but-undefined loader

The activation-context / SxS shim is inert at two independent levels:
- **Pointers never populated.** `actctx.h:35` declares `void _MyLoadActCtxPointers();` — **no definition anywhere in the tree.** A tree-wide grep finds the six pointers only as `NULL` initialisers (`actctx.c:3-8`), a guarded call (`:13-14`), and `extern` declarations (`actctx.h:28-33`). **Nothing assigns them.**
- **Guard cannot pass.** `if (PyWin_DLLhActivationContext && pfnActivateActCtx)` (`:13`) — both permanently `NULL` ⇒ `_My_ActivateActCtx` **always returns 0**; `_My_DeactivateActCtx` (`:22-23`) always a no-op.

**Mechanism: the header declaration exists, the definition was never written.** Distinct from a missing file (§13 persistence) and a commented body (JVM).
`[source: actctx.c:3-8, :13, :22-23; actctx.h:28-35]`

### 16.5 LIVE DEFECT (not a severed feature) — NULL-deref in `MySetUnhandledExceptionFilter`

```c
// MyLoadLibrary.c:771-779
lib = _FindMemoryModule(pszModuleName, NULL);
if (!lib) {
    dprint("Failed to set default thread handler for %s to %p - module not found\n", ...);
}
lib->ehFilter = handler;      // :779 — reached with lib == NULL
```
The `!lib` branch **logs and falls through** — no `return FALSE`, no early exit. Declared `BOOL`, returns `TRUE` on both surviving paths (`:768`, `:786`), so the failure branch was intended to return `FALSE` and does not. **Live, reachable crashing code in the loader's own exception-filter plumbing** — reachable by passing any non-memory-module name.
`[source: MyLoadLibrary.c:761-787]`

### 16.6 SIX severed features, six mechanisms

| # | Feature | Severed at |
|---|---|---|
| 1 | Windows persistence | **file absent** |
| 2 | JVM module | **source commented out ×3** |
| 3 | Android payload | **placeholder file** |
| 4 | ETW suppression (`MemoryModule.c`) | **macro never passed** |
| 5 | Crash-artefact generator | **build variable never set**; `.c` `#include`d not compiled |
| 6 | **Activation-context / SxS shim** | **declared-but-undefined loader function** |

**Do not conflate:** §16.5's NULL-deref is live crashing code; §16.1's manifest is live and operationally effective. The table lists *advertised capabilities that builds omit* — not every bug.
`[source: D6 §24.6]`

---

## 17. Platform scope of the severance pattern — Windows vs Linux

**Files read:** Linux `Makefile` (9,012 B / 307 lines), Linux `pupy_load.c` (3,048 B / 126 lines).
`[source: D6 §25]`

### 17.1 The pattern splits THREE ways

| # | Feature | **Windows** | **Linux** |
|---|---|---|---|
| 1 | Windows persistence | **severed** — file absent | **n/a** — real `linux/all/persistence.py` exists |
| 2 | JVM module | **severed** — commented ×3 | **severed IDENTICALLY** |
| 3 | Android payload | **severed** — `pp.py` placeholder | **n/a** — different bootstrap |
| 4 | ETW suppression | **severed** — macro never passed | **n/a** — no ETW on Linux |
| 5 | Crash-artefact generator | **severed** — `FEATURE_POSTMORTEM` never set | **n/a — INVERTED**: Linux *disables* core dumps (`setrlimit(RLIMIT_CORE, 0)`, `pupy_load.c:52-54`) |
| 6 | Activation-context / SxS shim | **severed** — undefined loader | **n/a** — no activation contexts |
| 7 | **Injector (`FEATURE_INJECTOR`)** | — | **SEVERED — new Linux instance** |

**Four are platform-absent, not severed** — `POSTMORTEM`, `_PUPY_PRIVATE_WS2_32`, `actctx` return **zero hits across the Linux tree**. Their absence there carries no information.

### 17.2 Cross-platform recurrence — JVM only

JVM is the **single true recidivist**, identical on both platforms: empty stub (`main_exe.c:22` `void setup_jvm_class(void) {}`), commented call site (`pupy.c:539` `//setup_jvm_class();`), live header declaration (`pupy_load.h:13`). **One defect, two platforms, same three-level structure** ⇒ a project-level maintenance defect, not a Windows build artefact.
`[source: main_exe.c:22; pupy.c:539; pupy_load.h:13; D6 §18]`

### 17.3 NEW Linux severance — and it is disguised as intent

```make
# sources-linux-py3/Makefile:71-74
else
NAME ?= $(MACH)
FEATURE_INJECTOR :=          # ← hard-assigned EMPTY
endif
# :145-153
ifneq ($(FEATURE_INJECTOR),) # ← can never fire
CFLAGS += -D_FEATURE_INJECTOR -Iinjector/include
endif
```
`FEATURE_INJECTOR` appears at **exactly four sites repo-wide**; **no build script ever passes it**. Because `:73` empties it inside the `else` of the same chain, the guard at `:145` is unreachable and `pupy.c:31`, `:188`, `:485` are dead.

**Mechanism differs from §16.6's:** there the variable was *never passed* (an omission); here it is **explicitly assigned to nothing in the file that guards on it** — which **reads as configuration, not oversight.** The severance is disguised as deliberate intent.
`[source: sources-linux-py3/Makefile:71-74, :145-153; pupy.c:31, :188, :485]`

### 17.4 The control proving the gate design works

`FEATURE_PATHMAP` uses the identical pattern **twelve lines above** and functions correctly: `Makefile:119-129` adds `ld_hooks.o`, defines `-D_FEATURE_PATHMAP`, and `pupy_load.c:56-80` consumes it live — `xz_dynload`s the hooks object, calls `set_pathmap_callback` via `dlsym`, with real failure diagnostics.

**⇒ The `FEATURE_*` conditional-gate design is sound and in active use. The failure is specific to `FEATURE_INJECTOR` being pre-emptively emptied. The pattern is NOT systematic — do not infer that every gated feature is broken.**
`[source: sources-linux-py3/Makefile:119-129; sources-linux-py3/pupy_load.c:56-80]`

### 17.5 Verdict

**The severance pattern is neither Windows-only nor uniformly Pupy-wide — it is a property of individual features, and it exists on both platforms.** Four of seven Windows severances are platform-absent. One (JVM) recurs cross-platform identically. One is new to Linux, mechanistically distinct, and disguised as intent. **Carry the rule — source presence is not build presence — to any platform and any feature; do not infer systematicity.** Seven failures, seven mechanisms; one working gate twelve lines away.
`[source: D6 §25.3]`
