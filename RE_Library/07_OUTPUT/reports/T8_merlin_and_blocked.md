# T8/T9 — Merlin Recovery and Blocked-Target Documentation

**Author:** `archive-diver`
**Scope:** outcome of the Merlin archive task, plus an honest account of every target that could not be reached from this host and the exact reason why.
**Evidence tags:** `[archive-header]` = read from the 7z container structure; `[binary]` = read from an extracted PE; `[rea-source]` = read from REA's own source at the cited file:line; `[host-probe]` = verified on this machine; `[external-research]` = upstream repo/web; `[inference]` = my deduction.

---

## PART 1 — MERLIN: NOT BLOCKED

The brief classified the Merlin archive as ENCRYPTED with password `infected`, and treated it as a problem target. **It is neither.** The archive is open, and `infected` is simply the wrong password.

| Item | Value |
|---|---|
| Target | `RE_Library/02_BINARIES/merlin/merlinServer-Windows-x64.7z` |
| Size | 68,780,065 B |
| SHA-256 | `6a93f70be0720d1ca3c4938f79fbef947c0be21d94b61a634d6a2a7061334983` |
| **Password** | **`merlin`** (lowercase, case-sensitive) |
| Result | `Everything is Ok` — exit 0 |
| Extracted | 89 files, 50 folders, 264,634,542 B |

### 1.1 The password is a vendor default, not a defeated secret

`[external-research]` The upstream README documents the release-archive password as `merlin`, and upstream `main.go` sets the server RPC flag default to the same literal. `[binary]` The agent's `main.psk` default is *also* `merlin`. One published literal serves as archive password, server RPC password, and agent pre-shared key.

This matters for how the result should be read. The archive was **never meaningfully protected**. An operator deploying Merlin without overriding `-password` and `-psk` is running a C2 whose key appears in the product documentation. The honest framing is *default reuse across three trust boundaries*, not *cryptanalysis* — and a genuinely strong passphrase would have made this target unrecoverable within the time available.

### 1.2 Reproducible recovery, with negative control

```powershell
# SUCCESS — exit 0
& "C:\Program Files\7-Zip\7z.exe" t -p"merlin"  `
  "RE_Library\02_BINARIES\merlin\merlinServer-Windows-x64.7z"
# -> Everything is Ok
#    Folders: 50  Files: 89  Size: 264634542  Compressed: 68780065  Headers Size = 2577

# NEGATIVE CONTROL — exit 2, one character changed
& "C:\Program Files\7-Zip\7z.exe" t -p"merlinX" `
  "RE_Library\02_BINARIES\merlin\merlinServer-Windows-x64.7z"
# -> ERROR: ... Cannot open encrypted archive. Wrong password?
```

Method: a bounded dictionary guess over a 13-entry candidate list, using `Path = ` in `7z l -slt` output as the success predicate. No plaintext attack, no header manipulation, no memory extraction.

| Candidate | Result | | Candidate | Result |
|---|---|---|---|---|
| `malware` | FAIL | | `infected123` | FAIL |
| `password` | FAIL | | `merlin123` | FAIL |
| **`infected`** | **FAIL** | | `malware123` | FAIL |
| `1234` | FAIL | | **`merlin`** | **SUCCESS** |
| `malwarebazaar` | FAIL | | `Merlin` | FAIL (case) |
| `abuse` | FAIL | | `MERLIN` | FAIL (case) |
| *(empty)* | FAIL | | | |

Every failure is recorded as a FAILED attempt. No candidate is credited with an unobserved success.

### 1.3 Correction — the header could not be listed without the password

An earlier working assumption was that `7z l` would reveal filenames without the password. **That is wrong.** `[archive-header]` Parsing the 32-byte start header:

| Field | Value |
|---|---|
| Signature | `37 7A BC AF 27 1C` (7z), version `0.4` |
| StartHeaderCRC | `0xFC661B8D` — recomputed, **match** |
| NextHeaderOffset | 68,779,968 |
| NextHeaderSize | 65 |
| NextHeaderCRC | `0xC29D5BDA` — recomputed, **match** |
| First next-header byte | **`0x17` = `kEncodedHeader`** |

`32 + 68779968 + 65 = 68780065` = exact file length, and both CRCs verify, so the container is intact. The decisive fact is byte `0x17`: the **header itself is an encrypted stream** (AES-256, method signature `E4 10 76 19`), protected independently of the content. There is **no plaintext filename listing anywhere in the file to recover.** The correct sequence is password → listing, not listing → password.

Archive method string: `ARM64 LZMA2:26 LZMA:20 BCJ2 ARM 7zAES`, `Solid = +`, `Blocks = 4`.

### 1.4 Merlin summary

Full analysis is in `T8_merlin_full.md`. Headline results: a **stock, unmodified upstream Ne0nd0g/merlin release** (server 2.2.2 / build `93d6898`, agent `merlin-agent/v2 v2.5.0`, CLI `13e7175`, DLLs `-buildmode=c-archive`), all five executables Go 1.27.2 / amd64; hardcoded defaults recovered verbatim from ldflags (`main.addr=127.0.0.1:4444`, `main.url=https://127.0.0.1:443`, `main.protocol=h2`, `main.psk=merlin`, `main.auth=opaque`, `main.transforms=jwe,gob-base`, `main.padding=4096`, `main.sleep=30s`, `main.secure=false`); and full **uTLS ClientHello impersonation** — the only target in this corpus that attacks the TLS handshake itself rather than HTTP semantics (Havoc) or traffic statistics (Pupy obfs3).

---

## PART 2 — BLOCKED TARGETS

Each entry gives the exact blocking condition, the evidence establishing it, and what would unblock it. Two categories appear: **latent blockers** (capability gated on a platform this host is not, but no target file is currently present) and **active blockers** (a target exists and cannot be processed).

### 2.1 Host baseline `[host-probe]`

| Fact | Value |
|---|---|
| OS | Microsoft Windows NT 10.0.26200.0 |
| Architecture | AMD64 |
| REA schema profile | `compact` |
| Ghidra | `C:\tools\ghidra_12.1.4_PUBLIC` (`GHIDRA_INSTALL_DIR`) — **present, working** |

Anything gated on `process.platform === "linux"` or `"darwin"` is unreachable here by construction, because this is a `win32` host.

---

### 2.2 Firmware extraction — HARD-GATED ON LINUX `[rea-source]`

**Tools affected:** `inspect_firmware_regions` (Binwalk 3.1.x), `extract_firmware` (Unblob 26.6.x).

**Exact blocking condition** — the platform check runs *before* tool resolution, so configuring a path cannot help:

```ts
// src/firmware/FirmwareCommand.ts:51-60
if (
  process.platform !== "linux" ||
  configured === undefined ||
  !isAbsolute(configured)
)
  throw firmwareToolUnavailable(
    engine,
    operation,
    `This integration requires Linux and an absolute ${variable} path to the caller-supplied tool`,
  );
```

**Corroborating evidence:** `src/firmware/FirmwareCommand.test.ts:11` — `const it = test.skipIf(process.platform !== "linux");`, i.e. upstream's own test suite skips on non-Linux. `[host-probe]` Both `binwalk` and `unblob` are additionally **absent from PATH**, and neither `REA_BINWALK_COMMAND` nor `REA_UNBLOB_COMMAND` is set.

**Why this is a latent rather than active blocker:** `[host-probe]` there is **no firmware image anywhere in this library.** A recursive search for `*.bin`, `*.img`, `*.fw`, `*.trx`, `*.chk`, `*.rom` returns only Metasploit payload templates, Havoc shellcode stubs, and Sliver encoder testdata — no device firmware. The gate is real but nothing is currently behind it.

**What would unblock it:** a Linux host, plus `REA_BINWALK_COMMAND` / `REA_UNBLOB_COMMAND` set to absolute paths of caller-supplied Binwalk and Unblob, plus `util-linux prlimit`. To make it *matter*, a firmware image would also need to be added to the corpus.

---

### 2.3 Signal recording decode — HARD-GATED ON LINUX `[rea-source]`

**Tools affected:** `decode_signal_recording`, `inspect_signal_decoders` (sigrok-cli 0.7.2).

**Exact blocking condition:**

```ts
// src/signals/SigrokRecordingProvider.ts:131-133
if (this.platform !== "linux")
  throw …(
    "Signal decoding requires Linux with util-linux prlimit and " +
    "REA_SIGROK_COMMAND so expanded recordings are processed under an enforced address-space limit."
  );
```

**Corroborating evidence:** line 148 defaults the limiter to `/usr/bin/prlimit`, a Linux-only binary; line 349 documents that the limiter "enforces soft and hard ceilings before execution"; line 493 instructs "On Linux, configure sigrok-cli 0.7.2 through `REA_SIGROK_COMMAND`". `[host-probe]` `sigrok-cli` is **absent** and `REA_SIGROK_COMMAND` is unset.

**What would unblock it:** a Linux host with `util-linux prlimit`, `sigrok-cli` 0.7.2 supplied at an absolute path, and an actual logic/signal capture file.

---

### 2.4 Apple/macOS tooling — HARD-GATED ON DARWIN `[rea-source]`

**Tools affected (8):** Apple asset catalog inspection, native DMG traversal, interface-builder decoding (storyboard/NIB), keyed-archive decoding, Mach-O slice inspection, dylib-resolution tracing, Mach-O signature inspection, Objective-C/Swift dispatch metadata. Apple application-graph projection also expects Apple bundle layouts.

**Exact blocking conditions** — each artifact family guards independently on `darwin`:

```ts
// src/artifacts/apple/AppleAssetCatalogAnalysis.ts:33-37
if (process.platform !== "darwin" && input.runAssetUtil === undefined)
  throw new ArtifactReaderFailure(
    "unavailable",
    "Apple asset catalog inspection requires macOS assetutil",
  );
```

```ts
// src/artifacts/NativeDmgArtifactReader.ts:144-148
if (process.platform !== "darwin" && host === undefined)
  throw new ArtifactReaderFailure(
    "unavailable",
    "Native DMG traversal is available only on macOS",
  );
```

```ts
// src/artifacts/apple/KeyedArchiveReader.ts:129-131
return platform === "darwin"
  ? "Inspect an ordinary property list with inspect_plist; …"
  : "Select an NSKeyedArchiver archive; inspect_keyed_archive decodes only those. " +
    "inspect_plist, which reads ordinary property lists, requires a macOS host.";
```

`[host-probe]` `/Applications/Hopper Disassembler.app` does not exist (this is Windows), and no Apple bundle, Mach-O binary, DMG, or `.car` asset catalog exists anywhere in the corpus.

**Why this is a latent rather than active blocker:** these gates protect Apple-format artifact families, and the corpus contains none. Every target actually present is PE, ELF-shaped source, APK, or an archive.

**What would unblock it:** a macOS host. `assetutil` ships with Xcode command-line tools; DMG mounting uses native macOS facilities.

---

### 2.5 Hopper Disassembler — HARD-GATED ON DARWIN/LINUX `[rea-source]`

**Exact blocking condition:**

```ts
// src/hopper/HopperProvider.ts:74-80
if (this.platform !== "darwin" && this.platform !== "linux")
  return {
    status: "unavailable",
    code: "unsupported_host",
    reason: `Hopper integration is not supported on ${this.platform}.`,
    diagnostics,
  };
```

**Corroborating evidence:** `src/cliHostInputs.test.ts:14-15` exercises exactly this case — it constructs `new HopperProvider(config(), silentLogger, {}, "win32")` and asserts Hopper reports unsupported. Upstream anticipates a `win32` host and documents it as unsupported. `[host-probe]` No `hopper` or `hopper-disassembler` command exists, and Hopper's default paths (`/Applications/Hopper Disassembler.app/Contents/MacOS/hopper`, `/opt/hopper/bin/Hopper`, per `src/config/parseConfig.ts:12-13`) are macOS/Linux locations.

**Mitigation available:** Hopper is not required. Ghidra 12.1.4 is present and working and was used successfully throughout this engagement — it fully analyzed the stripped Go agent (11,247 procedures, 25,040 strings, image base `0x140000000`). For PE and ELF native analysis, capability was **not** lost, only the alternative tool was.

**What would unblock it:** a macOS or Linux host with Hopper installed, plus `REA_HOPPER_*` configuration. Not needed for current targets.

---

### 2.6 IDA Pro — COMMERCIAL, VERIFIED ABSENT `[host-probe]`

**Tools affected:** the `ida` provider family (headless and attached modes), gated through `REA_IDA_MCP_CONFIG`.

**Exact blocking condition:** IDA is a commercial product requiring a paid license. `[host-probe]` `C:\Program Files\IDA*` and `C:\Program Files (x86)\IDA*` do not exist; no `ida64`, `ida`, or `idat64` command resolves. `REA_IDA_MCP_CONFIG` is unset.

**Structural note `[rea-source]`:** the IDA integration is bring-your-own and performs no provider startup during discovery (`src/ida/IdaProvider.ts:38` — *"Bring-your-own IDA MCP candidate; discovery performs no provider startup"*). REA never installs IDA, so absence is the expected steady state rather than a misconfiguration.

**Mitigation available:** Ghidra covers the same PE/ELF native-analysis ground and was used instead.

**What would unblock it:** an IDA Pro license and installation, plus a running IDA MCP server pointed at by `REA_IDA_MCP_CONFIG` (absolute path).

---

### 2.7 JEB Decompiler — COMMERCIAL, VERIFIED ABSENT `[host-probe]`

**Tools affected:** `decompile_jeb_item`, `list_jeb_units`, `open_jeb_project`, `inspect_jeb_client` — the JEB provider family, gated through `REA_JEB_MCP_URL` (default `http://127.0.0.1:8425/mcp`).

**Exact blocking condition:** commercial license required. `[host-probe]` a recursive search for `*jeb*` directories under `C:\`, both Program Files trees, and the user profile returns **nothing**; `REA_JEB_MCP_URL` is unset.

**Structural note `[rea-source]`:** `src/application/CapabilityInventory.ts:475` states the requirement explicitly — *"Start a JEB client serving MCP … and point `REA_JEB_MCP_URL` at it (default `http://127.0.0.1:8425/mcp`). **REA does not install or launch JEB.**"* Absence is by design.

**Mitigation available:** for the Android target in this corpus, JADX is present and sufficient. `[host-probe]` `REA_JADX_MCP_JAR=C:\Users\PC\Desktop\.agent\rea-tools\jadx-headless-mcp-0.7.1-all.jar`; Java 21 (Eclipse Adoptium) and `apktool` are both present. Android analysis was **not** blocked.

**What would unblock it:** a JEB license and a JEB client process serving MCP, with `REA_JEB_MCP_URL` pointed at it.

---

## PART 3 — VERIFIED AVAILABLE (for completeness)

Recorded so the blocked list is not mistaken for a shortage of tooling. `[host-probe]`

| Capability | Tool | Status |
|---|---|---|
| Native PE/ELF analysis | Ghidra 12.1.4 | **PRESENT** — used successfully on stripped Go PEs |
| Packet capture inspection | tshark 4.6.9.0, capinfos | **PRESENT** (`REA_TSHARK_COMMAND`, `REA_CAPINFOS_COMMAND`) |
| Archive handling | 7-Zip 26.04 | **PRESENT** — recovered the Merlin archive |
| Android decompilation | JADX, apktool, adb, Java 21 | **PRESENT** |
| .NET / managed analysis | dotnet | **PRESENT** |
| Go build provenance | REA `inspect_go_binary` | **PRESENT** — produced the provenance tables in T8_merlin_full.md |

---

## PART 4 — CONSOLIDATED BLOCKED-TARGET TABLE

| # | Target / capability | Blocking condition | Establishing evidence | What would unblock it | Active? |
|---|---|---|---|---|---|
| 1 | Firmware extraction (Binwalk, Unblob) | `process.platform !== "linux"` throws before tool resolution | `src/firmware/FirmwareCommand.ts:51-60`; test skip at `FirmwareCommand.test.ts:11`; both tools absent from PATH | Linux host + absolute `REA_BINWALK_COMMAND`/`REA_UNBLOB_COMMAND` + `prlimit`; **and a firmware image to analyze** | **Latent** — no firmware in corpus |
| 2 | Signal decoding (sigrok-cli) | `this.platform !== "linux"` | `src/signals/SigrokRecordingProvider.ts:131-133`; `prlimit` default `/usr/bin/prlimit` (line 148); tool absent | Linux host + `prlimit` + `REA_SIGROK_COMMAND` | **Latent** — no capture files |
| 3 | Apple asset catalogs | `process.platform !== "darwin"` — needs macOS `assetutil` | `src/artifacts/apple/AppleAssetCatalogAnalysis.ts:33-37` | macOS host | **Latent** — no Apple bundles |
| 4 | Native DMG traversal | `process.platform !== "darwin"` | `src/artifacts/NativeDmgArtifactReader.ts:144-148` | macOS host | **Latent** — no DMGs |
| 5 | Keyed archive / plain plist | `platform === "darwin"` required | `src/artifacts/apple/KeyedArchiveReader.ts:129-131` | macOS host | **Latent** — no Apple artifacts |
| 6 | Interface-builder decode (storyboard/NIB) | Apple bundle required (`decode_interface_builder` operates on the active bundle) | `KeyedArchiveReader.ts:127` routes NIBArchive to `decode_interface_builder` on the app bundle | macOS host + Apple app bundle | **Latent** — no Apple bundles |
| 7 | Mach-O slice / dylib tracing / signature | Apple Mach-O artifact required | `src/artifacts/MachOSliceArtifactReader.ts`; `MachoLoadCommandReader.ts` | A Mach-O binary (any host, with Apple readers enabled) | **Latent** — no Mach-O in corpus |
| 8 | Hopper Disassembler | `platform !== "darwin" && platform !== "linux"` → `unsupported_host` | `src/hopper/HopperProvider.ts:74-80`; test at `cliHostInputs.test.ts:14-15`; absent from PATH | macOS/Linux host + Hopper installed | **Latent — and non-blocking: Ghidra substitutes** |
| 9 | IDA Pro | Commercial license; not installed | `[host-probe]` no `IDA*` dirs, no `ida64`/`ida`/`idat64`; `REA_IDA_MCP_CONFIG` unset; BYO by design (`IdaProvider.ts:38`) | IDA Pro license + absolute `REA_IDA_MCP_CONFIG` | **Latent — non-blocking: Ghidra substitutes** |
| 10 | JEB Decompiler | Commercial license; not installed | `[host-probe]` no `*jeb*` dirs; `REA_JEB_MCP_URL` unset; REA never installs it (`CapabilityInventory.ts:475`) | JEB license + client serving MCP + `REA_JEB_MCP_URL` | **Latent — non-blocking: JADX substitutes** |
| 11 | ~~Merlin archive~~ | ~~Unknown password~~ | **RESOLVED** — password is `merlin`; `7z t` exit 0 with negative control | n/a | **No — unblocked** |

**No target in this corpus is actively blocked.** Every gate above is either a latent capability with nothing currently behind it, or is a commercial/alternate tool for which a present working substitute exists. The single genuinely-blocked target named in the brief — Merlin — was resolved during this task.

---

## PART 5 — RESIDUAL UNKNOWNS

1. Whether any real firmware image, logic capture, Mach-O binary, or Apple bundle is *intended* for this corpus. The gates in §2.2–2.4 are verifiable but currently unmotivated.
2. Whether the `dist/` build of REA reproduces the `src/` platform gates verbatim. The `dist/firmware/FirmwareCommand.js:20` and `dist/firmware/CapabilityInventory.js:322` paths named in tasking are not present in this session's accessible scope; the `src/` TypeScript cited here is the more authoritative source and is the file:line evidence relied upon.
3. Whether the `win32` Hopper refusal is reachable in production configuration or only in the tested constructor path. The code path is unambiguous; live configuration was not exercised.
4. Exact license state for IDA/JEB beyond filesystem absence — absence of installation is proven; entitlement could not be assessed from this host.

---

*Report written by `archive-diver`. All gates cited to REA source with file:line; all host facts verified by direct probe; all archive facts read from the container header and `7z` output; upstream facts cited to `github.com/Ne0nd0g/merlin`. Merlin analysis detail is in `T8_merlin_full.md`.*
