# DEEP lane status — live

Function-by-function reversal of every target in the corpus. Written incrementally; this file is
the board, the report files are the deliverables.

**Last verified: 23:41 — 1,093.6 KB across 8 files.** Seven deep reports complete or actively growing.

## Lead verification performed this round (round 5)

- **D1 §21 + §22 written (Lead).** D1 now **148.8 KB / 3,011 lines / §0–§22**.
- **D6 now 277,947 B / 4,372 lines / 22 headings §0–§21 / 1 trailer** — verified on disk by me.
  covenant-deep's structural claims are **all correct**.
- **D8 now 50,353 B / 682 lines / 9 `##` headings / 37 `[source:]` cites.** havoc-deep reports
  "8 sections / 38 cites" — **8 is correct** (the ninth `##` is `## TABLE OF CONTENTS`), **38 is off
  by one against a measured 37**.
- **task-16 COMPLETE** — U-4b and U-5 closed. **task-15 COMPLETE** — D7 fixes + D8.
- **Verified covenant-deep's U-5 in raw source:** `security.py` 78,800 B / 2,842 lines exact;
  `winlogon` selector real at `:1832` under `SID_SYSTEM` at `:1831`; credential negatives confirmed
  by grep (`lsass` 0, `MiniDumpWriteDump` 0, `ReadProcessMemory` 0, `Samr` 0).
- **Verified the third shipped-broken feature:** `client\android_sources\pp.py` is **138 B** and
  prints `"pp.py is not replaced with working one!"`; `main.py:19-25` drives it in `while True` with
  no exit path. Third defect class after missing-file and commented-out×3.
- **Verified havoc-deep's corrected D8 counts against disk:** `modules/exploits/windows` = **53
  subdirs, 0 loose .rb**, matching its own correction of a fabricated tail.

## Lead measurement errors THIS round — four, all false discrepancies

I generated four false discrepancies by probing with instruments too narrow to succeed. None was a
lane error; all four were mine:

1. `\*End of D6\*` → 0 matches, so I nearly called covenant-deep's "exactly 1 trailer" wrong. **It is
   correct** — the trailer exists at `L4372` and my literal failed on an em-dash + mojibake.
2. D8 `##` headings = 9, so I nearly called havoc-deep's "8 sections" wrong. **8 is correct** — the
   ninth is `## TABLE OF CONTENTS`.
3. `malleable_c2.rb` and `reverse_http.rb` probed under invented paths → both "missing." **Both
   exist**, at `lib/msf/core/payload/` and `lib/msf/core/handler/`; havoc-deep cited them correctly.
4. D1 §22 claimed the 128 KB guard appears at "two" sites; re-measuring found **three** (`:132`,
   `:416`, `:575`). Fixed in the report.

**Standing rule for this corpus:** a probe that returns nothing is not a measurement until it is
shown able to succeed. Any count or path asserted from recall — by the Lead or a lane — is treated as
unverified until re-enumerated against disk. havoc-deep recorded the same failure mode as its own
§1.3.2; it has now hit five participants, six times.

## Lead verification performed this round (round 4)

- **havoc-deep's D8 §§1–8 cross-verified.** All four headline claims hold in raw source:
  `malleable_c2.rb:320-326` emits `TLV_TYPE_C2_UUID_PREFIX`/`_SUFFIX` (`:325`) with
  `require 'rex/post/meterpreter/packet'` at `:11` ✓; `packet.rb:986` excludes `PACKET_TYPE_CONFIG`
  from encryption ✓; `stager.rb:24` `StageEncodingFallback` default **true**, raising only when
  disabled (`:312`) ✓; `reverse_http.rb` is **`lib/msf/core/handler/reverse_http.rb`, 19,124 B** ✓.
  **Two of my own probe paths were wrong; havoc-deep's citations were right both times.**
- **Added one TLV havoc-deep did not name:** `malleable_c2.rb:324` also emits
  `TLV_TYPE_C2_ENC_UUID` via `encoding_flags_for(section)`. The malleable-C2 chain is **three TLVs**
  on CONFIG, not two — user-controlled encoding flag *and* prefix/suffix, all outside the cipher.
- **covenant-deep's U-4b cross-verified.** `client/common/jni_on_load.c`, **1,012 lines / 30,294 B**
  exact; `:899-911` `setup_jvm_class` fully commented out with live
  `dprint("NOT IMPLEMENTED: broken jvm setup")`; `:889-898` `JvmModuleDef` commented out so
  `JVM_Methods[]` (`:870`) is unreachable. Uninitialised `JavaVMAttackArgs args;` at `:930` passed to
  `AttachCurrentThread` `:944` and read at `:946` — confirmed defect.
- **task-16 race resolved.** My `team_task_create` returned id `task-16` before it was readable; the
  task is real (rev 1, pending, ready) and covenant-deep was right not to guess an id.
- **My own path error, third occurrence of the class:** `01_SOURCE_c2\pupy\` holds `client\` and
  `pupy\` as *siblings*, so paths are **not** uniformly doubled. I probed both ways and got one wrong.
  Recorded here so no lane repeats it.

## Delivered and verified

| Report | Target | Bytes | Sections | Lane |
|---|---|---|---|---|
| [D1_sliver_implant_code.md](D1_sliver_implant_code.md) | Sliver (Go) — implant + server | 132,939 | 21 (§0–§20) | lead |
| [D2_covenant_code.md](D2_covenant_code.md) | Covenant (.NET/C#) | 195,734 | 18 (§0–§18) | covenant-deep |
| [D4_mythic_code.md](D4_mythic_code.md) | Mythic (Go/TS/Python) | 77,300 | 15 (§1–§14) | havoc-deep |
| [D5_havoc_code.md](D5_havoc_code.md) | Havoc (C, Demon agent) | 243,155 | 15 (§1–§14) | havoc-deep |
| [D6_pupy_code.md](D6_pupy_code.md) | Pupy (embedded-CPython RAT) | 217,603 | §0–§13 | covenant-deep |
| [D7_metasploit_code.md](D7_metasploit_code.md) | Metasploit meterpreter (Ruby) | 106,203 | 14 (§1–§14) | havoc-deep |

**Six of six deep reports are on disk.** D1 is the only one still growing.

## In flight

| Report | Target | Status | Lane | Task |
|---|---|---|---|---|
| [D1_sliver_implant_code.md](D1_sliver_implant_code.md) | Sliver — server half (§21+) | growing | lead | task-11 |
| [D6_pupy_code.md](D6_pupy_code.md) | Pupy §13 — U-1 picocmd wire format, U-4 client/ C | growing | covenant-deep | task-14 |
| [D7_metasploit_code.md](D7_metasploit_code.md) | fixes: TLV count 18→**17**, TOC physical order | claimed | havoc-deep | task-15 |
| [D8_msf_exploit_side.md](D8_msf_exploit_side.md) | Metasploit exploit side (new target) | starting | havoc-deep | task-15 |

## Lead verification performed this span

Every lane handoff was independently checked against raw source before acceptance. Results:

- **havoc-deep's four D7 corrections — three exact, one corrected.** `lib/rex/encoder` **does not
  exist** (False); `lib/msf/core/encoder` **does** (True); file count **15,051** exact; handlers
  **24** exact. But §7's "18 extension maps" is **17**:
  `lib/rex/post/meterpreter/extensions` holds **23 subdirectories, zero `.rb` directly in it**, and
  exactly **17** `tlv.rb` — because `stdapi/railgun/tlv.rb` sits one level deeper than the other 16.
  A flat count gives 23, a one-level count gives 16, the truth is 17.
- **havoc-deep's headline D7 evidence — verified real.** The Justin Steven TODO is at
  `packet.rb:1003-1005` verbatim, and `packet.rb:976-978` does say **"scramble"** — so the
  XOR-is-obfuscation proof holds on the source's own wording, not just on instruction.
- **covenant-deep's headline D6 finding — verified.** `pupwinutils\persistence.py` genuinely does
  not exist (15-file dir), and `pupwinutils.persistence` is the **only** dangling `pupwinutils.*`
  reference in the tree. Claim upgraded from "unconfirmed" to **verified non-functional**.
- **Exact byte counts confirmed** for all six reports (D4 77,300 / D5 243,155 / D7 106,203).

**Both deep lanes were corrected by verification at least once, and both accepted it.** That is the
system working.

## Corrections applied to earlier reports

- **`T1_sliver_client.md` §8 items 1–2 — corrected on disk.** Item 1's "implant is entirely
  unexamined / unrecoverable" was **wrong**: the implant source is on disk and is now the most
  completely reversed target in the corpus. Item 2 (crypto call-site mapping) is **closed** by
  D1 §1's exclusion argument. Original text preserved struck through.
- **`T1_sliver_client.md` §8 item 5 — figure corrected.** Bare `17,153 files` → measured and split:
  **17,124 total / 15,283 vendored / 1,841 first-party**; `.go` **14,229 / 12,996 / 1,233**.
  Implant is **345 files / 283 `.go` / 1.4 MB**. Clone `HEAD` `8e5d2f9d` (2026-10-14) vs binary
  revision `422044af` (2026-10-03).
- **`D1` §2.1** — same measured split added so both documents reconcile to identical numbers.

## Headline results so far

### D1 — Sliver (lead)
- **§7 / §16: Sliver has no direct syscalls at ANY level.** Zero `.s`/`.asm` in 280 first-party
  `.go`; no Hell's Gate / Halo's Gate / SSN table; `syscalls_windows.go` is `mkwinsyscall` `//sys`
  decls resolving by name via `GetProcAddress`. **Extended into the whole dependency closure in
  §16.3:** the ~500 KB of vendored loader code (`sliverarmory/reflektor` → WireGuard's `memmod`)
  also resolves imports via `LoadLibraryEx` + `GetProcAddress`. Nothing in the shipped tree is
  syscall-stealthy.
- **§15: the evasion payload is a 1-byte `0xC3` patch** into `amsi.dll` (`AmsiScanBuffer`,
  `AmsiInitialize`, `AmsiScanString`) and `ntdll!EtwEventWrite`, operator-selected per execution
  via `AmsiBypass`/`EtwBypass`. Crude, heavily signatured, and **it works** — the exact inverse of
  Havoc, whose AMSI bypass is sophisticated but broken on x86.
- **§15.4: Sliver ships NO reboot persistence.** A targeted grep of all first-party implant `.go`
  returned exactly one service hit, and it is `StartManual` (lateral movement, not survival). No
  registry `Run` key, no scheduled task, no WMI subscription. Havoc, Pupy and Covenant all ship
  persistence; **Sliver does not**, by architecture.
- **§16: the implant's in-memory code-loading engine is not Sliver's.** `handlers_bof.go` is a
  62-line shim over `sliverarmory/reflektor`, a vendored ~500 KB COFF/ELF/Mach-O parser + relocator
  set whose own loader is **WireGuard LLC's `memmod`** (11/11 files carry the WireGuard copyright).
  Three nested provenance layers: WireGuard → reflektor → Sliver.
- **§13: `tunnel.go` is a deliberate hardened rewrite** — generation-scoped state, capacity-derived
  bounds, copy-on-enqueue, bounded close deadline. Four hardening decisions, each with a comment
  stating the reason.
- **§12: `DecryptWithoutSignatureCheck` closed** — exactly two call sites, both in the pivot path,
  both behind a handshake-time `MinisignVerify`. Not a vulnerability.
- **§11: pivots use two independent cipher contexts** and the Minisign-signed peer key is what makes
  a network of mutually-stranger implants cryptographically coherent.
- **§14: service enumeration runs deliberately UNPRIVILEGED** (raw Win32 with minimum rights,
  bypassing the Go library) — so it raises no elevation event.

### D2 — Covenant
- **R-1 CONFIRMED (high).** The server's `GruntTaskingStatus` carries
  `[JsonConverter(typeof(StringEnumConverter))]` (`GruntTaskingStatus.cs:17`, wants `"Completed"`)
  while the implant hand-emits `{"status":"3",...}` via `String.Format` + `.ToString("D")`
  (`GruntHTTP.cs:1054-1061`). **Task output is silently lost server-side, always.**
- T2's original "enum interop break" was wrong in mechanism and corrected in place (§2) — but a
  *different, real* break exists in the task-output path (§18).
- Jitter bug proven at **four identical sites** (`GruntHTTP.cs:94`, `GruntSMB.cs:88`,
  `GruntBridge.cs:88`, `Brute.cs:79`) → exactly 5,000 ms every cycle, forever.
- Implant TLS ceiling is `Ssl3|Tls` (`GruntHTTP.cs:858`) while the server does
  `Tls12|Tls11|Tls` (`HttpListener.cs:219-221`).
- `"CovenantDev"` hardcoded cert password on a `0.0.0.0` listener (`HttpListener.cs:56`).

### D5 — Havoc
- **The `Parser.c:127` wraparound, and its twin.** Attacker-controlled 4-byte `Length` →
  `8 - 4096` wraps to `0xFFFFF004` → all four downstream guards defeated → `LocalAlloc` +
  `MemCopy` of an attacker-chosen size = heap OOB read on every task dispatch.
  **`ObjectApi.c:190` `BeaconDataExtract` has the identical three lines with the identical
  missing check** — a codebase pattern, not a typo. (Both verified independently in raw source.)
- Fixed 16-byte IV never rotates → AES-CTR is a many-time pad; task-stream header is cleartext
  and unauthenticated.
- `LsaConnectUntrusted` + `LsaLookupAuthenticationPackage` + `LsaCallAuthenticationPackage` reads
  the calling session's own TGT **with no elevation** — the head of a delegation chain starting
  unprivileged.
- Nine corrections to the original brief, incl.: file counts inflated ~10×; **neither AMSI bypass
  works on a 32-bit agent**; **APC injection does not exist** despite being selectable.

### D6 — Pupy (complete, 163,503 B / 2,588 lines / §0–§12) — covenant-deep
- **HEADLINE — Windows persistence is NON-FUNCTIONAL as shipped.** `scriptlets/persistence.py:9`
  declares `pupwinutils.persistence` as a dependency, `:29` does
  `from pupwinutils.persistence import add_registry_startup`, and `:66` calls it — but
  **`pupy/packages/windows/all/pupwinutils/persistence.py` does not exist.** The directory holds 15
  files and no `persistence.py`. Independently verified by the Lead: `Test-Path` false, and
  `pupwinutils.persistence` is the **only** dangling `pupwinutils.*` reference in the entire tree —
  every other one resolves to a real file. So this is **verified non-functional**, not a packaging
  quirk. `ImportError` at scriptlet load. Linux persistence **does** ship
  (`packages/linux/all/persistence.py`, 13,088 B).
- **The corpus-level persistence contrast is a correction to the Lead's framing.** The Lead proposed
  "Sliver ships none, Pupy ships named persistence." The verified answer is sharper: **Sliver ships
  no persistence by architecture; Pupy ships persistence as a default-configured, named,
  OneDrive-masquerading feature — and ships it broken on Windows.** They fail in opposite
  directions. (`conf/pupy.conf.default:178-181`: `name = OneDriveUpdate` **and**
  `preferred_methods = 2,8,3,9` are both live.)
- **The Lead's own T6 errors, confirmed by the follow-up lane:** "10 transports" → **13**;
  `~576 .py` → **509**; `dnscnc` is a launcher, not a package (encoders live in `picocmd/`);
  `ec4.py` is at `network/lib/transports/`, not `cryptoutils/`; and *"two 64-byte RC4 halves"* is
  **superseded** — `key_size=128` at `ec4.py:65,:74`.
- **Two transport trees, and the Lead got this wrong while verifying.** `pupy\network\lib\transports\`
  (8 files, client side) vs `pupy\network\transports\` (13 packages, each with its own `conf.py`).
- **`ws/conf.py` — static, nonce-free C2 path (exact-match IOC).**
  `path = '/ws/' + md5(PATH_GEN_SECRET+b"ws").hexdigest()[:8]` — **32 bits, no per-session nonce**,
  and byte-identical in `client_transport_kwargs` and `server_transport_kwargs`. `^/ws/[0-9a-f]{8}$`
  matches every default `ws`/`dfws` beacon forever.
- **`DEFAULT_USER_AGENT` is Chrome 60.0.3112.90 claiming Windows NT 6.1** — a 2017 browser string
  on Windows 7. Exact-string IOC.
- **`ecpv.py` signature bug (`:221-224`):** big-endian `s` is NUL-padded on the **RIGHT**, so each
  pad byte multiplies by 256 instead of left-padding; `:230` reads it back → signature silently
  fails to verify (~1/256 per leading zero byte).
- **Signer/verifier asymmetry:** `pack` requires `t > 1` (`:216`), `unpack` accepts `t >= 0` (`:238`).
  The verifier is strictly more permissive — a malleability surface.
- **Replay-deterministic KEX guard** (`:253-254`): the same request returns the cached response and
  key, with no nonce freshness.
- KEX derives both directions from one key by byte reversal (`:273`), asserted as a **requirement**
  at `:407-411`.
- **`allow_v1` REFUTED** — the config key does not exist; zero tree-wide matches. The real V1 paths
  are three separate mechanisms.
- **`vidcap.pyd` x2 RESOLVED without disassembly** — the full C++ source ships in-repo at
  `packages/src/VideoCapture/src/vidcapmodule.cpp` (27,393 B); the two `.pyd` are build outputs.
- `dns_encoder.py:845` writes `TREES={...}` via `repr()` — which is why `dns_encoder_table.py` is
  8 lines with one 22,289-char line: machine-generated.
- Huffman tables are **retrained from the operator's own observed traffic** (`:747-838`), so a
  deployment's TREES can differ from the shipped ones.
- `agent/__init__.py:612` subclasses private `_bootstrap_external._LoaderBasics` — a concrete
  reason the loader is **version-locked to CPython 3.10**, not merely preferring it.
- **AMSI: reasoned NEGATIVE** — zero matches, and inapplicable by architecture (no .NET,
  bytecode-only, `MemLoadLibrary` bypasses `LoadLibrary` hooks).

### D7 — Metasploit (in flight, 76.7 KB)
- Closes T7's weakest gap: T7 had **zero binary/source evidence**. D7 reads real Ruby.
- Carried forward for verification: the live `decrypt_packet` TODO that enc-type mismatch is not
  enforced; 32-byte meterpreter header; cleartext per-packet IV; plaintext `TLV_TYPE_SYM_KEY=552`
  fallback; migration destroying encryption.
- §7 is a **negative finding**: Sliver does **NOT** do direct syscalls. No Hell's Gate, no Halo's
  Gate, no SSN table, no assembly at all in the implant (0 `.s`/`.asm` files across 280 first-party
  `.go`). The `syscalls` package is `mkwinsyscall` decls resolving via `GetProcAddress`.
  **Contrast with Havoc, which does implement both gates.** Two leading frameworks made opposite
  choices on the most-watched Windows evasion axis.
- §9 DNS transport: base32 subdomain tunnel, 24-bit random session ID, A-vs-TXT record choice
  (A carries *more* payload: 192 B vs 182 B), and a resolver **fingerprint + RTT-benchmark +
  prune** pass before committing to the tunnel.
- §10 WireGuard: the Ed25519 envelope-signing layer is **shared**, not mTLS-specific —
  `env-signing-v1:` seed and 512 MiB ceiling byte-identical between `mtls.go:63,65` and
  `wireguard.go:77,79`.

## Corrections applied

- **`T1_sliver_client.md` §8 items 1 and 2 — corrected in place.** Item 1 claimed the implant is
  "entirely unexamined / unrecoverable from T1." That conflated the *binary on hand* with the
  *target*: the implant **source is on disk** at `01_SOURCE_c2\sliver\implant\` (345 files / 283
  `.go` / 1.4 MB) and is the most completely reversed artifact in the corpus (see D1). Item 2
  (crypto call-site mapping) is **closed** by D1 §1's exclusion argument. Original text preserved
  struck through, with the reasoning, rather than silently deleted.
- **`T1_sliver_client.md` §8 item 5 — figure corrected.** The bare `17,153 files` is the entire
  clone and read as first-party. Now stated with the vendored split: **17,124 total / 15,283
  vendored / 1,841 first-party**, and `.go` **14,229 / 12,996 / 1,233**. The implant is **345
  files / 283 `.go`**. Clone `HEAD` `8e5d2f9d` (2026-10-14) vs binary revision `422044af`
  (2026-10-03).
- **`D1` §2.1 — same split added**, so both reports reconcile to identical measured numbers.

## Platform note

Effective teammate registration cap is 8 on this box; `interrupt_agent` does not release roster
entries. Two lanes (covenant-deep, havoc-deep) proved they can write reliably under the
incremental-append discipline, so the remaining three targets were re-assigned to them rather than
spawning new members. Write scopes are disjoint: task-11 (D1), task-12 (D6), task-13 (D4+D7).
