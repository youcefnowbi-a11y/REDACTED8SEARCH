# D38 — Merlin Wire Protocol and the Boundary of the 286

**Lane:** archive-diver · **Date:** 2026-05-?? · **Method:** static analysis only — no execution, no network fetch, no disassembler opened.
**Write scope:** this file only. D29, D10, D11, D22, D17, STATUS.md untouched.

---

## Verification boundary — stated plainly, up front

| Boundary | Status |
|---|---|
| Binary provider (Ghidra/REA) | **NOT OPENED.** Shared single-target resource; not required for anything below. |
| Execution of any Merlin artifact | **NOT PERFORMED.** No Go runtime, no Ruby, no server started. |
| Network fetch / DNS / any URL touched | **NOT PERFORMED.** No reachability claim is made anywhere. |
| Merlin **Go source** read | **NOT AVAILABLE.** No Go source tree exists in this workspace (§5.1). Every protocol fact below is derived from **binary symbol tables, embedded strings, and the shipped `.json`/`.MD` files** — never from `.go` source. |
| D22's 286 Metasploit files read | **NOT READ, and deliberately so** — see §0.2 and §4. |

---

## Table of Contents

- [§0 Two corrections to the brief, before any finding](#0-two-corrections-to-the-brief-before-any-finding)
- [§1 Merlin's wire protocol — enumeration and count method](#1-merlins-wire-protocol--enumeration-and-count-method)
- [§2 The module schema — the on-disk half of the protocol](#2-the-module-schema--the-on-disk-half-of-the-protocol)
- [§3 The transformed channel — encoders and encrypters](#3-the-transformed-channel--encoders-and-encrypters)
- [§4 The 286 — bounded, not swept](#4-the-286--bounded-not-swept)
- [§5 R-29.3 — closing or bounding the strike against D29 §2](#5-r-293--closing-or-bounding-the-strike-against-d29-2)
- [§6 The corrupted `remote` field, quantified](#6-the-corrupted-remote-field-quantified)
- [§7 The DLL pair — pre-empted error, recorded and dropped](#7-the-dll-pair--pre-empted-error-recorded-and-dropped)
- [§8 Instrument record](#8-instrument-record)
- [§9 Residual unknowns](#9-residual-unknowns)
- [§10 Method notes](#10-method-notes)

---

## §0 Two corrections to the brief, before any finding

### 0.1 The brief's five asks are coherent, but two of them are not about the same target

`[inference]` The brief opens with *"D22 §7.5 names `286 unread protocol files`. That is the largest named gap in the corpus and it is yours to close"*, then immediately asks *"Merlin's protocol… nobody has read the protocol definition."* **The 286 and Merlin's protocol are two different targets.**

`[verified]` **The 286 is Metasploit.** D22 §4.1 line **261**: *"D9 covered only `http/` (16 files, 124,456 B). That leaves **286 files across 45 other protocol directories unread**."* D22 §7 U3 line **574**: *"`lib/rex/proto/` — 286 of 302 files unread… most heavily in `kerberos/` (81 files, 383 KB) and `smb/` (10 files, 181 KB)."*

`[verified]` `lib/rex/proto/` is **Rapid7's Ruby C2 framework**, in `01_SOURCE_c2\metasploit`. **Merlin is Go.** `[absence]` Probe: a recursive file census of the Merlin tree (§5.2) returns **86 files total under `data`**, of which **zero** are under any `lib/rex/` path. **Positive control:** the same census enumerates all 86 and their extensions, so the instrument bites.

`[inference]` **This is the same defect class as D29's Q4.** There, D11 §2 (DLL exports) and D11 §6 (agent release vs Debug) were fused into one brief against a binary that does not exist. Here, D22's Metasploit coverage ledger and the new Merlin protocol question are fused into one brief. **The tell is identical: a citation that is real, attached to a subject that is not.** §4 bounds the 286 as a cross-target item; §1 and §2 answer the Merlin question, which is what this deliverable is named for.

### 0.2 What that means for scope, decided up front

`[inference]` **I did not read Metasploit's `lib/rex/proto/`.** Reading 81 Kerberos files into a report titled `merlin_protocol_and_boundary.md` would produce a document whose name and contents disagree — the failure mode the corpus keeps recording. §4 gives the 286 a **census and a boundary statement** so the gap is honestly bounded rather than silently inherited or silently expanded.

---

## §1 Merlin's wire protocol — enumeration and count method

### 1.1 Where the protocol definition actually lives

`[verified]` **There is no `.proto` file, no `.go` source, and no protocol document in this tree.** A recursive census of the extracted Merlin archive returns **86 files under `data`** across exactly **7 extensions**:

| Extension | Count | Bytes |
|---|---|---|
| `.json` | **63** | 154,159 |
| *(no extension)* | 10 | 159,598,407 |
| `.MD` | 6 | 13,009 |
| `.exe` | 3 | 48,632,832 |
| `.dll` | 2 | 29,832,766 |
| `.def` | 1 | 882 |
| `.c` | 1 | 1,642 |

`[inference]` **The protocol is therefore defined in two places, and neither is a specification file:** the **Go type metadata compiled into the binaries**, and the **module JSON schema** shipped alongside them. §1 reads the first; §2 reads the second.

### 1.2 The protocol package, found in the agent

`[verified]` A regex sweep of the agent binary for Merlin-qualified symbols returns **386 unique strings / 649 occurrences.** The protocol package is a **separate Go module**:

```
github.com/Ne0nd0g/merlin-message
```

`[verified]` It has exactly **three sub-packages**, each carrying its own `Type.String` method — Go's `stringer` output, which is only generated for a **typed enum**:

| Package | Symbol evidence | Meaning |
|---|---|---|
| `merlin-message` | `merlin-message.Type.String` | **the base message** |
| `merlin-message/jobs` | `merlin-message/jobs.Type.String` | **job payload** |
| `merlin-message/opaque` | `merlin-message/opaque.Type.String` | **opaque payload** (padding / nonce) |

`[verified]` **Second method — the server carries the identical three.** Sweeping `merlinServer-Windows-x64.exe` returns the same three sub-packages, each with `Type.String`, `(*Type).String`, `init.0`, and `..inittask`. **Two binaries, same protocol package, same sub-package set.** `[inference]` This is the wire contract's structural footprint: agent and server must agree on these, and they do.

### 1.3 THE COUNT — three base message types, and how I counted

> **`[verified]` Merlin's base message has exactly THREE payload types: `opaque`, `jobs`, and `checkin`.**

**How the count was made — two independent methods, agreeing:**

`[verified]` **METHOD A — symbol topology.** Exactly **three** sub-packages exist under `merlin-message`, and each one independently implements a `Type` enum with a generated `String()` method. `stringer` does not emit `Type.String` for a package without a discrete enum, so **three stringers = three typed enums = three payload classes.** A fourth payload type would require a fourth sub-package or a fourth enum, and neither exists. **Count: 3.**

`[verified]` **METHOD B — the project's own CHANGELOG.** `merlin_extracted\CHANGELOG.MD` **line 364**, verbatim:

> *"Reduced base message payload types to just **opaque, jobs, and checkin**; Jobs payload now contains all other types"*

**Count: 3.** The CHANGELOG and the symbol table agree, and they are independent — one is prose written by the author, one is compiler-generated linkage metadata.

`[inference]` **METHOD B is the stronger of the two, and worth saying why.** The symbol table proves three *packages with enums* exist. Only the CHANGELOG states the *design intent* — that this is a **reduction** and that everything else was deliberately collapsed **into** `jobs`. That is a statement about protocol evolution, and it explains the shape: **`jobs` is not a peer of the others, it is the container for every other message kind.**

`[verified]` Corroborating, `CHANGELOG.MD` line **348**: *"Created constants for message types for easier comparison and switching."* `[verified]` line **126**: *"Replaced `github.com/Ne0nd0g/merlin/pkg/messages` with `github.com/Ne0nd0g/merlin-message`"* — confirming `merlin-message` is the **current** protocol module, not a legacy one. `[verified]` line **71** pins the version in use: **`merlin-message` to v1.3.0.**

### 1.4 The server-side handler set — 12 inbound message kinds

`[verified]` The **un-stripped server** exposes its method names, and `merlin/v2/pkg/agents.(*Agent)` carries **12 `Update*` methods plus their read accessors.** These are the server's inbound-message handlers:

| Handler | Accessor | Field it carries |
|---|---|---|
| `UpdateAlive` | `Alive` | liveness check-in |
| `UpdateAuthenticated` | `Authenticated` / `SetAuthenticated` | auth state |
| `UpdateBuild` | `Build` | agent build metadata |
| `UpdateComms` | `Comms` | comms profile |
| `UpdateHost` | `Host` | host identity |
| `UpdateInitial` | `Initial` | **first check-in payload** |
| `UpdateListener` | `Listener` | listener binding |
| `UpdateOPAQUE` | `OPAQUE` / `ResetOPAQUE` | opaque payload |
| `UpdateProcess` | `Process` | process listing |
| `UpdateNote` | `Note` | operator note |
| `UpdateStatusCheckin` | `StatusCheckin` | periodic check-in |
| *(links)* | `Links` / `AddLink` / `RemoveLink` | P2P link graph |

`[inference]` **The `Update*`/accessor pairing is itself evidence.** Every `UpdateX` has a matching `X` getter, and the pattern is exhaustive — there is no orphan `Update*` without a field, and no field without an `Update*`. **A field that is written is a field that is read, and both are named.** That is a property of a protocol that is internally consistent, and it is visible only because the server shipped un-stripped — which is **D29 §2's finding paying a second dividend**: the symbol asymmetry that D29 established as a Merlin trait is *why* the protocol's handler set is enumerable at all.

`[verified]` `merlin/v2/pkg/jobs.(*Info)` carries `ID`, `AgentID`, `Command`, `Created`, `Sent`, `Completed`, `Active`, `Cancel`, `Send`, `Status`, `StatusString`, `Token` — **the job lifecycle**, with a separate `jobs.Status.String` stringer, i.e. **a job-status enum distinct from the message-type enum.**

### 1.5 The wire field names — 66 enumerated from the agent binary

`[verified]` Go's `json:"…"` struct tags **are** the on-the-wire field names. Sweeping the agent yields **115 unique tags / 113 non-empty names.** These must be split, because the Go runtime links TLS and JOSE libraries whose tags are **not** Merlin's protocol:

| Class | Count | Evidence |
|---|---|---|
| JOSE / JWT (`aad`, `alg`, `ciphertext`, `crv`, `dp`, `dq`, `x5t#S256`, …) | **33** | `x5t#S256` has **zero** Merlin context within ±600 B |
| TLS stdlib (`cipher_suites`, `record_size_limit`, `max_vers`, …) | **14** | `record_size_limit`, `protocol_name_list`, `max_vers`, `min_vers` all sit in `golang.org/x/crypto/cryptobyte` / `crypto/internal` context, **merlin-pkg = 0** |
| **Merlin protocol** | **66** | the remainder |

`[verified]` **The classification was done by co-location, not by name-guessing, and it was verified by cross-checking against the server.** Ten ambiguous long tags were tested for presence in **both** binaries — `failedcheckin`, `waittime`, `maxretry`, `killdate`, `ja3`, `paddingmax`, `userguid`, `blob`, `integrity`, `skew` — and **all ten are present in both.** `[inference]` A field carried by both agent and server is a field on the wire.

`[verified]` **Merlin-specific field names in the set, which no generic library would supply:** `failedcheckin`, `keep_id`, `keep_data`, `padding`, `paddingmax`, `waittime`, `maxretry`, `killdate`, `skew`, `ja3`, `userguid`, `delegates` / `delegate`, `key_exchange`, `sysinfo`, `integrity`, `blob`, `token`.

`[inference]` **Six of these are the protocol's *behavioural* controls, not its data:** `waittime` + `skew` + `maxretry` + `failedcheckin` + `killdate` are the agent's **check-in timing and self-termination policy**, and `ja3` is a **TLS client fingerprint** the agent reports. **These are set by the server and obeyed by the agent — so the wire protocol carries command authority over agent timing, not just tasking.** That is a protocol property, and it is only visible because the tags are literal strings.

### 1.6 What is NOT established here

`[absence]` **The enum *values* — the literal message-type strings — were not recovered.** Probe: a scan of the 8.25–8.60 MB region of the server for a contiguous string blob containing the candidate type names returned **gRPC logging identifiers** (`GrpcLogEntry`, `statusCode`, `payloadTruncated`), not a stringer table. **Recorded as a failure in §8.2, not written up as a finding.** Positive control: the same blob-extraction method correctly returned the Merlin package names elsewhere in the file, so the method bites.

`[inference]` **What would close it:** the `merlin-message` v1.3.0 source, or a provider decompile of `merlin-message.Type.String` (a small switch, resolvable in one function). **Neither was required for the count in §1.3**, which rests on package topology and the CHANGELOG.

---

## §2 The module schema — the on-disk half of the protocol

### 2.1 The template directory IS the schema definition

`[verified]` `data\modules\templates\` contains exactly **two files**, and they are the authoritative field definitions for a module:

**`base.json` (500 B)** — the `base` object, **15 fields**: `name`, `type`, `author[]`, `credits[]`, `path[]`, `platform`, `arch`, `lang`, `privilege`, `remote`, `local[]`, `options[]`, `description`, `notes`, `commands[]`.

**`powershell.json` (92 B)** — the type-specific payload, **3 booleans**: `disableav`, `obfuscate`, `base64`.

`[inference]` **This is the protocol's second surface and it is a different kind of thing from §1's wire format.** §1 is what agent and server exchange over the network; §2 is what the **operator** provides to the server, and what the server **converts into** the commands an agent will run. **The `commands[]` array in `base.json` is the bridge** — it is the literal command line the agent's shell executes.

### 2.2 The discriminator — and it is not what the README says

`[verified]` The README (`modules\README.MD` line **18**) states the field is *"`type` | string | `standard` or `extended`"*. The **actual distribution across all 63 modules:**

| `base.type` | Count |
|---|---|
| `standard` | **55** |
| `extended` | **6** |
| **absent** | **2** |

| Top-level key set | Count |
|---|---|
| `base` only | **39** |
| `base` + `powershell` | **22** |
| `base` + `additionalInstructions` | **1** |
| **`powershell` only — no `base` at all** | **1** |

`[verified]` **Both anomalies are explained, and neither is a defect:**

1. **`modules\templates\powershell.json`** is the source of the `powershell`-only key set — **it is one of the two template files from §2.1, not a module.** `[inference]` Any census that counts "63 module JSONs" and then partitions by top-level keys will see this as a broken module. **It is a schema fragment living in a module-shaped directory.** Recorded because a future lane will hit it.
2. **`modules\linux\x64\bash\troll\Prank.json`** has `base` but **no `type` field whatsoever.** `[verified]` Its `base` fields otherwise match the template exactly. **This is a real module with a missing discriminator** — the same defect family as §6's corrupted `remote`: **a field the schema declares as required-ish that nothing validates.**

`[inference]` **The blank-`type` module is the more interesting of the two, and the README explains why it may be harmless.** README line **184**: *"type is currently lacking. At this time is being used as placeholder."* **The `type` field is documented as a placeholder** — which means its absence may be tolerated by the loader. **Not asserted:** whether `Prank.json`'s missing `type` breaks it at runtime is a **runtime** question, and nothing here was executed. Stated as `[inference]`, bounded.

### 2.3 The `standard` / `extended` split, and what it means for the protocol

`[verified]` README lines **37–49** define the axis precisely:

- **`standard`** — *"does not leverage any Go packages or functions from the `pkg/modules` directory"* — a command string, executed as-is.
- **`extended`** — *"DOES leverage code from an associated package `pkg/modules`"*, must *"expose a `Parse()` function that returns an array of strings that contain commands for the agent"*, and must be *"programmed into the `getExtendedCommand()` function in `modules.go`."*

`[inference]` **The `extended` path carries Go code execution inside the agent.** 6 of 63 modules are `extended`. `[verified]` This corroborates **D10's finding** that all 6 `extended` modules have an empty `remote` — they don't fetch, they call compiled-in functions. **Two lanes, independent methods, same partition.**

`[inference]` **The `Parse()` contract is the protocol-relevant fact:** `extended` modules return **an array of commands**, i.e. **the same `commands[]` shape the wire carries.** The extended path is a *generator* for the standard path's input. That is why one `commands[]` field suffices in the schema.

### 2.4 The `options[]` sub-schema

`[verified]` `base.json` defines `options[]` as an array of objects with **5 fields**: `name`, `value`, `required` (bool), `flag`, `description`. The template ships **two** entries — one `required: true`, one `required: false` — i.e. **the template demonstrates both polarity cases.**

`[inference]` **`flag` is the operator-facing command-line name and `name` is the internal key**, so the server maps an operator's CLI token onto a module argument. README line **68** confirms *"a list that of an object type that requires 4 parts"* — **the README says 4, the template implements 5.** `[inference]` The README is stale relative to the template. Minor, recorded for completeness.

### 2.5 Why this section matters to §1

`[inference]` **The module JSON and the wire protocol are two ends of one pipeline, and the `commands[]` field is where they meet.** An operator supplies `base` (with `options[]`, `remote`, `local`); the server resolves it into `commands[]`; the agent receives `commands[]` in a `jobs` message (§1.3) and executes them. **§1's `jobs` container is the delivery mechanism for §2's `commands[]` payload** — which is exactly the CHANGELOG's line 364 claim that *"Jobs payload now contains all other types."* **The two sections are consistent, and they were derived independently.**

---

## §3 The transformed channel — encoders and encrypters

### 3.1 The enumeration — 7 transformers, and a corrected first draft

`[verified]` The agent binary names its transformer sub-packages explicitly. **All 46 distinct `transformers/*` symbols were printed and grouped, not estimated:**

| Direction | Sub-packages | Count |
|---|---|---|
| **Encoders** | `base64`, `gob`, `hex` | **3** |
| **Encrypters** | `aes`, `jwe`, `rc4`, `xor` | **4** |
| | | **7 total** |

`[verified]` **METHOD B — subdirectory extraction.** Matching `transformers/<dir>/<name>` and deduplicating on the pair returns the identical **7**: `encoders/{base64,gob,hex}`, `encrypters/{aes,jwe,rc4,xor}`. **Both methods agree at 7.**

`[verified]` **This section's first draft said "5 encoders and 5 encrypters," extrapolated from the five *symbol suffixes* I saw in a prior probe.** The suffixes were `gob.`, `rc4.`, `base64.`, `xor.`, `hex.`, `aes.`, `jwe.` — **trailing-dot symbol fragments, not directory names.** Printing the full match list is what caught it. **Recorded in §8.3 as this lane's first instrument failure on D38.** The number 10 was an estimate wearing an enumeration's clothes.

### 3.2 The uniform interface — `Construct` / `Deconstruct` / `String`

`[verified]` **All 7 transformers implement the same three-method surface:**

```
transformers/encoders/base64.(*Coder).Construct
transformers/encoders/base64.(*Coder).Deconstruct
transformers/encoders/base64.(*Coder).String          ← and identically for gob, hex
transformers/encrypters/aes.(*Encrypter).Construct
transformers/encrypters/aes.(*Encrypter).Deconstruct
transformers/encrypters/aes.(*Encrypter).String       ← and identically for jwe, rc4, xor
```

`[inference]` **`Construct`/`Deconstruct` is a Go interface, and the near-miss method names are evidence of it.** `encoders` use receiver `*Coder`; `encrypters` use `*Encrypter` — **two distinct interfaces with the same method contract.** `Deconstruct` (not `Decode`) is the shared vocabulary, which means the abstraction is **byte-slice-in / byte-slice-out in both directions** — a transformer cannot need to know what it is transforming. `[inference]` That is what lets the agent compose them freely.

`[verified]` **A minority of transformers expose extra direction-specific methods:** `gob` adds `Encode`/`Decode`; `aes` adds `encrypt`/`decrypt` (unexported, lower-case); `jwe` adds only `(*Encrypter).encrypt`; `rc4` adds `xor`; `xor` adds `xor`. `[inference]` **The asymmetric ones are the ones with internal state or two-way mapping** — `gob`, `aes` and `jwe` all need direction-specific code; plain `xor` and `rc4` are self-inverse and need only one path.

### 3.3 The pipeline reading, and the correction it forces

`[inference]` **The two-level directory structure reads as a chain, not a menu.** A protocol offering independent alternatives would use one field with 7 values. **`transformers/encoders/…` and `transformers/encrypters/…` as siblings, each holding a closed set, describes encode-then-encrypt on egress and decrypt-then-decode on ingress.**

`[verified]` Corroborating: the base message carries a `token` field (§1.5), and `CHANGELOG.MD` line **482** states *"Base messages now contain a token; used to send an agent an encrypted JWT."* `[inference]` **`jwe` (JSON Web Encryption) is present as an encrypter — it is the JWT mechanism that line describes.**

`[inference]` **The `gob` encoder is the load-bearing one.** Go's `gob` is **self-describing** — it serializes Go type information into the stream. `[verified]` `base64` and `hex` are text-safe by contrast. `[inference]` **The encoder choice tracks the transport**: a text-mode HTTP channel needs base64/hex; a raw socket takes `gob` directly. `[verified]` This is consistent with the **five client packages** — `http`, `memory`, `smb`, `tcp`, `udp` — each a separate Go package in the agent.

### 3.4 The asymmetry this section found: the server has NO transformers

`[verified]` **The identical `transformers/<dir>/<name>` probe against `merlinServer-Windows-x64.exe` returns ZERO matches.** `[verified]` **Positive control:** the same probe against the agent returns **7**; and the same server binary *does* yield 386 Merlin-qualified symbols elsewhere, so the sweep method works on that file.

`[inference]` **The server does not implement encoding or encryption at all — it delegates the entire transform to the agent.** That is a **structural asymmetry of the same shape D29 §2 established for symbols**: one side carries the machinery, the other does not. `[inference]` **And it is the same direction as D29's finding** — the *agent* holds the transformers, the *operator* side holds the schema and the log. **The two lanes' asymmetries point the same way, which is weak mutual corroboration that the split is deliberate rather than incidental.**

`[inference]` **Consequence, and it loops back to D29 §3.5.** D29 established that module `remote` URLs are fetched **by the agent at runtime** over the agent's transport. §3 shows that transport is **one of five client packages, parameterised by a choice of 3 encoders × 4 encrypters.** `[inference]` **A defender cannot assume a fixed Merlin byte-signature** — the channel is parameterised on two independent axes and **the server end is agnostic to both.** D29 §3.5's deployment-property framing is corroborated without re-derivation.

`[absence]` **Whether the *operator* (CLI) side also lacks transformers was NOT tested.** `merlinCLI-*` binaries were not swept. Stated as an unclosed bound, not as a negative.

---
