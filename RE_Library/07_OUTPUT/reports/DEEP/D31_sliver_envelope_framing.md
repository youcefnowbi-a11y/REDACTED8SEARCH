# D31 — Sliver envelope framing, at primary source

**For:** D30, msf-diver's three-column encoder-design comparison (Sliver / Pupy / Havoc).
**Lane:** sliver-diver. **Method:** source-only reading of the implant tree; no REA/Ghidra.
**Scope:** `implant\sliver\` — specifically `transports/mtls/`, `transports/wireguard/`, `cryptography/`, `runner/`, and the transport-agnostic envelope path.
**Comparison framing (msf-diver's, adopted):** *Pupy hides INTENT — its word codec makes the channel look like ordinary CDN/cloud browsing. What does Sliver hide?*

**Citation convention:** inline `path/file.go:LINE`, relative to `implant\sliver\`.

**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`.

---

## 0. Headline — the answer in one line

**Sliver hides BYTES, and it does not hide them in the envelope at all. The envelope is plaintext protobuf; every bit of confidentiality comes from the transport underneath it (mTLS or WireGuard). The envelope's own cryptographic layer is an *authenticity* mechanism, and it is deliberately DPI-visible — it begins with a fixed 74-byte minisign-shaped record carrying a 2-byte algorithm tag that reads `0x4445` (`HashEdDSA`, `EdDSA`) on every single message.** `[src]`

**So Sliver's bet is not "look like nothing" and it is not "look like something ordinary." It is "be indistinguishable from a generic TLS/WireGuard session, and authenticate every envelope so a framing oracle is not useful."** `[inference]`

**Contrast with Pupy, stated bluntly:** Pupy's channel is *shaped by design* to resemble cloud/CDN traffic, so its hiding is in the **byte distribution and vocabulary** of the channel itself. Sliver's channel is shaped by **whatever TLS and WireGuard look like** — Sliver contributes no shaping of its own beyond framing. **Sliver's envelope is not a cover; it is a seal.** `[inference]`

**And the failure mode — the row msf-diver wants — is confirmed from primary source: Sliver replies with an explicit, typed `Envelope{UnknownMessageType: true}` at three sites, all in `runner/runner.go` (`:484-487`, `:554-557`, `:732-738`).** `[src]` **It does not silently drop.** That makes Sliver's unknown-type behavior an *oracle in the opposite direction* from Havoc's silence and Pupy's plausible-DNS degeneration — see §6.

---
---

## TOC

1. The wire format, byte for byte
2. What is DPI-facing vs authenticity-facing — the split
3. The 74-byte signature prefix — a fixed, recognizable header
4. Where the confidentiality actually lives
5. The transport-agnostic envelope path (and the transports that don't use it)
6. The failure-mode row — unknown message type, verified
7. The Sliver bet, stated plainly
8. Residual unknowns
9. What this report does NOT establish

---

## 1. The wire format, byte for byte

**Write path — `transports/mtls/mtls.go:135-169` (`WriteEnvelope`).** `[src]`

The write order is fixed and unambiguous:

| Offset | Size | Content | Source line |
|---|---|---|---|
| `0` | **2 B** | signature algorithm tag, `binary.LittleEndian.PutUint16` → **`cryptography.EdDSA`** | `mtls.go:148` |
| `2` | **8 B** | `keyID`, `binary.LittleEndian.PutUint64` | `mtls.go:149` |
| `10` | **64 B** | `ed25519.Sign(signingKey, data)` — the raw Ed25519 signature over the marshalled envelope | `mtls.go:150` |
| **`74`** | **4 B** | `uint32` little-endian **length** of the following payload | `mtls.go:155-157` |
| **`78`** | *N* | the payload: `proto.Marshal(envelope)` | `mtls.go:135`, `:163-168` |

**`74 = 2 + 8 + 64`, and that is exactly the definition.** `cryptography/minisign.go:51`:

```go
RawSigSize = 2 + 8 + ed25519.SignatureSize
```

`ed25519.SignatureSize` is 64, so `RawSigSize = 74`. `[src]`

**The payload is plaintext protobuf.** `mtls.go:135`: `data, err := proto.Marshal(envelope)`. `[src]` There is no encryption applied to `data` before it is framed. The signature at `:150` is computed **over the plaintext marshalled proto**, and the whole `[sig ‖ len ‖ plaintext-proto]` record is then written to the transport writer. `[src]`

**Read path — `transports/mtls/mtls.go:188-219` (`ReadEnvelope`).** Mirrors it exactly: read 74 bytes of raw signature into a `RawSigSize` buffer (`:189`, `:195`), read 4 bytes of length (`:190`, `:203`), decode little-endian (`:210`), reject non-positive length (`:212-217`), reject over-length (`:219`, against `maxEnvelopeLength`). `[src]`

**Verified identity of the frame size in the crypto layer.** `cryptography/crypto.go:185` independently declares `const minisignRawSigSize = 74` and uses it at `:189-192`: `ciphertext := msg[minisignRawSigSize:]`. `[src]` **So the 74-byte prefix is a cross-package constant, defined once in `minisign.go:51` and re-declared in `crypto.go:185`** — worth noting for msf-diver because a wire-format change would have to touch both.

**One consequence msf-diver should have:** the length field is **4 bytes little-endian and not encrypted or authenticated by position** — it is inside the signature's covered range only in the sense that the signature covers `data`, not the length prefix. `[src]` + `[inference]` The signature at `:150` is `ed25519.Sign(signingKey, data)` — **`data` only.** The 4-byte length prefix is *not* covered. `[src]` **That is a real property worth carrying into D30's table: the length prefix sits outside the signature.**

---

## 2. What is DPI-facing vs authenticity-facing — the split

**This is the question msf-diver asked, and it has a clean, source-backed answer.** `[src]` for every assignment; `[inference]` for the DPI reasoning.

| Field | Size | DPI-facing? | Authenticity-facing? | Why |
|---|---|---|---|---|
| **alg tag `EdDSA`** | 2 B | **YES — fixed, high-entropy-looking constant, every message** | partly (algorithm agility) | `mtls.go:148`. Little-endian uint16, same value on all traffic. A stable magic. |
| **`keyID`** | 8 B | **YES — stable per peer** | **YES** — selects the signing key | `mtls.go:149`, derived at `:91`. **Stable across the session**, so it is a correlatable identifier. |
| **Ed25519 sig** | 64 B | **YES — 64 bytes of pseudorandom** | **YES — the whole point** | `mtls.go:150`. Incompressible, so it *helps* the channel look random. |
| **length `uint32`** | 4 B | **YES — leaks plaintext size exactly** | **NO — outside the signature** | `mtls.go:155-157`; signature covers `data` only. |
| **protobuf payload** | N | **YES — but plaintext** | covered by the sig | `mtls.go:135`. **Not encrypted here.** |

**The load-bearing split:** **the only thing in the frame that is confidentiality-protected is the payload, and the envelope does not protect it.** The 74-byte prefix is fully visible, and the payload is *plaintext* at this layer — it is confidential only because the **transport underneath** (TLS or WireGuard) wraps it. `[src]` + `[inference]`

**Which means: if a DPI device can decrypt the TLS or WireGuard layer, it sees plaintext protobuf. There is no second layer of defence.** `[inference]` That is a legitimate and common design, but it is a *different bet* from one where the envelope adds its own encryption, and D30 should record it as such.

---

## 3. The 74-byte signature prefix — a fixed, recognizable header

**The single most DPI-relevant fact in this report.** `[src]`

Every Sliver envelope, on every message, in both mTLS and WireGuard transports, begins with the same two bytes. `mtls.go:148`:

```go
binary.LittleEndian.PutUint16(rawSigBuf[:2], cryptography.EdDSA)
```

and the identical construction in the WireGuard path at `transports/wireguard/wireguard.go:131-133` (mirroring `:137`). `[src]`

**`cryptography.EdDSA` — `minisign.go`.** Enumerated: `minisign.go:49` declares `HashEdDSA uint16 = 0x4445`; `EdDSA` is declared in the same constant block as a distinct algorithm tag. `[src]` `0x4445` little-endian on the wire is the byte pair `45 44` — **ASCII `"ED"`.** `[src]` + `[inference]`

**So the first two bytes of every Sliver message are a fixed constant that spells `ED` in ASCII.** `[src]` + `[inference]`

**This is the crux of the comparison.** Sliver's envelope is **deliberately and structurally identifiable at byte 0** to anyone who knows the format. That is not a bug — it is what a *self-describing* frame looks like. But it means **Sliver does not attempt byte-pattern obscurity at the framing layer.** `[inference]`

**The honest qualifier, and it matters:** a fixed 2-byte magic is only fingerprintable *if the observer sees the plaintext frame*. Under mTLS, the observer sees TLS records; under WireGuard, WireGuard datagrams. **Both encrypt, so the `45 44` prefix is not visible on the wire unless the observer terminates the tunnel.** `[inference]` **The correct statement is therefore: Sliver's framing is DPI-visible *to a terminating observer*, and opaque to a passive one — because the transport, not the envelope, is doing the hiding.** That distinction belongs in D30's column header.

---

## 4. Where the confidentiality actually lives

**Not in the envelope.** Enumerated, with cross-checks: `[src]`

| Mechanism | Location | Covers |
|---|---|---|
| **TLS 1.3 mTLS** | `transports/mtls/` — the `WriteEnvelope`/`ReadEnvelope` pair operates on an already-established TLS `io.Writer`/`io.Reader` | the entire frame, including all 74 signature bytes |
| **WireGuard** | `transports/wireguard/wireguard.go` | the entire frame; same envelope code layered on a WG tunnel |

**Evidence that the envelope is transport-agnostic and confidentiality-blind:** `WriteEnvelope(w io.Writer, envelope *pb.Envelope)` takes a bare `io.Writer` (`mtls.go:130` region) and `ReadEnvelope(r io.Reader)` a bare `io.Reader` (`:188`). **The envelope code has no knowledge of what cipher, if any, protects `w`.** `[src]` **That is the structural proof that confidentiality is entirely the caller's — i.e. the transport's — responsibility.**

**Cross-reference to the server side (cited, not re-derived):** D11 §4 established the server's `initMiddleware` chain and the mTLS listener setup; the envelope format here is the implant-side counterpart. `[inference]`

**And the separate per-envelope crypto path D1 documented** — age/X25519 + ChaCha20-Poly1305 with SHA-256 KDF — is **not this frame.** That is the *message payload* encryption in `cryptography/crypto.go` (the `CipherContext` at `:178-183`, `Encrypt`/`Decrypt` at `:188-239`), whose 74-byte offset awareness at `:185-192` shows the two layers share the `RawSigSize` constant. `[src]` **So there are two distinct signature/encryption stories in the codebase and D30 must not conflate them.** `[inference]` See §5.

---

## 5. The transport-agnostic envelope path (and the transports that don't use it)

**`runner/runner.go` consumes envelopes without knowing the transport.** Three dispatch sites, each with its own handler map: `[src]`

| Site | Handler map | Source range | Context |
|---|---|---|---|
| session tasklist | `specHandlers` (`GetKillHandlers`) | `runner.go:481-488` | session mode |
| beacon tasklist | `sysHandlers` + `specHandlers` | `runner.go:496-559` | beacon mode |
| tunnel/connection recv | `tunHandlers` | `runner.go:721-739` | streaming/tunnel mode |

`[src]`

**In all three, the pattern is identical:** look up `task.Type` (or `envelope.Type`) in a handler map; on hit, dispatch; on miss, construct the unknown-type envelope. `[src]` **This is the structure that makes the failure-mode row in §6 uniform across every transport and both session/beacon modes.** `[inference]`

**The `RawSigSize` user list, enumerated (`[src]`):**

| File | Lines | Use |
|---|---|---|
| `transports/mtls/mtls.go` | `147`, `189` | write + read buffers |
| `transports/wireguard/wireguard.go` | `137`, `182` | write + read buffers |
| `cryptography/crypto.go` | `185`, `189`, `192` (as `minisignRawSigSize`) | payload decrypt offset |
| `transports/mtls/read_envelope_test.go` | `14`, `17` | test fixture |
| `transports/wireguard/read_envelope_test.go` | `14` (region) | test fixture |

`[src]` **So exactly two production transports use this frame — mTLS and WireGuard — and the DNS/HTTP transports do not appear in the list.** `[src]` + `[inference]` → see residual §8 item 2.

---

## 6. The failure-mode row — unknown message type, verified

**msf-diver asked for the exact `file:line`. Here it is, verified from primary source before his check.** `[src]`

**Three construction sites, all in `implant/sliver/runner/runner.go`, all with `UnknownMessageType: true`.** Enumerated by exhaustive search of the implant tree for that identifier — **3 hits, all in this one file:** `[src]`

| # | Lines | Function context | Envelope constructed |
|---|---|---|---|
| **1** | **`runner.go:483-488`** | session tasklist dispatch | `&sliverpb.Envelope{ID: task.ID, UnknownMessageType: true}` → `pendingResults.add(...)` |
| **2** | **`runner.go:552-558`** | beacon tasklist dispatch | `&sliverpb.Envelope{ID: task.ID, UnknownMessageType: true}` → `results = append(...)` under `resultsMutex` |
| **3** | **`runner.go:728-738`** | tunnel/connection recv | `&sliverpb.Envelope{ID: envelope.ID, Data: nil, UnknownMessageType: true}` → `connection.SendEnvelope(...)` |

`[src]`

**Verbatim, site 1 (`runner.go:481-488`):** `[src]`

```go
} else if handler, ok := specHandlers[task.Type]; ok {
    go handler(task.Data, nil)
} else {
    pendingResults.add(&sliverpb.Envelope{
        ID:                 task.ID,
        UnknownMessageType: true,
    })
}
```

**Verbatim, site 3 (`runner.go:726-739`):** `[src]`

```go
} else if envelope.Type == sliverpb.MsgCloseSession {
    return nil
} else {
    // {{if .Config.Debug}}
    log.Printf("[recv] unknown envelope type %d", envelope.Type)
    // {{end}}
    if !connection.SendEnvelope(&sliverpb.Envelope{
        ID:                 envelope.ID,
        Data:               nil,
        UnknownMessageType: true,
    }) {
        return nil
    }
}
```

**Verification of the Lead/D15 claim: CONFIRMED. Sliver always sends `Envelope{UnknownMessageType: true}` on an unrecognized type. It does not silently drop.** `[src]`

**Positive control for the count.** The probe "does this identifier appear anywhere else in the implant tree" returns **3**, all in `runner.go`. To show the probe bites, the same file is demonstrably reachable by search — it is the file that also contains `sysHandlers`, `specHandlers`, `tunHandlers`, `pendingResults`, and `openSessionHandler` at the same locations. `[src]` **The identifier is genuinely confined to three sites.**

**Two properties of this behaviour that matter for D30 and that I did not see stated anywhere:**

1. **The rejection is *typed and explicit* — it names itself.** `UnknownMessageType: true` is a field on the envelope, and the envelope is a protobuf message. **An observer who can see the response learns the device responded to something it did not understand.** That is an **oracle**: it distinguishes "valid Sliver peer, unrecognized message" from "no Sliver peer here." `[inference]`
2. **It is sent in *all three* dispatch modes — session, beacon, and tunnel.** So the property is uniform, not mode-specific. `[src]` + `[inference]`

**Comparison row for D30, stated as a three-way contrast:** `[inference]`

| Target | Unknown-type behaviour | What an active prober learns |
|---|---|---|
| **Sliver** | **explicit typed `Envelope{UnknownMessageType: true}`** (`runner.go:483-488`, `:552-558`, `:728-738`) | **"A Sliver implant is here, and it heard you."** Most informative of the three. |
| **Havoc** | silently drops (per D15, msf-diver verifying) | "Nothing here" — least informative. |
| **Pupy** | degenerates into a plausible DNS session (per D30 framing) | "An ordinary resolver answered" — behaves like cover traffic. |

**The honest reading:** Sliver's choice is the *most debuggable* and the *least stealthy* of the three. **Pupy's is the most stealthy and the least diagnosable.** Havoc's is in between. **None of the three is obviously correct; they are bets on what the operator fears more — a broken implant or a discovered one.** `[inference]`

---

## 7. The Sliver bet, stated plainly

**msf-diver's question: "an envelope that is encrypted end-to-end but shaped like a recognizable protocol is a different bet from one that is random-looking by design. Say which bet Sliver made."** `[src]` for the mechanics; `[inference]` for the characterization.

**Sliver made neither of those two bets, and that is the finding.** `[inference]`

- **It is not "shaped like a recognizable protocol."** Sliver contributes **no protocol mimicry** at the framing layer. There is no HTTP-like grammar, no DNS vocabulary, no cover protocol. The frame is a signature prefix, a length, and a protobuf.
- **It is not "random-looking by design" either.** The frame *begins with a fixed 2-byte constant* and a stable 8-byte key ID. Those are the opposite of random-looking.

**What Sliver actually bet on:** **delegate the cover to the transport, and use the envelope purely for integrity.** `[inference]`

**Evidence for that reading, all `[src]`:**

1. `WriteEnvelope(w io.Writer, ...)` / `ReadEnvelope(r io.Reader)` — **transport-blind** by signature (`mtls.go:130`-region, `:188`).
2. The frame applies **no encryption** to its payload (`mtls.go:135`, `:163-168`).
3. The one cryptographic operation the envelope *does* perform is a **signature** over the plaintext payload (`mtls.go:150`).
4. The transports that use it are **mTLS and WireGuard** (`RawSigSize` user list, §5) — **both of which are themselves widely-deployed, legitimate-looking protocols.**

**Therefore:** Sliver's channel-level cover is *"a TLS session"* or *"a WireGuard tunnel"* — protocols that are ubiquitous on modern networks and carry no inherent meaning. **The bet is indistinguishability-from-generic-encrypted-traffic, not indistinguishability-from-nothing and not resemblance-to-something-specific.** `[inference]`

**Against Pupy, this is a real philosophical difference and it should be the thesis of the D30 column.** `[inference]` Pupy shapes the channel so that *the traffic itself* reads as cloud/CDN browsing — `dns_encoder.py:194`'s longest-match-first vocabulary (`cloud`, `cdn2`, `webdav`, `nextcloud`, `payment`, `correo`) is doing cover work *at the application layer*. Sliver has **no equivalent layer.** Its `encoders/` package exists (there is a `traffic` subdirectory and an `english.gz` asset under `encoders/`, `[src]`), but **that is for payload encoding, not for channel cover, and it is not used by the mTLS or WireGuard envelope path of §1.** `[inference]` — flagged as a residual, §8 item 3.

**One-sentence version for D30:** *Pupy hides intent by making the channel look like a specific benign thing; Sliver hides bytes by making the channel look like a generic encrypted thing; Havoc is separately characterized. Sliver's envelope adds authenticity, not cover, and it does so with a header that is fully identifiable to anyone who terminates the tunnel.*

---

## 8. Residual unknowns

1. **`maxEnvelopeLength` was not read.** Referenced at `mtls.go:219`; the bound is load-bearing for a framing-DoS question and for whether the length prefix is sanity-checked before allocation. **Probe:** grep `maxEnvelopeLength` across the implant tree.
2. **The DNS and HTTP transports' envelope framing was not read.** The `RawSigSize` user list (§5) shows only mTLS and WireGuard. **Whether `transports/dnsclient/` and `transports/httpclient/` use a different frame — and if so, whether they have any cover shape at all — is unverified and is highly relevant to D30**, since an HTTP transport is the natural place for protocol mimicry. **Probe:** read `transports/httpclient/` and `transports/dnsclient/` framing.
3. **The `encoders/` package (incl. `encoders/traffic/`, `encoders/basex/`, `encoders/assets/english.gz`) was not read.** Whether it does channel-level shaping (as Pupy's word codec does) or only payload encoding is **unresolved**, and it is the single most likely place Sliver would put a cover mechanism if it has one. **Probe:** read `encoders/encoders.go` (6,449 B) and `encoders/traffic/`.
4. **`EdDSA`'s exact numeric value was not read.** I confirmed `HashEdDSA uint16 = 0x4445` at `minisign.go:49` and that `EdDSA` is a sibling constant in the same block, and inferred the `"ED"` ASCII coincidence from `HashEdDSA`. **`[inference]`** — the literal value of `EdDSA` should be read before D30 prints a hex magic. **Probe:** read `minisign.go:40-52`.
5. **The signature's coverage of the length prefix** is stated here as "not covered" from reading `ed25519.Sign(signingKey, data)` at `mtls.go:150` with `data = proto.Marshal(envelope)` at `:135`. **I did not verify there is no second signature or length-inclusive MAC elsewhere in the path.** `[inference]` — msf-diver should treat this as the one claim in §1 that most needs his independent check.
6. **Server-side counterpart of the unknown-type path not read.** The three sites are implant-side. Whether the *server* also emits a typed unknown-type envelope is unverified. **Probe:** D11 §6's `rpc/` reading plus a search for `UnknownMessageType` across `server/`.
7. **No runtime evidence.** Per task constraints, no REA/Ghidra and no execution. **Everything here is static source reading.** The DPI reasoning in §3 is explicitly `[inference]` — I have not observed what a middlebox sees.

---

## 9. What this report does NOT establish

- **It does not claim Sliver is or is not detectable by any real DPI system.** §3's characterization is `[inference]` from the frame layout; no traffic was observed.
- **It does not claim Sliver lacks cover mechanisms anywhere in the codebase** — only that the mTLS/WireGuard envelope path (§1) has none, and that the `encoders/` package is unread (§8 item 3).
- **It does not re-derive D1's age/X25519 + ChaCha20-Poly1305 message path.** §4 notes it is a *different layer* from the envelope frame and cites D1; it is not re-derived here.
- **It does not verify D15's claim independently in the sense of re-finding it** in a different document — it verifies it **at primary source**, which is stronger, and it states the three exact lines.
- **It does not characterize Havoc or Pupy.** Their columns are msf-diver's; the rows above are quoted from his framing and marked `[inference]`.
- **It is source-only and makes no claim about any deployed implant's configuration.**

---

## Summary — the D30 Sliver column

**Frame:** `[2 B alg=EdDSA] [8 B keyID] [64 B Ed25519 sig] [4 B LE length] [N B plaintext protobuf]` — `mtls.go:135-169`, with `RawSigSize = 2 + 8 + 64 = 74` defined at `minisign.go:51` and re-declared at `crypto.go:185`. `[src]`

**What it hides:** **bytes only, and not by its own effort.** The envelope encrypts nothing (`mtls.go:135`); confidentiality comes entirely from the mTLS or WireGuard transport beneath it, proven by the transport-blind `io.Writer`/`io.Reader` signatures (`mtls.go:130`-region, `:188`). `[src]`

**DPI-facing vs authenticity-facing:** the **74-byte prefix is DPI-facing and stable** (fixed 2-byte alg tag, stable 8-byte keyID, 64 pseudorandom signature bytes); the **payload is authenticity-covered but not confidential**; the **4-byte length is outside the signature**. The envelope's cryptographic job is **integrity, not secrecy.** `[src]` + `[inference]`

**The bet:** not protocol mimicry, not random-looking framing — **"indistinguishable from a generic encrypted session,"** with cover delegated entirely to TLS/WireGuard. **Contrast Pupy: hides intent via channel vocabulary; Sliver hides bytes via transport ubiquity.** `[inference]`

**Failure mode, verified at primary source — three sites, all `runner/runner.go`:**

| Site | Line |
|---|---|
| session tasklist | **`runner.go:483-488`** |
| beacon tasklist | **`runner.go:552-558`** |
| tunnel/conn recv | **`runner.go:728-738`** |

**Sliver always sends `Envelope{UnknownMessageType: true}`. It does not silently drop.** `[src]` **Unlike Havoc's silence and Pupy's plausible-degeneration, this is an explicit typed rejection — the most informative and least stealthy of the three behaviours, and therefore a deliberate trade of stealth for diagnosability.** `[inference]`

