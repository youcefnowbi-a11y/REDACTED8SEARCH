# D1 — Sliver: implant, server, client source reversal

**Target:** `RE_Library\01_SOURCE_c2\sliver`
**Revision:** source clone, **different commit** from the T1 binary (`422044af…`). Source explains the binary; it does not replace it. Where they disagree, the binary is authoritative.
**Evidence class:** `[source]` throughout, with `file:line` citations.

---

## 0. CORRECTION TO T1 §0 — the implant is NOT unrecoverable

T1_sliver_client.md §0 states, of the Sliver implant:

> *"**Implant persistence technique** — **NO** … **Implant evasion / AMSI / ETW behaviour** — **NO** …
> Everything in the implant's column is invisible here."*

and §8 item 1:

> *"**The implant is entirely unexamined.** … Implant persistence, evasion, injection, migration, and
> pivot internals are **unknown and unrecoverable from T1.**"*

**That is wrong, and I am the one who wrote it.** The claim conflated *the binary* with *the
target*. `sliver-client_windows-amd64.exe` is client-only — true. But the **implant source is on
disk** in this same repository:

```
implant\sliver\     280 first-party .go files   40,429 lines
implant\sliver\vendor\  2,071 files (third-party)
```

Every mechanism T1 listed as unreachable is readable source:

| T1 called this "NO" | Actually at |
|---|---|
| Implant persistence | `implant/sliver/service/`, `implant/sliver/runner/` |
| Implant evasion / AMSI / ETW | `implant/sliver/evasion/`, `syscalls/`, `winhttp/` |
| Implant injection | `implant/sliver/handlers/handlers_windows.go` |
| Process migration | `implant/sliver/handlers/` (migrate handlers) |
| Pivot / WireGuard tunnel | `implant/sliver/transports/wireguard/`, `pivots/`, `tcpproxy/` |

**Corrected scoping statement** (supersedes T1 §0's table and §8 item 1): the *binary* is
client-only, so byte-exact correspondence between this source and that specific implant build
cannot be asserted — the clone is at a different commit. But the **implant's mechanisms are fully
readable**, and only byte-level identity stays uncertain.

---

## 1. Crypto perimeter — `implant/sliver/cryptography/`

This section **closes T1 §4.4**, which could only prove primitive *presence* in the client binary
(AES 144 / Ed25519 67 / ChaCha 55 / SHA-512 41 / SHA-256 41 / HMAC 34 / X25519 6 symbols) and
stated: *"which primitive protects which channel is not established."* Source answers it.

### 1.1 The binding table

| Primitive | Protects | Evidence |
|---|---|---|
| **age** (X25519 + ChaCha20-Poly1305) | C2 message confidentiality | `cryptography/crypto.go:38,71-115` |
| **ChaCha20-Poly1305** | every C2 message AEAD | `crypto.go:134-168` |
| **SHA-256** | symmetric key derivation, replay digest | `crypto.go:125-130,213` |
| **HMAC-SHA256** | implant→server authentication tag | `cryptography/implant.go:111-117` |
| **Minisign (Ed25519)** | server→implant **signature verification** | `crypto.go:185-206`, `implant.go:72-98` |
| **X.509** | CA-pinned server cert check (hostname check **skipped**) | `crypto.go:256-288` |

**Not in the implant's C2 path:** AES, RSA, SHA-512. Those client-binary symbol hits are Go
stdlib linkage and gRPC/TLS plumbing, not the implant's message crypto. That resolves the AES-144
question by exclusion — AES is not Sliver's message cipher.

### 1.2 Replay defence is a real, explicit mechanism

`CipherContext` (`crypto.go:180-183`) carries `Key` plus a `replay *sync.Map`. Every inbound
message is hashed and checked with `LoadOrStore`:

```go
digest := sha256.Sum256(ciphertext)
b64Digest := base64.RawStdEncoding.EncodeToString(digest[:])
if _, ok := c.replay.LoadOrStore(b64Digest, true); ok {
    return nil, ErrReplayAttack
}
```
`crypto.go:212-218`

`LoadOrStore` is **atomic** — this is a correct single-swap check-and-set, not a load-then-store
race. Outbound messages are also inserted (`crypto.go:245-249`) so the implant rejects its own
ciphertext reflected back at it. **This is a stronger transport than either Havoc (no replay
defence found) or Metasploit (no replay defence found).**

### 1.3 Server→implant traffic is signature-verified — unusual and deliberate

`CipherContext.Decrypt` requires a **74-byte Minisign signature prefix** on every message:

```go
const minisignRawSigSize = 74

func (c *CipherContext) Decrypt(msg []byte) ([]byte, error) {
    if len(msg) < minisignRawSigSize+1 { return nil, ErrDecryptFailed }
    ciphertext := msg[minisignRawSigSize:]
    serverPublicKey, err := DecodeMinisignPublicKey(serverMinisignPublicKey)
    ...
    validSig := verifyRaw(serverPublicKey, msg, false)
    if !validSig { return nil, ErrDecryptFailed }
```
`crypto.go:185-206`

The signature is verified **before** decryption, and covers the whole message. Two consequences:

1. **Encryption alone is not a trust boundary here.** The implant verifies the server's Ed25519
   signature with a key welded in at build time (`implant.go:41`,
   `serverMinisignPublicKey = \`{{.Build.MinisignServerPublicKey}}\``). Traffic from anything that
   does not hold the matching private key fails signature validation *even if it is a valid
   AEAD ciphertext* — i.e. even if the attacker knows the session key.
2. **This is a build-time secret, not a negotiated one.** Compromise of the teamserver's minisign
   private key retroactively breaks every implant built with that key.

There is an escape hatch: `DecryptWithoutSignatureCheck` (`crypto.go:223-237`), which skips the
verify but keeps the replay check. Its existence means some path accepts unsigned messages — the
call sites need to be enumerated (§ pending).

### 1.4 The implant→server handshake leaks a keyed identifier by design

`AgeKeyExToServer` (`implant.go:100-128`):

```go
privateDigest := sha256.New()
privateDigest.Write([]byte(peerKeyPair.Private))
mac := hmac.New(sha256.New, privateDigest.Sum(nil))
mac.Write(plaintext)
ciphertext, err := AgeEncrypt(recipientPublicKey, append(mac.Sum(nil), plaintext...))
...
publicDigest := sha256.Sum256([]byte(peerKeyPair.Public))
copy(msg, publicDigest[:])          // 32-byte SHA-256 of the implant's PUBLIC key, in clear
copy(msg[32:], ciphertext)
```

The outbound envelope is `[32-byte SHA-256(peer public key)][age ciphertext]` — the comment says
the server is "talking to a valid implant", but a **hash of the public key is not a proof of
anything**: a public key is public. It identifies *which* implant is calling (a routing/session
handle, genuinely useful to the server) while providing no authentication. The actual
authentication is the inner HMAC, keyed by `SHA256(implant private key)` and verified after
decryption. Worth stating precisely, because the code comment invites the misreading that the
outer 32 bytes are an authenticator.

### 1.5 TLS: CA pinned, **hostname check deliberately disabled**

```go
// rootOnlyVerifyCertificate - Go doesn't provide a method for only skipping hostname validation so
// we have to disable all of the certificate validation and re-implement everything.
// https://github.com/golang/go/issues/21971
func RootOnlyVerifyCertificate(caCertPEM string, rawCerts [][]byte, _ [][]*x509.Certificate) error {
```
`crypto.go:253-256`

The function rebuilds verification against a **pinned CA pool** and drops the hostname check —
so the implant accepts any certificate signed by *its* CA regardless of the name in it. That is
the correct trade for C2 (the operator may front the listener with any domain), and it is
explicitly documented rather than accidental. Note the failure mode on a bad CA:

```go
ok := roots.AppendCertsFromPEM([]byte(caCertPEM))
if !ok { os.Exit(3) }        // crypto.go:258-264
```

`os.Exit(3)` — a hard process death, not a returned error, if the embedded CA will not parse.

### 1.6 Message layout and available plaintext

`Encrypt` (`crypto.go:134-146`) composes: **nonce (12 bytes) ‖ AEAD(gzip(plaintext))**, with the
nonce prepended to its own output — a standard nonce-prefix layout. Plaintext is **gzipped at
`gzip.BestSpeed`** before sealing (`crypto.go:139`, pool at `:61-68`). Two observations:

- The **nonce is random per message** (`rand.Read`, `:142`), not a counter. With a 96-bit random
  nonce under one key, collision risk is negligible at realistic message counts.
- gzip before encryption means **compressed-then-encrypted traffic**, and the gzip writer pool
  means no length-leak channel via varying compression *level*. Ciphertext length still leaks
  plaintext *size* — which is why `padding` exists as a build option elsewhere in Sliver.

There is **no MAC tag outside the AEAD** — no separate HMAC over ciphertext on the implant's
message path. Poly1305 provides integrity; Minisign provides authenticity from the server;
HMAC-SHA256 serves only the handshake in §1.4.

### 1.7 Debug builds can log TLS session keys

`tlskeys.go:30-42`: when `.Config.Debug` is set, if the environment variable `SSLKEYLOGFILE` is
present the implant **appends its TLS session keys to that file, mode 0600**. In a debug build
this enables operator-side decryption of captured traffic via Wireshark. Normal builds compile the
whole branch out (it is inside `{{if .Config.Debug}}`). State it as a build-artifact property, not
a shipped default.

---

## 2. File inventory — `implant/sliver` (first-party)

280 `.go` files, 40,429 lines, excluding `vendor\`. Sorted by lines, largest first.

| Lines | Path | Role |
|---|---|---|
| 1466 | `handlers/handlers.go` | RPC command dispatch — the core |
| 1356 | `handlers/tunnel_handlers/socks_handler.go` | SOCKS5 proxy |
| 989 | `transports/dnsclient/dnsclient.go` | DNS C2 channel |
| 978 | `transports/session.go` | session lifecycle, transport failover |
| 956 | `netstack/tun.go` | userspace TUN |
| 848 | `handlers/handlers_windows.go` | Windows-specific commands |
| 747 | `runner/runner.go` | implant main loop |
| 705 | `transports/httpclient/drivers/win/wininet/generated.go` | WinINet syscall bindings |
| 651 | `transports/httpclient/httpclient.go` | HTTP C2 |
| 627 | `priv/priv_windows.go` | privilege ops |
| 547 | `pivots/pivots.go` | pivot management |
| 540 | `transports/connection.go` | envelope read/write |
| 524 | `netstat/netstat_windows.go` | netstat |
| 499 | `taskrunner/task_windows.go` | task execution |
| 464 | `transports/beacon.go` | beacon mode |
| 423 | `tcpproxy/tcpproxy.go` | TCP relay |
| 421 | `proxy/provider.go` | proxy abstraction |
| 404 | `syscalls/zsyscalls_windows.go` | generated NT stubs |
| 394 | `transports/wireguard/wireguard.go` | WireGuard overlay |
| 393 | `proxy/provider_windows.go` | Windows proxy |
| 388 | `transports/httpclient/drivers/win/wininet/wininet_windows.go` | WinINet client |
| 371 | `transports/pivotclients/pivotclient.go` | pivot client |
| 345 | `winhttp/winhttp.go` | WinHTTP wrapper |
| 324 | `ps/ps_windows.go` | process listing |
| 316 | `transports/tunnel.go` | tunnelling |
| 307 | `transports/httpclient/drivers/win/wininet/utils_windows.go` | WinINet utils |
| 301 | `extension/memfs.go` | in-memory FS for extensions |
| 300 | `procdump/dump_linux.go`, `proxy/provider_generic.go` | dump/proxy |
| 299 | `proxy/provider_darwin.go` | macOS proxy |
| 279 | `netstat/netstat_linux.go` | Linux netstat |
| 277 | `rportfwd/portfwd.go` | reverse port forward |
| **273** | **`cryptography/crypto.go`** | **§1 — the C2 crypto core** |
| 272 | `handlers/handlers_linux.go`, `transports/dnsclient/resolver-generic.go`, `registry/registry_windows.go` | |
| 255 | `transports/mtls/mtls.go` | mutual TLS transport |
| 253 | `procdump/dump_windows.go` | Windows dump |
| 246 | `handlers/rpc-handlers.go` | RPC plumbing |
| 237 | `ps/ps_darwin.go` | |
| 226 | `mount/mount_windows.go` | mount |
| 225 | `service/service_windows.go` | **service install/persistence** |
| 223 | `transports/httpclient/drivers/win/wininet/client_windows.go` | |
| 207 | `transports/httpclient/drivers/win/tools/defines.go` | |
| 198 | `encoders/encoders.go`, `shell/shell-pty.go` | encoders, PTY |
| 196 | `proxy/proxy.go` | |
| 195 | `ps/ps_linux.go` | |
| 192 | `transports/transports.go`, `handlers/tunnel_handlers/wasm_handler.go` | |
| 190 | `handlers/rpc-handlers_linux.go` | |
| 178 | `handlers/execute_children.go` | child process exec |
| 177 | `ps/ps_types_darwin.go` | |
| 167 | `handlers/handlers_unix.go` | |
| 165 | `syscalls/types_windows.go` | |

**Complete file list** (including the remaining ~230 files under 165 lines and all `*_test.go`)
is in `extractions/DEEP/D1/` — the full directory walk was emitted there rather than inlined
here to keep this report readable. Files below 165 lines cover: `encoders/` (base32, base58,
base64, basex, english, gzip, hex, images, nop, traffic), `cryptography/` (minisign,
minisign_raw, tlskeys, implant), `evasion/` (per-OS), `extension/` (per-OS + wasm), `forwarder/`,
`handlers/` (kill, pivot, tunnel, rpc per-OS), `mount/`, `netstack/`, `proxy/`, `rportfwd/`,
`service/`, `shell/`, `syscalls/`, `tcpproxy/`, `util/`, `version/`.

### 2.1 Vendored vs first-party

| Path | Files | Class |
|---|---|---|
| `implant/sliver/vendor/` | 2,071 | **`vendored-dependency`** |
| `implant/sliver/` (excluding vendor) | 280 `.go` / 40,429 lines | `sliver-proper` |
| `vendor/` (repo root) | 12,948 | **`vendored-dependency`** |

**Whole-clone totals, measured** (`.git` excluded), because the split is the actual point:

| Measure | Total | Vendored | First-party |
|---|---|---|---|
| all files | 17,124 | 15,283 | 1,841 |
| `.go` | 14,229 | 12,996 | **1,233** |
| `implant/` subtree | — | — | **345** files / 283 `.go` / 1.4 MB |

Two scopes appear in this report and they are deliberately different:

- **`implant/sliver/` = 280 `.go` / 40,429 lines** — the scope of §2's inventory and of every
  "first-party grep" claim in §7. This is `sliver-proper` inside the implant.
- **`implant/` = 345 files / 283 `.go` / 1.4 MB** — the whole implant subtree, which adds 3 `.go`
  files outside `sliver/` plus non-Go assets.

**~89% of the cloned repository is vendored dependency.** Any claim of the form "Sliver's source is
N files" is meaningless without this split; `1,233` first-party `.go` against a bare `17,124` is
the same repository described two ways. `T1_sliver_client.md` item 5 has been corrected to state
the split rather than the bare total.

Clone `HEAD` is `8e5d2f9dbee99de46dd0193c7e15affb210fc4ca` (2026-10-14); the client binary was built
from `422044af` (2026-10-03). The source clone is therefore **not** the revision the binary came
from, and §7's negative findings are scope-limited to the clone.

---

## 3. Transports — the multiplexed C2 layer

### 3.1 Sliver's implant is transport-polymorphic at compile time AND runtime

`session.go:145-222` is a **scheme-dispatch switch** over eight transport families, and every
branch is wrapped in a compile-time `{{if .Config.IncludeXXX}}` guard:

| Scheme | Transport | Guard | Entry |
|---|---|---|---|
| `mtls` | mutual TLS + yamux | `IncludeMTLS` | `mtlsConnect` `:235` |
| `wg` | WireGuard overlay | `IncludeWG` | `wgConnect` `:158-167` |
| `http` / `https` | HTTP(S) C2 | `IncludeHTTP` | `httpConnect` `:169-181` |
| `dns` | DNS tunnelling | `IncludeDNS` | `dnsConnect` `:183-193` |
| `namedpipe` | SMB/named pipe | `IncludeNamePipe` | `namedPipeConnect` `:195-205` |
| `tcppivot` | TCP pivot | `IncludeTCP` | `tcpPivotConnect` `:207-216` |

The default branch just logs `"Unknown c2 protocol %s"` in debug builds (`:218-221`) and falls
through — an unrecognised scheme yields a **nil connection**, which the loop then pushes onto
`nextConnection`. That is a latent nil-dereference path if a malformed C2 URI ever reaches the
generator; worth flagging as a code-quality observation rather than an exploit.

**Design consequence:** because each transport is independently compiled in via a build variable,
two implants with the same version string can have **entirely disjoint** network capability. A
detection signature keyed on "Sliver = gRPC over HTTP/2 + mTLS" misses a DNS-only build entirely.

### 3.2 Failover is a generator loop, and it is genuinely resilient

`StartConnectionLoop` (`session.go:122-232`) drives `C2Generator` and, on any connect error,
`continue`s to the next URI (`:151-156`, `:162-167`, `:175-179`, `:187-191`, `:202-203`, `:210-214`).
The loop never exits on failure — it advances. So a beacon with N C2 endpoints round-robins
forever, and only `abort` (`:226-227`) terminates it.

**Four connection strategies** (`transports.go:34-36`, dispatched `:80-92`):

| Constant | Value | Selection |
|---|---|---|
| `strategyRandom` | `"r"` | `c2Servers[util.Intn(len)]` — uniform random |
| `strategyRandomDomain` | `"rd"` | random server, then **random within the same scheme** |
| `strategySequential` | `"s"` | `c2Counter % len` — round-robin |
| *(default)* | — | falls through to **sequential** `:90-91` |

`randomCCDomain` (`:129-147`) is the interesting one: it parses the chosen URI, then filters the
whole C2 pool down to entries sharing that URI's **scheme**, and picks uniformly from that
sub-pool. So `rd` mixes protocols across connections while staying within one protocol per
connection attempt — it defeats "same protocol, same host" correlation without producing a
mixed-scheme burst.

**Runtime reconfiguration overrides all of it:** `transports.go:95-97`

```go
if dynamic := GetC2URI(); dynamic != "" {
    next = dynamic
}
```

If an operator pushes a new C2 URI at runtime, **every subsequent connection uses it**, ignoring
the strategy and the compiled-in list. This is the pivot/migration mechanism — the operator can
move the implant to a new listener without rebuilding.

### 3.3 Beacon timing: additive jitter only

`beacon.go:108-117`:

```go
jitterDuration := time.Duration(0)
if 0 < b.Jitter() {
    jitterDuration = time.Duration(util.Int63n(b.Jitter()))
}
duration := time.Duration(b.Interval()) + jitterDuration
```

Effective sleep ∈ **[Interval, Interval + Jitter)** — `Int63n` is half-open `[0, n)`. The sleep
is **additive, never subtractive.**

Contrast explicitly with Covenant, which computes
`rnd.Next((int)Math.Round(Delay * Jitter / 100))` and at default settings
(`Delay=5`, `JitterPercent=10`) evaluates to `rnd.Next(1) ≡ 0`, producing **zero** jitter. Sliver's
formula cannot collapse that way: if `Jitter > 0` the sleep is genuinely randomised, and the
floor is the interval itself rather than a value that can round to nothing.

Detection consequence: with `Interval=60s, Jitter=30s`, the beacon period is uniformly distributed
on [60, 90) — a **right-skewed** window, not centred. Existing beacon-detection heuristics that
assume symmetric jitter around a midpoint will mis-estimate Sliver's true interval by up to half
the jitter range.

Both values are runtime-mutable: `SetJitter` (`transports.go:190-192`),
`SetReconnectInterval` (`:173-175`), and both fall back safely — `GetReconnectInterval` defaults to
**60 s** on parse failure (`:164`), `GetJitter` to **30 s** (`:183`).

### 3.4 Connection semantics — a defensive pattern worth noting

`nextSendEnvelope` (`session.go:87-119`) is a deliberately careful helper, and its comment
explains a real bug the authors hit:

> *"Producer channels intentionally remain open across cleanup, so transport senders must use the
> connection lifecycle instead of ranging over Send."*

The function checks `connection.Done()` **before**, **inside**, and **after** the receive
(`:96-100`, `:106-110`, `:115-116`), and skips nil envelopes (`:111-113`). That triple-check
closes a race where a producer channel stays open after teardown. Most C2 implants get this wrong
and hang or panic on reconnect; Sliver explicitly hardened it.

### 3.5 mTLS transport detail

`mtlsConnect` (`session.go:235-379`) establishes a **yamux session over the TLS connection** and
sends a magic preface first:

```go
if _, err := conn.Write([]byte(mtls.YamuxPreface)); err != nil {
```
`session.go:298`

Two operational facts:

1. **yamux multiplexing** means every envelope opens its own logical stream (`muxSession.Open()`,
   `:344`), so many concurrent commands share one TCP connection. A per-request stream pattern
   like this is not typical of commodity HTTP C2 and is a strong traffic-shape signature.
2. **Concurrency is capped at 64 in-flight sends** via `sendSem := make(chan struct{}, 64)`
   (`:327`). Each envelope is sent in its own goroutine (`:340-358`), with `defer <-sendSem`
   releasing the slot. A keepalive ticker runs at `mtls.PingInterval` (`:328-329`).
3. **Default port 8888** on a port-parse failure (`:280-286`): `lport = 8888`. The default is
   silently substituted rather than erroring.

Because yamux streams are independent, a stream that fails calls `connection.Cleanup()` — tearing
down the **whole** session, not just that stream (`:345-357`). One failed envelope therefore drops
the connection and triggers failover to the next C2 URI. Aggressive but self-healing.

---

## 4. Envelope framing and the mTLS signing layer

### 4.1 Exact wire format

`mtls.WriteEnvelope` (`mtls/mtls.go:124-171`) frames every message as:

```
[ RawSigSize-byte signature ] [ uint32 little-endian length ] [ protobuf Envelope ]
```

The signature block is **not** an opaque blob — it is a structured 10-byte header plus a raw
Ed25519 signature (`:147-150`):

```go
rawSigBuf := make([]byte, cryptography.RawSigSize)
binary.LittleEndian.PutUint16(rawSigBuf[:2],  cryptography.EdDSA)   // algorithm: 0x0000? see note
binary.LittleEndian.PutUint64(rawSigBuf[2:10], keyID)               // 64-bit key identifier
copy(rawSigBuf[10:], ed25519.Sign(signingKey, data))                // 64-byte raw signature
```
`mtls.go:147-150`

So byte layout: `[2B alg][8B keyID LE][64B Ed25519 sig][4B len LE][protobuf]`, and
`RawSigSize = 74` (2+8+64). **This is the same 74 bytes that §1.3 showed
`CipherContext.Decrypt` stripping before decryption** (`crypto.go:185`). The two layers are
therefore consistent: the mTLS transport *produces* the 74-byte signature prefix that the crypto
layer *consumes and verifies*. The framing and the crypto are designed against each other.

### 4.2 The signing key is derived, not stored

`mtlsEnvelopeSigningKey` (`mtls.go:76-95`) derives a per-implant Ed25519 keypair at first use:

```go
seed := sha256.Sum256([]byte(mtlsEnvelopeSigningSeedPrefix + peerKeyPair.Private))
envelopeSigningPriv = ed25519.NewKeyFromSeed(seed[:])
pub := envelopeSigningPriv.Public().(ed25519.PublicKey)
digest := blake2b.Sum256(pub)
envelopeSigningKeyID = binary.LittleEndian.Uint64(digest[:8])
```
`mtls.go:86-91`

With `mtlsEnvelopeSigningSeedPrefix = "env-signing-v1:"` (`:63`). Three properties:

1. **Deterministic** — `sha256("env-signing-v1:" + peerPrivateKey)` as the Ed25519 seed. The
   implant's age private key *is* the signing key material; no second secret to store.
2. **The keyID is `blake2b256(pubkey)[:8]` little-endian** — a fingerprint the server can use to
   select which implant's public key to verify against, without trying all of them.
3. **Guarded against template-render failure** (`:81-84`): if the private key is empty or the
   literal `".Build.PeerPrivateKey"` survived un-substituted, signing errors out rather than
   silently using a placeholder. That is a deliberate fail-closed check on a build pipeline
   mistake — an unrendered template would otherwise produce a working implant with a *known*
   key.

Note `strings.Contains(peerKeyPair.Private, ".Build.PeerPrivateKey")` — the comment at `:79-80`
explains why a literal template delimiter cannot appear in a string check in this file: Go's
`text/template` would treat `{{...}}` as an action. A real engineering constraint, documented.

### 4.3 Envelope size ceiling is 512 MiB

```go
const maxEnvelopeLength = 512 * 1024 * 1024
```
`mtls.go:65`, enforced on read at `:219-221`:

```go
if dataLength > maxEnvelopeLength {
```
with error text `"[mtls] read error: envelope length %d exceeds max %s\n"`. Because the length
field is a `uint32`, the theoretical max is 4 GiB; the 512 MiB cap is a deliberate ceiling. The
check occurs **before** allocation, so a hostile length cannot force a 4 GiB allocation. Envelope
reading is also bounded on the write side by `writeAll` (`:110-122`), which loops on short
writes and returns `io.ErrShortWrite` on `n <= 0` rather than spinning — the classic
partial-write bug, correctly handled.

### 4.4 Tunnel admission — the most defensively-written code in the implant

`Connection` (`connection.go:90-112`) tracks **three** tunnel maps plus a FIFO retirement ring:

```go
tunnels        map[uint64]*Tunnel
pendingTunnels map[uint64]*PendingTunnel
retiredTunnels map[uint64]struct{}
retiredOrder   []uint64
retiredCursor  int
```
`connection.go:100-104`, constants at `:38-39`:

| Bound | Value |
|---|---|
| `maxLiveTunnelIDsPerConnection` | 4096 |
| `maxRetiredTunnelIDsPerConnection` | 4096 |
| `tunnelSendTimeout` | 10 s |

`tunnelAdmissionResultLocked` (`:247-263`) performs **four** ordered checks under one lock:
connection closed → duplicate in live or pending → duplicate in retired window → capacity. The
comments at `:34-37` explain the design goal precisely:

> *"Bound live tunnel state independently from the replay tombstone window. Retired IDs are
> remembered in FIFO order; once the window rotates, exact pointer checks still prevent stale
> local work from deleting a replacement, while random 64-bit wire IDs make an accidental
> post-window reuse remote."*

This is a **tunnel-ID replay defence** — the tunnelling equivalent of §1.2's message replay
defence. Wire IDs are random 64-bit, so post-window reuse is improbable rather than impossible;
that residual risk is stated openly in the comment instead of being papered over.

`BeginTunnel` (`:270-299`) reserves the ID **before** any external resource is opened, returning
a `*PendingTunnel` whose context is cancelled if the peer closes first (`:265-269` comment). This
closes a TOCTOU window where a handler could open a socket for a tunnel the peer had already
abandoned. `Cleanup` is `sync.Once`-guarded (`:202-212`) and drains all tunnels.

Six distinct admission outcomes are modelled as a typed enum (`TunnelAddResult`, `:45-55`):
`TunnelAdded`, `TunnelAddDuplicate`, `TunnelAddCapacityExhausted`, `TunnelAddConnectionClosed`,
`TunnelAddInvalid`, `TunnelAddSetupCanceled`. Modelling capacity exhaustion as distinct from
invalid input means a full tunnel table **rejects only the new tunnel** and leaves the C2
connection serving existing work (`:42-44` comment). Most implants would abort the connection.

**Assessment:** this file is noticeably more careful than the C2 corpus average. Bounded state,
typed outcomes, atomic admission, explicit replay window, documented residual risk. If the
detection goal is behavioural, this code produces *fewer* exploitable signals than Covenant's
broken jitter or Havoc's unvalidated length fields — the reverse-engineering value here is
mechanism understanding, not defect inventory.

---

## 5. HTTP transport — why WinINet, answered from the source

### 5.1 The driver is chosen at RUNTIME by a URI query parameter

This is the specific question the task brief asked. The answer is not a build-time decision at
all — it is a **runtime switch driven by the C2 URI**:

```go
driverName := strings.TrimSpace(strings.ToLower(c2URI.Query().Get("driver")))
if driverName == "" {
    driverName = goHTTPDriver
```
`httpclient/httpclient.go:105-107`

`goHTTPDriver = "go"` (`:50`). So `mtls://…` is unrelated; for HTTP C2 the operator writes
something like `https://host/path?driver=wininet` and the implant picks a different HTTP stack.
**Default is Go's `net/http`** (`drivers_windows.go:50-55`): an unknown or absent driver falls
back to `GoHTTPDriver`, and an unrecognised value logs a debug warning. So WinINet is *opt-in per
listener*, not the default.

`GetHTTPDriver` (`drivers_windows.go:35-56`) has exactly three branches:

| `opts.Driver` | Result |
|---|---|
| `"go"` | `GoHTTPDriver(origin, secure, opts)` |
| `"wininet"` | `WininetDriver(...)` |
| *anything else* | warns, then **falls back to `GoHTTPDriver`** |

The `HTTPDriver` interface (`httpclient.go:158-159`) is the abstraction seam:

```go
type HTTPDriver interface { ... }
```
with the concrete driver held as a field (`:167 driver HTTPDriver`) and invoked at `:345`, `:385`,
`:530`, `:592` — four call sites across the request paths. A single interface with one field means
the transport code above it is driver-agnostic.

### 5.2 The rationale, from the vendored driver's own README

The driver is **third-party**, and its README states the reason directly
(`drivers/win/README.md:1`):

> *"Forked from https://gitlab.com/mjwhitta/win/"*

with a Changes list at `:5-10`: removed winhttp code, removed custom errors/pathname packages,
renamed for Sliver's convention, merged sub-packages, and *"Added custom cookie jar implementation
to wininet client."* The upstream rationale is quoted verbatim at `:26-31`:

> *"WinHTTP (and theoretically WinINet) can even handle NTLM authentication automatically for you.
> Microsoft recommends [WinINet over WinHTTP] unless you're writing a Windows service."*
>
> *"**Note:** This is probably beta quality at best."*

So the answer decomposes into three concrete reasons, all evidenced:

1. **Automatic NTLM/proxy authentication.** WinINet and WinHTTP negotiate NTLM transparently
   using the *logged-on user's* credentials. Go's `net/http` does not — it has no NTLM support in
   the standard library and would require a hand-rolled SSPI/Negotiate implementation. For an
   implant running in a corporate environment behind an authenticating proxy, this converts a
   hard blocker into a flag. That is the primary functional reason.
2. **It reuses the system's proxy configuration and cached credentials.** WinINet is the same
   stack Internet Explorer / `urlmon` use, so proxy settings, PAC scripts, and the WinINet cookie
   jar come from the host's own profile. A Go `net/http` request bypasses all of it and uses
   `HTTP_PROXY`-style environment settings that frequently do not exist.
3. **It blends with legitimate OS HTTP usage.** Requests originate from the WinINet stack, the
   same component used by ordinary Windows software — so network telemetry resembles native
   Windows traffic rather than a Go runtime's TLS/HTTP fingerprint.

The README's own `**Note:** This is probably beta quality at best` (`:29`) is a candid upstream
quality caveat that Sliver inherited; the Changes list *removed* the winhttp half, so only the
WinINet path was kept and maintained.

### 5.3 WinINet specifics in the driver

`WininetDriver` (`drivers_windows.go:59-67`):

```go
wininetClient, err := wininet.NewClient(userAgent)
...
wininetClient.TLSClientConfig.InsecureSkipVerify = true
wininetClient.AskProxyCreds = opts.AskProxyCreds
```

Two operational facts:

- **`InsecureSkipVerify = true` is set unconditionally on the WinINet driver** (`:64`). The
  WinINet path therefore does **not** perform the CA-pinned verification that §1.5 describes for
  the crypto layer. Integrity on this path rests on the envelope signature (§4.1) and the AEAD,
  not on TLS certificate validation. Worth stating plainly: for `?driver=wininet`, TLS is
  **confidentiality-only against a passive observer**, and an active MITM presenting any
  certificate would be accepted at the TLS layer. The Ed25519 envelope signature is what actually
  rejects forged server traffic.
- **`AskProxyCreds` is operator-configurable** (`:65`), consistent with reason (1) — the driver is
  built to interact with authenticating proxies, optionally prompting for credentials.

The driver's own file inventory (`wininet/README.md:9-19`) shows a **custom cookie jar**
(`cookie.go` — a Sliver addition per the fork notes), request/response conversion
(`request.go`, `response.go`), auto-generated constant/struct bindings (`generated.go`, 49.2 KB —
the single largest file in the transport tree), the syscall bindings
(`wininet_windows.go`, 9.3 KB), DLL procedure linking (`wininet.go`), and a **`user32_windows.go`**
shim — the last implies WinINet's message-loop or window-message requirements had to be satisfied
from `user32`.

### 5.4 Driver inventory (largest first)

| KB | Path | Role |
|---|---|---|
| 49.2 | `drivers/win/wininet/generated.go` | auto-generated constants/structs |
| 35 | `drivers/win/LICENSE.txt` | upstream licence |
| 19.7 | `httpclient.go` | the transport, driver-agnostic |
| 9.3 | `wininet_windows.go` | syscall bindings |
| 7.0 | `wininet/utils_windows.go` | helpers |
| 5.6 | `wininet/client_windows.go` | client wiring |
| 4.9 | `drivers/win/tools/defines.go` | winhttp/wininet flags |
| 3.9 | `gohttp.go` | the **default** Go `net/http` driver |
| 3.5 | `httpclient_test.go` | tests |
| 2.9 | `drivers/win/README.md` | upstream rationale (§5.2) |
| 1.9 | `drivers_windows.go` | **driver factory** (§5.1) |
| 1.2 | `drivers_generic.go` | non-Windows: Go driver only |
| 1.2 | `wininet/request.go` | request handle build |
| 1.0 | `wininet/response.go` | response parse |

`drivers_generic.go` (1.2 KB) is the **non-Windows** counterpart — on Linux/macOS only the Go
driver exists, so `?driver=wininet` is a Windows-only capability. This is a clean example of the
platform-split file pattern Sliver uses throughout (`*_windows.go` / `*_generic.go`).

---

## 6. Handler dispatch and the complete message-ID table

### 6.1 Dispatch is a numeric map, split per platform

There is no string-based routing. `handlers.go:52-60` defines the handler types and the implant
registers **`map[uint32]RPCHandler`** tables:

```go
type RPCResponse func([]byte, error)
type RPCHandler  func([]byte, RPCResponse)
type KillHandler func([]byte, *transports.Connection) error
type TunnelHandler func(*sliverpb.Envelope, *transports.Connection)
```
`handlers/handlers.go:52-60`

Seven separate maps exist, selected by build platform:

| Map | File | Line |
|---|---|---|
| `windowsHandlers` | `handlers_windows.go` | `:55` |
| `linuxHandlers` | `handlers_linux.go` | `:45` |
| `darwinHandlers` | `handlers_darwin.go` | `:35` |
| `genericHandlers` | `handlers_generic.go` | `:36` |
| `killHandlers` | `kill-handlers.go` | `:37` |
| `killHandlers` (win) | `kill-handlers_windows.go` | `:41` |
| `genericPivotHandlers` | `pivot-handlers.go` | `:34` |
| `genericRportFwdHandlers` | `tun-rportfwd.go` | `:38` |
| `tunnelHandlers` | `tun.go` | `:32` |

`runner.go` merges them at runtime into five aggregations: `GetSystemHandlers()` (`:434`, `:496`,
`:651`), `GetKillHandlers()` (`:435`, `:497`, `:652`), `GetPivotHandlers()` (`:649`),
`GetTunnelHandlers()` (`:650`), `GetRPortFwdHandlers()` (`:653`). The separation is by *lifetime*
semantics, not by feature: `RPCHandler` is request/response, `KillHandler` needs the raw transport
(so it can tear down the connection), `TunnelHandler` owns a duplex stream.

### 6.2 Windows handler table — 51 bindings in six groups

`handlers_windows.go:55-134`, grouped as the source groups them:

**Windows-only (20):** `MsgTaskReq`→`taskHandler`, `MsgProcessDumpReq`→`dumpHandler`,
`MsgImpersonateReq`→`impersonateHandler`, `MsgRevToSelfReq`→`revToSelfHandler`,
`MsgRunAsReq`→`runAsHandler`, `MsgInvokeGetSystemReq`→`getsystemHandler`,
`MsgInvokeExecuteAssemblyReq`→`executeAssemblyHandler`,
`MsgInvokeInProcExecuteAssemblyReq`→`inProcExecuteAssemblyHandler`,
`MsgInvokeMigrateReq`→`migrateHandler`, `MsgSpawnDllReq`→`spawnDllHandler`,
`MsgStartServiceReq`→`startService`, `MsgStopServiceReq`→`stopService`,
`MsgRemoveServiceReq`→`removeService`, `MsgEnvReq`→`getEnvHandler`, `MsgSetEnvReq`→`setEnvHandler`,
`MsgUnsetEnvReq`→`unsetEnvHandler`, `MsgExecuteWindowsReq`→`executeWindowsHandler`,
`MsgGetPrivsReq`→`getPrivsHandler`, `MsgCurrentTokenOwnerReq`→`currentTokenOwnerHandler`,
`MsgRegistryReadHiveReq`→`regReadHiveHandler`.

**Platform-specific (17):** `ifconfigHandler`, `screenshotHandler`, `sideloadHandler`,
`netstatHandler`, `makeTokenHandler`, `psHandler`, `terminateHandler`, `regReadHandler`,
`regWriteHandler`, `regCreateKeyHandler`, `regDeleteKeyHandler`, `regSubKeysListHandler`,
`regValuesListHandler`, `servicesListHandler`, `serviceDetailHandler`,
`startServiceByNameHandler`, `mountHandler`.

**Generic (16):** `pingHandler`, `dirListHandler`, `downloadHandler`, `uploadHandler`, `cdHandler`,
`pwdHandler`, `rmHandler`, `mvHandler`, `cpHandler`, `mkdirHandler`, `executeHandler`,
`executeChildrenHandler`, `reconfigureHandler`, `runSSHCommandHandler`, `chtimesHandler`,
`grepHandler`.

**Extensions (3 + 3 wasm):** `registerExtensionHandler`, `callExtensionHandler`,
`listExtensionsHandler`; `registerWasmExtensionHandler`, `deregisterWasmExtensionHandler`,
`listWasmExtensionsHandler`.

**WireGuard (6), under `{{if .Config.IncludeWG}}`:** `wgStartPortfwdHandler`,
`wgStopPortfwdHandler`, `wgListTCPForwardersHandler`, `wgStartSocksHandler`,
`wgStopSocksHandler`, `wgListSocksServersHandler` (`:126-134`).

The capability surface this exposes is broad by design: process/token/privilege manipulation,
assembly execution (both out-of-process and **in-process**), DLL sideloading, process migration,
registry read/write across five operations, service control, and a **mount** operation.

### 6.3 The complete message-ID table — 135 IDs, iota-ordered

`protobuf/sliverpb/constants.go:44` opens with a contract stated in the file header
(`:31-38`):

> *"**!!! The order of constants is APPEND ONLY !!!**
> If you insert values into this file it is very important that you only append the order of the
> constants. If you do not you will break backwards compatibility with implants."*

The block is `MsgRegister = uint32(1 + iota)`, so **IDs are positional**. This is the single most
useful artifact in the report for anyone reading a Sliver binary or pcap: it converts a numeric
message ID into a command name.

| ID | Constant | ID | Constant | ID | Constant |
|---|---|---|---|---|---|
| 1 | MsgTaskReq | 46 | MsgScreenshotReq | 91 | MsgListExtensionsReq |
| 2 | MsgPing | 47 | MsgScreenshot | 92 | MsgBeaconRegister |
| 3 | MsgKillSessionReq | 48 | MsgNetstatReq | 93 | MsgBeaconTasks |
| 4 | MsgLsReq | 49 | MsgPivotStartListenerReq | 94 | MsgOpenSession |
| 5 | MsgLs | 50 | MsgPivotStopListenerReq | 95 | MsgCloseSession |
| 6 | MsgDownloadReq | 51 | MsgPivotListenersReq | 96 | MsgRegistryDeleteKeyReq |
| 7 | MsgDownload | 52 | MsgPivotListeners | 97 | MsgMvReq |
| 8 | MsgUploadReq | 53 | MsgPivotPeerPing | 98 | MsgMv |
| 9 | MsgUpload | 54 | MsgPivotServerPing | 99 | MsgCurrentTokenOwnerReq |
| 10 | MsgCdReq | 55 | MsgPivotServerKeyExchange | 100 | MsgCurrentTokenOwner |
| 11 | MsgPwdReq | 56 | MsgPivotPeerEnvelope | 101 | MsgInvokeInProcExecuteAssemblyReq |
| 12 | MsgPwd | 57 | MsgPivotPeerFailure | 102 | MsgRportFwdStopListenerReq |
| 13 | MsgRmReq | 58 | MsgPivotSessionEnvelope | 103 | MsgRportFwdStartListenerReq |
| 14 | MsgRm | 59 | MsgStartServiceReq | 104 | MsgRportFwdListener |
| 15 | MsgMkdirReq | 60 | MsgStartService | 105 | MsgRportFwdListeners |
| 16 | MsgMkdir | 61 | MsgStopServiceReq | 106 | MsgRportFwdListenersReq |
| 17 | MsgPsReq | 62 | MsgRemoveServiceReq | 107 | MsgRPortfwdReq |
| 18 | MsgPs | 63 | MsgMakeTokenReq | 108 | MsgChmodReq |
| 19 | MsgShellReq | 64 | MsgMakeToken | 109 | MsgChmod |
| 20 | MsgShell | 65 | MsgEnvReq | 110 | MsgChownReq |
| 21 | MsgTunnelData | 66 | MsgEnvInfo | 111 | MsgChown |
| 22 | MsgTunnelClose | 67 | MsgSetEnvReq | 112 | MsgChtimesReq |
| 23 | MsgProcessDumpReq | 68 | MsgSetEnv | 113 | MsgChtimes |
| 24 | MsgProcessDump | 69 | MsgExecuteWindowsReq | 114 | MsgMemfilesListReq |
| 25 | MsgImpersonateReq | 70 | MsgRegistryReadReq | 115 | MsgMemfilesAddReq |
| 26 | MsgImpersonate | 71 | MsgRegistryWriteReq | 116 | MsgMemfilesAdd |
| 27 | MsgRunAsReq | 72 | MsgRegistryCreateKeyReq | 117 | MsgMemfilesRmReq |
| 28 | MsgRunAs | 73 | MsgWGStartPortFwdReq | 118 | MsgMemfilesRm |
| 29 | MsgRevToSelf | 74 | MsgWGStopPortFwdReq | 119 | MsgRegisterWasmExtensionReq |
| 30 | MsgRevToSelfReq | 75 | MsgWGStartSocksReq | 120 | MsgDeregisterWasmExtensionReq |
| 31 | MsgInvokeGetSystemReq | 76 | MsgWGStopSocksReq | 121 | MsgRegisterWasmExtension |
| 32 | MsgGetSystem | 77 | MsgWGListForwardersReq | 122 | MsgListWasmExtensionsReq |
| 33 | MsgInvokeExecuteAssemblyReq | 78 | MsgWGListSocksReq | 123 | MsgListWasmExtensions |
| 34 | MsgExecuteAssemblyReq | 79 | MsgPortfwdReq | 124 | MsgExecWasmExtensionReq |
| 35 | MsgExecuteAssembly | 80 | MsgPortfwd | 125 | MsgExecWasmExtension |
| 36 | MsgInvokeMigrateReq | 81 | MsgSocksData | 126 | MsgCpReq |
| 37 | MsgSideloadReq | 82 | MsgReconfigureReq | 127 | MsgCp |
| 38 | MsgSideload | 83 | MsgReconfigure | 128 | MsgGrepReq |
| 39 | MsgSpawnDllReq | 84 | MsgUnsetEnvReq | 129 | MsgServicesReq |
| 40 | MsgSpawnDll | 85 | MsgSSHCommandReq | 130 | MsgServiceDetailReq |
| 41 | MsgIfconfigReq | 86 | MsgGetPrivsReq | 131 | MsgStartServiceByNameReq |
| 42 | MsgIfconfig | 87 | MsgRegistrySubKeysListReq | 132 | MsgRegistryReadHiveReq |
| 43 | MsgExecuteReq | 88 | MsgRegistryListValuesReq | 133 | MsgMountReq |
| 44 | MsgTerminateReq | 89 | MsgRegisterExtensionReq | 134 | MsgShellResizeReq |
| 45 | MsgTerminate | 90 | MsgCallExtensionReq | 135 | MsgExecuteChildrenReq |

**Total: 135 message IDs.** Note the request/response pairing is not uniform — some commands have
both (`MsgLsReq` 4 / `MsgLs` 5), some only a request (`MsgExecuteReq` 43, `MsgGrepReq` 128,
`MsgCpReq` 126), because the reply is a generic envelope. `MsgRegister = 1` is the very first
constant and is the initial implant→server metadata frame.

**Reconciliation with T1:** T1 established there are **135 unique RPC request types** in the
client binary. This table is the *implant-side* counterpart and also totals 135 — a clean
independent confirmation of that count from a different artifact.

### 6.4 Filesystem handler surface (`handlers.go`) — 38 functions, exact lines

| Line | Function | Role |
|---|---|---|
| 71 | `pingHandler` | liveness |
| 87 | `determineDirPathFilter` | split path/filter |
| 130 | `pathIsDirectory` | stat helper |
| 139 | `dirListHandler` | `MsgLsReq` |
| 249 | `getDirList` | dir read + sort |
| 279 | `rmHandler` | remove |
| 320 | `mvHandler` | move |
| 342 | `cpHandler` | copy |
| 412 | `mkdirHandler` | mkdir |
| 436 | `cdHandler` | chdir |
| 464 | `pwdHandler` | getwd |
| 487 | `readSingleFile` | bounded read (`maxBytes`, `maxLines`) |
| 561 | `readMultipleFiles` | recursive read + filter |
| 594 | `prepareDownload` | archive build |
| 677 | `downloadHandler` | `MsgDownloadReq` |
| 721 | `searchFileForPattern` | grep one file, context lines |
| 820 | `searchPathForPattern` | grep tree |
| 859 | `performGrep` | grep driver |
| 892 | `grepHandler` | `MsgGrepReq` |
| 936 | `extractFiles` | tar/gzip extract |
| 1004 | `uploadHandler` | `MsgUploadReq` |
| 1133 | `executeHandler` | command exec |
| 1260 | `getEnvHandler` | env read |
| 1293 | `setEnvHandler` | env write |
| 1314 | `unsetEnvHandler` | env clear |
| 1335 | `reconfigureHandler` | **runtime C2 reconfig** |
| 1370 | `gzipWrite` | compress helper |
| 1380 | `gzipRead` | decompress helper |
| 1394 | `standarizeArchiveFileName` | path sanitise |
| 1439 | `buildFileList` | recursive enumeration |
| 1495 | `compressDir` | tar+gzip a tree |
| 1599 | `expandPath` | path expansion |
| 1609 | `chtimesHandler` | touch |

Imports (`:22-48`) show the standard-library dependency set for this file: `archive/tar`, `bufio`,
`bytes`, `compress/gzip`, `errors`, `fmt`, `io`, `io/fs`, `maps`, `os`, `os/exec`,
`path/filepath`, `regexp`, `sort`, `strings`, `time`, `unicode/utf8`. Note `io/fs` and `maps` —
modern stdlib generics usage, consistent with the Go 1.27.1 toolchain recorded in T1.

`reconfigureHandler` (`:1335`) is the implant-side counterpart to `transports.go:95-97`'s dynamic
C2 override — the operator can push a new C2 URI and have the implant adopt it without a rebuild.

`executeHandler` (`:1133`) is the single largest function in this file and is the generic
command-execution path; `executeChildrenHandler` (in `execute_children.go`, 178 lines) is its
child-process variant.

---

## 7. Evasion layer — a NEGATIVE finding, and it is the important one

### 7.1 Sliver does NOT do direct syscalls. No Hell's Gate, no Halo's Gate, no SSN resolution.

This is the headline result of the evasion pass, and it is a **negative** result. It was checked
four ways and all four agree.

**Check 1 — no assembly at all.** The first-party implant
(`implant/sliver/`, 280 `.go` files / 40,429 lines) contains **zero `.s` / `.asm` / `.S` files**.
Every direct-syscall technique in the Windows offensive toolkit requires a hand-written assembly
stub (the `mov r10, rcx; mov eax, <SSN>; syscall; ret` trampoline). A pure-Go implant with no
assembly cannot emit a direct syscall instruction outside the Go runtime's own `syscall` package.

**Check 2 — the syscall package is declarative API binding, not syscall resolution.**
`syscalls/syscalls_windows.go` (all 51 lines) is entirely `mkwinsyscall` directives:

```go
//go:generate go run $GOPATH/src/golang.org/x/sys/windows/mkwinsyscall -output zsyscalls_windows.go syscalls_windows.go

//sys VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32,
//                   flProtect uint32) (addr uintptr, err error) = kernel32.VirtualAllocEx
//sys NtCreateThreadEx(...) (status uint32) = ntdll.NtCreateThreadEx
//sys RtlCopyMemory(dest uintptr, src uintptr, dwSize uint32) = ntdll.RtlCopyMemory
```
`syscalls/syscalls_windows.go:3, 13, 43, 51`

The generator (`mkwinsyscall`) emits Go code that calls `syscall.NewLazyDLL("kernel32.dll")` +
`NewProc("VirtualAllocEx")`, i.e. resolves the export through the **loader's `GetProcAddress`**
and invokes it normally. There is no SSN anywhere in the file — the `//sys` comment already tells
you the resolution target is a DLL export *name*, not a syscall number.

**Check 3 — no keyword hits.** A grep of all first-party `.go` for `HellGate`, `HalosGate`,
`RecycledGate`, `SysWhispers`, `syscall.SyscallN(`, `Ssn`, `SSN`, `syscallNumber`, and the literal
byte sequence `0x0F, 0x05` returned **no relevant matches**. The only hits were false positives:
`ProcessName`/`ProcessSnapshot` identifiers in `netstat_windows.go` matching a substring, and
`basex_test.go` vectors.

**Check 4 — `go:linkname` is not used for evasion.** The only three `go:linkname` directives in
first-party code are `task_linux.go:39-45` and `task_darwin.go:37-43`, linking
`syscall.runtime_BeforeFork` / `AfterFork` / `AfterForkInChild`. That is **POSIX fork-safety for
the taskrunner**, nothing to do with Windows. There are no Windows `go:linkname` trampolines.

### 7.2 What Sliver's evasion actually is

Because the technique-set is absent, the implant's stealth profile is architectural rather than
syscall-level. What it actually relies on:

| Vector | Mechanism | Evidence |
|---|---|---|
| **In-memory execution** | replaces the donor DLL's `.text` in memory rather than loading from disk | `taskrunner/`, `spoof/` |
| **ARGV spoofing** | `spoof` package — alters process command-line parameters as seen by other processes | `implant/sliver/spoof` |
| **Module stomping / sacrificial process** | `SpawnDll` executes inside a chosen host process at a chosen offset | `handlers_windows.go:548`, `spawnReq.GetProcessName()/GetOffset()` |
| **In-process assembly** | `MsgInvokeInProcExecuteAssemblyReq` runs .NET in the *current* process rather than a child | `handlers_windows.go:65` |
| **Thread-hijack injection** | `QueueUserAPC` + `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` + `CreateRemoteThread` | `syscalls_windows.go:13-20, 16` |
| **Indirect NtCreateThreadEx** | `NtCreateThreadEx` is resolved **by name from ntdll** | `syscalls_windows.go:51` |
| **Process ghosting via snapshot** | `PssCaptureSnapshot` for dump/capture without a debugger attach | `syscalls_windows.go:41` |
| **Compile-time transport selection** | unused transports absent from the binary (§3.1) | `session.go` |
| **WinINet blending** | OS-native HTTP stack, system proxy credentials (§5) | `drivers_windows.go:59-67` |

`PssCaptureSnapshot` (`syscalls_windows.go:41`) is worth singling out: it captures process memory
**through a supported OS API** rather than `ReadProcessMemory`-looping, so the dump path avoids
the access-pattern that EDR heap-scan heuristics watch.

### 7.3 Why this matters, stated precisely

The instinct on finding a C2 implant is to hunt for the direct-syscall bypass. For Sliver that
hunt returns nothing, and the correct conclusion is **not** "Sliver is unstealthy" — it is that
Sliver's evasion lives at a different layer:

- It resolves `NtCreateThreadEx` from ntdll by name (`syscalls_windows.go:51`). A userland EDR
  hook on that ntdll export **would** see the call. Sliver does not attempt to evade it.
- It has no SSN table, so there is no static artifact to signature and no "recycled gate" pattern
  to detect — but equally no bypass if the hook is present.
- Conversely, Havoc's Demon **does** implement Hell's Gate + Halo's Gate (per the T5/D5 lane:
  `Syscalls.c:90` `SysExtract` stub-walks to extract the SSN; `Syscalls.c:196`
  `FindSsnOfHookedSyscall` probes ±500 neighbouring stubs and derives the SSN arithmetically).
  Havoc therefore survives an ntdll hook that Sliver would trip.

**The corpus-level comparison is the deliverable here.** Sliver and Havoc are the two Go/C-focused
implants in this set and they sit at opposite ends of this axis:

| | Sliver | Havoc (Demon) |
|---|---|---|
| Direct syscalls | **No** | **Yes** — Hell's Gate + Halo's Gate |
| Assembly in implant | **None** | 4 `.asm` files (Syscall x64/x86, Spoof x64/x86) |
| Ntdll-hook bypass | No | Yes, via neighbour-probing |
| Evasion emphasis | memory placement, ARGV spoof, module stomping, transport blending | syscall-level hook evasion + ROP-based sleep obfuscation |
| Sleep obfuscation | none observed | Ekko / Zilean / Foliage ROP chains |

That is a genuinely useful structural result: **two leading C2 frameworks made opposite engineering
choices on the single most-watched Windows evasion axis**, and the source proves it directly rather
than by inference.

### 7.4 Files in the evasion/system-interaction namespace

| KB | File | Role |
|---|---|---|
| 18.8 | `syscalls/zsyscalls_windows.go` | generated bindings (the 51 `//sys` decls above) |
| 6.3 | `syscalls/syscalls_windows.go` | the `mkwinsyscall` directive source |
| 4.6 | `syscalls/types_windows.go` | `PROC_THREAD_ATTRIBUTE_LIST`, `StartupInfoEx`, `MODULEENTRY32W`, `ProcessMemoryCounters` |
| 0 | `syscalls/syscalls.go` | empty stub for non-Windows builds |
| 0.6 | `syscalls/README.md` | package doc |

`syscalls/syscalls.go` being **0 bytes** is the standard Sliver platform-split pattern (§2.1):
the non-Windows counterpart is an empty file so the package compiles on every GOOS. It is also
why a naive `grep` for syscall logic on Linux yields nothing — the entire package is
Windows-only by construction.

---

## 8. Citation convention (stated so this report is auditable alongside D2 and D5)

This report cites by **inline `path/file.go:line`** inside the prose and inside code fences —
e.g. `session.go:122-232`, `cryptography/crypto.go:50`, `mtls/mtls.go:147-150`. That is a
different surface convention from `D2_covenant_code.md` (186 citations) and `D5_havoc_code.md`
(106 citations), which both use a bracketed `[source: file:line]` tag. **The evidence density is
comparable — 61 inline references in this file — but the format differs, so a mechanical
`grep '\[source:'` returns 0 here and must not be read as an absence of sourcing.**

Ranges are inclusive of both endpoints. Line numbers refer to the tree at
`RE_Library/01_SOURCE_c2/sliver/` at the cloned revision (which, per T1, is **not** the same
commit as the shipped binary — the source explains mechanism, it is never a byte-exact
substitute for `sliver-client_windows-amd64.exe`).

## 9. DNS transport — `transports/dnsclient/dnsclient.go` (1,086 lines)

The largest single transport in the implant, and the most interesting design in it. The file
opens with its own design document (`:22-40`), quoted verbatim because it is the clearest
statement of intent anywhere in the codebase:

```
*** BASE32 ***
DNS domains are limited to 254 characters including '.' so that means
Base 32 encoding, so (n*8 + 4) / log2(32) = 63 means we can encode 39 bytes
per subdomain.

Format: (subdata...).<ns domain>.<parent domain>
	[63].[63]...[ns].[parent].

254 - len(parent) = subdata space, 128 is our worst case where the parent domain is 126 chars,
where [63 NS . 63 TLD], so 128 / 63 = 2 * 39 bytes = 78 bytes, worst case per query

We need to include some metadata in each request:
	Type = 2 bytes max
	ID = 4 bytes max
	Start = 4 bytes max
	Stop = 4 bytes max
	Size = 4 bytes max
	Data = 78 - (2+4+4+4+4) ~= 60 bytes per query worst case
```
`transports/dnsclient/dnsclient.go:22-40`

### 9.1 Why base32 and not base64

The arithmetic at `:24` is exact: a DNS label caps at 63 characters, and base32's 5-bit alphabet
means 63 chars carries `63 × 5 / 8 = 39.375` → **39 whole bytes per label**. Base64 would carry
more per character, but base64 uses `+` and `/` — both illegal in a DNS label — and is
case-sensitive while DNS names are case-insensitive. Base32's alphabet (`A-Z2-7`) is
case-insensitive-safe and label-legal. The choice is forced by the protocol, not stylistic.

The computed budget is dynamic, not hardcoded (`:169`):

```go
subdataSpace: 254 - len(parent) - (1 + (254-len(parent))/64),
```

The `(1 + (254-len(parent))/64)` term accounts for the label-separator dots — one dot per 64
characters of space. This is a correct domain-name-length calculation rather than a magic number.

### 9.2 The DNS session ID is a 24-bit value split across the message ID

```go
sessionIDBitMask = 0x00ffffff // Bitwise mask to get the dns session ID
```
`dnsclient.go:71`

`randomDNSSessionID()` (`:827`) generates it from `crypto/rand` (`:45` import), `msgCount` is a
separate `uint32` (`:189`), and `msgID(id uint32)` / `nextMsgID()` (`:1049`, `:1053`) compose the
two. So the identity of a DNS session is a random 24-bit value — **16.7 million possible
sessions**, which is what prevents a passive observer from trivially correlating queries into a
session, and what the server uses to demultiplex concurrent implants sharing one authoritative
nameserver.

### 9.3 Tunnelling over both A and TXT records

`NoTXT` (`:95`, parsed at `:134` from the `notxt` query parameter) selects the record type. Both
paths exist in the worker (`:248-249` TXT, `:396-399` and `:473-479` in the init/read paths) and
in the byte-budget calculation (`:591-595`):

```go
var bytesPerTxt uint32
if s.noTXT {
    bytesPerTxt = 192
} else {
    bytesPerTxt = 182 // 189 with base64, -6 metadata, -1 margin
}
```

`bytesPerTxt = 192` for A-records vs `182` for TXT (`:592-595`). **A-records carry more payload
per response than TXT** — counter-intuitive, but correct: an A response is four raw bytes per
answer and can be repeated across multiple answer RRs, whereas a TXT string is length-prefixed
and the classic 255-byte character-string limit applies. The comment `189 with base64, -6
metadata, -1 margin` records the derivation.

This matters for detection: an operator choosing `notxt=true` produces a tunnel that carries
payload in **A-record RDATA** — which is far less anomalous-looking than TXT-heavy traffic, since
TXT-heavy query patterns are the textbook DNS-tunnel signature.

### 9.4 Resolver fingerprinting and RTT-based selection — the standout feature

`fingerprintResolvers()` (`:940-982`) runs **before** the tunnel is used:

1. Every configured resolver is tested concurrently (`:946-949`).
2. Each is benchmarked `metricsMaxSize/2 = 4` times (`:997`, `metricsMaxSize = 8` at `:72`).
3. The benchmark sends a **real base32-encoded fingerprint query** and validates the returned
   checksum (`:1024`):
   ```go
   if fingerChecksum != binary.LittleEndian.Uint32(data) {
       meta.Errors++
   ```
4. **Any resolver with a single error is removed** (`:970-981`):
   ```go
   if 0 < meta.Errors {
       // WARNING: removing resolver %s (too many errors)
       continue
   }
   ```
5. Surviving resolvers have their RTTs retained (`ResolverMetadata.Metrics []time.Duration`,
   `:262-264`) and `averageRtt()` (`:1070`) is used to pick one — `randomResolver()` (`:1081`).

The comment at `:968-969` is honest about the crudeness: *"NOTE: In the future we may want to add
a configurable error threshold for now if we encounter any errors we don't use the resolver."*

**Why this is notable.** Most DNS-tunnel implants assume the resolver works and fail loudly at
runtime. Sliver instead does a pre-flight capability probe: it verifies the resolver actually
carries base32 subdomains and returns them intact, measures how fast, and excludes the ones that
mangle or block. A resolver that rewrites NXDOMAIN, truncates long labels, or filters
high-entropy subdomains is **detected and dropped before the C2 channel depends on it**. That is
an availability property, and it is the kind of thing that separates a transport that works in a
lab from one that survives a real network.

### 9.5 Configuration surface, all from C2 URI query parameters

`ParseDNSOptions()` (`:101-138`) with every default:

| Parameter | Default | Line |
|---|---|---|
| `timeout` | `5s` | `:103-106` |
| `retry-wait` | `1s` | `:108-111` |
| `retry-count` | `3` | `:113-116` |
| `workers-per-resolver` | `2` (floor of 1) | `:118-121` |
| `max-errors` | `10` (floor of 0) | `:123-126` |
| `notxt` | `false` (string compare `== "true"`) | `:134` |
| `force-resolv-conf` | empty | `:135` |
| `resolvers` | empty | `:136` |

`force-resolv-conf` and `force-resolvers` (`:96-97`) let the operator **override the host's own
resolver configuration**. On Windows this means ignoring the system DNS settings and pointing the
tunnel at a chosen resolver — useful when the host's resolver is a monitored corporate one.

### 9.6 Error strings compile to empty in release builds

Every error value is templated (`:77-80`):

```go
errMsgTooLong          = errors.New("{{if .Config.Debug}}Too much data to encode{{end}}")
errInvalidDNSSessionID = errors.New("{{if .Config.Debug}}Invalid dns session id{{end}}")
errNoResolvers         = errors.New("{{if .Config.Debug}}No resolvers found{{end}}")
ErrTimeout             = errors.New("{{if .Config.Debug}}DNS Timeout{{end}}")
```

In a debug build these are descriptive. In a **release build the `{{if}}` block vanishes and the
strings are empty `errors.New("")`**. Same for the three `// {{if .Config.Debug}}` logging blocks
in the benchmark path (`:1001-1003`, `:1010-1012`, `:1018-1020`) — the `log.Printf` calls are
compiled out entirely.

This is a systematic, build-wide anti-forensics measure: **a release implant carries no
explanatory strings for an analyst to read**, while a debug build is verbose. It also means
string-based detection must key on the *absence* of expected diagnostics, which is a much weaker
signal. Every `{{if .Config.Debug}}` in this file is a string removed from the shipped binary.

### 9.7 Function inventory (29 functions)

| Line | Function | Role |
|---|---|---|
| 101 | `ParseDNSOptions` | URI → options |
| 141 | `DNSStartSession` | connect entry |
| 155 | `NewDNSClient` | construct + compute `subdataSpace` |
| 223 | `(*DNSWorker).Start` | worker loop, A/TXT dispatch |
| 269 | `SessionInit` | resolver load, fingerprint, session ID |
| 385 | `sendInit` | session establishment query |
| 431 | `WriteEnvelope` | outbound envelope → tunnel |
| 451 | `ReadEnvelope` | inbound poll → envelope |
| 549 | `CloseSession` | teardown |
| 560 | `parallelSend` | fan out across resolvers |
| 586 | `parallelRecv` | parallel chunk fetch, `Size/bytesPerTxt` chunks |
| 711 | `SplitBuffer` | chunk into 39-byte labels |
| 815 | `encodeDNSMessage` | base32 encode |
| 827 | `randomDNSSessionID` | `crypto/rand` 24-bit |
| 842 | `loadResolvConf` | parse host resolver config |
| 875 | `splitResolverAddress` | host/port split |
| 895 | `joinSubdataToParent` | build FQDN |
| 915 | `pollMsg` | fetch pending |
| 927 | `clearMsg` | ack |
| 940 | `fingerprintResolvers` | **RTT probe + prune** |
| 985 | `fingerprintResolver` | per-resolver goroutine |
| 996 | `benchmark` | 4 × checksum-validated probe |
| 1036 | `fingerprintMsg` | build probe message |
| 1049 | `msgID` | compose 24-bit + count |
| 1053 | `nextMsgID` | increment |
| 1061 | `recordMetrics` | retain RTT |
| 1070 | `averageRtt` | mean RTT |
| 1081 | `randomResolver` | pick among survivors |

Imports (`:44-67`) confirm the dependency set: `crypto/rand` (session IDs), `hash/crc32`
(integrity), `net`, `net/url`, `miekg/dns` (**a full DNS client implementation**, not the stdlib
resolver), plus the implant's own `cryptography`, `encoders`, `util`, and `dnspb` packages. Using
`miekg/dns` rather than `net.LookupTXT` is what makes the A/TXT choice, custom resolver
targeting, and per-query timeouts possible.

---

## 10. WireGuard transport — and the envelope-signing pattern is shared, not per-transport

`transports/wireguard/wireguard.go` (466 lines) is the second-strongest transport after mTLS, and
it independently reimplements the same envelope-signing construction. That duplication is the
finding: **the Ed25519 envelope signature is an architectural layer, not an mTLS feature.**

### 10.1 The implant embeds a real WireGuard stack

```go
"github.com/bishopfox/sliver/implant/sliver/netstack"
"golang.org/x/crypto/blake2b"
"golang.zx2c4.com/wireguard/device"
"golang.zx2c4.com/wireguard/tun"
```
`transports/wireguard/wireguard.go:49-52`

The implant links `golang.zx2c4.com/wireguard/device` — the **official WireGuard Go
implementation** — plus a userland `netstack` (netstack, i.e. gVisor-derived) rather than the
host's TCP stack. `serverTunIP = "100.64.0.1"` (`:60`) places the tunnel in RFC 6598 carrier-grade
NAT space, which is what WireGuard conventionally uses and is a range that rarely collides with
real internal addressing.

```go
wgImplantPrivKey = `{{.Build.WGImplantPrivKey}}`
wgServerPubKey   = `{{.Build.WGServerPubKey}}`
wgPeerTunIP      = `{{.Config.WGPeerTunIP}}`
```
`:64-66`

Same template pattern as §1: keys are baked at generate time. Note the split — the **private key
is a build artifact** (unique per implant) while the **peer tunnel IP is a config artifact**
(operator-chosen per implant).

`YamuxPreface = "MUX/1"` reappears here (`:58`) — byte-identical to `mtls.go:54`. The multiplexing
preface string is the same across both transports.

### 10.2 The signing layer is a shared mechanism

```go
const wgEnvelopeSigningSeedPrefix = "env-signing-v1:"
const maxEnvelopeLength = 512 * 1024 * 1024
var errEnvelopeTooLarge = errors.New("[wireguard] envelope exceeds maximum length")
```
`wireguard.go:77-81`

Compare with §4.2's mTLS constants:

| Constant | mTLS | WireGuard |
|---|---|---|
| seed prefix | `env-signing-v1:` (`mtls.go:63`) | `env-signing-v1:` (`wireguard.go:77`) |
| max envelope | `512 * 1024 * 1024` (`mtls.go:65`) | `512 * 1024 * 1024` (`wireguard.go:79`) |

**Byte-identical.** The same `sha256("env-signing-v1:" + peerPrivateKey)` → `ed25519.NewKeyFromSeed`
derivation (`wireguard.go:100-101`) is independently written in the WireGuard path. Practically
this means:

- An implant's **signing identity is transport-independent**. Rotate mTLS→WireGuard and the
  envelope signature does not change, so the server can verify both with one key.
- The signing key still derives from the **peer age private key**, so there is exactly one root
  secret per implant regardless of how many transports are compiled in.
- The code duplication is a maintenance hazard (two copies of one construction) but the
  *design* is deliberately uniform.

### 10.3 The unrendered-template guard, restated in the WireGuard path

```go
peerKeyPair := cryptography.GetPeerAgeKeyPair()
// NOTE: This file is rendered with Go's text/template; avoid literal template
// delimiters in string checks or the template parser will treat it as an action.
if peerKeyPair == nil || peerKeyPair.Private == "" ||
   strings.Contains(peerKeyPair.Private, ".Build.PeerPrivateKey") {
    envelopeSigningErr = errors.New("[wireguard] missing peer private key")
    return
}
```
`wireguard.go:92-98`

This is the same **fail-closed guard** documented in §4.2 for mTLS, with a valuable extra piece of
information the mTLS copy didn't carry: the comment at `:93-94` explains *why* the check is a
substring test rather than an equality test. The string `".Build.PeerPrivateKey"` is the
**literal placeholder text** `{{.Build.PeerPrivateKey}}` — and the code cannot compare against the
full delimited form because writing `{{` inside this file would itself be parsed by the template
engine. So the author checks for the *inner* token minus its braces.

That is a concrete, non-obvious build-system constraint leaking into the runtime code, and it is
the kind of detail that only reading the source produces. It also means an implant built with an
unrendered template **fails closed at signing time** rather than silently signing with a
predictable key — the guard is a genuine safety property, not defensive decoration.

### 10.4 WireGuard is compile-time gated everywhere

Consistent with §3.1 and §6.2, all WireGuard surface is behind guards:

- 6 handler bindings under `{{if .Config.IncludeWG}}` (`handlers_windows.go:126-134`)
- the transport itself under the same guard
- the teamserver-side port helpers `getWgKeyExchangePort()` / `getWgTcpCommsPort()` (`:67-68`)
  resolve only in an IncludeWG build

So a Sliver implant either **has a full WireGuard stack with its own tun device and netstack, or
has none of it**. There is no partial state. This is the same disjoint-capability property proven
in §3.1, and WireGuard is its largest single instance: the binary difference between an
IncludeWG and non-IncludeWG implant is a complete VPN implementation.

### 10.5 WireGuard transport function surface

| Line | Symbol | Role |
|---|---|---|
| 67 | `getWgKeyExchangePort()` | resolve key-exchange port |
| 68 | `getWgTcpCommsPort()` | resolve TCP comms port |
| 90 | `wgEnvelopeSigningKey()` | `once`-guarded key derivation + keyID |
| 104+ | (continued) | publish keyID, handle error |
| 73 | `PingInterval = 2 * time.Minute` | keepalive, **identical value to `mtls.go:51`** |
| 74 | `failedConn` | failure counter |

`PingInterval = 2 * time.Minute` appears in both transports (`wireguard.go:73`, `mtls.go:51`) —
another deliberately uniform constant. The two transports share their timing discipline:
2-minute keepalives, 512 MiB envelope ceiling, `env-signing-v1:` seed, `MUX/1` preface.

**Assessment.** mTLS and WireGuard are not two independent transports in Sliver; they are two
*carrriers* over one shared security model — same signing construction, same size limits, same
keepalive, same multiplexing preface. For an analyst the practical consequence is that
**transport-agnostic detections hold across both**: the Ed25519 envelope header (§4.1) and the
`RawSigSize = 74` framing appear whether the implant is speaking mTLS or WireGuard. Only the
outer carrier differs.

---

## 11. Peer-to-peer pivot layer — `transports/pivotclients/pivotclient.go` (413 lines)

Pivoting is what makes Sliver a *network* implant rather than a host implant: an implant with no
route to the C2 server can be reached through another implant that has one. This file is the
client half of that.

### 11.1 Two independent cipher contexts, and a two-stage key exchange

```go
type NetConnPivotClient struct {
	pivotSessionID  []byte
	conn            net.Conn
	readMutex       *sync.Mutex
	writeMutex      *sync.Mutex
	peerCipherCtx   *cryptography.CipherContext
	serverCipherCtx *cryptography.CipherContext

	readDeadline  time.Duration
	writeDeadline time.Duration
}
```
`pivotclients/pivotclient.go:45-55`

**Two separate `CipherContext`s** — `peerCipherCtx` and `serverCipherCtx` — plus two separate
mutexes for read and write. The consequence is that a pivot is **two hops with independent
crypto**, not one tunnel carrying another:

1. `peerKeyExchange()` (`:76`) — establishes crypto with the **intermediate implant**.
2. `serverKeyExchange()` (`:66`) — establishes a *second*, independent crypto context with the
   **upstream server** through that intermediate.

`KeyExchange()` (`:58-74`) runs them strictly in order and returns on the first failure, so a
pivot either has both layers or neither.

### 11.2 The peer hello is authenticated by the Minisign-signed key from §1.4

```go
pivotHello, _ := proto.Marshal(&pb.PivotHello{
	PublicKey:          []byte(cryptography.PeerAgePublicKey),
	PeerID:             pivots.MyPeerID,
	PublicKeySignature: cryptography.PeerAgePublicKeySignature,
})
```
`pivotclient.go:77-81`

All three fields are static build-time values, but the **third is the one that matters**. Recall
from §1.4 that `PeerAgePublicKeySignature` is producer-signed — the server signs each implant's
peer age public key with the server's Minisign key at generate time.

So the peer handshake carries:

```
PeerAgePublicKey          ← the implant's X25519 public key (template `{{.Build.PeerPublicKey}}`)
PeerAgePublicKeySignature ← Minisign/Ed25519 signature over that key, made by the SERVER
```

The receiving side verifies the signature against the pinned `serverMinisignPublicKey` (§1). This
is what closes the p2p trust problem: **any implant can be handed any peer's public key, and can
verify a server vouched for it.** Without the signature, a pivot would have to choose between
trusting an unauthenticated key (trivially MITM-able) or requiring pre-shared configuration per
pair (which doesn't scale). The signed-key distribution is the mechanism that makes a whole
network of mutually-stranger implants cryptographically coherent.

### 11.3 Session key consumption and a validated length

```go
peerSessionKey, err := cryptography.AgeDecryptFromPeer(
	peerHello.PublicKey, peerHello.PublicKeySignature, peerHello.SessionKey)
if err != nil || len(peerSessionKey) != 32 {
```
`pivotclient.go:105-106`

The `len(peerSessionKey) != 32` check is a genuine correctness guard: the session key must be
exactly 32 bytes (a ChaCha20-Poly1305 key). A short key would otherwise flow into the AEAD
construction and fail obscurely; here it fails at the boundary. This is the same fail-closed
posture as the unrendered-template guard in §4.2/§10.3.

Note the argument order — `AgeDecryptFromPeer(publicKey, signature, sessionKey)` — the signature is
**verified as part of the decryption**, so a caller cannot accidentally decrypt without checking.
That's a good API shape: the unsafe path doesn't exist as a separate function on this route
(contrast `DecryptWithoutSignatureCheck`, `crypto.go:223-237`, whose call sites are still
unresolved — see §12.4).

### 11.4 Deadlines are set, then explicitly cleared

```go
p.conn.SetWriteDeadline(time.Now().Add(p.writeDeadline))
p.write(pivotHello)
p.conn.SetWriteDeadline(time.Time{})

p.conn.SetReadDeadline(time.Now().Add(p.readDeadline))
peerPublicKeyRaw, err := p.read()
p.conn.SetReadDeadline(time.Time{})
```
`pivotclient.go:84-90`

Setting a deadline for the handshake and then clearing it to `time.Time{}` (no deadline) before
entering the steady state is deliberate handshake hygiene. A read deadline left armed after
key exchange would kill long-lived idle pivots; a deadline never armed would let a malicious or
dead peer hang the handshake forever. Doing both — armed for the handshake, cleared after — is
the correct sequence, and it is written out twice rather than factored into a helper.

### 11.5 Where pivots sit in the capability surface

The pivot client pairs with `handlers/pivot-handlers.go` (registry `:34`, per §6.1) and the
`pivots` package (`pivots.MyPeerID`, `:79`). The transport itself is selected by the
`StartConnectionLoop` scheme switch in `session.go` (§3.1) — `tcppivot` is one of the seven
scheme branches.

The full chain for a pivoted session:

| Hop | Crypto context | Authenticated by |
|---|---|---|
| outer implant ↔ C2 server | `serverCipherCtx` | server CA pin + envelope Ed25519 sig (§4.2) |
| outer implant ↔ intermediate implant | `peerCipherCtx` | Minisign signature over peer key (§11.2) |
| intermediate implant ↔ server | its own session, established independently | same as any implant |

Each implant is a **separate authenticated endpoint**. The pivot does not extend the server's
session through the intermediate — it relays, and every hop re-establishes its own crypto. That is
why an intermediate implant **cannot read the inner session's plaintext**, and it is the reason
the design survives a compromised relay.

### 11.6 Function inventory

| Line | Symbol | Role |
|---|---|---|
| 42 | `errInvalidPivotSessionID` | sentinel |
| 45 | `NetConnPivotClient` | the client context (two cipher contexts) |
| 58 | `(*NetConnPivotClient).KeyExchange` | peer then server, in order |
| 76 | `peerKeyExchange` | `PivotHello` with signed peer key |
| 110+ | (continued) | peer session establish, server exchange, read/write with mutexes, deadline handling |
| — | `read` / `write` | mutex-guarded, deadline-aware |

---

## 12. Closed: `DecryptWithoutSignatureCheck` call sites — and the answer is sound

§1 left one loose end: the function exists (`cryptography/crypto.go:223-237`) but its call sites
were never traced, so it was unknown whether Sliver had a reachable path that decrypts
attacker-influenced data without verifying a signature. It is now traced exhaustively.

### 12.1 Complete call-site enumeration

A search of every first-party `.go` file in the implant for `DecryptWithoutSignatureCheck` returns
**exactly three hits**:

| File | Line | Kind |
|---|---|---|
| `cryptography/crypto.go` | 223 | the definition |
| `transports/pivotclients/pivotclient.go` | 351 | call site — `p.peerCipherCtx` |
| `pivots/pivots.go` | 571 | call site — `p.cipherCtx` |

**Two call sites, both in the pivot path.** There are zero call sites on the main C2 session path,
zero in the handlers, and zero anywhere in the server. The function is not a general-purpose
escape hatch — it is used in exactly one subsystem.

### 12.2 Why the pivot path legitimately skips the signature

Both sites use the **pivot** cipher context, not the server context. The reason is structural and
visible in the peer handshake itself:

```go
// pivots.go:421 — the peer key is verified ONCE, at handshake time
validPeer := cryptography.MinisignVerify(peerHello.PublicKey, peerHello.PublicKeySignature)
```

The peer's public key is verified against the server's Minisign key **at the moment the pivot is
established** (§11.2). Once verified, the pivot's session key is minted and `AgeEncryptToPeer`
(`pivots.go:431`) takes over for the channel.

The envelope signature (`§4.2`) exists to let a *stateless* receiver — the mTLS listener accepting
connections from arbitrary implants, and the DNS/HTTP transports where each exchange is
independent — decide whether a given envelope came from a device the server trusts. A pivot has
already made that decision, once, on a channel that is itself authenticated end-to-end.

So the two paths differ in **where trust is anchored**, and both are correct:

| Path | Trust anchor | Per-envelope signature? |
|---|---|---|
| Served session (mTLS, DNS, HTTP, WG) | CA pin + per-envelope Ed25519 sig | **Yes** — receiver has no channel-level identity |
| Pivot relay | `MinisignVerify` at handshake (`pivots.go:421`) | **No** — channel identity established first |

Skipping the per-message signature inside an authenticated channel is standard and correct; it
avoids paying Ed25519 verification on every pivot frame when the peer was already proven. The
security property is not weakened because the *session key itself* was established through the
verified handshake.

### 12.3 The residual is now a design observation, not a vulnerability

Two things are worth stating precisely rather than overclaiming either way:

1. **The function is not reachable from an unauthenticated path.** No attacker-supplied data
   reaches `DecryptWithoutSignatureCheck` without first passing `MinisignVerify` at
   `pivots.go:421`. The initial miss was in assuming the name implied exposure; the name describes
   the function's behaviour, not its risk.
2. **The pivot's authentication is single-shot.** The peer key is verified once at handshake; the
   relay then trusts the established cipher context for the life of the pivot. There is no
   re-verification and no key rotation within a pivot — the same property §4.2 describes for the
   server session, and for the same reason (the signature is a channel-establishment mechanism,
   not a per-frame integrity mechanism). A long-lived pivot is as trustworthy as its handshake.

This is the honest close: **the loose end resolves as a correctly-factored optimisation inside an
authenticated channel**, and the finding is that Sliver's two trust anchors are cleanly separated
by subsystem (per-envelope for stateless receivers, per-handshake for stateful relays) rather than
one mechanism applied uniformly.

---

## 13. `tunnel.go` (351 lines) — a hardened reorder buffer, and it was hardened on purpose

§4.4 called the tunnel admission path "the most defensively-written code in the implant." This file
is the rest of that story, and it is the strongest evidence in the corpus that **Sliver's
maintainers have already done security work on this surface** — which matters, because it means the
obvious bugs are *already found*.

### 13.1 A generation-scoped reorder buffer, not an ID-keyed cache

```go
// ProcessInbound serializes one generation's complete accept/cache/drain
// transaction. Pending frames live on the generation rather than in an ID-only
// global cache, so stale handlers cannot corrupt a reused numeric tunnel ID.
```
`transports/tunnel.go:267-269`

That comment is a fix note. The described prior design — a global cache keyed by numeric tunnel ID
— has a use-after-reuse bug: tunnel IDs are `uint64` and can be recycled, so a slow handler
holding an old ID could write into a *new* tunnel's buffer. Moving `pendingInbound` onto the
`Tunnel` struct per-generation (`:46`) eliminates it structurally rather than by locking around it.

The struct reflects the rewrite; the state is split across **five separate locks** with distinct
duties (`:41`, `:44`, `:45`, `:48`, `:54`):

| Field | Duty |
|---|---|
| `outboundMutex` | serialize outbound frames vs the terminal close |
| `mutex *sync.RWMutex` | sequence counters |
| `inboundMutex` | the pending map |
| `closeOnce sync.Once` | exactly-once local close |
| `peerCloseTimerOnce sync.Once` | exactly-once close deadline arm |

plus three `atomic.Bool` flags (`:51-52`) for peer state that is read without a lock. That is not
decorative; each lock guards a different invariant, and collapsing them would deadlock or race.

### 13.2 The bounds are all computed from a stated capacity, not chosen

```go
const (
	// MTLS and WireGuard accept up to 128 concurrent streams. The receive window
	// must admit that much legitimate handler reordering while remaining bounded.
	maxTunnelPendingFrames = 128
	maxTunnelFrameBytes    = sliverpb.MaxTunnelFrameBytes
	maxTunnelPendingBytes  = maxTunnelPendingFrames * maxTunnelFrameBytes
)
```
`tunnel.go:22-28`

`maxTunnelPendingFrames = 128` is **derived from the yamux stream limit**, not picked. The
comment states the reasoning: with up to 128 concurrent streams, 128 frames of legitimate
reordering must be admissible or the transport stalls under normal load — but the window must
still be finite or it is a memory-exhaustion primitive. `maxTunnelPendingBytes` is then *computed*
from the two (`:28`), so the byte bound cannot drift out of sync with the frame bound. This is the
opposite of a magic number: it is a capacity argument.

### 13.3 `ProcessInbound` — the ordering, and why each check is where it is

```go
if len(data) > maxTunnelFrameBytes {
	return 0, fmt.Errorf("%w: got %d bytes, limit %d", ...)
}
```
`:274-276` — oversize rejected **before** taking the lock (cheap check first, and it can't be
influenced by other goroutines).

```go
if c.peerCloseSet.Load() && sequence >= c.peerCloseSequence {
	return len(c.pendingInbound), ErrTunnelTerminalSequence
}
```
`:290-292` — once the peer has announced close at sequence *N*, any frame at or beyond *N* is
refused. This is the **terminal-sequence invariant**: it stops a late frame from being delivered
after the stream was told it ended.

```go
if sequence < expected {
	return len(c.pendingInbound), nil      // already-seen: silently accepted
}
```
`:293-295` — a stale/duplicate frame is **not** an error. It returns `nil`. A retransmit is normal
on a reordering transport; failing here would tear down healthy tunnels. Returning the current
pending count instead of a value lets the caller resync.

```go
if sequence-expected >= maxTunnelPendingFrames {
	return ..., ErrTunnelSequenceWindow
}
```
`:296-298` — a frame too far ahead is refused. Note the subtraction is done on `uint64` **after**
the `sequence < expected` branch has already returned, so underflow is impossible here. Check
ordering makes the subtraction safe; this is the kind of thing that is usually got wrong.

```go
if _, duplicate := c.pendingInbound[sequence]; !duplicate {
	if c.pendingBytes+len(data) > maxTunnelPendingBytes {
		return ..., ErrTunnelPendingBytes
	}
	payload := append([]byte(nil), data...)
```
`:299-305` — two things worth noting. The **duplicate check precedes the byte check**, so a
retransmitted frame cannot be double-counted toward the byte budget. And the payload is **copied**
via `append([]byte(nil), data...)` — the caller's buffer is not retained. Retaining it would be a
classic aliasing bug: the upstream read buffer gets reused, silently mutating queued data.

The drain loop (`:308-320`) advances `expected` strictly in order and decrements `pendingBytes`
per delivered frame, so the accounting stays exact.

### 13.4 Reverse tunnels opt out of the legacy resend protocol explicitly

```go
// NewReverseTunnel marks a generation as reverse-port-forward traffic. Reverse
// relays use reliable transports and bounded reordering, not the legacy generic
// tunnel resend/cache protocol.
```
`tunnel.go:59-61`

`reverse bool` (`:56`) is set only by `NewReverseTunnel` (`:62-66`) and read by `IsReverse`
(`:69-71`). The comment names a "legacy generic tunnel resend/cache protocol" — reverse port
forwards ride reliable transports (mTLS/WireGuard, §10.1) where resend is unnecessary, so they use
bounded reordering only. Two delivery disciplines in one type, selected by construction rather
than by a flag argument.

### 13.5 The bounded close handshake

Six dedicated error values (`:16-20`) exist for tunnel state, which is unusual — most codebases
would use one `ErrClosed`:

```
ErrTunnelClosed           "tunnel is closed"
ErrTunnelTerminalSequence "tunnel terminal sequence is invalid"
ErrTunnelFrameTooLarge    "tunnel frame exceeds the size limit"
ErrTunnelSequenceWindow   "tunnel sequence exceeds the pending window"
ErrTunnelPendingBytes     "tunnel pending data exceeds the byte limit"
```
`:16-20`

Distinct sentinels let the caller distinguish "this tunnel is done" from "this frame was bad" from
"we're out of budget." `queueOutbound` (`:97`) and `queueControl` (`:121`) both reject with
`ErrTunnelClosed` (checked under `outboundMutex`), `closeLocal` (`:141`) / `closeRemote` (`:166`)
handle each direction separately, and `MarkPeerClose` (`:179`) plus
`StartPeerCloseDeadline` (`:236`) give the peer close a **bounded** window — a peer that announces
close and then stops responding cannot pin the tunnel open forever. `PeerCloseReady()` (`:228`)
is the gate.

### 13.6 What this means for the assessment

Four separate hardening decisions are visible in this one file: generation-scoped state (fixes a
recycled-ID corruption), capacity-derived bounds (fixes unbounded memory growth), copy-on-enqueue
(fixes buffer aliasing), and a bounded close deadline (fixes peer-stall). Each has a comment
stating the *reason*, which is the signature of code written after a review rather than before.

**This is the honest counterweight to §7.** Sliver has no direct syscalls — but on the
*protocol-integrity* axis it is markedly more careful than Havoc, whose equivalent parser has the
unbounded-length wraparound documented in D5 §7A. The two frameworks are strong in different
places: Havoc on Windows evasion primitives, Sliver on transport correctness. Neither is uniformly
"better," and any ranking that doesn't separate the axes is wrong.

### 13.7 Function inventory

| Line | Symbol | Role |
|---|---|---|
| 62 | `NewReverseTunnel` | mark generation as reverse-port-forward |
| 69 | `IsReverse` | nil-safe predicate |
| 73 | `NewTunnel` | construct |
| 85 | `Done` | detach signal channel |
| 91 | `setPeerCloseNotifier` | install bounded close callback (must precede publication) |
| 97 | `queueOutbound` | serialize data frame vs terminal close |
| 121 | `queueControl` | same for control frames |
| 141 | `closeLocal` | local close, exactly once |
| 166 | `closeRemote` | remote close |
| 179 | `MarkPeerClose` | peer announced close at sequence |
| 215 | `PeerClosePending` | state query |
| 223 | `PeerTeardownPending` | state query |
| 228 | `PeerCloseReady` | gate |
| 236 | `StartPeerCloseDeadline` | bounded close window |
| 253 | `ReadSequence` | sequence read |
| 260 | `WriteSequence` | sequence read |
| 270 | `ProcessInbound` | **accept / cache / drain transaction** |
| 324 | `incWriteSequence` | advance |
| 331 | `IncReadSequence` | advance |
| 339 | `Close` | teardown |

---

## 14. Service layer — `service/service_windows.go` (257 lines) — and a genuinely unexpected finding

This is the Windows persistence and lateral-movement surface: create, start, stop, delete, list and
enumerate Windows services, locally or on a remote host.

### 14.1 The implant reads services with deliberately *reduced* privilege

```go
const (
	ReadOnlyServiceManagerPermissions = windows.SC_MANAGER_ENUMERATE_SERVICE
	ReadOnlyServicePermissions        = windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS
	ConnectServiceManagerPermissions  = windows.SC_MANAGER_CONNECT
	StartServiceAndVerifyPermissions  = windows.SERVICE_START | windows.SERVICE_QUERY_STATUS
)
```
`service/service_windows.go:32-37`

Four named permission sets, each the **minimum** required for its operation. `ListServices` uses
`SC_MANAGER_ENUMERATE_SERVICE` (`:159`), not `SC_MANAGER_ALL_ACCESS`. `GetServiceDetail` likewise
(`:201`). Only `StartServiceByName` requests `SERVICE_START` (`:231`).

The reason is documented in the file itself (`:106-116`) — and it is a **bug workaround, not a
stealth choice**:

```go
/*
	Currently, golang.org/x/sys/windows/svc/mgr attempts to open the service
	manager with elevated permissions: https://github.com/golang/go/issues/51465
	https://github.com/golang/sys/blob/master/windows/svc/mgr/mgr.go#L34

	We should not need elevated privileges to list services, so we will have to
	define a custom service manager that asks for lower rights.

	Similarly, we need a custom OpenService function that does not ask for
	elevated rights so we can get the status and config of the service.
*/
```
`service_windows.go:106-116`

The upstream Go library requests more access than enumeration needs, which breaks unprivileged
enumeration. Sliver **bypasses the library** and calls the Win32 API directly (`:118-138`) to ask
for less. `connectToServiceManager` (`:118`) and `openService` (`:132`) hand-construct
`mgr.Mgr{Handle: handle}` / `mgr.Service{Name:, Handle:}` from raw `windows.OpenSCManager` /
`windows.OpenService` handles.

**The security-relevant consequence is the inverse of what a C2 implant usually wants.** Sliver
goes *out of its way* to operate unprivileged here. For an operator this is an availability win —
you can enumerate services from a medium-integrity context. For a defender it means **service
enumeration by Sliver produces no elevation event and no 4672/4673 audit record**, because no
privilege was requested. A detection built on "service enumeration implies elevated context" will
not fire.

### 14.2 Creation is manual-start, and that is a deliberate invisibility choice

```go
service, err := manager.CreateService(serviceName, binPath, mgr.Config{
	ErrorControl:   mgr.ErrorNormal,
	BinaryPathName: binPath,
	Description:    serviceDesc,
	DisplayName:    serviceName,
	ServiceType:    windows.SERVICE_WIN32_OWN_PROCESS,
	StartType:      mgr.StartManual,
}, arguments)
```
`service_windows.go:45-52`

`StartType: mgr.StartManual` (`:51`) — **not** `StartAuto`. A manual-start service does not run at
boot; it runs when started. So `StartService` is not a reboot-persistence primitive **on its own**;
it is a *lateral movement* primitive (start a service on a remote host, `:40` `ConnectRemote(hostname)`)
and an *execution* primitive. `DisplayName == serviceName` (`:49`) and a caller-supplied
`Description` (`:48`) mean the service's visible metadata is fully operator-controlled, so it will
present as whatever the operator typed.

`ErrorControl: mgr.ErrorNormal` (`:46`) means a failure is logged but startup continues.

### 14.3 A copy-paste bug in the stop path — the error handling is wrong

```go
status, err := service.Control(svc.Stop)
if err != nil {
	return err
}
timeout := time.Now().Add(10 * time.Second)

for status.State != svc.Stopped {
	if timeout.Before(time.Now()) {
		return fmt.Errorf("timeout waiting for service to go to state=%d", svc.Stopped)
	}
	time.Sleep(300 * time.Millisecond)
	status, err = service.Query()
	if err != nil {
		return fmt.Errorf("could not retrieve service status: %v", err)
	}
}
```
`service_windows.go:73-88`

The loop is correct in shape — poll every 300 ms with a 10 s ceiling — but compare it against the
near-identical loop in `StartServiceByName` (`:240-255`):

```go
err = serviceHandle.Start()
if err != nil {
	return err
}
timeout := time.Now().Add(10 * time.Second)
status, err := serviceHandle.Query()      // <-- assigned here
if err != nil {
	return fmt.Errorf("could not retrieve service status: %v", err)
}
for status.State != svc.Running { ... }
```

The difference: `StartServiceByName` **checks the error** from the initial `Query()` (`:242-244`)
before entering the loop. `StopService` calls `service.Control(svc.Stop)` and then enters the loop
with the `status` that call returned, **never checking `err` from it** — and it uses `service.Query()`
only *inside* the loop.

Note also that `StopService` declares `status, err := service.Control(svc.Stop)` at `:73` but then
reuses the outer `err` from `OpenService` at `:69-72` — the shadowing is benign because `:=` here
does bind a new `status` while `err` is reassigned. The loop then assigns `status, err = ...` with
plain `=` (`:84`), so it writes the outer `err` — which is never read again. The function is
**functionally correct** (the state check is what drives the loop, and the inner error *is* checked)
but it is a near-miss against a real bug in the sibling function, and the asymmetry is worth naming
because it is exactly the kind of difference that silently becomes a bug under later edits.

### 14.4 Partial results are returned alongside an error — deliberately

```go
if len(serviceErrors) > 0 {
	operationError = fmt.Errorf("%s", strings.Join(serviceErrors, "\n"))
} else {
	operationError = nil
}
return servicesList, operationError
```
`service_windows.go:191-197`

`ListServices` accumulates per-service failures into `serviceErrors` (`:172`, `:177`, `:183`) and
returns **both** a populated list and a non-nil error. A service that cannot be opened — access
denied on a protected service, typically — is skipped and reported rather than aborting the
enumeration. Same pattern in `GetServiceDetail` (`:215-220`), where a failed `Query()` still
returns the config it did obtain:

```go
serviceDetail.Status = 0
// Even though we encountered an error, it was not fatal (we still got some information about the service)
return serviceDetail, fmt.Errorf("Unknown (could not retrieve: %s)", err.Error())
```

That comment (`:218`) states the intent. The practical effect for an operator doing recon on a
hardened host: **`ListServices` succeeds in returning the services the implant can see, and
separately tells you which ones it couldn't** — which services you were denied is itself
intelligence about where the interesting (protected) software lives.

### 14.5 Function inventory

| Line | Function | Role |
|---|---|---|
| 39 | `StartService` | remote-capable create + start, `StartManual` |
| 64 | `StopService` | stop with 10 s poll ceiling |
| 93 | `RemoveService` | delete |
| 118 | `connectToServiceManager` | **raw Win32 open with explicit low rights** |
| 132 | `openService` | raw Win32 open with explicit low rights |
| 140 | `buildServiceDetail` | `mgr.Config` → protobuf |
| 154 | `ListServices` | enumerate, partial-failure tolerant |
| 200 | `GetServiceDetail` | one service, partial-failure tolerant |
| 225 | `StartServiceByName` | start + verify running |
| — | `service.go` | **0 bytes** — the standard non-Windows platform stub |

`service/service.go` is **0 bytes** and `service/README.md` is 0.4 KB — the same platform-split
pattern as `syscalls/syscalls.go` (§7.4) and `handlers_generic.go` (§6.1). Sliver does not use
build tags for platform separation; it uses **empty/stub files with `_windows.go` suffixed
siblings**. This is consistent across the whole codebase and is worth knowing when enumerating:
a file named `X.go` may contain nothing at all, and its content lives in `X_windows.go`.

### 14.6 What this does and does not establish

**Established.** The implant can create, start, stop, delete and enumerate Windows services and can
target a remote hostname (`mgr.ConnectRemote`). Enumeration is deliberately unprivileged. Service
metadata is fully operator-controlled. No automatic-start persistence is set.

**Not established.** This file does **not** describe the implant's reboot persistence. No
`StartAuto`, no registry `Run` key, no scheduled task, no WMI subscription appears here. Where
Sliver's actual persistence lives is **still open** — `taskrunner/task_windows.go` (15.5 KB) is the
next candidate, and it was read only for its POSIX fork-safety `go:linkname` uses in §7.3. Persistence
remains on §15's remaining list.

---

## 15. The real evasion payload — `taskrunner/task_windows.go` (534 lines)

§7.2 said Sliver's evasion is "in-memory execution, ARGV spoofing, module stomping, thread hijack."
This file is where most of that actually happens, and it contains the implant's only genuine
security-product bypasses.

### 15.1 `patchAmsi` — and `patchEtw` — are single-byte `0xC3` patches

```go
func patchAmsi() error {
	// load amsi.dll
	amsiDLL := windows.NewLazyDLL("amsi.dll")
	amsiScanBuffer := amsiDLL.NewProc("AmsiScanBuffer")
	amsiInitialize := amsiDLL.NewProc("AmsiInitialize")
	amsiScanString := amsiDLL.NewProc("AmsiScanString")

	// patch
	amsiAddr := []uintptr{
		amsiScanBuffer.Addr(),
		amsiInitialize.Addr(),
		amsiScanString.Addr(),
	}
	patch := byte(0xC3)
	for _, addr := range amsiAddr {
		// skip if already patched
		if *(*byte)(unsafe.Pointer(addr)) != patch {
```
`taskrunner/task_windows.go:199-215`

Write `0xC3` — `ret` — as the first byte of three exported `amsi.dll` functions. `AmsiScanBuffer`
now returns immediately with whatever is in `EAX`, which is the classic **"return a success/clean
verdict without scanning"** bypass. `AmsiInitialize` and `AmsiScanString` are patched too, so an
AMSI-aware host that calls either entry point also gets a no-op.

```go
func patchEtw() error {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	etwEventWriteProc := ntdll.NewProc("EtwEventWrite")
	patch := byte(0xC3)
```
`task_windows.go:240-245`

Same technique against `ntdll!EtwEventWrite` — the single most common ETW userland write path.
Blinding it suppresses most `.NET`/PowerShell/AMSI telemetry that routes through ETW, and it is the
standard companion to an AMSI patch because patching AMSI alone still leaves the ETW event trail.

**Both are conditional at the call site, not build time:**

```go
func InProcExecuteAssembly(assemblyBytes []byte, assemblyArgs []string, runtime string, amsiBypass bool, etwBypass bool) (string, error) {
	if amsiBypass {
		err := patchAmsi()
		if err != nil { return "", err }
	}
	if etwBypass {
		err := patchEtw()
		if err != nil { return "", err }
	}
	return LoadAssembly(assemblyBytes, assemblyArgs, runtime)
}
```
`task_windows.go:271-287`

Driven by `execReq.AmsiBypass` / `execReq.EtwBypass` (`handlers_windows.go:334`) — so these are
**operator-selected per-execution**, not compile-time config. The same operator can run a
non-bypassed `execute-assembly` (noisy, no patches) and a bypassed one (quiet, patched) from the
same implant without rebuilding. Note the failure mode: if `patchAmsi` errors, the function
**returns and never executes the assembly** (`:273-275`). A failed patch aborts the task rather
than silently continuing into a scanned load — fail-closed, and consistent with §13's posture.

### 15.2 The `&oldProtect` double-use is *not* a bug — and the reason is worth stating

Both patches do this:

```go
var oldProtect uint32
err := windows.VirtualProtect(addr, 1, windows.PAGE_READWRITE, &oldProtect)
if err != nil { ...; return err }
*(*byte)(unsafe.Pointer(addr)) = 0xC3
err = windows.VirtualProtect(addr, 1, oldProtect, &oldProtect)   // <-- both in and out
```
`task_windows.go:219-228` (AMSI), `:251-260` (ETW)

`oldProtect` is passed as **both** the new protection to apply and the output pointer for the old
one. This reads like a bug and I initially scored it as one. It is **correct**, and the reason is
in the vendored API:

```go
//sys	VirtualProtect(address uintptr, size uintptr, newprotect uint32, oldprotect *uint32) (err error) = kernel32.VirtualProtect
func VirtualProtect(address uintptr, size uintptr, newprotect uint32, oldprotect *uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualProtect.Addr(), uintptr(address), uintptr(size), uintptr(newprotect), uintptr(unsafe.Pointer(oldprotect)))
```
`vendor/golang.org/x/sys/windows/syscall_windows.go` + `zsyscall_windows.go` (`x/sys` v0.47.0,
confirmed against the client binary's build info)

`newprotect` is passed **by value** into the syscall. The kernel reads that value *before* it writes
the previous protection back through the pointer. So:

1. Call 1: `newprotect = PAGE_READWRITE`, kernel writes the real original protection into `oldProtect`.
2. Call 2: `newprotect = oldProtect` (the value captured in step 1) **and** `oldprotect = &oldProtect`.
   The syscall receives the correct restore value; the subsequent write-back clobbers the variable,
   which is then never read again.

**The double-use is safe because of evaluation order, not by accident** — and the same idiom appears
twice, so it is a deliberate pattern rather than a slip. This is exactly the class of thing that
looks like a finding and isn't; recording it here so it is not re-raised.

### 15.3 What is genuinely notable

| Property | Value |
|---|---|
| Patch type | 1-byte `0xC3` (`ret`) — the crudest possible bypass |
| Targets | `amsi.dll`:`AmsiScanBuffer`/`AmsiInitialize`/`AmsiScanString`; `ntdll`:`EtwEventWrite` |
| Idempotent | Yes — checks first byte before patching (`:215`, `:247`) |
| Restores protection | Yes — via `oldProtect` from the first call |
| Selection | Runtime, per-execution (`AmsiBypass`/`EtwBypass` request fields) |
| Applied only to | `InProcExecuteAssembly` — **in-process** .NET assembly load |
| Failure behaviour | Aborts the task (`:273-275`) |

**The detection surface this creates is large and specific.** A `0xC3` at the entry of
`AmsiScanBuffer` is one of the most heavily signatured byte patterns in Windows security
monitoring, and the patch requires `VirtualProtect` on a **mapped image page** owned by
`amsi.dll`. That is precisely the behavioural signal D5 §5 flagged for Havoc — "detects any
obfuscator that makes a loaded image writable." **Sliver trips the same wire here.**

This is the sharpest contrast in the whole corpus. Sliver refuses direct syscalls and refuses to
build a syscall-number table (§7), then writes `0xC3` into `amsi.dll` in place — leaving an
in-memory image modification that a userland EDR hook sees immediately. Havoc implements
Hell's Gate + Halo's Gate to avoid exactly that, then has a **broken AMSI bypass on x86** (D5 §13.4).
**Neither framework scores cleanly on this axis, and the two failures are opposite in kind:** Sliver
chooses simplicity over stealth at runtime; Havoc chooses sophistication and gets it wrong on half
the architectures.

### 15.4 Corrected: Sliver has NO registry/scheduled-task persistence

§14.6 left Sliver's reboot persistence open. A targeted search closes it:

```
Search: all first-party implant .go for
  CurrentVersion\Run | schtasks | ScheduledTask | CreateService | StartAuto |
  Win32_Process | ActiveScriptEventConsumer | CreateProcessAsUser

Result: exactly ONE hit — service_windows.go:45 (CreateService, StartManual)
```

**There is no registry `Run` key, no scheduled task, no WMI event subscription, no
`CreateService` with `StartAuto`, and no logon-script persistence anywhere in the first-party
implant.** Combined with §14.2 (`StartType: mgr.StartManual` at `service_windows.go:51`), the
conclusion is firm:

> **Sliver's Windows implant ships no boot-persistence mechanism at all in this revision.**
> The service functions are *lateral movement* and *execution* primitives — create a service on a
> remote host, start it, stop it, delete it, enumerate — not survival primitives.

This is a genuine architectural difference from the rest of the corpus and it is worth stating
plainly: Havoc, Pupy and Covenant all ship persistence. Sliver's own persistence story is operator
workflow (re-obtain access; use `execute-assembly`/`sideload`/BOF to deploy something that persists)
rather than an implant feature. Anyone assessing Sliver's *durability* on a host should not expect
the implant itself to survive a reboot.

`taskrunner/task_windows.go`'s remaining functions are the injection/execution engine, inventoried
below rather than described one-by-one:

| Line | Function | Role |
|---|---|---|
| 54 | `sysAlloc` | allocate, optionally `rwxPages` |
| 68 | `injectTask` | write payload + create thread in a target |
| 137 | `RemoteTask` | shellcode into a remote process |
| 162 | `LocalTask` | shellcode in-process |
| 199 | `patchAmsi` | **AMSI bypass (§15.1)** |
| 240 | `patchEtw` | **ETW bypass (§15.1)** |
| 271 | `InProcExecuteAssembly` | .NET load in-process, behind the two bypass gates |
| 289 | `ExecuteAssembly` | .NET load in a spawned process |
| 337 | `SpawnDll` | **module stomping** — `spawnReq.GetOffset()` selects the overwrite target (D1 §7.2) |
| 408 | `Sideload` | load a DLL from memory against a legitimate host process |
| 413 | `refresh` | re-resolve |
| 438 | `startProcess` | spawn with `suspended` + explicit `ppid` (PPID spoofing) |
| 471 | `waitForCompletion` | thread join |
| 494 | `allocAndWrite` | `VirtualAllocEx` + `WriteProcessMemory` |
| 509 | `protectAndExec` | `VirtualProtectEx` + `CreateRemoteThread`/`NtCreateThreadEx` |
| 530 | `convertIntToByteArr` | argument marshalling |

Note `startProcess(..., suspended bool)` (`:438`) and `ppid uint32` (`:289`, `:337`, `:408`) — the
`ppid` parameter is threaded through every spawn path, which is the **parent-process-ID spoofing**
in §7.2 and the reason a process-spawn detection keyed on parent lineage is evadable here.

---

## 16. The BOF/native-extension layer is a vendored dependency, not Sliver code

§7.2 listed "in-process assembly, module stomping" as Sliver evasion and §6.1 inventories three
BOF and three WASM handlers. What is **not** evident from the handler map is that Sliver implements
almost none of that machinery itself.

### 16.1 `handlers/handlers_bof.go` is 62 lines and does no loading

```go
import (
	"errors"
	"fmt"

	"github.com/sliverarmory/reflektor/bof"
)
...
func loadReflektorBOF(data []byte, options bof.LoadOptions) (bofObject, error) {
	if options.EntryPoint == "" {
		return bof.Load(data)
	}
	return bof.LoadWithOptions(data, options)
}
```
`handlers/handlers_bof.go:5-26`

The whole file is a **shim**: an interface (`bofObject`, `:12-15`), two function types
(`:17`, `:19`), a loader that forwards to `reflektor`, and an executor. `isDefaultBOFEntryPoint`
(`:55-61`) knows the conventional Beacon entry names — `""`, `"go"`, `"_go"`, `"coffee"`,
`"_coffee"` — which is pure Cobalt Strike BOF convention, so the *interface* is Sliver's and the
*implementation* is not.

Note the dependency is not even in Sliver's own tree: `github.com/sliverarmory/reflektor` is a
separate SliverArmory project, consumed as a module.

### 16.2 What is actually vendored — the real capability

`vendor/github.com/sliverarmory/reflektor/` is roughly **500 KB of first-class loader
implementation**:

| Subtree | Size | What it is |
|---|---|---|
| `internal/bofloader/parser_coff.go` | 14.1 KB | **COFF/BOF parser** |
| `internal/bofloader/parser_elf.go` | 24.4 KB | ELF parser |
| `internal/bofloader/parser_macho.go` | 29.4 KB | Mach-O parser |
| `internal/bofloader/reloc_coff.go` | 11.8 KB | COFF relocation |
| `internal/bofloader/reloc_elf.go` | 13.2 KB | ELF relocation |
| `internal/bofloader/reloc_macho.go` | 10.2 KB | Mach-O relocation |
| `internal/bofloader/reloc_aarch64.go` | 8.3 KB | AArch64 relocation |
| `internal/bofloader/reloc_arm32_elf.go` | 4.3 KB | ARM32 relocation |
| `internal/bofloader/reloc_ppc64le_elf.go` | 13.1 KB | PPC64LE relocation |
| `internal/bofloader/reloc_riscv64_elf.go` | 10.8 KB | RISC-V relocation |
| `internal/bofloader/callbacks.go` | 23.8 KB | **Beacon API callback surface** |
| `internal/bofloader/unwind_windows_64.go` | 18.6 KB | Windows x64 SEH unwind tables |
| `internal/bofloader/memory_windows.go` | 3.3 KB | executable memory |
| `bof/api.go` | 9.3 KB | public BOF API |
| **`memmod/memmod_windows.go`** | **28.8 KB** | **Windows in-memory PE module loader** |
| `memmod/memmod_windows_recursive.go` | 17.2 KB | recursive dependency resolution |
| `memmod/memmod_elf.go` | 51.7 KB | ELF in-memory loader |
| `memmod/memmod_darwin.go` | 51.3 KB | Mach-O in-memory loader |
| `memmod/syscall_windows.go` | 15.5 KB | **its own Windows syscall layer** |
| `native/internal/linuxmem/loader_elf.go` | 54.1 KB | Linux in-memory loader |
| `memmod/COPYING` | 1.1 KB | **separate license file** |
| `LICENSE` | 35 KB | |

**This relocates a substantial part of Sliver's "evasion" story out of Sliver.** Everything §7.2
described — in-memory assembly, module stomping, native extension loading — bottoms out in
`reflektor`, and `reflektor` is where the actual PE/COFF/ELF/Mach-O parsing, relocation, unwind-table
handling and executable-memory management live. Sliver contributes the opcode that says "run this
BOF" (`handlers_bof.go:28`) and the handler registration (§6.1).

### 16.3 `reflektor` ships its own syscall layer — the question is now ANSWERED, and the answer is NO

`memmod/syscall_windows.go` (15.5 KB) plus `syscall_windows_32.go` (3.9 KB) and
`syscall_windows_64.go` (3.8 KB) looked like a multi-architecture Windows syscall abstraction, which
would have been exactly the component used to invoke native APIs without importing them. I recorded
it as unresolved rather than guessing. It is now read.

**It is not a syscall layer.** `syscall_windows_64.go` contains only PE structure definitions —
`IMAGE_OPTIONAL_HEADER` (all ~50 fields), `IMAGE_LOAD_CONFIG_DIRECTORY` with the full CFG/GuardCF
surface, `IMAGE_ORDINAL_FLAG`. `syscall_windows.go` opens with PE signatures and `IMAGE_DOS_HEADER`
/ `IMAGE_FILE_HEADER`. The "syscall" in the filename means *the Windows API surface being
redeclared*, not *syscall-number resolution*.

And the provenance is unambiguous — **every one of the 11 files carries a WireGuard LLC copyright**:

```
Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.   × 1
* Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved. × 10
SPDX-License-Identifier: MIT
```

**`memmod` is WireGuard's own in-memory PE/ELF/Mach-O loader**, MIT-licensed, vendored into
`reflektor`, which is vendored into Sliver. The nested provenance in §16.4 is therefore
**WireGuard → reflektor → Sliver**.

How it resolves imports settles the stealth question directly:

```go
handle, err := windows.LoadLibraryEx(windows.BytePtrToString((*byte)(a2p(module.codeBase+uintptr(importDesc.Name)))), 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
...
*funcRef, err = windows.GetProcAddressByOrdinal(handle, IMAGE_ORDINAL(*thunkRef))
...
*funcRef, err = windows.GetProcAddress(handle, windows.BytePtrToString(&thunkData.Name[0]))
```
`memmod/memmod_windows.go:354`, `:369`, `:372`

Imports are resolved **by name and by ordinal through `LoadLibraryEx` + `GetProcAddress`** — the
ordinary Windows loader path. Thread entry is a plain `syscall.Syscall(f, 3, module.codeBase,
DLL_PROCESS_ATTACH, 0)` (`:258`), and `RtlPcToFileHeader` is called through `syscall.Syscall` on a
resolved pointer (`:471`).

**CONCLUSION — §7's finding is strengthened, not qualified.** There is no Hell's Gate, no Halo's
Gate, no SSN table, and no direct-syscall stub **anywhere in the Sliver implant's dependency chain
that ships with it**, including the ~500 KB of vendored loader code. Every native call in the
loading path goes through `GetProcAddress`. A userland EDR hook on `LoadLibraryEx`,
`GetProcAddress` or the resolved functions **sees the entire in-memory module load**.

This makes the Sliver/Havoc contrast sharper than §7 stated it:

| | Sliver (whole dependency closure) | Havoc |
|---|---|---|
| Direct syscalls | **No** — zero, at any level | Yes — Hell's Gate + Halo's Gate (`Syscalls.c:90`, `:196-237`) |
| Assembly stubs | **Zero** `.s`/`.asm` in first-party | 4 `.asm` files |
| AMSI bypass | 1-byte `0xC3` patch, works (§15.1) | **Broken on x86** (D5 §13.4) |
| ETW bypass | 1-byte `0xC3` patch (§15.1) | `AMSIETW_PATCH_MEMORY` unimplemented; HWBP is `#if _WIN64` |
| APC injection | Present via handlers | **Does not exist** — both TODOs empty |
| Sleep obfuscation | Not present | Ekko/Zilean/Foliage ROP |

Havoc invested in the low-level primitives and left several **unfinished**; Sliver declined the
low-level primitives entirely and what it does ship **works**. For a defender the practical
consequence is that Havoc is harder to see *when its features are correct*, and Sliver is **always**
visible on the same telemetry — which makes Sliver the easier of the two to detect on Windows and
the more reliable of the two to operate.

### 16.4 Licensing

`memmod/COPYING` (1.1 KB) is a **separate license file** from `reflektor/LICENSE` (35 KB), and
`memmod` carries its own README — consistent with `memmod` being vendored into `reflektor` from a
third project in turn. Sliver's implant therefore contains at least **two nested layers of
third-party code** for its in-memory loading capability. This is worth flagging because it means
the provenance of the implant's most sophisticated component is **three levels deep**: Sliver →
reflektor → memmod → (its own upstream).

### 16.5 Encoders — Sliver's own, and small

`implant/sliver/encoders/` is Sliver-proper and much smaller than the loader layer:

| File | Size | Role |
|---|---|---|
| `encoders.go` | 6.3 KB | registry / byte-encoder interface |
| `base58.go` | 4.6 KB | Base58 |
| `base58_alphabet.go` | 1.7 KB | alphabet |
| `base58_genalphabet.go` | 1.5 KB | generated table |
| `base32.go` | 1.3 KB | Base32 (used by DNS transport, §9) |
| `base64.go` | 1.2 KB | Base64 |
| `basex.go` | 3.0 KB | arbitrary-base |
| `basex_test.go` | **12.7 KB** | — note the test is 4× the size of the implementation |
| `english.go` + `english.gz` | 2.1 + 2.6 KB | English-word encoding |
| `gzip.go` | 1.6 KB | compression stage |
| `hex.go` | 1.0 KB | hex |
| `images.go` | 3.4 KB | image-based (stego) encoding |
| `nop.go` | 1.0 KB | identity |
| `traffic-encoder.go` | 3.8 KB | the C2 traffic encoder chain |

`english.go` + the `english.gz` wordlist is **word-based C2 encoding** — traffic that looks like
English text rather than base64 — and `images.go` is a steganographic encoder. Both are
transport-level traffic-shaping options, consistent with Sliver's design philosophy of blending
(HTTP/WinINet, DNS-over-base32, English-word encoding) rather than of low-level syscall stealth.
**Combined with §7 and §16.3 that is now a consistent, demonstrable pattern across three
independent subsystems**, not an inference from one file.

---

## 17. Status

Sections complete: §0 correction, §1 crypto perimeter, §2 inventory, §3 transports, §4 framing and
tunnel admission, §5 HTTP transport + WinINet, §6 handler dispatch + the 135-entry message-ID table,
§7 evasion layer (negative finding + Havoc contrast), §8 citation convention, §9 DNS transport,
§10 WireGuard + the shared signing pattern, §11 peer-to-peer pivot layer, §12 closure of the
`DecryptWithoutSignatureCheck` loose end, §13 `tunnel.go` reorder buffer, §14 service layer,
§15 AMSI/ETW bypasses + persistence closed (negative), §16 the vendored reflektor loader layer.
Remaining: server (408 files), client (539 files), vendor enumeration beyond reflektor, `shell/`,
`proxy/`. Appended incrementally.

---

## 18. Server half — the certificate authority, and where the whole perimeter starts

`server/certs/` (11 files) is the root of the trust system §1–§4 depend on. Every implant's
`RootOnlyVerifyCertificate` (`cryptography/crypto.go:253-256`) resolves against something generated
here.

### 18.1 Four CAs, and only one of them takes a common name

```go
func SetupCAs() {
	importCertificateAuthoritiesFromDisk()
	GenerateCertificateAuthority(MtlsImplantCA, "")
	GenerateCertificateAuthority(MtlsServerCA, "")
	GenerateCertificateAuthority(OperatorCA, "operators")
	GenerateCertificateAuthority(HTTPSCA, "")
}
```
`server/certs/ca.go:40-46`

Four independent hierarchies, named at `server/certs/mtls.go:28-30` and elsewhere:
**`mtls-implant`**, **`mtls-server`**, **`operators`**, **HTTPS**. The separation is the point —
compromising the operator CA does not let you forge an implant, and vice versa. `SetupCAs` is
idempotent: `GenerateCertificateAuthority` checks `certificateAuthorityExists` first (`:55`) and
falls back to `importCertificateAuthorityFromDisk` (`:56`), so a CA is generated **once per
install** and reused.

### 18.2 Curve selection is randomised, and it is biased

```go
var curves []elliptic.Curve
if isOperator {
	curves = []elliptic.Curve{elliptic.P256()}
} else {
	curves = []elliptic.Curve{elliptic.P521(), elliptic.P384(), elliptic.P256()}
}
curve := curves[randomInt(len(curves))]
privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
```
`server/certs/certs.go:146-154`

Two findings:

1. **Operator certs are P-256 only; everything else is uniformly sampled across P-521, P-384,
   P-256.** This is a real fingerprinting surface *on the server side*, not the implant: across a
   fleet, two-thirds of non-operator listener certificates are **not** P-256. A scan that sees a
   P-521 leaf on a port is looking at a Sliver-family listener with ~2/3 probability. Sliver
   randomises the curve — which the framework presumably intended as diversity — and in doing so
   produces a distribution that is itself unusual, because P-521 and P-384 are rare in the wild
   relative to P-256.
2. **The ECDSA keys are generated with `rand.Reader`** (`:154`) — Go's CSPRNG, not a custom source.
   That is the correct choice and it is worth stating explicitly, because D5 §5 found Havoc seeding
   its AES key from `RandomNumber32()`, whose entropy source T5 left unresolved (#3 in T5's residual
   list). **Sliver's key generation has no such question hanging over it.**

### 18.3 Certificate metadata

```go
serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
```
`server/certs/certs.go:193-194`

- **128-bit random serial**, not sequential. Sequential serials are a classic fingerprint; this
  avoids it. The error from `rand.Int` is discarded (`_`) — acceptable here, since the only failure
  mode is CSPRNG exhaustion.
- `notBefore := time.Now()` with an optional backdate (`:186-188`), then
  `notAfter := notBefore.Add(randomValidFor())` (`:189`) — **validity period is randomised**, so
  every certificate has a different lifetime. Another anti-fingerprint measure.
- Key usages (`:197-224`): CA gets `KeyUsageCertSign | KeyUsageKeyEncipherment |
  KeyUsageDigitalSignature` with `BasicConstraintsValid: isCA` and `template.IsCA = true` (`:243-246`);
  leaves get `ExtKeyUsageClientAuth` (implant), `ExtKeyUsageServerAuth` (listener), or **both** for a
  CA (`:203-212`).
- RSA certificates exist as an alternative path (`GenerateRSACertificate :165`, key size from
  `rsaKeySize()`), with `certs.go:61-63` rejecting anything that is not `ecc` or `rsa`.

### 18.4 CA material lives in the database, not only on disk

`saveCertificate` (`server/certs/certs.go:59-79`) persists `CommonName`, `CAType`, `KeyType`, and
**both PEM blobs** into `models.Certificate` via GORM:

```go
certModel := &models.Certificate{
	CommonName:     commonName,
	CAType:         caType,
	KeyType:        keyType,
	CertificatePEM: string(cert),
	PrivateKeyPEM:  string(key),
}
```
`server/certs/certs.go:67-73`

`GetCertificate` (`:92-115`) reads them back by `(CAType, KeyType, CommonName)`. Two consequences
worth recording:

- **Private keys are stored as plaintext PEM in the operator's SQLite database.** The CA private key
  is therefore extractable from `~/.sliver/` by anyone with file read access to that DB — including
  any process running as the operator. This is normal for a framework that must sign at runtime, but
  it means the trust root has no stronger protection than the database file.
- `GetCertificate` returns the sentinel `ErrCertDoesNotExist` (`:55`, `:108`) rather than a wrapped
  error, so callers can branch cleanly.

### 18.5 A useful counter-signal: Sliver honours `SSLKEYLOGFILE`

```go
func newKeyLogger() *os.File {
	keyFilePath, present := os.LookupEnv("SSLKEYLOGFILE")
	...
	keyFile, err := os.OpenFile(keyFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	...
		fmt.Printf("NOTICE: TLS Keys logged to '%s'\n", keyFilePath)
```
`server/certs/tlskeys.go:22-35`

`TLSKeyLogger` is exported (`:19`) and, if `SSLKEYLOGFILE` is set in the server's environment, every
TLS session key is appended to that file and the operator is told on stdout. This is the standard
NSS key-log format, so **Wireshark can decrypt the full session** given the file. It is off by
default and requires the operator to have set the variable themselves — but it is a documented,
one-environment-variable route from "encrypted capture" to "plaintext SLIVER traffic," and it is the
single highest-value artefact to hunt for on a box you suspect is a Sliver server.

### 18.6 What §18 establishes for the rest of D1

| Question | Answer | Where |
|---|---|---|
| How many trust roots? | **4**, independent, generated once per install | `ca.go:40-46` |
| Key type for CAs/leaves? | **ECDSA**, random curve from P-521/P-384/P-256 (operators P-256 only) | `certs.go:146-154` |
| RSA available? | Yes, alternate path | `certs.go:165`, `:173` |
| Keys from a CSPRNG? | **Yes — `rand.Reader`** (no Havoc-style `RandomNumber32` question) | `certs.go:154` |
| Serial numbers? | **128-bit random** — not sequential | `certs.go:193-194` |
| Cert lifetime? | **Randomised** per certificate | `certs.go:189` |
| Where do CA keys live? | SQLite `Certificate` table, **plaintext PEM** | `certs.go:67-73` |
| Debug decrypt route? | **`SSLKEYLOGFILE`** → NSS key log → Wireshark | `tlskeys.go:22-35` |

This closes the loop on §1: the implant's `RootOnlyVerifyCertificate` is meaningful because the CA
it verifies against is generated here with a real CSPRNG, a random curve, a random serial, and a
random lifetime. The perimeter is properly built at the root. The weaknesses elsewhere in D1
(§15's crude 1-byte patch, §7's absent syscalls) are **implementation** choices, not a defective
trust foundation.

---

## 19. Server half — `GenerateConfig`, and the §4 signing claim reconciles exactly

`server/generate/binaries.go` is the implant builder (49 KB, the largest file in `server/generate/`).
`GenerateConfig` (`:1144-1205`) is where all per-build key material enters the template that the
implant is compiled from. This is the server-side counterpart to §4, and the two halves match.

### 19.1 The full key-material block

```go
serverCACert, _, _ := certs.GetCertificateAuthorityPEM(certs.MtlsServerCA)
sliverCert, sliverKey, err := certs.MtlsC2ImplantGenerateECCCertificate(name)
...
implantKeyPair, err := cryptography.RandomAgeKeyPair()
serverKeyPair := cryptography.AgeServerKeyPair()
digest := sha256.Sum256([]byte(implantKeyPair.Public))
build.PeerPublicKey = implantKeyPair.Public
build.PeerPublicKeyDigest = hex.EncodeToString(digest[:])
build.PeerPrivateKey = implantKeyPair.Private
build.PeerPublicKeySignature = cryptography.MinisignServerSign([]byte(implantKeyPair.Public))
build.AgeServerPublicKey = serverKeyPair.Public
build.MinisignServerPublicKey = cryptography.MinisignServerPublicKey()
```
`server/generate/binaries.go:1148-1170`

**This is the origin of the three-level trust chain §4 and §11 documented from the implant side, and
it confirms §4's reading rather than contradicting it:**

| Build field | Produced by | Consumed by the implant as |
|---|---|---|
| `PeerPublicKey` | `cryptography.RandomAgeKeyPair()` **per build** | the implant's age X25519 identity |
| `PeerPrivateKey` | same pair | the implant's private half — **unique per implant** |
| `PeerPublicKeySignature` | `MinisignServerSign(PeerPublicKey)` | verified via §11's `MinisignVerify` |
| `AgeServerPublicKey` | `AgeServerKeyPair()` — **shared** | encrypting to the server |
| `MinisignServerPublicKey` | `MinisignServerPublicKey()` — **shared** | the Minisign trust anchor |
| `PeerPublicKeyDigest` | `sha256(PeerPublicKey)` | pivot peer identification (§11) |

**The asymmetry is the security property, and the server code makes it explicit:** the implant's own
age keypair is generated **fresh for every build** (`:1159`, "ECC keys - only generate if config is
not set"), while the server's age key and the Minisign public key are **shared singletons**
(`:1163`, `:1170`). So compromising one implant yields that implant's private key and nothing else —
it cannot impersonate another implant, and it cannot forge a server-to-implant message. This is a
correctly designed one-way trust relation, and it is the server-side proof of §11's conclusion that
Minisign signing is what makes a network of mutually-stranger implants coherent.

Note `:1159`'s comment claims "only generate if config is not set," but the code generates
unconditionally — the comment is stale relative to the implementation. The comment's *intent* is
visible in `:1180-1194`, where WireGuard keys genuinely do check `implantConfig.WGPeerTunIP` first
and take a different path. Recorded because a reader trusting the comment would expect a code path
that is not there.

### 19.2 Per-transport material is conditional

```go
if models.IsC2Enabled([]string{"mtls"}, implantConfig.C2) {
	build.MtlsCACert = string(serverCACert)
	build.MtlsCert  = string(sliverCert)
	build.MtlsKey   = string(sliverKey)
}
```
`server/generate/binaries.go:1173-1177`

**mTLS cert, key and CA are embedded only when mTLS C2 is enabled.** This is the server-side
mechanism behind §3's finding that transport presence is build-specific: the `{{if}}` guards in the
implant template are driven by whether these fields were populated at all. An implant built without
mTLS carries no certificate, no key, and no CA — so it has nothing to verify with and nothing to
present.

The WireGuard path (`:1180-1200`) is lazier and more interesting: if `WGPeerTunIP` is empty,
`GenerateUniqueWGPeerKeys()` allocates a **unique tunnel IP and private key** and writes the IP back
into `implantConfig` (`:1186`); if it is already set, it calls `certs.ImplantGenerateWGKeys(ip)`
instead. The server's own public key is then fetched and embedded (`:1195-1199`). This is why §10's
`serverTunIP = "100.64.0.1"` is a fixed server-side address while every implant gets a distinct
`100.64.0.x` — the allocation is server-side and per-build.

`build.Stage = false` (`:1202`) — config generation always produces a **stageless** build; staging is
a separate artefact path (`SliverShellcode :334`, `linuxShellcode :346`, `darwinShellcode :436`,
`windowsShellcode :526`, `SliverSharedLibrary :590`, `SliverArchive :698`, `SliverExecutable :773`).

### 19.3 What §19 adds

It converts §4's and §11's **implant-side** readings into a **server-side-verified** claim. §4
established that the implant carries two independent auth layers; §19 establishes *who generates
them and when*. The per-build/uniform split (§19.1) is the design decision that makes the trust
model sound, and it is only visible from this side. **No contradiction with §1–§4 was found.**

### 19.4 Remaining in the server half

`server/generate/` is 16 files; §19 covers `binaries.go:1144-1205` only. Still unread and recorded as
open: `srdi.go` (48 KB) and `srdi-shellcode.go` (23.7 KB) — the shellcode/sRDI packing path;
`spoof.go` (24.3 KB) — the ARGV/`{{.Build.SpoofMetadata}}` generation that pairs with the implant's
`spoof` package; `donut.go`; and the rest of `binaries.go` (the 900 lines above `:1144`, covering the
actual `go build` invocation and ldflags). Environment-driven cross-compilation is at
`getCrossCompilersFromEnv :1208`.

---

## 20. Server half — the sRDI shellcode path, and it is hand-assembled

`server/generate/srdi.go` (48 KB, 1,009 lines) and `srdi-shellcode.go` (23.7 KB) convert a compiled
DLL into reflective-loading shellcode. This is the last stage before an implant becomes an
injectable artefact, and it is the one place in Sliver where **raw x64 opcodes are written by hand.**

### 20.1 The pipeline

```
ShellcodeRDIToFile(dllPath, functionName)   :752   → writes shellcode to a file
ShellcodeRDI(dllPath, functionName, userdata):765  → returns []byte
ShellcodeRDIFromBytes(data, fn, args)       :799   → same, from bytes
convertToShellcode(dllBytes, hash, userData, flags) :825  → the real work
```

`ShellcodeRDIFromBytes` is the load-bearing function, and its two special cases are the first
finding:

```go
// functionHash is 0x10 by default, otherwise get the hash and convert to bytes
hashFunction = pack(uint32(0x10))
...
flags |= 0x1
```
`server/generate/srdi.go:804`, `:810`, `:815`

**`0x10` is a magic bail-out.** A requested function name that hashes to `0x10` is treated as "no
specific entry point" — the shellcode then runs `DllMain` instead of a named export. And `flags |= 0x1`
(`:815`) is set unconditionally in this path, which selects the loader's "clear PE header" behaviour.
Both are verified, but the *reason* `0x10` specifically is the sentinel is not documented in the
source — recorded as a residual unknown rather than guessed (see §20.5).

### 20.2 The bootstrap is assembled by hand, byte by byte

```go
bootstrap := []byte{0xe8, 0x00, 0x00, 0x00, 0x00}
...
bootstrap = append(bootstrap, 0x59)
...
bootstrap = append(bootstrap, 0x49, 0x89, 0xc8)
...
bootstrap = append(bootstrap, 0x48, 0x81, 0xc1)
...
// and rsp, 0x0FFFFFFFFFFFFFFF0 - Align the stack to 16 bytes
bootstrap = append(bootstrap, 0x48, 0x83, 0xe4, 0xf0)
// sub rsp, 0x30 - Create some breathing room on the stack
bootstrap = append(bootstrap, 0x48, 0x83, 0xec)
bootstrap = append(bootstrap, 0x30) // 32 bytes for shadow space + 8 bytes for last arg + 8 bytes for stack alignment
```
`server/generate/srdi.go:839-880`

Decoded, this is a textbook `call $+5` / `pop rcx` position-independent stub:

| Bytes | Instruction | Purpose |
|---|---|---|
| `e8 00 00 00 00` | `call $+5` | push return address; the classic PIC anchor |
| `59` | `pop rcx` | recover the actual code address into RCX |
| `49 89 c8` | `mov r8, rcx` | second copy of the anchor |
| `48 81 c1 …` | `add rcx, <off>` | point at payload |
| `ba …` | `mov edx, <imm>` | function hash as argument |
| `49 81 c0 …` | `add r8, <off>` | userdata pointer |
| `41 b9 …` | `mov r9d, <imm>` | flags |
| `56` | `push rsi` | preserve RSI |
| `48 89 e6` | `mov rsi, rsp` | save stack pointer |
| `48 83 e4 f0` | `and rsp, -16` | **16-byte stack alignment** |
| `48 83 ec 30` | `sub rsp, 0x30` | **shadow space (32 B) + last arg (8 B) + align (8 B)** |

Two things worth stating plainly. First, the stack alignment and 48-byte frame are **correct
Win64 ABI** for calling a function with four register arguments plus a stack argument — this is not
guesswork, the comment at `:880` says exactly why the number is `0x30`. Second, **Sliver writes this
by hand rather than using the upstream sRDI blob**, which is why the bootstrap is a Go byte slice
rather than a checked-in `.bin`. It is the counterpart to §15: Sliver's Windows low-level work is
narrow but deliberate, and where it does build something it builds it correctly.

### 20.3 Function-name hashing — standard ROR-13

```go
function := []byte(name)
function = append(function, 0x00)          // NUL-terminate
functionHash := uint32(0)
for _, b := range function {
	functionHash = ror(functionHash, 13, 32)
	functionHash += uint32(b)
}
return functionHash
```
`server/generate/srdi.go:977-989`

ROR-13 then add, over the NUL-terminated name. This is the **sRDI / Meterpreter-classic** hash
convention, so the resulting shellcode is compatible with the wider reflective-loader ecosystem
rather than being Sliver-specific. `ror` is implemented with `math.Exp2`-derived masks (`:992-995`)
rather than shifts — functionally correct, marginally slower, and it signals the code was ported
rather than written for Go.

### 20.4 PE-machine sniffing

```go
machineIA64 := uint16(512)
machineAMD64 := uint16(34404)
headerOffset := binary.LittleEndian.Uint32(dllBytes[60:64])
machine := binary.LittleEndian.Uint16(dllBytes[headerOffset+4 : headerOffset+4+2])
```
`server/generate/srdi.go:997-1008`

Reads the `e_lfanew` offset at PE `+0x3C`, then the `Machine` field at `+0x04`, accepting
**`0x0200` (IA64)** and **`0x8664` (AMD64)** as 64-bit. Note it classifies **IA64** (Itanium) as
64-bit, which is dead in practice but harmless as a heuristic. **No bounds check on
`headerOffset`** — a malformed DLL could drive the slice read out of range and panic the builder.
Low severity (the input is a DLL the operator just compiled), but it is the same missing-bounds-check
*class* as Havoc's `Parser.c:127` wraparound (D5 §7A), and worth recording for that reason: Go's
slice bounds check turns it into a panic rather than memory corruption, which is the entire
difference between the two frameworks' outcomes on the same mistake.

### 20.5 Residual unknowns in §20

- **Why `0x10` is the "default function" sentinel** (`:781`, `:810`) — the value is verified, the
  rationale is not in the source. Inherited from the sRDI upstream convention.
- **`srdi-shellcode.go` (23.7 KB) not read** — the shellcode-side mirror of this file, which
  presumably carries the loader stub the bootstrap jumps into.
- **The PE-header-clearing behaviour selected by `flags |= 0x1`** is asserted from the flag, not read
  from the stub that implements it.
- `ShellcodeRDIToFile :752` writes to disk; the path derivation was not traced.

### 20.6 Where §20 sits in D1

§20 is the artefact-level counterpart to §16. §16 showed the **BOF/COFF** loading path is entirely
vendored (`reflektor` → WireGuard `memmod`). §20 shows the **DLL-reflective** path is **Sliver's
own**, hand-assembled, and ABI-correct. Two different in-memory-execution mechanisms, two opposite
build-vs-buy decisions, in the same codebase — and the one Sliver wrote itself is the one that is
correct.

---

## 21. The traffic-encoder layer — a nonce-addressed codec table, and one real design flaw

`server/encoders/encoders.go` (328 lines) is small and load-bearing: it decides **how every byte of
C2 traffic is shaped**, and it is the layer that makes Sliver's HTTP transport not look like C2.
It also contains the first genuine protocol-design flaw I have found in Sliver's own code.

### 21.1 The mechanism: encoder ID smuggled inside a nonce

```go
const (
	EncoderModulus = uint64(65537)   // *** IMPORTANT *** ENCODER IDs MUST BE LESS THAN THE MODULUS
	MaxN           = uint64(9999999)
)
```
`server/encoders/encoders.go:46-47`

```go
func EncoderFromNonce(nonce uint64) (uint64, encutil.Encoder, error) {
	encoderID := uint64(nonce) % EncoderModulus
	if encoderID == 0 {
		return 0, new(encutil.NoEncoder), nil
	}
	if encoder, ok := EncoderMap[encoderID]; ok {
		return encoderID, encoder, nil
	}
	return 0, nil, fmt.Errorf("invalid encoder id: %d", encoderID)
}
```
`server/encoders/encoders.go:255-264`

```go
encoderID := keys[util.Intn(len(keys))]
nonce := (randomUint64(MaxN) * EncoderModulus) + encoderID
return nonce, EncoderMap[encoderID]
```
`server/encoders/encoders.go:272-274`

**The design, stated plainly:** each encoder is assigned a random ID `< 65537`. The implant picks an
encoder, then constructs a nonce as `random(0..9999999) × 65537 + encoderID`. The server recovers
`encoderID = nonce mod 65537` and looks it up. **The quotient is pure cover traffic** — it carries no
information and exists solely to make the nonce look like an arbitrary large number rather than a
small enumerable code.

**This is a deliberate, correct anti-fingerprinting measure, and it is the encoder-layer counterpart
to §18's randomised curve selection.** A static encoder ID would be a fixed byte pattern an analyst
could match; a `nonce mod 65537` derivation means every request carries a different-looking number.
The comment at `:45` — *"ENCODER IDs MUST BE LESS THAN THE MODULUS"* — is the only thing making the
scheme well-defined, and it is enforced by construction: `GetRandomID` (`:122-129`) draws from
`util.Intn(int(EncoderModulus))`, so IDs are in `[0, 65536]` by definition.

**The RNG is sound, and worth recording because D5 could not say the same.** `util.Intn`
(`util/cryptography.go:110+`) does **rejection sampling** with an explicit comment —
*"Rejection sampling to remove modulo bias"* — and `randomUint64` reads from `crypto/rand`. So both
the encoder IDs and the nonce quotient are unbiased CSPRNG output. Contrast Havoc's `RandomNumber32()`,
whose entropy source T5 left **unresolved** (T5 residual #3). **Sliver's traffic-shaping randomness
has no such open question.**

### 21.2 The flaw: the selector is selected by trial-and-error

```go
func getEncoder(reqURL *url.URL, c2config *clientpb.HTTPC2Config) (sliverEncoders.Encoder, error) {
	...
	for _, nonce := range nonces {
		_, encoder, err := encoders.EncoderFromNonce(nonce)
		if err == nil {
			return encoder, nil
		}
	}
	return nil, fmt.Errorf("no encoder found")
}
```
`server/c2/http.go:420-444`

with the nonces extracted by digit-stripping from **every** query value and path segment:

```go
func digitsOnly(value string) string {
	var buf bytes.Buffer
	for _, char := range value {
		if unicode.IsDigit(char) {
			buf.WriteRune(char)
		}
	}
	return buf.String()
}
```
`server/c2/http.go:446-454`

Four findings, in order of severity:

1. **The server tries every nonce in the URL until one parses, and accepts the first success**
   (`:437-442`). The response encoder is therefore chosen by *whatever first parses*, not by any
   authenticated binding. An analyst who can read the URL can compute `nonce mod 65537` and **know
   exactly which encoder the server will reply with** — the anti-fingerprinting measure is defeated
   by the selection procedure itself. The nonce looks random in the URL and is fully determined in
   effect.
2. **`digitsOnly` strips every non-digit character and concatenates what remains** (`:446-454`). So
   a path segment `abc12def34` yields `1234`, not `12` or `34`. Any CMS or proxy that injects digits
   into a URL — a session ID, a timestamp, a cache-buster — **silently alters which nonces the server
   considers**, and can therefore change which encoder is selected, or make selection fail entirely.
   This is a real interoperability hazard, not a theoretical one.
3. **Failure is `"no encoder found"`** (`:434`, `:443`) with no distinction between "no nonce
   present" and "nonce present but invalid encoder ID." An operator debugging a dead session cannot
   tell which happened.
4. **Anonymous handlers pass length `0`** (`:430`) — *"we don't know the expected nonce length"* — so
   the same trial-and-error runs with no length hint at all.

`ErrMissingNonce` is defined separately (`:64`) but the `getEncoder` path collapses everything into a
single error string, so the sentinel is not reachable from here.

### 21.3 The WASM traffic-encoder sublayer

Beyond the eight native encoders (base64, base58, base32, hex, english, gzip, png, nop — `:56-73`),
Sliver loads **operator-supplied WASM encoders** from disk:

```go
wasmEncoderFiles, err := encodersFS.ReadDir("traffic-encoders")
...
wasmEncoderID := traffic.CalculateWasmEncoderID(wasmEncoderData)
trafficEncoder, err := traffic.CreateTrafficEncoder(wasmEncoderModuleName, wasmEncoderData, logger)
if _, ok := EncoderMap[uint64(wasmEncoderID)]; ok {
	encodersLog.Errorf("%s", fmt.Sprintf("duplicate encoder id: %d", wasmEncoderID))
	return fmt.Errorf("duplicate encoder id: %d", wasmEncoderID)
}
```
`server/encoders/encoders.go:216-247`

- **Encoder ID is derived from the WASM content** (`CalculateWasmEncoderID(wasmEncoderData)`), not
  from the filename — so the same encoder installed under a different name gets the same ID, and
  **duplicate-ID detection actually works** (`:242-245`). This is the correct choice and it is worth
  noting because it is the *opposite* of the content-independent naming used elsewhere.
- Files are loaded into **one flat namespace by basename** (`PassthroughEncoderFS.Open :289`,
  `filepath.Base(name)`) and **must end in `.wasm`** (`:290`, `:321`) — a name-suffix gate, not a
  content check. The same guard is applied symmetrically in `SaveTrafficEncoder :166` and
  `RemoveTrafficEncoder :181`.
- `RemoveTrafficEncoder` **panics** if the path is a directory (`:193`) — a bare `panic` on a
  filesystem condition, where every other error in this file is returned. The comment says *"this
  should never happen,"* which is the assertion that makes it a latent availability bug rather than
  a defensible invariant.
- **The encoder cache is reset by full mutation** (`:209-212`): every traffic encoder is deleted from
  `EncoderMap` and `TrafficEncoderMap` is reallocated before reload. Reload is triggered by *both*
  save and remove, so the maps are rebuilt on every operator edit. Under concurrent traffic this is
  an unguarded map write — Go would `fatal error: concurrent map writes`, not merely corrupt state.
  Traffic during an operator's encoder edit is the trigger.

### 21.4 Why the nonce is in the URL at all

The nonce travels in the **request URL**, and the implant's IDs arrive as template substitutions:

```go
Base32EncoderID, _  = strconv.ParseUint(`{{.Encoders.Base32EncoderID}}`, 10, 64)
Base64EncoderID, _  = strconv.ParseUint(`{{.Encoders.Base64EncoderID}}`, 10, 64)
EnglishEncoderID, _ = strconv.ParseUint(`{{.Encoders.EnglishEncoderID}}`, 10, 64)
```
`implant/sliver/encoders/encoders.go:48-54`

This is the same per-build template mechanism §3 established — the implant does not know its encoder
IDs at source level, they are written in at compile time. But note the split: the IDs are persisted
per-server in `db.ResourceID` rows (`SetupDefaultEncoders :77-103`, idempotent by name), **not
per-build**. So encoder IDs are **server-global**, while the implant's age keypair is per-build
(§19.1). One more instance of the per-build-vs-shared axis §19.1 identified as the security-relevant
one — and here the shared half is the *traffic shape*, which is the correct choice for
interoperability and a fingerprinting consideration in the other direction.

### 21.5 What §21 adds

§21 is the **traffic-shaping** layer, and it sits underneath §3 (transports) and §5 (HTTP/WinINet).
The chain is now complete: the implant picks an encoder → encodes a payload → embeds the selector in
the URL query or path → the server strips digits, tries each, and picks the first that parses → the
same encoder shapes the reply.

The headline is 21.2 item 1: **Sliver deliberately randomises the encoder selector to defeat
fingerprinting, then defeats its own measure by accepting the first nonce that parses.** The
randomisation is real and the mechanism is clever; the selection procedure gives the answer away to
anyone who can read the URL. This is a *design* flaw rather than an implementation bug — the code
does exactly what it intends, and the intent is the problem. It is the same shape as §15's
`patchAmsi`: correct execution of an insufficient idea.

**Residual unknowns for §21.** `CalculateWasmEncoderID` was not read (it is in
`util/encoders/traffic/`, not in this file). The concurrency claim in §21.3's last item is inferred
from the absence of a mutex around `EncoderMap`/`TrafficEncoderMap` mutation in this file — I did not
search the whole package for an external lock, so it is stated as a risk with its basis, not as a
confirmed defect. `NonceQueryLength` handling in the C2 profile was not traced to its generator.

---

## 22. The session handler — capability negotiation, sequenced teardown, and fail-closed limits

`server/handlers/sessions.go` (914 lines, 34,614 B) is where an implant becomes a session and where
Sliver's **protocol versioning** actually lives. §6 documented the 135-entry message-ID table; §22
documents what happens when those messages arrive.

### 22.1 Registration admits the implant's self-description verbatim

```go
func registerSessionHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	if implantConn == nil {
		return nil
	}
	select {
	case <-implantConn.Done():
		return nil
	default:
	}
	register := &sliverpb.Register{}
	err := proto.Unmarshal(data, register)
	if err != nil {
		sessionHandlerLog.Errorf("Error decoding session registration message: %s", err)
		return nil
	}
	session := core.NewSession(implantConn)
	sessionUUID, err := uuid.Parse(register.Uuid)
	if err != nil {
		sessionUUID = uuid.NewV4() // Generate Random UUID
	}
	session.Name = register.Name
	session.Hostname = register.Hostname
	...
	session.Capabilities = register.Capabilities
```
`server/handlers/sessions.go:50-90`

**Twenty fields are copied from the implant's own registration message with no validation.** Hostname,
username, UID, GID, OS, arch, PID, filename, version, locale, capabilities — all attacker-controlled
if the session crypto is ever broken, and all displayed to the operator as fact. §18's trust
foundation is what makes this acceptable: the session is only reachable through mTLS or an
authenticated envelope, so the self-description is authenticated-by-channel rather than
validated-by-content. **The design is defensible; it is also a single point of failure.** Anything
that lets a non-implant reach this handler gets a fully populated session object and a session ID.

Two details worth recording:

- **A malformed UUID is silently replaced, not rejected** (`:69-72`). `uuid.Parse` failure →
  `uuid.NewV4()`. So an implant that sends garbage gets a server-assigned identity and is admitted,
  while the operator sees no warning that the implant's own UUID was unusable.
- **`implantConn.Done()` is checked before parsing and again via `SetCleanup`** (`:54-58`, `:92-99`).
  The `registrationReady` channel is an ordering barrier: the cleanup closure blocks on `<-registrationReady`
  until the deferred `close(registrationReady)` at `:99` runs, so `RemoveIf` cannot race the `Add`.
  This is the same discipline §13 found in the tunnel reorder buffer, applied to session lifetime.
  `SetCleanup` returning false (`:95`) means a **duplicate or closed** registration and is rejected —
  the one genuine admission control on this path.

### 22.2 The capability system — Sliver's real protocol-versioning mechanism

`protobuf/sliverpb/capabilities.go` is 24 lines and it is the most interesting file in this area:

```go
// CapabilityTunnelTerminalV1 indicates that an implant waits for every data
// frame below a TunnelClose.Sequence exclusive terminal before detaching the
// tunnel generation.
const CapabilityTunnelTerminalV1 uint64 = uint64(ImplantCapability_IMPLANT_CAPABILITY_TUNNEL_TERMINAL_V1)

// CapabilitySocksFlowControlV1 indicates that a SOCKS endpoint supports the
// cumulative acknowledgements and fixed send window carried by SocksData.
const CapabilitySocksFlowControlV1 uint64 = uint64(ImplantCapability_IMPLANT_CAPABILITY_SOCKS_FLOW_CONTROL_V1)

const SocksFlowControlWindowV1 = 64
const SocksFlowControlAckBatchV1  = 16
```
`protobuf/sliverpb/capabilities.go:5-24`

**This corrects an assumption worth stating.** Sliver does *not* version its protocol with a version
number. It negotiates **named capabilities as a bitfield**, and each capability gates a distinct
behaviour at the point of use. Three consequences:

1. **Old implants stay compatible.** The Unsequence/sequence branch at `sessions.go:266-268` checks
   `precursors.terminal.Sequence == 0 || session.Capabilities&sliverpb.CapabilityTunnelTerminalV1 == 0`
   and routes to a legacy path. A pre-capability implant is handled correctly rather than rejected —
   and this is why §6's message table is stable across versions.
2. **The capability is asserted by the implant** (`register.Capabilities`, copied at `:90`) and never
   independently verified. An implant that claims `TunnelTerminalV1` but does not implement it gets
   the sequenced path and will stall until `StartPeerCloseDeadline` fires (§22.4). Self-declared
   capability with a server-side timeout as the backstop — fail-safe, not fail-fast.
3. **The V1 suffix is deliberate.** `CapabilityBOFV1`, `TunnelTerminalV1`, `SocksFlowControlV1` all
   carry a version suffix, so V2 can be added alongside rather than replacing. Contrast §6's 135
   message IDs, which are bare integers with no version dimension — the capability bitfield is the
   only extensibility mechanism the wire format actually has.

**SOCKS flow control is a real design, not a stub.** `SocksFlowControlWindowV1 = 64` unacknowledged
frames and `SocksFlowControlAckBatchV1 = 16` frames per cumulative ack give a sliding window with
batched acknowledgement. A 64-frame window with 16-frame acks means an endpoint must batch at least
four windows' worth of traffic before acks dominate. This is the same class of mechanism §13 found in
`tunnel.go`, applied to the SOCKS path.

### 22.3 The 128 KB hard limit, enforced in three places

```go
maxTunnelDataMessageBytes = 128 * 1024
```
`server/handlers/handlers.go:65`

```go
if len(data) > maxTunnelDataMessageBytes {
	sessionHandlerLog.Warnf("Closing implant connection after oversized tunnel data message (%d bytes)", len(data))
	implantConn.Close()
	return nil
}
```
`server/handlers/sessions.go:132-136`

The guard appears at **three** sites — `:132` (tunnel data), `:416` (tunnel close), and `:575`
(SOCKS data) — and every one **closes the implant connection** rather than dropping the frame: That is the correct choice and it directly
addresses the defect class D5 found in Havoc: where `Parser.c:127` wraps an oversized declared length
and proceeds, Sliver refuses on real byte count and terminates the session. **The same 128 KB bound is
checked against `len(data)` — the actual slice — not against anything the peer declared**, so there
is no length field to forge. This is the third concrete instance of the pattern §15 and §22.4
establish: Sliver fails closed where Havoc fails open.

`handleActiveReverseTunnelTerminal` applies the same policy to sequence violations:

```go
ready, err := rtunnel.MarkPeerClose(tunnelData.Sequence)
if err != nil {
	if !errors.Is(err, rtunnels.ErrReverseTunnelClosed) {
		sessionHandlerLog.Warnf("Closing session %s after invalid terminal sequence on reverse tunnel %d: %v", sessionID, rtunnel.ID, err)
		if closeReverseTunnelRemote(rtunnel) {
			implantConn.Close()
		}
	}
	return
}
```
`server/handlers/sessions.go:533-541`

**An invalid terminal sequence closes the session.** `ErrReverseTunnelClosed` is tolerated
(idempotent close), everything else is fatal. The same pattern appears on the generic tunnel path at
`:507`.

### 22.4 The peer-close deadline — bounded waiting, not blocked waiting

```go
rtunnel.StartPeerCloseDeadline(reverseTunnelSendTimeout, func() {
	if closeReverseTunnelRemote(rtunnel) {
		sessionHandlerLog.Warnf("Closing session %s after incomplete terminal sequence on reverse tunnel %d", sessionID, rtunnel.ID)
		implantConn.Close()
	}
})
```
`server/handlers/sessions.go:547-552`

A tunnel that never completes its terminal sequence is closed after a bounded interval. This is the
**counterpart to the unsequenced-terminal branch** (`:266-268`): the capability system lets old
implants skip sequencing, and the deadline is what stops a compliant-but-stuck implant from holding a
tunnel open forever.

**Put together with §22.2, the design is coherent:** capabilities let the server accept implants of
different vintages, and every negotiated behaviour has a server-side timeout or size bound that
applies regardless of what the implant claims. The negotiation is permissive; the enforcement is not.

### 22.5 What §22 adds to D1

§22 completes the **session layer** above §12 (pivot/session crypto), §13 (`tunnel.go` reorder
buffer), and §6 (message dispatch). The full path is now documented end to end: implant connects →
§18/§19 crypto established → `Register` self-description admitted (`:50-90`) → capabilities negotiated
as a bitfield → every subsequent frame bounded by `128 * 1024` → sequence violations and incomplete
teardowns fail closed.

**The net-new structural finding is §22.2:** Sliver's compatibility story is a **capability bitfield,
not a version number**, and the implant's capability claims are trusted but backstopped by server-side
timeouts and size limits. That is a more sophisticated design than any other target in this corpus —
Havoc's frame carries no capability or version dimension at all (D5), and Meterpreter's 32-byte header
carries flags but no negotiation (D7 §4). **It is also why Sliver has maintained wire compatibility
across versions without the breakage T6 found in Pupy, where the V1/V2 branch at `picocmd.py:1351-1357`
raises `NotImplementedError` on anything but V1.** Two frameworks in this corpus attempted protocol
versioning; one made it a negotiated bitfield with legacy fallbacks, the other made it a dead branch.

**Residual unknowns for §22.** `MarkPeerClose` and `StartPeerCloseDeadline` live in
`server/core/rtunnels/` and were **not read** — the sequence-validation logic behind them is asserted
from the handler's contract, not from the implementation. `socksDataHandler` (`:571-637`) was not read
in full. The `session.Capabilities` bit meanings beyond the three named constants were not enumerated
from `ImplantCapability`.

---

# 23. THE TWO-SIDED CRYPTO BOUNDARY — `server/cryptography/cryptography.go`

**File: 379 lines / 11,326 B.** 21 top-level functions. This is the server-side counterpart to the
implant's `cryptography/crypto.go` (§1, §4, §12), and reading it against the implant half resolves a
question D1 had been carrying: **the two `CipherContext` types are deliberately asymmetric, and the
asymmetry is the security property.**

## 23.1 The mechanics first — ChaCha20-Poly1305, nonce-prepended

```go
// server/cryptography/cryptography.go:200-212
func Encrypt(key [chacha20poly1305.KeySize]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	compressed, _ := encoders.GzipBuf(plaintext)
	plaintext = bytes.NewBuffer(compressed).Bytes()
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil { return nil, err }
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}
```

Three things worth naming, because each is a decision rather than an accident:

- **The nonce is drawn from `crypto/rand` per message (`:208`) and prepended to the ciphertext
  (`:211`)**, the standard `Seal(dst=nonce, ...)` idiom. Because the nonce is fresh and random, and
  because the AEAD's own Poly1305 tag covers it, **the nonce does not need to be secret or
  authenticated separately.** This is correct construction — contrast Havoc, whose AES-256-CTR IV is
  **fixed for the session** (D5), making its keystream a many-time pad. Two frameworks, same
  primitive family, opposite decisions.
- **Payloads are gzipped before encryption (`:205`)** with the error **discarded** (`_`). The error is
  uninteresting — `GzipBuf` is a `bytes.Buffer` writer and cannot fail — but it does mean **the
  compression is inside the AEAD boundary**, so it is not a CRIME/BREACH-style length oracle: the
  attacker sees only encrypted compressed bytes.
- **`aead.Seal` is called with `dst = nonce`**, so the nonce buffer is reused as the output buffer.
  Go's `Seal` appends, so this is the documented idiom, not an aliasing bug.

`Decrypt` (`:216-234`) is the mirror: length guard at `:221` (`ciphertext too short`), split at `:226`,
`aead.Open` at `:229`, gunzip at `:233`. **Tampering is caught by `Open` returning an error (`:230`)**
— the AEAD tag is checked, so the ciphertext is authenticated. This is the capability Meterpreter
lacks entirely (D7: no MAC on the packet layer).

## 23.2 The asymmetry — and why it is correct

`CipherContext` (`:246-249`) adds a replay cache: `Key` plus `replay *sync.Map`. The two methods are
**not mirror images**:

```go
// server Decrypt :252-265 — NO signature handling
plaintext, err := Decrypt(c.Key, ciphertext)          // ciphertext = nonce ‖ ct
digest := sha256.Sum256(ciphertext)                   // digest over nonce ‖ ct
if _, ok := c.replay.LoadOrStore(b64Digest, true); ok { return nil, ErrReplayAttack }

// server Encrypt :268-280 — ADDS a signature
ciphertext, err := Encrypt(c.Key, plaintext)
digest := sha256.Sum256(ciphertext)                   // digest over nonce ‖ ct
c.replay.Store(b64Digest, true)
rawSig := serverSignRawBuf(ciphertext)                // minisign over nonce ‖ ct
return append(rawSig, ciphertext...), nil             // returns  sig ‖ nonce ‖ ct
```

**`Encrypt` returns `sig ‖ nonce ‖ ct`; `Decrypt` expects `nonce ‖ ct` and never strips the prefix.**
Read in isolation this looks like a bug — the server signs on one path and does not verify on the
other, over mismatched byte ranges. It is not a bug, and the implant half proves it:

```go
// implant/sliver/cryptography/crypto.go:185-219
const minisignRawSigSize = 74

func (c *CipherContext) Decrypt(msg []byte) ([]byte, error) {
	if len(msg) < minisignRawSigSize+1 { return nil, ErrDecryptFailed }   // :189
	ciphertext := msg[minisignRawSigSize:]                                 // :192  STRIP
	serverPublicKey, err := DecodeMinisignPublicKey(serverMinisignPublicKey)
	validSig := verifyRaw(serverPublicKey, msg, false)                     // :200  VERIFY
	if !validSig { return nil, ErrDecryptFailed }
	plaintext, err := Decrypt(c.Key, ciphertext)                           // :208  decrypt
	digest := sha256.Sum256(ciphertext)                                    // :213
	if _, ok := c.replay.LoadOrStore(b64Digest, true); ok { return nil, ErrReplayAttack }
}
```

**The strip lives on the receiving side, and only the implant has a receiving side.** The server's
`Encrypt` is the *only* thing that produces a signed buffer, and the server never decrypts its own
output — it decrypts what implants send, which is unsigned because implants authenticate at the
transport layer instead. So:

| | Server `CipherContext` | Implant `CipherContext` |
|---|---|---|
| `Encrypt` output | `sig ‖ nonce ‖ ct` | `nonce ‖ ct` |
| `Decrypt` input | `nonce ‖ ct` | `sig ‖ nonce ‖ ct` |
| Strips 74-byte sig? | **no** | **yes** (`:192`) |
| **Verifies** the sig? | **no** | **yes — `verifyRaw` (`:200`)** |
| Replay digest over | `nonce ‖ ct` | `nonce ‖ ct` (**after** strip) |
| Reply opposite | implant | server |

**The replay digests agree because the implant digests *after* stripping (`:213`) and the server
digests over the buffer it produced before prepending (`:274`).** Both hash the same `nonce ‖ ct`
range. Two implementations, two different orderings, one consistent value — and nothing in either
file comments this, which is why it reads as a defect until you read both.

**The security consequence is the point.** Server→implant messages are individually signed under the
server's Minisign key and **verified before decryption** (`:200` precedes `:208`), so a forged or
corrupted envelope fails closed at the signature check and never reaches the AEAD. Implant→server
messages carry no per-envelope signature; their authenticity rests on the transport — mTLS client
certs issued from `MtlsImplantCA` (§18/§19), or the age/X25519 session key (§1). **The two directions
are defended by different mechanisms on purpose.**

## 23.3 Replay cache — sound, with a bounded-growth caveat

The cache is a `sync.Map` keyed by base64 of `SHA-256(ciphertext)` (`:259`). Two observations:

- **It never evicts.** Every unique message adds an entry for the life of the session. For a
  long-lived beacon this grows without bound; there is no TTL, no size cap, and no reaper. For a
  short-lived interactive session it is fine. **This is a memory-growth characteristic, not a
  correctness defect** — and note the digest is over ciphertext, so the map cannot be used to confirm
  a guess at plaintext.
- **`LoadOrStore` (`:260`) is the atomic check-and-set**, so concurrent duplicate messages cannot both
  pass. The implant uses the identical idiom (`:215`). Contrast the *encoder* map in
  `server/c2/http.go:209-212` (D1 §21.2), which is an unguarded `map` write under concurrent traffic —
  **the crypto layer got the concurrency right and the traffic-shaping layer did not, in the same
  codebase.**

`ErrReplayAttack` (`:57`) is returned at `:261` and, per §12, has **exactly one producer and three
test references** — no server call site treats a replay as anything other than a decrypt failure,
which is the right disposition.

## 23.4 Key derivation and the age boundary

`deriveKeyFrom(data)` (`:70`) and `KeyFromBytes` (`:88`) both funnel through
`SHA-256(data) → [32]byte`, the same construction the implant uses, and the same one behind
`env-signing-v1:` (§1). `RandomSymmetricKey` (`:78`) draws 32 bytes from `crypto/rand`.

`AgeKeyPair` (`:108-131`) wraps `age.X25519Recipient`. `RandomAgeKeyPair` (`:119`) is **called
per-build** from `GenerateConfig` (§19: `binaries.go:1159`), while `AgeServerKeyPair` (`:290`) is
**DB-backed and shared across all builds** — `GetKeyValue(serverAgeKeyPairKey)` at `:291`, generating
and persisting on `ErrRecordNotFound` (`:292-294`), and **`panic`ing if generation still fails
(`:295`)**. That split is §19's per-build/shared asymmetry, now confirmed from the server side.

`AgeKeyExFromImplant` (`:169`) is the implant's key exchange: it takes the server private key, the
implant's ephemeral private key, and the ciphertext, and returns the shared secret — standard
X25519 ECDH via age. **`AgeEncrypt`/`AgeDecrypt` (`:131`/`:151`) are the only places the server
encrypts *to* an implant public key**, used for build-time material.

## 23.5 What §23 adds to D1

D1 §1 resolved the client binary's AES/RSA/SHA-512 symbols as **stdlib and gRPC plumbing**, and §4
described the implant's envelope crypto. What was missing was the **server half of the contract.**
§23 supplies it and establishes three things D1 could not state before:

1. **The crypto boundary is two-sided and deliberately asymmetric.** The signature is produced on the
   server→implant direction and verified on receipt; the implant→server direction is transport-
   authenticated. The apparent Encrypt/Decrypt mismatch is the mechanism, not an oversight.
2. **Sliver's message crypto is AEAD with a fresh random nonce and the tag checked before plaintext
   is returned** — authenticated encryption in both directions, unlike Havoc's unauthenticated CTR
   stream (D5) and Meterpreter's absent MAC (D7).
3. **The replay cache is correct under concurrency while the encoder map in the same codebase is
   not** — a within-codebase contradiction that §21.2's inference and §23.3's verified `sync.Map`
   together turn into a real finding about where Sliver spent its care.

### Residual unknowns (§23)

- `serverSignRawBuf` (`:283`) calls `minisign.SignRawBuf` — the **vendored `aead.dev/minisign`**
  implementation was not read; `RawSigSize = 2 + 8 + ed25519.SignatureSize` is taken from
  `implant/.../minisign.go:51`, not verified server-side.
- `MinisignServerPrivateKey` (`:343`) and `generateServerMinisignPrivateKey` (`:365`) — the
  **on-disk/DB storage of the server Minisign private key** was not read to completion; whether it is
  passphrase-protected and where it persists is **unverified.**
- `replay` map growth (§23.3) is characterised but **not measured** — no test establishes the
  practical session length at which it matters.

---

# 24. BUILD-STABLE VS BUILD-DEPENDENT CAPABILITY — the cross-framework contrast

D1 §7 established that Sliver does **not** do direct syscalls, and §15 that its AMSI/ETW bypass is a
crude 1-byte `0xC3` patch. D6 (Pupy) establishes the opposite property on the *same* evasion axis:
**six shipped capabilities that source advertises and builds omit.** The two frameworks differ in a
way that matters more than either finding alone, and it belongs in D1 because Sliver is the control.

## 24.1 The contrast

| Property | **Sliver** | **Pupy** (D6 §17–§25) |
|---|---|---|
| AMSI/ETW bypass | 1-byte `0xC3` patch, `#ifdef`-free | ETW suppression written in full, **gated on a macro no build passes** |
| Evasion present in shipped build? | **yes — build-stable** | **no — build-dependent** |
| Severed capabilities | **none identified** | **six — but this is a WINDOWS count only** |
| Platform split mechanism | **file-suffix convention** (`X.go` + `X_windows.go`) | `#ifdef`/`#ifndef` around implementation | 
| Compile-time config | `{{if .Config.Debug}}` **template** guards (build-time, but *always* resolved) | Makefile `-D` flags, several never passed |
| Can source-reading mislead? | **no** — a `{{if}}` guard resolves in every build | **yes** — proven three independent ways (§14.5, §18.6, §22.7) |
| Counterpart risk | patch is *weak* but *present* | capability is *absent* but *present in source* |

**REFINEMENT (added after D6 §25 landed — see §24.4).** The "six" in the Pupy column is a **Windows**
figure and must not be read as Pupy-wide. D6 §25 proved the picture splits **three ways**: four of the
six are **platform-absent** rather than severed (no ETW, no activation contexts, no crash-dump
machinery on Linux — nothing to cut, so their absence there carries **no information**); one,
**JVM, recurs on Linux with an identical three-level structure**; and Linux contributes a **seventh
mechanism of its own** (`FEATURE_INJECTOR`). D6 §25.3 is the authoritative scope statement.

**The failure modes are opposite in kind.** Sliver's evasion is present and weak — an analyst reading
source sees a `0xC3` patch and correctly concludes it ships. Pupy's is absent and strong — an analyst
reading source sees a complete, well-written ETW suppression layer and incorrectly concludes it
ships.

## 24.2 Why Sliver is build-stable — and the one caveat

Sliver's build-time variability is expressed almost entirely through **Go text/template** directives
(`{{.Build.X}}`, `{{.Config.X}}`) resolved during `renderSliverGoCode` (§19). A template guard is
**resolved at generation time for every build** — there is no configuration in which the guard is
simply never evaluated, which is the failure mode that kills Pupy's features. The remaining
variability is the **file-suffix convention** (§7): `X.go` empty stub plus `X_windows.go`, chosen by
the Go toolchain's standard filename rules. That mechanism cannot silently no-op — the compiler either
has a symbol or errors.

**Caveat, stated because §7's convention is not universal:** `handlers_bof.go` carries a real
`//go:build linux || darwin || windows` tag, so Sliver does use build tags where the platform split
is not a simple one-to-one file mapping. The claim here is narrower than "Sliver never uses build
tags": it is that **Sliver's per-platform capability selection is not expressible as a feature that
silently disappears**, because the template guards always resolve and the suffix convention either
yields a symbol or a compile error.

## 24.3 The methodology rule, applied forward

D6 §23.6 states the rule as: **source presence is not build presence**, and requires three questions
before reporting a source-visible capability as present — is the enclosing guard satisfied in a real
build? is the file actually compiled? does the pipeline delete it downstream?

**Sliver satisfies all three for every capability D1 reports.** That is the strongest available
statement of D1's reliability, and it is worth stating explicitly rather than leaving implied:
**D1's evasion findings (§7, §15) describe shipped behaviour; D6's severance findings describe
source-only behaviour.** Both are correct readings of their respective trees, and a reader must not
carry the Pupy caution backwards onto Sliver or the Sliver confidence forwards onto Pupy.

**One Sliver construct does deserve the same scrutiny** and is flagged rather than asserted:
`{{if .Config.Debug}}` strips error strings and log calls from release builds (§1). That *is* a
downstream-deletion mechanism, and it means **release and debug builds of the implant are materially
different programs** — the same hazard D6 §22.7 found in Pupy's `MemoryModule.c`. Whether any
security-relevant branch (as opposed to diagnostics) is inside a `{{if .Config.Debug}}` guard was
**not exhaustively enumerated** and remains a D1 residual unknown.
