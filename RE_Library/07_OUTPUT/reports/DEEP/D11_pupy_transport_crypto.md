# D11 PART B — Pupy transport crypto: the stack, the selector, and three byte orders in one product

**Target:** `RE_Library/01_SOURCE_c2/pupy/pupy/network/`
**Gap closed:** D6 established ECPV's multi-curve perimeter and the credvault KDF. **The transport stack itself was never closed** — which transport runs, how it is chosen, and whether ECPV is reachable at all.
**Method:** source-only. No REA/Ghidra. Every count enumerated. Every absence carries a positive control. Inference marked `[inference]`.
**Path note:** the corpus root is `pupy\pupy\network\` — **single `pupy`, not doubled.** Confirmed by positive control after two empty probes (§9.1).

---

## HEADLINE

**Four answers, and two of them correct the brief.**

1. **§2 — The DEFAULT transport is `ssl`, and the selector is an argparse default.** Not a registry constant: `bind.py:34` declares `default="ssl"`, `base_launcher.py:73-74` copies it into `_default_transport`, and `:81` resolves `self._transport or self._default_transport`. The 13-package `transports/` tree is **auto-discovered** (`conf.py:51` `pkgutil.iter_modules`) but **carries no default**.
2. **§4 — `rsa_aes.py` is REAL RSA and REAL AES**, not a wrapper over something weaker: RSA-OAEP-wrap of a fresh 32-byte AES key (`:204`, `:207`), genuine AES-CBC (`cryptoutils/aes.py:68`). **But its own docstring calls it an XOR transport (`:12`), and the pre-auth RSA decrypt path is a decryption oracle (§4.3).**
3. **§3 — The endianness finding is confirmed and is larger than stated.** There are **three** byte orders, not two: **ec4 native (`'H'`), ecm explicit-little (`'<HH'`), picocmd explicit-big (`'>'`, with three `<` exceptions).** The boundary is a framing-layer seam (§3.4).
4. **§5 — ECPV IS reachable, from two transports — but NOT with the default curve.** `ec4.py:38`, `:44` and `ecm.py` all pass **`curve='brainpoolP384r1'` with `SHA384`**. **The P160R1/SHA1 default at `ecpv.py:65-68` is dead code in the transport path.** D6's primitive finding is correct and **does not describe what ships.**

**The synthesis:** Pupy's transport layer is **stronger at the crypto primitive layer and weaker at the framing layer** than its reputation suggests. The default transport is real mutual-TLS with certificate role-binding (§2.3); the weakest-looking transports (`ec4`, `ecm`) use a real 384-bit EC KEX. **The defects are in hand-rolled framing, documentation, and one oracle — not in the primitives.**

---

## TABLE OF CONTENTS

- §1 The two transport trees and why one is empty
- §2 Q1 — the DEFAULT transport and the selection mechanism
- §3 Q3 — three byte orders, and the boundary where order flips
- §4 Q2 — `rsa_aes.py`: real crypto, an XOR docstring, and an oracle
- §5 Q4 — is ECPV reachable, and with which curve
- §6 The transport inventory, enumerated
- §7 `obfs3` — a fourth crypto system (`UniformDH` + AES-CTR), chained under RSA/AES
- §8 Cross-framework contrast
- §9 Residual unknowns, corrections, and honest coverage

---

## 1. The two transport trees, and why one is empty

**There are two directories named `transports`, and only one holds logic.**

| Tree | Path | Contents |
|---|---|---|
| **Registry** | `network/transports/` | **13 packages**, each `conf.py` + **0-byte `__init__.py`** |
| **Implementation** | `network/lib/transports/` | `rsa_aes.py` 9,625 B, `websocket.py` 15,851 B, `http.py` 13,851 B, `httpwrap.py` 7,413 B, `ecm.py` 5,657 B, `ec4.py` 3,437 B, `dummy.py` 730 B, `utils.py` 528 B + `cryptoutils/`, `obfs3/`, `obfscommon/` |

`[source: enumerated — `network/transports/**` and `network/lib/transports/**`]`

**The structure is a registration/implementation split.** Each package under `network/transports/` is a **conf-only shell**: a `conf.py` declaring a `TransportConf` class, and a **0-byte `__init__.py`**. The actual transport behaviour lives in `lib/transports/<name>.py` and is referenced by the conf's `client`/`server`/`stream` attributes.
`[source: network/transports/*/__init__.py — all 0 B, enumerated; network/transports/ssl/conf.py:113-128]`

**Two packages have no matching `lib/transports/` module** and are therefore of a different kind: `tcp_cleartext` (818 B conf) and `udp_cleartext` (840 B) — trivial wrappers with no crypto module needed. **`dfws`, `kc4`, `rc4`-family and `ssl_rsa` reference modules that do exist as the shared `lib/transports/` files.** `[source: enumerated cross-reference of the two trees]`

---

## 2. Q1 — the DEFAULT transport, and the mechanism that selects it

### 2.1 The registry carries no default — verified by reading the selector in full

`network/conf.py` (**80 lines, read in full**) builds the transport registry:

```python
# network/conf.py:50-52
def load_network_modules():
    for loader, module_name, is_pkg in pkgutil.iter_modules(trlib.__path__):
        add_transport(module_name)
```

`add_transport` (`:26-47`) imports `pupy.network.transports.<name>.conf`, requires a `TransportConf` attribute, and registers it under `t.name` (`:39-43`). **There is no `DEFAULT_TRANSPORT`, no ordering, and no preference anywhere in this file.** Empirically: **`default` appears zero times in `conf.py`.** `[source: network/conf.py:22, :26-47, :50-52 — read in full, 80 lines]`

**A transport that fails to import is silently disabled, not fatal** — `:46-47` `except Exception as e: logging.exception('Transport disabled: %s: %s', module_name, e)`. **Consequence: a broken transport vanishes from the registry with a log line and no failure**, which means the *available* transport set is environment-dependent at runtime. `[source: network/conf.py:35-47]`

### 2.2 The default is an argparse default — the actual selector

```python
# lib/base_launcher.py:69-81
def parse_args(self, args):
    if not self.args:
        self.args = self.arg_parser.parse_args(args)
    if hasattr(self.args, 'transport'):
        self.set_default_transport(self.args.transport)     # :74
def set_default_transport(self, transport):
    self._default_transport = transport                    # :77
@property
def transport(self):
    return self._transport or self._default_transport      # :81
```

**And the argument is declared with a literal default:**

```python
# lib/launchers/bind.py:34
cls.arg_parser.add_argument('-t', '--transport', choices=transports, default="ssl", help="...")
```

**Answer: the DEFAULT transport is `ssl`.** The mechanism is a **two-level resolution** — an argparse `default="ssl"` supplying `_default_transport`, overridden per-connection by `_transport` when `set_connection_info(..., transport=...)` is called (`:83-88`). **`choices=transports` means the registry constrains the input**, so the auto-discovery in §2.1 supplies the valid set while the argparse default supplies the choice. `[source: lib/base_launcher.py:69-81, :83-88; lib/launchers/bind.py:34]`

**Second default worth noting:** `picocmd.py:725` `def __init__(self, ip, port, transport='ssl')` — **the picocmd protocol stack independently defaults to `ssl` too.** Two separate default declarations, same value. `[source: lib/picocmd/picocmd.py:725]`

### 2.3 What the default actually gets you — the `ssl` transport is real mutual TLS

**`ssl/conf.py` (128 lines, read in full) is the strongest transport in the product**, and materially so:

```python
# ssl/conf.py:25-29
self.ciphers = 'HIGH:!aNULL:!MD5:!RC4:!3DES:!DES:!AES128@STRENGTH'
self.client_cert_required = client_cert_required
self.cert_reqs = ssl.CERT_REQUIRED if self.client_cert_required else ssl.CERT_OPTIONAL
self.ssl_version = ssl.PROTOCOL_SSLv23
```

**Four properties, each verified at source:**
1. **Mutual certificate authentication by default** — `:27` `CERT_REQUIRED` when `client_cert_required` (`:83` defaults `True`).
2. **`RC4` is explicitly excluded** (`:25`) — significant, because `ec4.py` uses RC4 (§4, §5). **The product's default transport refuses RC4; two of its alternative transports are built on it.**
3. **Certificate role binding, application-layer** — `:69-76` extracts `organizationalUnitName` from the peer cert and **requires the complementary role**:
```python
# ssl/conf.py:74-76
if not (self.ROLE == 'CLIENT' and peer_role == 'CONTROL' or \
  self.ROLE == 'CONTROL' and peer_role == 'CLIENT'):
    raise AuthenticationError('Invalid peer role: {}'.format(peer_role))
```
   **A client certificate is not sufficient — it must be the opposite role.** This is a genuine authorization property, not just authentication, and it is the only such check found anywhere in the transport layer.
4. **Temporary credential files are unlinked in `finally`** (`:61-64`) — cert/key/CA written to `mkstemp` files (`:38-47`) and removed on both paths.

`[source: network/transports/ssl/conf.py:25-29, :38-47, :61-64, :69-76, :83, :113-128 — read in full]`

### 2.4 The 13 registered transports, enumerated

`dfws` · `ec4` · `ecm` · `http` · `kc4` · `obfs3` · `rsa` · `ssl` · `ssl_rsa` · `tcp_cleartext` · `udp_cleartext` · `udp_secure` · `ws` — **13 total**, each with `conf.py`. **That figure matches D6's "13 transports."** `[source: enumerated directory listing]`

---

## 3. Q3 — three byte orders in one product, and where the boundary runs

### 3.1 The census — enumerated, not sampled

Every `struct.pack` / `unpack` / `unpack_from` call site in the framing layers, categorized by declared byte order:

| Module | Total sites | big-endian `'>'` | little `'<'` | bare/native | other |
|---|---:|---:|---:|---:|---:|
| `picocmd/picocmd.py` | **64** | **37** | **2** | **18** | 7 |
| `transports/ecm.py` | 5 | 0 | **5** | 0 | 0 |
| `transports/ec4.py` | **3** | 0 | 0 | **3** | 0 |
| `transports/rsa_aes.py` | 2 | **2** | 0 | 0 | 0 |
`[source: enumerated across all four modules — every call site matched and counted]`

**Positive control:** the same probe against `picocmd.py` returns **64 total** with non-zero categories in all three buckets. **The instrument demonstrably counts; the zeros in `ec4.py`'s big/little columns are measurements, not probe failures.** (An earlier attempt at this census returned empty for every file because `[regex]::Matches` with a bare string pattern was marshaled into `RegexOptions` and threw — **the probe was broken, the data was not.** Recorded in §9.2.)

### 3.2 The D6 §13.2 finding, confirmed and localized

**D6 reported `ec4.py`'s native-order `'H'` against picocmd's `DataTransferControl` `'>HI'`. Both halves are confirmed at source:**

```python
# transports/ec4.py:57 — native order, NO prefix
length, = struct.unpack_from('H', data.peek(2))
# transports/ec4.py:71 — native order
self.downstream.write(struct.pack('H', len(response)) + response)
# transports/ec4.py:116 — native order
struct.pack('H', len(req)) + req
```

```python
# picocmd/picocmd.py:1567-1572 — EXPLICIT big-endian
def pack(self):
    packed = chr(self.action << 4 | self.transfer_id)
    if self.action == DataTransferControl.ACTION_START:
        packed += struct.pack('>HI', self.total_size, self.crc)
    return packed
```

**`:1570` `'>HI'` — explicitly big-endian, `total_size` then `crc`.** Against `ec4.py:57/71/116` **bare `'H'`, which resolves to the host's native order.** `[source: transports/ec4.py:57, :71, :116; picocmd/picocmd.py:1567-1572]`

### 3.3 The census reveals a third order — `ecm.py` is explicit little-endian

**This goes beyond D6's two-way contrast.** `ecm.py` uses **explicit little-endian** in all five of its sites — not bare codes, but `'<'` prefixes:

```python
# transports/ecm.py — all five sites, explicit little-endian
:89   reqlen, noncelen = struct.unpack_from('<HH', data.peek(4))
:103  self.downstream.write(struct.pack('<HH', len(response), len(nonce)) + response + nonce)
:142  self.chunk_len, = struct.unpack('<I', raw_chunk_len)
:168  buf.write(self.encryptor.encrypt(struct.pack('<I', ldata)))
:187  struct.pack('<HH', len(req), len(self.nonce)) + req + self.nonce
```

**So the product carries three distinct byte-order conventions:**

| Order | Modules | Evidence |
|---|---|---|
| **Explicit big-endian** | `picocmd` (37 sites), `rsa_aes` (2/2) | `picocmd.py:1570`, `rsa_aes.py:76` |
| **Explicit little-endian** | `ecm` (5/5) | `ecm.py:89, :103, :142, :168, :187` |
| **Native / undeclared** | `ec4` (3/3) | `ec4.py:57, :71, :116` |

`[source: §3.1 census; per-site quotations above]`

**`ec4.py` is the sole native-order module in the set — the only one whose on-wire format depends on the architecture it was built for.** `ecm.py` is explicit and therefore portable; `picocmd.py` is explicit and portable. **The three-way split means the anomaly is not "Pupy uses native order" but "exactly one module does, and it is a length prefix."** `[inference on portability consequence — the code evidence is direct]`

### 3.4 The boundary, localized — and why it is a seam, not a bug

**The two `'>'`-vs-bare systems are different framing layers, and they never parse each other's headers.** `ec4.py`'s `'H'` is the **transport-layer** length prefix for its ECPV KEX request/response (`:57` reads it, `:116` writes it). `picocmd.py`'s `'>HI'` is the **application-layer** `DataTransferControl` file-transfer packet (`:1570`), which rides *inside* whatever transport carries it.

**Consequently the endianness mismatch is real but latent within one process:** both endpoints run the same module set, so a client and server built for the same architecture agree. **The defect surfaces on cross-architecture deployment** — a 32-bit implant against an x86-64 C2 server (or any big-endian host) desynchronizes `ec4.py`'s framing while `ecm.py` and `picocmd.py` continue to interoperate. `[source: ec4.py:57/71/116 vs picocmd.py:1570 — layer separation is structural; cross-architecture consequence is inference]`

**The one-line fix, for the record:** `ec4.py:57, :71, :116` should carry an explicit prefix — `'>'` to match `rsa_aes.py:76` and `picocmd.py:1570`, or `'<'` to match `ecm.py`. **The absence of any prefix in a module that otherwise uses explicit `struct` calls is the tell: this is an oversight, not a decision.**

---

## 4. Q2 — `rsa_aes.py`: real crypto, an XOR docstring, and a pre-auth oracle

**File: `lib/transports/rsa_aes.py`, 9,625 B / 285 lines. Read in full across `:1-285`.**

### 4.1 It is REAL RSA and REAL AES — not a wrapper

**The brief asked whether `rsa_aes.py` is real or a wrapper. It is real.** Every element is present at source:

| Element | Evidence |
|---|---|
| RSA-4096, AES-256 | `:38` `rsa_key_size = 4096`, `:39` `aes_size = 256` → `:51-52` `key_size = 32` |
| Fresh AES key per connection | `:204` `self.aes_key = get_random(self.key_size)` in `on_connect` |
| RSA-wrapped key transmission | `:207` `pkey = rsa.encrypt(self.aes_key, pk)` · `:208` write |
| PEM key loading, both sides | `:203` `rsa.PublicKey.load_pkcs1` · `:242` `rsa.PrivateKey.load_pkcs1` |
| Genuine AES-CBC | `cryptoutils/aes.py:68` `def NewAESCipher(aes_key, iv, mode=AES_MODE_CBC)` — **CBC is the default** |
| IV negotiation | `:210` client sends IV · `:267` server sends IV · `:104`/`:105` peer reads and builds decryptor |
| Missing-key errors | `:197-200`, `:237-240` both raise `TransportError` rather than proceeding |

`[source: transports/rsa_aes.py:38-39, :51-52, :197-200, :203-210, :237-242, :264-268; cryptoutils/aes.py:64-68]`

### 4.2 FINDING — the module's own docstring calls it an XOR transport

```python
# transports/rsa_aes.py:12
""" This module contains an implementation of a simple xor transport for pupy. """
```

**Fifteen lines below the real imports — `rsa`, `struct`, and `from .cryptoutils import get_random, NewAESCipher` — the module declares itself XOR.** This is a **copy-paste from a sibling XOR transport, never updated.** Functionally it is documentation-only. **But it is load-bearing for any reviewer who greps first and reads second:** the module that implements the product's strongest alternative transport advertises the weakest primitive in its header. `[source: transports/rsa_aes.py:12 vs :14-25]`

**This is the same defect class as Mythic's `util_agent_message.go` documented-vs-actual mismatches (D11-A §3.3): the comment survived, the code changed.**

### 4.3 FINDING — a pre-authentication decryption oracle on the RSA handshake

**The server-side handshake distinguishes decryption success from failure with different observable behaviour:**

```python
# transports/rsa_aes.py:250-268
expected = self.rsa_key_size // 8          # :250 — 512 bytes for RSA-4096
if len(data) < expected:
    logger.debug('Read AES Key: Short read: %d < %d', len(data), expected)
    return                                 # :253 — wait for more
cmsg = data.read(expected)                 # :255 — fixed-length read
try:
    self.aes_key = rsa.decrypt(cmsg, self.pk)   # :258
except rsa.pkcs1.DecryptionError:
    logger.debug("decrypt failed")
    self.close()                           # :261 — CLOSE and stop
    return
self.enc_cipher = NewAESCipher(self.aes_key, self._iv_enc)   # :264 — PROCEED
...
self.downstream.write(self._iv_enc)        # :267 — ANSWER with an IV
```

**An unauthenticated peer that sends 512 bytes gets one of two distinguishable outcomes:** connection closed (`:261`) versus **an IV written back** (`:267`). **That is a validity oracle on RSA padding, reachable with no prior authentication** — the read at `:255` is the first substantive thing the server does with peer data, and `:247` (`if self.aes_key is None`) confirms it is the handshake entry state.

**Stated precisely, with the limits of my evidence:** the presence of a distinguishable success/failure path on RSA decryption of attacker-supplied ciphertext is the **necessary precondition** for a Bleichenbacher-style padding-oracle attack. **Whether it is *sufficient* depends on the `rsa` library's internals** — which are not in this corpus — because a library that raises a single unified `DecryptionError` for all padding and length failures (rather than leaking timing or distinct exceptions) narrows the channel. **The code's contribution is that it faithfully converts whatever the library distinguishes into a network-observable difference.** `[source: rsa_aes.py:247, :250-268; precondition claim is direct, exploitability is inference — see §9.3]`

### 4.4 FINDING — the client never authenticates the server

**`RSA_AESTransport` has no server-authentication step of any kind.** The client loads a public key (`:203`), encrypts to it (`:207`), and sends. **There is no signature check, no certificate, no pre-shared verification that the key belongs to the intended server.** The class declares only `password`, `iterations`, `rsa_key_size`, `aes_size` (`:36-39`).

**Consequence:** the confidentiality of the handshake rests entirely on the client's *offline* possession of the correct public key. **An active network attacker who supplies their own public key to a client — via configuration substitution rather than protocol attack — terminates the transport invisibly.** Contrast `ssl/conf.py:74-76`, where the certificate's `organizationalUnitName` must match the complementary role: **the default transport binds identity to the certificate; `rsa_aes` binds nothing.** `[source: rsa_aes.py:36-39, :203-211 vs ssl/conf.py:69-76]`

### 4.5 The framing is big-endian and consistent with picocmd

```python
# transports/rsa_aes.py:76
data.insert(struct.pack('>I', lctext))
```
**2 of 2 sites explicit big-endian** (§3.1). **So `rsa_aes.py` agrees with `picocmd.py` and disagrees with `ec4.py`** — the endianness split runs through the transport set, not between transport and application layers.

---

## 5. Q4 — ECPV IS reachable, but NOT with the default curve

### 5.1 Reachability — two transports, confirmed

**The brief asked whether ECPV is reachable from any transport. It is, from exactly two:**

| Transport | Site | Curve | Hash |
|---|---|---|---|
| `ec4.py` | `:37-41` (client, pubkey) | **`brainpoolP384r1`** | `SHA384` |
| `ec4.py` | `:43-47` (server, privkey) | **`brainpoolP384r1`** | `SHA384` |
| `ecm.py` | `:42`, `:48` | **`brainpoolP384r1`** | `SHA384` |

```python
# transports/ec4.py:36-47
if self.pubkey:
    self.encoder = ECPV(curve='brainpoolP384r1', public_key=self.pubkey, hash=SHA384)
else:
    self.encoder = ECPV(curve='brainpoolP384r1', private_key=self.privkey, hash=SHA384)
```
**Both branches pass the curve and hash explicitly.** `[source: ec4.py:36-47; ecm.py:42, :48; enumerated ECPV call sites]`

### 5.2 FINDING — the P160R1/SHA1 default is dead code in the transport path

**`ecpv.py:65` does default to the weak curve, exactly as D6 reported:**

```python
# cryptoutils/ecpv.py:65-68
def __init__(self, curve='brainpoolP160r1', hash=None, private_key=None, public_key=None):
    if not hash:
        if '160' in curve:
            hash = SHA1
```

**But every transport caller overrides both arguments** (§5.1). **`brainpoolP160r1` and the substring-matched `SHA1` are therefore unreachable from the transport layer.** The only remaining `ECPV(...)` constructions that use the default are at **`:372`** (`ECPV(curve='brainpoolP384r1')` — explicit again) and **`:154`** (`clone = ECPV()` in `PubKeyCache`), the latter being a cache helper.

**D6's finding is correct as a statement about the primitive and does not describe what ships.** The reconciliation: **`ecpv.py:65` is a latent footgun for a future caller, not an active weakness in the current transport set.** Both statements are true and they are not the same claim. `[source: ecpv.py:65-68, :154, :372; ec4.py:36-47; ecm.py:42, :48; enumeration of all ECPV sites]`

### 5.3 What `ec4` actually uses — RC4 keys derived from ECPV

```python
# transports/ec4.py:78-84
self.encryptor = RC4(key=key[0])
self.decryptor = RC4(key=key[1])
# https://wikileaks.org/ciav7p1/cms/files/NOD%20Cryptographic%20Requirements%20v1.1%20TOP%20SECRET.pdf
# Okay...
self.encryptor.encrypt(b'\x00'*3072)
self.decryptor.decrypt(b'\x00'*3072)
```

**Two RC4 instances, directional (`key[0]` enc / `key[1]` dec), with `128`-byte keys requested at `:65`/`:74` (`key_size=128`), and 3072 bytes of keystream discarded before use.** The source link is to the CIA's cryptographic requirements document and the comment is *"Okay..."* — **the 3072-byte discard is an explicit, sourced attempt to discard RC4's biased initial keystream.**

**Honest assessment:** discarding 3072 bytes mitigates the worst RC4 biases *but does not remove RC4's structural weaknesses* — the Fluhrer-Mantin-Shamir key-scheduling correlation and the 2-byte bias in the initial keystream extend beyond 3072 bytes in the statistical sense, and RC4 has been prohibited in TLS since RFC 7465 (2015). **The EC KEX is sound; the bulk cipher it feeds is deprecated.** And **`ssl/conf.py:25` explicitly excludes RC4 from the default transport's cipher list** — the product's own default refuses the primitive that `ec4`/`ecm`/`kc4` build on. `[source: ec4.py:65, :74, :78-84; ssl/conf.py:25; RFC 7465 — external]`

---

## 6. The transport inventory, and where each crypto module lands

**13 registered transports → their implementation modules**, enumerated by reading each `conf.py`'s `client_transport`/`server_transport` wiring:

| Transport | Implements | Crypto module | Cipher / KEX |
|---|---|---|---|
| **`ssl`** | `PupySSLClient` + `DummyPupyTransport` | TLS | **Real TLS, mutual cert, role-bound** (§2.3) |
| `ssl_rsa` | `PupySSLClient` + `RSA_AES*` | `rsa_aes.py` | TLS **unauthenticated** + RSA/AES (§6.2) |
| `rsa` | `PupyTCPClient` + `RSA_AES*` | `rsa_aes.py` | RSA-4096 → AES-256-CBC (§4) |
| **`ec4`** | `EC4Transport*` | `ec4.py` + `ecpv.py` | brainpoolP384r1 → RC4, 128-B keys (§5.3) |
| **`ecm`** | `ECMTransport*` | `ecm.py` + `ecpv.py` | brainpoolP384r1 → AES, little-endian framing (§3.3) |
| **`kc4`** | `EC4Transport*` over **UDP** | **`ec4.py` — shared** | **Inherits `ec4`'s native-order framing** (§6.1) |
| `obfs3` | `chain_transports(Obfs3*, RSA_AES*)` | `obfs3/obfs3.py`, `rsa_aes.py` | **UniformDH + AES-CTR + RSA/AES, 3 layers** (§7) |
| `http` / `ws` | `http.py` (13,851 B), `websocket.py` (15,851 B) | wrapping only | HTTP/WebSocket framing over another transport |
| `dfws` | conf-only (3,207 B) | — | domain-fronting WebSocket |
| `udp_secure` / `udp_cleartext` / `tcp_cleartext` | conf-only | — | cleartext or UDP wrappers |

`[source: enumerated from every network/transports/*/conf.py; implementation sizes from lib/transports/]`

### 6.1 `kc4` is not a separate transport — it is `ec4` over UDP, and it inherits the endianness defect

**`kc4/conf.py:12-19` is decisive:**

```python
# network/transports/kc4/conf.py:12-19
name = "kc4"
server = PupyUDPServer
client = PupyUDPClient
stream = PupyUDPSocketStream
client_transport = EC4TransportClient      # :16 — SAME CLASS as ec4
server_transport = EC4TransportServer      # :17
credentials = ['ECPV_RC4_PUBLIC_KEY', 'ECPV_RC4_PRIVATE_KEY']
dgram = True                               # :19
```

**`kc4` reuses `EC4TransportClient`/`EC4TransportServer` verbatim and adds UDP framing.** Two consequences, both direct:

1. **The §3 endianness defect propagates to `kc4` for free** — `struct.pack('H', ...)` at `ec4.py:71`/`:116` is the same code.
2. **On UDP the consequence is worse than on TCP.** `ec4.py:58` requires `len(data) >= 2 + length` after reading a length prefix at `:57`. **A length prefix read in the wrong byte order on a datagram stream means the KEX response length is misread, and UDP offers no stream resynchronization.** On TCP a desync eventually recovers via the byte stream; on UDP the datagram is simply lost.
3. **`kc4` is the only transport pairing `PupyUDP*` with a real crypto layer** — the one place the endianness defect meets a lossy transport.

`[source: network/transports/kc4/conf.py:12-19; lib/transports/ec4.py:57-58, :71, :91, :116]`

### 6.2 `ssl_rsa` — TLS that authenticates nothing, wrapping a handshake that authenticates nothing

**Two independent non-authentications stacked in one transport.** `ssl_rsa` uses `DummySSLAuthenticator`:

```python
# network/transports/ssl_rsa/conf.py:18-26
class DummySSLAuthenticator(object):
    def __init__(self, role, keystr, certstr, castr, server_side=False):
        self.keystr = keystr.strip()
        self.certstr = certstr.strip()
        self.castr = castr.strip()
        self.cert_reqs = ssl.CERT_NONE        # :23 — verification disabled
```

**`CERT_NONE` means the peer certificate is never validated** — no chain, no hostname, no role check. **Compare `ssl/conf.py:27-28` (`CERT_REQUIRED`) and its OU role binding (`:74-76`): the difference between the `ssl` and `ssl_rsa` transports is precisely the authentication `ssl` performs and `ssl_rsa` disables.**

**And the configuration that is written and then ignored:** `:46-54` passes `ca_certs=tmp_ca_path` into `ssl.wrap_socket` **while `cert_reqs=CERT_NONE`** — the CA bundle is materialized to a temp file (`:42`) and handed to a wrapper that will not consult it. **The transport carries the shape of a verified TLS configuration without the verification.**

**Beneath that, `:124-128` instantiates `RSA_AES*` — which per §4.4 also performs no server authentication.** So `ssl_rsa` is **two unauthenticated layers**, and its total identity guarantee is zero despite carrying certificate material in its credentials list (`:103` `'SSL_CLIENT_KEY', 'SSL_CLIENT_CERT'`). `[source: network/transports/ssl_rsa/conf.py:18-26, :42-54, :103, :124-128; lib/transports/rsa_aes.py:36-39, :203-211; ssl/conf.py:27-28, :74-76]`

---

## 7. `obfs3` — a fourth crypto system, chained, with its own KEX

**`obfs3` is the most layered transport in the product, and it does not use ECPV at all.** `obfs3/conf.py:16` states it plainly:

```python
# network/transports/obfs3/conf.py:16-21
info = "TCP transport using obfsproxy's obfs3 transport with a extra rsa+aes layer"
name = "obfs3"
credentials = ['SIMPLE_RSA_PUB_KEY', 'SIMPLE_RSA_PRIV_KEY']
```

**And the chaining is literal** — `:38-53` calls `chain_transports(Obfs3Client, ...)` then layers `RSA_AES*` above. **Three crypto systems in one transport: obfs3's DH, obfs3's AES-CTR, and RSA/AES.**

### 7.1 The obfs3 KEX is not ECPV — it is `UniformDH`

```python
# lib/transports/obfs3/obfs3_dh.py:17-25
class UniformDH(object):
    """
    This is a class that implements a DH handshake that uses public
    keys that are indistinguishable from 192-byte random strings.
    The idea (and even the implementation) was suggested by Ian
    Goldberg in:
    https://lists.torproject.org/pipermail/tor-dev/2012-December/004245.html
    https://lists.torproject.org/pipermail/tor-dev/2012-December/004248.html
```

**A separate, third-party-designed DH** from the Tor project's obfs lineage — **not `ecpv.py`, not the brainpool curves.** `obfs3.py:59` `self.dh = obfs3_dh.UniformDH()`. **This is the fourth KEX mechanism in the product** (TLS, RSA-4096, brainpool ECPV, UniformDH). `[source: obfs3/obfs3_dh.py:17-25; obfs3/obfs3.py:59; obfs3/conf.py:16]`

### 7.2 Its cipher layer is AES-CTR, and the padding is the obfuscation

```python
# lib/transports/obfs3/obfs3.py:19, :27, :30-31
NewAESCipher, AES_MODE_CTR,
MAX_PADDING = 8194
KEYLEN = 16   # is the length of the key used by E(K,s) -- that is, 16.
HASHLEN = 32  # length of output of sha256
```

**AES-CTR with a 16-byte key and SHA-256** — **the only CTR-mode use in the transport set** (`aes.py:64-79` supports CTR/CFB/CBC; `ecpv.py:317, :340` use CTR; **but `rsa_aes.py:105` uses the CBC default**). **And `:93-97` pads each handshake with `random.randint(0, MAX_PADDING/2)` random bytes** — up to ~4 KB — which is the actual obfuscation mechanism: the handshake is designed to be indistinguishable from random traffic.

**Honest note on CTR:** CTR mode is not authenticated by itself, so obfs3's integrity depends on the RSA/AES layer chained above it (`conf.py:38-53`). **Obfuscation and authentication are supplied by different layers — correct composition, provided both are present.** `[source: obfs3.py:19, :27, :30-31, :93-97; obfs3/conf.py:16, :38-53; cryptoutils/aes.py:64-79; rsa_aes.py:105]`

---

## 8. Cross-framework contrast

**Pupy's transport layer is the inverse of Mythic's (D11 Part A), and the two failures do not overlap.**

| Property | Pupy (D11-B) | Mythic (D11-A) | Sliver (D1 §24) |
|---|---|---|---|
| Default transport | **`ssl`, real mutual TLS** (argparse `default="ssl"`) | RabbitMQ consumer | mTLS |
| Where the strength is | **Crypto primitives** — 4 KEX mechanisms, no weak default reachable | **Crypto primitive** — verify-before-decrypt | **Build-stability** |
| Where the failure is | **Framing + documentation + authentication gaps** | **Integration** — key search, action-independent dispatch | **Evasion** |
| Weakest shipped path | `ec4`/`kc4` native-order framing → RC4 | Plaintext channel reporting as encrypted (§3.3) | `0xC3` patch |
| Best shipped path | `ssl` — mutual cert + **OU role binding** (`ssl/conf.py:74-76`) | correct AEAD | — |
| Doc contradicts code? | **Yes** — `rsa_aes.py:12` calls itself XOR | **Yes** — §4.2 of Part A | No |

**The generalization this supports, and it is the session's headline rule applied to a new corpus:** **Pupy's default is its strongest transport and its alternatives are its weakest.** `ssl` performs mutual authentication with role binding; `ssl_rsa` (the near-named sibling) disables that verification (`CERT_NONE`) and wraps an unauthenticated handshake. **A defender or analyst who reads "Pupy supports TLS" and a user who selects `ssl_rsa` believing it equivalent are both wrong in the same direction — the transport names do not encode their security properties.**

**And the reachability correction matters more than the primitive finding:** D6 correctly reports `ecpv.py:65` defaulting to `brainpoolP160r1`/`SHA1`. **Every shipping caller overrides it** (§5.2). Reporting the default without the reachability analysis would describe a weakness the product does not have — **the same failure mode as reporting a mitigation the product does not build (`{{if .Config.Debug}}`, D1 §24.3), pointed the other way.** `[source: §2.3, §3.3, §5.2, §6.1-6.2, §7; D1:3186-3244; D6 §22.6]`

---

## 9. Residual unknowns, corrections, and honest coverage

### 9.1 Read, or otherwise evidenced

**Read in full:** `network/conf.py` (80 L) · `network/transports/ssl/conf.py` (128 L) · `lib/transports/rsa_aes.py` (285 L) · `lib/transports/ec4.py` (117 L) · **read in windows:** `lib/base_launcher.py:45-89`, `cryptoutils/aes.py:60-104`, `cryptoutils/ecpv.py:59-70`, `lib/picocmd/picocmd.py:1560-1581`, `lib/transports/ecm.py` (5 struct sites), `transports/kc4/conf.py:12-40`, `transports/ssl_rsa/conf.py:18-61, :103, :124-128`, `transports/obfs3/conf.py:13-53`, `obfs3/obfs3.py` (heading lines), `obfs3/obfs3_dh.py:1-30`.
**Enumerated:** all 13 `conf.py` files · every `struct.pack`/`unpack` site in 4 modules (74 total, §3.1) · every `ECPV(...)` construction site.

### 9.2 CORRECTION — my own probe failure, recorded

**My first byte-order census returned empty counts for all four files.** Cause: `[regex]::Matches($text, "pattern")` marshaled the bare string into the `RegexOptions` parameter and threw `InvalidCastArgument`; I saw it in stderr and **almost recorded zeros as a finding.** Re-run with `Select-String`/`-AllMatches`, which cannot fail that way. **The corrected census (§3.1) is what the report rests on.** This is the same class of error the Lead named earlier in this session: *a count is a measurement only if you enumerate it* — and **a zero from a broken probe is not a measurement at all.**

### 9.3 CORRECTION — an edit-protocol failure in this artifact, recorded

**Three consecutive appends were anchored on the identical string `---`, and two of them silently landed at the wrong location, leaving §1–§5 out of document order.** Separately, the file was written with em-dashes that were stored as mojibake (`â€”`), so any later `edit` whose `old_string` contained a real em-dash could never match. Both defects are **structural, not substantive** — no content was lost — and both are recorded because **the Lead's write protocol requires a unique anchor and this report briefly violated it.** Recovered by (a) mapping exact block boundaries, (b) reassembling in correct order from the on-disk bytes, and (c) repairing the encoding to real UTF-8 without a BOM. **Final state verified by `Get-Item` and by heading enumeration.**

### 9.4 Inference inventory

| Claim | Status |
|---|---|
| §3.4 cross-architecture desync of `ec4` framing | **Inference.** The native-order code is direct; the deployment consequence is not observed. |
| §4.3 oracle exploitability | **Precondition is direct** (`:258-262` vs `:264-268` distinguishable). **Sufficiency depends on the `rsa` library internals, which are NOT in this corpus** — see §9.5. |
| §5.2 `brainpoolP160r1` unreachable from transports | **Direct** — enumerated all `ECPV(...)` sites; every transport caller passes the curve. |
| §6.1 `kc4` UDP desync | **Inference** from the shared code path + datagram semantics. |
| §8 naming-vs-security mismatch | **Direct** from conf files; the "defender would be misled" step is inference. |

### 9.5 NOT read — enumerated as unknowns, not implied covered

- **`lib/transports/http.py` (13,851 B), `websocket.py` (15,851 B), `httpwrap.py` (7,413 B)** — read: not at all. **These exist and their framing was not audited.** Any endianness or auth finding in them is unexamined.
- **`cryptoutils/ecpv.py` — 412 lines, read `:59-70` only.** The KEX protocol (`process_kex_request`/`process_kex_response`, `:260-347`) is **not read**; D6 §13.2 covered the MGF/curve perimeter and I did not re-verify it.
- **`cryptoutils/pbkdf2.py` (165 L), `sha.py` (39 L), `rc4.py` (93 L), `xor.py` (31 L)** — the credvault KDF and primitives. **D6 covered the iterative-MD5 credvault KDF; not re-verified here.**
- **The `rsa` Python library itself** — outside this corpus. **§4.3's sufficiency question cannot be answered from this tree.**
- **`lib/transports/obfs3/obfs3.py` body (10,475 B)** — read: heading lines only; the handshake state machine (`receivedUpstream`/`receivedDownstream`, `:107-171`) is unread.
- **`network/lib/` core**: `PupyTCPClient`/`PupyUDPClient`/`PupySocketStream`/`Buffer` — referenced by every conf, **not read**. The `chain_transports` mechanics are asserted from call sites only.
- **`lib/picocmd/picocmd.py` — 1,828 lines, read `:1560-1581` only** (the `DataTransferControl` pack). The `well_known_transports` tables at `:718`/`:1378` and the protocol state machine are unread.

### 9.6 What Part B did NOT find, stated so absence is not read as safety

- **No hardcoded credential, key, or backdoor** in any file read.
- **No broken KEX.** ECPV with brainpoolP384r1 + SHA-384 is sound; UniformDH is a published design; TLS is real TLS.
- **No weakness in the default transport.** `ssl` is the strongest component audited in either Part A or Part B.
- **The crypto primitives are not the problem.** As in Mythic, the defects are in framing, documentation, and what is *not* checked.

### 9.7 Headline, restated for the reader who reads only this section

**Pupy ships four KEX mechanisms and its security properties are inversely related to how its transports are named.** The default (`ssl`) does real mutual authentication with certificate role-binding; the near-named alternative (`ssl_rsa`) disables verification with `CERT_NONE` and stacks an unauthenticated RSA handshake beneath it. The weak `brainpoolP160r1`/`SHA1` default that D6 correctly identified in `ecpv.py` **is overridden by every shipping caller** — the real defects are a **native-order length prefix in `ec4.py` (inherited by `kc4` over UDP)**, a **pre-auth RSA decryption oracle in `rsa_aes.py`**, and **a module that calls itself XOR in its own docstring.**

---

*End of D11 Part B — `RE_Library/01_SOURCE_c2/pupy/pupy/network`. Companion artifact: `D11_mythic_crypto_postresponse.md` (Part A).*

---



