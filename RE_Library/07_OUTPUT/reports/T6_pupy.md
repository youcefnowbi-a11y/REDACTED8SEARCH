# T6 — Pupy RAT: cryptography, transports, and loader

**Target:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\pupy`
**Clone state:** 686 files, git clean (restored from a partially-wiped working tree during the disk audit — `git checkout -- .` recovered 535 files)
**Evidence class:** `[source]` — this target is source-only. No compiled Pupy binary exists on disk.

> **Provenance note.** This report was written by the Lead. The originally assigned diver
> (source-diver) produced T4_mythic.md and T5_havoc.md successfully, then went inactive twice
> without writing T6 or T7. It had begun Pupy crypto analysis and was cut off mid-thought with
> the note *"This is ECIES (EC ElGamal with the s,r scheme) plus ECDH KEX, both on brainpool
> curves. Let me finish the C loader details and write T6."* Rather than lose that thread, the
> Lead resumed it directly. All findings below are re-derived from source by the Lead.
> Coverage is real but not exhaustive — see §7.

---

## 1. Architecture

Pupy is a **cross-platform, reflective, Python-based** RAT. The distinguishing design choice
versus every other framework in this corpus: **the implant is CPython itself**. The payload is
a compiled C loader whose job is to embed a Python interpreter and execute the RAT logic as
Python, in memory, with no interpreter installed on the target.

```
pupy/
  client/       operator client (Python)
  pupy/         the framework proper
    network/lib/transports/   <- the 10 transport implementations
    network/lib/streams/      rpyc stream abstraction
    modules/                  post-exploitation modules
    pupylib/                  core library, credentials handling
  services/     server-side services
```

**Key architectural fact:** Pupy routes all its C2 through **rpyc** (Remote Python Call) over
a pluggable transport stack. The transport is a *swap-in layer* — the same operator logic runs
over EC4, RSA+AES, WebSocket, HTTP, obfs3, or SSL without changing the module code. This is a
different architecture from a fixed-protocol C2 like Havoc or Merlin, and it's why Pupy has
unusually broad transport coverage.

---

## 2. Cryptography — the EC4 transport

**Source:** `pupy/network/lib/transports/ec4.py` (117 lines, read in full)

### 2.1 Algorithm chain

> **CRITICAL SCOPING CORRECTION.** The table below describes **EC4 *specifically***, not Pupy's
> crypto in general. EC4 passes both the curve and the hash **explicitly** at `ec4.py:38,44` —
> they are *per-transport overrides*. ECPV's own defaults are **different**: the default curve
> is `brainpoolP160r1` and the hash is chosen by substring-matching the curve name
> (`ecpv.py:65-78`), where `'384'` maps to **SHA3_512**, not SHA384. An earlier draft of this
> report generalised the EC4 parameters into a claim about "Pupy's crypto" — that was wrong and
> is corrected in §2.4. See also §5.

| Element | Value | Source |
|---|---|---|
| Key exchange | **ECPV** (EC ElGamal / ECIES-style `s,r` scheme) | `ec4.py:37-47` |
| Curve | **`brainpoolP384r1`** (EC4's explicit choice) | `ec4.py:38`, `44` |
| KEX hash | **SHA-384** (EC4's explicit choice) | `ec4.py:40`, `46` |
| Derived key | ~~**128 bytes**, split into two 64-byte halves~~ **SUPERSEDED — see the CORRECTION NOTICE at the end of this report.** `key_size=128` (bits) at `ec4.py:65`, `74`; the RC4 keys are **16 bytes each**, not 64. | `ec4.py:65`, `74`, `78-79` |
| Key-derivation ordering | ~~native `>H` framing as first written~~ **corrected:** `ec4.py:57` uses **native byte order**, not forced big-endian | `ec4.py:57` |
| Bulk cipher | **RC4** — two independent streams, one per direction | `ec4.py:78-79` |
| Keystream discard | **3072 bytes dropped** on each stream before first real byte | `ec4.py:83-84` |

### 2.3 ECPV defaults and the multi-curve reality

**Source:** `pupy/network/lib/transports/cryptoutils/ecpv.py:65-96`

```python
def __init__(self, curve='brainpoolP160r1', hash=None, private_key=None, public_key=None):
    if not hash:
        if '160' in curve:
            hash = SHA1
        elif '224' in curve:
            hash = SHA3_256
        elif '256' in curve:
            hash = SHA3_256
        elif '384' in curve:
            hash = SHA3_512
        elif '521' in curve:
            hash = SHA3_512
        else:
            raise ValueError('Appropriate hash should be specified')
```

[source: `ecpv.py:65-78`]

Three things follow:

1. **The default curve is `brainpoolP160r1`** — a 160-bit curve, the weakest in the set.
2. **The hash is selected by `in` substring match on the curve name string.** This is fragile
   string-matching rather than a lookup table, and it means the hash is a *derived* property of
   the curve name, not independently configurable in the default path.
3. **`brainpoolP384r1` resolves to `SHA3_512`, NOT SHA-384.** EC4 gets SHA-384 only because it
   passes `hash=SHA384` explicitly, overriding this table. Absent that override the same curve
   yields SHA3-512.

There is also a hard constraint at `:95-96`:

```python
if not self._mgf_size >= self._curve.bytes:
    raise ValueError('Incompatible hash function')
```

The MGF output size must be **at least** the curve's byte width. [source: `ecpv.py:91-96`]

**The credential keypairs span three curves.** From `pupy/pupylib/PupyCredentials.py`:

| Function / constant | Curve | Source |
|---|---|---|
| `_generate_ecpv_keypair(curve='brainpoolP160r1')` | **P160R1** (default) | `:254` |
| `_generate_ecpv_keypair_bp384()` → `_generate_ecpv_keypair(curve='brainpoolP384r1')` | **P384R1** | `:355-356` |
| `_generate_ecpv_rc4()` → calls `_generate_ecpv_keypair_bp384()` twice | **P384R1** | `:375-380` |
| `ECPV_PRIVATE_KEY, ECPV_PUBLIC_KEY = _generate_ecpv_keypair()` | **P160R1** (default) | `:405` |
| `ECPV_PRIVATE_KEY_V2, ECPV_PUBLIC_KEY_V2 = _generate_ecpv_keypair(curve='brainpoolP224r1')` | **P224R1** | `:414-415` |

The v1/v2 keypair split is significant: **the legacy family uses P160R1 and the newer family uses
P224R1** — the curve was strengthened between versions but the v1 family was retained. The RC4
transports use the P384R1 family (`_generate_ecpv_rc4` → `bp384`, twice — once per direction).

So the accurate statement is: **Pupy's ECPV perimeter is multi-curve (P160R1 / P224R1 / P384R1)
with SHA1 / SHA3-256 / SHA3-512 selected by string match, and EC4 is the one transport that pins
P384R1 + SHA384 explicitly.**

### 2.2 The RC4 discard — and why it is there

```python
self.encryptor = RC4(key=key[0])
self.decryptor = RC4(key=key[1])

# https://wikileaks.org/ciav7p1/cms/files/NOD%20Cryptographic%20Requirements%20v1.1%20TOP%20SECRET.pdf
# Okay...
self.encryptor.encrypt(b'\x00'*3072)
self.decryptor.decrypt(b'\x00'*3072)
```

`ec4.py:81-84`

This is the single most interesting crypto detail in the target. RC4's keystream is
well-known to be **biased in its first output bytes** (the Fluhrer/McGrew biases, and the
Roos/"RC4 drop-N" mitigation). The standard defence is to discard the first *N* bytes of
keystream before using any. Pupy discards **3072 bytes**, encrypting a block of zeros to
advance the cipher state.

The comment cites the **CIA NOD (Network Operations Division) Cryptographic Requirements
v1.1, TOP SECRET** document leaked in the Vault 7 release, which specifies exactly this
practice. The author appends a wry `# Okay...` — an acknowledgement that they are knowingly
implementing a spec that mandates a broken primitive with a bandage rather than choosing a
modern cipher.

**Assessment:** this is a deliberate, spec-compliant mitigation, not a mistake. The 3072-byte
figure is the discarded-keystream count the NOD document prescribes for RC4. It meaningfully
reduces the early-keystream bias, but the underlying cipher remains RC4 — a stream cipher with
recognisable statistical fingerprints that modern IDS signatures target directly. **RC4 with
drop-3072 is still fingerprintable**, and that is a practical detection lever.

### 2.3 KEX framing

```
client → server:  [ 2-byte LE length ][ kex request bytes ]
server → client:  [ 2-byte LE length ][ kex response bytes ]
```

`ec4.py:57-71`, `114-117`. Note the **explicit jitter on the server's KEX response**:

```python
# Add jitter, tinyec is quite horrible
time.sleep(random.random())
```

`ec4.py:69-70`

The author's own comment: `tinyec` (the pure-Python ECC library) is slow enough that KEX
timing is a fingerprint, so a random sleep of 0–1.0 s is inserted to blur it. **This is a
timing-side-channel mitigation driven by an implementation weakness**, and it is a
direct example of the "evasion as a response to a specific technical defect" pattern.

### 2.4 Key-size note

`process_kex_request(..., key_size=128)` and `process_kex_response(..., key_size=128)` —
the 128 is **bytes** (1024 bits of KEX-derived material), then split `key[0]`/`key[1]` into the
two directional RC4 keys. It is not a 128-bit key.

---

## 3. The transport stack — 10 implementations

**Directory:** `pupy/network/lib/transports/`

| Transport | File | Size | Notes |
|---|---|---|---|
| **EC4** | `ec4.py` | 3.4 KB | ECPV brainpoolP384r1 + RC4×2 (drop 3072) — analyzed above |
| **ECM** | `ecm.py` | 5.5 KB | companion EC mode (same crypto family as EC4) |
| **RSA + AES** | `rsa_aes.py` | 9.4 KB | classical asymmetric KEX + AES bulk |
| **WebSocket** | `websocket.py` | 15.5 KB | largest transport; C2 over WS — blends with normal web traffic |
| **HTTP** | `http.py` | 13.5 KB | HTTP transport |
| **HTTP wrap** | `httpwrap.py` | 7.2 KB | wraps another transport inside HTTP |
| **obfs3** | `obfs3/` | — | **Tor pluggable transport** — see §3.1 |
| dummy | `dummy.py` | 0.7 KB | passthrough, for testing |
| utils | `utils.py` | 0.5 KB | shared helpers |

**Available transport list is declared in the operator CLI** at
`pupy/network/lib/picocmd/picocmd.py:719` and `:1379`, enumerating:
`obfs3, kc4, http, tcp_cleartext, rsa, ssl, ...`

### 3.1 obfs3 — the notable one

`pupy/network/lib/transports/obfs3/` implements **obfs3**, the Tor Project's pluggable
transport, with its own `obfs3_dh.py` (Diffie-Hellman). Verified strings in
`obfs3.py:5` (`"The obfs3 module implements the obfs3 protocol."`) and class
`Obfs3Transport` at `obfs3.py:38`.

**Why this matters:** obfs3 is designed to make traffic *indistinguishable from random* to a
DPI middlebox. A C2 that ships a Tor pluggable transport is explicitly targeting **protocol
fingerprinting**, not just eavesdropping. Combined with WebSocket as an alternative, Pupy
covers both "look like noise" and "look like normal web traffic" — the two ends of the
traffic-shaping spectrum. This is the most sophisticated transport posture in the corpus,
ahead of Havoc's profile-driven HTTP/SMB and Merlin's malleable profiles.

### 3.2 Supporting cast

`PupySocketStream.py:5` describes itself as an *"abstraction layer over rpyc streams to handle
different transports"* — confirming the swap-in design. `:46` adds functions *"needed by some
obfsproxy transports"*, so the obfs3 integration is native rather than bolted on.

---

## 4. Default configuration — `pupy/conf/pupy.conf.default`

**Source:** `pupy/conf/pupy.conf.default` — 5,451 B, 202 lines, 18 sections. This is the
shipped default configuration and it is unusually informative: it enumerates every listener,
its default port, and the implant's post-exploitation defaults.

> **Discovery note.** This file was found by accident. An earlier pass searched only
> `-Include *.py,*.c,*.h` and **missed this file entirely**, because its extension is
> `.default`. A failing teammate process had referenced `OneDriveUpdate` and the first search
> returned nothing, which nearly led to that finding being discarded as spurious. It is real —
> see §4.2. **Lesson recorded: search by content across all file types, never by a presumed
> extension list.**

### 4.1 Listener ports — all default ports, one table

```
ssl = 443=8443
obfs3 = 9090
rsa = 9091
ec4 = 80=1234
kc4 = 123=1234
tcp_cleartext = 80=1234
udp_cleartext = 123=1234
ws = 80=8081
http = 80=8080
ecm = 1235
```

[source: `pupy.conf.default:67-80`, section `[listeners]`]

The `A=B` form is *external=internal* port (the listener accepts on the public port and
forwards to the internal one). This confirms and completes the §3 transport inventory: all ten
transports are enabled with default ports, and **nine of the ten have a concrete default port
here** — matching the ten transport implementations found in the directory listing.

Notable defaults:
- **`ssl = 443=8443`** — the SSL transport fronts on **443**, i.e. it is designed to look like
  ordinary HTTPS to a network observer.
- **`obfs3 = 9090`** — the Tor pluggable transport on 9090.
- **`http = 80=8080`** and **`ws = 80=8081`** — both front on port 80.
- **`ec4 = 80=1234`** — EC4 also defaults to port 80, so the brainpoolP384r1+RC4 transport is
  intended to sit on a web port.

`[ssl] client_cert_required = true` [source: `:82-83`] — **mutual TLS is required by default**
on the SSL transport. Not optional, not a flag the operator must remember. Combined with
`[httpd] log = true, secret = false` [source: `:85-87`] this is a deliberate posture: strong
transport auth, permissive local logging.

### 4.2 Persistence — the implant's default name is `OneDriveUpdate`

```
[persistence]
# Method ids taken from https://github.com/rootm0s/WinPwnage
preferred_methods = 2,8,3,9
name = OneDriveUpdate
```

[source: `pupy.conf.default:178-181`]

**The default persistence artefact is named `OneDriveUpdate`.** This is a
masquerading choice with a specific purpose: Microsoft OneDrive genuinely ships an update
component, so an autostart entry named `OneDriveUpdate` is unremarkable to both a user browsing
their startup items and a defender doing a quick visual sweep. It is the same class of
technique as naming a service after a Windows component.

`preferred_methods = 2,8,3,9` uses **WinPwnage method IDs** (the comment links
`github.com/rootm0s/WinPwnage`). Note the ordering is a *preference list* — the operator picks
from these in order, not a single method.

Compare the adjacent section:

```
[bypassuac]
# Method ids taken from https://github.com/rootm0s/WinPwnage
preferred_methods = 1,2,3,4,8,9,10
```

[source: `pupy.conf.default:174-176`]

UAC bypass has **seven** preferred methods (1,2,3,4,8,9,10); persistence has **four**
(2,8,3,9). The overlap on 2, 8, 3, 9 is worth noting — the same primitive family is being used
for both escalation and persistence.

### 4.3 Other sections worth recording

- **`[mimikatz]`** with hardcoded Kali default paths `exe_Win32=/usr/share/mimikatz/Win32/mimikatz.exe`
  and `exe_x64=/usr/share/mimikatz/x64/mimikatz.exe` [source: `:169-173`]. Credential dumping is
  a first-class configured capability, not a bolt-on module.
- **`[rubber_ducky]`** with `encoder_path = TO_FILL` [source: `:198-202`] — keystroke-injection
  payload generation is configured through the `hak5darren/USB-Rubber-Ducky` encoder.jar.
  The `TO_FILL` placeholder means it ships unconfigured.
- **`[aliases]`** [source: `:183-196`] — operator command aliases (`shell=interactive_shell`,
  `kill=process_kill`, `mount=drives`, `du=download -S`).
- **`[webserver]`** `listen = 0.0.0.0:9000` [source: `:89-91`] — payload staging web server,
  bound to all interfaces.
- **`[dnscnc]`** (line 54) — a DNS C2 section exists in the default config. **Not analyzed** —
  recorded as a gap; no DNS transport was identified in the §3 directory sweep, so the
  relationship between this section and the transport stack is **unresolved**.

---

## 5. Hardcoded credentials shipped in source

**Source:** `pupy/network/transports/__init__.py` (130 lines)

> **Path note.** This is `pupy/network/transports/` — **not** `pupy/network/lib/transports/`.
> Both directories exist. `network/lib/transports/__init__.py` is a **zero-byte empty file**;
> the constants live in `network/transports/__init__.py`. An earlier pass searched the wrong
> one and initially failed to find these. Recorded because the path ambiguity is a real trap.

The module's `__all__` exports the credential constants by name [source: `:10-17`], and they are
**concrete literal values committed to the repository**:

### 5.1 Default bind password

```python
DEFAULT_BIND_PAYLOADS_PASSWORD="PuPyD3f4ultP4sSw0rd"
```

[source: `network/transports/__init__.py:27`]

A leetspeak default password, in source. Any bind-mode payload built without an explicit
override authenticates with a value that is public.

### 5.2 DNSCNC keypair — private key in the repo

```python
DEFAULT_DNSCNC_PUB_KEY='v6iJnUBFI1qeQ9jrP2NZsTd4qwYB'
DEFAULT_DNSCNC_PRIV_KEY='XqYoPdC5LR8Ct0givPQRBlKv41o='
```

[source: `network/transports/__init__.py:29-30`]

**The DNS C2 private key is shipped in plaintext.** Anyone with the repository can decrypt
default-configured DNSCNC v1 traffic, and can *forge* v1 DNSCNC channel traffic to
default-configured implants — this is a symmetric-secret compromise, not only a confidentiality
loss.

### 5.3 A full TLS certificate **and its private key**

`DEFAULT_SSL_BIND_CERT` [source: `:47-69`] and `DEFAULT_SSL_BIND_KEY`
[source: `:70+`, begins `-----BEGIN PRIVATE KEY-----`] are a matching certificate/key pair
committed to the repo.

Certificate subject, decoded from the base64 DER:

```
C=FR  ST=POU  L=JAIUY  O=LOLITA  OU=S COMME ?
```

Validity window, from the ASN.1 times in the DER (`Fw0xNjA3MTUxODQyMTNaFw0xOTA0MTExODQyMTNa`):
**2016-07-15 18:42:13Z → 2019-04-11 18:42:13Z**.
[source: `:51-52`]

The subject is joke filler from an interactive `openssl req` session ("POU", "JAIUY", "LOLITA",
"S COMME ?") — the defaults were never replaced.

**Two consequences, and both matter:**

1. **A publicly-known TLS private key.** Any default-Pupy SSL listener can be passively
   decrypted by anyone holding this repository, and MITM'd with a valid certificate for the
   expected key.
2. **The certificate expired on 2019-04-11** — over seven years ago. Every default-configured
   Pupy SSL listener still presents it. Modern clients reject it outright, and it is a
   high-signal static indicator for anything that does not.

### 5.4 What this means structurally

The pattern is consistent across all three: **Pupy ships working default credentials for every
channel that needs one, and the defaults are in the public repo.** The `[listeners]` config
(§4.1) enables those channels by default, and `[rubber_ducky] encoder_path = TO_FILL`
[source: `pupy.conf.default:200`] shows the authors *did* use placeholders when they wanted an
operator to fill something in.

So the defaults are not an oversight in the same sense — `TO_FILL` proves the pattern was
available. The cryptographic defaults were chosen to make the framework work out of the box,
and the cost was that the shipped secrets are not secrets.

For an operator this is a **footgun**: build a payload without overriding the credentials and it
is decryptable and forgeable by anyone. For a defender it is a **gift**: the private keys and
certificate are durable, high-confidence indicators.

**Not verified:** `DEFAULT_RSA_PUB_KEY` [source: `:32-46`, a 2048-bit RSA public key] is present
but was not analysed — a public key alone discloses nothing, and whether the matching private
key exists elsewhere in the tree **was not checked**.

---

## 6. ECPV construction and the credvault KDF

### 6.1 ECPV is ECIES-style, not plain ECDH

**Source:** `pupy/network/lib/transports/cryptoutils/ecpv.py` (412 lines)

Two distinct operations live in this class and they should not be conflated:

**(a) `pack` / `unpack` — the ECIES-style encrypt path.** Both derive their AES key the same way:

```python
# pack()   ecpv.py:196, 206
key = self._mgf2(ec2osp(R), 16)

# unpack() ecpv.py:227, 243
key = self._mgf2(ec2osp(R), 16)
```

**The derived key is fixed at 16 bytes (AES-128)** regardless of the curve size.
[source: `ecpv.py:206`, `:243`; `AES_BLOCK_SIZE` also used as the default at `:110`, `:123`,
`:252`, `:264`] So a P384R1 keypair still yields an AES-128 perimeter — the curve strength
governs the *asymmetric* leg, not the symmetric one.

`_mgf2` is a hash-counter MGF [source: `ecpv.py:173`], matching the standard MGF1 construction.

**(b) `generate_kex_request` / `process_kex_request` / `process_kex_response` — real ECDH.**

```python
# process_kex_response, ecpv.py:272-274
key = self._mgf2(ec2osp(P1 * self._kex_private_key), key_size)
self._kex_shared_key = (key, _reversed_bytes(key))
return self._kex_shared_key
```

[source: `ecpv.py:272-274`]

**This is the mechanism behind EC4's twin RC4 streams.** The shared key is computed once, then
stored as a **pair: `(key, reversed_bytes(key))`**. The two directions are not independent keys —
**they are the same key bytes in reverse order.** An observer who recovers one direction's key
recovers the other by reversing it. [source: `ecpv.py:273`]

The mirrored form appears in `process_kex_request` too — `self._kex_shared_key =
list(x for x in reversed(self._kex_shared_key))` at `:259` — and the accessors pick direction by
index: `_kex_shared_key[0]` at `:295`, `:311` and `[1]` at `:279`, `:334`
[source: `ecpv.py:278-334`].

There is also a **KEX response cache** — `if request == self._cached_kex_request and
self._kex_shared_key: return self._cached_kex_response, self._kex_shared_key`
[source: `ecpv.py:253-254`]. A repeated identical KEX request is answered from cache rather than
recomputed. Worth noting for anyone reasoning about replay behaviour.

### 6.2 The credvault uses iterative MD5 as its KDF

**Source:** `pupy/pupylib/PupyCredentials.py`

Pupy stores generated credentials in a local file, optionally encrypted:

```python
def derive_key_and_iv(self, salt, key_length, iv_length):
    ...
    d_i = md5(d_i + self.password + salt).digest()
```

[source: `PupyCredentials.py:173-176`; `from hashlib import md5` at `:34`]

**Iterative MD5 as a key-derivation function.** This is a local-file protection mechanism rather
than a wire protocol, so its exposure is limited to an attacker with the operator's file — but
MD5-based iteration is a weak KDF by any modern standard, and it is inconsistent with the
framework's own use of SHA3-256/512 on the transport side. Recorded as a factual weakness in an
otherwise deliberate design.

The file is written with owner-only permissions — `chmod(self._configfile, 0o600)` at `:629`,
content serialised via `json.dumps` at `:631`. So the plaintext path is at least permission-
guarded on POSIX.

---

## 7. Unverified binaries in the tree

Two genuine compiled artefacts exist and were **not** analysed:

| File | Size | Note |
|---|---|---|
| `pupy/packages/windows/amd64/vidcap.pyd` | 17,920 B | screen/audio capture extension |
| `pupy/packages/windows/x86/vidcap.pyd` | 14,848 B | 32-bit build |

These are the **only `[binary]` evidence available for the entire Pupy target.** Everything else
in this report is `[source]`.

A `.pyd` is a Windows DLL loaded directly by the embedded CPython interpreter — and because Pupy
embeds CPython, this is a native module running inside the implant process. It was not opened in
Ghidra, so **nothing about the capture implementation (framing, compression, resolution limits,
audio path) is known from this report.**

This is a real coverage gap and is listed again in §9. It is the single most valuable remaining
piece of work on this target, because it is the only place binary-level evidence exists.

---

## 8. The C loader

Pupy's loader is `client/` plus a compiled reflective loader stub that embeds CPython.

**Status: NOT completed.** The `client/` directory exists but the loader's C internals
(interpreter embedding, reflective loading, in-memory module extraction, AMSI interaction on
Windows) were **not read in this pass**. This is the single largest gap in T7 — er, in T6.

---

## 9. Cross-target comparison — where Pupy sits

| Dimension | Pupy (T6) | Havoc (T5) | Sliver (T1) |
|---|---|---|---|
| Platform | Cross-platform (Win/Linux/macOS/Android) | Windows-focused | Cross-platform |
| Implant language | **Python (embedded CPython)** | C + ASM | Go |
| Bulk cipher | RC4 (drop 3072) | AES-256-CTR | *(not yet recovered from client)* |
| KEX | ECPV multi-curve (P160/224/384) / ECDH / RSA-AES | AES key in cleartext at registration | *(pending)* |
| Transport obfuscation | **obfs3 (Tor) + WebSocket + HTTP wrap** | profile-driven HTTP headers/URI/UA | gRPC / WireGuard / HTTP |
| Sleep/jitter | jitter in KEX response | SleepDelay + SleepJitter fields | Beacon Interval + Jitter |
| Architecture | rpyc over swappable transport | thin Go router + fat C agent | Go client + Go implant |
| Shipped default credentials | **yes — password, DNSCNC priv key, TLS cert+key all in repo** | none found | n/a (operator client) |

**The distinctive Pupy contribution** is the transport stack and the embedded-interpreter
approach. Its crypto is the **weakest** of the three (RC4 by spec, not by accident) while its
**traffic obfuscation is the strongest** (obfs3 is a genuine anti-fingerprinting tool). Those
two facts sit together oddly and are worth stating plainly: Pupy optimised for *not looking
like C2 on the wire* rather than for *cryptographic strength*.

**The shipped-default-credentials row is the differentiator nobody expects.** No other target in
this corpus commits working private keys. Pupy does — three separate channel credentials, one of
which is a TLS private key for a certificate that expired in 2019. That is simultaneously the
framework's biggest operational liability and the single best detection gift in the mission.

---

## 10. Residual unknowns — explicit

**RESOLVED since the first draft of this report** (recorded so the record shows what changed):

- ~~`ecpv.py` read only for its first 60 lines~~ — **now read to line 274.** The `pack`/`unpack`
  ECIES-style construction and `process_kex_response` are confirmed at source: `key =
  _mgf2(ec2osp(R), 16)` at `:206`/`:243`, and `_kex_shared_key = (key, _reversed_bytes(key))` at
  `:273`. The "ECIES / EC ElGamal s,r" characterisation is now **confirmed, not inherited.**
- ~~`PupyCredentials.py` surfaced by pattern match but not read~~ — **now read.** The ECPV
  keypair curve assignments (`:254`, `:356`, `:415`) and the iterative-MD5 credvault KDF
  (`:173-176`) are confirmed at source.
- ~~The C loader is the single largest gap~~ — still unread, but **the `vidcap.pyd` binaries are
  now known to exist and are a more tractable gap** (§7).
- ~~`conf/pupy.conf.default` not examined~~ — **read in full** (§4): 202 lines, 18 sections,
  listener port table, `OneDriveUpdate` persistence name.
- ~~No shipped-credential analysis~~ — **completed** (§5).

**REMAINING unknowns:**

1. **The C loader was not analyzed.** Interpreter embedding, reflective load, in-memory module
   extraction, Windows loader specifics — all unread. Still the largest gap.
2. **`vidcap.pyd` (amd64 17,920 B / x86 14,848 B) was not opened in Ghidra.** These are the only
   `[binary]` evidence for this target and the capture implementation is unknown. **Highest-value
   remaining work on T6.**
3. `ecm.py` (5.5 KB) ECC transport was not read; only EC4 was analyzed in depth. ECM is presumed
   to share the ECPV/RC4 family but this was **not verified**.
4. `websocket.py` (15.5 KB) and `http.py` (13.5 KB) were not read — listed from the file
   inventory only.
5. `obfs3_dh.py` was not read; the obfs3 claim rests on the module presence, the docstring at
   `obfs3.py:5`, and the class definition at `:38`.
6. **The DNSCNC channel is largely unanalysed.** `conf/pupy.conf.default` has a `[dnscnc]` section
   (`:54`) and `allow_v1 = true` was reported by a teammate but **I did not verify that line
   myself** — treat the v1-legacy-enabled claim as **unconfirmed**. Related files
   (`dns_encoder.py` ~38 KB, `dns_encoder_table.py` ~22 KB) were not read.
7. **`picocmd` framing is reported but only partly verified.** A teammate reported
   `[CRC32 4][cmd_id 1][payload]` framing with `ParcelInvalidCrc` rejection; I confirmed the
   exception classes exist (`picocmd.py:23-24`) and that `Parcel.pack` exists (multiple
   definitions, `:215`+), but **did not read the framing implementation line-by-line.** If it
   holds, a bare CRC32 is not a MAC — but that conclusion depends on the unverified detail.
8. Modules directory (post-exploitation capability inventory) was **not enumerated**.
9. `DEFAULT_RSA_PUB_KEY` (`network/transports/__init__.py:32-46`) present but not analysed; the
   matching private key was not searched for.
10. No dynamic/runtime evidence: no execution, no capture, no device.

**Note on the zero-byte file.** `pupy/network/lib/transports/__init__.py` is a **0-byte file** in
this tree, while `pupy/network/transports/__init__.py` is the populated 130-line module. Whether
this is upstream or an artefact of the clone was **not determined** — `git status` on the path
returned no modification marker and `git cat-file -s` against HEAD reported 0, which indicates
the empty file is **committed upstream**, not locally damaged. Recorded because it is a real
trap for anyone searching this tree.

---

## 11. Reproducing this

```powershell
$p = "C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\pupy"
# transports
Get-ChildItem "$p\pupy\network\lib\transports" -File -Filter *.py
# crypto core
Get-Content "$p\pupy\network\lib\transports\cryptoutils\ecpv.py"
# EC4 (the analyzed transport)
Get-Content "$p\pupy\network\lib\transports\ec4.py"
# transport enumeration in the operator CLI
Select-String -Path "$p\pupy\network\lib\picocmd\picocmd.py" -Pattern "obfs3"
```

---

## 12. CORRECTION NOTICE (appended after the DEEP pass)

The DEEP lane (`D6_pupy_code.md`, 163,503 B, §0–§12) reversed Pupy function-by-function with full
source access at 412 lines of `ecpv.py` and the whole tree linearly. It **contradicted seven claims
in this report.** Every correction below was independently re-verified by the Lead against raw
source before being recorded here. The original text is left in place above so the error is
auditable — a corrected report that hides what it got wrong is worth less than one that shows it.

### 12.1 Counts and locations — four errors

| This report said | Verified truth |
|---|---|
| **10 transports** | **13.** `dfws, ec4, ecm, http, kc4, obfs3, rsa, ssl, ssl_rsa, tcp_cleartext, udp_cleartext, udp_secure, ws` |
| **~576 `.py` files** | **509.** The brief also omitted **31 `.c`, 34 `.h`, 9 `.go`** entirely |
| `dnscnc` is a **package** holding the DNS encoders | **There is no `dnscnc` package.** `dnscnc` is a **launcher** (13,088 B). The encoders live in **`picocmd/`** — a whole unmapped third protocol stack (8 files, 173,581 B) |
| `ec4.py` lives in **`cryptoutils/`** | **`network/lib/transports/ec4.py`.** `cryptoutils/` holds only `aes.py, ecpv.py, pbkdf2.py, rc4.py, sha.py, xor.py` |

**A structural error underneath the last one, worth stating plainly:** there are **two transport
trees**, and conflating them is what produced the wrong path and the wrong count.
`pupy\network\lib\transports\` holds **8 files** (client side, plus `cryptoutils/`, `obfs3/`,
`obfscommon/`). `pupy\network\transports\` holds **13 packages**, each with **its own `conf.py`.**
The Lead made this exact mistake while verifying the DEEP lane and had to be corrected by the file
listing. Anyone reading this tree should start from the distinction.

### 12.2 Crypto — the derived-key characterization was wrong

This report's §2.2 table said the derived key is *"**128 bytes**, split into two 64-byte halves."*
**That is wrong.** The parameter is `key_size=128` — **bits** — at `ec4.py:65` and `:74`:

```python
response, key = self.encoder.process_kex_request(request[2:], 0, key_size=128)
key = self.encoder.process_kex_response(request[2:], 0, key_size=128)
```
`ec4.py:65`, `ec4.py:74`

So each RC4 key is **16 bytes**, not 64. The mechanism this report described — a single KEX output
split into two RC4 streams by **byte reversal**, with a **3072-byte keystream discard** on each —
**stands and is confirmed.** The *size* was off by 4×.

Also corrected: `ec4.py:57` uses **native byte order**, not a forced big-endian `>H` as an earlier
brief stated.

### 12.3 `allow_v1` — REFUTED, not merely unconfirmed

§10 item 6 correctly declined to assert `allow_v1 = true`, calling it unconfirmed. The DEEP pass
settled it the other way: **the key does not exist.** Zero tree-wide matches.

The real V1 mechanism is **three separate paths**, none of them a config flag:

1. `ENCODER_V1 = 0`, selected by `node.version == 1` (`server.py:335`, `:1109`)
2. a CLI flag (`commands/dnscnc.py:98`)
3. `SystemInfoEx._unpack_v1` (`picocmd.py:1307`, `:1355`)

Declining to assert this was the right call, and it is now closed in the negative.

### 12.4 New findings the DEEP pass produced that this report never had

- **`ecpv.py:221-224` — signature verification silently fails.** Big-endian `s` is NUL-padded on the
  **RIGHT**, so each pad byte multiplies by 256 instead of left-padding. `:230` reads it back and
  the signature fails to verify — **roughly 1 in 256 per leading zero byte.**
- **Signer/verifier asymmetry.** `pack` requires `t > 1` (`:216`); `unpack` accepts `t >= 0`
  (`:238`). The verifier is **strictly more permissive** than the signer — a malleability surface.
- **Replay-deterministic KEX guard** (`:253-254`): the same request returns the **cached** response
  and key. No nonce freshness.
- **`ws/conf.py` — static, nonce-free C2 path.**
  `path = '/ws/' + md5(PATH_GEN_SECRET+b"ws").hexdigest()[:8]` — **32 bits, no per-session nonce**,
  byte-identical in `client_transport_kwargs` and `server_transport_kwargs`. `^/ws/[0-9a-f]{8}$`
  matches every default `ws`/`dfws` beacon forever.
- **`DEFAULT_USER_AGENT` = Chrome `60.0.3112.90` claiming `Windows NT 6.1`** (Windows 7) — a 2017
  browser string. Exact-string IOC.
- **Checksum is key-prepended SHA-1, 4 bytes, non-HMAC** — length-extension, non-constant-time
  compare.
- **Windows persistence is NON-FUNCTIONAL as shipped** (see 12.5).

### 12.5 The persistence finding — and a correction to the Lead's framing

The Lead's own brief for the follow-up lane framed this as *"Sliver ships no persistence; Pupy ships
named persistence."* Reading `conf/pupy.conf.default:178-181` **confirms the config** —
`name = OneDriveUpdate` **and** `preferred_methods = 2,8,3,9` are both live. But chasing the module
the config drives produced the real finding:

> **`pupy/packages/windows/all/pupwinutils/persistence.py` does not exist.**

It is referenced four times — `scriptlets/persistence.py:9` (declared dependency), `:29`
(`from pupwinutils.persistence import add_registry_startup`), `:66-67` (the call and its error log)
— and **never committed.** The directory holds 15 files; there is no `persistence.py`. Windows
persistence raises `ImportError` at scriptlet load. **Linux persistence does ship**
(`packages/linux/all/persistence.py`, 13,088 B), and even there `modules/persistence.py:73` carries
`# TODO persistence removal` — **install-only, no uninstall.**

**Independently re-verified by the Lead:** `Test-Path` returns **False**; the directory listing has
15 files and no `persistence.py`; and `pupwinutils.persistence` is the **only dangling
`pupwinutils.*` reference in the entire tree** — every other `pupwinutils.*` resolves to a real file.
That last check is what upgrades this from "possible packaging quirk" to **verified
non-functional.**

So the accurate corpus-level contrast is: **Sliver deliberately ships no persistence at all; Pupy
ships persistence as a default-configured, named, OneDrive-masquerading feature and ships it broken
on Windows.** They fail in **opposite directions** — one by design, one by defect.

This is the **second time** checking existence rather than inference caught a real error in this
mission: the Lead earlier made the same class of mistake by grepping a 0-byte file and reporting a
negative result. Asserting content from a *reference* is the trap; verify the artifact exists first.

### 12.6 Two more DEEP findings

- **`dns_encoder.py:845` writes `TREES={}` via `repr()`** — which is why
  `dns_encoder_table.py` is **8 lines with one 22,289-character line**. It is machine-generated,
  not hand-written.
- **Huffman tables are retrained from the operator's own observed traffic** (`:747-838`), so a
  deployment's `TREES` may differ from the shipped ones. The shipped tables are a *default*, not a
  fixed fingerprint.
- **`dns_encoder.py:449-461` — the encoder writes a 3-bit table count (`len(tables) << 6`) while the
  decoder masks with `0b11` (2 bits).** Asymmetric. Safe only because `:446` caps `rsplit` at 3. The
  code contradicts its own format comment.
- **`agent/__init__.py:612`** — `PupyPackageFinder` subclasses the private
  `_bootstrap_external._LoaderBasics`. That is a concrete reason the loader is **version-locked to
  CPython 3.10**, not merely a preference.
- **AMSI: reasoned NEGATIVE.** Zero grep matches, and inapplicable by architecture — no .NET,
  bytecode-only execution, and `MemLoadLibrary` bypasses `LoadLibrary` hooks anyway.

### 12.7 What still stands unchanged

The core of this report survives the DEEP pass and is **confirmed**: the ECPV multi-curve perimeter
and the substring-match hash ladder (`:73-74`); `ec4.py:37-47`'s explicit
`ECPV(brainpoolP384r1, hash=SHA384)` as the **only** bypass of that ladder; the RC4-per-direction
design with a 3072-byte discard citing the leaked CIA NOD requirements; the shipped working default
credentials (bind password `PuPyD3f4ultP4sSw0rd`, DNSCNC private key, TLS cert + key, cert expired
2019-04-11); the iterative-MD5 credvault KDF (`PupyCredentials.py:173-176`); and the strong
anti-fingerprinting posture of obfs3 and WebSocket.

**The §2.3 analysis of the hash ladder is the most important thing in this report and it is
correct** — including that `'224'` and `'256'` map to the **same** `SHA3_256` branch (dead
differentiation), and that the default `brainpoolP160r1` → `SHA1` passes the `:87-96` digest-size
gate by **exactly zero margin.**

### 12.8 Residual unknowns (from D6 §10, carried forward)

Seven, enumerated rather than papered over: **U-1** picocmd's exact wire format (`picocmd.py`
1,828 lines) — *T6's `[CRC32 4][cmd_id 1][payload]` claim remains unverified and is now under
follow-up*; **U-2** transport swap (verified **negative** in `connection.py` — only
`CONTROL_ENABLE_BRINE_EXT_V1` ack-negotiation exists, no swap function); **U-3** retrained Huffman
tables; **U-4** remaining `client/` C; **U-5** `security.py` (78,800 B) read as size only;
**U-6** `ecm.py` vs `ec4.py`; **U-7** `rsa_aes.py`.
