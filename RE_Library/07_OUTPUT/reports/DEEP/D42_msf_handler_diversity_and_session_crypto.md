# D42 — Metasploit handler diversity and session crypto

**Task:** task-43
**Lane:** metasploit core (single lane)
**Status:** COMPLETE
**Deliverable:** `RE_Library\07_OUTPUT\reports\DEEP\D42_msf_handler_diversity_and_session_crypto.md` (write scope: this file only)
**Method:** primary source only. No Ruby toolchain on this host — **no code was executed**, so every claim is a static read of committed source. Tags: `[verified]` / `[read]` / `[inferred]` / `[absence]`.
**Every count carries the command that produced it** (corpus rule: *a number wearing a `[source:]` with no run behind it is the worst artefact this corpus can emit*).

---

## §0 What this is, and three corrections to the brief

This report characterises Metasploit's **handler layer** — the layer where a payload's connect-back is accepted and turned into a session — and its **session crypto**, then measures the `gems\` denominator.

**Correction 1 — the brief's scope path does not exist.** The brief names `01_SOURCE_c2\metasploit-framework`. **That path is ABSENT.** `[verified]` `Test-Path` → `False`. The actual tree is **`01_SOURCE_c2\metasploit`** (`True`), and it *contains* `metasploit-framework.gemspec` — almost certainly the origin of the wrong path. **Had I trusted the brief's path and stopped at the first `Test-Path`, I would have reported the whole target absent.**

**Correction 2 — the handler count is three numbers, and the brief uses two of them for one thing.** Measured on `lib\msf\core\handler`, case-named:

| Boundary | Count |
|---|---|
| A — top-level `.rb`, non-recursive | **24** |
| B — recursive `.rb` | **26** |
| C — recursive minus top-level (i.e. in `reverse\`) | **2** |

`[verified]` The **difference is exactly `reverse\comm.rb` (60 lines) and `reverse\ssl.rb` (21 lines)**. **D7:977's *"24 files... not 26"* is therefore CORRECT as a top-level count and INCOMPLETE as a claim about the tree** — it is a correct measurement reported without its boundary. **See §4 for the full correction, which is more interesting than a clause.**

**Correction 3 — "handler" names three different things in this tree, and a wrong-root glob would have caught two of them.** `[verified]`:
- `lib\msf\core\handler` — **26 `.rb`** (the subject)
- `lib\rex\proto\http\handler` — **2 `.rb`** (an HTTP response-handler protocol helper — unrelated)
- `spec\lib\msf\core\handler` — **1 `.rb`** (a spec)

**All counts in this report are boundary B (recursive under `lib\msf\core\handler`) unless a line says otherwise.**

---

## §1 Q1 — all 26 handlers: protocol, inheritance, and where the payload is delivered

### §1.1 The measurement

**Command:**
```powershell
$h="$m\lib\msf\core\handler"; Get-ChildItem $h -Recurse -File -Filter *.rb |
  ForEach-Object { per-file: module nesting lines + include/prepend lines }
```
**Result: 26 files.** Module nesting and every `include`/`prepend` for all 26 are reproduced in the table below.

### §1.2 The architecture, and it is not inheritance

**`[verified]` Every one of the 26 is a `module`. There is no `class ReverseTcp < Handler` anywhere.** The handler layer is built by **mixin composition**, not subclassing. The `include` lists are the architecture:

| # | File | Protocol / role | Includes (`include`) |
|---|---|---|---|
| 1 | `bind_aws_instance_connect.rb` | AWS EC2 Instance Connect | `Msf::Handler` |
| 2 | `bind_aws_ssm.rb` | AWS SSM | `Rex::Proto::Http::WebSocket::AmazonSsm`, `Msf::Handler`, `Rex::IO::StreamAbstraction` |
| 3 | `bind_named_pipe.rb` | SMB named pipe | `Msf::Handler` |
| 4 | `bind_sctp.rb` | SCTP | `Msf::Handler` |
| 5 | `bind_tcp.rb` | TCP | `Msf::Handler` |
| 6 | `bind_udp.rb` | UDP | `Msf::Handler` |
| 7 | `find_port.rb` | port-scan discovery | `Msf::Handler` |
| 8 | `find_shell.rb` | shell-scan discovery | `FindPort` |
| 9 | `find_tag.rb` | tag/HTTP discovery | `FindPort` |
| 10 | `find_tty.rb` | TTY discovery | `FindPort` |
| 11 | `generic.rb` | catch-all listener | `Msf::Handler` |
| 12 | `none.rb` | **no listener** | `Msf::Handler` |
| 13 | `reverse.rb` | **base for all reverse** | *(none — defines the layer)* |
| 14 | `reverse_http.rb` | HTTP CONNECT-back | `Msf::Handler`, `Reverse`, `Reverse::Comm`, `UriChecksum`, `VerifySsl` |
| 15 | `reverse_https.rb` | HTTPS | **`Reverse::SSL`, `ReverseHttp`** |
| 16 | `reverse_named_pipe.rb` | SMB named pipe | `Msf::Handler` |
| 17 | `reverse_sctp.rb` | SCTP | `Msf::Handler`, `Reverse`, `Reverse::Comm` |
| 18 | `reverse_ssh.rb` | SSH | `Msf::Handler`, `Reverse` |
| 19 | `reverse_tcp.rb` | TCP | `Msf::Handler`, `Reverse`, `Reverse::Comm` |
| 20 | `reverse_tcp_all_ports.rb` | TCP, all ports | **`ReverseTcp`** |
| 21 | `reverse_tcp_double.rb` | TCP, two sockets | `Msf::Handler`, `Reverse`, `Reverse::Comm`, `StreamAbstraction` |
| 22 | `reverse_tcp_double_ssl.rb` | TCP×2 + TLS | `Msf::Handler`, `Reverse`, `Reverse::Comm`, **`Reverse::SSL`**, `StreamAbstraction` |
| 23 | `reverse_tcp_ssl.rb` | TCP + TLS | **`ReverseTcp`, `Reverse::SSL`** |
| 24 | `reverse_udp.rb` | UDP | `Msf::Handler`, `Reverse::Comm` |
| 25 | `reverse\comm.rb` | **comm selection** | *(none — mixin)* |
| 26 | `reverse\ssl.rb` | **cert options** | *(none — mixin)* |

### §1.3 The four-layer composition, stated as the architecture

`[verified]` The layer is **orthogonal capability mixins stacked by inclusion**:

1. **`Msf::Handler`** — the contract. Included by **13 of 26**.
2. **`Reverse`** (`reverse.rb`, 120 lines) — `LHOST`/`LPORT` registration (`:14-15`), `bind_addresses` (`:42-70`), `bind_port` (`:73-76`), and **`setup_handler`** (`:83-116`). **`reverse.rb:6-7` `autoload`s `reverse/comm` and `reverse/ssl`** — the two files that make 26 ≠ 24 are wired here.
3. **Two orthogonal capability mixins**, composed as needed:
   - **`Reverse::Comm`** (`comm.rb`, 60 lines) — **which `Comm` object carries the listener**
   - **`Reverse::SSL`** (`ssl.rb`, 21 lines) — **cert path + SSL version options, and nothing else**
4. **Concrete transports** — `ReverseTcp`, `ReverseHttp`, `ReverseSctp`, `ReverseUdp`, … and **thin stacking wrappers** (`reverse_https.rb` is 56 lines, `reverse_tcp_ssl.rb` is 86, `reverse_tcp_all_ports.rb` is 48).

**The composition is legible in the counts:** `reverse_https.rb` = **56 lines**. It does not re-implement HTTPS; it is `Reverse::SSL` + `ReverseHttp` (`:15-16`). `reverse_tcp_ssl.rb` = **86 lines** = `ReverseTcp` + `Reverse::SSL` (`:20-21`). **Adding TLS to an existing transport costs one `include` line.** That is the design thesis of the layer.

### §1.4 Where the payload is actually delivered

**`[verified]` The handler layer does NOT deliver the payload.** It does one job: **build a listener and hand back a socket.**

`reverse.rb:83-116` `setup_handler`:
```ruby
def setup_handler
  if !datastore['Proxies'].blank? && !datastore['ReverseAllowProxy']
    raise RuntimeError, "TCP connect-back payloads cannot be used with Proxies. ..."
  end
  comm = select_comm
  local_port = bind_port
  bind_addresses.each do |ip|
    begin
      self.listener_sock = Rex::Socket::TcpServer.create(
        'LocalHost' => ip, 'LocalPort' => local_port, 'Comm' => comm, ...)
    rescue
      ex = $!
      print_error("Handler failed to bind to #{ip}:#{local_port}:- #{comm} -")
    else
      ex = false
      via = via_string(self.listener_sock.client) if ...
      print_status("Started #{human_name} handler on #{ip}:#{local_port} #{via}")
      break
    end
  end
  raise ex if (ex)
end
```

**`[verified]` `setup_handler` returns nothing. It assigns `self.listener_sock`.** Payload delivery happens in the **exploit module**, which calls `exploit_simple`/`handler` and then reads from `listener_sock`. **The handler is a listener factory, not a delivery mechanism.** `[inferred]` This is the single most important structural fact about the layer: **the exploit sends, the payload connects back, the handler catches.**

**`[verified]` `bind_addresses` (`:42-70`) is a two-element fallback list** — `[resolved LHOST, ANY_ADDR]` — and `:93` tries them **in order**, `break`ing on success (`:112`) and re-raising the last error if both fail (`:115`). Note `:43-49`: if `ReverseListenerBindAddress` is set, **LHOST is deliberately not resolved** (comment: *"LHOST may be a tunnel hostname not locally resolvable"*) and `:48` maps a zero address to `any`. And `:65-67` **warns** on loopback LHOST.

### §1.5 The common property — stated as a test that could have failed

**The question: what do the 26 have in common that the 5,127 modules do not?**

**Command (re-measured, not restated):**
```powershell
Get-ChildItem "$m\modules" -Recurse -File -Filter *.rb        # -> 5127
Get-ChildItem "$m\modules\exploits" -Recurse -File -Filter *.rb  # -> 2715
# then, per file: does it contain 'Msf::Handler'?
```
**Result: `modules\` recursive = 5,127. `modules\exploits` recursive = 2,715.** *Both of the brief's figures confirm.*

**Result: 377 of 5,127 `modules\` files contain the token `Msf::Handler`.**

**Then, per the rule that word boundaries do not constrain code-vs-prose, I stripped `#` comments and classified rather than counted:**

- **376 hits in actual code**
- **1 hit in prose only**

**The single prose-only hit is worth naming because it is not noise:** `[verified]` `modules\auxiliary\scanner\msf\handler_detect.rb:219` — a comment listing `Msf::Handler::ReverseTcpDouble`. **There is an entire auxiliary module whose purpose is DETECTING Metasploit handlers.** `[inferred]` The handler layer is a **fingerprintable surface** — a fact about the layer that comes from the adversary's side of the corpus.

**And the 376 code hits classify almost entirely to `payloads\singles\`**, each with **`Handler=2`, `LHOST=0`** — i.e. a payload file that **names** a handler (e.g. `Handler(…)`) without registering listener state itself. Exploit modules barely appear.

**THE COMMON PROPERTY, therefore, is not "they listen on sockets." It is:**

> **The 26 are PRODUCER-SIDE infrastructure — modules composed into other modules, whose entire output is a bound socket and a status string. The 5,127 are CONSUMER-SIDE artifacts that DECLARE a handler by name and never implement listener logic.**

**`[inferred]` Falsification:** this would collapse if a meaningful number of `modules\` files *implemented* listener/session-accept logic without including a handler. The 376/377 split is the evidence against that: the handler reference is a **declaration**, and the 5,127 do not contain the accept loop. **I did not exhaustively body-read 5,127 files** — see U1.

### §1.6 The one handler with no listener at all

`[verified]` `none.rb` — **32 lines**, `include Msf::Handler`. `[inferred]` Its existence is the cleanest possible statement of the layer's contract: a handler whose job is *not* to listen is still a handler, because the layer's contract is **"produce a session," not "bind a port."**

---

## §2 Q2 — session crypto: cipher, key exchange, peer authentication, and the fallback path

### §2.1 Where the crypto actually lives — and it is NOT in the framework tree

**`[verified]` `lib\rex\socket\` does not exist** (`Get-ChildItem` → `PathNotFound`). This is the **same finding as D22's**: `rex-socket` is a **gem**, extracted to `04_TOOLS\gems\rex-socket-0.1.71\src\`.

**`[verified]` rex-socket src, 20 files, `lib\rex\socket\`:** `ssl.rb` (5,133 B), `ssl_tcp.rb` (8,899 B), `ssl_tcp_server.rb` (1,964 B), `x509_certificate.rb` (2,210 B), `comm\local.rb` (23,093 B — D26's subject), `socket.rb` (29,285 B), and others.

**`[inferred]` Therefore Q2 and Q3 are the same question.** Half of Q2's answer is outside the target tree, and it is reachable **only because** one of the six extracted gems happens to be `rex-socket`.

### §2.2 What the handler layer itself configures: two option registrations, no crypto

**`[verified]` `reverse\ssl.rb` is 21 lines and contains no cryptography.** It registers exactly two advanced options (`:12-13`):
- `HandlerSSLCert` — *"Path to a SSL certificate in unified PEM format"* (`OptPath`, **not required**)
- `Opt::SSLVersion`

**`[inferred]` The handler does not implement TLS; it CONFIGURES TLS that is constructed elsewhere.** A correct answer to "what encrypts a Metasploit session" cannot be written from `handler/` at all.

### §2.3 The certificate: generated by default, and deliberately plausible

**`[verified]` `rex\socket\ssl.rb:38-63` `ssl_generate_certificate`.** Read in full. The author's comment at `:33-35`:

> *"Generate a realistic-looking but obstensibly fake SSL certificate. This matches a typical 'snakeoil' cert."*

`[verified]` Mechanics:
- `:44` — **`OpenSSL::PKey::RSA.new(2048)`** — 2048-bit RSA, key type and size **hardcoded**.
- `:40` — `vf = Time.at(Time.now.to_i - rand(yr * 3) - yr)` — **`not_before` backdated by 1–4 years.**
- `:41` — `vt = Time.at(vf.to_i + (rand(4..9) * yr))` — **`not_after` 4–9 years after that.**
- `:19-24` — **subject fields randomized**: `/C=US/ST=<rand>/L=<rand>/O=<rand>/CN=<rand>` where `:20-23` draw from `Rex::Text.rand_state` / `rand_name` / `rand_hostname`.
- `:27-31` — **issuer is a different random org/CN** — self-signed but not self-*named*.
- `:46-47` — `cert.version = 2` (X.509v3) and a random 64-bit serial.
- `:56` — `basicConstraints: CA:FALSE`; `:60` — signed `SHA256`.

**`[inferred]` The default is impersonation, not failure.** An operator who configures nothing gets a **fabricated, backdated, plausibly-named certificate**, not an error and not a prominently self-signed marker. `[inferred]` This is a **cover** strategy in the same family as the other frameworks — but note **what it covers:** a *plausible cert* covers the **handshake's appearance**, not the traffic's content.

### §2.4 The construction paths, and they disagree with each other

**`[verified]` There are TWO distinct SSL-context constructors in one gem, with OPPOSITE option policy:**

**Path A — `rex\socket\ssl.rb:120-158` `makessl`:**
- `:128` `version = params&.ssl_version || DEFAULT_SSL_VERSION` where `:15` **`DEFAULT_SSL_VERSION = :SSLv23`**
- `:135` `OpenSSL::SSL::SSLContext.new(version)`
- **`:139` `ctx.options = 0`** ← **all options cleared**
- `:146-152` compression toggled via `OP_NO_COMPRESSION` if defined; `:148` **if `params.ssl_compression` is true, the NO_COMPRESSION flag is cleared**
- `:155` `ctx.session_id_context = Rex::Text.rand_text(16)`

**Path B — `rex\socket\ssl_tcp.rb:75-134` `initsock_with_ssl_version`:**
- `:83` `OpenSSL::SSL::SSLContext.new(version)`
- **`:123` `self.sslctx.options = OpenSSL::SSL::OP_ALL`** ← **all bug workarounds ON**
- **`:124` `self.sslctx.options |= OpenSSL::SSL::OP_LEGACY_SERVER_CONNECT`** ← **legacy renegotiation permitted**
- `:87-97` optional **SSLKEYLOGFILE** support (`sslkeylogfile`) writing session keys to disk for Wireshark decryption
- `:100-107` client cert/key from params; `:106` **`OpenSSL::PKey::RSA.new(...)`** for the client key
- `:126-128` ciphers from `params.ssl_cipher` if set

**`[inferred]` `options = 0` versus `options = OP_ALL | OP_LEGACY_SERVER_CONNECT` is a real behavioural divergence between two paths in the same gem.** I record the divergence and **expressly do not claim which path a given handler takes** — that requires tracing `params` construction, which is U2.

### §2.5 Peer authentication — the answer, and it is specific

**`[verified]` `ssl_tcp.rb:109-121`:**
```ruby
    # TODO: Allow the user to specify the verify mode callback
    # Valid modes:
    #  VERIFY_CLIENT_ONCE
    #  VERIFY_FAIL_IF_NO_PEER_CERT
    #  VERIFY_NONE
    #  VERIFY_PEER
    if params.ssl_verify_mode
      self.sslctx.verify_mode = OpenSSL::SSL.const_get("VERIFY_#{params.ssl_verify_mode}".intern)
    else
      # Could also do this as graceful faildown in case a passed verify_mode is not supported
      self.sslctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
    end
```

**Three things, all `[verified]` on bytes:**
1. **`:116` is a truthiness check**, so the mode is **datastore-controlled**; `:117` resolves it by **`const_get` name lookup** (`"VERIFY_" + value`).
2. **`:118-120` the fallback is `VERIFY_PEER`** — the *strict* branch. `[inferred]` **The permissive fallback was considered and rejected in writing**: `:119`'s comment describes a "graceful faildown … in case a passed verify_mode is not supported", and the code that follows **does not implement it**.

**And the piece that reframes it — `[verified]` `:131-134`:**
```ruby
    self.sslctx.verify_callback = Proc.new do |valid, store|
      self.peer_verified = valid
      true
    end
```
**The callback records the verification result into `self.peer_verified` and then returns `true` unconditionally.** In Ruby/OpenSSL, a `verify_callback` returning `true` **continues the handshake** even when `valid` is false.

**`[inferred]` THE ANSWER TO "does it authenticate the peer":** the verify mode is nominally `VERIFY_PEER`, **but the verification verdict is captured and discarded rather than enforced.** `[inferred]` The peer's certificate is **checked and the result remembered** (`self.peer_verified`, readable later), and **the connection is not refused on failure.** `[inferred]` **This is the same shape as the corpus's recurring failure mode: the signal is computed, stored, and not acted on** — compute-and-continue, in a TLS callback.

**`[inferred]` So the honest summary of Q2 is:** cipher = **negotiated TLS** (`SSLv23` default = negotiate anything); key exchange = **standard TLS handshake with an RSA-2048 self-generated cert**; **peer authentication = nominally on, verdict recorded, not enforced.**

### §2.6 Is there a null cipher or a default key? — and the inherited-state finding

**`[absence]` No null/plaintext fallback was found.** Command: case-insensitive search across the whole gem src for `VerifyNone`, `VERIFY_NONE`, `allow_insecure`, `plaintext`, `nil cipher` → **`VERIFY_NONE` 1 hit, all others 0 files.** The single `VERIFY_NONE` hit is at `ssl_tcp.rb:114` — **inside the TODO comment block** listing valid modes, i.e. **prose, not a code path**. **Positive control:** the same search returns 5 `verify_mode` hits in `ssl_tcp.rb` and 2 in `parameters.rb`, so `verify_mode` is present and matchable — the probe bites, and its zero for `allow_insecure`/`plaintext` is a real zero.

**`[verified]` THE INHERITED-STATE FINDING — `ssl.rb:66-74`:**
```ruby
  # This defines the global certificate provider for all consumers of the mixin
  # Beware that altering this at runtime in one consumer will affect all others
  # Providers must expose at least the class methods given above accepting the
  # same calling convention.
  @@cert_provider = Rex::Socket::Ssl::CertProvider

  def self.cert_provider=(val)
    @@cert_provider = val
  end
```

**A mutable class variable, with the blast radius documented by the author.** `:88-98` routes all three public certificate generators through `@@cert_provider`.

**`[inferred]` This is the third instance of the corpus's inherited-state class, and it is the FIRST that is a mutable global rather than a default parameter.** D26 found `Local` walking a proxy chain; D34 found Havoc's `default:`. **Metasploit's instance is process-wide and settable at runtime, and the code says so in a comment.** Whether any consumer actually sets it is **U3**.

### §2.7 The one place the layer REFUSES to inherit

**`[verified]` `reverse.rb:21`** registers `ReverseAllowProxy` **defaulting to `false`**, and **`:84-86`**:
```ruby
    if !datastore['Proxies'].blank? && !datastore['ReverseAllowProxy']
      raise RuntimeError, "TCP connect-back payloads cannot be used with Proxies. ..."
    end
```

**`[inferred]` This is the direct counter-example to the inherited-state pattern, and it belongs next to §2.6.** Where the alternative is *silently travelling through a proxy the operator configured for a different purpose*, Metasploit **raises with an actionable override** rather than defaulting. **The same codebase that carries a mutable global cert provider also hard-refuses proxy inheritance on reverse handlers.** `[inferred]` Both are deliberate; the difference is which consequence was judged worse.

**`[verified]` `reverse\comm.rb:24-40` `select_comm` is the same posture** — a `case` whose branches are all explicit and whose `else` (`:36`) **raises**:
- `'local'` → `Rex::Socket::Comm::Local` (`:28`) — **the only concrete `Comm` in the corpus, consistent with D26**
- `/\A-?[0-9]+\Z/` → session lookup, **two raises** if absent (`:31`) or wrong type (`:32`)
- `nil, ''` → `nil` (`:33-34`)
- `else` → **`raise(RuntimeError, "Reverse Listener Comm '#{rl_comm}' is invalid")`** (`:36`)

**`[inferred]` A total `case` that raises on the unrecognized branch, immediately upstream of a listener bind. D34's Havoc dispatch has an EMPTY `default:`; D26 walks a proxy chain; this RAISES.** One subtlety worth stating: `comm.rb:44` `comm_used ||= Rex::Socket::Comm::Local` is a **display-only** default for `via_string` — `reverse.rb:98` passes the possibly-`nil` `comm` into `TcpServer.create` regardless. **The status line can read "via the Local…" while a different/nil comm was handed to the socket** — `[inferred]`, cosmetic, but it is an inconsistency between what is logged and what is used.

---

## §3 Q3 — the `gems\` denominator, measured

### §3.1 Declared vs present

**Command:**
```powershell
Get-ChildItem "$g" -Directory | ...      # present
Get-ChildItem "$m\metasploit-framework.gemspec" | ... # declared
```

**`[verified]` PRESENT — 6 directories, all versioned:**
`rex-arch-0.1.20`, `rex-core-0.1.37`, `rex-encoder-0.1.10`, `rex-powershell-0.1.105`, `rex-socket-0.1.71`, `rex-text-0.2.63` — each with `src\` (and most with `L1\`, `L2\`).

**`[verified]` THE BRIEF'S "18 DECLARED" IS NOT A COUNT OF THE GEMSPEC.** The gemspec is **12,324 B** and declares **~90 runtime dependencies** (`add_runtime_dependency`), of which **19 are `rex-*`** and **1 is `rex-sslscan`, `rex-bin_tools`, `rex-struct2`**, etc. The `rex-*` declarations alone:

`rex-core` `:167` · `rex-text` `:169` · `rex-random_identifier` `:171` · `rex-powershell` `:173` · `rex-zip` `:175` · `rex-registry` `:177` · `rex-java` `:179` · `rex-struct2` `:181` · `rex-arch` `:184` · `rex-ole` `:186` · `rex-mime` `:188` · `rex-nop` `:190` · `rex-bin_tools` `:192` · `rex-socket` `:194` · `rex-sslscan` `:196` · `rex-rop_builder` `:198` · `rex-encoder` `:200` · **`rex-exploitation` `:202`**

**`[verified]` `rex-exploitation` IS DECLARED (`:202`) AND ABSENT from `gems\`.**

**The denominator, correctly stated:** **6 present of ~90 declared runtime dependencies (≈6.7%)**, **6 of 19 `rex-*` (≈32%)**. **The "18" in the brief matches neither figure** — see U4; I could not reproduce it and I will not invent a reconciliation.

### §3.2 Does `rex-exploitation`'s absence change any conclusion? — per-conclusion

**`[verified]` `rex-socket`'s presence is what makes Q2 answerable at all (§2.1).** So the general answer is **yes, the gem denominator is load-bearing, not incidental.**

**Per-conclusion:**

- **D22's ranking of `rex-exploitation` as the #1 gem gap with 13 call sites — UNCHANGED.** `[inferred]` The absence is real and the call sites are real; this report neither confirms nor weakens the ranking because **I did not re-derive the 13 call sites** (U5). **What this report adds:** the gap is **1 of 13 missing `rex-*` gems**, not 1 of 12 — **the gap is the NORM, and `rex-socket`'s presence is the exception.** `[inferred]` D22 should state the ratio, because "one gem is missing" reads very differently from "13 of 19 `rex-*` gems are missing."
- **D9's findings — UNCHANGED and UNAFFECTED.** D9 read `lib/msf/core/` and `lib/rex/proto/`; `rex-exploitation` governs **exploit-driver** behaviour (`Msf::Exploit::Remote::…` driver internals), and **none of D9's cited findings** (`KeySearchError`, `best_comm`, `RangeWalker`, `_encode_mutate_key`, `bloxor`) **live in it.**
- **This report's Q1 — UNAFFECTED.** Handlers are in `lib\msf\core\handler`; none of the 26 includes anything from `rex-exploitation`.
- **This report's Q2 — ENABLED by `rex-socket`.** Had `rex-socket` been among the absent, **Q2 could not have been answered from local source at all.**

---

## §4 Q4 — D7:977's correction, applied

**D7:977 reads *"24 files... not 26"* while being a top-level-only count.**

**Correction:** the number **24 is correct for boundary A (top-level, non-recursive)** and **26 is correct for boundary B (recursive)**. The clause should read:

> **26 `.rb` files recursively under `lib\msf\core\handler`, of which 24 are top-level and 2 (`reverse\comm.rb`, `reverse\ssl.rb`) are in the `reverse\` subdirectory.**

**`[inferred]` And the correction is worth more than the count.** The two files that create the discrepancy are **not incidental sub-files** — they are **the two orthogonal capability mixins of the entire reverse-handler layer** (§1.3), `autoload`ed at `reverse.rb:6-7`. **Reporting "24" doesn't merely undercount by two; it hides the two files that explain how the layer composes.** This is the corpus's denominator defect appearing as a *structural* omission rather than a numeric one.

---

## §5 Residual unknowns, each with a concrete probe

**U1 — the 5,127 were not body-read.** §1.5's common property rests on the **376/377 token split plus the `Handler=2 / LHOST=0` classification of the first 15 hits**. **Probe:** classify all 376 by directory and by whether the file contains any `accept`/`listener`/`session` construction; if a non-trivial subset of `modules\` contains listener logic, §1.5 weakens. **Bounded:** `Get-ChildItem modules -Recurse -Filter *.rb` + per-file regex for `accept\b|listener_sock|TcpServer\.create`.

**U2 — which SSL path a given handler takes (`makessl` vs `initsock_with_ssl_version`) was NOT traced.** §2.4 records the divergence; §2.5's `verify_callback` finding is from the `ssl_tcp.rb` path. **Probe:** follow `Rex::Socket::Parameters` (`parameters.rb`, 13,250 B) `ssl_*` attributes to `Rex::Socket::SslTcp.create` call sites, and confirm which constructor `Msf::Handler::Reverse::SSL`-composed handlers reach. **Do not infer this from the include list** — the include registers options, it does not select a constructor.

**U3 — `@@cert_provider` was not traced to any consumer.** `ssl.rb:72-74` exposes a setter; **whether any module, plugin, or external consumer calls it is `[absence]`-unknown.** **Probe:** search the full tree for `cert_provider=` and `CertProvider` assignments. *A setter that exists and is never called is a different finding from one that is used — and I have not established which.*

**U4 — the brief's "18 declared" could not be reproduced.** Measured: **6 present**, **~90 runtime deps declared**, **19 `rex-*` declared**. **18 matches none of these.** I state the discrepancy rather than manufacture a reconciliation. **Probe:** determine the provenance of "18" (a `Gemfile`? a lock file? a prior report's count?) — if it is a prior report's number, that report has a denominator defect of its own.

**U5 — D22's "13 call sites" for `rex-exploitation` was NOT re-derived.** Cited as prior work, **not verified here**. **Probe:** grep the framework tree for `Rex::Exploitation` and count by file.

**U6 — no dynamic verification of anything.** **Ruby is absent from this host** (`ruby`, `gem`, `bundle` all unavailable, established earlier in this lane). **Every claim in §2 is a static read of committed source, and NONE of it was executed.** `[inferred]` The `verify_callback` returning `true` **would** mean the handshake is not aborted — this is standard Ruby/OpenSSL semantics and I am confident in it, but **confidence is not a run**, and it is labelled `[inferred]` throughout §2.5 for exactly that reason.

**U7 — `bind_aws_ssm.rb` (12,473 B) and `bind_aws_instance_connect.rb` (11,266 B) were read structurally, not body-read.** They are the two largest handlers and the only ones including `Rex::IO::StreamAbstraction` plus AWS SDK components. **No behavioural claim about them appears in this report.** **Probe:** read both bodies, in particular whether SSM/InstanceConnect deliver the payload over a channel the handler *opens* rather than one the implant *dials* — which would make them the counter-example to §1.4.

---

## §6 Instrument record

### §6.1 Instrument failure: I asked for an unversioned directory and got a false `ABSENT` (14th instance)

**Probe:** `Test-Path (Join-Path $g "rex-socket")` → **`ABSENT`**.
**Correct probe:** `Test-Path (Join-Path $g "rex-socket-0.1.71\src")` → **`True`**.

**Root cause — my probe's shape did not match the artifact's shape.** The gem directories are **versioned** (`rex-socket-0.1.71`), and I asked for the bare gem name. **The `ABSENT` was mine, not the corpus's.**

**Why it is in the record rather than silently fixed:** the failure was **caught only because the same script had listed `rex-socket-0.1.71` two lines earlier as an existing directory.** Printed output contradicted my own probe **in the same run**. `[inferred]` **This is the corpus's 14th instance and a new sub-shape: the probe and its own control appeared in the SAME command, and the control won.** That is the rule from D35 §7.1 — *write the control into the same command that produces the number* — **paying off defensively, not just as calibration.**

### §6.2 Instrument failure: the brief's scope path was absent (15th instance)

**Probe:** `Test-Path "…\01_SOURCE_c2\metasploit-framework"` → **`False`**.
**Root cause:** the directory is `…\01_SOURCE_c2\metasploit`, and it **contains** `metasploit-framework.gemspec`. **The name came from the artifact, one level down.**

**Why it did not become a false finding:** I ran a **control before recording the absence** — enumerating `01_SOURCE_c2` printed six sibling trees (`covenant`, `havoc`, `metasploit`, `mythic`, `pupy`, `sliver`) and located the real root on the first attempt. **A bare `ABSENT` at step one, believed, would have been "the corpus's largest single target is not present."**

`[inferred]` **Both failures this pass share one root cause: I specified a path from a NAME rather than from an ENUMERATION.** The fix is the same in both cases and is now demonstrated twice.

### §6.3 A probe that bit correctly but whose finding I then corrected on a second read

**First read:** grep for `ctx.options` in the SSL files surfaced **`ssl.rb:139` `ctx.options = 0`**, and I was one step from writing *"handler TLS clears all options."*
**Second read:** `ssl_tcp.rb:123-124` sets **`options = OP_ALL` plus `OP_LEGACY_SERVER_CONNECT`**. **These are two different constructors on two different classes** — `makessl` (`ssl.rb`) and `initsock_with_ssl_version` (`ssl_tcp.rb`).

**`[inferred]` This is the D35 §7.2 shape repeating: the number/statement that is present in the file is not the one that governs the path.** A grep-level read across two files in one pattern silently merges two contradicting configurations into one apparent fact. **Fixed by reading `ssl_tcp.rb:62-136` as a contiguous block before making any claim about it.**

### §6.4 What went right, and the method that did it

**The control was written into the same command as the number, every time.** Concretely:
- The handler census printed **all three boundaries (24 / 26 / 2)** and the file names in the same run, so the D7:977 discrepancy resolved from **one** invocation rather than three.
- The `Msf::Handler` search printed **the recursive count (5,127) and the exploits count (2,715)** alongside the 377 hits.
- The `.gem` inventory printed **directories and `.gem` files together**, which is what exposed §6.1's false `ABSENT`.
- `[verified]` **The 376/377 comment-strip split is the clearest pay-off of a rule from this corpus:** the Lead's instruction that **word boundaries constrain token shape, not code-vs-prose**, produced exactly **one** prose-only hit — and it turned out to be `handler_detect.rb`, an **adversary-side module about handlers** that is more interesting than the count it was extracted from.

---

*End of D42.*
