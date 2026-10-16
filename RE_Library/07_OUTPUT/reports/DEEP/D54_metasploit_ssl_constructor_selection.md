# D54 — Metasploit SSL constructor selection (closing D42's U2)

**Task:** task-56
**Lane:** metasploit core
**Status:** COMPLETE
**Deliverable:** `RE_Library\07_OUTPUT\reports\DEEP\D54_metasploit_ssl_constructor_selection.md` (write scope: this file only)
**Method:** pure source. **Ruby is absent on this host — nothing was executed.** Every claim below is a static read; runtime semantics that follow from Ruby/OpenSSL contracts rather than from a run are labelled `[inferred]`.
**Tags:** `[verified]` / `[read]` / `[inferred]` / `[absence]`. Every count carries its invocation.

---

## §0 What this is, and one correction that reframes the whole question

D42's U2 left unmeasured: **which of the two SSL-context constructors a composed handler reaches.** D42 §2.5's `verify_callback` finding came from `ssl_tcp.rb` and was explicitly **not** to be generalized. This report traces the selection and closes it.

**THE CORRECTION — and it is to the framing, not to D42's numbers.** The brief describes the two constructors as competing alternatives that "a handler gets." **They are not competing on the same object. They are two different MODULES:**

| Module | File | Role | Constructor |
|---|---|---|---|
| `Rex::Socket::SslTcp` | `ssl_tcp.rb:10` | **CLIENT** — `:6-7` *"SSL TCP client connection"* | `initsock_with_ssl_version` (`:75`) |
| `Rex::Socket::SslTcpServer` | `ssl_tcp_server.rb:13` | **SERVER** — *"SSL wrapped TCP server"* | `makessl` (`:47`) |

**`[verified]` The selection is not per-handler and not per-transport. It is CLIENT vs SERVER.** A handler *listens*, so it is on the server path. **D42 §2.5's finding is in the CLIENT constructor — i.e. D42 described the peer-verification behaviour of the path a handler does not take.** §2.5 is not wrong about `ssl_tcp.rb`; it is **mis-scoped as a statement about handlers**, which is precisely the risk D42 flagged in its own U2.

**Everything in D42 §2.3–§2.4 (cert generation, `options = 0`) stands unchanged** — those are `makessl`, the server path.

---

## §1 Q1 — the selection, traced

### §1.1 The rule (uniform, not a per-handler table)

**`[verified]` `ssl_tcp_server.rb:42-51`:**
```ruby
  def initsock(params = nil)
    if params && params.sslctx && params.sslctx.kind_of?(OpenSSL::SSL::SSLContext)
      self.sslctx = params.sslctx
    else
      self.sslctx  = makessl(params)
    end
    super
  end
```

**Three faces:**
1. **`:44-45`** — a caller-supplied `SSLContext` is used verbatim. **Bypasses `makessl` entirely.**
2. **`:47`** — otherwise **`makessl`** is the default. **This is the handler case.**
3. **`:50` `super`** — reaches `TcpServer#initsock` for the plain-TCP bind.

**`[verified]` `makessl` has exactly ONE call site in the gem and ZERO in the Metasploit tree.** Invocation:
```powershell
# per file: [regex]::Matches($t,'makessl')  over gem src + 01_SOURCE_c2\metasploit
```
Result — **gem: 3 occurrences** (`parameters.rb:460`, `ssl.rb:120` def, **`ssl_tcp_server.rb:47`**); **msf tree: 0 occurrences.**

**`[inferred]` One call site. The entire server-side context construction funnels through it.**

### §1.2 Which handlers reach the server path

**Invocation:**
```powershell
# per file: [regex]::Matches($t,'\bSslTcpServer\b') over both trees
```
`[verified]` **`SslTcpServer` in the MSF tree: 8 hits, 6 files**, of which **exactly two are handlers**:
- `lib\msf\core\handler\reverse_tcp_ssl.rb` ×1
- `lib\msf\core\handler\reverse_tcp_double_ssl.rb` ×1

Other files: `base\sessions\ssh_command_shell_bind.rb`, `rex\post\meterpreter\client.rb` ×3, `...\tcp_server_channel.rb`, `modules\auxiliary\server\openssl_altchainsforgery_mitm_proxy.rb`.

**`[verified]` Of the 26 recursive handlers, exactly 2 create an SSL server, and both go through `makessl`:**

`reverse_tcp_ssl.rb:56` and `reverse_tcp_double_ssl.rb:78`:
```ruby
self.listener_sock = Rex::Socket::SslTcpServer.create(
  ...
  'SSLCert'    => datastore['HandlerSSLCert'],
  'SSLVersion' => datastore['SSLVersion'],
  ...)
```

**`[verified]` Note the parameter names: `'SSLCert'` and `'SSLVersion'` — NOT `'SSLContext'`.** So the `:44` bypass branch **cannot fire from a handler**.

**§1.3 `[absence]` no handler ever sets an `SSLContext`.** Invocation: per-file scan of all 26 for the tokens `SSLContext|sslctx` → **zero hits** (scan-terminator line printed). **Positive control:** the same token over the tree returns **11 `sslctx =` writes outside `handler\`** (e.g. `rdp.rb:1208`, `smtp_deliver.rb:299`, `vmauthd.rb:95`) — **the probe bites; the handler zero is a real zero.**

### §1.4 The remaining 24 handlers

**They never construct an SSL context at all.** Two sub-cases: handlers with **no TLS** (the plaintext transports — `reverse_tcp`, `bind_tcp`, `reverse_udp`, …), and **`reverse_https.rb`**, which is the interesting one — it includes `Reverse::SSL` (`reverse_https.rb:15`) but **does not use `SslTcpServer`**; it is HTTP-layer TLS. **`[inferred]` Its TLS is built elsewhere and is therefore outside this trace** — see U1.

### §1.5 Answer to Q1

**A uniform rule, with the invocation:**

> **Every handler that establishes TLS for its own listener does so through `Rex::Socket::SslTcpServer.create` with `'SSLCert'`/`'SSLVersion'`, which always selects `makessl` (`ssl_tcp_server.rb:47`). Exactly 2 of 26 handlers do this. The `params.sslctx` bypass at `:44-45` is unreachable from any handler.**

---

## §2 Q2 — on the `ssl_tcp` path: confirm/refute, and blast radius

**`[verified]` §2.5 CONFIRMED as a reading of `ssl_tcp.rb:131-134`:**
```ruby
    self.sslctx.verify_callback = Proc.new do |valid, store|
      self.peer_verified = valid
      true
    end
```
**The verdict is stored and `true` is returned unconditionally.** `[inferred]` In Ruby/OpenSSL a `verify_callback` returning `true` continues the handshake, so a failed verification does not abort the connection. **Static, not run.**

**`[verified]` The fallback at `:120` is `VERIFY_PEER`** and `:117` resolves the mode by `const_get("VERIFY_#{params.ssl_verify_mode}")`.

**BLAST RADIUS — and this is the correction:**

**`[inferred]` Zero of the 26 handlers.** The finding lives in `Rex::Socket::SslTcp` (`ssl_tcp.rb:10`), the **client** module. `[verified]` No handler creates `SslTcp` (the `SslTcpServer` scan §1.2 returned 8 hits / 2 handlers; the `SslTcp` scan is dominated by **client** call sites — `rdp.rb`, `smtp_deliver.rb`, `msf_tds\channel.rb`, `tcp_client_channel.rb`, `impersonate_ssl.rb`).

**So D42 §2.5 should be re-scoped: it describes the peer-verification behaviour of Metasploit's outbound TLS CLIENT, not of its handlers.** Whether that client-side code path is itself reached by those client call sites is **U2**.

**`[inferred]` Held carefully: I did not confirm that every `SslTcp` call site reaches `initsock_with_ssl_version`** — `ssl_tcp.rb:65-73` `initsock` dispatches there, but a caller supplying a `sslctx` bypasses it by the same pattern as the server. **Not generalized.**

---

## §3 Q3 — on the `makessl` path: peer verification

**`[verified]` `makessl` (`ssl.rb:120-158`), read whole. It sets: `:136` key, `:137` cert, `:138` chain, `:139` `ctx.options = 0`, `:141-143` cipher (conditional), `:146-152` compression flag, `:155` session id context, `:157` return.**

**`[verified]` `makessl` NEVER sets `verify_mode`. `makessl` NEVER sets `verify_callback`.** Invocation: the 39-line body at `:120-158` contains no occurrence of either token.

**`[inferred]` Therefore the OpenSSL default applies: `VERIFY_NONE`.** With no `verify_mode` and no callback, the Ruby/OpenSSL `SSLContext` default is `VERIFY_NONE` — the server does **not** request or validate a client certificate.

### §3.1 THE HEADLINE — two paths, two *different* failure mechanisms

The brief expected "two paths through one mixin with different security properties." **The divergence is real, and it is a divergence in KIND, not degree:**

| | **Server path — `makessl`** (`ssl.rb:120`, reached by handlers) | **Client path — `initsock_with_ssl_version`** (`ssl_tcp.rb:75`) |
|---|---|---|
| `ctx.options` | **`:139` `= 0`** — all options cleared | **`:123-124` `OP_ALL \| OP_LEGACY_SERVER_CONNECT`** — workarounds on, legacy renegotiation allowed |
| `verify_mode` | **never set → `VERIFY_NONE`** `[inferred]` | **`:120` `VERIFY_PEER`** fallback |
| `verify_callback` | **never set** | **`:131-134` records verdict, returns `true`** |
| Peer authentication | **not attempted at all** | **attempted, then not enforced** |
| Mechanism of failure | **absent** | **computed and discarded** |

**`[inferred]` These are two different security postures achieved two different ways.** The server path **never asks the question**; the client path **asks it, writes down the answer, and proceeds regardless**.

**`[inferred]` The consequence for D42's framing:** D42 §2.5's *"compute-and-continue"* shape — which it aligned with the corpus's recurring failure mode — **belongs to the client path only.** The handler path is **not** a compute-and-continue; it is a **never-compute**. **Those are different findings and D42's §2.5 alignment should not be carried onto handlers.**

**`[inferred]` On the other axis the two paths agree in effect: neither handler nor client *enforces* peer identity.** So the *conclusion* "Metasploit TLS does not authenticate the far end" survives — **but for two different reasons, and only one of them is the reason D42 gave.**

### §3.2 The `options = 0` consequence

**`[inferred]` `ctx.options = 0` clears `OP_ALL`** — i.e. **no OpenSSL bug workarounds** — and leaves `OP_NO_SSLv3`/`OP_NO_TLSv1` etc. **unset**. Combined with `DEFAULT_SSL_VERSION = :SSLv23` (`ssl.rb:15` = *negotiate*), **the server path accepts whatever version the peer negotiates, subject only to what the local OpenSSL/Ruby `METHODS_MAP` still supports.** `[verified]` `:130` validates the requested version against `system_ssl_methods` and raises otherwise — **but the check is on the CONFIGURED version, not on what is negotiated.** `[inferred]` Whether a downgrade to a weak negotiated version is possible depends on the local OpenSSL build, which is a host property — **not measured, and not measurable statically.**

**One asymmetry worth stating:** `:149`/`:151` means `OP_NO_COMPRESSION` is set **only if `params.ssl_compression` is falsy** — so the `options = 0` clearing is partially undone at `:151` in the default branch. `[inferred]` `options = 0` is therefore **not** "no options at all" in the common case; it is `0` then `|= OP_NO_COMPRESSION`.

---

## §4 Q4 — `@@cert_provider`: who writes it

**`[verified]` `ssl.rb:66-74`:**
```ruby
  # This defines the global certificate provider for all consumers of the mixin
  # Beware that altering this at runtime in one consumer will affect all others
  @@cert_provider = Rex::Socket::Ssl::CertProvider

  def self.cert_provider=(val)
    @@cert_provider = val
  end
```
`[verified]` Read at `:88-98`: the three public generators (`ssl_generate_subject`, `ssl_generate_issuer`, `ssl_generate_certificate`) all delegate to `@@cert_provider`.

**Invocation:** per-file scan of both trees for `cert_provider`, with hits and line numbers printed.

**`[verified]` RESULT — inside the gem, four occurrences, all in `ssl.rb` itself:** the initializer (`:70`), the writer (`:73`), and the three delegation reads (`:89`, `:93`, `:97`).

**`[absence]` NO WRITE ANYWHERE ELSE — and this is the honest answer to Q4.** `[verified]` **No occurrence of `cert_provider=` outside `ssl.rb`** in either the gem src or the Metasploit tree. **Nothing in this corpus writes `@@cert_provider`.**

**Answers:**
- **Who writes it:** only the setter at `ssl.rb:72-74`. **No caller exists in the corpus.**
- **When:** never, in any code present here.
- **Can one consumer's write change another's:** **`[inferred]` mechanically YES — the mechanism is exactly as the author's comment describes.** `@@cert_provider` is a **module-level class variable on `Rex::Socket::Ssl`**, which is mixed into `SslTcpServer` (`ssl_tcp_server.rb:15`). **A class variable in Ruby is shared across all including classes and all instances**; `Rex::Socket::Ssl.cert_provider = X` would change cert generation **process-wide, for every consumer, immediately.** **`[absence]` But no write exists in the corpus, so the documented blast radius is LATENT, not realised.**

**`[inferred]` The finding is therefore: an author-documented process-wide mutable global whose setter is never called by anything shipped here.** That is a **capability, not a live defect** — and the distinction is the point. **`[inferred]` It remains reachable by an external consumer, a plugin, or a third-party module loading `rex-socket`** — the setter is public API. **"Never invoked" and "cannot be invoked" are different claims**, and only the first is established.

---

## §5 Residual unknowns, each with a probe

**U1 — `reverse_https.rb`'s TLS was not traced.** It includes `Reverse::SSL` (`:15`) but does **not** use `SslTcpServer` (§1.2). `[inferred]` Its TLS is HTTP-layer. **Probe:** read `reverse_http.rb`'s SSL/`HttpServer` construction and locate its context creation; confirm whether it reaches `makessl`, a `parameters.rb` `'SSLContext'`, or an HTTP-server-internal path. **This is the largest remaining gap in this report's coverage of the 26.**

**U2 — the client-side `SslTcp` call sites were not traced to `initsock_with_ssl_version`.** §2's blast radius says "not handlers"; **it does not claim those client sites reach the callback.** **Probe:** for each `SslTcp` call site (`rdp.rb`, `smtp_deliver.rb`, `ms_tds\channel.rb`, `tcp_client_channel.rb`, `impersonate_ssl.rb`, `vmauthd.rb`), check whether a `sslctx` is supplied — which would bypass the constructor by the §1.1 pattern.

**U3 — `parameters.rb:121` `self.sslctx = hash['SSLContext']` was located but its CALLERS were not enumerated.** This is the bypass branch's only input path. **Probe:** grep for `'SSLContext'` / `"SSLContext"` in hash literals across both trees and classify by caller.

**U4 — no execution.** Ruby absent. **`VERIFY_NONE`-by-default and `verify_callback`-returning-`true` are Ruby/OpenSSL contract claims, labelled `[inferred]` throughout.** **A one-line Ruby probe on a host with Ruby would convert both to `[verified]`:** construct a `SSLContext` without `verify_mode` and print it; and call a callback returning `true` against a failing store.

**U5 — `OP_NO_COMPRESSION` interaction with `options = 0` depends on `params.ssl_compression`'s default.** **Probe:** read `parameters.rb` for the `ssl_compression` default and resolve `:149`/`:151` decisively rather than by branch inspection.

---

## §6 Instrument record

### §6.1 What went right — and it is the same rule for the third time

**The control was written into the same command as the number, and it caught a scope error before it became a claim.**

The `makessl` search printed **both roots' totals in one run** — `gem: 3` and **`msf: 0`** — alongside the per-file line numbers. **Reading only the gem result would have supported "there are three call sites"; the tree total of zero is what established that all three are internal to the gem and that the single external-facing site is `ssl_tcp_server.rb:47`.**

Same shape as D42's §6.1 (the versioned-gem `ABSENT`, caught because the enumeration was in the same run) and §6.4. **Three passes, one method: the enumeration and the measurement in one invocation.**

### §6.2 The §0 correction was found by reading a FILE HEADER, not by searching

**I was one step from writing a per-handler table.** The brief's framing — *"which of the two constructors a handler gets"* — presumes one object with two branches. **`ssl_tcp.rb:6-7` says "SSL TCP client connection"; `ssl_tcp_server.rb:9-10` says "SSL wrapped TCP server."** Two modules, two constructors.

**`[inferred]` The lesson is a new sub-shape of this corpus's oldest instrument rule:** *the probe's shape must match the evidence's shape* — **and here the BRIEF's shape (two branches of one thing) did not match the artifact's shape (two modules).** A per-handler table would have been a **correctly-executed measurement of the wrong structure**, and would have produced 26 rows where the truth is one rule plus two handlers. **Reading the module headers cost two reads and replaced the entire framing.**

### §6.3 No dead probe this pass

Every probe printed its control or its terminator in the same invocation (the handler scan's `(end handler scan)` sentinel; the handler-zero with its 11-hit control; both tree totals). **No `[absence]` in this report rests on a probe that did not demonstrably bite.**

---

*End of D54.*
