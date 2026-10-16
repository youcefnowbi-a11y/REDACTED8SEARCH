# D70 — Metasploit HTTP-service TLS, verify modes, key-log surface, and direct-context sites

**Task:** D70 (follow-on to D58; no board entry at write time — see §0.3)
**Lane:** metasploit core
**Status:** COMPLETE
**Deliverable:** `RE_Library\07_OUTPUT\reports\DEEP\D70_msf_http_service_tls_and_verify_modes.md` (write scope: this file only)
**Method:** pure source. **Ruby is absent on this host — nothing was executed.** Contract claims (OpenSSL/Ruby semantics) are labelled `[inferred]`.
**Tags:** `[verified]` / `[read]` / `[inferred]` / `[absence]`. **Every number carries its invocation.**

---

## §0 Corrections and boundary

### §0.1 A correction about the CORPUS, not the analysis: `rex-socket` and `rex-proto` are packaged differently

D58 §0 corrected a path that was **assumed vendored and is actually a gem.** Q1's target is the inverse, so I enumerated before touching it:

```powershell
Get-ChildItem "04_TOOLS\gems" -Directory          # any *proto* gem?
Get-ChildItem "$m\lib\rex\proto" -Directory       # in-tree?
```

**`[verified]` There is NO `rex-proto` gem.** The gems directory holds exactly six: `rex-arch`, `rex-core`, `rex-encoder`, `rex-powershell`, `rex-socket`, `rex-text`. **`rex\proto\` is IN-TREE** under `lib\`, with **47 protocol subdirectories**, and `lib\rex\proto\http\` holds **12 files** (enumerated, not assumed).

> **`[verified]` The asymmetry: `rex-socket` is a GEM; `rex-proto` is IN-TREE. Two namespaces from the same project, packaged two different ways.** This is why D58's brief mistook a gem file for a vendored one, and why the inverse assumption here would have been equally wrong. **Both directions of the error are available in this corpus.**

### §0.2 Boundary

**Read for this report:**
- `lib\rex\proto\http\server.rb` — **9,632 B / 355 lines**, read end to end (§1).
- `rex-socket-0.1.71\src\lib\rex\socket\comm\local.rb` — the class-selection sites (§1.2).
- `rex-socket-0.1.71\src\lib\rex\socket\socket.rb` — the dispatch (§1.1).
- `rex-socket-0.1.71\src\lib\rex\socket\parameters.rb` — `:124-136`, `:460-480`.
- The 11 `sslctx=` sites and their surrounding blocks (§4).

**Not in scope:** `rex\proto\http\client.rb` (28,244 B — the client side of the same protocol); the six gem files other than `rex-socket`; `modules\` beyond the cited sites.

### §0.3 Task bookkeeping

**`[verified]` No D70 task exists on the shared board.** Owned tasks for this lane: task-22, task-33, task-35, task-56 — **all `completed`.** task-57 is an unrelated deliverable and task-58 belongs to another lane. Proceeding on the fully-specified work rather than idling; a task record can be created retroactively.

---

## §1 Q1 — the HTTP-service TLS construction site

### §1.1 `rex\proto\http\server.rb` does NOT build an SSL context

**`[verified]` Its ENTIRE SSL surface is five lines of stashing.** The full enumeration of every `ssl|SSL|cert|ctx|verify|cipher|compression` match in 355 lines:

| Line | Content |
|---|---|
| `:48-50` | `initialize(port, listen_host, ssl, context, comm, ssl_cert, ssl_compression, ssl_cipher, ssl_version)` |
| `:53,:56-59` | assigns those five to `attr_accessor`s |
| `:70` | `inspect` → `http#{ssl ? "s" : ""}://` |
| **`:96-100`** | **the params hash — five keys, passed onward** |
| `:226` | `attr_accessor :ssl, :ssl_cert, :ssl_compression, :ssl_cipher, :ssl_version` |

```ruby
# server.rb:92-102
self.listener = Rex::Socket::TcpServer.create(
  'LocalHost'      => self.listen_host,
  'LocalPort'      => self.listen_port,
  'Context'        => self.context,
  'SSL'            => self.ssl,
  'SSLCert'        => self.ssl_cert,
  'SSLCompression' => self.ssl_compression,
  'SSLCipher'      => self.ssl_cipher,
  'SSLVersion'     => self.ssl_version,
  'Comm'           => self.comm
)
```

**`[verified]` There is NO `OpenSSL::SSL::SSLContext` construction, no `verify_mode`, no `verify_callback`, no `ciphers`, no `makessl`, and no `SslTcpServer` reference in this file.**

**So Q1's premise needs one refinement: `server.rb` is not the TLS construction site — it is the TLS PARAMETER HANDOFF.** The construction happens two dispatches further down, and the routing is not what a reader of `server.rb` would guess.

### §1.2 The routing: `TcpServer.create` + an SSL flag → the class is chosen inside `Comm::Local`

**`[read]` `socket.rb:44-53`:**
```ruby
def self.create(opts = {})
  return create_param(Rex::Socket::Parameters.from_hash(opts))
end
def self.create_param(param)
  return param.comm.create(param)
end
```

**`[verified]` The class selection — `comm\local.rb:289-305`:**
```ruby
if param.server?
  sock.listen(256)
  if !param.bare?
    if param.proto == 'tcp'
      klass = Rex::Socket::TcpServer
      if param.ssl
        klass = Rex::Socket::SslTcpServer      # :296
      end
    elsif param.proto == 'sctp'
      klass = Rex::Socket::SctpServer
    else
      raise Rex::BindFailed.new(param.localhost, param.localport), caller
    end
    sock.extend(klass)
    sock.initsock(param)                        # :305  <-- invokes the constructor
  end
```

**`[verified]` A parallel jruby path selects the same class — `comm\local.rb:59-67`:** `if param.ssl → klass = Rex::Socket::SslTcpServer` (`:65`), `if param.ssl → klass = Rex::Socket::SslTcp` for clients (`:73`). **Two selection sites, same rule.**

**`[inferred]` Full Q1 trace:**
```
rex\proto\http\server.rb:92   Rex::Socket::TcpServer.create('SSL'=>…, 'SSLCert'=>…)
  → socket.rb:51-52           Rex::Socket.create_param → param.comm.create(param)
  → comm\local.rb:296         klass = Rex::Socket::SslTcpServer   (because param.ssl)
  → comm\local.rb:305         sock.initsock(param)
  → ssl_tcp_server.rb:47      self.sslctx = makessl(params)
  → ssl.rb:120                the context is built HERE
```

> **`[inferred]` The answer to Q1: the HTTP service DOES reach `makessl` — by a different route than the handlers take.** The two SSL handlers call `SslTcpServer.create` **directly** (`reverse_tcp_ssl.rb:56`, `reverse_tcp_double_ssl.rb:78`). The HTTP service calls the **generic** `TcpServer.create` with an SSL flag, and `Comm::Local` upgrades the class. **Two entry paths, one constructor.** D54 §1's rule therefore holds for the HTTP layer too, and `reverse_https`/`reverse_http`/every fetch handler inherit `makessl`'s posture **whether or not their authors knew it.**

### §1.3 Therefore the HTTP service's verify posture IS `makessl`'s

**`[verified]` `makessl` (`ssl.rb:120-158`) sets:** `ctx.key`, `ctx.cert`, `ctx.extra_chain_cert` (`:136-138`), `ctx.options = 0` (`:139`) then `|= OP_NO_COMPRESSION` in the default branch (`:151`), `ctx.ciphers` if passed (`:141-143`), `ctx.session_id_context = Rex::Text.rand_text(16)` (`:155`). **It never sets `verify_mode` and never sets `verify_callback`.**

**`[inferred]` The HTTP service's `verify_mode` is therefore OpenSSL's default `VERIFY_NONE`, and there is no verification callback — so a client certificate is never demanded.** This propagates to `reverse_https`, `reverse_http`, and every fetch handler.

**`[verified]` Q1's "is the client cert ever actually demanded?" — NO, on this path, and the reason is structural: `makessl` has no code that could demand it.** Demanding a client cert requires `VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT` plus a CA store (`cert_store`/`ca_file`) — **`makessl` sets neither the mode nor a store.** `[inferred]` A server built through this path completes handshakes with anonymous clients.

**`[verified]` One nuance that limits the claim, stated rather than smoothed:** `comm\local.rb:292` gates the whole class-selection block on `if !param.bare?`. When `param.bare?` is true, **no class is extended and `initsock` is never called at all** (`:292-306`). **`bare?` is therefore a third path that reaches no constructor.** I did not enumerate `bare?` consumers; that is residual U1.

---

## §2 Q2 — is verification switchable off by configuration on a SERVER context?

### §2.1 The answer: NO — and the reason is that the field is never read on the server path

**`[verified]` `SSLVerifyMode` has 28 occurrences in the MSF tree.** The allow-list is at `parameters.rb:130-132`:
```ruby
supported_ssl_verifiers = %W{CLIENT_ONCE FAIL_IF_NO_PEER_CERT NONE PEER}
if (hash['SSLVerifyMode'] and supported_ssl_verifiers.include? hash['SSLVerifyMode'])
  self.ssl_verify_mode = hash['SSLVerifyMode']
```

**`[verified]` And the gem-wide enumeration of every verify-related symbol — 11 occurrences total:**
```
[gem] parameters.rb :132   self.ssl_verify_mode = hash['SSLVerifyMode']
[gem] parameters.rb :480   attr_accessor :ssl_verify_mode
[gem] ssl_tcp.rb     :116  if params.ssl_verify_mode
[gem] ssl_tcp.rb     :117  self.sslctx.verify_mode = OpenSSL::SSL.const_get("VERIFY_#{params.ssl_verify_mode}".intern)
[gem] ssl_tcp.rb     :119  # Could also do this as graceful faildown ...
[gem] ssl_tcp.rb     :120  self.sslctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
[gem] ssl_tcp.rb     :131  self.sslctx.verify_callback = Proc.new do |valid, store|
[gem] ssl_tcp.rb     :132  self.peer_verified = valid
[gem] ssl_tcp.rb     :363  attr_reader :peer_verified
[gem] ssl_tcp.rb     :372  attr_writer :peer_verified
```

> **`[verified]` `ssl_verify_mode` is READ in exactly ONE place in the entire gem: `ssl_tcp.rb:116` — and that is `initsock_with_ssl_version`, the CLIENT constructor. `makessl` (the SERVER constructor) never reads it.**

**`[inferred]` So on a server context the field is WRITE-ONLY.** It can be set (`parameters.rb:132`), it is validated against an allow-list including `NONE`, it is carried on the parameter object, and **the constructor that receives it never consults it.** **The answer to Q2 is NO: `SSLVerifyMode` cannot switch verification off on a server, because there is nothing to switch off — `makessl` never verifies in the first place.**

### §2.2 The consumers, classified — and the two that look like counterexamples

**`[verified]` All 28 `SSLVerifyMode` sites, by context:**

**CLIENT (23 sites):**
- `msf\core\exploit\remote\tcp.rb:68` — **the registration**: `OptEnum.new('SSLVerifyMode', [false, 'SSL verification method', 'PEER', %W{CLIENT_ONCE FAIL_IF_NO_PEER_CERT NONE PEER}])` — **default `PEER`**, `NONE` permitted.
- `tcp.rb:111`, `tcp.rb:318`; `metasploit\framework\tcp\client.rb:91`; `rex\proto\mssql\client.rb:93` — the `opts['SSLVerifyMode'] || ssl_verify_mode` pass-through pattern.
- `postgres\postgres-pr\connection.rb:360` — `ssl_opts[:ssl_verify_mode]`.
- **13 `*_login.rb` scanners** — `ssl_verify_mode: datastore['SSLVerifyMode']` (acpp, afp, db2, ftp, mqtt, mssql, mysql, pop3, postgres, brocade/telnet, telnet, vmware, vnc).
- `atg_client.rb:178` — **deregisters** the option.
- `ibm_was_dmgr_java_deserialization_rce.rb:61` — `OptRaw.new('SSLVerifyMode', [true, 'SSL verification method', 'CLIENT_ONCE'])` (see §2.4).
- `ivanti_connect_secure_stack_overflow_rce_cve_2025_22457.rb:150` and `fortimanager_rce_cve_2024_47575.rb:178` — `'SSLVerifyMode' => 'NONE'` on an outbound connect.

**SERVER-CONTEXT, and this is the interesting pair (2 sites):**
- `modules\auxiliary\server\jsse_skiptls_mitm_proxy.rb:132` — `'SSLVerifyMode' => 'NONE'`
- `modules\auxiliary\server\openssl_altchainsforgery_mitm_proxy.rb:170` — `'SSLVerifyMode' => 'NONE'`

**`[verified]` Both are server contexts — `openssl_altchainsforgery…:145` `Rex::Socket::SslTcpServer.create(` and `:161` `@proxy.accept`; `jsse_skiptls…:120` `@proxy.accept`. Both pass `NONE` INTO a server creation.**

### §2.3 The result: the two `NONE` server consumers are setting an inert field

**`[inferred]` Both MITM proxies set `SSLVerifyMode => 'NONE'` on a context that never reads it.** The value is accepted by the allow-list, carried to `makessl`, and **ignored** — while the resulting posture is `VERIFY_NONE` anyway, by omission. **The setting is a no-op that coincidentally matches intent.**

**`[inferred]` This is a specific and reportable shape: a configuration value that is valid, accepted, and inert — so it produces the right behaviour for the wrong reason, and it will keep producing it if `makessl` ever starts reading the field.** If a future `makessl` honoured `ssl_verify_mode`, `NONE` would still be `NONE` — but the *default* would change for every handler, and these two modules would be the only ones already explicit.

**`[inferred]` D42 §2.6 searched for an explicit-off switch at the gem level and did not find one. The finding is now sharper than "not found": the field EXISTS, is documented and validated, and is simply not consulted by the server constructor.** "Not found" and "found but unread" are different results, and the second is the one that holds.

### §2.4 Two sub-findings worth recording

**`[verified]` `ibm_was_dmgr_java_deserialization_rce.rb:61` uses `OptRaw` (not `OptEnum`) with default `'CLIENT_ONCE'`.** `[inferred]` `CLIENT_ONCE` is **not a peer-verification mode** in the usual sense — it is `VERIFY_CLIENT_ONCE`, which asks for a client certificate once per handshake. `const_get("VERIFY_CLIENT_ONCE")` resolves, so this is not an error; but the option is being modelled as a *verification method* when the underlying constant is a *client-cert requirement*. **The allow-list conflates the two categories** — `NONE`/`PEER` are peer-verification modes, `CLIENT_ONCE`/`FAIL_IF_NO_PEER_CERT` are client-cert requirements. `[inferred]` They are combinable bit flags in OpenSSL, and the allow-list treats them as mutually exclusive alternatives.

**`[verified]` The registration default is `PEER` (`tcp.rb:68`), not `NONE`.** So the *client* path defaults to verifying, and falls back to `VERIFY_PEER` when unset (`ssl_tcp.rb:118-120`). **The strict default is on the client; the absent default is on the server.**

---

## §3 Q3 — the key-log surface

### §3.1 The answer: NOT reachable from a handler — and it is opt-in via an ENVIRONMENT VARIABLE

**`[verified]` `handler\ SSLKeyLogFile occurrences = 0`**, with a control proving the probe bites in the same invocation: the identical token over `lib\msf\core\exploit\remote\` returns **`http_client.rb` ×3, `tcp.rb` ×5**.

**`[verified]` Exactly THREE registrations exist, all CLIENT mixins:**
```ruby
lib\msf\core\auxiliary\auth_brute.rb:45   OptString.new('SSLKeyLogFile', [ false, 'The SSL key log file', ENV['SSLKeyLogFile']]),
lib\msf\core\exploit\remote\http_client.rb:58   OptString.new('SSLKeyLogFile', [ false, 'The SSL key log file', ENV['SSLKeyLogFile']]),
lib\msf\core\exploit\remote\tcp.rb:70      OptString.new('SSLKeyLogFile', [ false, 'The SSL key log file', ENV['SSLKeyLogFile']]),
```

**`[inferred]` The default is `ENV['SSLKeyLogFile']` — an environment variable, NOT a datastore default.** So:

> **`[inferred]` A handler cannot set it (0 registrations under `handler\`). But ANY module including `HttpClient`, `Tcp`, or `auth_brute` will write TLS session keys to disk if `SSLKeyLogFile` is exported in the process environment — with no `set`, no prompt, and no console indication that it happened.**

**`[inferred]` Is that "without explicit operator action"? In the strict sense no — exporting a variable is an action. But it is opt-in OUTSIDE the tool's own configuration surface.** The forensic consequence: **the artifact appears and the console never says why.** An operator inheriting a shell environment, a wrapper script, or a CI job that exports the variable produces key-log files on every HTTPS module run, and nothing in MSF's own output distinguishes that run from one without it.

### §3.2 The write path, and its guard

**`[verified]` `ssl_tcp.rb:85-97`:**
```ruby
# writing to the sslkeylogfile is required, it adds support for network capture decryption which is useful to
if sslkeylogfile
  unless self.sslctx.respond_to?(:keylog_cb)
    raise 'Unable to create sslkeylogfile - Ruby 3.2 or above required for this functionality'
  end
  self.sslctx.keylog_cb = proc do |_sock, line|
    File.open(sslkeylogfile, 'ab') do |file|
      file.write("#{line}\n")
    end
  end
end
```

**`[verified]` `parameters.rb:54` documents it:** `# @option hash [String] 'SSLKeyLogFile' The SSL key log file path, used for network capture`.

**`[inferred]` Three observations:**
1. **It is a CLIENT-path feature.** `ssl_tcp.rb:85-97` is inside `initsock_with_ssl_version`, the client constructor. `makessl` has no key-log code. **`[verified]` `sslkeylogfile` in the gem appears only in `socket.rb:814/:900/:926` (attribute plumbing) and `parameters.rb:54/:124-125/:316-319` — never in `ssl.rb`.** So the HTTP service path does **not** write a key log.
2. **The guard is a Ruby-version check, not a policy check.** `:88` raises if `keylog_cb` is unsupported — i.e. below Ruby 3.2. **Once the version requirement is met, the feature is unconditional.**
3. **The comment states the purpose outright** — *"support for network capture decryption."* `[inferred]` This is a **deliberate, documented defect-support affordance**, not an accidental leak. It is the correct design for its purpose; the exposure is that its activation channel is an environment variable.

**`[verified]` The registration default is `false` at the three sites (`[false, …]` = not required), and no default VALUE is provided other than the env var.** `[absence]` No handler, no payload adapter, and no default path sets it.

---

## §4 Q4 — the direct `sslctx=` sites, traced

### §4.1 All 11 writes, classified

**`[verified]` Full enumeration of `\bsslctx\s*=` (excluding `==`) in the MSF tree — 11 writes:**

| # | Site | RHS | Context |
|---|---|---|---|
| 1 | `login_scanner\vmauthd.rb:95` | `nsock.sslctx = ctx` | client, from `generate_ssl_context` |
| 2 | `exploit\remote\rdp.rb:1208` | `self.rdp_sock.sslctx = ctx` | client |
| 3 | `exploit\remote\smtp_deliver.rb:299` | `nsock.sslctx = ctx` | client, STARTTLS |
| 4 | `rex\post\meterpreter\client.rb:253` | `self.sock.sslctx = ctx` | client |
| 5 | `rex\post\meterpreter\client.rb:266` | `self.sock.sslctx = nil` | **teardown** |
| 6 | `modules\…\vmauthd_version.rb:108` | `nsock.sslctx = ctx` | client |
| 7 | `modules\…\checkpoint_smartconsole…:225` | `@cpmi_socket.sslctx = context` | client, TLS1.2 pinned |
| 8 | `modules\…\nagios_nrpe_arguments.rb:177` | `self.sock.sslctx = ctx` | client |
| 9 | **`bmc_server_automation_rscd_nsh_rce.rb:232`** | **`OpenSSL::SSL::SSLContext.new(:SSLv23)`** | **client, INLINE BUILD** |
| 10 | **`hp_dataprotector_encrypted_comms.rb:127`** | **`OpenSSL::SSL::SSLContext.new(:SSLv23)`** | **client, INLINE BUILD** |
| 11 | `spec\lib\msf\core\exploit\remote\rdp_spec.rb:97` | RSpec double | **not production** |

**`[inferred]` Every one of the 10 production writes is a CLIENT-side socket upgrade, and none is a listener.** The uniform shape is `sock.extend(Rex::Socket::SslTcp)` → assign `sslctx`/`sslsock` → `sslsock.connect` on an **outbound** socket. **`[inferred]` None of the 10 assigns onto a `SslTcpServer`, so none of them influences the `ssl_tcp_server.rb:44-45` bypass, and none affects a handler's listener.** D58 §2.2's separation is confirmed: **the hash-key form (1 caller, a server-side MITM aux) and the direct-assignment form (10 callers, all clients) are disjoint in both mechanism and direction.**

### §4.2 The finding: there is a FOURTH context-construction pattern

**`[verified]` Two sites build a context inline and set `VERIFY_NONE` explicitly by hand** — `bmc_server_automation_rscd_nsh_rce.rb:232-236`:
```ruby
sock.extend(Rex::Socket::SslTcp)
sock.sslctx = OpenSSL::SSL::SSLContext.new(:SSLv23)
sock.sslctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
sock.sslctx.options = OpenSSL::SSL::OP_ALL
sock.sslctx.ciphers = 'ALL'
sock.sslsock = OpenSSL::SSL::SSLSocket.new(sock, sock.sslctx)
sock.sslsock.connect
```
and `hp_dataprotector_encrypted_comms.rb:127-138` — **the same construct**, with a comment at `:132-133` explaining the cipher choice (*"older versions of Data Protector only use some not enabled by default"*).

**`[verified]` `ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE` appears explicitly in 6 exploit modules** (`checkpoint_smartconsole…:213`, `cisco_rv340_sslvpn.rb:258`, `nagios_nrpe_arguments.rb:168`, `bmc_server_automation_rscd_nsh_rce.rb:233`, `ibm_tm1_unauth_rce.rb:221`, `hp_dataprotector_encrypted_comms.rb:128`).

> **`[inferred]` This is the explicit-off switch D42 §2.6 and D58's U3 both looked for at the gem level. It is not in the gem. It is hand-written in the modules** — six of them, each building or configuring its own context and each explicitly disabling verification. **`[inferred]` The framework's client default is `VERIFY_PEER` (`ssl_tcp.rb:120`); these modules opt out individually, because their targets use self-signed or unmatched certificates.**

### §4.3 The fifth pattern: `vmauthd.rb`'s key-without-certificate context

**`[verified]` `login_scanner\vmauthd.rb:98-107`:**
```ruby
def generate_ssl_context
  ctx = OpenSSL::SSL::SSLContext.new(:SSLv3)
  @@cached_rsa_key ||= OpenSSL::PKey::RSA.new(1024){}
  ctx.key = @@cached_rsa_key
  ctx.session_id_context = Rex::Text.rand_text(16)
  ctx
end
```

**`[inferred]` This sets a KEY and a session id but NO certificate, NO `verify_mode`, and NO chain** — a context that cannot present a certificate. It is built for one specific handshake shape. **`[inferred]` The `@@cached_rsa_key` is a mutable class variable** — the same construct the framework's own `AGENTS.md` names as a pattern to avoid (*"Avoid mutable global and class variables in modules and libraries"*), and the same construct as D54 §4's `@@cert_provider`. **Two independent instances of cached class-level key material in this corpus.**

### §4.4 The sixth pattern, and a category distinction: `ADH` is not a verification choice

**`[verified]` `nagios_nrpe_arguments.rb:167-169`:**
```ruby
ctx = OpenSSL::SSL::SSLContext.new(:TLSv1)
ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
ctx.ciphers = "ADH"
```

**`[verified]` `vmauthd.rb:99` uses `SSLv3`; this uses `TLSv1`; `bmc`/`hp` use `:SSLv23`.**

**`[inferred]` `ADH` is anonymous Diffie-Hellman — no certificate is exchanged at all, so `VERIFY_NONE` is not a decision among alternatives; there is nothing to verify.** This is a **category difference** from the other five `VERIFY_NONE` sites, and it is the same class of finding D42 recorded for `vmauthd`. **A reader comparing the six sites as "six modules that disabled verification" would merge a redundant setting with five meaningful ones.**

### §4.5 Posture taxonomy — four constructors, four postures

| Constructor | Where | `verify_mode` | options | callback | Client cert demanded? |
|---|---|---|---|---|---|
| **`makessl`** (SERVER) | `ssl.rb:120` | **never set** → `[inferred]` `VERIFY_NONE` | `0` then `\|= OP_NO_COMPRESSION` | none | **No** |
| **`initsock_with_ssl_version`** (CLIENT) | `ssl_tcp.rb:75` | `VERIFY_PEER` fallback (`:120`) | `OP_ALL \| OP_LEGACY_SERVER_CONNECT` | **records, returns `true`** (`:131-134`) | n/a |
| **hand-rolled** (CLIENT) | 6 modules | **`VERIFY_NONE` explicit** | `OP_ALL` | none | n/a |
| **key-only** (CLIENT) | `vmauthd.rb:98` | **never set** | unset | none | n/a |

**`[inferred]` The HTTP-service path (§1) lands in row 1.** So `reverse_https`, `reverse_http`, and every fetch handler inherit: no verification, no callback, no client-cert demand, compression off, and a framework-generated certificate.

---

## §5 Residual unknowns, each with a probe

**U1 — `param.bare?` is a third routing path that reaches no constructor.** `comm\local.rb:292` gates class extension and `initsock` on `!param.bare?`. **Probe:** enumerate `bare?` — its setter, and every caller that passes `'Bare' => true`. If any handler path can set it, the `makessl` trace in §1.2 does not apply there. **This is the largest residual: it is a branch that removes the constructor entirely.**

**U2 — `ssl_tcp_server.rb:44-45`'s `params.sslctx` bypass was not re-checked for the HTTP-service path.** D58 established the bypass is unreachable from `handler\` because no handler passes `'SSLContext'`. **Probe:** confirm `rex\proto\http\server.rb` never sets `'SSLContext'` (its five keys at `:96-100` do not include it — but `TcpServer`'s `create` may add keys I did not enumerate).

**U3 — `target_uri`/`SSLVerifyMode` on the SERVER path via `tcp_server.rb`.** The `TcpServer` mixin registers `Opt::SSLVersion` and `SSLCompression` (`:29-31`) but I did **not** confirm whether it registers `SSLVerifyMode`. **Probe:** read `tcp_server.rb:20-40` in full. If it does, a server-creating module gets the option and §2.3's inert-field finding widens.

**U4 — `verify_callback` is never set on the server path, but is `peer_verified` ever read?** `ssl_tcp.rb:363` `attr_reader :peer_verified`. **Probe:** enumerate `peer_verified` consumers. If a caller reads it and acts, the client's "record it and proceed" pattern has a second half I have not seen; if nothing reads it, **`[inferred]` the client captures a verification verdict that no code consumes** — which is D54 §3's headline made stronger.

**U5 — no execution.** Ruby absent. **`[inferred]`**: `makessl`'s `VERIFY_NONE`-by-default; `keylog_cb` availability; `ADH`'s no-certificate property; and every `const_get("VERIFY_…")` resolution. One Ruby session converts all to `[verified]`.

**U6 — `rex\proto\http\client.rb` (28,244 B) unread** — the client half of the same protocol, and the place `HttpClient`'s TLS actually runs. **Probe:** trace its SSL context construction; it is the HTTP-service path's mirror and has never been traced in this corpus.

---

## §6 Instrument record

### §6.1 No instrument failure this pass — and the reason is structural, so it is worth stating

**Every probe printed its matches, its control, or its terminator in the same invocation. Nothing returned zero unexpectedly; nothing was retried.**

**`[inferred]` The reason is not luck.** D58's §5.2 established the practice — *the positive control goes in the same command as the number* — and this pass applied it to **every** zero:
- **§0.1** — the absence of a `rex-proto` gem was reported **with the six-gem enumeration printed** and the 47-subdir in-tree listing printed. **The zero and its positive control are one artifact.**
- **§3.1** — `handler\ SSLKeyLogFile = 0` was reported **with a control on a sibling directory that returned `http_client.rb ×3, tcp.rb ×5`.**
- **§1.1** — "no SSLContext in `server.rb`" was reported by **printing every matching line and its count from a 355-line file**, so the negative is bounded by a complete enumeration rather than a failed pattern.
- **§4.1** — the 11 writes were **printed with the RHS text of each**, which is how rows 9 and 10 (the inline builds) became visible at all. **A count alone would have hidden the finding.**

### §6.2 The one thing that would have gone wrong without enumeration

**`[inferred]` `server.rb`'s SSL surface is five parameter keys and an `inspect` string. A reader looking for TLS construction there finds `'SSLCert' => self.ssl_cert` and `'SSL' => self.ssl` and can reasonably conclude the file configures TLS.** It does not — it forwards. **The construction is two dispatches away, and the dispatch is chosen inside `Comm::Local` by a flag, not by a named factory.**

**`[inferred]` This is a variant of D42 §6.3's shape** (a grep spanning two files merging two contradicting configurations into one apparent fact): here the risk was the opposite — **reading a handoff and mistaking it for a construction.** The defence was the same and is worth restating: **follow the value to the place it is USED, not the place it is named.**

### §6.3 The `SSLVerifyMode` result is a shape the ledger does not have

**`[inferred]` Existing instrument shapes concern probes that fail, return zero, or match the wrong thing. §2.3 is different in kind: the probe returns the right answer, the value is valid and accepted, and the code that receives it does nothing with it.**

> **A configured value that is validated and then never read is indistinguishable from a configured value that works — from the outside.** It produces the intended behaviour for an unintended reason, and it will keep doing so until the consumer changes.

**`[inferred]` The method that catches it is the one used here: enumerate the CONSUMERS of a field, not the DECLARATIONS of it.** Declaration counts (`SSLVerifyMode` = 28, `ssl_verify_mode` = 2 in the gem) suggest a live setting. **The read-site count (`ssl_tcp.rb:116` only, on the client) is what establishes that the server path ignores it.**

---

*End of D70.*
