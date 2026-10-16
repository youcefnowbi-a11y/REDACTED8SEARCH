# D58 — Metasploit handler/transport residual sweep

**Task:** D58 (task pending on board at write time — see §0)
**Lane:** metasploit core
**Status:** COMPLETE
**Deliverable:** `RE_Library\07_OUTPUT\reports\DEEP\D58_msf_handler_residuals.md` (write scope: this file only)
**Method:** pure source. **Ruby is absent on this host — nothing was executed.** Every claim is a static read; conclusions that follow from Ruby/OpenSSL *contracts* rather than from a run are labelled `[inferred]`.
**Tags:** `[verified]` / `[read]` / `[inferred]` / `[absence]`. **Every number carries its invocation.**

---

## §0 What this is, and one correction that removes a finding instead of adding one

This report closes the residuals D42 and D54 left open: **U1** (`reverse_https.rb` untraced), **U3** (`parameters.rb:121` `'SSLContext'`), **U5** (`ssl_compression` default), plus the **vendored-vs-gem `ssl_tcp.rb` copy-drift check**.

### §0.1 THE CORRECTION — there is no vendored copy to diff

**The brief states:** *"`metasploit\lib\rex\socket\ssl_tcp.rb:131-134` — that file is *inside* the MSF tree (a vendored copy) while the gem copy is separate. Diff the two copies."*

**`[absence]` THERE IS NO VENDORED COPY. The premise is wrong, and the diff has no second operand.**

**Invocation:**
```powershell
$mv = "$m\lib\rex\socket\ssl_tcp.rb"; $gv = "$g\lib\rex\socket\ssl_tcp.rb"
foreach ($p in @($mv,$gv)) { Test-Path $p; Get-FileHash $p -Algorithm SHA256 }
```
**Result:**
```
ABSENT  C:\...\01_SOURCE_c2\metasploit\lib\rex\socket\ssl_tcp.rb
EXISTS     8899 B  sha256=AECAFEACFC75B8E3CC079AAEB4EC6518AB61031C6A72DD02F8D1DE3E63BBCCBB
        C:\...\04_TOOLS\gems\rex-socket-0.1.71\src\lib\rex\socket\ssl_tcp.rb
```
**And `metasploit\lib\rex\socket\` IS NOT A DIRECTORY AT ALL** — `Test-Path` on the directory returns **absent**.

**Corpus-wide enumeration (the rule: enumerate, do not construct from a name):**
```powershell
Get-ChildItem "$root" -Recurse -File -Filter "ssl_tcp*.rb"
```
**`[verified]` Exactly TWO files corpus-wide** — `ssl_tcp.rb` (8,899 B, `AECA…CCBB`) and `ssl_tcp_server.rb` (1,964 B, `DDC8…0733`), **both in the gem, neither in a Metasploit tree.**

**`[verified]` POSITIVE CONTROL that the probe finds multiple copies when they exist:** the identical recursive enumeration for `*.gemspec` returns **7 files across 7 distinct directories**. The instrument demonstrably spans multiple locations; the count of **one** `ssl_tcp.rb` is a real count.

**`[verified]` There is exactly ONE `rex\socket` directory in the entire corpus** — `04_TOOLS\gems\rex-socket-0.1.71\src\lib\rex\socket\` — and one `rex\socket\comm\`. No vendored `rex` tree exists anywhere.

**`[inferred]` Why this matters more than a failed check:** D20 established copy-drift as a live mechanism in this corpus, so the check was the right instinct. **The result is stronger than byte-identity: no drift is possible because there is only one copy.** **D54's client-path finding (§2) and its `verify_callback` reading at `ssl_tcp.rb:131-134` read the only copy of that file that exists in this corpus.** The path is confirmed, not merely unrefuted.

**`[inferred]` Second point, and it is the reusable one:** D42 §2.1 and D54 §1.1 both recorded *"`lib\rex\socket\` does not exist; `rex-socket` is a gem."* **The brief's premise re-created the same error in the opposite direction** — a file assumed to be vendored inside the tree because its *path shape* looks like the tree's. **This is the third appearance of the shape "a path specified from a name instead of an enumeration"** (D42 §6.1, D42 §6.2, and now this), and the first where the wrong premise was supplied rather than self-generated.

### §0.2 Boundary, justified

**In scope (enumerated, never constructed):**
- **`lib\msf\core\handler\` — 26 recursive `.rb`, 24 top-level, 2 in `reverse\`** (`reverse\comm.rb`, `reverse\ssl.rb`). Invocation: `Get-ChildItem $h -Recurse -File -Filter *.rb` → **26**; `Get-ChildItem $h -File -Filter *.rb` → **24**; difference printed by path. **This reproduces D42 §0's census exactly.**
- **`04_TOOLS\gems\rex-socket-0.1.71\`** — the gem, **enumerated as a versioned directory** (`Get-ChildItem … -Directory -Filter "*socket*"`) because **the gem dirs are versioned** (D42 §6.1).

**Not in scope:** the other five extracted gems; `modules\`; `rex\proto\`. **Where a finding's blast radius reaches one of these it is stated as such.**

---

## §1 U1 — `reverse_https.rb`: where its TLS actually comes from

**`[read]` `reverse_https.rb` read end to end — 55 lines.** It contains **ZERO TLS code**: no `SslTcpServer`, no `makessl`, no `SSLContext`, no certificate handling, no socket construction.

**`[verified]` Its entire composition is two includes (`:15-16`):**
```ruby
  include Msf::Handler::Reverse::SSL
  include Msf::Handler::ReverseHttp
```
**`[verified]` And its entire `initialize` registers exactly two things (`:39-47`):**
- `:41` `OptPort.new('LPORT', [true, "The local listener port", 8443])` — **non-standard default (8443, not 4444)**
- `:46` `OptBool.new('StagerVerifySSLCert', [false, "Whether to verify the SSL certificate in Meterpreter"])`

### §1.1 The answer: its TLS is `ReverseHttp`'s HTTP server path, not the socket layer

**`[verified]` `reverse_http.rb:228-248`** is where the listener is built, and **`:248`** is the parameter that decides TLS:
```ruby
  (ssl?) ? datastore['HandlerSSLCert'] : nil, nil, nil, datastore['SSLVersion']
```

**`[verified]` `reverse_http.rb:168-179`:**
```ruby
    # Use the #refname to determine whether this handler uses SSL or not
    def ssl?
      ...
    (ssl?) ? 'https' : 'http'
```
**`[inferred]` So `reverse_https.rb` selects HTTPS by INHERITING `ReverseHttp`'s server-start path and having `ssl?` return true** — the subclass supplies *no* TLS logic, only the identity that flips the scheme.

**Therefore:**
- **The listener's certificate is `datastore['HandlerSSLCert']`, consumed at `reverse_http.rb:248` by the HTTP server service** — **not** by `SslTcpServer`.
- **`Reverse::SSL` contributes exactly its two option registrations** (`HandlerSSLCert`, `SSLVersion` — D42 §2.2 / D54 §1.3).
- **`[verified]` `reverse_http.rb:6` requires `rex/socket/x509_certificate`** — the cert *parsing* path, consistent with a context assembled for the HTTP service.

**`[inferred]` D54's Q1 rule is CONFIRMED from the other direction.** D54 said *"every handler that builds TLS for its own listener goes through `SslTcpServer.create`"* and covered **2 of 26**. **`reverse_https.rb` is the reason that rule needed stating as "for its own listener": it builds TLS, but through the HTTP server service, not the socket layer.** **D54 flagged exactly this in its U1 and the flag was correct.**

### §1.2 `StagerVerifySSLCert` — a name that reads like a listener setting and is not one

**`[verified]` Consumer enumeration — `StagerVerifySSLCert`, whole tree, 10 occurrences:**

| File | Line(s) |
|---|---|
| `lib\msf\core\handler\reverse_https.rb` | **46 — the registration** |
| `lib\msf\core\payload\transport_config.rb` | 51 |
| `lib\msf\core\payload\windows\reverse_win_https.rb` | 25, 34, 57 |
| `lib\msf\core\payload\windows\x64\reverse_win_https_x64.rb` | 24, 33, 56 |
| `lib\msf\core\exploit\remote\browser_autopwn2.rb` | 327 |
| `plugins\aggregator.rb` | 429 |

**`[verified]` NOT ONE occurrence is in a handler's listener path.** Six of ten are in **`payload\windows\reverse_win_https*.rb`** — the *implant-side* configuration.

**`[inferred]` `StagerVerifySSLCert` configures whether the IMPLANT verifies the handler's certificate. It does not configure the handler.** The `:46` description says so plainly — *"in Meterpreter"* — and the consumer list confirms it. **A reader scanning `reverse_https.rb` for its TLS posture would find this option and draw the wrong conclusion: it is the peer's verification setting, not the listener's.**

---

## §2 U3 — `parameters.rb:121` `'SSLContext'`: what it is for, and who reads it

**`[read]` `parameters.rb:114-132` in context:**
```ruby
    if (hash['SSL'] and hash['SSL'].to_s =~ /^(t|y|1)/i)
      self.ssl = true
    end

    if hash['SSLContext']
      self.sslctx = hash['SSLContext']
    end

    if (hash['SSLKeyLogFile'])
      self.sslkeylogfile = hash['SSLKeyLogFile']
    end

    self.ssl_version = hash.fetch('SSLVersion', nil)

    supported_ssl_verifiers = %W{CLIENT_ONCE FAIL_IF_NO_PEER_CERT NONE PEER}
    if (hash['SSLVerifyMode'] and supported_ssl_verifiers.include? hash['SSLVerifyMode'])
      self.ssl_verify_mode = hash['SSLVerifyMode']
```

**`[verified]` It is a documented public option — `parameters.rb:63`:**
```ruby
# @option hash [OpenSSL::SSL::SSLContext] 'SSLContext' Use a pregenerated SSL Context
```

**`[verified]` Enumeration of the `'SSLContext'` literal across BOTH trees — 4 occurrences total:**

| Tree | File:line | Kind |
|---|---|---|
| gem | `parameters.rb:63` | **doc comment** |
| gem | `parameters.rb:120` | the truthiness check |
| gem | `parameters.rb:121` | the assignment |
| **msf** | **`modules\auxiliary\server\openssl_altchainsforgery_mitm_proxy.rb:148`** | **`'SSLContext' => context,`** |

### §2.1 The answer: it exists for externals, and has exactly ONE in-corpus caller

**`[verified]` ONE caller in the entire MSF tree**, and it is **not a handler, not an exploit, not a payload** — it is **`openssl_altchainsforgery_mitm_proxy.rb`**, an auxiliary **MITM proxy that forges certificate chains.** `[inferred]` That module supplies its own pregenerated context **precisely because controlling the context is the module's purpose.**

**So D54's U3 is answered:** *"if a handler cannot reach the `SSLContext` option, what is `parameters.rb:121` for?"* — **it is a public option of the `Rex::Socket::Parameters` API, and the corpus's only consumer is a cert-forgery aux module.** **`[inferred]` This confirms D54 §1.1's Q1 rule from the consumer side: the bypass branch at `ssl_tcp_server.rb:44-45` is unreachable from `handler\` because nothing under `handler\` ever supplies the key.**

### §2.2 A distinction that must not be merged: two ways to inject a context

**`[verified]` `sslctx=` has 11 writes in the MSF tree, but only ONE goes through the `'SSLContext'` hash key** (§2.1). The other **10 write `sslctx` directly onto a socket object** — `rdp.rb:1208`, `smtp_deliver.rb:299`, `vmauthd.rb:95`, `rex\post\meterpreter\client.rb:253`, and others (D54 §1 enumerated these).

**`[inferred]` These are two different mechanisms with different reach.** The direct-assignment form sets an attribute on an already-constructed socket; the hash-key form feeds context *selection* at construction time (`ssl_tcp_server.rb:44`). **Reporting "11 `sslctx` writes" as one number would merge a construction-time selector with a post-construction override.** The correct statement is **1 by hash key, 10 by direct assignment.**

---

## §3 U5 — the `ssl_compression` default

**`[verified]` The authoritative datastore default — `lib\msf\core\exploit\remote\tcp_server.rb:29`:**
```ruby
OptBool.new('SSLCompression', [ false, 'Enable SSL/TLS-level compression', false ]),
```
**Default: `false`.**

**`[verified]` The mixin passes it through — `tcp_server.rb:135-138`:**
```ruby
# @return [Bool] enable SSL/TLS-level compression
def ssl_compression
  datastore['SSLCompression']
end
```

**`[verified]` And `parameters.rb:135-136` is a TRUTHINESS check, not a key-presence check:**
```ruby
if hash['SSLCompression']
  self.ssl_compression = hash['SSLCompression']
```
**`[inferred]` When the key is absent, `attr_accessor :ssl_compression` (`:466`) is never assigned, so it stays `nil` — which is FALSY.**

### §3.1 The answer: compression is OFF by default, and here is the chain

**`[inferred]` `ssl.rb:146-152`:**
```ruby
    if defined?(OpenSSL::SSL::OP_NO_COMPRESSION)
      if params.ssl_compression
        ctx.options &= ~OpenSSL::SSL::OP_NO_COMPRESSION
      else
        ctx.options |= OpenSSL::SSL::OP_NO_COMPRESSION
      end
    end
```
**`nil` → falsy → the `else` branch → `ctx.options |= OP_NO_COMPRESSION` → compression DISABLED.**

> **Compression is OFF by default. It is operator-enableable via the `SSLCompression` advanced option, and NOT version-dependent — the only conditionality is whether the local OpenSSL defines `OP_NO_COMPRESSION` at all (`:146`).**

**`[inferred]` This resolves D54 §3.2's caveat.** D54 wrote: *"`options = 0` is therefore not 'no options at all' in the common case; it is `0` then `|= OP_NO_COMPRESSION`."* **That is now settled — the common case is exactly that, because the default is `false` and the truthiness check sends it to `else`.**

### §3.2 No handler overrides it — stated with the enumeration

**`[verified]` `ssl_compression` — all 16 occurrences across both trees:**

| Tree | File:line |
|---|---|
| gem | `parameters.rb:136`, `:466`; `ssl.rb:148` |
| msf | `exploit\remote\tcp_server.rb:66`, `:136`; `payload\adapter\fetch\server\http.rb:51`, `:54`, `:149`, `:160`; `...\https.rb:33`, `:46`; `rex\proto\http\server.rb:49`, `:57` (×2), `:98`, `:226` |

**`[verified]` ZERO occurrences under `handler\`.** **Positive control:** the same token returns **16 hits in 8 files** elsewhere — the probe bites.

**`[inferred]` So no handler overrides compression; the default reaches every handler that builds a context.** For the 2 handlers that do (`reverse_tcp_ssl.rb`, `reverse_tcp_double_ssl.rb`), compression is off.

### §3.3 The three exploit modules that name `SSLCompression` are not applying it

**`[verified]` 12 `SSLCompression` occurrences; three are in exploit modules** — `chaos_rat_xss_to_rce.rb:292`, `log4shell_header_injection.rb:271`, `cve_2023_21839_weblogic_rce.rb:323`.

**`[verified]` All three are the SAME construct — passing the datastore value into a server-start call:**
```ruby
  datastore['SSL'], datastore['SSLCert'], datastore['SSLCompression'], datastore['SSLCipher'], datastore['SSLVersion']
```
**`[inferred]` None sets it to `true`.** They forward the operator's setting. **`[absence]` No module in this corpus forces `SSLCompression` on** — a probe for `SSLCompression.*true` or `=> true` in that position returns nothing, and the three sites are enumerated above so the claim is bounded by inspection rather than by count.

---

## §4 Residual unknowns, each with a probe

**U1 — `reverse_http.rb`'s HTTP server service was not read for its own context construction.** §1.1 establishes that `:248` passes `datastore['HandlerSSLCert']` into the service; **it does not establish what the service does with it** (`rex\proto\http\server.rb` is in the *MSF tree*, not the gem — its `:98` `'SSLCompression' => self.ssl_compression` was seen, `:49`/`:57` show a `ssl_cert` parameter). **Probe:** read `rex\proto\http\server.rb:40-110` and trace whether `ssl_cert` reaches `makessl`, a `'SSLContext'` key, or a third path. **This is the largest remaining gap: it is the TLS construction site for `reverse_https`, `reverse_http`, and every fetch/HTTP handler.**

**U2 — the 10 direct `sslctx=` assignments were not traced to a constructor.** §2.2 separates the two mechanisms; it does not claim the 10 bypass `makessl`. **Probe:** for each (`rdp.rb:1208`, `smtp_deliver.rb:299`, `vmauthd.rb:95`, `client.rb:253`/`:266`, `vmauthd_version.rb:108`, `checkpoint…:225`, `nagios…:177`, `bmc_server…:232`, `hp_dataprotector…:127`), classify whether the socket was already constructed.

**U3 — `SSLVerifyMode`'s datastore reachability was not enumerated.** `parameters.rb:131` gates on `%W{CLIENT_ONCE FAIL_IF_NO_PEER_CERT NONE PEER}` — an **allow-list**, so `verify_mode` is constrained. **Probe:** enumerate `SSLVerifyMode` across the tree and determine whether any consumer can set `NONE` on a **server** context, which would be the explicit-off switch D42 §2.6 searched for and did not find at the gem level.

**U4 — no execution.** Ruby absent. **`VERIFY_NONE`-by-default, the falsy-`nil` chain in §3.1, and the `OP_NO_COMPRESSION` outcome are contract claims, labelled `[inferred]`.** One Ruby session would convert all three to `[verified]`.

**U5 — `ssl_cn` / `SSLKeyLogFile` not traced.** `parameters.rb:124-125` accepts `SSLKeyLogFile`, and `ssl_tcp.rb:87-97` writes session keys to disk when set — **a deliberate TLS-decryption affordance.** **Probe:** enumerate `SSLKeyLogFile` consumers and whether any handler or default sets it. **`[inferred]` If a default ever set it, the corpus's "defender has the traffic, lacks the key" framing would invert** — no default was found, but I did not enumerate it.

---

## §5 Instrument record

### §5.1 The failure this pass was the BRIEF's, not the probe's — and it is shape #3 for the third time

**No instrument failure occurred in this pass.** Every probe printed its matches, its control, or its terminator in the same invocation. The notable event is that **the supplied premise was wrong** (§0.1): a file assumed vendored inside the Metasploit tree, when the tree has no `lib\rex\socket\` at all.

**`[inferred]` This is the same root cause as D42 §6.1 and D42 §6.2 — *a path specified from a name rather than from an enumeration* — but for the first time the name came from the task description rather than from my own assumptions.** The defence was identical and already in place: I ran the **existence check and the recursive corpus-wide enumeration together**, with a `*.gemspec` control proving the enumeration finds multiple copies. **Had I trusted the premise, I would have reported "the vendored copy is missing" — a false finding about the corpus, generated entirely by the brief.**

### §5.2 What went right: the control was in the same command as the number, every time

- **§0.1** — `Test-Path` + `Get-FileHash` for both operands, **plus** the recursive enumeration, **plus** a `*.gemspec` control, in one invocation.
- **§1.1** — `reverse_http.rb`'s TLS sites printed **with a file-bytes/lines control** (`19,124 B / 582 lines`) proving the probe read the file.
- **§3.2** — the `ssl_compression` handler-zero was reported **with its 16-hit cross-tree enumeration** in the same output; **the zero and its positive control are one artifact.**
- **§2.1** — the `'SSLContext'` enumeration printed **all 4 occurrences with their trees**, so "one caller" is a printed list, not a count.

### §5.3 The `StagerVerifySSLCert` near-miss

**I was one step from recording `StagerVerifySSLCert` as `reverse_https.rb`'s certificate-verification control.** Its name, its `OptBool` shape, and its position in a TLS handler all point that way. **The consumer enumeration showed 6 of 10 occurrences are in `payload\windows\reverse_win_https*.rb` — the implant side — and none is in a listener path.**

**`[inferred]` The general form, and it is a sub-shape worth adding to the ledger:** *an option's name encodes the FRAMEWORK's intent, but its consumers encode its DIRECTION.* `StagerVerifySSLCert` reads as "verify the SSL cert [here]"; it means "tell the stager to verify the SSL cert [there]." **The registration site and the consumption site are on opposite ends of the connection.** A handler-side read cannot distinguish them — only the consumer list can.

---

*End of D58.*
