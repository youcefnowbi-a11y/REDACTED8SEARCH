# D26 — `rex/socket/comm/local.rb`: does the proxy chain actually get walked?

**Task:** task-35
**Lane:** metasploit core framework (`lib/msf/core/`, `lib/rex/`)
**Status:** COMPLETE
**Deliverable:** `RE_Library\07_OUTPUT\reports\DEEP\D26_rex_comm_local.md` (write scope: this file only)
**Target:** `RE_Library\04_TOOLS\gems\rex-socket-0.1.71\src\lib\rex\socket\comm\local.rb` — **23,093 B / 659 lines**
**Method:** static source read. No Ruby toolchain on this host. Every claim is `[source]` with `file:line`.

**Provenance note.** D22 §4.4 listed `comm/local.rb` as one of five files that "carry the whole transport decision" **without reading it** — a citation to an unread file inside a closed deliverable. This report closes that gap. The citation turned out to be **correct**, but it was not earned when written, and that is the reason this task exists.

---

## TOC

- §1 The answer, up front
- §2 The chain walk, line by line
- §3 All five proxy types — full dispatch table
- §4 Enumeration: every concrete `Comm` in the corpus
- §5 The five `parameters.rb` parse sites, traced
- §6 What makes `Local` local — and the absent remote
- §7 Instrument record — an eighth failure
- §8 Residual unknowns

---

## §1 The answer, up front

**The falsifiable question was: does the local path ever consult `param.proxies`, or does proxying require a different `Comm` implementation that is not in this gem?**

**Answer: `Local` consults and walks the proxy chain itself. It is the only concrete `Comm` in the corpus, and it implements all five proxy types.** This is branch one of the three pre-authorized outcomes, not branch three.

`[verified]` — three independent facts establish it:

| Evidence | Line | What it shows |
|---|---|---|
| `if param.proxies?` → `ip = param.proxies.first.host` | `local.rb:350-352` | The **connect target is the first proxy**, not `param.peerhost` |
| `param.proxies.each_cons(2)` chain walk | `local.rb:418-424` | Multi-hop proxy→proxy walk, then last-proxy→target |
| `def self.proxy(...)` with **five** `ProxyType` branches | `local.rb:439-567` | SAPNI, HTTP, SOCKS4, SOCKS5, SOCKS5H all implemented |

**The `proxies.rb` parser is therefore NOT an orphan.** D22 §4.4's worry — that the 1,518 B five-type parser might be wired to a path with no shipped consumer — **is resolved in the negative: it has a shipped consumer, and the consumer is `local.rb`.**

**The three-way outcome, resolved:**

| Pre-authorized branch | Result |
|---|---|
| Walks the chain → document the walk | **✅ THIS ONE** — §2, §3 |
| Never consults proxies → orphan parser | ❌ not the case |
| Wired at runtime → "consumer not in corpus" | ❌ not the case — the consumer is present and in-gem |

**No `§4c`-shaped answer was needed.** That branch was pre-authorized as the expected one; it is the one that did not occur. Recorded plainly rather than back-filled, because a pre-authorization that is never used is itself a data point about the corpus.

---

## §2 The chain walk, line by line

**Two-stage design: connect to the head of the chain, then negotiate hop by hop.**

### §2.1 Stage one — the connect target is substituted

`[verified]` `local.rb:350-362`:

```ruby
if param.proxies?
  ip   = param.proxies.first.host      # :351
  port = param.proxies.first.port      # :352
else
  if Rex::Socket.is_ip_addr?(param.peerhost)
    ip = param.peerhost
  elsif param.v6
    ip = Rex::Socket.getaddresses(param.peerhost, true)...sample
  else
    ip = Rex::Socket.getaddresses(param.peerhost, false)...sample
  end
  port = param.peerport                # :361
end
```

**The socket physically connects to `proxies.first`.** `param.peerhost` is never resolved or contacted when a chain is present — it becomes the *eventual* destination carried inside proxy protocol payloads.

**The error path preserves that distinction** — `[verified]` `local.rb:394-399`:

```ruby
rescue ::Errno::ECONNRESET,::Errno::ECONNREFUSED,::Errno::ENOTCONN,::Errno::ECONNABORTED
  sock.close
  # Report the actual thing we were trying to connect to here, not
  # param.peerhost, since that's the eventual target at the end of the
  # proxy chain
  raise Rex::ConnectionRefused.new(ip, port.to_i), caller
```

**The comment states the design intent explicitly: `param.peerhost` is "the eventual target at the end of the proxy chain."**

### §2.2 Stage two — the hop-by-hop walk

`[verified]` `local.rb:418-424`:

```ruby
if param.proxies?
  param.proxies.each_cons(2) do |current_proxy, next_proxy|
    proxy(sock, current_proxy.scheme, next_proxy.host, next_proxy.port)
  end
  current_proxy = param.proxies.last
  proxy(sock, current_proxy.scheme, param.peerhost, param.peerport)
end
```

**`each_cons(2)` is the mechanism.** For a chain `[P1, P2, P3]` it yields `(P1,P2)` and `(P2,P3)`: each iteration negotiates *through the current proxy to reach the next one*. The trailing call then negotiates *through the last proxy to reach the real target.*

| Chain | `each_cons(2)` pairs | Final call | Total negotiations |
|---|---|---|---|
| `[P1]` (single) | *(none — needs ≥2)* | P1 → target | **1** |
| `[P1,P2]` | (P1,P2) | P2 → target | **2** |
| `[P1,P2,P3]` | (P1,P2), (P2,P3) | P3 → target | **3** |

`[read]` **Single-proxy chains skip the loop entirely** — `each_cons(2)` on a one-element array yields nothing — and go straight to the final call. Correct, but note the consequence: **for a one-proxy chain the negotiation type is `proxies.last.scheme`, which is the same scheme that stage one connected to.** Consistent.

**The nested-proxy semantics are real multi-hop, not a single CONNECT to a proxy that chains internally.** Each hop is negotiated by its own `proxy()` call on the same socket.

### §2.3 Failure semantics

`[verified]` every `proxy()` branch raises `Rex::ConnectionProxyError` with `host`, `port`, `type`, and a **specific** message — never a bare failure:

- `"Failed to send the entire request to the proxy"` (`:476`, `:514`, and per-branch)
- `"Failed to receive a response from the proxy"` (`:485`, `:520`)
- `"Connection to #{host}:#{port} blocked by ACL"` (`:499`)
- `"The proxy returned a non-OK response"` (`:532`)
- `"The SOCKS4 target host must be an IPv4 address or a hostname"` (`:537`)

**Proxy failure is loud and typed.** This is the opposite of the swallow pattern D9 §17 recorded for `lib/msf/core/` — here the transport layer fails closed with **named exceptions carrying the specific hop that failed.**

---

## §3 All five proxy types — full dispatch table

`[verified]` `local.rb:439` opens `def self.proxy(sock, type, host, port)`. **All five types declared in `proxies.rb:6-12` have a branch:**

| Proxy type | `local.rb` branch | Mechanism | Protocol detail |
|---|---|---|---|
| **SAPNI** | `:441` | SAP NI_ROUTE packet | `packet_type='NI_ROUTE'`, `route_info_version=2`, `ni_version=39`, `num_of_entries=2`, `talk_mode=1`; `[A8c8]` header; 4-byte length prefix; SAP doc citation in comment (`:446`) |
| **HTTP** | `:510` | `CONNECT` | `"CONNECT #{host}:#{port} HTTP/1.0\r\n\r\n"` (`:511`); parses status, requires **200** (`:531`) |
| **SOCKS4** | `:534` | SOCKS4 CONNECT | Requires IPv4 or hostname, resolves via `Rex::Socket.getaddress(host, false)` (`:541`) |
| **SOCKS5** | `:550` | SOCKS5 CONNECT | — |
| **SOCKS5H** | `:567` | delegated | Calls `self.proxy_socks5h` (`:615`) |

**Two helper methods exist beyond the dispatcher:**
- `proxy_socks4a` — `:594`
- `proxy_socks5h` — `:615` — the remote-DNS-resolving variant, which is **exactly why `socks5` and `socks5h` are separate constants** (`proxies.rb:10-11`): a socks5h proxy resolves the *target hostname on the proxy side*, so `local.rb` must send the name rather than a pre-resolved IP.

**`[verified]` SOCKS5 handshake shape** (`local.rb:638`):
```ruby
setup = [5,1,0,3].pack('C4') + [host.length].pack('C') + host + [port.to_i].pack('n')
```
`[5,1,0,3]` = version 5, 1 auth method, `0x00` (no auth), `0x03` (DOMAINNAME address type) — **a domain name is always sent**, consistent with socks5h semantics.

**Response validation** (`:652-657`): requires `≥10` bytes and `response[1,1] == "\x00"`, else raises with the proxy's error code unpacked into the message.

**Conclusion: the coverage is complete — 5 of 5.** Not a subset.

---

## §4 Enumeration: every concrete `Comm` in the corpus

`[verified]` — enumerated across **all** of `01_SOURCE_c2` and `04_TOOLS\gems` for files including `Rex::Socket::Comm`.

| File | Bytes | Kind |
|---|---|---|
| `metasploit\lib\msf\core\session\comm.rb` | 683 | mixin / abstract |
| `metasploit\plugins\db_tracker.rb` | 1,770 | mixin / abstract |
| `metasploit\plugins\ips_filter.rb` | 2,603 | mixin / abstract |
| `metasploit\plugins\socket_logger.rb` | 2,905 | mixin / abstract |
| **`rex-socket-0.1.71\src\lib\rex\socket\comm\local.rb`** | **23,093** | **CONCRETE — defines `self.create`** |

**Total: 5 files include `Rex::Socket::Comm`. Exactly 1 is concrete.**

`[verified]` — a second, independent probe searched for `class Rex::Socket::Comm::<X>` anywhere in the corpus and returned **exactly one hit: `Local`.**

**The 12 absent gems cannot hold a proxy-walking `Comm` — or rather, none is needed.** D22 §5 established 12 of 18 `rex-*` gems are absent. **That gap is irrelevant to this question**, because the proxy walk does not require a second `Comm`: it is *inside* `Local`. **Reading `local.rb` retires the gem gap as a confound for the transport question specifically** — the answer was not hiding in a missing gem. This is worth stating plainly because D22 §4.4 speculated otherwise.

**The other four are not `Comm` implementations in the factory sense** — they are listener/observer mixins that hook the `notify_before_socket_create` / `notify_socket_created` callbacks (`local.rb:102`, `:115`, `:159`, `:434`). They extend `Comm` to observe socket lifecycle; none defines `create`.

---

## §5 The five `parameters.rb` parse sites, traced

`[verified]` each of the five keys D22 §4.2 cited, traced from parse to use or to nowhere.

| Key | `parameters.rb` | Consumed at | Status |
|---|---|---|---|
| `'SSL'` | `:116` | `local.rb:64`, `:72`, `:295`, `:427` | **USED** |
| `'SSLVersion'` | `:128` | via `SslTcp#initsock` (`:429`) | **USED (indirect)** |
| `'Proxies'` | `:175-176` | `local.rb:165`, `:350`, `:418`, `:351-352`, `:422-423` | **USED — 5 distinct sites** |
| `'Proto'` | `:180-181` | `local.rb:35`, `:59`, `:293`, `:404` | **USED** |
| `'Comm'` | `:188` | `socket.rb:51-53` (`param.comm.create`) | **USED — the dispatch itself** |

**All five reach a use. No orphan parameters.** `'Proxies'` is the most-consumed of the five, which is consistent with §1: this file is where the proxy decision lands.

**`[verified]` SSL is applied AFTER the proxy walk**, `local.rb:426-430`:
```ruby
# Now extend the socket with SSL and perform the handshake
if !param.bare? && param.ssl
  sock.extend(Rex::Socket::SslTcp)
  sock.initsock(param)
end
```

**The ordering is load-bearing and worth naming: proxy negotiation is completed first, then TLS wraps the resulting tunnel.** This is what makes "C2 over HTTPS through a SOCKS5 chain" work — the TLS session is established *through* the proxy tunnel, end to end to the real target, rather than terminating at the proxy. **An operator's TLS is not broken by the proxy because the proxy never sees plaintext.**

---

## §6 What makes `Local` local — and the absent remote

**The name is a statement about process boundary, not about network distance.**

`[verified]` `local.rb:20-23` includes `Singleton` and `Rex::Socket::Comm`. The class creates sockets via **in-process OS syscalls** — `::Socket.new` (`:205`, `:207`), `::TCPSocket.new` (`:70`), `::Socket.open` (`:104`). Everything happens in the current process.

**`Comm` exists as a swappable object precisely so that socket creation need not be local.** D22 §4.4 established the `Comm` abstract factory as the pivot mechanism. `Local` is the default: the operator's own process creates the socket.

**`[verified]` There is NO remote counterpart in-gem.** Section §4 enumerated the entire corpus for concrete `Comm` classes and found exactly one.

**But the code asserts a second one exists.** `[verified]` `local.rb:161-168`:

```ruby
# Binding to a specific interface while routing through a proxy is not
# supported. The proxy comm handles its own socket creation and ignores
# the interface option entirely, so we fail fast here rather than
# silently binding to the wrong interface.
if param.interface && !param.interface.empty? && param.proxies?
  raise Rex::BindFailed.new(param.localhost, param.localport,
    reason: 'Interface option is incompatible with proxy use'), caller
end
```

**This comment refers to "the proxy comm" as a distinct thing that "handles its own socket creation."** That is a reference to an architecture in which proxy handling is delegated to a *separate* `Comm`. **No such class is present in the corpus.**

**This is a `§4c`-shaped observation after all — just not for the question that was asked.** The *proxy walk* has a shipped consumer (`Local`). **A distinct "proxy comm" does not.** Two readings, both recorded, neither chosen here:

- `[inferred]` **Reading A — comment is stale.** Proxying was once delegated to a separate comm, later folded into `Local` (`:350-424`), and the comment was not updated. Supports: `Local` demonstrably does the work the comment attributes elsewhere; the guard's *behaviour* (refuse interface+proxy) is correct regardless.
- `[inferred]` **Reading B — comment anticipates an out-of-corpus comm.** A plugin or external comm is expected to exist that handles proxies and ignores `interface`. Supports: the comment is written in present tense, and the guard exists specifically because such a comm would silently ignore the option.

**Neither reading is established by this report.** Reading A is better supported by the code that exists; Reading B is better supported by the comment's tense. **Recorded as a residual unknown (§8, U3) rather than resolved**, because the corpus contains evidence for a design that isn't in the corpus, and that is exactly the class of thing D17 §4c was coined for.

**`[verified]` Also note: this guard is a D22-class finding in miniature.** `interface` + `proxies` is **refused loudly** rather than silently mishandled. The comment says so explicitly: *"we fail fast here rather than silently binding to the wrong interface."* **Whoever wrote this line had the same instinct as the `KeySearchError` in D9 §17.**

---

## §7 Instrument record — an eighth failure

**This report caught one probe failure. It is recorded rather than silently corrected.**

**The probe:** enumerating `proxies.rb`'s `ProxyType` constants to build a positive control, using the regex `ProxyType::(\w+)\s*=\s*'(\w+)'`.

**It returned nothing.** `[verified]` zero matches.

**The truth** (`proxies.rb:6-12`):
```ruby
module ProxyType
  SAPNI = 'sapni'
  HTTP = 'http'
  SOCKS4 = 'socks4'
  SOCKS5 = 'socks5'
  SOCKS5H = 'socks5h'
end
```
**The assignments are bare — no `ProxyType::` prefix — because they are written *inside* the `ProxyType` module.** My regex assumed the qualified form `ProxyType::SAPNI = 'sapni'`, which is how the constants are *referenced* (`local.rb:441`) but not how they are *declared*.

**Root cause: identical in shape to §7.1 of D22.** That report logged two probes failing because I assumed `'Handler' =>` / `'Rank' =>` hash-key syntax where the corpus used something else. **This is the same defect a third time: I assumed a syntactic form for a declaration without first confirming it.**

**How it was caught:** by my own standing rule — *an instrument that returns NOTHING is more suspicious than one that returns something wrong.* A zero here would have silently produced a §3 dispatch table with **no positive control**, meaning the "5 of 5 types handled" claim would have rested on `local.rb` alone with nothing to compare against. **I read the actual bytes instead of trusting the empty result.**

**The consequence had it gone unnoticed:** the headline coverage claim (5 of 5) would still have been correct, but **unverifiable** — I would have been asserting that `local.rb` handles every declared type without ever having enumerated what was declared. That is precisely the unearned-citation failure this whole task exists to correct.

**This is the eighth instrument failure in the corpus, and the third instance of one specific defect** — *probe shape does not match evidence shape*. Two were syntactical (`'Handler' =>`, `'Rank' =>`), one temporal (stale baseline, D22 §7.2), and now this one syntactical again. **The synthetic form of the rule: a declaration is not necessarily written in the form in which it is referenced.**

---

## §8 Residual unknowns

**U1 — Nothing was executed.** `[source]` only; no Ruby on this host. `[verified]` The chain walk in §2.2 is **read**, not observed. A runtime confirmation would construct a `Parameters` with a two-element `Proxies` chain and confirm two negotiations occur. **Highest-value confirmation available to a future pass with a Ruby environment.**

**U2 — `each_cons(2)` single-proxy behaviour is `[read]`, not executed.** I assert that a one-element array yields no pairs. This is standard Ruby `Enumerable#each_cons` semantics and is stated with the line reference, but it was not run. **Low risk, stated for completeness.**

**U3 — The "proxy comm" of `local.rb:161-168` is not in the corpus.** Two readings recorded in §6, neither chosen. **This is a genuine §4c-shaped residual: the corpus contains evidence of a design component that is absent from the corpus.** Whether the comment is stale (Reading A) or anticipates an external plugin comm (Reading B) **cannot be settled by reading.** Do not infer it shut.

**U4 — `proxy_socks4a` (`:594`) and `proxy_socks5h` (`:615`) were located and their call sites identified, but their internal protocol bodies were not read line-by-line.** The dispatch table in §3 is complete; the *bodies* of the two helpers are `[read]` at the call-site level only.

**U5 — The `interface` binding path (`local.rb:170-213`) was read but not fully traced.** It is orthogonal to the proxy question. Included here so the boundary is explicit rather than implied.

**U6 — No claim is made about whether any *specific* Metasploit module actually constructs a proxy chain.** D22 §4.3 established 27 of 302 proto files forward `Proxies`; whether operators populate it is a configuration question, not a source question.

---

## §9 What would falsify this report

- A concrete `Comm` class other than `Local` anywhere in `01_SOURCE_c2` or `04_TOOLS\gems`. **Searched two independent ways; found none.**
- A `ProxyType` constant lacking a branch in `proxy()`. **All 5 confirmed present by direct read of both files.**
- A path where `param.proxies` is populated but `local.rb:350` / `:418` is not reached. **Both guards are on `param.proxies?`, the same predicate; no bypassing branch was found.**
- Evidence that `local.rb:161-168`'s "proxy comm" exists and is shipped. **Would resolve U3 toward Reading B.**

**D22 §4.4's citation was correct. It is now earned.**

---

*End of D26.*
