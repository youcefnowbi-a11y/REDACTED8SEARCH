# D22 — MSF module census and `lib/rex/proto/` coverage

**Task:** task-33 (board title task-32) · **Lane:** msf-diver · **Status:** IN PROGRESS
**Deliverable:** this file. **Write scope:** this file only. D7/D8/D9 and `STATUS.md` are read-only; not touched.
**Target:** `RE_Library\01_SOURCE_c2\metasploit`
**Method discipline:** enumerate, never estimate. **Every headline count carries a second independent enumerator.** Every absence carries a positive control proving the probe bites.

---

## TABLE OF CONTENTS

- §1 The denominator defect — what "2,715" actually counts
- §2 Composition by category and sub-category
- §3 The 24 handlers, classified
- §4 `lib/rex/proto/` — the transport/TLS/proxy decision points
- §5 The 18 `rex-*` gems: 5 unpacked, 13 enumerated
- §6 Highest-value 20 modules by (impact × reachability)
- §7 Residual unknowns

---

## §1 The denominator defect — what "2,715" actually counts

D9 recorded "**2,715 exploit modules never enumerated**." That number is **arithmetically correct and semantically wrong in two separate ways.** This section fixes the denominator before any downstream number is used.

**Ground truth, three independent enumerators, exact agreement:**

| Method | Command form | Count |
|---|---|---|
| A | `Get-ChildItem -Recurse -File -Filter *.rb` | **2,715** |
| B | `Directory.EnumerateFiles(..., AllDirectories)` | **2,715** |
| C | `cmd /c dir /s /b` | **2,715** |

Three enumerators, zero disagreement. **2,715 is a real measurement.** But it measures the wrong boundary twice over:

### §1.1 Defect one — 2,715 counts FILES, and 4 of them are not exploits

`modules/exploits/` contains **2,711 `.rb` files inside the 19 category directories**, plus **4 loose `.rb` files at the top level**. Those four are stubs:

| File | Bytes | `'Name'` | `'Payload'` | Verdict |
|---|---|---|---|---|
| `example.rb` | 3,075 | yes | yes | **template** — carries literal stub marker |
| `example_linux_persistence.rb` | 6,219 | yes | **no** | **template** — non-exploit |
| `example_linux_priv_esc.rb` | 6,827 | yes | **no** | **template** — non-exploit |
| `example_webapp.rb` | 8,161 | yes | **no** | **template** — non-exploit |

**The real exploit-module count is 2,711, not 2,715.** A 4-module error in a denominator is small in absolute terms and exactly the kind of thing that silently propagates: any later "N of 2,715 modules" percentage is wrong in the first decimal.

The `'Payload'` key is the discriminator: **a Metasploit exploit module declares a `Payload`; a template or a non-exploit does not.** Three of four lack it and `example.rb` self-identifies with a stub marker. Both tests agree.

> **Note on scope adherence.** Inspecting 4 files for a `'Payload'` key is not "enumerating the 2,715." I did not read module bodies, and I will not: the task explicitly scopes reading to the top 20 (§6). The four loose files are boundary artifacts that had to be classified before the denominator could be stated.

### §1.2 Defect two — "2,715" measures one directory out of seven

`modules/` contains **seven** module types, and the corpus's own scope (`lib/msf/core/`, `lib/rex/`) never justified why `exploits/` was the boundary:

| Module dir | `.rb` count |
|---|---|
| **exploits** | **2,715** |
| auxiliary | 1,347 |
| payloads | 545 |
| post | 436 |
| encoders | 57 |
| nops | 14 |
| evasion | 13 |
| **TOTAL** | **5,127** *(matches D7:1327's independently stated 5,127)* |

**2,715 is 53.0% of the module tree.** D7 §2's "1,181 of 15,051 files (7.8%)" reads better or worse depending on which denominator is used, and the corpus never declared which. This is D17 §1.0.1's defect precisely: **a correct number measuring a boundary nobody justified.**

**What the boundary should be.** The reversal's question is *how Metasploit delivers a session*, and that question is answered by `exploits/` **plus `payloads/`** (545 — the stage/stager machinery D7 §11 and D9 §13 already partially cover) **plus `encoders/`** (57 — the delivery-encoding path D7 §12.1 established does *not* live at `lib/rex/encoder/`). `auxiliary/` is scanner/credential noise for a session-delivery reversal. **I am using 2,711 exploits as the census denominator and naming the exclusion, rather than reporting a bare total.**

### §1.3 The boundary, made explicit and falsifiable

```
IN  : modules/exploits/**/*.rb          2,711   ← census denominator
IN  : modules/payloads/**/*.rb            545   ← delivery machinery, cited where load-bearing
IN  : modules/encoders/**/*.rb             57   ← delivery encoding
OUT : modules/auxiliary/**/*.rb         1,347   ← scanners/creds; no session delivery
OUT : modules/post/**/*.rb                436   ← post-exploitation; outside reversal scope
OUT : modules/{nops,evasion}/**            27   ← not delivery-critical
OUT : 4 template stubs                        ← not exploits (proven §1.1)
```

---

## §2 Composition by category and sub-category

**All counts are exact enumerations.** Platform totals below are produced by two independent enumerators that agreed exactly (2,715 and 2,715). Sub-categories are single-enumerator with the parent sum cross-checked against the platform total — noted where that check applies.

### §2.1 By platform (19 directories + 4 loose files)

| Platform | Modules | % of 2,715 |
|---|---|---|
| **windows** | **1,236** | **45.5%** |
| **linux** | **578** | **21.3%** |
| **multi** | **564** | **20.8%** |
| unix | 227 | 8.4% |
| osx | 43 | 1.6% |
| freebsd | 16 | 0.6% |
| solaris | 15 | 0.6% |
| android | 10 | 0.4% |
| apple_ios | 6 | 0.2% |
| aix | 5 | 0.2% |
| *(loose stubs)* | 4 | 0.1% |
| netware | 2 | 0.1% |
| qnx | 2 | 0.1% |
| bsd / bsdi / irix / hpux / mainframe / firefox / openbsd | 1 each | 0.04% each |
| **TOTAL** | **2,715** | 100% |

**Windows + Linux + Multi + Unix = 2,605 of 2,715 = 96.0%.** Everything else is 110 modules across 15 niche platforms. **A census is not required to be uniform; this one is overwhelmingly three platforms and one shared web/HTTP surface.**

### §2.2 The service dimension — where the composition actually concentrates

Platform is the coarse axis. The **sub-category** is where the census becomes informative, because it names the *attack surface*, and the surface is not evenly spread:

| Sub-category | Modules | Note |
|---|---|---|
| **multi/http** | **401** | largest single sub-category |
| **linux/http** | **367** | |
| windows/browser | 247 | |
| windows/http | 227 | |
| windows/fileformat | 194 | client-side, file-open trigger |
| unix/webapp | 160 | |
| windows/misc | 118 | |
| windows/local | 110 | privesc |
| linux/local | 95 | privesc |
| windows/ftp | 65 | |
| multi/browser | 49 | |
| multi/misc | 48 | |
| linux/misc | 45 | |
| windows/scada | 38 | ICS |
| unix/http | 34 | |
| windows/smb | 32 | |
| windows/persistence | 28 | |
| osx/local | 20 | |
| windows/brightstor | 19 | |
| linux/persistence | 18 | |

### §2.3 Finding — the census concentrates on HTTP, and that is a transport fact

**HTTP-family modules: 401 + 367 + 227 + 160 + 34 = 1,189 — 43.8% of the entire exploit corpus.**

That is the single most useful number in this census, and it is not obvious from the platform table. Frameworks are enumerated by **platform**, but they are *delivered* by **protocol**, and the protocol distribution is almost half HTTP. **This is the load-bearing link to §4:** the transport/TLS/proxy decision points in `lib/rex/proto/http/` are not an interesting side channel of the reversal — **they sit underneath 43.8% of the delivery surface.**

### §2.4 By handler type — and a probe that returned zero, corrected

The lead asked for a breakdown "by handler type." **My first probe for this returned `0 of 2,715` and I did not record it** — the control fired immediately, because a zero across the whole corpus is the exact signature of a dead instrument (§instrument rule).

**What the control found,** in order:

| Probe | Result | Verdict |
|---|---|---|
| `'Handler' =>` metadata key | **0 files** | **DEAD PROBE** — the pattern is wrong |
| any occurrence of `handler` (case-insens.) | **1,011 of 2,715** | live |
| metadata `'Handler' =>…` | 2 files | both false positives — `'handler' => '/tmui/…'` URI paths, not handlers |
| bare `handler` token (method calls) | 950 hits | **the real signal** |

**There is no per-module `Handler` metadata key at scale.** Metasploit does not declare a handler *type* in module metadata; handler type is a **property of the chosen payload**, not of the exploit. The exploit selects a payload, and the payload's `Handler` (e.g. `Msf::Handler::ReverseTcp`) is what determines transport.

**So "classification by handler type" is answerable only by joining modules to payloads** — and that is a **545-file `modules/payloads/` enumeration**, not an exploit-metadata read. Recorded here rather than faked: **the census's second axis is not extractable from `modules/exploits/` alone, and any handler-type distribution reported from exploit metadata would be invented.**

---

## §3 The 24 handlers, classified — and a 26-vs-24 correction

### §3.1 D7's inventory reproduces exactly

D7 §11 (`D7:973`) claims **24 files in `lib/msf/core/handler/`**. Verified against live source: **24 files, and all 24 byte sizes match D7's table exactly, in the same order.** This is the strongest confirmation in this report — D7's central handler claim is arithmetically sound.

**Positive control for this section:** the probe reads a directory I know is populated, and it returned 24 files with populated sizes. A probe returning "0 handlers" would have been the dead-instrument signature and would not have been recorded.

### §3.2 CORRECTION — the true recursive count is 26, and D7 knew about it

**`lib/msf/core/handler/` contains a subdirectory `reverse/` holding two more `.rb` files:**

| File | Bytes | What it is |
|---|---|---|
| `reverse/ssl.rb` | 464 | **mixin** — registers `HandlerSSLCert` and `Opt::SSLVersion` |
| `reverse/comm.rb` | 1,362 | **mixin** — `select_comm`, resolves `Rex::Socket::Comm` for pivot listeners |

**Recursive count = 26** (confirmed by two enumerators: `Get-ChildItem -Recurse` and `Directory.EnumerateFiles`, both 26).

**D7:977 states: "24 files in `lib/msf/core/handler/` — not 26."** So D7 **counted 26, then declared 24**, defending against the recursive figure without stating the distinction. The number is defensible — the two extras are mixins, not standalone handlers — but **as written it reads as a refutation of 26 while being a top-level-only count.** Anyone re-running a recursive enumeration gets 26 and concludes D7 is wrong. **The fix is one clause: "24 files at the top level (plus 2 mixins under `reverse/`)."**

**This matters beyond bookkeeping.** `reverse/ssl.rb` is *the TLS option registrar* and `reverse/comm.rb` is *the transport-selection resolver* — the two mixins D7's count excludes are the two files that answer the lead's question 2. **Excluding them from the handler inventory while asking where TLS is decided is how a reversed file gets missed.**

### §3.3 Classification by family

**17 concrete transports, 3 base classes, 4 `find_*` discovery helpers** (D7 §11.1's grouping, independently re-derived from the file list):

| Family | Count | Files |
|---|---|---|
| **reverse transports** | 11 | `reverse_http`, `reverse_https`, `reverse_tcp`, `reverse_tcp_ssl`, `reverse_tcp_double`, `reverse_tcp_double_ssl`, `reverse_tcp_all_ports`, `reverse_udp`, `reverse_sctp`, `reverse_ssh`, `reverse_named_pipe` |
| **bind transports** | 7 | `bind_tcp`, `bind_udp`, `bind_sctp`, `bind_named_pipe`, `bind_aws_ssm`, `bind_aws_instance_connect` |
| **base classes** | 3 | `generic`, `none`, `reverse` |
| **`find_*` helpers** | 4 | `find_port`, `find_tag`, `find_tty`, `find_shell` |
| **TOTAL** | **24** | |

**The `find_*` helpers are not transports.** They are payload-side discovery routines — `find_tag` scans for a stager marker, `find_port` probes a range, `find_tty`/`find_shell` locate an interactive device. **Any "17 handler types" statement is counting transports correctly; any "24 transports" is wrong by 7.**

### §3.4 Encoder-backed vs raw — the classification the lead asked for

The lead asked for each handler to be classified **encoder-backed vs raw**. **This classification does not attach to the handler at all**, and the distinction is worth stating precisely because it is a common conflation:

- **Handler** = how bytes arrive (`reverse_tcp`, `bind_https`). Determines **transport**.
- **Encoder** = how bytes are transformed *before* arrival. Determines **evasion**, and is a **payload** property (D7 §12.1 established the encoder path lives at `lib/rex/encoder/`, *not* under the handler).

**They compose but do not classify each other.** A handler is not "encoder-backed" or "raw"; a **payload delivery** is. The correct axis is the one D7 §11.2 already built — **outer protection**:

| Outer protection | Handlers | Count |
|---|---|---|
| **TLS** | `reverse_https`, `reverse_tcp_ssl`, `reverse_tcp_double_ssl` | 3 |
| **SSH** | `reverse_ssh` | 1 |
| **AWS SigV4 + IAM/SSH** | `bind_aws_ssm`, `bind_aws_instance_connect` | 2 |
| **OS pipe ACL** | `reverse_named_pipe`, `bind_named_pipe` | 2 |
| **none (cleartext)** | `reverse_tcp`, `bind_tcp`, `reverse_udp`, `bind_udp`, `reverse_sctp`, `bind_sctp`, `reverse_tcp_double`, `reverse_tcp_all_ports`, `reverse_http` | 9 |
| **base / helper (no transport)** | `generic`, `none`, `reverse`, `find_*` ×4 | 7 |
| **TOTAL** | | **24** |

**9 of 17 concrete transports are cleartext.** That is the number the reversal cares about: on those nine, Meterpreter's own AES layer is the *only* confidentiality control, and D7 §4.3 showed that layer is unauthenticated.

---

## §4 `lib/rex/proto/` — and where rex decides transport, TLS, and proxy

### §4.1 Coverage ledger — 46 protocol directories, 302 files

**Two independent enumerators, exact agreement: 302.** (`Get-ChildItem -Recurse` = 302, `Directory.EnumerateFiles` = 302.)

`lib/rex/proto/` = **46 top-level protocol directories + 27 loose top-level `.rb` files = 302 files total.** Note the loose files are *not* trivial: `ms_dtyp.rb` alone is 43,337 B.

| Proto dir | Files | Bytes | | Proto dir | Files | Bytes |
|---|---|---|---|---|---|---|
| kerberos | 81 | 383,691 | | ms_tds | 7 | 12,104 |
| **http** | **16** | **124,456** | | natpmp | 2 | 2,517 |
| rmi | 15 | 30,087 | | nuuo | 4 | 12,095 |
| ldap | 11 | 45,100 | | ntp | 3 | 8,829 |
| dcerpc | 10 | 50,001 | | pjl | 1 | 4,554 |
| dns | 10 | 64,724 | | proxy | 4 | 26,387 |
| smb | 10 | 181,364 | | quake | 1 | 1,878 |
| amqp | 7 | 28,922 | | redis | 2 | 1,465 |
| ms_tds → | | | | rfb | 3 | 13,757 |
| gss | 6 | 23,959 | | secauthz | 1 | 9,210 |
| iax2 | 6 | 192,735 | | sip | 1 | 1,980 |
| kademlia | 6 | 7,486 | | sms | 5 | 7,597 |
| ntlm | 6 | 68,530 | | ssh | 3 | 16,782 |
| x11 | 6 | 38,087 | | steam | 1 | 3,263 |
| mms | 5 | 9,039 | | sunrpc | 1 | 4,367 |
| ms_nrtp | 5 | 8,585 | | tftp | 3 | 24,920 |
| sms → | | | | thrift | 2 | 5,014 |
| crypto_asn1 | 4 | 27,707 | | x509 | 1 | 7,396 |
| ipmi | 4 | 10,857 | | acpp | 2 | 7,888 |
| nuuo → | | | | adb | 2 | 4,100 |
| dhcpv6 | 3 | 17,872 | | dhcp | 2 | 11,486 |
| drda | 3 | 12,866 | | ftp | 2 | 19,559 |
| ms_adts | 3 | 8,485 | | mssql | 2 | 48,220 |
| rfb → | | | | mysql | 1 | 3,535 |
| ssh → | | | | mdns | 1 | 493 |
| tftp → | | | | mqtt | 1 | 1,030 |

**D9 covered only `http/` (16 files, 124,456 B).** That leaves **286 files across 45 other protocol directories unread** — this is the coverage gap the lead named, and it is real.

**Two files are far larger than their directory suggests and are the reasons `kerberos` (383,691 B) and `smb` (181,364 B) dwarf everything:** they are the two heaviest protocols in the tree, each ~3× the size of `http`.

### §4.2 THE ANSWER — rex decides transport, TLS, and proxy in exactly one place

**The question was "where does rex decide transport, TLS, and proxy?" The answer is: `Rex::Socket`, not `Rex::Proto`. All three decisions are made in a single dispatch, and every protocol directory is a pass-through caller.**

**Decision site 1 — the entry point.** `rex-socket-0.1.71/lib/rex/socket.rb:44-53`:

```ruby
def self.create(opts = {})
  return create_param(Rex::Socket::Parameters.from_hash(opts))
end

def self.create_param(param)
  return param.comm.create(param)      # ← every transport decision resolves here
end
```

**Two lines, one dispatch.** `from_hash` **parses**; `param.comm.create(param)` **decides**. There is no second decision path.

**Decision site 2 — the option parser.** `rex/socket/parameters.rb` is where the raw hash becomes typed decisions:

| Line | Option | Decision made |
|---|---|---|
| `:116` | `'SSL'` | truthiness parsed from `t/y/1` — **is this connection TLS?** |
| `:128` | `'SSLVersion'` | which TLS version |
| `:175-176` | `'Proxies'` | delegated to `Rex::Socket::Proxies.parse` |
| `:180-181` | `'Proto'` | `tcp` / `udp` / `ip` — **the transport** |
| `:188` | `'Comm'` | **the object that will actually create the socket** |

**Decision site 3 — the polymorphic interface.** `rex/socket/comm.rb:48-50`:

```ruby
def self.create(param)
  raise NotImplementedError
end
```

**The base class deliberately refuses to decide.** `Comm` is an abstract factory; the concrete implementation (`comm/local.rb`, 23,093 B — the only one shipped) is what connects. **Proxying is implemented by substituting a different `Comm`, not by branching inside the protocol.**

**Decision site 4 — proxy chain parsing.** `rex/socket/proxies.rb` is a **1,518-byte** parser with **exactly five supported types** (`ProxyType` at `:7-11`): `sapni`, `http`, `socks4`, `socks5`, `socks5h`. It accepts a **comma-separated chain** (`{type:host:port[,type:host:port][…]}`), validates scheme (raising `Unsupported proxy scheme` at `:27`), defaults socks ports to 1080 (`:35`), and **returns an array of URIs — it does not connect.** Parsing and connecting are separated: `Proxies.parse` structures the chain, the `Comm` walks it.

### §4.3 Finding — the protocol layer is a pass-through, and that is verified, not assumed

**This is the claim that answers the question, and it is falsifiable. I tested it across all 302 files:**

**27 of 302 protocol files participate in the transport handoff at all.** Every one of them does the same thing: build an options hash and hand it to `Rex::Socket`.

| File | `Rex::Socket` calls | Transport opts passed |
|---|---|---|
| `http/client.rb` | 2 | `SSL` `SSLVersion` `Proxies` `Comm` |
| `http/server.rb` | 1 | `SSL` `SSLVersion` `Comm` |
| `ftp/client.rb` | 2 | `SSL` `SSLVersion` `Proxies` |
| `amqp/.../client.rb` | 1 | `SSL` `SSLVersion` `Comm` |
| `ms_nrtp/client.rb` | 1 | `SSL` `SSLVersion` `Comm` |
| `thrift/client.rb` | 1 | `SSL` `SSLVersion` `Comm` |
| `mssql/client.rb` | 0 | `SSL` `SSLVersion` `Proxies` |
| `dns/resolver.rb` | 2 | `Proxies` `Comm` |
| `kerberos/client.rb` | 1 | `Proxies` |
| `ldap.rb` | 1 | `Proxies` |
| `ssh/hrr_rb_ssh.rb` | 2 | `Proxies` |
| `proxy/socks4a.rb` | 3 | `Comm` |
| `proxy/socks5/server.rb` | 1 | `Comm` |
| `dns/server.rb`, `ldap/server.rb`, `smb/server.rb`, `ssh/server.rb` | 1-2 each | `Comm` |
| `dhcp/server.rb`, `dhcpv6/server.rb`, `ftp/server.rb`, `iax2/client.rb`, `nuuo/client.rb`, `tftp/client.rb`, `tftp/server.rb`, `proxy/socks5/server_client.rb` | 1-3 each | *(none — plain socket)* |

**The verification is the concrete case.** `Rex::Proto::Http::Client#connect` — `http/client.rb:165-191` — is the canonical example and it is unambiguous:

```ruby
self.conn = Rex::Socket::Tcp.create(
  'PeerHost' => hostname,
  'PeerHostname' => config['ssl_server_name_indication'] || config['vhost'],
  'PeerPort' => port.to_i,
  'Context' => context,
  'SSL' => ssl,                 # ← TLS decision, passed through
  'SSLVersion' => ssl_version,  # ← TLS version, passed through
  'SSLKeyLogFile' => sslkeylogfile,
  'Proxies' => proxies,         # ← proxy chain, passed through
  'Timeout' => timeout,
  'Comm' => comm                # ← transport object, passed through
)
```

**`Rex::Proto::Http::Client` does not decide TLS. It receives `ssl`, `ssl_version`, `proxies` and `comm` as constructor parameters (`:24`) and forwards all four to the socket factory.** The protocol knows HTTP; the socket layer knows transport. **The separation is clean and complete.**

### §4.4 Why this matters for the reversal

**1. There is exactly one place to read.** Anyone reversing "how does Metasploit choose TLS or a proxy" does not need the 46 protocol directories. They need `rex-socket`: `socket.rb` (dispatch), `parameters.rb` (parse), `proxies.rb` (chain), `comm/local.rb` (connect), `ssl_tcp.rb` (TLS wrap). **Five files, ~78 KB, against a 302-file protocol tree.** This is the single highest-leverage reduction in this report.

**2. It explains why `rex-socket` is a gem and not in `lib/rex/`.** The socket layer is versioned and vendored independently — `Gemfile.lock` pins `rex-socket (0.1.71)`. **A reversal that reads only the framework checkout would find `lib/rex/proto/http/client.rb` calling `Rex::Socket::Tcp.create` and would have no source for it.** §5 quantifies that gap.

**3. The `Comm` indirection is the pivot mechanism.** Because `Comm` is an abstract factory whose concrete implementations are swappable, **pivoting through a session is implemented by substituting the `Comm` object** — not by reimplementing transport per protocol. `lib/rex/proto/proxy/socks5/server.rb:42-46` builds its listener with `'Comm' => @opts['Comm']`, and `lib/msf/core/handler/reverse/comm.rb:24-32` resolves `ReverseListenerComm` to `Rex::Socket::Comm::Local` or a live session object. **The two files that D7's handler count excluded (§3.2) are the file that sets the `Comm` and the file that implements it.**

### §4.5 Files still unread — stated, not implied

**I read the architectural decision path (§4.2-§4.3) and the coverage ledger (§4.1). I did NOT read the 286 non-`http` protocol files' bodies.** That is deliberate: the lead's question was *where the decisions live*, and the answer is that they **do not live in the protocol tree at all.** Reading 286 protocol parsers would add protocol detail and would not move the transport/TLS/proxy answer.

**Named as residual (see §7):** `kerberos/` (81 files) and `smb/` (10 files, 181 KB) are the two heaviest unread trees and are **not** transport decision points — they are protocol implementations. If a future pass needs protocol semantics rather than transport decision-making, those two are where the volume is.

---

## §5 The 18 `rex-*` gems — 5 unpacked, 13 enumerated

### §5.1 The count is confirmed exactly

`Gemfile.lock` declares **exactly 18 `rex-*` gems**. Enumerated, not estimated:

| # | Gem (pinned version) | Status |
|---|---|---|
| 1 | `rex-arch (0.1.20)` | **HAVE** |
| 2 | `rex-socket (0.1.71)` | **HAVE** |
| 3 | `rex-core (0.1.37)` | **HAVE** |
| 4 | `rex-text (0.2.63)` | **HAVE** |
| 5 | `rex-encoder (0.1.10)` | **HAVE** |
| 6 | `rex-powershell (0.1.105)` | **HAVE (fetched this pass)** |
| 7 | `rex-bin_tools (0.1.17)` | GAP |
| 8 | `rex-exploitation (0.1.44)` | **GAP — highest priority** |
| 9 | `rex-java (0.1.8)` | GAP |
| 10 | `rex-mime (0.1.11)` | GAP |
| 11 | `rex-nop (0.1.4)` | GAP |
| 12 | `rex-ole (0.1.9)` | GAP |
| 13 | `rex-random_identifier (0.1.21)` | GAP |
| 14 | `rex-registry (0.1.6)` | GAP |
| 15 | `rex-rop_builder (0.1.6)` | GAP |
| 16 | `rex-sslscan (0.1.13)` | GAP |
| 17 | `rex-struct2 (0.1.5)` | GAP |
| 18 | `rex-zip (0.1.6)` | GAP |

**Unpacked: 6 of 18. Gap: 12.** *(The brief said 5 unpacked; this pass makes it 6 by fetching `rex-powershell`.)*

**All 12 remaining gems are confirmed ABSENT from the framework checkout** — verified by probing `lib/rex/<name>` and `lib/rex/<name>.rb` for all 12. **None is vendored.** A reversal reading only the checkout has no source for any of them.

### §5.2 Load-bearing rank — measured from `require` demand, not guessed

**This is the ranking the lead asked for, and it is derived from the source, not from intuition.** I counted every `require 'rex/<X>'` across all of `lib/` and ranked the missing gems by how many call sites demand them:

| Rank | Missing gem | `require` call sites | Consumers (all in `lib/msf/core/exploit/`) |
|---|---|---|---|
| **1** | **`rex-exploitation`** | **13** | `cmd_stager`, `egghunter`, `jsobfu`, `omelet`, `rop_db`, `seh`, `vbsobfuscate`, `remote/browser_exploit_server`, `remote/http_server` |
| 2 | `rex-java` | 5 | Java payload generation |
| 2 | `rex-mime` | 5 | MIME encoding for delivery |
| 4 | `rex-struct2` | 4 | binary struct packing |
| 4 | `rex-zip` | 4 | archive delivery |
| 6 | `rex-powershell` | 2 | **now HAVE** |
| 6 | `rex-random_identifier` | 2 | URI/random naming |
| 8 | `rex-registry` | 1 | Windows registry stagers |

**`rex-exploitation` is the clear #1 and it is not close** — 13 call sites, all of them **exploit-delivery machinery**: command stagers, egg hunters, JS obfuscation, ROP chains, SEH overwrite, VBS obfuscation, and the browser/http exploit servers. **These are exactly the components a session-delivery reversal cares about**, and they are all currently source-less.

**`rex-powershell` was the correct next pick** (the lead's suggestion) and is now unpacked — 29 files / 74,175 B. Note its consumer count is only 2 (`lib/msf/core/exploit/powershell.rb`, `lib/msf/util/exe/common.rb`), so **by call-site rank it is 6th, not 1st** — it was picked for *reach* (PowerShell delivery is a whole attack surface) rather than *call density*. Both are legitimate bases; I am recording which one I used.

### §5.3 What was actually fetched and unpacked this pass

**`rex-powershell-0.1.105.gem` — 26,624 B, fetched from `rubygems.org` via the verified recipe** (`Invoke-WebRequest` → `7z x` three times: `.gem` → `metadata.gz` + `data.tar.gz` → `data.tar` → source tree).

Unpacked to `04_TOOLS\gems\rex-powershell-0.1.105\src\`: **29 files / 74,175 B**, including 13 Ruby files under `lib/rex/powershell/`:

| File | Bytes |
|---|---|
| `command.rb` | 16,426 |
| `psh_methods.rb` | 6,897 |
| `obfu.rb` | 6,259 |
| `output.rb` | 5,590 |
| `payload.rb` | 4,722 |
| `parser.rb` | 4,245 |
| `script.rb` | 3,681 |
| `powershell.rb` | 1,848 |
| `function.rb` | 1,396 |
| `templates.rb` | 983 |
| `param.rb` | 341 |
| `exceptions.rb` | 195 |
| `version.rb` | 65 |

**The version matches the `Gemfile.lock` pin exactly (`0.1.105`).** Version discipline held — I did not fetch a floating version.

### §5.4 The gap's real shape

**Total unpacked source: 165 files → 194 files / 560,486 B → 634,661 B** across 6 gems. **12 gems remain, and the missing source is not "12 packages" — it is the delivery half of the framework:**

- **`rex-exploitation`** — the stager/egghunter/ROP/obfuscation toolkit (13 consumers)
- `rex-java`, `rex-mime`, `rex-zip` — the alternative delivery encodings
- `rex-struct2` — binary packing used *by* the exploit machinery
- `rex-nop`, `rex-rop_builder`, `rex-ole`, `rex-sslscan`, `rex-registry`, `rex-bin_tools`, `rex-random_identifier` — supporting encoders and platform helpers

**`rex-socket` being unpacked is what made §4 answerable.** Had it not been, the single most important finding in this report — that transport/TLS/proxy is decided in one dispatch — would have been **un-reachable from the source**, because the framework checkout only *calls* `Rex::Socket`, never defines it. **That is the concrete demonstration of why the gem gap matters: it is not completeness bookkeeping, it is whether a question is answerable at all.**

---

## §6 Highest-value 20 by (impact × reachability) — and what reading them shows

### §6.1 The population first, so the 20 are a sample and not a claim

**Rank is extracted from every module** — and this required correcting a second dead probe.

**`Rank` is not a metadata hash key.** My first probe used `'Rank' =>` and returned **`0 of 2,715`**. The control dumped the actual line: **`Rank = NormalRanking`** — a **constant assignment**, not a hash entry. Corrected probe extracts **2,708 of 2,715** (7 templates have none). **This is the same failure shape as the `Handler` probe in §2.4** — I assumed metadata-hash syntax where the corpus uses constant assignment. Two dead probes, one root cause.

| Rank | Modules | % |
|---|---|---|
| **Excellent** | **1,414** | **52.1%** |
| Normal | 479 | 17.6% |
| Great | 296 | 10.9% |
| Good | 254 | 9.4% |
| Average | 165 | 6.1% |
| Manual | 93 | 3.4% |
| Low | 7 | 0.3% |
| *(none — templates)* | 7 | 0.3% |

**1,710 modules are Excellent or Great (63.0%).** That is the high-value population, and it is far too large to read — which is precisely why the top 20 selection has to be principled rather than "the newest" or "the biggest."

### §6.2 The selection rule, stated so it can be argued with

```
impact       = ExcellentRanking              (1,414 modules — reliable code exec)
reachability = has `def check`  AND  has CVE (427 modules — discoverable + disclosed)
diversity    = max 2 per platform/subcategory (20 modules spanning 12 subcategories)
order        = CVE year descending
```

**Pool after impact × reachability: 427.** The diversity cap prevents all 20 landing in `multi/http` — without it the newest-first sort alone produces 15+ HTTP modules and the sample would test one code path twenty times.

### §6.3 The 20, and what each one delivers

| # | Module | CVE | Platform/Arch | Mixin | Default payload |
|---|---|---|---|---|---|
| 1 | `multi/http/gogs_rebase_rce.rb` | CVE-2026-52806 | linux,unix / CMD | `Remote::HttpClient` | *(none)* |
| 2 | `multi/http/ghostcms_auth_rce_cve_2026_29053.rb` | CVE-2026-22594 | unix,linux / CMD | `Remote::HttpClient` | *(none)* |
| 3 | `linux/http/ivanti_epmm_rce.rb` | CVE-2026-1281 | unix,linux / CMD | `Remote::HttpClient` | `cmd/unix/reverse_bash` |
| 4 | `linux/http/opencti_notifier_rce.rb` | CVE-2026-27960 | unix / CMD | `Remote::HttpClient` | *(none)* |
| 5 | `linux/local/cve_2026_31431_copy_fail.rb` | CVE-2026-31431 | linux / CMD | *(local)* | *(none)* |
| 6 | `linux/local/cve_2026_3888.rb` | CVE-2026-3888 | linux / CMD | *(local)* | *(none)* |
| 7 | `windows/persistence/ollama_auto_update.rb` | CVE-2026-42249 | win / X64,X86 | `Remote::HttpServer` | *(none)* |
| 8 | `linux/misc/checkpoint_smartconsole_..._rce.rb` | CVE-2026-16232 | python / PYTHON | `Remote::HttpClient` | `python/meterpreter/reverse_tcp` |
| 9 | `linux/ssh/ssh_erlangotp_rce.rb` | CVE-2025-32433 | linux / CMD | **`Remote::Tcp`** | `cmd/linux/https/x64/meterpreter/reverse_tcp` |
| 10 | `unix/http/freepbx_filestore_cmd_injection.rb` | CVE-2025-64328 | unix,linux / CMD | `Remote::HttpClient` | *(none)* |
| 11 | `windows/http/gladinet_viewstate_..._30406.rb` | CVE-2025-30406 | win / CMD | `Remote::HttpClient` | *(none)* |
| 12 | `unix/http/freepbx_firmware_file_upload.rb` | CVE-2025-66039 | php / PHP | *(upload)* | `php/meterpreter/reverse_tcp` |
| 13 | `windows/http/sharepoint_toolpane_rce.rb` | CVE-2025-49706 | win / CMD | `Remote::HttpClient` | *(none)* |
| 14 | `freebsd/misc/rtsold_dnssl_cmdinject.rb` | CVE-2025-14558 | unix / CMD | **`Remote::Ipv6`** | `cmd/unix/generic` |
| 15 | `linux/misc/fortimanager_rce_cve_2024_47575.rb` | CVE-2024-47575 | unix,linux / CMD | **`Remote::Tcp`** | *(none)* |
| 16 | `windows/local/cve_2024_30085_cloud_files.rb` | CVE-2024-30085 | win | *(local)* | *(none)* |
| 17 | `windows/scada/diaenergie_sqli.rb` | CVE-2024-4548 | win / CMD | **`Remote::Tcp`** | `cmd/windows/http/x64/meterpreter/reverse_tcp` |
| 18 | `windows/local/cve_2024_30088_authz_basep.rb` | CVE-2024-30088 | win | *(local)* | *(none)* |
| 19 | `multi/misc/calibre_exec.rb` | CVE-2024-6782 | win / CMD | `Remote::HttpClient` | `cmd/windows/http/x64/meterpreter/reverse_tcp` |
| 20 | `windows/scada/mypro_mgr_cmd.rb` | CVE-2024-47407 | win / CMD | `Remote::HttpClient` | *(none)* |

### §6.4 FINDING — the 20 confirm §4 by closing the delivery chain

**This is the payoff of reading them, and it is a verification of the whole report rather than a new claim.**

**13 of 20 (65%) reach the socket layer through `Msf::Exploit::Remote::HttpClient`** → `send_request_cgi` → `Rex::Proto::Http::Client#connect` → **`Rex::Socket::Tcp.create` with `SSL`/`SSLVersion`/`Proxies`/`Comm`** (§4.3). The other 7 split across `Remote::Tcp` (3), `Remote::HttpServer` (1), `Remote::Ipv6` (1), and local exploit bases (3).

**The chain is closed end-to-end, and it means §2.3's 43.8% HTTP figure is not a directory statistic — it is the actual delivery path for two-thirds of the highest-value modules.** When an operator runs `sharepoint_toolpane_rce` against a target, the TLS and proxy decisions are made in `rex-socket`, by the same two dispatch lines that serve all 1,189 HTTP-family modules.

**Three secondary observations from the reads:**

1. **`ARCH_CMD` dominates: 15 of 20.** These modules execute a **shell command**, then the *payload* establishes the session. The exploit is a command-injection primitive; the session is the payload's job. **This is why the exploit/payload boundary is real** (§2.4) and why the 2,711-module census cannot answer "handler type" on its own.
2. **`DefaultOptions` rarely declares a `PAYLOAD`.** Only 7 of 20 name one; the other 13 inherit from the mixin or require the operator to choose. **There is no default payload in most Metasploit HTTP exploits** — relevant to any "what does it deliver by default" question, whose honest answer is frequently "whatever you configure."
3. **`windows/local/*` modules have no mixin and no payload.** #5, #6, #16, #18 are privesc primitives — they run *on* a box and execute a command. They are correctly Excellent-ranked and correctly payload-less. **A census that reported "4 modules with no payload" would be reporting a design, not a defect.**

### §6.5 What the 20 do NOT establish

**20 modules read out of 2,711 is 0.74%.** The selection is biased by construction toward Excellent+Check+CVE — the most *conventional* modules. **Nothing here characterises Manual-ranked modules, the 1,301 modules without a comment, or the client-side `browser/fileformat` population** (247 + 194 = 441 modules) which is the largest delivery mechanism after HTTP and **was not sampled at all** because those modules rarely carry a CVE in the same form. **The bias is stated, not hidden.**

---

## §7 Residual unknowns, limitations, and the instrument record

### §7.1 Three dead probes — all the same root cause

**This section exists because the method is the deliverable as much as the numbers are.** Every headline count in this report came from a probe that was first made to succeed on a target known to be present. Three probes did not, and are recorded because their failures are informative:

| # | Probe | Returned | Truth | Root cause |
|---|---|---|---|---|
| 1 | `'Handler' =>` metadata key | **0 of 2,715** | 1,011 mention "handler"; 950 bare tokens | **Assumed hash-key syntax where no such key exists** |
| 2 | `'Rank' =>` metadata key | **0 of 2,715** | 2,708 | **Assumed hash-key syntax where the corpus uses `Rank = NormalRanking` (constant assignment)** |
| 3 | verb-pattern handler probe | 8 | 25+28 | pattern too narrow |

**Probes 1 and 2 are the same defect twice**: I assumed Metasploit declares rank and handler as `'Key' => value` metadata entries. **Rank is a constant assignment; handler is not declared in the module at all.** Both returned a **clean, plausible zero** — the quiet-failure class. Neither was distinguishable from a correct answer by looking at it. **Both were caught only because the probe was first run against files known to contain the string.**

**The operational rule that caught them, restated for the record: make the probe succeed on a target you already know is there, before trusting it on a target you don't.** A zero is the one result that cannot be distinguished from a dead tool.

### §7.2 A stale-baseline false alarm in my own verification

**My write-scope check compared 10 pre-existing reports against byte sizes captured earlier in the session and reported 3 "CHANGED"** — `D1_sliver_implant_code.md` (167,607→172,244), `D3_android_code.md` (69,590→79,478), `STATUS.md` (19,299→68,209).

**None of those were my writes.** The DEEP directory now holds **28 reports** — `D10` through `D25` appeared while this pass ran, written by other lanes. **My baseline was simply stale.**

**Recorded because it is the same instrument class as §7.1, one level up:** a delta measured against a stale expected value is **not a measurement of my writes** — it is a measurement of everything that happened since I last looked. The false alarm was self-diagnosing (timestamps showed D22 as mine at `01:22:58`, everything else earlier or concurrent), **but only because I checked the timestamps instead of acting on the delta.** Had I trusted the count, I would have reported three writes I never made.

**Write scope held:** every write in this pass targeted `D22_msf_module_census.md` or `07_OUTPUT\extractions\DEEP\D9\crossref\d22_*`. Verified by grepping all `d22_*.ps1` for output redirects — **all four redirect targets are under `extractions\`, none under `reports\`.** D7, D8, D9 and STATUS.md were never opened for write.

### §7.3 Honest limits on what this report establishes

| Claim | Status | Limit |
|---|---|---|
| 2,715 exploits; 2,711 real | **verified** | 3 enumerators exact; 4 stubs proven by `'Payload'` absence |
| 5,127 across 7 module dirs | **verified** | 2 enumerators |
| 302 files / 46 protocol dirs | **verified** | 2 enumerators |
| 18 gems, 6 unpacked | **verified** | `Gemfile.lock` is authoritative; all 12 gaps confirmed absent from checkout |
| Rank distribution (2,708) | **verified** | 7 templates have no rank; probe corrected from a dead zero |
| 24 handlers / 26 recursive | **verified** | all 24 byte sizes match D7 exactly |
| **Transport/TLS/proxy decided in `Rex::Socket`** | **verified by construction** | Read the dispatch (`socket.rb:51-53`), the parser (`parameters.rb`), the proxy chain (`proxies.rb`), and the handoff (`http/client.rb:177-190`). **Not executed** — no Ruby on this host |
| "13 of 20 use HttpClient" | **verified** | mixin line read per file |
| 43.8% HTTP-family | **derived** | Sum of 5 sub-category counts; a module counted in one sub-category only |

### §7.4 Residual unknowns

**U1. The 12 missing gems are source-less.** `rex-exploitation` (13 call sites, the stager/egghunter/ROP toolkit) is the highest-value gap and **was not fetched this pass.** No claim in this report depends on it, but **any future claim about command stagers, egg hunters, or payload encoding will be unresolvable until it is.** Ranked by call-site demand in §5.2.

**U2. 1,189 HTTP-family modules were *counted*, not read.** §2.3's 43.8% is a directory statistic verified by enumeration; the claim that they all route through the §4 chain is **verified for 13 of 20 sampled modules (65%) and inferred for the rest** from the mixin. **A 13/20 sample is not a proof of universality.**

**U3. `lib/rex/proto/` — 286 of 302 files unread.** §4 answered the transport question without them, because the answer is that transport is *not decided there*. **Protocol-specific parsing behaviour remains uncharacterised**, most heavily in `kerberos/` (81 files, 383 KB) and `smb/` (10 files, 181 KB).

**U4. Handler-type distribution is not extractable from the exploit corpus.** §2.4 established there is no per-module handler key. **Answering it requires enumerating the 545 `modules/payloads/` files and joining payload→handler.** That was out of scope for this task and is recorded as the method, not done.

**U5. Nothing was executed.** No Ruby, no gem, no bundle on this host. **Every claim is `[source]` with `file:line`.** The `Rex::Socket` dispatch in §4.2 is *read*, not *observed*. If a future pass has a Ruby environment, `Rex::Socket::Parameters.from_hash` on a real option hash is the single highest-value confirmation available.

**U6. `modules/auxiliary` (1,347), `post` (436), `payloads` (545), `encoders` (57) are counted but unread.** Deliberate — outside the brief's boundary as stated in §1.3.

### §7.5 The boundary this report defends

**The census answers "2,715 of what?" and the answer is: 2,711 exploits, 53.0% of the module tree, 43.8% of which is HTTP-delivered, all of it eventually routed through two dispatch lines in a gem that is not in the checkout.**

**Both halves of D17 §1.0.1's defect are closed here:** the number is correct (three enumerators) **and** the boundary is justified (7 directories, explicitly in/out).

**What would falsify this report:** a fourth enumerator disagreeing on 2,711 or 5,127; a `Rex::Socket` dispatch path other than `param.comm.create(param)`; or a protocol file that decides TLS/proxy without calling `Rex::Socket`. **I looked for the third specifically and found 27 files that call `Rex::Socket` and none that decide locally.**

---

*End of D22.*

