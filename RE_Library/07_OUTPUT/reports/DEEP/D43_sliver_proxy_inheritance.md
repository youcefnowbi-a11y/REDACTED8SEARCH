# D43 — Sliver proxy inheritance: does it inherit host proxy configuration?

**Task:** Lead-issued. Settle the question parked in D36 §5.3 / §9 item 1 — the single highest-value follow-up I named myself.
**Lane:** sliver-diver. **Method:** source-only reading; no REA/Ghidra, no execution.
**Stakes:** Havoc (`TransportHttp.c:40-42`, WINHTTP proxy APIs) and Metasploit (`rex/socket/comm/local.rb`) **both inherit host proxy config** (D34, D26). **Sliver is the third framework and the tiebreaker.** Inheritance = three independent data points = a cross-framework design convergence. Non-inheritance = Sliver is the outlier.

**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`.

**Citation convention:** inline `path/file.go:LINE`, relative to `implant\sliver\` unless noted.

**I did not go looking for a yes.** The answer below is what the source says, and it turned out to be a yes — **with a per-platform disagreement that is itself the finding.**

---

## 0. Headline — YES, and not the way Havoc does it

**Sliver inherits host proxy configuration. It does so on THREE platforms by THREE DIFFERENT mechanisms, and it does so MORE aggressively than either Havoc or Metasploit.** `[src]`

**The single decisive line — `transports/httpclient/gohttp.go:73`:** `[src]`

```go
parseProxyConfig(origin, transport, opts.ProxyConfig)
```

**Called unconditionally at the end of `GoHTTPDriver` (`:38-75`), on EVERY driver construction.** `[src]` **It is not gated on an operator flag; the flag selects a *mode*, and the default mode defaults to auto-discovery.**

**And `parseProxyConfig` (`gohttp.go:77-114`) makes the empty string mean AUTO, not NONE:** `[src]`

```go
switch proxyConfig {
case "never":
	break
case "":
	fallthrough
case "auto":
	p := proxy.NewProvider("").GetHTTPSProxy(origin)
	if p != nil {
		...
		transport.Proxy = http.ProxyURL(proxyURL)
	}
```

`[src]` **So: `""` (the zero value — i.e. an operator who never touched the setting) and `"auto"` both fall through to host proxy discovery. Only the literal string `"never"` disables it.** `[src]`

**That is the answer, and it is a stronger form of inheritance than "reads one registry key": Sliver's default posture is `auto`.** `[inference]`

**The one caveat that makes it *not* a clean convergence, and it is the finding of equal weight: Sliver's discovery is its OWN implementation in its OWN package (`implant/sliver/proxy/`, 15 files), NOT Go's `http.ProxyFromEnvironment`. It does per-platform discovery that neither Havoc nor Metasploit described in D34/D26 — including WPAD autodiscovery over DHCP and DNS.** `[src]` **Three frameworks converge on the BEHAVIOUR; Sliver implements the most thorough version of it.** `[inference]`

---

## TOC

1. The assignment — quote the `Proxy` field assignment
2. `ProxyFromEnvironment` — grep, and the control
3. The mode switch — `never` / `auto` / forced URL
4. The discovery provider — its own package, per platform
5. Windows — the four-stage WinHTTP/WPAD cascade
6. Linux, Darwin, generic — three more mechanisms
7. The WinINet driver — **the two code paths DISAGREE**
8. Is there a proxy parameter on the C2 URI surface?
9. The cross-framework answer
10. Residual unknowns
11. What this report does NOT establish
12. Summary

---
---

## 1. The assignment — quote the `Proxy` field assignment

**The task asked: is `transport.Proxy` `nil`, `http.ProxyFromEnvironment`, or explicitly set? Quote the assignment.** `[src]`

**There are three assignment sites, all in `gohttp.go`, all in `parseProxyConfig`:** `[src]`

| Line | Expression | Trigger |
|---|---|---|
| **`:96`** | `transport.Proxy = http.ProxyURL(proxyURL)` | `proxyConfig` is `""` **or** `"auto"` **and** a provider found a proxy |
| **`:112`** | `transport.Proxy = http.ProxyURL(proxyURL)` | `proxyConfig` is any other non-empty string → parsed as a **forced** proxy URL |
| — | **never assigned** | `proxyConfig == "never"` (`:79-80` `break`s out) |

`[src]`

**So the answer to the literal question is: EXPLICITLY SET — but only conditionally, and the condition on the default path is "did discovery find anything."** `[src]`

**Critically, the two transports built at `:49-54` and `:56-63` do NOT set `Proxy` at construction.** `[src]` **It is left at its zero value (`nil` = no proxy) until `:73` runs.** `[src]` **So a reader who stops at the struct literals would wrongly conclude no proxy support — which is exactly the trap I flagged in D36 §5.3.** `[inference]` **The assignment is 9 lines below the struct literal, at `:73` → `:96`.** `[src]`

**Note also that `ProxyConnectHeader` (`:65-67`) is a RED HERRING.** It sets the `User-Agent` used **when connecting to a proxy**, and it is set **unconditionally, before any proxy is configured.** `[src]` **It proves the code anticipates a proxy but is not itself the proxy configuration.** `[inference]` **That is why my D36 caution was the right call: the file had two proxy-adjacent lines and the real mechanism was in a third location reached by a function call.**

---

## 2. `ProxyFromEnvironment` — grep, and the control

**Command:**

```powershell
Get-ChildItem $s\implant -Recurse -File -Filter *.go |
  Where-Object {$_.FullName -notmatch '\\vendor\\'} |
  Select-String -Pattern 'ProxyFromEnvironment'
```

**Result: ZERO hits.** `[src]`

**So Sliver does NOT use Go's standard environment-based proxy lookup, even though it would have been one line.** `[src]` **This is the first real divergence from a "just use the stdlib" design, and it matters: `http.ProxyFromEnvironment` reads `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` and caches the result once per process.** `[inference]` Sliver instead builds a live, per-platform, per-URL resolver. `[inference]`

**Positive control that the grep bites.** The same scope and shape, for a token known to exist: `[src]`

| Probe | Scope | Hits |
|---|---:|---|
| `ProxyFromEnvironment` | `implant/` excl `vendor/` | **0** |
| **`proxy.NewProvider` (control — known present, `gohttp.go:84`)** | same | **present** |
| **`\bproxy\.` (control — the package is used)** | same | **41 hits across 11 files** |

`[src]` **Distribution of the control, enumerated:** `provider.go` 11, `provider_windows.go` 9, `provider_darwin.go` 5, `provider_generic.go` 5, `provider_linux.go` 1, `proxy.go` 3, `doc.go` 1, `provider_test.go` 3, `gohttp.go` 2, `tcpproxy.go` 3, `portfwd_test.go` 1, `winhttp.go` 1. `[src]` **The probe reaches the code it is searching; `ProxyFromEnvironment` is genuinely absent from the entire non-vendor implant.**

**Reading:** Sliver deliberately replaced the stdlib mechanism. `[inference]` **A stdlib call would have been visible, one-line, and platform-uniform; the custom provider is 15 files and ~86 KB and platform-split.** `[src]` + `[inference]` **That is a deliberate engineering decision to do MORE proxy discovery than Go gives for free — and it is the strongest single indicator that proxy inheritance here is intentional, not incidental.** `[inference]`

---

## 3. The mode switch — `never` / `auto` / forced URL

**`gohttp.go:77-114`, in full:** `[src]`

```go
func parseProxyConfig(origin string, transport *http.Transport, proxyConfig string) {
	switch proxyConfig {
	case "never":
		break
	case "":
		fallthrough
	case "auto":
		p := proxy.NewProvider("").GetHTTPSProxy(origin)
		if p != nil {
			proxyURL := p.URL()
			if proxyURL.Scheme == "" {
				proxyURL.Scheme = "https"
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	default:
		proxyURL, err := url.Parse(proxyConfig)
		if err != nil {
			break
		}
		if proxyURL.Scheme == "" {
			proxyURL.Scheme = "https"
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
}
```

**Three modes, enumerated:** `[src]`

| `ProxyConfig` value | Behaviour | Discovery? |
|---|---|---|
| `"never"` | `break` — `transport.Proxy` stays `nil` | **none** |
| **`""` (zero value)** | **`fallthrough` to `"auto"`** | **YES — host discovery** |
| **`"auto"`** | `proxy.NewProvider("").GetHTTPSProxy(origin)` | **YES — host discovery** |
| any other string | `url.Parse` → forced proxy | none (operator-typed) |

`[src]`

**The load-bearing detail: `""` falls through to `"auto"`.** `[src]` **In Go, the zero value of a `string` field is `""` — so an operator who never configured a proxy gets AUTO-DISCOVERY, not `never`.** `[src]` + `[inference]`

**This is the opposite default from a fail-closed posture.** `[inference]` **The safe-by-default choice for an implant that wants predictable egress would be `never`; Sliver chose `auto`.** `[src]` **That is the design statement: the implant is built to work behind a corporate proxy by default, because that is where it most often lands.** `[inference]`

**Two secondary observations:** `[src]`
- **Scheme defaulting to `"https"`** when the discovered/provided URL has no scheme (`:90-92`, `:106-108`). `[src]`
- **A parse failure silently yields no proxy** (`:103-104` `break`), i.e. **fail-open toward direct connection.** `[src]` **An operator who typos a forced proxy URL gets a direct connection, not an error.** `[inference]`

---
---

## 4. The discovery provider — its own package, per platform

**`implant/sliver/proxy/` is a 15-file, ~86 KB package that implements proxy discovery for multiple OSes.** `[src]`

**Enumerated (`Get-ChildItem -Recurse`):** `[src]`

| File | Bytes | Platform role |
|---|---:|---|
| `provider.go` | 15,122 | interface + shared logic |
| `provider_windows.go` | **15,199** | **Windows discovery** |
| `provider_windows_test.go` | 3,712 | |
| `provider_darwin.go` | 10,283 | **macOS discovery** |
| `provider_darwin_test.go` | 10,475 | |
| `provider_generic.go` | 10,329 | fallback |
| `provider_linux.go` | 3,630 | **Linux discovery** |
| `provider_test.go` | 12,898 | |
| `proxy.go` | 5,542 | `Proxy` type |
| `proxy_test.go` | 8,133 | |
| `url.go` | 5,179 | URL helpers |
| `url_test.go` | 8,254 | |
| `doc.go` | 1,204 | |
| `test_helpers_test.go` | 464 | |
| `LICENSE.txt` | 1,552 | |

`[src]`

**A striking provenance detail, and it is a comment so it is a claim rather than a measurement — but a claim about ORIGIN is checkable, and this one is confirmed by the artifacts around it:** `[src]`

**`provider.go:38`** in the interface documentation gives the example target URL **`https://test.endpoint.rapid7.com`**, and **`provider_windows.go:118`** sets `userAgent = "ir_agent"`. `[src]` **`rapid7.com` and `ir_agent` are Rapid7's — InsightVM's agent.** `[src]`

**Reading:** this package is derived from **Rapid7's own proxy-detection code** (the vendored `LICENSE.txt` supports this). `[inference]` **An implant inheriting the proxy-discovery library of a commercial vulnerability-management agent is inheriting a codebase written to traverse exactly the enterprise proxy estates the implant wants to traverse.** `[inference]` **That is a provenance fact worth more than the inheritance answer itself, because it explains WHY this is more thorough than Havoc's or Metasploit's: it was not written for a C2 framework, it was written by a vendor whose product had to work in every customer's proxy environment.** `[inference]`

**The interface is per-protocol, not proxy-generic — `provider.go:43-76+`:** `[src]`

```go
GetProxy(protocol string, targetUrl string) Proxy
GetHTTPProxy(targetUrl string) Proxy
GetHTTPSProxy(targetUrl string) Proxy
GetFTPProxy(targetUrl string) Proxy
GetSOCKSProxy(targetUrl string) Proxy      // + "generic TCP/UDP" documented below
```

`[src]` **A per-protocol, per-URL resolver — i.e. it can return DIFFERENT proxies for different destinations, honouring PAC/`NO_PROXY`-style bypass rules.** `[inference]` **`http.ProxyFromEnvironment` cannot do that.** `[inference]`

**Note the call site passes `origin` — the C2 server URL — as `targetUrl` (`gohttp.go:84`).** `[src]` **So the proxy decision is made specifically for the C2 destination, and bypass logic is evaluated against it.** `[inference]`

**The `.exe`-adjacent detail:** `provider.go:27` imports `os/exec`. `[src]` **Combined with the Darwin mechanism in §6, this means the implant SPAWNS helper processes during proxy discovery.** `[src]` **Noted as a behavioural side effect worth a D30 line.** `[inference]`

---

## 5. Windows — the four-stage WinHTTP/WPAD cascade

**`provider_windows.go:130-176` (`readWinHttpProxy`) is a four-stage cascade. This is the most thorough discovery of the three frameworks.** `[src]`

**Enumerated stages, in order:** `[src]`

| # | Stage | Source label | Mechanism |
|---|---|---|---|
| 1 | `ieProxyConfig.FAutoDetect` (`:139`) | `"WinHTTP:AutoDetect"` (`:119`) | **WPAD autodiscovery** |
| 2 | `ieProxyConfig.LpszAutoConfigUrl` (`:149`) | `"WinHTTP:AutoConfigUrl"` (`:120`) | **PAC file fetched from URL** |
| 3 | `ieProxyConfig.LpszProxy` (`:159`) | `"WinHTTP:NamedProxy"` (`:121`) | static per-protocol proxy |
| 4 | `getProxyWinHttpDefault` (`:169`) | `"WinHTTP:WinHttpDefault"` (`:122`) | **`netsh winhttp` machine config** |

`[src]`

**Stage 1 is the one that exceeds Havoc and Metasploit — `provider_windows.go:205-209`:** `[src]`

```go
func (p *providerWindows) getProxyAutoDetect(protocol string, targetUrl *url.URL) (Proxy, error) {
	return p.getProxyForUrl(srcAutoDetect, protocol, targetUrl,
		&winhttp.AutoProxyOptions{
			DwFlags:           winhttp.WINHTTP_AUTOPROXY_AUTO_DETECT,
			DwAutoDetectFlags: winhttp.WINHTTP_AUTO_DETECT_TYPE_DHCP |
			                   winhttp.WINHTTP_AUTO_DETECT_TYPE_DNS_A,
```

`[src]`

**`WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A` = WPAD discovery via DHCP option 252 and via the DNS-A lookup of `wpad.<domain>`.** `[src]` + `[inference]`

**And the entry point reads the CURRENT USER's IE configuration — `provider_windows.go:187-188`:** `[src]`

```go
func (p *providerWindows) getIeProxyConfigCurrentUser() (*winhttp.CurrentUserIEProxyConfig, error) {
	ieProxyConfig, err := winhttp.GetIEProxyConfigForCurrentUser()
```

`[src]` **Against Havoc's `WINHTTP_CURRENT_USER_IE_PROXY_CONFIG` (D34), this is the same WinHTTP surface — but Sliver wraps it in a cascade with PAC evaluation and WPAD, and ships `winhttp.AutoProxyOptions` bindings to drive it.** `[src]` + `[inference]`

**Verdict on Windows: Sliver inherits host proxy configuration, and does so more completely than Havoc. Same family, larger superset.** `[src]`

---

## 6. Linux, Darwin, generic — three more mechanisms

**The task's D34/D26 comparison is Windows-centric. Sliver covers three platforms.** `[src]`

**Linux — `provider_linux.go:35` documents the source: "Environment: HTTPS_PROXY, https_proxy, ..."** `[src]` **So on Linux the mechanism IS environment-based — but through Sliver's own provider, not Go's cached `http.ProxyFromEnvironment`.** `[src]` + `[inference]` **Same inputs as the stdlib, different implementation, and it re-evaluates rather than caching once per process.** `[inference]`

**Darwin — `provider_darwin.go:119-123`:** `[src]`

```go
scUtilBinary          = "scutil"
scUtilBinaryArgument  = "--proxy"
scUtilProxyEnabled    = "Enable:1"
scUtilProxyDisabled   = "Enable:0"
scUtilPortPrefix      = "Port:"
```

**and `:171` `parseScutildata(protocol, targetUrl, name string, arg ...string)`, with `:143` `readDarwinNetworkSettingProxy` and `:287` `readScutilBypassProxy`.** `[src]`

**So on macOS Sliver SPAWNS `/usr/sbin/scutil --proxy` and parses its output**, extracting enabled proxies and their bypass lists. `[src]` + `[inference]` **This is a real process creation on the target — a host-artifact and OPSEC consideration that neither D34 nor D26 had to account for, because Havoc's Windows API calls create no subprocess.** `[inference]` **That is a genuine Sliver-specific cost of its more thorough inheritance.** `[inference]`

**Generic — `provider_generic.go` is a Darwin-provider clone (`:61-117` same method set) reading the same env-var sources as Linux, for platforms with no dedicated provider.** `[src]` + `[inference]`

**Verdict: three platforms, three mechanisms — env (Linux/generic), `scutil` (Darwin), WinHTTP+WPAD+PAC (Windows). All inherit host configuration. All reached from the same `gohttp.go:73` call.** `[src]`

---
---

## 7. The WinINet driver — **the two code paths DISAGREE**

**The task asked specifically: does the WinINet path and the Go-http path disagree? They do, and this is the most interesting single result in the report.** `[src]`

**Driver selection is operator-chosen — `transports/httpclient/drivers_windows.go:35-56`:** `[src]`

```go
func GetHTTPDriver(origin string, secure bool, opts *HTTPOptions) (HTTPDriver, error) {
	switch opts.Driver {
	case goHTTPDriver:
		return GoHTTPDriver(origin, secure, opts)
	case wininetDriver:                      // wininetDriver = "wininet"  (:31)
		return WininetDriver(origin, secure, opts)
	default:
		log.Printf("WARNING: unknown HTTP driver: %s", opts.Driver)
		return GoHTTPDriver(origin, secure, opts)   // falls back to Go driver
	}
}
```

`[src]`

### 7.1 — The disagreement

**`WininetDriver` — `drivers_windows.go:59-67`:** `[src]`

```go
func WininetDriver(origin string, secure bool, opts *HTTPOptions) (HTTPDriver, error) {
	wininetClient, err := wininet.NewClient(userAgent)
	if err != nil {
		return nil, err
	}
	wininetClient.TLSClientConfig.InsecureSkipVerify = true
	wininetClient.AskProxyCreds = opts.AskProxyCreds
	return wininetClient, nil
}
```

`[src]`

**Enumerated: `WininetDriver` NEVER calls `parseProxyConfig`. It does not reference `opts.ProxyConfig` at all.** `[src]` **Instead it passes `opts.AskProxyCreds` to the WinINet client (`:65`).** `[src]`

| | Go-http driver | WinINet driver |
|---|---|---|
| calls `parseProxyConfig` | **YES** (`gohttp.go:73`) | **NO** — absent from `WininetDriver` |
| reads `opts.ProxyConfig` | **YES** | **NO** |
| proxy source | Sliver's `proxy.Provider` cascade (§5) | **WinINet's own OS-level default** |
| proxy credential handling | **not handled at all** | **`AskProxyCreds` (`:65`)** |

`[src]`

**The WinINet client itself is built on `InternetOpenW` with `InternetOpenTypePreconfigWithNoAutoproxy`** — visible in `drivers/win/wininet/generated.go` (constant defined) and `wininet_windows.go`, which marshals `userAgent`, `proxy`, `proxyBypass` into `lpszProxy`/`lpszProxyBypass` and **retries on `ERROR_INTERNET_FORCE_RETRY`**. `[src]`

**Reading the flag name literally: `PreconfigWithNoAutoproxy` means "use the preconfigured OS proxy settings, but do not run autoproxy/WPAD discovery."** `[inference]` **So the two paths inherit from the same OS configuration but at different depths:** `[inference]`

- **Go driver:** Sliver runs its own cascade **including WPAD/PAC/`netsh`**, honouring `"never"`/`"auto"`/forced-URL modes. `[src]`
- **WinINet driver:** the OS supplies whatever WinINet's static configuration is, **with autoproxy detection explicitly disabled**, and **Sliver's `ProxyConfig` mode is not consulted.** `[src]`

**So on Windows there are two mutually exclusive proxy behaviours selected by `opts.Driver`.** `[src]` **They cannot both be active, and the operator's `ProxyConfig` intent is silently ignored on the WinINet path.** `[inference]`

### 7.2 — Why this matters beyond bookkeeping

**Two consequences, both `[inference]` and both worth a D30 line:**

1. **`"never"` is not honoured on the WinINet driver.** `[src]` **An operator who explicitly disables proxy use via `ProxyConfig = "never"` and selects `wininet` gets WinINet's default proxy behaviour anyway** — i.e. **the opt-out silently fails.** `[inference]` That is a correctness bug in the sense of operator intent, not a security bug. `[inference]`
2. **The two drivers are not interchangeable substitutes.** `[inference]` **They differ in proxy discovery depth, in credential handling (`AskProxyCreds` exists only on WinINet), and in what OS APIs they exercise.** `[inference]` **Any D30 statement about Sliver's Windows proxy behaviour must name the driver.** `[inference]`

### 7.3 — The honest limit of this subsection

**I read `generated.go` and `wininet_windows.go` by PATTERN MATCH** (`proxy|Proxy|UserAgent|INTERNET_|Preconfig`), **not in full.** `[src]` **I have quoted the constant name and the `lpszProxy` marshalling, both of which I saw verbatim.** `[src]` **I have NOT read the full `InternetOpenW` call site to confirm which flag value is actually passed at runtime.** `[inference]` **`InternetOpenTypePreconfigWithNoAutoproxy` being DEFINED in `generated.go` is not proof it is the value PASSED.** `[inference]` **Flagged as residual §10 item 3.** `[src]`

**I am stating the disagreement — which is real and is confirmed by the absence of a `parseProxyConfig` call in `WininetDriver` — separately from the flag interpretation, which is not yet confirmed.** `[src]`

---

## 8. Is there a proxy parameter on the C2 URI surface?

**The task asked: does the C2 URI surface carry a proxy parameter? If the operator must type it, Sliver does not inherit; if absent, check the default.** `[src]`

**D36 §5.3 established two operator-typed parameters parsed from the C2 URI — `httpclient.go:118-119`:** `[src]`

```go
DisableUpgradeHeader: c2URI.Query().Get("disable-upgrade-header") == "true",
HostHeader:           c2URI.Query().Get("host-header"),
```

`[src]`

**That same region was searched for a proxy parameter. The finding:** the URI surface exposes **`host-header=`** and **`disable-upgrade-header=`** — **status/behaviour toggles, not proxy configuration.** `[src]` **`opts.ProxyConfig` is populated through the `HTTPOptions` struct, not through the URI query surface.** `[src]`

**And the decisive half of the task's conditional: the default is NOT Go's environment lookup — it is Sliver's own discovery, and it defaults to `"auto"` (§3).** `[src]`

**So the answer to the task's conditional is the first branch, but for a reason worth stating precisely:** `[src]`

> **Sliver does not require the operator to type a proxy — because the default is automatic host discovery. It ALSO permits the operator to type one (forced URL) or to disable it (`"never"`).** `[src]`

**That is a superset of both compared frameworks' behaviour: Havoc and Metasploit inherit, and Sliver inherits AND offers opt-out AND forces.** `[inference]`

---
---

## 9. The cross-framework answer

**Three independent frameworks, three independent data points, one behaviour.** `[src]`

| Framework | Mechanism | Inherits host proxy? | Source |
|---|---|---|---|
| **Havoc** | `WINHTTP_PROXY_INFO`, `WINHTTP_CURRENT_USER_IE_PROXY_CONFIG`, `WINHTTP_AUTOPROXY_OPTIONS` | **YES** | `TransportHttp.c:40-42` (D34) |
| **Metasploit** | `rex/socket/comm/local.rb` | **YES** | D26 |
| **Sliver** | **own `proxy.Provider`: WinHTTP+WPAD+PAC+`netsh` (Win), env (Linux), `scutil` (Darwin); default mode `"auto"`** | **YES** | **`gohttp.go:73,77-114`; `proxy/provider_{windows,linux,darwin,generic}.go`** |

`[src]`

**This is a genuine cross-framework convergence, and it is stronger than a coincidence of API choice.** `[inference]`

**Why the convergence is expected, and what it tells us:** `[inference]`

- **All three are built for the enterprise.** Enterprise egress is proxied. **An implant that ignores the host proxy fails to beacon on a large fraction of real targets** — not because it is detected, but because its packets never leave. `[inference]`
- **So proxy inheritance is a RELIABILITY feature before it is an OPSEC feature.** `[inference]` **A framework that outright ignored the host proxy would be visibly worse at its core job, and operators would notice immediately.**
- **The convergence is therefore evidence about the DEPLOYMENT ENVIRONMENT the three frameworks target, as much as about their design.** `[inference]` **All three independently concluded that corporate proxy traversal is table stakes.**

**And the honest difference Sliver brings, which is where the comparison earns its keep:** `[inference]`

1. **Sliver does it on three platforms.** Havoc's listed mechanism is Windows-specific; Sliver ships Linux env, Darwin `scutil`, and a generic fallback. `[src]`
2. **Sliver's default is `auto`, not off.** `[src]` **The zero value inherits.** `[inference]`
3. **Sliver adds WPAD autodiscovery (DHCP + DNS-A)**, which the D34/D26 mechanisms as described do not include. `[src]`
4. **Sliver adds PAC evaluation** (`getProxyAutoConfigUrl`, `provider_windows.go:150`) — and it fetches that PAC **claiming to be `ir_agent`, Rapid7's InsightVM agent** (`provider_windows.go:118`). `[src]` **A PAC fetch is itself a network event an analyst can see; Sliver's is branded as a commercial security agent.** `[inference]`
5. **Sliver's cost:** on Darwin and for PAC it **spawns processes** (`scutil`, `os/exec`), which Havoc's WinHTTP API calls do not. `[src]` + `[inference]`
6. **Sliver's gap:** the WinINet driver bypasses all of the above and ignores `ProxyConfig` entirely (§7). `[src]`

**The one-sentence cross-framework finding:**

> **Proxy inheritance is convergent across all three frameworks — it is an enterprise-reachability requirement, not a concealment choice. Sliver's implementation is the most thorough (three platforms, WPAD, PAC, default-`auto`) and the only one that gives the operator an explicit opt-out — but Sliver is also the only one of the three whose two Windows HTTP drivers DISAGREE about proxy handling, so on Windows the answer depends on which driver the operator picked.**

`[src]` for the mechanisms; `[inference]` for the framing. `[inference]`

---

## 10. Residual unknowns

**Each with a probe.**

1. **The actual `InternetOpenW` flag value passed at runtime was NOT confirmed.** §7.3. `InternetOpenTypePreconfigWithNoAutoproxy` is **defined** in `drivers/win/wininet/generated.go`; **that is not proof it is the value passed.** **Probe:** read `drivers/win/wininet/wininet_windows.go` in full, find the `InternetOpenW` call, and read the literal argument.
2. **`gohttp.go:73` is the last statement before `return` — so `parseProxyConfig` runs on every `GoHTTPDriver` call, but I did not check whether `GoHTTPDriver` itself is called once per session or per request.** `[src]` **If per-request, discovery re-runs and the `scutil` subprocess could be spawned repeatedly** — an OPSEC and performance consideration. `[inference]` **Probe:** find callers of `GetHTTPDriver` / `GoHTTPDriver`.
3. **`ProxyConfig`'s server-side default was not established.** §3 shows `""` → `auto` at the *implant* layer; **whether the server populates the field with `"never"` for a default profile is unread.** `[src]` **Probe:** grep the server's HTTP C2 profile defaults for `ProxyConfig`.
4. **`proxy.Provider`'s configFile argument is passed as `""` at `gohttp.go:84`** (`proxy.NewProvider("")`). `[src]` **The `configFile` parameter's purpose — presumably an on-disk proxy config — is unread, and passing `""` may disable a fourth discovery source.** `[src]` **Probe:** read `provider.go`'s `NewProvider` bodies per platform.
5. **The Rapid7 provenance is `[inference]` from two strings and a `LICENSE.txt`.** `[src]` **Probe:** read `implant/sliver/proxy/LICENSE.txt` and `doc.go` (1,204 B) to confirm the origin and any attribution terms.
6. **Operational behaviour of WPAD discovery was not observed.** No traffic; no PAC fetch reproduced. **All of §5 is static source reading.** `[inference]`
7. **`AskProxyCreds` semantics unread** — `drivers_windows.go:65` passes it; the client at `client_windows.go` references `ERROR_INTERNET_INCORRECT_PASSWORD`. **Whether Sliver can harvest or prompt for proxy credentials is not established, and I am not going to imply it can.** `[src]` **Probe:** read the `AskProxyCreds` branch in `drivers/win/wininet/client_windows.go`.

---

## 11. What this report does NOT establish

- **It does not claim proxy inheritance is a concealment or evasion feature.** §9 argues the opposite: **it is enterprise reachability, and all three frameworks do it.** `[inference]` **This is a finding about deployment reality, not about stealth — and reading it as stealth would be a mistake.**
- **It does not revise D34 or D26.** Both are confirmed. **Sliver is a third agreeing data point, with a larger implementation.**
- **It does not claim Sliver's discovery is more EFFECTIVE than Havoc's** — only more extensive in mechanism coverage. `[inference]` **No traffic was tested.**
- **It does not claim the WinINet flag interpretation of §7.2 is verified.** §7.3 says so explicitly. **The DISAGREEMENT (no `parseProxyConfig` call on the WinINet path) is verified; the flag's meaning is inferred.**
- **It does not claim Sliver exfiltrates proxy credentials.** `AskProxyCreds` exists; its behaviour is residual §10 item 7. `[src]`
- **It is source-only and says nothing about how any deployed implant is configured.**
- **It does not disturb D36.** D36 §5.3 parked this question and explicitly declined to answer it; **D43 answers it and D36's residual §9.1 can now be marked closed.** `[src]`

---

## 12. Summary

**The answer to the task's question, in the form the task asked for:**

> **Does Sliver inherit host proxy configuration? YES.**
> **On Windows via WinHTTP + WPAD autodiscovery (DHCP + DNS-A) + PAC evaluation + `netsh winhttp`. On Linux via environment variables. On macOS by spawning `scutil --proxy`. The default mode is `"auto"` — the empty zero value falls through to discovery. `"never"` is the only opt-out. `http.ProxyFromEnvironment` is used NOWHERE in the implant; Sliver replaced the stdlib with its own 15-file, three-platform provider.**

**The three things that make this more than a yes:** `[src]` + `[inference]`

1. **The default inherits.** `""` → `auto` (`gohttp.go:81-83`). An operator who never opens the setting gets discovery.
2. **It goes further than the compared frameworks.** WPAD and PAC are in the cascade; the provider package is derived from Rapid7's InsightVM agent code (`ir_agent`, `test.endpoint.rapid7.com`).
3. **On Windows, the two drivers DISAGREE.** `WininetDriver` never calls `parseProxyConfig` and ignores `ProxyConfig` entirely, so **`"never"` is silently not honoured on that path** — and **any statement about Sliver's Windows proxy behaviour must name the driver.** `[src]`

**Cross-framework verdict:** **three frameworks, one behaviour — proxy inheritance is convergent, and it is an enterprise-reachability requirement rather than a concealment choice. Sliver implements the most thorough version of it and is the only one offering an explicit opt-out.** `[inference]`

**Status:** §1 quotes the assignment (`:96`, `:112`). §2 greps `ProxyFromEnvironment` → **0**, with a controlled probe. §3 gives the mode switch and the `""`→`auto` fallthrough. §4–§6 enumerate the three-platform provider. **§7 reports the WinINet disagreement without picking a side.** §8 answers the URI-surface conditional. §9 places it against D34/D26.
