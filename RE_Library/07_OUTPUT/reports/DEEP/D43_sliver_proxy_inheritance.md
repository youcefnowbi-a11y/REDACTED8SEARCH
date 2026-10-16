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
<!--TAIL-->
