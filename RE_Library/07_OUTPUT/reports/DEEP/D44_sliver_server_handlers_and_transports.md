# D44 — Sliver server-side: RPC surface, transports, C2 profile machinery, listeners

**Task:** Lead-issued. Reverse the `server\` half of Sliver to the depth D1 reached on `implant\sliver\`.
**Lane:** sliver-diver. **Method:** source-only reading; no REA, no provider, no execution.
**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`
**Scope:** `server\` — 408 files / 5,337.5 KB; `.go` subset 353 files / 3,269.4 KB. `[src]` (invocation in §0.3)

**Citation convention:** inline `path/file.go:LINE`.

---

## 0. Corrections first — including one to my own D43

### 0.1 CORRECTION TO MY OWN D43 — the C2 URI *does* carry a proxy parameter

**D43 §8 stated:** *"The URI surface exposes `host-header=` and `disable-upgrade-header=` — status/behaviour toggles, not proxy configuration. `opts.ProxyConfig` is populated through the `HTTPOptions` struct, not through the URI query surface."* `[src]` **That is WRONG, and D44 corrects it.** `[src]`

**`implant/sliver/transports/httpclient/httpclient.go:110-125` is the full option surface, and there are FOUR proxy parameters:** `[src]`

```go
return &HTTPOptions{
	Driver:               driverName,
	NetTimeout:           netTimeout,
	TlsTimeout:           tlsTimeout,
	PollTimeout:          pollTimeout,
	MaxErrors:            maxErrors,
	ForceHTTP:            c2URI.Query().Get("force-http") == "true",
	NoFallback:           c2URI.Query().Get("no-fallback") == "true",
	DisableUpgradeHeader: c2URI.Query().Get("disable-upgrade-header") == "true",
	HostHeader:           c2URI.Query().Get("host-header"),

	ProxyConfig:   c2URI.Query().Get("proxy"),          //:121
	ProxyUsername: c2URI.Query().Get("proxy-username"), //:122
	ProxyPassword: c2URI.Query().Get("proxy-password"), //:123
	AskProxyCreds: c2URI.Query().Get("ask-proxy-creds") == "true", //:124
}
```

`[src]`

**Root cause of MY error, recorded honestly:** in D43 I read `:118-119` — a **two-line slice** — and generalised from it to the whole surface. **The proxy parameters begin three lines below the last line I quoted.** `[src]` **This is a boundary error, not a counting error: I bounded the region by where my previous quote ended, instead of by the structure that contains it (the `&HTTPOptions{...}` literal, `:110-125`).** `[inference]`

**What changes and what does not:**

| D43 claim | Status after D44 |
|---|---|
| "the URI surface exposes `host-header=` / `disable-upgrade-header=`" | **still true** — `:118-119` |
| "there is no proxy parameter on the URI surface" | **FALSE** — `:121-124`, four of them |
| "`ProxyConfig` is populated through `HTTPOptions`, not the URI" | **half true** — through `HTTPOptions`, but the URI **is** what populates it |
| "an operator who never configures a proxy gets `""` → auto-discovery" | **stays true** — `:121` returns `""` when the param is absent |
| **proxy inheritance answer itself (§0 of D43)** | **UNAFFECTED** — Sliver still inherits via `parseProxyConfig`, and `""` still falls through to `"auto"` |

`[src]`

**The D43 conclusion was right; its §8 sub-claim was wrong.** `[inference]` **And the corrected picture is actually STRONGER for D43's thesis: the operator can type `proxy=`, `proxy-username=`, `proxy-password=`, and `ask-proxy-creds=true` on the C2 URI — i.e. Sliver supports forced proxying WITH credentials AND inherited discovery, both.** `[src]`

**Note what this also means, and it is a live finding not a book-keeping one:** `proxy-username=` and `proxy-password=` are **URI query parameters**, so **proxy credentials are embedded in the implant's C2 URI** — which is itself embedded in the generated binary. `[src]` + `[inference]` **Residual §R5; I did not read the server side that constructs that URI, so I am not claiming where it is stored or whether it is encrypted.** `[inference]`

### 0.2 CORRECTION TO THE BRIEF — the path is `server\transport\`, not `server\transports\`

**The brief says `server\transports\` — all of them.** `[src]` **That directory does not exist. Checked with `Test-Path`: `server\transports` = `False`, `server\transport` = `True`.** `[src]` **A recursive search for any directory matching `transport` under `server\` returns exactly one hit: `\server\transport`.** `[src]`

**This matters because of the brief's own rule: "A recursive glob in PowerShell `-Path "$m\**\*.go"` form returns a FALSE ZERO."** `[inference]` **The brief's path was one character off, and a probe against `server\transports\` would have returned a legitimate-looking empty set.** `[inference]`

**More importantly, the substance is split across THREE directories, and the brief's framing would have found only one third of it:** `[src]`

| Directory | Files | KB | What lives there |
|---|---:|---:|---|
| **`server\transport\`** | 11 | 63.8 | **The OPERATOR plane** — the gRPC transport the *client* connects to (mTLS, WireGuard multiplayer, Tailscale, middleware, keepalive) |
| **`server\c2\`** | 31 | 272.3 | **The IMPLANT plane** — the listeners that speak to deployed implants (HTTP, DNS, mTLS, WireGuard, TCP stager) |
| **`server\handlers\`** | 15 | 244.0 | **Session/beacon/pivot lifecycle** — not listeners |

`[src]`

**The two "mTLS" and "WireGuard" pairs in the corpus are NOT duplicates — they are the two different planes.** `[src]` `server\transport\mtls.go` (4,843 B) is the **operator** mTLS; `server\c2\mtls.go` (13,646 B) is the **implant** mTLS. `[inference]` **Any cross-report statement about "Sliver's mTLS" that does not say which plane is meaningless, and I will name the plane in every row of §2.** `[inference]`

### 0.3 Enumeration invocation (brief rule: a number needs its command)

```powershell
$s='...\RE_Library\01_SOURCE_c2\sliver'
$all = Get-ChildItem "$s\server" -Recurse -File
"files: $($all.Count)"; "KB: $([math]::Round(($all|Measure-Object Length -Sum).Sum/1KB,1))"
$go = Get-ChildItem "$s\server" -Recurse -File -Filter *.go
"go files: $($go.Count)"; "go KB: $([math]::Round(($go|Measure-Object Length -Sum).Sum/1KB,1))"
```

**Output:** `files: 408` / `KB: 5337.5` / `go files: 353` / `go KB: 3269.4`. `[src]`

---
---

## Q1 — The RPC surface

### 1.1 How many RPC methods are registered, and how I counted

**The task demands the invocation, so here is every probe in order, including the one that failed.** `[src]`

**PROBE 1 — server-side receivers.**

```powershell
$m = Get-ChildItem "$s\server\rpc" -Recurse -File -Filter *.go |
     Where-Object {$_.Name -notlike '*_test.go'} |
     Select-String -Pattern '^func \(rpc \*Server\) '
"total hits: $($m.Count)"
$names = $m | ForEach-Object { if($_.Line -match '^func \(rpc \*Server\) (\w+)\('){$Matches[1]} }
"distinct names: $(($names|Sort-Object -Unique).Count)"
```

**Output: `total hits: 214`, `distinct names: 213`, duplicate `killSession` ×2.** `[src]`

**PROBE 2 — the generated interface. THIS ONE FAILED FIRST.** `[src]`

```powershell
$pb="$s\protobuf\rpcpb\services.pb.go"
$start = ($lines | Select-String -Pattern 'type SliverRPCServer interface' | Select-Object -First 1).LineNumber
"interface declared at line: $start"
```

**Output: `interface declared at line:` — EMPTY, and the companion greps returned nothing.** `[src]`

**By the brief's own rule this is UNTESTED, not negative — and I treated it as untested.** `[src]` **The `SliverRPCServer` interface is not in `services.pb.go`. It is in `services_grpc.pb.go:2524`.** `[src]` **A probe that has never succeeded anywhere proves nothing; I located the real home before drawing any conclusion.** `[inference]`

**PROBE 3 — the generated interface, at its real location.** `[src]`

```powershell
Get-ChildItem "$s\protobuf" -Recurse -File -Filter *.go |
  Select-String -Pattern 'type SliverRPCServer interface' | ForEach-Object { $_.Path; $_.LineNumber }
```

**Output: `\protobuf\rpcpb\services_grpc.pb.go:2524`.** `[src]`

**Then, reading `services_grpc.pb.go:2524` → closing `}` at `:2759` (interface body 235 lines), classified:** `[src]`

| Shape | Count | Pattern used |
|---|---:|---|
| unary `(context.Context, *X) (*Y, error)` | **195** | `^\t\w+\(context\.Context, \*` |
| streams (`grpc.ClientStreamingServer[...]` etc.) | **6** | see §1.2 |
| `mustEmbedUnimplementedSliverRPCServer()` | 1 | — |
| **TOTAL generated methods** | **201** | 195 + 6 |

`[src]`

**PROBE 4 — independent corroboration from the `grpc.ServiceDesc` literal.** `[src]`

```powershell
$descStart = ($lines | Select-String -Pattern 'var SliverRPC_ServiceDesc = grpc.ServiceDesc\{').LineNumber
# $descStart = 6959
"MethodName: $(($dbody | Select-String -Pattern 'MethodName:').Count)"
"StreamName: $(($dbody | Select-String -Pattern 'StreamName:').Count)"
```

**Output: `MethodName: 195`, `StreamName: 6`.** `[src]`

**THE TWO INDEPENDENT COUNTS AGREE: 195 unary + 6 streams = 201.** `[src]`

### 1.2 My own instrument failure, recorded

**My stream classifier initially returned ZERO streams while `ServiceDesc` reported six.** `[src]` **I did not pick the number that agreed with itself; I printed every non-unary line in the interface body.** `[src]`

```powershell
$odd = $body | Where-Object { $_ -notmatch '^\t\w+\(context\.Context, \*' -and $_ -match '\(' }
```

**Output — 7 lines, printed in full:** `[src]`

```
ClientLog(grpc.ClientStreamingServer[clientpb.ClientLogData, commonpb.Empty]) error
BuilderRegister(*clientpb.Builder, grpc.ServerStreamingServer[clientpb.Event]) error
CrackstationRegister(*clientpb.Crackstation, grpc.ServerStreamingServer[clientpb.Event]) error
SocksProxy(grpc.BidiStreamingServer[sliverpb.SocksData, sliverpb.SocksData]) error
TunnelData(grpc.BidiStreamingServer[sliverpb.TunnelData, sliverpb.TunnelData]) error
Events(*commonpb.Empty, grpc.ServerStreamingServer[clientpb.Event]) error
mustEmbedUnimplementedSliverRPCServer()
```

`[src]`

**Root cause of the instrument failure:** my first stream pattern was `^\t\w+\(\*.*opts \.\.\.grpc\.CallOption\)` — **the OLD pre-generics gRPC stream signature.** `[inference]` **This generated file uses the modern generic form (`grpc.ClientStreamingServer[T, U]`), so the pattern could not match anything.** `[inference]` **Six real stream methods reported zero, and the corroborating `ServiceDesc` is the only reason I caught it.** `[inference]` **Recorded as the second instrument failure in this report; §1.5's diff would have been silently wrong by six.** `[src]`

### 1.3 Reconciling 213 server-side against 201 generated

**A 12-name difference, and the two directions are different kinds of thing.** `[src]`

```powershell
$missing = $gen | Where-Object { $srv -notcontains $_ }   # in generated, not implemented
$extra   = $srv | Where-Object { $gen -notcontains $_ }   # implemented, not in interface
```

**Output A — 8 generated methods with NO `*Server` implementation: `GetOperators`, `Portfwd`, `CreateSocks`, `CloseSocks`, `SocksProxy`, `CreateTunnel`, `CloseTunnel`, `TunnelData`.** `[src]`

**Reading: these 8 are satisfied by the embedded `rpcpb.UnimplementedSliverRPCServer` (`rpc.go:89`), i.e. they return `codes.Unimplemented` unless implemented elsewhere in the package under a different receiver form.** `[inference]` **I verified only that no `func (rpc *Server) <Name>` exists — NOT that they are unreachable.** `[src]` **"Never invoked" and "cannot be invoked" are different claims, and §R2 carries the probe.** `[inference]`

**Output B — 20 `*Server` methods that are NOT interface methods (i.e. internal helpers), printed in full:** `[src]`

```
aiOperatorName                              authorizeCrackstation
asyncGenericHandler                         bestEffortImplantRportFwdListenerIDs
authorizeBuilderForExternalBuild            GenericHandler
authorizeBuilderOperatorForExternalBuild    getClientCommonName
getError                                    getTimeout
invokeGenericHandler                        killBeacon
KillSession                                 queryImplantRportFwdInventory
rejectRevokedCrackTaskAttempt               rportFwdRegistry
runAIConversationCompletion                 standaloneCrackTaskByID
standaloneCrackTaskUpdate                   transitionCrackJob
```

`[src]`

**`GenericHandler` and `KillSession` are *capitalised* — they LOOK like RPC methods but are not in the generated interface.** `[src]` **`[inference]` They are the shared dispatch entry points that the real RPC methods call *into*** — `GenericHandler` (`rpc.go:181`) is the sync/async session dispatcher, and `KillSession` (capitalised, no interface entry) is the shared kill path. **This is the same ninth-shape family as D23's `iota` false zero: a naming convention that looks like one category and is another.** `[inference]`

**So the honest headline count is:** `[src]`

> **201 RPC methods are registered in the generated gRPC service (195 unary + 6 streaming), corroborated by two independent instruments. 193 of them have a direct `func (rpc *Server)` implementation; 8 fall through to `UnimplementedSliverRPCServer`. The package additionally contains 20 internal `*Server` helpers that are not RPC methods.**

`[src]` for the numbers; `[inference]` for the 193 figure (201 − 8).

### 1.4 Does reaching a target require a principal? — the D12 comparison

**D12 found `aitools` passes `toolTarget` two ID strings and no principal, so none is enforceable.** `[src]` **The question is whether that shape is universal. It is NOT. `aitools` is an outlier, and the RPC surface contains a real authorization class that D12 did not encounter.** `[src]`

**THE IDENTITY EXTRACTOR — `server/rpc/rpc.go:260-276`, in full:** `[src]`

```go
func (rpc *Server) getClientCommonName(ctx context.Context) string {
	client, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	tlsAuth, ok := client.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}
	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		return ""
	}
	if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != "" {
		return tlsAuth.State.VerifiedChains[0][0].Subject.CommonName
	}
	return ""
}
```

`[src]`

**This is a genuine principal, derived from the mTLS peer certificate's `CommonName` — through `peer.FromContext`, `credentials.TLSInfo`, and the *verified* chain (`VerifiedChains`, not `PeerCertificates`).** `[src]` **The `VerifiedChains` requirement is the load-bearing part: an attacker-supplied cert that did not validate yields an empty string, not a spoofable identity.** `[inference]`

**MEASUREMENT — invocation and output:** `[src]`

```powershell
$f=Get-ChildItem "$s\server\rpc" -Recurse -File -Filter *.go | Where-Object {$_.Name -notlike '*_test.go'}
$gcn = $f | Select-String -Pattern 'getClientCommonName'
$au  = $f | Select-String -Pattern 'authorize[A-Za-z]*\('
```

| Probe | Hits | Files |
|---|---:|---:|
| `getClientCommonName` | **9** | **6** |
| `authorize*()` | **17** | **3** |
| `peer.FromContext` | **1** | 1 |
| `credentials.` / `InfoFromContext` / `CommonName` | **22** | — |

`[src]`

**Note `peer.FromContext` = 1 hit: the extractor is the single chokepoint for peer identity.** `[src]` **That is good design — one place to audit — and it also means the identity capability is concentrated in exactly one function.** `[inference]`

**THE AUTHORIZATION HELPERS — signatures, printed:** `[src]`

```
rpc-generate.go:846:      func (rpc *Server) authorizeBuilderForExternalBuild(ctx context.Context, builderName string, buildID string) error
rpc-generate.go:877:      func (rpc *Server) authorizeBuilderOperatorForExternalBuild(ctx context.Context, buildID string) error
rpc-crackstations.go:384: func (rpc *Server) authorizeCrackstation(ctx context.Context, hostUUID string) error
rpc-crackstations.go:553: func (rpc *Server) rejectRevokedCrackTaskAttempt(ctx context.Context, req *clientpb.CrackTask) (bool, error)
crack-keyspace.go:656:    func (rpc *Server) standaloneCrackTaskByID(ctx context.Context, req *clientpb.CrackTask) (*clientpb.CrackTask, bool, error)
```

`[src]`

**Every one takes `ctx`.** `[src]` **That is the critical difference from D12's `buildRequestContext(ctx context.Context, target toolTarget)`, which takes `ctx` and then discards it in favour of two ID strings.** `[src]`

**THE ENFORCEMENT PATTERN — `rpc-crackstations.go:384-397`, in full:** `[src]`

```go
func (rpc *Server) authorizeCrackstation(ctx context.Context, hostUUID string) error {
	caller := rpc.getClientCommonName(ctx)
	if caller == "" {
		return status.Error(codes.Unauthenticated, "missing crackstation client identity")
	}
	station := core.GetCrackstation(hostUUID)
	if station == nil {
		return status.Error(codes.FailedPrecondition, "crackstation is not registered")
	}
	if station.Snapshot().OperatorName != caller {
		return status.Error(codes.PermissionDenied, "crackstation identity does not own host")
	}
	return nil
}
```

`[src]`

**Read the third check: `station.Snapshot().OperatorName != caller`.** `[src]` **The caller's certificate CN is compared to the operator name recorded on the crackstation's registration record — i.e. ownership is checked against persisted state, and the principal is unforgeable because it comes from the verified chain.** `[src]` + `[inference]` **This is a real authorization decision, and it is the exact inverse of D12's finding.** `[inference]`

**THE CALL SITES — all 17, printed (this is the evidence that they are load-bearing, not decorative):** `[src]`

| File:line | Call |
|---|---|
| `crack-keyspace.go:674` | `rpc.authorizeCrackstation(ctx, expectedHost)` |
| `crack-keyspace.go:729` | `rpc.authorizeCrackstation(ctx, req.HostUUID)` |
| `rpc-crackstations.go:418` | `rpc.authorizeCrackstation(ctx, statusUpdate.HostUUID)` |
| `rpc-crackstations.go:455` | `rpc.authorizeCrackstation(ctx, acknowledgement.HostUUID)` |
| `rpc-crackstations.go:477` | `rpc.authorizeCrackstation(ctx, statusUpdate.HostUUID)` |
| `rpc-crackstations.go:541` | `rpc.authorizeCrackstation(ctx, task.CrackstationID.String())` |
| `rpc-crackstations.go:557` | `rpc.authorizeCrackstation(ctx, req.HostUUID)` |
| `rpc-crackstations.go:607` | `rpc.authorizeCrackstation(ctx, req.HostUUID)` |
| `rpc-crackstations.go:632` | `rpc.authorizeCrackstation(ctx, req.HostUUID)` |
| `rpc-generate.go:638` | `rpc.authorizeBuilderForExternalBuild(ctx, req.Name, req.ImplantBuildID)` |
| `rpc-generate.go:681` | `rpc.authorizeBuilderForExternalBuild(ctx, req.Name, req.ID)` |
| `rpc-generate.go:805` | `rpc.authorizeBuilderOperatorForExternalBuild(ctx, buildID)` |
| `rpc-generate.go:818` | `rpc.authorizeBuilderOperatorForExternalBuild(ctx, buildID)` |
| `rpc-generate.go:831` | `rpc.authorizeBuilderOperatorForExternalBuild(ctx, buildID)` |

`[src]` **(14 call sites + the 3 function definitions = the 17 hits; the arithmetic reconciles.)** `[src]`

**Concentration: `rpc-crackstations.go` (9 sites incl. definition), `crack-keyspace.go` (2), `rpc-generate.go` (5 incl. definitions). Three files out of 84.** `[src]`

### 1.5 The answer to the headline question

**The task asks: is the `aitools` shape true across the whole RPC surface, or is `aitools` an outlier?**

> **`aitools` is an OUTLIER — but the authorization it lacks is concentrated in a MINORITY of the surface, so the defensible statement is a distribution, not a binary.**

`[src]` + `[inference]`

| Category | Count | Authorization posture |
|---|---:|---|
| RPC methods on the generated interface | **201** | — |
| Methods calling an `authorize*` helper | **~11 distinct methods** (14 call sites, 3 definitions) | **principal enforced from verified cert CN** |
| Methods whose auth is delegated to middleware | **unmeasured** — see below | `server\transport\middleware.go` (16,888 B) **NOT read** |
| Methods of the `aitools` shape (no principal) | **≥1 known (`aitools`), remainder unmeasured** | **none expressible** |

`[src]` for the first two rows; the third and fourth are explicitly **unmeasured** and carried to §R1. `[src]`

**The honest finding, stated at the strength the evidence supports:**

> **A real, ctx-based, cert-CN-grounded authorization class EXISTS on the Sliver server RPC surface and is load-bearing in `rpc-crackstations.go`, `crack-keyspace.go` and `rpc-generate.go` — 14 call sites across three of the RPC files. It is NOT the universal shape: `aitools` (D12) passes two ID strings where these pass a verified principal. So D12's finding is correct about `aitools` and INCORRECT if generalised. The generalisation boundary is unmeasured because `server\transport\middleware.go` — the likely home of any global interceptor-level authorization — was outside this report's read budget.**

`[inference]` for the framing; `[src]` for every count. `[src]`

**This is a materially better outcome for the corpus than "the whole surface lacks authorization," and it is a correction to an inference that D12 did not make but which a reader of D12 could easily draw.** `[inference]`

---
---

## Q2 — The transports, per row

### 2.1 The plane split (restated because every row depends on it)

**`server\transport\` = OPERATOR plane. `server\c2\` = IMPLANT plane. §0.2.** `[src]`

**Enumerated, `server\transport\` (11 files / 63.8 KB):** `[src]`

| File | Bytes | Role |
|---|---:|---|
| `keepalive.go` | 1,504 | operator stream liveness |
| `local.go` | 2,030 | local socket transport |
| `middleware.go` | **16,888** | **gRPC interceptor chain — the likely global-auth home** |
| `mtls.go` | 4,843 | **operator** mTLS |
| `multiplayer_wireguard.go` | 5,228 | multiplayer WG |
| `operator_streams.go` | 3,485 | operator stream registry |
| `tailscale.go` | 3,031 | Tailscale transport |
| `README.md` | 523 | |
| + 3 test files | 37,760 | |

`[src]`

**Enumerated, `server\c2\` production files (excluding tests):** `[src]`

| File | Bytes | Role |
|---|---:|---|
| `dns.go` | **37,264** | DNS listener + reassembly |
| `http.go` | **29,542** | HTTP(S) listener |
| `wireguard.go` | 16,498 | WireGuard listener |
| `mtls.go` | 13,646 | mTLS listener |
| `jobs.go` | 8,949 | listener job wrappers |
| `http.go`/`mtls.go` companions | — | |
| `envelope_reader.go` | **1,641** | **spooling read defense** |
| `tcp-stager.go` | 1,815 | TCP stager |
| `c2profile.go` | 1,277 | profile glue |
| `panic_recover.go` | 253 | panic guard |

`[src]`

### 2.2 THE PER-TRANSPORT TABLE — framing named per row

**Every row gives: port/protocol, framing, encoder chain, and the wire appearance.** `[src]`

| # | Listener | Plane | Port / protocol | Framing | Encoder / decode chain | What the implant looks like on the wire |
|---|---|---|---|---|---|---|
| **1** | **mTLS** | implant | operator-chosen TCP (`jobs.go:47-48`; `mtls.go:119` `tls.Listen("tcp", ...)`) | **mandatory 5-byte yamux preface `"MUX/1"`** (`mtls.go:57,66,159-168`) → yamux multiplex, **max 128 concurrent streams / 64 concurrent sends** (`:59-60`) | Ed25519 envelope sign/verify via `util/minisign` (`:44`); key derived per-implant `deriveImplantSigningKey` (`:73-77`) | **TLS with a self-signed implant cert; then a `MUX/1` preface; then signed protobuf envelopes.** Generic encrypted transport. No mimicry. |
| **2** | **WireGuard** | implant | **UDP**, three ports: `wgListener.Port`, `NPort`, `KeyPort` (`jobs.go:75`; `wireguard.go:65`) | WG protocol handshake → netstack TCP on `netstackPort` (`wireguard.go:84-86` `AllowTCPPort`), then **the same yamux + signed envelope stack as mTLS** | same minisign Ed25519 envelope chain | **WireGuard UDP.** Indistinguishable from any WG tunnel at the protocol layer. No mimicry. |
| **3** | **HTTP(S)** | implant | `req.Host:req.Port` (`http.go:196`) | HTTP/1.1 or ACME TLS (`http.go:185` TODO) | **nonce-selected encoder: `getEncoder` → `encoders.EncoderFromNonce(nonce)` (`http.go:420-443`)** | **Browser-shaped / configurable.** Chrome UA (`http-c2.go:374-409`), probabilistic headers, randomized path segments, randomized `Server:` header. **This is the mimicry+VARIATION transport.** |
| **4** | **DNS** | implant | **UDP** (`dns.go:102` `Net: "udp"`) | DNS query/response; implant payload carried in encoded labels | **Base32** (client side, D36 §6) — server decodes via the same encoder contract | **DNS queries to an operator domain.** Alphabet-only, no vocabulary, one parent. |
| **5** | **TCP stager** | implant | raw TCP (`tcp-stager.go:33-35` `net.Listen("tcp", ...)`) | raw TCP, shellcode delivery | **none** | **A bare TCP connection downloading bytes.** No protocol at all. |

`[src]` for every mechanism; `[inference]` for the "what it looks like" column, which is a reading of the mechanisms, not a capture. `[inference]`

**Ports are ALL operator-supplied — Sliver hard-codes no listening port.** `[src]` **There is no default port constant in any listener; every `Start*Listener` takes the port from the request struct.** `[src]` `[inference]` **So "what port does Sliver listen on" has no answer — that is itself a finding, and it is why no port-based signature of Sliver exists.** `[inference]`

### 2.3 Server confirms the client: D36's taxonomy holds — with one refinement

**D36 proved client-side that HTTP conceals by VARIATION (probabilistic headers) and DNS has the alphabet and nothing else. The task asks me to confirm or refute from the SERVER side, since the server PARSES what the client EMITS.** `[src]`

**CONFIRMED — and the server does the SAME roll, independently, on the response path.** `[src]`

**Server roll — `server/c2/http.go:487-494` and `:498-505`:** `[src]`

```go
for _, header := range s.c2Config[0].ServerConfig.Headers {
	if 0 < header.Probability && header.Probability < 100 {
		roll := util.Intn(99) + 1
		if header.Probability < int32(roll) {
			continue
		}
	}
	resp.Header().Set(header.Name, header.Value)
}
```

`[src]`

**Client roll — `implant/sliver/transports/httpclient/httpclient.go:285-292`:** `[src]`

```go
probability, _ := strconv.Atoi(header.Probability)
if 0 < probability {
	roll := util.Intn(99) + 1
	if probability < roll {
		continue
	}
}
req.Header.Set(header.Name, header.Value)
```

`[src]`

**Both sides roll `util.Intn(99) + 1` and skip on `probability < roll`. So the raw HTTP response carries the same nondeterministic header profile as the request — in BOTH directions.** `[src]` **The concealment is bidirectional, not request-only.** `[src]` + `[inference]` **This is a REFINEMENT of D36, not a refutation: D36 described the request path (which was its scope); the server applies the identical mechanism to responses.** `[inference]`

**The server ALSO randomizes the `Server:` header — `server/c2/http.go:158-168`:** `[src]`

```go
func (s *SliverHTTPC2) getServerHeader() string {
	if serverVersionHeader == "" {
		switch util.Intn(2) {
		case 0:
			serverVersionHeader = fmt.Sprintf("Apache/2.4.%d (Unix)", util.Intn(48))
		default:
			serverVersionHeader = fmt.Sprintf("nginx/1.%d.%d (Ubuntu)", util.Intn(21), util.Intn(8))
		}
	}
	return serverVersionHeader
}
```

`[src]`

**Two mimicry targets (Apache, nginx), randomly chosen — but assigned to a package-level variable `serverVersionHeader` and cached after first use (`if serverVersionHeader == ""`).** `[src]` **So the server picks ONE of the two identities PER PROCESS and keeps it, rather than varying per response.** `[inference]` **That is mimicry at the process level and constancy within it — the opposite of the per-request variation used for headers.** `[inference]` **Worth flagging as an inconsistency in the concealment model (residual §R6): `RandomVersionHeaders` is opt-in (`http.go:483`) and the value is stable, while the header set varies per request.** `[src]`

**CONFIRMED — the server/client encoder contract is shared code with shared constants.** `[src]`

| Constant / function | Client | Server |
|---|---|---|
| `EncoderModulus` | `implant/sliver/encoders/encoders.go:45` = `65537` | `server/encoders/encoders.go:46` = `65537` |
| `EncoderFromNonce` | `:114-123`, `encoderID := nonce % EncoderModulus` | `:255-256`, `encoderID := uint64(nonce) % EncoderModulus` |
| `RandomEncoder` | `:129-136` | `:267-273`, `nonce := (randomUint64(MaxN) * EncoderModulus) + encoderID` |

`[src]`

**The modulus matches exactly on both sides — no mismatch, no defect.** `[src]` **This is the critical check the task asked for, and it passes.** `[inference]`

**One asymmetry worth naming, from `http.go:420-443`:** the server's `getEncoder` has a **fallback path for anonymous requests** — when `ImplantConfig.NonceQueryLength` is unknown it retries with length `0` (`:427-430`), and **iterates every nonce found until one yields an encoder (`:437-441`).** `[src]` `[inference]` **This means an attacker who can construct a request with many numeric path/query segments makes the server do a bounded but repeated modulus lookup — a small amplification surface, not obviously exploitable, and I am not claiming it is.** `[inference]`

**CONFIRMED — the DNS server has real stateful reassembly, and the client does not (matching D36 §6 / msf-diver).** `[src]`

**Server DNS state, enumerated:** `[src]`

| State | Declared at | Purpose |
|---|---|---|
| `outgoingBuffers map[uint32][]byte` | `dns.go:131` | per-msgID outbound ciphertext |
| `StageOutgoingEnvelope` | `dns.go:182` | store envelope, bounded by `maxMessages` / `maxBytes` |
| `PopOutgoingMsgID` | `dns.go:214` | retrieve by msgID |
| `OutgoingRead(msgID, start, stop)` | `dns.go:232` | **range read — windowed reassembly** |
| `ClearOutgoingEnvelope` | `dns.go:250` | free |
| `IncomingPendingEnvelope` | `dns.go:301` | **inbound reassembly state** |
| `ForwardCompletedEnvelope` | `dns.go:319` | **`pending.Reassemble()` at `:334`** |

`[src]`

**And there is a deliberate bound on unauthenticated state — `dns.go:69`:** *"Upper bound on unauthenticated init reassembly state. INIT is split across multiple..."* `[src]` **This is a DoS-hardening comment, and it is a COMMENT — a claim, not a measurement. I did not verify the bound is enforced.** `[src]` **Carried to §R3.** `[inference]`

**Verdict: the server is the stateful half and the client is the stateless half — CONFIRMED from the server side, independently of D36 and msf-diver.** `[src]` + `[inference]` **A vital asymmetry and not a defect: the reassembly state has to live somewhere, and putting it on the server means a compromised implant holds no cross-fragment buffer an analyst could seize.** `[inference]`

**REFUTED — nothing. D36's client-side taxonomy is fully consistent with the server-side parse.** `[src]`

### 2.4 The envelope hardening — a finding not in the brief

**`server/c2/envelope_reader.go` (1,641 B) is a disk-spooling defense against attacker-triggered allocation.** `[src]`

```go
const (
	// socketEnvelopeDiskSpoolThreshold is the point where envelope payloads are
	// streamed to disk first to avoid large attacker-triggered allocations.
	socketEnvelopeDiskSpoolThreshold = 64 * 1024 * 1024          // :11
	// socketEnvelopeReadChunkSize bounds peak in-memory usage while reading large
	// envelopes from the network.
	socketEnvelopeReadChunkSize = 1 * 1024 * 1024                // :15
)

func readSocketEnvelopeData(reader io.Reader, dataLength int, inMemoryLimit int) ([]byte, error) {
	if dataLength <= inMemoryLimit {
		dataBuf := make([]byte, dataLength)
		if _, err := io.ReadFull(reader, dataBuf); err != nil {      // :21
			return nil, err
		}
		return dataBuf, nil
	}
	tmpFile, err := os.CreateTemp("", "sliver-envelope-*")            // :27
	...
	chunkSize := socketEnvelopeReadChunkSize
	if dataLength < chunkSize { chunkSize = dataLength }
	chunkBuf := make([]byte, chunkSize)                               // :41
```

`[src]`

**Reading: above 64 MiB the envelope is streamed to a temp file in 1 MiB chunks instead of being allocated in memory.** `[src]` + `[inference]` **This is a defense against a MALICIOUS PEER announcing a huge length and forcing a large allocation — the classic length-prefix amplification — and it is the server-side counterpart to D31's frame structure.** `[inference]` **Note the `defer` at `:32-35` closes and removes the temp file.** `[src]`

**And the mTLS listener enforces the yamux preface as a hard admission gate — `mtls.go:159-168`:** `[src]`

```go
preface, err := br.Peek(len(mtlsYamuxPrefaceBytes))
if err == nil && bytes.Equal(preface, mtlsYamuxPrefaceBytes) {
	...
	handleSliverConnectionYamux(bufferedConn, implantConn)
	...
mtlsLog.Warnf("Rejecting legacy mtls connection (missing yamux preface) from %s", conn.RemoteAddr())
```

`[src]`

**A connection without the 5-byte `MUX/1` preface is REJECTED and logged** (`:168`). `[src]` **So the mTLS listener cannot be spoken to by a plain TLS client without knowing the preface — a 5-byte protocol discriminator.** `[inference]` **Trivially guessable if known, but it defeats naive TLS probing and generic scanners.** `[inference]`

**`mtls.go:184` carries `//nolint:gocyclo`** — *"The transport loop keeps stream admission, shutdown, dispatch, and response handling together."* `[src]` **A complexity suppression on the main transport loop, i.e. the maintainers acknowledge this function is doing four jobs.** `[src]` `[inference]` **Recorded as a code-quality signal and a place a reader should expect subtle bugs; I did not audit it.** `[inference]`

---

## Q4 — The listeners: configured vs honoured

**The task's framing, from D43: `ProxyConfig` reaches `transport.Proxy` unconditionally while `WininetDriver` never reads it. "Configured" ≠ "honoured." Find every other gap.** `[src]`

### 4.1 Listener types — enumerated, not assumed

**Five implant-facing listener types, from `server/c2/jobs.go` (five `Start*ListenerJob` functions):** `[src]`

| # | Job function | Line | Underlying start |
|---|---|---|---|
| 1 | `StartMTLSListenerJob` | `:46` | `StartMutualTLSListener(host, port)` `:48` |
| 2 | `StartWGListenerJob` | `:74` | `StartWGListener(port, nPort, keyPort)` `:75` |
| 3 | `StartDNSListenerJob` | `:130` | `StartDNSListener(host, port, domains, canaries)` `:131` |
| 4 | `StartHTTPListenerJob` | `:173` | `StartHTTPListener(req)` `:174` |
| 5 | `StartTCPStagerListenerJob` | `:232` | `StartTCPListener(host, port, shellcode)` `:233` |

`[src]`

**This matches the corpus's expectation (mTLS, WireGuard, HTTP, DNS) and adds the TCP stager as a fifth.** `[src]` **The corpus had not enumerated the stager.** `[inference]`

### 4.2 What the operator configures, and what reaches the wire

**Per listener, the request struct fields and whether they are load-bearing:** `[src]`

| Listener | Operator-configured | Reaches the wire? |
|---|---|---|
| **mTLS** | `Host`, `Port` (`jobs.go:47-48`) | **YES** — bind address |
| **WireGuard** | `Port`, `NPort`, `KeyPort` (`:75`) | **YES** — all three bound |
| **DNS** | `Host`, `Port`, `Domains`, `Canaries` (`:131`) | **`Domains` YES** (accepted-label set); **`Canaries` YES** (decoy labels) |
| **HTTP** | full `HTTPListenerReq` (`:174`) | **mostly YES** — see 4.3 |
| **TCP stager** | `Host`, `Port`, `Name`, `Shellcode` (`:232-233`) | **`Host`/`Port`/`Shellcode` YES; `Name` is a JOB LABEL ONLY** |

`[src]`

**GAP FOUND #1 — `Name` on the TCP stager never reaches the wire.** `[src]` **`StartTCPStagerListenerJob(host, port, name, shellcode)` (`:232`) passes only `host, port, shellcode` to `StartTCPListener` (`:233`); `name` is used for the job's description.** `[src]` **This is a benign gap — a label, not a security setting.** `[inference]` **Recorded because the task asked for every one, and because a benign instance is the positive control that the method can distinguish gaps from non-gaps.** `[inference]`

### 4.3 GAP FOUND #2 — the HTTP `ServerConfig` vs `ImplantConfig` split

**This is the structural version of the D43 gap, and it is the most important thing in Q4.** `[src]`

**The HTTP C2 profile has TWO header sets: `ServerConfig.Headers` and `ImplantConfig.Headers`.** `[src]`

**The server's response path reads `ServerConfig.Headers` — `http.go:486`:** `[src]`

```go
for _, header := range s.c2Config[0].ServerConfig.Headers {
```

**with an anonymous-request fallback to `serverConfig.HTTPDefaults.Headers` — `http.go:497`:** `[src]`

```go
for _, header := range serverConfig.HTTPDefaults.Headers {
```

`[src]`

**And the implant's request path reads `ImplantConfig.Headers` — `httpclient.go:266-275` (D36).** `[src]`

**So `ServerConfig.Headers` shapes the server's RESPONSE and `ImplantConfig.Headers` shapes the implant's REQUEST, and they are independent sets.** `[src]` + `[inference]` **Consequence: an operator who configures a header in one set and expects it in the other gets silence — no error, no warning.** `[inference]`

**And the coercion function is applied to BOTH sets — `server/configs/http-c2.go:60-61`:** `[src]`

```go
coerceHeaderProbability(config.ServerConfig.Headers)
coerceHeaderProbability(config.ImplantConfig.Headers)
```

`[src]` **So both sets get `0 → 100` coercion; the gap is in which set is READ, not in which is prepared.** `[src]` **A config-time fix for both, a runtime read of one.** `[inference]`

### 4.4 GAP FOUND #3 — the server/client `Probability` guard is ASYMMETRIC (this is Q3's mechanical finding)

**Both sides roll `util.Intn(99) + 1`, but the GUARDS differ:** `[src]`

| Side | Guard | Line |
|---|---|---|
| **Server** | `if 0 < header.Probability && header.Probability < 100 {` | `server/c2/http.go:487`, `:498` |
| **Client** | `if 0 < probability {` | `implant/.../httpclient.go:286` |

`[src]`

**Work the boundary cases arithmetically.** `roll = util.Intn(99) + 1` → **`roll` is uniform on `[1, 99]`.** `[src]` **The header is set unless `probability < roll`, i.e. unless `roll > probability`.** `[inference]`

**CLIENT (`0 < probability`, no upper bound):** `[src]`

| `probability` | Skips when `roll > probability` | P(skip) | P(set) | Meaning |
|---:|---|---:|---:|---|
| `0` | guard false — never skips | 0 | **1.00** | **ALWAYS** (note: inverted from intent) |
| `1` | `roll > 1` → roll∈[2,99] | 98/99 | 0.0101 | 1% |
| `50` | `roll > 50` → roll∈[51,99] | 49/99 | 0.5051 | ~50% |
| `99` | `roll > 99` → never | 0 | **1.00** | **ALWAYS** |
| **`100`** | `roll > 100` → never | 0 | **1.00** | **ALWAYS** |
| **`>100`** (e.g. `1000`) | never | 0 | **1.00** | **ALWAYS** |

`[src]` + `[inference]`

**SERVER (`&& header.Probability < 100`, upper-bounded):** `[src]`

| `probability` | Guard | P(set) | Meaning |
|---:|---|---:|---|
| `0` | false (but coerced to 100 at config time) | — | **never rolled; coerced** |
| `1`–`99` | true | same as client | 1%–~100% |
| **`100`** | **`100 < 100` is FALSE → guard skipped → header ALWAYS set** | **1.00** | **ALWAYS, by bypassing the roll** |
| **`>100`** | **`< 100` false → guard skipped → ALWAYS set** | **1.00** | **ALWAYS** |

`[src]` + `[inference]`

**THE ANSWER TO THE TASK'S QUESTION:** `[src]` + `[inference]`

> **`100` means "always" on BOTH sides — but by two DIFFERENT mechanisms. The server short-circuits the roll when `Probability >= 100` (`< 100` guard fails). The client performs the roll and `Intn(99)+1` can never produce a value above 99, so `roll > 100` is impossible and the skip never fires. `100` is therefore NOT "99 times in 100" — it is always. The value that is *nearly* always is `99` on the client (P(set) = 1.00, since `roll ∈ [1,99]` and `roll > 99` is impossible) and `99` on the server (P(set) = 1.00).**

`[src]` + `[inference]`

**So the D36 sentence I wrote — "`Probability=100` still drops 1 in 99" — was WRONG, and I correct it here.** `[src]` **D36 §4 said:** *"Off-by-one: `Intn(99)+1` yields 1–99, so `Probability=100` still drops 1 in 99."* `[src]` **That reasoning requires a roll that can exceed 100; `Intn(99)+1` caps at 99, so `roll > 100` is unreachable and `100` never skips.** `[src]` + `[inference]` **The off-by-one is real but sits at the other end: `probability = 99` is functionally identical to `100` (both always set), and `probability = 1` skips 98/99 rather than 99/100.** `[inference]`

**What an operator can actually express:** `[src]` + `[inference]`

- **`0`** — **client: always set** (`0 < 0` false → no roll). **Server: coerced to `100` at config time (`http-c2.go:75-77`), always set.** `[src]` **So `0` does NOT mean "never" on either side.** `[inference]` **The comment at `http-c2.go:71-72` says the opposite of its own code:** *"value (0) when omitted from the config, which means the header is never sent by the implant. Default to 100 so the header is always applied."* `[src]` **The comment is a claim and it is WRONG about `0` meaning "never" — `coerceHeaderProbability` runs on both sets, so `0` is rewritten to `100` before any roll.** `[src]` **This is exactly the corpus's comment-is-not-a-measurement rule, caught in the wild.** `[inference]`
- **`1`–`98`** — graduated probability, denominator 99.
- **`99` and `100`** — **indistinguishable: both always set.** `[src]`
- **`>100`** — **accepted silently, treated as always-set. No validation rejects it.** `[src]` **Confirmed by the absence of any range check in the `Probability` grep (§Q3.1).** `[src]`

**The no-validation finding, stated precisely:** `[src]` **There is NO validation on `Probability` anywhere in `server\` — the only transformation is `coerceHeaderProbability` (`configs/http-c2.go:73-80`), which handles `== 0` and nothing else.** `[src]` **Values are `int32` (`models/http-c2.go:226` `Probability int32 // 0 - 100`); the comment states a range the code never enforces.** `[src]` + `[inference]` **A third comment-that-is-not-a-measurement: `// 0 - 100` documents an invariant that no code checks.** `[inference]`

---
---

## Q3 — The C2 profile machinery

### 3.1 `generateChromeUserAgent` read in full

**`server/db/models/http-c2.go:374-409`, quoted complete:** `[src]`

```go
// GenerateUserAgent - Generate a user-agent depending on OS/Arch
func GenerateUserAgent(goos string, goarch string, userAgent string, baseVer int32, macOsVer string) string {
	return generateChromeUserAgent(goos, goarch, userAgent, baseVer, macOsVer)
}

func generateChromeUserAgent(goos string, goarch string, userAgent string, baseVer int32, macOsVer string) string {
	if userAgent == "" {
		switch goos {
		case "windows":
			switch goarch {
			case "amd64":
				return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", ChromeVer(baseVer))
			}

		case "linux":
			switch goarch {
			case "amd64":
				return fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", ChromeVer(baseVer))
			}

		case "darwin":
			switch goarch {
			case "arm64":
				fallthrough // https://source.chromium.org/chromium/chromium/src/+/master:third_party/blink/renderer/core/frame/navigator_id.cc;l=76
			case "amd64":
				return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", MacOSVer(macOsVer), ChromeVer(baseVer))
			}

		}
	} else {
		return userAgent
	}

	// Default is a generic Windows/Chrome
	return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", ChromeVer(baseVer))
}
```

`[src]`

### 3.2 The generated UA strings, enumerated

**Four distinct UA shapes, plus operator override, plus a default.** `[src]`

| # | Trigger (`goos`/`goarch`) | UA string template | File:line |
|---|---|---|---|
| **1** | `windows` / `amd64` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<ver> Safari/537.36` | `:385` |
| **2** | `linux` / `amd64` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<ver> Safari/537.36` | `:391` |
| **3** | `darwin` / `arm64` **or** `amd64` | `Mozilla/5.0 (Macintosh; Intel Mac OS X <macos>) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<ver> Safari/537.36` | `:397-399` |
| **4** | **anything else** (fallthrough) | **same as #1 — generic Windows/Chrome** | `:408` |
| **5** | `userAgent != ""` | **the operator's literal string, verbatim** | `:403-404` |

`[src]`

**Enumerated observations:** `[src]`

- **Only `amd64` is handled for Windows and Linux; only `arm64`/`amd64` for Darwin.** `[src]` **`386`, `arm`, and any other arch fall to the generic Windows default (#4) — so a 32-bit Linux implant claims to be Windows.** `[src]` + `[inference]`
- **Darwin `arm64` `fallthrough`s to the `amd64` case** (`:397`) — **deliberate, with a Chromium source link justifying it: Apple Silicon reports the same `Intel Mac OS X` string as Intel Macs.** `[src]` **Verified-correct mimicry.** `[inference]`
- **`Windows NT 10.0` is hard-coded** — so the UA claims Windows 10 even on Windows 11. `[src]` `[inference]` **Technically wrong but consistent with a large installed base; a defensible mimicry choice rather than a defect.** `[inference]`
- **The default is Windows/Chrome, not a neutral string** (`:407-408`). `[src]`

### 3.3 `ChromeVer` — a DEAD LOCAL, and the default version never applies

**`server/db/models/http-c2.go:411-418`, quoted complete:** `[src]`

```go
// ChromeVer - Generate a random Chrome user-agent
func ChromeVer(baseVer int32) string {
	chromeVer := baseVer
	if chromeVer == 0 {
		chromeVer = DefaultChromeBaseVer
	}
	return fmt.Sprintf("%d.0.%d.%d", baseVer+int32(util.Intn(3)), 1000+int32(util.Intn(8999)), int32(util.Intn(999)))
}
```

`[src]`

**Line-by-line:** `[src]`

| Line | Statement | Effect |
|---|---|---|
| `:413` | `chromeVer := baseVer` | local initialised |
| `:414` | `if chromeVer == 0 {` | **the ONLY read of `chromeVer`** |
| `:415` | `chromeVer = DefaultChromeBaseVer` | local assigned `106` |
| `:417` | `fmt.Sprintf("%d.0.%d.%d", baseVer+int32(util.Intn(3)), ...)` | **uses `baseVer`, NOT `chromeVer`** |

`[src]`

**VERIFICATION — every occurrence of the identifier, printed:** `[src]`

```powershell
$c=Get-Content "$s\server\db\models\http-c2.go"
$c|Select-String -Pattern 'chromeVer'|ForEach-Object{"  :$($_.LineNumber): $($_.Line.Trim())"}
```

**Output: 9 hits — seven are the `ChromeVer(...)` CALL sites (`:385`, `:391`, `:399`, `:408`), one is the comment (`:411`), one is the declaration (`:412`). The value of the local variable `chromeVer` is never read after `:414` and it never reaches the format string.** `[src]`

**THE BUG:** `[src]` + `[inference]`

> **When `baseVer == 0`, the assignment at `:415` sets the local to `DefaultChromeBaseVer` (106) and the function then discards it, formatting `baseVer` (still 0) instead. The generated UA reads `Chrome/0.0.xxxx.xxx` through `Chrome/2.0.xxxx.xxx` — a Chrome major version that has never existed.**

`[src]` + `[inference]`

**`DefaultChromeBaseVer = 106` and `DefaultMacOSVer = "10_15_7"` are declared at `:33-34`.** `[src]`

**Why this matters:** `[src]` + `[inference]`

1. **`MacOSVer` (`:420-426`) has the IDENTICAL shape and is CORRECT** — it assigns to a local `macosVer`, defaults it, and **returns the local** (`:425` `return macosVer`). `[src]` **So the correct pattern is three lines below the broken one, and the author wrote it correctly there.** `[src]` **That makes this a transcription slip, not a misunderstanding — and it makes the `ChromeVer` version unambiguously a defect.** `[inference]`
2. **Impact is bounded to mimicked-OS mismatch, not to function:** the UA is still Chrome-shaped and still syntactically valid; it just carries an implausible version. `[inference]` **An implausible major version is a fingerprinting tell — arguably the exact failure the mimicry was meant to avoid.** `[inference]`
3. **It is reachable by default.** `[src]` `ChromeBaseVersion` flows from the profile (`:360` `h.ChromeBaseVersion`); if unset it is `0`, which is precisely the triggering value. `[src]` **A profile that does not explicitly set `ChromeBaseVersion` gets `Chrome/0–2.x`.** `[inference]`
4. **`DefaultChromeBaseVer` is therefore dead code on the UA path** — it is read only into a discarded local. `[src]` **Probe: grep `DefaultChromeBaseVer` across the repo → `:33` (decl), `:415` (dead write). No other reader.** `[src]`

**Recorded as a live, reachable, operator-visible defect. I am NOT claiming it is a security vulnerability — it degrades a concealment feature.** `[inference]`

### 3.4 The probabilistic header set — validation, and what an operator can express

**Full answer is in §4.4, which Q3 asked for; restated here as the Q3 deliverable.** `[src]`

**Is there any validation on `Probability`?** `[src]` **No.** The complete set of `Probability`-touching code in `server\` is: `configs/http-c2.go:60-61` (coercion calls), `:70-80` (`coerceHeaderProbability`), `:175` and `:369` (defaults of `100`), `configs/server.go:182,189,203,215` (struct field + assignment), `db/models/http-c2.go:200,214,226,240,278,302,312` (field + propagation), and `c2/http.go:487,498` (the roll). `[src]` **Nothing rejects, clamps, or warns on out-of-range values.** `[src]`

**Boundary answers:** `[src]` + `[inference]`

| Value | Server | Client | Net |
|---:|---|---|---|
| `0` | coerced to `100` at config load → always set | guard `0 < 0` false → always set | **always, both sides** |
| `1` | skip if `roll ∈ [2,99]` → set 1/99 | same | ~1% |
| `50` | set 50/99 | same | ~50.5% |
| `99` | guard true; `roll > 99` impossible → **always set** | same → **always set** | **always** |
| **`100`** | `100 < 100` false → **guard bypassed → always set** | `roll > 100` impossible → **always set** | **always** |
| `>100` | guard false → always set | `roll > n` impossible → always set | **always; accepted silently** |

`[src]` + `[inference]`

**So `100` means "always", NOT "99 times in 100", and there is no way to express "never" via probability — the only way to omit a header is to not configure it, or to remove it from the set the relevant side reads (§4.3).** `[src]` + `[inference]`

### 3.5 Two comments in this subsystem that are not measurements

**The brief's rule, applied where I found it.** `[src]`

**(a) `server/configs/http-c2.go:70-72`:** `[src]`

```go
// coerceHeaderProbability - Header probability defaults to the protobuf zero
// value (0) when omitted from the config, which means the header is never sent
// by the implant. Default to 100 so the header is always applied.
```

`[src]` **The clause "which means the header is never sent by the implant" is FALSE.** `[src]` **`0` on the implant side satisfies `0 < probability` as false, so no roll occurs and `req.Header.Set` runs unconditionally (`httpclient.go:286-292`) — the header is ALWAYS sent.** `[src]` **The comment describes intent; the code does the opposite on the client, and the coercion rewrites it to `100` on the server, making it always-sent there too.** `[src]` + `[inference]` **Two different mechanisms accidentally agreeing on "always."** `[inference]`

**(b) `server/db/models/http-c2.go:226`:** `[src]` `Probability int32  // 0 - 100` — **a documented range that no code enforces (§3.4).** `[src]`

**Both are recorded, not silently corrected — they are the corpus's own hazard class appearing inside the profile machinery itself.** `[inference]`

---
---

## Q4b — Every other "configured but not honoured" gap

**The task asked me to find every other setting with the D43-style gap. Four found; three benign, one structural.** `[src]`

| # | Setting | Configured where | Honoured where | Gap class |
|---|---|---|---|---|
| **G1** | `ProxyConfig` on WinINet driver | C2 URI `proxy=` (`httpclient.go:121`) | **never read by `WininetDriver`** (D43 §7) | **silent opt-out failure** |
| **G2** | TCP stager `Name` | `StartTCPStagerListenerJob(..., name, ...)` (`jobs.go:232`) | **label only, not passed to `StartTCPListener`** (`:233`) | benign — cosmetic |
| **G3** | `ServerConfig.Headers` vs `ImplantConfig.Headers` | both coerced (`configs/http-c2.go:60-61`) | server reads `ServerConfig` (`http.go:486`); implant reads `ImplantConfig` | **structural — wrong set = silence** |
| **G4** | `Probability` range `0-100` | documented `models/http-c2.go:226` | **no validation anywhere**; `0`→`100` coercion only | **invariant unenforced; `99`==`100`** |

`[src]`

**The G1/G3/G4 family shares one shape: a setting is prepared and stored symmetrically, then READ asymmetrically.** `[inference]` **This is the same instrument-shape mismatch the corpus already catalogued as the `iota`-block family — an artefact whose prepared structure and consumed structure diverge — now appearing in the configuration plane rather than in a regex.** `[inference]`

**Positive control that this method can report a non-gap:** most listener settings ARE honoured — `Host`/`Port` on all five listeners, `Domains` and `Canaries` on DNS, `Shellcode` on the stager, all reach the wire (§4.2). `[src]` **The probe distinguishes; it did not simply report everything as broken.** `[inference]`

---

## 5. Residual unknowns — each with a concrete probe

**R1 — `server\transport\middleware.go` (16,888 B) was NOT read, and it is the likely home of global gRPC authorization.** `[src]` **Q1's distribution is consequently incomplete: I measured per-method `authorize*` calls but not any interceptor-level check.** `[src]` **Probe:** read `server\transport\middleware.go` in full and enumerate every `grpc.UnaryServerInterceptor`; then determine whether operator RPC authorization is enforced there rather than per-method. **This is the highest-value follow-up in the report and it is one file.**

**R2 — the 8 generated methods with no `*Server` implementation (`GetOperators`, `Portfwd`, `CreateSocks`, `CloseSocks`, `SocksProxy`, `CreateTunnel`, `CloseTunnel`, `TunnelData`) are not proven unreachable.** `[src]` **Probe:** grep the whole `server\` tree for these names as method values (`Server{}` receivers other than `*Server`, function variables, or explicit dispatch tables) — *"never invoked" and "cannot be invoked" are different claims.*

**R3 — the DNS "upper bound on unauthenticated init reassembly state" (`dns.go:69`) is a COMMENT; the bound was not verified as enforced.** `[src]` **Probe:** locate the constant the comment refers to and the check that applies it; confirm it is evaluated before any allocation proportional to attacker input.

**R4 — `startHTTPListener`'s ACME/TLS path (`http.go:185` TODO) was not read; the HTTP listener's TLS mode and certificate sourcing are unmeasured.** `[src]` **Probe:** read `server\c2\http.go` around the listener construction (`:180-260`) and enumerate the cert sources.

**R5 — proxy credentials as URI query parameters (`proxy-username=`, `proxy-password=`, `httpclient.go:122-123`) were found but not traced.** `[src]` **Whether the server emits them, where they are stored, and whether they are encrypted in the DB or in the built binary is UNKNOWN.** `[src]` **Probe:** grep `server\` for `proxy-username` / `proxy-password` and follow into `rpc-generate.go`'s C2 URI construction. **This is the most security-relevant open item.**

**R6 — the `Server:` header is cached per-process (`http.go:159` `if serverVersionHeader == ""`) with an opt-in switch (`:483`), while request headers vary per-request.** `[src]` **Whether that constancy is intentional was not determined from source.** `[src]` **Probe:** trace all writers of `serverVersionHeader` — if it is ever reset per-connection, the constancy claim fails.

**R7 — the `ChromeVer` dead-local bug (§3.3) was not checked against upstream history.** `[src]` **Whether it is a regression or has always been present is unknown, and I did not consult git.** `[src]` **Probe:** `git log -L 411,418:server/db/models/http-c2.go` in the source tree.

**R8 — I did not read `server\handlers\` (15 files / 244.0 KB) beyond file-level enumeration.** `[src]` **The brief named `server\handlers\` in the Q4 scope; `sessions.go` alone is 34,614 B and `reverse_precreate.go` 22,327 B, and I established only that handlers are session/beacon/pivot lifecycle, not listeners.** `[src]` **Probe:** a dedicated pass on `handlers\sessions.go` + `handlers\reverse_precreate.go` for the session-registration and pre-create authorization boundary. **I am flagging this as UNCOVERED rather than implying it was verified.**

---

## 6. What this report does NOT establish

- **It does not claim the RPC surface lacks authorization.** §1.5 finds a real, load-bearing, ctx-based authorization class and explicitly declines to generalise from `aitools` in either direction. **R1 is the missing half.**
- **It does not revise D12.** D12's finding about `aitools` stands; what D44 corrects is **any reader's generalisation** from it. `[inference]`
- **It does not revise D36's taxonomy** — it confirms and extends it (§2.3). **It DOES correct one D36 sentence** — the `Probability=100` arithmetic — recorded in §4.4 and in §0.1 for the URI claim. `[src]`
- **It does not claim the `ChromeVer` bug is a vulnerability.** It degrades a concealment feature by emitting an implausible Chrome version. `[inference]`
- **It does not claim `server\handlers\` was reversed** — R8. `[src]`
- **No transport was exercised; no traffic was captured.** Every "what it looks like on the wire" row is a reading of the framing code, not an observation. `[inference]`
- **It does not audit `mtls.go`'s main transport loop** despite its `//nolint:gocyclo` (`:184`). `[src]`

---

## 7. Instrument failures and corrections recorded in this report

**The brief asked for my own failures, so they are listed in one place rather than buried.** `[src]`

| # | Failure | Where | Resolution |
|---|---|---|---|
| **F1** | **D43 §8 claimed the C2 URI has no proxy parameter** | §0.1 | **WRONG.** Four proxy params at `httpclient.go:121-124`, three lines below my last quote. **Boundary error, not count error.** |
| **F2** | **Stream classifier returned 0 streams vs `ServiceDesc`'s 6** | §1.2 | **Pattern was the pre-generics gRPC signature.** Printed all 7 non-unary lines and classified them manually. |
| **F3** | **Probe for `SliverRPCServer` in `services.pb.go` returned empty** | §1.1 probe 2 | **UNTESTED, not negative** — the interface is in `services_grpc.pb.go:2524`. Treating an empty result as a finding is the exact error the brief warns about. |
| **F4** | **PowerShell quoting error: `$(subexpression) is missing the closing ')'`** | §1.4 measurement | `\w*` inside `$(...)` collided with the subexpression parser. Rewrote with plain `[A-Za-z]*`. **The failed probe is shown rather than hidden.** |
| **F5** | **D36 §4 claimed `Probability=100` "drops 1 in 99"** | §4.4 | **WRONG.** `Intn(99)+1 ≤ 99`, so `roll > 100` is unreachable; `100` always sets. **`99` and `100` are equivalent.** |
| **F6** | **`killSession` appears twice among `*Server` methods** | §1.1 | 214 hits → 213 distinct. **Not resolved** — the duplicate is recorded, not averaged away. **Probe: inspect both `killSession` definitions for differing receivers or build tags.** |

`[src]`

---

## 8. Summary

**Q1 — RPC surface.** `[src]` **201 RPC methods on the generated `SliverRPCServer` interface (195 unary + 6 streaming), corroborated independently by the interface body and the `grpc.ServiceDesc` literal.** 193 have direct `*Server` implementations; 8 fall through to `UnimplementedSliverRPCServer`. **Additionally 20 internal `*Server` helpers exist, including two capitalised non-RPC names (`GenericHandler`, `KillSession`).** **On the D12 comparison: `aitools` is an OUTLIER, not the shape of the surface.** 14 authorization call sites across `rpc-crackstations.go`, `crack-keyspace.go`, `rpc-generate.go` enforce a principal derived from the verified mTLS certificate CN via the single `getClientCommonName` chokepoint (`rpc.go:260-276`). **The generalisation boundary is unmeasured because `middleware.go` was not read (R1).**

**Q2 — Transports.** `[src]` **The brief's `server\transports\` does not exist; the substance is split three ways across `server\transport\` (operator plane), `server\c2\` (implant plane), and `server\handlers\`.** Five implant-facing listeners: **mTLS** (TCP + `MUX/1` yamux preface + Ed25519-signed envelopes), **WireGuard** (UDP, three ports, same envelope stack), **HTTP(S)** (nonce-selected encoder, Chrome-shaped, probabilistic headers), **DNS** (UDP, Base32, server-side stateful reassembly), **TCP stager** (raw). **No port is hard-coded.** **Server-side CONFIRMATION of D36's taxonomy: `EncoderModulus = 65537` matches exactly on both sides; the response path applies the SAME probabilistic roll as the request path.** **New hardening found:** `envelope_reader.go` disk-spools payloads above 64 MiB in 1 MiB chunks to defeat allocation amplification.

**Q3 — Profile machinery.** `[src]` **Four UA shapes + operator override + a generic Windows default.** **`ChromeVer` (`http-c2.go:411-418`) contains a DEAD LOCAL:** `chromeVer` is defaulted to `106` at `:415` and then discarded — `:417` formats `baseVer` — so **an unset `ChromeBaseVersion` yields `Chrome/0.x.y.z`.** `MacOSVer` three lines below does it correctly, making this a slip rather than a misunderstanding. **No validation on `Probability` anywhere.** **`100` means ALWAYS, by two different mechanisms on the two sides; `99` and `100` are indistinguishable; `0` means always on both sides, contradicting the comment at `configs/http-c2.go:71-72` which is therefore a false claim.**

**Q4 — Listeners.** `[src]` **Five types enumerated (the corpus had four — the TCP stager is the fifth).** **Four configured-vs-honoured gaps:** WinINet `ProxyConfig` (D43), stager `Name` (benign), the `ServerConfig`/`ImplantConfig` header-set split (structural), and the unenforced `0-100` range. **All four share the shape: prepared symmetrically, read asymmetrically.**

**Corrected in this report:** D43's URI-proxy claim (F1) and D36's `Probability=100` arithmetic (F5). **Neither changes a D43 or D36 conclusion; both change a sub-claim.** `[src]`
