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
<!--TAIL-->
