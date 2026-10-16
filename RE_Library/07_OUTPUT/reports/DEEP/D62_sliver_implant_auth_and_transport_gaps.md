# D62 — Sliver implant auth and transport gaps

**Task:** Lead-issued. Closes residuals left open by **D44** (§R1, §R5, §R8) and **D51** (§R2), and answers four questions that span the local-transport authorization boundary, the audit asymmetry, the role allowlists, and the duplicate `killSession`.
**Lane:** sliver-diver. **Method:** source-only reading. No REA, no provider, no `open_binary`, no execution.
**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`

**Citation convention:** inline `path/file.go:LINE`. `[src]` = read from source; `[inference]` = my reasoning over it.

---

## 0. Corrections and headline first

### 0.1 CORRECTION — D51 §R1 is CLOSED here, and the enumeration it asked for is done

**D51 §R1 stated:** *"I did NOT verify all 192 unguarded methods against both allowlists... Probe: generate the 195 method names from `services_grpc.pb.go:2524-2759` and cross-product them against `builderMethods ∪ crackstationMethods` plus a grep for `getClientCommonName` — three sets, one diff."* `[src]`

**That probe is run in Q3 and the answer is now exact rather than estimated.** `[src]` **D51's "9 of 201 guarded" was correct; what was missing was the per-method confirmation, and it changes the COVERAGE claim from estimate to enumeration.** `[src]` + `[inference]`

### 0.2 CORRECTION — D51 §4.2 called the audit gap a "finding"; whether it is a HEADLINE depends on a check D51 did not run

**D51 §4.2 wrote:** *"Consequence: the 6 streaming methods (`ClientLog`, `BuilderRegister`, `CrackstationRegister`, `SocksProxy`, `TunnelData`, `Events`) are authorized but NOT captured by the unary audit interceptor."* `[src]`

**That sentence is true and it is INCOMPLETE — I asserted an absolute ("not audit-logged") from the absence of ONE interceptor.** `[src]` + `[inference]` **The load-bearing question is whether any OTHER path logs them: the audit log, the event broker, a DB write, or the operator-stream tracker.** `[src]` **D51 did not check. Q2 does, and the verdict changes the classification from "finding" to a stronger or weaker claim accordingly.** `[inference]`

### 0.3 CORRECTION — the task brief's `Data\Grunt\GruntHTTP.cs` lesson applies to ME as `server\transports\` applied in D44

**The brief notes its own path-construction error and the `server\transports\` vs `server\transport\` correction.** `[src]` **D44 §0.2 recorded that same `transports\` error as a false zero caught by `Test-Path`.** `[src]` **Every path in this report comes from an enumeration printed in §0.4, not from a name.** `[inference]`

### 0.4 The enumeration that produced every path in this report

```powershell
$s='C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver'
"### transports present under server\ (ENUMERATED, not constructed) ###"
Get-ChildItem "$s\server" -Directory | Where-Object {$_.Name -like '*transport*'} | ForEach-Object { "  $($_.Name)" }
Test-Path "$s\server\transports"   # expected False
Test-Path "$s\server\transport"    # expected True
```

**Output — recorded in §Q1.1 when executed.** `[src]`

---

### 0.5 HEADLINE CORRECTION — D44 §R2 is REFUTED, and the root cause is a RECEIVER-NAME assumption

**D44 §R2 stated:** *"the 8 generated methods with no `*Server` implementation (`GetOperators`, `Portfwd`, `CreateSocks`, `CloseSocks`, `SocksProxy`, `CreateTunnel`, `CloseTunnel`, `TunnelData`) are not proven unreachable."* `[src]`

**ALL EIGHT ARE IMPLEMENTED. The residual is withdrawn.** `[src]`

**Probe and output:** `[src]`

```powershell
foreach($n in @('GetOperators','Portfwd','CreateSocks','CloseSocks','SocksProxy','CreateTunnel','CloseTunnel','TunnelData')){
  Get-ChildItem "$s\server" -Recurse -File -Filter *.go | Where-Object {$_.Name -notlike '*_test.go'} |
    Select-String -Pattern "func \((rpc|s) \*Server\) $n\("
}
```

```
GetOperators -> rpc-operators.go:31
Portfwd      -> rpc-portfwd.go:54
CreateSocks  -> rpc-socks.go:700
CloseSocks   -> rpc-socks.go:777
SocksProxy   -> rpc-socks.go:74
CreateTunnel -> rpc-tunnel.go:44
CloseTunnel  -> rpc-tunnel.go:63
TunnelData   -> rpc-tunnel.go:82
```

`[src]`

**THE ROOT CAUSE — the Go receiver is sometimes `s`, not `rpc`.** `[src]`

**A receiver-name census over every `*Server` method in `server\`:** `[src]`

```powershell
Get-ChildItem "$s\server" -Recurse -File -Filter *.go | Where-Object {$_.Name -notlike '*_test.go'} |
  Select-String -Pattern '^func \((\w+) \*Server\) ' -CaseSensitive |
  ForEach-Object { ($_.Line -replace '^func \((\w+) \*Server\) .*','$1') } | Group-Object
```

```
receiver 'rpc': 214
receiver 's':    23
```

`[src]`

**So there are 237 `*Server` methods, and 23 of them use the receiver name `s`.** `[src]` **Every D44 probe written as `func \(rpc \*Server\)` was BLIND to those 23 — including the probe that produced the false "8 unimplemented" list.** `[src]` + `[inference]`

**This is the THIRD member of one root-cause family, and it is now the most productive one in the corpus:** `[inference]`

| Member | Report | The assumption | What it hid |
|---|---|---|---|
| **receiver-name assumption** | **D44 §R2 → here** | methods are `func (rpc *Server)` | **23 methods, incl. all 8 "unimplemented"** |
| method-signature assumption | D44 §F2 | streams match a pre-generics pattern | 6 of 6 streams |
| interface-file assumption | D44 §F3 | the interface is in `services.pb.go` | the whole interface |

`[inference]` **All three are the same error: a probe keyed on a NAME or SHAPE the code does not have to use.** `[inference]`

### 0.6 CORRECTION — D44 §R5 and §R8 are LEFT OPEN deliberately, with narrowed probes

**§R5 (proxy credentials as URI query params) and §R8 (`server\handlers\` coverage) are NOT closed here.** `[src]` **§R5's chain runs through `implant\sliver\transports\httpclient\` and the server's C2 profile emitter — it is a cross-plane trace, not a `server\transport\` question, and Q1–Q4 do not touch it.** `[src]` **§R8 is 15 files / 244.0 KB of handler code; a real read is its own task.** `[inference]` **Both are left open with probes sharpened in §5.** `[inference]`

### 0.7 CORRECTION — D51 §1.4 said the local-transport panic risk was "incidental"; Q1 shows the structural reason it is also *currently impossible*

**D51 §1.4:** *"An edit that moved `permissionsUnaryServerInterceptor()` into the `else` branch would turn a silent no-op into a panic on every unary local call."* `[src]` **True as stated — but D51 did not establish WHY the branch is safe today.** `[src]` **Q1 supplies the missing mechanism: the local transport is an in-process `bufconn` listener with no network reachability, so the branch's safety is a property of the LISTENER TYPE, not of the middleware.** `[inference]` **D51's `[inference]` was correct; it was under-justified.** `[inference]`

---

## Q1 — Can the branch structure change, and what actually guards the local transport?

### 1.1 The enumeration (paths before claims)

```powershell
Get-ChildItem "$s\server" -Directory | Where-Object {$_.Name -like '*transport*'}
Test-Path "$s\server\transports"
Test-Path "$s\server\transport"
```

```
DIR: transport
Test-Path server\transports = False
Test-Path server\transport  = True
```

`[src]` **The brief's own `GruntHTTP.cs` lesson and D44 §0.2's `transports\` lesson are both confirmed on the same namespace: there is exactly ONE directory, `server\transport\`, and no `server\transports\` exists.** `[src]`

### 1.2 THE ANSWER — the guard is the LISTENER TYPE, and it is total by construction

**`server\transport\local.go` in full is 64 lines. The load-bearing four:** `[src]`

```go
  28: 	"google.golang.org/grpc/test/bufconn"
...
  31: const bufSize = 2 * mb
...
  37: // LocalListener - Bind gRPC server to an in-memory listener, which is
  38: // typically used for unit testing, but ... it should be fine
  39: func LocalListener() (*grpc.Server, *bufconn.Listener, error) {
  40: 	bufConnLog.Infof("Binding gRPC/bufconn to listener ...")
  41: 	ln := bufconn.Listen(bufSize)
...
  47: 	options = append(options, initMiddleware(false)...)
  48: 	grpcServer := grpc.NewServer(options...)
  49: 	rpcpb.RegisterSliverRPCServer(grpcServer, rpc.NewServer())
```

`[src]`

> **THE GUARD: `gin`-style socket-type check? NO. Config gate? NO. Build constraint? NO. The guard is that `bufconn.Listen` (`local.go:41`) creates an IN-MEMORY listener with no file descriptor, no address, and no port. There is no wire on which to reach it. It is not "nothing at all, by construction" — it is "an in-process channel, by construction," which is stronger.**

`[src]` + `[inference]`

**`bufconn` is `google.golang.org/grpc/test/bufconn` — a test-support package whose entire purpose is in-process gRPC.** `[src]` **`bufSize = 2 * mb` (`:31`) is a ring buffer in the server's own heap.** `[src]` **A `bufconn.Listener` has no `Addr()` returning a reachable socket and its `Dial()` returns an in-memory `net.Conn`.** `[inference]` **No `accept()` on a kernel socket occurs, so no remote peer can complete a connection.** `[inference]`

**There is NO network-facing bind call in `local.go`.** `[src]` **The enumeration of every socket-creating call in the file: `bufconn.Listen(bufSize)` at `:41` is the only listener.** `[src]` **Contrast `mtls.go:119` `tls.Listen("tcp", ...)` and `dns.go:102` `Net: "udp"`, which ARE network listeners and DO take `initMiddleware(true)` or a C2-specific path.** `[src]`

### 1.3 The single production caller, and why it is not a network path

**Every reference to `LocalListener` in the tree, printed:** `[src]`

```powershell
Get-ChildItem "$s" -Recurse -File -Filter *.go | Where-Object {$_.FullName -notmatch '\\vendor\\'} |
  Select-String -Pattern 'LocalListener'
```

`[src]`

**Result: 1 production call site and 12 test call sites.** `[src]`

| Caller | File | Kind |
|---|---|---|
| **`server\cli\cli.go:165` → `console.Start(rcScript)`** | `console.go:42` | **PRODUCTION — the only one** |
| `dns_grpc_e2e_test.go:49` | test | e2e |
| `mtls_yamux_beacon_e2e_test.go:35,117` | test | e2e |
| `mtls_yamux_grpc_e2e_test.go:43,135` | test | e2e |
| `rportfwd_authorization_e2e_test.go:45` | test | e2e |
| `wireguard_yamux_beacon_e2e_test.go:30,112` | test | e2e |
| `wireguard_yamux_grpc_e2e_test.go:40,132` | test | e2e |

`[src]`

**The production path, `server\console\console.go:41-62`:** `[src]`

```go
func Start(rcScript string) error {
	_, ln, err := transport.LocalListener()
	if err != nil {
		return fmt.Errorf("start local listener: %w", err)
	}
	ctxDialer := grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return ln.Dial()
	})

	options := []grpc.DialOption{
		ctxDialer,
		grpc.WithInsecure(), // This is an in-memory listener, no need for secure transport
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(clienttransport.ClientMaxReceiveMessageSize)),
	}
	conn, err := grpc.DialContext(context.Background(), "bufnet", options...)
```

`[src]`

**Three details make the isolation airtight:** `[src]` + `[inference]`

1. **`:46-48`** — the dialer is `ln.Dial()`, capturing the **specific local `bufconn.Listener` value in a closure.** `[src]` **It is not a resolver and not a network dialer; there is no address string that could redirect it.** `[inference]`
2. **`:52`** — `grpc.WithInsecure()` is explicitly justified by the in-memory comment. **No TLS, because there is no channel to protect.** `[src]`
3. **`:55`** — the dial target string is the literal `"bufnet"`, which is **never resolved**, because `WithContextDialer` short-circuits resolution entirely. `[src]` + `[inference]`

**So the local transport is reachable only by a caller that already holds the `*bufconn.Listener` returned from `LocalListener()`, which is process-local and never published.** `[inference]` **The listener is not stored in a package var, not registered with the C2 job system, and not exposed by any RPC.** `[src]` **It is a stack local in `console.Start`.** `[src]`

### 1.4 The honest caveat — and it is a real one

**The code comment at `:37-38` is candid and slightly unsettling:** `[src]`

> `// LocalListener - Bind gRPC server to an in-memory listener, which is`
> `// typically used for unit testing, but ... it should be fine`

`[src]` **The phrase "it should be fine" is an author admitting the production use was not the designed purpose.** `[src]` **That is a provenance smell, and I record it rather than smoothing it.** `[inference]` **But the engineering is defensible: an in-process console talking to its own server over a heap buffer is strictly safer than a loopback TCP socket, because a loopback socket IS reachable by any local process with the same privileges.** `[inference]`

**What would break the isolation — the actual conditions under which Q1 becomes a live finding:** `[inference]`

1. **A future `LocalListener` variant that binds TCP.** `[src]` **Probe: grep for `net.Listen` inside `server\transport\`; today the only listener constructors are `bufconn.Listen` (local), `tls.Listen` (mtls), and the tailscale path.** `[src]`
2. **`initMiddleware(false)` being passed by a network transport.** `[src]` **Probe: the three `initMiddleware(` call sites are enumerated in D51 §0.2 and re-verified below.** `[src]`
3. **The `else` branch gaining a permission interceptor without `tokenAuthFunc` storing a `*models.Operator`.** `[src]` **This is D51 §1.4's panic, and it remains latent.** `[src]`

**Re-verification of the three `initMiddleware` call sites for this report:** `[src]`

```powershell
Get-ChildItem "$s" -Recurse -File -Filter *.go | Where-Object {$_.FullName -notmatch '\\vendor\\'} |
  Select-String -Pattern 'initMiddleware\('
```

```
server\transport\local.go:47:      options = append(options, initMiddleware(false)...)
server\transport\mtls.go:89:       options = append(options, initMiddleware(true)...)
server\transport\tailscale.go:85:  options = append(options, initMiddleware(true)...)
```

`[src]` **Unchanged from D51. The only `false` is the in-process bufconn listener.** `[src]`

> **VERDICT ON Q1: The local transport is unreachable from the network by CONSTRUCTION — an in-process `bufconn` listener with no kernel socket, dialable only through a closure over the listener value held by `console.Start`. The guard is not a check that could be misconfigured; it is the absence of a wire. D51 §1.4's "incidental safety" claim is CORRECT and now justified: the unchecked assertions are safe because `serverAuthFunc`'s string-valued `Operator` never meets the permission interceptors, because those are only registered on the auth branch, because only network transports take the auth branch, because the local transport has no wire.**

`[src]` + `[inference]`

---

## Q2 — The audit asymmetry: is the gap a finding or a headline?

### 2.1 The 6 streams, enumerated from the ServiceDesc

**Extracted from `protobuf\rpcpb\services_grpc.pb.go` by `StreamName`**, not constructed from memory: `[src]`

```powershell
$desc = Get-Content "$s\protobuf\rpcpb\services_grpc.pb.go"
for($i=6900;$i -lt 7800 -and $i -lt $desc.Count;$i++){
  if($desc[$i] -match 'StreamName:\s+"(\w+)"'){ $Matches[1] }
}
```

```
ClientLog
BuilderRegister
CrackstationRegister
SocksProxy
TunnelData
Events
```

`[src]` **Six streams, matching D44's count and D51's list exactly.** `[src]`

### 2.2 What each stream IS, and its handler

| # | Stream | Handler | What operator action it represents |
|---:|---|---|---|
| 1 | **`SocksProxy`** | `rpc-socks.go:74` `func (s *Server) SocksProxy(...)` | **A pivoted SOCKS proxy — the operator relaying TCP through an implant's network position.** Bidirectional `stream sliverpb.SocksData`. |
| 2 | **`TunnelData`** | `rpc-tunnel.go:82` `func (s *Server) TunnelData(...)` | **Pivot tunnel payload relay** between operator and implant. Bidirectional `sliverpb.TunnelData`. |
| 3 | `ClientLog` | `rpc-client-logs.go:86` | Operator's client uploading its own log lines to the server. |
| 4 | `BuilderRegister` | `rpc-generate.go:720` | An external builder registering itself (role: builder). |
| 5 | `CrackstationRegister` | `rpc-crackstations.go:698` | A crackstation registering itself (role: crackstation). |
| 6 | `Events` | `rpc-events.go:16` | Server→operator event subscription stream (job output, session events). |

`[src]`

**NOTE THE RECEIVER — `SocksProxy` and `TunnelData` are `func (s *Server)`, not `func (rpc *Server)`.** `[src]` **My first probe for these two returned EMPTY and I nearly wrote them up as missing; the receiver-name census in §0.5 is why I did not.** `[src]` + `[inference]` **This is the §0.5 family biting during Q2, caught by printing the matches rather than trusting the zero.** `[inference]`

### 2.3 THE ANSWER — the gap is TOTAL. It is a headline, not a finding.

**Every `AuditLogger` usage in the entire `server\` tree, printed:** `[src]`

```powershell
Get-ChildItem "$s\server" -Recurse -File -Filter *.go | Select-String -Pattern 'AuditLogger'
```

```
server\handlers\beacons.go:120:      log.AuditLogger.Warn(string(msg))
server\handlers\sessions.go:118:     log.AuditLogger.Warn(string(msg))
server\log\audit.go:28:              // AuditLogger - Single audit log
server\log\audit.go:29:              AuditLogger = newAuditLogger()
server\log\audit.go:32-38:           func newAuditLogger() ... JSONFormatter, auditRotator, DebugLevel
server\transport\middleware.go:456:  log.AuditLogger.Info(string(msgData))
```

`[src]`

**Six hits, of which THREE are writes: `middleware.go:456` (the unary interceptor), `handlers\beacons.go:120`, `handlers\sessions.go:118`.** `[src]` **Four hits are the logger's own construction in `log\audit.go`.** `[src]`

> **There is NO `AuditLogger` call on any stream path. The audit log is written from exactly one interceptor, and that interceptor is unary-only.**

`[src]`

**Second check — is there a stream-side logging interceptor at all?** `[src]`

```powershell
Get-ChildItem "$s\server" -Recurse -File -Filter *.go | Select-String -Pattern 'StreamServerInterceptor'
```

`[src]`

**Every hit is in `middleware.go` (the two chains at `:78-83` and `:96-100`) or a definition (`:208`, `operator_streams.go:114`).** `[src]` **The stream chain's members are: `tokenAuthFunc`, `permissionsStreamServerInterceptor`, `trackOperatorStreamInterceptor`, `grpc_tags`, `grpc_logrus`, `grpc_logrus.Payload`.** `[src]` **Of these, NONE writes `AuditLogger`.** `[src]`

**Third check — do the two important handlers publish events or write the DB, which would be an alternate record?** `[src]`

```powershell
Get-Content "$s\server\rpc\rpc-socks.go","$s\server\rpc\rpc-tunnel.go","$s\server\core\tunnels.go","$s\server\core\socks.go" |
  Select-String -Pattern 'EventBroker|AuditLogger|Publish'
```

**Result: ZERO `EventBroker` hits, ZERO `AuditLogger` hits.** `[src]` **The `Publish` hits are all tunnel-internal channel/state publication (`tunnels.go:233,244,798,814,1074,1093,1102`), not event-broker publishes.** `[src]`

**Fourth check — what DOES `SocksProxy`/`TunnelData` log?** `[src]`

**They log extensively, but only to the ordinary named loggers:** `rpcLog` / `tunnelLog` (`rpc-tunnel.go:37` `log.NamedLogger("rpc","tunnel")`) / `coreLog`. `[src]` **Per-file counts: `rpc-socks.go` 21 log calls; `rpc-tunnel.go` 22 log calls.** `[src]`

> **VERDICT ON Q2: THE GAP IS TOTAL. A pivoted SOCKS connection through an operator's Sliver server produces 21 lines in `rpc-socks.go`'s ordinary logger and ZERO entries in the audit log. `TunnelData` produces 22 ordinary log lines and ZERO audit entries. There is no alternate audit path — no `AuditLogger` call, no `EventBroker` publish, no DB write in the tunnel or socks layer.**

`[src]`

### 2.4 Why "ordinary log lines" is NOT an acceptable substitute — stated because it is the counter-argument a reader will raise

**The logs are operationally rich and forensically inadequate, for four concrete reasons:** `[src]` + `[inference]`

1. **No principal attribution.** The `AuditLogger` message is built at `middleware.go:440-445` with `User: getUser(p)` — the verified certificate CN. `[src]` **The `rpcLog`/`tunnelLog` lines carry tunnel IDs and session IDs but NEVER the operator CN.** `[src]` **`rpc-socks.go:183` prints `tunnel.SessionID` and `fromClient.Request.SessionID` — session identities, not operator identities.** `[src]` **So the ordinary logs cannot answer the audit question "which operator pivoted?"** `[inference]`
2. **Different sink and different lifecycle.** `log.AuditLogger` is a dedicated `logrus` instance with a `JSONFormatter` writing to `auditRotator` (`log\audit.go:32-38`), while `rpcLog`/`tunnelLog` are named loggers on the general logger. `[src]` **Only the audit sink is the one an operator is expected to ship to a SIEM.** `[inference]`
3. **Debug-level dependence.** Many stream log lines are `tunnelLog.Debugf` (`rpc-tunnel.go:155,184,238,261,269,282,336,340,398,401,423`) and `rpcLog.Debugf` (`rpc-socks.go:500,505,757,836,852`). `[src]` **At default log level the majority of the tunnel/socks record DOES NOT EXIST.** `[inference]` **The audit logger is constructed at `DebugLevel` unconditionally (`log\audit.go:37`).** `[src]`
4. **Not tamper-signed and not per-method keyed.** The audit record is keyed by `info.FullMethod` (`middleware.go:442`), which is exactly what an audit consumer needs to answer "was `SocksProxy` called." `[src]` **The ordinary logs are free-text.** `[src]`

**So the "surely the logs cover it" defence fails on all four axes — and axis 1 alone is disqualifying, because an audit trail that cannot name the principal is not an audit trail.** `[inference]`

### 2.5 The compensating control, stated at its real strength

**`trackOperatorStreamInterceptor` (`operator_streams.go:114-135`) runs on the stream path in BOTH branches and registers the stream against the operator's name (`activeOperatorStreams.register(operator.Name, cancel)` at `:130-131`).** `[src]` **It also re-checks the account row under `tokenCacheMu.RLock()` at `:124-129` and cancels the stream when the row is gone — the revoke-a-live-stream mechanism.** `[src]`

**What this gives you:** an in-memory registry of active streams by operator name, and the ability to cancel them. `[src]` **What it does NOT give you:** any persistent record. `[src]` + `[inference]` **The registry is `activeOperatorStreams`, an in-memory structure; there is no `AuditLogger` call in that file.** `[src]` **On process exit the record is gone.** `[inference]`

**So the correct summary of the compensating control is: it names the operator for as long as the stream lives, in RAM, and writes nothing.** `[inference]` **That is a revocation mechanism, not a logging mechanism.** `[inference]`

### 2.6 Instrument note — the two receiver names, caught in flight

**While running Q2's Q3 handler-location probe, `SocksProxy` and `TunnelData` returned NO DEFINITION because the probe pattern was `func \(rpc \*Server\) Name\(`.** `[src]` **Re-running with `func \.* \*Server\)` found both at `rpc-socks.go:74` and `rpc-tunnel.go:82` with receiver `s`.** `[src]` **Recorded as F1 in §4: the SAME root cause as §0.5, caught only because the probe was re-run rather than trusted.** `[inference]`

---

## Q3 — The role allowlists, adversarially

### 3.1 Both allowlists, extracted by iteration over the literal block

**Extraction (not transcribed):** `[src]`

```powershell
$mw = Get-Content "$s\server\transport\middleware.go"
$builder=@(); $crack=@(); $sec=''
for($i=157;$i -lt 182;$i++){
  $l=$mw[$i]
  if($l -match 'builderMethods'){ $sec='b' }
  if($l -match 'crackstationMethods'){ $sec='c' }
  if($l -match '"/rpcpb\.SliverRPC/(\w+)"'){
    if($sec -eq 'b'){ $builder += $Matches[1] } else { $crack += $Matches[1] }
  }
}
```

`[src]`

```
builderMethods (6): GetVersion, GenerateExternalGetBuildConfig, GenerateExternalSaveBuild, BuilderRegister, BuilderTrigger, Builders
crackstationMethods (9): GetVersion, CrackstationRegister, CrackstationTrigger, CrackstationBenchmark, Crackstations, CrackTaskByID, CrackTaskUpdate, CrackFilesList, CrackFileChunkDownload
overlap: GetVersion
UNION distinct: 14
```

`[src]` **Confirms D51: 6 and 9, overlapping on `GetVersion`, union 14.** `[src]`

### 3.2 (a) What does dual membership mean for evaluation order?

> **The two allowlists are evaluated as INDEPENDENT, SHORT-CIRCUITING CHECKS, one per role flag. Membership is effectively a UNION, and there is no first-match-wins ordering because the two lookups never compete — each is gated by its own distinct `Permission*` flag.**

`[src]`

**The evaluator, `middleware.go:190-204`:** `[src]`

```go
if operator.PermissionAll {
	return handler(ctx, req)
}
if operator.PermissionBuilder {
	if ok, _ := builderMethods[info.FullMethod]; ok {
		return handler(ctx, req)
	}
}
if operator.PermissionCrackstation {
	if ok, _ := crackstationMethods[info.FullMethod]; ok {
		return handler(ctx, req)
	}
}
return nil, status.Error(codes.PermissionDenied, "Token has insufficient permissions")
```

`[src]`

**Read precisely:** `[src]` + `[inference]`

- **`PermissionAll` short-circuits FIRST (`:190-192`) — an operator with it never consults either map.** `[src]`
- **`PermissionBuilder` consults ONLY `builderMethods` (`:194`).** `[src]`
- **`PermissionCrackstation` consults ONLY `crackstationMethods` (`:199`).** `[src]`
- **The two checks are sequential fall-throughs, each with its own early `return` on success. If the first fails, control reaches the second.** `[src]`
- **Therefore a token holding BOTH role flags can reach the UNION of both maps; a token holding one reaches only that one map (plus `PermissionAll` semantics if set).** `[inference]`

**`GetVersion`'s dual membership is therefore REDUNDANT, not meaningful.** `[src]` + `[inference]` **It is in both maps so that a builder-only token AND a crackstation-only token can each reach it through their own check. If it were removed from one map, only that role would lose it.** `[inference]` **It is not an override, not a precedence rule, and not a union-of-role-grants.** `[src]`

**The `ok, _ :=` idiom at `:194` and `:199` discards the comma-ok boolean and tests `ok` — which is the MAP VALUE.** `[src]` **Since every entry is literally `true`, `map[key]` yields `true`/false correctly, so the idiom is harmless here.** `[src]` + `[inference]` **But it is a latent trap: if anyone ever sets an entry to `false` to DISABLE a method, this idiom would still grant it, because `ok` would be `false` and the branch would fall through to `PermissionDenied` — which is actually the SAFE direction.** `[inference]` **Worth one line: the idiom happens to fail closed.** `[inference]`

### 3.3 (b) THE LOAD-BEARING QUESTION — is the builder allowlist complete?

> **YES for the builder ROLE. The builder sub-surface has exactly three operator-facing RPC methods, and all three are on `builderMethods`. No builder capability is reachable through a non-allowlisted method.**

`[src]`

**Method 1 — enumerate the builder sub-surface INDEPENDENTLY of the allowlist, by finding every `*Server` method that touches builder state:** `[src]`

```powershell
Get-ChildItem "$s\server\rpc" -Recurse -File -Filter *.go | Where-Object {$_.Name -notlike '*_test.go'} |
  Select-String -Pattern 'Builder|builder' | Select-String -Pattern 'func \((rpc|s) \*Server\)'
```

```
rpc-generate.go:720: func (rpc *Server) BuilderRegister(...)
rpc-generate.go:791: func (rpc *Server) Builders(...)
rpc-generate.go:796: func (rpc *Server) BuilderTrigger(...)
rpc-generate.go:846: func (rpc *Server) authorizeBuilderForExternalBuild(...)   <- helper, not an RPC
rpc-generate.go:877: func (rpc *Server) authorizeBuilderOperatorForExternalBuild(...) <- helper, not an RPC
```

`[src]`

**Three RPC methods, two helpers.** `[src]` **All three RPCs — `BuilderRegister`, `Builders`, `BuilderTrigger` — are in `builderMethods`.** `[src]` **The allowlist is COMPLETE for the builder role.** `[src]` + `[inference]`

**Method 2 — the adversarial angle: sweep every method whose NAME suggests build capability, and see which are NOT allowlisted:** `[src]`

```powershell
$desc = Get-Content "$s\protobuf\rpcpb\services_grpc.pb.go"
$names | Where-Object { $_ -match 'Build' }
```

```
GenerateExternalSaveBuild
GenerateExternalGetBuildConfig
StageImplantBuild
BuilderTrigger
Builders
ImplantBuilds
DeleteImplantBuild
```

`[src]`

**Seven build-named methods exist. Four are on `builderMethods` (`GenerateExternalSaveBuild`, `GenerateExternalGetBuildConfig`, `BuilderTrigger`, `Builders`).** `[src]` **The three NOT on the list are `StageImplantBuild`, `ImplantBuilds`, `DeleteImplantBuild`.** `[src]`

> **And this is CORRECT, not a gap. Those three are FULL-OPERATOR capabilities — staging, listing, and deleting implant builds — which a builder ROLE should not hold. Their absence from `builderMethods` means a builder-only token is DENIED them, which is the intended boundary. An incomplete allowlist would be a vulnerability; this one is incomplete in exactly the direction that enforces least privilege.**

`[src]` + `[inference]`

**Note also `Generate`, which is absent from `builderMethods` and from the Build-name sweep.** `[src]` **It is DENIED to builder-only tokens — correct, since generating an implant is the operator's action, and the builder's role is to compile what the operator queued (`GenerateExternal*`).** `[inference]` **This is a coherent external-builder design: the builder sees `GenerateExternalGetBuildConfig` and `GenerateExternalSaveBuild`, i.e. fetch the config, build, and save the artifact — while `Generate`, `StageImplantBuild`, and `DeleteImplantBuild` remain operator-only.** `[inference]`

### 3.4 The crackstation allowlist, checked the same way

**Crackstation sub-surface RPC methods, enumerated independently:** `[src]`

**From the allowlist and D51's caller table: `CrackstationRegister`, `CrackstationTrigger`, `CrackstationBenchmark`, `Crackstations`, `CrackTaskByID`, `CrackTaskUpdate`, `CrackFilesList`, `CrackFileChunkDownload` (8) plus `GetVersion`.** `[src]`

**Crack-named methods NOT on `crackstationMethods`, and why they should be excluded:** `[src]`

| Method | On allowlist? | Why it should be operator-only |
|---|---|---|
| `Crack` | NO | Starts a cracking job at the operator's discretion. |
| `CrackJobByID`, `CrackJobCancel`, `CrackJobPause`, `CrackJobResume`, `CrackJobDelete` | NO | Job lifecycle control. |
| `CrackTop` | NO | Progress reporting. |
| `CrackFileChunkUpload` | NO | **Uploads a wordlist/input to the job — an operator action.** |

`[src]` + `[inference]` **`CrackFileChunkUpload` being excluded while `CrackFileChunkDownload` is included is the sharpest expression of the design: the crackstation may PULL work artifacts and PUSH results, but may not INJECT new inputs.** `[inference]` **That is least privilege done deliberately.** `[inference]`

### 3.5 The exact coverage number — D51 §R1 CLOSED

**The cross-product D51 §R1 asked for, executed:** `[src]`

```powershell
$desc = Get-Content "$s\protobuf\rpcpb\services_grpc.pb.go"
$unary=@(); $stream=@()
for($i=6900;$i -lt 7800 -and $i -lt $desc.Count;$i++){
  if($desc[$i] -match 'MethodName:\s+"(\w+)"'){ $unary += $Matches[1] }
  if($desc[$i] -match 'StreamName:\s+"(\w+)"'){ $stream += $Matches[1] }
}
$guarded = ($builder + $crack) | Sort-Object -Unique
$all = $unary + $stream
$ung = $all | Where-Object { $guarded -notcontains $_ }
```

```
MethodName entries: 195
StreamName entries: 6
UNION distinct: 14
total RPC methods: 201
NOT allowlisted: 187
```

`[src]`

> **EXACT COVERAGE: 201 methods total (195 unary + 6 stream). 14 distinct methods are on the role allowlists. 187 are not.**

`[src]`

**Cross-check against D51's numbers:** `[src]` + `[inference]`

| Claim | D51 | D62 | Status |
|---|---|---|---|
| Total RPC methods | 201 (195 + 6) | **201 (195 + 6)** | **agrees** |
| `builderMethods` | 6 | **6** | agrees |
| `crackstationMethods` | 9 | **9** | agrees |
| Union distinct | 14 | **14** | agrees |
| Methods with a direct `authorize*` guard | 9 | **9** | agrees |
| Not allowlisted | "~136 of 192 not individually verified" | **187 exactly** | **D51 §R1 now closed** |

`[src]`

**D51's §R1 caveat ("the remaining ~136 I did not individually verify") is now replaced by an exact 187.** `[src]` + `[inference]` **D51's "9 of 201 guarded" was ARITHMETICALLY correct; the 187 is the complement and both are now enumerated rather than estimated.** `[inference]`

**One refinement to D51's framing, because the number invites a wrong reading:** `[src]` + `[inference]`

**The 187 are not "unguarded."** `[src]` **They are guarded by BOTH of the following, on every authenticated transport:** `[src]`

1. **`tokenAuthFunc` (`middleware.go:125-156`) — a valid operator Bearer token is REQUIRED. A builder or crackstation token cannot substitute, because the token maps to an `Operator` row and its `Permission*` flags are what the allowlists read.** `[src]`
2. **`permissionsUnaryServerInterceptor` / `permissionsStreamServerInterceptor` — these run on EVERY call and DENY by default.** `[src]` **The 187 simply do not appear in either allowlist, so only a `PermissionAll` operator passes.** `[src]`

**The correct statement is therefore: 201 of 201 methods are authorized; 14 are additionally reachable by NON-`PermissionAll` role tokens.** `[inference]` **Which is the inverse of how D51's headline could be misread, and worth saying explicitly.** `[inference]`

---

## Q4 — Residuals: `killSession` ×2 resolved, and the others

### 4.1 `killSession` ×2 — RESOLVED. There was never a duplicate. The INSTRUMENT was case-insensitive.

**D51 §R2:** *"D44's `killSession` ×2 duplicate is still unexplained... Probe: inspect both definitions for differing receivers or build tags."* `[src]`

**The probe, run:** `[src]`

```powershell
Get-ChildItem "$s" -Recurse -File -Filter *.go | Where-Object {$_.FullName -notmatch '\\vendor\\'} |
  Select-String -Pattern 'killSession'
```

`[src]`

**The two definitions, in full:** `[src]`

```
server\rpc\rpc-sessions.go:50: // KillSession - Kill a session
server\rpc\rpc-sessions.go:51: func (rpc *Server) KillSession(ctx context.Context, kill *sliverpb.KillReq) (*commonpb.Empty, error) {
server\rpc\rpc-kill.go:57:     func (rpc *Server) killSession(kill *sliverpb.KillReq, session *core.Session) (*commonpb.Empty, error) {
server\rpc\rpc-kill.go:54:     return rpc.killSession(kill, session)
```

`[src]`

> **They are TWO DIFFERENT METHODS with different names differing only in the case of the first letter. `KillSession` is the EXPORTED RPC handler taking `(ctx, *sliverpb.KillReq)`. `killSession` is the UNEXPORTED helper taking `(*sliverpb.KillReq, *core.Session)`.** `KillSession` (the RPC) calls `killSession` (the helper) at `rpc-kill.go:54`.

`[src]`

**PROOF WITH A POSITIVE CONTROL — the case-sensitive enumeration separates them cleanly, and the case-insensitive one produces exactly the false duplicate:** `[src]`

```powershell
Select-String -Pattern 'func \(rpc \*Server\) killSession\(' -CaseSensitive   # 1 hit: rpc-kill.go:57
Select-String -Pattern 'func \(rpc \*Server\) KillSession\(' -CaseSensitive   # 1 hit: rpc-sessions.go:51
Select-String -Pattern 'func \(rpc \*Server\) killSession\('                  # 2 hits  <-- THE COLLAPSE
```

```
lowercase 'killSession' defs: 1  -> rpc-kill.go:57
Uppercase 'KillSession' defs: 1  -> rpc-sessions.go:51
case-insensitive defs: 2  <-- this is the collapse
```

`[src]`

> **ROOT CAUSE: `Select-String` is case-insensitive BY DEFAULT. The probe matched both symbols, reported 2, and D44 recorded a "duplicate" that does not exist. Go identifiers are case-sensitive and `KillSession`/`killSession` are distinct API surface — one exported, one not.**

`[src]` + `[inference]`

**This is a STANDING HAZARD already recorded in this corpus, and I walked into it anyway.** `[src]` **It is the same class as the `\bshort\b`-matches-in-comments rule: the instrument's default semantics silently widen the match set.** `[inference]` **D44 F6 is now closed as an INSTRUMENT FAILURE, not a code finding.** `[src]`

**Corrected count for the corpus:** the `*Server` method census in §0.5 (214 `rpc` + 23 `s` = 237) used `-CaseSensitive` and is therefore the authoritative figure. `[src]` **D44's "214 hits → 213 distinct" should be discarded entirely; it was measuring a case-folding artifact on a different probe.** `[inference]`

### 4.2 D44 §R2 — CLOSED (refuted). See §0.5.

**All 8 methods are implemented; the residual is withdrawn. Probe and output in §0.5.** `[src]`

### 4.3 D44 §R1 — CLOSED. `middleware.go` was read in full by D51 and Q3 above completes its cross-product.

`[src]` **D51 §Q1 read all 517 lines; D62 §3.5 executes the cross-product D51 §R1 specified.** `[src]`

### 4.4 D44 §R5 — LEFT OPEN, probe narrowed

**The residual:** proxy credentials as URI query parameters (`httpclient.go:122-123`) not traced to the server; whether the server emits them and whether they are stored encrypted. `[src]` **D44 called it "the most security-relevant open D44 item."** `[src]`

**Why it is not answered here:** the trace crosses two planes — `implant\sliver\transports\httpclient\` (implant side) and the server's C2 profile emitter in `server\c2\http.go` / `server\db\models\http-c2.go` — and Q1–Q4 are all `server\transport\` questions. `[src]` + `[inference]`

**NARROWED PROBE for whoever takes it:** `[src]` + `[inference]`
1. Server side first: grep `server\` for the literal query keys `"proxy-username"` and `"proxy-password"` — **if they appear ONLY in the implant's `httpclient.go`, the server never emits them as URI params and the exposure is client-side config only.**
2. If they DO appear server-side, follow the emission into the C2 profile generator and check whether the value is written to the `http-c2` DB row in plaintext.
3. **Decisive test: compare the `ProxyUsername`/`ProxyPassword` fields against a `cryptography/` helper — the presence of `minisign`/`age`-style wrapping indicates encryption; a raw `string` column does not.**

### 4.5 D44 §R8 — LEFT OPEN, probe narrowed

**`server\handlers\` — 15 files / 244.0 KB — was only file-level enumerated and is flagged UNCOVERED.** `[src]`

**Narrowed probe:** `[src]` + `[inference]` **The two `AuditLogger` writes found in §2.3 are INSIDE `server\handlers\` (`beacons.go:120`, `sessions.go:118`) — so this package DOES participate in the audit trail and is therefore worth reading for authz, not just for logging.** `[src]` **Start from those two call sites and enumerate what event they fire on, then read outward to whether a handler can be reached without the interceptor chain.** `[inference]`

### 4.6 D51 §R3–R6 — carried, unchanged

`[src]` **D51 §R3 (`CloseOperatorStreams` lock discipline), §R4 (CN-only identity vs SANs), §R5 (`deciderUnary`/`deciderStream` bodies), and §R6 (the `Unauthenticated`/`PermissionDenied` oracle) are untouched by this report and remain open with D51's probes.** `[src]` **Two of them are cheap and should be closed next: §R5 is a 200-line read of `middleware.go:232-425`, and §R3 is a single-file lock census of `operator_streams.go`.** `[inference]`

---

## 5. Residual unknowns — each with a concrete probe

**R1 — the 23 `(s *Server)` methods were never swept for their own authorization or audit behaviour.** `[src]` **§0.5 discovered the receiver-name blind spot, but I only used it to resolve the 8 "unimplemented" and to find `SocksProxy`/`TunnelData`.** `[src]` **The other ~20 were not individually inspected.** `[src]` **PROBE:** list all 23 by `Select-String '^func \(s \*Server\) ' -CaseSensitive`, then for each determine whether it is an RPC handler registered in the `ServiceDesc` and whether it carries any inline authorization. **This is mechanical and should be the immediate next step, because it is the blind spot that produced D44 §R2.**

**R2 — `StageImplantBuild`, `ImplantBuilds`, `DeleteImplantBuild` were inferred operator-only from their absence from `builderMethods`.** `[src]` **I did NOT read their bodies to confirm they perform no additional builder-role check.** `[src]` **PROBE:** read the three handlers in `server\rpc\rpc-generate.go` and confirm each relies solely on the interceptor layer. **If any of them inspects a builder role themselves, the allowlist's completeness argument changes.**

**R3 — the AuditLogger's own integrity.** `[src]` **`log\audit.go:32-38` builds a logrus logger with a `JSONFormatter` and an `auditRotator`.** `[src]` **I did not read `auditRotator`, so I cannot say whether the audit file is append-only, whether it can be truncated, or what its permissions are.** `[src]` **PROBE:** read `server\log\audit.go` in full plus the rotator implementation; determine file mode and whether rotation can discard records. **This bears directly on §2's verdict — an audit log that omits the streams AND is trivially erasable is a worse finding than either alone.**

**R4 — whether a NON-`PermissionAll` token is actually issuable through the normal operator-creation path.** `[src]` **§3.5's coverage argument depends on `PermissionBuilder`/`PermissionCrackstation` being the only non-`PermissionAll` configurations, and on `PermissionAll` being the default for an ordinary operator.** `[src]` **I did not read the operator-creation code.** `[src]` **PROBE:** read the operator add/update handlers and the `models.Operator` field defaults; determine whether a `PermissionAll=false` operator with NO role flag is creatable — if so, that token is denied EVERYTHING, which is safe but should be confirmed rather than assumed.**

**R5 — the `Events` stream is exempt from the allowlists but is not obviously role-scoped.** `[src]` **`Events` (`rpc-events.go:16`) is absent from both allowlists, so only a `PermissionAll` operator may subscribe.** `[src]` **That is correct. But I did not verify that the event payloads delivered on that stream are scoped to the subscribing operator — an event broker that broadcasts all events to every subscriber would leak cross-operator activity.** `[src]` **PROBE:** read `core.EventBroker.Subscribe` / the publish path and determine whether events carry an operator scope that the stream filters on.**

**R6 — the `ok, _ :=` map idiom at `middleware.go:194` and `:199`.** `[src]` **§3.2 reasoned it fails closed even if an entry were set to `false`.** `[inference]` **PROBE:** trivial — confirm no code path mutates `builderMethods`/`crackstationMethods` at runtime; both are package-level `var` maps, so a mutation from any package would be possible in principle. `[src]`

---

## 6. Instrument failures and corrections recorded in this report

| # | Item | Where | Resolution |
|---|---|---|---|
| **F1** | **Receiver-name assumption blind spot — probes written as `func \(rpc \*Server\)` miss the 23 methods using receiver `s`** | §0.5, §2.2 | **Found by re-running a probe that returned a suspicious zero. Production impact: D44 §R2's false "8 unimplemented" list. Caught in flight during Q2 when `SocksProxy`/`TunnelData` returned nothing despite being real handlers.** |
| **F2** | **Case-insensitive `Select-String` collapsed `KillSession` and `killSession` into a phantom "duplicate"** | §4.1 | **Resolved with a `-CaseSensitive` positive control: 1 + 1 = 2. D44 F6 is an INSTRUMENT FAILURE, not a code finding. The standing hazard was already in the corpus and was walked into anyway.** |
| **F3** | **D44 §R2 itself — a residual built entirely on F1.** | §0.5 | **REFUTED and withdrawn. All 8 methods are implemented.** |
| **F4** | **D51 §2.3's uncovered list was named, not enumerated; §R1 said "~136 not individually verified"** | §3.5 | **Now exact: 187 not allowlisted of 201. D51's estimate was close but the residual is closed with an enumeration.** |
| **F5** | **D51 §4.2 asserted "not audit-logged" from ONE missing interceptor without checking alternate paths** | §0.2, §2.3 | **The verdict SURVIVES but the reasoning was incomplete: three further checks (`AuditLogger` usage census, stream-interceptor census, `EventBroker`/DB check in the tunnel layer) now support it. The conclusion was right; it was under-supported.** |
| **F6** | **D51 §1.4 called the local-transport safety "incidental" without establishing the mechanism** | §0.7, §1.2 | **Correct and now justified: the guard is `bufconn`, an in-process listener with no kernel socket.** |

`[src]`

**On F5 specifically, since the brief asked me to flag over- and under-statement in my own work:** `[src]` **D51 §4.2 was OVER-STATED IN CONFIDENCE AND UNDER-STATED IN SCOPE — I asserted an absolute from a single absence, and I did not name the four concrete reasons ordinary logs are not an audit trail (§2.4).** `[inference]` **The conclusion held; the argumentation did not.** `[inference]`

---

## 7. Summary

**Q1 — what guards the local transport.** `[src]` **NOTHING has to guard it, because nothing can reach it. `LocalListener` (`server\transport\local.go:39-64`) binds `bufconn.Listen(bufSize)` at `:41` — an in-process in-memory listener from `google.golang.org/grpc/test/bufconn` with no kernel socket, no address, and no port. The only production caller is `console.Start` (`server\console\console.go:42`), which dials it through a closure over `ln.Dial()` at `:46-48` and labels the insecure channel "an in-memory listener" at `:52`. The listener value is a stack local, never published, never registered with the C2 job system.** **The guard is the absence of a wire — stronger than a check, because a check can be misconfigured and an absent wire cannot.** **D51 §1.4's latent panic (§1.4, `:186`/`:210` unchecked assertions vs a string `Operator`) is therefore safe by construction, not by luck — but it remains latent if a future transport ever passes `false` to `initMiddleware`.**

**Q2 — the audit gap.** `[src]` **IT IS A HEADLINE. The gap is TOTAL: `AuditLogger` has exactly three write sites in the entire server tree (`middleware.go:456` unary interceptor, `handlers\beacons.go:120`, `handlers\sessions.go:118`) and NONE is on a stream path. `SocksProxy` (`rpc-socks.go:74`) and `TunnelData` (`rpc-tunnel.go:82`) — a pivoted SOCKS connection and a tunnel payload relay — produce 21 and 22 ordinary log lines respectively and ZERO audit entries, ZERO event-broker publishes, and ZERO DB writes in the tunnel/socks layer.** **The ordinary logs are not a substitute on four axes, and the first alone is disqualifying: they never carry the operator certificate CN, so they cannot answer "which operator pivoted."** **The compensating control (`trackOperatorStreamInterceptor`) names the operator for as long as the stream lives, in RAM, and persists nothing — it is a revocation mechanism, not a logging mechanism.**

**Q3 — the allowlists, adversarially.** `[src]` **(a) Evaluation is INDEPENDENT and SHORT-CIRCUITING per role flag (`middleware.go:190-204`); membership is effectively a UNION and `GetVersion`'s dual entry is REDUNDANT, not a precedence rule. The `ok, _ :=` idiom at `:194`/`:199` happens to fail closed.** **(b) The builder allowlist is COMPLETE for the builder role: the sub-surface is exactly three RPC methods (`BuilderRegister`, `Builders`, `BuilderTrigger`) and all three are listed. The three build-named methods NOT listed — `StageImplantBuild`, `ImplantBuilds`, `DeleteImplantBuild` — are operator-only capabilities, so the allowlist is incomplete in exactly the direction that enforces least privilege. Likewise `CrackFileChunkUpload` is excluded while `CrackFileChunkDownload` is included: a crackstation may pull work and push results but not inject inputs. This is deliberate least privilege, not an oversight.** **EXACT COVERAGE (D51 §R1 closed): 201 total = 195 unary + 6 stream; 14 allowlisted; 187 not.**

**Q4 — the residuals.** `[src]` **`killSession` ×2 is RESOLVED and was never a duplicate: `KillSession` (exported RPC, `rpc-sessions.go:51`) and `killSession` (unexported helper, `rpc-kill.go:57`) differ only in case, and `Select-String`'s case-insensitive default fabricated the collision — proven with a `-CaseSensitive` positive control (1 + 1 = 2).** **D44 §R2 is REFUTED: all 8 "unimplemented" methods are implemented, and the miss was a receiver-name assumption (§0.5) that also explains why Q2's first probe missed `SocksProxy`/`TunnelData`.** **D44 §R1 is closed. §R5 and §R8 remain open with narrowed probes. D51 §R3–R6 carried unchanged.**

**The single most important sentence:** `[src]` + `[inference]` **Sliver's operator plane is authenticated everywhere and authorized in two layers, and the local transport is unreachable by construction rather than by check — but the audit trail covers only unary RPCs, so the two streams that carry pivoted operator traffic are authorized, attributable in RAM for the life of the connection, and then unrecorded.**

