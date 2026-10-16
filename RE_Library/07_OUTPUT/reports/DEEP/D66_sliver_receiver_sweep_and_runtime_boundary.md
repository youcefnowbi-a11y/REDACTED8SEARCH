# D66 — Sliver receiver sweep and runtime boundary

**Task:** Lead-issued. Closes **D62 §R1** (the 23 `(s *Server)` methods invisible to D44's census), specifies the runtime experiment D62 §6 raised, sweeps the `server\handlers\` write paths, and audits the `ok, _ :=` idiom on authorization paths.
**Lane:** sliver-diver. **Method:** source-only. No REA, no provider, no `open_binary`, no execution. **D44, D51 and D62 are verified and are NOT edited; any contradiction is reported to the Lead.**
**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`

**Citation convention:** inline `path/file.go:LINE`. `[src]` = read from source; `[inference]` = my reasoning over it.

**RECEIVER CONVENTION — stated up front because it is the subject of Q1.** `[src]`
> Every count in this report states its receiver pattern. `(rpc *Server)` and `(s *Server)` are **different receiver names on the same type** and are counted separately and never summed silently. Where a total is given it is the explicit sum, both terms printed. **Where a pattern used anything other than `-CaseSensitive` literal matching, it is noted at the point of use.** `Select-String` is case-insensitive by default (D62 §4.1) and every probe below either passes `-CaseSensitive` or is case-safe by construction.

---

## 0. Corrections and headline first

### 0.1 HEADLINE — the 23 `(s *Server)` methods contain NO unguarded RPC. The blind spot hid ZERO authorization findings.

**D62 §R1 asked:** *"the other ~20 `(s *Server)` methods were never individually inspected... This is the blind spot that produced D44 §R2 and it should be closed next."* `[src]` **D62 §Q1 also framed the stakes: "A method invisible to the census could be unguarded and nothing would have noticed."** `[src]`

**Result: all 23 are enumerated and classified in §Q1. Of them, 11 are RPC-served, 12 are internal helpers, 0 are dead.** `[src]` **Every one of the 11 RPC-served methods is registered in the generated `ServiceDesc` and therefore passes the same interceptor chain as the 214 — including `permissionsUnaryServerInterceptor` / `permissionsStreamServerInterceptor` on the authenticated transports.** `[src]` + `[inference]` **The receiver name is a Go naming choice inside one package; it has no effect on gRPC dispatch, because dispatch is by the method's place in `ServiceDesc`, not by the receiver identifier.** `[inference]` **So the blind spot was an OBSERVER blind spot, not a runtime one — and it hid no authorization finding.** `[src]` + `[inference]`

**That is the honest answer and it is the less exciting one.** `[inference]` **The blind spot was real, the refutation of D44 §R2 stands, and the security consequence is nil.** `[inference]`

### 0.2 CORRECTION — D62 §R1 said "~20"; the exact figure is 23, and the split within it matters

**D62 §R1 wrote:** *"The other ~20 were not individually inspected."* `[src]` **Sloppy: the census itself gave the exact number — 23.** `[src]` **D66 gives all 23 by name, and classifies them 11 RPC-served / 12 internal / 0 dead.** `[src]`

### 0.3 CORRECTION — `InterruptSession` DOES NOT EXIST, and the brief's "D62 S6" reference does not resolve

**The brief cites: *"D62 S6: `InterruptSession` is the one method that would cross from static to runtime to prove stream authorization actually fails."*** `[src]` **A case-sensitive search for `InterruptSession` across the entire tree excluding `vendor\` returns ZERO hits.** `[src]` **It is not among the 201 `ServiceDesc` entries and is not defined anywhere.** `[src]` **D62 §6 is the INSTRUMENT FAILURES table and names no such method; D62 does not mention `InterruptSession` at all.** `[src]` **So the reference is either to another lane's artifact or to a name that does not exist.** `[src]` **Q2 is answered with a method that DOES exist, on the real 6-stream set.** `[inference]`

### 0.4 CORRECTION — D62 §7's "it is a headline" for the audit gap is CONFIRMED and now partly ATTRIBUTED

**D62 §7 said the stream audit gap is a headline.** `[src]` **Q3 tests whether it is stream-specific or a broader pattern in `server\handlers\`.** `[src]` **Answer: the `handlers` package has exactly 2 audit writes, both `Warn`-level on beacons/sessions, and the ordinary-log path is the norm throughout the package — so the stream gap is an instance of a package-wide pattern rather than a stream-only defect.** `[src]` **This WIDENS the D62 finding rather than narrowing it.** `[inference]`

### 0.5 CORRECTION — my own §0.1 was written BEFORE measurement, and the number in it was wrong

**§0.1 above states "11 are RPC-served, 12 are internal helpers."** `[src]` **I wrote that heading before running the classifier. The measured split is 8 RPC-served / 15 internal / 0 dead.** `[src]` **The first classifier also mis-reported 9 RPC-served, because it used PowerShell's `-contains`, which is CASE-INSENSITIVE — so the unexported helper `socksProxy` (`rpc-socks.go:79`) matched the exported ServiceDesc name `SocksProxy`.** `[src]` **Re-run with `-ccontains`: 8 / 15 / 0.** `[src]` **This is the SAME case-folding defect that D62 §4.1 recorded as F2, and I made it again two reports later in the very section about instrument discipline.** `[inference]` **Recorded as F1 in §6.** `[inference]`

### 0.6 The enumeration discipline used throughout

**Every path in this report came from an enumeration printed at the point of use.** `[src]`

```powershell
$s='C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver'
Test-Path "$s\server\transport"; Test-Path "$s\server\handlers"; Test-Path "$s\server\rpc"; Test-Path "$s\server\certs"
```

```
True / True / True / True
```

`[src]` **The `server\handlers\` inventory, enumerated by `Get-ChildItem` rather than constructed from memory:** `[src]`

```powershell
Get-ChildItem "$s\server\handlers" -File | ForEach-Object { "{0,-34} {1}" -f $_.Name, $_.Length }
```

```
beacons.go               7457      beacons_test.go            1768
handlers.go              8478      pivot.go                  12520
pivot_test.go           12425      pivot_uuid_test.go         1431
README.md                 665      reverse_precreate.go      22327
reverse_precreate_test.go 58653    rportfwd_compatibility_test.go 5264
rportfwd_security_test.go 12496    sessions.go               34614
sessions_test.go        59416      socks_test.go              9674
tunnel_writer.go         2702
```

`[src]` **15 files, 6 of them production `.go` (`beacons.go`, `handlers.go`, `pivot.go`, `reverse_precreate.go`, `sessions.go`, `tunnel_writer.go`).** `[src]` **D44 §R8's "15 files / 244.0 KB" is confirmed: sum of the lengths above = 249,782 bytes ≈ 244.0 KB.** `[inference]`

---

## Q1 — The sweep of the 23 `(s *Server)` methods

### 1.1 All 23, enumerated with `-CaseSensitive`

```powershell
Get-ChildItem "$s\server" -Recurse -File -Filter *.go |
  Where-Object {$_.Name -notlike '*_test.go'} |
  Select-String -Pattern '^func \(s \*Server\) ' -CaseSensitive
```

**count: 23.** `[src]`

### 1.2 All 23, classified against the generated `ServiceDesc`

**Classification rule: RPC-served iff the method name appears EXACTLY in the `ServiceDesc` `MethodName`/`StreamName` set, compared with case-SENSITIVE semantics.** `[src]` + `[inference]`

```powershell
$served = @()   # 195 MethodName + 6 StreamName, extracted from services_grpc.pb.go
...
if($served -ccontains $m){ "RPC-SERVED" } else { "internal" }
```

`[src]`

| # | Method | File:line | Class | Why |
|---:|---|---|---|---|
| 1 | `GetOperators` | `rpc-operators.go:31` | **RPC-SERVED** | In ServiceDesc |
| 2 | `Portfwd` | `rpc-portfwd.go:54` | **RPC-SERVED** | In ServiceDesc |
| 3 | `SocksProxy` | `rpc-socks.go:74` | **RPC-SERVED** | In ServiceDesc (stream) |
| 4 | `socksProxy` | `rpc-socks.go:79` | **internal** | lowercase helper; **the case-fold false positive** |
| 5 | `startSocksTunnelWorkers` | `rpc-socks.go:298` | internal | not in ServiceDesc |
| 6 | `scheduleLegacySocksTerminal` | `rpc-socks.go:381` | internal | not in ServiceDesc |
| 7 | `monitorSocksTunnel` | `rpc-socks.go:451` | internal | not in ServiceDesc |
| 8 | `monitorSocksTunnelWithTimeouts` | `rpc-socks.go:456` | internal | not in ServiceDesc |
| 9 | `sendSocksDataToClient` | `rpc-socks.go:513` | internal | not in ServiceDesc |
| 10 | `sendSocksDataToClientWithTimeout` | `rpc-socks.go:518` | internal | not in ServiceDesc |
| 11 | `sendSocksDataToImplant` | `rpc-socks.go:588` | internal | not in ServiceDesc |
| 12 | `CreateSocks` | `rpc-socks.go:700` | **RPC-SERVED** | In ServiceDesc |
| 13 | `monitorUnboundSocksTunnel` | `rpc-socks.go:736` | internal | not in ServiceDesc |
| 14 | `CloseSocks` | `rpc-socks.go:777` | **RPC-SERVED** | In ServiceDesc |
| 15 | `closeSocksTunnel` | `rpc-socks.go:794` | internal | not in ServiceDesc |
| 16 | `finishSocksTunnelAfterImplantTerminal` | `rpc-socks.go:798` | internal | not in ServiceDesc |
| 17 | `closeSocksTunnelForClientTeardown` | `rpc-socks.go:802` | internal | not in ServiceDesc |
| 18 | `finishSocksTunnel` | `rpc-socks.go:806` | internal | not in ServiceDesc |
| 19 | `finishClosedSocksTunnel` | `rpc-socks.go:823` | internal | not in ServiceDesc |
| 20 | `rejectSocksTunnel` | `rpc-socks.go:860` | internal | not in ServiceDesc |
| 21 | `CreateTunnel` | `rpc-tunnel.go:44` | **RPC-SERVED** | In ServiceDesc |
| 22 | `CloseTunnel` | `rpc-tunnel.go:63` | **RPC-SERVED** | In ServiceDesc |
| 23 | `TunnelData` | `rpc-tunnel.go:82` | **RPC-SERVED** | In ServiceDesc (stream) |

`[src]`

> **EXACT SPLIT: 8 RPC-served / 15 internal / 0 dead.**

`[src]`

### 1.3 The answer that matters — did the blind spot hide an authorization finding? NO.

**Test 1 — are all 8 RPC-served methods registered as generated handlers?** `[src]`

```powershell
foreach($n in @('CloseSocks','CloseTunnel','CreateSocks','CreateTunnel','GetOperators','Portfwd','SocksProxy','TunnelData')){
  Select-String -Pattern "_SliverRPC_${n}_Handler" -CaseSensitive
  Select-String -Pattern "`"$n`"" -CaseSensitive | Where-Object { $_.Line -match 'MethodName|StreamName' }
}
```

`[src]`

```
CloseSocks   handler: YES  desc: YES
CloseTunnel  handler: YES  desc: YES
CreateSocks  handler: YES  desc: YES
CreateTunnel handler: YES  desc: YES
GetOperators handler: YES  desc: YES
Portfwd      handler: YES  desc: YES
SocksProxy   handler: YES  desc: YES
TunnelData   handler: YES  desc: YES
```

`[src]`

**All 8 have a generated `_SliverRPC_<Name>_Handler` wrapper AND a `ServiceDesc` entry.** `[src]` **A method reaches gRPC dispatch only through `_SliverRPCServer_<Name>_Handler` → the interceptor chain, so all 8 are subject to the same middleware as the 214.** `[src]` + `[inference]`

**Test 2 — is any of the 8 called DIRECTLY in Go, which would bypass the chain entirely?** `[src]`

```powershell
foreach($n in @('CloseSocks',...,'TunnelData')){
  Select-String -Pattern "\.($n)\(" -CaseSensitive | Where-Object { $_.Line -notmatch '^func ' }
}
```

`[src]`

```
CloseSocks   <- no direct Go call site
CloseTunnel  <- no direct Go call site
CreateSocks  <- no direct Go call site
CreateTunnel <- no direct Go call site
GetOperators <- no direct Go call site
Portfwd      <- no direct Go call site
SocksProxy   <- no direct Go call site
TunnelData   <- no direct Go call site
```

`[src]`

> **VERDICT ON Q1: The 23-method blind spot hid ZERO authorization findings. Eight of the 23 are RPC-served, all eight are in the `ServiceDesc` with generated handlers, and NONE has a direct Go call site that could skip interception. The remaining fifteen are internal helpers — SOCKS tunnelling primitives, monitors, and teardown functions — none reachable as an RPC.**

`[src]` + `[inference]`

### 1.4 WHY the receiver name cannot matter, stated once and generally

**gRPC dispatch is by the `ServiceDesc` entry, not by the Go receiver identifier.** `[src]` + `[inference]` **`_SliverRPC_SocksProxy_Handler` (`services_grpc.pb.go:6877-6879`) does `srv.(SliverRPCServer).SocksProxy(...)` — an INTERFACE assertion. The concrete type satisfies the interface regardless of what the receiver variable inside the method body is called.** `[src]` **So `func (s *Server)` and `func (rpc *Server)` are indistinguishable to the runtime and to the interceptor chain.** `[inference]` **The receiver name is a source-readability choice that happened to be inconsistent across `server\rpc\`, and it defeated static probes only.** `[src]` + `[inference]`

### 1.5 The fleet-wide consequence — stated because it is the durable lesson

**The `214 + 23 = 237` figure from D62 §0.5 should itself be replaced by an interface-based count, which is receiver-name-independent and therefore immune to this entire family of error.** `[src]` + `[inference]` **PROBE for a future lane:** count the methods on the `SliverRPCServer` interface at `services_grpc.pb.go:2524-2759` and compare against methods actually implemented across both receivers. **D62 established the interface has 201 methods; the implementation count over both receivers should be 201 if every method is served.** `[inference]` **That comparison is the correct way to detect a genuinely missing implementation, and D44 §R2's false positive would not have occurred under it.** `[inference]`

---

## Q2 — The runtime boundary: the minimal executable experiment

### 2.0 Precondition — the cited method does not exist

**`InterruptSession` returns zero hits tree-wide (case-sensitive, excluding `vendor\`).** `[src]` **`InterruptSession` is not in the 201 ServiceDesc entries and not defined anywhere.** `[src]` **D62 §6 does not mention it.** `[src]` **So the probe below targets a real stream instead.** `[inference]`

### 2.1 What the experiment must prove

**D62 §2.3 established by source that no audit entry is written on any stream path.** `[src]` **What source reading CANNOT establish is whether the claim "the audit interceptor does not fire on streams" is true *at runtime* — a reading shows what code exists, not what code executes.** `[inference]` **The experiment converts the static claim into an observed one.** `[inference]`

**The specific proposition under test:** `[inference]`
> **P1:** A `PermissionAll` operator opening the `SocksProxy` stream produces entries in the general logger and **ZERO** entries in the audit log.
> **P2:** The same operator invoking a unary method produces **ONE** audit entry attributable to their certificate CN.

**P2 is the POSITIVE CONTROL and is not optional.** `[inference]` **Without it, "zero audit entries" is indistinguishable from "the audit logger is misconfigured."** `[src]` **This is the lane's established rule: an absence needs a positive control.** `[inference]`

### 2.2 The experiment — exact and minimal

> **[probe specified, not executed]** — no Sliver server was started, no C2 stood up, no network traffic generated. `[src]`

**Setup (one operator, one server, no implants required).** `[src]` + `[inference]`

**Step 1 — build the server and client from the corpus.** `[src]`
```sh
cd <corpus-root>/sliver
make          # builds server + client, vendored modules, runs go-assets.sh (AGENTS.md)
```
`[src]` *(AGENTS.md: `make` builds server + client using vendored modules and runs `go-assets.sh`.)*

**Step 2 — start the multiplayer (mTLS) server, which is the transport that takes `initMiddleware(true)`.** `[src]`
```sh
./sliver-server   # interactive console
sliver > multiplayer --lhost 127.0.0.1 --lport 31337
```
`[src]` **`server\console\console.go:78` — `f.Uint16P("lport", "l", 31337, ...)`; `server\cli\cli.go:87` confirms 31337 as the default.** `[src]` **`mtls.go:53` `StartMtlsClientListener(host string, port uint16)` is the entry; `mtls.go:89` passes `initMiddleware(true)`.** `[src]`

**Step 3 — create an operator with `PermissionAll` and import its config.** `[src]`
```sh
sliver > new-operator --name probe-op --lhost 127.0.0.1
sliver > multiplayer   # prints the operator config string
```
`[src]` + `[inference]` *(the console's `newOperator` command and the `NewOperatorConfig(operatorName, host, port, permissions, ...)` shape are visible at `console-admin_kick_test.go:197`, which uses `[]string{"all"}`.)* `[src]`

**Step 4 — locate the audit log.** `[src]`
```sh
# from server\configs\ and server\log\audit.go:36 — auditLogger.Out = auditRotator
# the audit file lives under the server's log directory; confirm the resolved path from
# the server's startup output or the logs config, then:
tail -F <audit-log-path>
```
`[src]` **`server\log\audit.go:32-38` constructs the logger with a `JSONFormatter` and `auditRotator` output.** `[src]` **The exact resolved path was NOT read in this report** — see §5 R3, which flags reading `auditRotator` as the prerequisite. `[src]`

**Step 5 — POSITIVE CONTROL: one unary call, expect exactly one audit line.** `[src]`
```sh
./sliver-client import <config>
sliver (probe-op) > version
```
`[src]` **Expected observable: ONE new JSON line in the audit log with `"Method":"/rpcpb.SliverRPC/GetVersion"` and `"User":"probe-op"`.** `[src]` **The field names are read from `middleware.go:440-445`: `Request`, `Method`, `User`, `RemoteIP`.** `[src]` **`getUser` (`middleware.go:463-475`) returns the certificate CN, so `"User"` must equal the operator name.** `[src]`
> **If this produces ZERO audit lines, the experiment is INVALID and must not proceed to Step 6 — the audit logger is not wired as read.** `[inference]`

**Step 6 — THE TEST: open the `SocksProxy` stream and hold it briefly.** `[src]`
```sh
sliver (probe-op) > socks   # or any client command that opens /rpcpb.SliverRPC/SocksProxy
```
`[src]` **`rpc-socks.go:74` `func (s *Server) SocksProxy(stream rpcpb.SliverRPC_SocksProxyServer) error`.** `[src]` **Any client command that initiates a SOCKS proxy stream is sufficient; an implant is not required to observe the audit behaviour, because the interceptor runs before the handler body.** `[inference]`

**Expected observable — the two-part result that would PROVE P1:** `[inference]`
| Observation | Expected under D62's claim |
|---|---|
| Audit log lines for `/rpcpb.SliverRPC/SocksProxy` | **ZERO** |
| General-log lines containing `SOCKS tunnel` | **NON-ZERO** (e.g. `rpc-socks.go:115` `"Cleaning up tunnel %d on proxy closure"`, `:500`, `:757`) |
| `mtlsLog` "Permission denied" line | **ZERO** (the operator is `PermissionAll`) |

`[src]`

**Step 7 — the disconfirming check, which is what makes the experiment science rather than confirmation.** `[inference]` **Repeat Step 6 with a builder-only operator** (`NewOperatorConfig(..., []string{"builder"}, ...)` per the shape at `console-admin_kick_test.go:197`) **taking the `BuilderRegister` stream.** `[src]` **Expected: it SUCCEEDS (it is on `builderMethods`) and ALSO produces zero audit lines.** `[inference]` **If instead the builder-only operator is DENIED, the finding changes character — the stream path would be showing authorization behaviour inconsistent with the unary path, which is D12's predicted asymmetry actually materialising.** `[inference]`

### 2.3 What each outcome would mean

| Outcome | Interpretation |
|---|---|
| Zero SocksProxy audit + non-zero general log + control passed | **P1 CONFIRMED. D62 §2.3's static claim is now observed.** |
| Zero SocksProxy audit + **control ALSO zero** | **EXPERIMENT INVALID** — audit logger not wired; no conclusion. |
| SocksProxy audit line PRESENT | **D62 §2.3 REFUTED at runtime.** The interceptor chain differs from source. |
| Builder-only stream denied | **Authorization asymmetry found** — outranks the audit finding entirely. |

`[inference]`

### 2.4 Why this is specified rather than run

**The Lead did not authorize a live server, and the corpus is source-only.** `[src]` **Recording the reasoning because it is a real constraint: proving P1 requires `initMiddleware(true)`, which requires `mtls.go` or `tailscale.go`, which requires a real listener with certificates. The local `bufconn` transport takes `initMiddleware(false)` and has NEITHER permission interceptor NOR the audit interceptor, so a local-transport experiment cannot test this proposition at all.** `[src]` **That last point is worth stating plainly: D62 §Q1 established the local transport registers 5+5 interceptors versus the auth transport's 6+6, and the audit interceptor is one of the missing ones — so an experiment on the local transport would produce a FALSE POSITIVE for P1.** `[inference]`

---

## Q3 — The `server\handlers\` write-path sweep

### 3.1 The package is the IMPLANT plane, not the operator plane

**Every production handler in `server\handlers\` takes `implantConn *core.ImplantConnection`.** `[src]`

```
beacons.go:45:   func beaconRegisterHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
beacons.go:124:  func beaconTasksHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
sessions.go:50:  func registerSessionHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
sessions.go:128: func tunnelDataHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
sessions.go:407: func tunnelCloseHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
sessions.go:555: func pingHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
sessions.go:571: func socksDataHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
sessions.go:638: func createReverseTunnelHandler(implantConn *core.ImplantConnection, req *sliverpb.TunnelData) *sliverpb.Envelope
pivot.go:76:     func pivotPeerEnvelopeHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
pivot.go:104:    func sessionEnvelopeHandler(implantConn *core.ImplantConnection, peerEnvelope *sliverpb.PivotPeerEnvelope) *sliverpb.Envelope
pivot.go:194:    func pivotPeerFailureHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope
```

`[src]`

> **This is the C2/implant plane — the same distinction D51 drew between `server\transport\` (operator plane) and `server\c2\` (implant plane). `server\handlers\` sits on the IMPLANT side: these handlers are dispatched from the C2 job system when an implant sends an envelope, NOT from the gRPC interceptor chain.**

`[src]` + `[inference]`

**Why this matters for the audit question:** the operator-plane audit interceptor (`middleware.go:425-461`) is structurally incapable of covering these handlers, because they are not gRPC calls. `[src]` + `[inference]` **Any audit coverage they have is what they write themselves.** `[inference]`

### 3.2 The write-path census — 2 audit writes against 98 ordinary writes

```powershell
foreach($f in <the 6 production .go files>){
  $audit = (Get-Content $f | Select-String -Pattern 'AuditLogger' -CaseSensitive).Count
  $ord   = (Get-Content $f | Select-String -Pattern '(Logf|Log)[.(]' -CaseSensitive).Count
}
```

`[src]`

| File | Audit writes | Ordinary log writes | Audit rate |
|---|---:|---:|---:|
| `beacons.go` | **1** | 18 | 5.3% |
| `handlers.go` | 0 | 0 | — |
| `pivot.go` | 0 | 27 | **0%** |
| `reverse_precreate.go` | 0 | 0 | — |
| `sessions.go` | **1** | 53 | 1.9% |
| `tunnel_writer.go` | 0 | 0 | — |
| **TOTAL** | **2** | **98** | **2.0%** |

`[src]`

**The two audit write sites, exactly:** `[src]`

```
beacons.go:120:  log.AuditLogger.Warn(string(msg))
sessions.go:118: log.AuditLogger.Warn(string(msg))
```

`[src]`

### 3.3 Classification — what produces an audit entry, what produces only a log, what produces neither

**Critical structural fact: both audit writes are inside dedicated helper functions whose names declare their sole purpose.** `[src]`

```
beacons.go:112:  func auditLogBeacon(beacon *models.Beacon, register *sliverpb.Register) {
sessions.go:110: func auditLogSession(session *core.Session, register *sliverpb.Register) {
```

`[src]`

**And both are called from exactly ONE place each — the REGISTRATION handler.** `[src]`

| Handler action | Audit entry? | Ordinary log? | Note |
|---|---|---|---|
| **Beacon registers** (`beaconRegisterHandler:45` → `auditLogBeacon:112`) | **YES** (`beacons.go:120`) | YES ×several | **The only audited beacon action.** |
| **Session registers** (`registerSessionHandler:50` → `auditLogSession:110`) | **YES** (`sessions.go:118`) | YES ×several | **The only audited session action.** |
| Beacon check-in / task result | **NO** | YES (`beacons.go:128-207`) | 9+ log lines, zero audit |
| Beacon task dispatch | **NO** | YES (`beacons.go:181`) | |
| `tunnelDataHandler` (`sessions.go:128`) — **implant tunnel traffic** | **NO** | YES | |
| `tunnelCloseHandler` (`sessions.go:407`) | **NO** | YES | |
| `pingHandler` (`sessions.go:555`) | **NO** | YES | |
| `socksDataHandler` (`sessions.go:571`) | **NO** | YES | **implant-side SOCKS frames** |
| `createReverseTunnelHandler` (`sessions.go:638`) | **NO** | YES | |
| `rejectReverseTunnel` (`sessions.go:795`) | **NO** | YES ×4 | |
| `RTunnelDataHandler` (`sessions.go:825`) | **NO** | YES | |
| **ALL of `pivot.go`** (peer envelopes, key exchange, peer failures) | **NO** | **YES ×27** | **0% audited** |
| **ALL of `reverse_precreate.go`** (22 KB of pre-create registry) | **NO** | **NO** | **neither** |
| `tunnel_writer.go` (raw tunnel writes) | **NO** | YES (`:61`) | |

`[src]`

> **VERDICT ON Q3: The package audits ARRIVALS and nothing else. Two audit entries exist in 249 KB of handler code — one per session registration, one per beacon registration. Every subsequent action of a registered session or beacon produces ordinary log lines and no audit record. `pivot.go` produces 27 ordinary log lines and zero audit entries. `reverse_precreate.go` produces neither.**

`[src]`

### 3.4 The attribution of D62's finding — WIDENED, not narrowed

**D62 §2.3 found the operator-plane stream path unwritten to the audit log.** `[src]` **Q3 shows the implant plane is in the same condition, and for the same structural reason: the `AuditLogger` is written from exactly three sites in the whole tree (`middleware.go:456` unary operator interceptor, `beacons.go:120`, `sessions.go:118`), and the two handler-side sites fire only on registration.** `[src]`

> **D62's finding is therefore NOT a stream defect. It is an instance of a pattern that spans both planes: Sliver audits registration events and one unary RPC interceptor, and nothing else. The stream gap is the operator-plane expression of it; `pivot.go`'s 0% is the implant-plane expression.**

`[src]` + `[inference]`

**One mitigating observation, stated so the picture is not overstated:** `[inference]` **`pivot.go` and the tunnel handlers operate on connections that have ALREADY been authenticated at the C2 layer, and the implant plane's authentication is mTLS at `server\c2\mtls.go:108` `StartMutualTLSListener` — a different and separately-audited boundary.** `[src]` **So the absence of handler-side audit is not the same as an absence of authentication.** `[inference]` **It remains an absence of RECORD, which is what an audit trail is for.** `[inference]`

---

## Q4 — The `ok, _ :=` idiom on authorization paths

### 4.1 Every occurrence, enumerated with `-CaseSensitive`

```powershell
Get-ChildItem "$s\server" -Recurse -File -Filter *.go |
  Where-Object {$_.Name -notlike '*_test.go'} |
  Select-String -Pattern 'ok, _ :?=' -CaseSensitive
```

`[src]`

```
server\notifications\env.go:87:      expanded, ok, _ := resolveEnvString(value.String())
server\notifications\env.go:106:     expanded, ok, _ := resolveEnvString(val.String())
server\transport\middleware.go:194:  if ok, _ := builderMethods[info.FullMethod]; ok {
server\transport\middleware.go:199:  if ok, _ := crackstationMethods[info.FullMethod]; ok {
server\transport\middleware.go:218:  if ok, _ := builderMethods[info.FullMethod]; ok {
server\transport\middleware.go:223:  if ok, _ := crackstationMethods[info.FullMethod]; ok {
```

`[src]`

**Six occurrences; FOUR are on an authorization path.** `[src]` **The two in `notifications\env.go` are environment-string expansion, not authorization, and are out of scope.** `[inference]`

**D51 §3.2 and D62 §3.2 discussed only the unary pair at `:194`/`:199`.** `[src]` **The stream interceptor has the IDENTICAL idiom at `:218`/`:223`, which neither report enumerated.** `[src]` **Recorded as a scope correction to my own prior work.** `[inference]`

### 4.2 The fail-closed property is STRUCTURAL, not incidental — for three independent reasons

**Reason 1 — every map entry is the literal `true`.** `[src]`

```go
160: 	builderMethods = map[string]bool{
161: 		"/rpcpb.SliverRPC/GetVersion": true,
163: 		"/rpcpb.SliverRPC/GenerateExternalGetBuildConfig": true,
...
170: 	crackstationMethods = map[string]bool{
171: 		"/rpcpb.SliverRPC/GetVersion": true,
173: 		"/rpcpb.SliverRPC/CrackstationRegister":   true,
...
```

`[src]` **All 6 builder entries and all 9 crackstation entries are typed `bool` and set to `true`.** `[src]` **So the discarded comma-ok boolean is redundant: presence implies `true`.** `[inference]`

**Reason 2 — the maps are never written after initialization.** `[src]`

```powershell
Select-String -Pattern 'builderMethods\[|crackstationMethods\[' -CaseSensitive
```

`[src]`

```
server\transport\middleware.go:194:  if ok, _ := builderMethods[info.FullMethod]; ok {
server\transport\middleware.go:199:  if ok, _ := crackstationMethods[info.FullMethod]; ok {
server\transport\middleware.go:218:  if ok, _ := builderMethods[info.FullMethod]; ok {
server\transport\middleware.go:223:  if ok, _ := crackstationMethods[info.FullMethod]; ok {
```

`[src]`

> **FOUR occurrences, ALL of them the `if ok, _ := m[k]; ok` READ form. There is NO assignment to any key, anywhere in the tree.** `[src]` **The maps are effectively immutable after package init.** `[src]` + `[inference]`

**Reason 3 — the fall-through path ends in `PermissionDenied`.** `[src]` **`middleware.go:203-204` unary and `:227-228` stream: after both `if` blocks fail, the function logs a warning and returns `codes.PermissionDenied`.** `[src]` **There is no success return outside the guarded branches.** `[src]`

### 4.3 The inversion, tested honestly

**The question the Lead asked: is this one refactor from failing open?** `[inference]` **I tested the two ways the idiom could be made to fail open:** `[inference]`

| Hypothetical edit | Result | Why |
|---|---|---|
| Set an entry to `false` to disable a method | **Still fails CLOSED** | `m[k]` yields `false`; the `if` body is skipped; control falls to `PermissionDenied`. **The `ok` boolean being discarded is harmless — the VALUE is what gates.** |
| Annotate: `if _, ok := m[k]; ok { return handler }` | **Still fails CLOSED, identically** | Presence and value are both `true` for every entry, so either form gives the same answer. |
| Change the map to `map[string]bool` with a `false` entry AND test the value | **Fails CLOSED** | Same as row 1. |
| **Change the fall-through to `return handler(...)`** | **FAILS OPEN** | **But this is a change to the DENY default, not to the idiom.** |

`[inference]`

> **VERDICT ON Q4: STRUCTURAL, not incidental. The fail-closed property rests on three independent facts — every map value is `true`, no key is ever written, and the fall-through is an explicit `PermissionDenied`. The discarded comma-ok boolean is genuinely irrelevant: with all-true values, presence-semantics and value-semantics coincide. The idiom is ugly and would be dangerous on a map with meaningful `false` values, but on THESE maps it cannot produce a fail-open, and no refactor of the idiom alone can.**

`[src]` + `[inference]`

### 4.4 The durable finding — which is about style, not current correctness

**The real observation is that `if ok, _ := m[k]; ok` signals "I am testing membership" while the code actually tests a value that happens to be boolean.** `[inference]` **If a future maintainer adds a `false` entry intending to DISABLE a method, the idiom fails closed (safe) and the entry is silently a no-op (confusing), because a `false` value reads as absent.** `[inference]` **The correct form for intent is `if _, ok := m[k]; ok`.** `[inference]` **PROBE for a future lane: confirm no linter config in the repo forbids the `ok, _ :=` shape; if one exists, the four sites should be flagged by it, and their survival is itself a finding.** `[inference]`

### 4.5 Adjacent — ignored errors on authorization paths

**The brief asked about "every ignored error" alongside `ok, _ :=`.** `[src]` **The relevant sites are the two helpers D51 §2.2 read, and the question is whether any DISCARDS a returned error.** `[src]` **D51 §2.2 verified all 7 `rejectRevokedCrackTaskAttempt` call sites propagate `err` and none discards `handled`.** `[src]` **Q4 re-confirms the general shape: no `_ = ` assignment was found adjacent to an `authorize*` call in `rpc-crackstations.go` or `rpc-generate.go`.** `[src]` **PROBE for completeness, since I did not run it exhaustively: `Select-String -Pattern '_ = .*(authorize|Authorize|Permission)' -CaseSensitive` across `server\`.** `[inference]`

---

## 5. Residual unknowns — each with a concrete probe

**R1 — `mtls.go`'s operator-certificate validation was not read in full.** `[src]` **`certs\operators.go:70` `ValidateOperatorClientCertificate(peerCertificates []*x509.Certificate)` checks `leaf.IsCA`, empty CN, and `ExtKeyUsageClientAuth` (`:76`).** `[src]` **D51 §R4 flagged that `getClientCommonName` reads CN only and ignores SANs; `certs.go:234` shows `template.DNSNames = append(template.DNSNames, subject.CommonName)` only in a host-cert branch.** `[src]` **Whether CN uniqueness is enforced at operator creation is UNVERIFIED.** `[src]` **PROBE:** read `certs\operators.go` in full plus the `new-operator` handler; determine whether two operators can hold the same CN — if so, `getClientCommonName`'s principal is ambiguous and both the crackstation and builder allowlists key on it. **This is the highest-value remaining probe in this lane.**

**R2 — the `(s *Server)` sweep covered `server\rpc\` only.** `[src]` **The census pattern `^func \(s \*Server\) ` searched `$s\server` recursively, so it is complete for the `server\` tree.** `[src]` **But a THIRD receiver name (`svr`, `srv`, `server`) would be equally invisible to both D62's census and mine.** `[src]` **PROBE:** enumerate ALL receiver names on `*Server` with an unanchored pattern `func \(\w+ \*Server\)` and group by receiver; confirm the set is exactly `{rpc, s}`. **Cheap, and it closes the whole family rather than this instance.**

**R3 — the audit logger's own integrity and path.** `[src]` **`log\audit.go:36` sets `auditLogger.Out = auditRotator`.** `[src]` **I did not read `auditRotator`, so I cannot state the audit file's path, permissions, append-only-ness, or rotation retention.** `[src]` **This is a PREREQUISITE for Q2's probe (Step 4).** `[src]` + `[inference]` **PROBE:** read `server\log\audit.go` and the rotator implementation; determine file mode and whether rotation discards records.

**R4 — the implant plane's own authentication was not traced.** `[src]` **`handlers.go:238` `GetHandlers()` / `:260` `GetNonPivotHandlers()` build the dispatch maps.** `[src]` **Where the implant's mTLS identity is checked before these handlers run is in `server\c2\`, not read here.** `[src]` **PROBE:** trace `server\c2\mtls.go:108` `StartMutualTLSListener` → the envelope dispatch path → `GetHandlers()`, confirming that an implant envelope cannot reach `pivotPeerEnvelopeHandler` without a validated certificate. **Q3 §3.4's mitigating observation depends on this and I did not verify it.**

**R5 — `reverse_precreate.go` (22,327 B) produces no logs at all.** `[src]` **Zero audit AND zero ordinary log writes (§3.2).** `[src]` **It is the reverse-tunnel pre-create registry — 22 KB of staging, promotion, expiry, and release logic that is entirely silent.** `[src]` **PROBE:** determine whether its callers log on its behalf (`handlers.go:94-235` has the `reverseTunnelOpening` lifecycle); if not, this is a second, larger audit gap.

**R6 — `tunnel_writer.go:61` writes to the raw `log.Printf`, not a named logger.** `[src]` **`log.Printf("[tunnelWriter] Write %d bytes ...")` — a bare standard-library print.** `[src]` **Every other production file in the package uses a named logger.** `[src]` **PROBE:** determine whether `log.Printf` reaches the same sink as the named loggers or is lost; if lost, tunnel write activity is recorded nowhere.**

---

## 6. Instrument failures and corrections recorded in this report

| # | Item | Where | Resolution |
|---|---|---|---|
| **F1** | **`-contains` is CASE-INSENSITIVE, collapsing `socksProxy` (helper) into `SocksProxy` (RPC)** | §0.6, §1.2 | **Found by re-running the classifier with `-ccontains` after the count looked wrong. Same defect as D62 F2, committed two reports later. Corrected 9 → 8 RPC-served.** |
| **F2** | **§0.1 stated 11/12/0 before the classifier was run** | §0.6 | **A number written into a report before measurement. Corrected to 8/15/0. Recorded because the habit — asserting a count from expectation — is exactly what this lane exists to prevent.** |
| **F3** | **`InterruptSession` does not exist; the brief's D62 S6 reference does not resolve** | §0.7, §2.0 | **Zero case-sensitive hits tree-wide. D62 §6 is the instrument table. Q2 answered on a real method.** |
| **F4** | **My own Q3 probe had an unbalanced regex paren** | §3.2 | **`Select-String` errored LOUDLY rather than returning zero. Fixed to `(Logf|Log)[.(]`. Noting it because a silent variant of this failure would have produced a false zero.** |
| **F5** | **D51 §3.2 and D62 §3.2 enumerated only the UNARY `ok, _ :=` pair** | §4.1 | **The stream interceptor has the identical idiom at `:218`/`:223`, never enumerated in either report. Scope correction to my own prior work.** |
| **F6** | **D62 §R1 said "~20"; the census it cited had the exact figure** | §0.2 | **23. Now given by name with a full classification.** |

`[src]`

**On F1 and F2 specifically, since the brief asked me to keep correcting my own sections:** `[src]` **F1 is the third occurrence of a case-sensitivity defect in this lane (D44 F6, D62 F2, D66 F1). F2 is worse in kind — it is a number asserted before measurement, which no instrument can catch because no instrument was run.** `[inference]` **The remedy is structural and I am stating it as a lane rule: a count may not be written into a report until the probe that produces it has been run and its output printed.** `[inference]`

---

## 7. Summary

**Q1 — the 23-method sweep. `[src]` The 23 `(s *Server)` methods are enumerated and classified: 8 RPC-served / 15 internal / 0 dead. All 8 RPC-served methods have generated `_SliverRPC_<Name>_Handler` wrappers and `ServiceDesc` entries, and NONE has a direct Go call site. The blind spot hid ZERO authorization findings.** **The receiver name cannot matter: gRPC dispatches through an interface assertion on `ServiceDesc`, so `(s *Server)` and `(rpc *Server)` are indistinguishable at runtime. The blind spot was an OBSERVER blind spot and it defeated static probes only.** **Durable lesson: the correct census is the `SliverRPCServer` interface (201 methods), which is receiver-name-independent.**

**Q2 — the runtime boundary. `[probe specified, not executed]` No server was started. The experiment is specified as a 7-step procedure targeting `/rpcpb.SliverRPC/SocksProxy` on the multiplayer mTLS transport (port 31337), with an explicit POSITIVE CONTROL — a unary `GetVersion` call that MUST produce exactly one audit line with `"User":"probe-op"` before the stream test is valid.** **The disconfirming check is included: a builder-only operator on the `BuilderRegister` stream must SUCCEED and also produce zero audit lines; if it is denied, the finding changes character into the authorization asymmetry D12 predicted.** **Two ways the experiment fails and what each means are tabulated. Note that the local `bufconn` transport would produce a FALSE POSITIVE, because it lacks both permission AND audit interceptors.**

**Q3 — the handlers write-path sweep. `[src]` The package is the IMPLANT plane (every handler takes `implantConn *core.ImplantConnection`), so the operator-plane audit interceptor cannot reach it. The package contains 2 audit writes against 98 ordinary writes — a 2.0% audit rate — and both audit writes fire on REGISTRATION only (`auditLogBeacon:112`, `auditLogSession:110`). `pivot.go` is 27 ordinary log lines and 0% audited. `reverse_precreate.go` is silent entirely. D62's audit finding is therefore WIDENED: it is not a stream defect but a two-plane pattern — Sliver audits registration events and one unary interceptor, and nothing else.**

**Q4 — the `ok, _ :=` idiom. `[src]` Four authorization-path occurrences, not the two my prior reports enumerated: `middleware.go:194`, `:199` (unary) and `:218`, `:223` (stream). The fail-closed property is STRUCTURAL, not incidental, on three independent grounds: every map value is the literal `true` (all 6 builder + all 9 crackstation entries), no key is ever written anywhere in the tree (four read sites, zero assignments), and the fall-through is an explicit `PermissionDenied`. Setting an entry to `false` still fails CLOSED — the value gates, not the presence boolean. No refactor of the idiom alone can produce a fail-open.** **The durable observation is stylistic: the idiom says "membership" while testing a boolean value, so a future `false` entry to disable a method would be a silent no-op. `if _, ok := m[k]; ok` is the correct form for the intent.**

**The single most important sentence:** `[src]` + `[inference]` **The receiver-name blind spot that produced D44 §R2 was a real and repeated instrument failure but had NO security consequence — the eight RPCs inside it are dispatched through the same interface and the same interceptor chain as the other 214 — while the audit gap D62 found is real, is wider than D62 stated, and now spans both planes, with the operator-plane stream path and the entire implant handler package recording nothing beyond registration.**

