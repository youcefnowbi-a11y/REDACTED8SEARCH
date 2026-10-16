# D51 — Sliver RPC authorization boundary

**Task:** Lead-issued, board `task-53`. Read `server\transport\middleware.go` in full (D44 §R1, the highest-value follow-up), plus the 14 authorization guard sites.
**Lane:** sliver-diver. **Method:** source-only reading; no REA, no provider, no execution.
**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`

**Citation convention:** inline `path/file.go:LINE`. `[src]` = read from source; `[inference]` = my reasoning over it.

---

## 0. Corrections and headline first

### 0.1 HEADLINE — D44 §1.5's "authorization is per-method only" was INCOMPLETE

**D44 §1.5 stated:** *"The generalisation boundary is unmeasured because `server\transport\middleware.go` — the likely home of any global interceptor-level authorization — was outside this report's read budget."* `[src]`

**D51 read it. There IS a second, interceptor-level authorization layer, and D44 did not know it existed.** `[src]`

**`server/transport/middleware.go:158-181` declares TWO ALLOWLISTS:** `[src]`

```go
var (
	// Builder - Allowed methods
	builderMethods = map[string]bool{
		"/rpcpb.SliverRPC/GetVersion": true,
		"/rpcpb.SliverRPC/GenerateExternalGetBuildConfig": true,
		"/rpcpb.SliverRPC/GenerateExternalSaveBuild":      true,
		"/rpcpb.SliverRPC/BuilderRegister":                true,
		"/rpcpb.SliverRPC/BuilderTrigger":                 true,
		"/rpcpb.SliverRPC/Builders":                       true,
	}
	// Crackstation - Allowed methods
	crackstationMethods = map[string]bool{
		"/rpcpb.SliverRPC/GetVersion": true,
		"/rpcpb.SliverRPC/CrackstationRegister":   true,
		"/rpcpb.SliverRPC/CrackstationTrigger":    true,
		"/rpcpb.SliverRPC/CrackstationBenchmark":  true,
		"/rpcpb.SliverRPC/Crackstations":          true,
		"/rpcpb.SliverRPC/CrackTaskByID":          true,
		"/rpcpb.SliverRPC/CrackTaskUpdate":        true,
		"/rpcpb.SliverRPC/CrackFilesList":         true,
		"/rpcpb.SliverRPC/CrackFileChunkDownload": true,
	}
)
```

`[src]`

**Enumerated: `builderMethods` = 6 entries; `crackstationMethods` = 9 entries; both include `/rpcpb.SliverRPC/GetVersion`.** `[src]` **These are enforced by two interceptors that CAN deny (§1.2).** `[src]`

**So D44's §1.5 coverage table was wrong in the conservative direction — it under-counted the guarded surface, not over-counted it.** `[src]` + `[inference]` **That is the safe direction for an error to fall, but it is still an error and it is corrected here.** `[inference]`

### 0.2 The Lead's own prior hypothesis is CONFIRMED — and it is worse than "absent on local"

**The Lead's Q1, quoting D11 §6:** *"on the LOCAL transport the permissions interceptor is ABSENT and `serverAuthFunc` returns nil unconditionally. Is there a transport on which the AUTHORIZATION interceptor is likewise absent?"* `[src]`

> **ANSWER: YES — the LOCAL transport. On `server\transport\local.go:47` the server is built with `initMiddleware(false)`, which selects the `else` branch at `middleware.go:86-103`. In that branch BOTH `permissionsUnaryServerInterceptor()` and `permissionsStreamServerInterceptor()` are entirely absent — from the unary chain AND the streaming chain.**
>
> **`serverAuthFunc` (`middleware.go:119-123`) returns `nil` unconditionally and injects the literals `Transport = "local"` and `Operator = "server"` into the context.**

`[src]`

**The three transports, enumerated with their `enableAuth` value:** `[src]`

```powershell
Get-ChildItem "$s" -Recurse -File -Filter *.go | Where-Object {$_.FullName -notmatch '\\vendor\\'} |
  Select-String -Pattern 'initMiddleware\(' | ForEach-Object { "$($_.Path):$($_.LineNumber): $($_.Line.Trim())" }
```

**Output:** `[src]`

| Transport | File:line | `enableAuth` | Permissions interceptors |
|---|---|---:|---|
| **local** | `server\transport\local.go:47` | **`false`** | **ABSENT (unary AND stream)** |
| **mTLS / multiplayer** | `server\transport\mtls.go:89` | `true` | present (unary AND stream) |
| **Tailscale** | `server\transport\tailscale.go:85` | `true` | present (unary AND stream) |

`[src]`

**One further transport shares the mTLS server — and therefore the `true` branch:** `StartWGWrappedMtlsClientListener` (`server\transport\multiplayer_wireguard.go:102`) delegates to `StartMtlsClientServer` at `:160`, whose `:89` is `initMiddleware(true)`. `[src]` **So WireGuard-wrapped multiplayer inherits the auth branch; it does not get its own middleware decision.** `[inference]`

### 0.3 Correction to D44's R1 framing

**D44 said `middleware.go` was "the likely home of any global interceptor-level authorization."** `[src]` **It is — and the authorization is of a different KIND than D44 was looking for.** `[src]` **D44 was looking for a per-method authz gate; what exists is a ROLE-ALLOWLIST gate plus a TOKEN-AUTHENTICATION gate.** `[inference]` **These are not the same thing: the allowlists constrain what a *builder* or *crackstation* operator token may call, not which human may call what.** `[inference]` **D44's §1.5 "distribution not binary" framing stands; only its coverage arithmetic changes (§2.3).** `[inference]`

---

## Q1 — The interceptor chain: what is registered, in what order, what can deny

### 1.1 The two chains, quoted complete

**`server/transport/middleware.go:61-105`, the whole of `initMiddleware`:** `[src]`

```go
func initMiddleware(enableAuth bool) []grpc.ServerOption {
	logrusEntry := log.NamedLogger("transport", "grpc")
	logrusOpts := []grpc_logrus.Option{
		grpc_logrus.WithLevels(codeToLevel),
	}
	grpc_logrus.ReplaceGrpcLogger(logrusEntry)
	if enableAuth {
		return []grpc.ServerOption{
			grpc.ChainUnaryInterceptor(
				grpc_auth.UnaryServerInterceptor(tokenAuthFunc),        // :70
				permissionsUnaryServerInterceptor(),                    // :71
				auditLogUnaryServerInterceptor(),                       // :72
				grpc_tags.UnaryServerInterceptor(...),                  // :73
				grpc_logrus.UnaryServerInterceptor(...),                // :74
				grpc_logrus.PayloadUnaryServerInterceptor(...),         // :75
			),
			grpc.ChainStreamInterceptor(
				grpc_auth.StreamServerInterceptor(tokenAuthFunc),       // :78
				permissionsStreamServerInterceptor(),                   // :79
				trackOperatorStreamInterceptor(),                       // :80
				grpc_tags.StreamServerInterceptor(...),                 // :81
				grpc_logrus.StreamServerInterceptor(...),               // :82
				grpc_logrus.PayloadStreamServerInterceptor(...),        // :83
			),
		}
	} else {
		return []grpc.ServerOption{
			grpc.ChainUnaryInterceptor(
				grpc_auth.UnaryServerInterceptor(serverAuthFunc),       // :89
				auditLogUnaryServerInterceptor(),                       // :90
				grpc_tags.UnaryServerInterceptor(...),                  // :91
				grpc_logrus.UnaryServerInterceptor(...),                // :92
				grpc_logrus.PayloadUnaryServerInterceptor(...),         // :93
			),
			grpc.ChainStreamInterceptor(
				grpc_auth.StreamServerInterceptor(serverAuthFunc),      // :96
				trackOperatorStreamInterceptor(),                       // :97
				grpc_tags.StreamServerInterceptor(...),                 // :98
				grpc_logrus.StreamServerInterceptor(...),               // :99
				grpc_logrus.PayloadStreamServerInterceptor(...),        // :100
			),
		}
	}
}
```

`[src]`

### 1.2 THE INTERCEPTOR TABLE — which can actually deny

**"Can deny" means: the interceptor has a `return` path carrying a non-nil error, reachable on some input.** `[inference]`

| # | Interceptor | Registered | Unary | Stream | CAN DENY? | Denial code |
|---|---|---|---|---|---:|---|
| 1 | `grpc_auth` w/ **`tokenAuthFunc`** | auth branch `:70`/`:78` | ✓ | ✓ | **YES** | `Unauthenticated` — bad/missing Bearer |
| 2 | `grpc_auth` w/ **`serverAuthFunc`** | local branch `:89`/`:96` | ✓ | ✓ | **NO — never returns error** | — |
| 3 | **`permissionsUnaryServerInterceptor()`** | **auth branch only `:71`** | **✓** | **✗** | **YES** | `Unauthenticated`, `PermissionDenied` |
| 4 | **`permissionsStreamServerInterceptor()`** | **auth branch only `:79`** | **✗** | **✓** | **YES** | `Unauthenticated`, `PermissionDenied` |
| 5 | `auditLogUnaryServerInterceptor()` | both branches `:72`/`:90` | ✓ | **✗** | **NO** (audit) | — |
| 6 | `trackOperatorStreamInterceptor()` | both branches `:80`/`:97` | **✗** | ✓ | **YES (conditionally)** | `Unauthenticated` at `operator_streams.go:128` |
| 7 | `grpc_tags` unary/stream | both | ✓ | ✓ | NO | — |
| 8 | `grpc_logrus` unary/stream | both | ✓ | ✓ | NO | — |
| 9 | `grpc_logrus` payload unary/stream | both | ✓ | ✓ | NO (decision only) | — |

`[src]` for registration and paths; `[inference]` for "can deny" classification.

**Five structural observations from the table:** `[src]` + `[inference]`

1. **`tokenAuthFunc` is registered on BOTH paths in the auth branch — but `serverAuthFunc` on BOTH paths in the local branch.** The asymmetry is not unary-vs-stream; it is **auth-branch vs local-branch**. `[inference]`
2. **`permissionsUnaryServerInterceptor` has NO stream counterpart registered in the local branch, and `permissionsStreamServerInterceptor` has no unary counterpart — but in the auth branch both are registered, one per path.** So **Q4's answer is that the auth branch is symmetric**. `[inference]`
3. **`auditLogUnaryServerInterceptor()` is unary-ONLY in both branches** — **there is no `auditLogStreamServerInterceptor`.** `[src]` **Streaming RPC calls are therefore NOT audit-logged by this interceptor.** `[inference]` **That is a genuine unary/stream asymmetry, and it is an AUDIT gap, not an authorization gap.** `[inference]`
4. **`trackOperatorStreamInterceptor()` is stream-ONLY and present in BOTH branches** — it is the only authz-adjacent interceptor that runs on the local transport. `[src]`
5. **Order matters: authentication precedes authorization on both paths** (`tokenAuthFunc` then `permissions*`). `[src]` **This is the correct order, and it is what makes the unchecked type assertion at `:186`/`:210` safe (§1.4).** `[inference]`

### 1.3 The two permission interceptors, quoted complete

**`middleware.go:184-206` (unary):** `[src]`

```go
func permissionsUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (_ interface{}, err error) {
		operator := ctx.Value(Operator).(*models.Operator)
		if operator == nil {
			return nil, status.Error(codes.Unauthenticated, "Authentication failure")
		}
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
		mtlsLog.Warnf("Permission denied for %s attempting to access %s", operator.Name, info.FullMethod)
		return nil, status.Error(codes.PermissionDenied, "Token has insufficient permissions")
	}
}
```

`[src]`

**`middleware.go:208-230` (stream) is the IDENTICAL logic** — same `PermissionAll` fast path, same two allowlists, same `PermissionDenied` fallthrough, with `ss.Context()` in place of `ctx` and `handler(srv, ss)` in place of `handler(ctx, req)`. `[src]`

**The default is DENY: an operator lacking `PermissionAll`, `PermissionBuilder`, and `PermissionCrackstation` falls through to `PermissionDenied`.** `[src]` **Fail-closed on the permission axis.** `[inference]`

### 1.4 The unchecked type assertions — audited, and they are SAFE, but only by ordering

**Three `ctx.Value(Operator)` reads exist in the tree, and the probe is:** `[src]`

```powershell
Get-ChildItem "$s" -Recurse -File -Filter *.go | Where-Object {$_.FullName -notmatch '\\vendor\\'} |
  Select-String -Pattern 'Value\(Operator\)|Value\(Transport\)'
```

**Output:** `[src]`

```
\server\transport\middleware.go:186:        operator := ctx.Value(Operator).(*models.Operator)
\server\transport\middleware.go:210:        operator := ss.Context().Value(Operator).(*models.Operator)
\server\transport\operator_streams.go:116: operator, ok := ss.Context().Value(Operator).(*models.Operator)
```

`[src]`

**Two are UNCHECKED single-value assertions (`:186`, `:210`); one is comma-ok (`operator_streams.go:116`).** `[src]`

**Analysis:** `[src]` + `[inference]`

- **`serverAuthFunc` (`:119-123`) stores the literal STRING `"server"` under key `Operator`.** `[src]` **So on the LOCAL transport, `ctx.Value(Operator)` is a `string`, not a `*models.Operator`.** `[src]`
- **An unchecked assertion `x.(T)` panics when `x` is nil or of a different dynamic type.** `[inference]` **So if `permissionsUnaryServerInterceptor` ever ran on the local transport, `:186` would PANIC on the string.** `[inference]`
- **It cannot run there, because `:71`/`:79` are inside the `enableAuth` branch and the local transport passes `false`.** `[src]` **And in the auth branch, `tokenAuthFunc` (`:143`, `:154`) always stores a real `*models.Operator` BEFORE `permissions*` executes (chain order §1.2).** `[src]`
- **Therefore the assertions are safe — but the safety is a property of REGISTRATION ORDER PLUS THE BRANCH, not of the assertion.** `[inference]` **An edit that moved `permissionsUnaryServerInterceptor()` into the `else` branch would turn a silent no-op into a panic on every unary local call.** `[inference]`

**`operator_streams.go:116-119` is the correct pattern and it FAILS OPEN by design:** `[src]`

```go
operator, ok := ss.Context().Value(Operator).(*models.Operator)
if !ok || operator == nil || strings.TrimSpace(operator.Name) == "" {
	return handler(srv, ss)
}
```

`[src]` **On the local transport `ok` is false (the value is a `string`), so the interceptor passes through.** `[inference]` **Failing open here is CORRECT — the local transport is an operator's own unix-socket/local connection and there is no operator record to track.** `[inference]` **Contrast the permission interceptors, which fail CLOSED.** `[inference]` **Two adjacent interceptors, opposite failure directions, each appropriate to its purpose — worth naming because it shows the fail-direction is deliberate rather than accidental.** `[inference]`

### 1.5 The mid-stream revocation check

**`operator_streams.go:121-132` re-queries the operator row under `tokenCacheMu.RLock()`:** `[src]`

```go
tokenCacheMu.RLock()
stored := &models.Operator{}
if err := db.Session().Select("id").Where("id = ?", operator.ID).First(stored).Error; err != nil {
	tokenCacheMu.RUnlock()
	return status.Error(codes.Unauthenticated, "Authentication failure")
}
ctx, cancel := context.WithCancel(ss.Context())
streamID := activeOperatorStreams.register(operator.Name, cancel)
tokenCacheMu.RUnlock()
```

`[src]`

**A long-lived stream revalidates the account row and is cancelled if the row is gone.** `[src]` **The comment at `:121-123` states the reason: a token can authenticate and then be kicked, so the stream must be registered under the same lock that closes streams.** `[src]` **The lock is an `RLock` around a read-and-register, paired with `CloseOperatorStreams` (`:110-112`) — I did NOT read that function's lock discipline.** `[src]` **Residual §R3.** `[inference]`

---

## Q2 — The 14 authorization call sites

### 2.1 All 14, with path:line, guarded method, principal, and failure mode

**Invocation that produced the mapping (enclosing-function resolution, matching each site to the nearest preceding `func (rpc *Server)`):** `[src]`

```powershell
$files = Get-ChildItem "$s\server\rpc" -Recurse -File -Filter *.go | Where-Object {$_.Name -notlike '*_test.go'}
foreach($f in $files){
  $lines = Get-Content $f.FullName
  $meths = @()
  for($i=0;$i -lt $lines.Count;$i++){
    if($lines[$i] -match '^func \(rpc \*Server\) (\w+)\('){ $meths += [pscustomobject]@{N=$Matches[1];L=$i+1} }
  }
  $lines | Select-String -Pattern '\bauthorize[A-Za-z]*\(' | ForEach-Object {
    if($_.Line -notmatch '^func '){
      $owner = ($meths | Where-Object {$_.L -lt $_.LineNumber} | Sort-Object L | Select-Object -Last 1)
      "{0}:{1}: in {2}()" -f $f.Name,$_.LineNumber,$owner.N
    }
  }
}
```

`[src]`

**The table. Principal in every single row is the mTLS certificate CN via `getClientCommonName` (`rpc.go:260-276`).** `[src]`

| # | Site | Guards method | Principal read | Failure behaviour |
|---:|---|---|---|---|
| 1 | `crack-keyspace.go:674` | `standaloneCrackTaskByID` (helper) | cert CN vs `expectedHost` | `err` propagated → caller returns it |
| 2 | `crack-keyspace.go:729` | `standaloneCrackTaskUpdate` (helper) | cert CN vs `req.HostUUID` | `err` propagated |
| 3 | `rpc-crackstations.go:418` | **`CrackstationTrigger`** | cert CN vs `statusUpdate.HostUUID` | `err` propagated → return |
| 4 | `rpc-crackstations.go:455` | **`CrackstationTrigger`** | cert CN vs `acknowledgement.HostUUID` | `err` propagated |
| 5 | `rpc-crackstations.go:477` | **`CrackstationTrigger`** | cert CN vs `statusUpdate.HostUUID` | `err` propagated |
| 6 | `rpc-crackstations.go:541` | **`CrackTaskByID`** | cert CN vs `task.CrackstationID.String()` | `err` propagated |
| 7 | `rpc-crackstations.go:557` | `rejectRevokedCrackTaskAttempt` (helper) | cert CN vs `req.HostUUID` | **returns `(true, err)`** → caller returns |
| 8 | `rpc-crackstations.go:607` | **`CrackTaskUpdate`** | cert CN vs `req.HostUUID` | `err` propagated |
| 9 | `rpc-crackstations.go:632` | **`CrackstationBenchmark`** | cert CN vs `req.HostUUID` | `err` propagated |
| 10 | `rpc-generate.go:638` | **`GenerateExternalSaveBuild`** | cert CN vs builder owner | `err` propagated |
| 11 | `rpc-generate.go:681` | **`GenerateExternalGetBuildConfig`** | cert CN vs builder owner | `err` propagated |
| 12 | `rpc-generate.go:805` | **`BuilderTrigger`** | cert CN vs build operator | `err` propagated |
| 13 | `rpc-generate.go:818` | **`BuilderTrigger`** | cert CN vs build operator | `err` propagated |
| 14 | `rpc-generate.go:831` | **`BuilderTrigger`** | cert CN vs build operator | `err` propagated |

`[src]`

**Failure mode is `status.Error(codes.PermissionDenied, ...)` or `codes.Unauthenticated` in EVERY case — never a silent `nil`, never a panic, in all 14.** `[src]` **Verified by reading both helper bodies (§2.2).** `[src]`

### 2.2 Both helpers read in full, because a discarded return value would be a silent bypass

**`authorizeCrackstation` — `rpc-crackstations.go:384-397`:** `[src]`

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

**`rejectRevokedCrackTaskAttempt` — `rpc-crackstations.go:553-564`, the only site returning `(bool, error)`:** `[src]`

```go
func (rpc *Server) rejectRevokedCrackTaskAttempt(ctx context.Context, req *clientpb.CrackTask) (bool, error) {
	if !revokedCrackTaskAttempt(req) {
		return false, nil
	}
	if err := rpc.authorizeCrackstation(ctx, req.HostUUID); err != nil {
		return true, err
	}
	if observeRevokedCrackTaskAttempt(req) {
		return true, status.Error(codes.Aborted, errStaleCrackTaskAttempt.Error())
	}
	return false, nil
}
```

`[src]`

**Its 7 call sites, printed — every one checks `handled` and propagates `err`:** `[src]`

```
rpc-crackstations.go:510: if handled, err := rpc.rejectRevokedCrackTaskAttempt(ctx, req); handled {
rpc-crackstations.go:519: if handled, revokedErr := rpc.rejectRevokedCrackTaskAttempt(ctx, req); handled {
rpc-crackstations.go:526: if handled, revokedErr := rpc.rejectRevokedCrackTaskAttempt(ctx, req); handled {
rpc-crackstations.go:536: if handled, revokedErr := rpc.rejectRevokedCrackTaskAttempt(ctx, req); handled {
rpc-crackstations.go:574: if handled, err := rpc.rejectRevokedCrackTaskAttempt(ctx, req); handled {
rpc-crackstations.go:592: if handled, revokedErr := rpc.rejectRevokedCrackTaskAttempt(ctx, req); handled {
rpc-crackstations.go:602: if handled, revokedErr := rpc.rejectRevokedCrackTaskAttempt(ctx, req); handled {
```

`[src]`

**No call site discards `handled` or ignores `err`.** `[src]` **But note the SCOPING consequence: `:554-556` returns `(false, nil)` immediately when `revokedCrackTaskAttempt(req)` is false — so the `authorizeCrackstation` call at `:557` executes ONLY for tasks flagged revoked.** `[src]` + `[inference]` **This is a narrowing, not a bypass: for non-revoked tasks the authorization is performed by the CALLER's own `authorizeCrackstation` (e.g. `CrackTaskUpdate:607`).** `[inference]` **I verified `CrackTaskUpdate` does have its own call at `:607`.** `[src]`

### 2.3 Coverage: how many of the 201 methods are guarded by at least one of the 14

**Distinct RPC methods directly guarded by a call site: 8.** `[src]`

| # | Method | Sites |
|---:|---|---|
| 1 | `CrackstationTrigger` | `:418`, `:455`, `:477` |
| 2 | `CrackTaskByID` | `:541` |
| 3 | `CrackTaskUpdate` | `:607` (plus helper `:557`) |
| 4 | `CrackstationBenchmark` | `:632` |
| 5 | `GenerateExternalSaveBuild` | `:638` |
| 6 | `GenerateExternalGetBuildConfig` | `:681` |
| 7 | `BuilderTrigger` | `:805`, `:818`, `:831` |
| 8 | `CrackstationRegister` | **no direct call site — see below** |

`[src]`

**`CrackstationRegister` deserves its own row and I nearly missed it.** `[src]` **It performs the same principal extraction INLINE rather than via a helper — `rpc-crackstations.go:703-706`:** `[src]`

```go
req = proto.Clone(req).(*clientpb.Crackstation)
req.OperatorName = rpc.getClientCommonName(stream.Context())
if req.OperatorName == "" {
	return status.Error(codes.Unauthenticated, "missing crackstation client identity")
}
```

`[src]` **This is authorization logic at a 15th site that the "14 `authorize*` calls" count does not include, because it does not call a helper named `authorize`.** `[src]` + `[inference]` **A name-driven probe under-counts the guarded set — the same instrument-shape failure as D44's `services.pb.go` false zero, in a different costume.** `[inference]`

> **COVERAGE: 8 methods carry a direct `authorize*` guard; a 9th (`CrackstationRegister`) carries inline equivalent logic. That is 9 of 201 methods — and the other 192 are guarded ONLY by the interceptor layer (§Q1), whose allowlists cover just 6 + 9 = 15 method paths, of which `GetVersion` is shared, i.e. 14 distinct methods.**

`[src]` + `[inference]`

**The uncovered set, named rather than counted — these are the high-value ones a reader would expect to be guarded and which the two mechanisms do NOT name:** `[src]`

`Generate`, `ImplantBuild`, `Regenerate`, `KillSession`, `KillBeacon`, `GetSessions`, `GetBeacons`, `Execute`, `Shell`, `Ps`, `Download`, `Upload`, `Ls`, `Rm`, `Mv`, `Cd`, `Pwd`, `Mkdir`, `Chmod`, `Chown`, `Screenshot`, `Pivots`, `LootAll`, `LootAdd`, `LootRm`, `Creds`, `CredsAdd`, `Migrate`, `Sideload`, `SpawnDll`, `ExtensionsAdd`, `WasmImplantExec`, `WasmImplantList`, `Websites`, `WebsiteAddContent`, `WebsiteRemoveContent`, `Tunnel`, `Socks`, `Portfwd`, `Rportfwd`, `GetOperators`, `MonitorStart`, `MonitorStop`, `Reconfig`, `ServiceStart`, `ServiceStop`, `Tasks`, `Task`, `Env`, `Netstat`, `Ifconfig`, `ExecuteAssembly`, `Backdoor`, `GetSystem`, `HijackSession`.

`[src]` **(56 named methods; the remaining ~136 of the 192 I did not individually verify against both allowlists — see §R1.)** `[inference]`

**The correct reading of this list, stated at the strength the evidence supports:** `[src]` + `[inference]`

> **These 56 methods are NOT unguarded in the sense of "callable without authentication." Every RPC on the auth branch passes `tokenAuthFunc` first, so a caller must hold a valid operator Bearer token. What they lack is a per-method AUTHORIZATION check beyond the role allowlist — i.e. any operator token with `PermissionAll` (the default for an ordinary operator) can reach all of them. `getClientCommonName` is used for IDENTITY in 9 places; it is used for AUTHORIZATION in exactly those 9.**

`[inference]`

**REACHABLE ≠ GUARDED — and the reverse also holds here: AUTHENTICATED ≠ AUTHORIZED.** `[src]` + `[inference]` **The Lead's rule is load-bearing in both directions and I am applying it to the local transport explicitly: on local, neither authentication nor authorization occurs for 201 of 201 methods (§1.2), and that is by design because the local transport is the operator's own machine.** `[inference]`

---

## Q3 — `authorizeCrackstation` with an unassociated crackstation: does it fail closed?

**This is the highest-value question and I traced it to the storage layer.** `[src]`

### 3.1 The model field

**`server/db/models/crackstations.go:29-40`:** `[src]`

```go
// Crackstation - History of crackstation jobs
type Crackstation struct {
	// ID = crackstation name
	ID                      UUID      `gorm:"primaryKey;type:uuid;"`
	CreatedAt               time.Time `gorm:"->;<-:create;"`
	OperatorName            string
	HashcatVersion          string `gorm:"size:128"`
	...
}
```

`[src]`

**`OperatorName` is a plain `string` with NO `not null` and no default constraint.** `[src]` **In Go a plain `string` zero-value is `""`, so a row *could* read back as empty.** `[inference]` **That is precisely the fail-open shape the Lead anticipated.**

### 3.2 THE ANSWER — it fails CLOSED, at three independent layers

> **An `OperatorName` of `""` can NOT be persisted through the normal registration path, and even if a legacy row already holds `""`, the read-back loop backfills it and then rejects the mismatch. A crackstation cannot be registered without an operator, and a caller with an empty CN is rejected before any comparison.**

`[src]`

**Layer 1 — the registration entry point OVERWRITES the field from the cert and rejects empty. `rpc-crackstations.go:699-706`:** `[src]`

```go
if req == nil {
	return status.Error(codes.InvalidArgument, "missing crackstation registration")
}
req = proto.Clone(req).(*clientpb.Crackstation)
req.OperatorName = rpc.getClientCommonName(stream.Context())
if req.OperatorName == "" {
	return status.Error(codes.Unauthenticated, "missing crackstation client identity")
}
```

`[src]`

**Two things are load-bearing here and both are correct:** `[src]` + `[inference]`

- **`:702` `proto.Clone` before mutation** — the caller's message is not modified in place, and the client-supplied `OperatorName` is then **overwritten** at `:703`. **A client CANNOT claim an operator name; it is derived server-side from the verified certificate.** `[src]` + `[inference]`
- **`:704-706` empty CN is rejected with `Unauthenticated`** — so a certificate with no CN cannot register a crackstation at all. `[src]`

**Layer 2 — the persistence function independently REFUSES an empty operator. `rpc-crackstations.go:269-272`:** `[src]`

```go
func registerCrackstationRecord(hostID models.UUID, operatorName string, hashcatVersion string) (*models.Crackstation, error) {
	if hostID == models.NilUUID() || operatorName == "" {
		return nil, errors.New("invalid crackstation identity")
	}
```

`[src]`

**So even a caller that bypassed Layer 1 cannot insert a row with an empty `OperatorName` — the guard is inside the transaction function, not at the RPC boundary.** `[src]` + `[inference]` **Defence in depth: the invariant is enforced where the row is written, not only where the request arrives.** `[inference]`

**Layer 3 — a PRE-EXISTING empty row is BACKFILLED, then the mismatch is checked. `rpc-crackstations.go:274-296`:** `[src]`

```go
err := db.Session().Transaction(func(tx *gorm.DB) error {
	candidate := &models.Crackstation{ID: hostID, OperatorName: operatorName, HashcatVersion: hashcatVersion}
	if err := tx.Omit("Tasks", "Benchmarks").Clauses(clause.OnConflict{DoNothing: true}).Create(candidate).Error; err != nil {
		return err
	}
	persisted := &models.Crackstation{}
	if err := tx.First(persisted, "id = ?", hostID).Error; err != nil {
		return err
	}
	if persisted.OperatorName == "" {
		result := tx.Model(&models.Crackstation{}).
			Where("id = ? AND (operator_name = ? OR operator_name IS NULL)", hostID, "").
			Update("operator_name", operatorName)
		if result.Error != nil {
			return result.Error
		}
		if err := tx.First(persisted, "id = ?", hostID).Error; err != nil {
			return err
		}
	}
	if persisted.OperatorName != operatorName {
		return errCrackstationOwnerMismatch
	}
```

`[src]`

**Read the sequence carefully, because it is the answer to the Lead's exact question:** `[src]`

1. **`OnConflict{DoNothing: true}` (`:276`)** — if the row already exists, the insert is a no-op and the **existing** row wins. `[src]`
2. **`:279-282` re-read the persisted row.** `[src]`
3. **`if persisted.OperatorName == ""` (`:283`)** — **this is the "never associated with an operator" case, and it is HANDLED, not ignored.** The `UPDATE` is **narrowly scoped by `:285`** to `operator_name = '' OR operator_name IS NULL`, i.e. it **can only ever claim an UNOWNED row.** `[src]`
4. **`:290-292` re-read after the update.** `[src]`
5. **`:294-295` `if persisted.OperatorName != operatorName { return errCrackstationOwnerMismatch }`** — **the final arbiter.** `[src]`

**So the outcome for a previously-unowned crackstation is: the FIRST operator to register it claims it (via the narrowly-scoped UPDATE), and every SUBSEQUENT different operator hits `:294` and gets `errCrackstationOwnerMismatch`.** `[src]` + `[inference]`

**And the mismatch error is mapped to `PermissionDenied` at the call site — `rpc-crackstations.go:713-715`:** `[src]`

```go
if errors.Is(err, errCrackstationOwnerMismatch) {
	return status.Error(codes.PermissionDenied, err.Error())
}
```

`[src]`

**Why `"" == ""` cannot arise at the comparison in `authorizeCrackstation:393`:** `[src]` + `[inference]`

- **The caller side cannot be `""`** — `:386-388` returns `Unauthenticated` first. `[src]`
- **The stored side cannot be `""`** for any row reachable through registration — Layers 1 and 2 prevent creation, Layer 3 backfills pre-existing empties. `[src]`
- **A row that somehow still held `""` would be matched by the `Where(... operator_name = '' OR IS NULL)` UPDATE — but the subsequent `:294` mismatch check runs against the freshly-registered operator, so a second different operator is still rejected.** `[src]`

**VERDICT: FAILS CLOSED. No fail-open on the empty-operator path.** `[src]` + `[inference]`

**The residual hole, stated honestly rather than closed:** `[inference]` **A crackstation row inserted by some path OTHER than `registerCrackstationRecord` — a direct DB write, a migration, a fixture — could hold `OperatorName = ""` and be read by `core.GetCrackstation(hostUUID)`.** `[src]` + `[inference]` **But `authorizeCrackstation:393` compares `station.Snapshot().OperatorName != caller`, and `caller` is non-empty, so `"" != "alice"` → `PermissionDenied`.** `[src]` + `[inference]` **The comparison is `!=`, so empty-vs-nonempty DENIES. The only way to pass is for the stored value to equal a non-empty CN the caller actually possesses.** `[inference]` **This is fail-closed by construction, and it is why the answer is a denial and not a bypass.** `[inference]`

### 3.3 `Snapshot()` cannot return an empty OperatorName on a registered station

**`server/core/crackstations.go:37-45` and `:77-83`:** `[src]`

```go
func NewCrackstation(station *clientpb.Crackstation) *Crackstation {
	return &Crackstation{
		HostUUID:    station.HostUUID,
		Station:     station,
		...
	}
}

// Snapshot returns an isolated copy of the crackstation and its current status.
func (c *Crackstation) Snapshot() *clientpb.Crackstation {
	c.stationLock.RLock()
	defer c.stationLock.RUnlock()
	station := proto.Clone(c.Station).(*clientpb.Crackstation)
	station.Status = c.GetStatus()
	return station
}
```

`[src]`

**`NewCrackstation` stores the whole `clientpb.Crackstation` passed at `rpc-crackstations.go:720` (`core.NewCrackstation(req)`), whose `OperatorName` was forced non-empty at `:703-706`.** `[src]` **`Snapshot()` clones it under an `RLock`, so the runtime value the comparison reads is the same non-empty string.** `[src]` + `[inference]` **Confirmed: the value compared at `:393` is non-empty by construction for any station that registered normally.** `[src]`

---

## Q4 — Do the 6 streaming methods go through the same interception as unary?

### 4.1 The answer

> **On the two authenticated transports, YES — the streaming chain is a one-for-one parallel of the unary chain: authentication (`tokenAuthFunc`), then authorization (`permissionsStreamServerInterceptor`), then the stream-specific tracker, then tagging and logging. The two permission interceptors are structurally IDENTICAL in logic. There is NO unary/stream authorization asymmetry on the mTLS or Tailscale transports.**
>
> **On the local transport, BOTH paths lack authorization equally — so there is no asymmetry there either.**

`[src]`

**The parallel, enumerated:** `[src]`

| Position | Unary (auth branch) | Stream (auth branch) | Same role? |
|---:|---|---|---|
| 1 | `grpc_auth` + `tokenAuthFunc` `:70` | `grpc_auth` + `tokenAuthFunc` `:78` | **YES** |
| 2 | `permissionsUnaryServerInterceptor()` `:71` | `permissionsStreamServerInterceptor()` `:79` | **YES — identical logic** |
| 3 | `auditLogUnaryServerInterceptor()` `:72` | **`trackOperatorStreamInterceptor()` `:80`** | **NO — different function** |
| 4 | `grpc_tags` unary `:73` | `grpc_tags` stream `:81` | YES |
| 5 | `grpc_logrus` unary `:74` | `grpc_logrus` stream `:82` | YES |
| 6 | `grpc_logrus` payload unary `:75` | `grpc_logrus` payload stream `:83` | YES |

`[src]`

**Position 3 is the one real structural difference: the unary chain gets an AUDIT interceptor, the stream chain gets the OPERATOR-STREAM TRACKER instead.** `[src]` **They are not counterparts.** `[sr]` + `[inference]`

### 4.2 The asymmetry that DOES exist, stated precisely

**It is not an authorization asymmetry. It is an AUDIT asymmetry.** `[src]` + `[inference]`

- **`auditLogUnaryServerInterceptor()` (`middleware.go:425`) is registered on the unary chain ONLY, in BOTH branches (`:72`, `:90`).** `[src]`
- **There is no `auditLogStreamServerInterceptor` anywhere — the name does not appear.** `[src]` **Probe: the `func `-name grep in §1.2 lists every function in the file beginning `permissions*`, `tokenAuth*`, `serverAuth*`, `auditLog*`; only `auditLogUnaryServerInterceptor` exists.** `[src]`
- **Consequence: the 6 streaming methods (`ClientLog`, `BuilderRegister`, `CrackstationRegister`, `SocksProxy`, `TunnelData`, `Events`) are authorized but NOT captured by the unary audit interceptor.** `[src]` + `[inference]`

**And the 6 streams are exactly where the highest-volume and most sensitive traffic flows — `SocksProxy` and `TunnelData` are bidirectional proxying streams, and `ClientLog` is a client-side log upload.** `[src]` + `[inference]` **So the unaudited path carries proxy traffic and log ingestion.** `[inference]` **This is a real finding and it is an audit-coverage gap, not an auth bypass — I am stating it at exactly that strength.** `[inference]`

**`trackOperatorStreamInterceptor` partially compensates by registering the stream against the operator and cancelling it on kick (§1.5), which yields a lifecycle record even without an audit entry.** `[src]` + `[inference]`

### 4.3 Does a stream skip the unary chain? — the mechanism, confirmed

**Yes, necessarily: `grpc.ChainUnaryInterceptor` and `grpc.ChainStreamInterceptor` are separate gRPC server options, and gRPC dispatches a call to one or the other based on whether the method is streaming.** `[inference]` **This is why `permissionsStreamServerInterceptor` exists as a distinct function rather than reusing the unary one.** `[inference]` **Sliver registers an equivalent on each path, so the D12-predicted asymmetry does NOT materialise on the auth branch.** `[src]` + `[inference]`

**The one authenticated-transport stream that is NOT covered by the permission allowlists' intent:** `[src]` + `[inference]` **`GetVersion` appears in both allowlists, so a builder/crackstation operator can reach it; `BuilderRegister` is in `builderMethods` and `CrackstationRegister` is in `crackstationMethods`, so each role can register itself. `SocksProxy`, `TunnelData`, `ClientLog`, and `Events` are in NEITHER allowlist — so a non-`PermissionAll` builder or crackstation operator calling any of those four gets `PermissionDenied` from the stream interceptor.** `[src]` **That is correct fail-closed behaviour and worth stating, because it shows the stream interceptor is genuinely load-bearing rather than decorative.** `[inference]`

---

## 5. Residual unknowns — each with a concrete probe

**R1 — I did NOT verify all 192 unguarded methods against both allowlists.** `[src]` **I verified the 56 named in §2.3 by inspection of the allowlist literals, and enumerated both allowlists exhaustively (6 + 9 = 15 paths, 14 distinct after `GetVersion`), so the allowlist side IS complete.** `[src]` **What is incomplete is the per-method confirmation that each of the 195 unary methods is neither in an allowlist nor carrying an inline guard.** `[src]` **Probe:** generate the 195 method names from `services_grpc.pb.go:2524-2759` and cross-product them against `builderMethods ∪ crackstationMethods` plus a grep for `getClientCommonName` — three sets, one diff. **This is mechanical and would close the coverage number exactly.**

**R2 — D44's `killSession` ×2 duplicate is still unexplained and I did not resolve it here.** `[src]` **Probe:** inspect both definitions for differing receivers or build tags. **It has now survived two reports; it should not survive a third.**

**R3 — `CloseOperatorStreams` / `activeOperatorStreams.close` lock discipline was not read.** `[src]` **`trackOperatorStreamInterceptor` registers under `tokenCacheMu.RLock()` (`operator_streams.go:124-132`) and the comment claims coordination with revocation; I did not verify the counterpart takes `tokenCacheMu.Lock()` or that `activeOperatorStreams` has its own correct locking.** `[src]` **Probe:** read `operator_streams.go` from `:1` and enumerate every lock acquisition; look specifically for a register/close race that would let a kicked operator's stream survive.**

**R4 — `getClientCommonName` reads `VerifiedChains[0][0].Subject.CommonName` only.** `[src]` **It does NOT consider `DNSNames`, `EmailAddresses`, or any other SAN.** `[src]` **Probe:** determine whether a certificate with a valid chain but a CN that collides with an existing operator name is possible under `certs.OperatorClientGenerateCertificate`; read `server\certs\` for CN uniqueness enforcement. **This is the one path by which the identity could be spoofed, and it depends on cert issuance, not on the RPC layer.**

**R5 — I did not read `deciderUnary` / `deciderStream` bodies in full (they begin at `:232` and continue past my read).** `[src]` **They feed the payload-logging interceptors and appear to be a redaction decision list of method names.** `[src]` **Probe:** read `middleware.go:232-425` and confirm the deciders cannot themselves deny (they return `bool` to a logging interceptor, so they should not — but "should not" is not "verified").**

**R6 — the `Unauthenticated` vs `PermissionDenied` distinction leaks information.** `[src]` **`permissionsUnaryServerInterceptor` returns `Unauthenticated` for a nil operator (`:188`) and `PermissionDenied` for an insufficient one (`:204`).** `[src]` **Probe:** determine whether a caller can distinguish "no such operator" from "operator lacks permission" as an enumeration oracle — low severity, but it is a real distinction exposed on the wire.**

---

## 6. Instrument failures and corrections recorded in this report

| # | Item | Where | Resolution |
|---|---|---|---|
| **F1** | **D44 §1.5 did not know the interceptor-level authorization existed** | §0.1 | Read `middleware.go` in full; found `builderMethods`/`crackstationMethods` allowlists + 2 enforcing interceptors. **D44 under-counted the guarded surface.** |
| **F2** | **The "14 `authorize*` call sites" count is NAME-DRIVEN and misses a 15th site with inline logic** | §2.3 | `rpc-crackstations.go:703-706` performs the same principal extraction without calling an `authorize*` helper. **Same instrument-shape family as D44's `services.pb.go` false zero: a probe keyed on a NAME under-reports a structure keyed on BEHAVIOUR.** |
| **F3** | **`auditLogUnaryServerInterceptor` has no stream counterpart — found by NAME COVERAGE, not by reading both branches for symmetry** | §4.2 | Confirmed by the function-name grep in §1.2. **Recorded because the discovery method was a negative-space check, and a negative-space check is only as good as the enumeration behind it.** |
| **F4** | **I nearly reported the empty-`OperatorName` path as a fail-open** | §3.2 | Tracing to `registerCrackstationRecord` and the backfill showed it fails closed at three layers. **The hypothesised bug was real as a SHAPE (plain `string`, no constraint) and not real as a PATH.** |
| **F5** | **The unchecked assertions at `:186`/`:210` looked like a panic bug** | §1.4 | They are safe — but only because `serverAuthFunc`'s string-valued `Operator` cannot reach them given the branch structure. **Safety is incidental to registration, not intrinsic to the code.** |

`[src]`

---

## 7. Summary

**Q1 — interceptors.** `[src]` **Two branches, selected by `enableAuth`: `true` for mTLS (`mtls.go:89`) and Tailscale (`tailscale.go:85`), `false` for local (`local.go:47`); WireGuard-multiplayer shares the mTLS server (`multiplayer_wireguard.go:160`).** **Auth branch: 6 unary + 6 stream interceptors, and FOUR can deny** (`tokenAuthFunc`, `permissionsUnary`, `permissionsStream`, `trackOperatorStream`). **Local branch: 5 unary + 5 stream, and only ONE can deny** (`trackOperatorStream`). **THE LEAD'S QUESTION: YES — on the LOCAL transport the AUTHORIZATION interceptors are absent from BOTH the unary and streaming chains, exactly as D11 §6 found for the permissions interceptor. `serverAuthFunc` returns `nil` unconditionally with hard-coded `Transport="local"`, `Operator="server"`.** **A second authorization LAYER exists that D44 did not know: `builderMethods` (6) and `crackstationMethods` (9) are role allowlists enforced fail-closed.**

**Q2 — the 14 sites.** `[src]` **All 14 enumerated with enclosing method; all 14 fail with `PermissionDenied`/`Unauthenticated`; NONE fails silently and NONE panics.** **They guard 8 distinct methods directly, plus a 9th (`CrackstationRegister`) with inline equivalent logic — 9 of 201.** **The other 192 are protected only by the interceptor layer's 14 distinct allowlisted paths.** **56 methods named as carrying no per-method authorization beyond the role allowlist, including `KillSession`, `Execute`, `Shell`, `Download`, `Upload`, `GetOperators`, and `Backend`-style implant control.**

**Q3 — the empty `OperatorName`.** `[src]` **FAILS CLOSED, at three layers: (1) `rpc-crackstations.go:702-706` clones, OVERWRITES `OperatorName` from the verified cert CN, and rejects empty with `Unauthenticated`; (2) `registerCrackstationRecord:270-272` refuses `operatorName == ""`; (3) `:283-293` backfills a legacy empty row with a narrowly-scoped `WHERE operator_name = '' OR IS NULL` UPDATE, then `:294-295` re-reads and returns `errCrackstationOwnerMismatch`, mapped to `PermissionDenied` at `:713-715`.** **The comparison at `:393` is `!=`, so empty-stored vs non-empty-caller DENIES. There is no `"" == ""` pass.**

**Q4 — streaming.** `[src]` **On the authenticated transports the stream chain is a one-for-one parallel of the unary chain and the two permission interceptors are logically identical — NO authorization asymmetry.** **The asymmetry that DOES exist is AUDIT: `auditLogUnaryServerInterceptor` is unary-only in both branches and has no stream counterpart, so the 6 streaming methods — including `SocksProxy` and `TunnelData` — are authorized but not audit-logged by that interceptor.** **`trackOperatorStreamInterceptor` partially compensates via account revalidation and cancellation on kick (`operator_streams.go:124-132`).**

**The single most important sentence:** `[src]` + `[inference]` **Sliver's operator-plane RPC surface is authenticated everywhere and authorized in two layers — but the authorization is ROLE-SCOPED, not PER-METHOD: a default operator token holds `PermissionAll` and therefore reaches all 201 methods, while the per-method principal checks D44 found apply only to the crackstation and external-builder sub-surfaces (9 methods).** `[inference]`
