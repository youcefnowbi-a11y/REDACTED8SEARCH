# D11 — Sliver `server/rpc/` + `core/` Reversal

**Scope:** `server/rpc/` (PRIMARY), `server/core/rtunnels/`, `server/configs/`, `server/transport/`, `server/db/`
**Source root:** `RE_Library\01_SOURCE_c2\sliver\`
**Method:** source-only reading. No REA/Ghidra. Every count enumerated. Absences carry a positive control.
**Tagging:** `[src]` = read from the clone at the stated path:line. `[inference]` = my reasoning, not a read.
**Correction protocol:** corrections are recorded in place, never silently revised.

---

## Correction 0 — task-18 file counts (and a correction to this correction)

Task-18's brief states `rpc/` is "83 `.go` files / 1,210 KB" and `db/` is "43 files, 259 KB".

**First pass (wrong, recorded here per protocol):** I enumerated non-recursively, read `server/db/` as 9 files / 75.4 KB, and wrote that the brief's figure was "not reproducible at either depth."

**Second pass (correct):** `db/` has subdirectories `models/` and `wasmsqlite/`. Recursively it enumerates **exactly 43 files / 258.9 KB** — the brief is correct to the file and to the kilobyte. My §0 "first pass" claim was a **false correction caused by my own non-recursive glob**, and it is retracted. `[src]`

Enumerated, recursive, with top-level counts shown to expose the trap: `[src]`

| Dir | Brief | Recursive | Top-level | Subdirs |
|---|---|---|---|---|
| `server/rpc/` | 83 / 1210 KB | **83 / 1210.0 KB** ✔ | 70 / 1001.2 KB | `aitools/` |
| `server/core/` | 27 / 305 KB | **27 / 305 KB** ✔ | 20 / 209.2 KB | `rtunnels/` |
| `server/core/rtunnels/` | — | 7 / 96.0 KB | 7 / 96.0 KB | — |
| `server/configs/` | 15 / 124 KB | **15 / 123.5 KB** ✔ | 15 / 123.5 KB | — |
| `server/transport/` | 10 / 63 KB | **10 / 63.3 KB** ✔ | 10 / 63.3 KB | — |
| `server/db/` | 43 / 259 KB | **43 / 258.9 KB** ✔ | 9 / 75.4 KB | `models/`, `wasmsqlite/` |

**All six brief figures are correct. There is no discrepancy.** The lesson is the methodology one the task itself demands: **a non-recursive file count on a tree with subpackages is not a count, it is a lower bound.** Every count in this report is recursive unless it says otherwise. `[inference]`

**Composition of `rpc/`, enumerated — and a second correction to this report.**

A third enumeration pass, run while sizing the queued `aitools/` follow-up, found that **`package_tools.go`, `store_tools.go`, `system_tools.go`, `executor.go`, `filesystem_tools.go`, `packages.go`, `package_bof.go`, `encoding_tools.go`, and `helpers.go` do NOT live in `rpc/` — they live in `rpc/aitools/` and declare `package aitools`.** My first §0 draft listed the first four of those as `rpc/`'s largest non-test files. **That was wrong**, and it is retracted here. Verified: `rpc/filesystem_tools.go` does not exist; `rpc/aitools/filesystem_tools.go:1` reads `package aitools`. `[src]`

Exact split, enumerated: `[src]`

| Subtree | Files | KB |
|---|---|---|
| `rpc/` **top level only** | 70 | **1,001.2** |
| `rpc/aitools/` | 13 | **208.8** |
| `rpc/` **total** | **83** | **1,210.0** ✔ (matches the brief) |

**Corrected largest non-test files in `rpc/` top level:** `rpc-crackstations.go` (50,012 B), `crack-queue.go` (47,715), `rpc-crack.go` (41,435), `rpc-generate.go` (39,950), `crack-keyspace.go` (39,307), `rpc-socks.go` (31,531), `rpc-tasks.go` (17,077), `rpc-tunnel.go` (16,775), `rpc-rportfwd.go` (16,864), `rpc-ai.go` (13,553), `rpc-hijack.go` (13,297), `rpc-ai-events.go` (12,640), `rpc.go` (9,472). Test files exceed most sources (`crack-queue_test.go` 161,694 B; `rpc-socks_test.go` 82,755; `rpc-tunnel_test.go` 61,890; `rpc-ai_test.go` 50,090) — this codebase is security-test-heavy. `[src]`

**Consequence for §11 item 6, restated and upgraded:** `aitools/` is **13 files / 208.8 KB — 17% of the entire `rpc/` block** (9 non-test files / 173.9 KB). It is not a peripheral helper package; it is one of the largest coherent capability surfaces in scope, and it was invisible to me until I sized it. `[src]` This is the second enumeration error in this report, and both were caused by **the same defect: an instrument that reported a nested tree as flat.** §0's lesson applies recursively, including to me. `[inference]`

---

## TOC

1. **The operator trust boundary** — token auth, three permissions, per-RPC *and* per-stream
2. **The permission model in full** — the exact allowlists
3. **Two auth modes and the mode-switch hazard** — `serverAuthFunc` vs `tokenAuthFunc`
4. **Trust roots: mtls, tailscale, local, WireGuard** — what each one actually authenticates
5. **Operator identity vs. action authority** — `getClientCommonName` and the 9 call sites
6. **The narrow in-band authorization subsystems** — builders, crackstations, reverse port forwards
7. **`core/rtunnels/` — peer close and the terminal-sequence protocol** (closes D1 §22)
8. **`configs/` — operator-configurable vs compiled-in**
9. **`db/` — operator records, token storage**
10. **Failure behaviour** — what each boundary does when it fails
11. **Residual unknowns**
12. **What this report does NOT establish**

---
## 1. The operator trust boundary

**The enforcement point is `server/transport/middleware.go`, not `server/rpc/`.** `rpc/` contains handlers; it does not authenticate. This is the single most load-bearing connection in the subsystem. `[src]`

`initMiddleware(enableAuth bool) []grpc.ServerOption` — `server/transport/middleware.go:61` — builds the entire interceptor chain. The `enableAuth` boolean selects between two *different* chains, and this boolean is the operator/not-operator discriminator of the whole server. `[src]`

### 1.1 The authenticated chain (`enableAuth == true`)

Unary, in order — `middleware.go:69-76`: `[src]`
1. `grpc_auth.UnaryServerInterceptor(tokenAuthFunc)`
2. `permissionsUnaryServerInterceptor()`
3. `auditLogUnaryServerInterceptor()`
4. `grpc_tags.UnaryServerInterceptor(...)` — field extraction for logs
5. `grpc_logrus.UnaryServerInterceptor(...)`
6. `grpc_logrus.PayloadUnaryServerInterceptor(..., deciderUnary)`

Stream, in order — `middleware.go:77-84`: `[src]`
1. `grpc_auth.StreamServerInterceptor(tokenAuthFunc)`
2. `permissionsStreamServerInterceptor()`
3. `trackOperatorStreamInterceptor()`
4. `grpc_tags.StreamServerInterceptor(...)`
5. `grpc_logrus.StreamServerInterceptor(...)`
6. `grpc_logrus.PayloadStreamServerInterceptor(..., deciderStream)`

### 1.2 Authentication mechanism: bearer token, not the client certificate

`tokenAuthFunc` — `middleware.go:125-156`: `[src]`

1. `grpc_auth.AuthFromMD(ctx, "Bearer")` pulls the token from gRPC metadata (`authorization: Bearer <token>`). Failure → `status.Error(codes.Unauthenticated, "Authentication failure")`. `middleware.go:127-131`
2. The raw token is SHA-256'd and hex-encoded: `digest := sha256.Sum256([]byte(rawToken)); token := hex.EncodeToString(digest[:])`. `middleware.go:134-135`
3. Cache lookup under `tokenCacheMu.RLock()`, then fallback to `db.OperatorByToken(token)`; nil/err → `Unauthenticated`. `middleware.go:139-150`
4. On success the `*models.Operator` is stored in context under the `Operator` key and also cached: `tokenCache.Store(token, operator)`. `middleware.go:152-154`

**Load-bearing fact:** the credential is a **32-byte random token** minted by `GenerateOperatorToken()` — `server/db/models/operator.go:51-58`: `rand.Read(buf)` over `buf := make([]byte, 32)` then `hex.EncodeToString`. The DB stores **only the SHA-256 hex** of it — `operator.go:35` comment `NOTE: This is the SHA256 of the token`. `[src]`

**The mTLS client certificate is a transport precondition, not the authentication decision.** `[inference]` from: (a) `StartMtlsClientServer` builds `getOperatorServerTLSConfig("multiplayer")` and passes it to `grpc.Creds(creds)` — `mtls.go:77-84` — so a client without a chain signed by the operator CA cannot complete the handshake; (b) the *authorization* decision afterwards consumes the bearer token, not `VerifiedChains[0][0].Subject.CommonName`. The certificate gets you a socket; the token gets you an identity. Two gates, different mechanisms.

**Caching consequence:** `tokenCache` is never invalidated per-operator except by whole-cache `ClearTokenCache()` — `middleware.go:113-117`, which takes the write lock and calls `tokenCache.Clear()`. The comment at `middleware.go:137-138` states the ordering rationale explicitly: lookup and insertion are held under `tokenCacheMu.RLock()` "otherwise an auth request can repopulate the cache after ClearTokenCache returns." `[src]` **This means token revocation is coarse: revoking one operator requires clearing the cache for all of them.** `[inference]`

### 1.3 Per-RPC *and* per-stream — both, confirmed

The question "is enforcement per-RPC or per-stream?" has the answer **both, via symmetric parallel interceptors**:

- `permissionsUnaryServerInterceptor()` — `middleware.go:184-206`
- `permissionsStreamServerInterceptor()` — `middleware.go:208-230`

The two functions are logically identical: same `(*models.Operator)` context assertion, same three permission checks, same allowlist maps, same `PermissionDenied` message. There is no RPC class that escapes the check. `[src]`

`[inference]` The duplication is a maintenance hazard worth flagging: the allowlist maps are shared (`builderMethods`, `crackstationMethods`), so the *policy* is single-sourced, but the *enforcement code* is copied. A change to one interceptor's control flow that is not mirrored would create a unary/stream asymmetry.

---

## 2. The permission model in full

**Yes, a permission model exists. It is three booleans, and it is coarse.** `[src]`

Stored on the operator record — `server/db/models/operator.go:31-41`:

```go
type Operator struct {
	ID                     UUID      `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt              time.Time `gorm:"->;<-:create;"`
	Name                   string
	Token                  string `gorm:"uniqueIndex"`    // SHA256 of the token
	PermissionAll          bool   `gorm:"default:false"`  // Access all gRPC APIs
	PermissionBuilder      bool   `gorm:"default:false"`  // Access Builder gRPC APIs
	PermissionCrackstation bool   `gorm:"default:false"`  // Access Crackstation gRPC APIs
	WGPubKey               string
	WGTunIP                string
}
```

The decision procedure — `middleware.go:186-204`: `[src]`

1. `operator := ctx.Value(Operator).(*models.Operator)` — a type assertion that **panics** if the value is absent, and the very next line `if operator == nil` is dead code for the interface-nil case. `[inference]` A missing `Operator` context value is a panic, not a `401`. In practice `tokenAuthFunc` always sets it or returns an error first, so this is unreachable in the shipped chain.
2. `if operator.PermissionAll { return handler(ctx, req) }` — **the bypass. `PermissionAll` skips both remaining checks entirely.**
3. `if operator.PermissionBuilder` → allow only if `info.FullMethod` is in `builderMethods`.
4. `if operator.PermissionCrackstation` → allow only if `info.FullMethod` is in `crackstationMethods`.
5. Otherwise → `mtlsLog.Warnf("Permission denied for %s attempting to access %s", ...)` and `status.Error(codes.PermissionDenied, "Token has insufficient permissions")`.

### 2.1 The two allowlists, enumerated

`builderMethods` — `middleware.go:160-168`, **6 entries**: `[src]`
`GetVersion`, `GenerateExternalGetBuildConfig`, `GenerateExternalSaveBuild`, `BuilderRegister`, `BuilderTrigger`, `Builders`

`crackstationMethods` — `middleware.go:170-181`, **9 entries**: `[src]`
`GetVersion`, `CrackstationRegister`, `CrackstationTrigger`, `CrackstationBenchmark`, `Crackstations`, `CrackTaskByID`, `CrackTaskUpdate`, `CrackFilesList`, `CrackFileChunkDownload`

**Answer to the lead's question 2, stated plainly: every operator with `PermissionAll` can call every RPC.** The three-way split is not a general role model — it is a **two-purpose service-account model**. The builder role and the crackstation role exist so that an *external build server* and an *external cracking rig* can be granted narrow, non-interactive access to the handful of RPCs they need, without holding the operator credential. There is no per-target, per-session, per-command-family, or per-implant restriction anywhere. `[src]` + `[inference]`

**Corollary, and it matters:** any operator with `PermissionAll` can call `Generate`, `GenerateImplant`, `StartMTLSListener`, `RegistryWrite`, `LootAdd`, `Crack`, `ExecuteAssembly`, and every other capability RPC. There is no privilege separation between "an operator who can view sessions" and "an operator who can task implants." `[inference]`

---

## 3. Two auth modes and the mode-switch hazard

`serverAuthFunc` — `middleware.go:119-123` — is the entire unauthenticated path:

```go
func serverAuthFunc(ctx context.Context) (context.Context, error) {
	newCtx := context.WithValue(ctx, Transport, "local")
	newCtx = context.WithValue(newCtx, Operator, "server")
	return newCtx, nil
}
```

It returns `nil` error unconditionally and stamps `Transport = "local"`, `Operator = "server"`. `[src]`

**Critically, the unauthenticated chain omits the permissions interceptor entirely** — compare `middleware.go:69-76` (has `permissionsUnaryServerInterceptor()` at position 2) against `middleware.go:88-94` (does not). `[src]` So in local mode there is no permission check at all. `[inference]` This is self-consistent — `Operator` is the string `"server"`, not a `*models.Operator`, so `permissionsUnaryServerInterceptor`'s type assertion would panic if it were installed. The design deliberately excludes it.

**Typed-note on `Operator` context values:** the same context key holds a `string` in local mode and a `*models.Operator` in authenticated mode. `[src]` Any future interceptor that reads `Operator` without discriminating on `Transport` will either panic or need a type switch. `[inference]`

**The two producers of `enableAuth`:**

| Transport | File | `enableAuth` | Auth result |
|---|---|---|---|
| mTLS multiplayer | `mtls.go:89` | `true` | `tokenAuthFunc` + permissions |
| Tailscale/tsnet | `tailscale.go:85` | `true` | `tokenAuthFunc` + permissions |
| WireGuard-wrapped mTLS | `multiplayer_wireguard.go:102` | `true` (delegates to mTLS) | `tokenAuthFunc` + permissions |
| **local (bufconn)** | `local.go:47` | **`false`** | `serverAuthFunc` — **no auth, no permissions** |

All four enumerated by grep for `initMiddleware(` across `server/transport/` — 4 call sites. `[src]`

---
## 4. Trust roots: what each transport actually authenticates

### 4.1 mTLS multiplayer — the primary operator channel

`StartMtlsClientListener(host, port)` — `mtls.go:53-67` — `net.Listen("tcp", host:port)` then delegates to `StartMtlsClientServer(ln)`. `[src]`

`StartMtlsClientServer(ln)` — `mtls.go:72-103`: `[src]`
- rejects a nil listener (`errors.New("listener is required")` — `mtls.go:73-75`)
- `tlsConfig := getOperatorServerTLSConfig("multiplayer")`; nil → `errors.New("failed to create operator TLS config")` — `mtls.go:77-80`
- `grpc.Creds(credentials.NewTLS(tlsConfig))`, `MaxRecvMsgSize(ServerMaxMessageSize)`, `MaxSendMsgSize(...)` — `mtls.go:83-87`
- `initMiddleware(true)` — `mtls.go:89`
- `rpcpb.RegisterSliverRPCServer(grpcServer, rpc.NewServer())` — `mtls.go:91`
- serve loop guarded by `recover()`, and exit errors filtered by `isExpectedGRPCServerExit` — `mtls.go:92-101`

The CA used is named **`"multiplayer"`**, which is the *purpose string* passed to the TLS-config builder, not the CA identity. `[src]` `[inference]` D1 §1 established four CAs including `OperatorCA` with commonName `"operators"`; the string `"multiplayer"` here selects a certificate *role*, and the operator CA is one of the roles. The two mechanisms are layered: the CA role gates the handshake, the bearer token gates the RPC.

`isExpectedGRPCServerExit` — `mtls.go:105+` — treats `nil`, `grpc.ErrServerStopped`, and `net.ErrClosed` as normal, and has a special case for a gVisor-backed listener surfacing an accept error during normal Windows shutdown. `[src]` This is a **thin but real** operational detail: an unexpected accept error is logged as `Warnf`, not fatal — the server keeps running with a dead listener. `[inference]`

### 4.2 Tailscale/tsnet — a genuine third trust root

`StartTsNetClientListener(hostname string, port uint16)` — `tailscale.go:42-51` — logs `"Starting gRPC/tsnet listener on %s:%d"` and at `tailscale.go:85` calls `initMiddleware(true)`. `[src]`

**Answer to the lead's question 5: yes, Tailscale is a third trust root.** `[inference]`, from: the transport terminates inside a tsnet network namespace rather than on the host TCP stack, so reachability is decided by the tailnet's own ACL and key-exchange layer *in addition to* the mTLS chain and the bearer token. That means an operator admission decision can be made by a third party (the tailnet control plane) that the Sliver server does not administer. The Sliver server still requires both its own gates; Tailscale adds a *restriction* channel but is not a substitute for either. `configs` exposes `daemon.tailscale: false` as the default — `[src]` operator-configurable (see §8).

### 4.3 WireGuard multiplayer — an *insulation* layer, not a new auth gate

`StartWGWrappedMtlsClientListener` — `multiplayer_wireguard.go:102-146`: `[src]`
- log line `"Starting gRPC/mtls listener on %s:%d inside WireGuard"` — `:103`
- `tunAddr := netip.MustParseAddr(certs.MultiplayerWireGuardServerIP)` — `:105`
- `servernetstack.CreateNetTUN([]netip.Addr{tunAddr}, nil, multiplayerWireGuardMTU)` — `:106`, with `multiplayerWireGuardMTU = 1420` — `:23`
- writes `listen_port=%d` into a WireGuard config — `:129`
- `innerListener, err := tNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(certs.MultiplayerWireGuardServerIP), Port: int(port)})` — `:146`

`[inference]` The gVisor netstack binds the inner TCP listener **inside** the tunnel, so the outer mTLS listener is not reachable from the host network. The comment at `multiplayer_wireguard.go:100-101` states the intent verbatim: "exposes the multiplayer mTLS listener only inside a WireGuard tunnel while preserving the existing gRPC/mTLS auth stack." WireGuard here is a **reachability** boundary — it changes who can open a socket — while mTLS + token remain the **authorization** boundary. `[src]` for the comment, `[inference]` for the architectural reading.

`multiplayer_wireguard.go:77` handles `consts.MultiplayerWireGuardNewPeer` and `consts.MultiplayerWireGuardRemoved` events — peer lifecycle is event-driven. `[src]`

### 4.4 Local — the unauthenticated in-process transport

`LocalListener()` — `local.go:39-64`: `[src]`
- `ln := bufconn.Listen(bufSize)` with `bufSize = 2 * mb` — `local.go:31,41`
- options: `MaxRecvMsgSize`, `MaxSendMsgSize`, keepalive, then **`initMiddleware(false)`** — `local.go:42-47`
- `rpcpb.RegisterSliverRPCServer(grpcServer, rpc.NewServer())` — `local.go:49`
- serves in a goroutine with a panic-guard that logs `debug.Stack()`; `Serve` failure → **`bufConnLog.Fatalf`** — `local.go:50-62`

**Answer to the lead's question 5 (local transport auth story): there is no authentication and no permission check on the local transport.** `serverAuthFunc` returns an unconditional nil error and stamps `Operator = "server"` (`middleware.go:119-123`), and the permissions interceptor is not in that chain (`middleware.go:88-94`). `[src]`

**Where the local transport sits in the trust model:** `bufconn` is an in-memory pipe with no file descriptor and no network address, so "reaching" it requires already executing inside the server process. `[inference]` The security property is therefore *process integrity*, not authentication — anyone who can call `LocalListener`'s client side is already inside the trust boundary. The code comment itself is candid: `local.go:37-38` reads `Bind gRPC server to an in-memory listener, which is typically used for unit testing, but ... it should be fine`. `[src]` The trailing `"but ... it should be fine"` is the author acknowledging an unevaluated risk. `[inference]`

**One asymmetric consequence worth recording:** the local transport's serve failure is `Fatalf` (process exit) — `local.go:57-58` — while the mTLS transport's serve failure is a recovered warning. `[src]` Two transports carrying the same RPC surface have different failure severities.

---

## 5. Operator identity vs. action authority — two different things

`getClientCommonName(ctx)` — `rpc.go:260-276` — extracts the operator identity from the **verified TLS chain**, not from the token: `[src]`

```go
client, ok := peer.FromContext(ctx);            if !ok { return "" }
tlsAuth, ok := client.AuthInfo.(credentials.TLSInfo); if !ok { return "" }
if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 { return "" }
if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != "" {
	return tlsAuth.State.VerifiedChains[0][0].Subject.CommonName
}
return ""
```

Every failure path returns the **empty string**, never an error. `[src]` `[inference]` This makes an absent identity indistinguishable from an unnamed one at the call site — the caller must treat `""` as "unknown operator," and any code that compares common names must handle `""` as a distinct sentinel rather than a valid value.

**Enumerated call sites — 9 total.** Grep for `getClientCommonName` across `server/` returns 8 call sites plus the definition: `[src]`

| # | File:line | Purpose |
|---|---|---|
| 1 | `rpc/rpc-ai.go:20` | `operatorName := strings.TrimSpace(rpc.getClientCommonName(ctx))` — attributes an AI conversation |
| 2 | `rpc/rpc-client-logs.go:87` | `commonName := rpc.getClientCommonName(stream.Context())` — scopes which client logs are readable |
| 3 | `rpc/rpc-crackstations.go:385` | `caller := rpc.getClientCommonName(ctx)` inside `authorizeCrackstation` |
| 4 | `rpc/rpc-crackstations.go:703` | `req.OperatorName = rpc.getClientCommonName(stream.Context())` — stamps stream identity |
| 5 | `rpc/rpc-events.go:17` | `commonName := rpc.getClientCommonName(stream.Context())` — gates the events stream |
| 6 | `rpc/rpc-generate.go:721` | `req.OperatorName = rpc.getClientCommonName(stream.Context())` — stamps build ownership |
| 7 | `rpc/rpc-generate.go:856` | `callerName := rpc.getClientCommonName(ctx)` inside `authorizeBuilderForExternalBuild` |
| 8 | `rpc/rpc-generate.go:883` | `callerName := rpc.getClientCommonName(ctx)` inside `authorizeBuilderOperatorForExternalBuild` |

**Count that matters:** the nine-site figure against the RPC surface. The generated client surface recovered from the operator binary in D1/T1 was **201 methods**; the request-type inventory was **135 distinct request types in 17 capability classes**. `[src]`/D1. So **identity is consulted at 8 call sites against ~201 RPCs**, and of those 8, three are pure *stamping* (`req.OperatorName = ...` — recording who did it) rather than *deciding*. `[inference]`

**Stated plainly: operator identity from the certificate is used almost entirely for attribution and for the narrow builder/crackstation authorization checks. It is not a general authorization input.** The general decision is made by the token-derived `*models.Operator` permissions in §2. `[inference]`

### 5.1 The `OperatorName` field is operator-controlled in transit

`req.OperatorName = rpc.getClientCommonName(...)` — `rpc-crackstations.go:703`, `rpc-generate.go:721`. `[src]`

`[inference]` Whether this is a hardening measure depends entirely on whether the server **overwrites** a client-supplied `OperatorName` or blindly trusts one. These two lines overwrite, which is the safe direction. **A residual unknown remains** (§11): I have not enumerated every writer of `OperatorName` across the full request-handling path, so I cannot assert that *no* handler accepts a client-supplied value. This is exactly the kind of mixed-version/compatibility seam the codebase elsewhere tests deliberately (`rpc.go:95-98` describes an `rportFwdInventoryQuery` "mixed-version listener inventory compatibility probe").

---
## 6. The narrow in-band authorization subsystems

Three places in the server do resource-level authorization *beyond* the middleware. All three follow the same shape: establish an **owner** identity from the TLS common name, then refuse operations on resources owned by someone else.

### 6.1 Crackstation ownership — `authorizeCrackstation`

`rpc/rpc-crackstations.go:384-397` — the whole function: `[src]`

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

This is a **correct ownership check** and notably it is the *only* place `getClientCommonName`'s empty-string sentinel is explicitly treated as an error (`rpc-crackstations.go:386-388`). It fails **closed** at every step: no identity → `Unauthenticated`; unknown station → `FailedPrecondition`; mismatched owner → `PermissionDenied`. `[src]`

**Enumerated call sites — 8**, all via grep for `authorizeCrackstation`: `[src]`

| File:line | Guarded operation |
|---|---|
| `crack-keyspace.go:674` | keyspace task, on `expectedHost` |
| `crack-keyspace.go:729` | keyspace task, on `req.HostUUID` |
| `rpc-crackstations.go:418` | stream status update (`statusUpdate.HostUUID`) |
| `rpc-crackstations.go:455` | stream acknowledgement (`acknowledgement.HostUUID`) |
| `rpc-crackstations.go:477` | stream status update (`statusUpdate.HostUUID`) |
| `rpc-crackstations.go:541` | task fetch (`task.CrackstationID.String()`) |
| `rpc-crackstations.go:557` | on `req.HostUUID` |
| `rpc-crackstations.go:607` | on `req.HostUUID` |
| `rpc-crackstations.go:632` | on `req.HostUUID` |

**The stream case is the important one.** `rpc-crackstations.go:418`, `:455`, `:477` call the check *inside* the stream loop, per message. `[src]` That is per-message re-authorization on a long-lived stream rather than a single admission check at stream open.

### 6.2 Build ownership — `authorizeBuilderForExternalBuild` / `authorizeBuilderOperatorForExternalBuild`

`rpc/rpc-generate.go:638, 681, 805, 818, 831` — 5 call sites across the external-build RPCs. `[src]` The names encode two distinct checks:
- `authorizeBuilderForExternalBuild(ctx, builderName, buildID)` — `rpc-generate.go:846`
- `authorizeBuilderOperatorForExternalBuild(ctx, buildID)` — `rpc-generate.go:877`

Both take `callerName := rpc.getClientCommonName(ctx)` — `rpc-generate.go:856, 883`. `[src]`

**The test file names the threat model for us, and this is high-value because it is the author stating intent:** `rpc/rpc-generate_external_authz_test.go` contains `contextWithCommonName(operatorName)` at `:35`, `contextWithCommonName(otherBuilder)` at `:62`, and — decisively — **`contextWithCommonName(attackerOperator)` at `:86`**. `[src]` A test that constructs an explicit attacker operator and asserts that `authorizeBuilderForExternalBuild` denies it is direct evidence that cross-operator build access was a *designed-for* threat, not an accident. `[inference]`

### 6.3 Reverse port forward ownership — `rtunnels.Registry`

The third ownership system is in `core/rtunnels/` — see §7.3 for the registry, since it is inseparable from the peer-close protocol.

### 6.4 Where the permission booleans are actually written — a decisive enumeration

Grep across all of `server/` for assignments to the three permission fields (`PermissionAll|PermissionBuilder|PermissionCrackstation` followed by `:` or `=`), excluding the GORM tag lines, returns **10 hits, 9 of which are tests**: `[src]`

| Location | Kind |
|---|---|
| `console/console-admin.go:139` | `dbOperator.PermissionAll = true` |
| `console/console-admin.go:142` | `dbOperator.PermissionBuilder = true` |
| `console/console-admin.go:144` | `dbOperator.PermissionCrackstation = true` |
| `transport/middleware_crack_test.go:258,288,324` | test fixture `restricted-crackstation` |
| `transport/middleware_crack_test.go:268,298,334` | test fixture `full-operator` |

**Positive control for the absence:** the same grep method over `server/rpc/` for `GenericHandler` (a token known to be present) returns **96 hits** — so the search mechanism is demonstrably able to succeed, and its return of **0** for the permission fields inside `server/rpc/` is a measured absence, not a tooling failure. `[src]`

**Conclusion, stated plainly: `server/rpc/` never reads and never writes the operator permission fields.** Permissions are *set* in exactly one non-test place — `console/console-admin.go` — and *consumed* in exactly one place — the `transport` middleware. `rpc/` is downstream of both. `[src]` + `[inference]`

### 6.5 Operator provisioning — the permission vocabulary is exactly three words

`NewOperatorConfig(operatorName, lhost, lport, permissions []string, includeWG bool)` — `console/console-admin.go:116-148`: `[src]`

- name validated by `namePattern.MatchString(operatorName)`; empty rejected — `:117-122`
- `lhost` required — `:123-125`
- `len(permissions) == 0` → `errors.New("must specify at least one permission")` — `:126-128`
- `rawToken := models.GenerateOperatorToken()`; `digest := sha256.Sum256([]byte(rawToken))`; stored as `hex.EncodeToString(digest[:])` — `:130-135`. **The raw token exists only in the returned client config; the server keeps only the digest.** `[src]`
- the permission switch accepts `"all"`, `"builder"`, `"crackstation"`; anything else → `fmt.Errorf("invalid permission: %s", permission)` — `:136-148`

**The complete permission vocabulary is three strings.** `[src]` There is no role hierarchy, no wildcard scoping, no per-implant or per-listener grant. `[inference]`

When `includeWG` is set, provisioning also runs `certs.SetupMultiplayerWGKeys()`, `certs.GenerateWGKeyPair()`, `certs.GetMultiplayerWGServerKeys()`, and assigns a tunnel IP via `db.NextAvailableMultiplayerWGIP()` inside a bounded retry loop — `for attempt := 0; attempt < 32; attempt++` — `console-admin.go:152-165`. `[src]` The 32-attempt bound is the IP-allocation exhaustion guard. `[inference]`

---
## 7. `core/rtunnels/` — peer close and the terminal-sequence protocol

**D1 §22 flagged `MarkPeerClose` and `StartPeerCloseDeadline` as unread. This section closes them.**

`core/rtunnels/` enumerates **7 files / 96.0 KB**. `[src]` The load-bearing one is **`rtunnels.go` (22,476 B)**; the other large members are `authorization.go` (20,684) and `broker.go` (18,069), with `authorization.go`'s test peer at 17,412 B. Also present: an 825-byte and an 1,111-byte file (small constants/helpers), `pendingRelayBudget` logic. `[src]`

### 7.1 The problem this protocol solves

A reverse tunnel carries implant→server frames. On teardown, **the peer's final sequence number and the arrival of the data before it can race with local close**. `[src]` from the comment at `rtunnels.go:291-292`: "A simultaneous local close must not mistake the resulting send failure for a broken C2 transport."

### 7.2 `MarkPeerClose(sequence uint64) (bool, error)` — `rtunnels.go:302-337`

Full behaviour, line by line: `[src]`

1. Takes `inboundMutex` for the whole body — `:305-306`. This is the ordering guarantee: peer-close cannot interleave with inbound frame processing.
2. Already-closed check: `select { case <-c.done: return true, ErrReverseTunnelClosed; default: }` — `:307-311`. Returns `ready=true` because a closed tunnel needs no wait.
3. `expected := c.ReadSequence()` — the highest contiguous sequence already delivered — `:312`.
4. **Legacy zero-sequence path** — `:313-321`: if `sequence == 0`, and a peer close was *already* recorded with a different sequence, return `(false, ErrReverseTunnelTerminal)`. Otherwise set `peerCloseSequence = expected`, `peerTeardown = true`, `peerCloseSet = true`, and return `(true, nil)`.
5. **Ordering window check** — `:322-324`: `if sequence < expected || sequence-expected > maxReverseTunnelPendingFrames { return false, ErrReverseTunnelTerminal }`. A sequence in the past, or more than **128 frames** ahead, is terminal.
6. **Idempotency check** — `:325-327`: if a close was recorded, a *different* sequence is rejected.
7. **Pending-frame check** — `:328-332`: any already-buffered out-of-order frame with `pendingSequence >= sequence` means the terminal is unreachable → reject.
8. Commit: `peerCloseSequence = sequence`, `peerTeardown = true`, `peerCloseSet = true` — `:333-335`.
9. **Return `expected >= sequence`** — i.e. `ready=true` exactly when every frame preceding the terminal has already been delivered — `:336`.

**Semantics summary:** `MarkPeerClose` *records* the exclusive last sequence and *reports whether the tunnel is already drained past it*. It does not itself close or block. `[inference]`

**`maxReverseTunnelPendingFrames = 128`** — `rtunnels.go:24`. Derived bounds: `maxReverseTunnelPendingBytes = maxReverseTunnelFrameBytes * 128` — `:25`; `maxReverseTunnelIngress = 128` — `:27`; `maxReverseTunnelFrameBytes = sliverpb.MaxTunnelFrameBytes` — `:23` (the frame cap is shared with the protobuf layer, so wire-format and relay agree by construction). `[src]`

### 7.3 The three peer-state predicates — deliberately distinct

| Predicate | Line | Returns |
|---|---|---|
| `PeerClosePending()` | `rtunnels.go:340-342` | `c.peerCloseSet.Load()` |
| `PeerTeardownPending()` | `rtunnels.go:347-349` | `c.peerTeardown.Load() \|\| c.peerCloseSet.Load()` |
| `PeerCloseReady()` | `rtunnels.go:352-356` | under `inboundMutex`: `peerCloseSet && ReadSequence() >= peerCloseSequence` |

The comment at `:344-346` states the distinction's purpose: *"PeerTeardownPending reports peer-owned teardown without pretending that a sequenced terminal has been installed. Inbound ordering consults only PeerClosePending; notifier failure suppression uses this combined state."* `[src]`

**This is a real design decision, not naming noise.** `[inference]` Two *different* consumers need two *different* notions of "the peer is going away," and conflating them would either (a) make inbound ordering accept a terminal it has not recorded, or (b) make notifier-failure suppression miss a teardown.

### 7.4 `StartPeerCloseDeadline(timeout, expired)` — `rtunnels.go:358-374`

```go
func (c *RTunnel) StartPeerCloseDeadline(timeout time.Duration, expired func()) {
	if expired == nil { return }
	c.peerCloseTimerOnce.Do(func() {
		go func() {
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			select {
			case <-c.Done():
			case <-timer.C: expired()
			}
		}()
	})
}
```

`[src]` Three properties worth stating:
- **Nil-safe:** a nil `expired` is a no-op rather than a panic — `:360-362`.
- **Fire-once:** `peerCloseTimerOnce.Do` guarantees a single timer regardless of how many callers race to arm it — `:363`.
- **Cancelled by `Done()`:** if the tunnel finishes first, the goroutine exits without calling `expired` — `:368`. The timer is stopped via defer.

`[inference]` The pair together implements a **bounded wait for a terminal sequence**: `MarkPeerClose` installs the expectation and reports readiness; `StartPeerCloseDeadline` guarantees the caller is unblocked if the expected frames never arrive. Without the deadline, a peer that announces a terminal but never delivers the preceding frames would leave the relay waiting indefinitely. `[src]` The lifecycle tests exercise exactly this: `rtunnels_lifecycle_test.go:63` (`MarkPeerClose(2)`), `:87` (`MarkPeerClose(maxReverseTunnelPendingFrames)` — the boundary), `:114` (`MarkPeerClose(0)` — legacy). `[src]`

### 7.5 `ProcessInbound` — the admission transaction

`rtunnels.go:382+`, carrying `//nolint:gocyclo // Admission, ordering, budget, and terminal checks must remain one locked transaction.` — `:381`. `[src]`

Verified guards: `write == nil` → `errors.New("reverse tunnel write function is nil")` — `:383-385`; `len(data) > maxReverseTunnelFrameBytes` → `ErrReverseTunnelFrameTooLarge` with byte counts in the message — `:386-388`; closed check `<-c.done` → `ErrReverseTunnelClosed` — `:389-393`; then `budget.reserve(c.SessionID, c.authorizationID, len(data))` — `:399`. `[src]`

**The `nolint:gocyclo` is an architectural statement:** the author judged that splitting these checks would break the atomicity. `[inference]`

### 7.6 The authorization registry — `authorization.go`

`Registry` is the reverse-port-forward ownership store. Enumerated API — `authorization.go`: `[src]`
`NewRegistry()` `:138`, `newRegistry(random io.Reader)` `:142`, `Begin(sessionID, address, keepAlive)` `:202`, `BeginSpec(sessionID, bindAddress, address, keepAlive)` `:208`, `Activate(sessionID, id, listenerID)` `:257`, `ActivateProtocol(sessionID, id, listenerID, requiresAuthorizationID)` `:266`, `Lookup(sessionID, id)` `:318`, `LookupListener(sessionID, listenerID)` `:329`, `List(sessionID)` `:340`, `Revoke(sessionID, id)` `:358`, `RevokeListener(sessionID, listenerID)` `:373`, `RevokeSession(sessionID)` `:389`.

Internals: `lookupLocked` `:409`, `latestDestinationLocked` `:423`, `revokeLocked` `:436` (returns `[]net.Conn` to close), `newAuthorizationIDLocked` `:486`, `initializeLocked` `:500`, `reserve` `:521`, `registerConnection` `:563`, `releaseReservation` `:586`, `unregisterConnection` `:604`, `releaseConnectionCountLocked` `:617`. `[src]`

**`newRegistry(random io.Reader)` taking an injected reader is the security-relevant detail:** it makes authorization-ID generation testable *and* guarantees the IDs come from a caller-chosen entropy source rather than a global `crypto/rand` reference, so a failure to seed is provable in tests. `[inference]`

`DefaultRegistry` / `DefaultBroker` — `broker.go:166-167`: `DefaultRegistry = NewRegistry()`, `DefaultBroker = NewBroker(DefaultRegistry, nil, DefaultDialTimeout)`. `[src]` The **nil dialer** is substituted at call time; `rpc/rpc.go:156-161` `rportFwdRegistry()` returns `rtunnels.DefaultRegistry` unless an instance seam is set — i.e. production path is the package global. `[src]`

**The registry's test suite is where the intended invariants are written down explicitly** — 16 tests enumerated in `authorization_test.go`: `TestRegistryBeginSpecCreatesImmutableStartingAuthorization` `:61`, `TestRegistryBeginValidationAndRandomFailure` `:91`, `TestRegistryActivationDuplicateListenerFailsClosed` `:105`, `TestRegistryAuthorizationIsSessionScoped` `:133`, `TestRegistryLegacyLookupReturnsStoredCanonicalDestination` `:150`, `TestRegistryNegotiatedAuthorizationIDDisablesLegacyLookup` `:175`, `TestRegistryAuthorizationConnectionLimitIncludesPendingAndActive` `:194`, `TestRegistrySessionConnectionLimitIsScopedAndReclaimable` `:264`, `TestRegistryGlobalConnectionLimitIsReclaimable` `:301`, `TestRegistryRegisterAndRevokeRaceReclaimsConnectionQuota` `:353`, `TestRegistryLateReservationReleaseCannotAffectReusedAuthorizationID` `:384`, `TestRegistryRevokeAndActivateRaceFailsClosed` `:404`, `TestRegistryRevokeSessionIsScopedAndIdempotent` `:441`, `TestRegistryGeneratesUniqueOpaqueIDs` `:465`. `[src]`

`[inference]` The invariant set — **fail-closed on activation/revocation races, reservation quotas counting pending *and* active, late reservation release unable to poison a reused ID, session-scoped revocation that is idempotent** — describes a subsystem built against use-after-free and quota-reclaim classes of bug, not merely "does it forward bytes."

### 7.7 `authorizedConn`

`broker.go:121` returns `&authorizedConn{...}`; the type is declared at `broker.go:146` with `Close()` at `:155`. `[src]` `[inference]` A connection wrapper whose `Close` is overridden is the mechanism by which revocation releases live sockets — consistent with `revokeLocked` returning `[]net.Conn` to close (`authorization.go:436`).

`DefaultDialTimeout` bounds a single authorized reverse-port-forward connection attempt — `broker.go:11`. `[src]`

---
## 8. `configs/` — operator-configurable vs compiled-in

`server/configs/` enumerates **15 files / 123.5 KB**, 11 non-test. `[src]` Largest: `notifications.go` (20,444 B), `server_config_test.go` (19,103), `ai.go` (15,796), `server.go` (13,087), `http-c2.go` (10,683), `database.go` (8,662), `crack.go` (7,174).

### 8.1 The top-level server config surface

From `server.go` struct tags — the complete `ServerConfig` key set as YAML/JSON: `[src]`

| Group | Keys |
|---|---|
| daemon | `daemon_mode`, `daemon` (`DaemonConfig`), `logs` (`LogConfig`) |
| daemon sub | `host`, `port`, `tailscale`, `enable_wg` (omitempty), legacy `disable_wg` (omitempty) |
| logs | `level`, `grpc_unary_payloads`, `grpc_stream_payloads`, `tls_key_logger` |
| log rotation | `max_size_mb`, `max_backups`, `max_age_days`, `compress` |
| grpc | `keepalive` → `min_time_seconds`, `permit_without_stream` |
| jobs | `multiplayer` `[]*MultiplayerJobConfig`, `mtls` `[]*MTLSJobConfig` (omitempty), `wg` `[]*WGJobConfig` (omitempty), `dns` `[]*DNSJobConfig` (omitempty), `http` `[]*HTTPJobConfig` (omitempty) |
| ai | `ai` → `*AIConfig` |
| http-c2 | `http_default.headers[]` → `HttpDefaultHeader`, plus `HttpC2ServerConfigID` / `HttpC2ImplantConfigID` / `ID` |

**Listener/job config shapes (enumerated):** `[src]`
- `MultiplayerJobConfig`: `host`, `port` (uint16), `job_id`, `tailscale`, `wire_guard`
- `MTLSJobConfig`: `host`, `port` (uint16), `job_id`
- `WGJobConfig`: `port`, `nport`, `key_port` (all uint16), `job_id`
- `DNSJobConfig`: `domains` `[]string`, `canaries`, `host`, `port`, `job_id`, `enforce_otp`
- `HTTPJobConfig`: `domain`, `host`, `port`, `secure`, `website`, `cert` `[]byte`, `key` `[]byte`, `acme`, `job_id`, `enforce_otp`, `long_poll_timeout`, `long_poll_jitter`, `randomize_jarm`

`[inference]` Two observations: (a) **`enforce_otp` appears on both DNS and HTTP job configs** — the only per-listener authentication concept in the config surface, and it is an implant-side OTP, not an operator control. (b) **`cert` and `key` are `[]byte` inline in the config**, meaning listener TLS material is persisted inside the YAML/JSON config file rather than referenced by path. That is a config-file confidentiality dependency.

### 8.2 Threat-intel API keys — operator-configurable credentials

`VTApiKey` (`vt_api_key`), `XForceApiKey` (`xforce_api_key`), `XForceApiPassword` (`xforce_api_password`) — `[src]` (VirusTotal and IBM X-Force). These are the `monitor` command family's backing credentials, sitting in the same config file. `[inference]`

### 8.3 `http_default.headers[]` — the randomized-header mechanism

`HttpDefaultHeader` carries `method`, `name`, `value`, **`probability int32`** — `[src]`. `[inference]` A per-header `probability` field means the server randomizes which default headers are emitted per request, weighted by the configured probability. This is a *compiled-in*-supported, *operator-configured* traffic-shaping mechanism, and it exists in two near-identical forms in the struct listing (a `HttpDefaultHeader` and a second 4-field struct with the same field names) — likely the persisted vs. runtime form. `[inference]`

### 8.4 `crack.go` — dual-schema config with legacy keys

`crack.go` declares each field **three times**: `[src]`
- new lowercase: `auto_fire`, `max_file_size`, `chunk_size`, `max_disk_usage`
- new lowercase pointer form: `*bool` / `*int64` for the same four
- **legacy** capitalized: `AutoFire`, `MaxFileSize`, `ChunkSize`, `MaxDiskUsage` — all `*bool` / `*int64`, suffixed `Legacy` in Go

`[inference]` A three-form enumeration where two forms are lowercased duplicated names and the third preserves the original capitalized YAML keys is a **backward-compatibility migration schema**: old configs with `AutoFire` still parse, new writes use `auto_fire`, and the pointer types make "unset" distinguishable from "set to zero." The same pattern appears in `server.go` for `enable_wg` vs. legacy `disable_wg` (an *inverted* legacy key — the migration must negate).

### 8.5 Log payload capture — a privacy-relevant operator switch

`grpc_unary_payloads`, `grpc_stream_payloads`, `tls_key_logger` — `[src]` (`server.go`, `LogConfig`). These are wired into the interceptor chain in §1.1: `grpc_logrus.PayloadUnaryServerInterceptor(logrusEntry, deciderUnary)` and `PayloadStreamServerInterceptor(..., deciderStream)` — `middleware.go:75, 83`. `[src]`

`[inference]` **`tls_key_logger` is an operator-settable switch that would export TLS session keys**, and the `deciderUnary`/`deciderStream` functions are the per-call gate on whether payloads are captured. This is the mechanism by which an operator can capture full gRPC request/response bodies to the server log — the log itself is therefore a sensitive artifact whose capture is optional and config-driven.

### 8.6 `notifications.go` — 20 KB, the largest config file

`NotificationsConfig`: `enabled`, `events []string`, `templates map[string]*NotificationTemplateConfig`, `services *NotificationsServicesConfig` — `[src]`. `NotificationTemplateConfig`: `enabled`, `events`, `type`, `template`.

**Service providers, enumerated from the struct list — this is a measured count.** `[src]` The `NotificationsServicesConfig` fields are: AmazonSES, AmazonSNS, Bark, DingDing, Discord, FCM, GoogleChat, HTTP, Lark, Line, LineNotify, Mail, Mailgun, Matrix, Mattermost, MSTeams, PagerDuty, Plivo, Pushbullet, PushbulletSMS, Pushover, Reddit, RocketChat, SendGrid, Slack, Syslog, Telegram, TextMagic, Twilio, Twitter, Viber, WebPush, WeChat — **33 provider integrations**, plus the trailing entries truncated in my read. `[src]`

`[inference]` This is the single largest integration surface in `configs/` and it is **outbound-only**: notifications exfiltrate server events to third-party APIs. Every enabled service is a credential (`*Config` structs hold keys) and a network egress path. `WatchTower` / `cc` / `cxx` appeared in the operator-side config documentation recovered in T1 (`embedded_help_blob.txt`) as `watch_tower: null`, `cc: {}`, `cxx: {}` — consistent with these being empty-by-default extension points. `[src]` for T1, `[inference]` for the linkage.

### 8.7 `write.go` and `legacy.go` — the compiled-in content

`write.go` (1,737 B) and `legacy.go` (642 B) are the two smallest non-test files. `[src]` `[inference]` `legacy.go` at 642 bytes is consistent with the migration logic implied by §8.4 — the mapping from old key names to new. `write.go` is the persist path. **What is compiled-in rather than operator-configurable:** the default `DaemonConfig` values (`host: ""`, `port: 31337`, `tailscale: false`, `enable_wg: false`), the default log level `4`, and the default gRPC keepalive (`min_time_seconds: 30`, `permit_without_stream: true`) — these were recovered from the embedded `server.yaml` in the T1 operator binary (`embedded_help_blob.txt`), which corroborates that the same defaults are compiled into the client's config-documentation blob and the server's defaults. `[src]`(T1) + `[inference]`

**Answer to question 4:** operational parameters are broadly operator-configurable (listeners, ports, TLS material, log verbosity and payload capture, notification egress, threat-intel keys, crack quotas, AI providers); the **security model is not** — the permission model (§2) has no config representation at all. `[src]` + `[inference]`

---

## 9. `db/` — operator records and token storage

`server/db/` recurses to **43 files / 258.9 KB** with subdirectories `models/` and `wasmsqlite/` — `[src]` (§0).

### 9.1 The load-bearing operator functions

- `db.OperatorByToken(token)` — consumed at `transport/middleware.go:143-146` for cache-miss authentication.
- `models.GenerateOperatorToken()` — `db/models/operator.go:51-58`: 32 bytes from `crypto/rand`, hex-encoded, **panics** on short read (`panic(errors.New("failed to read from secure rand"))`). `[src]`
- `Operator.BeforeCreate` — `db/models/operator.go:44-48`: assigns `ID = NewUUID()` and `CreatedAt = time.Now()`. `[src]`
- `db.NextAvailableMultiplayerWGIP()` — `console/console-admin.go:164`, called in a 32-attempt loop when provisioning WireGuard operators. `[src]`
- `db.BeaconByID(...)` — `rpc/rpc.go:223` (async task dispatch) and `transport/middleware.go:498`. `[src]`

### 9.2 Token storage — verified properties

| Property | Value | Evidence |
|---|---|---|
| Token length | 32 random bytes → 64 hex chars | `db/models/operator.go:52-57` |
| Stored form | SHA-256 hex of the token | `db/models/operator.go:35` + `console-admin.go:131-134` |
| Unique | `gorm:"uniqueIndex"` | `db/models/operator.go:35` |
| Comparison | exact string equality on the digest | `middleware.go:134-146` |

`[inference]` Because the stored value is an unsalted SHA-256 of a 32-byte random secret, offline recovery from a stolen DB is not feasible by precomputation — the keyspace is 2^256. **However, this is not a password-hash construction and should not be described as one:** there is no salt, no work factor, and no per-record cost, which is correct for a high-entropy machine token and would be wrong for a human-chosen secret. The DB is therefore a **bearer-credential store, not a defensible password store**.

### 9.3 `wasmsqlite/`

`[inference]` The presence of a `wasmsqlite/` subpackage inside `db/` is consistent with the client's `go_sqlite` build tag observed in the operator binary's build info (`go_sqlite,client`) — the SQLite driver is compiled to WASM and executed in a WASM runtime (`tetratelabs/wazero` is a declared dependency of the client). The server and client therefore share the same SQLite-over-WASM mechanism. `[src]` for the build tag (T1), `[inference]` for the mechanism linkage. **This is the single clearest connection between the client binary reversal and the server source in this task.**

---
## 10. Failure behaviour — what each boundary does when it fails

| Boundary | Failure | Behaviour | Evidence |
|---|---|---|---|
| Token auth | missing/invalid bearer token | `codes.Unauthenticated, "Authentication failure"` — **fails closed** | `middleware.go:127-131` |
| Token auth | unknown token digest | `codes.Unauthenticated` — fails closed | `middleware.go:147-150` |
| Token auth | `ClearTokenCache` race | lookup + insert held under `RLock` so a request cannot repopulate after clear | `middleware.go:113-117, 137-138` |
| Permissions | operator lacks the required role | `codes.PermissionDenied, "Token has insufficient permissions"` + `Warnf` with operator name and method — fails closed | `middleware.go:203-205` |
| Permissions | `Operator` context value missing | **type assertion panics** (the following `nil` check is unreachable for interface-nil) | `middleware.go:186-187` + `[inference]` |
| Permissions | `PermissionAll` set | all checks skipped — fail open **by design** | `middleware.go:188-190` |
| Local transport | any caller | `serverAuthFunc` returns nil error unconditionally; **no auth, no permissions** | `middleware.go:119-123`, `local.go:47` |
| mTLS TLS config | `getOperatorServerTLSConfig` returns nil | `errors.New("failed to create operator TLS config")`, listener closed by caller | `mtls.go:78-80`, `:61-65` |
| mTLS listener | nil listener | `errors.New("listener is required")` | `mtls.go:73-75` |
| mTLS serve loop | panic | `recover()` logs `"gRPC server panic"` + stack; **server survives** | `mtls.go:93-97` |
| mTLS serve loop | unexpected accept error | `Warnf` unless `isExpectedGRPCServerExit` — **dispatcher may be dead while the process looks healthy** | `mtls.go:98-100, 105+` + `[inference]` |
| Local serve loop | serve error | **`Fatalf` — process exit** | `local.go:57-58` |
| Local serve loop | panic | recover + `Errorf("stacktrace from panic")` | `local.go:51-56` |
| Crackstation authz | no client identity | `codes.Unauthenticated, "missing crackstation client identity"` | `rpc-crackstations.go:386-388` |
| Crackstation authz | station absent | `codes.FailedPrecondition, "crackstation is not registered"` | `:390-392` |
| Crackstation authz | caller ≠ owner | `codes.PermissionDenied, "crackstation identity does not own host"` | `:393-395` |
| Operator token generation | `rand.Read` short read | **panic** `"failed to read from secure rand"` | `db/models/operator.go:54-56` |
| Reverse tunnel | peer terminal < expected, or >128 frames ahead | `ErrReverseTunnelTerminal` — fails closed | `rtunnels.go:322-324` |
| Reverse tunnel | conflicting peer-close sequence | `ErrReverseTunnelTerminal` | `rtunnels.go:325-327` |
| Reverse tunnel | pending frame ≥ terminal | `ErrReverseTunnelTerminal` | `rtunnels.go:328-332` |
| Reverse tunnel | terminal frames never arrive | `StartPeerCloseDeadline` fires `expired()` | `rtunnels.go:358-374` |
| Reverse tunnel | frame over `maxReverseTunnelFrameBytes` | `ErrReverseTunnelFrameTooLarge` with byte counts | `rtunnels.go:386-388` |
| Reverse tunnel | `write` nil | `errors.New("reverse tunnel write function is nil")` | `rtunnels.go:383-385` |
| Registry | activation/revocation race | fails closed (test-enforced) | `authorization_test.go:404` |
| Registry | quota reclaim after race | reclaimed, not leaked | `authorization_test.go:353` |
| Generic handler | nil `Request` field | `ErrMissingRequestField` | `rpc/rpc.go:184-186` |
| Generic handler | unknown session | `ErrInvalidSessionID` | `rpc/rpc.go:193-196` |
| Async handler | unknown beacon | `ErrInvalidBeaconID` + `Errorf` | `rpc/rpc.go:223-227` |
| Async handler | DB save failure | `ErrDatabaseFailure` | `rpc/rpc.go:243-254` |

**Positive control for the absence probes in §2/§6/§10** — the search mechanism was validated before any zero was reported: `[src]`
- `PermissionDenied` over all of `server/` → **38 hits** (probe demonstrably succeeds)
- `GenericHandler` over `server/rpc/` → **96 hits** (probe demonstrably succeeds)

**Absence probes, with hits inspected rather than assumed:** `[src]`
- `acl|ACL|rbac|RBAC|roleManager|CanCall|AllowList|DenyList` over all of `server/` → **6 hits, all substring false positives**: `cryptography.go:130` (`Nacl` in "Nacl Box"), `encoders_test.go:311` (`"PENTACLE"`), and four `rpc-tunnel_test.go` test names matching `...CLoses` (`:179, :410, :551, :1078`). **No ACL or RBAC type exists.**
- `IsAdmin|is_admin|AdminOnly|RequireAdmin` over all of `server/` → **0 hits.** **There is no administrator/operator privilege distinction.**

---

## 11. Residual unknowns

1. **`OperatorName` trust direction — not fully enumerated.** Two writers overwrite it server-side from the TLS common name (`rpc-crackstations.go:703`, `rpc-generate.go:721`). I did **not** enumerate every reader/writer of `OperatorName` across the whole request path, so I cannot assert that no handler accepts a client-supplied value. **Probe:** enumerate all `OperatorName` occurrences in `protobuf/` and every `rpc/` handler that both reads a request field and compares it to `getClientCommonName`.
2. **`getClientCommonName` returns `""` on every failure** (`rpc.go:260-276`). The crackstation path treats `""` as an error; the other call sites do not visibly. **Probe:** for each of the 8 call sites, determine whether `""` can reach a comparison that would treat an unnamed operator as matching a stored empty name.
3. **`tokenCache` invalidation granularity.** `ClearTokenCache()` (`middleware.go:113-117`) is whole-cache. I did not find a per-operator invalidation path. **Consequence (inference):** revoking one operator's token may require clearing all. **Probe:** find every caller of `ClearTokenCache` and confirm whether a per-operator revoke exists.
4. **Tailscale as a third trust root is inferred, not read.** I read the tsnet listener construction and its `initMiddleware(true)` call (`tailscale.go:42-51, 85`) but did **not** read the tsnet ACL/key handling. The assertion "reachability is additionally decided by the tailnet" is an inference from tsnet's architecture. **Probe:** read the full `tailscale.go` plus any tsnet key/ACL configuration.
5. **`tls_key_logger` runtime effect unverified.** It exists as a config field and is named for key logging; I did not locate the code that consumes it. **Probe:** find the reader of `LogConfig.TLSKeyLogger`.
6. **`aitools/` subpackage unread.** `server/rpc/aitools/` exists and contains at least `filesystem_tools.go` (observed: `:206-210`, a `change permissions` tool definition with `path` parameter). The AI tool-calling surface is a **new capability class** — an LLM given tool definitions that map to implant operations. **This is the most consequential unread area in scope** and I did not size it. **Probe:** enumerate `server/rpc/aitools/` fully.
7. **`db/wasmsqlite/` unread.** I inferred the WASM-SQLite linkage from the `go_sqlite` build tag and the `wazero` dependency but did not read `wasmsqlite/`. **Probe:** read `db/wasmsqlite/` for the runtime and the sandbox boundary it creates.
8. **Notifications provider list truncated.** I enumerated 33 `*Config` fields before my read truncated; the true count may be higher. **Probe:** re-read `NotificationsServicesConfig` in full.
9. **`rpc/` test files substantially unread.** `crack-queue_test.go` (161,694 B), `rpc-socks_test.go` (82,755), `rpc-tunnel_test.go` (61,890), `rpc-ai_test.go` (50,090), `rpc_rportfwd_security_test.go` (36,144) — ~750 KB of tests encoding intended invariants. Names alone show deliberate security testing (`rpc_rportfwd_security_test.go`, `TestTunnelDataCloseRacePublishesEachPeerTerminalOnce`). **Probe:** read the security-named tests for stated invariants.
10. **`rpc/` handler bodies are largely unread.** I read the auth/permission/ownership machinery and the `rpc.go` core, not the 70 handler implementations. The **capability** inventory of `rpc/` is therefore not established here — only its **control** structure is.

---

## 12. What this report does NOT establish

- **It does not enumerate the RPC surface.** §1–§10 establish the *control plane* over the RPCs (who may call, how identity is established, what fails). The RPC inventory itself lives in D1/T1 (135 request types, 201 generated methods) and is not repeated.
- **It does not analyze implant-side behaviour.** This is server source. Persistence, evasion, and injection are not in scope.
- **It does not treat `crack-*`, `rpc-socks`, `rpc-tunnel`, `rpc-generate`, or `package_tools.go` internals as reversed.** Those are the largest files in scope and they are read here only for their authorization seams.
- **It makes no claim about the deployed server's configuration.** §8 enumerates what *may* be configured; the actual values on any deployment are unknown.
- **It does not reconcile the source clone against the shipped binary.** The clone at `01_SOURCE_c2\sliver` is at a **different commit** than the analyzed operator binary (VCS `422044af...`, 2026-10-03). Every `[src]` claim is about the clone. Where the T1 binary reversal corroborates a value (the `server.yaml` defaults, `port 31337`), that is marked explicitly. **No `[src]` claim in this report should be read as a claim about the shipped binary's bytes.**

---

## Summary — the five questions, answered

| # | Question | Answer |
|---|---|---|
| 1 | What authenticates an operator? Per-RPC or per-stream? | A **32-byte SHA-256-stored bearer token** in gRPC metadata, validated by `tokenAuthFunc` (`middleware.go:125-156`). The mTLS certificate is a transport precondition, not the auth decision. Enforcement is **both** per-RPC and per-stream via parallel interceptors (`middleware.go:184-230`). The enforcement point is `transport/`, **not** `rpc/`. |
| 2 | Is there a permission model? | **Yes, and it is three booleans**: `PermissionAll`, `PermissionBuilder`, `PermissionCrackstation` (`db/models/operator.go:36-38`), set in exactly one non-test place (`console/console-admin.go:139-144`) and consumed in exactly one (`transport/middleware.go`). Builder = 6 allowlisted methods; crackstation = 9. **No ACL, no RBAC, no admin role (0 hits each, positive-controlled). Every `PermissionAll` operator can call every RPC.** |
| 3 | `MarkPeerClose` / `StartPeerCloseDeadline` | Closed in §7. `MarkPeerClose` records an exclusive terminal sequence, rejects out-of-window/conflicting/pending-blocked terminals, returns ready = already-drained; `StartPeerCloseDeadline` is a fire-once, nil-safe, `Done()`-cancelled timer that fires `expired()` if the terminal never completes. Bounds: 128 frames, 128 ingress. |
| 4 | Configurable vs compiled-in | Broadly configurable: listeners/ports, inline TLS material, log level and **payload capture**, TLS key logging, 33+ notification egress providers, threat-intel keys, crack quotas, AI providers. **Not configurable: the permission model.** |
| 5 | Local transport auth, and is Tailscale a third trust root? | **Local: no auth and no permission check at all** — `serverAuthFunc` returns nil unconditionally and the permissions interceptor is absent (`middleware.go:88-94, 119-123`; `local.go:47`). Its security property is process integrity. **Tailscale: yes, a third trust root** (inference) — tsnet reachability is decided by the tailnet in addition to mTLS + token; WireGuard, by contrast, is a reachability *insulation* layer over the same mTLS+token stack. |

**The single most important structural finding:** the operator control plane's entire security model lives in **one 517-line file**, `server/transport/middleware.go`. `server/rpc/` — 83 files, 1,210 KB, the largest unread block in the corpus — contains **zero** authentication and **zero** permission logic. Redirecting attention from file size to the interceptor chain is what closed all five questions.

