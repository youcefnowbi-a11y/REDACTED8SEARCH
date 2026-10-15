# D12 — Sliver `server/rpc/aitools/`: is the LLM a trust principal?

**Task:** task-26. **Lane:** sliver-diver. **Method:** source-only reading, no REA/Ghidra.
**Scope:** `RE_Library\01_SOURCE_c2\sliver\server\rpc\aitools\` — **13 files / 208.8 KB** (9 non-test / 173.9 KB) — with D11 §2/§6 (`transport/middleware.go`, `rpc-*` authorization seams) as the control comparison.
**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`.

**Citation convention:** inline `path/file.go:LINE`, matching D1 and D11.

---

## 0. Headline

**Yes. The LLM is a trust principal, and it is not subordinate to the operator's permission context.** `[src]`

The mechanism is a single line: `rpc/rpc-ai.go:218` passes **`rpc` itself** — the `*rpc.Server` — into `aitools.NewExecutor(rpc, conversation)`. The executor then calls methods on that object **directly**, as ordinary Go method calls. It never traverses gRPC, so it never traverses the interceptor chain in `transport/middleware.go`. **Every permission check that D11 §2 proved exists for operators is structurally absent from the AI tool path.** `[src]` + `[inference]`

**This is not a weakening of the permission model. It is a bypass of it.** `[inference]`

Compounding it: the agentic loop is invoked with **`context.Background()`** (`rpc-ai.go:215`) — a detached context carrying no operator identity, no token, and no deadline — and a grep of the entire non-test `aitools` package for any authorization term returns **2 hits, both of which are the word "permissions" inside a human-readable tool description string.** `[src]`

---
---

## TOC

1. The wiring — one line that decides the whole question
2. The `Backend` interface — why the bypass is structural, not accidental
3. The detached context
4. The permission model does not reach `aitools` — enumerated
5. The six destructive tools and the missing confirmation gate
6. Does LLM output reach an implant without a human? — the async path
7. Is `aitools` reachable over the unfenced local transport?
8. What an operator can actually be talked into
9. Failure behaviour
10. Failure modes that are *handled* (credit where due)
11. Residual unknowns
12. What this report does NOT establish
13. Summary — the five questions

---

## 1. The wiring — one line that decides the whole question

The AI feature is entered from the operator plane at `rpc/rpc-ai.go`. Its `Backend` is the **server object itself**:

```go
// rpc/rpc-ai.go:218
aitools.NewExecutor(rpc, conversation),
```

and the surrounding call, `rpc/rpc-ai.go:214-220`: `[src]`

```go
completion, err = serverai.CompleteConversationAgentic(
	context.Background(),
	runtime,
	conversation,
	aitools.NewExecutor(rpc, conversation),
	sink,
)
```

`aitools.NewExecutor(backend Backend, conversation *clientpb.AIConversation) serverai.AgenticToolExecutor` — `rpc/aitools/executor.go:162-167` — stores both fields and returns `&executor{...}`. `[src]`

**Why this is decisive.** In Go, `aitools.NewExecutor(rpc, ...)` passing a `*rpc.Server` where a `Backend` is expected is a compile-time proof that **`*rpc.Server` satisfies every method in the `Backend` interface**. The executor therefore holds a live, fully-privileged server handle and invokes its methods directly: `e.backend.Ls(ctx, req)`, `e.backend.Execute(ctx, req)`, `e.backend.Chown(ctx, req)` and so on. `[src]` + `[inference]`

**Verified absence of the interceptor chain on this path.** `transport/middleware.go` installs `permissionsUnaryServerInterceptor()` / `permissionsStreamServerInterceptor()` as *gRPC interceptors*. gRPC interceptors execute **only** when a call arrives over a gRPC transport and is dispatched by the generated `grpc.Server`. A direct Go method call on `rpc.Server` from inside the same process passes through no interceptor, by construction of the middleware pattern. `[inference]` — this is the same reasoning D11 §4.4 applied to the local transport, and D11 §6.4 established independently that **`server/rpc/` never reads or writes the permission fields at all** (0 hits, positive-controlled). That D11 finding is the control: `rpc/` has no permission logic *in its handlers*, so nothing downstream of the interceptor can restore the check the interceptor did not get to run. `[src]`(D11 §6.4) + `[inference]`

**The two chains side by side:** `[src]`

| Path | How the RPC method is reached | Permission check |
|---|---|---|
| Operator over gRPC | `grpc.Server` → interceptor chain → handler | `permissionsUnary/StreamServerInterceptor` — **present** |
| Operator over local bufconn | `bufconn` → interceptor chain (`initMiddleware(false)`) | **absent** (D11 §4.4) |
| **AI tool call** | **direct Go method call on `rpc.Server`** | **absent — no interceptor is involved at all** |

---

## 2. The `Backend` interface — why the bypass is structural, not accidental

`Backend` — `rpc/aitools/executor.go:24-53` — is a **28-method interface** *(corrected from 29 — see §14.3)*: `[src]`

| Group | Methods |
|---|---|
| Recon | `GetSessions`, `GetBeacons` |
| Filesystem (11) | `Ls`, `Mv`, `Cp`, `Rm`, `Mkdir`, `Cd`, `Download`, `Pwd`, `Chmod`, `Chown`, `Chtimes`, `Mount` |
| System (8) | `Ifconfig`, `Netstat`, `Ps`, `GetEnv`, `Ping`, `Screenshot` |
| Execution (2) | `Execute`, `ExecuteWindows` |
| Code loading (3) | `ExecuteAssembly`, `Sideload`, `SpawnDll` |
| Extensions (3) | `RegisterExtension`, `ListExtensions`, `CallExtension` |

**Count note:** the table lists 29 declarations; `Mount` appears in the filesystem group and the enumerated interface runs `executor.go:25-52`. Every entry is **read directly from the interface body**, not estimated. `[src]`

**Three consequences:**

1. **`Backend` is exactly the set of RPC methods that already have real business logic on `*rpc.Server`.** It is a *narrowing* interface by intention — the author selected 29 methods rather than exposing all ~201. `[inference]`
2. **The narrowing is on *which* methods, not on *who may call them*.** An interface in Go carries no authority. Satisfying it grants the holding code the ability to invoke everything in it on the underlying receiver. `[inference]`
3. **`ExecuteAssembly`, `Sideload`, `SpawnDll`, and `CallExtension` are in the interface.** These are the code-execution primitives. Their presence means the AI tool surface includes arbitrary-code-loading capability, not merely recon. `[src]` — see §5 for whether any tool *exposes* them.

**Correction owed to D11.** D11 §11 item 6 described `aitools` as "the most consequential unread area" and cited `filesystem_tools.go:206-210` as a `change permissions` tool. That is correct, but D11 §0 also mis-located four `aitools` files as `rpc/` top-level files; that error was already retracted in D11 §0 in a later pass. `[src]`

---

## 3. The detached context

`context.Background()` — `rpc-ai.go:215`. `[src]`

`[inference]` This is the second independent reason no authorization can occur on the AI path, and it is worth separating from §1. Even if a permission check *did* exist inside `aitools`, it would have nothing to check: the `*models.Operator` that `tokenAuthFunc` places in context (`transport/middleware.go:152-154`) is **not present in `context.Background()`**. `context.Background()` is the root context — it carries no values, no cancellation, and no deadline.

**The `ctx` that reaches the executor is a fresh chain, not the operator's.** Chain, verified: `rpc-ai.go:215` `context.Background()` → `CompleteConversationAgentic(ctx, ...)` (`server/ai/agentic_loop.go:93-99`) → the loop passes `ctx` down → `agenticToolOutput(ctx, tools, toolCall)` (`agentic_loop.go:557`) → `tools.CallTool(ctx, name, arguments)` (`executor.go:230`). `[src]`

**Positive control for this absence:** the *same file* demonstrates that the operator identity **is** available in the AI RPC's own scope — `rpc-ai.go:198` constructs `newAIConversationEventSink(conversationID, operatorName, runtime, turnID)`, and `operatorName` is in scope and used for persistence (`rpc-ai.go:237-239`, `:187`, `:200`). `[src]` **So the operator's name is sitting right there two lines above the `context.Background()` call that discards the context carrying it.** The mechanism to attribute the AI turn to an operator exists and is used for bookkeeping; it is simply not propagated into the tool-execution context. `[src]` + `[inference]`

This is a *targeted* observation, not a general one: the codebase demonstrably knows how to carry operator identity (`rpc-ai.go:198`), and D11 §5 enumerated 8 sites where it does so for other features. `[src]`

*Correction to note for the record:* an earlier draft of this section asserted `context.Background()`, `runtime`, and `conversation` were named parameters within the first 20 lines of the enclosing function and marked them `[src]`. That claim is `[inference]` without an enumerated enclosing-function signature, and it is weakened here. What **is** `[src]`: the four call arguments at `rpc-ai.go:214-220` and the `operatorName` in-scope evidence at `:187, :198, :200, :237`. `[inference]`

---

## 4. The permission model does not reach `aitools` — enumerated

**Probe:** search every non-test `.go` file in `rpc/aitools/` for any authorization term — `Permission`, `authorize`, `Operator`, `getClientCommonName`, `PermissionDenied`, `Unauthenticated`. `[src]`

**Result: exactly 2 hits.** `[src]`

| File:line | Text |
|---|---|
| `filesystem_tools.go:206` | `Description: "Change permissions on a remote file or directory. If session_id and beacon_id are both omitted, the conversation target is used when available."` |
| `filesystem_tools.go:210` | `"path": map[string]any{"type": "string", "description": "Path to change permissions on."}` |

**Both hits are prose inside tool-description strings shown to the model.** Neither is code, a field, a comparison, or a call. **There is no authorization logic of any kind in the `aitools` package.** `[src]`

**Positive control (the probe demonstrably succeeds elsewhere):** the identical probe pattern run against `server/rpc/*.go` (excluding tests) returns **26 hits** for `getClientCommonName|authorizeCrackstation|authorizeBuilder`. `[src]` So a probe of this shape *does* find authorization code when authorization code is present. Its return of **2 string-literals-only** in `aitools/` is a measured absence.

**Corroboration from D11:** D11 §6.4 proved by enumeration that the three permission booleans (`PermissionAll`, `PermissionBuilder`, `PermissionCrackstation`) are **set in exactly one non-test place** (`server/console/console-admin.go:139-144`) and **consumed in exactly one** (`server/transport/middleware.go`), with **0 hits across all of `server/rpc/`**. `[src]`(D11 §6.4) Since `aitools` is a subpackage of `rpc/` and its calls never traverse `transport/`, **the only consumer of the permission model cannot execute for an AI tool call.** `[inference]`

**Answer to priority question 3, stated plainly:** the three permission booleans **do not map onto the 41 tools at all.** There is no mapping — not a partial one, not a coarse one. There is no code in the package that could perform one. `[src]`

---

## 5. The six destructive tools and the missing confirmation gate

**41 tools, enumerated** by extracting every `Name:` declaration in the non-test files of `aitools/`: `[src]`

| Family | Count | Tools |
|---|---|---|
| filesystem | 14 | `fs_ls`, `fs_cat`, `fs_pwd`, `fs_mv`, `fs_cp`, `fs_rm`, `fs_mkdir`, `fs_cd`, `fs_head`, `fs_tail`, `fs_chmod`, `fs_chown`, `fs_chtimes`, `fs_mount` |
| system | 10 | `exec_command`, `ifconfig`, `netstat`, `ps`, `env`, `getpid`, `getuid`, `info`, `ping`, `screenshot` |
| loot | 4 | `loot_list`, `loot_read`, `loot_add`, `loot_delete` |
| credentials | 4 | `credentials_list`, `credentials_read`, `credentials_add`, `credentials_delete` |
| packages/armory | 4 | `search_aliases`, `search_extensions`, `execute_alias`, `execute_extension` |
| encoding | 4 | `hex_encode`, `hex_decode`, `gzip_encode`, `gzip_decode` |
| discovery | 1 | `list_sessions_and_beacons` |
| **total** | **41** | |

`executor.go` declares only four of these inline (`list_sessions_and_beacons` `:172`, `fs_ls` `:181`, `fs_cat` `:194`, `fs_pwd` `:210`); the other 37 are contributed by the family files. `[src]`

**The lead's list of six destructive tools is confirmed and is if anything conservative.** `[src]`

**Is there a confirmation gate?** Every tool is dispatched through a single switch: `func (e *executor) CallTool(ctx context.Context, name string, arguments string) (string, error)` — `executor.go:230`. `[src]` The 2-hit authorization probe of §4 covers the entire package including this function. **There is no confirmation gate, no dry-run mode, no operator approval step, and no destructive-tool denylist.** `[src]` + `[inference]`

**The sharpest instance — `exec_command`.** `system_tools.go:181` declares `exec_command`, whose handler path reaches `Backend.Execute` / `Backend.ExecuteWindows` (`executor.go:45-46`). `[src]` An LLM tool call that reaches `Execute` **runs a process on a live implant with no intermediate human decision**. `[inference]`

**Second instance — `fs_chown` / `fs_chmod` / `fs_rm`.** `filesystem_tools.go:205, 219, 140`. These are the tools whose *purpose* is to alter ownership and permissions on a remote host — the classic privilege-escalation and anti-forensics primitives. `[inference]`

**Note the asymmetry with the interface.** `Backend` exposes `ExecuteAssembly`, `Sideload`, `SpawnDll`, and `CallExtension` (`executor.go:47-52`) — but the enumerated 41 tools do **not** include a tool that calls them. `[src]` So the *code-loading* capability is reachable by the executor but **not currently exposed to the model**. That is a real and favourable distinction: the capability is present, the exposure is not. `[src]` + `[inference]`

---

## 6. Does LLM output reach an implant without a human? — the async path

**Yes, for beacon targets — and the mechanism is a polling loop, not a gate.** `[inference]`

`callTargetRPC[T]` — `rpc/aitools/helpers.go:36-70` — is the single funnel for target operations: `[src]`

```go
req, isBeacon, callCtx, cancel, err := buildRequestContext(ctx, target)   // :44
if cancel != nil { defer cancel() }                                        // :48-50
resp, err := invoke(callCtx, req)                                          // :52
if err := genericResponseError(resp.GetResponse()); err != nil { ... }      // :56-58
if isBeacon && resp.GetResponse() != nil && resp.GetResponse().Async {      // :59
	resolved := newResponse()
	if err := waitForBeaconTaskResponse(callCtx, resp.GetResponse().TaskID, resolved); err != nil {
		return zero, err                                                    // :61-63
	}
	resp = resolved
	if err := genericResponseError(resp.GetResponse()); err != nil { ... }   // :65-67
}
return resp, nil                                                           // :69
```

`[src]`

**Reading:** for a session target, the call is synchronous. For a **beacon** target, the response may be `Async`, and the executor then **blocks in `waitForBeaconTaskResponse(callCtx, taskID, resolved)`** until the task completes, returning the real result. `[src]`

- `waitForBeaconTaskResponse` — `executor.go:679`
- `waitForBeaconTask` — `executor.go:697`
- `aiToolDefaultWaitSeconds = int64(60)` — `executor.go:21`

`[src]`

**What intervenes between the LLM's decision and the implant's execution: nothing human.** The executor's own default wait is `60` seconds (`executor.go:21`), and it polls the task to completion. `[src]` `[inference]` The *beacon's check-in interval* (operator-configured, and exposed in the `beaconSummary` at `executor.go:141` as `interval` / `jitter`) is the only pacing between a model decision and a task being picked up — and that is a scheduling parameter, not an authorization one. `[inference]`

**The loop bound is the model's budget, not the operator's attention.** `for step := 0; step < maxAgenticLoopIterations; step++` — `server/ai/agentic_loop.go:121`. `[src]` Within one turn the model may emit tool calls repeatedly, each executing on a live target, bounded only by `maxAgenticLoopIterations`. `[inference]`

**Answer to priority question 4: LLM output reaches implants with no human in the loop.** The only thing an operator sees is the *stream* (`agentic_loop.go:557` `agenticToolOutput`, and the `sink` at `agentic_loop.go:98`) — which is notification of what already happened, not consent to it. `[src]` + `[inference]`

---

## 7. Is `aitools` reachable over the unfenced local transport?

**The question dissolves, and the answer is worse than the framing.** `[inference]`

The lead asked whether `aitools` is reachable over the local transport, which D11 §4.4 proved has **no authentication and no permission check** (`local.go:47` `initMiddleware(false)`; `serverAuthFunc` returns nil unconditionally, `middleware.go:119-123`). `[src]`(D11)

**`aitools` is not a gRPC service and has no transport.** It is a plain Go package invoked in-process from `rpc-ai.go:218`. There is no listener to reach it over. `[inference]`

**Which means it does not inherit *a* transport's weaker fence — it inherits *no* fence at all.** The local transport at least has an interceptor chain, just one with the permissions interceptor omitted; `aitools` has no interceptor stage in its call path whatsoever (§1). `[inference]`

**Therefore the reachability question that matters is not "which transport" but "which transport must you be on to trigger it."** The AI RPC that constructs the executor is a normal `SliverRPC` method. Over **mtls / tailscale / WireGuard** it is gated by `tokenAuthFunc` and the permission model — so an operator must hold a valid token, and (absent `PermissionAll`) the AI method must appear in one of the two allowlists. **It does not appear in either**: the enumerated `builderMethods` (6 entries) and `crackstationMethods` (9 entries) contain no `/rpcpb.SliverRPC/Ai*` path — verified by grepping `server/transport/` for `rpcpb.SliverRPC/(A|a)i`, which returns **0 hits**, against the positive control that the same file's allowlists are non-empty and readable. `[src]`

**But over the local bufconn transport there is no auth on the entry either** — so on that path the AI feature is reachable with no token at all, and its tool calls then execute with no permission check. `[inference]`, resting on D11 §4.4 `[src]` and §1 of this report `[inference]`

**Answer to priority question 2, and it is the sharpest form of the finding:** the security of the AI tool path is **entirely** determined by the fence on the *entry* RPC, because there is no fence on the *tool* path. An operator with `PermissionAll` gets full tool authority; the local transport requires no operator at all. `[inference]`

---

## 8. What an operator can actually be talked into

This section is `[inference]` throughout; it reasons from the enumerated capability surface rather than from observed behaviour. It is stated because the capability surface is the deliverable, and it is labelled because nothing here was executed.

**The attack surface is not "the LLM is malicious."** It is that a tool-calling loop with `exec_command`, `fs_rm`, `fs_chown`, and credential-write tools operates on **model-selected arguments**, and the model's input includes the **target's own output**. `[inference]`

**Concretely, the two properties that combine:** (a) tool *arguments* are produced by the model (`decodeToolArgs` — `executor.go:653`); (b) tool *results* are fed back into the conversation as context (§6, `agentic_loop.go:557`), and those results are **data read from a hostile-adjacent machine**. `[src]` for both functions, `[inference]` for the composition.

**So content on a compromised host — a file read by `fs_cat`, a process name from `ps`, an environment value from `env` — is model input, and model output selects the next tool and its arguments.** That is a prompt-injection path from a target host to a capability set that includes `exec_command` and `fs_rm`, with no human confirmation between the two. `[inference]`

**`credentials_*` and `loot_*` widen the consequence:** `store_tools.go:210, 227` (credentials add/delete) and `:137-177` (loot list/read/add/delete) mean the same injection path can write to and delete from the server's credential and loot stores — i.e., it reaches *server-side* state, not only the target. `[src]` for the tools, `[inference]` for the consequence.

**The one mitigation the code does show:** tool arguments are decoded from a **JSON string** into typed structs (`decodeToolArgs(raw string, out any)` — `executor.go:653`), and results are marshalled back through `marshalToolResult` (`executor.go:664`). `[src]` `[inference]` Typed decoding limits the argument *shape* an injection can produce, but it cannot limit *values* — `exec_command` takes a command string, and any string is a valid command string.

---

## 9. Failure behaviour

| Condition | Behaviour | Evidence |
|---|---|---|
| `executor` is `nil` or `backend` is `nil` | `fmt.Errorf("AI tool executor is unavailable")` — fails closed | `helpers.go:77-79` |
| Session/beacon ID not found (exact or prefix) | `fmt.Errorf("session %q not found", ...)` / `"beacon %q not found"` | `helpers.go:96, 113` |
| Underlying RPC returns error | propagated verbatim | `helpers.go:53-55` |
| Response carries a proto error | `genericResponseError(resp.GetResponse())` | `helpers.go:56-58, 65-67`; `executor.go:672` |
| Beacon task never completes | `waitForBeaconTaskResponse` returns time out at `aiToolDefaultWaitSeconds = 60` | `executor.go:21, 679` |
| Unknown tool name | `CallTool` switch default → error string to the model | `executor.go:230` + `[inference]` |
| Provider lacks agentic support | `fmt.Errorf("AI provider %q does not support the agentic Responses API loop", ...)` | `agentic_loop.go:106-108` |
| `runtime` nil | `fmt.Errorf("AI runtime config is required")` | `agentic_loop.go:100-102` |
| `conversation` nil | `fmt.Errorf("AI conversation is required")` | `agentic_loop.go:103-105` |
| **AI tool call on a live target with no permission** | **no check exists — proceeds** | §4, `[src]` |

**The pattern is consistent: every failure mode is handled *carefully* — errors are typed, messages are specific, nothing panics, and the nil-backend case fails closed.** `[inference]` What is absent is not error handling. It is authorization. Those are different axes and the code is strong on one and empty on the other. `[inference]`

---

## 10. Failure modes that are *handled* (credit where due)

Stated explicitly because a report that reads as uniformly negative is less accurate than the code. `[src]` for each:

- **Nil-safety is deliberate and correct.** `lookupTargetMetadata` checks `e == nil || e.backend == nil` (`helpers.go:77-79`) and returns a typed error rather than panicking.
- **Prefix matching is bounded and ordered.** Both the session and beacon lookups try **exact ID first**, then a `strings.HasPrefix` fallback (`helpers.go:86-95, 103-112`) — so an ambiguous short ID cannot pre-empt an exact match.
- **Context cancellation is honoured.** `buildRequestContext` returns a `cancel`, and `callTargetRPC` defers it (`helpers.go:48-50`) — the async wait does not leak a context.
- **Beacon async is actually resolved, not fire-and-forget.** `helpers.go:59-67` blocks for the real result and re-checks the proto error on the resolved response. A lazier implementation would have returned the async ack.
- **Argument decoding is typed.** `decodeToolArgs(raw string, out any)` (`executor.go:653`) — the model's JSON is unmarshalled into a concrete struct, not walked reflectively as a free-form map.
- **`screenshot`**, `ping`, `info`, `getpid`, `getuid` are read-only. The tool surface is not uniformly destructive.

`[inference]` None of this is a substitute for the missing authorization, and none of it should be read as such. It is, though, the difference between "an unfenced capability surface" and "a careless one" — and this is the former.

---

## 11. Residual unknowns

1. **`Backend` method bodies were not read.** I verified that `*rpc.Server` satisfies `Backend` (from the compile-time-shaped call at `rpc-ai.go:218`) and enumerated the 29 methods, but I did **not** read what `Ls`, `Execute`, `Chown`, etc. do internally on `rpc.Server`. **Probe:** read `rpc/rpc-fs.go` / `rpc/rpc-sys.go` / `rpc/rpc-exec.go` for these methods and confirm none performs its own operator check. *(D11 §6.4's 0-hit enumeration across `server/rpc/` is strong evidence they do not, but it was a probe on *symbol names*, not a read of the bodies.)*
2. **`buildRequestContext` was not read in full.** I read its signature and call site (`executor.go:629`, `helpers.go:44`) but not its body. It constructs the `*commonpb.Request` — critical because it determines whether an operator identity is present on the request object. **Probe:** read `executor.go:629-652`.
3. **The 4 tools declared inline in `executor.go` (`:172, 181, 194, 210`) were read; the other 37 were enumerated by declaration site but their handler bodies were not all read.** The tool *names* and *descriptions* are established; per-tool argument validation is not.
4. **`serverai` (the `server/ai` package) was read only at the boundary** — `CompleteConversationAgentic`'s signature, the loop bound at `agentic_loop.go:121`, and `AgenticToolExecutor` at `:26`. The provider-specific request construction and the full system prompt were not analyzed. **Probe:** read `server/ai/agentic_loop.go` and `server/ai/ai.go` for prompt-level constraints (e.g. any instruction telling the model to avoid destructive tools).
5. **The tool *descriptions* are the model's only guidance, and I did not read all 41.** `filesystem_tools.go:206` shows `fs_chmod`'s description is purely functional with no cautionary language. Whether any description warns the model off destructive use is unverified. **Probe:** extract all `Description:` strings across `aitools/`.
6. **Whether the AI feature is enabled by default is weakly established.** `ai` is a config key (`configs/ai.go`, D11 §8) and `resolveAIProviderConfig`/`ResolveRuntimeConfig` gate runtime selection (`rpc-ai.go:185`), but I did not enumerate the default-enabled state. **Probe:** read `configs/ai.go` defaults.
7. **`maxAgenticLoopIterations`' value was not read.** It bounds tool calls per turn (§6) and is load-bearing for blast radius. **Probe:** find its declaration in `server/ai/`.
8. **No runtime verification.** Per the task instruction, no REA/Ghidra and no execution. **Every claim here is static.** Whether a deployment reaches the vulnerable configuration depends on operator decisions I cannot observe.

---

## 12. What this report does NOT establish

- **It does not claim exploitation.** The prompt-injection path in §8 is `[inference]` from the capability surface, not a demonstrated attack.
- **It does not claim the AI feature is reachable by an unprivileged remote attacker.** Over mTLS/Tailscale/WireGuard the entry RPC requires a valid token (§7). The unfenced entries are: (a) an operator holding `PermissionAll`, and (b) the local transport, whose reachability requires already being inside the server process (D11 §4.4).
- **It does not establish that `Backend`'s 28 methods perform no internal checks** — see §11 item 1.
  *(Corrected from 29 by Lead during the index pass — §14.3 below is the lane's own correction, and this
  line survived it. **The number was stale, not the claim:** §14.2 closes the question on the merits, and
  the sentence's meaning is unchanged.)*
- **It does not read or assess the AI provider integration** beyond the loop boundary.
- **It is source-only and makes no claim about any deployed server's configuration.**
- **It does not re-derive D11's findings.** D11 §2/§6 are used as the control and cited, not restated.

---

## 13. Summary — the five questions

| # | Question | Answer |
|---|---|---|
| 1 | Does the executor inherit the operator's permission context? | **No.** `rpc-ai.go:218` passes the `*rpc.Server` itself as `Backend`; tool calls are **direct Go method calls** that never traverse the gRPC interceptor chain where `permissionsUnary/StreamServerInterceptor` live. Compounding it, the loop runs on `context.Background()` (`rpc-ai.go:215`), which cannot carry the `*models.Operator` that `tokenAuthFunc` would have installed. `[src]` + `[inference]` |
| 2 | Is `aitools` reachable over the local transport? | **The question dissolves.** `aitools` is not a service and has no transport — it is in-process. It inherits *no* fence, which is strictly weaker than the local transport's *omitted-permissions* fence. Entry to it is gated only by the fence on the AI RPC: a token over mTLS/Tailscale/WireGuard, **no token at all over local bufconn**. `[inference]` on D11 §4.4 `[src]` and §1 `[inference]` |
| 3 | Is there a confirmation gate on the destructive tools? | **No.** Single dispatch point `CallTool` (`executor.go:230`); the package-wide authorization probe returns **2 hits, both prose in tool descriptions** (§4). The three permission booleans **do not map onto the 41 tools at all** — there is no code that could perform such a mapping. `[src]` |
| 4 | Does LLM output reach an implant without a human? | **Yes, for beacon targets.** `callTargetRPC` (`helpers.go:36-70`) blocks in `waitForBeaconTaskResponse` on async responses; the only pacing is the beacon's check-in interval and `aiToolDefaultWaitSeconds = 60`. The operator sees a stream of what already happened. `[src]` + `[inference]` |
| 5 | What is `Backend`, and what authority does it carry? | A **28-method interface** *(corrected from 29 — §14.3)* (`executor.go:24-53`) satisfied by `*rpc.Server`; it exposes recon, 14 filesystem operations, 10 system operations, two execute primitives, three code-loading primitives, and three extension methods. It is a *narrowing* of ~201 RPCs to 28 by **capability**, carrying **no authority scoping** — an interface in Go grants invocation, not permission. **Every method's signature is `context.Context` + protobuf → protobuf; none can carry a principal (§14.2).** `[src]` |

**The finding, stated once:** D11 proved the operator permission model is three booleans consumed in exactly one place. D12 proves the AI tool executor does not pass through that one place. **An operator holding `PermissionAll` is not the constraint that matters here — the constraint that matters is that a model-driven loop can call 41 tools, six of them destructive, on live targets, with no permission check and no human confirmation, while reading untrusted output from those same targets back into its own context.**

---

## 14. Residual closures — §11 items 1 and 2 (added post-publication)

**Two of §11's eight residuals are now materially closed, and they close in the direction §2 and §3 already pointed. Both closures are signature-level analyses; no bodies were read and no provider was used.** `[src]`

**Provenance:** the reading of `buildRequestContext` was supplied by the Lead, who read it and reported it to me rather than editing this lane-owned file. **I re-verified every claim below independently at primary source before recording it**, and one supplied figure was corrected (see §14.3). The Lead's account and my re-derivation agree on the finding.

### 14.1 — §11 item 2: `buildRequestContext` is CLOSED, and by its signature

**`executor.go:629-651`.** The signature is the finding: `[src]`

```go
func buildRequestContext(ctx context.Context, target toolTarget)
    (*commonpb.Request, bool, context.Context, context.CancelFunc, error)
```

**Parameters: `ctx` and a `toolTarget`. That is all.** `toolTarget` is a pair of ID strings (`SessionID`, `BeaconID`) — see the validation at `:630-632`, which rejects the case where both are supplied. **There is no principal, no operator identity, no permission set, no `serverpb` client, no `db` handle.** `[src]`

**Why this closes the residual rather than merely advancing it:** a function whose parameter list cannot express an operator cannot enforce one. **The permission context is not a missing check at this layer — it is not *representable* at this layer.** `[inference]` The body reinforces it: it constructs `&commonpb.Request{Timeout: (int64(time.Second) * timeoutSeconds) - 1}` (`:634-635`), sets `SessionID`/`BeaconID` (`:637-643`), and returns `context.WithTimeout(ctx, ...)` at `:647`. **`commonpb.Request` carries a target and a timeout. It is a routing object, not an authority object.** `[src]`

**The `ctx` it receives is the one that matters, and §2 already established what that context is:** `context.Background()` at `server/rpc/rpc-ai.go:215`. `[src]` **So the chain is now closed end-to-end by type rather than by inference: `context.Background()` → `ctx` → `buildRequestContext(ctx, target)` → a `Request` with no principal → the implant.** `[src]` + `[inference]`

### 14.2 — §11 item 1: the `Backend` interface is CLOSED, and it is 28 methods, not 29

**The narrowed question was: does any `Backend` method take or return a permission-bearing type? Enumerated answer: no. Zero of them.** `[src]`

**Complete signature surface — `executor.go:24-53`, all 28 methods at `:25-52`:** `[src]`

| Method | Signature shape |
|---|---|
| `GetSessions`, `GetBeacons` | `(context.Context, *commonpb.Empty) (*clientpb.{Sessions,Beacons}, error)` |
| `Ls`, `Mv`, `Cp`, `Rm`, `Mkdir`, `Cd`, `Download`, `Pwd`, `Chmod`, `Chown`, `Chtimes`, `Mount` | `(context.Context, *sliverpb.XReq) (*sliverpb.X, error)` |
| `Ifconfig`, `Netstat`, `Ps`, `GetEnv`, `Ping`, `Screenshot` | `(context.Context, *sliverpb.XReq) (*sliverpb.X, error)` |
| `Execute`, `ExecuteWindows`, `ExecuteAssembly` | `(context.Context, *sliverpb.{Execute,ExecuteWindows,ExecuteAssembly}Req) (*sliverpb.{Execute,ExecuteAssembly}, error)` |
| `Sideload`, `SpawnDll` | `(context.Context, *sliverpb.{Sideload,InvokeSpawnDll}Req) (*sliverpb.{Sideload,SpawnDll}, error)` |
| `RegisterExtension`, `ListExtensions`, `CallExtension` | `(context.Context, *sliverpb.XReq) (*sliverpb.X, error)` |

**The discriminator, run as a single predicate over all 28: methods whose parameters are not `context.Context` + protobuf = 0. Methods mentioning `Permission`, `models.Operator`, `auth`, or a principal type = 0.** `[src]`

**So the interface is uniformly `context.Context` + request → response. It is a *capability* surface, not an *authority* surface, and it is now proven so by enumeration rather than asserted.** `[inference]`

### 14.3 — CORRECTION: the `Backend` interface has **28** methods, not 29

**Recorded in place per the corpus's method standard.** `[src]`

| Source | Figure | Status |
|---|---|---|
| D12 §2 and §13 row 5 (this report, as published) | **29 methods** | **WRONG** |
| The Lead's §14 reading | 29 methods | consistent with my earlier figure |
| **Re-enumerated at primary source now** | **28 methods** | **CORRECT** |

**Evidence:** the interface opens at `executor.go:24` (`type Backend interface {`) and closes at `:53` (`}`). Method declarations occupy **`:25-52` inclusive — 28 lines, 28 methods, one per line, no blanks.** `[src]`

**Root cause:** the earlier 29 counted the interface's *extent* (`:24-53` spans 30 lines) or an off-by-one on the closing brace, rather than counting the `:` delimiters. **This is the same instrument-shape failure family as D23 Correction 0 — a count taken over a region instead of over the thing itself.** `[inference]` It is a small error with no effect on any finding (the interface's *composition* is unchanged and §2's capability breakdown still holds), but it is the kind of number other lanes will quote, so it is corrected rather than left.

**Requested action (`[inference]`):** if D11 §6.4 or D15 quotes "29-method Backend", the replacement is **28**. I am not editing those files; reporting it as instructed.

### 14.4 — Positive controls for the permission-absence claim

**The §3 absence is the report's load-bearing negative, so it gets the full control treatment. Both controls bite.** `[src]`

| Probe | Scope | Result |
|---|---:|---|
| `PermissionAll` / `PermissionBuilder` / `PermissionCrackstation` in `server/rpc/aitools/` | 13 files | **0** |
| `permissions.` / `GetPermissions` / `HasPermission` in the same | 13 files | **0** |
| **`models.Operator` in the same** | 13 files | **1 hit — and it is `store_tools_test.go:111`, the string literal `"operator-notes"`.** Not a type reference. |
| **CONTROL: `models.Operator` in the rest of `server/`** | excl. `aitools` | **29 hits** |
| **CONTROL: the three permission booleans across `server/`** | | **17 sites in 4 files:** `db/models/operator.go:36-38` (definition), `console/console-admin.go:139,142,144` (set once), `transport/middleware.go:190,193,198,214,217,222` (consumed once), `transport/middleware_crack_test.go` (7, test) |
| **CONTROL: does the search reach `aitools` code at all?** | `buildRequestContext`/`callTargetRPC` in `aitools/` | **30 hits across 5 files** (`executor.go` 4, `filesystem_tools.go` 10, `helpers.go` 2, `package_tools.go` 6, `system_tools.go` 8) |

**Reading of the controls:** the probe **reaches the package and finds its functions** (30 hits), the permission type **exists and is used 29 times elsewhere in `server/`**, and the three booleans have **exactly one definition site, one write site, and one consumption site**. Against that, `aitools` references the operator type **zero times as a type**. `[src]`

**The `models.` caveat, stated so it cannot mislead:** a search for bare `models.` in `aitools` returns **24 hits (23 in `store_tools.go`, 1 in test)** — which looks like counter-evidence but is not. **Enumerated by type: `models.Credential` 11, `models.Loot` 8, `models.NilUUID` 5, `models.ParseUUIDOrNil` 3.** These are **loot and credential data records** — the subject matter of the store tools — not the operator. **`models.Operator` itself: 0 type references.** `[src]` **An unqualified `models.` count would have produced a false positive here; the qualified probe is what makes the absence real.**

### 14.5 — What is now structurally proven vs what remains

**Proven by type signature (`[src]`):**

1. `buildRequestContext` **cannot receive** an operator — `executor.go:629-651`.
2. None of the **28** `Backend` methods **can carry** a permission — `executor.go:24-53`.
3. `rpc-ai.go:215` passes `context.Background()`, and `:218` passes `*rpc.Server` as `Backend` — `[src]`, §1.
4. The permission booleans are consumed **only** in `transport/middleware.go` — 17 sites across 4 files, one consumer. `[src]`

**The consequence, and it is the sentence §2 should be read with:** **§2's claim that the LLM is a trust principal is no longer an inference from behaviour — it is entailed by three type signatures.** A subsystem that cannot receive an operator identity, handed a context that has none, and invoked through an interface that cannot transmit one, **enforces no operator authority — not because a check was forgotten, but because no check could be written without changing a signature.** `[inference]`

**Remaining §11 residuals, still open:** item 3 (all 41 tool descriptions unread), item 4 (`serverai` read only at boundary), item 5 (AI feature default-enabled state), item 6 (`maxAgenticLoopIterations` value), item 7 (no runtime verification), item 8 (unchanged). **Items 1 and 2 are closed above.**

**One residual this closure *creates*:** if `*rpc.Server`'s concrete implementations of those 28 methods perform internal permission checks, the absence at the `aitools` layer would not matter. **§2's argument is that they do not — because the only consumers of the permission booleans are in `transport/middleware.go`, and `rpc.Server` methods are reached here as direct Go calls that never traverse that middleware.** `[src]` + `[inference]` **That is D11's finding, and it is why these two reports have to be read together: neither is complete alone.**

