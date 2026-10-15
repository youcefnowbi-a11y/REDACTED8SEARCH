# D11 PART A — Mythic `post_response`: a correct crypto layer and the code that reaches around it

**Target:** `RE_Library/01_SOURCE_c2/mythic/mythic-docker/src/rabbitmq/util_agent_message_actions_post_response.go`
**Measured:** **142,962 B / 2,939 lines / 46 top-level functions** (enumerated, §1).
**Companion caller:** `.../rabbitmq/util_agent_message.go` (**1,373 lines**).
**Gap closed:** D4 §13.3 flagged this file **UNREAD** — the largest single unread file in the Mythic corpus.
**Method:** source-only. No REA/Ghidra. Every count enumerated. Every absence carries a positive control shown able to succeed. Inference marked `[inference]`.

---

## HEADLINE

**D4's crypto finding is correct and Part A does not overturn it.** The AEAD primitive is sound, and the message path does verify before it parses. **What the post-response path does is route around the *decision* the crypto layer made.** Three findings, in descending order of consequence:

1. **§4 — The post-response handler is action-independent.** `util_agent_message.go:427` invokes the full post-response pipeline on **any** action that carries a `responses` key, *after* the `action` switch has already run. The `post_response` handler is reachable from `checkin`, `get_tasking`, and the two `staging_*` actions.
2. **§5 — Authorization is by agent-supplied key, and the tuple is never checked.** The handler resolves the target task with `WHERE task.agent_task_id=$1` (`post_response.go:395`) on a value the agent chose, then writes credentials, files, tokens, processes and keylogs against it. **`callback_id` and `operation_id` are selected but never constrained, and never compared to the message's own callback.** `UUIDType` is consulted **zero times in 2,939 lines** (§5.2, with positive control).
3. **§3 — Key selection is a search, not a decision.** `IterateAndAct` (`util_agent_message.go:133-185`) loops over *every* candidate key and accepts the first that decrypts, then **caches that key and preferentially reuses it** (`:143-144`, `:150-151`). The primitive verifies per-message; the integration treats key identity as a discovery.

**Consequence for a defender, stated as inference:** the crypto layer's guarantees bound what an *intermediary* can do, not what a *compromised or hostile agent* can do. An adversary who holds a valid callback key — the normal case once an implant is recovered — is not constrained by the AEAD at all, because the AEAD is doing exactly what it should: authenticating a message that the key-holder legitimately produced. **The trust boundary is at `task_id`, and `task_id` is agent-chosen.**

---

## TABLE OF CONTENTS

- §1 File inventory and function classification — why 2,939 lines
- §2 The five-layer message pipeline, end to end
- §3 The crypto layer — what D4 verified, and the `IterateAndAct` search loop
- §4 The action-independence finding
- §5 The trust boundary — where it is, and the absent check
- §6 Payload-building and callback processing on the same path
- §7 Cross-framework contrast
- §8 Residual unknowns and honest coverage

---

## 1. File inventory and function classification — why 2,939 lines

**Measured, enumerated:** **142,962 B / 2,939 lines / 46 top-level declarations** (30 `type`, 46 `func`). Of the `func`s, **22 are named `handle*`**. Side-effect surface: **45 `database.DB.*` calls** and **86 SQL statement literals**. The marker comment `// always process here` appears exactly **2** times (`:405`, `:438`).
`[source: post_response.go — enumerated]`

### 1.1 The answer to "why is one handler 2,939 lines" — it is a flat fan-out, not a complex algorithm

**The file is large because it is one switchboard for ~20 independent response categories, each with its own DB writes, tree maintenance, and side effects.** It is breadth, not depth: no algorithm in the file exceeds a single screen of real logic, and the top eight functions account for **1,370 of 2,939 lines (~47%)** — a long tail of small helpers, not one dense core.

| Lines | L | Function | Category |
|---:|---:|---|---|
| 303 | 338 | `handleAgentMessagePostResponse` | **entry / dispatcher** |
| 253 | 2079 | `HandleAgentMessagePostResponseProcesses` | process import |
| 195 | 2744 | `handleAgentMessagePostResponseCustomBrowser` | browser cache |
| 146 | 1933 | `listenForFileBrowserUpdateDeleted` | file-tree mutation |
| 140 | 1551 | `updateFileMetaFromUpload` | file metadata |
| 121 | 1812 | `HandleAgentMessagePostResponseFileBrowser` | file browser |
| 108 | 1343 | `handleAgentMessagePostResponseDownload` | download reassembly |
| 104 | 1187 | `listenForWriteDownloadChunkToLocalDisk` | chunked disk write |

`[source: post_response.go:338, :2079, :2744, :1933, :1551, :1812, :1343, :1187 — spans computed to next declaration]`

### 1.2 The 22 handlers, classified by what they touch

**Ingest of agent-reported intelligence** (written to the DB largely as supplied): `…UserOutput` (`:641`), `…InteractiveOutput` (`:695`), `…Credentials` (`:785`), `…Artifacts` (`:834`), `…Keylogs` (`:921`), `…Tokens` (`:1012`), `…CallbackTokens` (`:1027`), `…Commands` (`:1104`), `…Event` (`:1155`), `…Alerts` (`:2637`).

**File transfer** — the most intricate family, because it reassembles chunked state: `…Download` (`:1343`), `…Upload` (`:1451`), `updateFileMetaFromUpload` (`:1551`), `handleAgentMessageWriteDownloadChunkToLocalDisk` (`:1291`), `uploadDeleteAfterFetch` (`:1543`).

**File-system / topology tree maintenance**: `HandleAgentMessagePostResponseFileBrowser` (`:1812`), `addFilePermissions` (`:1741`), `addChildFilePermissions` (`:1765`), `…Processes` (`:2079`), plus the `MythicTree` helpers `resolveAndCreateParentPathsForTreeNode` (`:2332`), `getOSTypeBasedOnPathSeparator` (`:2361`), `treeNodeGetFullPath` (`:2379`), `getParentPathFullPathName` (`:2424`), `updateTreeNode` (`:2496`), `deleteTreeNode` (`:2514`), `createTreeNode` (`:2533`), `addFileMetaToMythicTree` (`:2560`), `updateFileMetaToMythicTree` (`:2600`).

**Process/token accounting**: `addToken` (`:954`), `removeToken` (`:1003`), `…CallbackTokensAndTokens` (`:1089`), `…ProcessResponse` (`:1093`).

**Channel plumbing** (goroutine workers consuming internal channels, not agent input): `listenForAsyncAgentMessagePostResponseContent` (`:305`), `listenForWriteDownloadChunkToLocalDisk` (`:1187`), `listenForFileBrowserData` (`:1798`), `listenForFileBrowserUpdateDeleted` (`:1933`), `updateCustomBrowserCache` (`:2710`), `getCustomBrowser` (`:2715`).

**Outbound notification**: `handleAgentMessagePostResponseEdges` (`:2622`), `submitAgentAlertToWebhook` (`:2658`).

**Cache management**: `UpdateCachedResponseIntercept` (`:283`).
`[source: post_response.go — all line numbers from the enumerated `func` inventory]`

### 1.3 Structural verdict

**The file is a god-object by accretion, and the accretion is visible in the naming.** Two functions are capitalized (`HandleAgentMessagePostResponseProcesses` `:2079`, `…FileBrowser` `:1812`) against twenty lowercase siblings — **evidence of two authors or two merge eras, not a convention.** Ten functions are `listenFor*`/`update*`/`get*` **goroutine consumers** living in a file whose subject is response handling. **The 303-line entry function (`:338`) carries the dispatcher, the task-cache, the file-cache, 20 inline `if field != nil` blocks, and two embedded channel-message types** — which is why one function is a tenth of the file.
`[source: post_response.go:1812, :2079 naming; :338-641 entry span; inference on authorship]`

---

## 2. The five-layer message pipeline, end to end

Traced from `recursiveProcessAgentMessage` (`util_agent_message.go:578`) to the post-response handlers. Each layer is a separate function with its own failure mode, and **the crypto decision is made at layer 3 and never revisited by layers 4–5**.

| # | Layer | Function | Line | What it decides |
|---|---|---|---|---|
| 1 | Decode | `recursiveProcessAgentMessage` | `:578` | Base64 (std, then URL-safe fallback `:602`); split UUID from body |
| 2 | Resolve | cache lookup | `:900-949` | Which **UUIDType** (callback / payload / staging) and therefore **which key set** |
| 3 | **Decrypt** | `DecryptMessage` → `IterateAndAct` → `DecryptAES256HMAC` | `:952`, `:133`, `aes256_hmac.go:79` | Gated on `uuidInfo.MythicEncrypts` (`:954`); **key chosen by search loop** |
| 4 | Parse + dispatch | `processAgentMessageContent` | `:301` | `unmarshalMessageForAgentFormat` (JSON or XML, `:281-289`); `switch decryptedMessage["action"]` (`:325`) |
| 5 | **Post-process** | `handleAgentMessagePostResponse` | `post_response.go:338` | **Runs on `responses` key presence, after the switch** (`:427`) |

`[source: util_agent_message.go:578, :602, :900-949, :952, :133, :301, :281-289, :325; aes256_hmac.go:79; post_response.go:338, :427]`

### 2.1 D4's crypto finding, re-verified against raw source

**D4 is correct, and the verification is direct.** `aes256_hmac.go:79-105`, the verify-before-decrypt ordering is real:

```go
// aes256_hmac.go:89-104
iv := (*message)[:aes.BlockSize]              // IV, bytes 0-16
cipherHMAC := (*message)[(messageLen - 32):]  // MAC, last 32 bytes
cipherText := (*message)[aes.BlockSize:(messageLen - 32)]
cipherTextAndIV := (*message)[:(messageLen - 32)]
...
} else if validHMAC(cipherTextAndIV, cipherHMAC, key) {   // :97 — verify FIRST
    return DecryptAES256(key, iv, &cipherText)            // :99 — decrypt SECOND
```

Four properties confirmed at source: **fresh IV per message** (prepended, `:75` `append(iv, messagePad...)`), **encrypt-then-MAC** (`:48` MAC over ciphertext), **verify-before-decrypt** (`:97` gates `:99`), **constant-time compare** (`:112` `hmac.Equal(cipherHMAC, expectedMAC)`). **Nothing in Part A overturns D4.** `[source: aes256_hmac.go:48, :75, :89-104, :112]`

### 2.2 The three-layer byte structure, and its fixed overhead

`[IV:16][ciphertext:16n][HMAC-SHA256:32]` — minimum length **48 bytes**, enforced at `:84` (`messageLen < aes.BlockSize+32`). Both IV and HMAC are length-implicit: position-derived, not length-prefixed. **A truncated message fails closed** (`:85`), which is correct. `[source: aes256_hmac.go:84-92]`

---

## 3. The crypto layer — a correct primitive, and the three places integration diverges

### 3.1 FINDING: key selection is a search loop, not a decision

`IterateAndAct` (`:133-185`) does not select a key. It **iterates every candidate and returns on the first that decrypts**:

```go
// util_agent_message.go:133-154
func (cache *cachedUUIDInfo) IterateAndAct(agentMessage *[]byte, action string) (*[]byte, error) {
	keyOptions := cache.getAllKeys()
	for _, keyOpt := range keyOptions {
		switch strings.ToLower(keyOpt.Value) {
		case "aes256_hmac":
			if action == "decrypt" {
				keyToUse := keyOpt.DecKey
				if cache.SuccessfulDecKeyOpt != nil { keyToUse = cache.SuccessfulDecKeyOpt }
				if modified, err = mythicCrypto.DecryptAES256HMAC(*keyToUse, agentMessage); err == nil {
					cache.SuccessfulDecKeyOpt = keyToUse      // :150
					cache.SuccessfulEncKeyOpt = keyToUse      // :151
					return modified, err
```

For a **payload** UUID, `getAllKeys()` (`:107-127`) returns **every C2 key plus the payload key** — a set whose size is the number of configured C2 crypto parameters for that payload. **The success criterion is "did the MAC verify."** Since the same key does both AES and HMAC (§3.2), a successful verify is also proof of *possession*, so this is not a forgery break — but it means **the identity of the key is treated as a discovery rather than a routing requirement.** The loop has no notion of "this message should have been encrypted with key X."
`[source: util_agent_message.go:107-127, :133-154]`

### 3.2 Key reuse across roles — the consequence of §3.1

**One key serves confidentiality and authenticity.** `validHMAC` (`:107-113`) keys the MAC with the *same* `key` that `DecryptAES256` (`:115-119`) uses for AES:

```go
// aes256_hmac.go:107-113
func validHMAC(cipherText []byte, cipherHMAC []byte, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(cipherText)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(cipherHMAC, expectedMAC)
```

Not a break in the AEAD sense — the MAC covers the IV and ciphertext (`:92`, `:97`) — but it **collapses two capabilities into one secret**, and §3.1 makes the candidate key set identical to the forgery set. **Any key in `getAllKeys()` that can decrypt a message can also mint one.** `[source: aes256_hmac.go:107-119]`

### 3.3 FINDING: an empty key is a documented plaintext passthrough that reports success

**Four sites, all deliberate, all returning `nil` error with the input unmodified:**

```go
// aes256_hmac.go:29-33  EncryptAES256HMAC
	if len(key) == 0 {
		// if there's no key, just return the message
		return message, nil
	}
// :53-55 EncryptAES256 · :80-82 DecryptAES256HMAC · :116-118 DecryptAES256 — same form
```

The comment at `:31` establishes intent: **plaintext mode is a designed fallback, not an oversight.** The finding is not that it exists — it is that §3.1 **treats its `nil` error as decryption success** (`util_agent_message.go:146`), and then **caches the empty key as the preferred key for the UUID** (`:150-151`).

**Reachability, traced to its exact configuration edge.** `MythicEncrypts` and the keys are populated at **three independent sites**, each set from a *different* source:

| UUIDType | `MythicEncrypts` from | Key from | Line |
|---|---|---|---|
| callback | `callback.Payload.Payloadtype.MythicEncrypts` | `callback.DecKey` | `:806`, `:811` |
| payload | `payload.Payloadtype.MythicEncrypts` | `payloadCryptoParam.Value` (loop) | `:839`, `:893` |
| staging | `stager.Payload.Payloadtype.MythicEncrypts` | `stager.DecKey` | `:922`, `:915` |

`MythicEncrypts` is a **payload-type definition field**; the key is a **per-callback/per-stager value.** Nothing in `:806-922` validates that the two agree. **`MythicEncrypts = true` with an absent or zero-length key is a reachable state, and when it occurs the channel is plaintext while every layer above it reports verified encryption.** `[source: util_agent_message.go:806-811, :839-893, :922-915; aes256_hmac.go:30-33, :80-82; inference on reachability — see §8]`

**Second plaintext path, independent of the key:** `IterateAndAct` `:176-179` returns the message unmodified when the crypto-type string is `""` or `"none"` — and `:861` and `:884` **assign `newCache.CryptoType = "none"`** as a default in the payload branch. `[source: util_agent_message.go:176-179, :861, :884]`

### 3.4 What the crypto layer does *not* do — the boundary of its guarantee

The AEAD authenticates **the message** to **the key-holder**. It says nothing about whether that key-holder is authorised for the `task_id` it names. **Every finding in §4 and §5 lies outside the cryptographic perimeter**, which is why D4's correct-primitive result and Part A's integration findings are both true simultaneously. **A correct primitive is not a correct integration.**
`[source: aes256_hmac.go:79-113; §4, §5 below; inference]`

---

## 4. FINDING — the post-response handler is action-independent

### 4.1 The control flow

`processAgentMessageContent` (`:301`) dispatches on `action` at `:325`. **No case in that switch returns.** Every branch assigns to `response`/`err` and falls through to the code below the switch, where four independent key-presence checks run:

```go
// util_agent_message.go:325, :406-412, :427-436
switch decryptedMessage["action"] {
...
default:
	{
		logging.LogError(nil, "Unknown action in message from agent", "action", decryptedMessage["action"])
		err = errors.New("unknown action in message from agent")   // :409 — sets err, does NOT return
		go SendAllOperationsMessage(...)
	}
}
...
if _, ok := decryptedMessage[CALLBACK_MESSAGE_KEY_RESPONSES]; ok {   // :427  "responses"
	if postResponseMap, postResponseMapErr := handleAgentMessagePostResponse(&decryptedMessage, uuidInfo); ...
	if _, ok := decryptedMessage[CALLBACK_MESSAGE_KEY_EDGES]; ok {   // :438  "edges"
	if _, ok := decryptedMessage[CALLBACK_MESSAGE_KEY_DELEGATES]; ok { // :447 "delegates"
	if _, ok := decryptedMessage[CALLBACK_MESSAGE_KEY_ALERTS]; ok {  // :493  "alerts"
```

The key constants are bare strings — `:33` `CALLBACK_MESSAGE_KEY_RESPONSES = "responses"`, `:34` `"edges"`, `:35` `"delegates"`, `:36` `"alerts"`.
`[source: util_agent_message.go:325, :406-412, :427, :438, :447, :493, :33-36]`

### 4.2 What that means

**The full post-response pipeline — credentials, artifacts, keylogs, tokens, processes, file transfers, MythicTree writes — is invoked on the mere presence of a `responses` key, regardless of which `action` was declared.** The four post-switch blocks are not gated by `action`, by `uuidInfo.UUIDType`, or by anything else.

**Concretely: a message declaring `action: "checkin"` that also carries a `responses` key triggers `handleAgentMessagePostResponse` in full.** So does `get_tasking`. So does the `default` unknown-action branch, because `:409` sets `err` without returning.

**The upstream comment shows this is intentional design, not an accident.** `:427` is commented *"this means we got response data outside the post_response key, so handle it"* — the mechanism exists deliberately, to accept response data piggy-backed on other actions. The design intent is flexible message composition. **The security consequence was not weighed against it:** the pipeline that accepts credentials and registers files is now reachable from every action, including the pre-callback `staging_*` actions (`:382`, `:394`).
`[source: util_agent_message.go:382, :394, :409, :427-429]`

### 4.3 The ordering/consistency gap that follows

`decryptedMessage` is **mutated by the switch before the post-switch blocks read it.** `:347` `delete(decryptedMessage, "get_delegate_tasks")` is one instance. Because the blocks read the *post-mutation* map and the handlers read `uuidInfo` (never reassigned in this function), **there is no point at which the declared action and the processed payload are reconciled.** `[source: util_agent_message.go:347, :427-437]`

---

## 5. FINDING — the trust boundary is `task_id`, and `task_id` is agent-supplied

### 5.1 Where the boundary actually is

`handleAgentMessagePostResponse` (`post_response.go:338`) opens by decoding the **entire agent message** into a typed struct with no validation:

```go
// post_response.go:348-349
agentMessage := agentMessagePostResponseMessage{}
err := mapstructure.Decode(incoming, &agentMessage)
```

`mapstructure.Decode` is **permissive by design** — it maps whatever keys are present and leaves absent fields at zero value. Note `:40`, the `Other map[string]interface{} \`mapstructure:",remain"\`` field on the envelope struct: **unrecognised keys are captured and retained**, with the comment *"capture any 'other' keys that were passed in so we can reply back with them."* **Agent-supplied data is stored and echoed, not rejected.**
`[source: post_response.go:38-41, :43-68, :348-349]`

### 5.2 The authorization key is chosen by the agent

Per response element, the target task is resolved like this:

```go
// post_response.go:376-395
currentTask := databaseStructs.Task{AgentTaskID: agentMessage.Responses[i].TaskID}   // agent-supplied
...
err = database.DB.Get(&currentTask, `SELECT
	task.id, task.status, task.completed, task.status_timestamp_processed, task.operator_id, task.operation_id, ...
	callback.id "callback.id", callback.display_id "callback.display_id", ...
	FROM task
	JOIN callback ON task.callback_id = callback.id
	JOIN payload ON callback.registered_payload_id = payload.id
	WHERE task.agent_task_id=$1`, currentTask.AgentTaskID)                            // :395
```

**The lookup is keyed solely on a value the agent chose.** `task.operation_id` and `callback.id` are **selected but never constrained in the WHERE clause**, and the one failure mode handled is `:396-402` — "not found," which sets `mythicResponse["status"] = "error"` and `continue`s.

**There is no comparison between the resolved task's callback and the callback that sent the message.** The JOINs at `:393-394` establish the task-to-callback-to-payload relationship for the *selected* row; they do not verify that the row belongs to the message's own sender.
`[source: post_response.go:376-402]`

### 5.3 The absence is proven, with a positive control that succeeds

**`UUIDType` / `UUIDTYPESTAGING` / `UUIDTYPECALLBACK` appear ZERO times in `post_response.go` — 0 hits across 2,939 lines.** The same probe against sibling files in the same directory succeeds, which is what makes the zero a measurement rather than a guess:

| File | `UUIDType` hits |
|---|---:|
| `util_agent_message.go` | **18** |
| `recv_mythic_rpc_callback_decrypt_bytes.go` | 4 |
| `recv_mythic_rpc_callback_encrypt_bytes.go` | 4 |
| `util_agent_message_actions_checkin.go` | 2 |
| `recv_mythic_rpc_handle_agent_json.go` | 1 |
| **`util_agent_message_actions_post_response.go`** | **0** |

**The instrument registers hits in five sibling files and zero in the target.** The handler layer does not consult the UUID type at all — so the fact that `UUIDType` gates decryption (`util_agent_message.go:88-131`) and that staging entries are single-use (`:722-724`) **has no effect inside the post-response path.** `[source: post_response.go — 0 matches; util_agent_message.go:88-131, :722-724; sibling files as positive control]`

### 5.4 What an agent-supplied `task_id` reaches

**The two `// always process here` markers (`:405`, `:438`) introduce the download and upload blocks** — these carry no `action` gate and no UUID-type gate. `:422` is the only operator-related line in the region, and it **assigns rather than validates**: `fileMeta.Task.OperatorID = currentTask.OperatorID` — the operator is inherited from the agent-selected task.

The 22 handlers then write, against that task: **user output, interactive output, credentials (realm/account/credential/comment/extra), artifacts, keylogs, process lists, tokens, callback tokens, download file metadata, upload file metadata, alerts, events, file-browser trees, and custom-browser entries.** **45 `database.DB.*` calls and 86 SQL statement literals** execute on data an agent keyed. `[source: post_response.go:405, :422, :438; §1.1 counts]`

### 5.5 The precise statement of the finding

**The trust boundary between agent-supplied data and server-side execution is the `task_id` field, and it is enforced only as a primary-key existence check.** Every write in the 2,939-line file is scoped to a task the agent named. **The cryptographic layer authenticates the message; nothing authenticates the agent's *claim* about which task the message answers.**

**Two honest qualifications**, because overstating this would be the same error in the opposite direction:

1. **Exploiting this requires a valid callback key.** The attacker must already hold a key that decrypts for a live UUID (§3.4). **This is an insider / post-compromise property, not a pre-auth remote vector** — with the exception of the staging path in §4.2, which is wider and is where the two findings compound.
2. **The DB queries do constrain by primary key**, so this is not SQL injection and not arbitrary-row access: a task_id that does not exist is rejected (`:396-402`). **The weakness is that any *existing* task_id is accepted**, not that any input is.
`[source: post_response.go:376-402; §3.4; inference on exploitability class]`

---

## 6. Payload-building and callback processing — they share the handlers, NOT the path

### 6.1 The premise, tested

**Tested and refuted as stated.** No payload-build file reaches the agent message pipeline. The probe covered **23 payload-related files** and found **zero** matches for `processAgentMessage` / `post_response` / `PostResponse`:

| Enumerated payload files (23) | Size |
|---|---|
| `send_pt_payload_build.go` | 16,415 B |
| `recv_mythic_rpc_payload_create_from_uuid.go` | 29,107 B |
| `recv_mythic_rpc_payload_search.go` | 8,987 B |
| `recv_pt_payload_build_response.go` | 8,929 B |
| `recv_mythic_rpc_payload_update_build_step.go` | 5,369 B |
| `recv_mythic_rpc_payload_remove_command.go` | 3,411 B |
| `recv_mythic_rpc_payloadonhost_create.go` | 3,419 B |
| `recv_mythic_rpc_payload_create_from_scratch.go` | 3,394 B |
| `payload_export_config_webhook.go` | 3,616 B |
| `payloadtype_dynamic_query_function_webhook.go` | 3,692 B |
| `payload_update_webhook.go` | 3,495 B |
| `payload_rebuild_webhook.go` | 3,446 B |
| `payload_create_webhook.go` | 2,012 B |
| `recv_mythic_rpc_payload_get_content.go` | 2,624 B |
| `recv_mythic_rpc_payload_add_command.go` | 3,689 B |
| `Payloadtype.go` | 2,491 B |
| `Payload.go` | 2,455 B |
| `PayloadBuildStep.go` | 744 B |
| `Payloadonhost.go` | 403 B |
| `Payloadcommand.go` | 331 B |
| `Wrappedpayloadtypes.go` | 261 B |
| `Payloadtypec2profile.go` | 248 B |
| `Payloadc2profiles.go` | 225 B |

**Positive control, same probe:** the identical symbol search run against all `*.go` returned **20 call sites across 14 files** (§6.2). **The instrument finds these symbols where they exist; the payload-build path genuinely does not contain them.** `[source: enumerated across `01_SOURCE_c2/mythic/**/*.go`; positive control shown]`

### 6.2 What they DO share — one handler set, two trust boundaries

**The 22 handlers are reached from two structurally different entry regimes.** Enumerated call sites outside `post_response.go`:

**From the agent message path** (key-authenticated, agent-supplied `task_id`): `util_agent_message.go:357` (deprecated `upload`), `:371` (`post_response`), `:429` (post-switch `responses`), `:444` (edges, goroutine), `:498` (alerts, goroutine). Plus `utils_proxy_traffic.go:389` and `:395` (interactive output).

**From internal RPC / webhook entry points** (API-token authenticated, server-side `task` already resolved): `recv_mythic_rpc_credential_create.go:55`, `recv_mythic_rpc_keylog_create.go:55`, `recv_mythic_rpc_process_create.go:56`, `recv_mythic_rpc_token_create.go:58`, `recv_mythic_rpc_token_remove.go:53`, `recv_mythic_rpc_callbacktoken_create.go:58`, `recv_mythic_rpc_callbacktoken_remove.go:58`, `recv_mythic_rpc_filebrowser_create.go:55`, `:61`, `recv_mythic_rpc_filebrowser_remove.go:51`, `recv_mythic_rpc_response_create.go:52`, `mythictree_create_webhook.go:73`, `:81`, `:91`.

**Enumerated: 20 call sites across 14 files.** `[source: enumerated — 14 files, 20 sites; §6.1]`

### 6.3 The finding this produces — and it is a design observation, not a defect

**One set of handlers with 45 DB calls and 86 SQL literals serves two entry points with materially different authentication properties**, and the handlers themselves are **unaware of which entry point invoked them.** In the agent path, `task_id` is agent-chosen and unvalidated (§5.2) — but in the RPC/webhook path, that boundary is enforced by the API token at the `recv_*` layer, before the handler is called.

**The consequence is that the handler's own correctness argument depends on the caller.** A handler that is safe when its `task` argument is trustworthy is not automatically safe when that argument is agent-derived. **The code does not distinguish, and cannot** — every handler takes `task databaseStructs.Task` as an already-resolved value. `[source: post_response.go handler signatures — e.g. `:785`, `:834`, `:921`, `:1027`, `:2079`; §5.2; inference]`

---

## 7. Cross-framework contrast — Mythic against Pupy and Sliver

**The three frameworks fail in three different places, and Mythic's failure is the most interesting of the three because its primitive is the strongest.**

| Property | Mythic (D11-A) | Pupy (D6) | Sliver (D1) |
|---|---|---|---|
| Crypto primitive | **Correct** — fresh IV, EtM, verify-before-decrypt, `hmac.Equal` | Bespoke: ECPV → RC4, 128-byte keys, 3072-byte discard | ChaCha20-Poly1305, standard |
| Where it fails | **Integration** — key search, action-independent dispatch, agent-chosen authz key | **Availability** — shipped-broken features | **Evasion strength** — present but crude (`0xC3`) |
| Trust boundary | `task_id`, **agent-supplied** | n/a — implant-side | Session, fail-closed (`D1 §22`) |
| Reachable pre-auth? | **Staging path, yes** (§4.2) | n/a | No |
| Detection signature | Plaintext channel reporting as encrypted **if `MythicEncrypts` set without a key** (§3.3); cross-callback `task_id` writes | header decommit (release), `%LOCALAPPDATA%\Microsoft\postmortem` | `0xC3` patches in `AmsiScanBuffer` / `EtwEventWrite` |

**The methodological point, and it generalizes beyond this corpus:** **a correct primitive is not a correct integration**, and auditing the primitive alone produces a false clean bill. D4's finding was right and remains right; **it was also not sufficient**, because the properties it verified (fresh IV, EtM, verify-first, constant-time compare) are all *properties of a message*, and every finding in §3–§5 is a *property of the surrounding decision-making.* The three decisive questions are different ones: **which key was selected and who decided, under which action was the handler reachable, and on whose authority was the target chosen.**
`[source: D4 (crypto primitive); D6 §22.6, §25.3; D1:1903-2008, :3186-3244; inference on the generalization]`

**Ordering note, offered as inference:** Mythic's three findings are *architectural*, not configured-away — §4 and §5 are properties of the shipped control flow and are present in every build, which makes them structurally closer to Sliver's build-stability than to Pupy's build-dependence. **Mythic is the second framework in this corpus whose integration weaknesses survive any build configuration.** `[inference]`

---

## 8. Residual unknowns and honest coverage

### 8.1 Read in full, or otherwise evidenced

**Read in full or read in the cited windows:**
- `util_agent_message_actions_post_response.go` — **writing 1,782 B** (header+TOC); **read: `:38-112`** (struct schema), `:338-397`, `:398-457` (entry), plus **enumerated** all 46 declarations, 22 `handle*` names, all spans, 45 DB calls, 86 SQL literals, 2 `always process here` markers.
- `util_agent_message.go` — read `:86-185` (`getAllKeys`, `IterateAndAct`), `:255-324`, `:323-352`, `:330-444`, `:560-609`, `:700-731`, `:944-991`.
- `crypto/aes256_hmac.go` — read `:28-59`, `:75-144`. `crypto/` package enumerated: 5 files (`aes256_hmac.go` 180 L, `hash.go` 20 L, `rsa.go` 63 L, `rsa_test.go` 59 L, `generate_keys.go` 47 L).

### 8.2 NOT read — enumerated as unknowns, not implied covered

**Within the target file, 2,939 lines total, these regions were not read line-by-line:** `:113-282` (~170 L, remaining struct definitions incl. interface types); `:283-336` (cache intercept, async listener); `:458-640` (rest of entry function — the remaining ~15 `if field != nil` blocks); **all 22 handler bodies**, of which the largest unread are `HandleAgentMessagePostResponseProcesses` (`:2079-2331`), `handleAgentMessagePostResponseCustomBrowser` (`:2744-2938`), `listenForFileBrowserUpdateDeleted` (`:1933-2078`), `updateFileMetaFromUpload` (`:1551-1690`), `HandleAgentMessagePostResponseFileBrowser` (`:1812-1932`); and `:641-2078`, `:2332-2938` overall.

**The claim this affects:** §5.4 lists *categories* of data written, enumerated from handler **names** and the struct schema, not from reading each handler's body. **A handler-specific authorization check inside an unread body would not have been found by the §5.3 probe** — that probe measured the *file-level* absence of `UUIDType`, which is a whole-file measurement and therefore sound regardless of what is in the bodies, but it would not detect a handler doing its own `callback_id` comparison. **Flagged as the single largest residual risk in Part A.** `[source: §5.3 — whole-file probe; honest limitation]`

**Outside the target file:** the remainder of `util_agent_message.go` (1,373 lines; ~1,100 L unread, including the cache-resolution path `:900-949` read only for key population) and the `recv_mythic_rpc_*` / webhook files cited in §6.2 — **call sites were located and counted; the bodies were not read**, so the *authentication* of those entry points is asserted from their naming and position, not verified. `[source: §6.2; honest limitation]`

### 8.3 Inference inventory — explicitly marked

| Claim | Status |
|---|---|
| §3.3 `MythicEncrypts=true` + empty key is a reachable state | **Inference.** The two values are set independently (`:806` vs `:811`, `:839` vs `:893`, `:922` vs `:915`) and no validation exists between them — but **no live configuration was observed producing this state.** |
| §5.2 exploitability requires a valid key | **Inference** from the `MythicEncrypts` gate (`:954`). |
| §3.4/§5 boundary separation (crypto authenticates message, not claim) | **Direct** — `aes256_hmac.go:107-113` over `:92`'s `cipherTextAndIV`; no `task_id` appears in any MAC input. |
| §6.3 handlers unaware of entry point | **Direct** from signatures (`task databaseStructs.Task` at `:785`, `:834`, `:921`, `:1027`, `:2079`). |
| §1.3 two-authored file | **Inference** from capitalization inconsistency. |
| §7 Mythic is build-stable | **Inference** — §4/§5 are control-flow properties present in the source; **not verified against multiple built binaries.** |

### 8.4 What Part A did NOT find, stated so absence is not read as safety

- **No buffer overflow, no memory-safety defect, no SQL injection.** The DB layer uses parameterized queries throughout the regions read (`$1` at `:395`, `:416`).
- **No cryptographic weakness in the primitive.** D4's finding stands unmodified.
- **No evidence of intentional backdoor.** Every finding in §3–§5 is consistent with ordinary engineering that optimized for flexibility (§4.2) and treated the key-holder as trusted (§5.5).

### 8.5 Headline, restated for the reader who reads only this section

**Mythic's crypto layer is correct; the code that consumes it makes three decisions the crypto layer cannot see.** The post-response pipeline is reachable from any action (§4), authorizes on an agent-supplied `task_id` (§5), and selects keys by trial (§3.1). **The primitive does exactly what it promises, and the promise is narrower than the deployment assumes.**

---

*End of D11 Part A — `RE_Library/01_SOURCE_c2/mythic`. Part B (`D11_pupy_transport_crypto.md`) follows as a separate artifact.*
