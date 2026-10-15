# T4 — Mythic C2 Framework

**Version:** 3.4.36 [source: `VERSION`, `mythic-docker/src/utils/config.go:12` (`mythicServerVersion = "3.4.36"`)]
**Docker image tag:** `v3.4.0.61` [source: `Mythic_CLI/src/cmd/config/constants.go:5`]
**Corpus:** 1,072 files — 399 Go, 274 JavaScript, 70 YAML
**Repo layout:** multi-container, microservice architecture (Go server + Hasura GraphQL + Postgres + RabbitMQ + React UI + Nginx + Python agent/C2 containers)

---

## 1. Architecture

### 1.1 Component split

| Component | Directory | Language | Role |
|---|---|---|---|
| Mythic Server (core) | `mythic-docker/` | Go | Agent message processor, tasking, crypto, RabbitMQ router, webserver, gRPC |
| PostgreSQL | `postgres-docker/` | config | Persistent state (27 migrations) |
| Hasura GraphQL | `hasura-docker/metadata/` | YAML | GraphQL API over Postgres with JWT-derived claims |
| RabbitMQ | `rabbitmq-docker/` | config | Inter-container message bus (vhost `mythic_vhost`) |
| React UI | `MythicReactUI/`, `mythic-react-docker/` | JavaScript | Operator interface |
| Mythic CLI | `Mythic_CLI/` | Go | Management CLI (install/start/stop/backup/restore) |
| Nginx | `nginx-docker/` | config | TLS termination / reverse proxy |
| Prometheus / Grafana / postgres-exporter | `prometheus-docker/`, `grafana-docker/`, `postgres-exporter-docker/` | config | Metrics |
| Jupyter | `jupyter-docker/` | Python notebooks | Scripting examples |
| Documentation | `documentation-docker/` | Hugo | Docs |

**Agents (the implant side) and C2 profiles are NOT in this repo.** They are separate Docker containers pulled at install time — `InstalledServices/` contains only `.keep` [source: `InstalledServices/.keep`]. The Mythic server repo is the *controller* half only. This is the single most important scoping fact for T4: Mythic = C2 orchestration server; the implant tradecraft lives in out-of-tree agent repos (Apollo, Poseidon, Apollo, Athena, etc.) and C2 profile repos (http, websocket, smb, tcp, dns, github, slack…).

### 1.2 Server ↔ agent split

The server is fully agent-agnostic. Everything agent-specific is data-driven through four registration concepts stored in Postgres:

- **`payloadtype`** — declares `message_format` (`json` | `xml`), `message_uuid_length` (16 or 36), `mythic_encrypts` (bool), `translation_container_id`, and container RPC entry points [source: `mythic-docker/src/rabbitmq/util_agent_message.go:784-829`]
- **`c2profile`** — declares whether it `is_p2p`, plus crypto-typed parameters [source: `util_agent_message.go:761-779`]
- **`c2profileparameters` / `c2profileparametersinstance`** — per-payload C2 crypto parameters (e.g. AES key, XOR key, base64 variant) flagged with `crypto_type=true` [source: `util_agent_message.go:850-875`]
- **`buildparameterinstance`** — payload build-time crypto key material (`enc_key`, `dec_key`, `value`) [source: `util_agent_message.go:876-894`]

Dispatch is via **RabbitMQ RPC** for C2 profiles / translation containers and **gRPC streaming** for translation containers. Payload-type containers communicate over RabbitMQ fanout exchanges.

### 1.3 Language breakdown of the core

Go is the entire server. Key package map:

```
src/authentication/     jwt.go, middleware.go, ValidateLogin.go, mythicjwt/jwt.go
src/crypto/             aes256_hmac.go, rsa.go, generate_keys.go, hash.go
src/database/           27 migrations, enums/, structs/
src/eventing/           workflow/eventing engine (+ eventing.go, 68 KB)
src/files/              27 migrations, enums/, structs/
src/grpc/               initialize.go, 6 translation/push handlers, services/*.pb.go
src/logging/
src/rabbitmq/           ~140 files; the entire agent-message pipeline
src/webserver/          controllers/ (91 files), initialize.go
src/utils/              config.go (viper/.env loader)
```

The largest Go files are the message pipeline: `util_agent_message_actions_post_response.go` (143 KB), `utils_proxy_traffic.go` (74 KB), `recv_pt_sync.go` (74 KB), `eventing.go` (69 KB), `util_agent_message.go` (63 KB), `utils.go` (62 KB). This concentration confirms the design intent: Mythic's complexity is in **task routing, proxying, and container orchestration**, not in the wire protocol itself (which is a deliberately minimal envelope).

---

## 2. Protocol Detail

### 2.1 Transport: outer envelope is base64-of-(UUID || encrypted JSON)

This is Mythic's single most important protocol fact. The **agent-facing wire format** is:

```
AS_SENT_TO_C2_PROFILE = base64( UUID_bytes || ENCRYPTED_JSON )
```

The server does **not** speak raw TCP to agents. It receives already-decapsulated agent messages from C2 profile containers. Handoff to Mythic is either:

- **HTTP**: `POST /api/v1.4/agent_message` or `POST /agent_message` (also `GET` variants), body = base64 message, **required header `mythic: <c2_profile_name>`** [source: `mythic-docker/src/webserver/initialize.go:145-148`; `mythic-docker/src/webserver/controllers/agent_process_message.go:90-99`]
- **GET variants** also accept the message from the first URL query parameter value (tried as `base64.URLEncoding` then `base64.StdEncoding`), or the first cookie value (`base64.StdEncoding`), or the request body [source: `agent_process_message.go:138-231`]
- **gRPC PushC2** streaming: `PushC2.StartPushC2Streaming` / `StartPushC2StreamingOneToMany` (for C2 profiles that pull rather than push, e.g. websocket/DNS-ish designs) [source: `mythic-docker/src/grpc/services/pushC2GRPC.proto:6-10`]

Response is delivered back as `application/octet-stream` containing base64 of `UUID || ENCRYPTED_JSON` [source: `agent_process_message.go:116`].

### 2.2 Message parse pipeline (canonical, `recursiveProcessAgentMessage`)

[source: `mythic-docker/src/rabbitmq/util_agent_message.go:578-726`]

```
1. Receive base64 blob
2. base64.StdEncoding.DecodeString  -> fallback base64.URLEncoding.DecodeString
3. Determine UUID length:
     len < 16            -> error "message too short"
     16 <= len < 36      -> parse uuid.FromBytes(msg[:16]); uuidLen = 16
     len >= 36           -> try uuid.Parse(string(msg[:36])); on failure fall back
                            to uuid.FromBytes(msg[:16]); uuidLen = 16
4. LookupEncryptionData(c2profile, uuid.String(), updateCheckinTime)
5. If UUID == "00000000-0000-0000-0000-000000000000" -> connectivity test message,
   returns error message "[*] Detected Testing message!"
6. If payload.callback_allowed == false and the UUID is a payload -> block
7. body = msg[uuidLen:]; decrypt -> map[string]interface{}
8. Switch on body["action"]:
     checkin | get_tasking | post_response | update_info | upload (deprecated)
     | staging_rsa | staging_translation
9. Encrypt response, prefix UUID, base64 encode, return
```

**UUID type discrimination** is done by three sequential DB lookups against the received UUID [source: `util_agent_message.go:781-937`]:

1. `SELECT ... FROM callback JOIN payload JOIN payloadtype WHERE callback.agent_callback_id=$1` → **UUIDTYPECALLBACK**
2. `SELECT ... FROM payload JOIN payloadtype WHERE payload.uuid=$1` → **UUIDTYPEPAYLOAD**
3. `SELECT ... FROM staginginfo JOIN payload JOIN payloadtype WHERE staginginfo.staging_uuid=$1` → **UUIDTYPESTAGING**

A callback UUID is the *agent's own* callback ID (distinct from the payload UUID baked into the implant at build time). A payload UUID means the agent has checked in from an unbuild-then-checked-in payload; a staging UUID is a transient staging-session ID.

**Cache key is `uuid + c2profile`**, with `uuid` alone as a secondary key [source: `util_agent_message.go:740-758`]. This means the same UUID can carry different encryption keys per C2 profile — relevant for multi-C2 / hot-swap payloads.

### 2.3 Action set and message shapes

#### `checkin` (agent → new callback)
[source: `mythic-docker/src/rabbitmq/util_agent_message_actions_checkin.go:11-31`]

```go
type agentMessageCheckin struct {
    User, Host string; PID int; IP string; IPs []string
    PayloadUUID string `json:"uuid"`
    IntegrityLevel int
    OS, Domain, Architecture, ExternalIP, ExtraInfo, SleepInfo, ProcessName string
    EncKey, DecKey *[]byte
    Cwd, ImpersonationContext *string
    Other map[string]interface{} `mapstructure:",remain"`
}
```

Any unrecognized top-level key is captured in `Other` and **reflected back to the agent** in the response via `reflectBackOtherKeys` [source: `checkin.go:84`; `util_agent_message.go:553`]. This "reflect back unknown keys" behaviour is pervasive across every action handler and is a signature behaviour for identifying Mythic traffic.

Response: `{"id": "<new_callback_uuid>", "status": "success", ...reflected_other}` [source: `checkin.go:81-88`].

If the checkin UUID resolves to an **existing callback**, `handleAgentMessageCheckin` delegates to `handleAgentMessageUpdateInfo` instead of creating a new callback — Mythic treats repeat checkins as re-sync/re-establish-P2P [source: `checkin.go:41-46`].

#### `get_tasking`
[source: `mythic-docker/src/rabbitmq/util_agent_message_actions_get_tasking.go:15-110`]

```go
type agentMessageGetTasking struct {
    GetDelegateTasks bool `json:"get_delegate_tasks"`
    TaskingSize      int  `json:"tasking_size"`   // -1 or negative = unlimited
    Other map[string]interface{} `mapstructure:",remain"`
}
type agentMessageGetTaskingTask struct {
    Timestamp  int64  `json:"timestamp"`   // task.Timestamp.Unix()
    Command    string `json:"command"`     // command_name
    Parameters string `json:"parameters"`  // raw params string
    ID         string `json:"id"`          // agent_task_id
    Token      *int   `json:"token,omitempty"`
}
```

Response: `{"tasks":[...], ...reflected_other}` [source: `get_tasking.go:104-109`]. Tasks are fetched by `agent_task_id`, `ORDER BY id ASC`, and moved to `PT_TASK_FUNCTION_STATUS_PROCESSING` on issue [source: `get_tasking.go:47-103`]. `tasking_size` is deleted from the reflected keys.

Default `get_delegate_tasks` is **true** — an agent that omits the field receives delegated/P2P tasks and proxy data wrapped for its downstream delegates [source: `util_agent_message.go:340-347`].

#### `post_response`
The largest handler (143 KB). Top-level shape [source: `util_agent_message_actions_post_response.go:38-69`]:

```json
{ "action": "post_response",
  "responses": [ { "task_id": "...", "sequence_num": 0, "completed": true,
                   "user_output": "...", "status": "...", "stdout": "...", "stderr": "...",
                   "file_browser": {...}, "removed_files": [...], "credentials": [...],
                   "artifacts": [...], "processes": [...], "edges": [...],
                   "commands": [...], "process_response": {...}, "keylogs": [...],
                   "tokens": [...], "callback_tokens": [...],
                   "download": {...}, "upload": {...}, "alerts": [...],
                   "callback": {...}, "events": [...], "custom_browser": {...} } ] }
```

Nested message shapes that define agent capability reporting [source: `post_response.go:43-258`]:

- **`file_browser`**: `host`, `is_file`, `permissions`, `name`, `parent_path`, `success`, `access_time`, `modify_time`, `size`, `update_deleted`, `files[]`, `set_as_user_output`
- **`processes`**: `host`, `process_id`, `parent_process_id`, `architecture`, `bin_path`, `name`, `user`, `command_line`, `integrity_level`, `start_time`, `description`, `signer`, `protected_process_level`, `update_deleted`, `os`
- **`token`**: `action`, `token_id`, `user`, `groups`, `privileges`, `thread_id`, `process_id`, `session_id`, `logon_sid`, `integrity_level_sid`, `restricted`, `default_dacl`, `handle`, `capabilities`, `app_container_sid`, `app_container_number` — a full Windows access-token inventory
- **`credentials`**: `credential_type`, `realm`, `account`, `credential`, `comment`, `metadata`. Valid types: `plaintext`, `certificate`, `hash`, `key`, `ticket`, `cookie`, `hex` [source: `post_response.go:71`]
- **`artifacts`**: `base_artifact`, `artifact`, `host`, `needs_cleanup`, `resolved`, `id` — IOC bookkeeping with an explicit `needs_cleanup` flag for operator-driven artifact removal
- **`download`** (agent→server file pull): `total_chunks`, `chunk_size`, `chunk_data`, `chunk_num`, `full_path`, `filename`, `file_id`, `host`, `is_screenshot`
- **`upload`** (server→agent file push): `chunk_size`, `chunk_num`, `full_path`, `file_id`, `host`
- **`interactive`** (task_id, data, message_type) — for shell/PTY streams
- **`edges`**: `source`, `destination`, `action`, `c2_profile`, `metadata` — P2P link announcements
- **`alerts`**: `source`, `alert`, `webhook_alert`, `level`, `send_webhook`
- **`callback`**: incremental callback-metadata update (user/host/pid/integrity/os/domain/arch/sleep_info/process_name/cwd/impersonation_context/ips)
- **`events`**: `keyword` + arbitrary `data` map — triggers the eventing engine
- **`custom_browser`**: generic hierarchical browser (name/separator/type/os from a `custombrowser` DB table) used for LDAP/registry/agent-specific trees [source: `post_response.go:2696-2743`]

**Proxy data channels** are keyed by three port types [source: `mythic-docker/src/rabbitmq/utils_proxy_traffic.go:26-30`]:

```go
CALLBACK_PORT_TYPE_SOCKS       = "socks"
CALLBACK_PORT_TYPE_RPORTFWD    = "rpfwd"
CALLBACK_PORT_TYPE_INTERACTIVE = "interactive"
```

Proxy frames on the wire [source: `utils_proxy_traffic.go:32-43`]:

```go
type proxyToAgentMessage   struct { ServerID uint32 `json:"server_id"`; Message []byte `json:"data"`; IsExit bool `json:"exit"`; Port int `json:"port,omitempty"` }
type proxyFromAgentMessage struct { ServerID uint32 `json:"server_id"`; Message string `json:"data"`; IsExit bool `json:"exit"`; Port int `json:"port"` }
```

`ServerID` correlates a proxied connection; `IsExit` terminates it. Socks, reverse-port-forward and interactive (shell) all multiplex over the same `get_tasking`/`post_response` envelope — there is **no separate proxy transport**.

#### `update_info`
Updates callback metadata (host/user/pid/ip/domain/sleep/etc.) without creating a new callback. Shares the `agentMessagePostResponseCallback` field set [source: `util_agent_message_actions_update_info.go`, `post_response.go:218-232`].

#### `upload` (deprecated)
Retained for backwards compatibility; emits a deprecation notice and rewrites itself into a `post_response` with a synthetic `responses[0].upload` [source: `util_agent_message.go:352-368`]:

```
"Agent %s is using deprecated method of file transfer with the 'upload' action."
```

### 2.4 Delegate / P2P wrapping protocol

Mythic supports agents relaying for other agents over an arbitrary graph. Wrapper shapes [source: `util_agent_message.go:241-254`]:

```go
// agent -> mythic (inside "delegates")
type delegateMessage struct {
    Message       string `json:"message"`
    SuppliedUuid  string `json:"uuid"`
    C2ProfileName string `json:"c2_profile"`
}
// mythic -> agent
type delegateMessageResponse struct {
    Message       string `json:"message"`
    SuppliedUuid  string `json:"uuid,omitempty"`
    C2ProfileName string `json:"c2_profile"`
    MythicUuid    string `json:"mythic_uuid,omitempty"`
    NewUuid       string `json:"new_uuid,omitempty"`
}
```

Recursive encapsulation [source: `util_agent_message.go:1150-1180`]: for a path `1 → 2 → 4`, Mythic encrypts the payload for **each hop but the last**, then wraps. The wrapping message is always:

```go
{ "action": "get_tasking", "tasks": []string{} }   // plus the pre-encrypted "delegates" entry
```

Delegate messages are dispatched via a BFS route over the `callbackgraphedge` table (`callbackGraph.GetBFSPath`) and are only generated when `callbackGraph.CanHaveDelegates(callbackID)` is true [source: `get_tasking.go:112-197`; `util_callback_graph.go`]. Proxy data is wrapped the same way and routed through `getDelegateProxyMessages` [source: `get_tasking.go:199-269`]. This is the mechanism that makes Mythic a mesh/P2P-capable C2 rather than a strict star topology.

### 2.5 Staging protocol

Two staging models.

**(a) `staging_rsa`** — RSA key exchange for the stage [source: `util_agent_message_actions_staging_rsa.go:27-88`]

Request:
```json
{ "action": "staging_rsa",
  "pub_key": "LS0tLS1CRUdJTi...",     // base64 of PEM public key
  "session_id": "jGAlyBTrsrbYNDcpj65T" } // random string, anti-replay
```
Response:
```json
{ "uuid": "<new staging uuid>", "session_id": "<echo>",
  "session_key": "<base64 RSA-OAEP-encrypted 32-byte AES-256 key>" }
```

Branch logic: if `pub_key` starts with `LS0t` (base64 of `-----`) it is base64-decoded; otherwise it is wrapped as `-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----` [source: `staging_rsa.go:47-56`]. The new key is written to `staginginfo(session_id, enc_key, dec_key, crypto_type, payload_id, staging_uuid)` with `crypto_type = "aes256_hmac"` and used for all subsequent stage traffic [source: `staging_rsa.go:68-79`].

**(b) `staging_translation`** — used when a translation container is present; the translation container supplies the next hop's keys and the final bytes [source: `util_agent_message_actions_staging_translation.go:13-21`]

```json
{ "action": "staging_translation", "session_id": "...",
  "enc_key": "<b64>", "dec_key": "<b64>", "type": "aes256_hmac",
  "next_uuid": "<uuid for the next request>", "message": "<final stage bytes>" }
```
The `message` field is returned **unmodified and unencrypted by Mythic** (`instanceResponse.Message = *finalBytes`, bypassing `EncryptMessage`) — the translation container is trusted to have already produced the final wire form [source: `util_agent_message.go:394-405`].

### 2.6 Translation container protocol (gRPC)

Proto: `translationContainerServices.TranslationContainer` [source: `mythic-docker/src/grpc/services/translationContainerGRPC.proto:6-13`]

```protobuf
rpc TranslateFromCustomToMythicFormat (stream TrCustomMessageToMythicC2FormatMessageResponse) returns (stream TrCustomMessageToMythicC2FormatMessage)
rpc TranslateFromMythicToCustomFormat (stream TrMythicC2ToCustomMessageFormatMessageResponse) returns (stream TrMythicC2ToCustomMessageFormatMessage)
rpc GenerateEncryptionKeys            (stream TrGenerateEncryptionKeysMessageResponse)       returns (stream TrGenerateEncryptionKeysMessage)
```

Note the inversion: **Mythic sends the first message, the container replies on the same stream.** The container identifies itself by sending an initial message whose `TranslationContainerName` is set [source: `mythic-docker/src/grpc/generate_encryption_keys.go:12-30`].

Key-generation request/response [source: `translationContainerGRPC.proto:50-62`]:
```protobuf
message TrGenerateEncryptionKeysMessage  { string TranslationContainerName=1; string C2Name=2; string CryptoParamValue=3; string CryptoParamName=4; }
message TrGenerateEncryptionKeysMessageResponse { bool Success=1; string Error=2; bytes EncryptionKey=3; bytes DecryptionKey=4; string TranslationContainerName=5; }
```

Crypto keys travel alongside the message in `CryptoKeysFormat { bytes EncKey=1; bytes DecKey=2; string Value=3; }` — the container is handed **all candidate keys** (C2-profile keys + payload keys + staging keys, each with a `Location` tag of `callback`/`staging`/`c2`/`payload`) and is expected to figure out which to use [source: `util_agent_message.go:87-132`].

### 2.7 PushC2 protocol (pull-style C2 profiles)

[source: `mythic-docker/src/grpc/services/pushC2GRPC.proto:6-36`]

```protobuf
service PushC2 {
  rpc StartPushC2Streaming        (stream PushC2MessageFromAgent) returns (stream PushC2MessageFromMythic) {}
  rpc StartPushC2StreamingOneToMany (stream PushC2MessageFromAgent) returns (stream PushC2MessageFromMythic) {}
}
message PushC2MessageFromAgent {
  string C2ProfileName=1; string RemoteIP=2; bytes Message=3;
  string OuterUUID=4; bytes Base64Message=5; string TrackingID=6; bool AgentDisconnected=7;
}
message PushC2MessageFromMythic { bool Success=1; string Error=2; bytes Message=3; string TrackingID=4; }
```
`Message` and `Base64Message` are mutually exclusive; `TrackingID` correlates async request/response; `AgentDisconnected` lets a long-poll profile signal agent teardown. Implementation: `push_c2_stream_one_to_many.go`, `push_c2_stream_one_to_one.go`.

### 2.8 Internal RabbitMQ routing keys

Complete constant inventory [source: `mythic-docker/src/rabbitmq/constants.go`]:

Exchanges: `mythic_exchange` (direct), `mythic_topic_exchange`. `RPC_TIMEOUT = 10s`, `RETRY_CONNECT_DELAY = 5s`, `CHECK_CONTAINER_STATUS_DELAY = 10s`.

Mythic-consuming fanout routes:
```
pt_sync, pt_rpc_resync, pt_build_response, pt_on_new_callback_response,
pt_check_if_callbacks_alive, pt_c2_build_response, pt_task_opsec_pre_check_response,
pt_task_create_tasking_response, pt_task_opsec_post_check_response,
pt_task_completion_function_response, pt_task_process_response_response,
c2_sync, c2_rpc_resync, tr_sync, tr_rpc_resync,
consuming_container_sync, consuming_container_rpc_resync,
eventing_custom_function[_response], eventing_conditional_check[_response],
eventing_task_intercept[_response], eventing_response_intercept[_response],
auth_rpc_get_idp_redirect, auth_rpc_process_idp_response, auth_rpc_get_idp_metadata,
auth_rpc_get_nonidp_redirect, auth_rpc_process_nonidp_response, auth_rpc_get_nonidp_metadata,
container_on_start[_response],
custombrowser_sync, custombrowser_exportfunction[_response]
```

Container-consuming fanout routes (prefix `<containerName>_`): `payload_build`, `payload_c2_build`, `pt_task_opsec_pre_check`, `pt_task_create_tasking`, `pt_on_new_callback`, `pt_task_opsec_post_check`, `pt_command_dynamic_query_function`, `pt_build_parameter_dynamic_query_function`, `pt_command_typedarray_parse`, `pt_task_completion_function`, `pt_task_process_response`, `pt_command_help_function`.

Exclusive RPC routes (prefix `<containerName>_`): `c2_rpc_opsec_check`, `c2_rpc_config_check`, `c2_rpc_get_ioc`, `c2_rpc_sample_message`, `c2_rpc_redirector_rules`, `c2_rpc_start_server`, `c2_rpc_stop_server`, `c2_rpc_get_server_debug_output`, `c2_rpc_host_file`, `container_rpc_get_file`, `container_rpc_remove_file`, `container_rpc_list_file`, `container_rpc_write_file`, `tr_rpc_generate_keys`, `tr_rpc_from_mythic_c2`, `tr_rpc_to_mythic_c2`, `tr_rpc_encrypt_bytes`, `tr_rpc_decrypt_bytes`.

`mythic_rpc_*` routes: file create/search/update/get_content/register; payload create_from_uuid / create_from_scratch / search / get_content / update_build_step / add_command / remove_command; task search / display_to_real_id_search / update / create / create_subtask / create_group; response search / create; command search; callback create / search / edge_search / edge_remove / display_to_real_id_search / next_checkin_range / add_command / remove_command / search_command / update / encrypt_bytes / decrypt_bytes; agentstorage create/search/remove; process create/search; artifact create/search; keylog create/search; credential create/search; eventlog create; filebrowser create/remove/parse_path; payloadonhost create; callbacktoken create/remove/search; token create/remove; proxy start/stop; tag search/create; tagtype get_or_create; c2 update_status; apitoken create; handle_agent_message_json; custombrowser search; blank.

This is the operative internal API surface. Any container that can publish to `mythic_exchange` with the right routing key can drive Mythic's data model — there is no per-route authentication on the bus itself, only network isolation of the Docker network.

---

## 3. Cryptography

### 3.1 The agent-message envelope: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)

[source: `mythic-docker/src/crypto/aes256_hmac.go:29-113`]

```
Encrypt AES-256-HMAC(key, msg):
    cipherText  = AES-256-CBC(key, IV=random(16), PKCS7(msg))
    mac         = HMAC-SHA256(key, cipherText)
    return  cipherText || mac            # NOT IV-prefixed at this layer
```

Wait — precisely: `EncryptAES256` returns `IV || cipherText` [source: `aes256_hmac.go:75`], and `EncryptAES256HMAC` computes the HMAC over that combined `IV||cipherText` buffer and appends it [source: `aes256_hmac.go:36-49`]:

```
wire = IV(16) || AES256-CBC(PKCS7(plaintext)) || HMAC-SHA256(IV||ciphertext)(32)
```

Decryption [source: `aes256_hmac.go:79-105`]:
```
require len(msg) >= 16 + 32
iv         = msg[0:16]
cipherHMAC = msg[len-32:]
cipherText = msg[16:len-32]
if hmac.Equal(HMAC-SHA256(key, msg[0:len-32]), cipherHMAC):
    AES-256-CBC-decrypt(cipherText, iv) -> PKCS7 unpad
else: "Failed to validate HMAC"
```

**Facts:**
- Algorithm: **AES-256-CBC**, block size 16, IV random per message via `crypto/rand`, prepended in-band [source: `aes256_hmac.go:56-68`]
- Integrity: **HMAC-SHA256**, 32-byte tag, appended in-band, verified with `hmac.Equal` (constant-time) [source: `aes256_hmac.go:107-113`]
- **Same key used for both encryption and MAC** (key reuse — a single 32-byte key drives AES and HMAC). This is a design weakness worth noting: no key separation/HKDF.
- Padding: PKCS#7 with explicit validity checks (padding byte value, no zero-length, all pad bytes equal) [source: `aes256_hmac.go:142-179`]
- Crypto type string on the wire/in DB: **`"aes256_hmac"`**; alternative **`"none"`** means passthrough (no encryption) [source: `generate_keys.go:17-46`; `util_agent_message.go:139-184`]
- Empty key → identity function, no encryption [source: `aes256_hmac.go:30-33`]

### 3.2 Key generation and provenance

[source: `mythic-docker/src/crypto/generate_keys.go:17-46`]

```go
case "aes256_hmac":
    bytes := make([]byte, 32)
    rand.Read(bytes)          // crypto/rand
    return CryptoKeys{ EncKey: &bytes, DecKey: &bytes, Value: cryptoType }
```
**EncKey == DecKey** — a single symmetric key for both directions. 32 bytes / 256 bits.

Where keys come from, in priority order for a **payload** UUID [source: `util_agent_message.go:87-132`, `848-894`]:
1. **C2 profile crypto parameters** (`c2profileparameters.crypto_type = true`) — one `CryptoKeys` entry per instance, `Location: "c2"`. *Multiple* entries are possible; the server tries each in turn.
2. **Payload build parameter crypto** (`buildparameterinstance.enc_key/dec_key/value` where `dec_key IS NOT NULL`) — single entry, `Location: "payload"`.

For a **callback** UUID: only `callback.enc_key/dec_key/crypto_type`, `Location: "callback"`.
For a **staging** UUID: only `staginginfo.enc_key/dec_key/crypto_type`, `Location: "staging"`.

**Key-selection fallback loop** [source: `util_agent_message.go:133-187`]: `IterateAndAct` walks every candidate key; for `decrypt` it returns on the first successful HMAC verification and memoizes it in `SuccessfulDecKeyOpt`; for `encrypt` it uses the memoized `SuccessfulEncKeyOpt`. This makes decryption an **HMAC-oracle-driven key search** — the tag doubles as a key-selection discriminator.

### 3.3 Staging key exchange: RSA-4096-OAEP-SHA1

[source: `mythic-docker/src/crypto/rsa.go`]

- Keypair generation: `rsa.GenerateKey(rand.Reader, 4096)` — **RSA-4096** [source: `rsa.go:13`]
- Public key serialized as **PKCS#1** DER in a `-----BEGIN RSA PUBLIC KEY-----` PEM block [source: `rsa.go:19-26`]
- Encryption: `rsa.EncryptOAEP(sha1.New(), ...)` — **RSA-OAEP with SHA-1** as the OAEP hash, no label [source: `rsa.go:57`]
- Decryption: `rsa.DecryptOAEP(sha1.New(), ...)` [source: `rsa.go:31`]
- Public key parse fallback chain: `ParsePKCS1PublicKey` → on failure `ParsePKIXPublicKey` [source: `rsa.go:47-55`]
- Payload of the RSA encryption is the **32-byte AES-256 key** generated above

**SHA-1 as the OAEP hash is the notable crypto finding here** — it is the standard `crypto/rsa` default in older Go code but is cryptographically dated. The RSA modulus itself is 4096-bit which is fine.

### 3.4 Hash functions

[source: `mythic-docker/src/crypto/hash.go`]
- `HashSha512(data []byte) [64]byte` — SHA-512
- `HashMD5(data []byte) string` — MD5 hex (used for legacy/cache keying)
- `HashSha1(data []byte) string` — SHA-1 hex

### 3.5 Operator-plane crypto: HS256 JWT

[source: `mythic-docker/src/authentication/mythicjwt/jwt.go`]

- Signing: **HMAC-SHA256 (`jwt.SigningMethodHS256`)** with `utils.MythicConfig.JWTSecret` [source: `mythicjwt/jwt.go:110-111`]
- **The parser explicitly rejects non-HMAC signing methods**, returning `ErrUnexpectedSigningMethod` if `token.Method` is not `*jwt.SigningMethodHMAC` [source: `mythicjwt/jwt.go:71-77`]. This closes the classic `alg:none` / RS256-HMAC confusion attack.
- Claims: `user_id`, `auth` (auth method), `eventstepinstance_id`, `apitokens_id`, `operation_id`, plus `iat`/`exp` [source: `mythicjwt/jwt.go:17-24`]
- Token lifetime: `JWTTimespan = 4 * time.Hour` [source: `mythicjwt/jwt.go:29`]
- Auth methods: `user`, `api`, `event`, `task`, `graphql_spectator` [source: `mythicjwt/jwt.go:30-34`]
- Refresh tokens: 20-char random alphanumeric from `crypto/rand` via `rand.Int`, cached in-memory map keyed by access token; mismatch → `ErrRefreshTokenMissmatch` [source: `mythicjwt/jwt.go:40-52`, `54-95`]. **Refresh-token cache is in-process only** — a server restart invalidates all refresh tokens.
- JWT secret default: `utils.GenerateRandomPassword(30)` at first install [source: `Mythic_CLI/src/cmd/config/env.go:331`]. It is **not** a fixed default.

### 3.6 Password generation

`generateRandomPassword(n)` uses `crypto/rand.Int` over `[A-Za-z0-9]` [source: `mythicjwt/jwt.go:40-52`]. Used for refresh tokens (20) and the JWT secret / admin password (30) at install time.

### 3.7 Crypto summary table

| Purpose | Algorithm | Key/params | Source |
|---|---|---|---|
| Agent ↔ Mythic message | AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, IV prepended, tag appended) | 32-byte symmetric key reused for both | `crypto/aes256_hmac.go` |
| Staging key transport | RSA-4096 OAEP-SHA1 | 4096-bit RSA, SHA-1 OAEP hash | `crypto/rsa.go` |
| Staging payload | AES-256 key, 32 random bytes | generated per staging session | `crypto/generate_keys.go` |
| Operator auth | JWT HS256 | HMAC-SHA256 over `jwt_secret` (30 random chars) | `authentication/mythicjwt/jwt.go` |
| Hashing | SHA-512 / SHA-1 / MD5 | unkeyed | `crypto/hash.go` |
| C2-profile-specific crypto | delegated | translation container or C2 container generates keys | `grpc/...translationContainerGRPC.proto`, `send_tr_rpc_generate_encryption_keys.go` |
| Container RPC encrypt/decrypt | delegated | `tr_rpc_encrypt_bytes` / `tr_rpc_decrypt_bytes` | `rabbitmq/constants.go` |

### 3.8 What the crypto does *not* provide

- No forward secrecy: the AES key is static for the lifetime of the callback (persisted in `callback.enc_key`) [source: `util_agent_message.go:810-812`]
- No per-message key ratchet
- Key reuse between the cipher and the MAC
- No AEAD — CBC+HMAC with a shared key, not AES-GCM/CCM
- `mythic_encrypts=false` is a supported configuration, in which case the payload/handler body is plaintext JSON inside a base64 wrapper, and only the C2 profile may encrypt

---

## 4. Hardcoded Values

### 4.1 Default ports

[source: `mythic-docker/src/utils/config.go:56-63`; mirrored in `Mythic_CLI/src/cmd/config/env.go`]

| Config key | Default | Notes |
|---|---|---|
| `mythic_server_port` | **17443** | Mythic Go webserver |
| `mythic_server_grpc_port` | **17444** | gRPC (translation containers, PushC2) |
| `mythic_server_dynamic_ports` | **7000-7010** | port range for proxied sockets (socks/rpfwd listeners) |
| `mythic_server_bind_localhost_only` | `true` | |
| `mythic_server_dynamic_ports_bind_localhost_only` | `true` | |
| `mythic_docker_networking` | `bridge` | |
| `postgres_port` | **5432** | |
| `rabbitmq_port` | **5672** | |
| `rabbitmq_host` | `mythic_rabbitmq` | Docker service name |
| `rabbitmq_vhost` | `mythic_vhost` | |
| `postgres_host` | `mythic_postgres` | |
| `postgres_db` | `mythic_db` | |
| `postgres_user` | `mythic_user` | |
| `rabbitmq_user` | `mythic_user` | |

Webserver binds `0.0.0.0:<mythic_server_port>` or `127.0.0.1:<port>` depending on `ServerBindLocalhostOnly` [source: `mythic-docker/src/webserver/initialize.go:51-65`].

### 4.2 Default credentials

[source: `mythic-docker/src/utils/config.go:59-60`, `344-345`; `Mythic_CLI/src/cmd/config/env.go:384-393`]

| Key | Default (server code) | Default (CLI installer) |
|---|---|---|
| `mythic_admin_user` | `mythic_admin` | `mythic_admin` |
| `mythic_admin_password` | **`mythic_password`** | `utils.GenerateRandomPassword(30)` |
| `jwt_secret` | `""` (empty) | `utils.GenerateRandomPassword(30)` |
| `postgres_password` | `""` (empty) | random |
| `rabbitmq_password` | `""` (empty) | random |

**The `mythic_password` default is present in the Go server source** (`config.go:60`). The CLI installer overrides it with a random 30-char string, but any deployment that starts `mythic-docker` directly against an empty `.env` gets `mythic_admin` / `mythic_password` and an **empty JWT secret**. An empty `jwt_secret` means every JWT is signed with a zero-length HMAC key — a trivially forgeable instance. This is the highest-severity hardcoded-value finding for T4.

### 4.3 Default config strings

- `allowed_ip_blocks` = `0.0.0.0/0` — **the operator API is open to every IP by default** [source: `config.go:62`]. Access control is RBAC/JWT-based plus this CIDR filter.
- `debug_level` = `warning`
- `default_operation_name` = `Operation Chimera` [source: `config.go:81`]
- `global_server_name` = `mythic`
- `mythic_server_allow_invite_links` = `false`
- `mythic_server_allow_webhooks_on_new_callbacks` = `true`
- `postgres_sslmode` = `disable`

### 4.4 Magic values, constants, identifiers

- **Testing UUID**: `00000000-0000-0000-0000-000000000000` — connectivity-test marker. Its presence triggers the message `"[*] Detected Testing message!\nConnectivity to Mythic through C2 Profile %s confirmed"` [source: `util_agent_message.go:773-776`]
- **UUID lengths supported**: `16` (raw binary UUID) or `36` (canonical string form). `GetUUIDBytes` errors on anything else with `"unknown UUID length"` [source: `util_agent_message.go` — `GetUUIDBytes`]. Default assumption is 36 [source: `util_agent_message.go:625`]
- **HMAC tag length**: 32 bytes; minimum decryptable message length 48 bytes (`aes.BlockSize + 32`) [source: `aes256_hmac.go:84`]
- **RSA public-key base64 prefix test**: `"LS0t"` (base64 of `-----`) [source: `staging_rsa.go:48`]
- **`CALLBACK_MESSAGE_KEY_*`**: `responses`, `edges`, `delegates`, `alerts` [source: `util_agent_message.go:33-36`]
- **`UUIDTYPECALLBACK`/`UUIDTYPEPAYLOAD`/`UUIDTYPESTAGING`** = `callback`/`payload`/`staging` [source: `util_agent_message.go:26-28`]
- **`CRYPTO_LOCATION_*`** = `callback`, `staging`, `c2`, `payload` [source: `util_agent_message.go:29-32`]
- **Postgres integer ceilings** used as clamps: `POSTGRES_MAX_INT = 2147483647`, `POSTGRES_MAX_BIGINT = 9223372036854775807` [source: `post_response.go:35-36`]
- **`RPC_TIMEOUT` = 10s**, **`RETRY_CONNECT_DELAY` = 5s**, **`CHECK_CONTAINER_STATUS_DELAY` = 10s** [source: `rabbitmq/constants.go`]
- **`TASK_STATUS_CONTAINER_DOWN` = `"Error: Container Down"`** [source: `rabbitmq/constants.go`]
- **`mythic` HTTP header** — mandatory on agent message ingestion; its value is the C2 profile name [source: `agent_process_message.go:90-99`]
- **IP-forwarding header precedence** on agent messages: `CF-Connecting-IP` → `X-Real-Ip` → `X-Forwarded-For` (first element) → `c.ClientIP()` → fallback literal `"127.0.0.1"` [source: `agent_process_message.go:30-53`]
- **Forwarded-URL/UA/Host override headers**: `x-forwarded-url`, `x-forwarded-user-agent`, `X-Forwarded-Host` [source: `agent_process_message.go:54-74`]
- **`MythicSource` header** on operator requests, defaults to `scripting` when absent, set to `cookie` by the cookie-auth middleware [source: `initialize.go:105-108`; `authentication/middleware.go:36`]

### 4.5 Default-port/route inventory

Unauthenticated (IP-block-filtered) routes [source: `webserver/initialize.go:143-171`]:
```
POST /api/v1.4/agent_message      GET /api/v1.4/agent_message
POST /agent_message               GET  /agent_message
GET  /health                      GET  /healthDetailed
POST /auth                        POST /invite
GET  /auth_services
GET  /auth_metadata/:containerName/:IDPName
GET  /auth_metadata/:containerName/:IDPName/metadata
GET  /auth_redirect/:containerName/:IDPName
GET  /auth_acs/:containerName/:IDPName      POST /auth_acs/:containerName/:IDPName
GET  /direct/download/:file_uuid
POST /direct/upload/:file_uuid
```

Cookie-authenticated: `GET /static/*`, `GET /direct/view/:file_uuid`, `GET /api/v1.4/files/download/:file_uuid`, `GET /api/v1.4/files/screencaptures/:file_uuid`.

JWT-protected: `POST /graphql/webhook`, `GET /me`, `POST /api/v1.4/me_webhook`, `generate_apitoken_webhook`, `delete_apitoken_webhook`, `update_current_operation_webhook`, `update_operator_password_webhook`, `create_operator`, `operator_get_secrets_webhook`, `operator_update_secrets_webhook`, `operator_get_preferences_webhook`, `operator_update_preferences_webhook`, plus the RBAC-gated operation/agent/task/payload surface (`initialize.go:210-341`).

**Unauthenticated payload hosting** (`/direct/download/:file_uuid`) is by design: agents and payload containers fetch stage bytes by UUID. The security property is UUID unguessability, not authentication.

---

## 5. Persistence + Evasion Mechanisms

**Critical scoping statement:** Mythic **itself** performs no process injection, no sleep obfuscation, no AMSI/ETW bypass, and no host persistence. Those are properties of the **agent** (implant) that lives in a separate repository. What Mythic provides is the *server-side infrastructure* those techniques depend on. The evasion-relevant surfaces in this repo are:

### 5.1 Server-side operational-security (OPSEC) gating framework

Mythic implements a two-phase OPSEC gate around every task, driven by the payload type's container:

- `PT_TASK_OPSEC_PRE_CHECK` → `pt_task_opsec_pre_check_response` [source: `rabbitmq/constants.go`; `websocket/controllers` → `rabbitmq/recv_pt_task_opsec_pre_response.go`]
- `PT_TASK_OPSEC_POST_CHECK` → `pt_task_opsec_post_check_response` [source: `recv_pt_task_opsec_post_response.go`]

Database fields per task: `opsec_pre_blocked`, `opsec_pre_bypassed`, `opsec_pre_bypass_role`, `opsec_pre_bypass_user_id`, `opsec_post_blocked`, `opsec_post_bypassed`, `opsec_post_bypass_role`, `opsec_post_bypass_user_id` [source: `util_request_opsec_bypass.go:29-33`].

Bypass roles [source: `util_request_opsec_bypass.go:38-90`]:
- `OPSEC_ROLE_LEAD` — only the operation lead may approve
- `OPSEC_ROLE_OPERATOR` — operator or lead
- `OPSEC_ROLE_OTHER_OPERATOR` — any operator who is *not* the task submitter; if the submitter is the only remaining non-spectator operator, self-approval succeeds (with bot accounts excluded from the count)

This is the mechanism that makes agent-side evasion decisions auditable and approval-gated: an agent reports "this action would trip a detection", the payload-type container marks the task blocked, and an operator must explicitly bypass.

### 5.2 Container/agent health probing as dead-drop resilience

- `PT_CHECK_IF_CALLBACKS_ALIVE` / `pt_check_if_callbacks_alive` [source: `rabbitmq/constants.go`; `send_pt_rpc_check_if_callbacks_alive.go`]
- `MYTHIC_RPC_CALLBACK_NEXT_CHECKIN_RANGE` — server-side computation of the next expected checkin window [source: `recv_mythic_rpc_callback_next_checkin_range.go`]
- `callback.trigger_on_checkin_after_time` — per-callback trigger scheduling [source: `util_agent_message.go:81`, `UpdateCallbackInfoTriggerOnCheckin`]
- `callback.last_checkin` tracking on every message with `updateCheckinTime=true` [source: `util_agent_message.go:743-756`]

### 5.3 C2-profile redirector-rule retrieval

Mythic fetches redirector configuration from the C2 container: `C2_RPC_REDIRECTOR_RULES_ROUTING_KEY = "c2_rpc_redirector_rules"` with request/response types `C2GetRedirectorRulesMessage`, plus webhooks `c2profile_redirect_rules_webhook.go` [source: `rabbitmq/constants.go`; `webserver/controllers/c2profile_redirect_rules_webhook.go`]. Redirector rules are the server-side representation of traffic redirection (nginx/Apache mod_rewrite style) that hides the real C2 behind a legit-looking front.

### 5.4 IOC extraction and artifact-cleanup tracking

- `C2_RPC_GET_IOC_ROUTING_KEY = "c2_rpc_get_ioc"` — queries each C2 profile for its indicators [source: `c2profile_get_ioc_webhook.go:92-105`]
- Response iteration: `for _, ioc := range c2GetIOCMessageResponse.IOCs { output += fmt.Sprintf("%s, %s\n", ioc.Type, ioc.IOC) }`
- `agentMessagePostResponseArtifacts` carries `needs_cleanup *bool` and `resolved *bool` — an explicit, per-artifact "did the operator clean this up" ledger [source: `post_response.go:107-118`]

### 5.5 Sleep / beacon configuration is agent-declared

`sleep_info` is a **string field** on both checkin and callback-update messages [source: `checkin.go:24`; `post_response.go:227`]. Mythic stores and displays it but does not implement or influence the sleep algorithm. Any sleep-obfuscation (Ekko/FOLIAGE/ZilEan/StackFrenzy-style) lives in the agent.

Likewise `extra_info`, `impersonation_context`, `process_name`, `cwd`, and `integrity_level` are free-form agent-reported fields — Mythic is a passive recorder here.

### 5.6 Evasion-adjacent server behaviours worth naming

- **Payload hosting restart workflow**: `RestartC2ServerAfterUpdate` stops and restarts the C2 profile after a new file is hosted, so hosted payload bytes and the running profile stay consistent [source: `send_c2_rpc_start_server.go:23-90`]
- **C2 profile start/stop RPC** with `InternalServerRunning` state tracking: `C2_RPC_START_SERVER_ROUTING_KEY`, `C2_RPC_STOP_SERVER_ROUTING_KEY` [source: `send_c2_rpc_start_server.go:90-118`; `rabbitmq/constants.go`]
- **C2 config pre-flight check**: `C2_RPC_CONFIG_CHECK_ROUTING_KEY = "c2_rpc_config_check"` [source: `rabbitmq/constants.go`]
- **Custom browser export functions**: `CUSTOMBROWSER_EXPORT_FUNCTION` — agents can register UI export handlers (e.g. dump an LDAP tree to a file) [source: `rabbitmq/constants.go`; `webserver/controllers/custombrowser_export_function_webhook.go`]
- **Eventing engine**: full server-side automation (`eventing.go`, 69 KB; `eventing/` package) with triggers `TriggerResponseIntercept`, `TriggerTaskIntercept`, conditional checks, custom functions, keywords. Response interception (`agentMessagePostResponseTriggerEvent` → `updateEventingTriggerKeywords`) lets operators rewrite or suppress agent output mid-flight [source: `post_response.go:233-236`, `1155-1176`; `recv_eventing_response_intercept_response.go`]

---

## 6. Capability Inventory

### 6.1 Operator-facing (server) capabilities
- Multi-operation, multi-operator with three RBAC view modes: `lead`, `operator`, `spectator` [source: `authentication/middleware.go:95-113`]
- API tokens (`apitokens` table) with their own JWT auth method and per-token usage logging [source: `authentication/mythicjwt/jwt.go:22`; `webserver/controllers/user_generate_apitoken_webhook.go`]
- Invite-link based user onboarding [source: `webserver/controllers/invite_link_utilities.go`, 15 KB]
- IdP / SSO auth via auth containers (`auth_services`, `auth_metadata`, `auth_redirect`, `auth_acs` routes) [source: `webserver/initialize.go:158-165`]
- Global settings, operator secrets, operator preferences [source: `webserver/controllers/update_global_settings_webhook.go`, `user_secrets_webhook.go`, `user_preferences_webhook.go`]
- Webhook emission on events (SIEM integration): `emit_siem_message.go`, `utils_siem_message_create_and_emit.go` (7 KB), `reporting_webhook.go`, `utils_generate_report.go` (41 KB) [source: `rabbitmq/`]
- MITRE ATT&CK mapping: `utils_mitre_attack.go`, `add_attack_to_task_webhook.go`, `attack` / `attackcommand` / `attacktask` Hasura tables [source: `rabbitmq/utils_mitre_attack.go`; `hasura-docker/metadata/databases/default/tables/`]
- Full reporting/export: payload config export, callback config export/import, eventing export/import, file bulk download [source: `webserver/controllers/*_export_*`, `*_import_*`]
- Grafana/Prometheus metrics stack
- Jupyter notebook integration for programmatic operation [source: `jupyter-docker/jupyter/`]

### 6.2 Agent-facing (protocol) capabilities
- Task issue/fetch with arbitrary batch size and token impersonation (`token` field on task)
- Bidirectional file transfer in chunks (download/upload), including screenshot flagging (`is_screenshot`)
- File browser, process browser, custom hierarchy browsers, credential capture, keylog capture, artifact/IOC registry
- Windows access-token management (full token struct + callback-token association)
- Socks5 proxy, reverse port forward, interactive shell/PTY — all multiplexed over the standard envelope
- P2P/mesh delegation with arbitrary-depth wrapping and BFS routing
- Eventing triggers/dynamic tasking from agent-reported keywords
- Staging (RSA or translation-container driven) with stage-size decoupling from the primary payload
- Push-C2 (pull-model) support for profiles that cannot accept inbound connections

### 6.3 Data model (Hasura-exposed tables)

Complete table list [source: `hasura-docker/metadata/databases/default/tables/`]:
`agentstorage`, `apitokens`, `artifact`, `attack`, `attackcommand`, `attacktask`, `browserscript`, `browserscriptoperation`, `buildparameter`, `buildparameterinstance`, `c2profile`, `c2profileparameters`, `c2profileparametersinstance`, `callback`, `callbackc2profiles`, `callbackgraphedge`, `callbackport`, `callbacktoken`, `command`, `commandopsec`, `commandparameters`, `credential`, `disabledcommandsprofile`, `filebrowserobj`, `filemeta`, `keylog`, `loadedcommands`, `operation`, `operationeventlog`, `operator`, `operatoroperation`, `payload`, `payloadc2profiles`, `payloadcommand`, `payloadonhost`, `payloadtype`, `payloadtypec2profile`, `payload_build_step`, `process`, `response` (plus `staginginfo`, `eventgroup`/`eventstep`, `mythictree`, `tag`/`tagtype`, `token`, `translationcontainer`, `consumingcontainer`, `custombrowser` referenced in Go).

27 DB migrations present [source: `mythic-docker/src/database/migrations/`].

### 6.4 Webserver controller surface (91 files)

Grouped: agent message ingestion; auth/login/invite/IdP; user & operator management; API tokens & secrets; operation management; payload create/update/rebuild/export; task create/dynamic-query/typedArray-parse/upload-file; callback create/update/import-config/export-config/create-edge/remove-edge; artifact create; credential create; keylog create; file delete/download-bulk/preview/direct-up/download-auth; C2 profile config-check/create-param/import-param/host-file/redirect-rules/sample-message/start-stop/status/get-IOC; container download/list/remove/write file; eventing register/export/import/test/trigger(×6 variants); proxy start-stop-test; MythicTree create; custom browser export; reporting; global settings get/update; tag & tagtype management; request-opsec-bypass; healthcheck; Hasura claims.

---

## 7. Residual Unknowns

1. **Agent implementations are entirely absent from this corpus.** `InstalledServices/` holds only `.keep`. Every implant-side capability claim (injection technique, AMSI/ETW bypass, sleep obfuscation, persistence, privilege escalation) is out of scope for T4 and cannot be resolved from this tree. `mythic-docker` is the controller only.
2. **C2 profile implementations are absent.** The http/websocket/smb/tcp/dns/github/slack profiles that generate the actual wire obfuscation live in their own repositories. The exact per-profile `message_format`, URI paths, headers and encoding used by the default `http` profile cannot be determined from this tree — only the generic envelope (`base64(UUID || encrypted JSON)`) and the mandatory `mythic` header. Whether any profile in this corpus uses a non-default `message_format` (xml) or `message_uuid_length` (16) is unknown.
3. **`Success:false` semantics of `IterateAndAct`.** When every candidate key fails to decrypt, the function returns `(modified, err)` where `err` is from the last AES attempt — but for a `none`/unknown crypto value it can also return success without decrypting. The precise observable behaviour on malformed key sets (which error surfaces to the operator, whether the operator sees the raw ciphertext) was not traced end-to-end.
4. **`reflectBackOtherKeys` implementation was not read in full.** It is invoked on nearly every action handler and is a strong traffic signature. Which key names are filtered/blocked (if any), and whether an agent can inject keys that collide with Mythic's own response keys (`action`, `tasks`, `delegates`, `socks`, `rpfwd`, `interactive`, `status`, `error`) is unresolved. This matters because the agent controls `Other` entirely.
5. **`callback_allowed` gating has a hole that was not fully characterized.** `recursiveProcessAgentMessage` blocks payload-originated messages when `Payload.CallbackAllowed` is false — but only *after* `LookupEncryptionData` (which already selected keys from the payload record) and only for the payload UUID type. Whether a callback UUID derived from that payload is likewise blocked is not proven.
6. **Empty-JWT-secret behaviour was inferred, not executed.** `config.go` defaults `jwt_secret` to `""` and `MythicConfig.JWTSecret = []byte("")`. With an empty HMAC key, `SignedString`/`ParseWithClaims` will accept any token signed with the empty key. This was reasoned from source; the exact Go behaviour (whether `hmac.New` with a zero-length key errors, or `SignedString([]byte{})` succeeds) was not verified by execution. Treat as **high-likelihood, unverified**.
7. **The exact `graphql/webhook` Hasura claims contract.** `GetHasuraClaims` (`webserver/controllers/hasura_claims.go`) builds JWT claims for Hasura's `x-hasura-*` model. The full claim set and its role format were not enumerated here.
8. **Eventing engine semantics are only sketched.** `eventing.go` (69 KB) and the `eventing/` package define triggers, conditionals, custom functions, intercepts, keywords, and step retry. The complete trigger/action/condition grammar and the exact response-intercept rewrite capability were not enumerated.
9. **`utils_proxy_traffic.go` (74 KB) internal proxy state machine** — the full SOCKS negotiation state handling, `ServerID` allocation, byte accounting (`bytesSentToAgentMessage`, `bytesReceivedFromAgentMessage`), and dynamic-port listener lifecycle (ports 7000-7010) were only partially traced.
10. **No compiled Go binary was present in the corpus**, so there is no `[binary]` evidence for T4. All findings are `[source]`. (The REA `inspect_go_binary` tool was available and unnecessary — there were zero `.exe`/`.so`/`.dll`/ELF files in the tree.)
11. **The 274 JavaScript files (React UI) were not swept.** They are operator UI code (graphql queries, component logic) rather than protocol/evasion logic; a full UI sweep was deprioritized against the core Go pipeline. Any client-side quirks (e.g. how the UI renders `sleep_info` or constructs GraphQL subscriptions) remain unexamined.
12. **`utils_generate_report.go` (41 KB) and `utils_siem_message_create_and_emit.go`** — the exact report/SIEM payload schemas were not extracted; they define what telemetry leaves Mythic toward a SOC/SIEM, which is operationally relevant but not protocol-critical.
13. **RabbitMQ bus authorization.** It was not determined whether the Docker RabbitMQ is configured with per-container credentials or a single shared `mythic_user` credential. If shared (the config default), any compromised container on the Docker network can publish arbitrary `mythic_rpc_*` routing keys and drive the Mythic data model. Flagged as unknown rather than a confirmed finding.
14. **Translation container trust boundary.** `staging_translation` returns the container's `message` field to the agent **without** Mythic-side encryption or validation [source: `util_agent_message.go:394-405`]. Whether any validation exists in the translation-container handshake beyond name matching was not traced.
