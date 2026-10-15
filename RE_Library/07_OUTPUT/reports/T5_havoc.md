# T5 — Havoc C2 Framework

**Corpus:** 743 files. Full framework: Go teamserver + Qt/C++ client + **complete Demon agent C source** (33 `.c` files, 619 KB) + compiled shellcode templates.
**Repo:** `github.com/HavocFramework/Havoc` structure — `teamserver/`, `client/`, `payloads/`, `profiles/`, `data/`.
**Significance:** unlike Mythic (T4), Havoc ships its implant. This report contains **both** `[source]` (Go/C/yaotl) and the wire protocol at byte level, derived from matching the C packer against the Go parser — a cross-verified reconstruction.

---

## 1. Architecture

### 1.1 Component split

| Component | Path | Language | Role |
|---|---|---|---|
| Teamserver | `teamserver/` | Go | Listeners, agent registry, task queue, SOCKS/portfwd, SQLite persistence |
| Client GUI | `client/` | C++/Qt | Operator UI (`.ui` files, `.qss` stylesheets, Qt resources) |
| **Demon agent** | `payloads/Demon/` | C + x86/x64 ASM | The implant — full source |
| DllLdr | `payloads/DllLdr/` | C | Reflective DLL loader (a separate PE) |
| Shellcode | `payloads/Shellcode/` | C + prebuilt `.bin` | Shellcode template that hosts the DLL |
| Profiles | `profiles/` | yaotl (HCL) | `havoc.yaotl`, `http_smb.yaotl`, `webhook_example.yaotl` |
| Cross-compilers | `data/` | prebuilt toolchain | `x86_64-w64-mingw32-gcc`, `i686-w64-mingw32-gcc`, `nasm` |

### 1.2 Server/agent split

The **teamserver is a thin router**; the **agent is where the tradecraft lives**. Concretely:

- Teamserver responsibilities: HTTP/S listener with profile-driven header/URI/UA validation, SMB pipe listener, "External" listener (for third-party agents), agent registration parsing, job queue, request-ID tracking, SOCKS server, port-forward relay, SQLite persistence, Discord webhooks, multi-operator chat.
- Agent responsibilities: sleep obfuscation, AMSI/ETW patching, indirect syscalls, stack spoofing, injection, token manipulation, Kerberos, .NET/CLR, COFF loading, SMB pivoting, memory-only file ops, key exchange.

### 1.3 Language / size breakdown

```
teamserver/pkg/agent/demons.go          191,942 b   <- the command dispatcher (largest file)
teamserver/pkg/agent/types.go            35,257 b
teamserver/pkg/agent/agent.go            32,446 b
teamserver/pkg/common/builder/builder.go 30,730 b   <- compile-time config generation
teamserver/cmd/server/dispatch.go        27,186 b   <- command -> dispatcher mapping
teamserver/cmd/server/teamserver.go      25,510 b
teamserver/pkg/profile/yaotl/*           ~200 KB    <- vendored HCL2 parser (OpenTofu-derived)

payloads/Demon/src/core/Command.c       123,571 b   <- all agent command handlers
payloads/Demon/src/core/Win32.c          53,230 b   <- dynamically resolved NTAPI
payloads/Demon/src/core/Token.c          46,140 b   <- full token manipulation
payloads/Demon/src/core/Obf.c            33,406 b   <- Ekko/Zilean/Foliage
payloads/Demon/src/core/CoffeeLdr.c      30,387 b   <- Cobalt Strike BOF loader
payloads/Demon/src/core/Kerberos.c       26,947 b
payloads/Demon/src/core/ObjectApi.c      25,085 b
payloads/Demon/src/core/Dotnet.c         23,502 b   <- CLR hosting
payloads/Demon/src/core/Runtime.c        23,089 b
payloads/Demon/src/core/TransportHttp.c  19,365 b
payloads/Demon/src/core/Socket.c         20,530 b
payloads/Demon/src/core/SysNative.c      15,131 b
payloads/Demon/src/core/Package.c        13,257 b   <- the wire packer
payloads/Demon/src/core/Inject.c         13,246 b
payloads/Demon/src/core/Thread.c         11,941 b
payloads/Demon/src/core/Download.c       11,274 b
payloads/Demon/src/core/Pivot.c          10,543 b
payloads/Demon/src/core/HwBpEngine.c      9,908 b
payloads/Demon/src/crypt/AesCrypt.c       8,157 b   <- tiny-AES-c, CTR mode
payloads/Demon/src/core/Syscalls.c        7,171 b
payloads/Demon/include/common/Native.h   538,813 b  <- NTAPI struct/typedef wall
payloads/Demon/include/common/Defines.h   21,538 b  <- API hash table
```

Notable design decision: the **Go teamserver is ~55% vendored HCL parser** (`pkg/profile/yaotl/`), i.e. Havoc's own logic is small. Its complexity budget went into the agent.

---

## 2. Protocol Detail

### 2.1 The outer wire frame

Every agent→teamserver transmission is:

```
[ SIZE        ] 4 bytes  LE   total size of everything after this field
[ Magic Value ] 4 bytes  LE   0xDEADBEEF  (DEMON_MAGIC_VALUE)
[ Agent ID    ] 4 bytes  LE   random per-build session ID
[ COMMAND ID  ] 4 bytes  LE   first command
[ REQUEST ID  ] 4 bytes  LE   first request ID
[ DATA ...    ]
```

[source: `payloads/Demon/include/common/Defines.h:15` (`#define DEMON_MAGIC_VALUE 0xDEADBEEF`); `teamserver/pkg/agent/agent.go:181-213` (`ParseHeader`) parses Size → MagicValue → AgentID, then hands the remaining parser to the dispatcher]

**Magic value `0xDEADBEEF`** is the single strongest static/dynamic signature for Havoc Demon traffic. On the wire (little-endian) it appears as `EF BE AD DE` [source].

Header parse failure modes: `"failed to parse package size"`, `"failed to parse magic value"`, `"failed to parse agent id"` [source: `agent.go:190,196,202`].

Dispatch: if `MagicValue == 0xDEADBEEF` → `handleDemonAgent`; otherwise → `handleServiceAgent` (third-party agent support) [source: `handlers/handlers.go:44-50`].

### 2.2 The DEMON_INITIALIZE (registration) packet — exact layout

This is the agent's first message and the **only** one carrying plaintext key material.

```
[ SIZE         ] 4 bytes
[ Magic Value  ] 4 bytes   DEADBEEF
[ Agent ID     ] 4 bytes
[ COMMAND ID   ] 4 bytes   = DEMON_INITIALIZE (99)
[ Request ID   ] 4 bytes
[ AES KEY      ] 32 bytes  CLEARTEXT, random per build
[ AES IV       ] 16 bytes  CLEARTEXT, random per build
AES-256-CTR Encrypted {
    [ Agent ID     ] 4 bytes   <- decrypt-verification sentinel
    [ Host Name    ] size+bytes  (size = 4-byte LE)
    [ User Name    ] size+bytes
    [ Domain       ] size+bytes
    [ IP Address   ] size+bytes
    [ Process Name ] size+bytes  (UTF-16!)
    [ Process ID   ] 4 bytes
    [ Thread  ID   ] 4 bytes
    [ Parent  PID  ] 4 bytes
    [ Process Arch ] 4 bytes
    [ Elevated     ] 4 bytes
    [ Base Address ] 8 bytes
    [ OS Info      ] 5 * 4 bytes
    [ OS Arch      ] 4 bytes
    [ SleepDelay   ] 4 bytes
    [ SleepJitter  ] 4 bytes
    [ Killdate     ] 8 bytes
    [ WorkingHours ] 4 bytes
    [ Optional     ] pivots / extra data
}
```

[source: `payloads/Demon/src/Demon.c` `DemonMetaData()` comment block + implementation; `teamserver/pkg/agent/agent.go:328-606` `ParseDemonRegisterRequest` — the Go side reads exactly this order with `ParseAtLeastBytes(32)`, `ParseAtLeastBytes(16)`, `ParseString()`, `ParseUTF16String()`, `ParseInt32()` ×n, `ParseInt64()`]

**Sentinel check:** the Go side reads the first 4 decrypted bytes and compares to the header AgentID: `if AgentID != DemonID { if AgentID != 0 { logger.Debug("Failed to decrypt agent init request"); return nil } }` [source: `agent.go:406-413`]. So a wrong key produces demonstrably no registration. That is a clean detection primitive.

Optional/unknown addresses are sent as a literal 4-byte `0` in place of a size-prefixed string when an API fails — e.g. `PackageAddInt32(*MetaData, 0)` when `GetComputerNameExA`/`GetUserNameA` fails [source: `Demon.c` DemonMetaData].

**Reconnect variant** (command == `DEMON_INIT`): teamserver replies with a packer containing only the 4-byte AgentID, encrypted with the known key — proving key continuity without re-registration [source: `handlers.go:69-89`].

### 2.3 Post-registration framing and encryption

Once registered, agent→server and server→agent bodies are encrypted with **AES-256-CTR**. The counter mode encrypts **in place with no IV on the wire** — the IV is fixed for the session (the one from registration) and is **never reset or incremented per message** in the C implementation [source: `AesCrypt.c:217-244` — `AesXCryptBuffer` mutates `ctx->Iv` as it runs, so a single logical stream continues; `Package.c` re-inits `AesInit` per package].

Server→agent payload construction [source: `teamserver/pkg/agent/agent.go:29-179` `BuildPayloadMessage`]:

```
for each Job:
    [ Command ID   ] 4 bytes LE
    [ Request ID   ] 4 bytes LE
    [ Payload Size ] 4 bytes LE
    [ Payload      ] Payload Size bytes, AES-256-CTR encrypted
```

Note the interleaving: **the command ID, request ID and size are plaintext; only the payload is encrypted** [source: `agent.go:160-173`]. `crypt.XCryptBytesAES256` = `aes.NewCipher(key)` + `cipher.NewCTR(block, iv)` + `XORKeyStream` [source: `common/crypt/aes.go:10-25`].

Agent→server responses use the same structure: dispatcher reads `(Command, RequestID)` pairs in a loop while `Header.Data.CanIRead([ReadInt32, ReadInt32])`, and calls `Header.Data.DecryptBuffer(key, iv)` on **first iteration only** [source: `handlers.go:57-95`]. The **first decryption is an in-place CTR XOR of the whole remaining buffer** — meaning the agent encrypts its entire command-payload region as one CTR stream, and the server decrypts it in one shot, then parses multiple `(cmd, reqid)` tuples from the decrypted blob. This is a genuine structural quirk: multi-command batches share one keystream.

**Missing-job response:** `COMMAND_NOJOB` (10) with empty data [source: `handlers.go:97-113`].

### 2.4 HTTP transport

- The listener is a Gin engine with `POST /*endpoint` → `request` handler and `GET /*endpoint` → `fake404` [source: `handlers/http.go:211-212`]
- **Profile-driven validation** — a request must match, case-insensitively, every header in `Config.Headers`, the exact `RequestURI` (if `Uris` is non-empty), and the `User-Agent` if set. Any mismatch → `fake404` [source: `handlers/http.go:119-173`]
- The `fake404` handler serves a bundled `404.html`, sets `Server: nginx`, `Content-Type: text/html`, `X-Havoc: true`, HTTP 404 [source: `handlers/http.go:80-91`]. This is the decoy page — the client index is the file `teamserver/pkg/handlers/404.html`
- `Connection` and `Accept-Encoding` are exempted from header checks [source: `handlers/http.go:121`]
- Response headers are taken verbatim from the profile's `Response { Headers = [...] }` block [source: `handlers/http.go:179-184`]
- External IP: `X-Forwarded-For` **only if** `BehindRedir` is set, else `RemoteAddr` split on `:` [source: `handlers/http.go:102-106`]
- TLS: `HTTPSGenerateRSACertificate` generates a self-signed cert per-listener into `logr` listener path as `server.crt`/`server.key`, written **mode 0644** [source: `handlers/http.go:32-77`]
- Agent-side transport is WinHTTP: `HostAdd`/`HostRotation`/`HostFailure`/`HostCheckup` implement multi-host rotation with failover, plus an optional explicit proxy (`Proxy.Url/Username/Password`) [source: `payloads/Demon/include/core/TransportHttp.h:15-68`; `TransportHttp.c`]
- Host rotation strategies: `TRANSPORT_HTTP_ROTATION_ROUND_ROBIN = 0`, `TRANSPORT_HTTP_ROTATION_RANDOM = 1` [source: `TransportHttp.h:11-12`]
- Hardcoded error constant `ERROR_INTERNET_CANNOT_CONNECT = 12029` [source: `TransportHttp.h:13`]

### 2.5 SMB pivot transport (agent↔agent)

The SMB pivot is implemented as a **named pipe with message-type semantics**, and the framing is deliberately *different* from HTTP:

```
[ DemonID     ] 4 bytes
[ PackageSize ] 4 bytes
[ Data        ] PackageSize bytes
```

[source: `payloads/Demon/src/core/TransportSmb.c:65-110` `SmbRecv` — reads `DemonId` (4), then `PackageSize` (4), then allocates and reads that many bytes; the Go side has the matching reader]

Pipe creation [source: `TransportSmb.c:15-34`]:
```
CreateNamedPipeW( name, PIPE_ACCESS_DUPLEX,
                  PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                  PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_MAX, PIPE_BUFFER_MAX, ... )
```
`ConnectNamedPipe` blocks until a peer links. Security attributes are configured to **allow "anyone" to connect** to the pipe [source: `TransportSmb.c:15` comment].

Default pipe name from the shipped profile: **`demon_pipe`** [source: `profiles/http_smb.yaotl` — `PipeName = "demon_pipe"`].

Agent-side pivot bookkeeping [source: `payloads/Demon/include/core/Pivot.h`]:
```c
#define MAX_SMB_PACKETS_PER_LOOP 30
typedef struct _PIVOT_DATA { UINT32 DemonID; BUFFER PipeName; HANDLE Handle; struct _PIVOT_DATA* Next; } PIVOT_DATA;
```
`PivotAdd`, `PivotRemove`, `PivotCount`, `PivotGet`, `PivotParseDemonID`, `PivotPush`. **`MAX_SMB_PACKETS_PER_LOOP = 30`** is a hardcoded throughput bound worth noting for detection (bursty 30-packet trays on a pipe). Server-side child tracking: `db.TS_Links` table with `ParentAgentID`/`LinkAgentID` [source: `teamserver/pkg/db/db.go`].

### 2.6 SOCKS / port-forward protocol

Agent-side socket types and commands [source: `payloads/Demon/include/core/Socket.h:3-26`]:

```c
SOCKET_TYPE_NONE             0x0
SOCKET_TYPE_REVERSE_PORTFWD  0x1
SOCKET_TYPE_REVERSE_PROXY    0x2   /* socks5 */
SOCKET_TYPE_CLIENT           0x3

SOCKET_COMMAND_RPORTFWD_ADD      0x0
SOCKET_COMMAND_RPORTFWD_ADDLCL   0x1
SOCKET_COMMAND_RPORTFWD_LIST     0x2
SOCKET_COMMAND_RPORTFWD_CLEAR    0x3
SOCKET_COMMAND_RPORTFWD_REMOVE   0x4
SOCKET_COMMAND_SOCKSPROXY_ADD    0x5
SOCKET_COMMAND_SOCKSPROXY_LIST   0x6
SOCKET_COMMAND_SOCKSPROXY_REMOVE 0x7
SOCKET_COMMAND_SOCKSPROXY_CLEAR  0x8
SOCKET_COMMAND_OPEN              0x10
SOCKET_COMMAND_READ              0x11
SOCKET_COMMAND_WRITE             0x12
SOCKET_COMMAND_CLOSE             0x13
SOCKET_COMMAND_CONNECT           0x14

SOCKET_ERROR_ALREADY_BOUND       0x1
```

Everything rides inside `DEMON_COMMAND_SOCKET` (2540) with a `SocketID`/parent-ID correlation field. `SocketNew(...)` takes `Type, UseIpv4, IPv4, IPv6, LclPort, FwdAddr, FwdPort, ParentID` [source: `Socket.h:86`]. Reverse-portfwd is IPv4-only by design [source: `Socket.h:153` comment in `Socket.c`]. Socks5 clients are tracked server-side by `SocksClientAdd(SocketID, conn, ATYP, IpDomain, Port)` / `SocksClientRead` / `SocksClientClose` [source: `teamserver/pkg/agent/agent.go:1053-1163`].

### 2.7 Command ID table (complete)

[source: `payloads/Demon/include/core/Command.h`]

Agent→server internal codes:
```
DEMON_COMMAND_GET_JOB       1      DEMON_COMMAND_CHECKIN      100
DEMON_COMMAND_NO_JOB        10     DEMON_INFO                  89
DEMON_COMMAND_SLEEP         11     DEMON_OUTPUT                90
                                   DEMON_ERROR                 91
                                   DEMON_EXIT                  92
                                   DEMON_KILL_DATE             93
                                   BEACON_OUTPUT               94
                                   DEMON_INITIALIZE            99
```

Task commands (teamserver→agent):
```
DEMON_COMMAND_PROC                    0x1010 (4112)
DEMON_COMMAND_PROC_LIST               12
DEMON_COMMAND_FS                      15
DEMON_COMMAND_INLINE_EXECUTE          20
DEMON_COMMAND_JOB                     21
DEMON_COMMAND_INJECT_DLL              22
DEMON_COMMAND_INJECT_SHELLCODE        24
DEMON_COMMAND_SPAWN_DLL               26
DEMON_COMMAND_TOKEN                   40
DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE 0x2001 (8193)
DEMON_COMMAND_ASSEMBLY_VERSIONS       0x2003 (8195)
DEMON_COMMAND_NET                     2100
DEMON_COMMAND_CONFIG                  2500
DEMON_COMMAND_SCREENSHOT              2510
DEMON_COMMAND_PIVOT                   2520
DEMON_COMMAND_TRANSFER                2530
DEMON_COMMAND_SOCKET                  2540
DEMON_COMMAND_KERBEROS                2550
DEMON_COMMAND_MEM_FILE                2560
DEMON_PACKAGE_DROPPED                 2570
```

Sub-commands [source: same header]: `PROC_MODULES 2 / PROC_GREP 3 / PROC_CREATE 4 / PROC_MEMORY 6 / PROC_KILL 7`; `FS_DIR 1 / FS_DOWNLOAD 2 / FS_UPLOAD 3 / FS_CD 4 / FS_REMOVE 5 / FS_MKDIR 6 / FS_COPY 7 / FS_MOVE 8 / FS_GET_PWD 9 / FS_CAT 10`; `TOKEN_IMPERSONATE 1 / STEAL 2 / LIST 3 / PRIVSGET_OR_LIST 4 / MAKE 5 / GET_UID 6 / REVERT 7 / REMOVE 8 / CLEAR 9 / FIND_TOKENS 10`; `NET_COMMAND_DOMAIN 1 … USER 9`; `PIVOT_LIST 1 / SMB_CONNECT 10 / SMB_DISCONNECT 11 / SMB_COMMAND 12`; `JOB_LIST 1 / SUSPEND 2 / RESUME 3 / KILL_REMOVE 4 / DIED 5`; `TRANSFER_LIST 0 / STOP 1 / RESUME 2 / REMOVE 3`; `CONFIG_IMPLANT_SLEEPMASK 1 / SPFTHREADADDR 3 / VERBOSE 4 / SLEEP_TECHNIQUE 5 / COFFEE_THREADED 6 / COFFEE_VEH 7`; `CONFIG_MEMORY_ALLOC 101 / EXECUTE 102`; `CONFIG_INJECTION_TECHNIQUE 150 / SPOOFADDR 151 / SPAWN64 152 / SPAWN32 153 / KILLDATE 154 / WORKINGHOURS 155`.

Error sub-codes: `CALLBACK_ERROR_WIN32 0x1`, `CALLBACK_ERROR_COFFEXEC 0x2`, `CALLBACK_ERROR_TOKEN 0x3` [source: `Command.h:51-53`]. `PackageTransmitError(ID, ErrorCode)` emits a `DEMON_ERROR` (91) package containing `[ID][ErrorCode]` [source: `Package.c:471-484`].

Agent info codes: `DEMON_INFO_MEM_ALLOC 10 / MEM_EXEC 11 / MEM_PROTECT 12 / PROC_CREATE 21` [source: `Command.h:92-95`].

Inline-execute result codes: `INLINE_EXECUTE_EXCEPTION 1 / SYMBOL_NOT_FOUND 2 / RAN_OK 3 / COULD_NO_RUN 4` [source: `Command.h:40-43`].

.NET info codes: `DOTNET_INFO_PATCHED 0x1 / NET_VERSION 0x2 / ENTRYPOINT_EXECUTED 0x3 / FINISHED 0x4 / FAILED 0x5` [source: `Command.h:45-49`].

### 2.8 Serialisation primitives

Agent→server (C `Package.c`):
- All integers **big-endian**: `Int32ToBuffer` writes `(Size>>24)`, `(Size>>16)`, `(Size>>8)`, `Size` [source: `Package.c:39-47`]; `Int64ToBuffer` likewise big-endian [source: `Package.c:13-37`]
- Strings/buffers: `[uint32 size][bytes]`, size big-endian, **no null terminator added by `PackageAddBytes`** [source: `Package.c:125-145`]
- `PackageAddString` = `PackageAddBytes(data, StringLengthA(data))` — length excludes the terminator [source: `Package.c:147-150`]

Server→agent (Go `BuildPayloadMessage` + `Packer`):
- **Little-endian** (`binary.LittleEndian`) [source: `agent.go:44-151`; `common/packer/packer.go`]
- Strings get a `\x00` appended if absent, and the **NUL is included in the length** [source: `agent.go:111-119`]
- `bool` → 4-byte LE 1/0; `byte` → 1 byte; `[]byte` → size-prefixed
- Unknown types log `"Could not package, unknown data type: %v"` [source: `agent.go:155-157`]

**Endianness asymmetry between the C agent's own package builder (big-endian) and the Go teamserver's task builder (little-endian) is a real, exploitable protocol detail** — the C parser (`Parser.c`) is configured accordingly per direction. This is one of the sharpest fingerprints available for a Havoc implementation.

Size limits: `DEMON_MAX_REQUEST_LENGTH = 0x300000` (3 MiB) [source: `payloads/Demon/include/core/Package.h:6`].

Package struct [source: `Package.h:8-18`]:
```c
typedef struct _PACKAGE {
    UINT32 RequestID; UINT32 CommandID; PVOID Buffer; SIZE_T Length;
    BOOL Encrypt; BOOL Destroy; BOOL Included; struct _PACKAGE* Next;
} PACKAGE, *PPACKAGE;
```
`Destroy` controls whether the package survives a failed transmit — the registration package sets `Destroy = FALSE` so it can be retried [source: `Demon.c` DemonMetaData].

### 2.9 Server-side command dispatch

Teamserver dispatcher lives in `teamserver/pkg/agent/demons.go` (192 KB) with the command→handler mapping in `teamserver/cmd/server/dispatch.go` (27 KB). Request-ID validation is `IsKnownRequestID(teamserver, RequestID, CommandID)` [source: `agent.go:609-631`], which **always accepts `COMMAND_SOCKET` and `COMMAND_PIVOT`** regardless of outstanding request IDs — because those are stream-oriented rather than request/response:

```go
switch CommandID {
case COMMAND_SOCKET: return true
case COMMAND_PIVOT:  return true
}
```

That exemption is a protocol-level fact: SOCKS and pivot traffic is unsolicited and asynchronously interleaved into the response stream.

Download tracking server-side: `DownloadAdd(FileID, FilePath, FileSize)` / `DownloadWrite(FileID, data)` / `DownloadClose(FileID)` / `DownloadGet(FileID)` [source: `agent.go:816-910`].

### 2.10 Operator ↔ teamserver protocol

The client talks to the teamserver on a **separate port** (default 40056, distinct from listener ports) [source: `profiles/havoc.yaotl` — `Teamserver { Host = "0.0.0.0"  Port = 40056 }`]. The "External" listener type (`LISTENER_EXTERNAL = 3`, `AGENT_EXTERNAL = "External"`) exists specifically so third-party agents can be integrated from other frameworks [source: `handlers/types.go` constants block].

Listener type constants [source: `handlers/types.go`]:
```go
LISTENER_HTTP      = 1
LISTENER_PIVOT_SMB = 2
LISTENER_EXTERNAL  = 3
LISTENER_SERVICE   = 4
AGENT_HTTPS = "Https"; AGENT_HTTP = "Http"; AGENT_EXTERNAL = "External"; AGENT_PIVOT_SMB = "Smb"
```

---

## 3. Cryptography

### 3.1 AES-256-CTR (the only message cipher)

- **Algorithm: AES-256 in CTR mode**, `AES_BLOCKLEN 16`, `AES_KEYLEN 32`, `AES_keyExpSize 240`, `CTR 1`, `AES256 1` [source: `payloads/Demon/include/crypt/AesCrypt.h:6-15`]
- Implementation is **tiny-AES-c** (`sbox`, `Rcon`, `KeyExpansion`, `Cipher`, `InvCipher`) [source: `payloads/Demon/src/crypt/AesCrypt.c:23-213`]. `Rcon[11]` uses the odd `0x8d` first element to make `Rcon[i/Nk]` indexing work — a known tiny-AES-c quirk that is itself a **fingerprint** [source: `AesCrypt.c:42-43`]
- `AesXCryptBuffer(ctx, buf, length)` is the CTR transform: it encrypts `ctx->Iv` with the round keys to produce the keystream block, then **increments the IV big-endian across all 16 bytes** (`for bi = 15 down to 0: if Iv[bi]==255 { Iv[bi]=0; continue } Iv[bi] += 1; break`) [source: `AesCrypt.c:217-244`]
- Duplex: `XCryptBytesAES256` is used identically for encrypt and decrypt (CTR symmetry) [source: `teamserver/pkg/common/crypt/aes.go:10-25`; `Package.c` uses the same call for both directions]

### 3.2 Key generation and origin — the critical finding

```
Instance->Config.AES.Key = LocalAlloc(LPTR, 32);
Instance->Config.AES.IV  = LocalAlloc(LPTR, 16);
for (i = 0; i < 32; i++) Instance->Config.AES.Key[i] = RandomNumber32();
for (i = 0; i < 16; i++) Instance->Config.AES.IV[i]  = RandomNumber32();
```

[source: `payloads/Demon/src/Demon.c` `DemonMetaData()`]

**The AES key and IV are generated by the AGENT at runtime and transmitted to the teamserver in cleartext, unencrypted, inside the DEMON_INITIALIZE packet** [source: `Demon.c` — `PackageAddPad(*MetaData, Instance->Config.AES.Key, 32); PackageAddPad(*MetaData, Instance->Config.AES.IV, 16);` placed before any encrypted content; `agent.go:387-389` `AESKey: Parser.ParseAtLeastBytes(32), AESIv: Parser.ParseAtLeastBytes(16)`].

Consequences, stated plainly:
1. **There is no key exchange protocol.** The key is simply handed over in the clear on first contact.
2. **Any observer positioned on the first HTTP/S request** (redirector logs, TLS-terminating proxy, IDS capturing the victim's egress) sees the 32-byte key and 16-byte IV and can decrypt 100% of that session's traffic for the life of the agent.
3. **The server is a passive recipient** — it never generates, contributes to, or verifies key material. There is no PFS, no ratchet, no rotation, no rekey message.
4. `RandomNumber32()` — `Runtime.c` implements it from a non-cryptographic source (`hSystemTime`-like entropy, seeded per-session). This is not `CryptGenRandom`/`BCryptGenRandom`; the key space is materially weaker than 2^256 [source: `payloads/Demon/src/core/Runtime.c` — `RandomNumber32`].
5. Two keys/IVs are all that exist. `Instance->Config.AES` is a single struct, so **all C2 channels for that agent (HTTP + SMB) share one key and IV**.
6. In the Go teamserver, when the key is all-zeros the packer **skips encryption entirely** — `bytes.Compare(p.AesKey, Temp) == 0` → returns plaintext, and logs `"No Aes Key specified"` [source: `common/packer/packer.go:75-84`]. A 32-zero-byte key therefore means plaintext C2 as a supported mode.

### 3.3 Key at rest

The key and IV are persisted **unencrypted, as text, in the teamserver's SQLite database** [source: `teamserver/pkg/db/db.go` `init()`]:
```sql
CREATE TABLE "TS_Agents" ("AgentID" int, "Active" int, "Reason" string,
  "AESKey" string, "AESIv" string, ... );
```
`TS_Listeners` stores each listener's `Config` as text. `TS_Links` stores the parent/child agent graph. There is no column encryption and no database password — the SQLite file is the crown jewel on a teamserver host. Agent session keys are also written to per-agent session directories (`logr` instance; `SessionDir` per agent) [source: `teamserver/pkg/logr/demon.go`].

### 3.4 TLS

`HTTPSGenerateRSACertificate(ipv4)` generates a **self-signed RSA certificate** per listener at start [source: `handlers/http.go:60`; `pkg/common/certs/https.go`]. Cert and key written to disk as `server.crt` / `server.key` with mode `0644` [source: `handlers/http.go:62-72`] — group/world readable. A profile may instead point at external cert/key paths via the `Cert { Cert = ""  Key = "" }` block, which overrides the generated pair [source: `handlers/http.go:235-238`].

Note: the server itself has no TLS for the operator channel in this repo's handlers — the client↔teamserver link on 40056 is handled in `teamserver/cmd/` and `client/`, and its transport (raw TCP with a custom handshake) is outside the files read here. Documented as a gap.

### 3.5 No hashing, no MAC, no authentication of ciphertext

There is **no HMAC, no AEAD tag, no integrity check** anywhere in the message path. AES-CTR provides confidentiality only. A single-bit flip in the ciphertext flips exactly the corresponding plaintext bit with no detection. There is also **no per-message nonce** — the CTR counter continues across the session, so a replayed capture of an earlier response plus knowledge of the keystream position allows forgery.

The only "authentication" in the whole protocol is:
- `Magic Value == 0xDEADBEEF` (a static constant — not a secret)
- the post-decrypt AgentID sentinel check (which requires the key, so it does verify key possession indirectly during registration) [source: `agent.go:406-413`]
- profile-matching on HTTP headers/URI/UA (obfuscation, not authentication — all values are in the profile file and on the wire) [source: `handlers/http.go:119-173`]
- operator usernames and plaintext passwords in the yaotl profile [source: `profiles/havoc.yaotl`]

### 3.6 Operator and service credentials

From `profiles/havoc.yaotl` [source]:
```
Operators { user "5pider" { Password = "password1234" }
            user "Neo"    { Password = "password1234" } }
Service   { Endpoint = "service-endpoint"  Password = "service-password" }
```
`profiles/http_smb.yaotl` repeats the same `password1234` pair [source]. **`password1234` is the hardcoded default operator password in both shipped profiles**, and `service-password` the default service credential. These are plaintext in the config file — no hash, no salt. The `Operators`/`Service` blocks are parsed into `UsersBlock{Name, Password}` and `ServiceConfig{Endpoint, Password}` [source: `teamserver/pkg/profile/config.go`].

Demon checkin options constant `DEMON_CHECKIN_OPTION_PIVOTS = 1` [source: `Command.h:97`].

---

## 4. Hardcoded Values

### 4.1 Ports and addresses

| Value | Where | Note |
|---|---|---|
| **40056** | `profiles/*.yaotl` `Teamserver { Port = 40056 }` | operator/client ↔ teamserver port |
| **443** | `profiles/http_smb.yaotl` `PortBind = 443`, `PortConn = 443` | example HTTP listener |
| `0.0.0.0` | both profiles, `Teamserver.Host`, `Http.HostBind` | bind-somewhat-anything default |
| `5pider.net` | `profiles/http_smb.yaotl` `Hosts = [...]` | example callback host |
| `/Collector/2.0/settings/` | `profiles/http_smb.yaotl` `Uris` | example URI — Teams-themed mimicry |
| `demon_pipe` | `profiles/http_smb.yaotl` `Smb.PipeName` | **default SMB pivot pipe name** |
| `/usr/bin/nasm` | `havoc.yaotl` `Build.Nasm` | |
| `/usr/bin/x86_64-w64-mingw32-gcc`, `/usr/bin/i686-w64-mingw32-gcc` | `http_smb.yaotl` | |
| `data/x86_64-w64-mingw32-cross/bin/…`, `data/i686-w64-mingw32-cross/bin/…` | `havoc.yaotl` | bundled toolchain |

### 4.2 Magic numbers and constants

```c
DEMON_MAGIC_VALUE        0xDEADBEEF      // Defines.h:15  -- THE Havoc signature
DEMON_MAX_REQUEST_LENGTH 0x300000        // Package.h:6   3 MiB
MAX_SMB_PACKETS_PER_LOOP 30              // Pivot.h
LDR_GADGET_MODULE_SIZE   0x1000 * 0x1000 // Defines.h:31  (16 MiB) reflective loader
LDR_GADGET_HEADER_SIZE   0x1000          // Defines.h:32
ERROR_INTERNET_CANNOT_CONNECT 12029      // TransportHttp.h:13
PROXYLOAD_NONE/RTLREGISTERWAIT/RTLCREATETIMER/RTLQUEUEWORKITEM  0/1/2/3   // Defines.h:34-37
AMSIETW_PATCH_NONE/HWBP/MEMORY          0/1/2     // Defines.h:39-41
SLEEPOBF_NO_OBF/EKKO/ZILEAN/FOLIAGE     0x0/0x1/0x2/0x3  // SleepObf.h
SLEEPOBF_BYPASS_NONE/JMPRAX/JMPRBX      0/0x1/0x2  // SleepObf.h
PROCESS_ARCH_UNKNOWN/X86/X64/IA64       0/1/2/3   // Defines.h:4-7
DEMON_COMMAND_INLINE_EXECUTE_EXCEPTION 1 / SYMBOL_NOT_FOUND 2 / RAN_OK 3 / COULD_NO_RUN 4
```

`RandomNumber32()` seeds the AES key/IV and the AgentID [source: `Runtime.c`].

### 4.3 Full API-hash table

`payloads/Demon/include/common/Defines.h` (21,538 b) contains **precomputed 32-bit hash constants for every resolved Windows API**, used to build the import table without string literals. Representative cluster [source: `Defines.h:44-91`]:

```c
#define H_FUNC_LDRLOADDLL                     0x9e456a43
#define H_FUNC_LDRGETPROCEDUREADDRESS         0xfce76bb6
#define H_FUNC_NTADDBOOTENTRY                 0x8cfcc776
#define H_FUNC_NTALLOCATEVIRTUALMEMORY        0xf783b8ec
#define H_FUNC_NTFREEVIRTUALMEMORY            0x2802c609
#define H_FUNC_NTUNMAPVIEWOFSECTION           0x6aa412cd
#define H_FUNC_NTWRITEVIRTUALMEMORY           0xc3170192
#define H_FUNC_NTSETINFORMATIONVIRTUALMEMORY  0x946ac239
#define H_FUNC_NTQUERYVIRTUALMEMORY           0x10c0e85d
#define H_FUNC_NTOPENPROCESSTOKEN             0x350dca99
#define H_FUNC_NTOPENTHREADTOKEN              0x803347d2
#define H_FUNC_NTQUERYOBJECT                  0xc85dc9b4
#define H_FUNC_NTTRACEEVENT                   0x70c25cd8
#define H_FUNC_NTOPENPROCESS                  0x4b82f718
#define H_FUNC_NTTERMINATEPROCESS             0x4ed9dd4f
#define H_FUNC_NTOPENTHREAD                   0x968e0cb1
#define H_FUNC_NTSETCONTEXTTHREAD             0xffa0bf10
#define H_FUNC_NTGETCONTEXTTHREAD             0x6d22f884
#define H_FUNC_NTCLOSE                        0x40d6e69d
#define H_FUNC_NTCONTINUE                     0xfc3a6c2c
#define H_FUNC_NTSETEVENT                     0xcb87d8b5
#define H_FUNC_NTCREATEEVENT                  0x28d3233d
#define H_FUNC_NTWAITFORSINGLEOBJECT          0xe8ac0c3c
#define H_FUNC_NTSIGNALANDWAITFORSINGLEOBJECT 0x78983aed
#define H_FUNC_NTGETNEXTTHREAD                0xa410fb9e
#define H_FUNC_NTRESUMETHREAD                 0x5a4bc3d0
#define H_FUNC_NTSUSPENDTHREAD                0xe43d93e1
#define H_FUNC_NTDUPLICATEOBJECT              0x4441d859
#define H_FUNC_NTQUERYINFORMATIONTHREAD       0xf5a0461b
#define H_FUNC_NTCREATETHREADEX               0xaf18cfb0
#define H_FUNC_NTQUEUEAPCTHREAD               0xa6664b8
#define H_FUNC_NTQUERYSYSTEMINFORMATION       0x7bc23928
#define H_FUNC_NTQUERYINFORMATIONTOKEN        0xf371fe4
#define H_FUNC_NTQUERYINFORMATIONPROCESS      0x8cdc5dc2
#define H_FUNC_NTSETINFORMATIONTHREAD         0xc3c03f1
#define H_FUNC_NTPROTECTVIRTUALMEMORY         0x50e92888
#define H_FUNC_NTREADVIRTUALMEMORY            0xa3288103
```
A separate `H_COFFAPI_*` block covers the BOF (COFF) loader's API set — e.g. `H_COFFAPI_NTREADVIRTUALMEMORY 0xc24062e3`, `H_COFFAPI_NTTERMINATETHREAD 0xac3c9dc8`, `H_COFFAPI_NTALERTRESUMETHREAD 0x482e8408`, `H_COFFAPI_NTSIGNALANDWAITFORSINGLEOBJECT 0x7bdd15cd`, `H_COFFAPI_NTQUERYVIRTUALMEMORY 0xe39d8e5d`, `H_COFFAPI_NTQUERYINFORMATIONTOKEN 0x2ce5a244`, `H_COFFAPI_NTQUERYINFORMATIONTHREAD 0xc91f149b`, `H_COFFAPI_NTQUERYOBJECT 0x218116f4`, `H_COFFAPI_NTCLOSE 0x8b8e133d`, `H_COFFAPI_NTSETINFORMATIONTHREAD 0x54212e31`, `H_COFFAPI_NTSETINFORMATIONVIRTUALMEMORY 0xe7aea539`, `H_COFFAPI_NTGETNEXTTHREAD 0x8f8000fe` [source: `Defines.h:340-366`]

Module hashes [source: `Defines.h:368-369`]:
```c
#define H_MODULE_KERNEL32  0xadd31df0
#define H_MODULE_NTDLL     0x70e61753
```

These constants are **directly usable as YARA-style static signatures** — a compiled Demon contains these immediates regardless of string obfuscation.

### 4.4 Duplicate/buggy defines (worth noting in the record)

`Defines.h:22-23` defines `WIN_VERSION_2008_R2` **twice** (`5` then `6`), and `Defines.h:54`/`60` define `H_FUNC_NTOPENTHREADTOKEN` twice with the same value, and `Defines.h:51`/`80` define `H_FUNC_NTSETINFORMATIONVIRTUALMEMORY` twice (`0x946ac239` both). Repeated defines with identical values are benign but the `WIN_VERSION_2008_R2` collision (5 vs 6) means the second definition wins and `5` is unreachable — an OS-version-detection edge case [source: `Defines.h:22-23`].

### 4.5 Default injection targets

`profiles/havoc.yaotl`: `Spawn64 = "C:\\Windows\\System32\\notepad.exe"`, `Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"` [source].
`profiles/http_smb.yaotl`: `Spawn64 = "C:\\Windows\\System32\\Werfault.exe"`, `Spawn32 = "C:\\Windows\\SysWOW64\\Werfault.exe"` [source]. `Werfault.exe` is the notable one — a signed Microsoft binary chosen for parent-process legitimacy.

### 4.6 Default agent parameters

Both shipped profiles: `Demon { Sleep = 2, Jitter = 15|20, TrustXForwardedFor = false }` [source]. `.yaotl` also carries `DotNetNamePipe` (a named pipe for CLR hosting) and a `Binary { Header { MagicMz-x64, MagicMz-x86, CompileTime, ImageSize-x64, ImageSize-x86 } ReplaceStrings-x64/-x86 }` block for PE header and string replacement during build [source: `teamserver/pkg/profile/config.go`].

---

## 5. Persistence + Evasion Mechanisms

All of this section is `[source]` from `payloads/Demon/` and is **implant-side** — the real tradecraft.

### 5.1 Sleep obfuscation — three techniques, all implemented

[source: `payloads/Demon/include/core/SleepObf.h`; `payloads/Demon/src/core/Obf.c`]

```c
#define SLEEPOBF_NO_OBF  0x0
#define SLEEPOBF_EKKO    0x1
#define SLEEPOBF_ZILEAN  0x2
#define SLEEPOBF_FOLIAGE 0x3
```

`Obf.c` contains `FoliageObf(...)` (line 22), `TimerObf(...)` (line 339), and the `SleepObf()` dispatcher (line 714).

**Foliage** [source: `Obf.c:16-22` comment — *"foliage is a sleep obfuscation technique that is using APC calls"*] builds a chain of 13 prepared `CONTEXT` structures executed as an APC-driven ROP chain:

```
RopInit, RopCap, RopSpoof, RopBegin, RopSetMemRw, RopMemEnc,
RopGetCtx, RopSetCtx, RopWaitObj, RopMemDec, RopSetMemRx, RopSetCtx2, RopExitThd
```
Each is `LocalAlloc(LPTR, sizeof(CONTEXT))` with `ContextFlags = CONTEXT_FULL` [source: `Obf.c:83-111`]. The sequence is the canonical Foliage pattern:
1. `NtCreateEvent` (SynchronizationEvent) [source: `Obf.c:79`]
2. `NtCreateThreadEx` on `Instance->Config.Implant.ThreadStartAddr` with **stack size and max stack both `0x1000 * 20` (80 KB)**, created **suspended** (`TRUE`) [source: `Obf.c:81`]
3. `NtDuplicateObject(NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupObj, THREAD_ALL_ACCESS, 0, 0)` — duplicate the current thread handle so the APC can operate on it [source: `Obf.c:113`]
4. `NtGetContextThread(hThread, RopInit)` and `MemCopy(RopBegin, RopInit, sizeof(CONTEXT))` — capture and clone the real context [source: `Obf.c:115-117`]
5. Encrypt image, wait, decrypt, restore RX, terminate helper thread

The `OBF_JMP` macro encodes the return-address bypass [source: `SleepObf.h`]:
```c
#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    Rop[ i ].Rax = U_PTR( p ); } \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {    Rop[ i ].Rbx = U_PTR( & p ); } \
    else {                                          Rop[ i ].Rip = U_PTR( p ); }
```
`SLEEPOBF_BYPASS_JMPRAX = 0x1`, `SLEEPOBF_BYPASS_JMPRBX = 0x2` — this is the **call-stack / return-address spoofing** used to avoid RIP-based detections during the obfuscated sleep.

Explicitly invoked as a ROP gadget target: the chain uses `RopSetMemRw` → `NtProtectVirtualMemory(RW)` → encrypt → `RopWaitObj`(wait) → `RopMemDec` → `RopSetMemRx` (`NtProtectVirtualMemory(RX)`). Text section base and size come from `Instance->Session.TxtBase`/`TxtSize`, populated at init [source: `Demon.h` Session struct; `Obf.c:49-51`].

**Zilean** (`SLEEPOBF_ZILEAN = 0x2`) and **Ekko** (`SLEEPOBF_EKKO = 0x1`) share this ROP-chain scaffolding in `Obf.c` (TimerObf at line 339 is the timer-queue variant).

### 5.2 AMSI / ETW patching — two modes

[source: `Defines.h:39-41`; `builder.go:60-62, 833-840`]
```c
#define AMSIETW_PATCH_NONE   0
#define AMSIETW_PATCH_HWBP   1
#define AMSIETW_PATCH_MEMORY 2
```

**Hardware-breakpoint mode (HWBP)**: `HwBpEngine.c` (9,908 b) + `HwBpEngine.h` + `HwBpExceptions.c` implement a VEH-based hardware breakpoint engine:
```c
typedef struct _BP_LIST { DWORD Tid; PVOID Address; PVOID Function; BYTE Position; struct _BP_LIST* Next; } BP_LIST;
typedef struct _HWBP_ENGINE { HANDLE Veh; BYTE First; PBP_LIST Breakpoints; } HWBP_ENGINE;
NTSTATUS HwBpEngineInit(PHWBP_ENGINE Engine, PVOID Exception);   /* Vectored Exception Handler */
NTSTATUS HwBpEngineAdd(PHWBP_ENGINE, DWORD Tid, PVOID Address, PVOID Function, BYTE Position);
NTSTATUS HwBpEngineRemove(PHWBP_ENGINE, DWORD Tid, PVOID Address);
```
This is the **hardware-breakpoint AMSI/ETW bypass**: instead of writing the `AmsiScanBuffer`/`EtwEventWrite` prologue (which executes an ETW-ti telemetry event / is scanned by memory-integrity checks), it sets DR0–DR3 breakpoints on those functions and handles the resulting single-step exception in a VEH, rewriting the return value. **No bytes are modified in the target function**, so page-hash and prologue-integrity checks see the original code.

**Memory mode** patches the function prologue directly.

Both modes are selectable at build time from the yaotl profile via `AmsiEtwPatching = "..."` [source: `profile/config.go` — `AmsiEtwPatching string`; `builder.go:833` `ConfigAmsiPatch = AMSIETW_PATCH_HWBP`].

### 5.3 Indirect / native syscalls

[source: `payloads/Demon/src/core/Syscalls.c`; `SysNative.c` (15,131 b); `asm/Syscall.x64.asm`, `asm/Syscall.x86.asm`]

- `SyscallInit(Ntdll)` resolves the `syscall` instruction address from a "dummy nt function" [source: `Syscalls.c:22-30`] — the standard approach of finding any unhooked stub and reusing its `syscall` instruction, so the call site is a legitimate address inside ntdll
- x86 fallback via `__readfsdword(0xC0)` (*SystemCall* at KUSER_SHARED_DATA) [source: `Syscalls.c:39,153`]
- `ExtractSsnAndSysAddr(Function, ResolveHooked, &Ssn, &SysAddr, ...)` extracts the SSN by matching instruction byte patterns [source: `Syscalls.c:91-183`]:
  - `mov rcx, [ssn]` prologue: `0x4C 0x8B 0xD1 0xB8` [source: `Syscalls.c:125-128`]
  - `mov eax, [ssn]` prologue: `0xB8` [source: `Syscalls.c:133`]
  - SSN assembled from `DREF_U8(Function + Offset + SSN_OFFSET_1)` and `SSN_OFFSET_2`: `*Ssn = (SsnHigh << 0x08) | SsnLow` [source: `Syscalls.c:139-141`]
  - walks forward scanning `DREF_U16(Function + Offset + i) == SYSCALL_ASM` to locate the `syscall` opcode [source: `Syscalls.c:161-162`]
- **Hooked-syscall recovery**: if the prologue doesn't match, `FindSsnOfHookedSyscall(Function, Ssn)` is invoked to recover the SSN by other means [source: `Syscalls.c:177-178`] — this defeats classic "hook the first 5 bytes" EDR instrumentation
- `SysIndirect` config flag gates the indirect technique at compile time [source: `Demon.h` `_CONFIG.SysIndirect`; `builder.go` `ConfigSysIndirect`]

### 5.4 Stack spoofing / call-stack obfuscation

[source: `payloads/Demon/src/asm/Spoof.x64.asm`, `Spoof.x86.asm` (ASM); `Spoof.c`; `InjectUtil.c`]

`Instance->Config.Implant.StackSpoof` and `ThreadStartAddr` control the spoofed thread start address [source: `Demon.h` `_CONFIG`]. `DEMON_CONFIG_IMPLANT_SPFTHREADADDR = 3` sets it at runtime via the `config` command [source: `Command.h:59`]. This places a **legitimate module address** (`ThreadStartAddr`) on the stack in place of the real return path, defeating stack-walking heuristics that flag returns to non-module memory.

### 5.5 Module proxy loading

[source: `Defines.h:34-37`; `builder.go:53-56, 572, 791-819`]
```c
#define PROXYLOAD_NONE             0
#define PROXYLOAD_RTLREGISTERWAIT  1
#define PROXYLOAD_RTLCREATETIMER   2
#define PROXYLOAD_RTLQUEUEWORKITEM 3
```
Module proxy loading injects a DLL not by `LoadLibrary` but by invoking a **benign Windows callback** (`RtlRegisterWait`, `RtlCreateTimer`, `RtlQueueWorkItem`) whose function pointer lands on the target module — so the load is performed by a genuine OS callback path, and `LoadLibrary` never appears in the call stack or the ETW module-load event's immediate caller. Selectable per-build via `ProxyLoading = "..."` in the yaotl profile [source: `profile/config.go` — `ProxyLoading string`].

### 5.6 Reflective loading and PE manipulation

- `LDR_GADGET_MODULE_SIZE = 0x1000 * 0x1000` (16 MiB) and `LDR_GADGET_HEADER_SIZE = 0x1000` — the reflective loader's memory layout constants [source: `Defines.h:31-32`]
- `KAYN_ARGS { KaynLdr; DllCopy; Demon; DemonSize; TxtBase; TxtSize; }` with `#pragma pack(1)` [source: `Demon.h:36-45`] — the KaynLdr handoff structure between `DllLdr` and Demon
- `ObjectApi.c` (25,085 b) + `ObjectApi.h` implement low-level NTAPI object manipulation (open/query/duplicate without high-level Win32 wrappers)
- `payloads/DllLdr/Source/` is a separate reflective DLL loader, and `payloads/Shellcode/` is the shellcode bootstrap that hosts it
- Builder supports `Binary { Header { MagicMz-x64, MagicMz-x86, CompileTime, ImageSize-x64, ImageSize-x86 } }` plus **`ReplaceStrings-x64` / `ReplaceStrings-x86`** string-replacement maps applied at build time [source: `profile/config.go` `HeaderBlock`/`Binary` types] — i.e. the operator can rewrite PE header fields (timestamp, image size) and swap arbitrary strings to defeat static signature matching
- `payloads/Demon/scripts/` provides the shellcode/PIC conversion pipeline

### 5.7 Injection techniques

[source: `payloads/Demon/include/inject/Inject.h`]
```c
#define INJECTION_TECHNIQUE_WIN32    1
#define INJECTION_TECHNIQUE_SYSCALL  2
#define INJECTION_TECHNIQUE_APC      3
#define SPAWN_TECHNIQUE_SYSCALL      2
#define SPAWN_TECHNIQUE_APC          3
#define SPAWN_TECHNIQUE_DEFAULT      SPAWN_TECHNIQUE_SYSCALL
#define INJECTION_TECHNIQUE_DEFAULT  INJECTION_TECHNIQUE_SYSCALL
#define INJECT_WAY_SPAWN   0
#define INJECT_WAY_INJECT  1
#define INJECT_WAY_EXECUTE 2
```

Exported primitives:
```c
DWORD Inject(...);
BOOL  ShellcodeInjectDispatch(BOOL Inject, SHORT InjectionMethod, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx);
BOOL  ShellcodeInjectionSys(LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx);
BOOL  ShellcodeInjectionSysApc(HANDLE hProcess, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx);
DWORD DllInjectReflective(HANDLE hTargetProcess, LPVOID DllLdr, DWORD DllLdrSize, LPVOID lpDllBuffer, DWORD dwDllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx);
DWORD DllSpawnReflective(LPVOID DllLdr, DWORD DllLdrSize, LPVOID lpDllBuffer, DWORD dwDllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx);
```
`INJECTION_CTX` carries target process/thread handles, arch, memory permissions and the spawn path. Error codes: `INJECT_ERROR_SUCCESS 0 / FAILED 1 / INVALID_PARAM 2 / PROCESS_ARCH_MISMATCH 3` [source: `Inject.h:48-51`]. `CommandInjectDLL` (Command.c:1203), `CommandSpawnDLL` (1247), `CommandInjectShellcode` (1266) are the entry points. **Default technique is syscall-based injection with a syscall-based spawn**, both configurable via `DEMON_CONFIG_INJECTION_TECHNIQUE = 150` [source: `Command.h:68`].

Note the arch-mismatch guard (`INJECT_ERROR_PROCESS_ARCH_MISMATCH`) — the agent refuses cross-architecture injection from a WOW64 process unless the process arch matches [source: `Inject.h:51`].

### 5.8 Memory / API hygiene

- `Win32.c` (53,230 b) resolves **every** NTAPI function dynamically at init via the `H_FUNC_*` hashes, and stores them in `Instance->Win32.*`. No `GetProcAddress` string literals, no import-table entries for the sensitive functions — the import table shows almost nothing.
- `H_MODULE_KERNEL32`/`H_MODULE_NTDLL` hashes locate the modules without name strings [source: `Defines.h:368-369`]
- `Memory.c` (7,471 b) wraps `NtAllocateVirtualMemory`/`NtProtectVirtualMemory`/`NtFreeVirtualMemory` with reporting via `DEMON_INFO_MEM_ALLOC 10 / MEM_EXEC 11 / MEM_PROTECT 12` [source: `Command.h:92-94`] — the operator sees every RW→RX transition
- `SysNative.c` (15,131 b) provides the concrete native-function table
- `MiniStd.c`/`MiniStd.h` implement `MemCopy`, `MemSet`, `StringLengthA` etc. without CRT linkage — the agent links no C runtime.

### 5.9 Runtime self-configuration

The `config` command (`DEMON_COMMAND_CONFIG = 2500`) lets the operator mutate the running implant's evasion posture without re-imaging it [source: `Command.c:1865` `CommandConfig`; `Command.h:56-74`]:
- `DEMON_CONFIG_IMPLANT_SLEEPMASK = 1` — sleep mask on/off
- `DEMON_CONFIG_IMPLANT_SPFTHREADADDR = 3` — spoofed thread start address
- `DEMON_CONFIG_IMPLANT_VERBOSE = 4`
- `DEMON_CONFIG_IMPLANT_SLEEP_TECHNIQUE = 5` — switch Ekko/Zilean/Foliage live
- `DEMON_CONFIG_IMPLANT_COFFEE_THREADED = 6`, `DEMON_CONFIG_IMPLANT_COFFEE_VEH = 7` — BOF execution model
- `DEMON_CONFIG_MEMORY_ALLOC = 101`, `DEMON_CONFIG_MEMORY_EXECUTE = 102` — default memory permissions
- `DEMON_CONFIG_INJECTION_TECHNIQUE = 150`, `INJECTION_SPOOFADDR = 151`, `SPAWN64 = 152`, `SPAWN32 = 153`
- `DEMON_CONFIG_KILLDATE = 154`, `DEMON_CONFIG_WORKINGHOURS = 155`

`DEMON_CONFIG_SHOW_ALL = 0` dumps the full current config.

### 5.10 Kill date and working hours

`KillDate` (8 bytes, UINT64) and `WorkingHours` (UINT32) are honoured in the agent and settable both at build and runtime [source: `Demon.h` `_CONFIG.Transport.KillDate/WorkingHours`; `Command.h:73-74`]. `DEMON_KILL_DATE = 93` is the agent's self-termination notification. Working hours encode a start/end window (profile format `"8:00-17:00"` [source: `profile/config.go` comment]) — the agent only beacons inside that window, so out-of-hours C2 traffic is a detection signal.

### 5.11 Anti-forensic file handling

- `Download.c` (11,274 b) + `DEMON_COMMAND_TRANSFER = 2530` with `TRANSFER_LIST/STOP/RESUME/REMOVE` [source: `Command.h:105-108`] — in-flight file transfer is resumable and **cancellable with disk cleanup**
- `DEMON_COMMAND_MEM_FILE = 2560` (`Memory.c`) — file operations that never touch disk
- `Jobs.c`/`Jobs.h` — job suspension/resumption/kill with `DEMON_COMMAND_JOB_DIED = 5` reporting, so long-running operations (e.g. a port scan) can be suspended across sleep cycles
- `DEMON_PACKAGE_DROPPED = 2570` — signals a package that was generated but could not be delivered

### 5.12 Persistence

Notable: **there is no dedicated persistence command.** There is no `DEMON_COMMAND_PERSIST` / registry-Run / scheduled-task / service-install handler in `Command.h`. The full command surface is process/file/token/network/injection/assembly/Kerberos/memory. Persistence in Havoc is achieved by:
1. `MainSvc.c` — the DLL can be built as a Windows **service** (`-D SVC_EXE` at compile time, `builder.go:371,373`), giving service-based persistence if the operator installs it
2. `DllLdr` + reflective loading, typically triggered from an existing persistence primitive established by other tooling
3. The `external` / `service` listener types integrating third-party agents that do carry persistence

This is a genuine architectural finding: **Havoc's Demon is a post-exploitation implant, not a persistence framework.** The `service` command path and `MainExe`/`MainSvc`/`MainDll` entry points [source: `payloads/Demon/src/main/`] are the only built-in hosting modes.

---

## 6. Capability Inventory

Complete, from `Command.c` handler list and `Command.h` constants.

### 6.1 Process
- `Proc::List` (12) — full process enumeration with arch
- `Proc::Modules` (PROC_MODULES=2), `Proc::Grep` (3) — module listing and pattern search in process memory
- `Proc::Create` (4) — process creation with parent spoofing
- `Proc::Memory` (6) — remote process memory read
- `Proc::Kill` (7)
- `CommandProcList` at Command.c:562

### 6.2 Filesystem
`FS::Dir`(1), `FS::Download`(2), `FS::Upload`(3), `FS::Cd`(4), `FS::Remove`(5), `FS::Mkdir`(6), `FS::Copy`(7), `FS::Move`(8), `FS::GetPwd`(9), `FS::Cat`(10) [source: `Command.c:675-1114`]

### 6.3 Execution and code loading
- `InlineExecute` (20) — **Cobalt Strike BOF / COFF execution** via `CoffeeLdr.c` (30,387 b). Threading and VEH execution models selectable (`COFFEE_THREADED`, `COFFEE_VEH`). Result codes for exception/symbol-not-found/ran-ok/couldn't-run [source: `Command.c:1114`; `Command.h:40-43`]
- `AssemblyInlineExecute` (`0x2001`) — **.NET assembly execution in memory** via `Dotnet.c` (23,502 b) + `Clr.h` (21,619 b). Uses a named pipe for output (`DotNetNamePipe` config). Progress codes `DOTNET_INFO_PATCHED/NET_VERSION/ENTRYPOINT_EXECUTED/FINISHED/FAILED` [source: `Command.c:1708`; `Command.h:45-49`]
- `AssemblyListVersion` (`0x2003`) [source: `Command.c:1792`]
- `InjectDLL` (22) — static DLL injection; `SpawnDLL` (26) — spawn-and-inject with argument passing; `InjectShellcode` (24) [source: `Command.c:1203,1247,1266`]

### 6.4 Token manipulation (full Windows access-token toolkit)
`Token::Impersonate`(1), `Token::Steal`(2), `Token::List`(3), `Token::PrivsGetOrList`(4), `Token::Make`(5) — token **creation** with supplied credentials, `Token::GetUID`(6), `Token::Revert`(7), `Token::Remove`(8), `Token::Clear`(9), `Token::Find`(10) — token discovery across processes [source: `Command.c:1373-1708`; `Token.c` 46,140 b]. Server tracks a token vault and the active impersonation token (`PTOKEN_LIST_DATA Vault; PTOKEN_LIST_DATA Token; BOOL Impersonate;`) [source: `Demon.h:541-547`]

### 6.5 Kerberos
`CommandKerberos` (2550) [source: `Command.c:3077`; `Kerberos.c` 26,947 b]. Capabilities include ticket manipulation via the Kerberos API surface (`Kerberos.h` 6,512 b — `KerberosForward`, ASN.1 encoding helpers, LSA/Kerberos package calls).

### 6.6 Network
- `net` command (2100): `net domain`, `net logons`, `net sessions`, `net computer`, `net dclist`, `net share`, `net localgroup`, `net group`, `net user` [source: `Command.c:2109`; `Command.h:76-84`]
- SOCKS5 proxy: `SOCKSPROXY_ADD/LIST/REMOVE/CLEAR` (5–8) [source: `Socket.h:14-17`]
- Reverse port forward: `RPORTFWD_ADD/ADDLCL/LIST/CLEAR/REMOVE` (0–4) [source: `Socket.h:8-12`]. `ADDLCL` = add a *local* listener on the target
- Raw socket ops: `OPEN`(0x10), `READ`(0x11), `WRITE`(0x12), `CLOSE`(0x13), `CONNECT`(0x14) [source: `Socket.h:19-23`]

### 6.7 Pivoting
`PIVOT` (2520) with `PIVOT_LIST`(1), `PIVOT_SMB_CONNECT`(10), `PIVOT_SMB_DISCONNECT`(11), `PIVOT_SMB_COMMAND`(12) [source: `Command.c:2463`; `Command.h:86-90`; `Pivot.c` 10,543 b]. SMB pivots via named pipe with DemonID-addressed framing (§2.5). Server-side parent/child graph in `TS_Links`.

### 6.8 Surveillance
- `CommandScreenshot` (2510) [source: `Command.c:2084`]
- `CommandMemFile` (2560) — memory-only file ops [source: `Command.c:3237`]
- `CommandDownload`/`transfer` (2530) — resumable file exfil [source: `Command.c:2608`]

### 6.9 Self-management
`Job` (21) with LIST/SUSPEND/RESUME/KILL_REMOVE/DIED [source: `Command.c:188`]; `Config` (2500) [source: `Command.c:1865`]; `Sleep` (11) [source: `Command.c:174`]; `Checkin` (100) [source: `Command.c:163`]; `Exit` (92) [source: `Command.c:3315`]; `Transfer` (2530) [source: `Command.c:2608`].

### 6.10 Teamserver-side capabilities
- HTTP/S listener with profile-driven header/URI/UA gating and a decoy 404 page [source: `handlers/http.go`]
- SMB named-pipe listener [source: `handlers/smb.go`]
- "External" listener for third-party agent integration [source: `handlers/types.go`]
- Multi-host rotation with failure tracking and dead-host marking [source: `TransportHttp.h`; `agent.go`]
- Multi-operator support with chat (`events/chatlog.go`) and live event broadcast (`Teamserver.EventBroadcast`) [source: `events/*.go`]
- Discord webhook notifications (`WebHookDiscordConfig{ Url, AvatarUrl, User }`) [source: `profile/config.go`]
- SQLite persistence of listeners, agents, links [source: `db/db.go`]
- Per-agent session directories and logging (`logr` package: `demon.go`, `listener.go`, `server.go`) [source: `pkg/logr/`]
- Payload builder producing EXE / DLL / service EXE / shellcode from C source at runtime, with the cross-compiler invoked from `data/` [source: `pkg/common/builder/builder.go`]
- `packager` package for payload packaging [source: `pkg/packager/`]
- `win32` package for Windows-specific teamserver helpers [source: `pkg/win32/`]

---

## 7. Residual Unknowns

1. **Operator↔teamserver protocol is not characterized.** The client link on port 40056 is implemented across `teamserver/cmd/` (`client.go`, `server.go`, `teamserver.go` 25 KB), `teamserver/pkg/handlers/external.go`, and the entire `client/` C++ tree. I read the listener/agent side in depth but did **not** decode the operator handshake, message framing, or whether that link is TLS-wrapped. This is the largest remaining gap in T5.
2. **`demons.go` (191,942 b) was not read line-by-line.** It is the command dispatcher for every Demon command on the server side. I mapped its interface (`TaskDispatch`, `IsKnownRequestID`, `AddRequest`, `GetQueuedJobs`) but did not enumerate every per-command response parser. Individual command response wire layouts (e.g. the exact `Proc::List` response field order) are therefore only partially pinned.
3. **`RandomNumber32()` entropy source not established.** `Runtime.c` was not read in full for that function. If it is seeded from a predictable source (tick count / PID), the AES key and AgentID are brute-forceable, which would be a severe additional weakness on top of the cleartext-transmission finding. **High-priority follow-up.**
4. **`client/` (C++/Qt) not examined.** Contains operator UI, GraphQL-ish state, and the `.ui` layouts. Any client-side quirks, stored-credential handling, or profile-editing behaviour are unknown.
5. **`payloads/DllLdr/` and `payloads/Shellcode/` were listed but not read.** Their entry-point logic, the shellcode's position-independent resolution, and how `Shellcode.x64.bin`/`Shellcode.x86.bin` prepend to the DLL are described only from the teamserver builder's perspective.
6. **`payloads/Shellcode/Bin/` prebuilt binaries were not disassembled.** I did not run `inspect_go_binary` or Ghidra on them since they are raw shellcode (not PE/ELF/Go), which the available native tooling does not cover directly. The compiled template's exact bytes remain unexamined; all shellcode-layer claims are `[source]`-inferred from the builder.
7. **CTR IV lifecycle across messages is ambiguous.** `AesXCryptBuffer` mutates `ctx->Iv` in-place, and `Package.c` calls `AesInit` per package — but whether the agent re-initializes the IV from `Instance->Config.AES.IV` for each package, or lets the counter continue across the session, was not conclusively traced. This matters for decryption tooling: continuous-counter vs per-package-reset produce different plaintexts from the same capture. **High-priority follow-up for anyone writing a Havoc decoder.**
8. **`SSN_OFFSET_1` / `SSN_OFFSET_2` / `SYSCALL_ASM` values** were referenced in `Syscalls.c` but their `#define` values were not read from `Syscall.h`. The exact byte offsets used for SSN extraction are therefore unconfirmed (the pattern bytes `0x4C 0x8B 0xD1 0xB8` and `0xB8` are confirmed).
9. **`Freeze`/`Hook`/`Unhook` engine details** — `HwBpExceptions.c` (859 b) is the exception handler; I read its interface but not its full logic, so exactly which registers are manipulated and how the AMSI/ETW return value is faked is only known at the design level.
10. **`ObjectApi.c` (25,085 b) not read.** It implements direct object-manager calls; the full set of objects it can open/duplicate/query is unmapped.
11. **Webhook payload format** — `webhook_example.yaotl` (914 b) exists and `pkg/webhook/` is present, but the emitted JSON schema was not extracted.
12. **yaotl (HCL2) parser is vendored, not Havoc-authored.** ~200 KB of `pkg/profile/yaotl/` is an HCL2 implementation derived from an OpenTofu/Terraform ancestor. Any parser-level behaviour (dynamic blocks, expression evaluation, `dynblock`) is inherited code, not a Havoc design choice — worth noting so it is not over-reported as Havoc-specific.
13. **No compiled teamserver binary was available in the corpus**, so the Go-side findings are `[source]`-only. The prebuilt shellcode `.bin` files in `payloads/Shellcode/Bin/` and any toolchain binaries in `data/` are the only non-source artifacts, and neither was disassembled.
14. **`payloads/Demon/scripts/` contents not enumerated** — the build/obfuscation pipeline scripts that convert the DLL to shellcode are unread.

---

## CORRECTION NOTICE (appended after the DEEP pass)

The DEEP lane (`D5_havoc_code.md`, 243,155 B, §1–§14) reversed the Demon agent at function level and
**disproved several claims in this report** in addition to producing its own findings. Two of the
disproofs below were independently re-verified by the Lead directly against raw source before being
recorded. The original text is left in place above so the error is auditable.

### C-1. The "AgentID decrypt-verification sentinel" does NOT exist (§2.2, lines 105 / 129 / 384)

This report described the 32-byte header as:

```
[ Agent ID     ] 4 bytes   <- decrypt-verification sentinel
```

and at `:129` said *"the Go side reads the first 4 decrypted bytes and compares to the header
AgentID"*, and at `:384` built an argument on it: *"the post-decrypt AgentID sentinel check (which
requires the key, so it does verify key possession)."*

**All of that is wrong.** There is no post-decrypt sentinel check. The relevant code is:

```c
UINT32 Padding = 0;
...
Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );
...
if ( Package->CommandID == DEMON_INITIALIZE ) {
    Padding += 32 + 16;
}
...
AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
```
`payloads/Demon/src/core/Package.c:236`, `:250`, `:253-254`, `:258`

The `DEMON_INITIALIZE` case adds **`32 + 16` = 48 bytes of padding precisely so the AES key (32) and
IV (16) are NOT encrypted** — they must be transmitted in the clear for the handshake to bootstrap.
For **every other command**, padding stays at the base header size and the whole payload is
encrypted.

**Consequence, and it is worse than the claim it replaces:** registration is the one message that
carries the session key in plaintext, which is inherent to any bootstrap. But this report's claim
that the design includes a key-possession check is unfounded, and the sentence at `:384` that builds
on it must be struck.

### C-2. The SSN mechanism is dynamic at runtime, not a Tartarus/FreshyCalls table

This report framed the syscall layer as **Tartarus** (or "FreshyCalls") — i.e. a **static
syscall-number table** resolved at build time.

**Wrong.** `Syscalls.c` implements **runtime extraction** of the SSN from the native function's own
prologue, with a fallback for hooked functions:

```c
 * extract syscall service number (SSN) and or
 * @param Function       Native function address to extract Ssn/SysAddr from
 * @param ResolveHooked  if the function should call FindSsnOfHookedSyscall upon failure
```
`payloads/Demon/src/core/Syscalls.c:82-86`

The `ResolveHooked` parameter and its `FindSsnOfHookedSyscall` fallback are the **Halo's Gate**
technique, and the primary extraction is **Hell's Gate** (both are confirmed present). There is **no
hardcoded SSN table anywhere.** The report's naming was wrong in a way that matters: a static table
is trivially signatured by table contents, whereas dynamic extraction is not.

Confirmed present, `payloads/Demon/src/core/Syscalls.c:8` (`Initialize syscall addr + ssn`), `:43`
(`/* Resolve Ssn */`), `:93-98` (`OUT PWORD Ssn`), `:108-110`.

### C-3. The AMSI/ETW situation is much worse than "two modes"

This report (§5.2, `:548-569`) presented `AMSIETW_PATCH_NONE/HWBP/MEMORY` (`Defines.h:39-41`) as two
working modes. The DEEP pass found:

- **`AMSIETW_PATCH_MEMORY` is unimplemented** — it is a `/* todo: */` stub at
  `payloads/Demon/src/core/Dotnet.c:131`.
- **`AMSIETW_PATCH_HWBP` is wrapped in `#if _WIN64`** — so it does not exist on a 32-bit agent.

**Therefore neither AMSI bypass works on a 32-bit build**, and one of the two does not work at all.
The "two modes" framing overstated the capability.

### C-4. APC injection does not exist despite being selectable

- `INJECTION_TECHNIQUE_APC` — empty TODO
- `THREAD_METHOD_NTQUEUEAPCTHREAD` — empty TODO

Both are selectable enum values with no implementation. `INJECTION_TECHNIQUE_DEFAULT = SYSCALL`
(`Demon.c:787`) while `Inject.c` hardcodes `DX_MEM_DEFAULT` / `DX_MEM_SYSCALL` — the default in the
enum and the default actually used disagree.

### C-5. x86 stack spoofing is a no-op

This report credited stack spoofing as a capability. `payloads/Demon/src/asm/Spoof.x86.asm` is
**80 bytes** and is a **bare `ret`** — it does nothing. `Spoof.x64.asm` (450 B) is real. So stack
spoofing is **x64-only and non-functional on x86**, mirroring the AMSI pattern.

### C-6. The file counts in the original brief were inflated ~10×

For the record, the measured counts are **38 `.c`, 54 `.h`, 4 `.asm`, 2 `.s`, 3 `.cpp`** (Demon
side), plus **202 `.go`, 51 `.hcl`, 40 `.ui`, 28 `.hpp`** (teamserver/client). The brief this report
was written from stated 420 / 481 / 408 / 190 / 191 / 44 — approximately **10× too high.**

### C-7. Related: injection code is in `src/inject/`, not `src/core/`

The brief located injection logic in `src/core/`. It is actually in **`payloads/Demon/src/inject/`**
(`Inject.c`, `Syscalls.c`, `HwBpExceptions.c`, and the asm). Anyone navigating by the brief's map
will look in the wrong directory.

### C-8. `ObjectApi.c` was unread here and produced the report's most serious finding

Residual unknown #10 above says `ObjectApi.c` (25,085 b) was not read. The DEEP pass read it and
found **`BeaconDataExtract` (`ObjectApi.c:190`) contains the identical three lines as the
`Parser.c:127` wraparound bug** — `INT Length = 0;` with the same missing bounds check. Only the
signedness differs, which bounds the damage to an over-read rather than an attacker-chosen heap
allocation. **This is a codebase pattern, not a typo**, and it was invisible from this report's
coverage.

### C-9. What still stands

Unaffected and confirmed: the frame layout
`[SIZE 4][MagicValue 4 = 0xDEADBEEF][AgentID 4][CommandID 4][RequestID 4][DATA]` little-endian,
appearing on the wire as `EF BE DE AD` (`Defines.h:15`); AES-256-CTR with a **fixed session IV**
(a many-time pad); the task-stream header being **cleartext and unauthenticated**; the
`LsaConnectUntrusted` → `LsaLookupAuthenticationPackage` → `LsaCallAuthenticationPackage` chain that
reads the calling session's own TGT **with no elevation**; and residual-unknown #12, the ~200 KB of
vendored HCL2 (`pkg/profile/yaotl/`) being inherited rather than Havoc-authored.

**The DEEP pass also supplied the fixes for three of this report's open items:** #7 (CTR IV
lifecycle), #8 (`SSN_OFFSET_*` values), and #10 (`ObjectApi.c`) are all now closed in
`D5_havoc_code.md`.
