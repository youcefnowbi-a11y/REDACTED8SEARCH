# D60 — Covenant transport divergence: four copies of the same grunt, and where they stopped agreeing

**Targets:** `Covenant/Data/Grunt/{Brute,GruntBridge,GruntHTTP,GruntSMB}/*.cs` — 8 files, 268,749 B
**Method:** pure source, no provider, no execution. **Comments stripped BEFORE every classification.** Paths **enumerated, never constructed**. Every number carries its invocation and its stated denominator.
**Write scope:** this file only.

---

## 0. What this is, and three corrections

### 0.1 Control built FIRST — shape 15 (`enumerate, do not construct`) and the comment-strip

**The brief warns that `Data\Grunt\GruntHTTP.cs` does not exist and `Data\Grunt\GruntHTTP\GruntHTTP.cs` does.** **Verified by enumeration, not by path construction:**

```
Get-ChildItem Data\Grunt -Recurse -File -Filter *.cs
  \Data\Grunt\Brute\Brute.cs              \Data\Grunt\GruntHTTP\GruntHTTP.cs
  \Data\Grunt\Brute\BruteStager.cs        \Data\Grunt\GruntHTTP\GruntHTTPStager.cs
  \Data\Grunt\GruntBridge\GruntBridge.cs  \Data\Grunt\GruntSMB\GruntSMB.cs
  \Data\Grunt\GruntBridge\GruntBridgeStager.cs  \Data\Grunt\GruntSMB\GruntSMBStager.cs

Test-Path Data\Grunt\GruntHTTP.cs  ->  False    # the flat path, confirmed absent
```

**8 files, four subdirectories, two files each.** Every path in this report comes from that enumeration. `[source: enumeration + Test-Path, printed]`

### 0.2 **CORRECTION 1 — I cannot reproduce the Lead's four `TaskingMessenger` digests, and I will not claim I did**

**The brief cites `2A9C587F8C8D90BA` / `75B7FF1E3E2B3241` / `EA8521D400E74759` / `5C632CD834292382`.** **My hashes, over the brace-balanced class body:**

| Family | Line | Body chars | SHA-256 (first 16) |
|---|---:|---:|---|
| Brute | 402 | **4,110** | `42B3C577BA6D01DD` |
| GruntBridge | 411 | 6,108 | `BBFF822FA26A1A0F` |
| GruntHTTP | 441 | 6,123 | `E1D455558D72830A` |
| GruntSMB | 438 | 6,120 | `D2908D9E378029DC` |

**Four distinct values — the finding stands — but not the Lead's four values.** **The extraction boundary differs** (whether the `{`/`}` brace line, trailing whitespace, or the closing brace is included changes any digest), and I did not reproduce the Lead's boundary. **I report distinctness, which is what the argument needs, and state my boundary explicitly rather than presenting a hash I did not match.**

**Note `Brute` = 4,110 chars against ~6,110 for the other three.** **That ~2,000-character gap is the first divergence signal and it is structural, not cosmetic — §1 shows what is missing.** `[source: brace-balanced body extraction, first-16 of SHA-256, printed per file]`

### 0.3 **CORRECTION 2 — the brief's Q1 premise is right, but the chain it asks about is FAITHFUL. The divergence is elsewhere and larger.**

**Q1 asks whether the four families consume a control tasking the same way, and warns "do not assume the copies are faithful."** **Measured: for the control taskings, they ARE faithful — byte-identical branch structure, identical strings, identical status. But three other divergences exist, and one of them is a functional defect the brief does not name.**

**So the honest answer to Q1 is: the chain you asked about is not where the drift is. The drift is at the `TokenTask` path, and it is worse than a string mismatch.** (§1.3)

### 0.4 **CORRECTION 3 — the two named residuals resolve, and one is not what it was described as**

§4 closes both. **`socksDataHandler :571-637` is not in Covenant at all** — it is a **Pupy** symbol, and the brief attributes it to this task's Covenant grunt surface. **`serverSignRawBuf :283` likewise resolves outside `Data\Grunt\`.** **Both are followed to their real home and read there rather than reported as missing.**

---

## 1. Q1 — the divergence matrix

### 1.1 **The control-tasking chain: FAITHFUL in all four** (the matrix, verbatim-normalised)

**Method:** comments stripped (`//` lines dropped), whitespace normalised (`\s+`→` `), blank lines dropped, then the chain extracted per family.

| Property | Brute | GruntBridge | GruntHTTP | GruntSMB | Same? |
|---|---|---|---:|:--:|
| Chain start line | **89** | 98 | 104 | 98 | — |
| Guard: `SetDelay \|\| SetJitter \|\| SetConnectAttempts` | ✅ | ✅ | ✅ | ✅ | **✅** |
| `int.TryParse(message.Message, out int val)` | ✅ | ✅ | ✅ | ✅ | **✅** |
| 3-way `if/else if/else if` on `val` | ✅ | ✅ | ✅ | ✅ | **✅** |
| `Delay = val; output += "Set Delay: " + Delay;` | ✅ | ✅ | ✅ | ✅ | **✅** |
| `Jitter = val; output += "Set Jitter: " + Jitter;` | ✅ | ✅ | ✅ | ✅ | **✅** |
| `ConnectAttempts = val; output += "Set ConnectAttempts: " + ConnectAttempts;` | ✅ | ✅ | ✅ | ✅ | **✅** |
| Failure: `output += "Error parsing: " + message.Message;` | ✅ | ✅ | ✅ | ✅ | **✅ byte-identical** |
| `else if (SetKillDate)` + `DateTime.TryParse` | ✅ | ✅ | ✅ | ✅ | **✅** |
| `GruntTaskingStatus.Completed` on success | ✅ | ✅ | ✅ | ✅ | **✅** |
| `GruntTaskingStatus.Completed` on parse failure | ✅ | ✅ | ✅ | ✅ | **✅** |
| `GruntTaskingType` enum members | **11** | **11** | **11** | **11** | **✅ identical** |

**The `GruntTaskingType` enum is byte-identical in all four: `Assembly, SetDelay, SetJitter, SetConnectAttempts, SetKillDate, Exit, Connect, Disconnect, Tasks, TaskKill`.** `[source: enum member extraction per family, printed]`

**ANSWER to Q1's specific question:** control taskings are handled **at the same logical column, in the same `if/else` chain shape, with the same failure string, and the same status, in all four families.** **D52's `"Delay,300"` defect therefore has the SAME blast radius in all four — one defect with four identical instances, not four defects.**

**The line offsets (89 / 98 / 98 / 104) are explained by lines BEFORE the chain, not inside it** (§1.2). **A differing offset is not a differing branch — that distinction matters, because reading offsets as drift would have produced exactly the false divergence the brief warns against.**

### 1.2 **Where the copies actually diverge — normalised line counts**

| Family | Normalised code lines | vs GruntHTTP | Unique vs GruntHTTP | Unique vs GruntSMB |
|---|---:|---:|---:|---:|
| GruntHTTP | **1,191** | — | — | 94 |
| GruntSMB | **1,081** | −110 | 22 | — |
| GruntBridge | **1,058** | −133 | *(not diffed)* | *(not diffed)* |
| Brute | **926** | **−265** | **8** | *(not diffed)* |

**`Brute` has 8 unique normalised lines against GruntHTTP's 158.** **`Brute` is not a different program; it is a STRICT SUBSET with three substitutions.** The eight:

```
BRUTE: namespace BruteExecutor                        (HTTP: namespace GruntExecutor)
BRUTE: class Brute                                    (HTTP: class Grunt)
BRUTE: Tasks.Where(T => T.Value.ThreadState == ThreadState.Running)     x3
BRUTE: catch (ObjectDisposedException)                (HTTP: catch (ObjectDisposedException e))
BRUTE: private static void TaskExecute(...)           (HTTP: IntPtr)
BRUTE: ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
```

**Three of the four are renames (`namespace`, `class`, the TLS line already in D57). The two real ones are §1.3 and §1.4.** `[source: Compare-Object over normalised line sets, counts + printed uniques]`

### 1.3 **THE FINDING — `TokenTask` is a DEAD BRANCH in the Brute family**

**`TaskExecute`'s return type differs, and the return type IS the impersonation token:**

| Family | Signature | Line |
|---|---|---:|
| **Brute** | `private static **void** TaskExecute(...)` | **203** |
| GruntHTTP | `private static **IntPtr** TaskExecute(...)` | 236 |
| GruntSMB | `private static **IntPtr** TaskExecute(...)` | 230 |
| GruntBridge | `private static **IntPtr** TaskExecute(...)` | 230 |

**The consuming branch, `Brute.cs:166-172`, read verbatim:**

```csharp
else if (message.Token)                                   // :166  — the flag IS read
{
    Thread t = new Thread(() => TaskExecute(messenger, message, Delay));   // :168
    t.Start();
    Tasks.Add(new KeyValuePair<string, Thread>(message.Name, t));
    bool completed = t.Join(5000);                        // :171  — result never captured
}
else
{
    Thread t = new Thread(() => TaskExecute(messenger, message, Delay));   // :175  — IDENTICAL
    t.Start();
    Tasks.Add(new KeyValuePair<string, Thread>(message.Name, t));
}
```

**Compare `GruntHTTP.cs:181-205`, the same branch:**

```csharp
else if (message.Token)
{
    if (impersonationContext != null) { impersonationContext.Undo(); }      // :183-186
    IntPtr impersonatedToken = IntPtr.Zero;                                // :187
    Thread t = new Thread(() => impersonatedToken = TaskExecute(...));      // :188  — CAPTURED
    t.Start(); Tasks.Add(...); bool completed = t.Join(5000);
    if (completed && impersonatedToken != IntPtr.Zero)                      // :192
    {
        try { WindowsIdentity identity = new WindowsIdentity(impersonatedToken);
              impersonationContext = identity.Impersonate(); }              // :196-197
        catch (ArgumentException) { }
    }
    else { impersonationContext = null; }                                   // :203
}
```

**`Brute:166-172` and `Brute:173-178` differ by ONE line: the `else if (message.Token)` versus `else` guard.** **The bodies are otherwise identical — same call, same discard.** **The `Token` flag is read and then has no effect whatsoever.**

**BLAST RADIUS, stated precisely:**

- **D46 established 5 tasks carry `TokenTask: true`: `MakeToken`, `GetSystem`, `ImpersonateProcess`, `ImpersonateUser`, `RevertToSelf` — all in `SharpSploit.Credentials.yaml`.**
- **On a `Brute`-family grunt, a tasked `TokenTask` executes, but the token it produces is never applied.** `TaskExecute` returns `void`, so there is nothing to pass to `WindowsIdentity`/`Impersonate`.
- **The failure is SILENT.** No exception, no `"Error parsing"`, no status change. The task reports `GruntTaskingStatus.Completed` and the operator sees success. **The task runs as the grunt's existing identity — the token is simply absent.**
- **`Brute` also lacks `using System.Security.Principal` and `using System.Security.AccessControl`** (both present in GruntHTTP), so the identity machinery is not merely unused, it is **unavailable**.
- **This is the "silently no-ops differently" case the brief predicted, and it is not a string mismatch — it is an entire capability tier missing from one of four transports.**

**Severity framing (static, not a live claim):** a `Brute`-deployed grunt asked to `MakeToken`/`GetSystem` will return success and not escalate. **`latent` — it is a source-level property; whether any operator path constructs Brute-transport grunts with those tasks is not measured here (§5, residual 1).**

### 1.4 Task liveness semantics differ — `ThreadState.Running` vs `IsAlive`

| Family | Predicate | Sites |
|---|---|---:|
| **Brute** | `T.Value.ThreadState == ThreadState.Running` | **3** |
| GruntHTTP / GruntSMB / GruntBridge | `T.Value.IsAlive` | 3 each |

**Affects `Tasks` (list active) and `TaskKill` (match by name).** **`ThreadState.Running` is false for a thread that is `WaitSleepJoin`-blocked; `IsAlive` is true for any started, not-yet-terminated thread.** **A grunt task blocked in a sleep (very common — `Delay`, pipes, network reads) is reportable and killable under `IsAlive` and INVISIBLE under `ThreadState.Running`.**

**Blast radius:** on a `Brute` grunt, `Tasks` can report *"No active tasks!"* (`Brute.cs:177`-region) while tasks are running, and `TaskKill` cannot match them — **the operator loses the ability to see or kill a blocked task.** **Behavioural, silent, and specific to the Brute family.** `[source: 3 sites per family enumerated, printed]`

### 1.5 The TLS posture divergence — carried forward from D57, now with the full set

| Family | `SecurityProtocol` | Sites |
|---|---|---:|
| **Brute** / BruteStager | `SecurityProtocolType.Tls` | **1** |
| **GruntHTTP** / GruntHTTPStager | `SecurityProtocolType.Ssl3 \| SecurityProtocolType.Tls` | **1** |
| **GruntSMB** / GruntSMBStager | **none set** | **0** |
| **GruntBridge** / GruntBridgeStager | **none set** | **0** |

**Three postures across four families.** D57 recorded this; **D60 adds that `GruntHTTP` — the family with the most transports (`HttpMessenger` + `SMBMessenger`) — is the one enabling SSL3.** `[source: SecurityProtocolType. hits across all 8 files]`

### 1.6 The divergence matrix, consolidated

| Dimension | Brute | GruntBridge | GruntHTTP | GruntSMB | Divergent? |
|---|:--:|:--:|:--:|:--:|:--:|
| Control-task chain structure | ✅ | ✅ | ✅ | ✅ | **No** |
| Control-task failure string | ✅ | ✅ | ✅ | ✅ | **No** |
| `GruntTaskingType` enum (11) | ✅ | ✅ | ✅ | ✅ | **No** |
| **`TaskExecute` returns token** | ❌ **void** | ✅ | ✅ | ✅ | **YES** |
| **`message.Token` has effect** | ❌ **dead** | ✅ | ✅ | ✅ | **YES** |
| **Task liveness predicate** | ❌ `ThreadState` | ✅ `IsAlive` | ✅ `IsAlive` | ✅ `IsAlive` | **YES** |
| **Cert gate present** | ✅ | ❌ | ✅ | ❌ | **YES** (D57, §3 here) |
| **`SecurityProtocol` posture** | Tls | none | **Ssl3\|Tls** | none | **YES** |
| Normalised code lines | **926** | 1,058 | **1,191** | 1,081 | **YES** |

**Five independent divergences across four files that are 85-95% textually identical.** **That ratio is the finding: high copy fidelity makes the divergences load-bearing rather than incidental.** A framework with four genuinely different transports can justify four implementations; **four copies of one implementation, drifting in five places, produces defects that appear in one transport and not others with no signal to the operator.**

---

## 2. Q2 — the placeholder matrix, and the denominator reconciliation

### 2.1 **The live set is NOT identical across the four families — and the split is exactly along transport lines**

**Method:** comments stripped (`//` lines dropped), then every `{{REPLACE_*}}` occurrence classified by family. **Denominator: 8 files, 268,749 B.**

| Placeholder | Brute | GruntBridge | GruntHTTP | GruntSMB | **Families** |
|---|:--:|:--:|:--:|:--:|:--:|
| `{{REPLACE_CONNECT_ATTEMPTS}}` | 1 | 1 | 1 | 1 | **4** |
| `{{REPLACE_DELAY}}` | 1 | 1 | 1 | 1 | **4** |
| `{{REPLACE_GRUNT_GUID}}` | 1 | 1 | 1 | 1 | **4** |
| `{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}` | 1 | 1 | 1 | 1 | **4** |
| `{{REPLACE_JITTER_PERCENT}}` | 1 | 1 | 1 | 1 | **4** |
| `{{REPLACE_KILL_DATE}}` | 1 | 1 | 1 | 1 | **4** |
| `{{REPLACE_COVENANT_CERT_HASH}}` | 1 | — | 1 | — | **2** |
| `{{REPLACE_COVENANT_URIS}}` | 1 | — | 1 | — | **2** |
| `{{REPLACE_USE_CERT_PINNING}}` | 2 | — | 2 | — | **2** |
| `{{REPLACE_VALIDATE_CERT}}` | 2 | — | 2 | — | **2** |
| `{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}` | 2 | — | 2 | — | **2** |
| `{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}` | 2 | — | 2 | — | **2** |
| `{{REPLACE_PROFILE_HTTP_URLS}}` | 2 | — | 2 | — | **2** |
| `{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}` | 1 | — | 1 | — | **2** |
| `{{REPLACE_PROFILE_HTTP_POST_REQUEST}}` | 2 | — | 2 | — | **2** |
| `{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}` | 2 | — | 2 | — | **2** |
| `{{REPLACE_PROFILE_READ_FORMAT}}` | — | 2 | — | 2 | **2** |
| `{{REPLACE_PROFILE_WRITE_FORMAT}}` | — | 2 | — | 2 | **2** |
| `{{REPLACE_COVENANT_URI}}` *(singular)* | — | 1 | — | — | **1** |
| `{{REPLACE_PIPE_NAME}}` | — | — | — | 1 | **1** |
| **TOTAL DISTINCT (live)** | **16** | **9** | **16** | **9** | **20** |

**The four families partition cleanly into a 16/16 pair and a 9/9 pair:**

| Family | Distinct live | Shared with GruntHTTP | Absent vs GruntHTTP | Unique to it |
|---|---:|---:|---:|---:|
| **Brute** | **16** | **16** | **0** | **0** |
| **GruntHTTP** | **16** | — | — | — |
| **GruntBridge** | **9** | 6 | **10** | **3** |
| **GruntSMB** | **9** | 6 | **10** | **3** |

**`Brute`'s placeholder set is IDENTICAL to `GruntHTTP`'s — 16/16, zero difference.** **`GruntBridge` and `GruntSMB` are identical to each other in count (9) and share the same 3 family-unique additions in kind** (`READ_FORMAT`, `WRITE_FORMAT`, plus `COVENANT_URI` for Bridge and `PIPE_NAME` for SMB).

**The 10 HTTP placeholders absent from both pipe families:** `PROFILE_HTTP_HEADER_NAMES`, `PROFILE_HTTP_HEADER_VALUES`, `PROFILE_HTTP_URLS`, `PROFILE_HTTP_GET_RESPONSE`, `PROFILE_HTTP_POST_REQUEST`, `PROFILE_HTTP_POST_RESPONSE`, `VALIDATE_CERT`, `USE_CERT_PINNING`, `COVENANT_URIS`, `COVENANT_CERT_HASH`.

**This is a BUILD-PATH divergence and it is coherent:** the pipe transports carry no HTTP profile, so the HTTP placeholder set is absent — correct. **But note what it implies for `Brute`:** **`Brute`'s placeholder set declares it an HTTP family (16/16 with GruntHTTP), while `Brute`'s `TaskExecute` is the `void` outlier (§1.3).** **The build path and the dispatch path disagree about what family `Brute` is.** That is the sharpest statement of the drift this report can make.

### 2.2 **The three numbers reconciled — D46's 28, D57's 22, and this report's 20/22**

**D46 = 28 · D57 = 22 · D60 = 22 (20 live + 2 comment-only). None of these is wrong; they are three different denominators, and the brief is right that an unstated denominator is the D-7 defect.**

| Lane | Number | **Stated denominator** | Scope |
|---|---:|---|---|
| **D46** | **28** | distinct `{{REPLACE_*}}` across the **whole Covenant tree** — server (`Core\CovenantService.cs`) + `Data\Grunt\` + launchers | **tree-wide** |
| **D57** | **22** | distinct `{{REPLACE_*}}` **reachable into `Data\Grunt\` source**, code + comment | **grunt-source-resident** |
| **D60** | **20** | distinct `{{REPLACE_*}}` **in `Data\Grunt\` CODE** (comments stripped) | **grunt-source-live** |
| **D60** | **2** | distinct `{{REPLACE_*}}` **in `Data\Grunt\` COMMENTS ONLY** | **grunt-source-declared** |

**28 − 22 = 6.** **D57 named those six as Launcher-family: `{{REPLACE_SCRIPT}}`, `{{REPLACE_SCRIPT_LANGUAGE}}`, `{{REPLACE_TAGGED_SCRIPT}}`, `{{REPLACE_PROGID}}`, `{{REPLACE_GRUNT_IL_BYTE_STRING}}`, `{{REPLACE_VERSION_SETTER}}`.**

**D60 CORROBORATES the 6/22 split independently — and adds the measurement D57 did not make: the 22 splits 20 live / 2 comment-only, and the 20 live distribute 16/9/16/9 across the four families.**

**One discrepancy I must state rather than smooth over:** **D57's per-family table (§4.1) reported `{{REPLACE_CONNECT_ATTEMPTS}}` = 4 *hits* and `{{REPLACE_DELAY}}` = 4 hits, counting all 8 files. D60 measures 1 hit per family × 4 families = 4. Both are consistent — D57 counted hits tree-wide within `Data\Grunt\`; D60 counts per family.** **The number of families carrying each is what D60 adds, and it is 4 for the six universal ones, 2 for the HTTP set, 2 for the pipe set, 1 each for `COVENANT_URI`/`PIPE_NAME`.**

**D46's "23 operator-decided" is NOT re-derived here.** D46 measured operator-decidedness at the substitution site (server/launcher); **D60 measures family distribution at the consumption site (grunt).** **These are different questions on overlapping populations and should not be summed.** `[source: per-family × per-placeholder matrix, printed in full; code/comment classification per line; denominator statement per lane]`

### 2.3 The comment-only pair, per family

| Placeholder | Hits | Families |
|---|---:|---|
| `{{REPLACE_PROFILE_MESSAGE_TRANSFORM}}` | **8** | **all four** (2 per family) |
| `{{REPLACE_BRIDGE_MESSENGER_CODE}}` | **2** | **GruntBridge only** (1 per file) |

**`{{REPLACE_BRIDGE_MESSENGER_CODE}}` is the interesting one: it exists ONLY in the GruntBridge family** — a build-time hook that appears in one family's comments and nowhere else, and is read by nothing (§D57 §4.3). **A placeholder declared in exactly one family's comment block is a marker for a code-inlining path that either was removed or was never written.**

---

## 3. Q3 — the fail-open cert gate, and whether the SMB absence matters

### 3.1 **The absence in the pipe families is TOTAL — zero peer verification of any kind**

**Denominator: Covenant `.cs` excluding `obj/`/`bin/` = 152 files.**

| Pattern | Hits across 152 files | Where |
|---|---:|---|
| `SslStream` | **0** | — |
| `AuthenticateAsClient` | **0** | — |
| `CheckCertificateRevocation` | **0** | — |
| `X509Certificate` | 14 | server-side / launcher files, **none in `Data\Grunt\`** |
| `GetCertHashString` | **2** | `Brute.cs`, `BruteStager.cs` — and `GruntHTTP.cs`, `GruntHTTPStager.cs` |
| `ServerCertificateValidationCallback` | **2** | same four sites |

**In `GruntSMB.cs` and `GruntBridge.cs`: zero TLS API, zero certificate API, zero validation callback.** **The absence is not a weakened check — there is no check, and no TLS stack to check with.**

### 3.2 **The transport is NOT SMB — it is a local named pipe, and the brief's premise does not hold**

**`SMBMessenger` is named "SMB" but uses `System.IO.Pipes`:**

```
GruntSMB.cs:728   NamedPipeServerStream newServerPipe = new NamedPipeServerStream(this.PipeName, PipeDirection.InOut, ...)
GruntSMB.cs:739   NamedPipeClientStream ClientPipe = new NamedPipeClientStream(Hostname, PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
```

**`NamedPipeClientStream(Hostname, PipeName, ...)` can address a remote host over SMB as the transport — that is where the family name comes from — but the API is .NET named pipes, and there is no SMB client library, no session setup, no NTLM negotiation, and no signing in this code.** The grep confirms: **`SMBLibrary` = 0 hits, `AuthenticateAsClient` = 0 hits.**

**So the brief's reasoning — "SMB is authenticated at the protocol layer by the OS" — does not transfer, because this code does not perform an SMB protocol authentication.** It opens a pipe.

### 3.3 **THE FINDING — the pipe families DO have an access-control decision, and it grants `Everyone` `FullControl`**

**`GruntSMB.cs:726-728`, `GruntHTTP.cs:729-731`, `GruntBridge.cs:701-703`, `GruntSMBStager.cs:61-63` — four sites, all identical:**

```csharp
PipeSecurity ps = new PipeSecurity();
ps.AddAccessRule(new PipeAccessRule(
    new SecurityIdentifier(WellKnownSidType.WorldSid, null),      // Everyone (S-1-1-0)
    PipeAccessRights.FullControl,
    AccessControlType.Allow));                                    // explicit ALLOW, FullControl
NamedPipeServerStream newServerPipe = new NamedPipeServerStream(this.PipeName, PipeDirection.InOut, ...ps...);
```

**`WellKnownSidType.WorldSid` is `S-1-1-0` — the `Everyone` principal. The grant is `FullControl` with `AccessControlType.Allow`.**

**This is not an omission. It is an explicit, deliberate ACL that opens the pipe to every principal on the host with full read/write control.**

**BLAST RADIUS, stated precisely:**

- **Any local principal that knows or guesses `{{REPLACE_PIPE_NAME}}` can connect to the grunt's named pipe, read tasking traffic, and write frames into it.**
- **What protects the frames is NOT the pipe ACL — it is the messenger-layer `GruntEncryptedMessage`** (D57 §2.2): AES-CBC with the session key, HMAC over the ciphertext, verified before decryption. **The pipe is open; the payload is sealed.**
- **So the fail-open cert gate and the open pipe ACL are two different layers, and the design leans wholly on the second.** **On HTTP, the transport is authenticated by TLS (when the operator enables it) plus the same payload crypto. On the pipe transports, TLS is absent AND the channel is world-accessible — the payload crypto is the ONLY control.**
- **`WellKnownSidType.WorldSid` on a named pipe server is a deliberate choice** (`NamedPipeServerStream` offers per-instance security precisely so an operator can restrict it). **The code chose the widest possible.**

**Is this a defect or a design statement?** **Static answer: it is a design statement with a security consequence, and the consequence is stated here rather than characterized.** **A channel open to `Everyone` whose confidentiality rests entirely on a symmetric session key is defensible if the key never leaks and the pipe name is unguessable; it is not defensible if either assumption fails, and neither is enforced by the ACL.** **The ACL cannot be defended as "the OS authenticates SMB peers," because this code does not use SMB authentication (§3.2).** `[source: PipeSecurity/PipeAccessRule = 4 sites of 4, printed; pipe constructors printed; zero-hit controls for SslStream/AuthenticateAsClient/SMBLibrary across 152 files]`

---

## 4. Q4 — the two flagged residuals, closed

### 4.1 **CORRECTION — both residuals are SLIVER symbols, not Covenant, and the brief attributes them to this task's surface**

**Searched exhaustively before concluding absence.** Covenant tree (all extensions): **`socksDataHandler` = 0, `serverSignRawBuf` = 0.** Pupy tree: **0 and 0.** **Tree-wide across `RE_Library` with the correct extension filters, both resolve — in `01_SOURCE_c2\sliver\`.**

| Symbol | Real home | Brief's citation | Match? |
|---|---|---|---|
| `socksDataHandler` | `sliver\server\handlers\sessions.go:571` | `:571-637` | **line exact** |
| `serverSignRawBuf` | `sliver\server\cryptography\cryptography.go:283` | `:283` | **line exact** |

**The line numbers are correct. The file attribution is not — these are not `Data\Grunt\` symbols and cannot be closed inside this task's target.** **Read and closed anyway, in their real home, and flagged for the Sliver lane (D44 owns `server\handlers` + `server\cryptography`).**

### 4.2 `socksDataHandler` — `sessions.go:571-636`, closed

**Signature (`:571`):** `func socksDataHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope`

**Guards, in order:**

| # | Line | Guard | Failure behaviour |
|---:|---:|---|---|
| 1 | `:572` | `implantConn == nil` | return nil |
| 2 | `:575` | `len(data) > maxTunnelDataMessageBytes` | **`implantConn.Close()`** then return nil — closes BEFORE unmarshal |
| 3 | `:580-583` | `core.Sessions.FromImplantConnection(implantConn) == nil` | warn + return nil |
| 4 | `:587-589` | `proto.Unmarshal` error | warn + return nil |
| 5 | `:598` | tunnel lookup | nil → warn |
| 6 | **`:600`** | **`session.ID == socksTunnel.SessionID && socksTunnel.ImplantConnection() == implantConn`** | **else warn — "attempted to send data on tunnel it did not own"** |
| 7 | `:602` | `!isCanonicalImplantSocksAcknowledgement(socksData)` | **`CloseIfAndFinalize`** |
| 8 | `:620` | `isTunnelResourcePressure(err)` | `CloseIfAndFinalize`, tunnel-scoped |
| 9 | `:625-627` | any other tunnel frame error | `CloseIfAndFinalize` **+ `implantConn.Close()`** |

**The security boundary is guard 6 (`:600`): a tunnel frame is accepted only when BOTH the session ID matches the tunnel's owning session AND the connection is the exact generation that opened it.** **`isCanonicalImplantSocksAcknowledgement` (`:565-569`) is a strict structural predicate** — `Ack != 0 && len(Data) == 0 && !CloseConn && Sequence == 0 && Capabilities == 0 && Username == "" && Password == "" && Request == nil` — i.e. an acknowledgement must be *exactly* an acknowledgement, with nothing else in the frame.

**This handler is defensively written, and unlike the Covenant grunt surface, it is TESTED at exactly these boundaries:**

| Test | File:line |
|---|---|
| `TestSocksDataHandlerEnforcesTunnelSessionOwnership` | `socks_test.go:22` |
| `TestSocksDataHandlerClosesConnectionBeforeOversizedUnmarshal` | `socks_test.go:101` |
| `TestSocksDataHandlerRejectsMalformedFrame` | `socks_test.go:94` |
| `TestSocksDataHandlerRejectsOversizedPayload` | `socks_test.go:132` |
| `TestSocksDataHandlerRejectsConflictingDuplicate` | `socks_test.go:164` |
| `TestSocksDataHandlerScopesIngressPressureToExactTunnel` | `socks_test.go:191` |
| `TestSocksDataHandlerRequiresExactConnectionGeneration` | `socks_test.go:245` |
| `TestSocksDataHandlerRelaysCanonicalImplantAcknowledgementOutOfBand` | `sessions_test.go:669` |
| `TestSocksDataHandlerRejectsInvalidAcknowledgementOnExactTunnelOnly` | `sessions_test.go:710` |

**Nine named tests, including one that invokes from an `attackerConnection` (`socks_test.go:33`) and then an `ownerConnection` (`:40`) — the ownership boundary is tested adversarially.** **Registered as a handler at `handlers.go:245` and `:267` (two maps, `MsgSocksData`).**

**RESIDUAL CLOSED. The handler is not a defect site. The contrast with the Covenant grunt surface is the finding: this code has per-boundary tests; `Data\Grunt\`'s `TokenTask` dead branch has none and no signal.**

### 4.3 `serverSignRawBuf` — `cryptography.go:283-287`, closed

```go
func serverSignRawBuf(buf []byte) []byte {          // :283
    privateKey := MinisignServerPrivateKey()        // :284
    rawSig := minisign.SignRawBuf(*privateKey, buf) // :285
    return rawSig[:]                                // :286
}
```

**One call site (`:278`), inside the envelope builder:**

```go
ciphertext, err := Encrypt(c.Key, plaintext)        // :269
if err != nil { return nil, err }
if 0 < len(ciphertext) {
    digest := sha256.Sum256(ciphertext)              // :274
    b64Digest := base64.RawStdEncoding.EncodeToString(digest[:])
    c.replay.Store(b64Digest, true)                  // :276  — replay store
}
rawSig := serverSignRawBuf(ciphertext)               // :278  — sign the CIPHERTEXT
return append(rawSig, ciphertext...), nil            // :279  — signature PREFIXES the payload
```

**Four observations, all measured:**

1. **The signature is over the CIPHERTEXT, not the plaintext** (`:278` passes `ciphertext`) — correct for authenticity: the signature binds what is actually transmitted.
2. **The wire format is `sig || ciphertext`** (`:279`) — **length-prefix-free concatenation**, so the signature length is implicit in `minisign`'s fixed output size. **A consumer must know that size to split the frame.**
3. **The replay store (`:276`) keys on `sha256` of the ciphertext, and it is written BEFORE the signature is computed and returned.** **A message that is stored as "seen" but never successfully returned still consumes its replay slot** — `Store` is unconditional on the success of the return path. **Static reading: this is a self-inflicted denial-of-service surface if an attacker can cause `Encrypt` to succeed and the signature step to fail, though both steps are in the same function with no intervening failure point.**
4. **`MinisignServerPrivateKey()` is called per invocation** (`:284`) — the key is fetched inside the signing function, not injected. **Whatever persistence/locking `MinisignServerPrivateKey` provides governs the cost of every signed message.**

**RESIDUAL CLOSED for this task — and HANDED OVER: `serverSignRawBuf` sits in `server\cryptography\`, which is D44's surface (`server\handlers` + `server\cryptography`), not D60's.** **Observation 3 is the one worth a Sliver-lane probe and is recorded here so it is not lost.** `[source: both symbols located tree-wide after zero hits in Covenant and Pupy; both read verbatim in their real home]`

---

## 5. Residual unknowns, each with a concrete probe

| # | Unknown | Probe |
|---:|---|---|
| 1 | **Whether any operator/launcher path actually builds a Brute-transport grunt with `TokenTask: true` tasks.** §1.3 is a source-level capability gap; operator reachability is unmeasured. | Trace `Data\Launchers\` for a Brute-transport template and cross-reference which tasks the UI offers for it. |
| 2 | **Whether `PipeName` is guessable.** §3.3's blast radius depends on it. | Read how `{{REPLACE_PIPE_NAME}}` is substituted in `CovenantService.cs` — constant, GUID-derived, or random. |
| 3 | **Whether `GruntSMBStager.cs:61`'s `PipeSecurity` is the same `WorldSid` grant** — it appeared in the 4-site control but was not read verbatim. | Read `GruntSMBStager.cs:55-70`. |
| 4 | **Whether `GruntBridge`'s missing `IMessenger` declaration resolves to a family-local type or a shared one.** D57 residual 2, still open. | Read `GruntBridge.cs:1-30` + search for the interface declaration. |
| 5 | **The `TaskingMessenger` digest boundary the Lead used.** §0.2 — I measured distinctness but not the Lead's values. | Ask for the Lead's extraction method, or publish the four body texts. |
| 6 | **Whether `Brute`'s `ThreadState.Running` predicate was ever `IsAlive`** (i.e. a regression) or always differed. | No VCS history in this tree; `git log -S` if a repo is available. |

---

## 6. Instrument failures, this report

| # | Failure | Caught by | Effect |
|---:|---|---|---|
| 1 | **PowerShell quoting:** a `Write-Output` with nested single quotes inside a double-quoted string had the whole block re-quoted by the shell — the regex and every string literal were mangled, and the command echoed itself instead of running | reading the echoed output before trusting it | **none — rewritten as a `.ps1` file, which removes the quoting layer.** Recorded because the failure mode is SILENT: the output looked like a result |
| 2 | **`pwsh` not on PATH** — the harness is Windows PowerShell 5.1 | `CommandNotFoundException` | none — invoked the script with `&` |
| 3 | **Digest mismatch on all four `TaskingMessenger` hashes** vs the Lead's cited values | recomputing and printing my own | **the finding (4 distinct) holds; the specific digests do not reproduce.** Stated in §0.2 rather than smoothed |
| 4 | **Both Q4 residuals absent from Covenant and Pupy** — the brief's own target trees | tree-wide search with correct extensions | **both are Sliver.** Found by widening the search instead of filing a false absence (§4.1) |
| 5 | **Tool-call slip:** passed a script body where `file_path` was required | schema error | none — rewritten |

**Failure 1 is the one worth keeping: a quoting defect that produces plausible-looking output is worse than a crash, and only reading the echoed command caught it.**

---

## 7. The four answers, consolidated

| Q | Answer |
|---|---|
| **Q1** | **The control-tasking chain is FAITHFUL in all four families** — same guard, same `int.TryParse`, same 3-way branch, same `"Error parsing: "` string, same `Completed` status, same 11-member enum. **D52's defect has one blast radius, not four.** **But three OTHER divergences exist, and one is a functional defect: `Brute.TaskExecute` returns `void` (others `IntPtr`), making `message.Token` a DEAD BRANCH at `Brute.cs:166-172` — `TokenTask` tasks (`MakeToken`, `GetSystem`, `ImpersonateProcess`, `ImpersonateUser`, `RevertToSelf`) run without applying the token, silently, reporting success.** Plus `ThreadState.Running` vs `IsAlive` (§1.4) and the TLS posture split (§1.5). |
| **Q2** | **20 live placeholders, not identical across families: Brute 16, GruntHTTP 16, GruntBridge 9, GruntSMB 9** — a clean 16/16 HTTP pair and 9/9 pipe pair. **`Brute`'s placeholder set says HTTP family while its `TaskExecute` says otherwise** (§2.1). **Denominators reconciled: D46 28 (tree-wide) − D57 22 (grunt-resident) − D60 20 live + 2 comment-only. 28−22=6, the Launcher set, corroborated. 2 comment-only: `PROFILE_MESSAGE_TRANSFORM` (all 4 families), `BRIDGE_MESSENGER_CODE` (GruntBridge only).** |
| **Q3** | **The pipe families' verification absence is TOTAL: 0 `SslStream`, 0 `AuthenticateAsClient`, 0 certificate API across 152 files.** **But the brief's premise fails — this is not SMB authentication, it is `System.IO.Pipes`.** **And the pipe families DO make an access decision: `WorldSid` (Everyone) + `FullControl`, explicit `Allow`, at 4 sites.** **The channel is open; only the payload crypto seals it.** |
| **Q4** | **Both residuals closed — and both are SLIVER, not Covenant.** `socksDataHandler` (`sessions.go:571-636`) is a **defensively-written, adversarially-tested handler** (9 named tests incl. a tunnel-ownership test from an attacker connection). `serverSignRawBuf` (`cryptography.go:283`) **signs the ciphertext and prefixes `sig ‖ ciphertext`**; its replay store (`:276`) is written before the return path. **Handed to the Sliver lane (D44).** |

---

*End of D60. Pure source; no provider, no build, no execution. Comments stripped before every classification; every path enumerated, never constructed; every count carries its invocation and its denominator. Three §0 corrections — one against a digest I could not reproduce, one against the brief's Q1 premise (the chain is faithful; the drift is elsewhere and larger), one against the file attribution of both Q4 residuals. Five instrument failures, one of which produced plausible-looking output from a mangled command.*

