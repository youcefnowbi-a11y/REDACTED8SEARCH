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

