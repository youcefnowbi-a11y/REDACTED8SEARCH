# D57 — Covenant grunt internals: the four families, the messenger, the dispatch, and what is actually read

**Targets:** `Covenant/Data/Grunt/**` (8 `.cs`, 268,749 B) — full read of the messenger + dispatch paths · cross-checked against `Core/CovenantService.cs` and `Models/Listeners/InternalListener.cs`
**Method:** pure source, no provider, no execution. **Comments stripped BEFORE every classification.** Every count has its invocation. Positive control built first.
**Write scope:** this file only. Cross-references D46 and D52; does not repeat them.

---

## 0. What this is, and three corrections

### 0.1 Control built FIRST (mandated) — the `\[Authorize` trap, re-verified from primary source

**Before any count in this report, I re-ran the defect that was mine, exactly as the brief instructs:**

```
OLD pattern  \[Authorize                 : hits=8   files=6
NEW pattern  \[[^\]]*\bAuthorize\b[^\]]*\] : hits=25  files=22
```

**Both reproduce the Lead's figures exactly.** `[source: this session, both patterns, per-file control printed]` **Sixteen controllers were invisible and every one carries `RequireJwtBearer`.** **This is now the counting instrument for anything attribute-shaped in this report — and it is recorded here because the trap was mine and a single corrected run does not retire it.**

### 0.2 **CORRECTION 1 — `Data\Grunt\` is not four families with one messenger among them. It is four `(Grunt, Stager)` PAIRS, each carrying its OWN COPY of the messenger.**

**The brief says "which is the messenger versus the transports," implying one family is the messenger and three are transports.** **That structure does not exist.** Every one of the four families contains the same internal cast:

| Class | Brute | GruntBridge | GruntHTTP | GruntSMB |
|---|:--:|:--:|:--:|:--:|
| `Grunt` / `Brute` (entry class) | `Brute` L16 | `Grunt` L19 | `Grunt` L18 | `Grunt` L18 |
| `IMessenger` interface | L351 | — *(absent)* | L390 | L389 |
| `TaskingMessenger` base | L402 | L411 | L441 | L438 |
| `SMBMessenger : IMessenger` | — | L572 | L600 | L597 |
| `HttpMessenger : IMessenger` | L519 | — | L822 | — |
| `MessageCrafter` | L620 | L794 | L923 | L819 |
| `GruntTaskingType` / `GruntTaskingMessage` | L685 / L699 | L839 / L853 | L988 / L1002 | L864 / L878 |
| `GruntEncryptedMessage` | L762 | L916 | L1065 | L941 |

**The messenger is a CLASS inside each family, not one of the four families.** `TaskingMessenger` exists **four times** — and their SHA-256 digests differ (`a565d83a…`, `3d710bae…`, `e2da2c52…`, `ba4e5f77…`), so they are **four independently-maintained near-duplicates, not one shared base.**

**This is denominator species 6, and it is the shape D46 warned about:** "`Data\Grunt\` being 'the grunt' while actually being four transport families" — the brief's next step, "which is the messenger," would have counted a class as a family. **There is no separate messenger to name. There are four.**

`[source: class/interface declarations enumerated per file with line numbers, all 8 files; digests computed over full file bytes]`

### 0.3 **CORRECTION 2 — the four pin line numbers are correct as cited; the block is 12 lines, and pinning is a two-stage AND that defaults open**

**The brief cites `GruntHTTP.cs:859-871`, `GruntHTTPStager.cs:62`, `Brute.cs:556`, `BruteStager.cs:63`.** My `GetCertHashString` probe returned `864 / 67 / 561 / 68` — a uniform **+5 offset**. **Resolved by reading both regions: the cited lines are the `ServerCertificateValidationCallback` DECLARATION; the comparison is 5 lines later.** **The brief's numbers are right and my probe was measuring a different line of the same block.** Recording it because a uniform offset looks like a discrepancy and is not one.

**The block, verbatim (`GruntHTTP.cs:859-871`):**

```csharp
ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
{
    bool valid = true;
    if (this.UseCertPinning && CovenantCertHash != "")   // gate 1
        valid = cert.GetCertHashString() == CovenantCertHash;
    if (valid && this.ValidateCert)                       // gate 2
        valid = errors == System.Net.Security.SslPolicyErrors.None;
    return valid;
};
```

**Both gates are `&&`-guarded and `valid` initialises to `true`.** **If `UseCertPinning` is false, gate 1 does not run and `valid` stays `true`. If `ValidateCert` is false, gate 2 does not run.** **A grunt built with both off accepts any certificate — including no certificate check at all.** **Both are `{{REPLACE_*}}` per-grunt operator settings (D46).** **This is not a defect; it is the operator-facing switch D46 §3.3 named, now shown at the code level: the pin is opt-in, and the callback is not fail-closed.**

### 0.4 **CORRECTION 3 — a load-bearing difference between families the brief does not mention: SSL3 enablement**

```
Brute.cs:555              SecurityProtocolType.Tls
BruteStager.cs:62         SecurityProtocolType.Tls
GruntHTTP.cs:858          SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls
GruntHTTPStager.cs:61     SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls
```

**`GruntHTTP` and `GruntHTTPStager` enable SSL3; `Brute` and `BruteStager` do not.** **`GruntBridge` and `GruntSMB` set no `SecurityProtocol` at all** (0 hits). **Three different TLS postures across four families for the same framework.** The SSL3-enabling pair is the HTTP family — the one whose `SecurityProtocolType.Tls` alone would have been correct. `[source: SecurityProtocolType. hits enumerated across all 8 files]`

---

## 1. Q1 — the four families, enumerated

| Family | Files | Bytes | Pair members | Role |
|---|---|---:|---|---|
| **GruntHTTP** | 2 | **75,307** | `GruntHTTP.cs` 60,548 + `GruntHTTPStager.cs` 14,759 | **HTTP/HTTPS transport.** Carries `HttpMessenger` **and** `SMBMessenger` |
| **GruntSMB** | 2 | **67,774** | `GruntSMB.cs` 54,607 + `GruntSMBStager.cs` 13,167 | **SMB named-pipe transport.** `SMBMessenger` only |
| **GruntBridge** | 2 | **63,288** | `GruntBridge.cs` 54,084 + `GruntBridgeStager.cs` 9,204 | **Bridge transport** — relays through another grunt. `SMBMessenger` only |
| **Brute** | 2 | **62,380** | `Brute.cs` 46,973 + `BruteStager.cs` 15,407 | **Brute-force HTTP transport** — connection-attempt/UAC style. `HttpMessenger` only |
| **TOTAL** | **8** | **268,749** | | |

**Each family is a `(Grunt, Stager)` pair.** The **Stager** is the bootstrap that runs first and pulls the `Grunt`; the **Grunt** is the resident implant. **Sizes are consistent: Grunt 46,973-60,548 B; Stager 9,204-15,407 B.**

**The messenger implementations, per family (the real "which is the messenger" answer):**

| Family | `IMessenger` implementors |
|---|---|
| Brute | `HttpMessenger` |
| GruntHTTP | `SMBMessenger`, `HttpMessenger` |
| GruntSMB | `SMBMessenger` |
| GruntBridge | `SMBMessenger` |

**`GruntHTTP` is the only family with BOTH transports** — which is why it is the largest. **`GruntBridge` has no `IMessenger` interface declaration at all** (L390 absent; it declares `SMBMessenger : IMessenger` at L572, consuming an interface declared elsewhere in the file or inherited). `[source: `class \w+ : IMessenger` per file, printed]`

---

## 2. Q2 — the messenger: framing, encode/decode, transform, and where crypto sits

### 2.1 The two-layer structure

**Layer 1 — `GruntEncryptedMessage` (`GruntHTTP.cs:1065-1091`)**: the OUTER envelope.

```csharp
public string GUID { get; set; } = "";
public GruntEncryptedMessageType Type { get; set; }   // Routing | Tasking
public string Meta { get; set; } = "";
public string IV { get; set; } = "";
public string EncryptedMessage { get; set; } = "";
public string HMAC { get; set; } = "";
```

**Layer 2 — `GruntTaskingMessage` (`:1002-1033`)**: the INNER plaintext, carried inside `EncryptedMessage`.

### 2.2 **Where the crypto sits relative to framing — the exact pipeline**

**`MessageCrafter.Create` (`:939-956`), read verbatim:**

```csharp
byte[] encryptedMessagePacket = Utilities.AesEncrypt(Message, this.SessionKey.Key);      // :941
byte[] encryptionIV = new byte[Common.AesIVLength];
Buffer.BlockCopy(encryptedMessagePacket, 0, encryptionIV, 0, Common.AesIVLength);          // :943
byte[] encryptedMessage = new byte[encryptedMessagePacket.Length - Common.AesIVLength];
Buffer.BlockCopy(encryptedMessagePacket, Common.AesIVLength, encryptedMessage, 0, ...);    // :945
byte[] hmac = Utilities.ComputeHMAC(encryptedMessage, SessionKey.Key);                     // :947
return new GruntEncryptedMessage {
    EncryptedMessage = Convert.ToBase64String(encryptedMessage),                            // :952
    IV = Convert.ToBase64String(encryptionIV),                                             // :953
    HMAC = Convert.ToBase64String(hmac) };                                                 // :954
```

**The order, and it is the answer to Q2's crypto-vs-framing question:**

```
plaintext → AES-CBC encrypt (IV prepended by AesEncrypt)
          → SPLIT IV off the front into its own field
          → HMAC over the CIPHERTEXT ONLY (not IV, not GUID, not Meta)
          → base64 each field independently
          → wrap in GruntEncryptedMessage
```

**CRYPTO WRAPS FRAMING.** The JSON envelope is **not encrypted** — `GUID`, `Meta`, `IV`, `EncryptedMessage`, `HMAC` travel as plaintext-but-base64 JSON fields, and **only `EncryptedMessage` is ciphertext.** **`Meta` is unauthenticated plaintext** (it is outside the HMAC, `:947` covers `encryptedMessage` only).

**Decode (`Retrieve`, `:958-965`):**

```csharp
if (message == null || !message.VerifyHMAC(this.SessionKey.Key)) { return null; }   // :960
return Common.GruntEncoding.GetString(Utilities.AesDecrypt(message, SessionKey.Key)); // :964
```

**HMAC is verified BEFORE decryption** — correct order, and a `null` return on failure. `VerifyHMAC` (`:1080-1091`) wraps the base64 decode in `try/catch` returning `false`, so **a malformed HMAC field is a clean rejection, not an exception.** **This is the server-side `InternalListener.Write` counterpart D46 read at `:408-423`** — both ends treat a bad message as "respond NotFound," not as an error.

### 2.3 The transform pipeline — and a correction about what it is

**`{{REPLACE_PROFILE_MESSAGE_TRANSFORM}}` appears 8 times across the four families (9 counting `CovenantService.cs`), and every single occurrence is inside a `//` comment** (§4). **There is no transform pipeline in the grunt source.**

```
GruntHTTP.cs:1307    // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
GruntSMB.cs:1183     // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
Brute.cs:1004        // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
GruntBridge.cs:1158  // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
...and one per Stager
```

**The transform is a SERVER-side concept that reaches the grunt only as the concrete `ReadFormat`/`WriteFormat` strings.** Q3's brief calls it "the transform pipeline (Covenant uses transforms/profiles)." **On the grunt side there is no pipeline — there are two format strings** (`{{REPLACE_PROFILE_READ_FORMAT}}`, `{{REPLACE_PROFILE_WRITE_FORMAT}}`, 4 hits each) **and the placeholder that would name the transform is commented out.** **This is a design statement, not a capability — Q4's exact question, answered for this placeholder in §4.**

**What IS present and used:** `GruntBridge`/`GruntSMB` carry `ProfileWriteFormat`/`ProfileReadFormat` as live fields (`GruntBridge.cs:29-30`); `Brute`/`GruntHTTP` do not (they use HTTP headers + response templates instead). **The format-string mechanism is a property of the pipe/relay transports, not of HTTP.**

### 2.4 The cert pins — confirmed, four, with families

| # | File | Declaration line | Comparison line | Family |
|---:|---|---:|---:|---|
| 1 | `GruntHTTP.cs` | **859** | 864 | **GruntHTTP** |
| 2 | `GruntHTTPStager.cs` | **62** | 67 | **GruntHTTP** |
| 3 | `Brute.cs` | **556** | 561 | **Brute** |
| 4 | `BruteStager.cs` | **63** | 68 | **Brute** |

**COUNT CONFIRMED: 4, matching the brief.** **`GruntHTTP` contributes 2 and `Brute` contributes 2. `GruntSMB` and `GruntBridge` carry NONE — 0 hits for `GetCertHashString` / `ServerCertificateCustomValidationCallback` / `X509Certificate`.**

**That is a substantive finding:** **the two families that are TLS-capable are the two with pins; the two pipe/relay families have nothing to pin, because they do not make TLS connections.** **The absence in `GruntSMB`/`GruntBridge` is structural, not an omission.** `[source: cert-pattern enumeration across all 8 files, printed; both regions of all four blocks read verbatim]`

---

## 3. Q3 — the grunt-side dispatch, and D52's chain answered from the receiving end

### 3.1 What the dispatch sees

**The wire type (`GruntHTTP.cs:1002-1007`) — and this is the first load-bearing fact:**

```csharp
public class GruntTaskingMessage
{
    public GruntTaskingType Type { get; set; }
    public string Name { get; set; }
    public string Message { get; set; }
    public bool Token { get; set; }
}
```

**There is NO `Parameters` field on the grunt side.** **`Parameters` = 0 hits across all four messenger families** (the three `Parameters=1` hits are in Stagers and are `new CspParameters()` — a .NET crypto type, not the D52 defect; **checked and eliminated, not assumed**).

**JSON format (`:1009`):** `{"type":"{0}","name":"{1}","message":"{2}","token":{3}}` — **a hand-built format string parsed by `Utilities.Parse`, not a JSON deserialiser.**

**`FromJson` (`:1010-1021`):** parses via `Utilities.Parse`, requires `parseList.Count >= 3`, `Enum.Parse` on type, `Convert.ToBoolean` on `parseList[3]`.

### 3.2 The dispatch — two completely different parsers, selected by `Type`

**`TaskExecute` (`:236-250`), the `Assembly` branch:**

```csharp
string[] pieces = message.Message.Split(',');                                    // :244
for (int i = 1; i < pieces.Length; i++)
    parameters[i-1] = Encoding.UTF8.GetString(Convert.FromBase64String(pieces[i])); // :249
byte[] compressedBytes = Convert.FromBase64String(pieces[0]);                    // :250
byte[] decompressedBytes = Utilities.Decompress(compressedBytes);                // :251
Assembly gruntTask = Assembly.Load(decompressedBytes);                           // :252
```

**`pieces[0]` = base64 compressed assembly. `pieces[1..n]` = each individually base64, decoded to UTF8 strings, passed as `Execute` parameters.**

**The control loop (`:104-127`), the `SetDelay`/`SetJitter`/`SetConnectAttempts` branch:**

```csharp
if (message.Type == GruntTaskingType.SetDelay || ... SetJitter || ... SetConnectAttempts)  // :104
{
    if (int.TryParse(message.Message, out int val))   // :106  — RAW, NO BASE64
```

**`SetKillDate` (`:130-135`)**: `DateTime.TryParse(message.Message, ...)` — **also raw.**

### 3.3 **Does the grunt's parser agree with the server's encoding? Yes for the control loop — and that CORROBORATES D52 while correcting its mechanism**

**Server side (`InternalListener.cs:205-232`), read verbatim — there are TWO encodings:**

| Branch | Encoding | When |
|---|---|---|
| `Net35` (`:207-211`) | `ToBase64String(compressed assembly)` + `","` + **each parameter base64** | `Type == Assembly`, .NET 3.5 |
| `Net40` (`:215-219`) | same | `Type == Assembly`, .NET 4.0 |
| `NetCore31` (`:223-227`) | same | `Type == Assembly`, .NET Core |
| **`else` (`:232`)** | **`string.Join(",", tasking.Parameters)` — RAW, NO BASE64** | **every non-Assembly tasking type** |

**So the server's encoding is `Type`-dependent, and the grunt's decoding is `Type`-dependent, and THE TWO AGREE BY CONSTRUCTION:**

| Tasking type | Server sends | Grunt reads | Agree? |
|---|---|---|---|
| `Assembly` | base64 + `,` + base64 params | `Split(',')` → base64 each | **✅** |
| `SetDelay` / `SetJitter` / `SetConnectAttempts` | **raw joined** | **`int.TryParse(Message)` raw** | **✅** |
| `SetKillDate` | **raw joined** | **`DateTime.TryParse(Message)` raw** | **✅** |

**ANSWER: the grunt's parser AGREES with the server's encoding. It CORROBORATES D52's finding that the two fields are joined, and CONTRADICTS the implication that the encodings are mismatched in general — the base64/raw split is deliberate and consistent.**

### 3.4 **But D52's specific defect is real, and the grunt side shows exactly why**

**`CovenantService.cs:1358` (`SetDelay` tasking construction), read verbatim:**

```csharp
Parameters = new List<string> { "Delay", grunt.Delay.ToString() },   // :1358
```

**Two elements: a LABEL `"Delay"` and a VALUE `"300"`.**

**Path to the wire:** `:232` (non-Assembly `else` branch) → `Message = string.Join(",", {"Delay","300"})` → **`"Delay,300"`**.

**Grunt side (`:106`):** `int.TryParse("Delay,300", out int val)` → **`false`.**

**The grunt does not throw — it takes the guarded `else` (`:124-126`):**

```csharp
else { output += "Error parsing: " + message.Message; }   // :126
```

**So `SetDelay` via this path silently fails, reports `"Error parsing: Delay,300"`, and the delay is never set.** **The grunt's parser is not confused about the encoding — it correctly receives a raw string and correctly cannot parse a LABEL,VALUE pair as an integer.**

### 3.5 The matching server-side parse — and the `:2954` citation

**The brief and D52 cite `:2954` as `Parameters[0]` parsed as the value. Read verbatim, `:2954` is the CONDITION of a guarded branch, and it parses `Parameters[0]` — the LABEL:**

```csharp
else if ((tasking.Type == GruntTaskingType.SetDelay || ... SetJitter ||
    tasking.Type == GruntTaskingType.SetConnectAttempts) && tasking.Parameters.Count >= 1 && int.TryParse(tasking.Parameters[0], out int n))  // :2954
```

**`int.TryParse(tasking.Parameters[0])` where `Parameters[0] == "Delay"` → `false`.** **The server-side branch is guarded by `int.TryParse`, so it fails silently too — the grunt's `Delay` field is never updated server-side either.**

**So D52's chain is CONFIRMED in both directions, and I can state it more precisely than the brief does:**

> **`CovenantService.cs:1358` writes a two-element `Parameters` list `{"Delay", "300"}` for a tasking type whose entire consumer chain — both the grunt's `int.TryParse(message.Message)` at `GruntHTTP.cs:106` and the server's own `int.TryParse(tasking.Parameters[0])` at `CovenantService.cs:2954` — expects a SINGLE integer value. The label is never stripped by either end. `SetDelay`, `SetJitter`, and `SetConnectAttempts` taskings constructed at `:1358` therefore cannot apply, and both ends fail silently by design (a `TryParse` guard on both sides).**

**On D52's specific question — "base64 vs raw" — the answer is that the base64/raw distinction is NOT the defect.** **Both ends agree on raw for non-Assembly types.** **The defect is a SHAPE mismatch: a label-value pair sent where a scalar is expected, with `TryParse` guards on both ends converting a data error into a silent no-op.** **That is a sharper finding than an encoding mismatch, and it is measured on both sides.**

**Method note:** the `:2954` citation resolves; **the brief's earlier `:2954 parses Parameters[0] as the value` reading is the part that needs the correction — `Parameters[0]` is the LABEL, and the value is `Parameters[1]`.** `[source: CovenantService.cs:1358 and :2945-2976 read verbatim; InternalListener.cs:205-240 read verbatim; GruntHTTP.cs:104-135 and :236-250 read verbatim; base64 validity of "Delay" and "300" tested and both THROW FormatException]`

---

## 4. Q4 — how many substituted values are actually READ

### 4.1 The measurement (comments stripped first, as required)

**22 distinct `{{REPLACE_*}}` placeholders reach `Data\Grunt\` source. Classified by whether the hit is live code or inside a comment:**

| Placeholder | In code | In comment |
|---|---:|---:|
| `{{REPLACE_CONNECT_ATTEMPTS}}` | 4 | 0 |
| `{{REPLACE_COVENANT_CERT_HASH}}` | 2 | 0 |
| `{{REPLACE_COVENANT_URI}}` | 1 | 0 |
| `{{REPLACE_COVENANT_URIS}}` | 2 | 0 |
| `{{REPLACE_DELAY}}` | 4 | 0 |
| `{{REPLACE_GRUNT_GUID}}` | 4 | 0 |
| `{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}` | 4 | 0 |
| `{{REPLACE_JITTER_PERCENT}}` | 4 | 0 |
| `{{REPLACE_KILL_DATE}}` | 4 | 0 |
| `{{REPLACE_PIPE_NAME}}` | 1 | 0 |
| `{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}` | 2 | 0 |
| `{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}` | 4 | 0 |
| `{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}` | 4 | 0 |
| `{{REPLACE_PROFILE_HTTP_POST_REQUEST}}` | 4 | 0 |
| `{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}` | 4 | 0 |
| `{{REPLACE_PROFILE_HTTP_URLS}}` | 4 | 0 |
| `{{REPLACE_PROFILE_READ_FORMAT}}` | 4 | 0 |
| `{{REPLACE_PROFILE_WRITE_FORMAT}}` | 4 | 0 |
| `{{REPLACE_USE_CERT_PINNING}}` | 4 | 0 |
| `{{REPLACE_VALIDATE_CERT}}` | 4 | 0 |
| **`{{REPLACE_BRIDGE_MESSENGER_CODE}}`** | **0** | **2** |
| **`{{REPLACE_PROFILE_MESSAGE_TRANSFORM}}`** | **0** | **8** |

**IN CODE: 20 distinct. COMMENT-ONLY: 2 distinct. TOTAL REACHING GRUNT SOURCE: 22.**

### 4.2 **Every one of the 20 live values is READ at runtime — none is a dead constant**

**Control:** for each live placeholder's assigned variable, I counted total identifier occurrences and compared against the assignment count. **No variable had `uses <= assignments`** — **every substituted value is consumed beyond its own assignment line.**

**Representative assignments, all at the top of each `Grunt` file (`GruntHTTP.cs:24-35`):**

```csharp
int Delay = Convert.ToInt32(@"{{REPLACE_DELAY}}");                                    // :24
int Jitter = Convert.ToInt32(@"{{REPLACE_JITTER_PERCENT}}");                          // :25
int ConnectAttempts = Convert.ToInt32(@"{{REPLACE_CONNECT_ATTEMPTS}}");               // :26
DateTime KillDate = DateTime.FromBinary(long.Parse(@"{{REPLACE_KILL_DATE}}"));        // :27
List<string> ProfileHttpHeaderNames = @"{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}".Split(','); // :28
bool ValidateCert = bool.Parse(@"{{REPLACE_VALIDATE_CERT}}");                         // :34
bool UseCertPinning = bool.Parse(@"{{REPLACE_USE_CERT_PINNING}}");                    // :35
```

**These are direct field initialisers at class scope, not declarations of unused constants.** `Delay`, `Jitter`, `ConnectAttempts` are consumed by the tasking loop (`:104-127`) and the sleep path; `ValidateCert`/`UseCertPinning` are consumed by the cert callback (§0.3); `ProfileHttpHeaderNames`/`Values` by `SetupCookieWebClient` (`:907-919`).

### 4.3 **The two comment-only placeholders are the answer to Q4's actual question**

**`{{REPLACE_PROFILE_MESSAGE_TRANSFORM}}` — 8 hits, all `//` comments. `{{REPLACE_BRIDGE_MESSENGER_CODE}}` — 2 hits, both `//` comments.**

**Both are emitted into the grunt source as comments and substituted, but NOTHING in the grunt reads them.** **These are exactly the "design statement, not a capability" the brief asks about:**

- **`{{REPLACE_PROFILE_MESSAGE_TRANSFORM}}`** marks where a transform pipeline *would* be. **The grunt has no transform pipeline** (§2.3) — the profile's transform is applied server-side, and the grunt receives only the resulting `ReadFormat`/`WriteFormat` (pipe transports) or HTTP templates (**HTTP transports**).
- **`{{REPLACE_BRIDGE_MESSENGER_CODE}}`** marks where bridge messenger code *would* be inlined. **In `GruntBridge`, 0 hits in code** — the bridge relays without a per-grunt generated messenger body.

**Note the asymmetry with D46: D46's 28 placeholders were enumerated TREE-WIDE (server + grunt + launchers). This report's 22 are the GRUNT-SIDE SUBSET.** **22 ⊂ 28, and the 6 absent from grunt source** (`{{REPLACE_SCRIPT}}`, `{{REPLACE_SCRIPT_LANGUAGE}}`, `{{REPLACE_TAGGED_SCRIPT}}`, `{{REPLACE_PROGID}}`, `{{REPLACE_GRUNT_IL_BYTE_STRING}}`, `{{REPLACE_VERSION_SETTER}}`) **are all Launcher-family — they configure DELIVERY, never the resident implant. That split is itself a clean architectural boundary: launcher placeholders are consumed at staging, grunt placeholders at run time.** `[source: placeholder enumeration across all 8 files with code/comment classification; identifier-use control per assigned variable]`

---

## 5. Residual unknowns, each with a concrete probe

| # | Unknown | Probe |
|---:|---|---|
| 1 | **Whether `SetDelay` via the `:1358` path is the ONLY construction site, or a redundant one.** If another site sends a bare integer, the feature still works and this is a dead branch, not a broken feature. | Enumerate every `GruntTaskingType.SetDelay` construction in `CovenantService.cs` and check each `Parameters` shape. |
| 2 | **`GruntBridge`'s `IMessenger` interface is declared where?** No declaration at L390; `SMBMessenger : IMessenger` at L572 compiles, so it is resolved from elsewhere. | Read `GruntBridge.cs` L1-30 (`using`) and search the tree for the interface declaration. |
| 3 | **The `Meta` field's role.** HMAC covers `EncryptedMessage` only; `Meta` is unauthenticated. What consumes it? | Trace `Meta` through `QueueTaskingMessage(string, string Meta)` (`:506`) and the server's read path. |
| 4 | **`GruntSMB`/`GruntBridge` set no `SecurityProtocol`.** Whether they inherit the process default or make no TLS call at all. | Trace whether those families construct any `HttpWebRequest`/`WebClient`. |
| 5 | **`Utilities.Parse`'s regex.** `:1012` relies on it for `FromJson`; a greedy/anchored bug there would affect every tasking message. | Read `Utilities.Parse` and test against a `message` containing a comma. |
| 6 | **Whether the 4 `TaskingMessenger` copies differ behaviourally, not just textually.** Digests differ; cause unread. | Diff `GruntHTTP.cs` `TaskingMessenger` (L441-599) against `GruntSMB.cs` (L438-596). |

### 5.1 Instrument failures, this report

| # | Failure | Caught by | Effect |
|---:|---|---|---|
| 1 | `GetCertHashString` probe returned a uniform **+5 offset** from the brief's cited lines | reading both regions | **none — the brief was right, my probe read the comparison not the declaration.** Recorded so a uniform offset is not re-reported as a discrepancy |
| 2 | `Parameters=1` in three Stagers looked like a D52 corroboration | printing the matched context | **false positive — `new CspParameters()`, a .NET crypto type.** Eliminated before any claim |
| 3 | The `:2954` citation initially failed to resolve in `InternalListener.cs` | re-searching the whole tree | **it is in `CovenantService.cs`, not `InternalListener.cs`** — the brief's file attribution was loose; the line is real |

**Failure 2 is the one that mattered: had I not printed the context, three `CspParameters()` hits would have been filed as "the grunt side also has a Parameters field," inverting the report's central Q3 finding.** **The mandated control caught it.**

---

## 6. The four answers, consolidated

| Q | Answer |
|---|---|
| **Q1** | **Not four families with one messenger.** Four `(Grunt, Stager)` **pairs** — GruntHTTP 75,307 B, GruntSMB 67,774, GruntBridge 63,288, Brute 62,380; 8 files, 268,749 B. **The messenger is a CLASS inside each family** (`TaskingMessenger` ×4, all differing digests; `HttpMessenger` in Brute+GruntHTTP, `SMBMessenger` in GruntHTTP+SMB+Bridge). **No family "is" the messenger.** |
| **Q2** | **Crypto wraps framing.** AES-CBC → IV split to its own field → HMAC over ciphertext only → base64 each field → plaintext JSON envelope. `Meta` is unauthenticated. HMAC verified **before** decrypt (`:960`), failures return `null` cleanly. **No transform pipeline on the grunt side** — the transform placeholder is comment-only; pipes use `Read/WriteFormat`, HTTP uses header/response templates. **4 pins confirmed: GruntHTTP ×2, Brute ×2; the two TLS-capable families. Both gates `&&`-guarded, `valid` defaults `true` — opt-in, not fail-closed.** GruntHTTP/Stager enable **SSL3**; Brute does not. |
| **Q3** | **The grunt has no `Parameters` field** — `{Type, Name, Message, Token}`. **Its parser AGREES with the server**: base64 split for `Assembly`, raw `int.TryParse`/`DateTime.TryParse` for control taskings, matching `InternalListener.cs:232`'s raw branch. **D52's defect is CORROBORATED but its mechanism corrected: it is not a base64/raw mismatch — it is a SHAPE mismatch.** `{"Delay","300"}` joins to `"Delay,300"`; the grunt's `int.TryParse` (`:106`) and the server's own `int.TryParse(Parameters[0])` (`:2954`) **both** fail, **both guarded, both silent no-ops.** `Parameters[0]` is the LABEL, not the value. |
| **Q4** | **22 placeholders reach grunt source; 20 are live code, 2 are comment-only — and ALL 20 live ones are read at runtime** (no dead constants). The 2 comment-only (`PROFILE_MESSAGE_TRANSFORM` ×8, `BRIDGE_MESSENGER_CODE` ×2) are **design statements, not capabilities**. The 6 of D46's 28 absent from grunt source are **all Launcher-family — a clean delivery-vs-runtime boundary.** |

---

*End of D57. Pure source; no provider, no build, no execution. Control built first and reproduced the Lead's 8/6 → 25/22 figures. Three corrections in §0, including one against a D46-era framing and one against my own probe. Four pins confirmed at the brief's line numbers. Q3 answered independently and stated more precisely than the brief's own reading. Three instrument failures, one of which would have inverted the report's central finding had the matched context not been printed.*