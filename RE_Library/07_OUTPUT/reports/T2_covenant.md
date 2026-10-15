# T2 — Covenant (.NET/C# C2 Framework) — Exhaustive Reverse-Engineering Report

**Target:** `RE_Library/01_SOURCE_c2/covenant`
**Artifact class:** complete source tree (GPLv3, Ryan Cobb / @cobbr_io), 1,005 files, 152 `.cs`
**Stack:** ASP.NET Core 3.1 (Blazor Server + SignalR + EF Core), C#; implants compiled at runtime via Roslyn
**Engagement note:** working tree restored; **git submodules deliberately left uninitialized** (8 directories present, 0 entries each) and documented only.
**Evidence tags:** `[source]` = read directly from tree; `[compiled-artifact]` = read from a real PE/CLI binary via ILSpy; `[inference]` = my deduction.

---

## 1. Architecture Map

### 1.1 Solution and project layout

`Covenant.sln` contains **exactly one project**:

```
"Covenant", "Covenant\Covenant.csproj", {D5865774-CD82-4CCE-A3F1-7F2C4639301B}
Debug|Any CPU, Release|Any CPU ; SolutionGuid = {105B1E42-390C-47A0-9C36-5F0699DAD9C2} ; VS 16, Format 12.00
```
`[source]` The server is a monolith; there is no separate agent project in the solution. Implant source lives as **raw C# text under `Covenant/Data/Grunt/`** and is compiled on demand — it is never built by the solution.

### 1.2 Runtime roles

| Layer | Implementation | Role |
|---|---|---|
| Web UI | Blazor Server pages (`Covenant/Pages/`) | Operator console |
| Realtime | SignalR (`CovenantHubService.cs`, 47 KB) | Grunt/listener/task live events |
| Persistence | EF Core + SQLite (`covenant.db`) | Model storage |
| API | `CovenantAPI.cs` (1,084,841 B, AutoRest-generated) + `ICovenantAPI.cs` (93,517 B) + `CovenantAPIExtensions.cs` (212,491 B) | The server calls **its own REST API** over HTTP to mutate state |
| Listener host | Kestrel / `IWebHost`, self-hosted per listener | HTTP(S) and Bridge listeners |
| Listener core | `InternalListener.cs` (53 KB, 1,074 lines) | **Protocol hub** — all crypto + stage machine |
| Implant builder | `Compiler.cs` (20,298 B) + Roslyn | Compiles stagers, executors, and task assemblies |
| Tasking | 11 YAML task definitions (95 tasks) | Task library metadata + inline source |

`[source]` The self-referential API design is architecturally significant: `InternalListener` mutates grunt state by calling `_client.EditGruntAsync(...)`, `_client.CompileGruntExecutorAsync(...)` etc. — the listener is an **API client of its own server**, so listener and server can in principle be split across hosts.

### 1.3 The listener / grunt / task model

**ListenerTypes** (seeded in `DbInitializer.cs` L118–119): `HTTP` ("Listens on HTTP protocol."), `Bridge` ("Creates a C2 Bridge for custom listeners."). `[source]`

**Listener** base (`Models/Listeners/Listener.cs`):
`Name`, `GUID` = `Utilities.CreateShortGuid()` (regex `^[a-zA-Z0-9]*$`), `BindAddress` (IPv4-validated, default `0.0.0.0`), `BindPort`/`ConnectPort` (`Range(1,65535)`, default 80), `ConnectAddresses`, `ProfileId`, `ListenerTypeId`, `Status`, `CovenantUrl`, `CovenantToken`, `StartTime`; virtual `Start()` / `Stop(CancellationTokenSource)`. `ListenerDirectory = Common.CovenantListenersDirectory + GUID + separator`. `[source]`

**ListenerStatus**: `Uninitialized`, `Active`, `Stopped`. `[source]`

**ImplantTemplates** (seeded L45–73) — the four shipped implants:

| Implant | Description (verbatim) |
|---|---|
| `GruntHTTP` | A Windows implant written in C# that communicates over HTTP. |
| `GruntSMB` | A Windows implant written in C# that communicates over SMB. |
| `GruntBridge` | A customizable implant written in C# that communicates with a custom C2Bridge. |
| `Brute` | A cross-platform implant built on .NET Core 3.1. |
`[source]`

**ImplantTemplate** model carries `Language` (`CSharp` only), `CommType` (`HTTP`/`SMB`/`Bridge`), `ImplantDirection` (`Push`/`Pull`), `CompatibleListenerTypes`, `CompatibleDotNetVersions`, `StagerCode`, `ExecutorCode`. `[source]` `ImplantDirection` is the pivot that separates *egress* implants (Push) from *pivot/relay* implants (Pull, i.e. SMB and Bridge).

**GruntStatus state machine:**

```
Uninitialized -> Stage0 -> Stage1 -> Stage2 -> Active      (and: Lost)
```
Dispatch is done by exactly this field in `InternalListener.Write` → `PostStage0` / `PostStage1` / `PostStage2` / `RegisterGrunt` / `PostTask`. `[source]`

**GruntTaskingType** (full enum, from `API/Models/GruntTaskingType.cs`): `Assembly`, `SetDelay`, `SetJitter`, `SetConnectAttempts`, `SetKillDate`, `Exit`, `Connect`, `Disconnect`, `Tasks`, `TaskKill`. `[source]`

**CommunicationType**: `HTTP`, `SMB`, `Bridge`. `[source]`

### 1.4 Directory map (runtime data)

`Core/Common.cs` defines the operational layout: `Data/` → `covenant.db`, `Temp/`, `Profiles/`, `Downloads/`, `AssemblyReferences/{net35,net40}/`, `EmbeddedResources/`, `ReferenceSourceLibraries/`, `Tasks/` (+ `Tasks/CSharp/netcoreapp3.0/`, `Tasks/CSharp/Compiled/{net35,net40,netcoreapp3.0}/`), `Logs/`, `Listeners/`, `Launchers/`, plus `covenant-dev-private.pfx` / `covenant-dev-public.cer` and `appsettings.json`. `[source]`

---

## 2. Protocol Detail

### 2.1 HTTP(S) listener — request routing

`Controllers/ListenerControllers/HttpListenerController.cs` is `[AllowAnonymous]`, DI-injected with `HttpListenerContext` (a nested `IdentityDbContext`, not the ASP.NET `HttpListenerContext`) and `InternalListener`. `[source]`

**Route resolution.** The listener registers one MVC route **per profile URL** (path only, query stripped):

```csharp
foreach (string route in JsonConvert.DeserializeObject<List<string>>(Configuration["ProfileUrls"])) {
    string urlOnly = route.Split("?").First();
    endpoints.MapControllerRoute(urlOnly, urlOnly, new { controller = "HttpListener", action = "Route" });
}
```
`[source]` — `Models/Listeners/HttpListener.cs` L375–378. Static file serving is layered on the same host via `UseStaticFiles` against `PhysicalFileProvider(Configuration["ListenerStaticHostDirectory"])`, with `Common.ContentTypeMappings`, `ServeUnknownFileTypes = true`, `DefaultContentType = "text/plain"`. `[source]`

**GUID extraction (`GetGuid()`).** The controller tries, in order: (1) iterate `HttpRequestHeaders` for any header `Name` or `Value` containing the literal `{GUID}`, substitute the actual GUID, and take it; (2) otherwise match the request path against each `HttpUrls` entry that starts with the request path, then `ParseExact` over `Path + QueryString`. `[source]`

**Body format extraction (`Parse()`).** Uses `Regex.Escape(format)` then replaces `{0}`→`(?'group0'.*)` … up to `{5}`. Any exception is swallowed and converted to `NotFound(response)`. `[source]`

**GET flow:** `SetHeaders()` copies every profile `HttpResponseHeaders` entry onto the response, then the body is `HttpGetResponse` formatted with `await _internalListener.Read(guid)`. `[source]`

**POST flow:** read body → `body.ParseExact(HttpPostRequest...)` → `_internalListener.Write(guid, ExtractedMessage)` → then `Read(guidToRead)` → return `HttpPostResponse`. `[source]`

**Template escaping (subtle, and a real bug class):**
```csharp
.Replace("{","{{").Replace("}","}}")
.Replace("{{DATA}}","{0}").Replace("{{GUID}}","{1}")
```
`[source]` Braces are doubled *before* the placeholders are re-opened, so a profile whose static body contains literal `{` / `}` must be authored with escaped braces. Any profile not accounting for this produces a malformed `string.Format` template.

### 2.2 Profile schema (`Models/Listeners/Profile.cs`)

`ProfileType { HTTP, Bridge }`. Base `Profile`: `Id`, `Name`, `Description`, `Type`, `MessageTransform`, with defaults `Transform` = Base64, `Invert` = FromBase64. `[source]`

**HttpProfile** members and defaults:

| Member | Default |
|---|---|
| `HttpUrls` | `["/index.html?id={GUID}"]` |
| User-Agent | `Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36` |
| Response header | `Server: Microsoft-IIS/7.5` |
| `HttpPostRequest` / `HttpGetResponse` / `HttpPostResponse` | `"{DATA}"` |
`[source]`

**BridgeProfile** adds `ReadFormat` / `WriteFormat` (default `"{DATA},{GUID}"`), plus an embedded `BridgeMessengerCode` containing a full `IMessenger` interface (`Hostname`, `Identifier`, `Authenticator`, `Read()`, `Write(Message)`, `Close()`) and a `BridgeMessenger(string CovenantURI, string Identifier, string WriteFormat)` constructor. `[source]`

**Message transforms** are not delegates — they are **compiled assemblies loaded by reflection at runtime**:

```csharp
Assembly TransformAssembly = Assembly.Load(ProfileTransformAssembly.ProfileTransformBytes);
Type t = TransformAssembly.GetType("MessageTransform");
return (string)t.GetMethod("Transform").Invoke(null, new object[] { bytes });
```
`[source]` — `InternalListener.ModelUtilities.ProfileTransform` / `ProfileInvert`. The hard-coded type and method names (`MessageTransform.Transform` / `.Invert`, both static) are the profile-transform ABI.

### 2.3 Shipped profiles (exact)

**`Data/Profiles/DefaultHttpProfile.yaml`** `[source]`
- `MessageTransform`: Base64 / FromBase64
- `HttpUrls`: `/en-us/index.html`, `/en-us/docs.html`, `/en-us/test.html`
- Headers: UA = Chrome/41 (as above) + `Cookie: ASPSESSIONID={GUID}; SESSIONID=1552332971750`
- `HttpPostRequest: i=a19ea23062db990386a3a478cb89d52e&data={DATA}&session=75db-99b1-25fe4e9afbe58696-320bea73`
- `HttpResponseHeaders: Server: Microsoft-IIS/7.5`
- GET/POST responses are HTML documents wrapping `{DATA}`: `<html>…// Hello World! {DATA}…</html>`

**`Data/Profiles/CustomHttpProfile.yaml`** `[source]` — identical except the `Cookie` header is absent and the GUID moves into the query string: `/en-us/index.html?page={GUID}&v=1`, `/en-us/docs.html?type={GUID}&v=1`, `/en-us/test.html?message={GUID}&v=1`.

The GUID-in-Cookie vs GUID-in-query split defines the two ID-transport idioms. Response content type and status are constant across the profile; the only field carrying payload is the templated `{DATA}` slot inside otherwise-innocuous HTML. `[inference]`

**`Data/Profiles/DefaultBridgeProfile.yaml`** `[source]` — Base64 transform; `ReadFormat`/`WriteFormat` = `{DATA},{GUID}`; embedded `BridgeMessengerCode` with `enum MessageType {Read, Write}`, `ProfileMessage {Type, Message}`, `MessageEventArgs {Message}`, and the `IMessenger` contract. The bridge wire format is a simple `"<payload>,<guid>"` text pair, letting an operator point the bridge at any transport they can read/write lines on.

**`Data/Profiles/TCPBridgeProfile.yaml`** (5,630 B) — present; not byte-dumped this pass (see §8).

### 2.4 SMB channel

There is **no separate SMB listener class**. SMB traffic arrives through the HTTP listener's GUID routing plus a `CommunicationType.SMB` special case in `InternalListener`, and the channel itself is a **Windows named pipe** between implants:

- Default pipe name: `gruntsvc` (`Launcher.SMBPipeName`). `[source]`
- Implant side (`Data/Grunt/GruntSMB/GruntSMB.cs`): `Execute(string GUID, Aes SessionKey, NamedPipeServerStream ServerPipe = null, string PipeName = null)`; `SMBMessenger : IMessenger` holds a `PipeStream` + `PipeName`; bidirectional roles: `NamedPipeServerStream(PipeName, PipeDirection.InOut, MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 1024, 1024, ps)` then `WaitForConnection()` for the server role, `NamedPipeClientStream(Hostname, PipeName, PipeDirection.InOut, PipeOptions.Asynchronous)` for the client role. `[source]`
- Reconnect semantics are explicit in the source: the *server*-role grunt blocks in read until a connection returns; the *client*-role grunt blocks in write. `[source]`
- `Connect(string Hostname, string PipeName)` maintains `DownstreamMessengers`, keyed by lowercased `Hostname + ":" + PipeName`, reusing an existing downstream messenger when one matches. `[source]`

**Stage-0 composite GUID convention** (the pivot addressing scheme): when a grunt reports over SMB with `message.GUID.Length == 20`, the server splits it —
```csharp
originalServerGuid = GUID.Substring(0, 10);
guid               = GUID.Substring(10, 10);
// lookup via GetGruntByOriginalServerGUIDAsync
```
`[source]` i.e. `CompositeGUID = OriginalServerGuid(10) + Guid(10)`. With no egress grunt present, the server walks **all** taskings to find the latest `GruntTaskingType.Connect` in status `Progressed`/`Tasked` — and the source itself flags the hazard:

> `// TODO: Finding the connectTasking this way could cause race conditions`
`[source]`

### 2.5 Bridge listener

`Models/Listeners/BridgeListener.cs` `[source]`:
- Defaults `BindPort = 7444`, `ConnectPort = 7445`; `ConnectAddresses` resolved from `Dns.GetHostAddresses(Dns.GetHostName())` first IPv4, falling back to `[""]` on `SocketException`.
- `Start()` constructs an `InternalListener`, calls `Configure(InternalListener.ToProfile(this.Profile), this.GUID, this.CovenantUrl, this.CovenantToken)`, then runs a `TcpListener` accept loop.
- **Single-bridge invariant:** on each new `AcceptTcpClientAsync`, any previous `clientSource` is cancelled and disposed — the bridge holds exactly one connected client at a time, and `IsBridgeConnected` tracks it. `[source]`
- `RunClient` subscribes to `InternalListener.OnNewMessage` and pumps `Read(e.Guid)` out to the socket in a loop. `[source]`

### 2.6 Listener bootstrap / state propagation

`HttpListener.Start()`: builds the Kestrel `IHost`; opens a DI scope; `HttpListenerContext.Database.EnsureCreated()`; **deletes all rows from `HttpProfiles` and inserts exactly one** built from the current profile (`context.ToHttpProfile((HttpProfile)this.Profile)`) — the listener's own SQLite DB is profile-scoped and single-row; then `internalListener.Configure(...)` and `host.RunAsync(token)`. Startup failure is detected by `Thread.Sleep(500)` then checking `task.Status == TaskStatus.Faulted`. `[source]`

`InternalListener.Configure(profile, ListenerGuid, CovenantUrl, CovenantToken)` performs the SignalR handshake and `_connection.InvokeAsync("JoinGroup", ListenerGuid)`. `[source]`

Kestrel binding and config injection (`HttpListener.cs` L214–241):
```csharp
options.Listen(new IPEndPoint(IPAddress.Parse(this.BindAddress), this.BindPort), o => …);
.UseSetting("CovenantUrl", this.CovenantUrl)
.UseSetting("ProfileUrls", JsonConvert.SerializeObject((this.Profile as HttpProfile).HttpUrls))
.UseUrls((this.UseSSL ? "https://" : "http://") + this.BindAddress + ":" + this.BindPort);
```
`[source]`

TLS: `UseSSL`, `SSLCertificate`, `SSLCertificatePassword` (default literal `CovenantDev`), and cert file `ListenerDirectory + "httplistener-" + GUID + "-certificate.pfx"`; `SSLCertHash` reads `X509Certificate2(...).GetCertHashString()`. `[source]`

### 2.7 Exact encrypted-message shape

Server side (`InternalListener.ModelUtilities.GruntEncryptedMessage`) `[source]`:
```csharp
public string GUID { get; set; }
public GruntEncryptedMessageType Type { get; set; }   // Routing | Tasking
public string Meta { get; set; } = "";
public string IV { get; set; }
public string EncryptedMessage { get; set; }
public string HMAC { get; set; }
```
Serialized with `JsonConvert.SerializeObject` after the `MessageTransform` is applied.

Implant side (`Data/Grunt/GruntHTTP/GruntHTTP.cs` L1065+) uses a **hand-rolled string formatter, not a JSON serializer** `[source]`:
```csharp
private static string GruntEncryptedMessageFormat =
  @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";
```
with `message.Type.ToString("D")` (integer) and `Utilities.JavaScriptStringEncode(...)` on every string field.

> **Wire-format divergence `[inference]` + `[source]`:** server emits `Type` as a Newtonsoft string enum; implant parses with `(GruntEncryptedMessageType)int.Parse(parseList[1])` — an integer. These are reconciled because the implant's `FromJson` uses its own `{0}`-substitution parser, and the implant only ever *parses* server→implant messages. But any third-party or reimplemented peer that sends `"Type":"Tasking"` to a grunt will fail `int.Parse`. This is a genuine interop sharp edge.

`GruntEncryptedMessage.Create(grunt, message, Type)` selects the key by status `[source]`:
```csharp
if (grunt.Status == Uninitialized || grunt.Status == Stage0)
    return Create(grunt.Guid, message, Convert.FromBase64String(grunt.GruntSharedSecretPassword), Type);
return Create(grunt.Guid, message, Convert.FromBase64String(grunt.GruntNegotiatedSessionKey), Type);
```

Stage comments in the source state the wire formats verbatim `[source]`:
```
// Stage0Response: "Id,Name,Base64(IV),Base64(AES(RSA(SessionKey))),Base64(HMAC)"
// Stage1Response: "Base64(IV),Base64(AES(challenge1 + challenge2)),Base64(HMAC)"
// Stage2 / executor: "Base64(IV),Base64(AES(GruntExecutorAssembly)),Base64(HMAC)"
```

---

## 3. Cryptography

### 3.1 Primitives (confirmed on both sides)

`Core/Common.cs` L20–23 `[source]`:
```csharp
public static Encoding CovenantEncoding = Encoding.UTF8;
public static int AesIVLength = 16;
public static CipherMode  AesCipherMode  = CipherMode.CBC;
public static PaddingMode AesPaddingMode = PaddingMode.PKCS7;
```
`InternalListener.EncryptUtilities` (L820–892) `[source]`:

- **AES** — `Aes.Create()`, CBC, PKCS7, fresh `GenerateIV()` per message, key supplied externally. `AesEncrypt` returns `IV ‖ ciphertext`; `AesDecrypt` slices the first `AesIVLength` bytes as IV.
- **HMAC** — `HMACSHA256(key).ComputeHash(data)` where `data` is the **ciphertext only** (not IV, not GUID, not Type, not Meta).
- **HMAC verification** — `Enumerable.SequenceEqual(calculatedHash, hash)`, i.e. **not constant-time**. The source annotates it: `// Should do double hmac?` `[source]`
- **RSA** — `RSAEncrypt(toEncrypt, RSAPublicKeyXMLString)` with `RSAEncryptionPadding.OaepSHA1`. `[source]`

The implant file repeats the identical constants (`Common.AesIVLength = 16`, CBC, PKCS7, UTF8) and the identical HMAC-over-ciphertext construction `[source]` — the two implementations are byte-compatible. The one divergence is verification style: implant compares `Convert.ToBase64String(calculatedHash) == Convert.ToBase64String(hash)` (string compare) vs. server `SequenceEqual` (byte compare). `[source]`

### 3.2 RSA key encoding

Custom `RSAKeyExtensions` (L1025–1073) `[source]` — **XML `RSAKeyValue`**, both directions:
```
<RSAKeyValue><Modulus>…</Modulus><Exponent>…</Exponent><P>…</P><Q>…</Q>
<DP>…</DP><DQ>…</DQ><InverseQ>…</InverseQ><D>…</D></RSAKeyValue>
```
`FromXmlString` throws `"Invalid XML RSA key."` on a non-`RSAKeyValue` root. `ToXmlString(bool includePrivateParameters)` emits all eight fields with `null` for any absent parameter. This is the classic .NET Framework `RSACryptoServiceProvider.ToXmlString` format, reimplemented by hand — it is *not* the native `FromXmlString` available on .NET Core for Windows only.

### 3.3 Key exchange and session-key derivation

Stage 0 `[source]`:
1. `targetGrunt.GruntRSAPublicKey = Convert.ToBase64String(
       EncryptUtilities.AesDecrypt(gruntStage0Response, FromBase64String(GruntSharedSecretPassword)))`
   The source comment is explicit: `// EncryptedMessage is the RSA Public Key`.
2. Server generates the session key:
   ```csharp
   using (Aes newAesKey = Aes.Create()) { newAesKey.GenerateKey();
       targetGrunt.GruntNegotiatedSessionKey = Convert.ToBase64String(newAesKey.Key); }
   ```
3. Server encrypts the session key under the grunt's RSA public key:
   `EncryptUtilities.GruntRSAEncrypt(targetGrunt, FromBase64String(GruntNegotiatedSessionKey))`
   → `RSAEncrypt(…, Common.CovenantEncoding.GetString(FromBase64String(grunt.GruntRSAPublicKey)))` → **RSA-OAEP-SHA1**.

So: **shared secret (AES, out of band) protects the RSA public key upload; RSA-OAEP protects the AES session key download.** The shared secret is the root of trust and lives in `GruntSharedSecretPassword`, transported in the stager/launcher.

`Aes.Create().GenerateKey()` is size-agnostic — the effective key length is **the runtime default**, not a hard-coded 128/256. Under .NET Core on modern Windows this is AES-256; under .NET Framework it is also 256 by default. `[inference]` There is no explicit `KeySize =` assignment anywhere in the protocol path, which is a portability ambiguity worth noting. `[inference]`

### 3.4 Activation: challenge–response

`PostStage1` `[source]`:
- Guard: `Status != Stage0` **or** `!VerifyHMAC(FromBase64String(GruntNegotiatedSessionKey))` → `NotFound`.
- `challenge1 = GruntSessionDecrypt(targetGrunt, gruntStage1Response)` — the grunt's first challenge.
- `challenge2 = new byte[4]` filled by `RandomNumberGenerator.Create()` (CSPRNG).
- Persist `GruntChallenge = Convert.ToBase64String(challenge2)`, `Status = Stage1`, `LastCheckIn = UtcNow`, `EditGruntAsync`.
- Reply body = `AES(challenge1 ‖ challenge2)` under the session key, wrapped in the standard envelope.

`PostStage2` `[source]`:
- Guard: `Status != Stage1` **or** bad HMAC → `NotFound`.
- `challenge2test = GruntSessionDecrypt(targetGrunt, gruntStage2Response)`;
  `if (GruntChallenge != Convert.ToBase64String(challenge2test)) → NotFound`
- On match: `Status = Stage2`, `EditGruntAsync`, then
  `GruntExecutorAssembly = await _client.CompileGruntExecutorAsync(targetGrunt.Id)`
  and the executor is shipped **AES-encrypted under the session key**.
- If no egress grunt, `egressGrunt = targetGrunt`.

`challenge2` is **4 bytes** — it proves possession of the session key but is not a strong authenticator on its own; the HMAC over ciphertext is the actual integrity gate. `[inference]`

`RegisterGrunt` `[source]`:
- Guard: `Status != Stage2` or bad HMAC → `NotFound`.
- Decrypts to a JSON `Grunt`, then copies: `IpAddress`, `Hostname`, `OperatingSystem`, `UserDomainName`, `UserName`, `Integrity`, `Process`.
- `Status = Active`; `EditGruntAsync`.
- Immediately issues a tasking: `{ Message = targetGrunt.Guid, Name = Guid.NewGuid().ToString().Replace("-","").Substring(0,10), Type = Tasks, Token = false }`.

`PostTask` `[source]`: bad GUID → `NotFound`; `TaskName = outputMessage.Meta`.

**Every stage guard funnels to the same response with the identical comment:**
> `// Always return NotFound, don't give away unnecessary info`
`[source]` — the protocol is deliberately indistinguishable-failure at every stage.

### 3.5 Where the base64 happens

The `GruntEncryptedMessage` fields are base64; the whole serialized envelope is then passed through the profile's `MessageTransform` (Base64 in every shipped profile) and decoded with `Common.CovenantEncoding` (UTF-8) on the way in. So a default-profile POST body is **base64-of-JSON**, itself containing four nested base64 fields (GUID may be plaintext, IV/EncryptedMessage/HMAC are base64). `[source]`

---

## 4. Grunt / Agent Internals

### 4.1 Implant source inventory (`Covenant/Data/Grunt/`)

| File | Size (B) |
|---|---|
| `GruntHTTP/GruntHTTP.cs` | 60,548 |
| `GruntHTTP/GruntHTTPStager.cs` | 14,759 |
| `GruntSMB/GruntSMB.cs` | 54,607 |
| `GruntSMB/GruntSMBStager.cs` | 13,167 |
| `GruntBridge/GruntBridge.cs` | 54,084 |
| `GruntBridge/GruntBridgeStager.cs` | 9,204 |
| `Brute/Brute.cs` | 46,973 |
| `Brute/BruteStager.cs` | 15,407 |
| (plus `.csproj` / `.sln` for Brute / BruteStager / Task) | — |
`[source]`

### 4.2 Compile-time template substitution

The implant sources are **not** compiled as-is; they carry `{{REPLACE_*}}` tokens substituted by `Compiler.cs` at build time. `[source]`

`GruntHTTP.Grunt.Execute` signature and template reads `[source]`:
```csharp
public static void Execute(string CovenantURI, string CovenantCertHash, string GUID, Aes SessionKey)
{
    int Delay = Convert.ToInt32(@"{{REPLACE_DELAY}}");
    int Jitter = Convert.ToInt32(@"{{REPLACE_JITTER_PERCENT}}");
    int ConnectAttempts = Convert.ToInt32(@"{{REPLACE_CONNECT_ATTEMPTS}}");
    DateTime KillDate = DateTime.FromBinary(long.Parse(@"{{REPLACE_KILL_DATE}}"));
    List<string> ProfileHttpHeaderNames = @"{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}".Split(',')
        .ToList().Select(H => Encoding.UTF8.GetString(Convert.FromBase64String(H))).To…
```
Header names **and values are base64-embedded** in the compiled implant to survive quoting. The four parameters — `CovenantURI`, `CovenantCertHash`, `GUID`, `Aes SessionKey` — are exactly the stage-2 activation inputs, matching the server's `CreateMessageForGrunt` payload. `[source]`

### 4.3 Beacon loop

`GruntHTTP` main loop `[source]`:
```csharp
Random rnd = new Random();
while (alive) {
    int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));
    if (rnd.Next(2) == 0) { change = -change; }
    Thread.Sleep((Delay + change) * 1000);
    GruntTaskingMessage message = messenger.ReadTaskingMessage();
    …
```
**Sleep-with-jitter is applied to `Delay` before every check-in**, and jitter is **symmetric** (50% chance of subtracting). `[source]` Note the jitter bound: `rnd.Next((int)Math.Round(Delay * Jitter/100))` — with the default `Delay=5`, `JitterPercent=10` this yields an integer range of `rnd.Next(1)` = always 0, so **default settings produce no jitter at all**. `[inference]`

A pre-loop blank write is issued deliberately:
```csharp
// A blank upward write, this helps in some cases with an HTTP Proxy
messenger.QueueTaskingMessage("");
messenger.WriteTaskingMessage();
```
`[source]`

**TaskingType handling in the loop** `[source]`: `SetDelay` / `SetJitter` / `SetConnectAttempts` mutate the local loop variables and append `"Set Delay: " + Delay` style output. Runtime control tasks are handled **in-loop**, everything else is dispatched.

**Task execution and output streaming** `[source]`: tasks run on a dedicated `Thread t = new Thread(() => TaskExecute(messenger, message, Delay));` — and there is a token/impersonation variant (`impersonatedToken = TaskExecute(...)`). For streaming tasks the grunt uses an **anonymous pipe pair** to capture live stdout:
```csharp
using (AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
using (AnonymousPipeClientStream pipeClient = new AnonymousPipeClientStream(PipeDirection.Out, pipeServer.GetClientHandleAsString()))
{
    streamProp.SetValue(null, pipeClient, null);     // reflection-inject the stream into the task
    invokeThread.Start();
    using (StreamReader reader = new StreamReader(pipeServer)) { … MAX_MESSAGE_SIZE chunks … }
```
`[source]` The stream is injected into the task via **reflection on a property named `stream`** — that is the undocumented contract a task must honor to stream output. Chunking is by `MAX_MESSAGE_SIZE`, and a stalled reader is bounded by `DateTime.Now > lastTime.Add(TimeSpan.FromSeconds(Delay))`.

Default tasking behaviors `[source]`: `Delay=5`, `JitterPercent=10`, `ConnectAttempts=5000`, `KillDate=DateTime.Now.AddDays(30)`.

### 4.4 Launchers

`LauncherType` (full, source enum + API enum identical): **`Wmic, Regsvr32, Mshta, Cscript, Wscript, PowerShell, Binary, MSBuild, InstallUtil, ShellCode`** `[source]`

Base `Launcher` fields: `ListenerId`, `ImplantTemplateId`, `Name`, `Description`, `Type` (default `Binary`), `DotNetVersion` (default `Net35`), `RuntimeIdentifier` (default `win_x64`), `ValidateCert=false`, `UseCertPinning=false`, `SMBPipeName="gruntsvc"`, `Delay=5`, `JitterPercent=10`, `ConnectAttempts=5000`, `KillDate=+30d`, `LauncherString`, `StagerCode`, `Base64ILByteString` (reads/writes `Common.CovenantLauncherDirectory + Name`), `OutputKind` (default `DynamicallyLinkedLibrary`), `CompressStager=false`. Two virtuals: `GetLauncher(...)` and `GetHostedLauncher(Listener, HostedFile)`. `[source]`

`DiskLauncher : Launcher` adds `DiskCode`. `ScriptletLauncher : DiskLauncher` adds `ScriptingLanguage {JScript, VBScript}`, `ProgId = Utilities.CreateSecureGuid().ToString()`, `ScriptType {Plain, Scriptlet, TaggedScript, Stylesheet}`. `[source]`

| Launcher | Base | OutputKind | Compress | Launch command (verbatim) |
|---|---|---|---|---|
| `Wmic` | Scriptlet | DLL | false | `wmic os get /format:"file.xsl"` |
| `Regsvr32` | Scriptlet | DLL | false | `regsvr32 /u /s /i:file.sct scrobj.dll` |
| `Mshta` | Scriptlet | DLL | false | `mshta …` (DotNetToJScript scriptlet) |
| `Cscript` | Scriptlet | DLL | false | `cscript …` (JScript/VBScript) |
| `Wscript` | Scriptlet | DLL | false | `wscript file.js` |
| `PowerShell` | Launcher | WindowsApp | **true** | `powershell -Sta -Nop -Window Hidden -EncodedCommand <b64-UTF16LE>` |
| `Binary` | Launcher | ConsoleApp | false | `<template>.exe` |
| `MSBuild` | DiskLauncher | WindowsApp | **true** | `msbuild.exe <template>.xml` |
| `InstallUtil` | DiskLauncher | — | — | `InstallUtil.exe /U <template>.dll` |
| `ShellCode` | Launcher | ConsoleApp | false | `<template>.bin` (Donut output) |
`[source]`

**PowerShell launcher detail** `[source]` — dual form: `-EncodedCommand` with `Convert.ToBase64String(Encoding.Unicode.GetBytes(code))` (the source flags this: *"PowerShell EncodedCommand MUST be Unicode encoded, frustrating."*) and a plain `-Command` form with `"` → `\\"\\"` escaping. The payload template uses `sv`/`gv` aliases specifically to dodge `$` interpolation when run from an interactive PowerShell prompt:
```powershell
sv o (New-Object IO.MemoryStream);
sv d (New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('{{GRUNT_IL_BYTE_STRING}}'),[IO.Compression.CompressionMode]::Decompress));
sv b (New-Object Byte[](1024));
sv r (gv d).Value.Read((gv b).Value,0,1024);
while((gv r).Value -gt 0){ (gv o).Value.Write((gv b).Value,0,(gv r).Value); sv r (gv d).Value.Read((gv b).Value,0,1024); }
[Reflection.Assembly]::Load((gv o).Value.ToArray()).EntryPoint.Invoke(0,@(,[string[]]@()))|Out-Null
```
This is a **Deflate-in-memory assembly load** — matching `Common.Compress` (DeflateStream) and `PowerShellLauncher.CompressStager = true`.

**DotNetToJScript scriptlets** `[source]` — the scriptlet launchers embed a serialized `BinaryFormatter` delegate plus the stager assembly, credited in-source: `// Credit DotNetToJScript (tyranid - James Forshaw)`. The VBScript path reverses base64 through `System.Security.Cryptography.FromBase64Transform` and `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize_2`, then `delegate.DynamicInvoke(array.ToArray()).CreateInstance("Grunt.GruntStager")`. A **`{{REPLACE_VERSION_SETTER}}`** slot injects `COMPLUS_Version = "v4.0.30319"` via `WScript.Shell` Environment for the Net40 case. The MSBuild/Regsvr32/Wmic launcher descriptions all carry the same caveat:

> "Please note that DotNetToJScript-based launchers may not work on Windows 10 and Windows Server 2016."
`[source]`

**MSBuild launcher** `[source]` — XML template with `<UsingTask TaskName="{{TASK_NAME}}" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">` and a `<Code Type="Fragment" Language="cs">` block; `TargetName`/`TaskName` are operator-editable properties (defaults literally `"TargetName"`/`"TaskName"`).

**InstallUtil launcher** `[source]` — template is a `[System.ComponentModel.RunInstaller(true)]` class `Sample : System.Configuration.Install.Installer` overriding **`Uninstall`** (hence `InstallUtil.exe /U`), doing the same Deflate→`Assembly.Load(...).EntryPoint.Invoke(0, new object[] { new string[]{ } })` chain.

**ShellCode launcher** `[source]` — writes the stager to `Temp/<name>.exe`, then:
```csharp
DonutConfig config = new DonutConfig { Arch = 3, Bypass = 3, InputFile = inputf,
    Class = "GruntStager", Method = "Execute", Args = "", Payload = outputf };
int ret = Generator.Donut_Create(ref config);
```
With `Donut.dll` reference-resolved constants: `Arch = 3` = `DONUT_ARCH_X84` (**dual x86/x64**), `Bypass = 3` = `DONUT_BYPASS_CONTINUE`, success = `DONUT_ERROR_SUCCESS (0)`. `[source]` + `[compiled-artifact]` (see §7)

### 4.5 Stagers

`ImplantTemplate` exposes `StagerCode` and `ExecutorCode` read from `Data/Grunt/<Name>/<Name>Stager.cs` and `<Name>.cs`. The two-phase implant design is: **stager** (small, network/auth only) → `GruntStager` entry → stage machine through `Stage0`/`Stage1` → server compiles and returns the **executor** (`CompileGruntExecutorAsync`) → `Active`.

`GruntHTTPStager` (14,759 B) does stage-0/1/2; `GruntSMBStager` (13,167 B) same over the pipe; `GruntBridgeStager` (9,204 B) via the bridge; `BruteStager` (15,407 B) for the cross-platform .NET Core implant. `[source]`

The stage-0 upload is the RSA public key (AES-encrypted under the shared secret); stage-1 is the challenge exchange; stage-2 receives the executor.

### 4.6 Compiler

`Core/Compiler.cs` `[source]`:
- Two request types: `CsharpFrameworkCompilationRequest` and `CsharpCoreCompilationRequest` (adds `RuntimeIdentifier`).
- Two backends: `CompileCSharpCoreSubProcess(...)` (invokes an external `dotnet`/SDK-style build for .NET Core) and `CompileCSharpRoslyn(...)` (in-process Roslyn).
- Roslyn options: `new CSharpCompilationOptions(outputKind: request.OutputKind, optimizationLevel: OptimizationLevel.Release, platform: request.Platform, allowUnsafe: request.UnsafeCompile)`.
- `CSharpCompilation.Create(...)` with `MetadataReference.CreateFromFile(R.File)` per reference assembly (the 36 shipped BCL DLLs).
- Roslyn dependency pruning: `SyntaxTreeDefinesUsedType`, `GetUsedTypes`, `GetUsedTypesRecursively` — the compiler walks the syntax tree and only attaches reference assemblies for types actually referenced, keeping emitted task assemblies small. `[source]`

**RuntimeIdentifier** (full enum) `[source]`: `win_x64`, `win_x86`, `linux_x64`, `linux_musl_x64`, `linux_arm`, `linux_arm64`, `osx_x64`, `osx_10_10_x64`, `osx_10_11_x64`, `osx_10_12_x64`, `osx_10_13_x64`, `osx_10_14_x64`, `osx_10_15_x64` — mapped to the RID strings `win-x64`, `win-x86`, `linux-x64`, `linux-musl-x64`, `linux-arm`, `linux-arm64`, `osx-x64`, `osx.10.10-x64` … `osx.10.15-x64`. The `Brute` implant (per its description "built on .NET Core 3.1") is what consumes these.

---

## 5. Task Library Inventory

**11 YAML files, 95 top-level tasks** (all tasks are `TaskingType: Assembly`; the `DefaultGruntTasks` control tasks are the exceptions: `Connect`, `Exit`, `Tasks`, `TaskKill`, `Delay`, `Jitter`, `ConnectAttempts`, `KillDate`, `Disconnect`). `[source]`

**Common task entry schema** `[source]`:
`Name`, `Aliases[]`, `Description`, `Author{Name,Handle,Link}`, `Help`, `Language: CSharp`, `CompatibleDotNetVersions[]`, `Code` (inline C#), `TaskingType`, `UnsafeCompile`, `TokenTask`, `Options[]` (`Name`, `Value`, `DefaultValue`, `Description`, `SuggestedValues[]`, `Optional`, `DisplayInCommand`, `FileOption`), `ReferenceSourceLibraries[]`, `ReferenceAssemblies[]`, `EmbeddedResources[]`.

**The task ABI** `[source]` — every task's `Code` is a compilable unit exposing:
```csharp
public static class Task {
    public static string Execute(<options…>) { … }
}
```
invoked by the grunt as `gruntTask.GetType("Task").GetMethod("Execute").Invoke(null, parameters)`. See §4.3 — `options[]` order/arity must match the method signature exactly.

### 5.1 `DefaultGruntTasks.yaml` — 23 tasks `[source]`
**Core / control:** `Help`, `PowerShellImport`, `Connect`, `Exit`, `Tasks`, `TaskKill`, `Delay` (`SetDelay`), `Jitter` (`SetJitter`), `ConnectAttempts` (`SetConnectAttempts`), `KillDate` (`SetKillDate`), `Disconnect`
**Survey / desktop:** `ScreenShot` ("Takes a screenshot of the currently active desktop, move into a targeted pid for specific desktops")
**File transfer:** `Download` (remote file name), `Upload` (base64 contents)
**Recon:** `WhoAmI`, `GetCurrentDirectory`
**Filesystem:** `ChangeDirectory`, `ReadTextFile`, `CreateDirectory`, `Delete`, `Copy`
**Execution:** `Kill` (by `ProcessID`), `SharpShell` (inline C# execution)
`CompatibleDotNetVersions`: `Net35, Net40` for most; `Net35, Net40, NetCore31` for the control tasks (`Help`, `Exit`, `Tasks`, `TaskKill`, `Delay`, `Jitter`, `ConnectAttempts`, `KillDate`).

### 5.2 `DotNetCore.yaml` — 13 tasks `[source]` — all `NetCore31`
`ListDirectory`, `Assembly` (params to EntryPoint), `ShellCmd`, `Shell`, `WhoAmI`, `ChangeDirectory`, `ReadTextFile`, `CreateDirectory`, `Delete`, `Copy`, `ProcessList`, `Download`, `Upload`

### 5.3 `SharpSploit.Credentials.yaml` — 15 tasks `[source]` — author `cobbr_io`
`MakeToken` (**TokenTask=true**), `GetSystem` (**true**), `ImpersonateProcess` (**true**), `ImpersonateUser` (**true**), `BypassUACGrunt`, `BypassUACCommand`, `RevertToSelf` (**true**), `LogonPasswords`, `LsaSecrets`, `LsaCache`, `SamDump`, `Wdigest`, `DCSync`, `Mimikatz`, `SafetyKatz`

`MakeToken` option set (representative of the credential tasks) `[source]`: `Username`, `Domain`, `Password`, `LogonType` with default `LOGON32_LOGON_NEW_CREDENTIALS` and the accepted set `INTERACTIVE | NETWORK | BATCH | SERVICE | UNLOCK | NETWORK_CLEARTEXT | NEW_CREDENTIALS`; unknown values return `"MakeToken failed. Invalid LogonType specified."`

### 5.4 `SharpSploit.Enumeration.yaml` — 16 tasks `[source]` — authors `cobbr_io`, `checkymander`
`GetNetSession`, `GetNetLoggedOnUser`, `GetNetLocalGroupMember`, `GetNetLocalGroup`, `GetDomainGroup`, `GetDomainUser`, `GetDomainComputer`, `Keylogger`, `Kerberoast`, `PortScan`, `ListDirectory`, `ProcessList`, `SetRegistryKey`, `GetRegistryKey`, `SetRemoteRegistryKey`, `GetRemoteRegistryKey`

### 5.5 `SharpSploit.Execution.yaml` — 9 tasks `[source]` — authors `cobbr_io`, `001SPARTaN`
`Shell`, `ShellCmd`, `ShellRunAs`, `ShellCmdRunAs`, `CreateProcessWithToken`, `PowerShell`, `Assembly`, `AssemblyReflect`, `ShellCode`

### 5.6 `SharpSploit.LateralMovement.yaml` — 6 tasks `[source]` — authors `cobbr_io`, `_RastaMouse`
`WMIGrunt`, `WMICommand`, `PowerShellRemotingGrunt`, `PowerShellRemotingCommand`, `DCOMGrunt`, `DCOMCommand`
(The `*Grunt` variants spawn a new implant remotely; the `*Command` variants execute a one-shot command.)

### 5.7 `SharpSploit.Persistence.yaml` — 4 tasks `[source]` — authors `_RastaMouse`, `den_n1s`
`PersistStartup`, `PersistCOMHijack`, `PersistWMI`, `PersistAutorun` (`PersistAutorun` takes `TargetHive`, `Name`, `Value`)

### 5.8 `SharpSploit.PrivilegeEscalation.yaml` — 1 task `[source]` — author `den_n1s`
`PrivExchange` (options `EWSUri`, `RelayUri`, `ExchangeVersion`)

### 5.9 `SharpSploit.Evasion.yaml` — 1 task `[source]` — author `_RastaMouse`
`BypassAmsi`

### 5.10 `GhostPack.yaml` — 6 tasks `[source]` — author `harmj0y`
`Rubeus`, `SharpDPAPI`, `SharpUp`, `SharpDump` (option `ProcessID`), `Seatbelt` (has extra `SuggestedValues` beyond the version list: `NetworkProfiles`, `NetworkShares`), `SharpWMI`

### 5.11 `SharpSC.yaml` — 1 task `[source]` — author `djhohnstein`
`SharpSC` (Windows service manipulation)

### 5.12 Hardcoded `.task` templates (`Data/Tasks/CSharp/netcoreapp3.0/`) — 7 files `[source]`
`Assembly.task` (10,286 B), `ChangeDirectory.task` (403), `ListDirectory.task` (7,522), `ProcessList.task` (7,065), `Shell.task` (4,366), `ShellCmd.task` (5,782), `WhoAmI.task` (331)
These are pre-written sources for the `DotNetCore.yaml` task set. **No `net35`/`net40` `.task` sources exist in the tree** — the .NET Framework tasks are supplied purely as YAML `Code:` blocks. `[source]`

### 5.13 Category rollup

| Category | Tasks | Count |
|---|---|---|
| Credential access / theft | LogonPasswords, LsaSecrets, LsaCache, SamDump, Wdigest, DCSync, Mimikatz, SafetyKatz, Kerberoast, Keylogger, MakeToken, LogonType abuse | 15 (Credentials) + Kerberoast/Keylogger |
| Token / privilege | GetSystem, ImpersonateProcess, ImpersonateUser, RevertToSelf, BypassUACGrunt, BypassUACCommand, PrivExchange | 7 |
| Lateral movement | WMIGrunt/WMICommand, PowerShellRemoting*, DCOMGrunt/DCOMCommand | 6 |
| Persistence | PersistStartup, PersistCOMHijack, PersistWMI, PersistAutorun | 4 |
| Execution | Shell, ShellCmd, ShellRunAs, ShellCmdRunAs, CreateProcessWithToken, PowerShell, Assembly, AssemblyReflect, ShellCode, SharpShell, Kill, Assembly | 12 |
| Enumeration / recon | Net*, Domain*, Seatbelt, SharpUp, PortScan, ProcessList, ListDirectory, WhoAmI, GetCurrentDirectory, Set/GetRegistryKey (+Remote) | 16 + 6 |
| File ops / transfer | Download, Upload, ReadTextFile, CreateDirectory, Delete, Copy, ChangeDirectory | 7 |
| Evasion | BypassAmsi | 1 |
| Control / C2 mgmt | Help, PowerShellImport, Connect, Exit, Tasks, TaskKill, Delay, Jitter, ConnectAttempts, KillDate, Disconnect | 11 |
`[inference]` on the rollup buckets; every task name itself is `[source]`.

---

## 6. Submodule Dependency Map

`.gitmodules` (8 submodules, all under `Covenant/Data/ReferenceSourceLibraries/`, all `ignore = dirty`): `[source]`

| Submodule | Upstream | Contributes |
|---|---|---|
| `Rubeus` | `github.com/GhostPack/Rubeus` | Raw Kerberos interaction/abuse → `Rubeus` task |
| `SharpSploit` | `github.com/cobbr/SharpSploit` | The **backbone library**: Credentials, Enumeration, Execution, LateralMovement, Persistence, PrivilegeEscalation, Evasion task families + `powerkatz` embedded DLLs |
| `SharpDPAPI` | `github.com/GhostPack/SharpDPAPI` | DPAPI credential decryption → `SharpDPAPI` task |
| `SharpUp` | `github.com/GhostPack/SharpUp` | PowerUp-equivalent privilege checks → `SharpUp` task |
| `Seatbelt` | `github.com/GhostPack/Seatbelt` | Host survey/"safety checks" → `Seatbelt` task |
| `SharpDump` | `github.com/GhostPack/SharpDump` | `Out-Minidump.ps1` port → `SharpDump` task |
| `SharpWMI` | `github.com/GhostPack/SharpWMI` | WMI functionality → `SharpWMI` task |
| `SharpSC` | `github.com/djhohnstein/SharpSC` | Service control → `SharpSC` task |
`[source]`

`DbInitializer.cs` seeds the corresponding `ReferenceSourceLibrary` records with **exactly these descriptions** (`SharpSploit`, `Rubeus`, `Seatbelt`, `SharpDPAPI`, `SharpDump`, `SharpUp`, `SharpWMI`, and `SharpSC`), and a **commented-out `SharpChrome`** entry:

```csharp
// new ReferenceSourceLibrary { Name = "SharpChrome", Description = "SharpChrome is a C# port of some
//     Mimikatz DPAPI functionality targeting Google Chrome.",
//     Location = Common.CovenantReferenceSourceLibraries + "SharpDPAPI" + Path.DirectorySeparatorChar
//              + "SharpChrome" + Path.DirectorySeparatorChar, },
```
`[source]` — a disabled capability. `SharpChrome` would have added browser-credential theft on top of DPAPI; it is present as a submodule-adjacent path (`SharpDPAPI/SharpChrome/`) but never registered.

**Verification of the submodule state `[source]`:** all eight directories exist but contain **0 entries** each — uninitialized, as instructed. `ReferenceSourceLibraries: []` is **empty in all 11 task YAMLs** `[source]`, so the library→task linkage is realized at *compile* time by the `using` directives inside each task's inline `Code:` (e.g. `using SharpSploit.Credentials; using SharpSploit.Execution;`) resolving against the ReferenceSourceLibrary's source paths, not by an explicit YAML field. `[inference]`

**Reference assemblies** shipped as build inputs: `Data/AssemblyReferences/net35/` (18 DLLs) and `net40/` (~18 DLLs) — `mscorlib`, `System`, `System.Core`, `System.Data`, `System.Data.DataSetExtensions`, `System.DirectoryServices{,.Protocols,.AccountManagement}`, `System.Management{,.Automation}`, `System.Security`, `System.ServiceProcess`, `System.Web.Extensions`, `System.Windows.Forms`, `System.XML`, `System.Configuration.Install`, `System.Drawing`, `System.IdentityModel`. `[source]` These are exactly the BCL surfaces the 95 tasks compile against.

**Embedded resources** (`Data/EmbeddedResources/`): `SharpSploit.Resources.powerkatz_x86.dll` (936,960 B) and `SharpSploit.Resources.powerkatz_x64.dll` (986,624 B) `[source]` — native credential-dumping payloads shipped inside the tree.

---

## 7. Compiled Assemblies Found — Decompilation Findings

### 7.1 Headline answer to the compiled-artifact question

**No Covenant-built assembly exists anywhere on disk.** `[source]`

- `Covenant/Data/Tasks/CSharp/Compiled/{net35,net40,netcoreapp3.0}/.gitignore` — content is exactly `*` + `!.gitignore` (16 B). All runtime-built task assemblies are gitignored and absent. `[source]`
- `RE_Library/02_BINARIES/havoc_BUILDFROM_SOURCE/` contains **only `README.md` (307 B)** stating the folder "stays empty until you build it." No Covenant artifacts. `[source]`
- A recursive PE sweep of `RE_Library` found 199 `.exe`/`.dll`; filtering to the Covenant tree yields **11 files**, of which only the `refs/` set are managed.

Therefore a **source-vs-bytecode divergence analysis of Covenant's own code is impossible from this tree** — recorded as a residual unknown (§8), not fabricated.

### 7.2 The 9 genuine .NET CLI assemblies (all in `Covenant/refs/`)

CLI-header probe (data-directory index 14, RVA non-zero = managed) `[compiled-artifact]`:

| Assembly | Bytes | CLI header | Types |
|---|---|---|---|
| `Confuser.Core.dll` | 178,688 | rva=0x2008 size=72 | 180 |
| `Confuser.DynCipher.dll` | 47,104 | rva=0x2008 size=72 | 61 |
| `Confuser.MSBuild.Tasks.dll` | 12,288 | rva=0x2008 size=72 | 6 |
| `Confuser.Protections.dll` | 135,168 | rva=0x2008 size=72 | 160 |
| `Confuser.Renamer.dll` | 313,344 | rva=0x2008 size=72 | 148 |
| `Confuser.Runtime.dll` | 45,056 | rva=0x2008 size=72 | 54 |
| `dnlib.dll` | 1,144,320 | rva=0x2008 size=72 | 860 |
| `Donut.dll` | 50,688 | rva=0x2008 size=72 | 37 |
| `PeNet.dll` | 152,576 | rva=0x2008 size=72 | 166 |

Decompiled with `ilspycmd 9.1.0.7988` → `07_OUTPUT/extractions/T2/refs_decompiled/`. `[compiled-artifact]`

The two `EmbeddedResources` powerkatz DLLs are **`PE-NO-CLI`** — native, not managed. `[compiled-artifact]`

**Note on `Covenant.csproj`:** the project references `Confuser.Core`, `Confuser.DynCipher`, `Confuser.MSBuild.Tasks`, `Confuser.Protections`, `Confuser.Renamer`, `Confuser.Runtime`, `dnlib`, `PeNet`, `Donut` via `HintPath refs\`. `[source]` So this is a **vendored, pinned dependency set** delivered as binaries — the only compiled code in the repository.

### 7.3 Bytecode-vs-source verification

**Donut — verified, no divergence** `[compiled-artifact]`:

Decompiled `Donut.Structs.DonutConfig`:
```csharp
public struct DonutConfig { public int Arch; public int Bypass; public string Domain;
    public string Class; public string Method; public string Args;
    public string InputFile; public string Runtime; public string Payload; public string URL; }
```
This field set **exactly** matches the initializer in `ShellCodeLauncher.cs`. Decompiled `Constants` confirms the call-site magic numbers:
- `DONUT_ERROR_SUCCESS = 0` → matches `ret == Constants.DONUT_ERROR_SUCCESS` guard
- `DONUT_ARCH_X84 = 3` → **confirms `Arch = 3` is dual-arch x86/x64**, not x64-specific
- `DONUT_BYPASS_CONTINUE = 3` → **confirms `Bypass = 3` means AMSI/WLDP bypass is continued regardless of failure**
- `CIPHER_BLK_LEN = 16`, `DONUT_KEY_LEN = 16` → Donut's own Maru cipher parameters (`MARU_BLK_LEN=16`, `MARU_HASH_LEN=8`, `MARU_IV_LEN=8`)
- Runtime strings present: `DONUT_RUNTIME_NET2 = "v2.0.50727"`, `DONUT_RUNTIME_NET4 = "v4.0.30319"` (the latter is the exact string the scriptlet launchers inject via `COMPLUS_Version`)
- `PAYLOAD_EXE_x86` / `PAYLOAD_EXE_x64` static byte arrays are the **embedded Donut loader shellcode** (decompiled as `Donut.Payloads.payload_exe_x86` 36,191 B and `payload_exe_x64` 38,818 B of C# source, i.e. very large literal byte arrays) — this is the actual position-independent loader that Covenant ships inside the server. `[compiled-artifact]`

Decompiled `Generator`: entry point is `Donut_Create(ref DonutConfig args)` → `Helper.ParseArguments` → `Donut_Create(ref DSConfig)` → `Helper.ParseConfig` → `CreateModule` → `CreateInstance` → `GenerateOutput`, with `Marshal.FreeHGlobal(config.pic)` on the way out. `[compiled-artifact]` The hardcoded API resolution set is visible in `Constants` (`ntdll`, `kernel32`, `advapi32`, `crypt32`, `mscoree`, `ole32`, `oleaut32`, `wininet`, `combase`, `user32`, `shlwapi`) plus the CLR GUIDs (`xCLSID_CorRuntimeHost`, `xIID_ICorRuntimeHost`, `xCLSID_CLRMetaHost`, `xIID_ICLRMetaHost`, `xIID_ICLRRuntimeInfo`, `xIID_AppDomain`, `xCLSID_VBScript`, `xCLSID_JScript`, `xCLSID_DOMDocument30`, …) — i.e. the loader can run managed assemblies and also VBS/JS/XSL modules. `[compiled-artifact]`

**ConfuserEx — verified** `[compiled-artifact]`: `Confuser.Runtime.dll` decompiles to the protector's runtime payload, confirming what Covenant can apply to generated implants: `AntiDebugAntinet.cs` (25,701 B), `AntiDebugWin32.cs`, `AntiDebugSafe.cs`, `AntiDump.cs`, `AntiTamperAnti.cs`, `AntiTamperNormal.cs`, `AntiTamperJIT.cs` (16,940 B, with `ICorJitInfo`/`ICorMethodInfo`/`compileMethod`/`getJit` COM interop structs — **JIT-hooking anti-tamper**), `Compressor.cs`, `CompressorCompat.cs`, `Constant.cs`, `Lzma.cs` (16,859 B — LZMA resource compression), `RefProxyKey.cs`, `RefProxyStrong.cs`, `Resource.cs`, `Resource_Packer.cs`, `Mutation.cs`, `CFGCtx.cs`. `[compiled-artifact]`

`Confuser.MSBuild.Tasks.dll` decompiles to `ConfuseTask.cs`, `CreateProjectTask.cs`, `MSBuildLogger.cs` — the MSBuild integration, i.e. **Covenant can invoke ConfuserEx as a build step** over generated implants. `[compiled-artifact]`

**PeNet — verified** `[compiled-artifact]`: 166 types covering full PE parsing (`PeFile`, `PeValidator`, `NativeStructureParsers`, `DotNetStructureParsers`, `DataDirectoryParsers`, `Structures/IMAGE_*`), `Authenticode/SignatureInformation`, `ImpHash`, `PatternMatching`, and DN metadata tables (`MetaDataTables/Tables.cs`, `Assembly`, `AssemblyRef`, `TypeDef`, `TypeRef`, …). This is the server-side binary inspection capability — used for operator inspection of PE artifacts and (in the ConfuserEx integration) rewrite validation.

**dnlib — verified** `[compiled-artifact]`: 860 types, the standard .NET module read/write library underpinning both ConfuserEx and PeNet's managed-metadata path.

**No divergence found between source call-sites and compiled callee signatures** across the three assemblies Covenant actually calls into (`Donut`), guards with (`PeNet`), or rewrites with (`Confuser*`, `dnlib`). `[compiled-artifact]`

### 7.4 Operationally significant compiled findings

1. **Covenant ships a full Donut loader as a binary dependency**, not source — the embedded `payload_exe_{x86,x64}` PIC shellcode plus AMSI/WLDP bypass and CLR GUID set are present in `Donut.dll` on disk. `[compiled-artifact]`
2. **ShellCode launcher defaults to `Bypass = 3` (`CONTINUE`)** — it proceeds with execution even if the AMSI bypass attempt fails. `[compiled-artifact]` + `[source]`
3. **`Arch = 3` produces a dual-arch payload**, so a single `.bin` runs on both x86 and x64 targets. `[compiled-artifact]`
4. **ConfuserEx runtime anti-tamper includes a JIT hook** (`AntiTamperJIT`) and **LZMA-compressed resource packing** — available to Covenant for generated implant protection. `[compiled-artifact]`
5. `Covenant.Covenant.csproj`'s `HintPath`-based dependency on these six Confuser assemblies means **the protection capability is compiled into the server**, not an optional external tool. `[source]`

### 7.5 Compiled artifacts that do NOT exist

- No `Covenant.dll`, no launcher EXEs, no stager DLLs, no compiled `.task` assemblies, no `covenant.db`, no generated `.pfx`. `[source]`
- The 36 `Data/AssemblyReferences/{net35,net40}` DLLs are **input** BCL reference assemblies, not Covenant output. `[source]`

---

## 8. Residual Unknowns

Explicitly unresolved; each is a gap in this pass, not a claim of absence.

1. **Covenant bytecode-vs-source divergence is unverifiable.** No Covenant-built assembly exists on disk (§7.1). Any statement about how the built server differs from source would require the operator to build it. `[source]`
2. **`Data/Profiles/TCPBridgeProfile.yaml` (5,630 B) was not byte-dumped.** Its transforms, `ReadFormat`/`WriteFormat`, GUID transport and messenger code are unread. `[source]`
3. **`InternalListener.cs` L1–405 and L890–955 not read in full this pass.** Specifically unexamined: the `OnNewMessage` event plumbing, `PushCache`/`GetGruntForGuid`/`CheckInGrunt`/`MarkTasked` internals, the `GruntMessageCacheInfo` lifecycle, and lines 890–955 (which include `ProfileTransformAssembly`). `[source]`
4. **`InternalListener.Read`/`InternalRead` L324–408** — the cache-pop and SignalR-side read path — not read in full. `[source]`
5. **`CovenantService.cs` (255,768 B)** — the largest file — was not exhaustively read. Listener/grunt/task API endpoint surface is therefore mapped only through the generated `ICovenantAPI.cs`/`CovenantAPI.cs`, not through the service implementation. `[source]`
6. **`CovenantAPI.cs` (1,084,841 B) and `CovenantAPIExtensions.cs` (212,491 B)** were not enumerated endpoint-by-endpoint. The complete REST surface of the C2 is unlisted. `[source]`
7. **AES effective key size is not pinned in source.** `Aes.Create().GenerateKey()` sets no explicit `KeySize`, so the negotiated session key length is the runtime default. The actual key length cannot be stated from source alone. `[inference]`
8. **Jitter at default settings computes to zero.** `rnd.Next((int)Math.Round(Delay * Jitter/100))` with `Delay=5, Jitter=10` → `rnd.Next(1)` ≡ 0. Whether the intended default jitter is genuinely 0, or the integer truncation is an unintended bug, is not determinable from source. `[inference]`
9. **The `stream` reflection contract for streaming tasks is unnamed in documentation.** The grunt sets a property by reflection (`streamProp.SetValue(null, pipeClient, null)`) whose exact declared name/type on the task class was not extracted. `[source]`
10. **`UnsafeCompile` was observed as `false` on all 95 tasks**, so `allowUnsafe` paths in Roslyn are never exercised by the shipped library; whether any non-shipped task requires it is unknown. `[source]`
11. **Race condition acknowledged in source but not resolved:** the SMB connectTasking lookup walks all taskings for the latest `Connect` in `Progressed`/`Tasked` state, annotated `// TODO: … could cause race conditions`. Under concurrent SMB pivots this can mis-bind the egress path. `[source]`
12. **`ReferenceSourceLibraries: []` is empty in all 11 task YAMLs**, so the library→task binding is implicit via `using` directives at compile time. The exact resolver in `Compiler.cs` that maps a `using SharpSploit.*` to a `ReferenceSourceLibrary.Location` was not traced end-to-end. `[inference]`
13. **`SharpChrome` is seeded as a commented-out `ReferenceSourceLibrary`** with location under `SharpDPAPI/SharpChrome/`; the submodule list contains no `SharpChrome` entry, so that path would resolve to a nonexistent directory if the entry were enabled. `[source]`
14. **`CovenantHubService.cs` (47,196 B) SignalR hub surface** (`JoinGroup`, and the message types pushed to Blazor clients) not enumerated. `[source]`
15. **`NotificationService.cs` (17,001 B)** — its transport and payload shape were not read. `[source]`
16. **`Grunt.cs` and the remaining `Models/Grunts/*`** (beyond `ImplantTemplate`, `GruntTask`, `GruntTaskComponents`) not read; the full persisted grunt schema (including `GruntSharedSecretPassword` generation, `OriginalServerGuid` semantics, and `Integrity`/`Process` value domains) is only partially characterized. `[source]`
17. **The eight submodules remain uninitialized** by instruction, so all GhostPack/SharpSploit/SharpSC *library* internals are outside this pass. What each library *contributes* is mapped (§6) only at the task-and-description level. `[source]`
18. **`Brute.cs` (46,973 B), `BruteStager.cs` (15,407 B) and the `GruntBridge*` pair** were not read line-by-line; their exact cross-platform and bridge transport logic is characterized only from the `GruntSMB`/`GruntHTTP` siblings and the `Brute` implant description. `[source]`
19. **`CovenantHubService` / `InternalListener` SignalR authentication** — how `CovenantToken` is validated on `JoinGroup` was not traced. `[source]`
20. **No dynamic execution was performed.** Every behavioral claim in this report is static. Runtime validation (a built server, a live grunt, a captured handshake) is outside this pass. `[inference]`

---

### Appendix A — Files produced by this pass

- `07_OUTPUT/reports/T2_covenant.md` (this report)
- `07_OUTPUT/extractions/T2/refs_decompiled/` — ILSpy projects for `Donut`, `PeNet`, `Confuser.Runtime`, `Confuser.MSBuild.Tasks`; type listings for all nine `refs/` assemblies.

### Appendix B — Tooling

`ilspycmd 9.1.0.7988` / `ICSharpCode.Decompiler 9.1.0.7988` at `C:\Users\PC\.dotnet\tools\ilspycmd.exe` (note: `--help` exits 1 by design; the update banner prints to stdout and must be filtered; type listing requires one `-l <kind>` flag per invocation — `c,i,s,e,d` combined fails silently).
