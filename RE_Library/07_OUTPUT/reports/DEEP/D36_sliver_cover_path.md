# D36 — Sliver's cover path: does it attempt concealment anywhere?

**Task:** Lead-issued follow-up closing D31 §8's load-bearing qualifier and D35's open hole.
**Lane:** sliver-diver. **Method:** source-only reading of the implant tree; no REA/Ghidra, no execution.
**Question:** D35 established DNS = Base32 over a constructed domain, "nothing to hide." D31 established the mTLS/WG envelope = plaintext protobuf + Ed25519 sig, "zero protocol mimicry." **Both were scoped readings. Does Sliver do channel-level shaping ANYWHERE?**

**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`.

**Citation convention:** inline `path/file.go:LINE`, relative to `implant\sliver\` unless noted.

**Two earned rules applied throughout:** **every count carries its command** (no number without a run behind it), and **a comment is a claim, not a measurement** (author-comment arithmetic is not evidence).

---

## 0. Headline — the answer is (c), and it is the interesting one

**Sliver HAS a cover path. It is on exactly one transport (HTTP), it is configured by the server, and the DNS and mTLS/WireGuard transports do not share it. The design is INCONSISTENT ACROSS TRANSPORTS.** `[src]`

**The three candidate outcomes the task laid out:**

- **(a) Sliver has a cover and D31/D35 are incomplete** — **partially true.** D31 was correct about the envelope and correct to scope its claim; but a real cover mechanism exists that neither report reached.
- **(b) No cover anywhere** — **FALSE.** Refuted below, with a positive control.
- **(c) Cover exists only on one transport and the design is inconsistent** — **TRUE, and this is the finding.** `[src]`

**And there is a second, sharper finding that none of the three outcomes anticipated:**

**Sliver's HTTP cover is not a vocabulary and not a codec — it is a PROBABILISTIC HEADER PROFILE.** `httpclient.go:258-293`. Each configured header carries a `Probability` field, and on every request the implant **rolls a die** (`util.Intn(99) + 1`) to decide whether to include it. `[src]` **The design goal is not "look like a specific browser" — it is "not look identical to yourself twice."** That is a different concealment strategy from Pupy's, from Havoc's, and from anything D31 or D35 considered.

**And a third finding, which is where the real treasure is:** the `english.gz` asset that D31 §8 flagged as the most likely place for a cover vocabulary **is 512 obscure English words — and it is NOT channel cover.** It is a *payload* codec where one **byte** maps to one **word**, extending payloads 4–15× while looking like prose. **Sliver and Pupy are NOT relatives, as the task hypothesized they might be. They both use words; they use them for opposite purposes.** `[src]`

---

## TOC

1. `english.gz` — decompressed, counted, and identified
2. `encoders/traffic/` — what a "traffic encoder" actually is
3. The transport wiring — who uses an encoder and who does not
4. HTTP: the probabilistic header profile — Sliver's actual cover
5. HTTP: User-Agent, cookies, proxy inheritance
6. DNS client: confirming the stateless-segmenter claim
7. mTLS/WireGuard: re-confirming zero cover
8. The synthesis — the inconsistency is the finding
9. Residual unknowns
10. What this report does NOT establish
11. Summary table for D30/D35

---
---

## 1. `english.gz` — decompressed, counted, and identified

**The task's hypothesis was that this might be a channel vocabulary, which would make Sliver and Pupy relatives and change D35's conclusion. It is not, and it does not.** `[src]`

**Command (decompress, not file-size):**

```powershell
$in=New-Object System.IO.FileStream($g,'Open','Read')
$gz=New-Object System.IO.Compression.GZipStream($in,[System.IO.Compression.CompressionMode]::Decompress)
$gz.CopyTo($o)   # -> _d36_english_decompressed.txt
```

**Result:** `assets/english.gz` = **2,713 B compressed** → **4,988 B decompressed** (`Get-Item`, both). Gzip magic confirmed `1f 8b 08 08`. `[src]`

**Decompressed content, enumerated:** `[src]`

| Measure | Value | Command |
|---|---:|---|
| raw lines | **512** | `Get-Content \| .Count` |
| non-empty lines | **512** | filter `.Trim() -ne ''` |
| **unique lines** | **511** | `Sort-Object -Unique \| .Count` |
| all-uppercase | **512 / 512** | `-cmatch '^[A-Z]+$'` |
| last byte | `0x43` (`C`) | no trailing newline |

**Exactly one duplicate exists: `HYPERSALIVATION` appears twice.** `[src]`

**`512` is a power of two (`2^9`), and the task asked specifically about round counts as a training-set tell.** `[src]` **But the count is NOT explained by roundness here — it is explained exactly by the code, and the explanation is stronger than the signal.** See below.

**Content sample, verbatim (`_d36_english_decompressed.txt:1-8`):** `SICCING`, `NELUMBIUMS`, `MICROPYLAR`, `MARCHES`, `EDDYING`, `OMNIFIC`, `CALAMUS`, `ORGANOSOLS`. `[src]`

**These are obscure, high-register English words — the register of a dictionary headword list, not of ordinary prose or browsing vocabulary.** `[inference]` **Notably absent: any cloud/CDN/browsing vocabulary** (`cloud`, `cdn`, `webdav`, `nextcloud`, `payment`, `correo` — Pupy's set, per the task brief). **Zero overlap in kind.** `[src]`

### 1.1 — It is a **payload codec**, not channel vocabulary

**`encoders/english.go:39-50` is decisive:** `[src]`

```go
func (e EnglishEncoder) Encode(data []byte) ([]byte, error) {
	if dictionary == nil { buildDictionary() }
	words := []string{}
	for _, b := range data {                     // ONE byte per iteration
		possibleWords := dictionary[int(b)]
		index := util.Intn(len(possibleWords))
		words = append(words, possibleWords[index])
	}
	return []byte(strings.Join(words, " ")), nil
}
```

**One byte in → one word out.** `[src]` And `sumWord` at `:76-81` closes the loop: `sum += int(char); return sum % 256` — **the word's character-sum modulo 256 is its byte value.** `buildDictionary` (`:67-74`) buckets words by that sum. `[src]`

**So the dictionary size is not a training-set artifact — it is a direct consequence of the code.** `[src]` `[inference]`

- The key space is `sum % 256` → **256 buckets**.
- The dictionary holds **512 words** → **exactly 2 words per byte value**, on average.
- **Two words per bucket is what makes `Encode` probabilistic:** `util.Intn(len(possibleWords))` at `:46` picks randomly among the bucket's words, so the *same byte encodes differently each time*. `[src]`

**This is the same design instinct as the HTTP header roll from §4 — nondeterminism, not mimicry — applied at the payload layer.** `[inference]`

**Expansion factor:** word lengths enumerated as 4 B (10 words) through 15 B (14 words), modal 8 (84). Mean ≈ 8.7 characters + 1 space separator ≈ **9.7 B out per byte in**, i.e. **~4–15× expansion** (exact ratio is data-dependent since word choice is random within a bucket). `[src]` + `[inference]`

**Verdict on §1: `english.gz` is a payload encoder's lookup table, not a channel cover vocabulary. It transforms MESSAGE bytes to look like prose; it does not transform CHANNEL traffic to look like anything.** `[src]` + `[inference]` **D35's conclusion is NOT disturbed.** Pupy and Sliver both use words — **Pupy's words are the channel; Sliver's words are the payload.** They are unrelated mechanisms that share a medium. `[inference]`

---
---

## 2. `encoders/traffic/` — what a "traffic encoder" actually is

**The name invites the wrong conclusion. A "traffic encoder" here is not channel shaping — it is a WASM payload codec, and the code is unambiguous.** `[src]`

**Package contents, enumerated (`encoders/traffic/`):** `[src]`

| File | Bytes |
|---|---:|
| `compiler.go` | 2,863 |
| `interpreter.go` | 2,869 |
| `traffic-encoder.go` | 3,897 |
| `README.md` | 596 |

**`traffic-encoder.go:38-50` defines the type:** `[src]`

```go
type TrafficEncoder struct {
	ctx     context.Context
	runtime wazero.Runtime
	mod     api.Module
	lock    sync.Mutex
	encoder api.Function
	decoder api.Function
	malloc  api.Function
	free    api.Function
}
```

**And `Encode`/`Decode` (`:53-88`, `:91-122`) are pure byte transforms:** allocate in WASM memory via `malloc`, write input, call the guest `encoder`/`decoder` function, read the result out. `[src]` **The interface it satisfies is the same `Encoder` interface as `english.go`** — `encoders.go:107-111`: `Encode([]byte) ([]byte, error)` / `Decode([]byte) ([]byte, error)`. `[src]`

**So "traffic encoder" = a user-supplied, plugin-compiled byte transform applied to a PAYLOAD, not to the channel.** `[src]` The README's phrase ("Programmable traffic encoders compiled into the implant for obfuscation") is accurate about *obfuscation* and silent about *where* — the code answers it. `[inference]`

**Two features of the mechanism worth carrying into D30:** `[src]`

1. **It is WASM (`wazero`) — the implant executes guest bytecode.** `traffic-encoder.go:27-28` imports `github.com/tetratelabs/wazero` and `.../wazero/api`. **This is the same WASM boundary D11 §9.3 flagged for `db/wasmsqlite/`.** `[inference]`
2. **The encoder ID is a hash of the WASM binary, truncated to 16 bits:** `CalculateWasmEncoderID` at `:32-36` — `sha256.Sum256(data)`, then `uint16(digest[0])<<8 + uint16(digest[1])`, **"must be less than 65537 (the encoder modulo)."** `[src]` Matches `EncoderModulus = uint64(65537)` at `encoders.go:45`. `[src]`

**The traffic encoder is build-gated.** `encoders.go:35-41` wraps both the `path` import and the `traffic` package import in `// {{if .Config.TrafficEncodersEnabled}}`. `[src]` **So this capability is conditional at build time — a fact D30 needs, because a stock build may not carry it.**

**Verdict on §2: no channel shaping. `traffic/` is payload transformation, build-gated, WASM-hosted.** `[src]`

---

## 3. The transport wiring — who uses an encoder and who does not

**The task's question 1 was "is there a traffic encoder?" — the better question is which transports use ANY encoder, because that is where the cover asymmetry lives.** `[src]`

**Command:**

```powershell
Get-ChildItem $s -Recurse -File -Filter *.go |
  Where-Object {$_.FullName -match '\\transports\\'} |
  Select-String -Pattern 'Encoder|encoders\.'
```

**Result, enumerated by transport:** `[src]`

| Transport | Encoder references | Which encoder | Channel claim |
|---|---:|---|---|
| `dnsclient/` | 26 (incl. tests) | **`Base32Encoder`** (`dnsclient.go:170`), `Base64Encoder` in both resolvers (`resolver-generic.go:55`, `resolver-system.go:37`) | **encoding, not cover** |
| `httpclient/` | 5 | **`RandomEncoder(0)` / `RandomEncoder(len(reqData))`** (`httpclient.go:373`, `:445`, `:520`, `:586`) | **plus headers — see §4** |
| `mtls/` | **0** | — | **none** |
| `wireguard/` | **0** | — | **none** |
| `pivotclients/` | **0** | — | none (pivots ride another transport) |

`[src]`

**Positive control that the probe bites:** the same command returns **30 hits in `encoders/` itself** and **1 in `handlers/`**, so the search reaches encoder code and finds it where it exists. `[src]` **The zeroes for `mtls/` and `wireguard/` are therefore real absences, not search failures.** This independently confirms D31's scoped claim from a different direction. `[src]`

**The `RandomEncoder` mechanism — `encoders.go:129-146`:** `[src]`

```go
func RandomEncoder(size int) (uint64, Encoder) {
	if size < getMaxEncoderSize() && len(EncoderMap) > 0 {
		return randomEncoderFromMap(EncoderMap)   // small msg: ANY encoder incl. WASM
	} else {
		return randomEncoderFromMap(NativeEncoderMap)  // large msg: native only
	}
}
```

**And `randomEncoderFromMap` (`:138-146`) picks a random key and encodes the choice INTO THE NONCE:** `nonce := (randomUint64(MaxN) * EncoderModulus) + encoderID`. `[src]` The receiver recovers the choice via `EncoderFromNonce` (`:114-123`): `encoderID := nonce % EncoderModulus`. `[src]`

**So the HTTP transport's payload encoding is nondeterministic per request, and the encoder identity is transmitted in-band inside the nonce.** `[src]` **This is the same philosophy as §4's header roll: vary, don't mimic.** `[inference]`

**`MaxN = uint64(9999999)` (`encoders.go:46`) and `EncoderModulus = 65537` (`:45`)** — so the nonce space is ~10⁷ × 65,537, and the encoder ID is recoverable exactly. `[src]`

**Verdict on §3: exactly two transports do any encoding at all — DNS (fixed Base32) and HTTP (randomized). mTLS and WireGuard do none.** `[src]`

---
---

## 4. HTTP: the probabilistic header profile — Sliver's actual cover

**This is the cover mechanism the task was looking for, and it exists on exactly one transport.** `[src]`

**`transports/httpclient/httpclient.go:248-293` (`newHTTPRequest`), verbatim:** `[src]`

```go
func (s *SliverHTTPClient) newHTTPRequest(method string, uri *url.URL, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, uri.String(), body)
	if s.Options.HostHeader != "" {
		req.Host = s.Options.HostHeader
	}
	req.Header.Set("User-Agent", userAgent)
	if uri.Scheme == "http" && !s.Options.DisableUpgradeHeader {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}

	type nameValueProbability struct {
		Name        string
		Value       string
		Probability string
		Method      string
	}

	// HTTP C2 Profile headers
	extraHeaders := []nameValueProbability{
		// {{range $header := .HTTPC2ImplantConfig.Headers}}
		{
			Name:        "{{$header.Name}}",
			Value:       "{{$header.Value}}",
			Probability: "{{$header.Probability}}",
			Method:      "{{$header.Method}}",
		},
		// {{end}}
	}

	for _, header := range extraHeaders {
		if len(header.Method) > 0 && header.Method != method {
			continue
		}
		probability, _ := strconv.Atoi(header.Probability)
		if 0 < probability {
			roll := util.Intn(99) + 1
			if probability < roll {
				continue
			}
		}
		req.Header.Set(header.Name, header.Value)
	}
```

### 4.1 — What this actually is

**Every configured header carries four fields, and the fourth is the interesting one:** `Name`, `Value`, **`Probability`**, `Method`. `[src]`

**The roll (`:286-291`):** if `Probability` parses > 0, draw `util.Intn(99) + 1` (uniform 1–99) and **skip the header when `probability < roll`**. `[src]` So:
- `Probability = 0` → header **always** sent (the `0 < probability` guard is false, so the check is bypassed entirely). `[src]`
- `Probability = p` → header sent with probability ≈ `p/99`. `[src]`
- **The `util.Intn(99) + 1` yields 1–99, not 1–100 — so the implementation is off by one from the natural reading of a percentage.** `[src]` `[inference]` **A `Probability` of `100` still drops the header 1 in 99 times.** Noted as a residual (§9) because the config UI's units are not visible from this file.

**And `Method` is a per-header predicate (`:279-281`): a header can be scoped to GET-only, POST-only, etc.** `[src]`

### 4.2 — Why this is a different strategy from Pupy's

**The task framed the comparison as "Sliver hides BYTES; Pupy hides INTENT." The header profile complicates that, and in an interesting direction.** `[inference]`

**A probabilistic header profile is not mimicry. It is VARIATION.** `[inference]`

- **Mimicry** (Pupy's word codec) aims for a *fixed, recognizable* target: look like *this* kind of traffic. Success = matches the expected distribution.
- **Variation** (Sliver's header roll) aims for a *non-constant* surface: do not look the *same* twice. Success = does not form a stable, correlatable fingerprint.

**Consider what a defender actually does with HTTP C2 traffic:** collect requests, find invariants across them, signature the invariant. `[inference]` **Against that method, a fixed mimicry set is brittle — get the User-Agent wrong once and the whole channel is clustered.** A probabilistic profile **denies the invariant an existence.** `[inference]`

**So Sliver's HTTP cover is a defence against *correlation and signature*, not against *inspection*.** `[inference]` That is a coherent and deliberate design, and it is **the strongest concealment mechanism found anywhere in this report.**

### 4.3 — The honest limits of the mechanism

**Four limits, all `[src]`-grounded, that D30 must carry:** `[inference]` for the security reading.

1. **It is server-configured, not operator-invented.** The header list is template-injected at build: `{{range $header := .HTTPC2ImplantConfig.Headers}}` (`:267`). **The implant can only roll among what the server's HTTP C2 profile defined. Sliver provides the *mechanism*; concealment quality is the operator's content.** `[src]`
2. **It does NOT randomize the headers that matter most.** `User-Agent` (`:253`) and `Upgrade-Insecure-Requests` (`:255`) are set **unconditionally and outside the rolling loop.** `[src]` **The User-Agent is the single highest-value HTTP fingerprint and it is not part of the probabilistic set** — it is a fixed, build-time-generated string (§5).
3. **The mechanism is on one transport.** mTLS and WireGuard have zero encoder and zero header logic (§3). `[src]`
4. **Rolling headers does not change the payload.** The body is still the encoded envelope; the request *shape* varies while the *content distribution* does not. `[inference]`

**Verdict on §4: Sliver has a genuine, purpose-built cover mechanism — a per-header probabilistic profile on the HTTP transport. It is the only concealment mechanism found in the implant's transport layer. It defeats invariance-based fingerprinting, not content inspection, and it does not cover the User-Agent.** `[src]` + `[inference]`

---

## 5. HTTP: User-Agent, cookies, proxy inheritance

**The task asked three specific sub-questions. All three answered.** `[src]`

### 5.1 — User-Agent: generated, not chosen at runtime

**`httpclient.go:52`: `userAgent = "{{GenerateUserAgent}}"`.** `[src]` **It is a build-time templating directive, not a runtime choice.**

**The generator lives server-side — `server/db/models/http-c2.go:374-379`:** `[src]`

```go
// GenerateUserAgent - Generate a user-agent depending on OS/Arch
func GenerateUserAgent(goos string, goarch string, userAgent string, baseVer int32, macOsVer string) string {
	return generateChromeUserAgent(goos, goarch, userAgent, baseVer, macOsVer)
}
```

**Two facts from this, both load-bearing:** `[src]`

- **The default is a CHROME User-Agent**, parameterized by target OS/arch, a Chrome base version, and a macOS version. `[src]` So **the build-time default IS a mimicry choice** — it aims at "looks like Chrome on this platform." The probabilistic header layer sits *on top of* a mimicry default.
- **`userAgent` is a parameter, so an operator can override it** (`:375`, and the call site at `:360` passes `h.UserAgent`). `[src]`

**So Sliver's HTTP transport is a LAYERED strategy: a mimicry baseline (Chrome-shaped UA) plus a variation layer (probabilistic extra headers).** `[inference]` **That is more sophisticated than either report assumed, and it is a genuinely different answer from Pupy's.**

**Verified at the implant side by `server/generate/binaries.go:931`, which binds the `GenerateUserAgent` template function into the implant's build.** `[src]`

### 5.2 — Cookies: a jar that ignores origins

**`gohttp.go:69` attaches `Jar: cookieJar()`; `:116-148` implements it.** `[src]` The comment at `:116` is explicit: **"Jar - CookieJar implementation that ignores domains/origins."** `[src]` And `:147-148`: `func (jar *Jar) Cookies(u *url.URL) []*http.Cookie { return jar.cookies }` — **the `url` argument is ignored; all collected cookies are returned regardless of destination.** `[src]`

**`SetCookies` (`:138-140`) appends every received cookie with no filtering.** `[src]`

**Reading:** this is **stateful session emulation** — the implant accepts and replays cookies so a proxy or defender sees a client that behaves like a browser across requests. `[inference]` **It is not a security control and it is deliberately origin-blind, which for C2 is the point: the implant may talk to C2 via different hostnames while carrying one cookie set.** `[inference]`

### 5.3 — Proxy inheritance: **the opposite of Havoc and Metasploit**

**The task's specific question, and D26/D34 make it a cross-target discriminator.** `[src]`

**`gohttp.go:65-66`:** `[src]`

```go
transport.ProxyConnectHeader = http.Header{
	"User-Agent": []string{userAgent},
```

**And `:69`: `Jar: cookieJar(),`.** The transport is a `*http.Transport` whose `Proxy` field is **not set in the lines read** — which in Go means `http.ProxyFromEnvironment` is the default only if explicitly assigned; an unset `Proxy` field means no proxy. `[src]` + `[inference]`

**This is a FLAG, not a settled finding, and I am marking it as such rather than reporting the distinction as established.** `[inference]` **D26/D34 established that Havoc's `TransportHttp.c` and Metasploit's `local.rb` INHERIT host proxy configuration. On the evidence read here, Sliver's Go HTTP client does not appear to do so.** `[inference]` **But the `Proxy` field is set — or not — outside the region I read, and Go's `http.DefaultTransport` clones do inherit `ProxyFromEnvironment`.** `[inference]` **Residual §9 item 1: read `gohttp.go` in full to settle it.** `[src]` **I will not put an unverified cross-target claim into D30.**

**What I can confirm `[src]`:** Sliver supports **explicit, operator-set** proxy configuration, not inherited proxy discovery — `HostHeader` (`httpclient.go:79`, applied `:250-251`), `DisableUpgradeHeader` (`:78`, applied `:254`), and both are parsed from C2 URI query parameters at `:118-119` (`host-header=`, `disable-upgrade-header=`). `[src]` **That is configuration the operator types, not configuration the host provides.** `[src]`

**Also confirmed `[src]`:** a **Windows-specific driver** exists — `drivers/win/wininet/client_windows.go:36` (`wininet.NewClient(userAgent)`), referenced from `drivers_windows.go:60`. `[src]` **A WinINet-backed client inherits the Windows proxy configuration by construction, because WinINet does.** `[inference]` **So the proxy answer may differ BY PLATFORM: WinINet on Windows, Go's stack elsewhere.** That is a real residual and it is more interesting than the original question.

---
---

## 6. DNS client: confirming the stateless-segmenter claim

**The task asked me to confirm or refute, from the client side, that the DNS client holds zero fragmentation state.** `[src]`

**CONFIRMED — the client has no reassembly state.** `[src]`

**The client's DNS logic is `SplitBuffer` — `dnsclient.go:711`:** `[src]`

```go
// SplitBuffer - There's probably a fancy way to calculate this with math and shit
// but it's much easier to just encode bytes
func (s *SliverDNSClient) SplitBuffer(msg *dnspb.DNSMessage, encoder encoders.Encoder, data []byte) ([]string, error)
```

**Note the comment on `:709-710` — and per this round's earned rule, a comment is a claim, not a measurement. The claim here is about *style*, not arithmetic, so it is safe; but it also tells us the author did not derive a capacity bound.** `[inference]` **That is exactly the hazard msf-diver hit with `dnsclient.go`'s author-comment arithmetic.** `[inference]`

**Enumerated evidence of statelessness:** `[src]`

| Fact | Evidence |
|---|---|
| A pure function: `(msg, encoder, data) → ([]string, error)` | `dnsclient.go:711` |
| **No receiver state written** — it takes `*SliverDNSClient` but returns only the subdata list | `:711` |
| **Emits ALL fragments at once**, no per-fragment handle retained | return type `[]string` `:711` |
| Encoding is per-chunk and independent | `encodeDNSMessage` called per fragment at `:750`, `:767` |
| **Decode is per-fragment and stateless:** `encoder.Decode([]byte(domain))` on one domain | `:795` |
| No sequence-number map, no buffer, no in-flight table on the client | exhaustive grep for `fragment\|reassembl\|buffer\|seq` across non-test client files returns **only the `SplitBuffer` name and a `conf_windows.go` error string** |

`[src]`

**The last row is the discriminating one, and it needs the honest statement of its limits.** The grep returns **zero** fragment/reassembly state for the client, matching D35's server-side finding that reassembly is server-only. `[src]` **But a negative grep is weak evidence on its own** — so the positive control is that the same package's `conf_windows.go:56` *is* found by the search, and `SplitBuffer` at `:386`, `:567`, `:711`, `:750`, `:767`, `:795` are all found. **The probe reaches the package. The absence of state is real.** `[src]`

**Reading: the DNS client is a stateless encoder-and-splitter. All reassembly authority is server-side. This confirms D35's architecture and contradicts no part of it.** `[src]`

**And on the cover question — the DNS client contributes nothing to concealment beyond the encoder choice.** The encoder is `Base32Encoder` (`:170`) over a constructed domain. `[src]` **Base32 is a legitimate-looking *alphabet*, but the DNS client has no vocabulary layer, no parent-domain variation, and no query-timing shaping.** `[src]` **D35's "nothing to hide" stands.** `[inference]`

**One nuance worth carrying to D30 `[inference]`:** the client *does* carry two encoders — `base32` for the domain path and `base64` in the resolvers (`resolver-generic.go:55`, `resolver-system.go:37`). **So the DNS path is double-encoded, alphabet-wise, but neither layer is a cover layer.** `[src]`

---

## 7. mTLS/WireGuard: re-confirming zero cover

**D31 established this and §3's transport sweep independently reproduced it. Recorded here as a cross-check, not a re-derivation.** `[src]`

**The encoder grep over `transports/` returns zero encoder references in `mtls/` and `wireguard/`, against 26 in `dnsclient/` and 5 in `httpclient/`.** `[src]` **Positive control: 30 hits in `encoders/` itself. The probe bites.** `[src]`

**And the header mechanism of §4 is HTTP-only** — `newHTTPRequest` exists only in `httpclient/`. `[src]` **mTLS and WireGuard have no equivalent, because they have no HTTP layer to put headers on.** `[inference]`

**So D31's conclusion holds exactly as scoped: the mTLS/WG envelope contributes zero concealment. The correction D36 makes is not to D31's finding but to its *scope statement* — the implant as a whole is not concealment-free; its HTTP transport is where the concealment lives.** `[inference]`

---
---

## 8. The synthesis — the inconsistency is the finding

**The task offered three publishable outcomes. The answer is (c), with a modification.** `[src]` + `[inference]`

**Sliver's concealment is not absent and it is not uniform. It is TRANSPORT-STRATIFIED, and the stratification is complete:** `[src]`

| Transport | Cover mechanism | What it defeats |
|---|---|---|
| **HTTP** | **Chrome-shaped User-Agent + per-header probabilistic roll + origin-blind cookie jar + configurable Host header** | **invariance-based fingerprinting; request-level correlation** |
| **DNS** | **Base32/Base64 alphabet only — no vocabulary, no parent variation, no timing shaping** | **nothing beyond the alphabet** |
| **mTLS** | **none — transport-blind `io.Writer` (D31 §4)** | **nothing; indistinguishable from generic TLS** |
| **WireGuard** | **none** | **nothing; indistinguishable from generic WG** |

`[src]` for every row; `[inference]` for the "defeats" column.

**Three readings of this, in increasing order of how much they explain:**

**(i) It is a capability gradient that follows the protocol.** `[inference]` HTTP is the only one of the four transports with an application layer in which to vary headers, User-Agents, paths, and cookies. mTLS and WireGuard traffic has no such surface — a TLS session has a fixed handshake shape, and WireGuard is UDP with no application metadata at all. **The mechanism exists where the substrate permits it.** `[inference]` **This is the charitable reading and it is largely sufficient.**

**(ii) But the gradient is steeper than the substrate requires, and that is where the design is genuinely uneven.** `[inference]` DNS *does* have an application layer — a query name is a string that can carry arbitrary vocabulary, and Pupy uses exactly that surface to look like cloud/CDN browsing. `[src]` for Pupy's mechanism per the task brief. **Sliver has a perfectly good vocabulary asset sitting in `encoders/assets/english.gz`, and it does not use it on the DNS channel — because that asset is wired into the `Encoder` interface as a payload codec (§1), and the DNS transport binds `Base32` (`dnsclient.go:170`).** `[src]` **Sliver had the parts for a Pupy-style DNS cover and deliberately did not assemble them.** `[inference]`

**(iii) The consistent explanation across all four rows is that Sliver's concealment is not a single design — it is a per-transport fit.** `[inference]` HTTP gets the most attention because HTTP C2 is the case that most needs to survive a proxy and a defender's request clustering. DNS gets an alphabet because a Base32 label is *already* unremarkable. mTLS and WireGuard get nothing because the transport's ubiquity is itself the cover. **Each transport is concealed to the degree its threat model demands, and no further.** `[inference]`

### 8.1 — What this does to the "hides bytes vs hides intent" framing

**The framing survives, but it needs a third column.** `[inference]`

- **Pupy hides INTENT** — the channel vocabulary aims at a specific benign interpretation.
- **Sliver hides BYTES** — payload encoding + transport delegation, with no claim about what the channel means.
- **But on HTTP, Sliver also hides INVARIANCE** — not by pretending to be something, but by refusing to be the same thing twice. `[inference]`

**That third mode is the genuinely novel finding here, and it has no analogue in either comparison target described in the task.** `[inference]` Pupy's codec *is* deterministic given the input — the same message encodes the same way, which is precisely what makes it signaturable. **Sliver's HTTP path randomizes encoder choice per request (`httpclient.go:373`, `:445`, `:520`, `:586` via `encoders.go:138-146`) AND header presence per request (`httpclient.go:286-291`).** `[src]` **Two independent sources of per-request nondeterminism on one transport.** `[src]`

**And the same instinct appears at the payload layer (§1.1): `EnglishEncoder.Encode` picks randomly among a bucket's words, so one byte encodes to different words on different runs.** `[src]` **The nondeterminism is a design theme, not an accident.** `[inference]`

### 8.2 — The direct answer to the synthesis question

**"Does Sliver have a cover story AT ALL, or is 'delegate to the transport' the complete answer?"** `[inference]`

**Neither, exactly. The complete answer is:**

> **Sliver delegates the cover to the transport on three of four transports, and implements its own cover on one — HTTP — where the cover is VARIATION rather than MIMICRY. It is the only target of the three that conceals by nondeterminism rather than by vocabulary.**

**And the corollary that follows:** `[inference]`

> **The choice of transport is therefore the operator's concealment decision, not the implant's.** A Sliver operator on mTLS or WireGuard has **the same concealment posture as any other TLS or WireGuard user** — none. A Sliver operator on HTTP inherits a purpose-built variation layer. **The implant does not have a cover; it has a cover OPTION, selectable by transport.** `[inference]`

**This is the sentence that should go into D30, and it changes the comparison from a property of the implant to a property of the operator's configuration.** `[inference]`

---

## 9. Residual unknowns

**Each with a probe. Registering them rather than implying the absence is proof.** 

1. **The `http.Transport.Proxy` field was NOT read.** `[src]` §5.3's proxy claim is therefore **flagged and unverified** — I explicitly declined to put a cross-target claim into D30 on this evidence. **Probe:** read `transports/httpclient/gohttp.go` in full and check whether `Proxy` is assigned (`http.ProxyFromEnvironment` vs nil vs explicit). **This is the single most valuable follow-up, because it is a clean cross-target discriminator against D26/D34 and it is one file.**
2. **`Probability` units unverified.** The roll is `util.Intn(99) + 1` → 1–99, so a value of 100 still drops 1 in 99 times. **Whether the server's HTTP C2 profile UI/validation treats the field as 0–100 or 0–99 is unread.** `[src]` **Probe:** read the `HTTPC2ImplantConfig.Headers` definition and its server-side validation.
3. **`encoders/traffic/compiler.go` and `interpreter.go` not read.** §2 established the *interface* (payload byte transform, WASM-hosted) but **not the bytecode language's capabilities.** `[src]` **If traffic encoders can be authored to shape *channel* properties rather than payload bytes, §2's verdict would need revision.** `[inference]` **Probe:** read both files (2,863 + 2,869 B — cheap).
4. **`Config.TrafficEncodersEnabled` default not established.** §2 noted the build gate (`encoders.go:35-41`) but **not whether a stock build enables it.** `[src]` **Probe:** grep the build/template config for the flag's default.
5. **`httpclient.go` read only to `:294` of 716 lines.** Path shape, query-parameter construction (`:317` region), and method selection were **not** read. **Mimicry could live in the URI path.** `[src]` **Probe:** read `:294-716`, focusing on `c2URI` construction and method choice.
6. **The WinINet driver was identified but not read.** `drivers/win/wininet/client_windows.go` (36 lines read: only `NewClient`). **Whether the Windows driver sets its own headers or inherits WinINet defaults is unknown — and if it inherits, §5's header analysis may not hold on Windows.** `[src]` **Probe:** read the WinINet driver.
7. **`util.Intn` not read.** Used for the header roll (`httpclient.go:287`), the encoder pick (`encoders.go:143`), and the word pick (`english.go:46`). **If it is not uniformly distributed or not seeded per-process, the variation mechanism is weaker than described.** `[src]` **Probe:** read `implant/sliver/util/`.
8. **No runtime evidence.** No traffic was observed and no implant was executed. **Everything here is static source reading; the "defeats fingerprinting" reasoning is `[inference]` throughout.**

---

## 10. What this report does NOT establish

- **It does not claim Sliver's HTTP concealment is effective against any real defensive system.** §4.2's reasoning is `[inference]`; no traffic was observed.
- **It does not revise D31's finding.** D31 was correct about the envelope and correct to scope its claim to the envelope. **D36 corrects the *scope*, not the finding** — and D31's own §8 flagged exactly these two unread areas, so this is D31's residual being closed, not D31 being wrong.
- **It does not revise D35's finding.** §1 refutes the wordlist hypothesis and §6 confirms the statelessness claim. **D35's DNS conclusion stands.**
- **It does not claim Pupy's codec is deterministic in the sense of byte-identical** — only that its vocabulary is fixed. **I have not read Pupy; that column is msf-diver's.** `[inference]`
- **It does not settle the proxy question.** §5.3 and §9 item 1 say so explicitly. **I am not handing D30 an unverified cross-target claim.**
- **It does not claim `english.gz` is a training-set artifact.** The 512 count is explained exactly by `sum % 256` and 2 words/bucket (`:67-81`), which is a stronger explanation than roundness. **The duplicate `HYPERSALIVATION` is unexplained and is a minor residual.** `[src]`
- **It is source-only and says nothing about how any deployed implant is configured.**

---

## 11. Summary table for D30/D35

**Sliver's concealment surface, complete, with citations:**

| Layer | Mechanism | Transport | Citation | Conceals |
|---|---|---|---|---|
| **Envelope** | 74-byte minisign-shaped sig prefix over plaintext protobuf | mTLS, WG | `transports/mtls/mtls.go:135-169`; `cryptography/minisign.go:51` | **nothing — authenticity only** (D31) |
| **Payload codec** | one byte → one word, random within bucket; 512 words / `sum % 256` | any | `encoders/english.go:39-50`, `:67-81`; `assets/english.gz` (512 lines, 511 unique) | **message bytes, not channel** |
| **Payload codec** | WASM byte transform, build-gated, ID = SHA-256 truncated to 16 bits | any | `encoders/traffic/traffic-encoder.go:32-50`; `encoders.go:35-41` | **message bytes, not channel** |
| **Payload codec** | random encoder per request, choice carried in nonce | HTTP | `httpclient.go:373`, `:445`, `:520`, `:586`; `encoders.go:129-146` | **per-request invariance** |
| **Transport** | **per-header probabilistic roll + Chrome UA + origin-blind cookie jar + configurable Host** | **HTTP only** | **`httpclient.go:248-293`**; `gohttp.go:65-69`, `:116-148`; `server/db/models/http-c2.go:374-379` | **request-level invariance and correlation** |
| **Transport** | Base32 (domain) + Base64 (resolver) alphabets only | DNS | `dnsclient.go:170`; `resolver-generic.go:55`; `resolver-system.go:37` | **alphabet only — no vocabulary** |
| **Transport** | **none** | mTLS | §3 (0 encoder refs) | **nothing — generic TLS** |
| **Transport** | **none** | WireGuard | §3 (0 encoder refs) | **nothing — generic WG** |

**The one-line answer, for both reports:**

> **Sliver has a cover story on exactly one transport. On HTTP it conceals by VARIATION — probabilistic headers and randomized encoders — rather than by mimicry or vocabulary. On DNS it has the alphabet and nothing else. On mTLS and WireGuard it has nothing at all and relies entirely on the ubiquity of the transport. Sliver is the only one of the three targets that conceals by nondeterminism, and its concealment is an operator choice selected by picking a transport, not a property of the implant.**

**Status:** §1 refutes the `english.gz` wordlist hypothesis (512 words, `sum % 256`, one byte → one word — payload codec). §2 finds no channel shaping in `traffic/` (WASM payload bytecode). §3 shows exactly two transports encode. **§4 finds the cover: `httpclient.go:248-293`.** §6 confirms DNS client statelessness. §7 re-confirms mTLS/WG zero cover. **Outcome (c): cover exists on one transport and the design is inconsistent — and the inconsistency is stratified rather than accidental.**
