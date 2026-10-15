# The Serious C2 / Post-Exploitation Landscape

Companion to `MANIFEST.md`. Same rule applies: everything listed as a *framework* is public
open source, cloneable, inert until compiled and deployed. Anything listed as a *sample repo*
is a placement op — VM only.

---

## Tier 1 — The ones people actually bring to real engagements

### 1. Cobalt Strike — the commercial benchmark
The paid tool the whole field is measured against. Not open source, no repo.
- **Beacon** payload, **Malleable C2 profiles** to disguise traffic as normal HTTP/DNS
- Reflective loader, XOR'd config (classic keys `0x69` / `0x2e`), watermark attribution
- Cracked copies are everywhere in ransomware crews — which is exactly why analysts
  learn to reverse it. The *legit* license is what red teams buy.
- **Why it matters:** the Malleable C2 profile format is a de-facto standard other
  frameworks now imitate. Understanding it is table stakes for network detection.

### 2. Brute Ratel C4 — the Cobalt Strike successor
Built by a former Mandiant/CrowdStrike red teamer specifically because CS was getting
caught. Commercial, tightly licensed.
- Badger agent, custom syscall execution, strong EDR evasion by design
- Notable legally: **leaked and pirated into the wild**, so detection work on it is real
- **Why it matters:** the most direct competitor to Havoc's evasion approach.

### 3. Sliver — already cloned (`c2/sliver`)
Open-source CS alternative, Go, multi-protocol (mTLS, WireGuard, HTTP, DNS). Community
default when teams won't buy CS.

### 4. Havoc — already cloned (`c2/havoc`)
Demon agent, indirect syscalls, Ekko/Zilean sleep obfuscation. The peer-reviewed
EDR-bypass study target.

### 5. Mythic — already cloned (`c2/mythic`)
Microservice C2, pluggable agents. The one to study if you care about *cross-platform*:
Rust (Apollo, Athena), Swift/macOS (Apfell), C# (Poseidon).

---

## Tier 2 — Same power, different shape

### 6. Empire / Starkiller
PowerShell + Python post-exploitation. **BC Security**, actively maintained. Its whole
pitch: fileless, in-memory, living-off-the-land — no compiled implant needed.
- PowerShell agents, C# agents, Python agents
- Fork of the original PowerShell Empire (dead) that stayed alive
- **Why it matters:** the definitive study of *script-based* tradecraft and AMSI/script-block
  logging bypass. Complementary to every .NET study you'd do on Covenant.

### 7. Nighthawk
Commercial. Very little public info by design — the vendor keeps a low profile.
- Known for extremely careful memory hygiene and call-stack spoofing
- **Why it matters:** exists mainly as a reminder that the *best* evasions are private,
  and public frameworks always lag them.

### 8. Silent Trinity / Brute Ratel-adjacent forks
Smaller commercial/leaked tooling in the same space. Not worth a deep study; know they exist.

---

## Tier 3 — Older, still-taught, still-cited

### 9. Merlin
Go C2 that tunnels over **HTTP/2 and HTTP/3**, actively maintained (Ne0nd0g).
- Interesting because most detections are built for HTTP/1.1
- Good modern-protocol RE target

### 10. Covenant — already cloned (`c2/covenant`, archived 2021)
.NET tradecraft history: Grunt, Roslyn in-memory compile, `Assembly.Load`, AMSI patching.
Still the best *teaching* codebase for CIL/CLR even though it's dead.

### 11. Pupy — already cloned (`c2/pupy`)
Reflective-DLL + embedded Python runtime. `.pyc` extraction from RAM.

### 12. Metasploit / Meterpreter — already cloned (`c2/metasploit`)
The classics: staged/stageless, `shikata_ga_nai`, TLV protocol.

### 13. Caldera (MITRE)
Not a C2 in the classic sense — an **automated adversary emulation** platform.
- ATT&CK-driven, plugin-based, red/blue team in one
- **Why it matters:** it's the bridge between "here's a tool" and "here's a full attack
  chain mapped to ATT&CK techniques." Best study target for defense design.

### 14. C3 (Custom Command and Control, C2Matrix)
**c2matrix.com** — not one tool, a *comparison matrix* of ~50 C2 frameworks, scored on
evasion, protocols, languages, and maturity. This is the actual "what are the other
powerful ones" answer, maintained as a live reference.
- **Clone/reference it first** if you want the complete landscape rather than my Tier 1.

---

## Tier 4 — Legit admin tools abused as C2 (living off the land)

These are *not* malware. They're also how modern intrusions actually move.

- **Cobalt Strike's *opposite*: legitimate RMM tools** — AnyDesk, TeamViewer, ScreenConnect,
  Atera, Splashtop. Heavily abused because they're signed and expected on networks.
- **PsExec / WMI / WinRM** — built-in Windows remote execution.
- **ngrok / cloudflared / reverse SSH tunnels** — legitimate tunneling turned C2 channel.
- **Why it matters:** you catch more real intrusions by knowing what *normal* looks like
  than by signature-matching frameworks.

---

## Mobile tier (beyond AhMyth)

| Tool | Platform | Note |
|---|---|---|
| AhMyth (`mobile/ahmyth`) | Android | cloned; classic tutorial target |
| AndroRAT (real one) | Android | **not cloned** — wrong repo, see manifest |
| SpyNote / CypherRat | Android | commercial-adjacent, heavily used in the wild |
| Pegasus (NSO) | iOS/Android | **not obtainable, not a repo** — zero-click, nation-state; study only via published forensic research |
| Predator (Intellexa) | iOS/Android | same category as Pegasus |
| Mobile C2 in Mythic (Apfell) | macOS/iOS | the legit RE path for Apple tradecraft |

---

## How to choose what to study

1. **Want the complete map first?** → c2matrix.com, then pick.
2. **Want EDR bypass at the lowest level?** → Havoc (cloned), then Brute Ratel writeups.
3. **Want script/fileless tradecraft?** → Empire/Starkiller.
4. **Want cross-platform (esp. macOS)?** → Mythic + Apfell.
5. **Want defense/ATT&CK alignment?** → Caldera.
6. **Want the historical baseline?** → Metasploit + Covenant (both cloned).

---

## Standing rules for this library

- Frameworks: clone freely, read freely, **do not build-and-run outside a snapshot VM.**
- Samples (MalwareBazaar, theZoo, malware-traffic-analysis): **VM only, no network back
  to the host.** Still not cloned.
- Commercial tools (Cobalt Strike, Brute Ratel, Nighthawk, Pegasus): **not obtainable as
  source.** Study via published analyses, not acquisition.

—docket
