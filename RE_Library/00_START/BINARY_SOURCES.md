# Compiled-Binary Study Sources — Modern, Legally Obtainable

Companion to `MANIFEST.md` and `LANDSCAPE.md`.
Scope: **compiled/binary artifacts you can lawfully obtain and reverse**, current generation only.
Not included: crack sites, warez forums, pirated commercial tools, live malware samples.

---

## The one rule that governs this whole page

**You can always reverse what you can lawfully possess.**
Everything below is either open-source-licensed, freeware, vendor-published, or your own
licensed copy. Reversing any of it is standard security research and, in most
jurisdictions, explicitly protected for interoperability and analysis.

**What is *not* on this page, deliberately:**
- Pirated Cobalt Strike / Brute Ratel / Nighthawk builds — these circulate as *malware*
  (backdoored by whoever cracked them) and possession alone is a licensing violation.
- Crack sites, DDL forums, Telegram distros.
- Live malware samples — that stays in the `research/` folder, VM-only, still uncloned.

---

## 1. Official framework release binaries (open source → compiled, ready)

These projects ship **prebuilt binaries** on their GitHub Releases pages. No compiling,
no source reading required — you get the actual stripped, production-compiled artifact.

| Tool | Where | Artifact type | Why reverse it |
|---|---|---|---|
| **Sliver** | `github.com/BishopFox/sliver/releases` | server + implant binaries, all platforms | stripped Go binary, runtime type reconstruction |
| **Havoc** | `github.com/HavocFramework/Havoc/releases` | client + Demon payloads | the modern low-level evasion target |
| **Mythic** | Docker images + agent releases | per-agent binaries | multi-language agent comparison |
| **Merlin** | `github.com/Ne0nd0g/merlin/releases` | Go server/agent | HTTP/2 + HTTP/3 protocol RE |
| **Empire/Starkiller** | `github.com/BC-SECURITY/Empire/releases` | Python + PowerShell payloads | script tradecraft, AMSI bypass |

**This is the honest answer to "compiled, modern, not old."** Same tools as the cloned
repos, but the *shipped* binary form — which is what you'd actually find in the wild and
what you'd actually reverse.

---

## 2. Legitimate remote-admin / post-exploitation binaries (free or trial)

Real software, real licenses, genuinely abused in intrusions — so genuinely worth reversing.

| Software | Source | License | Note |
|---|---|---|---|
| **AnyDesk** | `anydesk.com` | Free for personal | Most-abused RMM in intrusions |
| **TeamViewer** | `teamviewer.com` | Free personal tier | Same category |
| **ScreenConnect / ConnectWise** | `connectwise.com` | Trial | Heavily abused by ransomware crews |
| **Splashtop** | `splashtop.com` | Trial | Same |
| **RustDesk** | `github.com/rustdesk/rustdesk` | **Open source, AGPL** | Also ships release binaries — fully reversible |
| **MeshCentral** | `github.com/Ylianst/MeshCentral` | **Open source, Apache-2.0** | Self-hosted RMM; studyable end to end |
| **ngrok** | `ngrok.com` | Free tier | Tunnel turned C2 channel |
| **cloudflared** | `github.com/cloudflare/cloudflared` | **Open source, Apache-2.0** | Same, plus releases |

**Why this list is stronger than the framework list for blue-team study:** these are
signed, expected, and present on legitimate networks. Reversing them teaches you what
*normal* looks like — which is how you actually catch an intrusion.

---

## 3. Vendor-published security tools (free, modern, legitimately reverse-able)

| Tool | Vendor | Note |
|---|---|---|
| **Sysinternals suite** | Microsoft | Process Explorer, Procmon, Autoruns — the RE toolbox itself |
| **Process Hacker / System Informer** | open source | Modern process/memory inspection |
| **x64dbg / x32dbg** | open source | The debugger; source + binaries both available |
| **Ghidra** | NSA, open source | The decompiler; study its own internals if you like |
| **Cuckoo / CAPE** | open source | Sandbox — CAPE ships full binaries and configs |
| **Volatility 3** | open source | Memory forensics; modern Python |

Reversing the *tools of the trade* is legitimate, encouraged, and there's no ceiling.

---

## 4. Hangar / lab platforms — legitimate environments that ship binaries

| Platform | What you get | Access |
|---|---|---|
| **Malware Traffic Analysis** (`malware-traffic-analysis.net`) | pcaps + the matching binaries, educational walkthroughs | Free, registration |
| **ANY.RUN** | Live sandbox, public analysis reports, downloadable tasks | Free tier |
| **Hybrid Analysis** (`hybrid-analysis.com`) | Free public sandbox, reports + hashes | Free |
| **Joe Sandbox** | Cloud sandbox, public reports | Free public reports |
| **VirusTotal** | 70+ engines, static analysis, memory screenshots | Free |
| **Triage** (`tria.ge`) | Public sandbox, modern sample reports | Free |
| **abuse.ch** / **Feodo Tracker** | C2 IP/domain blocklists (not binaries) | Free |

These give you **the artifact plus a report** — you can reverse the binary and check
your findings against a professional analysis. That's a legitimate study loop.

---

## 5. Legally-obtainable commercial C2 (the honest answer)

If you genuinely want to reverse Cobalt Strike, Brute Ratel, or Nighthawk, there is
exactly one clean path:

- **Buy the license.** Cobalt Strike requires a corporate/business identity and a real
  security engagement context. Brute Ratel requires similar vetting.
- The EULA may restrict reverse engineering — check it. Many commercial EULAs do.
- **Elsevier/legal reality:** in the EU, decompilation for interoperability is protected
  (Software Directive 2009/24/EC Art. 6); in the US it's a case-by-case fair-use question.
  Jurisdiction matters more than intent.

**What I will not do:** point you at a cracked build. They're backdoored routinely,
possession is a licensing violation, and downloading one is how researchers actually
get their own machines owned.

---

## 6. Where compiled modern software legitimately lives

For general "modern compiled software I can reverse" beyond security tooling:

- **GitHub Releases** — the single best source. Every serious project ships binaries.
- **Chocolatey / winget / Scoop** — package managers; install, then reverse the installed artifact.
- **Firmware/images** — vendor download pages for routers, cameras, IoT. Legal to obtain, rich RE target.
- **Microsoft Store / winget manifests** — signed modern Windows apps.
- **Docker Hub** — pull an image, extract the binaries.
- **Steam / game installs** — you licensed them; studying the anti-cheat is a known discipline.

---

## Summary — what to actually do

1. **Modern + compiled + legal, no friction** → GitHub Releases of the six frameworks already cloned. That's your "not old" shelf, right now.
2. **Modern + signed + real-world relevant** → RustDesk, MeshCentral, cloudflared, AnyDesk, ScreenConnect. These are what show up in actual intrusions.
3. **Artifact + professional analysis side by side** → malware-traffic-analysis.net, Triage, Hybrid Analysis. Free.
4. **Commercial tools** → license them, or study published analyses. No third path.
5. **Live malware samples** → `research/` folder, VM only, still not cloned.

---

## Updated standing rules

- **Open-source binary releases:** download, reverse, study — no restriction.
- **Commercial tool binaries:** licensed copy only. Cracks are out of scope, permanently.
- **Live malware samples:** disposable snapshot VM, no network to host. Still uncloned.
- **Everything you reverse stays on the analysis box, not the daily driver.**

—docket
