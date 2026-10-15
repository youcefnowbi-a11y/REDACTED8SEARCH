# RE_Library — INDEX

Reverse-engineering library for the REDACTED platform.
Organized 2026-10-15. **Read this file first.**

---

## THE RULE

`01_SOURCE_*` and `02_BINARIES` are **safe on the host** — source code and official
release artifacts, inert until compiled and run.

`03_SAMPLES` is **VM only.** Live malware. Never extracted on the host. The folders
are currently empty placeholders on purpose — the fetchers live in
`00_START\FETCH_SAMPLES.md`.

---

## STRUCTURE

```
RE_Library/
│
├── 00_START/                     ← read first
│   ├── INDEX.md                  (this file)
│   ├── MANIFEST.md               clone record: HEADs, sizes, licenses
│   ├── LANDSCAPE.md              the wider C2 field (CS, BRc4, Empire, c3matrix)
│   ├── BINARY_SOURCES.md         where compiled binaries lawfully come from
│   └── FETCH_SAMPLES.md          sample fetchers — RUN IN VM ONLY
│
├── 01_SOURCE_c2/                 ← framework source, all git-cloned
│   ├── sliver/          BishopFox/sliver            8e5d2f9d   418 MB   Go
│   ├── mythic/          its-a-feature/Mythic        96b24b4     53 MB   Python/Docker
│   ├── havoc/           HavocFramework/Havoc        c84f775    8.8 MB   C/C++/ASM
│   ├── metasploit/      rapid7/metasploit-framework fa174ade   198 MB   Ruby
│   ├── pupy/            n1nj4sec/pupy               56b7aac    0.9 MB   Python
│   └── covenant/        cobbr/Covenant              5decc3c    0.1 MB   C#/.NET (archived 2021)
│
├── 01_SOURCE_mobile/             ← mobile RAT source
│   ├── ahmyth/          AhMyth/AhMyth-Android-RAT   97465b1    139 MB   Java/Node
│   └── androrat_WRONGREPO/  wishihab/Android-RATList cd0ffcc   ~0 MB   ⚠ NOT AndroRAT
│
├── 02_BINARIES/                  ← compiled artifacts (host-safe)
│   ├── sliver/          sliver-client_windows-amd64.exe      62.8 MB  v1.7.8
│   │                    + .minisig signature
│   ├── merlin/          merlinServer-Windows-x64.7z          65.6 MB  v2.2.2
│   └── havoc_BUILDFROM_SOURCE/   (empty — Havoc ships no releases)
│
├── 03_SAMPLES/                   ← 🔴 VM ONLY 🔴
│   ├── theZoo/          theZoo_families.csv — 789 families indexed (text only)
│   ├── MalwareBazaar/   (empty — needs abuse.ch Auth-Key)
│   └── malware-traffic-analysis/  (empty — manual download per post)
│
├── 04_TOOLS/                     ← analysis toolchain
│   ├── REA/             (MCP server — the installed one lives at
│   │                     C:\Users\PC\Desktop\.agent\rea, v6.4.0)
│   ├── ghidra/          (empty — install here or point at existing)
│   ├── x64dbg/          (empty — same)
│   └── emulation/       (empty — Unicorn/Qiling/Speakeasy for stubs)
│
├── 05_TARGETS/                   ← what to actually reverse
│   ├── REDACTED/        (your own app — START.exe / INSTALL.exe / STOP.exe)
│   └── practice/        (staging for binaries before analysis)
│
├── 06_NOTES/                     ← working notes, findings, offsets
│
└── 07_OUTPUT/                    ← results
    ├── reports/         written analyses
    ├── extractions/     recovered configs, strings, dumps
    └── configs/         decoded C2 profiles, beacon configs
```

---

## STATUS — what's actually present

| Shelf | State |
|---|---|
| Framework source | ✅ 8 repos, all git-verified |
| Release binaries | ✅ Sliver client + Merlin server |
| RE toolchain (REA) | ✅ installed at `Desktop\.agent\rea` |
| theZoo catalog | ✅ 789 families indexed (index only) |
| Malware samples | 🔴 0 — needs VM + abuse.ch key |
| Havoc compiled | 🔴 none exists — build from source |
| Cracked commercial | 🔴 out of scope — no source exists |

**Total on disk: 44,015 files, ~1006 MB**

---

## KNOWN ISSUES TO FIX

1. **`androrat_WRONGREPO` is not AndroRAT.** `wishihab/Android-RATList` is a curated
   *list* repo, two markdown files. Real targets: the 2012 original, or
   `karma9874/AndroRAT` (Python-3 rewrite).
2. **Havoc releases = zero.** `HavocFramework/Havoc` has no release tags at all.
   The source in `01_SOURCE_c2\havoc` is the deliverable. Build it or read it.
3. **Empire v7.0.2** has a release tag but no attached assets. Source only.
4. **Covenant archived April 2021.** Read-only value.
5. **`02_BINARIES\havoc_BUILDFROM_SOURCE` is intentionally empty** — a marker, not an error.

---

## BEFORE STARTING — the 3 things missing

1. **A VM** — VirtualBox/VMware, Windows 11 guest, **Host-only network**, snapshot labeled `CLEAN`
2. **An abuse.ch Auth-Key** — free, from `https://auth.abuse.ch/`
3. **The fetchers run inside the guest** — `00_START\FETCH_SAMPLES.md`

Source work can start now. Sample work cannot start until 1–3 are done.

---

## QUICK START (once VM exists)

```powershell
# 1. verify REA responds
npx rea-agents@latest --help

# 2. register it with your agent
npx rea-agents@latest setup

# 3. first target — a real compiled offensive binary, host-safe
#    (a stripped 63 MB Go binary; the ideal first RE exercise)
npx rea-agents@latest analyze-javascript-application `
  "C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\02_BINARIES\sliver"
```

Binary analysis of the Sliver client is the correct first exercise: it is on disk,
it is official, it is large enough to be non-trivial, and you have the **full Go
source next to it** in `01_SOURCE_c2\sliver` for ground-truth comparison.

—docket
