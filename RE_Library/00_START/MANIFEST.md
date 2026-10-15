# RE_Library — Framework Source Manifest

Cloned: 2026-10-15 · shallow (`--depth 1`) · public open-source frameworks only
**No live malware samples were downloaded.** theZoo / MalwareBazaar were deliberately skipped — see "Not Cloned" below.

> **This manifest describes the original clone layout.** The library was reorganized
> into a numbered structure afterward. Current layout and status: **`INDEX.md`**.
> Paths below map as `c2/*` → `01_SOURCE_c2/*`, `mobile/*` → `01_SOURCE_mobile/*`.

## Original Layout (pre-reorganization)

```
RE_Library/
├── c2/                  # Command & Control frameworks
│   ├── sliver/          # Go, BishopFox
│   ├── mythic/          # Python/Docker, its-a-feature
│   ├── havoc/           # C/C++/ASM, HavocFramework
│   ├── metasploit/      # Ruby, rapid7
│   ├── pupy/            # Python, n1nj4sec
│   └── covenant/        # C#/.NET, cobbr (ARCHIVED)
├── mobile/              # Android RATs
│   ├── ahmyth/          # Java/Node.js, AhMyth
│   └── androrat/        # ⚠ WRONG REPO — see notes
└── research/            # empty — sample repos intentionally not cloned
```

## Cloned Repos

| Tool | Path | Language | HEAD | Last commit | Size | License / State |
|---|---|---|---|---|---|---|
| Sliver | `c2/sliver` | Go | `8e5d2f9d` | 2026-10-14 | 418 MB | GPL-3.0 |
| Mythic | `c2/mythic` | Python, Docker | `96b24b4` | 2026-10-11 | 53 MB | BSD-3-Clause |
| Havoc | `c2/havoc` | C/C++/ASM, Qt | `c84f775` | 2025-12-18 | 8.8 MB | GPL-3.0 |
| Metasploit | `c2/metasploit` | Ruby | `fa174ade` | 2026-10-15 | 198 MB | BSD-3-Clause (framework) |
| Pupy | `c2/pupy` | Python | `56b7aac` | 2024-02-06 | 4.9 MB | BSD-3-Clause |
| Covenant | `c2/covenant` | C#/.NET | `5decc3c` | 2021-04-21 | 57 MB | **ARCHIVED 2021 — unmaintained** |
| AhMyth | `mobile/ahmyth` | Java (APK) + Node.js | `97465b1` | 2020-09-11 | 139 MB | GPL-3.0, dormant |
| ~~AndroRAT~~ | `mobile/androrat` | — | — | — | 0 MB | ⚠ **NOT the tool — see below** |

Total: ~880 MB

## ⚠ Corrections

**`mobile/androrat` is not AndroRAT.** The URL used (`wishihab/Android-RATList`) is a
*curated list* repo — it contains only `README.md` and `new-readme.md`. No source, no APK.
To get the actual 2012 AndroRAT source, the original is `AndroRAT` by
*DesignativeDave* / the later maintained forks (e.g. `karma9874/AndroRAT` for the
Python-3 rewrite). Re-clone from one of those; the list repo can stay as an index.

**Covenant is dead.** Last commit April 2021, repo archived. It is still worth reading for
.NET tradecraft history (Grunt, Roslyn in-memory compile, `Assembly.Load`), but do not
expect it to run against a current Windows/.NET stack.

## Not Cloned (deliberate — placement op)

These are live malware sample repositories, not frameworks. Pulling them onto a
daily-driver box is a placement operation, not a research one. If you take this half,
do it in a **disposable, snapshotted VM with no network path back to your real files**:

- **MalwareBazaar** (`bazaar.abuse.ch`) — live samples, password-protected ZIPs, password `infected`
- **theZoo** (`ytisf/theZoo`) — historical malware zoo, double-encrypted archives
- **VirusTotal** — not cloneable; browser/hash-submission analysis surface only
- **malware-traffic-analysis.net** — Brad Duncan's pcaps + binaries, educational

## Suggested Use

- `sliver` → Go RE practice: runtime type reconstruction, goroutine scheduling, string deobfuscation
- `havoc` → the prize for low-level study: Demon agent, indirect syscalls, Ekko/Zilean sleep obfuscation
- `metasploit` → shellcode encoders (`shikata_ga_nai`), staged/stageless, TLV protocol
- `covenant` → CIL bytecode, CLR internals, AMSI patching history
- `pupy` → reflective DLL + embedded Python runtime, `.pyc` extraction from RAM
- `mythic` → multi-OS agent comparison (Rust/Swift/C#)
- `ahmyth` → APK anatomy, AndroidManifest analysis, background Service lifecycle

## Re-Update

```powershell
$root = "C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library"
Get-ChildItem -Recurse -Directory $root |
  Where-Object { $_.Name -eq ".git" } |
  ForEach-Object { git -C $_.Parent.FullName pull --depth 1 }
```

—docket
