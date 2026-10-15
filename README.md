# RE_Library — Deep Reverse Engineering Corpus

Static reverse engineering of nine command-and-control frameworks and remote-access
tooling families. Every report here is derived from **source code and shipped release
artifacts read statically** — nothing in this repository was executed as part of the
analysis, and no live malware samples are included.

## What this repository is

This is the **analysis**, not the corpus. The third-party source clones and binaries
that the analysis was performed against are excluded by `.gitignore` — they are public
at known commits, they are large, and they are not ours to redistribute. What ships
here is the reading of them: per-target code-level reports, function-level findings,
and the cross-target comparative results.

## Layout

```
RE_Library/
  00_START/     index, landscape, manifests, binary sources
  04_TOOLS/     tool inventory + unpacked dependency sources (Rex gem layer)
  06_NOTES/     working notes
  07_OUTPUT/
    reports/    the deliverables
    configs/    configuration artifacts
```

## The reports

### Per-target (`reports/`)

| Report | Target |
|---|---|
| `T1_sliver_client.md` | Sliver client — operator-side binary |
| `T2_covenant.md` | Covenant |
| `T3_android_mobile.md` | AhMyth + AndroRAT |
| `T4_mythic.md` | Mythic |
| `T5_havoc.md` | Havoc |
| `T6_pupy.md` | Pupy |
| `T7_metasploit.md` | Metasploit |
| `T8_merlin_and_blocked.md`, `T8_merlin_full.md` | Merlin + blocked-target analysis |

### Deep code-level (`reports/DEEP/`)

| Report | Target | Size |
|---|---|---|
| `D1_sliver_implant_code.md` | Sliver implant + server | 164 KB |
| `D2_covenant_code.md` | Covenant | 191 KB |
| `D3_android_code.md` | AhMyth + AndroRAT | 68 KB |
| `D4_mythic_code.md` | Mythic | 76 KB |
| `D5_havoc_code.md` | Havoc Demon agent | 238 KB |
| `D6_pupy_code.md` | Pupy | 338 KB |
| `D7_metasploit_code.md` | Metasploit, exploit side | 104 KB |
| `D8_msf_exploit_side.md` | Metasploit, module surface | 49 KB |
| `D9_msf_core_library.md` | Metasploit engine + externalized Rex layer | 159 KB |
| `D10_merlin.md` | Merlin | 78 KB |

`STATUS.md` tracks corpus state and known gaps.

## Findings that carried across targets

A few results generalised beyond the target they were found in, and are worth
surfacing here because they are the reason the reports are in one repository:

**Source presence is not build presence.** Pupy ships seven capabilities whose source
is present and whose builds omit them, severed eight different ways — a missing file,
a commented-out implementation, an `#ifdef` on a macro no build passes, a build
variable explicitly assigned empty in the file that guards on it. A file scan lists all
seven as present.

**Joint self-defeat.** Two mechanisms, each correct alone, jointly cancel. Pupy's
release builds decommit PE headers *and* omit the minidump path — it cannot have both.
Havoc's evasion design works *because* it is visible, and that visibility rides the one
channel the framework deliberately never ciphers. MSF's stage encoding silently
degrades to unencoded on failure. In the Android target, the persistence mechanism
re-runs an icon-unhide on every fire while concealment runs once — the operator's own
persistence defeats the operator's concealment.

**The corpus has a hole, measured.** Metasploit's `Rex::Socket`, `Rex::Text`,
`Rex::Arch` and `Rex::Encoder` are **not files in the checkout** — they are gems,
declared in `metasploit-framework.gemspec` (18 `rex-*` runtime dependencies) and pinned
in `Gemfile.lock`. The in-tree `lib/rex/` is the residual Rex. Five of those gems were
subsequently obtained and unpacked; `04_TOOLS/gems/` holds the source.

**Artifact names point the opposite way from content, repeatedly.** Pupy's `jumper`
class does not jump — it un-hides a launcher icon. Merlin's `merlin.x64.dll` is a Go
binary, not C. `data/src/` and `data/x509/` ship README files only. `lib/rex/encoder`
does not exist; the encoder interface is elsewhere. A report that trusts filenames
over enumeration is wrong in this corpus more often than not.

**A pointer set is not a payload set.** 42 of Merlin's 45 module URLs float on a branch
the operator does not own and the JSON records no digest. 39 modules declare both a
remote URL and a local path with nothing in the schema resolving which executes. No
static analysis of that archive can bound what runs.

## Method

Every report follows the same discipline, and the reports should be read with it in
mind:

- **A count is a measurement only if it is enumerated.** Estimates were repeatedly
  wrong; enumeration caught them. Where a number appears, it was counted.
- **An absence needs a positive control.** A grep returning zero hits establishes
  nothing until the same probe is shown able to succeed. Structural absences in these
  reports are backed by a probe that returned the expected hit elsewhere.
- **Inference is marked as inference.** Runtime consequences that were not observed are
  labelled; the distinction between *verified*, *read*, and *inferred* is preserved
  throughout.
- **Corrections are recorded in place, not revised away.** Several delivered sections
  carry explicit correction notices naming the earlier claim. That is deliberate.

## Scope and use

Open-source framework source and officially published release binaries, read
statically. No live malware samples are present, and none were run. The analysis is
presented for defensive purposes: understanding how these frameworks are built is what
makes their behaviour detectable.

## Provenance

Analysis performed with [REA](https://github.com/morluto/rea) (MCP reverse-engineering
toolbelt; Ghidra-backed native provider) together with static reading of the sources
themselves. Reports were produced per-target by parallel analysis lanes with independent
verification of every completion claim against the artifact on disk.
