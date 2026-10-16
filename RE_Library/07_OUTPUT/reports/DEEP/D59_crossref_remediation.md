# D59 — CROSSREF Remediation: the audit re-run, and the fix table that was never executed

**Task:** crossref remediation (longest-standing unowned debt) · **Lane:** archive-diver · **Method:** the §1 pipeline of `CROSSREF_AUDIT.md` rebuilt from its own text, with positive and negative controls run before any count was trusted · **No REA/Ghidra** · **Read-only on every file except this one.**

**Provenance.** `DEEP/CROSSREF_AUDIT.md` (§1) is the predecessor. It audited **15 reports / D1–D11** and reported **1,648 edges / 1,626 OK / 16 SUB-MISSING / 6 DANGLING**. Its fix table was drafted and **never executed**. The tree has since grown to **77 documents / 61 distinct document numbers**, so that figure is not merely stale — it was never reproducible, because **its population was never stated in the report as a query.**

---

## Verification boundary — stated plainly, up front

| Claim | Status | Why |
|---|---|---|
| The predecessor's **1,648 / 16 / 6** | **`[verified]` as recorded; `[absence]` as generalisable** | Its §0.1 states the row's corpus revision (15 reports / 1,212 headings). The number is right for *that* revision. It is not the number for this one. |
| **This report's 3,696 / 132 / 0** | **`[verified]`** | Produced by the invocation in §0.2, re-run after nine instrument corrections, each printed. |
| **The pipeline itself** | **`[verified]` against controls** | Positive control: constructed strings with a real §. Negative control: `/beta-1.0/`, `rex-socket-0.1.71`, `Figure 12.4` — all must match **0**. Both run, both printed, §0.3. |
| **The fix table (§5)** | **`[inference]` on the *framing*, `[verified]` on the strings** | Every old-string is quoted from the live file at a stated revision. **I did not execute it** — per the brief, that is the Lead's call. |
| **This audit is a snapshot** | **stated** | The tree grew **three times during this audit** (§6). Every count is anchored to a byte size. |

---

## Table of Contents

- [§0 What this is, and the four corrections](#0-what-this-is-and-the-four-corrections)
- [§1 Q1 — the audit re-run: extraction rule, controls, counts](#1-q1--the-audit-re-run)
- [§2 Q2 — the failure classes, with why each fails](#2-q2--the-failure-classes)
- [§3 Q3 — is there a shape? The distribution](#3-q3--is-there-a-shape)
- [§4 Q4 — the DANGLING set](#4-q4--the-dangling-set)
- [§5 The fix table — executable](#5-the-fix-table)
- [§6 The corpus moved during this audit](#6-the-corpus-moved-during-this-audit)
- [§7 Residual unknowns](#7-residual-unknowns)
- [§8 Instrument failures in this audit](#8-instrument-failures-in-this-audit)

---

## §0 What this is, and the four corrections

`[verified]` **The recorded figure is 1,648 edges over 15 reports. The current figure is 3,696 over 77 documents.** That is not drift in the number; it is **2.2× more corpus**.

### 0.1 Four corrections before any finding

**`[verified]` Correction 1 — the brief's "D41–D57 added by round 19" understates the gap by five.**

The brief says the 1,648 predates D41–D57. `[verified]` Enumerated on the current tree, the documents that did **not** exist at the predecessor's revision include **D41–D57**, **and additionally `D58`, `D60`, `D62`, `D63`, `D64`** — plus `D59` is this file. The predecessor's population was `D1–D11`; **everything from D12 up arrived after it.**

**`[verified]` Correction 2 — `D45` does not exist, and the sequence has six gaps.**

```
present: 1..26, 28..44, 46..57, 62, 63, 64
MISSING from 1..64: 27, 45, 58, 59, 60, 61
```
`[verified]` **58 distinct D-numbers among `D*-named files`, 61 once multi-file numbers are unioned** (§1.2). A missing number is **not** a dangling reference — no report cites `D45 §x`. But it matters for Q4: **a gap means a number could be reused, and #13 already names two different failures.**

**`[verified]` Correction 3 — the predecessor's own §7 found "no drift," and that finding does not survive the population change.**

`[verified]` `CROSSREF_AUDIT.md:190` — *"No document silently restates another's number without attribution. That is why class-2 drift is absent, and it is a stated practice, not luck."* `[verified]` **That was true of 15 reports.** It is **not** a claim about 77, and D61 (numeric claim audit) re-opens it. **I record the predecessor's finding as correct-for-its-population and do not repeat it forward.**

**`[verified]` Correction 4 — the brief's three buckets are right, but a fourth class exists and the predecessor named it.**

`[verified]` The brief asks for PARENT-OK-SUB-MISSING / DANGLING / OK **plus anything new**. The predecessor's §7 already documented **four structural habits (Modes A–D)** that are *causes*, not classes. `[verified]` Running them, I find a **genuine fourth verdict class: `SELF-SECTION-MISSING`** (§2.4) — a document citing **its own** sub-section that it never created. `[inference]` **It is a distinct defect from PARENT-OK-SUB-MISSING**: there is no *other* document to fix, so the repair is to **create the section or drop the reference**, not to repoint it.

### 0.2 The invocation, stated so this report is auditable

`[inference]` **This is the thing the predecessor lacked** — D55's **D-7**, the denominator entirely unstated. Every count in §1–§4 is reproducible by this script.

```powershell
# POPULATION - enumerated, never named (the corpus has produced this error five times)
$r    = "RE_Library\07_OUTPUT\reports"
$all  = Get-ChildItem $r -Recurse -File -Filter '*.md'          # NOT -Path "$m\**\*.md"
$docs = $all | Where-Object {
          $_.FullName -ne "$r\README.md" -and $_.FullName -notmatch '\\extractions\\' }
#   -> 77 documents.  README.md and DEEP\extractions\... are excluded, and WHY is stated.

# EXTRACTION - two passes (a single regex produced false XDOC/LOCAL splits; §8 F2)
$SS  = [string][char]0x00A7                                       # NEVER a literal section sign
#   PASS 1  locate every section sign in the line
#   PASS 2a read the dotted number immediately after it
#   PASS 2b scan BACK a 60-char window for the nearest \bD(\d+)\b
#           found -> XDOC (that document is the target)
#           absent -> LOCAL (the citing document is the target)

# RESOLUTION
#   target document number absent from the index        -> DANGLING
#   target major section present                        -> OK
#   target 'n.m' where major n present but n.m absent   -> SUB-MISSING (parent exists)
#   target major absent entirely                        -> SUB-MISSING (parent absent)
```

### 0.3 The controls, run before the count

`[verified]` **Positive control** — constructed with the real character, never typed:

| input | doc | maj | sub |
|---|---|---|---|
| `D6 §25.6` | `D6` | `25` | `6` |
| `see D1 §12.4 for detail` | `D1` | `12` | `4` |
| `§9.1 only` | *(none → LOCAL)* | `9` | `1` |
| `D11 §13 and §13.3` | `D11` | `13` | — |

`[verified]` **Negative control** — must not match:

| input | matches | verdict |
|---|---|---|
| `/beta-1.0/` | **0** | OK |
| `rex-socket-0.1.71` | **0** | OK |
| `no section sign here` | **0** | OK |
| `D5` | **0** | OK |
| `Figure 12.4` | **0** | OK |

`[inference]` **These five negatives are the load-bearing part.** The first two are the exact strings that a broken character class *did* match during development (§8 F1) — they produced phantom `§1.0` and `§0.1.71` references and inflated the edge count **5×**. **The negative control is what caught it, not inspection.**
