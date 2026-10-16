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

### 0.4 Self-exclusion, stated rather than silent

`[inference]` **This report is excluded from its own audit, and the predecessor set the same convention.** Both documents *quote* section references as examples of the very defect they measure. `CROSSREF_AUDIT.md` contributed **120 edges** and this file would contribute **~30** — all of them quotations, none of them claims.

`[verified]` The exclusion is a **stated filter**, not an omission:
```powershell
$metaRe = 'CROSSREF_AUDIT\.md$|D59_crossref_remediation\.md$'
```
`[inference]` **The cost is recorded:** the two documents that contain the most section-sign text in the corpus are the two whose own references are **not** audited. A reference *inside* a quoted example is not a pointer and cannot dangle — but that is an argument, not a measurement, and it is why this is a residual (§7 R-59.3).

---

## §1 Q1 — the audit re-run

### 1.1 The population

`[verified]` **Enumeration, not recollection.** The predecessor audited 15 reports. The tree now holds:

| Measure | Value | Invocation |
|---|---|---|
| `.md` files under `reports\` (recursive) | **79** | `Get-ChildItem $r -Recurse -File -Filter '*.md'` |
| — excluded: `README.md` (56 B, a stub: *"# Reports / Written analyses. One per target.") | 1 | |
| — excluded: `DEEP\extractions\DEEP\D6\IOC_pupy.md` (a **4-deep extraction artifact**, not a report) | 1 | |
| **AUDIT POPULATION** | **77 documents** | |
| distinct document numbers indexed | **63** | |
| **multi-file document numbers** | **`D11` = 5 files, `D12` = 2 files** | §6.2 |

`[verified]` **Two corrections to the enumeration itself, both from a first pass that was wrong:**

1. My first breakdown read *"DEEP 64 + other 1"* — **arithmetically right, semantically wrong.** The "other 1" was `DEEP\extractions\...`, which is *inside* DEEP at depth 4. `[inference]` This is the predecessor's **Mode C** problem in a new place: a path-prefix test that keys on the first directory name conflates a subtree with a file set.
2. `IOC_pupy.md`'s first line **displays** as `# D6 â€” Pupy IOC...`. `[verified]` **The bytes are correct**: `23 20 44 36 20 E2 80 94 20` — that is a well-formed UTF-8 em-dash. `[inference]` **The mojibake is in the console, not the file.** I nearly recorded a byte defect that does not exist; measuring the bytes stopped it. This is the corpus's **fourth** rendering-vs-bytes instance (§8 F4).

### 1.2 The extraction rule

`[inference]` **Stated explicitly and printed, because the predecessor's rule was not, and that is D55's D-7.** A bare count has no population. This section is the population.

**Rule R — a reference is a section sign followed by a dotted number, with an optional backward-visible document prefix.**

```
PASS 1   On every non-heading line, locate every U+00A7 SECTION SIGN.
PASS 2a  Read the dotted number immediately after it (up to 3 digits, 3 components).
PASS 2b  Scan BACKWARD up to 60 characters for the nearest \bD(\d+)\b.
           found  -> XDOC : that document number is the target
           absent -> LOCAL: the citing document's own number is the target
```

**Excluded by rule, each counted:**

| Excluded form | Count | Why |
|---|---|---|
| section sign with no readable number following | **52** | e.g. `§B4` (appendix letters, D14's Part B), `§II` |
| section sign followed immediately by `:` | **2** | the corpus's **section-line** convention — `§:107-110` means *lines 107–110* |
| section sign followed by **3+ digits** | **1** | an offset/line number, not a section |
| duplicate `(file, line, target)` | **208** | one line that names the same target twice is **one edge**, not two |

`[verified]` **A sample of what the rule matches** — the first twelve edges found, with their source line:

| file:line | matched | → target | kind |
|---|---|---|---|
| `D55:57` | `D29 §5 / D38 §8.6` | `D29 §5` | XDOC |
| `D55:57` | *(same line)* | `D38 §8.6` | XDOC |
| `D6:4367` | `D5 §21` | `D5 §21` | XDOC |
| `D17:935` | `D3 ... §23.3` | `D3 §23.3` | XDOC |
| `D14:762` | `§9.1 — CLOSED` | `D14 §9.1` | LOCAL |
| `D1:1453` | `see §12.4` | `D1 §12.4` | LOCAL |
| `D6:5258` | `D6 §25.6` | `D6 §25.6` | XDOC |
| `D48:10` | `§0.1 — The Makefile...` | `D48 §0.1` | LOCAL |
| `D32:257` | `D24 §8` | `D24 §8` | XDOC |

`[inference]` **`D55:57` is the pair that proves the two-pass design.** A single regex captured `doc=''` for the second reference on that line — because `Regex.Matches` resumes scanning **after** the first match consumed `D29 §5`, and the `D38` prefix then sits behind the cursor. (§8 F2.) The backward scan is not a refinement; it is the difference between **2 false SUB-MISSING** and the correct **2 OK**.

### 1.3 The counts

`[verified]` **77-document corpus, 3,941 extracted edges, meta-excluded:**

| Verdict | Count | Share |
|---|---|---|
| **OK** | **3,685** | **97.204 %** |
| **PARENT-OK, SUB-MISSING** | **106** | 2.796 % |
| **DANGLING** | **0** | **0.000 %** |
| **total (excl. meta)** | **3,791** | |
| *meta-quoted edges excluded* | *150* | |

`[verified]` **The comparison with the predecessor, stated as a comparison and not as a correction:**

| | Predecessor | This audit | Ratio |
|---|---|---|---|
| documents | 15 | **77** | 5.13× |
| edges | 1,648 | **3,941** | 2.39× |
| OK | 1,626 (98.66 %) | **3,685 (97.20 %)** | — |
| SUB-MISSING | 16 | **106** | 6.6× |
| DANGLING | 6 | **0** | — |

`[inference]` **Three things follow, and the third is the interesting one.**

1. **The brief's instruction was right: the old number cannot be trusted forward.** It was a true statement about 15 reports.
2. **`SUB-MISSING` grew faster than the corpus did** — 6.6× against 5.13× more documents. `[inference]` The failure rate **rose** from 0.97 % to 2.80 %.
3. **`DANGLING` went to zero, and that is not a repair.** `[verified]` §4 shows all six predecessor dangles are **still present, still unresolved** — they now resolve as `SUB-MISSING` because **the documents they point into have themselves grown new sections**, or because a `D<n>` that had no file now has one. **A dangle that disappears without an edit is a boundary movement, not a fix.** §4.1 resolves each by hand.

[^1]: **A correction to this section, caught by re-reading, kept rather than erased.** The first draft of this header read *"36-document corpus."* `[verified]` The correct figure, measured in §1.1 and used everywhere else in this report, is **77 documents / 63 document numbers**. The `36` was transcribed from an intermediate scratch value and never re-measured before it was written down — **which is precisely the defect this report exists to audit, committed inside it.** It is recorded here because deleting it would make this document's own arithmetic look cleaner than its method was. §8 F-7.
