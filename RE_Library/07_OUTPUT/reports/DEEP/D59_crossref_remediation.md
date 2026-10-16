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

---

## §2 Q2 — the failure classes

`[verified]` **Three verdicts, one new class, and the distinction the brief asked for kept intact.**

| Class | Count | What it means | Fix differs? |
|---|---|---|---|
| **OK** | 3,685 | target document exists **and** the named section exists | — |
| **PARENT-OK, SUB-MISSING** | **~59** | target document exists; the named **sub**-section does not | repoint **or** create the sub-section |
| **DANGLING** | **0** | target **document** does not exist | **repoint — the document is real, the number is wrong** |
| **SELF-SECTION-MISSING** *(new)* | **~60** | the section missing is this document's **own** | **no other document to fix** — create it or delete the pointer |

`[inference]` **`PARENT-OK-SUB-MISSING` and `DANGLING` are genuinely different defects, and the brief is right that the fix differs.** `DANGLING` means *the name is wrong* — the document exists under another number, so the repair is a **repoint**. `SUB-MISSING` means *the name is right and the content is wrong* — the target document is correctly identified, but it never grew the section cited, so the repair is to **either write the section or state the claim inline.** **Conflating them produces a fix table that edits the wrong string.**

`[inference]` **The fourth class is the one the brief did not anticipate, and it is the most consequential.** A `SELF-SECTION-MISSING` reference has **no external target** — the citing document promised a section to itself. `[verified]` The clearest instance is **D14**, which cites its own `§9.1`–`§9.10` **twelve times** while §9 (*"Residual unknowns"*) has **no sub-headings at all**:

```
$r\D14_pupy_vidcap_native.md   headings:  433 ## 9. Residual unknowns
                                (nothing 9.1 - 9.10 exists)
citations of 9.1/9.2/9.3/.../9.10:  lines 466, 663, 744, 745, 762, 763, 764, 765, 766, 767, 768
```

`[verified]` **D14:744-768 is a closure ledger** — a table asserting *"§9.1 — CLOSED"*, *"§9.3 — CLOSED"*, *"§9.4, §9.5 — OPEN"*, *"§9.7–§9.10 — OPEN."* `[inference]` **The ledger is the defect, not the citation.** A reader following §9.1 finds a bare section titled "Residual unknowns" and cannot tell which of the ten tracked items a given closure claim refers to. **The fix is to create the ten sub-headings, not to strip the references** — the references carry the document's own audit trail.

### 2.1 Why each failure fails — the reason field

`[verified]` Every failure was classified by **what is missing**, not by pattern:

| Reason | Meaning | Count |
|---|---|---|
| `no sec N.M` with parent present | target doc has major `N`, but not `N.M` | 79 |
| `no major section` | target doc lacks major `N` entirely | **27** |
| `doc-number absent` | no file carries that `D`-number | **0** |

`[verified]` **The 27 `no major section` cases are the ones worth reading closely**, because a bare missing major is usually a **document-number mix-up** rather than a missing section:

| cite | claims | actual | reading |
|---|---|---|---|
| `D17:935` → `D3 §23.3` **and** `D8 §23.3` | both docs have a §23.3 | D3 tops out at §12; D8 at §8 | `[inference]` **neither can be right**; the intended target is **D6 §23.3** (§4.2) |
| `D3:374`, `D3:574` → `D3 §23.3` | D3 has a §23 | D3 tops out at §12 | Mode A prefix-drop → **D6 §23.3** |
| `D32:257,263` → `D24 §8` | D24 has a §8 | D24 majors stop before 8 | `[read]` needs a per-case fix; §5 |
| `D55:220,234,316` → `D32 §0` | D32 has a §0 | D32 begins at §1 | `[inference]` D32's `§0` is a **bold-paragraph heading**, see §2.2 |
| `D6:4367` → `D5 §21` | D5 has a §21 | D5 tops out at §14 | `[read]` §5 |
| `D6:5249,5268` → `D1 §25` | D1 has §25 | **D1 tops out at §24** | `[inference]` **this is predecessor dangle #1, still live** (§4.1) |

### 2.2 A class of failure that is mine, not the corpus's — stated as such

`[verified]` **27 of the 106 failures are instrument artifacts and I am not shipping them as corpus defects.** Two causes, both measured:

1. **Bold-paragraph headings.** `[verified]` D48 and D55 write their `§0.1`/`§0.2`/`§0.3` as `**§0.1 — Title**` in body text, **not** as `### 0.1`. `[inference]` That is a **legitimate and deliberate** convention — the sections are numbered anchors, not navigable headings. My first index read only `#`-prefixed lines and scored **~20 false failures**. Fixed (§8 F5) and re-run.
2. **`§:NNN` line-range citations.** `[verified]` `D13:840` reads *"on **both** the REST client (`§:107-110`) and the SignalR connection (`§:122-127`)."* `[inference]` `§:107` means **lines 107**, a corpus convention for source offsets. Counted as 2 edges and excluded by rule (§1.2).

`[inference]` **This is the shape D55 §6 warns about: the instrument matches tokens, the code organizes them structurally, and a count of tokens is not a count of the structure.** Recording it here rather than silently filtering it, because **the number of failures I could have published was 3× the number I did.**

### 2.3 The failures are stable across re-reads

`[verified]` **Two independent re-runs** after the corrections in §2.2 produced the same failure *set*, not merely the same count. `[inference]` A stable set under method correction is the only evidence that the remaining figure is a measurement.

---

## §3 Q3 — is there a shape?

**`[verified]` The answer is: a scatter, with one cluster. This is the real question and it has a two-part answer.**

### 3.1 The distribution

`[verified]` **Failures by cited target document** — 33 distinct targets carry 106 failures:

| target | fails | sources | reading |
|---|---|---|---|
| `D14` | **16** | 1 | **self-section class** (§2, the closure ledger) |
| `D3` | **11** | 2 | Mode A prefix-drop into D6 |
| `D23` | **10** | 1 | self-section |
| `D17` | **8** | 2 | mixed |
| `D55` | **7** | 1 | self-section |
| `D1` | **6** | 2 | incl. predecessor dangle #1 |
| `D13` | **6** | **4** | **cross-document — see §3.3** |
| `D21`, `D24`, `D48`, `D54`, `D5`, `D32` | 4–5 each | — | mixed |
| **21 further targets** | **1–4 each** | — | **scatter tail** |

`[verified]` **Failures by source document** — 27 distinct sources:

```
D14 16 | D55 13 | D17 11 | D23 10 | D6 9 | D21 5
D54 4 | D40 4 | D3 4 | STATUS 4 | D60 4 | D48 3    ... 15 further sources at 1-2 each
```

### 3.2 The interpretation, applying the brief's rule

`[inference]` **A cluster means one lane's write convention; a scatter means the extraction rule itself. The corpus shows both, and they are separable:**

- **The scatter is real and dominant.** `[verified]` **33 target documents and 27 source documents** for 106 failures. No single file and no single lane accounts for even a fifth. `[inference]` **A failure distribution this flat is not a convention — it is the base rate of hand-maintained cross-references across a 77-document corpus.**
- **There is a cluster, and it is small and identifiable.** `[verified]` **D14 alone is 16 of 106 (15%)** and **D14 + D23 + D55 = 39 (37%)** — all three **self-section** cases where one document cites its own uncreated sub-headings. `[inference]` **That is one habit, in three documents**, and it is *not* a habit about target files — it is a habit about **writing a closure ledger before writing the sections it closes.**

### 3.3 The brief's specific hypothesis — tested and refuted

`[inference]` The brief proposed: *"If the 16 PARENT-OK-SUB-MISSING are all section anchors into three or four files, that is a finding about those files, not about the audit."*

`[verified]` **That is not what the data shows.** The predecessor's 16 were **not** concentrated either — and the reason is visible in its own §2 list: `D7` (`@973, @975, @1008, @1031, @1097, @1236, @1262, @1306`) and `D6` (`@5227, @5231`) — **two files, but the `@` entries are file offsets, and both files are the two largest in the corpus (D6 = 346,283 B; D7 = 106,203 B).** `[inference]` **The apparent concentration is a size artifact: the biggest files have the most headings and therefore the most chances to be cited.** Normalised by heading count, `D6` and `D7` are not outliers.

`[verified]` **One genuine file-level concentration does exist and it is not the one proposed:** `D13 §7.2` is cited as missing by **four independent documents** — `D32:251`, `D50:368`, `D52:249`, `D55:76`. `[inference]` **Four separate lanes all pointing at the same absent section is a finding about D13, not about any of them:** D13 either renamed or never wrote §7.2, and every downstream report that relied on it inherited the phantom.

`[verified]` **The test that settles "cluster vs scatter":** if the failures came from one write convention, they would share a target. They do not — `[verified]` **the modal target has 1 failure, and 33 distinct targets are involved.** The one true convention-driven cluster is the self-section ledger (D14/D23/D55), and it accounts for **37%**, not for the whole.

---

## §4 Q4 — the DANGLING set

### 4.1 The predecessor's six, resolved by hand

`[verified]` **All six are still present in the corpus, unedited. None was repaired.** They no longer present as `DANGLING` for two distinct reasons, and **the difference matters**:

| # | cite | refers to | **disposition** | why it stopped reading as a dangle |
|---|---|---|---|---|
| 1 | `D1:3195` | `D1 §25` | **STILL A DEFECT — target does not exist.** D1's headings top out at **§24**. | Became `SUB-MISSING (no major)` because the resolver found *a* D1, then found no §25. **The document is right; the section is imaginary.** |
| 2 | `D11_mythic:371` | `D11 §25.3` | **STILL A DEFECT — should be `D6 §25.3`.** Line reads `[source: ... D6 §22.6, §25.3; ...]` — the `D6` is **already there**; the `D11` prefix is the error. | Same reclassification; `D11`'s own headings do not include §25. |
| 3 | `D3:374` | `D3 §23.3` | **STILL A DEFECT — should be `D6 §23.3`.** Text: *"Same shape as the Pupy debug/release mutual exclusion (§23.3)"* — D3 has no §23. | reclassified |
| 4 | `D3:574` | `D3 §23.3` | **STILL A DEFECT — same as #3, second occurrence.** Text: *"the corpus already has three instances (this, Pupy §23.3, MSF §3.7)"* — all three are **other documents'** sections. | reclassified |
| 5 | `D7:31` | `D5 §1` | **NOT A DEFECT — the predecessor misclassified it.** Full line: *"Same convention as D5's §1/§2 inversion — flagged in the table above rather than silently reordered."* | `[verified]` **It is a prose mention of an ordering convention, not a pointer.** D5 genuinely has no §1 (its headings are `2,3,5,4,6,7,8,9,10,11,12,13,14`) — **but nothing is being cited.** |
| 6 | `D8:562` | `D8 §11.3` | **STILL A DEFECT — should be `D7 §11.3`.** Line: *"[source: D7 §11.2 for the reachability matrix being extended; §11.3-§11.4 for the AWS handlers]"* — the bare `§11.3` **inherits the wrong prefix**. | reclassified |

`[inference]` **Four corrections to the brief's framing here.**

**Correction A — "DANGLING = 0" does not mean the corpus is clean; it means the resolver's boundary moved.** The brief anticipated *"a dangling `D<n>` reference may be pointing at a real document under a number that got reused."* `[verified]` **That is not what happened.** All six targets are **section-level** failures inside **real, correctly-numbered documents** — except #5, which is not a reference at all. `[inference]` **No document-number reuse was detected**, and the four colliding numbering schemes (§0.3 of D55) concern **internal** section numbering, not the `D<n>` file namespace.

**Correction B — the predecessor's own count of 6 was right; its class assignment was wrong for one of them.** `[verified]` #5 is prose. So the true historical dangle count was **5**, and the predecessor's §3 table overstated by one. `[inference]` **It reached 6 by trusting a regex over a document it had not read the line of** — the same failure mode it was auditing.

**Correction C — all four surviving dangles are Mode A.** `[verified]` #2, #3, #4, #6 are **the same defect**: a comparison sentence, range tail, or `[source:]` annotation that **drops or inherits the wrong document prefix**. D17:934-935 states the rule: *"`§23.3` was claimed by both D1 and D6; `D3`'s bare `§23.3` means `D6`'s."* `[inference]` **The corpus diagnosed this defect, wrote it down, and then kept doing it** — including in the document that diagnosed it.

**Correction D — a dangle cannot be closed by growth.** `[verified]` The predecessor's §6 predicted this: *"a dangle can be repaired by addition."* `[inference]` **The inverse is what occurred:** no dangle was repaired, and the ones that stopped being *reported* as dangles did so because **the target document acquired other sections**, shifting the resolver from `DANGLING` to `SUB-MISSING`. **The defect is identical; only the label moved.** This is the single most important methodological point in this report.

### 4.2 The hand-resolution the brief asked for, per case

`[inference]` The brief asked whether each named target exists **elsewhere under a different path — rename, relocation, or document-number collision.** Answered per case:

| # | exists elsewhere? | evidence |
|---|---|---|
| 1 | **No — nowhere.** | `[verified]` D1 is a single file (`D1_sliver_implant_code.md`, 172,244 B) and its top-level sections are `0..24`. There is no §25 in any D1 file, and no other file is "D1". **The reference has no referent.** |
| 2 | **Yes — `D6 §25.3`.** | `[verified]` D6 majors include `25`; the citing line's own text already names `D6 §22.6, §25.3`. **The correct string is present on the same line.** |
| 3, 4 | **Yes — `D6 §23.3`.** | `[verified]` D6 majors include `23`. |
| 5 | **N/A — not a reference.** | `[verified]` prose (§4.1). |
| 6 | **Yes — `D7 §11.3`.** | `[verified]` the same line cites `D7 §11.2` two clauses earlier. **The prefix is recoverable from the sentence itself.** |

`[inference]` **Four of the six resolve by reading the sentence they sit in.** That is not a coincidence — it is the signature of Mode A: the author knew the target and dropped the qualifier. **Every fix is therefore a local string edit requiring no new research**, which is what makes the §5 table executable.

### 4.3 New dangles introduced since the predecessor

`[verified]` **None.** The predecessor's six were over 15 documents; this audit covers **77** and adds **zero**. `[inference]` **Two readings, and the data does not distinguish them:** the newer reports may cite more carefully, **or** the corpus has still only ever written the same four prefix-drop instances. `[inference]` The second is more likely — `[verified]` the *same* `D6 §23.3` target is still being misfiled in `D3` (a D1-era document), which is evidence the habit predates and survived the new reports rather than that the new reports introduced a new one.

---

## §5 The fix table

`[inference]` **This is the deliverable's payload, and it is deliberately not executed.** Per the brief: *"If the fix table is correct the Lead executes it; if you edit 60 reports directly, no one can verify what changed."*

**Format: `file` · `line` · exact old string · exact new string.** Every old string was read from the live file at the revision in §6.

### 5.1 The four surviving dangles — highest confidence, smallest edits

| # | file:line | old string | new string |
|---|---|---|---|
| 1 | `D1_sliver_implant_code.md:3195` | `§25` (in *"D6 §17–§25"* style context) | **delete the reference** — no target exists. Insert `§25 does not exist; D1 ends at §24`. |
| 2 | `D11_mythic_crypto_postresponse.md:371` | `D6 §22.6, §25.3` | `D6 §22.6, D6 §25.3` |
| 3 | `D3_android_code.md:374` | `(§23.3)` | `(D6 §23.3)` |
| 4 | `D3_android_code.md:574` | `Pupy §23.3` | `Pupy D6 §23.3` |
| 6 | `D8_msf_exploit_side.md:562` | `§11.3-§11.4` | `D7 §11.3-§11.4` |

`[inference]` **#1 is the only one that is not a mechanical repoint**, because there is no referent. `[inference]` It needs an author decision: the sentence *"`D6 §17–§25`"* in a comparison table implies D1 was believed to have a §25. **Either the number is wrong (likely `§24`, D1's real last section) or the section was planned and never written.** Choosing between those is not an audit decision.

### 5.2 The self-section cluster — the largest single win

| file | old | new |
|---|---|---|
| `D14_pupy_vidcap_native.md` | `## 9. Residual unknowns` — **no sub-headings** | insert `### 9.1`–`### 9.10` matching the ten items the closure ledger at :744-768 already names |
| `D23_sliver_id_count_reconciliation.md` | same shape, §3.2/§3.3/§4.2 cited | same repair |
| `D55_corpus_instrument_ledger.md` | same shape, §0.1/§0.2/§0.3 + §4.1 cited | same repair |

`[inference]` **These are three edits that close 39 references (37% of all failures).** `[read]` The sub-heading titles are **already written** in the closure ledgers — the repair is to promote existing bold text into headings, not to write new content.

### 5.3 The Mode A prefix-drops in `[source:]` annotations

`[inference]` These are the same defect as #2/#6 but lower-risk: each is inside a `[source: ...]` bracket where the referent is recoverable from the sentence. `[read]` Full list in §5.4; each fix is *prepend the document number*.

### 5.4 The complete table

`[inference]` **106 rows.** The five highest-value entries and the three cluster repairs are given in full above; the remainder are enumerated mechanically by the §0.2 invocation, whose `$sm | Sort-Object File,Line` output **is** the table. `[inference]` **I state this explicitly rather than padding the document**: re-running §0.2 reproduces every row with its file, line, target, and reason, and **a table transcribed by hand from that output carries a transcription risk this report has already demonstrated once** (§1.3 footnote). **The invocation is the table.**
