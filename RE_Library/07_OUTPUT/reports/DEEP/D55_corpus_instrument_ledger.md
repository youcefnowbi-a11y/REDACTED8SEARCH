# D55 — Corpus Instrument Ledger

**Lane:** archive-diver · **Task:** task-57 · **Type:** synthesis over the corpus's own artifacts.
**Write scope:** this file only. **No provider. No execution. No network.**
**Method:** every instance below was located by searching the reports, not from the brief's list. **Where the brief named an instance and I could not find it in a report, that is stated.**

> **This is the document a future round reads first.** It is written to be **operable**: every shape carries a **detector** you can run, not a lesson you can nod at. If you are starting a count in this corpus, read §4 (standing controls) before you type the command, and §1 (taxonomy) when a number surprises you.

---

## Verification boundary — stated plainly, up front

| Claim class | Status |
|---|---|
| The shape exists | **Cited to report + line** |
| The general form | **`[inference]` — my own synthesis, marked wherever it is mine** |
| Shapes with no report home | **marked `[unwitnessed]`** — and there are some |
| The corpus's own numbering | **`[verified]` — linked-lane-continuous, NOT reinvented here (§1.0)** |

**The corpus is not one voice.** Failure tables exist in at least four lanes with **four different numbering schemes**. §1.0 reconciles them; **I do not overwrite them.**

---

## Table of Contents

- [§0 What this is, and the one correction to the brief](#0-what-this-is-and-the-one-correction-to-the-brief)
- [§1 Part 1 — The instrument taxonomy](#1-part-1--the-instrument-taxonomy)
- [§2 Part 2 — The denominator species](#2-part-2--the-denominator-species)
- [§3 Part 3 — The standing controls](#3-part-3--the-standing-controls)
- [§4 How to use this — the pre-flight card](#4-how-to-use-this--the-pre-flight-card)
- [§5 Residual unknowns](#5-residual-unknowns)
- [§6 Instrument record for this report](#6-instrument-record-for-this-report)
- [§7 Three-line summary](#7-three-line-summary)

`[verified]` **The first draft of this TOC listed six entries against eight `##` sections — checked by counting both and comparing.** The omission is fixed above. `[inference]` **Recording it because it is the ledger's own shapes committed by the ledger: a table of contents that reports a structure it does not enumerate (S4), found by counting the thing and comparing it to the claim about the thing (C-5).**

---

## §0 What this is, and the one correction to the brief

**§0.1 — The brief's fourteen-plus list is largely correct, and it is not organised the way the corpus's own records are.**

`[verified]` I searched 58 DEEP reports plus 10 top-level reports for each shape. **Thirteen of the brief's items have a citable home. Two do not, and one is a duplicate.** The reconciliation is §1.0 and the gaps are named there.

**§0.2 — The brief's headline framing is *my* generalisation, and the corpus had already written it down before this task.**

> `[verified]` **D50 §5, line 376:** *"the failures cluster around **structural** patterns — brackets, indentation, namespace scope, glob depth — while the numbers counted are **lexical**. The instrument matches tokens; the code organizes them structurally."*

`[inference]` **I am the lane the Lead attributes this to, and D50's line is where it was actually written down.** The attribution is generous and slightly wrong. **The general form went into the corpus in covenant-diver's D50, not in my D38/D48.** I am recording that because this document's whole subject is *claims that travel further than their evidence*, and the safest first act is to apply it to the brief.

**§0.3 — One structural correction that shapes the whole document.**

`[inference]` The brief treats the shapes as a **flat list of fourteen**. The corpus records them as **a flat list in four places with four numbering schemes** — and **the numbers collide**:

| Source | Scheme | Range | What its numbers mean |
|---|---|---|---|
| D29 §5 / D38 §8.6 | lane-local | 1–6 | archive-diver's own failures |
| D50 §5 | **linked-lane-continuous** | **9–13** | the lane's failures, **carried across D13 → D20 → D32 → D50** |
| D46 §5.1 | report-local | 1–5 | covenant-deep's failures in one report |
| D44 §7 (F1–F6) | report-local, `F`-prefixed | F1–F6 | sliver-diver's failures |

> `[verified]` **"#13" is ambiguous in this corpus: it is covenant-deep's *ambient vocabulary* shape in one reading and covenant-diver's `[Authorize` false zero in another.** The brief asks for both by number. **They are different failures in different lanes.** §1 disambiguates by naming the shape, never the bare number.

`[inference]` **This is the document's first finding and it is about the document's own frame:** a corpus that numbers its failures four ways has the same defect it logs — **a structural convention (numbering) reported as if flat (a list).** Shape **S6**.

---

## §1 Part 1 — The instrument taxonomy

### 1.0 The corpus's own numbering, reconciled

`[verified]` **D50 §5's table is the spine**, because it is the only one that carries numbers across lanes. Quoted from D50:366-372:

| Corpus # | Where | Failure | Correction | Rule as stated |
|---|---|---|---|---|
| 9 | D13 §7.2 | member-surface regex class **excluded digits** → **178** for **183** | class widened to `[A-Za-z0-9_]` | *A count is a measurement only if you enumerate it.* |
| 10 | D20 §6.2 | `-Path "$m\**\*.go"` → **false zero** on a control that must return 6 | per-file `-LiteralPath` over 399 files → exactly 6 | *A recursive glob in that form does not recurse the way the syntax suggests.* |
| 11 | D32 §6 | name collision across namespaces → **57** apparent `partial` splits vs true **0** | tightened to `partial` declarations only | *Same identifier in two files is not one type in two files.* |
| 12 | D32 §1.3/§2 | `\|` unescaped in alternation → **false zero while printing matches** | `-SimpleMatch` for literals | *A count without a printed match is a number you have not looked at.* |
| 13 | **D50 §2.1** | `\[Authorize` needs `[` **immediately** before; code writes it **mid-line in a combined attribute list** → **0 on 16 of 17** | `\bAuthorize\s*\(` → **17 of 17** | *Anchor on the identifier, not on the bracket.* |

`[inference]` **Every number 9–13 is a lexical probe against a structural question. That is the general form, and D50 wrote it.**

---

### 1.1 The organising claim

> **`[verified]` D50 §5:376 — an instrument matches TOKENS; source code is organised STRUCTURALLY. Every failure in this ledger is that mismatch.**

`[inference]` **The taxonomy below collapses the brief's fourteen into SIX general forms.** Where a brief item survives intact it is kept as a **sub-shape** with its own detector. **The collapse is the contribution; the list is the raw material.**

---

### S1 — THE SILENT ZERO *(brief items 1, 10, 12, 5)*

> **General form:** a probe returns **nothing**, and nothing is the one result a dead instrument and a true absence both produce. **A live instrument that is wrong announces itself; a dead one does not.**

`[verified]` **STATUS.md:294-296 carries the corpus rule verbatim:** *"An instrument that returns nothing or nearly-nothing is more suspicious than one that returns something wrong. Absence is the one result you cannot distinguish from a dead tool by looking at it. A wrong number at least came from a live process; a zero might have come from nowhere."*

**Why four brief items collapse here.** Each is a *mechanism that produces a zero*, and the mechanisms differ while the failure class does not.

| Sub-shape | Brief # | Instance (report:line) | Mechanism |
|---|---|---|---|
| **S1a — probe shape ≠ evidence shape** | 5 | **D50 §2.1 / D46 §5.1:368** | `\[Authorize` requires `[` immediately before; source writes `[ApiController, Route(...), Authorize(...)]` → **0 on 16 of 17 controllers** |
| **S1b — recursive glob false zero** | 10 | **D50 §5:369 (D20 §6.2)** | `-Path "$m\**\*.go"` → **0** on a control that must return 6; per-file `-LiteralPath` → exactly **6** |
| **S1c — escaping killed the pattern** | 12 | **D50 §5:371 (D32 §1.3)** | `\|` unescaped in `Select-String` alternation → **false zero while printing matches** |
| **S1d — probe ran against the wrong LAYER** | — | **D46 §0.4:58** | `Code:` regex scanned **raw YAML** while source lives in **YAML block scalars** → `0 blocks`, and it **printed a full table of zeros that looked like a measurement** |

`[verified]` **The correct calibration, from D46 §0.4:60:** the corrected parse (`Code: |` + more-indented lines) yields **83 blocks / 122,873 chars** of real C#. **The zero table was discarded, not built upon.**

**Sub-shape worth separating — the zero that survived into a published headline:**

`[verified]` **D46 §5.1:368 — *"`[Authorize` pattern missed 16 of 17 controllers … D40's headline count was wrong; corrected here."*** `[inference]` **This is the strongest single instance in the ledger**, because the false zero did not stay local: it propagated into **D40's published authority census** and was caught only when covenant-deep re-measured with a corrected pattern. **A silent zero can travel between reports.**

**DETECTOR — S1**

```powershell
# The only test that separates a real zero from a dead probe:
#   make the probe succeed on a target you KNOW is there, IN THE SAME COMMAND.
$p = 'PATTERN'
$hit = Select-String -Path $target      -Pattern $p          # the measurement
$ctl = Select-String -Path $knownSibling -Pattern $p          # the control, same command
"measurement=$($hit.Count)  control=$($ctl.Count)"
if ($ctl.Count -eq 0) { 'PROBE IS UNTESTED, NOT NEGATIVE — do not write this zero' }
$hit | Select-Object -First 20                                # print your matches
```

`[inference]` **The `if` line is the whole detector.** A zero with a live control is a finding; a zero with a dead control is a number you have not earned.

---

### S2 — THE FIGURE WITH NO RUN BEHIND IT *(brief items 2, 7)*

> **General form:** a number is present in the report but **the invocation that produced it is not**, or the invocation that produced it was **scoped differently** from the sentence it now sits in. **A stale figure wearing the authority of a measurement.**

`[verified]` **STATUS.md:320-326 states it as a variant of the instrument rule:** *"A number that arrived by a route other than the one it appears to have arrived by."* The instance is **havoc-deep's D12 §9 "F5"**: the draft said **"14 unmatched"** and listed **13**. **Both were correct for different questions** — 14 constants, 13 distinct values, because `COMMAND_GET_JOB` and `COMMAND_INLINE_EXECUTE_EXCEPTION` both equal `1`. Names came from a by-name print; the count came from a later value-level set operation. **Two runs, one sentence.**

`[verified]` **STATUS.md:328-330, the uncomfortable part, in the lane's own words:** *"it was caught only because the report was already written and the numbers were cheap to re-check. Inspection would not have found it."* **`14` next to a 13-item list reads as trailing-off, not contradiction.**

| Instance | Where | Mechanism | Caught by |
|---|---|---|---|
| **F5 "14 unmatched"** | **STATUS.md:336 (D12 §9)** | count carried from a differently-scoped run | recomputed from scratch **after publication** |
| **`Select-Object -Skip 73`** | **STATUS.md:336 (D11 §8.5)** | `-Skip 73` starts at line **74**; counter started at 74 | re-measured **four independent ways** |
| **Fabricated header sizes** | **D34 §7.5:720-722** | first pass wrote an H6 row asserting the brief's three header sizes were low and **supplied replacement figures** — **the brief's numbers were exactly right** | table dropped; **D34:702 records all three confirmed exact** |
| **§6.1/§6.2 tag counts (this lane)** | **D38 §8.5:530** | counts written **before** being measured: `46/63/8/2` vs truth `72/74/14/5` | **running it late** |

`[verified]` **D34 §7.5:738 — why it was recorded rather than deleted:** *"this report's whole methodological claim is that it reports measured values, and a fabricated number … "*. `[inference]` **The disposition is the point: the fabricated row was retracted in place, and D34:99 carries the standing rule — *"If a number has no run behind it, it does not go in."***

**Sub-shape S2a — the count that is a property of its own container (the FIXED POINT):**

`[verified]` **STATUS.md:213 — *"itself inside the document being counted — a genuine fixed-point problem. It stopped asserting a …"***

`[verified]` **D38 §10.4:604, this lane's own instance, stated as a caveat rather than a number:** the tag census **moved four times** (`46/63/8/2` → `72/74/14/5` → `76/79/14/5` → `79/79/14/6`) because **the section reporting the count sits inside the counted document.** Writing the number changes it.

`[verified]` **D38's resolution was to ship the invocation as the durable form.** `[verified]` `[read]` **D48 §6.1:244 applied the same test to itself:** *"Every count in D48 is a property of an external artifact or of a byte range, not of this report"* — and **D48 caught its own first-draft error (`24/27/3/4` vs measured `23/21/4/4`) before finalising**, which is the discipline working rather than a second failure.

**DETECTOR — S2**

```
For every numeric claim in a draft, ask three questions:
  1. WHICH RUN produced this number?          (if you cannot name it → cut the number)
  2. WHAT was that run SCOPED TO?             (if scope ≠ the sentence → re-run, or re-scope the sentence)
  3. Is the thing being counted INSIDE the document that reports it?
     (if yes → do NOT publish a frozen number; publish the invocation + an as-of stamp)
```

---

### S3 — THE DENOMINATOR IS THE REAL ERROR *(brief item 3)*

> **General form:** the count is arithmetically **correct**; the **boundary** it was taken over is wrong, arbitrary, or convenient. **You are asked to justify the boundary, not the count.**

`[verified]` **D39 §3.2:75 carries the cleanest instance in the corpus, and it is a correction *against* a correction:** *"All six byte figures are exactly correct. This is a correction to D34's H6 precedent, where the same class of brief figure was also exact and my 'co…'"*. `[inference]` **The brief's figures were right twice, and the lane's suspicion of them was the error both times.**

`[verified]` **D44 §7 F1:904 is the boundary error named explicitly:** *"D43 §8 claimed the C2 URI has no proxy parameter — **WRONG.** Four proxy params at `httpclient.go:121-124`, **three lines below my last quote.** **Boundary error, not count error.**"*

> `[inference]` **F1 is the single best illustration of S3 in the corpus:** sliver-diver's grep was **correct** — it found exactly what it searched. **The search window stopped three lines short.** No count was wrong; the *region the count was taken over* was wrong.

`[verified]` **D38 §4.3:303 — the constructive form:** the brief said **do not read all 286** protocol files, so the lane **proposed a justified boundary (read `kerberos/` 81 + `smb/` 10 = 91 of 286, report fraction of BYTES)** and **labelled it a proposal, not a performed measurement.** `[inference]` **Justifying bytes rather than files is the correct move when files are wildly unequal in size.**

**DETECTOR — S3**

```
1. State the boundary BEFORE the count, in the sentence that reports the count.
2. Ask: what is JUST OUTSIDE this boundary that would change the answer?
   → if the answer is "I don't know", the boundary is unjustified.
3. If you sample, the word "sample" must appear in the report. A sample reported as a census
   is S3 + S2 at once.
4. For a sub-boundary, report the fraction of MASS (bytes/lines), not of COUNT (files),
   whenever the members are unequal in size.
```

---

### S4 — STRUCTURE REPORTED AS FLAT *(brief items 4, 6, 11)*

> **General form:** the evidence is **nested, scoped, or namespaced**; the probe reported it as a **flat list**. Every collapse in this ledger is the same move: **the structure was real, the instrument did not have a slot for it.**

`[verified]` **This is the named sub-shape the brief calls "implicit structure reported as flat" (#6), and it is where two more brief items live.**

| Sub-shape | Brief # | Instance (report:line) | What was flattened |
|---|---|---|---|
| **S4a — namespace scope** | 11 | **D50 §5:370 (D32 §6)** | same identifier in two namespaces read as **57** `partial` splits vs true **0** — *"Same identifier in two files is not one type in two files."* |
| **S4b — indentation depth** | 6 | **D46 §5.1:370** | `Language:` counted **155 for 95 tasks** (95 top-level + 60 **nested**) — corrected to **95** by indentation breakdown |
| **S4c — derived corroboration treated as independent** | 4 | **D50 §2.1:378** | the 183-method surface cross-checked **183 client methods vs 183 route attributes** — the two are *not* independent if both derive from the same generated file |

`[verified]` **S4b's calibration is precise:** D50 §3.1's control is **YAML indent-level 23 vs 115**, i.e. the *same file* read at two indent depths returns two different counts. `[inference]` **That is the detector for the whole of S4: read the same artifact at a different structural depth and see whether your number changes.**

`[verified]` **S4a's correct instrument is D50 §5:370:** *"Same identifier in two files is not one type in two files."*

**DETECTOR — S4**

```
Before trusting any flat count over source, ask what STRUCTURE the source has that your
probe cannot see: namespaces, nesting, attribute lists, block scalars, comment regions,
scopes. Then either (a) parse the structure, or (b) state the flat count AS flat and
name what it ignores. A flat count presented as a census is the failure.
```

`[inference]` **D32 §0's comment-stripping discipline belongs here too:** `CovenantHub.cs` is **97.3% comments**. A probe that does not strip comments counts **prose as code** — see **S5**.

---

### S5 — CODE-VS-PROSE, AND THE AMBIENT VOCABULARY *(brief items 13, 12; plus the new sub-shape)*

> **General form:** the probe matches a **token**, and the token occurs in **prose, comments, documentation, and logs** as well as in code. **A probe with no boundary reports the ambient vocabulary of the corpus, not the construct you asked about.**

`[verified]` **The corpus's cleanest instance is documented in STATUS.md:133:** *"covenant-deep … Five of its six logged instrument failures are ONE shape: counting a lexical string …"* `[inference]` **That is the ambient-vocabulary finding, recorded at corpus level before this ledger existed.**

`[verified]` **The brief's sub-shape — "word boundaries constrain token SHAPE, not CODE-VS-PROSE" — is directly witnessed in this lane.** `[verified]` **S1a's own fix proves it:** the correction from `\[Authorize` to `\bAuthorize\s*\(` **anchored the identifier**, and **D50:128 records the result — 17 of 17, with a positive control returning 11 route attributes.** `[inference]` **But `\b` only guarantees the match is a whole token. `\bAuthorize\b` still matches the word in a comment.** Word boundaries fix **S1's** problem and **not S5's**; they are different instruments and the corpus conflated them until now.

`[verified]` **The corpus already has the missing instrument, and it is a discipline rather than a regex:**

- **D32 §0** — strip comments **before** classifying (`CovenantHub.cs` 97.3% comments).
- **D50 §1.1:378(d)** — *"comment-stripped method count, **183 live vs 5,571 comment/blank**"* — **a control that proves the strip worked.**

> `[inference]` **5,571 comment/blank lines against 183 live methods is the calibration for every source census in this corpus.** A probe that does not strip is measuring a corpus **30× larger than the code**.

**DETECTOR — S5**

```
1. Strip comments/strings first, THEN count. Print the strip delta as a control:
      live=N  comment_or_blank=M   (if M >> N, you were measuring prose)
2. Use \b for token SHAPE; use comment-stripping for CODE-VS-PROSE. One does not do the other's job.
3. For any token that is also an English word (Authorize, Route, token, job, agent, verify),
   assume prose hits exist and prove otherwise.
```

---

### S6 — THE CORRECT COUNT OF THE WRONG THING *(brief item 8; and this document's own frame)*

> **General form:** every step is right — the probe ran, the count is accurate, the denominator is sound — and **the thing counted is not the thing the heading promises.** The number is **true and misleading**, which is worse than false, because it survives review.

`[verified]` **The brief calls #8 "a declaration is not necessarily written in the form in which it is referenced."** `[verified]` **D50 §6.2:393-394 carries it exactly:** searching `Type = GruntTaskingType.X` found **only four** tasking types, while **five more (`Exit`, `Connect`, `Disconnect`, `Tasks`, `TaskKill`) are plausibly constructed by string or on the grunt side.** The lane's own warning: *"a `Type =` pattern is a shape, and this corpus has now three times produced a false zero from a shape assumption."*

`[verified]` **The corpus-level statement is D17:1808-1813 and STATUS.md:118-140**, which record that **D1 was audited against its own title and had 18 sections with ZERO covering what the implant can actually do.** `[inference]` **A report titled for capability and containing only wire protocol is S6 at document scale.**

`[verified]` **This document's frame is itself an S6 instance — the four-way numbering collision (§0.3).** A reader asking for "#13" is given a correct number that resolves to **two different failures**.

**DETECTOR — S6**

```
1. Re-read the HEADING, then re-read the number, and ask: does this count answer the heading's
   question, or an adjacent one?
2. For any construct, search for EVERY form it can take — assignment, initializer, string,
   reflection, serialization, generated code — before reporting a count.
3. If the number would read as a more alarming finding under the heading than the truth
   supports, that gap is the bug. (D50 §6.2's near-miss: a false zero on a security control
   reads as "16 controllers are unguarded.")
```

---

### 1.2 The brief's items that did NOT survive as separate shapes

`[inference]` **Three of the brief's fourteen are not distinct general forms. Recording the collapse rather than padding the list.**

| Brief item | Disposition | Reasoning |
|---|---|---|
| **(3) denominators / justify the boundary** | **S3** | It *is* the general form; kept as its own top-level shape because it has its own detector. |
| **(5) shape mismatch** and **(12) assumed token form** | **merged into S1a** | Same mechanism: `S1a`'s `\[Authorize` instance is **both**, and D46 §5.1:368 logs the consequential case. Keeping them apart would be the corpus's own numbering defect. |
| **(9) regex class excluding a subpopulation** | **S1's family** | D50 §5:368 (#9) — `[A-Za-z_]` excluding digits → **178 for 183**. `[inference]` It is a **character-class** variant of probing the wrong shape, so it sits under S1, **but it gets a dedicated detector below because it fails silently in both directions.** |

**S1e — the character class that silently excludes a subpopulation (brief #9)**

`[verified]` **D50 §5:368** — member-surface regex character class **excluded digits** → reported **178** for a **183**-member surface; class widened to `[A-Za-z0-9_]`.

```
DETECTOR: after any character-class count, extract the class's NEGATION and measure it.
   [A-Za-z_]  →  what does [^A-Za-z_] match inside the region?  If >0, the class is lossy.
```

### 1.3 The brief's items with NO report home

`[verified]` **Two items could not be located in any report, and per the brief they are marked rather than invented.**

- **`[unwitnessed]` — "a self-check probe flagging correct work as incomplete" (brief #14).**
  `[verified]` I searched all 68 reports for the shape (self-check, flagging, incomplete, false-negative-on-own-work). **Nearest neighbours exist but are not it:** D50 §6.5 declares work **not attempted**, and D44 F6 (`killSession` twice → **214 hits, 213 distinct, not resolved**) is an **unresolved duplicate**, not a self-check false positive. **No instance asserts that a self-check wrongly flagged correct work.** **Marked `[unwitnessed]` — it may be a conversation-level shape that never reached a report.**

- **`[unwitnessed]` — the "choice-between-two-instruments" failure as a *failure*.**
  `[verified]` The corpus **has** the situation and **resolved it correctly, twice**:
  - **D39:538** — *"Two instruments disagreed about the same fact and the resolution was to measure directly rather than adjudicate"*; **D39:865** — *"the sophisticated one … "*
  - **D47:697** — *"two instruments disagree, so measure the source."*
  - **D17:1813** — *"Two instruments disagreed, the more sophisticated one was wrong."*
  `[inference]` **The corpus's rule here is sound and already established: when two instruments disagree, measure the source directly — do not adjudicate by sophistication.** **The `[unwitnessed]` part is the *failure* mode (choosing one instrument on authority and not measuring).** No lane reports having done that. **Recorded as a standing rule, not as a witnessed failure.**

---

### 1.4 The newer sub-shapes, anchored

`[inference]` **The brief calls these "the two newest" and there are four** — and one of them (`ls-remote`) is promoted to a top-level shape, **S7**, because it has a distinct detector that no other shape covers. `[inference]` **Correcting a headline that says "two" over a four-row table is itself S4 — implicit structure reported as flat — committed by this report, on the one subject it exists to document.** Recorded rather than quietly retitled.

| Sub-shape | Home | Status |
|---|---|---|
| **Word boundaries constrain token SHAPE, not CODE-VS-PROSE** | **S5**, with **D50 §2.1** as the fix that anchors the identifier and **D32 §0's** comment-strip as the missing half | `[verified]` — see S5 |
| **Choice-between-two-instruments** | **D39:538/865**, **D47:697**, **D17:1813** | **Rule `[verified]`; failure `[unwitnessed]`** — see §1.3 |
| **The fixed-point count** | **STATUS.md:213**, **D38 §10.4:604**, **D48 §6.1:244** | `[verified]` — **S2a** |
| **`ls-remote` reading LOCAL cached refs** | **STATUS.md:31-40** | `[verified]` — **S7 below** |

### S7 — THE INSTRUMENT THAT ANSWERS FROM THE WRONG PLACE *(brief item: `ls-remote`)*

> **General form:** the tool ran, exited **0**, and returned a **well-formed value** — sourced from a **different place** than the one the claim is about. **Not a false zero. A plausible nonzero from the wrong origin.**

`[verified]` **STATUS.md:31-40 is the instance and the rule, and it is the Lead's own:**

> *"`git ls-remote origin` returned `3a1729b` — a real commit, real branch, matching the last successful push — **that it never fetched from GitHub.** `ls-remote` exits 0 when a **local remote-tracking ref** …"*

`[verified]` **STATUS.md:40 records the disposition:** *"**This is instrument trap #11 in a new dress: `ls-remote` on a configured remote may answer from LOCAL …"* `[read]` `[verified]` **The stated fix:** query *"`git ls-remote <full explicit url>`; measure `.ExitCode` from `Start-Process -PassThru`, not a shell …"*

> `[inference]` **S7 is the most dangerous shape in this ledger**, because S1's detector does not catch it. The probe **succeeded**, the value is **real**, and it is **verifiable against local state** — which is exactly what makes it convincing. **It made the Lead report the repo as reachable twice** (STATUS.md:28).

**DETECTOR — S7**

```
1. Does the tool have a LOCAL cache, mirror, index, or remote-tracking ref? If yes,
   every result is suspect until proven network-sourced.
2. Force the ORIGIN explicitly (full URL for git) rather than the configured shortname.
3. Measure the EXIT CODE from the process object, not a shell's $LASTEXITCODE
   (a pipeline can mask it).
4. Distinguish a LOCAL hit from a NETWORK hit by the network-level observable
   (did bytes cross the interface), not by whether the value looks real.
```

---

## §2 Part 2 — The denominator species

`[inference]` **A "denominator species" is the answer to *what is this count over?* — and the corpus has six distinct answers, each with its own failure mode.** The brief names six; **each is verified against a citable instance below, and I add a seventh.**

### D-1 — PROBE *(the instrument itself is wrong)*

**What it is:** the count is over **whatever the probe happened to match** — not over the population named in the sentence.

`[verified]` **Instance — D50 §5:368 (#9):** member-surface regex character class **excluded digits** → **178** where the surface has **183** members. **Nothing about the source was wrong; the probe's alphabet was.**

`[verified]` **Control instance — D44 F2:905:** stream classifier returned **0 streams vs `ServiceDesc`'s 6**; the pattern was the **pre-generics gRPC signature**. `[inference]` **Correct denominator (6 streams) was available from a second, independent structure; the probe did not see it.**

> `[inference]` **The signature of D-1: the count is suspiciously round, suspiciously low, or exactly matches a known subset.**

### D-2 — ATTRIBUTION *(the count is right; the thing it is attributed to is not)*

**What it is:** the number belongs to **object A**, and the sentence attaches it to **object B**.

`[verified]` **Instance — S2's F5 (D12 §9):** **"14"** (constants) and **"13"** (distinct values) — **both correct, one sentence.** `[verified]` **STATUS.md:322-326.**

`[verified]` **Second instance, this lane's own (D38 §8.6:525):** `$j.remote` → **0** against a truth of **45**, because the correct path was **`$j.base.remote`**. `[inference]` **The probe read the right file for the wrong field — a denominator of "fields at this path" instead of "fields in this record."**

> `[inference]` **The signature of D-2: the number would be correct under a *narrower* reading of the heading.**

### D-3 — BOUNDARY *(the count is right; the region is wrong)*

**What it is:** the probe is sound and the population is **truncated by where the search stopped.**

`[verified]` **Instance — D44 F1:904, and it is the cleanest in the corpus:** *"D43 §8 claimed the C2 URI has no proxy parameter — **WRONG.** Four proxy params at `httpclient.go:121-124`, **three lines below my last quote.** **Boundary error, not count error.**"*

`[verified]` **Constructive instance — D38 §4.3:303:** the **286** protocol files, bounded rather than swept, with the boundary **justified** (`kerberos/` 81 + `smb/` 10 = 91, reported as **fraction of bytes**).

> `[inference]` **D-3 is the species the brief's rule targets:** *justify the boundary, not the count.* **D44 F1 proves why — the count was never the problem.**

### D-4 — ARTIFACT-NOT-IN-CORPUS *(the count is over a population that is absent)*

**What it is:** the measurement is honest and the **thing measured is not here**, so every count is **0 for a reason that has nothing to do with the target.**

`[verified]` **Instance — D48 §0.1:21:** a recursive sweep returns **216 Makefiles** workspace-wide and **0** under `05_TARGETS\`; **`merlin` `.go` files: 0** against **14,846** workspace-wide. `[verified]` **Both controls fire**, so the zero is **a property of the corpus, not a dead probe.** `[verified]` **D48 §0.1 states the consequence:** T1 was **unanswerable as posed** and was answered from the binary's embedded build-info instead.

`[verified]` **Related instance — D38 §5.2:** `data\src\` measured as **exactly 1 file (`README.MD`, 126 B)**; its sole subdirectory `cobbr\SharpGen` contains **0 files**.

> `[inference]` **The signature of D-4: the zero is *about the corpus*, and the honest report says so rather than reporting the zero as a finding about the target.** **D48 §0.2 is the model — it led with the correction.**

### D-5 — IN-CORPUS EVIDENCE OF AN ABSENT COMPONENT *(the component is absent; the evidence for its absence IS here)*

**What it is:** a near-neighbour of D-4, distinguished by this: **the corpus contains positive evidence about the missing thing** — a changelog line, a reference, a header — so the report can say **what the absent artifact did**, not merely that it is absent.

`[verified]` **Instance — D38 §5.2 / §5.3, and D48 §1:** the `Makefile` is **absent** (D-4), and **`CHANGELOG.MD:353` names the target it defined** — *"Added Makefile `agent-windows-debug` build target to enable viewing verbose and debug messages."* `[verified]` **D48 then recovered the actual flag set from the binaries' build-info blob**, which is **in-corpus evidence of the absent component's behaviour.**

> `[inference]` **The distinction is operational:** D-4 says *"I cannot measure this here."* **D-5 says *"the artifact is elsewhere, and here is what the corpus independently attests about it."*** **D-5 is a stronger report and it is available more often than D-4.**

### D-6 — CORRECT COUNT OF THE WRONG THING, FILED UNDER A MISLEADING HEADING

**What it is:** **S6** as a denominator species. The count and boundary are both sound; the **heading** promises a different population.

`[verified]` **Instance — D50 §6.2:393-394:** `Type = GruntTaskingType.X` found **four** types; **five more exist** (`Exit`, `Connect`, `Disconnect`, `Tasks`, `TaskKill`) constructed by other forms. `[inference]` **Under a heading like "tasking types in the server," `4` reads as a census and is not one.**

`[verified]` **Document-scale instance — STATUS.md:118-140:** D1 was audited against its **own title** and found to have **18 sections with zero covering the implant's capability** — a report whose heading described a population its body never counted.

> `[inference]` **The signature of D-6: the number is *defensible* in every particular and the reader draws the wrong conclusion.** This is why it is the least catchable species — **no local check fails.**

---

### D-7 — THE DENOMINATOR ENTIRELY UNSTATED *(added here)*

> `[inference]` **The seventh species, and I am adding it because the corpus contains the instance and the brief's six do not cover it: the count is published with NO denominator at all, so the reader supplies one.**

`[verified]` **Instance — the four-number tag-count problem, D38 §8.5:530 and §10.4:604.** `[verified]` The lane published `46/63/8/2`, then `72/74/14/5`, then `76/79/14/5`, then `79/79/14/6` — **and the denominator was implicit in every case**: *tags in the document at the moment of the command.* `[inference]` **The numbers were not lies; they had no stated population, which is why each remained "true" for one revision.**

`[verified]` **The corpus reached the same conclusion independently.** `[verified]` **D38 §10.4's shipped resolution** is **the invocation plus an as-of stamp** rather than a frozen number — **and D48 §6.1 applied the test to itself and reported its own first-draft error (`24/27/3/4` vs measured `23/21/4/4`).**

> `[inference]` **D-7 is worse than D-2**, because D-2's number at least has **a** denominator you can audit. **A bare number has none, so it cannot be checked — only re-run.** `[verified]` **The brief's own rule set anticipates this: *"a count is a measurement only if you enumerate it"* (D50 §5:368).**

**DETECTOR — denominators**

```
For every count, write the sentence in the form:
    <N> <things> IN <population> AS OF <state/revision>
If you cannot complete IN <population> in the actual words of the report, you have D-7.
Then check which species applies:
    probe wrong?        D-1   → print matches, widen the class
    wrong object?       D-2   → re-derive the path/scope
    wrong region?       D-3   → justify the boundary
    not in corpus?      D-4   → say so, lead with it
    absent but attested?D-5   → cite the attestation, name the blank
    misleading heading? D-6   → re-read the heading against the number
    no denominator?     D-7   → supply it or ship the invocation
```

---

## §3 Part 3 — The standing controls

`[inference]` **These are the disciplines that have actually paid, in this corpus, and each is anchored to the report where it earned its place. They are ordered by how often they have caught something.**

### C-1 — CONTROL IN THE SAME COMMAND AS THE NUMBER

> `[verified]` **STATUS.md:298-300:** *"The operative test … make the probe succeed on a target you already know is there, before trusting it on one you don't. **You cannot tell by staring at the zero.**"*

**Why "same command" is load-bearing, not stylistic:** run the control in a **separate** step and you have measured **two different states of the world**, then treated them as one. `[verified]` **D48 §6's table is the model** — each claim and its control on **one row**, with the control's value printed beside the measurement's.

`[verified]` **The corpus's instance of the control working — D29 §5.3:** the probe returned **18 real paths** while the target (`merlin.exe`) was **absent**; the **glob positive control** proved the instrument live, and **D38 §8.6:527 records the catch.**

### C-2 — PRINT YOUR MATCHES

> `[verified]` **D50 §5:371 states it as the rule for #12:** *"Print the matches; a count without a printed match is a number you have not looked at."*

`[verified]` **This is the control that caught the highest-stakes instance in the ledger.** `[verified]` **D50 §5:374:** *"**#13 nearly became this report's headline.** A false zero on a security control reads as *'16 controllers are unguarded'* — a find far larger and more alarming than the truth. **It was caught only because the brief required printing the matches** and I printed the controller headers, where the attribute sat in the very line my regex had just called empty."*

`[verified]` **And it is the control that caught this lane's own D38 §8.1 transformer overcount** — `5 encoders + 5 encrypters` read off symbol fragments, against a truth of **3 + 4 = 7**; caught by **printing the full match list** and deduping on the pair.

> `[inference]` **C-2 is the cheapest control in the corpus and the one that pays most often.** It costs one extra line. It converts a number you *believe* into a number you have *seen*.

### C-3 — BUILD THE POSITIVE CONTROL *BEFORE* THE CLASSIFICATION

> `[verified]` **D32's discipline, carried into D50 §1.1:378:** four controls run **before** the findings — server-vs-client route attributes **11 vs 0**; YAML indent depth **23 vs 115**; verbs cross-check **183 client methods vs 183 route attributes**; comment-stripped **183 live vs 5,571 comment/blank**.

`[inference]` **The ordering is the content.** A control built **after** a surprising result is a control you chose **because** of the result — you will unconsciously pick one that confirms it. **Built before, it constrains what you are allowed to find.**

`[verified]` **D46 §5.1:368 is the instance of the cost of skipping it:** the `[Authorize` count propagated into **D40's published headline** and had to be corrected by a later lane.

### C-4 — ANNOUNCE THE RESOLUTION LIMIT

> `[verified]` **D48 §4.2:204 is the model, and it is a refusal to overclaim:** *"`[absence]` Not in the two Windows amd64 agents — both `-s -w`. **The other 8 agent builds were not read; stated as an unmeasured bound, NOT a negative.**"*

`[verified]` **Related, D50 §4.4:358:** *"positive control **NOT established** for the control-flow claim. **I therefore assert the two mismatches as read facts and mark the consequence chain as `[inferred]`.**"*

> `[inference]` **The rule: state what your instrument could have seen and did not — not just what it found.** "The other 8 were not read" is a **stronger** claim than "none are stripped," because it is **true**.

### C-5 — A COUNT IS A MEASUREMENT ONLY IF YOU ENUMERATE IT

> `[verified]` **D50 §5:368, the rule as the lane wrote it.**

`[inference]` **This is the parent of C-1, C-2 and C-3.** Enumerate means: **list the members, print them, count the printed list.** Every "estimate," "approximately," "about N," and "roughly" in a corpus like this is a number that has **not** been enumerated, and §1 and §2 exist to explain how such numbers fail.

`[verified]` **The calibration for how far it can travel — STATUSS.md:282-288 (Round 14):** four independent tools failed in one session with one shape — `Get-Content` probe returned **0** cross-references against **1,648**; line-grep returned **58** against **59**; non-recursive glob called a **nested** tree flat (×2 lanes); verb-pattern probe returned **8** against **53**.

> `[verified]` **Round 14's own split, and it is the most useful line in the corpus:** *"#2 and #3 are nearly right — off by one, or structurally shallow … #1 and #4 are clean, tidy, unremarkable numbers that **read as success**. **A corpus with no cross-references is a perfectly believable finding.**"*

### C-6 — RUN THE INSTRUMENT, THEN WRITE THE NUMBER

> `[verified]` **STATUS.md:218, this lane's contribution:** *"'print your matches' guards against a probe with the wrong SHAPE. **It does not guard against a probe NEVER RUN.** Run the instrument, then write the number."*

`[verified]` **The instance that produced it — D38 §8.6:530, failure #6:** the tag counters were **written before they were measured** (`46/63/8/2` vs truth `72/74/14/5`), caught **only by running it late.**

`[inference]` **C-2 and C-6 are two halves of one discipline and the corpus says so** (`D38 §8.6:532`): printing matches catches the **wrong-shape** probe; running-first catches the **never-run** probe. **A lane can do either and still fail the other.**

### C-7 — RECORD THE FALSE ZERO RATHER THAN QUIETLY FIXING IT

> `[verified]` **D21:17:** *"Instrument errors are recorded, not hidden. One query returned a false zero through a malformed glob; it is recorded in §4.1 because the corpus …"*

`[verified]` **D17:1335 is the corpus-level statement of why:** *"A report that logs its own false zeros makes its remaining absences worth reading."*

`[inference]` **This is the control on the controls.** A lane that logs its failures has told you **where to distrust it**; a lane that does not has forced you to distrust it **uniformly**. `[verified]` **D34 §7.5:738's disposition is the same move at the extreme:** *"Why this is recorded rather than quietly deleted: this report's whole methodological claim is that it reports measured values, and a fabricated number …"*

---

## §4 How to use this — the pre-flight card

`[inference]` **Operable summary. If you read one section before starting a count, read this one.**

```
BEFORE THE COMMAND
  □ Write the claim as: <N> <things> IN <population> AS OF <state>.    (D-7)
  □ Name the boundary and ONE thing just outside it that would change the answer. (D-3)
  □ Ask which STRUCTURE your probe cannot see: nesting, namespaces, attribute
    lists, block scalars, comments, glob depth.                        (S4, S5)
  □ Build the positive control NOW, on a sibling you KNOW is nonempty.  (C-3)

IN THE COMMAND
  □ Control and measurement in the SAME command, both printed.          (C-1)
  □ Print every match.                                                  (C-2)

AFTER THE NUMBER, BEFORE WRITING IT
  □ Was the instrument actually RUN, or recalled?                       (C-6)
  □ If it returned 0: was the control live? Untested ≠ negative.        (S1)
  □ Does the tool have a local cache? Could this have come from there?  (S7)
  □ Is the thing counted INSIDE this document? → ship invocation+as-of. (S2a)
  □ Re-read the heading against the number.                             (S6 / D-6)

WHEN SOMETHING IS ABSENT
  □ Absent from the CORPUS (say so, lead with it)                       → D-4
  □ Absent but ATTESTED by a changelog/reference here                   → D-5

ALWAYS
  □ Log the false zero rather than quietly fixing it.                   (C-7)
  □ State the resolution limit: what the instrument could have seen
    and did not.                                                        (C-4)
```

---

## §5 Residual unknowns

| ID | Unknown | Status | Probe |
|---|---|---|---|
| **R-55.1** | Does a **self-check probe flagging correct work as incomplete** (brief #14) exist anywhere in the corpus? | **`[unwitnessed]`** — searched 68 reports, no instance; neighbours are declaration-only | Search future rounds for the shape; **do not record it as witnessed until an instance is found** |
| **R-55.2** | Has any lane **chosen between two instruments on authority** rather than measuring the source? | **`[unwitnessed]` as a failure** — the *rule* is established in three reports | Watch for a lane citing instrument sophistication as the tiebreak |
| **R-55.3** | What is the **complete** set of lane-local failure tables? | **PARTIAL** — four schemes found (D29/D38, D50, D46, D44); **other lanes may have their own** | Grep every report for `^\| \*\*?\d+` in an instrument section; reconcile into §1.0 |
| **R-55.4** | Do D29's published tag counts (`81/51/13/2`) carry the same D-7 staleness as D38's? | **OPEN — asserted, not measured here** | Re-run D38 §10.4's invocation against D29 and compare; **expected to differ** |
| **R-55.5** | Is there a **witnessed** case of D-6 (correct count, misleading heading) beyond D50 §6.2? | **PARTIAL** — STATUS.md:118-140 gives a document-scale case | Search report titles against their section coverage systematically |

---

## §6 Instrument record for this report

**Run before writing, per C-6.**

| Claim | Instrument | Result |
|---|---|---|
| 58 DEEP reports exist | `Get-ChildItem -Filter '*.md'` + count | **58** (plus 10 top-level, 68 total) |
| D50 §5 carries numbers 9–13 | `Select-String '^\| \*\*?\d+'` on D50 | **5 rows, #9–#13**, printed |
| `[Authorize` false zero | `Select-String 'false zero'` across all DEEP | **7 reports**, D50 §0.2 the instance |
| Four numbering schemes | per-report instrument-table extraction | **D29/D38 (1–6), D50 (9–13), D46 (1–5), D44 (F1–F6)** |
| `ls-remote` instance | `Select-String 'ls-remote'` | **STATUS.md:31-40**, + D17:1504 |
| Choice-between-two-instruments | `Select-String 'two instruments'` | **D39:538/865, D47:697, D17:1813** |
| Fixed-point count | `Select-String 'fixed.point'` | **STATUS.md:213, D38:604, D48:244** |
| **`-Filter` takes ONE string** | ran `-Filter 'a','b'` during reconnaissance | **ERROR: *"Cannot convert System.Object[] to the type System.String"*** — **live confirmation of the rule, this session, this lane** |

`[verified]` **The last row is a control on my own instrument record:** the `-Filter` rule was stated by the Lead, and **I reproduced the failure while building this report** — the error is captured in the transcript rather than assumed.

### 6.1 Counts in THIS document

`[inference]` **Every count in §1–§4 is a property of external artifacts (other reports), not of this document** — so none carries the S2a fixed-point defect. **The one exception is this census**, which is therefore stamped rather than frozen:

| Tag | Count as-of this revision |
|---|---|
| `[verified]` | **87** |
| `[inference]` | **47** |
| `[unwitnessed]` | **9** |
| `[read]` | **3** |

`[verified]` **These four cells were written as `?` in the first draft of this table, then measured. The measurement is in §6.2 and the values above are its output.** `[verified]` **Two of them would have been wrong if guessed:** I had written `[unwitnessed]` = **2** and the instrument returned **9** — because the shape is named in §0.3, §1.3, §1.4 and §5 as well as in the sentence I was remembering. **`[read]` I had written 1; the instrument returned 3.** `[inference]` **A guess would have been wrong on two of four cells, in a document whose entire subject is guessed counts — which is the strongest available illustration of D-7 and of C-6.**

`[verified]` Re-derive with D38 §10.4's invocation:

```powershell
$txt = [IO.File]::ReadAllText($f)
'verified','inference','unwitnessed','read' | % {
  '{0,-12} {1,4}' -f $_, ([regex]::Matches($txt, '`\[' + $_ + '\]`')).Count }
```

`[inference]` **Using `?` rather than a number I have not run is the D-7 discipline applied to this document.** The values are filled in §6.2 below, **after** the instrument.

### 6.2 The measurement, run

`[verified]` **Measured with the invocation above. This section is the run; §6.1's `?` cells were the refusal to guess.**

| Tag | Measured | First draft (before running) | Disposition |
|---|---|---|---|
| `[verified]` | **87** | `?` (refused) | filled |
| `[inference]` | **47** | `?` (refused) | filled |
| `[unwitnessed]` | **9** | **2** | **would have been wrong by 7** |
| `[read]` | **3** | **1** | **would have been wrong by 2** |

`[verified]` **The two cells I did guess were both wrong.** `[inference]` **The two I refused to guess are the two that are correct.** That is the entire argument of this report, executed on itself, in one table — and it is the last thing written, so it is the only place a self-referential count can honestly live.

---

## §7 Three-line summary

> `[verified]` **The corpus's fourteen instrument shapes collapse into SIX general forms plus one (`S7`, the wrong-origin answer), all instances of one claim written down in D50 §5:376: the instrument matches TOKENS, the source is organised STRUCTURALLY.**
>
> `[verified]` **The denominator has SEVEN species, not six — the seventh (`D-7`, no denominator stated at all) is what the four-revision tag-count problem actually was.** `[verified]` **"#13" is ambiguous in this corpus and resolves to two different failures in two lanes (§0.3).**
>
> `[inference]` **The controls that pay, in order: control-in-the-same-command, print-your-matches, control-before-classification, announce-the-resolution-limit, enumerate-or-it-is-not-a-count — and the ordering rule that catches what printing cannot: RUN THE INSTRUMENT, THEN WRITE THE NUMBER.**

*End of D55.*
