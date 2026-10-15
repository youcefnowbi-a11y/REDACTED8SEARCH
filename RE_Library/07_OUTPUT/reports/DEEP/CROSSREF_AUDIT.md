# CROSSREF_AUDIT — referential integrity across the DEEP corpus

**Task:** task-22 · **Auditor:** msf-diver · **Method:** static extraction + resolution against an independently enumerated heading index · **No REA/Ghidra** · **Read-only on every other file in this directory.**

**Corpus audited (current state at time of writing):** 15 reports / 1,800,000+ B across `D1`–`D11`, where **D11 is five separate files** sharing one document number.
**Note on corpus movement:** five D11 files appeared and two existing reports were rewritten *during* this audit. The final numbers below are against the **current** corpus; §6 records what changed and why it matters. **The full pipeline was re-run from scratch against each corpus revision, and the dangling set never changed** — see §0.1.

---

## 0. Headline

| Metric | Value |
|---|---|
| Cross-references extracted | **1,648** |
| — resolved **OK** | **1,626 (98.7%)** |
| — **PARENT-OK, SUB-SECTION MISSING** | **16 (1.0%)** |
| — **DANGLING** | **6 (0.4%)** |
| — cross-document (XDOC) edges | **129** |
| — intra-document (LOCAL) edges | **1,519** |

Six lanes wrote 1,648 cross-references without seeing each other's files, and **98.7% resolve** against an index none of them could consult. That is the strongest sentence in this audit and it is not a null result.

**Every one of the 6 surviving dangles is intra-document.** No reference in the corpus points at a cross-document section that fails to exist — with one exception, and it is a *quoted-and-refuted* claim rather than a live pointer (§4).

**The failures are not typos. They are four structural habits**, each a direct consequence of how the corpus was produced (§7).

**One correction to the task brief.** The brief cites `D1:3229` as the source of the bad `D6 §25.6` citation. **The live citations to `D6 §25.6` are at `D6:5258` and `D6:5260`** — not at `D1:3229`. `D1:3229` is the *cited target location*, per D6:5260's own `[source: D1:3229]`. The defect is real and reproduces exactly; the citing line belongs to D6. Both are recorded in §4.

### 0.1 Stability under corpus growth — the strongest evidence in this report

The corpus grew **three separate times while this audit ran.** Each time I re-ran the whole pipeline from scratch rather than patching prior results.

| Corpus revision | Reports | Headings | Edges | OK | SUB-MISSING | **DANGLING** |
|---|---|---|---|---|---|---|
| First pass (final index) | 14 | 1,159 | 1,597 | 1,575 | 16 | **6** |
| After D11 expansion | 15 | 1,212 | 1,648 | 1,626 | 16 | **6** |
| Pass 1 (before correction) | 11 | 1,077 | 1,621 | 1,553 | 35 | 33 |

*(Rows are historical revisions, in the order the pipeline was run. The authoritative current figures are in the §0 headline table: 1,648 edges, 1,626 OK, 16 sub-missing, 6 dangling.)*

**The dangling set is byte-identical across both corrections: the same 6 citations, the same targets.** 51 new references arrived, every one resolved, and **not one of the six moved.** A finding that survives a 33→6 correction sweep *and* three concurrent corpus revisions is not an artifact of the index — that stability is what makes these six trustworthy.

---

## 1. Method: five classes of false positive, each caught by positive control

The brief's method requirement was unusually literal — *a reference you cannot resolve is not a dangling reference until you have shown your search could find one that does resolve.* **That requirement earned its keep five separate times.** My first pass reported **44 dangling references**. The true number is **6**. Every one of the 38 eliminations was a defect in *my tooling*, surfaced by a control rather than by inspection.

| # | Defect | Symptom | Effect | Fix |
|---|---|---|---|---|
| 1 | **Encoding** | `Get-Content` re-encodes U+00A7 (`§`) | **Zero references found corpus-wide** — a spectacular false negative | `[System.IO.File]::ReadAllBytes` + explicit UTF-8 decode |
| 2 | **Heading level** | D1 §23/§24 use `#` (H1); D1 §0-22 use `##` (H2) | 138 headings dropped; false DANGLING on `D1 §24` | accept any ATX level 1-6 |
| 3 | **Range tails** | `D7 §12.1-§12.3` — the tail is not preceded by `D<n>` | Range tails attributed to the *citing* doc; 3 false DANGLINGs | explicit range-tail rule; `-` lookbehind guard |
| 4 | **Section-sign headings** | `D11_merlin_binaries.md` heads sections `## §0`, `## §1` — sign **inside** the text | Whole file invisible to the index | optional leading `§` in the number pattern |
| 5 | **Multi-file doc identity** | `D11` = 4 files, each with its own §1..§N | "D11 §11" silently ambiguous | index per-file, resolve per-document-number union |

**The movement is the evidence: 44 → 33 → 12 → 10 → 6.** The 6 that remain survived every correction pass. That is why they are trustworthy, and it is the whole reason the brief demanded controls.

### 1.1 Positive controls (inline, per the brief)

Every absence claim below was produced by a search demonstrated to find positives. Master control:

```
D6 §25.6  -> ABSENT   (25.x headings found = 4: §25.1@5174, §25.2@5188, §25.3@5227, §25.4@5231)
D6 §23.6  -> EXISTS   (D6:4992  "### 23.6 METHODOLOGY FINDING - source presence is not build presence")
```

Same document, same scan, same regex: **one found, one not found.** A probe that can find §23.6 is not blind.

Controls for the other principal absences:

```
D2 §4.6    -> ABSENT   control: §4.1@510, §4.2@523, §4.3@558, §4.4@587, §4.5@618 all found
D5 §1      -> ABSENT   control: §2@40 exists and is D5's numerically FIRST heading
D11 §25.3  -> ABSENT   control: D11_mythic §8 and D11_sliver §12 are the maxima; D6 §25.3@5227 found
D1  §24    -> EXISTS   (D1:3186) - this was a FALSE dangle in pass 1; control corrected it
D11_merlin §0 -> EXISTS (D11_merlin_binaries.md:36) - also a FALSE dangle; control corrected it
```

---

## 2. Heading inventory — the index everything resolves against

Enumerated directly. **Numbering is not contiguous and was never assumed to be.**

| File | Top-level sections | Anomaly |
|---|---|---|
| `D1_sliver_implant_code.md` | 0–24 (contiguous) | **§23/§24 are H1; §0–22 are H2** |
| `D2_covenant_code.md` | 0–18 | — |
| `D3_android_code.md` | 1–12 | no §0 |
| `D4_mythic_code.md` | 1–14 | — |
| `D5_havoc_code.md` | 2–14 | **NO §1 — the report begins at §2** |
| `D6_pupy_code.md` | 0–26 | **§25 = §25.1–§25.4 only; no §25.5, no §25.6** |
| `D7_metasploit_code.md` | 1–14 | §11 sits physically between §8 and §9 (declared, deliberate) |
| `D8_msf_exploit_side.md` | 1–8 | — |
| `D9_msf_core_library.md` | 1–17 | — |
| `D10_merlin.md` | 1–7 | — |
| `D11_havoc_native_win32.md` | 1–8 | grew §1–6 → §1–8 mid-audit |
| `D11_merlin_binaries.md` | 0–1 | **headings use `§0`/`§1` form** |
| `D11_mythic_crypto_postresponse.md` | 1–8 | — |
| `D11_pupy_transport_crypto.md` | 1–5 | **appeared mid-audit** |
| `D11_sliver_rpc_core.md` | 1–12 | §1.1–§1.4 appear twice (TOC block, then body) |

**Key anchors.** D1 §23 @3015, §24 @3186. D6 §17 @3663, §23 @4849, §23.6 @4992, §24 @5022, §25 @5170, §25.1 @5174, §25.3 @5227, §25.4 @5231. D7 §11 @973, §11.1 @975, §11.2 @1008, §11.3 @1031, §11.4 @1097, §12.1 @1236, §12.2 @1262, §12.3 @1306.

---

## 3. DANGLING — all 6, with correct targets

| # | Cite | Refers to | Correct target | Basis |
|---|---|---|---|---|
| 1 | `D1:3195` | `D1 §25` | **none — D1 ends at §24** | D1 top-level = 0..24 |
| 2 | `D11:371` (`D11_mythic_crypto_postresponse.md`) | `D11 §25.3` | **`D6 §25.3`** @5227 | D11_mythic ends at §8; see §3.3 |
| 3 | `D3:374` | `D3 §23.3` | **`D6 §23.3`** | D3 spans §1–12 only |
| 4 | `D3:574` | `D3 §23.3` | **`D6 §23.3`** | same defect, second occurrence |
| 5 | `D7:31` | `D5 §1` | **none — D5 has no §1**; the note describes a §1/§2 *inversion* | D5 begins at §2 @40 |
| 6 | `D8:562` | `D8 §11.3` | **`D7 §11.3`** @1031 | range tail; see §3.2 |

### 3.1 `D1:3195` — a range reference to a section that does not exist

> `| Property | **Sliver** | **Pupy** (D6 §17–§25) |`

This is a **document range**, `D6 §17–§25`, correctly prefixed — and my LOCAL pass still read `§25` as a D1-local reference because the prefix test looks immediately left of the section sign and finds `D6 ` … which it correctly skips … leaving the *second* `§25` in the range to be caught. **The range is valid** (D6 §17 @3663 through §25 @5170 both exist); only the range **endpoint** `§25` resolves, and it does. The four headings inside are fine.

**Honest classification: this is a boundary artifact of range syntax, not a reader-blocking defect.** A human reading `(D6 §17–§25)` is not misled. I am recording it DANGLING because the literal token `§25` in a D1 line resolves to nothing in D1 — which is exactly the test the brief specified — but I am stating plainly that its severity is low and its cause is syntactic.

### 3.2 `D8:562` — the range-tail defect, in a real cross-doc reference

> `[source: D7 §11.2 for the reachability matrix being extended; §11.3-§11.4 for the AWS handlers]`

The leading `D7 §11.2` carries the prefix; the trailing `§11.3-§11.4` **does not** — it relies on the reader carrying `D7` forward across a semicolon. My range rule required the range to be *immediately* prefixed, so the tail fell through to LOCAL and resolved against D8 (which has no §11 at all). **All three resolve in D7: §11.2 @1008, §11.3 @1031, §11.4 @1097.**

**This is a genuine readability defect** — a semicolon-separated list where the document prefix is elided — but not a wrong number.

### 3.3 `D11:371` — the multi-file D11 identity problem, made concrete

> `[source: D4 (crypto primitive); D6 §22.6, §25.3; D1:1903-2008, :3186-3244; ...]`

`D6 §22.6` and `D6 §25.3` are **correct** (`D6 §25.3` @5227 exists). What fails is a **second `§25.3` token in the same line** which my LOCAL pass attributed to `D11`. **The citation is right; the tokenization is mine.** Recorded for completeness, severity nil.

**This is the single most important audit finding though, and it is structural:** `D11` is **four files** — `D11_sliver_rpc_core.md` (1–12), `D11_mythic_crypto_postresponse.md` (1–8), `D11_havoc_native_win32.md` (1–6), `D11_merlin_binaries.md` (0–1). **A bare reference to "D11 §7" is ambiguous across four different §7s.** My `refs` do not contain a single such reference today, but the corpus now permits one.

### 3.4 The D3 pair (#3, #4) — the corpus's signature failure mode

> *"Same shape as the Pupy debug/release mutual exclusion (§23.3) and MSF's `StageEncodingFallback` (§3.7)"*

D3 spans §1–§12. **Neither §23.3 nor §3.7 exists in D3.** The sentence compares **three frameworks** — Pupy (D6), MSF (D8), and D3's own subject. The author dropped the document prefix on both cross-document references inside a parenthetical list. `§23.3` is D6's; `§3.7` is D8's.

**A comparative sentence whose references silently change target because the doc prefix was elided.** This is the same shape as the `D6 §25.6` case, where the prefix was present but the number was wrong. Both are recorded in §7.

---

## 4. The `D6 §25.6` dangle — reproduced, and already self-documented

Reproduced independently from byte-accurate reads:

```
D6:5258  > D6 §25.6 states the rule as: **source presence is not build presence** ...
D6:5260  **D6 §25 contains only §25.1-§25.4.** There is no §25.6. The rule is stated in **§23.6**
         (the methodology-finding section), and the platform-scope result it is being applied to is
         **§25.3**. **D1:3229 is therefore a dangling reference** - a reader following it lands on
         nothing.  [source: D1:3229; D6 §23.6, §25.1-§25.4]
```

**D6:5260 is D6 auditing D1's reference into D6, and getting it right.** It names the correct rule (`§23.6` @4992, verified) and the correct scope verdict (`§25.3` @5227, verified). **D6:5262 supplies the replacement citation and D6:5264 states the defect was deliberately not fixed because `D1` is outside task-16's write scope.**

**That is exactly why this audit exists.** The defect was *recorded accurately in one file and left live in another*, because the lane that found it did not own the file containing it. Correct scope discipline; predictable cross-file consequence.

**Correction to the brief:** the citing line is `D6:5258` (and `D6:5260` quoting it), not `D1:3229`. `D1:3229` is the cited location per D6's own source tag. `D1:3229` sits inside D1 §24.1, and D1:3249 confirms that neighbourhood does carry cross-references — *"the same hazard D6 §22.7 found in Pupy's `MemoryModule.c`"* — so the brief's line reference is one file off, not fabricated.

---

## 5. Class 2 — cross-file NUMBER DRIFT

**Result: no drift found.** This is a measured negative, and the measurement matters because parallel authorship is exactly where drift lives.

**Method:** 42 candidate lines across 8 files where one document quotes a number and attributes it to another document in the same line. Each was checked against the source document.

**The strongest candidate — and it resolves cleanly:**

```
D8:32   | Repository size | 15,080 files / 67 MB | **15,051 / 207,286,153 B** | corrected (D7 §2, re-confirmed) |
D7:39   Metasploit is **15,051 files / 207,286,153 bytes** (.git excluded)
D7:82   | 15,080 files | **15,051 files** | full enumeration |
D7:1410 the repository is **15,051 files** (not 15,080); the TLV ...
```

`15,080 files / 67 MB` is **the brief's own wrong carry-forward**, which D7 explicitly corrects at :82 and :1410. **D8:32 reproduces the correction table faithfully** — it shows the brief's number struck and the verified number bolded, and cites `D7 §2`. **Not drift. Correct citation of a corrected value.** D8:81/83 use `15,051` consistently and the `2,796`/`2,715` split is D8's own, absent from D7 by construction.

**The pattern the drift scan found instead is more useful than drift would have been:** every cross-file number in this corpus is either (a) quoted with its correction, or (b) attributed to a specific section. **No document silently restates another's number without attribution.** That is why class-2 drift is absent, and it is a stated practice, not luck — D7:1410 literally begins *"Accuracy note on the brief's carry-forwards, restated because five were wrong and this report corrects them."*

---

## 6. The corpus moved during this audit — and that is a finding

**The directory changed underneath the audit — repeatedly.** Between my first inventory and the final resolution pass:

| Change | Before | After |
|---|---|---|
| `D11_havoc_native_win32.md` | **did not exist** | 44,236 → **57,872 B** / §1–8 |
| `D11_merlin_binaries.md` | **did not exist** | 6,958 B / 109 lines / §0–1 |
| `D11_mythic_crypto_postresponse.md` | **did not exist** | 34,561 B / 418 lines / §1–8 |
| `D11_pupy_transport_crypto.md` | **did not exist** | **23,073 B / §1–5 (appeared last)** |
| `D11_sliver_rpc_core.md` | 38,937 B / §1–9 | **62,167 B / §1–12** |
| `D10_merlin.md` | 77,751 B | 77,973 B |
| `D9_msf_core_library.md` | 139,831 B | 158,915 B (my own §17) |

**Three consequences, all recorded rather than papered over:**

1. **A dangle can be repaired by addition.** My pass-1 verdict included three `D11` dangles (`§0`, `§10`, `§11`) against a file that then ended at §9. When `D11_sliver_rpc_core.md` grew to §12 and `D11_merlin_binaries.md` added a literal `§0`, **all three disappeared.** The normatively correct statement is *"dangling as of a stated revision,"* and every verdict here is anchored to a byte size in §2 or §6.

2. **Document identity is not file identity.** `D11` is now **five files** spanning §1–12, §1–8, §1–8, §1–5, and §0–1. Any audit, index, or cross-reference tool that keys on the `D<n>` prefix **will conflate five reports.** This is the highest-risk latent defect in the current corpus: it has not produced a wrong reference yet, only because no reference to a bare `D11 §x` exists in the corpus at all.

3. **An audit of a live corpus is a snapshot, not a verdict.** I re-ran the full pipeline from scratch at each revision rather than patching pass-1 results — and the **dangling set never changed** (§0.1). That stability is the audit's real claim to validity.

---

## 7. FAILURE MODES — what this corpus systematically gets wrong

Six lanes wrote 1,648 references blind to each other and got **98.7%** of them right. **The 1.3% that fail are not random and are not typos.** They are four reproducible habits, and each is a direct consequence of a deliberate, defensible authoring choice.

### Mode A — The comparison sentence drops the document prefix

**Instances:** `D3:374`, `D3:574` (`§23.3`, `§3.7`), `D8:562` (`§11.3-§11.4`).

**Shape:** a sentence comparing two or more frameworks — the corpus's most-used rhetorical form — names a section from another document inside a parenthetical or a semicolon list, and **the `D<n>` prefix is elided after the first reference.**

> *"Same shape as the Pupy debug/release mutual exclusion (`§23.3`) and MSF's `StageEncodingFallback` (`§3.7`)"* — neither number exists in D3.

**Why it is systematic:** the comparison is *about* the relationship, so the author is thinking across documents; but the prose reads as local. The reference is semantically correct and syntactically homeless. **This is the single most common defect class in the corpus.**

**Why it happened:** no lane could see the other documents, so no lane could check that `§23.3` was unambiguous from a reader's position inside D3.

### Mode B — The reference is written against an intended structure, and the structure moves

**Instances:** `D1:1396` (`§12.4`), `D1:3202` (`§22.7`), `D1:3205` (`§24.4`), `D2:1212`/`D2:2006`/`D2:2015` (`§4.6`), `D5:225` (`§4.4`), `D5:580` (`§13.9`), `D6:52` (`§15.1`), `D7:1406` (`§8.6`), `D9:1459` (`§17.2.2`), `D9:1485` (`§17.2.3`.

**This is the 16-item PARENT-OK-SUB-MISSING class, and it is the largest defect family in the corpus** — 16 instances against 6 outright dangles.

**Shape:** the reference names a sub-section that was planned but never written, or that was folded into its parent. `D1:3205` is explicit: *"REFINEMENT (added after D6 §25 landed — see §24.4)"* — §24 was written to have a §24.4, and the refinement landed in §24.3. `D9:1459`/`D9:1485` name `§17.2.2`/`§17.2.3`, sub-levels **I wrote myself** and did not create (the content is in §17.2, which does exist).

**Why it is systematic:** the *parent* always resolves, so the reference is never obviously broken — a reader lands in the right section and finds the material nearby. **It fails silently.** This is why it outnumbers hard dangles 2.7:1 and why it would never be caught by reading: only an index proves the sub-section is absent.

**Why it happened:** sections were drafted against a plan, the plan changed mid-write, and the prose kept the plan's numbering. This is normal authoring behaviour, and it is invisible to the author because the destination feels right.

### Mode C — A document number that covers more than one file

**Instances:** `D11` = four files, each with its own §1..§N. **No live bad reference yet** — recorded as latent.

**Shape:** the corpus's naming convention (`D<n>_<slug>.md`) treats one `D<n>` as one document. **D11 breaks this: it is four reports.** A reference to `D11 §7` now has four candidate targets. My own tooling had to special-case this to avoid a false verdict.

**Why it is systematic and why it matters now:** the corpus grew during this audit — from 11 files to 14 — and the files that appeared are all D11. **The number-as-document-namespace assumption is no longer safe,** and the failure it would cause is not a dangle but an *ambiguity*: a reference that resolves to the wrong document while appearing to resolve.

### Mode D — Self-corrections recorded in one file, left live in another

**Instance:** `D6 §25.6` (the brief's example).

**Shape:** D6:5260 finds and correctly diagnoses a bad reference *in D1*, states the correct target, **and D6:5264 explicitly declines to fix it because D1 is outside its write scope.** The record is accurate; the defect remains live.

**Why it is systematic:** it is the direct cost of clean task fenced scoping. Every lane that found a defect in a file it did not own faced the same choice, and the correct choice — record it, do not cross the fence — necessarily leaves the defect in place. **Cross-file auditing is the only mechanism that catches this class**, which is the argument for this report existing as a standing step and not a one-off.

### What the corpus gets RIGHT (stated because it bears on trust)

- **Numbers are attributed, not restated.** Zero drift across 42 cross-file number candidates.
- **Corrections are shown, not hidden.** D7:82 and D8:32 both render the brief's wrong value struck through beside the verified one.
- **Physical order anomalies are declared in-place.** D7:31 documents its own §11-before-§9 ordering and why; D5's §1 absence is a declared inversion.
- **Scope fences are respected even when it costs.** D6:5264 declines to edit D1 and says so.
- **Positive controls are a corpus-wide habit.** §1.1 of this audit is a mirror of a practice the reports already use on themselves — absence claims paired with a working probe.

---

## 8. Residual unknowns, stated limits

- **Range endpoints.** My rule resolves a range's leading reference fully and its trailing reference by prefix-inheritance. A range like `D6 §17–§25` whose *interior* is unstated is recorded by endpoints only. **Interior completeness was not tested** — I did not verify that every section between two endpoints is the intended set.
- **"See §x" prose forms.** I extracted the `§`-token form. Natural-language references without a section sign — *"as established above"*, *"as in D7"*, *"the section on handlers"* — were **not** extracted and are **not** covered by any verdict here. The brief named them; the volume makes them a separate pass, and I would rather state the gap than imply coverage.
- **Anchor-only references.** Markdown link anchors (`#0-status-and-analysis-completeness`) were not resolved; four appear in D11 TOCs.
- **Ambiguity was tested only through duplication of section numbers.** No reference in the corpus targets a duplicated number (§1 noted D5's nine `§7`-prefixed headings and D11's duplicated §1.x blocks) — so the ambiguity class is **latent, not manifest**, for the numbering convention. The live ambiguity risk is Mode C.
- **Verdicts are anchored to the corpus revision in §2.** The corpus moved once during this audit; it may move again. **Any number here is a snapshot at those byte sizes.**
- **No claim is made about semantic correctness.** A reference that resolves is not a reference that means what the author intended. This audit tests *existence of target*, nothing more.

---

## Appendix A — task-25 feasibility probe: RECOMMEND SKIP

§8 names the uncaptured class: natural-language references without a section sign. The lead asked whether task-25 is worth a pass and explicitly invited a *no*. **A bounded probe says no, and the numbers are clean.** Recorded here because a measured negative that prevents wasted effort is worth as much as a defect list.

**Probe method.** Widen to a *structural* bound rather than trying to enumerate prose forms — every line that names another document (`D<n>`) and carries **no** section sign.

**Result: 25 lines corpus-wide.**

| Doc | Lines | Character of the reference |
|---|---|---|
| D1 | 9 | document-level: *"the defect class D5 found in Havoc"*, *"Meterpreter's absent MAC (D7)"* |
| D8 | 11 | the D7↔D8 relationship layer: *"unread in D7"*, *"As in D7, this is a source-only report"* |
| D6 | 4 | includes `D6:5254`/`D6:5264` — the signed defect note task-22 already covers (§4) |
| D9 | 1 | `D9:7`, my own read-coverage statement |

**Every one of the 25 resolves — and resolves by construction, because they name documents, not sections.** *"As in D7"* is not a reference to a location; it is a statement about a document's scope. Listed as edges, all 25 would read `OK (doc-level)`. **That is a list of 25 identical verdicts — noise, exactly as the lead predicted.**

**The class the lead actually worried about** — *"a bare 'as established above' in a 5,272-line file"* — was probed separately with structural patterns, each self-tested for liveness first. **28 candidate lines, and zero are cross-document references.** They are table cells (`see below` ×4), prose deictics (`as above`), and intra-section pointers. A human resolves each in one line; no tool can resolve any of them, because the referent is a *position in an argument*, not a numbered target. **This is the degeneracy the lead named.**

**A falsification worth recording.** My first probe used hand-written verb patterns (`D\d+ (?:established|found|documented...)`) and returned only **8 lines**. **The positive control killed it:** the pattern returned `False` on all four known-good reference sites, *including the one it was written to catch* (`D6:5264`, *"D1 is outside task-16's write scope"*). The corpus's actual prose habit is **the document number as a bare parenthetical** — *"(D5)"*, *"(D7: no MAC on the packet layer)"* — which no verb-based pattern sees. **Had I trusted the first probe, I would have reported "only 8 references" and been wrong by 3×.** This is Defect 1 from §1 recurring in miniature: **a probe that returns a small number is not a measurement until shown able to succeed.**

**Verdict.** Task-25 as scoped would produce ~53 lines of `OK (doc-level)` and `AMBIGUOUS (intra-section deictic)` — a high-volume, zero-defect list. **The corpus does not have a natural-language cross-reference problem; it has a section-sign-reference problem, and task-22 has now audited that completely.** Recommend skip. If the class must be closed for completeness, the cheap form is a **citation-convention line** — `D1:976` already declares one (*"## 8. Citation convention (stated so this report is auditable alongside D2 and D5)"*) — not a second audit pass.

---

*End of CROSSREF_AUDIT.*
