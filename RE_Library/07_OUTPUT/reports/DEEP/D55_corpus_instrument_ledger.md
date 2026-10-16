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
