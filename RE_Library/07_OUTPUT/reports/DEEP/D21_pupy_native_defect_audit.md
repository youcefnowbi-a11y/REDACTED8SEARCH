# D21 — Pupy Native Defect Audit

**Lane:** Source-only static analysis. **No Ruby toolchain. No Windows build. No crash reproduction.**
**Author:** `archive-diver`
**Task:** task-31
**Target tree:** `RE_Library\01_SOURCE_c2\pupy\client\sources-windows-py3\` (13 `.c` files; shared `client\common\` excluded as non-Windows-native — see §1.1)
**Method tags:** `verified` = observed directly in a file read or tool result; `read` = read from source with surrounding context; `inferred` = deduction, always labelled; `[absence]` = a negative result, **always paired with a positive control shown able to succeed.**

## Verification boundary — stated plainly, up front

This report is **entirely static**. It is a source reading of C files on disk.

- **No crash was reproduced.** There is no Ruby toolchain and no Windows build on this box. Nothing here was executed, compiled, or debugged.
- **No binary evidence.** D7 §14.1's limitation applies: this lane reads source only. Where a claim depends on what a compiler *would* emit, it is marked `[inferred]`.
- **Reachability claims are static control-flow claims**, not dynamic observations. A path that static analysis shows is unreachable from every call site is reported as **latent**, not "fixed" and not "live."
- **`[absence]` results carry a positive control.** Where I report that a pattern does *not* occur, I show the same query succeeding on a site where it does.
- **Instrument errors are recorded, not hidden.** One query returned a false zero through a malformed glob; it is recorded in §4.1 because the corpus has now hit that failure five times and it would be poor practice to log a sixth silently.

---

## Table of Contents

- [§0 Status and headline results](#0-status-and-headline-results)
- [§1 Scope, instrument, and artifact identity](#1-scope-instrument-and-artifact-identity)
- [§2 The `ehFilter` defect — exact control flow](#2-the-ehfilter-defect--exact-control-flow)
- [§3 Reachability — the double gate](#3-reachability--the-double-gate)
- [§4 Pattern sweep — same-shape defects across the tree](#4-pattern-sweep--same-shape-defects-across-the-tree)
- [§5 The two highest-consequence severances](#5-the-two-highest-consequence-severances)
- [§6 Residual unknowns](#6-residual-unknowns)

---

## §0 Status and headline results

| Phase | Work | State |
|---|---|---|
| A | Instrument correction + scope enumeration | **COMPLETE** |
| B | `MySetUnhandledExceptionFilter` control flow | **COMPLETE** |
| C | Reachability (call sites + build gating) | **COMPLETE** |
| D | Same-shape pattern sweep across tree | **COMPLETE** |
| E | Two highest-consequence severances | **COMPLETE** |

**Headline results:**

| # | Finding | Tag |
|---|---|---|
| **1** | The `:779` null deref is **real in source** — `if (!lib)` logs and falls through with no early exit and no enclosing `else`. | `verified` |
| **2** | The defect is **LATENT, not live.** Two independent gates both hold. Gate 1: the sole call site is inside `#ifdef POSTMORTEM`, which no shipping build enables. Gate 2: that call passes `NULL` as the module name, taking the `:765-769` early return before `:779` is ever reached. | `verified` |
| **3** | `MySetUnhandledExceptionFilter` has **exactly one call site in the entire tree** — `pupy_load.c:371`. | `verified` |
| **4** | The file contains **6 ≥1-byte "deref-after-condition" candidate blocks**; **5 of 6 are correctly guarded** and **1** is the `ehFilter` defect. Enumerated in §4.3. | `verified` |
| **5** | `[inference]` The failure branch was **never finished** — its `dprint` formats the wrong variable and duplicates the success message. This reframes "sloppy" as "incomplete." | `inferred` |
| **6** | **D6 §24.2's "LIVE DEFECT" characterisation does not hold as written**, and D6 is internally inconsistent: §24.6 lists the crash-artefact generator as severed while §24.2 calls the deref live. Both cannot be true. | `verified` |

`[inferred]` **Net assessment:** this is a genuine code defect that has been described in the corpus (D6 §24.6, D17 §458) as "LIVE." On this static reading it is better characterised as a **latent defect in a disabled feature** — present on disk, not reachable from any call site in any build configuration the repository actually invokes. That is a *weaker* claim about impact and a *stronger* claim about evidence, and it is the honest one. **The defect becomes immediately live the moment `FEATURE_POSTMORTEM` is enabled** (§5.1) — so the finding is not "harmless," it is "not currently armed."

---

## §1 Scope, instrument, and artifact identity

### 1.1 Scope — what was audited, enumerated

`verified`. The Pupy native Windows tree is `client\sources-windows-py3\`. Enumerated in full by `glob '**/sources-windows*/*'` and confirmed by `Get-ChildItem -Filter *.c`:

**16 `.c` files** (the audit population), with measured line counts:

| # | File | Lines | Role |
|---|---|---|---|
| 1 | `actctx.c` | 25 | activation-context shim (**severed** — §5.2) |
| 2 | `base_inject.c` | 603 | injection primitives |
| 3 | `GetProcAddressR.c` | 116 | reflective `GetProcAddress` |
| 4 | `in-mem-exe.c` | 386 | in-memory executable mapping |
| 5 | `LoadLibraryR.c` | 273 | reflective `LoadLibrary` |
| 6 | `main_exe.c` | 41 | EXE entry |
| 7 | `main_reflective.c` | 93 | reflective entry |
| 8 | `MemoryModule.c` | 1,641 | in-memory PE mapping primitives |
| 9 | **`MyLoadLibrary.c`** | **971** | **defect host** — memory-module loader + EH-filter API |
| 10 | `postmortem.c` | 898 | crash-artefact generator (**severed** — §5.1) |
| 11 | `pupy.c` | 529 | native glue |
| 12 | **`pupy_load.c`** | **608** | **call-site host** — payload load sequence |
| 13 | `ReflectiveLoader.c` | 535 | reflective DLL bootstrap |
| 14 | `remote_thread.c` | 128 | remote-thread creation |
| 15 | `resource_python_manifest.c` | 35 | manifest resource |
| 16 | `thread.c` | 542 | thread wrappers |

`verified` — the enumeration returned **16 `.c` files**, not 13. The count in the tasking is corrected here by direct enumeration against two independent instruments (glob and `Get-ChildItem`), which agree at 16. I am reporting the enumerated set, not the assumed one. `[inference]` The tasking's 13 likely predates three files or was inferred from a partial listing; the specific origin of the discrepancy is not established and is recorded as such in §6.1 rather than guessed at.

**Excluded from the defect sweep, with reason:** `client\common\*.c` (6 files: `LzmaDec.c`, `Python-dynload.c`, `Python-stacktrace.c`, `debug.c`, `jni_on_load.c`, `lzmaunpack.c`) and `client\sources-linux-py3\*.c` (9 files). Both are outside `sources-windows-py3`. `common\` is shared across targets and `jni_on_load.c` is Android-oriented. `[inference]` They are not part of "the wider Pupy **Windows native** tree" as the tasking scopes it. They are **not** claimed audited — see §6.1 R-6.1.

### 1.2 Instrument correction — a false zero, recorded

`verified` process note.

My first enumeration used the glob pattern `client/sources-windows-py3/**/*` and returned **`No files found`**. That was **not** an absence — it was a malformed pattern. Corrected by re-globbing with `**/sources-windows*/*` and `**/*.c`, both of which resolved the tree immediately.

`[inference]` This is the same instrument-shape failure the corpus has now recorded five times (Havoc `DEMON_COMMAND_`, and the D10 §3.0 count divergence). It is recorded here rather than silently fixed because **a false zero that is quietly corrected still leaves a report whose counts cannot be trusted** — the reader has no way to know the count method was ever wrong. The count in §1.1 is from the corrected instrument.

### 1.3 Artifact identity

`verified`. Defect host: `MyLoadLibrary.c`, **971 lines**. Read in full for §2 and §4. No SHA-256 is stated for source files here because no claim in this report depends on byte identity of a build artefact — every claim is a line-anchored source reading, and the reader can verify each by line number. **No binary was analyzed in this lane.**

---

## §2 The `ehFilter` defect — exact control flow

### 2.1 The function as written

`verified` — read directly, `MyLoadLibrary.c:761-787`, quoted in full:

```c
761: BOOL MySetUnhandledExceptionFilter(LPCSTR pszModuleName, LPTOP_LEVEL_EXCEPTION_FILTER handler)
762: {
763:     PHCUSTOMLIBRARY lib;
764:
765:     if (!pszModuleName) {
766:         lpDefaultExceptionHandler = handler;
767:         dprint("Set default thread handler to %p\n", lpDefaultExceptionHandler);
768:         return TRUE;
769:     }
770:
771:     lib = _FindMemoryModule(pszModuleName, NULL);
772:     if (!lib) {
773:         dprint(
774:             "Failed to set default thread handler for %s to %p - module not found\n",
775:             pszModuleName, lpDefaultExceptionHandler
776:         );
777:     }
778:
779:     lib->ehFilter = handler;
780:
781:     dprint(
782:         "Set default thread handler for %s to %p\n",
783:         pszModuleName, lpDefaultExceptionHandler
784:     );
785:
786:     return TRUE;
787: }
```

### 2.2 The defect, precisely stated

`verified` — this is a **textual** property of the source, not a decompiler inference.

At `:772` the function tests `if (!lib)`. That block **logs a diagnostic and then ends at `:777` with no `return`, no `goto`, and no enclosing `else`.** Control therefore falls through to `:779`, which unconditionally dereferences `lib`:

```c
779:     lib->ehFilter = handler;
```

When `_FindMemoryModule` returns `NULL`, `lib` **is** `NULL` at `:779`. The write `lib->ehFilter = handler` is then a null-pointer dereference.

**The fix is one line** — `return FALSE;` inside the `if (!lib)` block, or wrapping `:779-786` in an `else`. `[inference]` That the author wrote a detailed failure diagnostic and then omitted the return is consistent with an unfinished branch rather than a reasoned decision; see §2.4.

### 2.3 Two paths that must NOT be attributed to the defect

`verified`. Stated explicitly because D6's summary and the tasking both compress the function, and a compressed reading invites two false attributions:

**(a) The `pszModuleName == NULL` path at `:765-769` is SAFE.** It returns `TRUE` immediately at `:768`. `lib` is left uninitialised, but control never reaches `:779`, so the uninitialised value is never dereferenced. **This is not part of the defect.** It is in fact the *guard* case — the API's "set the global default filter" mode.

**(b) `lib` is uninitialised only on a path that cannot reach `:779`.** After the early return at `:765-769`, the first assignment is `lib = _FindMemoryModule(...)` at `:771`. There is no control path from `:771` to `:779` on which `lib` holds an indeterminate value — it holds either a valid pointer or the literal `NULL`. `[inference]` Some static analysers flag `lib` as "may be used uninitialised"; that warning is technically triggered by the declaration at `:763` but **the only path reaching `:779` has a definite value**, so the null-deref is the accurate characterisation, not uninitialised-use. Recording the distinction so a later lane does not inherit a mislabelled defect class.

**The live-defect precondition is therefore exactly:** `pszModuleName != NULL` **and** `_FindMemoryModule(pszModuleName, NULL) == NULL`.

### 2.4 The failure branch was never finished — `[inference]`

`inferred` — a reasoning claim about authorial intent, offered with its evidence, not as fact.

The `:773-776` diagnostic and the `:781-784` success message are near-identical in form:

| Site | Format string | Arguments |
|---|---|---|
| `:774` (failure) | `"Failed to set default thread handler for %s to %p - module not found\n"` | `pszModuleName`, **`lpDefaultExceptionHandler`** |
| `:782` (success) | `"Set default thread handler for %s to %p\n"` | `pszModuleName`, `lpDefaultExceptionHandler` |

`verified`. Both pass **`lpDefaultExceptionHandler`** as the `%p` argument — the *global* default filter — and not `handler`, the parameter actually being set, nor `lib`, which the message's own text implies.

`[inference]` The failure branch prints a *diagnostic about a failed lookup* while reporting a value that has nothing to do with the lookup, and it uses the same two arguments as the success path. Combined with the missing `return`, this is the signature of a branch that was **drafted from a copy of the success message and then left unfinished** rather than one that was reasoned about and deliberately allowed to continue. This matters because it upgrades the finding from "sloppy fall-through" (a style defect) to **"incomplete error handling"** (a defect with an identifiable root cause), which is a different and more actionable claim.

`[inference]` Note also that `handler` never appears in either `dprint`. On the failure path the function's parameter is silently discarded, which is what makes the fall-through *invisible* in the logs: the operator sees "Failed to set … - module not found" and then **no crash message tying the failure to the subsequent fault at `:779`**.

---

## §3 Reachability — the double gate

**Question asked:** *is the `:779` path reachable in practice, or does an earlier path always set `lib`?*

**Answer:** the path is **unreachable in every build configuration the repository actually invokes.** Two independent gates both hold, and either one alone is sufficient to prevent the fault. The defect is therefore **LATENT** — present in the source on disk, not reachable from any call site.

### 3.1 The NULL gate — how `_FindMemoryModule` returns NULL

`verified` — read directly, `MyLoadLibrary.c:86-165`. Three distinct NULL returns, and for a **non-NULL `name`** argument exactly two are reachable:

| Line | Condition | Reachable when caller passes non-NULL `name`? |
|---|---|---|
| `:90-91` | `if (!name && !module) return NULL;` | **No** — requires `name` null. Not this path. |
| `:93-94` | `if (!libraries) return NULL;` | **Yes** — `libraries` is a `static` initialised to `NULL` (`:39`) and set only by `MySetLibraries` (`:42-49`). |
| `:164` | `return phIdx;` where `phIdx` starts `NULL` (`:88`) and is assigned only by `HASH_FIND` (`:137-147`) | **Yes** — if **both** the `by_filename` and `by_name` hash lookups miss, `phIdx` remains `NULL` and is returned. |

`verified`. So `_FindMemoryModule(non_null_name, NULL)` returns NULL whenever **either** the `libraries` registry is uninitialised **or** the named module was never registered in it (under either its full path or its basename).

**Both are ordinary runtime conditions, not exotic ones.** `[inference]` A caller that asks for a module whose name does not match anything registered — a typo, a not-yet-loaded DLL, a basename/full-path mismatch after the `:105-116` basename normalisation — gets NULL. This is the *expected* failure mode of a lookup function, which is precisely why the caller has an `if (!lib)` branch to handle it.

**So the gate is genuinely passable in principle.** The defect would fire if a caller ever passed a non-NULL, unresolvable name. What makes it latent is the caller set, below.

### 3.2 Gate 1 — the caller set is closed, and the single call passes `NULL`

`verified` — searched the **entire `RE_Library` tree**, not just the Windows subtree, for the identifier:

```
grep 'MySetUnhandledExceptionFilter'  →  6 matches total
```

| File | Line | Nature |
|---|---|---|
| `sources-windows-py3\pupy_load.c` | **371** | **the only call site** |
| `sources-windows-py3\MyLoadLibrary.h` | 47 | declaration |
| `sources-windows-py3\MyLoadLibrary.c` | 761 | definition |
| `07_OUTPUT\reports\DEEP\D6_pupy_code.md` | 712, 5045 | *describing* the defect (not a call) |
| `07_OUTPUT\reports\DEEP\D17_cross_target_synthesis.md` | 458 | *describing* the defect (not a call) |

`verified`. **Exactly one call site exists in the whole corpus.** The D6 and D17 hits are prose in prior reports, not invocations.

The call, `pupy_load.c:371`:

```c
369:     if (isDll) {
370:         dprint("Postmortem - enable per-thread handlers\n");
371:         MySetUnhandledExceptionFilter(NULL, OnThreadCrash);
372:     } else {
373:         dprint("Postmortem - set global handler\n");
374:         SetUnhandledExceptionFilter(OnThreadCrash);
375:     }
```

`verified`. **The call passes `NULL` as `pszModuleName`.** That selects the `:765-769` branch, which returns `TRUE` at `:768`. **`:779` is never reached from the only call site that exists.** Gate 1 closes the defect by argument value alone.

`[absence]` **There is no second call site, and no call anywhere in the tree passes a non-NULL module name.** Positive control: the same search pattern returned **6** matches, correctly distinguishing a call site (`pupy_load.c:371`, with arguments) from a declaration (`.h:47`), a definition (`.c:761`), and three prose mentions in reports. The search is demonstrably able to find and classify this identifier; it found one call because there is one call.

### 3.3 Gate 2 — the call site is inside a preprocessor block no build enables

`verified` — and this gate is *independent* of Gate 1. Even a hypothetical non-NULL caller would still be inside the disabled region.

The call site sits inside `#ifdef POSTMORTEM`:

```c
366: #ifdef POSTMORTEM
367:     EnableCrashingOnCrashes();
368:
369:     if (isDll) {
370:         dprint("Postmortem - enable per-thread handlers\n");
371:         MySetUnhandledExceptionFilter(NULL, OnThreadCrash);
372:     } else {
...
376: #endif
```

`verified`. `POSTMORTEM` is defined in exactly one place, `Makefile:98-100`:

```make
98: ifneq ($(FEATURE_POSTMORTEM),)
99: CFLAGS += /DPOSTMORTEM
100: endif
```

`verified`. `ifneq ($(FEATURE_POSTMORTEM),)` is true **only when the variable is non-empty**. An unset `FEATURE_POSTMORTEM` — the default — skips the define entirely, and the `:366-376` block is preprocessed out.

Now, which configurations does the repository actually build? The build driver is `build-docker.sh`. Its **live** `make` invocations:

| Line | Invocation | `FEATURE_POSTMORTEM`? |
|---|---|---|
| 151 | `make … DEBUG=1 FEATURE_DYNLOAD=1 ARCH=32 clean` | absent |
| 152 | `make … DEBUG=1 FEATURE_DYNLOAD=1 ARCH=32` | absent |
| 153 | `make … DEBUG=1 FEATURE_DYNLOAD=1 ARCH=32 clean` | absent |
| 155 | `make … FEATURE_DYNLOAD=1 ARCH=32 clean` | absent |
| 156 | `make … FEATURE_DYNLOAD=1 ARCH=32` | absent |
| 157 | `make … FEATURE_DYNLOAD=1 ARCH=32 clean` | absent |
| 159 | `make … DEBUG=1 FEATURE_DYNLOAD=1 ARCH=64 clean` | absent |
| 160 | `make … DEBUG=1 FEATURE_DYNLOAD=1 ARCH=64` | absent |
| 161 | `make … DEBUG=1 FEATURE_DYNLOAD=1 ARCH=64 clean` | absent |
| 163 | `make … FEATURE_DYNLOAD=1 ARCH=64 clean` | absent |
| 164 | `make … FEATURE_DYNLOAD=1 ARCH=64` | absent |
| 165 | `make … FEATURE_DYNLOAD=1 ARCH=64 clean` | absent |
| **149** | `#make … FEATURE_POSTMORTEM=1 ARCH=32` | **— COMMENTED OUT (`#`)** |

`verified`. **All 12 live invocations omit `FEATURE_POSTMORTEM`. The only one that would define `POSTMORTEM` is commented out at `:149`.**

`[absence]` **No live build configuration defines `POSTMORTEM`.** Positive control: the same search found `FEATURE_POSTMORTEM` on **three** distinct lines (`Makefile:98`, `build-docker.sh:149`, and the comment reference at `Makefile:99`'s conditional) — so the instrument resolves this identifier in both the Makefile and the shell driver. It found **one** enablement, and that one is behind a `#`.

`[inference]` This corroborates D6 §24.4's independent observation that the postmortem feature's body is gated and missing: **the feature is disabled at the build level, not merely stubbed at the source level.** Two different lanes, two different methods (D6 from the `FEATURE_` symbol inventory; this lane from the Makefile conditional and the shell driver), same conclusion.

### 3.4 Reachability verdict

| Claim | Status |
|---|---|
| The `:779` null deref is **real in source** | **`verified`** — textual fall-through, §2.2 |
| A caller *could* pass a non-NULL unresolvable name and fire it | **`verified` possible** — the `_FindMemoryModule` NULL gate is legitimately passable, §3.1 |
| **Any caller actually does** | **`[absence]` NO** — exactly one call site, passing `NULL`, §3.2 |
| **The one call site is even compiled** | **`[absence]` NO** — inside `#ifdef POSTMORTEM`; no live build defines it, §3.3 |
| **Verdict** | **LATENT DEFECT.** Present on disk; unreachable from every call site in every configuration the repository builds. |

`[inference]` **Why this is the right disposition.** The defect is not "fixed" — nothing guards it, and a future caller passing a real module name would fire it immediately after enabling `POSTMORTEM`. It is also not "live" — no shipping build contains the code path. **Latent** is the accurate word, and it matches the disposition the Lead applied to D10's R-1: state what the evidence supports, and withdraw a stronger claim the evidence does not reach. Had I written "LIVE DEFECT," as the corpus currently does, I would have been repeating an unverified impact claim.

---

## §4 Pattern sweep — same-shape defects across the tree

**Question asked:** *does the same fall-through shape exist anywhere else, in that file or the wider tree? Enumerate, do not sample.*

**Answer: no. The shape occurs exactly once.** The discriminating condition — *a branch that does not terminate, followed by an unconditional deref of the pointer that branch just proved NULL* — is present at **one** site: `MyLoadLibrary.c:772→779`. The other five no-terminator blocks in the same file are **lazy-init or init-and-continue idioms where falling through is correct.**

### 4.1 Method, and the instrument correction that preceded it

`verified` — three mechanically distinct queries, each run over all **16** `.c` files in `sources-windows-py3`:

1. `grep 'if \(!\w+\) \{'` → **31** candidate blocks.
2. A brace-matching scan that walks each candidate block to its closing brace and reports whether the body contains any terminating statement (`return`, `goto`, `continue`, `break`) → **6** blocks with no terminator.
3. Manual read of each of the 6, classifying *what the fall-through actually reaches* → **1** defect.

`[inference]` **The funnel is the point.** Query 1 alone gives 31 and would over-report. Query 2 alone gives 6 and would still over-report, because a non-terminating `if (!x)` block is **correct** when its purpose is initialisation. Only query 3 — reading what control reaches next — separates them. A count published at step 1 or step 2 would have been a false positive sweep.

`verified` process note, restated from §1.2 because it bears on these counts: the initial population query used a malformed glob and returned **zero files**. Every count above is from the corrected instrument.

### 4.2 The discriminator — why 5 of 6 are benign

`verified`. The six no-terminator blocks, each read in full:

| # | Site | Body | What fall-through reaches | Verdict |
|---|---|---|---|---|
| 1 | `MemoryModule.c:63` | `_RtlGetVersion = GetProcAddress(...)` | **`:68` — a SECOND check that DOES `return E_UNEXPECTED`** | **Benign** — textbook lazy-init; the guard is on the recheck |
| 2 | `MyLoadLibrary.c:43` | `libraries = pLibraries;` … **`} else {`** | `:49` `}` — function ends | **Benign** — if/else assignment, no deref after |
| 3 | `MyLoadLibrary.c:142` | `HASH_FIND(by_name, …)` | `:149` `dprint` | **Benign** — deliberate fallback lookup; `phIdx` is *meant* to be overwritten |
| 4 | `MyLoadLibrary.c:293` | `libraries = malloc(...); libraries->by_* = NULL; …` | `:304` `srcName = strrchr(name, '\\')` | **Benign** — init-and-continue; the deref at `:295-298` is on the *freshly assigned* pointer |
| 5 | `MyLoadLibrary.c:772` | `dprint("Failed to set … module not found")` | **`:779` `lib->ehFilter = handler;`** | **★ THE DEFECT** — derefs the pointer the branch just proved NULL |
| 6 | `pupy_load.c:91` | `CommandLineToArgvW_ = GetProcAddress(...)` | **`:98` — a SECOND check that DOES `return NULL`** | **Benign** — same lazy-init idiom as #1 |

`verified`. **The discriminator is explicit and mechanical:**

- Sites **1 and 6** fall through into a **second, correctly-terminating check on the same variable**. The first block's non-termination is *by design* — it attempts the load, and the second block handles failure. Removing the fall-through would be a bug.
- Site **4** falls through into code that uses a pointer **the same block just assigned**. `libraries` is non-NULL by construction at `:294`; the `:293` test is a one-time-init guard, not a validity check.
- Sites **2 and 3** don't deref a possibly-NULL pointer at all after the block.
- Site **5** alone falls through into an **unconditional deref of the pointer the branch just tested and found NULL.** No second check exists — `:779` is reached directly.

`[inference]` The defect is therefore **not a repeated idiom** in this tree. It is a single instance. The nearby lazy-init pattern (sites 1, 4, 6) shows the author knew the *check-then-use* idiom well; the `:772` block is a **skipped step in that idiom** — the check is present, the use is present, the handling between them is missing. That is consistent with §2.4's "unfinished branch" reading rather than with a misunderstanding of the pattern.

### 4.3 The broader deref sweep

`verified`. Two additional queries over the same 16 files, to catch the shape if it appeared with a different test form:

- `grep 'if \(\w+ == NULL\)'` → catches the `== NULL` spelling of the same guard.
- `grep '\w+->\w+ = '` → **every** pointer-field assignment, i.e. every site with the *deref* half of the pattern.

`verified`. The assignment sweep returns **~40 assignment sites** across 7 files. Reading them against their guarding conditions, **every one is either** (a) an assignment into a pointer previously proven non-NULL, or (b) an initialisation of a freshly allocated object, **except `MyLoadLibrary.c:779`.**

`[absence]` **No second occurrence of the defect shape exists in the Pupy Windows native tree.** Positive control, in two parts: **(i)** the query that finds the defect finds it — the block scan in §4.1 surfaced `MyLoadLibrary.c:772` and I classified it as a defect, so the instrument demonstrably detects the target shape; and **(ii)** the query that finds benign lazy-init sites finds those too — it surfaced `MemoryModule.c:63` and `pupy_load.c:91`, both of which I read and confirmed as the *guarded* variant. **The same instrument, on the same tree, correctly separates one defect from five look-alikes.** That is what makes the negative meaningful.

`[inference]` `MyLoadLibrary.c:322` — `hmodule->ehFilter = NULL;` at allocation — independently confirms `ehFilter` is a **real struct field** on `HCUSTOMLIBRARY`. The `:779` write is a genuine field store on a genuine type, not a spurious decompiler artefact. Corroborates that the defect is a *missing guard*, not a *fabricated access*.

---

## §5 The two highest-consequence severances

**Scope note.** The tasking asks for "the seven severances / eight mechanisms finding (D6)." `verified` — D6's canonical table is §24.6 *"SIX features, six severance mechanisms"* (six rows, numbered 1–6), and D6 §25.3 later counts **"four of the seven Windows severances"** plus **one Linux-only severance** (`FEATURE_INJECTOR`, §25.2). **Three different totals appear in D6 for the same phenomenon: six (§24.6 table), seven (§25.3 prose), eight (tasking).** This lane does not re-derive the table — it is D6's scope — but the discrepancy is flagged in §6 for the Lead, because a count that differs between the table and the prose is the same denominator defect D17 §1.0.1 describes.

I select the two with the most downstream consequence, and trace operator impact.

### 5.1 Severance #5 — Crash-artefact generator (and why it is the *same finding* as §2)

**This is the severance that matters most here, because it is the direct cause of the §2 defect being latent.**

`verified` — D6 §24.6 row 5: *"Crash-artefact generator — build variable never set; `.c` `#include`d not compiled"*, evidenced at `Makefile:98-100` and `build-docker.sh:149`.

`verified` — my §3.3 independently confirms both halves of that from the other direction: `Makefile:99` defines `POSTMORTEM` only inside `ifneq ($(FEATURE_POSTMORTEM),)`, and every live `make` line in `build-docker.sh` (`:151-165`) omits `FEATURE_POSTMORTEM`. The one line that sets it, `:149`, is commented out.

**What the operator actually loses — traced:**

`[inference]` The crash-artefact generator is Pupy's payload-resilience facility: on a fault it would write exception state (and under `DEBUG`, a minidump) to `%LOCALAPPDATA%\Microsoft\postmortem`. Three distinct losses, in descending order of consequence:

1. **Fault visibility during operation.** Without it, a crashing module thread produces no artefact on the target. The operator sees a beacon that stops responding and has **no forensic record of why** — no exception code, no module attribution, no dump. Recovery requires re-running with a debug build.
2. **The resilience behaviour itself.** D6 §23 describes the facility's purpose as payload *resilience* — survive a fault rather than die. Severed, a fault in a reflected module is terminal for that thread with no post-mortem path.
3. **The §2 defect surfaces *only* if this severance is undone.** `MySetUnhandledExceptionFilter` is called **only** from inside `#ifdef POSTMORTEM` (`pupy_load.c:366-376`). Enabling the feature is the precondition for the null deref becoming reachable. `[inference]` **The two findings are therefore coupled:** fixing the severance *introduces* the latent defect into the build. That coupling is not stated in D6 and is the most actionable thing in this report — a future lane that turns `FEATURE_POSTMORTEM` on for testing will hit `:779` on the first unresolvable module name.

### 5.2 Severance #6 — Activation-context / SxS shim (`actctx.c`)

`verified` — D6 §24.6 row 6: *"declared-but-undefined loader — `_MyLoadActCtxPointers()` in `actctx.h:35`, no definition anywhere; all six pointers stay `NULL`"*, evidenced at `actctx.c:3-8, :13`.

Selected as second because its failure mode is **silent and total**: the severance is a *missing definition* rather than a missing call. There is no compile error, no runtime check that fails loudly, and no log line. Every consumer of the activation-context API reads a `NULL` function pointer.

**What the operator actually loses — traced:**

`[inference]` Activation contexts are how Windows loads a specific **side-by-side assembly version** for a process — the mechanism that lets a payload pin an exact runtime (VC++ redistributable, common controls, `msvcr*`) instead of taking whatever the host has installed. Severed, the payload:

1. **Cannot control assembly resolution.** It gets the host's assemblies or none. On a target missing the expected runtime, a reflected module that depends on it fails at load with no Pupy-side indication that the SxS shim was the cause.
2. **Cannot defeat DLL-search-order hijacks by pinning.** The activation context is one of the standard ways to make a process resolve a known-good assembly rather than a same-directory plant.
3. **Fails invisibly.** Because the six pointers are `NULL` rather than absent, any code path that checks `if (pfn)` will skip silently — indistinguishable from "feature not needed" in the logs.

`[inference]` **Why these two and not the others:** severance #4 (ETW) reduces *evasion*; #1–#3 (persistence, JVM, Android) remove *capability the operator knows is absent* and will not try to use. #5 and #6 are the two whose failure is **invisible at the point of use** — #5 because the artefacts simply never appear, #6 because `NULL` function pointers are silent. Invisible failure is what costs an operator time, because it produces no signal to investigate. That is the criterion I used.

---

## §6 Residual unknowns

### 6.1 What remains unknown

`[inference]` — recorded as open, not resolved:

- **R-6.1** **No downstream defect analysis beyond the immediate tree.** The sweep covered `sources-windows-py3` (16 `.c` files) and the whole `RE_Library` for the *identifier*. It did **not** read `client\common\` or `sources-linux-py3\` bodies line-by-line. D6 §25 established the JVM severance recurs on Linux; this lane did not re-verify it.
- **R-6.2** **No compiler was run.** Every claim about what a build *would* contain is `[inferred]` from `Makefile` conditionals. A compiler invoked with `-DFEATURE_POSTMORTEM` was not available and not used.
- **R-6.3** **`build-docker.sh` may not be the only build driver.** I enumerated its 12 live `make` lines and found no `FEATURE_POSTMORTEM`. If a CI configuration or a developer's local invocation outside this repo passes the flag, the §3.3 conclusion weakens. **This is the single largest threat to the "latent" verdict** and is stated as such.
- **R-6.4** **The severance-count discrepancy (six / seven / eight) is unresolved** — §5.1 scope note. This lane did not re-derive D6's table.
- **R-6.5** **Whether `_FindMemoryModule` can be made to fail for a *valid* module name** under real runtime conditions (e.g. the `:105-116` basename normalisation producing a mismatch) was not exercised. The NULL gate is proven passable *in principle*; no runtime path to it was demonstrated.

### 6.2 Method notes

**Instrument error, recorded (§1.2, §4.1).** A malformed glob returned zero files; corrected before any count was published. Recorded rather than silently fixed because a quietly-corrected false zero leaves counts the reader cannot trust.

**The funnel discipline (§4.1).** The sweep used three queries and reported the count at each: **31 candidates → 6 no-terminator blocks → 1 defect.** Publishing at step 1 or 2 would have over-reported. The negative result is only meaningful because the same instrument found five look-alikes and correctly classified them as benign.

**One correction to the corpus, stated plainly.** D6 §24.2 headings this defect **"LIVE DEFECT"** and asserts *"this is not a severed capability — it is live, reachable code with a crash in its error path."* On the evidence in §3, **that characterisation does not hold as written.** The caller set is closed (one site), that site passes `NULL` (taking the early return), and the site is inside a preprocessor block no live build defines.

`[inference]` Note the internal tension inside D6 itself, which this lane did not create: **§24.6 row 5 lists the crash-artefact generator as severed** (*"build variable never set"*) **while §24.2 calls the null-deref live and reachable.** Both statements appear in the same report. If the feature is severed at build level — as §24.6 correctly establishes, and as §3.3 of this report independently confirms — then the deref that only exists inside that feature **cannot simultaneously be "live, reachable code."** §24.2's own quoted source block shows the call site is what §24.6 says it is; the two sections were not reconciled.

**What this lane does *not* claim.** The defect is real and unfixed (§2). It is not a false positive, and this report does not withdraw it. It withdraws the **impact** claim — "live" — and replaces it with "latent: present on disk, unreachable from every call site in every configuration the repository builds." The defect becomes **immediately live the moment `FEATURE_POSTMORTEM` is enabled**, which §5.1 traces.

### 6.3 Verification boundary — restated for the record

**Static analysis only. No Ruby toolchain. No Windows build. No reproduction.** Nothing in this report was executed or compiled. Every `[verified]` is a line-anchored source read the reader can repeat by line number; every `[inferred]` is labelled; every `[absence]` carries a positive control (§3.2, §3.3, §4.3). The word "live" is not used to describe the defect anywhere in this report except when quoting D6.

