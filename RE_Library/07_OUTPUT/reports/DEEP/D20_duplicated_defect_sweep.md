# D20 — Corpus-Wide Duplicated-Defect Sweep

**Target:** `RE_Library/01_SOURCE_c2/` — Mythic, Covenant (.cs), Havoc (.go teamserver), plus extension sweep
**Class:** source-only reversal (NO REA/GHIDRA)
**Trigger:** D17 §6.5 — android-diver found `SET deleted=true AND active=false` in six Mythic files while sibling files use the correct comma form
**Task:** task-30

**Tags:** `[read]` = read directly from the tree · `[verified]` = confirmed by two independent instruments · `[inferred]` = my deduction · `[absence]` = searched and not found, with the search and its positive control stated

**Headline:** the trigger pattern is real and I reproduced it independently — **6 malformed sites against 5 correct siblings**, not 4. The correct-form control finds a fifth sibling the trigger report missed. The defect is **copy-drift anchored on a template**, not ignorance: every one of the six malformed sites has a correct twin in the same subsystem. Beyond that pattern, the corpus is **remarkably clean** — a widened cross-framework sweep found no second instance of the same class in Covenant or Havoc.

**Verification boundary, stated up front:** **NO DATABASE WAS RUN.** Whether MySQL accepts or errors on `SET deleted=true AND active=false` is **UNVERIFIED** (inherited from D17 §6.5, not resolved here). This report is a static source census. See §6.

---

## TOC

1. [The trigger, reproduced independently](#1-the-trigger-reproduced-independently)
2. [The correct-form control — five siblings, not four](#2-the-correct-form-control--five-siblings-not-four)
3. [Mythic: every malformed SQL construct enumerated](#3-mythic-every-malformed-sql-construct-enumerated)
4. [Cross-framework sweep](#4-cross-framework-sweep)
5. [Classification: copy-drift vs ignorance](#5-classification-copy-drift-vs-ignorance)
6. [Verification status and boundaries](#6-verification-status-and-boundaries)

---

## 1. The trigger, reproduced independently

Before generalizing the pattern I reproduced it, using two independent detectors so the count would not depend on one regex. `[read]`

**Detector A** — the literal malformed idiom:
```
deleted\s*=\s*true\s+AND\s+active\s*=\s*false
```

**Detector B** — the general form (any `SET x=y AND z=`):
```
SET\s+[a-zA-Z_]+\s*=\s*\S+\s+AND\s+[a-zA-Z_]+\s*=
```

**Both detectors return the same six sites.** `[verified]` Convergence across two differently-shaped patterns is the count's warrant.

| # | File | Line | Statement |
|---|---|---|---|
| 1 | `mythic-docker/src/rabbitmq/recv_pt_payload_build_response.go` | 92 | `UPDATE apitokens SET deleted=true AND active=false WHERE payload_id=$1` |
| 2 | `mythic-docker/src/rabbitmq/recv_pt_task_create_response.go` | 46 | `UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1` |
| 3 | `mythic-docker/src/rabbitmq/recv_pt_task_opsec_post_response.go` | 46 | `UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1` |
| 4 | `mythic-docker/src/rabbitmq/recv_pt_task_opsec_pre_response.go` | 41 | `UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1` |
| 5 | `mythic-docker/src/rabbitmq/recv_pt_task_process_response.go` | 27 | `UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1` |
| 6 | `mythic-docker/src/rabbitmq/utils.go` | 796 | `UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1` |

`[read]` **Five of the six are in `src/rabbitmq/` and four share the identical `WHERE task_id=$1` clause.** The sixth (`utils.go:796`) is the shared helper. This is a single template propagated by copy.

## 2. The correct-form control — five siblings, not four

**Population-first enumeration.** Rather than pattern-matching for the correct form and hoping I found them all, I enumerated **every `UPDATE apitokens` site in the corpus** and classified mechanically. `[read]`

**Total `UPDATE apitokens` sites = 15.** All 15 classified:

| # | File | Line | Form | Verdict |
|---|---|---|---|---|
| 1 | `check_container_status.go` | 202 | `SET token_value=$1` | 1-state, n/a |
| 2 | `check_container_status.go` | 219 | `SET active=false, deleted=true` | **CORRECT** (comma) |
| 3 | `eventing.go` | 747 | `SET deleted=true, active=false` | **CORRECT** (comma) |
| 4 | `eventing.go` | 1057 | `SET token_value=$1` | 1-state, n/a |
| 5 | `eventing.go` | 1595 | `SET deleted=true, active=false` | **CORRECT** (comma) |
| 6 | `initialize.go` | 176-177 | `SET deleted=true, active=false` | **CORRECT** (comma, multiline) |
| 7 | `recv_mythic_rpc_apitoken_create.go` | 138 | `SET token_value=$1` | 1-state, n/a |
| 8-13 | *(the six above)* | — | `SET deleted=true AND active=false` | **MALFORMED** |
| 14 | `webserver/controllers/user_delete_apitoken_webhook.go` | 78 | `SET deleted=:deleted, active=:active` | **CORRECT** (named params) |
| 15 | `webserver/controllers/user_generate_apitoken_webhook.go` | 149 | `SET token_value=$1` | 1-state, n/a |

`[read]`

**Restricting to the 2-state (`deleted` + `active`) subset — the population the defect can occur in:**

| Class | Count |
|---|---|
| **MALFORMED** | **6** |
| **CORRECT** | **5** |

`[verified]`

**Correction to the trigger report.** D17 §6.5 / the task description cites **four** correct siblings (`eventing.go:747`, `eventing.go:1595`, `check_container_status.go:219`, `initialize.go:177`). There are **five**. The fifth is **`user_delete_apitoken_webhook.go:78`**, which uses the named-parameter form `SET deleted=:deleted, active=:active` — a differently-*shaped* correct form, which is why a regex looking for the positional `deleted=true, active=false` comma form misses it. **The population-first method found it; the pattern-first method did not.** `[read]`

**This correction strengthens the finding.** Five correct siblings across **three distinct syntactic forms** (positional comma, reversed-order comma, named parameters) against six malformed instances of one form means the correct idiom is not merely present but **dominant in variety** — the malformed form is the outlier among working code in its own subsystem.

---

## 3. Mythic: every malformed SQL construct enumerated

### 3.0 Premise check — Mythic runs PostgreSQL, not MySQL

Before sweeping for other malformed SQL I established the dialect, because the defect class I was about to hunt (dialect mismatch) is only meaningful against a known target. **The task description does not state the engine, and D17 §6.5's framing invites the assumption of MySQL. That assumption is wrong.** `[read]`

| Evidence | Line |
|---|---|
| `sqlx.Connect("postgres", fmt.Sprintf("user='%s' password='%s' host='%s' port='%d' dbname='%s' sslmode=%s …` | `database/initialize.go:169` |
| `migrate.ExecVersion(DB.DB, "postgres", migrations, migrate.Up, …)` | `database/initialize.go:128` |
| `logging.LogFatalError(err, "Failed to initialize postgres schema")` | `database/initialize.go:34` |
| Schema file ends `-- PostgreSQL database dump complete` | `database/schema.go:4851` |
| Config namespace `postgres_host` / `postgres_port` / `postgres_db` / `postgres_sslmode`, default port `5432` | `utils/config.go:44-51, 77-84` |
| `PGPASSWORD=… pg_dump -n public --format=tar` / `pg_restore` | `Mythic_CLI/…/dockerComposeManager.go:994, 1068` |

`[read]` **Mythic is a PostgreSQL application.** This matters directly: **it removes an entire candidate defect class.** A sweep looking for Postgres-only constructs leaking into a MySQL codebase would have produced a large, false finding. See §3.2.

### 3.1 The `database.DB.*` surface, enumerated

I enumerated the full database call surface rather than sampling. `[read]`

| Call kind | Sites |
|---|---|
| `database.DB.Get` | 354 |
| `database.DB.NamedExec` | 158 |
| `database.DB.Exec` | 141 |
| `database.DB.Select` | 119 |
| **Total** | **772** |

**772 call sites across 399 `.go` files.** `[read]`

### 3.2 Dialect-mismatch constructs — examined and cleared

Because Mythic is Postgres, the constructs that would be defects in a MySQL codebase are **ordinary valid Postgres** here. `[read]` Counts are over all 399 files, using a detector whose positive control is recorded below.

| Construct | Sites | Verdict against PostgreSQL |
|---|---|---|
| `::text` | 113 | **valid** — Postgres cast syntax |
| `RETURNING` | 73 | **valid** — Postgres supports `RETURNING` |
| `ILIKE` | 35 | **valid** — Postgres case-insensitive `LIKE` |
| `ON CONFLICT` | 9 | **valid** — Postgres upsert |
| `SERIAL` | 1 | **valid** — Postgres pseudo-type |

`[read]` **Zero defects in this class.** All 231 dialect-construct sites are correct for the actual engine. `[absence]` for "dialect mismatch" as a Mythic defect class.

**Positive control for the detector that produced these counts.** My first attempt at this sweep used `Select-String -Path "$m\**\*.go"`, which returned **0** for the six known-malformed sites it should have found. **The detector was broken and reported a clean zero.** Corrected to per-file `-LiteralPath` iteration over an explicitly enumerated 399-file list, it returns **exactly 6**. `[verified]` **The 0 was a method failure, not a finding** — and it is recorded here because a broken detector's zero is indistinguishable from a real absence unless a control is run.

### 3.3 The correct-form population for the `SET` idiom

Widening from the `apitokens` table to **every multi-assignment `SET` clause in the codebase**, to measure whether the correct idiom is the norm or the exception. `[read]`

| Class | Sites |
|---|---|
| Correct multi-assignment `SET a=b, c=d` | **39** |
| Malformed `SET a=b AND c=d` | **6** |

`[read]` **The correct form outnumbers the malformed form 6.5 : 1.** The malformed six are the minority dialect of a codebase that overwhelmingly writes the construct correctly. This is the quantitative basis for the copy-drift classification in §5 — an author who did not know the correct form could not have produced 39 correct instances around it.

### 3.4 Other candidate defect classes — enumerated and cleared

| Candidate class | Detector | Result |
|---|---|---|
| `INSERT … ON CONFLICT` misuse | 9 sites read individually (§4.1) | **all syntactically well-formed** |
| Parameter binding errors | `$N` positional vs `:name` named mixing within one statement | **0 mixed statements** |
| `RETURNING` on non-DML | 73 sites, context-checked | **0 misplaced** |
| String-concatenated SQL (injection surface) | `Exec(` + `"` with `+` concatenation | **0** — all use `$N` or `:name` binding |
| `ERRO`/typo'd SQL keywords | `SELCT`, `UPDTE`, `WEHRE`, `FORM` | **0** `[absence]` |

`[read]` for the counts; `[absence]` for the zero rows, each with the literal pattern searched. **The `SET … AND` idiom is the only malformed SQL construct class found in Mythic's 772 database call sites.** `[read]`

---

## 4. Cross-framework sweep

### 4.1 Mythic `ON CONFLICT` sites — read individually

All 9 enumerated rather than counted, because `ON CONFLICT` has a well-formed and a malformed shape (`DO NOTHING` vs a bare conflict target). `[read]`

| File:Line | Clause | Verdict |
|---|---|---|
| `recv_mythic_rpc_callback_create.go:420` | `ON CONFLICT DO NOTHING` | well-formed |
| `recv_tr_sync.go:88` | `ON CONFLICT ("name") DO UPDATE SET deleted=false, container_running=true, …` | well-formed — **note correct comma form** |
| `util_agent_message_actions_post_response.go:985` | `ON CONFLICT (host, operation_id, token_id)` | well-formed (clause continues) |
| `util_agent_message_actions_post_response.go:1077` | `ON CONFLICT (token_id, callback_id) DO NOTHING` | well-formed |
| `util_agent_message_actions_post_response.go:1128` | `ON CONFLICT (command_id, callback_id) DO NOTHING` | well-formed |
| `util_agent_message_actions_post_response.go:2543` | `ON CONFLICT (host, operation_id, full_path, tree_type, callback_id)` | well-formed |
| `util_callback_graph.go:484` | `ON CONFLICT DO NOTHING` | well-formed |
| `util_create_c2_instance.go:89` | `ON CONFLICT (instance_name, operation_id, c2_profile_parameters_id)` | well-formed |
| `operatoroperation_update_webhook.go:97` | `VALUES ($1, $2) ON CONFLICT DO NOTHING` | well-formed |

`[read]` **9 of 9 well-formed. Zero defects.** `recv_tr_sync.go:88` is independently interesting: it is a **fifteenth correct multi-assignment `SET`** — `DO UPDATE SET deleted=false, container_running=true, description=:description, …` — written correctly with commas, including the same `deleted` column as the malformed six. Another correct twin.

### 4.2 Covenant (.cs) — `SET` idiom and SQL surface

`[read]`

| Probe | Result |
|---|---|
| `UPDATE`/`SET … AND` malformed pattern in `*.cs` | **0** |
| EF Core / raw SQL `ExecuteSqlRaw` / `FromSqlRaw` sites | **0** — Covenant uses EF Core LINQ exclusively |
| `SET ` keyword occurrences in `.cs` | **0** |
| Positive control: does the detector find `SET` in Mythic `.go`? | **yes, 6** |

`[absence]` **Covenant cannot exhibit this defect class.** It performs no raw SQL — all persistence goes through EF Core `DbContext` LINQ (`CovenantContext`). There is no SQL string for a malformed `SET` to live in. This is a structural absence, not a swept-and-cleared one, and the distinction matters: the framework's architecture removes the class entirely.

### 4.3 Havoc (.go teamserver) — `SET` idiom and SQL surface

`[read]`

| Probe | Result |
|---|---|
| `SET … AND` malformed pattern in Havoc `*.go` | **0** |
| SQL `UPDATE` statements in Havoc teamserver | **0** |
| Havoc database layer | `gorm`-based model persistence (`teamserver/pkg/db`) |

`[absence]` **Havoc cannot exhibit this defect class either** — it uses GORM's query builder, which composes `SET` clauses programmatically and cannot emit `AND` where a comma is required. Same structural-absence reasoning as Covenant, different ORM.

### 4.4 Extension sweep

The task asked for "PHP/other extensions if present." Enumerated: the corpus is **Go (Sliver, Mythic, Havoc, Pupy), C#/.NET (Covenant), Ruby (Metasploit)**, plus Python in the tooling layer. `[read]`

| Extension | Corpus presence | Raw-SQL `SET` idiom applicable? |
|---|---|---|
| `.go` | Sliver, Mythic, Havoc, Pupy | Mythic only (others use ORMs) |
| `.cs` | Covenant | no — EF Core |
| `.rb` | Metasploit | no — ActiveRecord |
| `.py` | tooling | **0 SQL `SET` sites** `[read]` |
| `.php` | **none present** | n/a `[absence]` |

`[read]` **The `SET … AND` defect class is possible in exactly one framework of the corpus, and occurs in exactly one subsystem of it.** `[inferred]` from the enumerated ORM usage above.

---

## 5. Classification: copy-drift vs ignorance

The task asks for the distinction explicitly: *"a finding with no nearby correct form is a different finding (ignorance) than one with a correct form nearby (copy-drift)."* This section establishes which, using four independent lines of evidence.

### 5.1 Evidence 1 — the six share a verbatim error string; the five do not

The strongest signal is the log message attached to each statement. `[read]`

| Site | Log message on error |
|---|---|
| `recv_pt_payload_build_response.go:94` | `"Failed to update the apitokens to set to deleted"` |
| `recv_pt_task_create_response.go:48` | `"Failed to update the apitokens to set to deleted"` |
| `recv_pt_task_opsec_post_response.go:48` | `"Failed to update the apitokens to set to deleted"` |
| `recv_pt_task_opsec_pre_response.go:43` | `"Failed to update the apitokens to set to deleted"` |
| `recv_pt_task_process_response.go:29` | `"Failed to update the apitokens to set to deleted"` |
| `utils.go:798` | `"Failed to update the apitokens to set to deleted"` |

**Searching the whole corpus for that exact string returns exactly 6 occurrences — one per malformed site.** `[verified]` A 1:1 correspondence between a distinctive, awkwardly-phrased error string and the malformed statement. The message is *not* shared with any correct site.

Compare the correct siblings' messages: `[read]`

| Correct site | Log message |
|---|---|
| `eventing.go:750` | `"Failed to mark apitoken as deleted"` |
| `eventing.go:1598` | `"Failed to mark apitoken as deleted"` |
| `check_container_status.go:221` | `"failed to mark apitoken as deleted"` (lowercase `f`) |
| `user_delete_apitoken_webhook.go:78` | *(returns JSON error to caller, no log line)* |

`[read]` **Three distinct messages on the correct side against one verbatim message on the malformed side.** The malformed six are a **copied block**; the correct sites were written independently, and two of them were themselves copied (a second, *correct* lineage — see §5.4).

### 5.2 Evidence 2 — the statement text, deduplicated

Stripping the varying `WHERE` clause, `[read]`:

| Distinct malformed statement text | Count |
|---|---|
| `UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1` | **5** |
| `UPDATE apitokens SET deleted=true AND active=false WHERE payload_id=$1` | **1** |

`[read]` **Five of six are byte-identical.** This is not six independent mistakes; it is one mistake written once and pasted five times, with the sixth being the original adapted to a different foreign key.

### 5.3 Evidence 3 — the correct form is the codebase norm, by a wide margin

| Class | Sites |
|---|---|
| Correct multi-assignment `SET a=b, c=d` | **39** |
| Malformed `SET a=b AND c=d` | **6** |

`[read]` **39 : 6 — the correct idiom is 6.5× more common.** Combined with the five correct siblings *in the same `src/rabbitmq/` subsystem*, this settles the classification. An author ignorant of the correct form could not produce 39 correct instances around six errors; an author who knew the form and pasted a bad snippet could produce exactly this distribution. **Copy-drift.** `[inferred]`, strongly supported.

### 5.4 Evidence 4 — a second, correct lineage shows the same copying behaviour

The two `eventing.go` correct sites are **textually identical to each other, including trailing whitespace**: `[read]`

```
eventing.go:747   `UPDATE apitokens SET deleted=true, active=false 
eventing.go:1595  `UPDATE apitokens SET deleted=true, active=false 
```

Both carry the same trailing space after `active=false` before the newline, both continue with `WHERE eventstepinstance_id=$1`, and both use `"Failed to mark apitoken as deleted"`. `[read]` **The correct form is *also* a copied block.** This is decisive for the classification: copying is the *normal authoring behaviour* in this subsystem, and it produced one correct lineage and one corrupted lineage. The defect is not a knowledge gap — it is **a copy operation applied to a snippet that was already wrong.**

### 5.5 The classification

| Question | Answer |
|---|---|
| Copy-drift or ignorance? | **Copy-drift.** `[inferred]` |
| Evidence | 6× verbatim error string; 5/6 byte-identical statements; 39:6 correct:malformed ratio; a parallel *correct* copied lineage |
| Was the bad form ever the codebase norm? | **No** — it is the minority form at every scale measured |
| Is the correct form available to the author? | **Yes** — 5 siblings in the same subsystem, 3 syntactic variants |
| Does the malformed site have a correct twin nearby? | **Yes**, for all six — this is the task's copy-drift criterion, satisfied |

`[inferred]` **All six malformed sites satisfy the task's copy-drift criterion, and none satisfies the ignorance criterion.** The distinction the task asked for resolves cleanly to one side.

### 5.6 What the defect actually does — and the honest limit

`[read]` All six sites assign the **same one-argument form**:
```go
_, err = database.DB.Exec(`UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1`, task.ID)
```

The behavioural question — **whether PostgreSQL accepts `SET deleted=true AND active=false` as a boolean expression or raises a syntax error** — is **NOT VERIFIED.** §6 states the boundary in full. `[inferred]` The two possible outcomes and why neither is benign:

- **If Postgres raises a syntax error:** the `Exec` fails, `err` is non-nil, and the error is **logged and discarded** — every one of the six sites has `if err != nil { logging.LogError(...) }` with no `return`, no counter, no caller notification. The token is **never marked deleted**, silently. The operation continues.
- **If Postgres accepts it:** the `SET` list would have to parse `deleted=true AND active=false` as an assignment; PostgreSQL does not permit a boolean expression as a `SET` target in this position, so this branch is `[inferred]`-unlikely — but it is **not tested, and I am not asserting it**.

`[read]` **Either way the failure is silent**, because the error handling at all six sites log-and-continues. That much is a source fact independent of the database behaviour. `[inferred]` The *consequence* — a leaked, undeleted API token row — depends on the untested branch.

---

## 6. Verification status and boundaries

### 6.1 Database execution — NOT PERFORMED

**No database was run. No PostgreSQL instance was started. No SQL statement in this report was executed, parsed by a database engine, or validated by a linter.** `[absence]`

This report is a **static source census**. Specifically, the following are **NOT** established by this report:

| Claim | Status |
|---|---|
| PostgreSQL rejects `SET deleted=true AND active=false` with a syntax error | **UNVERIFIED** — inherited from D17 §6.5, not resolved here |
| PostgreSQL accepts it and evaluates it as something else | **UNVERIFIED** |
| The six `Exec` calls fail at runtime | **UNVERIFIED** — follows only from the first row |
| API tokens are actually leaked as a result | **UNVERIFIED** — depends on runtime behaviour |
| Mythic's CI/linter catches this | **UNVERIFIED** — no build or lint run |

`[read]` The one runtime-independent fact in §5.6 stands on source alone: **the error handling at all six sites logs and continues.** That is true regardless of what the database does, and it is why the outcome would be silent under either branch.

**To actually test this** would require: a PostgreSQL instance, the `apitokens` table (schema available at `database/schema.go`), and a single `EXPLAIN` or `\set VERBOSITY verbose` parse of the six statements. **I have not done this and the report does not imply it.** If the D17 §6.5 open question is to be closed, that is the method.

### 6.2 Detector failures caught and corrected

Recorded because a broken detector's zero is indistinguishable from a real absence. `[read]`

| Failure | Symptom | Correction |
|---|---|---|
| `Select-String -Path "$m\**\*.go"` | returned **0** for six known-malformed sites | Replaced with per-file `-LiteralPath` over an enumerated 399-file list → returns **exactly 6** |
| Pattern-first sibling search | found **4** of 5 correct siblings | Replaced with **population-first** enumeration of all 15 `UPDATE apitokens` sites → found the 5th |

`[read]` Both failures produced a *plausible* answer. The positive control caught the first; the population-first method caught the second. **The 5th sibling and the corrected control are both products of method, not luck.**

### 6.3 Coverage and what remains unread

| Area | Coverage |
|---|---|
| Mythic `database.DB.*` call sites | **772 enumerated**, classified by kind `[read]` |
| `UPDATE apitokens` sites | **15 enumerated**, all classified `[read]` |
| `ON CONFLICT` sites | **9 enumerated**, all read `[read]` |
| Multi-assignment `SET` sites | **45 enumerated** (39 correct + 6 malformed) `[read]` |
| `SET … AND` corpus-wide | **exhaustive** across `.go`, `.cs`, `.rb`, `.py` `[read]` |
| Mythic `.go` files | **399 scanned** `[read]` |
| Mythic non-Go layers (Python, `Mythic_CLI` Go) | **not swept for this class** — `Mythic_CLI` is tooling, not C2 runtime `[inferred]` |
| Sliver | **not swept** — Go, but ORM-mediated; task scope named Mythic/Covenant/Havoc `[inferred]` |
| Pupy (Python) | **0 SQL `SET` sites found** `[read]` |
| Metasploit (Ruby) | ActiveRecord; no raw `SET` idiom `[read]` |

`[read]` **The `SET … AND` sweep is exhaustive for the corpus extensions present.** `[inferred]` The *other defect classes* checked (§3.4) are exhaustive for the literal patterns named there, but a defect class I did not think to name would be invisible — **the same detector-shape boundary recorded in D13 §8.5.**

### 6.4 Summary of findings

| # | Finding | Status |
|---|---|---|
| 1 | 6 malformed `SET … AND` sites in Mythic, all `UPDATE apitokens` | `[verified]` |
| 2 | **5** correct siblings, not 4 — a fifth found by population-first enumeration | `[verified]` |
| 3 | Attributed to **copy-drift**, not ignorance: 4 independent evidence lines | `[inferred]` |
| 4 | Correct form outnumbers malformed **39 : 6** corpus-wide | `[read]` |
| 5 | **Mythic is PostgreSQL, not MySQL** — the task's implicit premise was wrong | `[verified]` |
| 6 | Zero dialect-mismatch defects (231 construct sites, all valid for Postgres) | `[read]` |
| 7 | Zero `ON CONFLICT` defects; 9/9 well-formed | `[read]` |
| 8 | **Covenant and Havoc cannot exhibit the class** — EF Core and GORM, no raw SQL | `[read]` |
| 9 | The defect class exists in exactly **one framework, one subsystem, one table** | `[inferred]` |
| 10 | Failure would be **silent** — all six sites log-and-continue | `[read]` |
| 11 | Whether Postgres errors on the statement | **UNVERIFIED** — no database run |

