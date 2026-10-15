# D25 — Mythic `recv_*` siblings: the four remaining six-file sites, read for logic

**Scope owner:** android-diver (task-34)
**Target:** `01_SOURCE_c2/mythic/mythic-docker/src/rabbitmq/` — four files, **22,780 B / 573 lines**
**Read:** all 573 lines. **No other file in this report was read for logic.**

| File | Bytes | Lines | Malformed `SET` |
|---|---|---|---|
| `recv_pt_task_opsec_pre_response.go` | 4,195 | 106 | `:41` |
| `recv_pt_task_create_response.go` | 8,280 | 211 | `:46` |
| `recv_pt_task_process_response.go` | 1,376 | 38 | `:27` |
| `recv_pt_payload_build_response.go` | 8,929 | 218 | `:92` |

**EXCLUDED, stated as excluded:** `utils.go` (1,488 lines, out of proportion for this pass). `util_agent_message_actions_post_response.go` (142,962 B) is **out of scope** — D11 owns it and declared its own residue in `D11 §8.2`.

---

## 1. What this report confirms, and what it completes

The six-file set is `D18`'s count. `recv_pt_task_opsec_post_response.go` was read in full there (D18, 187 lines). **These four complete it.** `utils.go:796` is the sixth site and is excluded — **the six-file claim is a claim about five read files plus one string match, and it is stated that way throughout.**

## 2. THE ERROR-HANDLING TABLE — confirmed per site, from the body

**Requested by the lead. Confirmed per site by reading the eight lines following each `SET`.**

| # | File | `SET` at | `if err != nil` block | Returns? |
|---|---|---|---|---|
| 1 | `recv_pt_task_opsec_pre_response.go` | `:41` | `:42-44` `LogError(err, "Failed to update the apitokens to set to deleted")` | **NO — falls through** |
| 2 | `recv_pt_task_create_response.go` | `:46` | `:47-49` same string | **NO — falls through** |
| 3 | `recv_pt_task_process_response.go` | `:27` | `:28-30` same string | **NO — falls through** |
| 4 | `recv_pt_payload_build_response.go` | `:92` | `:93-95` same string | **NO — falls through** |
| 5 | `recv_pt_task_opsec_post_response.go` *(D18)* | `:46` | `:47-49` same string | **NO — falls through** |
| 6 | `utils.go` *(excluded)* | `:796` | `:797-799` same string | **NOT READ — per string match only** |

**The preliminary holds, verified from the bodies rather than the pattern.** All four report sites log and continue. **The log string is byte-identical at all six sites:** `"Failed to update the apitokens to set to deleted"`.

**And the failure mode is worse than "no return."** In four of the four files read here, the swallowed error is *not the only consequence* — the handler proceeds to write the task row that the missing token update was meant to accompany. A reader of the log sees one error line and a task that appears to have completed normally.

## 3. THE KEY-MISMATCH VERDICT — **intentional. Not drift.**

**The lead asked whether `WHERE payload_id=$1` at `payload_build_response.go:92` is copy-paste drift. It is not, and the schema settles it.**

`apitokens` carries **both** keys as independent foreign keys:
```
003003000_3.3.0.sql:153   alter table "public"."apitokens" add column IF NOT EXISTS "payload_id" integer;
003003000_3.3.0.sql:155   alter table "public"."apitokens" add column IF NOT EXISTS "task_id" integer;
003003000_3.3.0.sql:300   add constraint "apitokens_payload_id_fkey" FOREIGN KEY (payload_id) REFERENCES payload(...)
003003000_3.3.0.sql:304   add constraint "apitokens_task_id_fkey"   FOREIGN KEY (task_id)   REFERENCES task(id) ON UP...
```
[source: `database/migrations/003003000_3.3.0.sql:153,155,300,304`]

**Two columns, two referential targets, one table.** An API token can be scoped to a task *or* a payload, and this handler family is the payload-side counterpart of the task-side five. **The key choice is correct and mirrors the handler's subject.**

**The handler's own logic confirms the family.** `processPayloadBuildResponse` operates end-to-end on `payload`: it selects `FROM payload ... JOIN filemeta` (`:79-87`), updates `filemeta` (`:106-108`), updates `payload` (`:113-115`), and emits `TriggerPayloadBuildFinish` with `PayloadID` (`:128-137`). Every identifier in the function is payload-scoped. **`payload_id` is the consistent key for this file, not an accident.**

**Consequence for the pattern claim: the six sites are ONE statement in ONE family and ONE key-mismatch-free shape — except this one, which is correctly different.** The defect is the `SET` clause and the swallowed error, **not** the `WHERE`. I am stating this explicitly because the lead's framing offered "intentional or drift," and **the answer is intentional, which removes a candidate defect rather than adding one.** Reporting it as drift would have been a false finding.

## 4. THE STRONGER FRAMING — **VERIFIED. "One template copied six times, defect included."**

**The lead's third request, and it holds.** Three properties are identical across all six sites:

| Property | Identical across all six? |
|---|---|
| The statement `UPDATE apitokens SET deleted=true AND active=false WHERE <key>=$1` | **YES** — 5 read + `utils.go` matched |
| The log string `"Failed to update the apitokens to set to deleted"` | **YES** — all six, byte-identical |
| `if err != nil { LogError(...) }` with **no return** | **YES** — all six |

**Plus a fourth, which strengthens it further:** the `SET` text is character-identical including the malformed `AND`. A template copied six times reproduces its defects exactly; six independent typos would not produce one identical wrong idiom while the correct comma form exists elsewhere in the same package.

**Evidence the correct form was known to the same author, same package:**
```
eventing.go:747                SET deleted=true, active=false      <- comma form
eventing.go:1595               SET deleted=true, active=false      <- comma form
check_container_status.go:219  SET active=false, deleted=true      <- comma form
initialize.go:177              SET deleted=true, active=false      <- comma form
user_delete_apitoken_webhook.go:78   SET deleted=:deleted, active=:active   <- comma form
```
[source: string match across `rabbitmq/**/*.go`]

**Verdict: one template, copied six times, defect included.** This is a **live** defect in shipped code — the six sites are the task/payload completion path, i.e. they run on every completed task and every finished payload build.

## 5. NEW FINDING — `create_response.go:187-199`: a second, independent swallowed error

**Not in the pattern. Found by reading the body.**

```go
187:  _, err = database.DB.NamedExec(`UPDATE task SET
188:        status=:status, stderr=:stderr, completed=:completed
189:        WHERE
190:        id=:id`, task)
191:  _, err = database.DB.Exec(`INSERT INTO response (task_id, operation_id, response)
192:        VALUES ($1, $2, $3)`, task.ID, task.OperationID, task.Stderr)
193:  if err != nil {
194:      logging.LogError(err, "failed to add error to responses")
195:  }
196:  if err != nil {
197:      logging.LogError(err, "Failed to update task status")
198:      return
199:  }
```

**Two consecutive writes assign to the same `err`, and the first is never checked.** `:191` overwrites the value from `:187` before any `if` inspects it.

Three consequences, in order of certainty:

1. **The `UPDATE task` at `:187` has its error discarded entirely.** If the task status/stderr write fails, **nothing reports it** — `:193` and `:196` are both testing the `INSERT INTO response` result.
2. **`:196`'s message is wrong.** It says *"Failed to update task status"* but the error it prints came from the `INSERT INTO response` at `:191`. **A failed response-insertion is logged as a failed status update.**
3. **The task is left with `Completed=false` and an un-updated status**, having already emitted `TriggerTaskFinish` at `:200` with `ActionSuccess: false` — so downstream consumers are told the task finished while the row may not reflect it.

**Category: live.** This is the same class as the `SET` defect — a write whose failure is invisible — but it is a **separate occurrence** in a file already in the six-file set, and it is **not** part of the copied template. It is a second, independent instance of the same *authoring habit*.

## 6. Further observations from the four bodies

**`process_response.go:27` uses `err =` where no `err` is in scope at that point.** `:23` declares `err` inside `if err := json.Unmarshal(...)` — scoped to that `if` and its `else` block, which is where `:27` sits, so it compiles. **Not a defect; noted because it is the shallowest of the six handlers (38 lines) and it is the one where the swallowed-error path has the least surrounding context to recover from.**

**`opsec_pre_response.go:65-77` is the only site of the four that returns after its write.** `:68-70` returns on `NamedExec` failure; `:71-77` returns after dispatching to create-tasking. **This is the correct shape and it is the contrast case: the same author, the same package, the same handler structure — and here the error path returns.** It strengthens the template claim by showing what the template should have been.

**`opsec_pre_response.go:90-94`** — the `INSERT INTO response` on the error path logs and continues (`:92-94`), same swallowed-write habit, third occurrence in this file set.

## 7. UNRESOLVED AND MARKED — MariaDB/MySQL semantics

**Whether the server ACCEPTS `SET deleted=true AND active=false` or rejects it is NOT resolved and is NOT guessed.**

- **`deleted` exists**: `003003000_3.3.0.sql:147` adds it as `boolean not null default false`. **So the statement cannot fail on a missing column** — the defect is purely in how the `SET` list is written. [source: migration file, read]
- **If the server parses `AND` as a boolean expression:** the statement runs and writes `deleted = (true AND active = false)`. `active` is **never assigned** — so the token is never deactivated, and `deleted` receives a computed value rather than `true`.
- **If the server rejects a non-assignment in a `SET` list:** the `Exec` returns an error and **no write occurs at all**.

**Both outcomes are defects. The difference decides severity, and it cannot be settled without executing against the server — which is out of scope here.** The pattern stands regardless.

## 8. Method and limits

**Read:** the four named files in full, 573/573 lines, plus `003003000_3.3.0.sql` lines 147-305 and `database/schema.go:701-707` for the `apitokens` definition, plus a string match across `rabbitmq/**/*.go` for the correct-form controls.

**Not read:** `utils.go`, `D11`'s file, and the five other files in the correct-form control list (matched as strings, not read for logic).

**Positive controls that fired.** The `SET`-form probe returned the malformed form in 6 files and the correct form in 5 — **both directions present, so the probe discriminates rather than matching everything**. The `deleted`-column probe returned the column at `003003000_3.3.0.sql:147` and returned nothing for an `add column ... deleted` on `apitokens` in any other migration, with `callbackport` at `003001000_3.1.0.sql:15` as the control showing the probe matches other tables.

**Every count in this report was produced by enumeration, and every line citation by reading the file at that offset.**
