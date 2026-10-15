# Mythic `recv_pt_task_opsec_post_response.go` — 187-line read

**Target:** `01_SOURCE_c2/mythic/mythic-docker/src/rabbitmq/recv_pt_task_opsec_post_response.go`
**Size:** 7,270 B / 187 lines
**Purpose:** retires the D4/D17 residual. Format: handoff note for placement in D17 §8 item 4.

---

## Coverage statement first

**This is a full read of all 187 lines.** Not a naming, not a string extraction. Prior coverage in the corpus was `T4_mythic.md:559`, which cites the file once as the `[source:]` for a queue name.

**What I did not read:** the two functions this file calls but does not define — `SendAllOperationsMessage`, `CheckAndProcessTaskCompletionHandlers`, `checkForTaskInterception` (defined here at `:162`), and the `submittedTasksAwaitingFetching` singleton. **`checkForTaskInterception` IS defined in this file and is in scope.** The other three are elsewhere; I make no claim about them.

---

## The structural finding — the post-check is a gate with four terminal states

The handler `processPtTaskOPSECPostMessages` (`:26-161`) resolves a task into exactly one of four statuses, and **the branch structure is a two-level gate rather than a single verdict**:

| Status | Set at | Condition |
|---|---|---|
| `PT_TASK_FUNCTION_STATUS_SUBMITTED` | `:52` | `Success` && (not blocked OR blocked-and-bypassed) |
| `PT_TASK_FUNCTION_STATUS_OPSEC_POST_BLOCKED` | `:54` | `Success` && blocked && not bypassed |
| `PT_TASK_FUNCTION_STATUS_COMPLETED` | `:91` | script-only command, no child tasks, from `SUBMITTED` |
| `PT_TASK_FUNCTION_STATUS_OPSEC_POST_ERROR` | `:142` | `!payloadMsg.Success` |

**The interesting branch is `:87`.** A *script-only* command with no unfinished children is moved **past** `SUBMITTED` straight to `COMPLETED` (`:88-92`), with both `status_timestamp_submitted` and `status_timestamp_processed` set to the same `time.Now()` value (`:93-96`). **The task never enters the submitted-awaiting-fetching queue**, which is the state the agent normally polls. That is correct — there is nothing for an agent to fetch — but it means **the `submittedTasksAwaitingFetching.addTaskById` call at `:132` is unreachable for script-only tasks.**

## The bypass default — `false` not `true`, and it's asymmetric by design

`:59-65` resolves a tri-state into a bool, and the default differs by whether the check blocked:

```
OpsecPostBypassed != nil  -> use the value        (:59-60)
nil &&  blocked           -> false                (:61-62)   <- blocked stays blocked
nil && !blocked           -> true                 (:63-64)   <- unblocked counts as bypassed
```

**An absent bypass field on a blocked task resolves to "not bypassed."** The fail-safe direction is correct: a missing field cannot silently approve. **Worth noting as the one place in this handler where a nil is not a hazard.**

## LIVE DEFECT — `:46` is a malformed SQL statement, propagated across SIX handlers

```
_, err = database.DB.Exec(`UPDATE apitokens SET deleted=true AND active=false WHERE task_id=$1`, task.ID)
```

**`SET deleted=true AND active=false` is not two assignments.** SQL requires comma separation; `AND` inside a `SET` clause makes the right-hand side a **boolean expression**, so this parses as `SET deleted = (true AND active=false)` — assigning `deleted` the result of a comparison rather than setting two columns.

**My first pass called this an isolated typo in this file. That was wrong, and the corrected version is a bigger finding.** A corpus-wide probe over Mythic's Go sources returns the malformed form in **six files**:

| File | Line |
|---|---|
| `recv_pt_task_opsec_post_response.go` | 46 |
| `recv_pt_task_opsec_pre_response.go` | 41 |
| `recv_pt_task_create_response.go` | 46 |
| `recv_pt_task_process_response.go` | 27 |
| `recv_pt_payload_build_response.go` | 92 |
| `utils.go` | 796 |

[source: `Select-String -Pattern 'SET\s+\w+\s*=\s*true\s+AND'` across `rabbitmq/**/*.go`]

**And the same codebase uses the correct comma form for the identical intent** — which proves the idiom and isolates the defect:

```
eventing.go:747      UPDATE apitokens SET deleted=true, active=false ...
eventing.go:1595     UPDATE apitokens SET deleted=true, active=false ...
check_container_status.go:219   UPDATE apitokens SET active=false, deleted=true WHERE ...
initialize.go:177    SET deleted=true, active=false WHERE token_type=$1 OR ...
```

[source: `Select-String -Pattern 'SET\s+[\w\s]+=[\w"''\.\-]+\s*,\s*\w+\s*='`]

**So this is a copy-paste error propagated across six handlers, sitting in a file where the correct form exists twelve lines away in a sibling file.** That is the finding: **the defect is not that someone didn't know SQL; it is that a wrong idiom was duplicated five times while the right one was in use elsewhere in the same directory.**

Consequences, in order of certainty:

1. **`active` is never set in any of the six.** It is not in the assignment list at all. **API tokens tied to finished tasks are never deactivated by these paths** — six handlers, one class of omission. (The `eventing.go` and `check_container_status.go` sites DO set it, so deactivation happens on those paths; the six do not.)
2. **`deleted` is set to `true AND active=false`.** In SQL semantics, `active=false` with `active` NULL yields NULL, so `deleted` may become NULL rather than a clean value — and if the driver rejects the expression, the `Exec` returns an error and **nothing is updated**.
3. **The error is swallowed.** `:47-49` logs and continues; the handler does not return. So the failure is invisible to the caller and the task completes normally.

**This is a live defect in shipped Mythic code, in the same class as the D3 `Looper.prepare()` and D10 `padding` findings: it fails silently, and the surrounding code is written as though it succeeded.** The comment at `:48` reads *"Failed to update the apitokens to set to deleted"* — the author's own description confirms the intent was two assignments, which the SQL does not express.

**Confidence: the string is verbatim from all six sites and the parse is unambiguous.** What I did NOT verify: whether MySQL/MariaDB accepts `deleted=true AND active=false` in a `SET` clause or errors. **That determines whether the effect is "wrong value written" or "no write at all," and I have not executed it.** Both outcomes are defects; the difference is severity. **I also did not read the other five files** — I matched the string, which establishes the pattern, not their surrounding logic.

## Second finding — task interception sits outside the OPSEC gate

`:119-121`: when a task is **not** completed, the handler calls `checkForTaskInterception(&task)` (`:162-187`). That function queries for an active `TriggerTaskIntercept` event group and, if found, **overwrites the status to `INTERCEPTED` and sets `Completed = false`** (`:179-180`).

**So the interception check runs only for non-completed tasks, and it can reverse a `SUBMITTED` verdict.** A task that passed OPSEC post-check and was about to be fetched can be held by an operator-defined interception event group. **The OPSEC gate is therefore not the final authority on whether a task runs** — an event group layered on top can stop it after the gate approved. That is a capability-layer fact about Mythic's sequencing that no report carries.

`:172-174` returns cleanly on `sql.ErrNoRows` (no intercept group) — that error path is correct.

## Error paths — inconsistent, and one is missing

Four `LogError`-and-return paths (`:42`, `:72`, `:84`, `:105`) **abandon the task mid-update**: the task status is not written and no event fires. The task stays in whatever state the agent's earlier callback left it. **A database failure during post-check leaves a task permanently un-updated with no retry and no operator-visible signal beyond a log line.**

`:126-129` is the exception that proves the pattern — it also logs and returns, but it is the *final* write, so nothing is left half-done.

## What this retires

D17 §8 item 4 said the file "is in no report." **Corrected: T4 names it, and this read covers it.** The residual is closed, and it produced three findings — a malformed SQL statement propagated across six handlers, the interception-after-gate sequencing fact, and an unreachable queue-add for script-only tasks — none of which was visible from the file's citation.

**The largest finding came from checking the smallest claim.** My first pass called the SQL defect an isolated typo. One `Select-String` across the directory turned it into six files and found the correct form in use nearby. **Had I written it up as isolated, the corpus would carry a one-file defect where a six-file pattern exists** — and the pattern is the useful artefact, because it names an idiom to search for rather than a line to fix. Same shape as the D3 §10.1 denominator: the first measurement was correct and the scope was wrong.

**Category discipline:** the SQL defect is **live** and **propagated across six handlers**; the interception sequencing is **by-design**; the script-only `:87` path is **intentional but makes `:132` dead for that class**; the error-path inconsistency is **live but lower severity**. Nothing here is inferred except the two possible SQL outcomes, which are marked.
