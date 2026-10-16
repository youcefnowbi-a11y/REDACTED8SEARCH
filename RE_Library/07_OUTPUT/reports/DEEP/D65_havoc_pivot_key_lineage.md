# D65 — HAVOC PIVOT KEY LINEAGE

**Closes D56 §5 S-3.**
**Artifact:** `teamserver/pkg/agent/demons.go` and the `payloads/Demon` C sources.
**Method:** pure source read. No REA, no Ghidra, no execution.
**Write scope:** this file only. D47 and D56 are complete and were not touched.

---

## §0 — WHAT THIS IS

### 0.1 The question, inherited

**D56 §5 S-3 recorded, and did not measure:**

> `COMMAND_PIVOT`'s `DEMON_PIVOT_SMB_COMMAND` sub-arm calls `AgentHdr.Data.DecryptBuffer(PivotAgent.Encryption.AESKey, PivotAgent.Encryption.AESIv)` at L5373 — a SECOND agent's key/IV, not the session's. Is the pivot agent's key also fixed, or does the pivot handshake re-key?

**D56 proved no rotation exists on the primary path** (agent: alloc `Demon.c:115`, fill `:119`, teardown `:530`; server: one assignment at `demons.go:2372` inside the `COMMAND_CHECKIN` arm). **If `:5373` reads a DIFFERENT agent's material, that material is subject to the same non-rotation proof only if the same write sites produce it. If the pivot path sources key material anywhere else, the proof does not carry over.**

**That is what this report measures.**

### 0.2 The depth convention, stated up front

**The Lead's verification of D56 found that `depth-1` was not a measurement until the depth convention was named: a one-tab scan returns 30 cases, a two-tab scan returns 64, and both are internally consistent under their own definition.**

**This report's convention for any depth or nesting count:** a `case` or `default` label is at **depth 1** when the switch's own brace block contains it directly — equivalently, **exactly one tab of indentation** in this file's formatting. **Anything counted below states the convention in the same sentence as the number.**

### 0.3 What "the pivot path" means here

**Two directions, and both are in scope:**

- **Agent side:** `Pivot.c` — the pivot agent's own handling of a pivot connection and the `DEMON_PIVOT_SMB_*` commands it is asked to execute.
- **Server side:** `demons.go`'s `COMMAND_PIVOT` arm (L5154–L5411) and the `DEMON_PIVOT_SMB_COMMAND` sub-arm that reads `:5373`.

---

*(Q1 follows)*
