# D13 — Covenant API Control Plane

**Target:** `RE_Library/01_SOURCE_c2/covenant/Covenant/`
**Class:** source-only reversal (NO REA/GHIDRA, per task-25)
**Control document:** D2 (`D2_covenant_code.md`, 195,734 B / 2,529 lines) — conventions followed, not restated
**Companion:** D11 (`D11_sliver_rpc_core.md`) — the Sliver comparison this report tests against

**Tags:** `[src]` = read directly from the tree · `[inference]` = my deduction · `[absent]` = searched and not found, with the search stated

**Headline, stated up front so it is not buried:** Covenant's API layer is **1,084,841 B across 23,549 lines but only 183 operations** — it is an AutoRest-generated REST client façade with provably uniform structure. The authorization model is **not** in that file, and it is materially more rigorous than Sliver's: **18 of 18 API controllers carry a class-level `Authorize` policy**, and there is a real five-role Identity model. But there is **one unannotated 1,153-line SignalR hub — `CovenantHub`, mounted at `/covenanthub` — with ~230 callable methods and no `[Authorize]`**, while all five of its sibling hubs carry it. That is the D11 pattern repeating, and it is this report's primary finding.

---

## TOC

1. [Why CovenantAPI.cs is 1.08 MB — measured, not inferred](#1-why-covenantapics-is-108-mb)
2. [The authentication mechanism](#2-the-authentication-mechanism)
3. [The role and permission model](#3-the-role-and-permission-model)
4. [The SignalR Hub layer — a second command channel](#4-the-signalr-hub-layer)
5. [InternalListener — what it is and who can create one](#5-internallistener)
6. [Comparison against D11 §2](#6-comparison-against-d11-2)
7. [Residual unknowns](#7-residual-unknowns)

---

*(sections appended below)*
