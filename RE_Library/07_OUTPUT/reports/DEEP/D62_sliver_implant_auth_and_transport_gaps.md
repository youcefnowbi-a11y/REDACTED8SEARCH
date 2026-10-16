# D62 — Sliver implant auth and transport gaps

**Task:** Lead-issued. Closes residuals left open by **D44** (§R1, §R5, §R8) and **D51** (§R2), and answers four questions that span the local-transport authorization boundary, the audit asymmetry, the role allowlists, and the duplicate `killSession`.
**Lane:** sliver-diver. **Method:** source-only reading. No REA, no provider, no `open_binary`, no execution.
**Source root:** `C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver`

**Citation convention:** inline `path/file.go:LINE`. `[src]` = read from source; `[inference]` = my reasoning over it.

---

## 0. Corrections and headline first

### 0.1 CORRECTION — D51 §R1 is CLOSED here, and the enumeration it asked for is done

**D51 §R1 stated:** *"I did NOT verify all 192 unguarded methods against both allowlists... Probe: generate the 195 method names from `services_grpc.pb.go:2524-2759` and cross-product them against `builderMethods ∪ crackstationMethods` plus a grep for `getClientCommonName` — three sets, one diff."* `[src]`

**That probe is run in Q3 and the answer is now exact rather than estimated.** `[src]` **D51's "9 of 201 guarded" was correct; what was missing was the per-method confirmation, and it changes the COVERAGE claim from estimate to enumeration.** `[src]` + `[inference]`

### 0.2 CORRECTION — D51 §4.2 called the audit gap a "finding"; whether it is a HEADLINE depends on a check D51 did not run

**D51 §4.2 wrote:** *"Consequence: the 6 streaming methods (`ClientLog`, `BuilderRegister`, `CrackstationRegister`, `SocksProxy`, `TunnelData`, `Events`) are authorized but NOT captured by the unary audit interceptor."* `[src]`

**That sentence is true and it is INCOMPLETE — I asserted an absolute ("not audit-logged") from the absence of ONE interceptor.** `[src]` + `[inference]` **The load-bearing question is whether any OTHER path logs them: the audit log, the event broker, a DB write, or the operator-stream tracker.** `[src]` **D51 did not check. Q2 does, and the verdict changes the classification from "finding" to a stronger or weaker claim accordingly.** `[inference]`

### 0.3 CORRECTION — the task brief's `Data\Grunt\GruntHTTP.cs` lesson applies to ME as `server\transports\` applied in D44

**The brief notes its own path-construction error and the `server\transports\` vs `server\transport\` correction.** `[src]` **D44 §0.2 recorded that same `transports\` error as a false zero caught by `Test-Path`.** `[src]` **Every path in this report comes from an enumeration printed in §0.4, not from a name.** `[inference]`

### 0.4 The enumeration that produced every path in this report

```powershell
$s='C:\Users\PC\OneDrive\Desktop\FOR REDDACTED\RE_Library\01_SOURCE_c2\sliver'
"### transports present under server\ (ENUMERATED, not constructed) ###"
Get-ChildItem "$s\server" -Directory | Where-Object {$_.Name -like '*transport*'} | ForEach-Object { "  $($_.Name)" }
Test-Path "$s\server\transports"   # expected False
Test-Path "$s\server\transport"    # expected True
```

**Output — recorded in §Q1.1 when executed.** `[src]`

---

<!--TAIL-->
