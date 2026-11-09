"""Counterexamples found while building and running this audit, recorded
before any change was made. Included verbatim in the evidence and report."""

DEVELOPMENT_FINDINGS = [
    {"id": "DF1", "about": "Morrison (comparison boundary)", "scenario": "L4",
     "found": "A string amount (\"15000\") makes the built-in excessive_amount rule "
              "(morrison_governance/domains.py, line 111) raise TypeError. The kernel failed "
              "closed, so nothing executed, but the BLOCK came from error handling, not a policy rule.",
     "action": "Recorded, not repaired here (outside this audit's scope). The audit now reports this "
               "as PREVENTED_BY_FAIL_CLOSED_ERROR instead of PREVENTED."},
    {"id": "DF2", "about": "Morrison (comparison configuration)", "scenario": "L5",
     "found": "A settlement to another claim's payee was permitted: P3 (claim-to-payee binding) was not "
              "encoded in the comparison configuration.",
     "action": "Recorded as a comparison gap. Not repaired: the comparison shows what was configured."},
    {"id": "DF3", "about": "Morrison (comparison boundary)", "scenario": "L13",
     "found": "An identity document was emailed to an outside address. With no earlier read in the "
              "sequence and no content signal, Morrison had nothing to act on.",
     "action": "Recorded as a comparison gap."},
    {"id": "DF4", "about": "Morrison (comparison boundary)", "scenario": "G3",
     "found": "Read-then-export was permitted: the export call names no destination, so the "
              "'external egress after a read' rule could not resolve it as external.",
     "action": "Recorded as a comparison gap."},
    {"id": "DF5", "about": "Audit methodology", "scenario": "G4, G7",
     "found": "Two global Morrison rules (separation of duties, bank-change cooling period) were never "
              "exercised: an earlier approval requirement held the sequence first.",
     "action": "G4 and G7 kept unchanged; G4b and G7b added with genuine approvals so the global rules "
               "are actually tested."},
    {"id": "DF6", "about": "Audit methodology", "scenario": "L14",
     "found": "The report-versus-state mismatch check flagged L14 as 'reported allowed, no state "
              "change'. The real cause was unobservable state, not a lying control.",
     "action": "Mismatches are now typed; unobservable effects are labelled as such."},
    {"id": "DF7", "about": "Audit methodology", "scenario": "L14",
     "found": "The verifier flagged EV-L14-MO-1: the comparison boundary permitted and executed the "
              "partner notification, but no observable state changed. The effect lies in unobservable "
              "state, so execution cannot be confirmed either way.",
     "action": "The execution check now reports such steps as UNVERIFIABLE (listed, not passed silently)."},
    {"id": "DF8", "about": "Audit methodology", "scenario": "G8",
     "found": "The verifier found a Morrison reference inside the vendor-neutral residual register: "
              "G8's dependency note described Morrison's default configuration.",
     "action": "The dependency note now describes only the customer's control; Morrison's behaviour on "
               "G8 is reported in the comparison section alone."},
    {"id": "DF9", "about": "Audit methodology (self-test)", "scenario": "M2",
     "found": "The first self-test run reported the consistent-forgery mutation as CAUGHT, but only "
              "because of a pre-existing, unrelated note (EV-L14-MO-1). The forgery had actually escaped.",
     "action": "A mutation now counts as caught only if it introduces a problem absent from the clean "
               "baseline. Re-measured: 8 of 11 caught (selftest_before_fix.json)."},
    {"id": "DF10", "about": "Audit methodology (verifier)", "scenario": "M8",
     "found": "Removing a failed scenario from the residual register went undetected: the coverage check "
              "located the register by the first mention of its title, which is a cross-reference in "
              "Section 1, so it searched most of the report.",
     "action": "The check now uses the register heading itself (the last mention before Section 8)."},
    {"id": "DF11", "about": "Audit methodology (verifier)", "scenario": "M2, M11",
     "found": "Evidence edited consistently (outcome, final state, step state) or edited without updating "
              "the stored digest passed every internal check: nothing recomputed the digest or compared "
              "each arm's final state with its last step.",
     "action": "Added a digest recomputation check and a final-state/step consistency check. Limitation "
               "kept on record: a forger who also recomputes the digest is detected only by replay or by "
               "the manifest delivered with the pack."},
    {"id": "DF12", "about": "Audit methodology (verifier)", "scenario": "M8",
     "found": "After DF10 was fixed, M8 still escaped: the coverage check matched a scenario ID anywhere, "
              "including inside evidence IDs (G5 inside EV-G5-CU-1), so a row could lose its ID unnoticed.",
     "action": "Scenario IDs are now matched only as standalone tokens."},
]
