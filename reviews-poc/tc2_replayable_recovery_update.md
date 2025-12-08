# Review for PoC: tc2_replayable_recovery_update.rs

## Verdict
Accepted

## Technical Review
- Setup realism: The test uses the real `swafe_lib::account::AccountSecrets` API to create owner and guardian identities, configure recovery, and derive a legitimate Recovery Initiation Key (RIK) (`security-poc/tests/tc2_replayable_recovery_update.rs:10-55`), matching the documented workflow.
- Vulnerability fidelity: The exploit path calls `AccountStateV0::initiate_recovery` through the public API, which in `lib/src/account/v0.rs:171-214` only requires the public account ID plus the RIK to fabricate a recovery update signed by the embedded key, so the PoC exercises the exact missing-authentication branch.
- Attacker assumptions: Only a stolen RIK is required, which aligns with TC2’s threat model; no owner MSK or guardian secrets are accessed once the RIK is captured (`security-poc/tests/tc2_replayable_recovery_update.rs:46-66`).
- Cheatcodes / unrealistic powers: None — the test exclusively uses exported library functions and randomness seeded via `ChaCha20Rng` for determinism.
- Determinism: Fixed RNG seed `[7u8; 32]` ensures the same keys, associations, and forged recovery update are produced across runs, yielding repeatable behavior.
- Assertions & impact: After forging the recovery update, the PoC calls `guardian1.check_for_recovery` and confirms a non-empty share JSON is returned (`security-poc/tests/tc2_replayable_recovery_update.rs:70-93`), proving guardians honor the attacker’s recovery request.
- Logical consistency: Every prerequisite (initial allocation, guardian configuration, recovery setup) is completed via the same methods production clients use; there are no shortcuts or manual state mutation.
- Final impact accuracy: The observed guardian response demonstrates that possession of the RIK alone is enough to coerce guardians into encrypting shares to an attacker-controlled key, exactly matching the report’s claim.

## Final Determination
The PoC conclusively shows that a stolen RIK lets an attacker forge recovery updates that guardians accept, so TC2’s vulnerability is real and reproducible.
