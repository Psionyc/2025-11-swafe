# TC2-replayable-recovery-update

## Threat Component
- Based on: Threat Component #2 in `THREATMODEL.md` (Account lifecycle & recovery logic)
- Relevant assets: Account update versioning, recovery initiation key (RIK), guardian recovery flow state
- Relevant actors: Network attacker able to capture a prior recovery RIK/association, or any party with transient access to a user’s RIK

## Summary
Possessing a single Recovery Initiation Key (RIK) is sufficient to fabricate a recovery update with an attacker-chosen recovery public key. The contract accepts it without any proof of account ownership, and guardians will dutifully re-encrypt their shares to the attacker. A transient leak of the RIK (e.g., from a compromised off-chain node) therefore yields full recovery control.

## Affected Components
- Files: `lib/src/account/v0.rs`
- Functions / Classes: `AccountStateV0::initiate_recovery`, `AccountUpdateV0::verify_update` (recovery branch)

## Steps to Reproduce (Manual)
1. Create an account with guardians and complete the initial allocation (version 0).
2. Configure recovery and add an association, capturing the emitted RIK once (the attacker’s opportunity window).
3. With only the public account state and stolen RIK, initiate recovery and build a recovery update using the attacker’s recovery PKE.
4. Submit the forged recovery update; the contract accepts it, and guardians responding to `check_for_recovery` encrypt their shares to the attacker.

## Automated PoC
- Test file: `security-poc/tests/tc2_replayable_recovery_update.rs`
- Run using:
  ```
  cargo test --manifest-path security-poc/Cargo.toml --offline --test tc2_replayable_recovery_update -- --nocapture
  ```

## Impact
Anyone who ever gains access to the RIK (or a forged association derived from it) can unilaterally trigger recovery and have guardians encrypt shares to their own recovery key, bypassing the account owner and seizing control of the master secret once enough shares arrive.

## Suggested Remediation (High-Level)
- Require authenticated proof of account ownership (or fresh EmailCert-equivalent) in recovery updates, not just possession of the RIK-derived signing key.
- Bind recovery requests to short-lived authorization tokens or rate-limit/expire associations so a transient RIK compromise cannot be abused indefinitely.
- Have guardians refuse to re-encrypt shares unless a threshold of independent, recent associations or owner attestations are present.
