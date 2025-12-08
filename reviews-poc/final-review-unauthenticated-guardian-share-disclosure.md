# Final Report Review — Unauthenticated Guardian Share Disclosure

## Verdict
VALID

## Summary
Report correctly shows `/reconstruction/get-shares` returns all guardian ciphertexts to unauthenticated callers for any `(account_id, backup_id)`, breaking guardian threshold protections.

## Threat Model Alignment
- Directly maps to Threat Component #4 (guardian backup/recovery): guardian shares must be gated by authenticated recovery; the endpoint leaks them.
- Risk is consistent with README/THREATMODEL invariants on guardian approval.

## POC and Revert / Abort Analysis
- Associated tests: `security-poc/tests/tc1_guardian_leak.rs` and `security-poc/tests/tc4_guardian_share_leak.rs` (functions `unauthenticated_attacker_can_download_guardian_shares` and `tc4_attacker_can_download_guardian_shares_without_authentication`).
- Both call the real handler, complete successfully (HTTP 200), and assert leaked shares; no aborts, so observed state matches claimed impact.

## Validation Steps Check
- Commands `cargo test --manifest-path security-poc/Cargo.toml --test tc1_guardian_leak --offline` and `--test tc4_guardian_share_leak` match files/tests; expected outputs align with assertions in both PoCs.

## Vulnerability Validity
- Evidence is sufficient; no unrealistic harness behavior. The leak is reproducible and survives execution.
- Note: Content overlaps with other guardian-share download reports; deduplication may be desirable but does not undermine validity.

## Report Quality & Recommendations
- Clear and complete for external use; includes reproduction for two scenarios.
- Recommend consolidating overlapping guardian-share leak reports to avoid repetition.
