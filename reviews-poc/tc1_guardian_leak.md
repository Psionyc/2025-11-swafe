# Review for PoC: tc1_guardian_leak.rs

## Verdict
Accepted

## Technical Review
- Setup realism: The test seeds `OffChainContext` using the same `GuardianShareCollection::store` path the production handler reads (`security-poc/tests/tc1_guardian_leak.rs:126-143`), so the storage view matches a real node after honest guardians upload ciphertexts.
- Vulnerability fidelity: The PoC invokes the actual `/reconstruction/get-shares` handler via `include!("../../contracts/src/http/endpoints/reconstruction/get_shares.rs")`, so it exercises the real logic shown in `contracts/src/http/endpoints/reconstruction/get_shares.rs:17-35` where no authentication occurs before shares are returned.
- Attacker assumptions: The attacker only supplies publicly guessable identifiers `(account_id, backup_id)` and never forges privileges; this is consistent with TC1 where those IDs are exposed once a RIK is compromised.
- Cheatcodes / unrealistic powers: None — the test issues a normal HTTP request struct and never mutates storage with vm-level primitives.
- Determinism: Inputs are constant byte arrays, so repeated `cargo test --manifest-path security-poc/Cargo.toml --test tc1_guardian_leak` always reproduces the leak.
- Assertions & impact: The PoC decodes the HTTP 200 body into `get_shares::Response` and compares the base64-encoded ciphertexts against the ground truth (`security-poc/tests/tc1_guardian_leak.rs:169-183`), clearly proving total exfiltration.
- Logical consistency: Control flow mirrors the documented reproduction steps; there are no leaps such as manual storage edits or bypassed preconditions.
- Final impact accuracy: The demonstrated result matches the report claim — an unauthenticated caller recovers every guardian share without owner proof, violating Threat Component #1 assumptions.

## Final Determination
The PoC faithfully demonstrates that `/reconstruction/get-shares` leaks all guardian shares to an unauthenticated caller that knows the victim's account and backup identifiers.
