# Review for PoC: tc4_guardian_share_leak.rs

## Verdict
Accepted

## Technical Review
- Setup realism: Guardian ciphertexts are inserted through the production `GuardianShareCollection::store` mapping (`security-poc/tests/tc4_guardian_share_leak.rs:138-158`), which mirrors how honest guardians populate storage after `/reconstruction/upload-share`.
- Vulnerability fidelity: The PoC reuses the actual `/reconstruction/get-shares` handler by including `contracts/src/http/endpoints/reconstruction/get_shares.rs`, so it hits the same unauthenticated code path that simply deserializes the request and dumps every stored share (`contracts/src/http/endpoints/reconstruction/get_shares.rs:17-35`).
- Attacker assumptions: The attacker only knows the victim’s account and backup IDs — identical to TC4’s assumption after a recovery-key compromise — and never requires privileged context.
- Cheatcodes / unrealistic powers: None; the attack is a normal HTTP POST crafted with serde, and the environment uses the same off-chain context as production.
- Determinism: Fixed byte arrays for IDs and shares make the leak reproducible in every run of `cargo test --manifest-path security-poc/Cargo.toml --test tc4_guardian_share_leak`.
- Assertions & impact: The PoC parses the HTTP 200 body and asserts that every base64-encoded ciphertext exactly matches the seeded guardian shares (`security-poc/tests/tc4_guardian_share_leak.rs:173-188`), conclusively proving information disclosure.
- Logical consistency: Steps follow the documented reproduction precisely — honest setup, unauthenticated request, inspection of leaked data — with no artificial storage edits beyond what real guardians would do.
- Final impact accuracy: The demonstrated leak shows that Threat Component #4’s guardian confidentiality assumption is broken because any caller can download all shares before the owner authorizes recovery.

## Final Determination
The PoC deterministically proves that `/reconstruction/get-shares` serves all guardian shares to an unauthenticated caller, validating the TC4 impact statement.
