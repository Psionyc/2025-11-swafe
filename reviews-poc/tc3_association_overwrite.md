# Review for PoC: tc3_association_overwrite.rs

## Verdict
Invalid - Impossible Attacker Ability

## Technical Review
- Setup realism: The test replaces the real `swafe_lib` and HTTP stack with hand-written shims and never exercises the production handlers via `include!`. Critical cryptographic checks (Pedersen commitments, proofs of knowledge, signature verification) are entirely removed in this harness.
- Fidelity to the described vulnerability: The report claims an attacker with only a stolen `EmailCert` token can overwrite an association. In the canonical code (`lib/src/association/v0.rs:168-215` and `lib/src/association/v0.rs:434-460`), `AssociationRequestEmail::verify` enforces that the provided share matches the Pedersen commitments and that the signer proves knowledge of the victim’s MSK-derived secret. Without those secrets, overwriting is cryptographically impossible even if the token leaks.
- Attacker assumptions: The PoC fabricates a new `AssociationRequestEmail` by setting `fixed_user_pk` to the victim’s key and arbitrary payload strings (`security-poc/tests/tc3_association_overwrite.rs:119-158, 624-671`). Real attackers cannot mint such a payload because they lack the victim’s signing key and the MSK needed for the SoK proof; the shim simply skips those requirements.
- Cheatcodes / unrealistic powers: The shim `AssociationRequestEmail::verify` only checks for string equality and ignores all cryptographic structure, while the shim `EmailCert::verify` always succeeds without verifying signatures or freshness (`security-poc/tests/tc3_association_overwrite.rs:119-233`). These shortcuts grant the attacker abilities that do not exist on chain.
- Determinism / assertions: Although the test deterministically shows the overwrite, it does so in an artificial model that omits critical validations, so the resulting assertion does not map to real deployments.
- Logical inconsistencies: Because the PoC never demonstrates how an attacker would satisfy the genuine verification steps, it fails to bridge the gap between “stolen token” and “attacker-controlled association record.”
- Final impact accuracy: The claimed overwrite cannot be reproduced against the actual contracts without additional secrets (the victim’s association/MSK data). Therefore the PoC does not meet the stated threat scenario.

## Final Determination
The PoC invents cryptographic capabilities by stubbing out `AssociationRequestEmail::verify`, so it does not prove that a stolen EmailCert token lets an attacker overwrite another user’s association on the real contract.
