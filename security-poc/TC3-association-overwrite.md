# TC3-association-overwrite

## Threat Component
- Based on: Threat Component #3 in `THREATMODEL.md`
- Relevant assets: Encrypted RIK data and MSK shares stored per email association; secrecy of the email ↔ account link.
- Relevant actors: Attackers with access to a valid `EmailCert` token for the target email (e.g., stolen within its validity window).

## Summary
The `/association/upload-association` endpoint blindly overwrites any existing MSK association for an email tag. Once an attacker presents a valid `EmailCert` token (even if stolen), they can resend the upload API with attacker-chosen ciphertexts and commitments. Because the handler never checks for an existing entry or enforces write-once semantics, the attacker replaces the legitimate RIK/MSK payload. Subsequent `/association/get-ss` calls return the poisoned record, enabling takeover or denial of recovery for the victim.

## Affected Components
- Files: `contracts/src/http/endpoints/association/upload_msk.rs`, `contracts/src/storage.rs`
- Modules / Functions: `upload_msk::handler`, `MskRecordCollection::store`

## Steps to Reproduce (Manual)
1. Complete node initialization so `OffchainSecrets` are stored.
2. Upload a legitimate association via `/association/upload-association` using a valid `EmailCert` token and VDRF evaluation.
3. With a stolen or replayed `EmailCert` token for the same email, call `/association/upload-association` again but supply attacker-chosen association data.
4. Call `/association/get-ss` for the same email tag; the response now returns the attacker-controlled record instead of the original.

## Automated PoC
- Test file: `security-poc/tests/tc3_association_overwrite.rs`
- How to run:
  - `cargo test --manifest-path security-poc/Cargo.toml --test tc3_association_overwrite -- --nocapture`

## Impact
An attacker who steals or replays a valid `EmailCert` token can replace a victim's stored association, causing guardians to release shares for attacker-controlled recovery keys or permanently corrupting the victim's recovery state.

## Suggested Remediation (High-Level)
Treat association uploads as append-only or enforce per-tag write-once semantics: refuse overwrites unless accompanied by authenticated revocation/rotation logic, and authenticate requests with freshness and anti-replay protections (e.g., nonce or version checks) before calling `MskRecordCollection::store`.
