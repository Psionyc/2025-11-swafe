# TC4-unauthenticated-guardian-share-disclosure

## Threat Component
- Based on: Threat Component #4 in `THREATMODEL.md`
- Relevant assets: guardian share ciphertexts stored under `/reconstruction/upload-share`, backup metadata tied to a user's MSK
- Relevant actors: remote attackers with HTTP access who can guess or learn account/backup IDs

## Summary
The guardian backup subsystem exposes `/reconstruction/get-shares` without any authentication or recovery proof. Anyone who knows an account ID and backup ID receives every guardian share that was uploaded for that backup. Threat Component #4 assumes guardians keep shares secret and only release them when the owner has authenticated; this endpoint violates that boundary by handing out all encrypted shares to unauthenticated callers. An attacker who has already forged or stolen the recovery public key (a TC4 precondition) can have guardians encrypt to the attacker-controlled key and then download all shares, bypassing the guardian threshold.

## Affected Components
- Files:
  - `contracts/src/http/endpoints/reconstruction/get_shares.rs`
  - `cli/src/commands/reconstruction.rs`
  - `contracts/java-test/src/test/java/com/partisia/blockchain/contract/TC4UnauthorizedGuardianShareDisclosureIT.java`
  - `security-poc/tests/tc4_guardian_share_leak.rs`
- Functions / Classes:
  - `get_shares::handler`
  - `create_get_guardian_shares_request_command`
  - `TC4UnauthorizedGuardianShareDisclosureIT.should_leak_guardian_shares_to_unauthenticated_attackers_under_tc4`
  - `tc4_attacker_can_download_guardian_shares_without_authentication`

## Steps to Reproduce (Manual)
1. Deploy the Swafe contract, initialize VDRF nodes, and create an account with a social-recovery backup plus several guardians (follow the helper workflow in `BackupWorkflow`).
2. Have each guardian decrypt and upload their share via `/reconstruction/upload-share`.
3. On any machine (no secrets needed), run `cargo run --bin swafe-cli -- create-get-guardian-shares-request --account-id <victim-account> --backup-id <victim-backup> --output attack.json`.
4. POST the contents of `attack.json` to `/reconstruction/get-shares`.
5. Insecure outcome: the HTTP 200 response lists every guardian share even though the caller never proved ownership or recovery authorization.

## Automated PoC
- Java test: `contracts/java-test/src/test/java/com/partisia/blockchain/contract/TC4UnauthorizedGuardianShareDisclosureIT.java`
  - Run using:
    ```bash
    cd contracts/java-test
    mvn test -Dtest=TC4UnauthorizedGuardianShareDisclosureIT#should_leak_guardian_shares_to_unauthenticated_attackers_under_tc4
    ```
- Rust test: `security-poc/tests/tc4_guardian_share_leak.rs`
  - Run using:
    ```bash
    cargo test --manifest-path security-poc/Cargo.toml --test tc4_guardian_share_leak --offline -- --nocapture
    ```

## Impact
An attacker aligning with Threat Component #4 can harvest every guardian share for a backup and, after compromising the recovery key, decrypt the MSK without the user or guardians authorizing the request, nullifying the guardian-threshold guarantee.

## Suggested Remediation (High-Level)
Require `/reconstruction/get-shares` to enforce recovery ownership: bind responses to a proof of possession of the committed recovery key or another authenticated token tied to the recovery session, and reject requests that are not signed by the legitimate owner.
