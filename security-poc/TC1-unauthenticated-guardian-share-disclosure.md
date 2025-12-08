# TC1-unauthenticated-guardian-share-disclosure

## Threat Component
- Based on: Threat Component #1 in `THREATMODEL.md`
- Relevant assets: guardian share ciphertexts, recovery traffic on `/reconstruction/get-shares`
- Relevant actors: remote attackers with HTTP access to Partisia off-chain routers

## Summary
The contract's `/reconstruction/get-shares` endpoint returns every stored guardian share to anyone who knows an account ID and backup ID. There is no authentication, recovery-proof, or EmailCert requirement, even though the threat model requires `update_account` and every HTTP endpoint to ensure only authenticated owners can drive recovery. An attacker who compromises a Recovery Initiation Key (as already assumed in TC1) can upload a recovery key that points to their own encryption key, wait for guardians to respond, and then simply harvest all guardian shares over HTTP without any additional secrets. This leaks the ciphertexts needed to decrypt the victim's MSK once the attacker controls the recovery key, fully defeating the guardian threshold invariant.

## Affected Components
- Files:
  - `contracts/src/http/endpoints/reconstruction/get_shares.rs`
  - `cli/src/commands/reconstruction.rs`
  - `contracts/java-test/src/test/java/com/partisia/blockchain/contract/TC1UnauthorizedGuardianShareDisclosureIT.java`
- Functions / Classes:
  - `get_shares::handler`
  - `create_get_guardian_shares_request_command`
  - `TC1UnauthorizedGuardianShareDisclosureIT.should_leak_guardian_shares_to_unauthenticated_attackers`

## Steps to Reproduce (Manual)
1. Deploy the Swafe contract and initialize VDRF nodes (follow the existing Java integration test setup).
2. Create an account with a social-recovery backup plus three guardians using the CLI helpers (`generate-account-allocation`, `create-backup-ciphertext`, `add-backup-to-account`).
3. Have each guardian decrypt and upload their share via `/reconstruction/upload-share` (again following `BackupWorkflow`).
4. On a completely unauthenticated machine, run `cargo run --bin swafe-cli -- create-get-guardian-shares-request --account-id <victim-account> --backup-id <victim-backup> --output attack.json`.
5. POST the contents of `attack.json` to `/reconstruction/get-shares`.
6. Insecure outcome: the HTTP 200 response lists every guardian share even though the caller never proved ownership or recovery authorization.

## Automated PoC
- Test file: `contracts/java-test/src/test/java/com/partisia/blockchain/contract/TC1UnauthorizedGuardianShareDisclosureIT.java`
- Run with:
  ```bash
  cd contracts/java-test
  mvn test -Dtest=TC1UnauthorizedGuardianShareDisclosureIT#should_leak_guardian_shares_to_unauthenticated_attackers
  ```

## Impact
Once an attacker compromises or forges the victim's recovery key (the very scenario Threat Component #1 is worried about), they can trivially download every guardian share by making this unauthenticated HTTP call. The shares will be encrypted to the recovery key controlled by the attacker, allowing complete theft of the master secret key and takeover of the victim's account.

## Suggested Remediation (High-Level)
Require authenticated recovery requests for `/reconstruction/get-shares`. For example, enforce a signed token derived from the currently committed recovery key, validate EmailCert freshness, or tie the download to the requester’s recovery-session secret so that only the legitimate account owner (or whoever set `rec.pke`) can fetch the shares. Ideally, the endpoint should verify the recovery initiation signature and refuse to serve shares unless the caller proves possession of the recovery private key.
