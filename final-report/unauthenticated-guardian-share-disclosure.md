# Unauthenticated Access to Encrypted Guardian Shares

## Link to Affected File(s)
- https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/reconstruction/get_shares.rs

## Severity
Medium

## Vulnerability Details
The `/reconstruction/get-shares` endpoint allows any caller to download all guardian-share ciphertexts for any `(account_id, backup_id)` pair without authentication. While the shares are encrypted to the recovery key of the active session, this unrestricted access constitutes a significant privacy leak and increases the attack surface.

## Expected Behavior
Access to guardian shares should be restricted to the authenticated account owner or the entity currently authorized to perform recovery (e.g., possessing a session capability). Unauthenticated callers should not be able to harvest encrypted share data.

## Affected Files and Line Number Ranges
* contracts/src/http/endpoints/reconstruction/get_shares.rs: lines 1–35

## Attack Preconditions
* Public knowledge of a target's `account_id` and `backup_id`.
* Guardian shares must exist in storage.

## Exploitation Path
1. Attacker calls `/reconstruction/get-shares` with target identifiers.
2. Endpoint returns all encrypted guardian shares.
3. **Impact:**
    *   **Privacy Violation:** Attacker confirms recovery activity and the number of guardians who have responded.
    *   **Data Harvesting:** Attacker collects ciphertexts for offline storage. If the ephemeral recovery key for that specific session is ever compromised in the future (forward secrecy failure), these harvested shares can be decrypted to steal the master secret.
    *   **Protocol Bypass:** The lack of checks bypasses the intended access control layer, treating public endpoints as an open database.

## Proof of Concept (PoC)
See `security-poc/tests/tc1_guardian_leak.rs` and `security-poc/tests/tc4_guardian_share_leak.rs`. These tests confirm that an unauthenticated caller can successfully retrieve the full list of encrypted guardian shares.

## Recommended Fixes
* Implement authentication for `/reconstruction/get-shares`.
* Require a signature from the `recovery_pke` associated with the active recovery session.
* Rate limit or restrict access to prevent mass enumeration.

## Reviewer Notes
This finding was originally classified as High under the assumption it bypassed threshold security. It has been downgraded to Medium because the shares are encrypted to a session key that an external attacker (without the RIK) cannot produce. The risk is primarily information leakage and forward secrecy concerns.
