# Stale Guardian Shares Persist Indefinitely, Causing DoS and Forward Secrecy Risks

## Link to Affected File(s)
- https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/reconstruction/upload_share.rs
- https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/reconstruction/get_shares.rs

## Severity
Medium

## Vulnerability Details
Guardian shares uploaded for any recovery are stored under `(account_id, backup_id)` in `GuardianShareCollection` without binding to a recovery nonce/session and without pruning. `/reconstruction/get-shares` returns every cached share to the caller.

Because these shares are not wiped after a recovery session, they persist indefinitely. While these shares are encrypted to the specific ephemeral recovery key of the session they were created for, their persistence creates two distinct risks:
1.  **Denial of Service (DoS):** A legitimate user starting a *new* recovery session (with a fresh recovery key) will download these stale shares. Attempting to decrypt them with the new key will fail, potentially causing the client application to error out or abort the recovery process, blocking access.
2.  **Forward Secrecy Violation:** The encrypted shares remain stored on the node indefinitely. If the ephemeral private recovery key from a past session is ever compromised (e.g., via a compromised device or log leak), an attacker can retroactive download the persisted shares and reconstruct the secret, even years later.

## Expected Behavior
Shares should be scoped to a specific recovery session (e.g., keyed by nonce/version) and deleted/pruned after the recovery is completed or expires.

## Affected Files and Line Number Ranges
* contracts/src/http/endpoints/reconstruction/upload_share.rs: lines 1–80 (stores shares and never prunes)
* contracts/src/http/endpoints/reconstruction/get_shares.rs: lines 1–40 (returns all stored shares without session filtering)

## Attack Preconditions
* A prior legitimate recovery where guardians uploaded shares.
* For DoS: A user attempts a subsequent recovery.
* For Forward Secrecy: An attacker gains access to an old, expired recovery private key.

## Exploitation Path (DoS Scenario)
1. Victim performs one successful recovery (Session A); shares are cached.
2. Victim later loses access again and starts a new recovery (Session B) with a new key pair.
3. Victim calls `/reconstruction/get-shares` and receives the stale shares from Session A.
4. Victim's client attempts to decrypt Session A shares with Session B's key.
5. Decryption fails (authentication tag mismatch or garbage output), causing the client to error and the recovery to fail.

## Proof of Concept (PoC)
The vulnerability is demonstrated by `security-poc/tests/tc5_guardian_share_cache.rs`, which confirms that shares from "Session One" are returned unchanged during "Session Two".

### Rust Reproduction (tc5_guardian_share_cache)
- Prereq: Rust toolchain installed.
- Directory layout (from repo root):
```
.
├── lib/                     # swafe library (path dependency)
├── contracts/               # contract sources (handler included by test)
└── security-poc/
    ├── Cargo.toml
    ├── src/
    │   └── lib.rs           # can be empty
    └── tests/
        └── tc5_guardian_share_cache.rs
```
- One-time build:
  ```bash
  cargo test --manifest-path security-poc/Cargo.toml --tests --offline
  ```
- Run the test:
  ```bash
  cargo test --manifest-path security-poc/Cargo.toml --test tc5_guardian_share_cache --offline -- --nocapture
  ```
- **Observation:** The test successfully asserts that `response.status_code()` is 200 and the returned body contains the old shares, proving persistence.

## Recommended Fixes
* **Session Binding:** Store shares under a key that includes a session ID or nonce, e.g., `(account_id, backup_id, recovery_nonce)`.
* **Pruning:** Implement a mechanism to delete shares after they are retrieved or after a set expiration time (TTL).
* **Client Handling:** Ensure clients filter shares by trial decryption or attached metadata before failing the entire process, though server-side fixes are preferred to prevent storage bloat and forward secrecy issues.

## Reviewer Notes
This report replaces the previously identified "Account Takeover" risk. The takeover is not possible because shares are encrypted to a specific session key. However, the persistence of these shares constitutes a valid Medium severity issue regarding DoS and data hygiene/forward secrecy.
