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
