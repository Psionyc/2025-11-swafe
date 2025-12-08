
#[cfg(test)]
mod fuzz {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn fuzz_account_transitions() {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        for i in 0..50 {
            let mut secrets = AccountSecrets::gen(&mut rng).expect("Gen failed");
            let state_v0_initial = match secrets.state(&mut rng).unwrap() {
                AccountState::V0(s) => s,
            };
            let update = secrets.update(&mut rng).expect("Update failed");
            let update_v0 = match update.clone() {
                AccountUpdate::V0(u) => u,
            };

            // Valid update
            let new_state = update_v0.clone().verify_update(&state_v0_initial).expect("Valid update failed");
            assert_eq!(new_state.cnt, state_v0_initial.cnt + 1);

            // Invalid signature
            let mut corrupted_update = update_v0.clone();
            let other_secrets = AccountSecrets::gen(&mut rng).unwrap();
            let other_update = other_secrets.update(&mut rng).unwrap();
            let other_sig = match other_update {
                AccountUpdate::V0(u) => match u.msg {
                    AccountMessageV0::Update(full) => full.sig,
                    _ => panic!("Expected update"),
                }
            };
            
            match &mut corrupted_update.msg {
                AccountMessageV0::Update(full) => full.sig = other_sig, // Visible here!
                _ => {},
            }
            
            assert!(corrupted_update.verify_update(&state_v0_initial).is_err(), "Invalid signature accepted at iter {}", i);
        }
    }
}
