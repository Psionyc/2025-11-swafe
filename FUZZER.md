# Swafe Fuzzing Strategy & Invariant Analysis

This document outlines a specialized fuzzing strategy for the Swafe protocol, designed to uncover logic bugs and broken invariants in the core library and contract handlers.

## 1. Protocol Invariant Extraction

Based on `THREATMODEL.md` and codebase analysis, we define the following critical properties that must always hold true.

### 1.1 Solvency & Access Control (Vaults & Accounts)
| Invariant | Description | Failure Impact |
| :--- | :--- | :--- |
| **Monotonicity of Account Version** | `AccountState.cnt` must strictly increase by exactly 1 for any valid update. | Replay attacks, state rewinding. |
| **Signature Integrity** | A state update must *always* be signed by the `sig` key present in the immediate previous state. | Unauthorized account modification. |
| **Recovery State Transition** | `rec.pke` (Recovery Public Key) can only transition from `None` to `Some` via a valid `AccountMessageV0::Recovery` signed by the association key. | Unilateral account takeover (TC2). |
| **Share Threshold** | `AccountSecrets::recover` must *never* succeed with fewer than `threshold` unique, valid shares. | Security bypass (threshold violation). |

### 1.2 Conservation of Mass & Data Integrity
| Invariant | Description | Failure Impact |
| :--- | :--- | :--- |
| **Share Deduplication** | Providing the same valid share multiple times must not count towards the threshold. | Threshold bypass via replay. |
| **Share Index Validity** | `GuardianShare.idx` must strictly be `< total_guardians`. | Panic (index out of bounds) or logic error. |
| **Ciphertext Integrity** | `BackupCiphertext` decryption must fail for any ciphertext modified after creation (authentication tag check). | Malleability attacks. |

### 1.3 System Liveness & Robustness
| Invariant | Description | Failure Impact |
| :--- | :--- | :--- |
| **No Panics** | Public-facing functions (parsers, handlers, `verify` methods) must *never* panic on arbitrary input. | Denial of Service (DoS). |
| **Deterministic Failure** | Deterministic inputs must produce deterministic errors (no flaky behavior based on unseeded randomness). | Unreproducible bugs. |

---

## 2. Fuzzing Workflow & Harness Design

We use `cargo-fuzz` (libFuzzer) to stress-test these invariants.

### 2.1 Target A: Account State Transitions
**Location:** `lib/src/account/v0.rs`
**Goal:** Prove `verify_update` enforces monotonicity and signature validity under chaos.

**Harness Logic:**
1.  **Setup:** Generate a valid initial `AccountStateV0` (State A).
2.  **Input:** Fuzz a byte sequence representing `AccountUpdateV0` (Update U).
3.  **Action:** Call `U.verify_update(&A)`.
4.  **Invariants Checked:**
    *   **No Panic:** The verification logic must handle malformed signatures/keys gracefully.
    *   **Success Conditions:** If `Result::Ok(State B)`:
        *   `B.cnt == A.cnt + 1`
        *   `B.sig` matches `A.sig` (unless rotated, then valid transition).
        *   If `U` was `Recovery`, `B.rec.pke` must be `Some`.

### 2.2 Target B: Shamir Secret Sharing (SSS) Robustness
**Location:** `lib/src/backup/v0.rs`
**Goal:** Ensure threshold logic is mathematically sound and implementation is robust against duplicate/malformed shares.

**Harness Logic:**
1.  **Setup:** Create a valid `BackupCiphertext` for a secret $S$ with threshold $T$ and $N$ guardians.
2.  **Input:** Fuzz a `Vec<GuardianShare>` (can be valid, invalid, duplicates, reordered).
3.  **Action:** Call `AccountSecrets::recover`.
4.  **Invariants Checked:**
    *   **No Panic:** Handle duplicate indices, invalid crypto tags, etc.
    *   **Threshold Violation:** If unique valid shares < $T$, result *must* be `Err`.
    *   **Reconstruction:** If unique valid shares >= $T$, result *must* be `Ok(S)`.

### 2.3 Target C: HTTP Handler Resilience
**Location:** `contracts/src/http/endpoints/`
**Goal:** Verify routers handle garbage JSON and malformed headers without crashing (500 Internal Server Error / Panic).

**Harness Logic:**
1.  **Mock:** Create dummy `OffChainContext` and `ContractState`.
2.  **Input:** Fuzz `Vec<u8>` for the request body.
3.  **Action:** Call `handler(..., body, ...)`.
4.  **Invariants Checked:**
    *   **No Panic:** `unwrap()` or `expect()` on user input is forbidden.
    *   **Error Codes:** Malformed input should yield HTTP 400, not 500.

---

## 3. Execution Strategy

### 3.1 Setup
```bash
# Install tools
cargo install cargo-fuzz
rustup default nightly

# Initialize inside 'lib' to test core logic
cd lib
cargo fuzz init
```

### 3.2 Harness Implementation (Mental Model)

**`fuzz/fuzz_targets/account_transition.rs`**
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use swafe_lib::account::{AccountStateV0, AccountUpdateV0};

fuzz_target!(|data: (AccountStateV0, AccountUpdateV0)| {
    let _ = data.1.verify_update(&data.0);
});
```

**`fuzz/fuzz_targets/sss_threshold.rs`**
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use swafe_lib::account::AccountSecrets;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|seed: [u8; 32]| {
    let mut rng = ChaCha20Rng::from_seed(seed);
    // 1. Generate valid backup (T=2, N=3)
    let secrets = AccountSecrets::gen(&mut rng).unwrap();
    // 2. Fuzz logic to select/corrupt shares...
    // 3. Assert recovery fails if shares < 2
});
```

### 3.3 Running & Triage
1.  **Sanity Check:** `cargo test` to ensure base logic passes.
2.  **Fuzzing:** `cargo fuzz run account_transition -- -max_total_time=3600` (1 hour).
3.  **Analysis:** If a crash occurs, `cargo-fuzz` dumps the input to `fuzz/artifacts/`. Replay this input to debug the invariant violation.

---

## 4. Specific Attack Vectors to Explore

1.  **Zero Threshold / Empty Guardians:**
    *   Does the system handle $T=0$ or $N=0$ gracefully?
    *   Can `recover` be tricked into succeeding with 0 shares?

2.  **Integer Overflows in Quorum Calc:**
    *   If $N$ is large (`u32::MAX`), does the threshold calculation overflow?

3.  **Deserialization Bombs:**
    *   Does `StrEncoded` or nested JSON parsing panic on deep recursion or huge allocations?

4.  **Key Malleability:**
    *   Can a signature be slightly modified but still verify (e.g., ECDSA malleability) to bypass "seen hash" checks?

## 5. Output Reporting Template

When a fuzzing campaign finds a violation, document it as follows:

```markdown
### [Invariant Violation] Account Monotonicity Broken
**Severity:** High
**Target:** `lib/src/account/v0.rs`
**Invariant:** `new_cnt == old_cnt + 1`
**Input Artifact:** `fuzz/artifacts/account_transition/crash-sha1...`
**Trace:**
1. State cnt = 5.
2. Update calls `verify_update`.
3. Returns Ok(State) with cnt = 5 (No increment).
**Impact:** Replay attack possible.
```
