## Swafe audit notes (prompt-driven sweep)

### Methodology
- Performed three focused passes: (1) endpoint authz/replay, (2) recovery/backups invariants and state persistence, (3) crypto/threshold handling (VDRF, association storage, share validation).
- Scoped to README in-scope files; ignored preexisting final-report items as instructed.

### Attack ideas explored
1. Guardian share cache persists across recoveries; later email compromise can replay cached shares without fresh guardian approval (**success**, see Finding 1).
2. Replayability of `/reconstruction/get-shares` with arbitrary callers (info leak / offline use) — partially covered by Finding 1, no separate exploit.
3. Duplicate share counting in `association::reconstruct_*` to bypass thresholds by reusing one share — requires already having the RIK, not directly exploitable here.
4. Majority vote uses `ceil(n/2)` allowing no-consensus selection — needs additional foothold; left as suspicion.
5. EmailCert replay within validity window to overwrite association records — requires stolen fresh token; not pursued further.
6. Offchain `/init` race if node secrets weakly generated — mitigated by committed hash; deprioritized.
7. Recovery update replays (no version bump) — signatures still required; no bypass found.
8. Guardian share overwrites to grief recovery — signatures bound to ciphertext; no bypass found.
9. Account state exposure via `/account/get` (rec.pke/backups) — public by design; no exploit found.
10. Threshold-zero backups trivially recoverable — user-misconfig only; not claimed.

### Finding 1 — Guardian share cache enables post-recovery takeover
**Impact:** Once a guardian quorum uploads shares for any backup, the shares remain indefinitely in `GuardianShareCollection` and are freely downloadable via `/reconstruction/get-shares` without authentication. A later attacker who compromises only the user’s email/RIK (but no guardians) can pull the cached shares and reconstruct the MSK/backup, bypassing the guardian threshold on every subsequent recovery. This violates the invariant that recovery requires fresh guardian approval each time.

**Where:**
- `contracts/src/http/endpoints/reconstruction/upload_share.rs`: shares inserted into `GuardianShareCollection` and never pruned.
- `contracts/src/http/endpoints/reconstruction/get_shares.rs`: returns all stored shares to any caller; no nonce/version binding to the current recovery session.

**Exploit sketch:**
1) Victim performs a legitimate recovery once; guardians upload shares (encrypted to that session’s `rec.pke`). Shares are stored permanently under `(account_id, backup_id)`.
2) Attacker later steals the victim’s email/RIK (no guardian cooperation). They obtain the current recovery request’s decryption key and call `/reconstruction/get-shares` to download the previously cached shares.
3) Using the stolen RIK/decryption key, the attacker decrypts the cached shares and reconstructs the MSK/backup without contacting any guardian, achieving account/backup takeover.

**Why exploitable:** Share storage is unbounded and unauthenticated; prior guardian approvals are reusable forever. Guardian thresholds collapse after the first successful recovery, reducing future recoveries to “email-only”.

**Suggested fix:** Bind stored shares to a recovery nonce/version and purge them on completion. Require guardians to upload shares per recovery session (e.g., include `rec.pke`/nonce in storage key and wipe after use) so old shares cannot satisfy new recoveries.

### Notes
- No code changes were made; no tests executed (doc-only finding report).
