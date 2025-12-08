# TC4 Additional Assessment (Guardian Backup & Reconstruction)

## Scope
Focused solely on Threat Component #4 (guardian backup & reconstruction subsystem) per `THREATMODEL.md`. Reviewed the reconstruction HTTP endpoints, guardian share storage, and backup/sharing crypto flows.

## Areas Reviewed
- `contracts/src/http/endpoints/reconstruction/get_shares.rs`
- `contracts/src/http/endpoints/reconstruction/upload_share.rs`
- `lib/src/backup/v0.rs` (threshold handling, share verification, recovery logic)
- `cli/src/commands/reconstruction.rs` and `cli/src/commands/backup.rs`

## Findings
No additional exploitable issues were confirmed beyond the previously reported unauthenticated guardian-share disclosure via `/reconstruction/get-shares`. Input handling, share verification, and guardian-share storage did not reveal another exploitable path within TC4 given current attacker capabilities.

## Notes
- The reconstruction endpoints remain unauthenticated, so existing PoCs still apply. No new distinct exploit was identified in this pass.
- Guardian threshold handling in `lib/src/backup/v0.rs` allows threshold `0`, but this is an explicit design choice documented in code comments and requires owner cooperation, so it was not treated as a new TC4 vulnerability.
