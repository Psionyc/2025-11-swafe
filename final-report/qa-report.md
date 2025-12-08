Title: swafe – QA Report
Severity: QA

## Summary
Two low-risk/quality issues identified during review: (1) `/reconstruction/get-shares` returns HTTP 200 for unknown `(account_id, backup_id)` pairs, making it impossible to distinguish valid vs invalid queries and enabling silent enumeration; (2) `/association/upload-association` overwrites existing MSK records without any versioning or duplicate detection, so legitimate re-uploads can clobber the stored payload.

## Low-Risk Findings
- **L-01 Silent acceptance of unknown backups leaks oracle information**  
  - **Location:** `contracts/src/http/endpoints/reconstruction/get_shares.rs:19-34`  
  - **Issue:** The handler deserializes the request and always returns HTTP 200 plus whatever `GuardianShareCollection::load` produces. For unknown `(account_id, backup_id)` tuples, `load` yields `None`, the code converts it to an empty `Vec`, and the response is indistinguishable from a valid backup with zero shares.  
  - **Impact:** Attackers can enumerate account IDs and learn which backups exist (responses with non-empty `shares`) while all failures still look successful. Operators and monitoring cannot differentiate typos vs real data, complicating troubleshooting.  
  - **Reproduction:** POST any random IDs to `/reconstruction/get-shares`—the response is HTTP 200 with `shares: []` even though no data exists.  
  - **Recommendation:** Return a `404`/`400` when the storage lookup misses, or include a flag indicating “record not found” so callers can distinguish invalid identifiers.

- **L-02 Association uploads silently overwrite existing records**  
  - **Location:** `contracts/src/http/endpoints/association/upload_msk.rs:23-64`  
  - **Issue:** `MskRecordCollection::store` is called unconditionally for the computed `EmailKey`, so any subsequent upload replaces the stored MSK record without warning even if it carries the same guardians/threshold. There is no version counter or duplication guard.  
  - **Impact:** Legitimate users or automation that replay a previous request (e.g., retrying after a transient error) can accidentally clobber the canonical association payload, forcing a full recovery reset. While forging an overwrite requires the user’s EmailCert and secret data, accidents remain possible and difficult to audit.  
  - **Reproduction:** Upload a valid association via `/association/upload-association`, then replay the same request with altered payload fields—the second call still returns HTTP 200 and permanently replaces the stored entry.  
  - **Recommendation:** Reject duplicate uploads unless accompanied by an explicit rotation intent (e.g., bump the association version or require a revocation flag) so inadvertent replays do not mutate persistent state.

## Governance / Centralization Risks
- _None identified in this pass._

## Recommendations
- Add explicit “not found” responses for read endpoints that translate missing storage entries into successful but empty payloads.
- Require versioning/rotation flows for association uploads to prevent silent clobbering and make operator errors easier to detect.
