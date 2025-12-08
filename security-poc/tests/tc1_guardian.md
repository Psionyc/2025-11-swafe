# Code4rena Audit Submission Playbook

A reference for producing high-signal reports on Code4rena. Build every submission around clarity, reproducibility, and impact.

## 1. Quality-First Principles
- Submit before the contest cut-off, through the official form for that audit, and stick to the published scope and known-issue list. Missing these basics risks auto-invalidations ([submission guidelines](https://docs.code4rena.com/competitions/submission-guidelines)).
- Each High/Medium report must stand alone with precise root-cause links, impact analysis, and a runnable PoC unless the README states otherwise. QA items belong in a single combined report and should not be up-severityed ([submission guidelines](https://docs.code4rena.com/competitions/submission-guidelines#qa-reports-low-governance)).
- Judges grade both validity and presentation: arguments must prove exploitability without asking them to finish the reasoning, and writing must stay concise and technical ([judging criteria](https://docs.code4rena.com/competitions/judging-criteria)).
- Stay within acceptable behaviour: avoid spammy shotgun reports, respect confidentiality until the official report ships, and follow the Code of Conduct ([submission policy](https://docs.code4rena.com/legal/submission-policy)).

## 2. High/Medium Submission Template
Mirror the structure that already passed review in `findings/gtl-withdrawal-mispricing.md` and `findings/h-backstop-zero-points-dos.md`.

```
Title: Guardian share download lacks authentication
Severity: High
Target: contracts/src/http/endpoints/reconstruction/get_shares.rs – handler

## Summary
The `/reconstruction/get-shares` endpoint returns every guardian ciphertext for a victim account without requiring any authentication or proof of ownership, enabling arbitrary downloads by anyone who can guess the account/backup IDs.

## Impact
An attacker can enumerate user IDs and exfiltrate guardian shares in bulk. With enough leaked ciphertexts, they can reconstruct seed phrases or break confidentiality guarantees, undermining the entire recovery system.

## Root Cause
- `get_shares::handler` never checks the caller's identity or session state.
- Storage lookups solely rely on `(account_id, backup_id)` tuples that are publicly guessable.
- The HTTP handler immediately serializes and returns all stored shares on success.

## Proof of Concept
1. Run `cargo test --manifest-path security-poc/Cargo.toml --test tc1_guardian_leak --offline`.
2. Observe the `[attack]` log while the test sends only public identifiers.
3. The response contains both guardian shares despite no authentication.

## Recommended Mitigation
Require authenticated sessions or signed recovery proofs before invoking `get_shares`. At minimum, validate the caller owns the target account (e.g., via signature verification) and gate responses behind capability checks.
```

Tips:
- Keep the Summary short enough to scan. Use Impact and Root Cause for depth.
- In PoCs, favour `forge test`/`hardhat test` files that run in the provided harness. Note log output or revert strings so judges can compare quickly.
- Close with mitigation that aligns with sponsor constraints (permissions, upgradeability, tokenomics).

## 3. QA Report Template
Submit one QA report per audit and label findings sequentially (`L-01`, `C-01`, etc.).

```
Title: swafe – QA Report by <handle>
Severity: QA

## Summary
Total issues found and general theme (rounding, configuration, governance).

## Low-Risk Findings
- `L-01` Short title — describe deviation, reference code, expected vs actual behaviour.
- `L-02` …

## Governance / Centralization Risks
- `C-01` Short title — identify privileged call, assumptions, impact.

## Recommendations
Cross-cutting suggestions or monitoring alerts.
```

For each bullet include: scoped file/function, step-by-step reproduction (or rationale for theoretical issues), and the concrete effect (dust accrual, stuck queue, etc.). Drop non-critical refactors unless the audit README explicitly invites them.

## 4. Workflow per Audit
1. **Pre-join prep** – Read contest README, scope, and sponsor Q&A. Note exclusions and live-code handling ([participate in audits](https://docs.code4rena.com/platform-guide/platform-guide-for-wardens/participate-in-audits)).
2. **Model the system** – Sketch invariants, token flows, and privileged roles. Use the severity matrix to anchor what “High” and “Medium” mean ([severity classifications](https://docs.code4rena.com/competitions/severity-categorization)).
3. **Hunting phase** – Alternate between manual review and targeted fuzz/simulation. Log hypotheses with pointers so you can cite them later.
4. **PoC hardening** – Before writing, turn every High/Medium idea into a deterministic test or script that passes in the supplied harness. Capture outputs, balances, and revert messages for reuse in the report.
5. **Write once, edit twice** – Draft using the template above, then re-read for clarity and proof burden. If teammates reviewed, note their usernames for the submission form.
6. **Submit early** – Upload at least a few minutes before the deadline; the form rate-limits near closing time ([submission guidelines](https://docs.code4rena.com/competitions/submission-guidelines#submit-early-and-often)).
7. **Post-submission window** – You have two hours to edit or withdraw via "Your submissions"; after that, the entry is locked ([submission guidelines](https://docs.code4rena.com/competitions/submission-guidelines#editing-submissions), [participate in audits](https://docs.code4rena.com/platform-guide/platform-guide-for-wardens/participate-in-audits#editing-submissions)).

## 5. Handling Sensitive or Misrouted Findings
- For parent-project or zero-day disclosures, file a placeholder (e.g. “Potentially sensitive issue”) with a hash in the body, then open a Help Desk ticket under "Sensitive disclosure". Follow up once the upstream team responds ([submission guidelines](https://docs.code4rena.com/competitions/submission-guidelines#how-to-submit-zero-day-or-otherwise-highly-sensitive-bugs)).
- If you accidentally submit to the wrong audit, re-file correctly and withdraw the mistaken entry within the two-hour window.

## 6. Maintaining Signal & Avoiding Spam Labels
- Only escalate severities when the exploit path truly threatens assets or protocol liveness; judges down-rank exaggeration and repeated low-quality attempts ([judging criteria](https://docs.code4rena.com/competitions/judging-criteria#validity-and-quality), [submission guidelines](https://docs.code4rena.com/competitions/submission-guidelines#quality-and-good-citizenship)).
- Avoid copying other wardens’ reports or dumping automated-tool output. Each submission should read like a professional audit excerpt. Multiple weak entries can invalidate your entire batch and damage signal ([submission guidelines](https://docs.code4rena.com/competitions/submission-guidelines#quality-and-good-citizenship)).
- Respect disclosure rules: public sharing before the official report forfeits awards and can lead to a ban ([submission policy](https://docs.code4rena.com/legal/submission-policy#confidentiality)).

## 7. Quick Reference Links
- Submission guidelines: https://docs.code4rena.com/competitions/submission-guidelines
- Judging criteria: https://docs.code4rena.com/competitions/judging-criteria
- Severity classifications: https://docs.code4rena.com/competitions/severity-categorization
- Platform guide for wardens: https://docs.code4rena.com/platform-guide/platform-guide-for-wardens/participate-in-audits
- Submission policy: https://docs.code4rena.com/legal/submission-policy
- Recent Code4rena reports for exemplar write-ups: https://code4rena.com/reports

Keep iterating on this playbook as you collect more accepted submissions. Treat every report as if it will be quoted verbatim in the sponsor’s final audit document.
