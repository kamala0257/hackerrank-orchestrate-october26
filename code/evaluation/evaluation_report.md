# Evaluation report

## Method
The solver performs deterministic request authorization, current and historical identifier resolution, timestamp-bounded evidence retrieval, resource classification, policy-shaped remediation, and phase/operation ordering. It reads only participant-facing files under `dataset/` and writes the required root `output.csv`.

## Full-dataset checks
- Case/row coverage: checked after generation; expected 518 data rows plus header.
- Field validity: every row has one of `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`; every steps value is a JSON array.
- Sequence validity: generated step numbers are consecutive from 1 and phase order is FINDING, REMEDIATION, VERIFICATION.
- Evidence validity: findings use manifest file IDs or activity IDs; proposed remediation and post-remediation verification use an empty evidence ID.
- Sequence accuracy: sorting uses phase, contract operation order, system ID, and resource ID.

## Additional evaluation cases
1. Historical-email request: resolves the current user through audit identifiers and searches old and new identifiers.
2. Non-deletion request: access/export/correction language produces `NOT_APPLICABLE` and `[]`.
3. Restore-risk request: emits `REPORT_RESTORE_RISK`, `BLOCK_RESTORE`, and `VERIFY_RESTORE_BLOCKED` in order while retaining required audit records.
4. Tombstone/support case: distinguishes a retained security/audit record from a deletable support or account record and applies redaction where the context is shared.

## Failures found and improvements
The initial starter contained no usable implementation. The final implementation avoids trusting workflow result fields, applies the `audit_at` cutoff to evidence and activity, includes historical identity values, handles text evidence defensively, and serializes stable deterministic output. Binary/PDF evidence is not OCR'd in the standard-library implementation; future improvement would add an optional OCR/PDF extraction dependency while preserving the same retrieval and policy layers.
