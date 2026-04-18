# CloakLLM Compliance Coverage

**Version:** 0.6.1  ·  **Last updated:** 2026-04-16

This document maps CloakLLM's technical features to specific articles of the EU AI Act and GDPR. It is intended for compliance officers, DPOs, and auditors evaluating CloakLLM as PII-protection middleware for high-risk AI systems.

For the regulatory rationale and full architectural argument, see [The Article 12 Paradox whitepaper](https://cloakllm.dev/whitepaper).

---

## EU AI Act

### Article 12 — Record-Keeping
**Status:** Satisfied
**How:** CloakLLM automatically logs every `sanitize` and `desanitize` operation to a hash-chained JSONL audit file. Each entry records the event type, timestamp, model, provider, entity counts, category distribution, latency, and per-pass timing — without storing any original PII. Logs survive process restarts and are designed for regulator inspection.

**Activation:** Enable compliance mode explicitly with `ShieldConfig(compliance_mode="eu_ai_act_article12")`. This adds four metadata fields to every entry (`compliance_version`, `article_ref`, `retention_hint_days`, `pii_in_log`) and asserts the no-PII invariant at runtime.

### Article 19 — Automatically Generated Logs
**Status:** Satisfied
**How:** CloakLLM's audit logger is automatic — every sanitization is logged without user intervention. Each entry's SHA-256 `entry_hash` is computed over the full payload plus the previous entry's hash, producing a tamper-evident chain. Verify integrity at any time:

```bash
cloakllm verify ./cloakllm_audit/ --format compliance_report
```

Returns a structured report with `verdict: "COMPLIANT"` or `"NON_COMPLIANT"` plus a list of detected anomalies.

### Article 4a — Data Processing for Bias Detection
**Status:** Partial (full implementation in v0.7.0)
**How (today):** CloakLLM's deterministic tokenization qualifies as pseudonymisation under GDPR Recital 26 and Article 4(5), which is the baseline requirement of Article 4a. Tokens such as `[PERSON_0]`, `[PHONE_3]`, `[EMAIL_2]` cannot be re-attributed to an individual without the in-memory token map (which is never persisted).

**Coming in v0.7.0:** A dedicated `BiasDetectionSession` API enabling pseudonymised processing of GDPR Article 9 special-category data (health, ethnic origin, religious beliefs, political opinion, biometric identifiers, sexual orientation) for the explicit purpose of bias auditing in high-risk AI systems.

---

## GDPR

### Article 5(1)(c) — Data Minimisation
**Status:** Satisfied
**How:** CloakLLM removes personal data at the input layer before it reaches any logger, model, or downstream system. Audit entries contain hashes (SHA-256 of the prompt and the sanitized output), token counts, and category distributions — no raw text, no original values.

### Article 5(1)(e) — Storage Limitation
**Status:** Satisfied
**How:** Logs are designed to be retainable indefinitely without violating storage limitation, because they contain no personal data to retain. The `retention_hint_days` field (default `180` — the Article 12 minimum for deployers) is metadata for downstream log-rotation systems, not a data lifecycle requirement on personal data.

### Article 25 — Privacy by Design
**Status:** Satisfied
**How:** CloakLLM is middleware. It installs between user input and the model, intercepting every prompt before any downstream processing. Privacy is enforced architecturally — there is no opt-out path that exposes PII to the model or the log.

---

## Code Invariants

The following invariants are enforced in code (not merely documented). Any violation is a regression.

1. **Audit logs contain zero original PII.**
   - Enforced by the `_assert_no_pii_in_entry` runtime guard in `audit.py` (Python) and `audit.js` (JavaScript), invoked on every log entry when `compliance_mode` is set.
   - Tested in `tests/test_compliance_mode.py::test_pii_guard_*`.

2. **Token maps are never persisted to disk.**
   - The `TokenMap` object lives in process memory for the duration of a session. The Shield API never writes it to a file or transmits it to any external system.
   - Tested implicitly by the absence of any persistence code paths.

3. **Compliance-mode entries are part of the hash chain.**
   - The four compliance fields (`compliance_version`, `article_ref`, `retention_hint_days`, `pii_in_log`) are added to the entry payload *before* the SHA-256 entry hash is computed. Any tampering with these fields breaks the chain.
   - Tested in `tests/test_compliance_mode.py::test_compliance_fields_part_of_hash_chain`.

---

## Cross-Language Compatibility (v0.6.1+)

CloakLLM ships parallel Python and JavaScript SDKs. Audit chains written by one SDK can normally be verified by the other — the canonical-JSON serializer and SHA-256 hashing are byte-equivalent across both.

**One known asymmetry exists for chains written before v0.6.1:**

Python v0.6.0 and earlier serialized non-ASCII characters in audit entries using JSON `\uXXXX` escapes (e.g. `é` → `\u00e9`). JavaScript v0.6.0 and earlier preserved the raw UTF-8 bytes. As a result, an audit chain written by Python v0.6.0 containing non-ASCII data (e.g. an `error_message` with European characters) cannot be verified by the JS SDK, and vice versa, when running with `legacy_canonical=True` / `legacyCanonical: true`.

**Resolution:** v0.6.1 introduced a unified canonical serializer (`canonical.py` / `canonical.js`) that preserves UTF-8 in both SDKs. All chains written by v0.6.1 or later are fully cross-SDK verifiable.

**For legacy chains:**
- Verify Python-written chains with `shield.verify_audit(legacy_canonical=True)` from Python.
- Verify JS-written chains with `shield.verifyAudit({ legacyCanonical: true })` from JS.
- Re-running verification with `legacy_canonical=False` (the default) on a v0.6.1+ chain works from either SDK.

This limitation only affects chains written by v0.6.0 that contain non-ASCII characters. ASCII-only legacy chains verify correctly across both SDKs.

---

## How to Verify Compliance

### Programmatic verification (Python)

```python
from cloakllm import Shield, ShieldConfig

shield = Shield(ShieldConfig(compliance_mode="eu_ai_act_article12"))

# Get a structured coverage map for the auditor
summary = shield.compliance_summary()

# Export it to a JSON file the auditor can keep
shield.export_compliance_config("./compliance_snapshot.json")

# Verify the audit chain integrity at any point
report = shield.verify_audit(output_format="compliance_report")
assert report["verdict"] == "COMPLIANT"
```

### Programmatic verification (JavaScript)

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const shield = new Shield(new ShieldConfig({
  complianceMode: 'eu_ai_act_article12',
}));

const summary = shield.complianceSummary();
shield.exportComplianceConfig('./compliance_snapshot.json');
const report = shield.verifyAudit({ outputFormat: 'compliance_report' });
console.log(report.verdict); // "COMPLIANT" or "NON_COMPLIANT"
```

### Command-line verification

```bash
cloakllm verify ./cloakllm_audit/ --format compliance_report
```

Outputs structured JSON. Exit code `0` = COMPLIANT, `1` = NON_COMPLIANT.

---

## Enterprise Key Management

> **⚠ EXPERIMENTAL (v0.6.1)** — The KMS providers shipped in v0.6.0 had bugs that produced unverifiable signatures (incorrect public-key encoding and signing algorithm per provider). v0.6.1 ships them as scaffolding only: each provider raises `NotImplementedError` at runtime with a pointer to the v0.7.0 rebuild plan. Use `LocalKeyProvider` (the default in-process Ed25519 keypair) for production attestation.

The KMS provider scaffolding (Python SDK only) covers four providers:

| Provider | Config value | Status |
|---|---|---|
| AWS KMS | `attestation_key_provider="aws_kms"` | Experimental — disabled in v0.6.1 |
| GCP KMS | `attestation_key_provider="gcp_kms"` | Experimental — disabled in v0.6.1 |
| Azure Key Vault | `attestation_key_provider="azure_keyvault"` | Experimental — disabled in v0.6.1 |
| HashiCorp Vault | `attestation_key_provider="hashicorp_vault"` | Experimental — disabled in v0.6.1 |

`pip install cloakllm[kms]` installs the SDKs (boto3, google-cloud-kms, etc.) so future development continues, but operations raise immediately with a clear message.

Production attestation should use `LocalKeyProvider` (default) until v0.7.0.

When `key_rotation_enabled=True` (with `LocalKeyProvider`), a `key_rotation_event` audit entry is logged at session init recording the key id, provider, and version — no PII.

---

## Scope and Limitations

CloakLLM addresses the input-layer PII problem and the no-PII-in-logs requirement. It does **not** address:

- Model output content moderation or hallucination control.
- Identity-traceability for incident reconstruction (intentionally — see whitepaper §5.4).
- AI Act conformity assessment, CE marking, or notified body procedures.
- AI Act Article 9 (risk management system) or Article 10 (data governance for training data).

CloakLLM is a compliance infrastructure component. Full AI Act compliance for a high-risk system requires complementary measures across the full system lifecycle.

---

## Contact

Issues, audit questions, or partner inquiries: https://github.com/cloakllm/CloakLLM/issues
