# CloakLLM Compliance Coverage

**Version:** 0.6.3  ·  **Last updated:** 2026-04-19

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
   - Enforced by the always-on B3 allow-list schema validator (`_validate_audit_entry_schema` in `audit.py` / `audit.js`, replaced the v0.6.0 `_assert_no_pii_in_entry` deny-list approach in v0.6.1). The validator enforces three layers:
     - Top-level keys must be in the verified-allowed set (rejects arbitrary fields that could carry PII).
     - `entity_details` elements may only contain the 9 allowed metadata keys.
     - `metadata` values are strict-typed and length-bounded (max 256 chars per string, max nesting depth 3, only str/int/float/bool/None or homogeneous collections).
   - v0.6.3 G2: also closes a hash-based PII oracle in desanitize entries — `sanitized_hash` now hashes the tokenized input (same as `prompt_hash`), not the restored PII output. Hash matching against candidate PII no longer succeeds. See "Audit-log hash semantics" below.
   - v0.6.3 G7: audit log files written mode `0o600` and the audit dir mode `0o700` on POSIX so other system users can't read entity hashes / token counts / categories. Windows operators must rely on NTFS ACLs.
   - Tested in `tests/test_compliance_mode.py`, `tests/test_desanitize_hash_oracle.py`, `tests/test_audit_permissions.py`.

2. **Token maps are never persisted to disk.**
   - The `TokenMap` object lives in process memory for the duration of a session. The Shield API never writes it to a file or transmits it to any external system.
   - Tested implicitly by the absence of any persistence code paths.

3. **Compliance-mode entries are part of the hash chain.**
   - The four compliance fields (`compliance_version`, `article_ref`, `retention_hint_days`, `pii_in_log`) are added to the entry payload *before* the SHA-256 entry hash is computed. Any tampering with these fields breaks the chain.
   - Tested in `tests/test_compliance_mode.py::test_compliance_fields_part_of_hash_chain`.

4. **Audit chain recovery is corruption-resilient and tampering-evident** (v0.6.3 H4).
   - Process restarts pick up the last *valid* entry by scanning backward through the most-recent log file. A partial-write trailing line no longer strands earlier valid entries from the chain.
   - Optional `audit_strict_chain` (env `CLOAKLLM_AUDIT_STRICT_CHAIN=true`) refuses to silently restart from GENESIS when log files exist but recovery returned nothing — closes the surface where an attacker who can corrupt all logs could mask tampering as a routine restart.
   - Tested in `tests/test_audit_chain_restart.py`.

5. **Streaming desanitize writes exactly one audit entry per stream lifecycle** (v0.6.3 NEW-3).
   - All four streaming wrappers (sync/async × OpenAI/LiteLLM) emit a `desanitize_stream` entry from a `finally:` block — fires on normal completion, mid-stream errors, or generator-close. Even zero-PII streams write an entry (no Article 12 gap).
   - Tested in `tests/test_streaming_audit.py`.

---

## Audit-log hash semantics (v0.6.3+)

Each audit entry contains two SHA-256 hashes:

| Field | `sanitize` entries | `desanitize` entries (v0.6.3+) | `desanitize` entries (pre-v0.6.3) |
|---|---|---|---|
| `prompt_hash` | sha256(original input) | sha256(tokenized input from LLM) | sha256(tokenized input from LLM) |
| `sanitized_hash` | sha256(tokenized output) | **sha256(tokenized input from LLM)** — same as `prompt_hash` | sha256(restored PII output) ← **the v0.6.3 G2 oracle, now closed** |

**Why `prompt_hash == sanitized_hash` on v0.6.3+ desanitize entries:** the restored PII (the desanitize output) is never hashed and never enters the audit log via any field. An attacker with audit log read access cannot hash candidate PII and confirm matches against `sanitized_hash` — because that field now hashes the tokenized input, not the restored PII.

**Backward compatibility:** chain integrity verification (`verify_chain` / `verifyChain`) is unaffected — it re-computes the entry-level chain hash, not these field-level hashes. Pre-v0.6.3 chains continue to verify correctly without any flag. External tools that matched `sanitized_hash` against restored PII text are intentionally broken — that capability *was* the oracle.

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

v0.6.3 I4: KMS provider construction is short-circuited at the factory layer (`build_key_provider`) before the SDK clients (boto3, google-cloud-kms, azure-keyvault-keys, hvac) are imported. Operators with `cloakllm[kms]` installed pay zero import cost AND keep the SDKs out of memory while they remain experimental — smaller attack surface for any CVE in those packages while we can't actually use them.

---

## v0.6.3 Hardening Summary

For full details see the v0.6.3 CHANGELOG entries in each repo. This section is a compliance-reviewer overview of every fix landed against the audit + attestation surface.

| ID | Surface | Fix |
|---|---|---|
| **NEW-3** | Streaming audit | All four streaming wrappers (sync/async × OpenAI/LiteLLM) write exactly one `desanitize_stream` audit entry per stream lifecycle (normal completion, errors, generator-close). Closes the Article 12 gap where streaming responses bypassed audit logging. |
| **H2** | Ollama SSRF | Cloud-metadata IP ranges (169.254.0.0/16, 100.64.0.0/10, 192.0.0.0/24, fd00:ec2::/64) blocked even when `llm_allow_remote=True`. IPv4-mapped IPv6 normalized before range checks. Per-request DNS re-validation closes the rebinding window. |
| **H3** | Desanitize disclosure | Audit `tokens_used` filtered to subset present in input (was: full token map). Timing fields bucketed to 10 ms to defeat the per-token timing oracle. |
| **H4** | Audit chain restart | Backward-scan recovery finds the last *valid* entry instead of stranding earlier entries on partial-write corruption. Optional `audit_strict_chain` refuses silent GENESIS restart. Partial-write tail detection prepends `\n` on next write to keep the chain machine-readable across restarts. |
| **H5** | Path traversal | `log_dir` and `attestation_key_path` reject NUL bytes (always) and existing symlinks (always); strict mode also rejects outside-CWD paths. |
| **H8** | MCP metadata PII | The MCP server scans `metadata` string values for unambiguous PII patterns (EMAIL, SSN, CREDIT_CARD, IBAN, JWT) and rejects with a clear error before passing to the Shield. |
| **H9** | JS prototype pollution | Centralized `_isPrototypePollutionKey` rejection in audit metadata validators (was: silent `continue` hid the issue). `customPatterns` name validation parity with `customLlmCategories`. Legacy canonical JSON path filters prototype keys. |
| **I3** | Cross-SDK doc | Documented the v0.6.0 canonical-JSON asymmetry between Python and JS so operators understand legacy-chain verification limits. v0.6.1+ chains are byte-equivalent. |
| **I4** | KMS lazy-init | `build_key_provider` short-circuits to `NotImplementedError` BEFORE importing the cloud SDK — keeps boto3 / google-cloud-kms / azure-keyvault / hvac out of memory. |
| **I5** | Lowercase-token warning | One-time warning per process when desanitize substitutes a case-variant token (LLM lowercased canonical token). Wired into both batched `Tokenizer.detokenize` AND streaming `StreamDesanitizer.feed` (G3 review-pass fix). |
| **I6 / I6.1** | OIDC trusted publishing | All three packages (cloakllm, cloakllm-mcp, cloakllm-js) publish via PyPI / npm OIDC trusted publishers — no long-lived API tokens in CI. Auto-provenance attestations on npm. |
| **I7** | Cross-SDK round-trip | Each SDK ships a fixture corpus that the OTHER SDK verifies — Python verifies JS-written audit chains and certificates and vice versa. Future canonical-JSON or signing-scheme drift breaks CI on both sides immediately. |
| **G1** | Runtime path validation | `Shield.export_compliance_config(path)` runs the same `validate_filesystem_path` checks as `ShieldConfig.__post_init__` and uses `O_NOFOLLOW` + `0o600` for the open. Closes a TOCTOU symlink-swap window at the runtime call site. |
| **G2** | Hash oracle (revised H3) | `sanitized_hash` on desanitize entries now hashes the tokenized input, not the restored PII. Closes the direct PII oracle in audit logs. See "Audit-log hash semantics" above. |
| **G5** | MCP prompt injection | `custom_llm_categories.description` values scanned for prompt-injection patterns ("ignore all previous instructions", ChatML tags, Anthropic chat markers, etc.) before flowing into the Ollama detector prompt. |
| **G6** | Python customPatterns | `ShieldConfig.custom_patterns` names validated against `^[A-Z][A-Z0-9_]*$` and reserved-name collision (parity with JS H9). |
| **G7** | Audit file permissions | Audit dir mode `0o700`, audit log files mode `0o600` on POSIX so other system users can't read entity hashes / token counts / categories. |

All v0.6.3 fixes ship with new tests and pass cross-SDK round-trip verification (I7).

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
