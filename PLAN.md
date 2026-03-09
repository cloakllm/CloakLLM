# Design Discussion: Differential Privacy + Cryptographic Attestation for CloakLLM

## Context
CloakLLM v0.2.0 provides deterministic PII detection, tokenization, hash-chained audit logs, and custom LLM detection categories. A contributor proposes evolving this into a system where:
1. Detection accuracy is validated at 99.9% across the 3-pass pipeline (Regex/NER/LLM)
2. Tokenization is normalized into a standard format
3. PII is one-way hashed with pre-signed attestation
4. This enables otherwise-sensitive workloads to run safely on public infrastructure

## What CloakLLM Has Today

| Capability | Status | Details |
|---|---|---|
| 3-pass detection | Done | Regex (0.95 conf), spaCy NER (0.85), Ollama LLM (configurable) |
| Deterministic tokenization | Done | `[CATEGORY_N]` format, in-memory forward/reverse map |
| Irreversible redaction | Done | `mode="redact"` -- no forward map, no recovery |
| Hash-chained audit | Done | SHA-256, genesis hash, tamper-evident JSONL |
| Audit verification | Done | O(n) chain walk, detect tampering |
| Custom LLM categories | Done | User-defined semantic PII types via Ollama |
| Batch processing | Done | `sanitize_batch()` with shared token map |
| Performance metrics | Done | Per-pass timing, `shield.metrics()` API |
| Detection benchmarking | **Missing** | No F1/recall/precision measurement suite |
| Differential privacy | **Missing** | No epsilon/delta, no noise injection |
| Cryptographic attestation | **Missing** | No signatures, no pre-signed proofs |
| Normalized/canonical tokens | **Partial** | Format is consistent but not a formal standard |
| One-way PII hashing | **Partial** | Audit logs hash original text, but no keyed/salted per-entity hashes |

## Gap Analysis & Proposed Architecture

### Gap 1: Detection Accuracy Validation (99.9% target)

**What's needed:** A benchmark suite that measures recall/precision/F1 against labeled PII datasets.

- **Recall** is the critical metric -- a missed PII entity breaks the guarantee
- 99.9% recall means at most 1 in 1000 PII entities slip through
- Need to measure per-category (EMAIL is ~100% with regex; PERSON via NER is lower)
- The 3-pass architecture already layers detection, but we need proof

**Approach options:**
- A) Curate a labeled test corpus (synthetic + annotated real-world) and run detection benchmarks
- B) Use existing NER evaluation datasets (CoNLL, OntoNotes) + synthetic structured PII
- C) Build a "red team" adversarial test suite (obfuscated PII, edge cases)

**Key question:** Does 99.9% need to be per-category or aggregate? Regex categories (EMAIL, SSN) are likely >99.99%. NER categories (PERSON) are the weak link.

### Gap 2: Normalized Tokenization Standard

**What's needed:** A formal spec for tokens that's interoperable across systems.

Currently: `[CATEGORY_N]` is CloakLLM-specific. To be a standard:
- Define a canonical token grammar (RFC-style)
- Namespace tokens: `[cloakllm:EMAIL_0]` or URN format
- Support versioning of the token spec
- Define serialization for token maps (JSON schema)

### Gap 3: One-Way PII Hashing (per-entity)

**What's needed:** Each detected entity gets a deterministic, one-way hash so you can:
- Link the same entity across documents without knowing the original value
- Prove to a third party that specific PII was handled
- Enable "k-anonymity" style analysis on hashed data

**Design:**
```
hash = HMAC-SHA256(server_key, category + ":" + normalized_value)
```

- Keyed hash (HMAC) prevents rainbow table attacks
- Category prefix prevents cross-category collisions
- Normalization (lowercase, strip whitespace) ensures consistency
- Server key is per-deployment, never shared
- This goes in `entity_details` alongside existing metadata

### Gap 4: Cryptographic Attestation (Pre-Signed Proofs)

**What's needed:** A verifiable proof that sanitization occurred, signed by the CloakLLM instance.

**Design options:**
- A) **Ed25519-signed audit entries** -- each entry gets a digital signature from the CloakLLM instance's keypair. Third parties can verify without access to the full chain.
- B) **Sanitization certificates** -- a signed JSON document containing: input hash, output hash, entity count, timestamp, detection passes used. Compact, standalone proof.
- C) **Merkle tree** for batch operations -- a single root hash covers all entries in a batch, enabling efficient partial verification.

**Key question:** Who is the verifier? An internal compliance team (simpler) or an external auditor/regulator (needs PKI/certificate chain)?

### Gap 5: Formal Differential Privacy

**Important distinction:** What the user describes may be closer to "provable PII removal" than formal differential privacy (which adds calibrated noise to query results). Two possible interpretations:

**Interpretation A -- Detection guarantee:** "We can prove with 99.9% confidence that all PII has been removed." This is a detection recall problem, not differential privacy per se. The 3-pass pipeline achieves this through layered detection.

**Interpretation B -- True differential privacy:** Adding epsilon-bounded noise to outputs so that any individual's data cannot be distinguished. This is a fundamentally different mechanism -- it applies to aggregate queries, not text sanitization.

CloakLLM's architecture aligns with Interpretation A. Formal DP (Interpretation B) would be a separate system.

## Recommendation

### Privacy model: Detection Guarantee (not formal DP)

CloakLLM is a **text sanitization tool**, not a query engine. Formal differential privacy (epsilon/delta, noise injection) applies to aggregate statistical queries -- it doesn't map naturally to "remove PII from a prompt before sending to an LLM." What CloakLLM needs is a **provable detection guarantee**: "we can demonstrate that 99.9%+ of PII entities are caught by our 3-pass pipeline."

This is a recall/precision benchmarking problem, and the 3-pass architecture (regex + NER + LLM) is designed for exactly this kind of layered coverage.

### Verifier: Automated systems (public cloud intake)

The endgame -- "public workloads" -- means the verifier is a **programmatic system** (cloud platform, API gateway, data pipeline) that needs to check a machine-readable proof that sanitization occurred before accepting the data. This rules out "just trust the audit logs" and requires cryptographic attestation with a standard format.

### Phased implementation (recommended order)

#### Phase 1: Detection Benchmark Suite (v0.3.0)
**Why first:** You can't claim 99.9% without measuring it. This is the foundation.

- Curate labeled PII corpus (synthetic + annotated samples) covering all categories
- Evaluation harness: per-category recall/precision/F1, per-pass contribution
- Red team suite: adversarial edge cases (obfuscated emails, partial SSNs, Unicode tricks)
- Output: a published accuracy report per release
- Realistic target: 99.99% for regex categories, 95-98% for NER, 90-95% for LLM semantic

#### Phase 2: Per-Entity One-Way Hashing (v0.3.1)
**Why second:** Quick win, high value. Enables linkability without exposing originals.

- `HMAC-SHA256(deployment_key, category + ":" + normalized_value)` per entity
- Add `entity_hash` field to `entity_details` in TokenMap and audit logs
- Keyed hash prevents rainbow table attacks; category prefix prevents cross-type collisions
- Enables: "same person appeared in 47 requests" without knowing who
- Config: `ShieldConfig(entity_hashing=True, hash_key="...")`

#### Phase 3: Cryptographic Attestation (v0.3.2)
**Why third:** The differentiator for public workloads. Needs Phase 1 + 2 as foundation.

- Generate Ed25519 keypair per CloakLLM deployment
- Sign each audit entry (or batch) with the deployment key
- Issue **sanitization certificates**: compact signed JWT containing:
  - Input hash, output hash, entity count, categories
  - Detection passes used, accuracy claim
  - Timestamp, deployment public key
- Verifier SDK: lightweight library that validates certificates without needing CloakLLM
- Merkle tree for batch certificates (single root hash covers N entries)

#### Phase 4: Normalized Token Standard (v0.4.0)
**Why last:** Standardization only makes sense once the format is battle-tested.

- Formal grammar for tokens (RFC-style BNF)
- Namespace: `[cloakllm:EMAIL_0]` or keep `[EMAIL_0]` with a version header
- JSON schema for token maps (interoperable serialization)
- Published spec that other tools could adopt

### What this enables

With all 4 phases:
1. You run `shield.sanitize(text, mode="certified")`
2. PII is detected (3-pass, benchmarked at 99.9%+), one-way hashed, and replaced with normalized tokens
3. A signed sanitization certificate is generated
4. The sanitized text + certificate are sent to a public LLM/cloud service
5. The receiving system verifies the certificate signature, confirms sanitization claims
6. The workload runs on public infrastructure with cryptographic proof that PII was handled
7. No original PII exists anywhere except in-memory during the sanitize call

### Files that would be affected

| Phase | New files | Modified files |
|---|---|---|
| 1. Benchmarks | `cloakllm-py/benchmarks/`, `cloakllm-js/benchmarks/` | CI configs |
| 2. Entity hashing | -- | `tokenizer.py/js`, `config.py/js`, `audit.py/js`, `shield.py/js` |
| 3. Attestation | `cloakllm-py/cloakllm/attestation.py`, `cloakllm-js/src/attestation.js`, `cloakllm-verify/` (new verifier package) | `shield.py/js`, `audit.py/js`, `config.py/js` |
| 4. Token standard | `TOKEN_SPEC.md` | `tokenizer.py/js` |

### Not recommended

- **Formal differential privacy (epsilon/delta)** -- wrong tool for the job. DP is for statistical databases, not text sanitization pipelines.
- **Blockchain-based audit** -- adds complexity without meaningful benefit over signed hash chains.
- **Homomorphic encryption of tokens** -- massive performance overhead, no practical benefit for this use case.
