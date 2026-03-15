# CloakLLM — Comprehensive Codebase Report

**Date:** 2026-03-13
**Version:** 0.2.2
**Author:** Ziv (Zivuch) Chen | **License:** MIT | **GitHub Org:** `cloakllm`

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Layout](#2-repository-layout)
3. [Python SDK (cloakllm-py)](#3-python-sdk-cloakllm-py)
4. [JavaScript SDK (cloakllm-js)](#4-javascript-sdk-cloakllm-js)
5. [MCP Server (cloakllm-mcp)](#5-mcp-server-cloakllm-mcp)
6. [Hub Repository (CloakLLM)](#6-hub-repository-cloakllm)
7. [Website (cloakllm-web)](#7-website-cloakllm-web)
8. [Cross-SDK Comparison](#8-cross-sdk-comparison)
9. [Security Model](#9-security-model)
10. [Known Bugs](#10-known-bugs)
11. [Roadmap](#11-roadmap)

---

## 1. Project Overview

CloakLLM is an open-source PII protection middleware for LLMs. It detects sensitive data in prompts, replaces it with deterministic tokens (e.g., `[EMAIL_0]`), lets the LLM process the sanitized text, and restores original values in the response. All operations are logged in tamper-evident, hash-chained audit files designed for EU AI Act Article 12 compliance.

**Core value proposition:** PII never leaves your infrastructure. The LLM only sees anonymized tokens.

**Published packages:**
- `cloakllm` on PyPI (Python SDK)
- `cloakllm-mcp` on PyPI (MCP server)
- `cloakllm` on npm (JavaScript SDK)

---

## 2. Repository Layout

```
cloakllm/                        # workspace root (not a git repo)
├── CloakLLM/                    # hub repo — README, GUIDE, LICENSE, SECURITY, CONTRIBUTING
├── cloakllm-py/                 # Python SDK (PyPI: cloakllm)
├── cloakllm-js/                 # JavaScript SDK (npm: cloakllm)
├── cloakllm-mcp/                # MCP server (PyPI: cloakllm-mcp)
├── cloakllm-web/                # Next.js documentation site (Vercel)
├── logos/                       # branding assets (SVG/PNG, dark/light/transparent/favicon)
├── testbackup/                  # end-to-end verification scripts (not in any repo)
├── CLAUDE.md                    # project instructions for Claude Code
├── PLAN.md                      # v0.3.x design discussion
├── TODO.md                      # action items
└── BUG_REPORT.md                # 22 tracked bugs across all SDKs
```

Each subdirectory is its own git repo on `github.com/cloakllm/<name>`, all on `main` branch. CI/CD via GitHub Actions: `ci.yml` (test on push/PR) and `publish.yml` (publish on `v*` tag).

---

## 3. Python SDK (cloakllm-py)

### 3.1 Architecture

```
Shield (shield.py, 448 lines)
├── DetectionEngine (detector.py, 276 lines)
│   ├── Pass 1: Regex (built-in + custom patterns)
│   ├── Pass 2: spaCy NER (PERSON, ORG, GPE, LOC, FAC, NORP)
│   └── Pass 3: Ollama LLM (optional, semantic detection)
├── Tokenizer (tokenizer.py, 202 lines)
│   └── TokenMap (forward/reverse mapping, entity_details, HMAC hashing)
├── AuditLogger (audit.py, 252 lines)
│   └── Hash-chained JSONL audit logs
└── ShieldConfig (config.py, 107 lines)
```

**Flow:**
1. `shield.sanitize(text)` → DetectionEngine finds PII across 3 passes
2. Tokenizer replaces PII with `[CATEGORY_N]` tokens, stores mapping in TokenMap
3. AuditLogger records tamper-evident entry (no PII stored)
4. Returns `(sanitized_text, token_map)`
5. LLM processes sanitized text (middleware injects system hint about placeholders)
6. `shield.desanitize(response, token_map)` restores original values
7. Audit entry logged for desanitization

### 3.2 Three-Pass Detection Pipeline

#### Pass 1: Regex (detector.py:220-240)

Fastest pass. High precision for structured data. Built-in patterns:

| Pattern | Regex | Confidence |
|---------|-------|------------|
| EMAIL | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | 0.95 |
| SSN | `(?!000\|666\|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}` | 0.95 |
| CREDIT_CARD | Visa/MC/Amex/Discover BIN patterns | 0.95 |
| PHONE | International + US formats (7-digit minimum filter) | 0.95 |
| IP_ADDRESS | IPv4 octets 0-255 | 0.95 |
| API_KEY | `sk/pk/api/key/token/secret/bearer` prefix + 20+ chars | 0.95 |
| AWS_KEY | `AKIA/ASIA` + 16 alphanumerics | 0.95 |
| JWT | Three base64 segments separated by dots | 0.95 |
| IBAN | Country code + check digits + account number | 0.95 |

**Custom patterns** registered via `ShieldConfig(custom_patterns=[("NAME", "regex")])`. User patterns take priority over built-ins (prepended, line 148). Each custom pattern is tested for ReDoS vulnerability via a 50ms timeout test with pathological input (detector.py:113-119).

**Overlap detection:** Maintains `covered_spans` list to prevent the same text region from being matched twice.

#### Pass 2: spaCy NER (detector.py:242-264)

- Model: `en_core_web_sm` (configurable, lazy-loaded, auto-downloads)
- Entity types: PERSON, ORG, GPE, LOC, FAC, NORP (configurable via `ner_entity_types`)
- Skips spans already covered by regex
- Filters entities shorter than 2 characters
- Confidence: 0.85 for all NER matches
- **Model whitelist** (detector.py:18-26): Only approved spaCy models allowed (supply-chain attack prevention)

#### Pass 3: Ollama LLM (llm_detector.py, 215 lines, optional)

- Enabled via `ShieldConfig(llm_detection=True)`
- Local Ollama instance at `http://localhost:11434` (configurable)
- Default model: `llama3.2`
- Detects semantic/contextual PII: ADDRESS, DATE_OF_BIRTH, MEDICAL, FINANCIAL, NATIONAL_ID, BIOMETRIC, USERNAME, PASSWORD, VEHICLE
- Excluded categories (already handled): EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS, API_KEY, IBAN, JWT, ORG, GPE, PERSON
- Custom categories via `custom_llm_categories` (list of `(name, description)` tuples)
- LRU cache (max 1024 entries) prevents redundant Ollama queries
- Availability check: pings `/api/tags` once, caches result permanently
- Confidence: configurable (default 0.85)
- System prompt instructs Ollama to return `{"entities": [{"value": "exact text", "category": "CATEGORY"}]}`

### 3.3 Tokenization (tokenizer.py)

**Token format:** `[CATEGORY_N]` (e.g., `[EMAIL_0]`, `[PERSON_1]`)
- Sequential counter per category within a TokenMap
- Same original text always produces same token within a session (deterministic)
- Different TokenMap instances have independent counters

**Redaction mode:** `[CATEGORY_REDACTED]` (irreversible, no token map storage)

**Injection prevention — fullwidth bracket escaping:**
- Before tokenization: existing `[TOKEN_LIKE]` patterns in input are escaped to fullwidth Unicode brackets (`\uFF3B`, `\uFF3D`)
- After desanitization: fullwidth brackets restored to ASCII
- Prevents attacker-injected fake tokens from leaking real PII

**Desanitization:**
- Case-insensitive replacement (handles LLMs lowercasing tokens)
- Longest-first sorting prevents partial matches
- Lambda-based replacement prevents backreference injection (`$1`, `$$`, `$&`)
- Fullwidth brackets unescaped after replacement

### 3.4 TokenMap (tokenizer.py:28-131)

```python
@dataclass
class TokenMap:
    forward: dict[str, str]          # original_value → token
    reverse: dict[str, str]          # token → original_value
    _counters: dict[str, int]        # CATEGORY → next_index
    detections: list[Detection]      # All detected entities
    mode: str                        # "tokenize" or "redact"
    entity_hashing: bool
    entity_hash_key: str
```

**Properties:**
- `entity_count` — `len(forward)` in tokenize mode, 0 in redact
- `categories` — counts entities per category from detections list
- `entity_details` — per-entity metadata array (PII-safe): category, start, end, length, confidence, source, token, optional `entity_hash`
- `to_summary()` / `to_report()` — audit-safe representations

**Entity hashing (HMAC-SHA256):**
- Enabled via `ShieldConfig(entity_hashing=True, entity_hash_key="...")`
- Formula: `HMAC-SHA256(key, "CATEGORY:normalized_text")`
- Normalized = `original.strip().lower()`
- Deterministic: same (category, text, key) → same hash across sessions/SDKs
- Auto-generated 64-char hex key if not provided
- Enables cross-request/document entity correlation without storing PII

### 3.5 Audit Logging (audit.py)

**Format:** JSONL files at `{log_dir}/audit_YYYY-MM-DD.jsonl` (one per UTC day, append-only)

**Entry fields:**
| Field | Type | Description |
|-------|------|-------------|
| seq | int | Sequential counter |
| event_id | str | UUID4 |
| timestamp | str | ISO 8601 UTC |
| event_type | str | sanitize, desanitize, sanitize_batch, desanitize_batch |
| model | str? | LLM model name |
| provider | str? | anthropic, openai, etc. |
| entity_count | int | Entities detected |
| categories | dict | `{"EMAIL": 2, "SSN": 1}` |
| tokens_used | list | `["[EMAIL_0]", "[SSN_0]"]` |
| prompt_hash | str | SHA-256 of original text |
| sanitized_hash | str | SHA-256 of sanitized text |
| latency_ms | float | Total elapsed time |
| mode | str? | tokenize or redact |
| entity_details | list | Per-entity metadata (no PII) |
| timing | dict | Per-pass breakdown (regex_ms, ner_ms, llm_ms, tokenization_ms) |
| prev_hash | str | Previous entry's entry_hash |
| entry_hash | str | SHA-256 of this entry (including prev_hash) |
| metadata | dict | Custom context (user_id, session_id, etc.) |

**Hash chaining:**
- Genesis hash: `"0" * 64`
- Deterministic serialization: `json.dumps(data, sort_keys=True, separators=(",", ":"))`
- Each entry_hash = SHA-256 of all fields including prev_hash
- Tamper detection: modifying any field invalidates entry_hash and breaks chain

**Verification:** `shield.verify_audit()` or CLI `cloakllm verify <dir>` — O(n) chain walk checking each entry_hash matches recomputed hash.

**Statistics:** `shield.audit_stats()` — total events, entities detected, category breakdown, models used, log files.

### 3.6 Configuration (config.py)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| spacy_model | str | "en_core_web_sm" | spaCy model name |
| ner_entity_types | set | PERSON, ORG, GPE, LOC, FAC, NORP | spaCy entity types to detect |
| detect_emails | bool | True | Enable EMAIL regex |
| detect_phones | bool | True | Enable PHONE regex |
| detect_ssns | bool | True | Enable SSN regex |
| detect_credit_cards | bool | True | Enable CREDIT_CARD regex |
| detect_api_keys | bool | True | Enable API_KEY regex |
| detect_ip_addresses | bool | True | Enable IP_ADDRESS regex |
| detect_iban | bool | True | Enable IBAN regex |
| custom_patterns | list | [] | `[(name, regex)]` pairs |
| custom_llm_categories | list | [] | `[(name, description)]` pairs |
| llm_detection | bool | False | Enable Ollama LLM pass |
| llm_model | str | "llama3.2" | Ollama model name |
| llm_ollama_url | str | "http://localhost:11434" | Ollama endpoint |
| llm_timeout | float | 10.0 | Ollama timeout (seconds) |
| llm_confidence | float | 0.85 | LLM detection confidence |
| mode | str | "tokenize" | "tokenize" or "redact" |
| entity_hashing | bool | False | Enable HMAC-SHA256 per entity |
| entity_hash_key | str | "" | HMAC key (auto-generated if empty) |
| audit_enabled | bool | True | Enable audit logging |
| log_dir | Path | ./cloakllm_audit | Audit log directory |
| skip_models | list | [] | Model prefixes to skip |

All fields support environment variable overrides (e.g., `CLOAKLLM_LLM_DETECTION`, `CLOAKLLM_LOG_DIR`).

### 3.7 Middleware Integrations

#### LiteLLM (integrations/litellm_middleware.py, 275 lines)

```python
import cloakllm
cloakllm.enable(config=ShieldConfig(...))   # Patches litellm.completion + acompletion
# ... use litellm normally ...
cloakllm.disable()
```

- Monkey-patches `litellm.completion` and `litellm.acompletion`
- Sanitizes all messages, injects system hint about placeholders
- Stores token_map per call (UUID key) in thread-safe dict
- Desanitizes response after LLM call

#### OpenAI SDK (integrations/openai_middleware.py, 364 lines)

```python
from cloakllm import enable_openai, disable_openai
client = OpenAI()
enable_openai(client, config=ShieldConfig(...))
# ... use client normally ...
disable_openai(client)
```

- Patches `client.chat.completions.create`
- Supports **sync**, **async**, and **streaming**
- Streaming: buffers all chunks, desanitizes on `finish_reason`, yields final chunk
- Multiple clients supported independently (keyed by `id(client)`)

**System hint** (injected when PII is found):
> "This conversation contains placeholders like [PERSON_0], [EMAIL_0], [ORG_0], etc. Treat each placeholder as if it were the real value. Use them exactly as-is in your response."

### 3.8 CLI

```bash
python -m cloakllm scan "Text with PII"    # Detect PII, show analysis
python -m cloakllm scan -                  # Read from stdin
python -m cloakllm verify ./cloakllm_audit # Verify audit chain integrity
python -m cloakllm stats ./cloakllm_audit  # Audit statistics
```

### 3.9 Metrics & Timing

```python
shield.metrics()       # Accumulated performance stats
shield.reset_metrics() # Clear accumulators
```

Returns:
```python
{
    "calls": {"sanitize": 10, "desanitize": 10, ...},
    "total_ms": 1234.56,
    "avg_ms": 100.0,
    "detection": {"regex_ms": 50.0, "ner_ms": 600.0, "llm_ms": 0.0},
    "tokenization_ms": 30.5,
    "entities_detected": 45,
    "categories": {"EMAIL": 20, "SSN": 15, ...},
}
```

Per-call timing breakdown also stored in each audit entry.

### 3.10 Batch Processing

```python
sanitized_texts, token_map = shield.sanitize_batch(
    texts=["Email john@acme.com", "SSN 123-45-6789"],
    model="claude-3", provider="anthropic"
)
restored = shield.desanitize_batch(sanitized_texts, token_map)
```

- Processes multiple texts with **shared token map** (same entity across texts → same token)
- Single audit entry for entire batch (event_type: `sanitize_batch`)
- `entity_details` include `text_index` field for per-text correlation

### 3.11 Tests

- **136 tests** in `tests/test_shield.py` (1215+ lines)
- Covers: detection, tokenization, audit chaining, middleware, redaction, batch ops, entity hashing, security regressions, custom patterns, metrics
- Run: `pytest tests/ -v`
- Requires: `python -m spacy download en_core_web_sm`

---

## 4. JavaScript SDK (cloakllm-js)

### 4.1 Architecture

Mirrors the Python SDK with 6 core classes:

```
Shield (src/shield.js, 391 lines)
├── DetectionEngine (src/detector.js, 171 lines)
│   ├── Pass 1: Regex (9 built-in patterns)
│   └── Pass 2: Ollama LLM (optional, via curl)
├── Tokenizer (src/tokenizer.js, 199 lines)
│   └── TokenMap (forward/reverse Map, entity_details, HMAC hashing)
├── AuditLogger (src/audit.js, 231 lines)
│   └── Hash-chained JSONL audit logs
├── ShieldConfig (src/config.js, 59 lines)
└── LlmDetector (src/llm-detector.js, 206 lines)
```

**Key difference from Python:** No spaCy NER pass. Detection is 2-pass (regex + optional Ollama LLM). The LLM pass includes PERSON, ORG, GPE in its category set to compensate.

### 4.2 Detection Pipeline

#### Pass 1: Regex (detector.js:23-60)

Same 9 patterns as Python (EMAIL, SSN, CREDIT_CARD, PHONE, IP_ADDRESS, API_KEY, AWS_KEY, JWT, IBAN) with identical regexes. Custom patterns take priority (prepended). Coverage spans prevent overlapping matches. All regex detections have confidence 0.95.

#### Pass 2: Ollama LLM (llm-detector.js, optional)

- Uses `child_process.execFileSync` + `curl` to call Ollama (sync, no async needed)
- Includes PERSON, ORG, GPE in LLM categories (compensating for no spaCy)
- Same excluded categories as Python (EMAIL, PHONE, SSN, etc.)
- Cache: `Map<string, Array>` (unbounded, session-scoped)
- Custom categories supported
- Temperature 0.0 for deterministic output

### 4.3 Tokenization & TokenMap

Identical mechanics to Python:
- Format: `[CATEGORY_N]` / `[CATEGORY_REDACTED]`
- Fullwidth bracket escaping for injection prevention
- Lambda-based replacement for backreference injection mitigation
- Case-insensitive desanitization
- HMAC-SHA256 entity hashing with same formula: `HMAC-SHA256(key, "CATEGORY:normalized")`

### 4.4 Audit Logging

Identical to Python:
- JSONL format, hash-chained with SHA-256
- Genesis hash: `'0'.repeat(64)`
- Deterministic serialization with recursive key sorting
- Same entry fields
- `verifyChain()` and `getStats()` methods

### 4.5 Middleware: OpenAI SDK (middleware.js, 298 lines)

```javascript
const { enable, disable } = require('cloakllm');
const client = new OpenAI();
enable(client);
// ... use client normally ...
disable(client);
```

- Patches `client.chat.completions.create`
- Sanitizes all message roles (system/user/assistant)
- Handles array content (vision messages): sanitizes text parts only
- System hint injection when PII found
- **Streaming:** Buffers all chunks, desanitizes on `finish_reason`, yields single final chunk
- **Non-streaming:** Desanitizes all choices
- Model skipping via `skipModels` config
- State: `_shield` (singleton), `_activeMaps` (UUID → TokenMap), `_originalFunctions` (WeakMap), `_patchedClients` (Set)

### 4.6 Middleware: Vercel AI SDK (vercel-middleware.js, 246 lines)

```javascript
const { createCloakLLMMiddleware } = require('cloakllm');
const middleware = createCloakLLMMiddleware({ detectEmails: true });
const model = wrapLanguageModel({ model: openai('gpt-4o'), middleware });
```

Returns a `LanguageModelV3Middleware` with three hooks:

1. **transformParams** — Sanitizes prompt messages, injects system hint, stores TokenMap in WeakMap keyed by new params object
2. **wrapGenerate** — Desanitizes complete response; handles V3 `content: Part[]` and V1 `text: string` formats
3. **wrapStream** — Buffers text-deltas per block ID, desanitizes on text-end event, passes non-text chunks through; uses TransformStream

### 4.7 TypeScript Declarations (index.d.ts, 246 lines)

Full type coverage for all classes, interfaces, and functions. Includes:
- ShieldConfigOptions, ShieldConfig, Detection, EntityDetail, BatchEntityDetail
- TokenMap, Shield (all methods), Timing, DetectorTiming, Metrics
- DetectionEngine, Tokenizer, AuditLogger
- Middleware functions (enable, disable, getShield, isEnabled)
- CloakLLMMiddleware interface, createCloakLLMMiddleware factory

### 4.8 CLI

```bash
npx cloakllm scan "Text with PII"
npx cloakllm verify ./cloakllm_audit
npx cloakllm stats ./cloakllm_audit
```

### 4.9 Tests

- **130 tests** in `test/test_shield.js` (1192 lines) + `test_llm_detector.js` (328 lines) + `test_vercel_middleware.js` (518 lines)
- Node.js native test runner (`node --test`)
- Zero runtime dependencies
- Security regression tests for backreference injection, fake token injection, ReDoS

---

## 5. MCP Server (cloakllm-mcp)

### 5.1 Overview

Exposes the Python SDK as 4 MCP tools for Claude Desktop, Cursor, and other MCP-compatible clients.

**File:** `server.py` (391 lines)
**Framework:** FastMCP (`mcp[cli]>=1.0.0`)
**Dependency:** `cloakllm>=0.2.2`

### 5.2 Tools

#### `sanitize(text, model, provider, metadata, token_map_id, mode, custom_llm_categories, entity_hashing, entity_hash_key)`

Detects and replaces PII with tokens. Returns:
```json
{
  "sanitized": "Contact [EMAIL_0] about [PERSON_0]",
  "token_map_id": "uuid-...",
  "entity_count": 2,
  "categories": {"EMAIL": 1, "PERSON": 1},
  "entity_details": [...]
}
```

#### `sanitize_batch(texts, model, provider, metadata, token_map_id, custom_llm_categories, mode, entity_hashing, entity_hash_key)`

Batch sanitization with shared token map. Same entity across texts → same token.

#### `desanitize(text, token_map_id)`

Restores original values using stored token map.

#### `analyze(text, custom_llm_categories)`

Detection-only (no tokenization). Returns entity list with text, category, start, end, confidence, source.

### 5.3 Session Management

- In-memory token map store: `_TOKEN_MAPS` dict (string ID → `{token_map, created}`)
- TTL: 1 hour (auto-cleanup on access)
- Multi-turn support: pass `token_map_id` to reuse and refresh

### 5.4 Tests

- **24 tests** in `test_server.py`
- Run: `pytest test_server.py`

---

## 6. Hub Repository (CloakLLM)

Central documentation hub containing:

- **README.md** — Project overview, SDK comparison table, install instructions, links
- **GUIDE.md** (1000+ lines) — Comprehensive usage guide covering all features across all SDKs:
  - Installation, Quick Start (7 integration paths)
  - 3-pass architecture explanation
  - Configuration reference
  - Multi-turn conversations, batch processing, metrics
  - Redaction mode, custom patterns, LLM detection, custom categories
  - Entity hashing, audit logs, CLI
- **SECURITY.md** — Vulnerability reporting process
- **CONTRIBUTING.md** — Contribution guidelines
- **LICENSE** — MIT

---

## 7. Website (cloakllm-web)

### 7.1 Tech Stack

- **Framework:** Next.js 15.x (App Router)
- **Documentation:** Fumadocs (MDX-based)
- **UI:** Tailwind CSS, Geist, Lucide icons
- **Deployment:** Vercel CLI (`vercel --prod`)

### 7.2 Structure

```
cloakllm-web/
├── src/app/
│   ├── page.tsx          # Landing page (Hero, Problem, HowItWorks, Features, CodeExamples, Install, Comparison, Footer)
│   └── docs/             # Documentation (Fumadocs)
├── content/docs/
│   ├── index.mdx         # Docs home
│   └── guide.mdx         # Full guide (synced with CloakLLM/GUIDE.md)
├── src/components/
│   ├── landing/          # 8 landing page components
│   └── ui/               # CopyButton, Terminal
└── public/               # demo.gif, logos, favicon
```

### 7.3 Branding Assets (logos/)

- `logo-dark-rounded.{svg,png}` — Dark background variant
- `logo-light.{svg,png}` — Light background variant
- `logo-transparent.{svg,png}` — Transparent background
- `logo-favicon.{svg,png}` — Small favicon
- `social-card.png` — OpenGraph social media card
- `cloakllm-brand-kit.jsx` — React brand kit component

---

## 8. Cross-SDK Comparison

| Feature | Python | JavaScript | MCP |
|---------|--------|------------|-----|
| Regex detection | 9 patterns | 9 patterns (identical) | Via Python SDK |
| spaCy NER | PERSON, ORG, GPE, LOC, FAC, NORP | N/A | Via Python SDK |
| Ollama LLM detection | Via HTTP requests | Via curl + execFileSync | Via Python SDK |
| Custom patterns | Yes (with ReDoS check) | Yes (with ReDoS check) | N/A |
| Custom LLM categories | Yes | Yes | Yes |
| Tokenize mode | `[CATEGORY_N]` | `[CATEGORY_N]` | `[CATEGORY_N]` |
| Redact mode | `[CATEGORY_REDACTED]` | `[CATEGORY_REDACTED]` | `[CATEGORY_REDACTED]` |
| Entity hashing | HMAC-SHA256 | HMAC-SHA256 (identical) | Yes |
| Audit logging | Hash-chained JSONL | Hash-chained JSONL (identical) | Via Python SDK |
| Batch processing | sanitize_batch/desanitize_batch | sanitize_batch/desanitize_batch | sanitize_batch |
| Metrics/timing | Per-pass breakdown | Per-pass breakdown | N/A |
| LiteLLM middleware | Yes | N/A | N/A |
| OpenAI SDK middleware | Sync + async + streaming | Async + streaming | N/A |
| Vercel AI middleware | N/A | Yes (V3 format) | N/A |
| CLI | scan, verify, stats | scan, verify, stats | N/A |
| TypeScript types | N/A | Full declarations (246 lines) | N/A |
| Runtime dependencies | spacy, hmac, hashlib | Zero | cloakllm, mcp |
| Test count | 136 | 130+ | 24 |

---

## 9. Security Model

### 9.1 PII Protection

- PII never reaches the LLM — only `[CATEGORY_N]` tokens are sent
- No PII stored in audit logs — only SHA-256 hashes of original/sanitized text
- Entity details contain metadata (category, offsets, confidence) but never original text
- Entity hashing uses HMAC-SHA256 for correlation without storing plaintext

### 9.2 Token Injection Prevention

- **Fullwidth bracket escaping:** Existing `[TOKEN_LIKE]` patterns in user input are converted to fullwidth Unicode brackets before tokenization, preventing an attacker from planting fake tokens that map to other users' PII
- **Backreference injection:** Desanitization uses callback-based replacement (not string-based) to prevent `$1`, `$$`, `$&`, `` $` `` injection in original PII values

### 9.3 ReDoS Prevention

- Custom patterns tested for catastrophic backtracking (25 'a's + '!' in <50ms)
- Dangerous patterns rejected with a warning

### 9.4 spaCy Model Whitelist (Python only)

- Only approved model names allowed (prevents supply-chain attacks via malicious spaCy models)
- Unrecognized models fall back to blank NER

### 9.5 Audit Chain Integrity

- SHA-256 hash chain with genesis hash `"0" * 64`
- Modifying any field in any entry breaks the chain
- Verifiable via `shield.verify_audit()` or CLI

---

## 10. Known Bugs

22 bugs tracked in `BUG_REPORT.md` (dated 2026-03-10, v0.2.1):

### High Severity (2)

| ID | SDK | Bug |
|----|-----|-----|
| P1 | Python | Multi-choice desanitization fails when `n>1` — token map popped on first choice, rest leak tokens |
| J1 | JS | Vercel middleware WeakMap lookup silently fails if SDK copies params between hooks |

### Medium Severity (13)

| ID | SDK | Bug |
|----|-----|-----|
| P2 | Python | Thread-safety of `Shield._metrics` — concurrent mutation without locking |
| P3 | Python | `token_map.detections` accumulates across multi-turn — stale offsets |
| P4 | Python | Metrics use cumulative `token_map.categories` instead of delta |
| P5 | Python | `LlmDetector._cache` unbounded growth — memory leak |
| J2 | JS | Multi-choice desanitization fails when `n>1` (same as P1) |
| J3 | JS | Second `enable()` silently ignores new config |
| J4 | JS | Null token maps stored for every non-PII call |
| J5 | JS | `_checkAvailable` never validates HTTP status code |
| J6 | JS | Unix-specific `/dev/null` in curl args fails on Windows |
| J7 | JS | `.sort()` mutates cached entities array |
| M1 | MCP | `provider` and `metadata` params silently dropped |
| M2 | MCP | `sanitize_batch` missing `mode`/`entity_hashing` support |
| M3 | MCP | Category counting inconsistent between modes |

### Low Severity (7)

| ID | SDK | Bug |
|----|-----|-----|
| P6 | Python | Audit chain recovery fails on empty last file |
| J8 | JS | PHONE filter doesn't strip `+` prefix |
| J9 | JS | `_patchedClients` Set prevents garbage collection |
| M4 | MCP | `metadata` is `str` but Shield expects `dict` |
| M5 | MCP | Docstring says 3 tools, server has 4 |
| M6 | MCP | `sanitize_batch` missing `entity_details` in response |
| M7 | MCP | `desanitize` always uses global `_shield` |

---

## 11. Roadmap

From `PLAN.md` — v0.3.x design discussion:

| Phase | Feature | Status |
|-------|---------|--------|
| Phase 1 | Detection benchmarks (precision/recall per category) | Planned |
| Phase 2 | Per-entity HMAC hashing | Completed (v0.2.1) |
| Phase 3 | Ed25519 cryptographic attestation for audit entries | Planned |
| Phase 4 | Normalized token standard (cross-vendor interoperability) | Planned |

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | 2026-02-27 | Initial release |
| 0.1.1 | 2026-03-01 | LLM detection, Vercel middleware, MCP server |
| 0.1.2 | 2026-03-01 | Fixed `__version__` mismatch |
| 0.1.3 | 2026-03-02 | Custom patterns priority |
| 0.1.4 | 2026-03-04 | Async litellm, MCP multi-turn, JS streaming desanitization |
| 0.1.5 | 2026-03-04 | Python OpenAI SDK middleware |
| 0.1.6 | 2026-03-04 | Redaction mode |
| 0.1.7 | 2026-03-06 | Entity details metadata |
| 0.1.8 | 2026-03-07 | Batch processing API |
| 0.1.9 | 2026-03-08 | Per-pass timing, shield.metrics() |
| 0.2.0 | 2026-03-09 | Custom LLM detection categories |
| 0.2.1 | 2026-03-10 | Per-entity HMAC hashing |
| 0.2.2 | 2026-03-10 | Bug fix patch (20 fixes, 2 PII leakage security fixes) |

---

## 12. Recommendations

### 12.1 Fix PII Leakage Bugs Immediately (P1/J2, J1)

These are **security defects** in a security product. They should block any other work.

- **P1/J2 (multi-choice desanitization):** Both SDKs delete the token map on the first `n>1` choice. Fix: retrieve without deleting, then delete after the loop. Simple 2-line fix in each SDK.
- **J1 (Vercel WeakMap fragility):** The entire desanitization path silently fails if the Vercel SDK spreads params. Fix: replace the WeakMap with a `Map` keyed by a UUID symbol attached to the params object, or use a closure-based approach that doesn't depend on object identity.

These should be a **v0.2.3 patch release** with nothing else in it.

### 12.2 Address the Multi-Turn Accumulation Bug (P3/P4)

`token_map.detections` grows unboundedly across turns. This means:
- `categories` returns cumulative counts (not current-turn)
- `entity_details` contains stale offsets from prior texts
- Metrics accumulate inflated numbers

Fix: clear `detections` at the start of each `tokenize()` call, or track a per-turn detection list separate from the cumulative forward/reverse maps. This is a design issue that affects audit correctness.

### 12.3 Add Bounded Caches

Both SDKs have unbounded LLM detector caches that will leak memory in long-running services. The Python side has an LRU cache (max 1024) but the JS side uses a plain `Map` with no eviction. Recommendation:
- JS: implement a simple LRU with a size cap (even 256 entries would suffice)
- Python: verify the LRU is actually limiting (the code at `llm_detector.py:53` suggests it might be a plain dict, not `functools.lru_cache`)

### 12.4 Ship a Confidence Calibration / Benchmark Suite

Right now all regex detections return 0.95 and all NER detections return 0.85. These are hardcoded, not empirically calibrated. For a product claiming compliance readiness, this is a gap.

Recommendation: build the Phase 1 benchmark from PLAN.md — a labeled dataset with precision/recall per category. This would:
- Validate that the regex patterns don't produce excessive false positives (PHONE and API_KEY are the riskiest)
- Give users real confidence scores instead of constants
- Provide a regression test for detection quality across versions

### 12.5 Consolidate the Streaming Strategy

Both SDKs buffer the entire streamed response and emit it as a single chunk at the end. This **defeats the purpose of streaming** — users see nothing until the full response is ready.

Recommendation: implement incremental desanitization. Since tokens have a known format (`[CATEGORY_N]`), you can:
- Stream text through until you see `[`
- Buffer only the potential token
- If it resolves to a known token, emit the original value
- If it doesn't match, emit the buffered text as-is

This is a meaningful UX improvement that would differentiate CloakLLM from alternatives.

### 12.6 Make the MCP Server Feature-Complete

The MCP server is missing several features that both SDKs support:
- `sanitize_batch` has no `mode`, `entity_hashing`, or `entity_details` support
- `provider` and `metadata` are accepted but silently dropped
- `metadata` is typed as `str` but should be parsed as JSON

These aren't just bugs — they make the MCP server a second-class citizen. If a Claude Desktop user reads the docs and tries to use redact mode via MCP, it silently doesn't work.

### 12.7 Harden the JS LLM Detector for Cross-Platform

The JS LLM detector shells out to `curl` with `/dev/null` — this fails on Windows. Two options:
- Replace `curl` with Node.js `http`/`https` module (zero deps, works everywhere)
- At minimum, use `process.platform === 'win32' ? 'NUL' : '/dev/null'`

The curl approach also doesn't validate HTTP status codes — Ollama returning 500 is treated as "available."

### 12.8 Improve Thread-Safety (Python)

`Shield._metrics` has a lock, but `_accumulate_metrics` still has a TOCTOU race on nested dict updates. For production use with concurrent requests (e.g., FastAPI), this needs either:
- A proper `threading.Lock` around the entire accumulation block (not just individual field updates)
- Or switch to `collections.Counter` which is more atomic for the category counting

### 12.9 Add Integration Tests for Middleware Round-Trips

The test suites are thorough for unit tests, but there are no integration tests that exercise the full middleware path with a real (or mocked) OpenAI/LiteLLM client doing `n>1` choices, streaming, or multi-turn conversations. The P1/J2 bug (multi-choice PII leakage) existed because this path was never tested end-to-end.

Recommendation: add parametric tests for:
- `n=1`, `n=3` choices (non-streaming and streaming)
- Multi-turn with shared token map
- Mixed PII / no-PII messages in same conversation
- Error paths (API timeout, malformed response)

### 12.10 Version the Website

`cloakllm-web/package.json` is still at `0.1.9` while everything else is at `0.2.2`. The CLAUDE.md checklist says to update the website, but this was missed. Keep it in sync or decouple website versioning entirely.

### Priority Order

| Priority | Action | Effort |
|----------|--------|--------|
| **Now** | Fix P1/J2/J1 PII leakage → v0.2.3 patch | Small (1-2 hours) |
| **Now** | Fix P3/P4 multi-turn accumulation | Medium |
| **Soon** | MCP feature parity (M1-M6) | Medium |
| **Soon** | JS LLM detector cross-platform + status validation | Small |
| **Soon** | Bounded JS cache | Small |
| **Next** | Incremental streaming desanitization | Large |
| **Next** | Integration tests for middleware round-trips | Medium |
| **Later** | Benchmark suite / confidence calibration | Large |
| **Later** | Thread-safety audit | Small |

The first three items should be tackled before any feature work. A security product with known PII leakage bugs and silently broken features undermines trust.

### 12.11 Cryptographic Hardening

The current cryptography layer has fundamental gaps that limit CloakLLM's compliance and trust claims.

#### 12.11.1 Hash Chain is Tamper-Evident, Not Tamper-Proof

The SHA-256 audit chain detects modifications to individual entries, but **anyone with file access can rewrite the entire chain from genesis**. There are no digital signatures — `verify_chain()` only proves internal consistency, not authorship. An attacker or rogue admin can delete all logs, fabricate new entries, recompute hashes, and pass verification.

**Recommendation:** Implement Ed25519 digital signatures (as outlined in PLAN.md Phase 3). Each audit entry should be signed by a deployment keypair. Third-party verifiers can validate signatures without needing the full chain. This transforms the audit log from "internally consistent" to "cryptographically attributable."

#### 12.11.2 No Key Management

The HMAC entity hash key is stored in plaintext in ShieldConfig — either auto-generated (ephemeral, lost on restart) or user-provided (hardcoded in source). There is no:
- Key rotation strategy (what happens when a key is compromised?)
- Key derivation from a master secret (KDF)
- Secure storage guidance (env vars, vaults, HSMs)
- Key lifecycle documentation

**Recommendation:** Add key management utilities:
- `Shield.rotate_key(new_key)` that re-hashes existing entity mappings
- Support for KDF-based key derivation (HKDF-SHA256 from a master key + salt)
- Documentation recommending environment variables or secret managers over hardcoded keys
- Warn on startup if entity_hashing is enabled with the auto-generated key (ephemeral = hashes are useless across restarts)

#### 12.11.3 No Trusted Timestamping

Audit entries use `datetime.now(timezone.utc)` — the local system clock. A compromised or misconfigured system can backdate entries, undermining the temporal integrity of the audit trail. For EU AI Act compliance, provable timestamps matter.

**Recommendation (lightweight):** Add an optional `timestamp_authority` config that counter-signs entry hashes via RFC 3161 or a simpler nonce-based scheme. For most users, system time is sufficient — but the option should exist for regulated environments.

#### 12.11.4 Sanitization Certificates (PLAN.md Phase 3)

The PLAN.md design for signed sanitization certificates (compact JWTs with input hash, output hash, entity count, detection passes used) is the right approach for the "public workloads" use case. This should include:
- Ed25519 keypair generation on first run (`shield.generate_keypair()`)
- Compact certificate format (JWT or CBOR)
- Standalone verifier package (`cloakllm-verify`) that validates certificates without the full SDK
- Certificate chaining to a deployment root key for organizational trust

#### 12.11.5 Merkle Trees for Batch Attestation

Current batch processing creates a single audit entry with concatenated hashes. For large batches, a Merkle tree would enable:
- O(log n) proof that a specific text was part of a batch
- Partial verification without revealing other texts in the batch
- Compact batch certificates (single root hash)

This becomes important when batches contain thousands of texts (e.g., document pipelines).

### 12.12 Multi-Language PII Detection

Both SDKs are English-only by default. For international adoption:

- **Regex patterns** are mostly language-agnostic (EMAIL, SSN, IBAN) but PHONE patterns assume US formatting
- **spaCy NER** (Python) supports 20+ languages via model swaps (`en_core_web_sm` → `de_core_news_sm`, etc.) but this isn't documented
- **Ollama LLM detection** can handle any language the model supports, but prompt templates are English-only

**Recommendation:**
- Document spaCy model selection for non-English languages in GUIDE.md
- Add locale-aware regex patterns (e.g., European phone numbers, national ID formats)
- Provide Ollama prompt templates for common languages (German, French, Spanish, Japanese)
- Add a `locale` config option to ShieldConfig that selects appropriate regex/NER defaults

### 12.13 JS NER Feature Parity

Python has spaCy NER as a built-in second detection pass. JavaScript has no equivalent — without Ollama, the JS SDK is regex-only for all entity types including PERSON, ORG, and GPE.

This is a significant detection gap. A user running the JS SDK without Ollama will miss most name/organization entities.

**Recommendation:**
- Evaluate lightweight JS NER options: `compromise` (npm, zero deps, ~200KB), `wink-ner` (rule-based), or ONNX-based models
- If no suitable library exists, document the gap prominently and recommend Ollama as mandatory for production JS deployments
- Consider a `warnOnPartialDetection` config that alerts when NER/LLM passes are unavailable

### 12.14 Context-Based PII Leakage Validation

Even after tokenization, surrounding context can leak PII. For example: "The CEO of [ORG_0], who lives at [ADDRESS_0] in the same building as [PERSON_1]" — the relationship graph itself may be identifying.

**Recommendation:**
- Research k-anonymity validation: can the sanitized text be de-anonymized by cross-referencing context?
- Add an optional `context_analysis` post-processing step that flags high-risk sanitized outputs
- This is a research-heavy effort — start with a literature review and threat model before implementing

### 12.15 Stale Documentation

- **CloakLLM/README.md line 95** says "three tools" but MCP now exposes 4 tools (sanitize_batch added in v0.1.8)
- **BUG_REPORT.md** was written against v0.2.1; ~15 of 22 bugs were fixed in v0.2.2. The report should be revised to reflect current state
