# CloakLLM Usage Guide

PII protection middleware for LLMs — detect, tokenize, and audit before prompts leave your infrastructure.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Python — OpenAI SDK](#python--openai-sdk)
  - [Python — LiteLLM](#python--litellm)
  - [Python — Standalone Shield](#python--standalone-shield)
  - [JavaScript — OpenAI SDK](#javascript--openai-sdk)
  - [JavaScript — Vercel AI SDK](#javascript--vercel-ai-sdk)
  - [JavaScript — Standalone Shield](#javascript--standalone-shield)
  - [MCP — Claude Desktop](#mcp--claude-desktop)
- [How It Works](#how-it-works)
- [Configuration Reference](#configuration-reference)
  - [Python ShieldConfig](#python-shieldconfig)
  - [JavaScript ShieldConfig](#javascript-shieldconfig)
  - [Environment Variables](#environment-variables)
- [Multi-Turn Conversations](#multi-turn-conversations)
- [Batch Processing](#batch-processing)
- [Performance Metrics](#performance-metrics)
- [Redaction Mode](#redaction-mode)
- [Custom Patterns](#custom-patterns)
- [LLM-Powered Detection (Ollama)](#llm-powered-detection-ollama)
- [Custom LLM Categories](#custom-llm-categories)
- [Multi-Language Detection](#multi-language-detection)
- [Entity Hashing](#entity-hashing)
- [Incremental Streaming](#incremental-streaming)
- [Cryptographic Attestation](#cryptographic-attestation)
- [Entity Detection Reference](#entity-detection-reference)
- [CLI](#cli)
- [Audit Logs](#audit-logs)
- [Security](#security)
- [Disabling / Re-enabling](#disabling--re-enabling)

---

## Installation

### Python

```bash
pip install cloakllm
python -m spacy download en_core_web_sm
```

For LiteLLM middleware integration:

```bash
pip install cloakllm[litellm]
```

Requires Python 3.10+.

### JavaScript

```bash
npm install cloakllm
```

Zero runtime dependencies. Requires Node.js 18+.

### MCP Server

```bash
pip install cloakllm-mcp
```

Depends on `cloakllm` (the Python SDK).

---

## Quick Start

### Python — OpenAI SDK

One line to wrap your OpenAI client:

```python
from cloakllm import enable_openai, ShieldConfig
from openai import OpenAI

client = OpenAI()
enable_openai(
    client,
    config=ShieldConfig(
        skip_models=["ollama/"],
        log_dir="./audit_logs",
    ),
)

# Use OpenAI normally — CloakLLM works transparently
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {
            "role": "user",
            "content": (
                "Help me write a follow-up email to Sarah Johnson "
                "(sarah.j@techcorp.io) about the Q3 security audit. "
                "Her direct line is +1-555-0142."
            ),
        }
    ],
)

# Response is automatically desanitized — original names/emails restored
print(response.choices[0].message.content)

# Disable when done
from cloakllm import disable_openai
disable_openai(client)
```

### Python — LiteLLM

One line to protect all your LLM calls:

```python
import cloakllm
from cloakllm import ShieldConfig

cloakllm.enable(
    config=ShieldConfig(
        skip_models=["ollama/", "huggingface/"],
        log_dir="./audit_logs",
    )
)

# Use LiteLLM normally — CloakLLM works transparently
import litellm

response = litellm.completion(
    model="anthropic/claude-sonnet-4-20250514",
    messages=[
        {
            "role": "user",
            "content": (
                "Help me write a follow-up email to Sarah Johnson "
                "(sarah.j@techcorp.io) about the Q3 security audit. "
                "Her direct line is +1-555-0142. "
                "Reference ticket SEC-2024-0891."
            ),
        }
    ],
)

# Response is automatically desanitized — original names/emails restored
print(response.choices[0].message.content)

# Disable when done
cloakllm.disable()
```

### Python — Standalone Shield

Use the Shield directly without any LLM framework:

```python
from cloakllm import Shield

shield = Shield()

# Sanitize
prompt = (
    "Please draft an email to John Smith (john.smith@acme.com) about the "
    "Project Falcon deployment. His SSN is 123-45-6789 and the server is "
    "at 192.168.1.100. Use API key sk-abc123def456ghi789jkl012mno345pqr."
)
sanitized, token_map = shield.sanitize(prompt, model="claude-sonnet-4-20250514")
# sanitized → "Please draft an email to [PERSON_0] ([EMAIL_0]) about the ..."

# Desanitize an LLM response
llm_response = (
    "I've drafted the email to [PERSON_0] at [EMAIL_0] regarding "
    "Project Falcon. I noticed the server [IP_ADDRESS_0] may need "
    "additional security configuration before deployment."
)
restored = shield.desanitize(llm_response, token_map)
# restored → "I've drafted the email to John Smith at john.smith@acme.com ..."

# Analyze without modifying
analysis = shield.analyze("Call me at +972-50-123-4567 or email sarah@example.org")
# → { "entity_count": 2, "entities": [...] }

# Per-entity metadata (no original text — PII-safe)
token_map.entity_details
# [{"category": "PERSON", "start": 0, "end": 10, ...}, ...]

# Full report for dashboards
token_map.to_report()
# {"entity_count": 5, "categories": {...}, "tokens": [...], "mode": "tokenize", "entity_details": [...]}
```

### JavaScript — OpenAI SDK

One line to wrap your OpenAI client:

```javascript
const { enable } = require('cloakllm');
const OpenAI = require('openai');

const client = new OpenAI();
enable(client);

const response = await client.chat.completions.create({
  model: 'gpt-4o-mini',
  messages: [
    {
      role: 'user',
      content:
        'Write a meeting reminder for sarah.j@techcorp.io ' +
        'about the Q3 security audit. Call +1-555-0142 if needed.',
    },
  ],
});

// PII automatically restored in the response
console.log(response.choices[0].message.content);
```

### JavaScript — Vercel AI SDK

Use as language model middleware:

```javascript
const { createCloakLLMMiddleware } = require('cloakllm');
const { generateText, streamText, wrapLanguageModel } = require('ai');
const { openai } = require('@ai-sdk/openai');

const middleware = createCloakLLMMiddleware({
  logDir: './example_audit',
  auditEnabled: true,
});

const model = wrapLanguageModel({
  model: openai('gpt-4o-mini'),
  middleware,
});

// Non-streaming
const { text } = await generateText({
  model,
  prompt: 'Write a reminder for sarah.j@techcorp.io about the Q3 audit.',
});

// Streaming
const result = streamText({
  model,
  prompt: 'Draft an email to sarah.j@techcorp.io about Project Falcon.',
});

for await (const chunk of result.textStream) {
  process.stdout.write(chunk);
}
```

### JavaScript — Standalone Shield

Use the Shield directly without any LLM framework:

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const config = new ShieldConfig({
  logDir: './example_audit',
  auditEnabled: true,
});
const shield = new Shield(config);

const text = `
  Name: Sarah Johnson
  Email: sarah.j@techcorp.io
  SSN: 123-45-6789
  Phone: +1-555-0142
  Credit Card: 4111111111111111
  Server: 192.168.1.100
`;

// Sanitize
const [sanitized, tokenMap] = shield.sanitize(text);

// Desanitize an LLM response
const llmResponse = `I've processed the customer record for [EMAIL_0].
Their SSN ([SSN_0]) has been verified. I'll send a confirmation to [PHONE_0].`;
const restored = shield.desanitize(llmResponse, tokenMap);

// Verify audit chain
const { valid, errors } = shield.verifyAudit();
```

### MCP — Claude Desktop

Add CloakLLM to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cloakllm": {
      "command": "python",
      "args": ["/path/to/cloakllm-mcp/server.py"],
      "env": {
        "CLOAKLLM_LOG_DIR": "./cloakllm_audit",
        "CLOAKLLM_LLM_DETECTION": "false"
      }
    }
  }
}
```

Or using `uvx`:

```json
{
  "mcpServers": {
    "cloakllm": {
      "command": "uvx",
      "args": ["mcp", "run", "/path/to/cloakllm-mcp/server.py"]
    }
  }
}
```

The MCP server exposes 6 tools:

**`sanitize`** — Detect and cloak PII, returns sanitized text + token map ID.

```json
// Tool call
{ "text": "Email john@acme.com about the meeting with Sarah Johnson", "model": "claude-sonnet-4-20250514" }

// Response
{
  "sanitized": "Email [EMAIL_0] about the meeting with [PERSON_0]",
  "token_map_id": "a1b2c3d4-...",
  "entity_count": 2,
  "categories": { "EMAIL": 1, "PERSON": 1 },
  "entity_details": [
    { "category": "EMAIL", "start": 6, "end": 19, "length": 13, "confidence": 0.95, "source": "regex", "token": "[EMAIL_0]" },
    { "category": "PERSON", "start": 42, "end": 56, "length": 14, "confidence": 0.85, "source": "spacy", "token": "[PERSON_0]" }
  ]
}
```

**`sanitize_batch`** — Sanitize multiple texts with a shared token map.

```json
// Tool call
{ "texts": ["Email john@acme.com", "SSN 123-45-6789"] }

// Response
{
  "sanitized": ["Email [EMAIL_0]", "SSN [SSN_0]"],
  "token_map_id": "a1b2c3d4-...",
  "entity_count": 2,
  "categories": { "EMAIL": 1, "SSN": 1 }
}
```

**`desanitize`** — Restore original values using a token map ID.

```json
// Tool call
{ "text": "I've drafted an email to [EMAIL_0] regarding [PERSON_0]'s request.", "token_map_id": "a1b2c3d4-..." }

// Response
{ "restored": "I've drafted an email to john@acme.com regarding Sarah Johnson's request." }
```

**`desanitize_batch`** — Restore original values in multiple texts using a shared token map.

```json
// Tool call
{ "texts": ["Reply to [EMAIL_0]", "SSN is [SSN_0]"], "token_map_id": "a1b2c3d4-..." }

// Response
{ "restored": ["Reply to john@acme.com", "SSN is 123-45-6789"] }
```

**`analyze`** — Detect PII without cloaking.

```json
// Tool call
{ "text": "Contact john@acme.com, SSN 123-45-6789" }

// Response
{
  "entity_count": 2,
  "entities": [
    { "text": "john@acme.com", "category": "EMAIL", "start": 8, "end": 21, "confidence": 0.95, "source": "regex" },
    { "text": "123-45-6789", "category": "SSN", "start": 27, "end": 38, "confidence": 0.95, "source": "regex" }
  ]
}
```

**`analyze_batch`** — Analyze multiple texts for PII without cloaking.

```json
// Tool call
{ "texts": ["Email john@acme.com", "SSN 123-45-6789"] }

// Response
{
  "results": [
    { "entity_count": 1, "entities": [{ "text": "john@acme.com", "category": "EMAIL", ... }] },
    { "entity_count": 1, "entities": [{ "text": "123-45-6789", "category": "SSN", ... }] }
  ],
  "total_entity_count": 2
}
```

---

## How It Works

CloakLLM uses a multi-pass detection pipeline to find PII before it reaches an LLM provider.

### 3-Pass Detection

1. **Regex** (both SDKs) — High-precision pattern matching for structured data: emails, SSNs, credit cards, phone numbers, IP addresses, API keys, AWS keys, JWTs, IBANs.

2. **spaCy NER** (Python only) — Named entity recognition for names, organizations, and locations (PERSON, ORG, GPE). The JS SDK does not include spaCy; instead, these categories are handled by the optional Ollama LLM pass.

3. **Ollama LLM** (opt-in, both SDKs) — Local LLM-based semantic detection for contextual PII: addresses, dates of birth, medical terms, financial data, and more. Data never leaves your machine.

### Tokenization

Detected entities are replaced with deterministic tokens in `[CATEGORY_N]` format:

- `john@acme.com` → `[EMAIL_0]`
- `Sarah Johnson` → `[PERSON_0]`
- `123-45-6789` → `[SSN_0]`

Tokens are **deterministic** — the same input produces the same token within a session. A `TokenMap` stores the bidirectional mapping and can be reused across multi-turn conversations.

Token injection is prevented by escaping fullwidth brackets in user input.

The `TokenMap` also exposes `entity_details` (Python) / `entityDetails` (JS) — per-entity metadata (category, offsets, confidence, source, token) without original text. Use `to_report()` / `toReport()` for a full summary suitable for compliance dashboards.

### Audit Logs

Every sanitize/desanitize operation is logged to hash-chained JSONL files:

- **No PII stored** — only hashes and token counts
- **Tamper-evident** — each entry's `prev_hash` links to the previous entry's `entry_hash` (SHA-256)
- **Genesis hash** — first entry links to `"0" * 64`
- Designed for **EU AI Act Article 12** compliance

---

## Configuration Reference

### Python ShieldConfig

| Option | Type | Default | Env Var | Description |
|--------|------|---------|---------|-------------|
| `spacy_model` | `str` | `"en_core_web_sm"` | `CLOAKLLM_SPACY_MODEL` | spaCy model for NER |
| `ner_entity_types` | `set[str]` | `{"PERSON", "ORG", "GPE", "LOC", "FAC", "NORP", "EMAIL", "PHONE"}` | — | Entity types for spaCy NER |
| `detect_emails` | `bool` | `True` | — | Detect email addresses |
| `detect_phones` | `bool` | `True` | — | Detect phone numbers |
| `detect_ssns` | `bool` | `True` | — | Detect Social Security Numbers |
| `detect_credit_cards` | `bool` | `True` | — | Detect credit card numbers |
| `detect_api_keys` | `bool` | `True` | — | Detect API keys |
| `detect_ip_addresses` | `bool` | `True` | — | Detect IP addresses |
| `detect_iban` | `bool` | `True` | — | Detect IBAN numbers |
| `custom_patterns` | `list[tuple[str, str]]` | `[]` | — | Custom `(name, regex)` patterns |
| `llm_detection` | `bool` | `False` | `CLOAKLLM_LLM_DETECTION` | Enable Ollama LLM detection |
| `llm_model` | `str` | `"llama3.2"` | `CLOAKLLM_LLM_MODEL` | Ollama model name |
| `llm_ollama_url` | `str` | `"http://localhost:11434"` | `CLOAKLLM_OLLAMA_URL` | Ollama server URL |
| `llm_timeout` | `float` | `10.0` | — | LLM request timeout (seconds) |
| `llm_confidence` | `float` | `0.85` | — | Confidence threshold for LLM detections |
| `custom_llm_categories` | `list[tuple[str, str]]` | `[]` | — | Custom `(name, description)` categories for LLM detection |
| `llm_allow_remote` | `bool` | `False` | `CLOAKLLM_LLM_ALLOW_REMOTE` | Allow non-localhost Ollama URLs (SSRF prevention) |
| `locale` | `str` | `""` | — | Locale for country-specific PII patterns (e.g., `"de"`, `"fr"`) |
| `entity_hashing` | `bool` | `False` | `CLOAKLLM_ENTITY_HASHING` | Enable per-entity HMAC-SHA256 hashing |
| `entity_hash_key` | `str` | `None` | `CLOAKLLM_ENTITY_HASH_KEY` | HMAC key (auto-generated if omitted) |
| `descriptive_tokens` | `bool` | `True` | — | `[PERSON_0]` vs `[TKN_A3F2]` |
| `audit_enabled` | `bool` | `True` | — | Enable audit logging |
| `log_dir` | `Path` | `./cloakllm_audit` | `CLOAKLLM_LOG_DIR` | Audit log directory |
| `otel_enabled` | `bool` | `False` | `CLOAKLLM_OTEL_ENABLED` | Enable OpenTelemetry |
| `otel_service_name` | `str` | `"cloakllm"` | `OTEL_SERVICE_NAME` | OTel service name |
| `auto_mode` | `bool` | `True` | — | Auto-sanitize in middleware |
| `mode` | `str` | `"tokenize"` | — | `"tokenize"` (reversible) or `"redact"` (irreversible) |
| `skip_models` | `list[str]` | `[]` | — | Model prefixes to skip |

### JavaScript ShieldConfig

| Option | Type | Default | Env Var | Description |
|--------|------|---------|---------|-------------|
| `detectEmails` | `boolean` | `true` | — | Detect email addresses |
| `detectPhones` | `boolean` | `true` | — | Detect phone numbers |
| `detectSsns` | `boolean` | `true` | — | Detect Social Security Numbers |
| `detectCreditCards` | `boolean` | `true` | — | Detect credit card numbers |
| `detectApiKeys` | `boolean` | `true` | — | Detect API keys |
| `detectIpAddresses` | `boolean` | `true` | — | Detect IP addresses |
| `detectIban` | `boolean` | `true` | — | Detect IBAN numbers |
| `customPatterns` | `Array<{name, pattern}>` | `[]` | — | Custom regex patterns |
| `llmDetection` | `boolean` | `false` | `CLOAKLLM_LLM_DETECTION` | Enable Ollama LLM detection |
| `llmModel` | `string` | `"llama3.2"` | `CLOAKLLM_LLM_MODEL` | Ollama model name |
| `llmOllamaUrl` | `string` | `"http://localhost:11434"` | `CLOAKLLM_OLLAMA_URL` | Ollama server URL |
| `llmTimeout` | `number` | `10000` | — | LLM request timeout (ms) |
| `llmConfidence` | `number` | `0.85` | — | Confidence threshold for LLM detections |
| `customLlmCategories` | `Array<{name, description?}>` | `[]` | — | Custom categories for LLM detection |
| `llmAllowRemote` | `boolean` | `false` | `CLOAKLLM_LLM_ALLOW_REMOTE` | Allow non-localhost Ollama URLs (SSRF prevention) |
| `locale` | `string` | `""` | — | Locale for country-specific PII patterns (e.g., `"de"`, `"fr"`) |
| `entityHashing` | `boolean` | `false` | `CLOAKLLM_ENTITY_HASHING` | Enable per-entity HMAC-SHA256 hashing |
| `entityHashKey` | `string` | `undefined` | `CLOAKLLM_ENTITY_HASH_KEY` | HMAC key (auto-generated if omitted) |
| `descriptiveTokens` | `boolean` | `true` | — | `[PERSON_0]` vs opaque tokens |
| `auditEnabled` | `boolean` | `true` | — | Enable audit logging |
| `logDir` | `string` | `"./cloakllm_audit"` | `CLOAKLLM_LOG_DIR` | Audit log directory |
| `autoMode` | `boolean` | `true` | — | Auto-sanitize in middleware |
| `mode` | `string` | `"tokenize"` | — | `"tokenize"` (reversible) or `"redact"` (irreversible) |
| `skipModels` | `string[]` | `[]` | — | Model prefixes to skip |

### Environment Variables

These work across all three SDKs:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOAKLLM_LOG_DIR` | `./cloakllm_audit` | Audit log directory |
| `CLOAKLLM_LLM_DETECTION` | `false` | Enable LLM-based detection |
| `CLOAKLLM_LLM_MODEL` | `llama3.2` | Ollama model for LLM detection |
| `CLOAKLLM_OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `CLOAKLLM_LLM_ALLOW_REMOTE` | `false` | Allow non-localhost Ollama URLs |
| `CLOAKLLM_SPACY_MODEL` | `en_core_web_sm` | spaCy model (Python only) |
| `CLOAKLLM_ENTITY_HASHING` | `false` | Enable per-entity HMAC-SHA256 hashing |
| `CLOAKLLM_ENTITY_HASH_KEY` | *(auto-generated)* | HMAC key for entity hashing |
| `CLOAKLLM_AUDIT_ENABLED` | `true` | Enable/disable audit logging (MCP) |
| `CLOAKLLM_OTEL_ENABLED` | `false` | Enable OpenTelemetry (Python only) |
| `OTEL_SERVICE_NAME` | `cloakllm` | OpenTelemetry service name (Python only) |

---

## Multi-Turn Conversations

Reuse the token map across turns so the same entities always map to the same tokens.

### Python

```python
from cloakllm import Shield

shield = Shield()

# Turn 1
prompt1 = "Schedule a call with Sarah Johnson (sarah.j@techcorp.io) for Monday."
sanitized1, token_map = shield.sanitize(prompt1)

# Turn 2 — pass the same token_map
prompt2 = "Also invite john@acme.com to the call with Sarah Johnson."
sanitized2, token_map = shield.sanitize(prompt2, token_map=token_map)
# sarah.j@techcorp.io → [EMAIL_0] in both turns
# Sarah Johnson → [PERSON_0] in both turns
# john@acme.com → [EMAIL_1] (new entity, new token)

# Desanitize any response using the same token_map
restored = shield.desanitize(llm_response, token_map)
```

### JavaScript

```javascript
const { Shield } = require('cloakllm');

const shield = new Shield();

// Turn 1
const [sanitized1, tokenMap] = shield.sanitize(
  'Schedule a call with sarah.j@techcorp.io for Monday.'
);

// Turn 2 — pass the same tokenMap
const [sanitized2] = shield.sanitize(
  'Also invite john@acme.com to that call.',
  { tokenMap }
);

// Desanitize any response using the same tokenMap
const restored = shield.desanitize(llmResponse, tokenMap);
```

---

## Batch Processing

Sanitize multiple texts at once with a shared token map and a single audit entry. Same entities across texts get the same token.

### Python

```python
from cloakllm import Shield

shield = Shield()

texts = [
    "Email john@acme.com about the project",
    "Also notify jane@acme.com and john@acme.com",
]
sanitized_texts, token_map = shield.sanitize_batch(texts)
# sanitized_texts[0]: "Email [EMAIL_0] about the project"
# sanitized_texts[1]: "Also notify [EMAIL_1] and [EMAIL_0]"
# john@acme.com → [EMAIL_0] in both texts (shared token map)

# Desanitize batch
responses = ["Reply to [EMAIL_0]", "CC [EMAIL_1]"]
restored = shield.desanitize_batch(responses, token_map)
```

### JavaScript

```javascript
const { Shield } = require('cloakllm');

const shield = new Shield();

const [sanitizedTexts, tokenMap] = shield.sanitizeBatch([
  'Email john@acme.com about the project',
  'Also notify jane@acme.com and john@acme.com',
]);

// Desanitize batch
const restored = shield.desanitizeBatch(
  ['Reply to [EMAIL_0]', 'CC [EMAIL_1]'],
  tokenMap
);
```

### MCP

Use the `sanitize_batch` tool:

```json
// Tool call
{ "texts": ["Email john@acme.com", "SSN 123-45-6789"] }

// Response
{
  "sanitized": ["Email [EMAIL_0]", "SSN [SSN_0]"],
  "token_map_id": "a1b2c3d4-...",
  "entity_count": 2,
  "categories": { "EMAIL": 1, "SSN": 1 }
}
```

### Key Behaviors

- **Shared token map**: Same entity in different texts gets the same token
- **Single audit entry**: One `sanitize_batch` event instead of N separate `sanitize` events
- **Per-text entity tracking**: Each entity detail includes a `text_index` field indicating which text it came from
- **Reusable token map**: Pass `token_map` / `tokenMap` from a previous call for multi-turn batch conversations

---

## Performance Metrics

Track detection performance with per-pass timing breakdowns in audit logs and accumulated metrics via the `metrics()` API.

### Per-Pass Timing in Audit Logs

Every audit entry includes a `timing` object with per-pass breakdowns:

```json
{
  "timing": {
    "total_ms": 12.5,
    "detection_ms": 8.2,
    "regex_ms": 1.1,
    "ner_ms": 6.8,
    "llm_ms": 0.0,
    "tokenization_ms": 4.3
  }
}
```

### Accumulated Metrics API

Use `metrics()` to get accumulated performance stats across all calls, and `reset_metrics()` / `resetMetrics()` to clear them.

### Python

```python
from cloakllm import Shield

shield = Shield()

# ... perform sanitize/desanitize calls ...

stats = shield.metrics()
# {
#   "calls": { "sanitize": 5, "desanitize": 3, "sanitize_batch": 1, "desanitize_batch": 0 },
#   "total_ms": 62.4,
#   "avg_ms": 6.9,
#   "detection": { "regex_ms": 5.5, "ner_ms": 34.0, "llm_ms": 0.0 },
#   "tokenization_ms": 22.9,
#   "entities_detected": 18,
#   "categories": { "EMAIL": 7, "PERSON": 5, "SSN": 3, "PHONE": 3 }
# }

shield.reset_metrics()  # Clear accumulated stats
```

### JavaScript

```javascript
const { Shield } = require('cloakllm');

const shield = new Shield();

// ... perform sanitize/desanitize calls ...

const stats = shield.metrics();
// {
//   calls: { sanitize: 5, desanitize: 3, sanitizeBatch: 1, desanitizeBatch: 0 },
//   total_ms: 45.2,
//   avg_ms: 5.0,
//   detection: { regex_ms: 5.5, llm_ms: 0.0 },
//   tokenization_ms: 39.7,
//   entities_detected: 18,
//   categories: { EMAIL: 7, SSN: 3, PHONE: 3 }
// }

shield.resetMetrics();  // Clear accumulated stats
```

---

## Redaction Mode

Redaction mode provides **irreversible** PII removal — entities are replaced with `[CATEGORY_REDACTED]` placeholders instead of numbered tokens. No token map is stored, so the original values cannot be recovered. This is designed for GDPR right-to-erasure and scenarios where you must guarantee PII is permanently destroyed.

### Python

```python
from cloakllm import Shield, ShieldConfig

shield = Shield(ShieldConfig(mode="redact"))

redacted, token_map = shield.sanitize("Email john@acme.com about Sarah Johnson")
# redacted: "Email [EMAIL_REDACTED] about [PERSON_REDACTED]"
# token_map.entity_count == 0 (no forward mappings in redact mode)

# Desanitize is a no-op in redact mode — original values are gone
restored = shield.desanitize(redacted, token_map)
# restored == redacted (unchanged)
```

### JavaScript

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const shield = new Shield(new ShieldConfig({ mode: 'redact' }));

const [redacted, tokenMap] = shield.sanitize('Email john@acme.com about Sarah Johnson');
// redacted: "Email [EMAIL_REDACTED] about [PERSON_REDACTED]"
// tokenMap.entityCount == 0 (no forward mappings in redact mode)

// Desanitize is a no-op in redact mode
const restored = shield.desanitize(redacted, tokenMap);
// restored === redacted (unchanged)
```

### MCP

Pass `mode: "redact"` to the `sanitize` tool. No `token_map_id` is returned in redact mode.

### Key Behaviors

- Token format: `[CATEGORY_REDACTED]` (e.g., `[EMAIL_REDACTED]`, `[PERSON_REDACTED]`)
- Token map is empty — no bidirectional mappings stored
- `desanitize()` returns the input unchanged (no-op)
- Audit log entries include `"mode": "redact"` for traceability

---

## Custom Patterns

Add your own regex patterns to detect domain-specific PII.

### Python

```python
from cloakllm import Shield, ShieldConfig

config = ShieldConfig(
    custom_patterns=[
        ("EMPLOYEE_ID", r"EMP-\d{6}"),
        ("CASE_NUMBER", r"CASE-\d{4}-\d{4}"),
    ]
)
shield = Shield(config=config)

sanitized, token_map = shield.sanitize("Contact EMP-123456 about CASE-2024-0891")
# → "Contact [EMPLOYEE_ID_0] about [CASE_NUMBER_0]"
```

### JavaScript

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const config = new ShieldConfig({
  customPatterns: [
    { name: 'EMPLOYEE_ID', pattern: 'EMP-\\d{6}' },
    { name: 'CASE_NUMBER', pattern: 'CASE-\\d{4}-\\d{4}' },
  ],
});
const shield = new Shield(config);

const [sanitized, tokenMap] = shield.sanitize('Contact EMP-123456 about CASE-2024-0891');
// → "Contact [EMPLOYEE_ID_0] about [CASE_NUMBER_0]"
```

---

## LLM-Powered Detection (Ollama)

Both SDKs support an optional local LLM pass via [Ollama](https://ollama.com) for detecting PII that requires contextual understanding.

### Enabling

```python
# Python
config = ShieldConfig(llm_detection=True)
```

```javascript
// JavaScript
const config = new ShieldConfig({ llmDetection: true });
```

Or via environment variable:

```bash
export CLOAKLLM_LLM_DETECTION=true
```

### What It Catches

| Category | Examples |
|----------|----------|
| `ADDRESS` | 742 Evergreen Terrace, Springfield |
| `DATE_OF_BIRTH` | born January 15, 1990 |
| `MEDICAL` | diabetes mellitus, blood type A+ |
| `FINANCIAL` | account 4521-XXX, routing 021000021 |
| `NATIONAL_ID` | TZ 12345678 |
| `BIOMETRIC` | fingerprint hash F3A2... |
| `USERNAME` | @johndoe42 |
| `PASSWORD` | P@ssw0rd123 |
| `VEHICLE` | plate ABC-1234 |

In the **JS SDK**, the LLM pass also detects `PERSON`, `ORG`, and `GPE` (since JS has no spaCy NER).

### Configuration

| Option | Python | JavaScript | Default |
|--------|--------|------------|---------|
| Model | `llm_model` | `llmModel` | `"llama3.2"` |
| Server URL | `llm_ollama_url` | `llmOllamaUrl` | `"http://localhost:11434"` |
| Timeout | `llm_timeout` | `llmTimeout` | `10.0`s / `10000`ms |
| Confidence | `llm_confidence` | `llmConfidence` | `0.85` |

If Ollama is not running, the LLM pass is silently skipped.

---

## Custom LLM Categories

Define domain-specific PII types that the Ollama LLM pass should detect. This extends the built-in LLM categories (ADDRESS, MEDICAL, etc.) with your own semantic types.

### Python

```python
from cloakllm import Shield, ShieldConfig

config = ShieldConfig(
    llm_detection=True,
    custom_llm_categories=[
        ("PATIENT_ID", "Hospital patient ID, format PAT-XXXXX"),
        ("EMPLOYEE_NUMBER", "Internal employee number"),
    ],
)
shield = Shield(config=config)

sanitized, token_map = shield.sanitize("Patient PAT-12345 was seen by Dr. Smith")
# If LLM detects "PAT-12345" as PATIENT_ID → "[PATIENT_ID_0]"
```

### JavaScript

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const config = new ShieldConfig({
  llmDetection: true,
  customLlmCategories: [
    { name: 'PATIENT_ID', description: 'Hospital patient ID, format PAT-XXXXX' },
    { name: 'EMPLOYEE_NUMBER', description: 'Internal employee number' },
  ],
});
const shield = new Shield(config);

const [sanitized, tokenMap] = shield.sanitize('Patient PAT-12345 was seen by Dr. Smith');
// If LLM detects "PAT-12345" as PATIENT_ID → "[PATIENT_ID_0]"
```

### MCP

Pass `custom_llm_categories` as a JSON string of `[name, description]` pairs:

```json
// Tool call
{
  "text": "Patient PAT-12345 was seen by Dr. Smith",
  "custom_llm_categories": "[[\"PATIENT_ID\", \"Hospital patient ID\"]]"
}
```

### Key Behaviors

| Behavior | Details |
|----------|---------|
| **Name validation** | Must match `^[A-Z][A-Z0-9_]*$` (Python enforces at config time) |
| **Excluded categories** | Categories handled by regex/NER (EMAIL, PHONE, SSN, etc.) are skipped with a warning |
| **Description hints** | Descriptions are injected into the Ollama system prompt to guide detection |
| **Requires LLM detection** | `llm_detection` / `llmDetection` must be enabled for custom categories to take effect |

---

## Multi-Language Detection

CloakLLM supports locale-specific PII detection for 13 non-US locales. Setting a locale activates country-specific regex patterns for SSNs, phone numbers, IBANs, tax IDs, and national IDs. In Python, it also auto-selects the appropriate spaCy NER model for that language.

### Supported Locales

| Locale | Country | Example Patterns |
|--------|---------|-----------------|
| `de` | Germany | Steuer-IdNr, Personalausweis, DE phone, DE IBAN |
| `fr` | France | NIR (INSEE), carte d'identite, FR phone, FR IBAN |
| `es` | Spain | DNI/NIE, ES phone, ES IBAN |
| `it` | Italy | Codice Fiscale, IT phone, IT IBAN |
| `pt` | Portugal | NIF, PT phone, PT IBAN |
| `nl` | Netherlands | BSN, NL phone, NL IBAN |
| `pl` | Poland | PESEL, NIP, PL phone, PL IBAN |
| `se` | Sweden | Personnummer, SE phone, SE IBAN |
| `no` | Norway | Fodselsnummer, NO phone, NO IBAN |
| `dk` | Denmark | CPR-nummer, DK phone, DK IBAN |
| `fi` | Finland | Henkilotunnus, FI phone, FI IBAN |
| `gb` | United Kingdom | NINO, GB phone, GB IBAN |
| `au` | Australia | TFN, AU phone |

### Python

```python
from cloakllm import Shield, ShieldConfig

# German locale — activates DE-specific patterns and de_core_news_sm spaCy model
shield = Shield(ShieldConfig(locale="de"))

sanitized, token_map = shield.sanitize("Steuer-IdNr: 12345678901, Tel: +49 30 1234567")
# → "Steuer-IdNr: [SSN_0], Tel: [PHONE_0]"
```

### JavaScript

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

// German locale — activates DE-specific patterns
const shield = new Shield(new ShieldConfig({ locale: 'de' }));

const [sanitized, tokenMap] = shield.sanitize('Steuer-IdNr: 12345678901, Tel: +49 30 1234567');
// → "Steuer-IdNr: [SSN_0], Tel: [PHONE_0]"
```

### Key Behaviors

- **spaCy model auto-selection** (Python only): Each locale maps to the appropriate spaCy language model (e.g., `de` uses `de_core_news_sm`, `fr` uses `fr_core_news_sm`). Install the model with `python -m spacy download <model_name>`.
- **Pattern replacement**: Locale-specific patterns replace the default US-centric patterns for SSN, phone, and similar categories.
- **Composable**: Locale patterns work alongside custom patterns, LLM detection, and entity hashing.
- **Default**: When no locale is set (empty string), US patterns are used.

---

## Entity Hashing

Per-entity HMAC-SHA256 hashing enables cross-request entity correlation without storing PII. Each detected entity gets a deterministic, keyed hash — the same entity always produces the same hash, allowing you to track "the same person appeared in 47 requests" without knowing who.

### Python

```python
from cloakllm import Shield, ShieldConfig

config = ShieldConfig(
    entity_hashing=True,
    entity_hash_key="my-secret-key-hex",  # optional — auto-generated if omitted
)
shield = Shield(config=config)

sanitized, token_map = shield.sanitize("Email john@acme.com about Sarah Johnson")

# entity_details now includes entity_hash
for detail in token_map.entity_details:
    print(detail["category"], detail["token"], detail["entity_hash"])
    # EMAIL  [EMAIL_0]  a3f2...  (64-char hex)
    # PERSON [PERSON_0] b7c1...
```

### JavaScript

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const config = new ShieldConfig({
  entityHashing: true,
  entityHashKey: 'my-secret-key-hex',  // optional — auto-generated if omitted
});
const shield = new Shield(config);

const [sanitized, tokenMap] = shield.sanitize('Email john@acme.com about Sarah Johnson');

// entityDetails now includes entity_hash
for (const detail of tokenMap.entityDetails) {
  console.log(detail.category, detail.token, detail.entity_hash);
}
```

### MCP

Pass `entity_hashing` and optionally `entity_hash_key` to the `sanitize` tool:

```json
// Tool call
{ "text": "Email john@acme.com", "entity_hashing": true, "entity_hash_key": "my-key" }

// Response — entity_details includes entity_hash
{
  "entity_details": [
    { "category": "EMAIL", "token": "[EMAIL_0]", "entity_hash": "a3f2..." }
  ]
}
```

### How It Works

- **HMAC-SHA256**: `HMAC(key, "CATEGORY:normalized_text")` — keyed hash prevents rainbow table attacks
- **Category prefix**: `EMAIL:john@acme.com` and `PERSON:john@acme.com` produce different hashes, preventing cross-type collisions
- **Normalization**: Input is lowercased and stripped of whitespace for consistency (`John Smith` and `john smith` produce the same hash)
- **Auto-key**: If `entity_hashing=True` but no key is provided, a random 32-byte hex key is generated per Shield instance
- **Deterministic**: Same entity + same key = same hash, across requests and SDK languages
- **Works everywhere**: Compatible with `tokenize` mode, `redact` mode, `sanitize_batch`, and multi-turn conversations

### Security Notes

- The HMAC key is a deployment secret — never share it or log it
- Entity hashes are one-way — you cannot recover the original PII from a hash
- Use a consistent key across requests to enable correlation; rotate the key to break correlation

---

## Incremental Streaming

When using streaming LLM responses, CloakLLM desanitizes tokens incrementally as chunks arrive — no buffering of the full response. The `StreamDesanitizer` state machine replaces `[CATEGORY_N]` tokens as soon as the closing `]` arrives, passing plain text through immediately.

All middleware integrations (OpenAI SDK, LiteLLM, Vercel AI SDK) use `StreamDesanitizer` automatically. You only need the standalone API if you're building a custom streaming pipeline.

### Python

```python
from cloakllm import Shield, StreamDesanitizer

shield = Shield()
sanitized, token_map = shield.sanitize("Email john@acme.com about Sarah Johnson")

# Simulate streaming chunks from an LLM
chunks = ["Hi ", "[PER", "SON_0]", ", your email is ", "[EMAIL_0]", "."]

desan = StreamDesanitizer(token_map)
for chunk in chunks:
    output = desan.feed(chunk)
    if output:
        print(output, end="")  # prints incrementally
# Flush any remaining buffer at end of stream
remaining = desan.flush()
if remaining:
    print(remaining, end="")
```

### JavaScript

```javascript
const { Shield, StreamDesanitizer } = require('cloakllm');

const shield = new Shield();
const [sanitized, tokenMap] = shield.sanitize('Email john@acme.com about Sarah Johnson');

// Simulate streaming chunks from an LLM
const chunks = ['Hi ', '[PER', 'SON_0]', ', your email is ', '[EMAIL_0]', '.'];

const desan = new StreamDesanitizer(tokenMap);
for (const chunk of chunks) {
  const output = desan.feed(chunk);
  if (output) process.stdout.write(output);
}
const remaining = desan.flush();
if (remaining) process.stdout.write(remaining);
```

### How It Works

- **Plain text** passes through `feed()` immediately — no latency added
- **`[` bracket** triggers internal buffering of a potential token
- **`]` bracket** resolves the buffer against the token map (case-insensitive) and emits the original value, or the literal text if not a known token
- **Buffer overflow** — if the buffer exceeds 40 characters without a `]`, it flushes incrementally to prevent unbounded memory use
- **`flush()`** — call at end-of-stream to emit any remaining buffered text

### Middleware Integration

All middleware paths use `StreamDesanitizer` internally:

| Middleware | Streaming Support |
|-----------|------------------|
| Python OpenAI SDK (`enable_openai`) | Incremental desanitization |
| Python LiteLLM (`cloakllm.enable`) | Incremental desanitization |
| JS OpenAI SDK (`enable`) | Incremental desanitization |
| JS Vercel AI SDK (`createCloakLLMMiddleware`) | Incremental desanitization |

No configuration needed — streaming desanitization is automatic when `stream: true` / `stream=True` is used.

---

## Cryptographic Attestation

Ed25519 digital signatures prove that sanitization occurred. Each `sanitize()` call produces a signed certificate containing input/output hashes, entity count, categories, and detection passes. Batch operations use Merkle trees for efficient multi-text proofs.

### Setup

```python
# Python — generate and save a signing key
from cloakllm import Shield, ShieldConfig, DeploymentKeyPair

keypair = DeploymentKeyPair.generate()
keypair.save("./keys/signing_key.json")

shield = Shield(ShieldConfig(attestation_key=keypair))
```

```javascript
// JavaScript
const { Shield, ShieldConfig, DeploymentKeyPair } = require('cloakllm');

const keypair = DeploymentKeyPair.generate();
keypair.save('./keys/signing_key.json');

const shield = new Shield(new ShieldConfig({ attestationKey: keypair }));
```

Or load from file / environment variable:

```python
shield = Shield(ShieldConfig(attestation_key_path="./keys/signing_key.json"))
# Or: export CLOAKLLM_SIGNING_KEY_PATH=./keys/signing_key.json
```

### Using Certificates

```python
sanitized, token_map = shield.sanitize("Email john@acme.com")
cert = token_map.certificate

# Certificate fields: version, timestamp, nonce, input_hash, output_hash,
# entity_count, categories, detection_passes, mode, key_id, signature
# The nonce field contains a random value for replay prevention

# Verify the certificate
assert cert.verify(keypair.public_key)
assert shield.verify_certificate(cert)

# Serialize for storage or transmission
cert_dict = cert.to_dict()
```

### Batch Attestation with Merkle Trees

```python
texts = ["Email john@acme.com", "SSN 123-45-6789", "Call 555-0100"]
sanitized_texts, token_map = shield.sanitize_batch(texts)

# Batch certificate uses Merkle roots instead of individual hashes
cert = token_map.certificate
merkle_tree = token_map.merkle_tree

# Verify individual text inclusion in the batch
from cloakllm import MerkleTree
import hashlib

leaf = hashlib.sha256(texts[0].encode()).hexdigest()
proof = merkle_tree["input"].proof(0)
assert MerkleTree.verify_proof(leaf, proof, merkle_tree["input"].root)
```

### Cross-Language Compatibility

Certificates are fully cross-language compatible. A certificate signed in Python verifies in JavaScript and vice versa, using identical canonical JSON serialization and Ed25519 signatures.

### Configuration

| Option | Python | JavaScript | Default |
|--------|--------|------------|---------|
| Signing keypair | `attestation_key` | `attestationKey` | `None` |
| Key file path | `attestation_key_path` | `attestationKeyPath` | `None` |
| Environment variable | `CLOAKLLM_SIGNING_KEY_PATH` | `CLOAKLLM_SIGNING_KEY_PATH` | — |

### Python Optional Dependencies

```bash
pip install cloakllm[attestation]  # installs pynacl
# or: pip install cryptography     # also works
```

JavaScript uses Node.js built-in `crypto` module — no extra dependencies.

---

## Entity Detection Reference

| Category | Examples | Detection Method |
|----------|----------|-----------------|
| `EMAIL` | john@acme.com | Regex |
| `PHONE` | +1-555-0142, 050-123-4567 | Regex |
| `SSN` | 123-45-6789 | Regex |
| `CREDIT_CARD` | 4111111111111111 | Regex |
| `IP_ADDRESS` | 192.168.1.100 | Regex |
| `API_KEY` | sk-abc123..., AKIA... | Regex |
| `AWS_KEY` | AKIA1234567890ABCDEF | Regex |
| `JWT` | eyJhbGciOi... | Regex |
| `IBAN` | DE89370400440532013000 | Regex |
| Custom | *(your patterns)* | Regex |
| `PERSON` | John Smith, Sarah Johnson | spaCy NER (Python) / Ollama LLM (JS) |
| `ORG` | Acme Corp, Google | spaCy NER (Python) / Ollama LLM (JS) |
| `GPE` | New York, Israel | spaCy NER (Python) / Ollama LLM (JS) |
| `ADDRESS` | 742 Evergreen Terrace | Ollama LLM |
| `DATE_OF_BIRTH` | 1990-01-15 | Ollama LLM |
| `MEDICAL` | diabetes mellitus | Ollama LLM |
| `FINANCIAL` | account 4521-XXX | Ollama LLM |
| `NATIONAL_ID` | TZ 12345678 | Ollama LLM |
| `BIOMETRIC` | fingerprint hash | Ollama LLM |
| `USERNAME` | @johndoe42 | Ollama LLM |
| `PASSWORD` | P@ssw0rd123 | Ollama LLM |
| `VEHICLE` | plate ABC-1234 | Ollama LLM |
| Custom LLM | *(your categories)* | Ollama LLM (via `custom_llm_categories`) |

---

## CLI

Both SDKs include a CLI for scanning text, verifying audit logs, and viewing statistics.

### Python

```bash
# Scan text for PII (PII values redacted by default)
python -m cloakllm scan "Send email to john@acme.com, SSN 123-45-6789"

# Show original PII values in output
python -m cloakllm scan --show-pii "Send email to john@acme.com, SSN 123-45-6789"

# Scan from stdin
echo "Contact sarah@example.org" | python -m cloakllm scan -

# Verify audit chain integrity
python -m cloakllm verify ./cloakllm_audit/

# Show audit statistics
python -m cloakllm stats ./cloakllm_audit/
```

### JavaScript

```bash
# Scan text for PII
npx cloakllm scan "Send email to john@acme.com, SSN 123-45-6789"

# Verify audit chain integrity
npx cloakllm verify ./cloakllm_audit/

# Show audit statistics
npx cloakllm stats ./cloakllm_audit/
```

### Example Output

**`scan`:**

```
Found 2 entities:
  [EMAIL]  "john@acme.com"    (confidence: 95%, source: regex)
  [SSN]    "123-45-6789"      (confidence: 95%, source: regex)

Sanitized:
  Send email to [EMAIL_0], SSN [SSN_0]
```

**`verify`:**

```
Audit chain integrity verified — no tampering detected.
```

**`stats`:**

```json
{
  "total_events": 12,
  "total_entities_detected": 34,
  "categories": { "EMAIL": 10, "PERSON": 8, "SSN": 6, "PHONE": 5, "IP_ADDRESS": 5 }
}
```

---

## Audit Logs

### File Format

Audit logs are stored as JSONL files in the configured log directory:

```
cloakllm_audit/
  audit_2026-03-01.jsonl
  audit_2026-03-02.jsonl
```

### Entry Structure

Each line is a JSON object with these key fields:

| Field | Description |
|-------|-------------|
| `event_id` | Unique event ID (UUID4) |
| `seq` | Sequence number within the file |
| `timestamp` | ISO 8601 timestamp |
| `event_type` | `"sanitize"`, `"desanitize"`, `"sanitize_batch"`, `"desanitize_batch"`, `"shield_enabled"`, or `"shield_disabled"` |
| `entity_count` | Number of entities detected |
| `categories` | Map of category → count |
| `prompt_hash` | SHA-256 hash of the original text |
| `sanitized_hash` | SHA-256 hash of the sanitized text |
| `model` | LLM model name (if provided) |
| `provider` | LLM provider name (if provided) |
| `tokens_used` | List of tokens used (no original values) |
| `latency_ms` | Processing time in milliseconds |
| `metadata` | Additional context (e.g., `user_id`, `session_id`) |
| `mode` | `"tokenize"` or `"redact"` |
| `entity_details` | Per-entity metadata array (PII-safe: category, offsets, confidence, source, token, and `entity_hash` when hashing is enabled) |
| `timing` | Per-pass breakdown: `total_ms`, `detection_ms`, `regex_ms`, `ner_ms`, `llm_ms`, `tokenization_ms` |
| `prev_hash` | SHA-256 hash of the previous entry |
| `entry_hash` | SHA-256 hash of this entry |

No original PII is stored in audit logs — only hashes, token counts, and categories.

### Verification

**Python:**

```python
shield = Shield()

# Programmatic verification — returns (valid, errors, final_seq)
# final_seq is the last sequence number, useful for truncation detection
is_valid, errors, final_seq = shield.verify_audit()

# Statistics
stats = shield.audit_stats()
```

**JavaScript:**

```javascript
const shield = new Shield();

// Programmatic verification — returns { valid, errors, finalSeq }
// finalSeq is the last sequence number, useful for truncation detection
const { valid, errors, finalSeq } = shield.verifyAudit();

// Statistics
const stats = shield.auditStats();
```

**CLI:**

```bash
# Python
python -m cloakllm verify ./cloakllm_audit/

# JavaScript
npx cloakllm verify ./cloakllm_audit/
```

### Tamper Detection

The hash chain makes tampering evident. Each entry's `entry_hash` is computed from its contents including `prev_hash`. If any entry is modified, deleted, or reordered, the chain breaks and `verify_audit()` / `verifyAudit()` reports the specific entries that fail validation. The returned `final_seq` / `finalSeq` value indicates the last sequence number seen, which can be compared against expected counts to detect log truncation.

---

## Security

### Ollama SSRF Prevention

By default, the Ollama LLM detection pass only connects to `localhost` URLs. This prevents server-side request forgery (SSRF) if an attacker controls the `llm_ollama_url` / `llmOllamaUrl` configuration. To allow connections to remote Ollama servers, explicitly opt in:

```python
# Python
config = ShieldConfig(llm_detection=True, llm_allow_remote=True)
```

```javascript
// JavaScript
const config = new ShieldConfig({ llmDetection: true, llmAllowRemote: true });
```

Or via environment variable:

```bash
export CLOAKLLM_LLM_ALLOW_REMOTE=true
```

### CLI PII Redaction

The CLI `scan` command redacts detected PII values by default. To display original values in the output, use the `--show-pii` flag:

```bash
# Default — PII values are redacted in output
python -m cloakllm scan "Email john@acme.com"
# → [EMAIL] "j***@***.com"

# Show original PII values
python -m cloakllm scan --show-pii "Email john@acme.com"
# → [EMAIL] "john@acme.com"
```

### Thread Safety

CloakLLM is designed for concurrent use:

- **TokenMap**: Thread-safe. Multiple threads can read/write tokens concurrently.
- **AuditLogger**: Thread-safe. Concurrent sanitize calls produce correctly ordered, hash-chained audit entries.
- **LLM cache**: Thread-safe. The Ollama detection cache handles concurrent access without corruption.

### Redacted Analysis

The `analyze()` method supports redacting PII values in its output:

```python
# Python — redact values in analysis output
analysis = shield.analyze("Email john@acme.com", redact_values=True)
# entities[0]["text"] → "[REDACTED]" instead of "john@acme.com"
```

```javascript
// JavaScript — redact values in analysis output
const analysis = shield.analyze('Email john@acme.com', { redactValues: true });
// entities[0].text → "[REDACTED]" instead of "john@acme.com"
```

---

## Disabling / Re-enabling

### Python (OpenAI SDK)

```python
from cloakllm import enable_openai, disable_openai
from openai import OpenAI

client = OpenAI()

enable_openai(client)   # Start protecting
disable_openai(client)  # Stop — restore original client behavior
enable_openai(client)   # Re-enable at any time
```

### Python (LiteLLM)

```python
import cloakllm

cloakllm.enable()   # Start protecting LLM calls
cloakllm.disable()  # Stop — LiteLLM calls pass through unchanged
cloakllm.enable()   # Re-enable at any time
```

### JavaScript (OpenAI SDK)

```javascript
const { enable, disable } = require('cloakllm');
const OpenAI = require('openai');

const client = new OpenAI();

enable(client);    // Start protecting
disable(client);   // Stop — restore original client behavior
enable(client);    // Re-enable at any time
```
