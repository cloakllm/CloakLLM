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
- [Context Risk Analysis](#context-risk-analysis)
- [Token Specification](#token-specification)
- [Pluggable Detection Backends](#pluggable-detection-backends)
- [Article 12 Compliance Mode](#article-12-compliance-mode)
- [Article 4a Bias Detection Workflow](#article-4a-bias-detection-workflow-v070) **(v0.7.0)**
- [Article 50 Content-Labeling Record-Keeping](#article-50-content-labeling-record-keeping-v0100) **(v0.10.0)**
- [Compliance Reporting](#compliance-reporting-v080) **(v0.8.0)**
- [Externally-Verifiable Key Provenance](#externally-verifiable-key-provenance-v081) **(v0.8.1+)**
- [Enterprise Key Management](#enterprise-key-management)
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

> **Important:** MCP tools are called *by the LLM*, not before it. Your prompt is sent to the LLM provider first, then the LLM decides to call CloakLLM's tools. This means the MCP server **cannot** prevent PII in your prompt from reaching the provider. It is useful for sanitizing data the LLM works with *during* a conversation (documents, files, tool outputs). To protect prompts before they leave your infrastructure, use the SDK middleware instead (`enable_openai` / `cloakllm.enable()`).

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

CloakLLM uses a multi-pass detection pipeline to find PII before it reaches an LLM provider. The pipeline is built from pluggable backends — you can replace or extend any stage (see [Pluggable Detection Backends](#pluggable-detection-backends)).

### Default 3-Pass Detection

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
| `context_analysis` | `bool` | `False` | `CLOAKLLM_CONTEXT_ANALYSIS` | Enable automatic context risk analysis on every `sanitize()` call |
| `context_risk_threshold` | `float` | `0.5` | — | Log a warning when context risk score exceeds this threshold |
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
| `contextAnalysis` | `boolean` | `false` | `CLOAKLLM_CONTEXT_ANALYSIS` | Enable automatic context risk analysis on every `sanitize()` call |
| `contextRiskThreshold` | `number` | `0.5` | — | Log a warning when context risk score exceeds this threshold |
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
| `CLOAKLLM_CONTEXT_ANALYSIS` | `false` | Enable automatic context risk analysis |
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
| `entity_count` | On `sanitize` entries: number of entities detected in the input. On `desanitize` entries (v0.6.3+): number of tokens that actually appeared in the input passed to `desanitize()` (not the size of the token map). |
| `categories` | Map of category → count |
| `prompt_hash` | SHA-256 hash of the original text |
| `sanitized_hash` | SHA-256 hash of the sanitized text |
| `model` | LLM model name (if provided) |
| `provider` | LLM provider name (if provided) |
| `tokens_used` | On `sanitize` entries: every token issued for the input. On `desanitize` entries (v0.6.3+): only the tokens actually present in the desanitize input — not the full map. To reconstruct the full map, read the matching `sanitize` entry. |
| `latency_ms` | Processing time in milliseconds. On `desanitize` and `desanitize_batch` entries (v0.6.3+) this is bucketed to 10 ms granularity to close a token-presence side channel; the `Shield.metrics()` API still exposes full-precision values for performance debugging. |
| `metadata` | Additional context (e.g., `user_id`, `session_id`) |
| `mode` | `"tokenize"` or `"redact"` |
| `entity_details` | Per-entity metadata array (PII-safe: category, offsets, confidence, source, token, and `entity_hash` when hashing is enabled). On `desanitize` entries (v0.6.3+): filtered to the present subset, matching `tokens_used`. |
| `timing` | Per-pass breakdown: `total_ms`, `detection_ms`, `regex_ms`, `ner_ms`, `llm_ms`, `tokenization_ms`. On `desanitize` and `desanitize_batch` entries (v0.6.3+) the `total_ms` and `tokenization_ms` fields are 10 ms-bucketed for the same reason as `latency_ms`. |
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

## Context Risk Analysis

Even after tokenization, surrounding context can reveal identity. CloakLLM's `ContextAnalyzer` scores this re-identification risk.

### Standalone Analysis

**Python:**
```python
from cloakllm import Shield

shield = Shield()
sanitized, _ = shield.sanitize("The CEO of Acme Corp works at their office")

risk = shield.analyze_context_risk(sanitized)
print(risk)
# {'token_density': 0.375, 'identifying_descriptors': 1, 'relationship_edges': 1,
#  'risk_score': 0.513, 'risk_level': 'medium', 'warnings': [...]}
```

**JavaScript:**
```javascript
const { Shield } = require('cloakllm');

const shield = new Shield();
const [sanitized] = shield.sanitize('The CEO of Acme Corp works at their office');

const risk = shield.analyzeContextRisk(sanitized);
console.log(risk);
// { token_density: 0.375, identifying_descriptors: 1, relationship_edges: 1,
//   risk_score: 0.513, risk_level: 'medium', warnings: [...] }
```

### Automatic Analysis

Enable `context_analysis` to automatically analyze every `sanitize()` call:

**Python:**
```python
shield = Shield(ShieldConfig(context_analysis=True, context_risk_threshold=0.5))
sanitized, token_map = shield.sanitize("The CEO of Acme Corp lives in New York")

print(token_map.risk_assessment)
# {'risk_score': 0.65, 'risk_level': 'medium', ...}
# Warning logged if risk_score > context_risk_threshold
```

**JavaScript:**
```javascript
const shield = new Shield(new ShieldConfig({
  contextAnalysis: true,
  contextRiskThreshold: 0.5,
}));
const [sanitized, tokenMap] = shield.sanitize('The CEO of Acme Corp lives in New York');

console.log(tokenMap.riskAssessment);
// { risk_score: 0.65, risk_level: 'medium', ... }
```

### Three Signals

| Signal | Description | Weight |
|--------|-------------|--------|
| Token density | Ratio of tokens to total words | ×1.5 |
| Identifying descriptors | Words like "CEO", "founder", "only" near tokens | ×0.15 each |
| Relationship edges | Phrases like "works at", "lives in" connecting two tokens | ×0.20 each |

Risk levels: **low** (≤0.3), **medium** (0.3–0.7), **high** (>0.7). Score capped at 1.0.

### CLI

```bash
# Python
python -m cloakllm scan "The CEO of Acme Corp works in NYC" --context-risk

# JavaScript
npx cloakllm scan "The CEO of Acme Corp works in NYC" --context-risk
```

---

## Token Specification

CloakLLM v0.5.1 introduces a formal token standard. The full spec is in [TOKEN_SPEC.md](TOKEN_SPEC.md).

### Token Format

All tokens follow the grammar `[CATEGORY_N]` in tokenize mode or `[CATEGORY_REDACTED]` in redact mode:

- Category: uppercase letters, digits, and underscores (e.g., `EMAIL`, `CREDIT_CARD`, `DATE_OF_BIRTH`)
- Suffix: zero-based counter (e.g., `0`, `1`, `42`) or `REDACTED`
- Maximum token length: 40 characters (including brackets)

### Validation Utilities

Both SDKs export functions to validate and parse tokens:

**Python:**

```python
from cloakllm import validate_token, parse_token, is_redacted_token, validate_category_name
from cloakllm import BUILTIN_CATEGORIES, MAX_TOKEN_LENGTH

validate_token("[EMAIL_0]")          # True
validate_token("[email_0]")          # False (lowercase)
parse_token("[PERSON_3]")           # ("PERSON", "3")
parse_token("[SSN_REDACTED]")       # ("SSN", "REDACTED")
is_redacted_token("[SSN_REDACTED]") # True
validate_category_name("MY_TYPE")   # True
len(BUILTIN_CATEGORIES)             # 62 built-in categories
```

**JavaScript:**

```javascript
const {
  validateToken, parseToken, isRedactedToken, validateCategoryName,
  BUILTIN_CATEGORIES, MAX_TOKEN_LENGTH,
} = require('cloakllm');

validateToken('[EMAIL_0]');          // true
validateToken('[email_0]');          // false
parseToken('[PERSON_3]');           // { category: 'PERSON', suffix: '3' }
isRedactedToken('[SSN_REDACTED]');  // true
validateCategoryName('MY_TYPE');    // true
BUILTIN_CATEGORIES.size;            // 62
```

### Custom Category Names

Custom categories (via `custom_patterns` or `custom_llm_categories`) must:

- Match the pattern `^[A-Z][A-Z0-9_]*$`
- Not collide with any of the 62 built-in category names

Both SDKs enforce these rules at config creation time.

---

## Pluggable Detection Backends

v0.5.2 introduces a `DetectorBackend` base class that lets you replace or extend the default detection pipeline. The built-in pipeline runs regex → NER → LLM (opt-in). With pluggable backends, you can swap any stage, add custom detectors, or build an entirely custom pipeline.

### Writing a Custom Backend

**Python:**

```python
from cloakllm import DetectorBackend, Shield

class ProfanityBackend(DetectorBackend):
    @property
    def name(self):
        return "profanity"

    def detect(self, text, covered_spans):
        from cloakllm.detector import Detection
        detections = []
        bad_words = {"badword1", "badword2"}
        for word in bad_words:
            idx = text.lower().find(word)
            if idx != -1:
                span = (idx, idx + len(word))
                if not any(s <= idx and idx + len(word) <= e for s, e in covered_spans):
                    detections.append(Detection("PROFANITY", idx, idx + len(word), word, 1.0, "profanity"))
                    covered_spans.append(span)
        return detections
```

**JavaScript:**

```javascript
const { DetectorBackend, Shield } = require('cloakllm');

class ProfanityBackend extends DetectorBackend {
  get name() { return 'profanity'; }

  detect(text, coveredSpans) {
    const detections = [];
    const badWords = ['badword1', 'badword2'];
    for (const word of badWords) {
      const idx = text.toLowerCase().indexOf(word);
      if (idx !== -1) {
        const end = idx + word.length;
        const overlaps = coveredSpans.some(([s, e]) => s <= idx && end <= e);
        if (!overlaps) {
          detections.push({ category: 'PROFANITY', start: idx, end, text: word, confidence: 1.0, source: 'profanity' });
          coveredSpans.push([idx, end]);
        }
      }
    }
    return detections;
  }
}
```

### Using Custom Backends

Pass a `backends` array to `Shield` to replace the default pipeline:

**Python:**

```python
from cloakllm import Shield, RegexBackend, ShieldConfig

config = ShieldConfig()
profanity = ProfanityBackend()
regex = RegexBackend(config)

# Custom pipeline: regex first, then profanity
shield = Shield(config, backends=[regex, profanity])
sanitized, token_map = shield.sanitize("Email john@acme.com, badword1 detected")
```

**JavaScript:**

```javascript
const { Shield, ShieldConfig, RegexBackend } = require('cloakllm');

const config = new ShieldConfig();
const profanity = new ProfanityBackend();
const regex = new RegexBackend(config);

const shield = new Shield(config, { backends: [regex, profanity] });
const [sanitized, tokenMap] = shield.sanitize('Email john@acme.com, badword1 detected');
```

### Built-In Backends

Both SDKs export three built-in backend classes:

| Backend | Name | Description |
|---------|------|-------------|
| `RegexBackend` | `"regex"` | Pattern matching for structured PII (emails, SSNs, etc.) |
| `NerBackend` | `"ner"` | Named entity recognition (spaCy in Python, compromise in JS) |
| `LlmBackend` | `"llm"` | Ollama-based semantic detection for contextual PII |

When no `backends` parameter is provided, Shield builds the default pipeline automatically (regex → NER → LLM if enabled).

### Dynamic Metrics

When custom backends are used, timing keys in `shield.metrics()` and audit log entries are derived from each backend's `name` property (e.g., `profanity_ms`), instead of the hardcoded `regex_ms`/`ner_ms`/`llm_ms`.

---

## Article 12 Compliance Mode

CloakLLM v0.6.0 introduces a formal EU AI Act Article 12 compliance profile. Activating it adds tamper-detectable compliance metadata to every audit entry, enables a runtime guard against PII leakage in logs, and unlocks structured compliance reporting for auditors.

For the regulatory rationale, see [The Article 12 Paradox whitepaper](https://cloakllm.dev/whitepaper) and [COMPLIANCE.md](COMPLIANCE.md).

### Activation

**Python:**

```python
from cloakllm import Shield, ShieldConfig

shield = Shield(ShieldConfig(
    compliance_mode="eu_ai_act_article12",
    retention_hint_days=180,  # default; Article 12 minimum for deployers
))
```

**JavaScript:**

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const shield = new Shield(new ShieldConfig({
  complianceMode: 'eu_ai_act_article12',
  retentionHintDays: 180,
}));
```

When activated, every audit entry gains four fields, all included in the SHA-256 hash chain:

| Field | Value | Purpose |
|---|---|---|
| `compliance_version` | `"eu_ai_act_article12_v1"` | Schema version for regulator-facing tooling |
| `article_ref` | `["EU_AI_Act_Art_12", "EU_AI_Act_Art_19"]` | Articles satisfied by this entry |
| `retention_hint_days` | `180` (default) | Recommended retention for downstream log-rotation systems |
| `pii_in_log` | `false` | Asserted at runtime — never `true` |

### compliance_summary()

Returns a structured map of EU AI Act and GDPR articles addressed by the current configuration.

**Python:**

```python
summary = shield.compliance_summary()
# summary["compliance_mode"]: "eu_ai_act_article12"
# summary["articles_addressed"]: list of 6 article entries (each: article, status, notes)
# summary["config_snapshot"]: current config
# summary["generated_at"]: ISO timestamp
# summary["cloakllm_version"]: "0.6.0"
```

**JavaScript:** `shield.complianceSummary()` (same structure).

### export_compliance_config()

Writes the compliance summary to a JSON file. This is the artifact you hand to an auditor.

**Python:**

```python
shield.export_compliance_config("./compliance_snapshot.json")
```

**JavaScript:**

```javascript
shield.exportComplianceConfig('./compliance_snapshot.json');
```

### verify_audit() compliance report

Returns a structured compliance report with a `verdict` field of `"COMPLIANT"` or `"NON_COMPLIANT"`.

**Python:**

```python
report = shield.verify_audit(output_format="compliance_report")
# {
#   "audit_dir": "./cloakllm_audit",
#   "period": {"from": "...", "to": "..."},
#   "total_entries": 142,
#   "chain_integrity": "verified",
#   "pii_in_logs": False,
#   "compliance_mode_entries": 142,
#   "non_compliance_mode_entries": 0,
#   "pii_categories_detected": {"EMAIL": 34, "PERSON": 28, ...},
#   "certificates_present": 0,
#   "anomalies": [],
#   "verdict": "COMPLIANT",
# }
```

**JavaScript:**

```javascript
const report = shield.verifyAudit({ outputFormat: 'compliance_report' });
console.log(report.verdict);  // "COMPLIANT" | "NON_COMPLIANT"
```

### CLI

```bash
cloakllm verify ./cloakllm_audit/ --format compliance_report
```

Emits the report as JSON to stdout. Exit code `0` for COMPLIANT, `1` for NON_COMPLIANT.

### The PII guard

In compliance mode, every audit entry passes through `_assert_no_pii_in_entry` before being hashed. If any field of `entity_details` contains forbidden keys (`original_value`, `original_text`, `raw_text`, `plain_text`, `value`), the write is rejected with a `RuntimeError`. This is the structural enforcement of CloakLLM's core invariant: **audit logs contain zero original PII.**

---

## Article 4a Bias Detection Workflow (v0.7.0+)

The EU AI Act's new **Article 4a** (added by the May 7 2026 Digital Omnibus) permits processing GDPR Article 9 special-category data — race, ethnic origin, religion, political opinion, health, biometric data, sexual orientation, trade union membership, genetic data — strictly for **bias detection and correction in AI systems**, subject to six safeguards.

CloakLLM's `BiasDetectionSession` operationalises all six. The session is a **sibling class** over a `Shield` (composition, not inheritance) and requires the underlying Shield to be in `compliance_mode="eu_ai_act_article12"` — Article 4a builds on Article 12.

### Eight new special-category tokens

`SPECIAL_CATEGORY_CATEGORIES` (added v0.7.0): `RACE`, `ETHNICITY`, `RELIGION`, `POLITICAL_OPINION`, `HEALTH_BIOMETRIC`, `SEXUAL_ORIENTATION`, `TRADE_UNION`, `GENETIC`. These are **deliberately not auto-detected by regex** — the patterns have unacceptably high false-positive rates and the categories are context-dependent. Spans are introduced either by caller-declared `force_categories` in `pseudonymise()` or by opt-in LLM detection.

### Python

```python
from cloakllm import Shield, ShieldConfig, BiasDetectionSession

shield = Shield(ShieldConfig(compliance_mode="eu_ai_act_article12"))

with BiasDetectionSession(
    shield=shield,
    purpose="Pre-deployment fairness audit of credit-scoring model v3.2",
    necessity_justification=(
        "Synthetic data evaluated and rejected — does not preserve "
        "covariance between protected characteristics and credit history. "
        "See internal report XYZ-2026-04."
    ),
    categories_allowed={"RACE", "ETHNICITY", "RELIGION"},
    max_lifetime_seconds=86400,  # 24 hours (required; max 7 days)
) as session:
    for record in protected_dataset:
        pseudonymised, counts = session.pseudonymise(
            record["text"],
            force_categories=[(s, e, cat) for s, e, cat in record["spans"]],
        )
        # ... run bias-detection over `pseudonymised` ...
    session.record_finding(
        finding_summary="No significant disparate impact detected.",
        bias_metrics={"demographic_parity_diff": 0.012, "sample_size": 5000},
    )
# On exit: session token map wiped (best-effort secure overwrite + reference
# drop), bias_session_end entry logged with wipe_confirmed=True.
```

### JavaScript

```javascript
const { Shield, ShieldConfig, BiasDetectionSession } = require('cloakllm');

const shield = new Shield(new ShieldConfig({
  complianceMode: 'eu_ai_act_article12',
}));

await BiasDetectionSession.run({
  shield,
  purpose: 'Pre-deployment fairness audit of credit-scoring model v3.2',
  necessityJustification: 'Synthetic data evaluated and rejected. See report XYZ-2026-04.',
  categoriesAllowed: ['RACE', 'ETHNICITY', 'RELIGION'],
  maxLifetimeSeconds: 86400,
}, (session) => {
  for (const record of protectedDataset) {
    const [pseudonymised, counts] = session.pseudonymise(record.text, {
      forceCategories: record.spans, // [[start, end, category], ...]
    });
    // ...
  }
  session.recordFinding({
    findingSummary: 'No significant disparate impact detected.',
    biasMetrics: { demographic_parity_diff: 0.012, sample_size: 5000 },
  });
});
```

### Required fields

| Field | Required | Purpose |
|---|---|---|
| `purpose` | yes | Free-text purpose (≤ 500 chars). Logged to the audit chain. Must not contain PII (the MCP layer additionally applies a PII-pattern scan before reaching the session). |
| `necessity_justification` | yes | ≤ 2000 chars. Article 4a safeguard #1 — recorded reason why synthetic / anonymised data is insufficient. |
| `categories_allowed` | yes | Non-empty subset of `SPECIAL_CATEGORY_CATEGORIES`. Out-of-scope categories at pseudonymise time raise `BiasDetectionScopeError`. |
| `max_lifetime_seconds` | yes | 1 .. 604800 (7 days). No default — Article 4a safeguard #5 forces the operator to think about deletion timing. |

### Errors

| Exception | When |
|---|---|
| `BiasDetectionError` | Base class for all four. Inherits from `RuntimeError`. |
| `BiasDetectionScopeError` | `pseudonymise()` called with a category not in `categories_allowed`. State unchanged: no token map mutation, no audit entry. |
| `BiasDetectionTimeoutError` | Operation attempted after `max_lifetime_seconds` elapsed. The session is force-ended and wiped BEFORE the error is raised. |
| `BiasDetectionStateError` | Operation on a session that is closed, or before `__enter__` / `.start()`. |

### Audit-chain shape

Each operation produces one entry, all part of the existing Article 12 hash chain:

| event_type | bias_context fields |
|---|---|
| `bias_session_start` | session_id, purpose, necessity_justification, categories_allowed, max_lifetime_seconds |
| `bias_pseudonymise` | session_id, entity_count, categories_used |
| `bias_finding` | session_id, finding_summary (≤ 500 chars), bias_metrics (numeric dict, B3-validated) |
| `bias_session_end` | session_id, exit_reason (clean/error/timeout/evicted), wipe_confirmed, entries_processed, duration_seconds |

When the Shield is in `compliance_mode="eu_ai_act_article12"`, bias events get `EU_AI_Act_Art_4a` appended to `article_ref` — same chain satisfies both articles. All four entries pass the always-on B3 schema validator (no source PII anywhere).

### Post-deletion forensics — by design

After `bias_session_end` the in-memory token map is wiped. The audit chain retains entry counts, categories, timing, and finding summaries but **cannot be used to reconstruct source values from tokens**. This is the Article 4a safeguard #5 guarantee, not a forensics gap.

### MCP

Three new MCP tools (cloakllm-mcp 0.7.0+): `bias_detection_session_start`, `bias_pseudonymise`, `bias_detection_session_end`. The MCP layer adds a PII-pattern scan on `purpose` / `necessity_justification` / `finding_summary` before they reach the session, so PII-containing values are rejected with `{"error": "..."}` rather than reaching the audit chain.

See [COMPLIANCE.md § Article 4a](COMPLIANCE.md) for the full safeguard mapping table.

---

## Article 50 Content-Labeling Record-Keeping (v0.10.0+)

The EU AI Act's **Article 50** transparency obligation (applies **2 December 2026**) requires providers of generative AI to mark synthetic output as machine-readable AI-generated, and deployers to disclose deep-fakes. CloakLLM does **not** embed watermarks or C2PA manifests in your media — that's the C2PA / Adobe / SynthID asset-layer lane. CloakLLM owns the **compliance record-keeping** layer: a tamper-evident, signed, per-generation record that content was AI-produced and whether it was labeled, ready for the auditor who is *already* asking you for Article 12 logs.

The key property: **the generated content never enters CloakLLM.** You hash your own bytes and pass the digest; the audit log holds metadata + a hash, never the asset. The no-PII-in-logs invariant extends here to a no-content-in-logs invariant.

```python
from cloakllm import Shield, ShieldConfig
import hashlib

shield = Shield(ShieldConfig(compliance_mode="eu_ai_act_article12"))

# After your model generates an image and you apply (or don't apply) a label:
image_bytes = open("generated.png", "rb").read()
shield.record_content_generation(
    modality="image",                 # text | image | audio | video
    synthetic=True,
    labeled=True,                     # was a machine-readable AI-gen label applied?
    disclosure_method="c2pa",         # c2pa | watermark | metadata | visible_notice | none
    deepfake=False,                   # Article 50(4) deep-fake disclosure trigger
    content_hash=hashlib.sha256(image_bytes).hexdigest(),   # you compute it; CloakLLM never sees the bytes
)
```

```javascript
const { Shield, ShieldConfig } = require('cloakllm');
const crypto = require('crypto');

const shield = new Shield(new ShieldConfig({ complianceMode: 'eu_ai_act_article12' }));
shield.recordContentGeneration({
  modality: 'image',
  synthetic: true,
  labeled: true,
  disclosureMethod: 'c2pa',
  deepfake: false,
  contentHash: crypto.createHash('sha256').update(imageBytes).digest('hex'),
});
```

This writes a `content_generation` audit event with `article_ref=[Art_12, Art_19, Art_50]` — it counts as Article 12 record-keeping evidence **and** Article 50 labeling evidence. `generate_compliance_report()` then rolls it up on the `EU_AI_Act_Art_50` row (`generation_events`, `labeled_events`, `label_coverage_pct`, `deepfake_events`, `modality_distribution`). **Any unlabeled synthetic-content event flips the report to NON_COMPLIANT** (strict in v0.10.0).

The `c2pa_manifest_hash` field is a forward-compat hook: if you later embed a C2PA manifest downstream, record its hash here to bind the two records — the bridge export itself is deferred until a customer running C2PA tooling pulls it.

**CLI summary** (CI-gating — exit 1 if any synthetic content is unlabeled):

```bash
cloakllm content-log ./cloakllm_audit
# CloakLLM -- EU AI Act Article 50 content-labeling summary
# Generation events:   142
# Labeled events:      140
# Label coverage:      98.59%
# Deep-fake events:    3
# Modality breakdown:  audio=2, image=20, text=120
# Unlabeled generation events (2): ...
```

The `record_content_generation` MCP tool (13th) exposes the same to Claude Desktop / Cursor. See [COMPLIANCE.md § Article 50](COMPLIANCE.md) and [SPIKE_content_provenance.md](SPIKE_content_provenance.md) for the reject-asset-watermarking / pursue-record-keeping rationale.

---

## Compliance Reporting (v0.8.0+)

**The artifact you hand to an EU AI Act auditor.** v0.6.0 shipped Article 12 Compliance Mode. v0.7.0 added Article 4a bias-detection. v0.8.0 turns those into a regulator-facing report.

One call reduces the audit chain to a per-article rollup -- Article 12 evidence event count, Article 4a `bias_sessions` with `wipe_confirmed_pct`, Article 19 hash-chain verdict -- reconciles cross-article events via `decision_id`, and emits a COMPLIANT / NON_COMPLIANT verdict with human-readable reasons.

### Python

```python
from cloakllm import Shield, ShieldConfig

shield = Shield(config=ShieldConfig(
    log_dir="./cloakllm_audit",
    compliance_mode="eu_ai_act_article12",
))

# JSON (default) -- canonical structured contract for downstream tooling.
report = shield.generate_compliance_report(
    period_from="2026-04-01T00:00:00+00:00",
    period_to="2026-06-30T23:59:59+00:00",
)
print(report["verdict"])  # COMPLIANT or NON_COMPLIANT
for art, stats in report["per_article"].items():
    print(art, stats["evidence_event_count"])

# Markdown -- DPO / compliance officer narrative.
md = shield.generate_compliance_report(format="markdown")

# PDF -- regulator-ready. Requires: pip install cloakllm[reporting]
shield.generate_compliance_report(format="pdf", out_path="2026-Q2.pdf")
```

### JavaScript

```javascript
const cloakllm = require('cloakllm');
const shield = new cloakllm.Shield(new cloakllm.ShieldConfig({
  logDir: './cloakllm_audit',
  complianceMode: 'eu_ai_act_article12',
}));

const report = shield.generateComplianceReport({
  periodFrom: '2026-04-01T00:00:00+00:00',
  periodTo: '2026-06-30T23:59:59+00:00',
});
console.log(report.verdict);

const md = shield.generateComplianceReport({ format: 'markdown' });
// PDF is Python-only (reportlab is a Python-native lib).
```

### CLI

```bash
# Exit 0 on COMPLIANT, exit 1 on NON_COMPLIANT -- CI-friendly.
cloakllm compliance-report ./cloakllm_audit \
  --from 2026-04-01T00:00:00+00:00 \
  --to   2026-06-30T23:59:59+00:00 \
  --format markdown
```

### MCP

The `generate_compliance_report` MCP tool (11th) exposes the same engine to Claude Desktop / Cursor. PDF is rejected at the MCP layer with a helpful error; use the CLI for PDF output.

### Output schema

The JSON contract is published as JSON Schema 2020-12 at `examples/compliance_report_schema.json`. Top-level keys: `report_metadata`, `period`, `articles_in_scope`, `chain_integrity` (verdict / total_entries / anomalies), `per_article` (per-article rollup with optional `bias_sessions` / `findings_recorded` / `wipe_confirmed_pct` ONLY on Article 4a), `attestation` (entries_with_certificates / signatures_valid / key_ids + v0.8.1 forward-compat `provenance_summary` slot), `decisions` (when `include_decisions=True`), `verdict`, `verdict_reasons`.

A canonical sample report ships at `examples/compliance_report_sample.{json,md,pdf}`.

### Correctness invariant

`bias_sessions` / `findings_recorded` / `wipe_confirmed_pct` attach **only** to `EU_AI_Act_Art_4a`. Although bias events claim `article_ref=[Art_12, Art_19, Art_4a]` (because Article 4a builds on Article 12), an auditor reading the Article 12 section must not see bias-specific stats there. Tested in both SDKs.

The same invariant applies to v0.10.0's Article 50 fields: `generation_events` / `labeled_events` / `label_coverage_pct` / `deepfake_events` / `modality_distribution` attach **only** to `EU_AI_Act_Art_50`, never to the Art_12 / Art_19 rows, even though `content_generation` events claim all three. All Article 50 fields are additive (no `schema_version` bump); pre-v0.10.0 reports simply have no Art_50 row.

---

## Externally-Verifiable Key Provenance (v0.8.1+)

**The trust-anchor closer.** v0.8.0 lets your compliance officer generate Article 12 reports. v0.8.1+ lets an external auditor verify those reports' Ed25519 signatures **without trusting CloakLLM, your deployer, or any out-of-band claim about which keys are real**.

### Install

```bash
# Python — KeyManifest signing needs an Ed25519 backend.
pip install cloakllm[attestation]

# MCP — auto-pulls the extras transitively (v0.8.2+).
pip install cloakllm-mcp

# JavaScript — Node's built-in crypto covers Ed25519; nothing extra needed.
npm install cloakllm
```

**v0.8.2+ fail-hard guard:** if you set `ShieldConfig.deployer_id` without an Ed25519 backend installed, `Shield.__init__` raises `RuntimeError` pointing at the install hint. Silent degradation is a footgun the project explicitly rejects -- the deployer who opts in to KeyManifest must get working KeyManifest, not silent skipping.

### Minimal Python example

```python
from cloakllm import (
    Shield, ShieldConfig, DeploymentKeyPair,
    derive_key_manifest, verify_key_provenance,
)

# 1. Generate a signing key (one-time deployment setup)
kp = DeploymentKeyPair.generate()
kp.save("./prod-key.json")

# 2. Configure Shield with deployer_id -- triggers key_registered emission
shield = Shield(config=ShieldConfig(
    audit_enabled=True,
    log_dir="./cloakllm_audit",
    compliance_mode="eu_ai_act_article12",
    attestation_key=kp,
    deployer_id="acme-corp/ai-platform-team",
    key_valid_from="2026-01-01T00:00:00+00:00",
    key_valid_until="2027-01-01T00:00:00+00:00",
))

# 3. Sanitize as normal — every cert is now Ed25519-signed AND auditors
#    can verify provenance against the key_registered manifest in the chain.
sanitized, tm = shield.sanitize("Email alice@example.com about the deal")

# 4. Compliance report includes the v0.8.1 provenance_summary
report = shield.generate_compliance_report()
print(report["attestation"]["provenance_summary"])
# -> {'manifests_found': 1, 'manifests_valid': 1,
#     'within_validity_window_pct': 100,
#     'root_signature_status_distribution': {'NOT_REQUESTED': 1, ...}}
```

### Offline ceremony (root-signed manifest)

For high-stakes deployments, sign the manifest with a SEPARATE offline root key (the chain-of-trust anchor). The runtime CloakLLM process never holds the root key:

```bash
cloakllm key-manifest generate \
  --signing-key-path ./prod-key.json \
  --deployer-id "acme-corp/ai-platform-team" \
  --valid-until "2027-05-31T00:00:00+00:00" \
  --root-key /secure/usb/root-key-2026.json \
  --root-key-id "acme-root-2026" \
  --out /publish/manifest.json
```

### Auditor verification

```bash
# Exit 0 = VERIFIED, exit 1 = any check failed. CI-friendly.
cloakllm key-manifest verify \
  --manifest /publish/manifest.json \
  --certificate ./cert.json \
  --root-public-key /auditor/acme-root-2026.pub
```

### What KeyManifest does NOT prove

- **Trusted timestamping** (attacker with key + clock control can backdate). Out of scope; v1.0 candidate via RFC 3161 (see `SPIKE_timestamping.md`).
- **Anything outside the deployer's root-key custody** -- if the deployer loses their root key, the chain-of-trust anchor is gone.
- ~~Revocation~~ **SHIPPED in v0.9.0** -- see the next section.

See [COMPLIANCE.md § Externally-Verifiable Key Provenance](COMPLIANCE.md) for the full threat-model table, the field reference, and sample JSON.

---

## Key Revocation (v0.9.0+)

**A leaked key gets a signed, dated tombstone the runtime cannot erase.** `valid_until` covers planned rotation; the `RevocationList` covers compromise.

**The one design rule that matters:** the revocation list is OUT-OF-BAND. A compromised runtime controls the audit chain and will never write a `key_revoked` event against its own stolen key -- so the security boundary is a root-signed list published OUTSIDE the attacker's write path. Inline `key_revoked` events exist (`shield.record_key_revocation()`) but are advisory timeline records only.

### Revoke a key (offline root ceremony)

```bash
cloakllm key-manifest revoke \
  --key-id 7e053f5b332c5e40 \
  --reason compromised \
  --revoked-at "2026-01-15T00:00:00+00:00" \
  --deployer-id "acme-corp/ai-platform-team" \
  --list /publish/revocations.json \
  --root-key /secure/usb/root-key-2026.json \
  --root-key-id "acme-root-2026" \
  --out /publish/revocations.json
```

Entries are permanent (no un-revoking -- rotate instead). The empty root-signed list is itself meaningful: publish one at setup so "nothing revoked as of date X" is a signed claim.

### Auditor verification

```bash
cloakllm key-manifest verify \
  --manifest /publish/manifest.json \
  --certificate ./cert.json \
  --root-public-key /auditor/acme-root-2026.pub \
  --revocation-list /publish/revocations.json
# revocation_status: NOT_REVOKED | REVOKED | REVOKED_BUT_CERT_PREDATES
#                    | NOT_CHECKED | LIST_INVALID
# REVOKED and LIST_INVALID fail (exit 1). Certs signed BEFORE revoked_at
# stay valid (X.509/OCSP semantics).
```

### Runtime guard + reports

```python
shield = Shield(config=ShieldConfig(
    attestation_key=kp,
    revocation_list_path="/publish/revocations.json",  # or CLOAKLLM_REVOCATION_LIST
))
# RuntimeError at init if THIS shield's signing key is in the list --
# signing with a revoked key is always a mistake (the v0.8.2 doctrine).

report = shield.generate_compliance_report()  # uses the configured list
print(report["attestation"]["provenance_summary"]["revoked_keys_found"])
```

### v0.9.0 breaking change: legacy_canonical removed

`verify_audit(legacy_canonical=True)` / `verifyAudit({legacyCanonical: true})` now raises an actionable error (sunset phase 2, announced in v0.7.1). Pre-v0.6.1 archival chains must be re-verified and re-archived under a v0.6.1..v0.8.x release before upgrading.

---

## Enterprise Key Management

> **⚠ EXPERIMENTAL — disabled in v0.6.1.** The KMS providers shipped in v0.6.0 had bugs that produced unverifiable signatures. They now raise `NotImplementedError` at runtime. Use `LocalKeyProvider` (the default) for production attestation. Full rebuild planned for v0.7.0.

The scaffolding for HSM-backed signing keys is in place but not production-usable:

```bash
pip install cloakllm[kms]  # installs SDK deps for future development
```

### Supported providers (scaffolding)

| Provider | Config value | SDK installed by `[kms]` extra |
|---|---|---|
| AWS KMS | `attestation_key_provider="aws_kms"` | `boto3` |
| GCP KMS | `attestation_key_provider="gcp_kms"` | `google-cloud-kms` |
| Azure Key Vault | `attestation_key_provider="azure_keyvault"` | `azure-keyvault-keys`, `azure-identity` |
| HashiCorp Vault | `attestation_key_provider="hashicorp_vault"` | `hvac` |

### Usage

```python
from cloakllm import Shield, ShieldConfig

shield = Shield(ShieldConfig(
    attestation_key_provider="aws_kms",
    attestation_key_id="arn:aws:kms:eu-west-1:123:key/abc-...",
    key_rotation_enabled=True,
))
```

When `key_rotation_enabled=True`, a `key_rotation_event` audit entry is logged at session init recording `key_id`, `key_provider`, and `key_version`. No PII is included.

### Custom providers

Subclass `KeyProvider` and implement the `key_id`, `public_key_b64`, and `sign(data)` interface:

```python
from cloakllm import KeyProvider

class MyHSMProvider(KeyProvider):
    @property
    def key_id(self): ...
    @property
    def public_key_b64(self): ...
    def sign(self, data: bytes) -> bytes: ...
```

Then pass an instance via `ShieldConfig(attestation_key=provider)`.

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
