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
- [Custom Patterns](#custom-patterns)
- [LLM-Powered Detection (Ollama)](#llm-powered-detection-ollama)
- [Entity Detection Reference](#entity-detection-reference)
- [CLI](#cli)
- [Audit Logs](#audit-logs)
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

The MCP server exposes 3 tools:

**`sanitize`** — Detect and cloak PII, returns sanitized text + token map ID.

```json
// Tool call
{ "text": "Email john@acme.com about the meeting with Sarah Johnson", "model": "claude-sonnet-4-20250514" }

// Response
{
  "sanitized": "Email [EMAIL_0] about the meeting with [PERSON_0]",
  "token_map_id": "a1b2c3d4-...",
  "entity_count": 2,
  "categories": { "EMAIL": 1, "PERSON": 1 }
}
```

**`desanitize`** — Restore original values using a token map ID.

```json
// Tool call
{ "text": "I've drafted an email to [EMAIL_0] regarding [PERSON_0]'s request.", "token_map_id": "a1b2c3d4-..." }

// Response
{ "restored": "I've drafted an email to john@acme.com regarding Sarah Johnson's request." }
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
| `descriptive_tokens` | `bool` | `True` | — | `[PERSON_0]` vs `[TKN_A3F2]` |
| `audit_enabled` | `bool` | `True` | — | Enable audit logging |
| `log_dir` | `Path` | `./cloakllm_audit` | `CLOAKLLM_LOG_DIR` | Audit log directory |
| `log_original_values` | `bool` | `False` | — | Log original PII values (not recommended) |
| `otel_enabled` | `bool` | `False` | `CLOAKLLM_OTEL_ENABLED` | Enable OpenTelemetry |
| `otel_service_name` | `str` | `"cloakllm"` | `OTEL_SERVICE_NAME` | OTel service name |
| `auto_mode` | `bool` | `True` | — | Auto-sanitize in middleware |
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
| `descriptiveTokens` | `boolean` | `true` | — | `[PERSON_0]` vs opaque tokens |
| `auditEnabled` | `boolean` | `true` | — | Enable audit logging |
| `logDir` | `string` | `"./cloakllm_audit"` | `CLOAKLLM_LOG_DIR` | Audit log directory |
| `logOriginalValues` | `boolean` | `false` | — | Log original PII values (not recommended) |
| `autoMode` | `boolean` | `true` | — | Auto-sanitize in middleware |
| `skipModels` | `string[]` | `[]` | — | Model prefixes to skip |

### Environment Variables

These work across all three SDKs:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOAKLLM_LOG_DIR` | `./cloakllm_audit` | Audit log directory |
| `CLOAKLLM_LLM_DETECTION` | `false` | Enable LLM-based detection |
| `CLOAKLLM_LLM_MODEL` | `llama3.2` | Ollama model for LLM detection |
| `CLOAKLLM_OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `CLOAKLLM_SPACY_MODEL` | `en_core_web_sm` | spaCy model (Python only) |
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

---

## CLI

Both SDKs include a CLI for scanning text, verifying audit logs, and viewing statistics.

### Python

```bash
# Scan text for PII
python -m cloakllm scan "Send email to john@acme.com, SSN 123-45-6789"

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
| `event_type` | `"sanitize"`, `"desanitize"`, `"shield_enabled"`, or `"shield_disabled"` |
| `entity_count` | Number of entities detected |
| `categories` | Map of category → count |
| `prompt_hash` | SHA-256 hash of the original text |
| `sanitized_hash` | SHA-256 hash of the sanitized text |
| `model` | LLM model name (if provided) |
| `provider` | LLM provider name (if provided) |
| `tokens_used` | List of tokens used (no original values) |
| `latency_ms` | Processing time in milliseconds |
| `metadata` | Additional context (e.g., `user_id`, `session_id`) |
| `prev_hash` | SHA-256 hash of the previous entry |
| `entry_hash` | SHA-256 hash of this entry |

No original PII is stored in audit logs — only hashes, token counts, and categories.

### Verification

**Python:**

```python
shield = Shield()

# Programmatic verification
is_valid, errors = shield.verify_audit()

# Statistics
stats = shield.audit_stats()
```

**JavaScript:**

```javascript
const shield = new Shield();

// Programmatic verification
const { valid, errors } = shield.verifyAudit();

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

The hash chain makes tampering evident. Each entry's `entry_hash` is computed from its contents including `prev_hash`. If any entry is modified, deleted, or reordered, the chain breaks and `verify_audit()` / `verifyAudit()` reports the specific entries that fail validation.

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
