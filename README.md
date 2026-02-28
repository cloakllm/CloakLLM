# CloakLLM

**Cloak your prompts. Prove your compliance.**

Open-source PII protection middleware for LLMs. Detect sensitive data, replace it with reversible tokens, and maintain tamper-evident audit logs — all before your prompts leave your infrastructure.

## SDKs

| SDK | Install | Docs |
|-----|---------|------|
| [CloakLLM-PY](https://github.com/cloakllm/CloakLLM-PY) | `pip install cloakllm` | [Python README](https://github.com/cloakllm/CloakLLM-PY#readme) |
| [CloakLLM-JS](https://github.com/cloakllm/CloakLLM-JS) | `npm install cloakllm` | [JS/TS README](https://github.com/cloakllm/CloakLLM-JS#readme) |

## What it does

- **PII Detection** — emails, SSNs, credit cards, phone numbers, API keys, and more
- **Reversible Tokenization** — deterministic `[CATEGORY_N]` tokens that preserve context for the LLM
- **Tamper-Evident Audit Logs** — hash-chained entries for EU AI Act Article 12 compliance
- **Middleware Integration** — drop-in support for LiteLLM (Python) and OpenAI/Vercel AI SDK (JS)

## Quick Start

### Python

```bash
pip install cloakllm
```

```python
import cloakllm

cloakllm.enable()  # Wraps LiteLLM — all calls are now protected
```

### JavaScript / TypeScript

```bash
npm install cloakllm
```

```javascript
const cloakllm = require('cloakllm');

cloakllm.enable(openaiClient);  // Wraps OpenAI SDK
```

## License

MIT
