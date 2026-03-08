<p align="center">
  <img src="assets/social-card.png" alt="CloakLLM — Cloak your prompts. Prove your compliance." width="720" />
</p>

<p align="center">
  <a href="https://pypi.org/project/cloakllm/"><img src="https://img.shields.io/pypi/dw/cloakllm?label=pypi%20%28sdk%29" alt="PyPI Downloads"></a>
  <a href="https://pypi.org/project/cloakllm-mcp/"><img src="https://img.shields.io/pypi/dw/cloakllm-mcp?label=pypi%20%28mcp%29" alt="PyPI Downloads (MCP)"></a>
  <a href="https://www.npmjs.com/package/cloakllm"><img src="https://img.shields.io/npm/dw/cloakllm?label=npm" alt="npm Downloads"></a>
</p>

# CloakLLM

**Cloak your prompts. Prove your compliance.**

Open-source PII protection middleware for LLMs. Detect sensitive data, replace it with reversible tokens, and maintain tamper-evident audit logs — all before your prompts leave your infrastructure.

<p align="center">
  <a href="https://asciinema.org/a/odNEs0kWP51YRGtl" target="_blank">
    <img src="assets/demo.gif" alt="CloakLLM 30-second demo" width="720" />
  </a>
  <br>
  <sub>▶ <a href="https://asciinema.org/a/odNEs0kWP51YRGtl">Watch interactive demo on asciinema</a></sub>
</p>

## SDKs

| SDK | Version | Install | Docs |
|-----|---------|---------|------|
| [CloakLLM-PY](https://github.com/cloakllm/CloakLLM-PY) | 0.1.9 | `pip install cloakllm` | [Python README](https://github.com/cloakllm/CloakLLM-PY#readme) |
| [CloakLLM-JS](https://github.com/cloakllm/CloakLLM-JS) | 0.1.9 | `npm install cloakllm` | [JS/TS README](https://github.com/cloakllm/CloakLLM-JS#readme) |
| [CloakLLM-MCP](https://github.com/cloakllm/cloakllm-mcp) | 0.1.9 | `python -m mcp run server.py` | [MCP README](https://github.com/cloakllm/cloakllm-mcp#readme) |

## What it does

- **PII Detection** — emails, SSNs, credit cards, phone numbers, API keys, and more
- **LLM-Powered Detection** — opt-in local Ollama integration catches context-dependent PII that regex misses (addresses, medical terms)
- **Reversible Tokenization** — deterministic `[CATEGORY_N]` tokens that preserve context for the LLM
- **Redaction Mode** — irreversible `[CATEGORY_REDACTED]` replacement for GDPR right-to-erasure
- **Tamper-Evident Audit Logs** — hash-chained entries for EU AI Act Article 12 compliance
- **Performance Metrics** — per-pass timing breakdowns (regex, NER, LLM) in audit logs and via `shield.metrics()` API
- **Middleware Integration** — drop-in support for LiteLLM and OpenAI SDK (Python) and OpenAI/Vercel AI SDK (JS)
- **MCP Server** — use CloakLLM directly from Claude Desktop, Cursor, or any MCP-compatible client

## Quick Start

### Python

```bash
pip install cloakllm
```

```python
# Option A: OpenAI SDK
from cloakllm import enable_openai
from openai import OpenAI

client = OpenAI()
enable_openai(client)  # Wraps OpenAI SDK — all calls are now protected

# Option B: LiteLLM
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

### MCP (Claude Desktop)

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cloakllm": {
      "command": "python",
      "args": ["-m", "mcp", "run", "server.py"],
      "cwd": "/path/to/cloakllm-mcp"
    }
  }
}
```

This exposes three tools to Claude: **sanitize**, **desanitize**, and **analyze**.

## License

MIT
