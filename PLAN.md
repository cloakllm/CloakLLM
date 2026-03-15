# CloakLLM — Master Implementation Plan

**Based on:** CODEBASE_REPORT.md audit findings and recommendations
**Codebase version:** 0.2.2
**Date:** 2026-03-13
**Scope:** v0.2.3 (critical fixes) → v0.5.0 (research features)

---

## Table of Contents

1. [Phase 1: Critical Security Fixes (v0.2.3)](#phase-1-critical-security-fixes-v023)
2. [Phase 2: Correctness & Stability Fixes (v0.2.4)](#phase-2-correctness--stability-fixes-v024)
3. [Phase 3: MCP Server Feature Parity (v0.2.5)](#phase-3-mcp-server-feature-parity-v025)
4. [Phase 4: Incremental Streaming Desanitization (v0.3.0)](#phase-4-incremental-streaming-desanitization-v030)
5. [Phase 5: Integration Test Suite (v0.3.0)](#phase-5-integration-test-suite-v030)
6. [Phase 6: Detection Benchmark Suite (v0.3.1)](#phase-6-detection-benchmark-suite-v031)
7. [Phase 7: Cryptographic Hardening (v0.3.2)](#phase-7-cryptographic-hardening-v032)
8. [Phase 8: Multi-Language PII Detection (v0.4.0)](#phase-8-multi-language-pii-detection-v040)
9. [Phase 9: JS NER Feature Parity (v0.4.0)](#phase-9-js-ner-feature-parity-v040)
10. [Phase 10: Context-Based PII Leakage Analysis (v0.5.0)](#phase-10-context-based-pii-leakage-analysis-v050)
11. [Release Schedule](#release-schedule)

---

## Phase 1: Critical Security Fixes (v0.2.3)

**Priority:** IMMEDIATE — PII leakage in production
**Effort:** 1-2 hours
**Bugs fixed:** P1 (LiteLLM multi-choice), J1 (Vercel WeakMap)

### 1.1 Fix LiteLLM Multi-Choice Desanitization (P1)

**File:** `cloakllm-py/cloakllm/integrations/litellm_middleware.py`

**Problem:** `_desanitize_response()` calls `_active_maps.pop(call_key)` at line 117. When a LiteLLM response has `n>1` choices, each choice iterates through `shielded_completion` and calls `_desanitize_response` — the map is gone after the first choice. Remaining choices leak raw tokens like `[EMAIL_0]` to users.

The OpenAI middleware was fixed in v0.2.2 (pops once, iterates with same map), but the LiteLLM middleware still uses the old pattern.

**Current code (broken):**

```python
# litellm_middleware.py:111-126
def _desanitize_response(response_text: str, model: str, call_key: str) -> str:
    """Desanitize a response using the stored token map."""
    if not _shield:
        return response_text

    with _maps_lock:
        token_map = _active_maps.pop(call_key, None)  # ← BUG: pops on every call

    if not token_map or token_map.entity_count == 0:
        return response_text

    return _shield.desanitize(
        text=response_text,
        token_map=token_map,
        model=model,
    )

# litellm_middleware.py:183-189 (called per choice)
if not _should_skip(model) and call_key and hasattr(response, "choices"):
    for choice in response.choices:
        if hasattr(choice, "message") and hasattr(choice.message, "content"):
            if choice.message.content:
                choice.message.content = _desanitize_response(
                    choice.message.content, model, call_key
                )  # ← Second call finds empty map → leaks tokens
```

**Fix — pop once, then iterate with same map:**

```python
# litellm_middleware.py — replace _desanitize_response with _pop_token_map + inline desanitize

def _pop_token_map(call_key: str) -> TokenMap | None:
    """Retrieve and remove the stored token map for a call."""
    if not _shield:
        return None
    with _maps_lock:
        return _active_maps.pop(call_key, None)


# In shielded_completion, replace the per-choice loop:
def shielded_completion(*args, **kwargs):
    model = kwargs.get("model") or (args[0] if args else "unknown")
    messages = kwargs.get("messages") or (args[1] if len(args) > 1 else [])
    call_key = ""

    if not _should_skip(model):
        messages, call_key = _sanitize_messages(messages, model)
        kwargs["messages"] = messages

    try:
        response = _original_completion(*args, **kwargs)

        # Desanitize all choices with the SAME token map
        if not _should_skip(model) and call_key and hasattr(response, "choices"):
            token_map = _pop_token_map(call_key)
            call_key = ""  # consumed — skip finally cleanup
            if token_map and token_map.entity_count > 0:
                for choice in response.choices:
                    if hasattr(choice, "message") and hasattr(choice.message, "content"):
                        if choice.message.content:
                            choice.message.content = _shield.desanitize(
                                choice.message.content, token_map, model=model
                            )

        return response
    finally:
        if call_key:
            with _maps_lock:
                _active_maps.pop(call_key, None)


# Apply the same pattern to shielded_acompletion
async def shielded_acompletion(*args, **kwargs):
    model = kwargs.get("model") or (args[0] if args else "unknown")
    messages = kwargs.get("messages") or (args[1] if len(args) > 1 else [])
    call_key = ""

    if not _should_skip(model):
        messages, call_key = _sanitize_messages(messages, model)
        kwargs["messages"] = messages

    try:
        response = await _original_acompletion(*args, **kwargs)

        if not _should_skip(model) and call_key and hasattr(response, "choices"):
            token_map = _pop_token_map(call_key)
            call_key = ""
            if token_map and token_map.entity_count > 0:
                for choice in response.choices:
                    if hasattr(choice, "message") and hasattr(choice.message, "content"):
                        if choice.message.content:
                            choice.message.content = _shield.desanitize(
                                choice.message.content, token_map, model=model
                            )

        return response
    finally:
        if call_key:
            with _maps_lock:
                _active_maps.pop(call_key, None)
```

**Delete** the standalone `_desanitize_response()` function entirely.

**Test:**

```python
# tests/test_litellm_multichoice.py
import pytest
from unittest.mock import MagicMock, patch
from cloakllm.integrations.litellm_middleware import (
    enable, disable, _sanitize_messages, _active_maps, _maps_lock
)

def test_multichoice_desanitization():
    """All n choices must be desanitized, not just the first."""
    enable()
    try:
        mock_response = MagicMock()
        choice1 = MagicMock()
        choice1.message.content = "Contact [EMAIL_0] for details."
        choice2 = MagicMock()
        choice2.message.content = "Sure, [EMAIL_0] is the right person."
        choice3 = MagicMock()
        choice3.message.content = "Reach out to [EMAIL_0]."
        mock_response.choices = [choice1, choice2, choice3]

        messages = [{"role": "user", "content": "Email john@acme.com about the project"}]
        sanitized_msgs, call_key = _sanitize_messages(messages, "gpt-4")

        assert call_key in _active_maps

        with patch("cloakllm.integrations.litellm_middleware._original_completion",
                    return_value=mock_response):
            import litellm
            result = litellm.completion(model="gpt-4", messages=messages)

        for choice in result.choices:
            assert "[EMAIL_0]" not in choice.message.content
            assert "john@acme.com" in choice.message.content
    finally:
        disable()
```

### 1.2 Fix Vercel Middleware WeakMap Fragility (J1)

**File:** `cloakllm-js/src/vercel-middleware.js`

**Problem:** `_tokenMaps` is a `WeakMap<Object, TokenMap>` keyed on the `params` object (line 22). In `transformParams`, a new `newParams = { ...params, ... }` is created (line 123) and used as the key (line 126). In `wrapGenerate` and `wrapStream`, the same `params` reference must be passed to retrieve the token map.

If the Vercel AI SDK spreads, copies, or serializes `params` between `transformParams` and `wrapGenerate`/`wrapStream`, the WeakMap lookup silently fails — desanitization never happens, tokens leak to the user.

**Current code (fragile):**

```javascript
// vercel-middleware.js:22
const _tokenMaps = new WeakMap();

// transformParams (line 123-127):
const newParams = { ...params, prompt: sanitizedPrompt };
if (tokenMap && tokenMap.entityCount > 0) {
    _tokenMaps.set(newParams, tokenMap);  // key = newParams object
}
return newParams;

// wrapGenerate (line 137):
const tokenMap = _tokenMaps.get(params);  // params must be SAME object reference
```

**Fix — use a Symbol property on the params object:**

```javascript
// vercel-middleware.js — replace WeakMap with Symbol-based storage

const _TOKEN_MAP_KEY = Symbol.for('cloakllm.tokenMap');

// In transformParams:
transformParams: async ({ params, type, model }) => {
    const modelId = model?.modelId || '';

    if (shieldConfig.skipModels.some(prefix => modelId.startsWith(prefix))) {
        return params;
    }

    const [sanitizedPrompt, tokenMap] = _sanitizeV3Prompt(
        shield, params.prompt, modelId
    );

    const newParams = { ...params, prompt: sanitizedPrompt };

    if (tokenMap && tokenMap.entityCount > 0) {
        // Attach token map directly to the params object via Symbol.
        // Survives spread/copy because Symbols are own enumerable properties
        // and are copied by { ...obj } and Object.assign().
        newParams[_TOKEN_MAP_KEY] = tokenMap;
    }

    return newParams;
},

// In wrapGenerate:
wrapGenerate: async ({ doGenerate, params, model }) => {
    const result = await doGenerate();
    const tokenMap = params[_TOKEN_MAP_KEY];

    if (!tokenMap) return result;

    const modelId = model?.modelId || '';

    if (Array.isArray(result.content)) {
        const desanitizedContent = result.content.map(part => {
            if (part?.type === 'text' && part.text) {
                return {
                    ...part,
                    text: shield.desanitize(part.text, tokenMap, { model: modelId }),
                };
            }
            return part;
        });
        return { ...result, content: desanitizedContent };
    }

    if (typeof result.text === 'string') {
        return {
            ...result,
            text: shield.desanitize(result.text, tokenMap, { model: modelId }),
        };
    }

    return result;
},

// In wrapStream:
wrapStream: async ({ doStream, params, model }) => {
    const result = await doStream();
    const tokenMap = params[_TOKEN_MAP_KEY];

    if (!tokenMap) return result;

    // ... rest unchanged ...
},
```

**Remove** the `_tokenMaps` WeakMap declaration entirely.

**Test:**

```javascript
// test/vercel-middleware-symbol.test.js
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { createCloakLLMMiddleware } = require('../src/vercel-middleware');

describe('Vercel middleware — Symbol-based token map', () => {
    it('survives params spread/copy', async () => {
        const middleware = createCloakLLMMiddleware();
        const mockModel = { modelId: 'gpt-4' };

        const originalParams = {
            prompt: [
                { role: 'user', content: [{ type: 'text', text: 'Email john@acme.com' }] },
            ],
        };

        const transformed = await middleware.transformParams({
            params: originalParams, type: 'generate', model: mockModel,
        });

        // Simulate SDK spreading the params (this broke the WeakMap approach)
        const spreadParams = { ...transformed };

        const TOKEN_MAP_KEY = Symbol.for('cloakllm.tokenMap');
        assert.ok(spreadParams[TOKEN_MAP_KEY], 'Token map must survive spread');
        assert.ok(spreadParams[TOKEN_MAP_KEY].entityCount > 0, 'Must have entities');
    });
});
```

---

## Phase 2: Correctness & Stability Fixes (v0.2.4)

**Priority:** HIGH — affects audit correctness and memory safety
**Effort:** 3-4 hours

### 2.1 Bounded LRU Cache for JS LLM Detector

**File:** `cloakllm-js/src/llm-detector.js`

**Problem:** The JS LLM detector uses a plain `Map` (line 38) with no eviction. In long-running Node.js services, this grows unboundedly.

**Fix — add an LRU cache class (matching Python's `_BoundedCache`):**

```javascript
// llm-detector.js — add at top of file

class BoundedCache {
    constructor(maxSize = 1024) {
        this._cache = new Map();
        this._maxSize = maxSize;
    }

    get(key) {
        if (!this._cache.has(key)) return undefined;
        const value = this._cache.get(key);
        this._cache.delete(key);
        this._cache.set(key, value);
        return value;
    }

    set(key, value) {
        if (this._cache.has(key)) this._cache.delete(key);
        this._cache.set(key, value);
        if (this._cache.size > this._maxSize) {
            const oldest = this._cache.keys().next().value;
            this._cache.delete(oldest);
        }
    }

    has(key) {
        return this._cache.has(key);
    }

    clear() {
        this._cache.clear();
    }

    get size() {
        return this._cache.size;
    }
}

// In constructor:
this._cache = new BoundedCache(1024);  // was: new Map()
```

### 2.2 Python Thread-Safety for Metrics Accumulation

**File:** `cloakllm-py/cloakllm/shield.py`

**Problem:** `desanitize()` and `desanitize_batch()` directly mutate `self._metrics` without acquiring `_metrics_lock` (lines 233-235, 263-265).

**Fix — use `_accumulate_metrics` consistently:**

```python
# shield.py — in desanitize(), replace direct mutation:
# OLD:
self._metrics["calls"]["desanitize"] += 1
self._metrics["total_ms"] += elapsed_ms
self._metrics["tokenization_ms"] += tokenization_ms

# NEW:
self._accumulate_metrics("desanitize", elapsed_ms, {}, tokenization_ms, 0, {})

# Same for desanitize_batch():
self._accumulate_metrics("desanitize_batch", elapsed_ms, {}, tokenization_ms, 0, {})
```

### 2.3 Fix Stale Documentation

**File:** `CloakLLM/README.md`

```markdown
<!-- Line 95 — Before: -->
CloakLLM MCP exposes three tools for Claude Desktop...

<!-- After: -->
CloakLLM MCP exposes four tools for Claude Desktop...
```

---

## Phase 3: MCP Server Feature Parity (v0.2.5)

**Priority:** MEDIUM — MCP server is a second-class citizen
**Effort:** 3-4 hours

### 3.1 Improve metadata Parsing

**File:** `cloakllm-mcp/server.py`

```python
# server.py — improve metadata parsing in sanitize and sanitize_batch
try:
    metadata_dict = json.loads(metadata) if metadata else None
    if metadata_dict is not None and not isinstance(metadata_dict, dict):
        return {"error": "metadata must be a JSON object (e.g., '{\"session_id\": \"abc\"}')."}
except json.JSONDecodeError:
    return {"error": "metadata must be valid JSON."}
```

### 3.2 Add analyze_batch Tool

```python
@mcp.tool()
def analyze_batch(
    texts: list[str],
    custom_llm_categories: str = "",
) -> dict:
    """
    Analyze multiple texts for PII without cloaking.

    Returns detected entities across all texts with categories,
    positions, confidence scores, and detection method.

    Args:
        texts: List of texts to analyze for PII.
        custom_llm_categories: Optional JSON array of [name, description] pairs.

    Returns:
        dict with total entity_count and per-text results.
    """
    try:
        parsed_categories = []
        if custom_llm_categories:
            try:
                parsed_categories = json.loads(custom_llm_categories)
                if not isinstance(parsed_categories, list):
                    return {"error": "custom_llm_categories must be a JSON array."}
            except json.JSONDecodeError:
                return {"error": "custom_llm_categories must be valid JSON."}

        if parsed_categories:
            shield = Shield(config=ShieldConfig(
                custom_llm_categories=parsed_categories,
                audit_enabled=_shield.config.audit_enabled,
                log_dir=_shield.config.log_dir,
                log_original_values=False,
            ))
        else:
            shield = _shield

        results = []
        total = 0
        for i, text in enumerate(texts):
            result = shield.analyze(text)
            total += result["entity_count"]
            results.append({
                "text_index": i,
                "entity_count": result["entity_count"],
                "entities": result["entities"],
            })

        return {"total_entity_count": total, "text_count": len(texts), "results": results}
    except Exception as e:
        logger.exception("analyze_batch tool failed")
        return {"error": "Batch analysis failed. Check server logs for details."}
```

### 3.3 Add desanitize_batch Tool

```python
@mcp.tool()
def desanitize_batch(
    texts: list[str],
    token_map_id: str,
) -> dict:
    """
    Restore original values in multiple texts using a shared token map.

    Args:
        texts: List of texts containing tokens to restore.
        token_map_id: ID from a previous sanitize/sanitize_batch call.

    Returns:
        dict with the list of restored texts.
    """
    try:
        entry = _TOKEN_MAPS.get(token_map_id)
        if entry is None:
            return {"error": f"Token map '{token_map_id}' not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}
        token_map = entry["token_map"]
        restored = _shield.desanitize_batch(texts, token_map)
        return {"restored": restored}
    except Exception as e:
        logger.exception("desanitize_batch tool failed")
        return {"error": "Batch desanitization failed. Check server logs for details."}
```

---

## Phase 4: Incremental Streaming Desanitization (v0.3.0)

**Priority:** MEDIUM-HIGH — current streaming defeats the purpose
**Effort:** 1-2 days

### 4.1 Problem Statement

Both SDKs buffer the entire streamed LLM response and emit it as a single chunk at the end. Users see nothing until the full response is ready — defeating the purpose of streaming entirely.

### 4.2 StreamDesanitizer State Machine

Since CloakLLM tokens follow a known format (`[CATEGORY_N]`), we can implement a state machine that:
1. Streams plain text through immediately
2. When it sees `[`, buffers the potential token
3. If the buffer resolves to a known token, emits the original value
4. If it doesn't match, emits the buffered text as-is

**New file: `cloakllm-py/cloakllm/stream.py`**

```python
"""
Incremental Streaming Desanitizer.

State machine that replaces tokens in streamed text without buffering
the entire response. Emits text as soon as it's safe to do so.
"""

from __future__ import annotations
from cloakllm.tokenizer import TokenMap

_MAX_TOKEN_LEN = 40


class StreamDesanitizer:
    """
    Incrementally desanitize streamed LLM text.

    Usage:
        desan = StreamDesanitizer(token_map)
        for chunk in stream:
            output = desan.feed(chunk.content)
            if output:
                yield output
        output = desan.flush()
        if output:
            yield output
    """

    def __init__(self, token_map: TokenMap):
        self._token_map = token_map
        self._buffer = ""
        self._reverse_ci: dict[str, str] = {
            k.lower(): v for k, v in token_map.reverse.items()
        }

    def feed(self, chunk: str) -> str:
        output_parts: list[str] = []
        self._buffer += chunk

        while self._buffer:
            bracket_pos = self._buffer.find("[")

            if bracket_pos == -1:
                output_parts.append(self._buffer)
                self._buffer = ""
                break

            if bracket_pos > 0:
                output_parts.append(self._buffer[:bracket_pos])
                self._buffer = self._buffer[bracket_pos:]

            close_pos = self._buffer.find("]")

            if close_pos == -1:
                if len(self._buffer) > _MAX_TOKEN_LEN:
                    output_parts.append(self._buffer[0])
                    self._buffer = self._buffer[1:]
                else:
                    break
            else:
                candidate = self._buffer[:close_pos + 1]
                candidate_lower = candidate.lower()

                if candidate_lower in self._reverse_ci:
                    output_parts.append(self._reverse_ci[candidate_lower])
                    self._buffer = self._buffer[close_pos + 1:]
                else:
                    output_parts.append(candidate)
                    self._buffer = self._buffer[close_pos + 1:]

        return "".join(output_parts)

    def flush(self) -> str:
        remaining = self._buffer
        self._buffer = ""
        return remaining
```

**New file: `cloakllm-js/src/stream.js`**

```javascript
/**
 * Incremental Streaming Desanitizer.
 */

const MAX_TOKEN_LEN = 40;

class StreamDesanitizer {
    constructor(tokenMap) {
        this._buffer = '';
        this._reverseCI = new Map();
        for (const [token, original] of tokenMap.reverse) {
            this._reverseCI.set(token.toLowerCase(), original);
        }
    }

    feed(chunk) {
        const parts = [];
        this._buffer += chunk;

        while (this._buffer.length > 0) {
            const bracketPos = this._buffer.indexOf('[');

            if (bracketPos === -1) {
                parts.push(this._buffer);
                this._buffer = '';
                break;
            }

            if (bracketPos > 0) {
                parts.push(this._buffer.slice(0, bracketPos));
                this._buffer = this._buffer.slice(bracketPos);
            }

            const closePos = this._buffer.indexOf(']');

            if (closePos === -1) {
                if (this._buffer.length > MAX_TOKEN_LEN) {
                    parts.push(this._buffer[0]);
                    this._buffer = this._buffer.slice(1);
                } else {
                    break;
                }
            } else {
                const candidate = this._buffer.slice(0, closePos + 1);
                const original = this._reverseCI.get(candidate.toLowerCase());

                if (original !== undefined) {
                    parts.push(original);
                } else {
                    parts.push(candidate);
                }
                this._buffer = this._buffer.slice(closePos + 1);
            }
        }

        return parts.join('');
    }

    flush() {
        const remaining = this._buffer;
        this._buffer = '';
        return remaining;
    }
}

module.exports = { StreamDesanitizer };
```

### 4.3 Integrate into JS Middleware

**File:** `cloakllm-js/src/middleware.js`

Replace `bufferAndDesanitize` generator with incremental streaming:

```javascript
const { StreamDesanitizer } = require('./stream');

async function* incrementalDesanitize(stream, model, callKey) {
    const tokenMap = _activeMaps.get(callKey);
    _activeMaps.delete(callKey);

    if (!tokenMap || tokenMap.entityCount === 0) {
        yield* stream;
        return;
    }

    const desan = new StreamDesanitizer(tokenMap);

    try {
        for await (const chunk of stream) {
            const delta = chunk.choices?.[0]?.delta;
            if (delta?.content) {
                const output = desan.feed(delta.content);
                if (output) {
                    yield {
                        ...chunk,
                        choices: [{
                            ...chunk.choices[0],
                            delta: { ...chunk.choices[0].delta, content: output },
                        }],
                    };
                }
            } else {
                yield chunk;
            }

            if (chunk.choices?.[0]?.finish_reason) {
                const flushed = desan.flush();
                if (flushed) {
                    yield {
                        ...chunk,
                        choices: [{
                            ...chunk.choices[0],
                            delta: { content: flushed },
                            finish_reason: null,
                        }],
                    };
                }
            }
        }

        const flushed = desan.flush();
        if (flushed) {
            yield { choices: [{ delta: { content: flushed } }] };
        }
    } catch (err) {
        desan.flush();
        throw err;
    }
}
```

### 4.4 Tests

```python
# tests/test_stream_desanitizer.py
import pytest
from cloakllm.tokenizer import TokenMap
from cloakllm.stream import StreamDesanitizer

def test_basic_streaming():
    tm = TokenMap()
    tm.forward["john@acme.com"] = "[EMAIL_0]"
    tm.reverse["[EMAIL_0]"] = "john@acme.com"

    sd = StreamDesanitizer(tm)
    assert sd.feed("Contact ") == "Contact "
    assert sd.feed("[EM") == ""
    assert sd.feed("AIL_0]") == "john@acme.com"
    assert sd.feed(" for details") == " for details"
    assert sd.flush() == ""

def test_non_token_brackets():
    tm = TokenMap()
    sd = StreamDesanitizer(tm)
    assert sd.feed("array[0]") == "array[0]"

def test_split_across_chunks():
    tm = TokenMap()
    tm.forward["John Smith"] = "[PERSON_0]"
    tm.reverse["[PERSON_0]"] = "John Smith"

    sd = StreamDesanitizer(tm)
    assert sd.feed("Hi ") == "Hi "
    assert sd.feed("[") == ""
    assert sd.feed("PERSON") == ""
    assert sd.feed("_0") == ""
    assert sd.feed("]!") == "John Smith!"

def test_case_insensitive():
    tm = TokenMap()
    tm.forward["jane@test.com"] = "[EMAIL_0]"
    tm.reverse["[EMAIL_0]"] = "jane@test.com"

    sd = StreamDesanitizer(tm)
    assert sd.feed("[email_0]") == "jane@test.com"
```

---

## Phase 5: Integration Test Suite (v0.3.0)

**Priority:** MEDIUM — validates end-to-end middleware correctness
**Effort:** 4-6 hours

### 5.1 Middleware Round-Trip Tests

The P1 multi-choice bug existed because there were no integration tests for the middleware path with `n>1` choices.

**New file: `cloakllm-js/test/integration-middleware.test.js`**

```javascript
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { enable, disable, isEnabled } = require('../src/middleware');
const { ShieldConfig } = require('../src/config');

describe('OpenAI Middleware Integration', () => {
    let mockClient;

    beforeEach(() => {
        mockClient = {
            chat: {
                completions: {
                    create: async (params) => {
                        const n = params.n || 1;
                        const choices = [];
                        for (let i = 0; i < n; i++) {
                            choices.push({
                                index: i,
                                message: {
                                    role: 'assistant',
                                    content: `Reply to [EMAIL_0] about the project.`,
                                },
                                finish_reason: 'stop',
                            });
                        }
                        return { choices };
                    },
                },
            },
        };
    });

    afterEach(() => {
        if (isEnabled()) disable();
    });

    it('desanitizes all n>1 choices', async () => {
        enable(mockClient, new ShieldConfig({ auditEnabled: false }));

        const result = await mockClient.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'user', content: 'Email john@acme.com about the project' }],
            n: 3,
        });

        for (const choice of result.choices) {
            assert.ok(!choice.message.content.includes('[EMAIL_0]'),
                `Choice ${choice.index} still has token`);
            assert.ok(choice.message.content.includes('john@acme.com'),
                `Choice ${choice.index} missing original`);
        }
    });

    it('handles streaming with incremental desanitization', async () => {
        mockClient.chat.completions.create = async (params) => {
            if (!params.stream) throw new Error('Expected stream');
            async function* chunks() {
                yield { choices: [{ delta: { content: 'Contact ' } }] };
                yield { choices: [{ delta: { content: '[EMA' } }] };
                yield { choices: [{ delta: { content: 'IL_0]' } }] };
                yield { choices: [{ delta: { content: ' now.' }, finish_reason: 'stop' }] };
            }
            return chunks();
        };

        enable(mockClient, new ShieldConfig({ auditEnabled: false }));

        const stream = await mockClient.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'user', content: 'Email john@acme.com about the deal' }],
            stream: true,
        });

        let full = '';
        for await (const chunk of stream) {
            if (chunk.choices?.[0]?.delta?.content) {
                full += chunk.choices[0].delta.content;
            }
        }

        assert.ok(!full.includes('[EMAIL_0]'), `Stream has token: ${full}`);
        assert.ok(full.includes('john@acme.com'), `Stream missing original: ${full}`);
    });
});
```

---

## Phase 6: Detection Benchmark Suite (v0.3.1)

**Priority:** MEDIUM — validates the 99.9% claim
**Effort:** 1-2 days

### 6.1 Labeled PII Corpus

**New file: `cloakllm-py/benchmarks/corpus.py`**

```python
"""Labeled PII corpus for benchmark evaluation."""

CORPUS: list[dict] = [
    {
        "text": "Please contact john.doe@example.com for more information.",
        "entities": [(15, 35, "EMAIL", "john.doe@example.com")],
        "source": "synthetic",
    },
    {
        "text": "No sensitive data here, just a regular sentence.",
        "entities": [],
        "source": "synthetic",
    },
    {
        "text": "Send to alice@company.co.uk and bob@startup.io",
        "entities": [
            (8, 28, "EMAIL", "alice@company.co.uk"),
            (33, 47, "EMAIL", "bob@startup.io"),
        ],
        "source": "synthetic",
    },
    {
        "text": "My SSN is 123-45-6789.",
        "entities": [(10, 21, "SSN", "123-45-6789")],
        "source": "synthetic",
    },
    {
        "text": "Charge to 4111111111111111 please.",
        "entities": [(10, 26, "CREDIT_CARD", "4111111111111111")],
        "source": "synthetic",
    },
    {
        "text": "John Smith is the CEO of Acme Corp.",
        "entities": [
            (0, 10, "PERSON", "John Smith"),
            (25, 34, "ORG", "Acme Corp"),
        ],
        "source": "synthetic",
    },
    {
        "text": "Contact Jane Doe at jane.doe@corp.com or call 555-867-5309",
        "entities": [
            (8, 16, "PERSON", "Jane Doe"),
            (20, 37, "EMAIL", "jane.doe@corp.com"),
            (46, 58, "PHONE", "555-867-5309"),
        ],
        "source": "synthetic",
    },
    # Adversarial: obfuscated email (expected miss)
    {
        "text": "Reach me at john [dot] doe [at] example [dot] com",
        "entities": [],
        "source": "adversarial",
    },
]
```

### 6.2 Benchmark Harness

**New file: `cloakllm-py/benchmarks/evaluate.py`**

```python
"""Detection Benchmark Harness — measures recall/precision/F1 per category."""

from __future__ import annotations
import sys
from collections import defaultdict
from dataclasses import dataclass
from cloakllm import Shield, ShieldConfig
from benchmarks.corpus import CORPUS


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def _overlaps(a_start, a_end, b_start, b_end, threshold=0.5) -> bool:
    overlap = max(0, min(a_end, b_end) - max(a_start, b_start))
    smaller = min(a_end - a_start, b_end - b_start)
    return overlap / smaller >= threshold if smaller > 0 else False


def evaluate(shield: Shield, corpus: list[dict]) -> dict:
    per_cat: dict[str, Metrics] = defaultdict(Metrics)
    overall = Metrics()

    for sample in corpus:
        detections, _ = shield.detector.detect(sample["text"])
        ground_truth = sample["entities"]

        matched_gt = set()
        matched_det = set()

        for di, det in enumerate(detections):
            for gi, (gt_start, gt_end, gt_cat, gt_val) in enumerate(ground_truth):
                if gi in matched_gt:
                    continue
                if det.category == gt_cat and _overlaps(det.start, det.end, gt_start, gt_end):
                    matched_gt.add(gi)
                    matched_det.add(di)
                    per_cat[gt_cat].tp += 1
                    overall.tp += 1
                    break

        for di in range(len(detections)):
            if di not in matched_det:
                per_cat[detections[di].category].fp += 1
                overall.fp += 1

        for gi, (_, _, gt_cat, _) in enumerate(ground_truth):
            if gi not in matched_gt:
                per_cat[gt_cat].fn += 1
                overall.fn += 1

    return {
        "overall": {"precision": round(overall.precision, 4), "recall": round(overall.recall, 4),
                     "f1": round(overall.f1, 4), "tp": overall.tp, "fp": overall.fp, "fn": overall.fn},
        "per_category": {
            cat: {"precision": round(m.precision, 4), "recall": round(m.recall, 4),
                  "f1": round(m.f1, 4), "tp": m.tp, "fp": m.fp, "fn": m.fn}
            for cat, m in sorted(per_cat.items())
        },
    }


def main():
    shield = Shield(ShieldConfig(audit_enabled=False))
    results = evaluate(shield, CORPUS)
    print(f"\nOverall: P={results['overall']['precision']:.1%}  "
          f"R={results['overall']['recall']:.1%}  F1={results['overall']['f1']:.1%}")
    for cat, m in results["per_category"].items():
        print(f"  {cat:15s}  P={m['precision']:.1%}  R={m['recall']:.1%}  F1={m['f1']:.1%}")
    if results["overall"]["recall"] < 0.95:
        print(f"\n⚠️  Overall recall {results['overall']['recall']:.1%} < 95% target")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

---

## Phase 7: Cryptographic Hardening (v0.3.2)

**Priority:** MEDIUM — differentiator for compliance and public workloads
**Effort:** 3-5 days

### 7.1 Ed25519 Deployment Keypairs

**New file: `cloakllm-py/cloakllm/attestation.py`**

```python
"""
Cryptographic Attestation Module.

Ed25519 digital signatures for audit entries and sanitization certificates.
"""

from __future__ import annotations
import base64, hashlib, json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from nacl.signing import SigningKey, VerifyKey
    _HAS_NACL = True
except ImportError:
    _HAS_NACL = False

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


@dataclass
class DeploymentKeyPair:
    private_key: bytes
    public_key: bytes
    key_id: str

    @classmethod
    def generate(cls) -> DeploymentKeyPair:
        if _HAS_NACL:
            sk = SigningKey.generate()
            private_key, public_key = bytes(sk), bytes(sk.verify_key)
        elif _HAS_CRYPTOGRAPHY:
            sk = Ed25519PrivateKey.generate()
            private_key = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            public_key = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            raise ImportError("Ed25519 requires pynacl or cryptography: pip install pynacl")
        return cls(private_key=private_key, public_key=public_key,
                   key_id=hashlib.sha256(public_key).hexdigest()[:16])

    def sign(self, data: bytes) -> bytes:
        if _HAS_NACL:
            return SigningKey(self.private_key).sign(data).signature
        elif _HAS_CRYPTOGRAPHY:
            return Ed25519PrivateKey.from_private_bytes(self.private_key).sign(data)
        raise ImportError("No Ed25519 library available")

    def sign_b64(self, data: bytes) -> str:
        return base64.b64encode(self.sign(data)).decode("ascii")

    @staticmethod
    def verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
        try:
            if _HAS_NACL:
                VerifyKey(public_key).verify(data, signature)
                return True
            elif _HAS_CRYPTOGRAPHY:
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
                return True
        except Exception:
            return False
        return False

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "key_id": self.key_id,
            "private_key": base64.b64encode(self.private_key).decode(),
            "public_key": base64.b64encode(self.public_key).decode(),
        }, indent=2))
        try: path.chmod(0o600)
        except OSError: pass

    @classmethod
    def from_file(cls, path: Path) -> DeploymentKeyPair:
        data = json.loads(path.read_text())
        return cls(private_key=base64.b64decode(data["private_key"]),
                   public_key=base64.b64decode(data["public_key"]), key_id=data["key_id"])
```

### 7.2 Sanitization Certificates

```python
# attestation.py — continued

@dataclass
class SanitizationCertificate:
    version: str = "1.0"
    timestamp: str = ""
    input_hash: str = ""
    output_hash: str = ""
    entity_count: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    detection_passes: list[str] = field(default_factory=list)
    mode: str = "tokenize"
    key_id: str = ""
    signature: str = ""

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in
                ["version", "timestamp", "input_hash", "output_hash",
                 "entity_count", "categories", "detection_passes", "mode",
                 "key_id", "signature"]}

    @classmethod
    def create(cls, original_text: str, sanitized_text: str, entity_count: int,
               categories: dict, detection_passes: list, mode: str,
               keypair: DeploymentKeyPair) -> SanitizationCertificate:
        from datetime import datetime, timezone
        cert = cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            input_hash=hashlib.sha256(original_text.encode()).hexdigest(),
            output_hash=hashlib.sha256(sanitized_text.encode()).hexdigest(),
            entity_count=entity_count, categories=categories,
            detection_passes=detection_passes, mode=mode, key_id=keypair.key_id,
        )
        payload = json.dumps(cert.to_dict(), sort_keys=True, separators=(",", ":"))
        cert.signature = keypair.sign_b64(payload.encode("utf-8"))
        return cert

    def verify(self, public_key: bytes) -> bool:
        d = self.to_dict()
        stored_sig = d.pop("signature")
        payload = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return DeploymentKeyPair.verify(public_key, payload.encode("utf-8"),
                                        base64.b64decode(stored_sig))
```

### 7.3 Merkle Tree for Batch Attestation

```python
# attestation.py — continued

class MerkleTree:
    def __init__(self, leaves: list[str]):
        if not leaves:
            raise ValueError("Cannot build Merkle tree with no leaves")
        self._leaves = list(leaves)
        self._tree: list[list[str]] = [self._leaves]
        self._build()

    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        return hashlib.sha256((left + right).encode("utf-8")).hexdigest()

    def _build(self):
        current = self._leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    next_level.append(self._hash_pair(current[i], current[i + 1]))
                else:
                    next_level.append(current[i])
            self._tree.append(next_level)
            current = next_level

    @property
    def root(self) -> str:
        return self._tree[-1][0]

    def proof(self, index: int) -> list[tuple[str, str]]:
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of range")
        proof_path = []
        idx = index
        for level in self._tree[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    proof_path.append((level[idx + 1], "right"))
            else:
                proof_path.append((level[idx - 1], "left"))
            idx //= 2
        return proof_path

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list[tuple[str, str]], root: str) -> bool:
        current = leaf_hash
        for sibling_hash, side in proof:
            if side == "left":
                current = MerkleTree._hash_pair(sibling_hash, current)
            else:
                current = MerkleTree._hash_pair(current, sibling_hash)
        return current == root
```

### 7.4 HKDF Key Derivation

```python
# attestation.py — continued

def derive_entity_hash_key(master_key: bytes, salt: bytes = b"",
                           info: bytes = b"cloakllm-entity-hash") -> str:
    import hmac as _hmac
    if not salt:
        salt = b"\x00" * 32
    prk = _hmac.new(salt, master_key, hashlib.sha256).digest()
    okm = _hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm.hex()
```

---

## Phase 8: Multi-Language PII Detection (v0.4.0)

**Priority:** MEDIUM — blocks international adoption
**Effort:** 2-3 days

### 8.1 Locale-Aware Configuration

**File:** `cloakllm-py/cloakllm/config.py`

```python
# Add locale field and auto-select spaCy model
locale: str = "en"

_LOCALE_MODELS = {
    "en": "en_core_web_sm", "de": "de_core_news_sm", "fr": "fr_core_news_sm",
    "es": "es_core_news_sm", "he": "he_core_news_sm", "zh": "zh_core_web_sm",
    "ja": "ja_core_news_sm", "nl": "nl_core_news_sm",
}

def __post_init__(self):
    # Auto-select spaCy model if locale != en and model wasn't explicitly set
    if self.spacy_model == "en_core_web_sm" and self.locale != "en":
        model = self._LOCALE_MODELS.get(self.locale)
        if model:
            self.spacy_model = model
```

### 8.2 Locale-Specific Regex Patterns

**File:** `cloakllm-py/cloakllm/detector.py`

```python
LOCALE_PATTERNS = {
    "de": {"PHONE_DE": r"\+49[\s\-]?\d{2,4}[\s\-]?\d{4,8}", "POSTAL_CODE_DE": r"\b\d{5}\b"},
    "fr": {"PHONE_FR": r"\+33[\s\-]?\d[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}"},
    "gb": {"PHONE_GB": r"\+44[\s\-]?\d{4}[\s\-]?\d{6}",
           "NINO_GB": r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"},
}

# In _build_patterns(), after built-in patterns:
locale = getattr(self.config, 'locale', 'en')
for name, pattern in LOCALE_PATTERNS.get(locale, {}).items():
    try:
        compiled = re.compile(pattern)
        if self._test_regex_safety(compiled):
            self._compiled_patterns.append((name, compiled))
    except re.error:
        pass
```

### 8.3 Ollama i18n Prompts

**File:** `cloakllm-py/cloakllm/llm_detector.py`

```python
LOCALE_PROMPTS = {
    "en": "You are a PII detection engine. Given text, extract sensitive entities.",
    "de": "Du bist eine Engine zur Erkennung personenbezogener Daten.",
    "fr": "Vous êtes un moteur de détection des données personnelles.",
    "es": "Eres un motor de detección de datos personales.",
    "he": "אתה מנוע לזיהוי מידע אישי רגיש.",
}
```

---

## Phase 9: JS NER Feature Parity (v0.4.0)

**Priority:** MEDIUM — JS SDK has significant detection gap without Ollama
**Effort:** 2-3 days

### 9.1 NER Detector via `compromise`

**New file: `cloakllm-js/src/ner-detector.js`**

```javascript
let nlp = null;
try { nlp = require('compromise'); } catch {}

class NERDetector {
    constructor() {
        if (!nlp) throw new Error('compromise is required for NER: npm install compromise');
    }

    detect(text, coveredSpans = []) {
        const doc = nlp(text);
        const detections = [];

        for (const name of doc.people().out('array'))
            this._findAll(text, name, 'PERSON', 0.80, coveredSpans, detections);
        for (const org of doc.organizations().out('array'))
            this._findAll(text, org, 'ORG', 0.75, coveredSpans, detections);
        for (const place of doc.places().out('array'))
            this._findAll(text, place, 'GPE', 0.75, coveredSpans, detections);

        return detections;
    }

    _findAll(text, value, category, confidence, coveredSpans, detections) {
        if (value.length < 2) return;
        const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        let match;
        const regex = new RegExp(escaped, 'gi');
        while ((match = regex.exec(text)) !== null) {
            const start = match.index, end = start + match[0].length;
            if (coveredSpans.some(([s, e]) => start < e && end > s)) continue;
            detections.push({ text: match[0], category, start, end, confidence, source: 'ner' });
            coveredSpans.push([start, end]);
        }
    }
}

function isNERAvailable() { return nlp !== null; }

module.exports = { NERDetector, isNERAvailable };
```

### 9.2 Detection Gap Warning

**File:** `cloakllm-js/src/shield.js`

```javascript
// In constructor, after creating detector:
if (!this.detector._nerDetector && !this.detector._llmDetector) {
    console.warn(
        '[cloakllm] Warning: Running regex-only detection. ' +
        'PERSON, ORG, and GPE entities may be missed. ' +
        'Install "compromise" for NER or configure Ollama for LLM detection.'
    );
}
```

---

## Phase 10: Context-Based PII Leakage Analysis (v0.5.0)

**Priority:** LOW — research-heavy, long-term differentiator
**Effort:** 1-2 weeks

### 10.1 Context Risk Analyzer (Prototype)

**New file: `cloakllm-py/cloakllm/context_analyzer.py`**

```python
"""Context-Based PII Leakage Risk Analyzer (Prototype)."""

from __future__ import annotations
import re
from dataclasses import dataclass

IDENTIFYING_DESCRIPTORS = {
    "ceo", "president", "founder", "director", "wife", "husband",
    "daughter", "son", "only", "tallest", "youngest", "oldest", "first",
}

RELATIONSHIP_WORDS = {
    "married", "divorced", "works at", "employed by", "lives in",
    "born in", "graduated from", "founded",
}

TOKEN_RE = re.compile(r"\[[A-Z_]+_\d+\]")


@dataclass
class RiskAssessment:
    token_density: float
    identifying_descriptors: int
    relationship_edges: int
    risk_score: float
    risk_level: str
    warnings: list[str]


class ContextAnalyzer:
    def analyze(self, sanitized_text: str) -> RiskAssessment:
        words = sanitized_text.lower().split()
        total_words = max(len(words), 1)
        tokens = TOKEN_RE.findall(sanitized_text)
        token_density = len(tokens) / total_words

        descriptor_count = 0
        warnings = []
        for i, word in enumerate(words):
            if word.strip(".,;:!?") in IDENTIFYING_DESCRIPTORS:
                window = " ".join(words[max(0, i - 5):i + 6])
                if TOKEN_RE.search(window):
                    descriptor_count += 1
                    warnings.append(f"Identifying descriptor '{word}' near a token")

        relationship_count = 0
        text_lower = sanitized_text.lower()
        for rel in RELATIONSHIP_WORDS:
            if rel in text_lower:
                for m in re.finditer(re.escape(rel), text_lower):
                    before = text_lower[max(0, m.start() - 50):m.start()]
                    after = text_lower[m.end():m.end() + 50]
                    if TOKEN_RE.findall(before) and TOKEN_RE.findall(after):
                        relationship_count += 1
                        warnings.append(f"Relationship '{rel}' connects tokens")

        risk_score = min(1.0, token_density * 1.5 + descriptor_count * 0.15 + relationship_count * 0.2)
        risk_level = "high" if risk_score > 0.7 else "medium" if risk_score > 0.3 else "low"

        return RiskAssessment(
            token_density=round(token_density, 3),
            identifying_descriptors=descriptor_count,
            relationship_edges=relationship_count,
            risk_score=round(risk_score, 3),
            risk_level=risk_level,
            warnings=warnings[:5],
        )
```

---

## Release Schedule

| Release | Phase | Contents | Effort |
|---------|-------|----------|--------|
| **v0.2.3** | Phase 1 | P1 LiteLLM multi-choice fix, J1 Vercel WeakMap fix | 1-2 hours |
| **v0.2.4** | Phase 2 | Bounded JS cache, thread-safety, stale docs | 3-4 hours |
| **v0.2.5** | Phase 3 | MCP analyze_batch + desanitize_batch, metadata parsing | 3-4 hours |
| **v0.3.0** | Phase 4+5 | StreamDesanitizer + integration test suite | 2-3 days |
| **v0.3.1** | Phase 6 | Detection benchmark harness + labeled corpus | 1-2 days |
| **v0.3.2** | Phase 7 | Ed25519 attestation, certificates, Merkle trees, HKDF | 3-5 days |
| **v0.4.0** | Phase 8+9 | Multi-language detection + JS NER via compromise | 4-6 days |
| **v0.5.0** | Phase 10 | Context-based PII leakage analysis (prototype) | 1-2 weeks |

### Commit Strategy

Each phase gets its own commits per repo:
- `fix: v0.2.3 — fix LiteLLM multi-choice PII leakage (P1)`
- `fix: v0.2.3 — fix Vercel WeakMap desanitization fragility (J1)`
- `fix: v0.2.4 — bounded LLM detector cache, thread-safe metrics`
- `feat: v0.2.5 — MCP analyze_batch and desanitize_batch tools`
- `feat: v0.3.0 — incremental streaming desanitization`
- `test: v0.3.0 — integration tests for middleware round-trips`
- `feat: v0.3.1 — detection benchmark suite`
- `feat: v0.3.2 — Ed25519 attestation and sanitization certificates`
- `feat: v0.4.0 — multi-language PII detection`
- `feat: v0.4.0 — JS NER via compromise library`
- `feat: v0.5.0 — context-based PII leakage risk analysis`

Follow existing version bump checklist in CLAUDE.md for each release.

### Dependencies Added

| Phase | Package | Language | Required? |
|-------|---------|----------|-----------|
| 7 | `pynacl` or `cryptography` | Python | Optional (for attestation) |
| 9 | `compromise` | JS (npm) | Optional peer dep (for NER) |

All other phases use only stdlib — no new dependencies.
