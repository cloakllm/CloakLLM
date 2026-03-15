# CloakLLM Implementation Plan

**Based on:** CODEBASE_REPORT.md findings and recommendations
**Target release:** v0.2.3 (critical fixes) → v0.3.0 (feature improvements)
**Date:** 2026-03-13

---

## Table of Contents

1. [Phase 1: Critical Security Fixes (v0.2.3)](#phase-1-critical-security-fixes-v023)
2. [Phase 2: Correctness Fixes (v0.2.4)](#phase-2-correctness-fixes-v024)
3. [Phase 3: MCP Feature Parity (v0.2.5)](#phase-3-mcp-feature-parity-v025)
4. [Phase 4: Streaming Desanitization (v0.3.0)](#phase-4-streaming-desanitization-v030)
5. [Phase 5: Integration Tests](#phase-5-integration-tests)
6. [Phase 6: Benchmark Suite](#phase-6-benchmark-suite)
7. [Phase 7: Cryptographic Hardening (v0.3.2)](#phase-7-cryptographic-hardening-v032)
8. [Phase 8: Multi-Language PII Detection (v0.4.0)](#phase-8-multi-language-pii-detection-v040)
9. [Phase 9: JS NER Feature Parity (v0.4.0)](#phase-9-js-ner-feature-parity-v040)
10. [Phase 10: Context-Based PII Leakage Analysis (v0.5.0)](#phase-10-context-based-pii-leakage-analysis-v050)

---

## Phase 1: Critical Security Fixes (v0.2.3)

**Priority:** IMMEDIATE — PII leakage in production
**Effort:** Small (1-2 hours)
**Bugs fixed:** P1, J1

### 1.1 Fix LiteLLM Multi-Choice Desanitization (P1)

**File:** `cloakllm-py/cloakllm/integrations/litellm_middleware.py`
**Problem:** `_desanitize_response()` pops the token map from `_active_maps` on every call (line 117). When LiteLLM returns `n>1` choices and each choice calls `_desanitize_response`, the map is gone after the first choice. Remaining choices leak raw tokens like `[EMAIL_0]` to users.

**Root cause:** The OpenAI middleware was fixed in v0.2.2 (pops once, iterates with same map), but the LiteLLM middleware still uses the old per-choice pop pattern.

**Fix — Option A (recommended): Pop once before the loop**

Change `shielded_completion` (lines 182-189):

```python
# BEFORE (broken):
if not _should_skip(model) and call_key and hasattr(response, "choices"):
    for choice in response.choices:
        if hasattr(choice, "message") and hasattr(choice.message, "content"):
            if choice.message.content:
                choice.message.content = _desanitize_response(
                    choice.message.content, model, call_key
                )

# AFTER (fixed):
if not _should_skip(model) and call_key and hasattr(response, "choices"):
    with _maps_lock:
        token_map = _active_maps.pop(call_key, None)
    call_key = ""  # consumed
    if token_map and token_map.entity_count > 0:
        for choice in response.choices:
            if hasattr(choice, "message") and hasattr(choice.message, "content"):
                if choice.message.content:
                    choice.message.content = _shield.desanitize(
                        text=choice.message.content,
                        token_map=token_map,
                        model=model,
                    )
```

Apply the same pattern to `shielded_acompletion` (lines 210-216).

**Fix — Option B: Make `_desanitize_response` idempotent**

Change `_desanitize_response` to use `.get()` instead of `.pop()`:

```python
def _desanitize_response(response_text: str, model: str, call_key: str) -> str:
    if not _shield:
        return response_text
    with _maps_lock:
        token_map = _active_maps.get(call_key)  # .get() not .pop()
    if not token_map or token_map.entity_count == 0:
        return response_text
    return _shield.desanitize(text=response_text, token_map=token_map, model=model)
```

Then pop in the `finally` block (which already exists at line 193-195). Option A is preferred because it matches the pattern already used in the OpenAI middleware.

### 1.2 Fix Vercel WeakMap Fragility (J1)

**File:** `cloakllm-js/src/vercel-middleware.js`
**Problem:** Token map is stored in a `WeakMap` keyed by the `newParams` object (line 126). If the Vercel AI SDK spreads or copies the params object between `transformParams` and `wrapGenerate`/`wrapStream`, the WeakMap lookup returns `undefined` and desanitization silently fails.

**Fix: Use a symbol property on the params object**

Replace the WeakMap approach with a unique symbol that survives object spreading:

```javascript
// BEFORE:
const _tokenMaps = new WeakMap();

// transformParams:
const newParams = { ...params, prompt: sanitizedPrompt };
if (tokenMap && tokenMap.entityCount > 0) {
    _tokenMaps.set(newParams, tokenMap);
}
return newParams;

// wrapGenerate:
const tokenMap = _tokenMaps.get(params);


// AFTER:
const _CLOAKLLM_TOKEN_MAP = Symbol.for('cloakllm.tokenMap');

// transformParams:
const newParams = { ...params, prompt: sanitizedPrompt };
if (tokenMap && tokenMap.entityCount > 0) {
    newParams[_CLOAKLLM_TOKEN_MAP] = tokenMap;
}
return newParams;

// wrapGenerate:
const tokenMap = params[_CLOAKLLM_TOKEN_MAP];
```

**Why this works:** `Symbol.for()` creates a global symbol that survives `{...spread}` operations. The symbol won't show up in `Object.keys()` or `JSON.stringify()`, so it won't interfere with the Vercel SDK.

**Changes required:**
1. `vercel-middleware.js` line 22: Remove `const _tokenMaps = new WeakMap();`
2. Add `const _CLOAKLLM_TOKEN_MAP = Symbol.for('cloakllm.tokenMap');` at module top
3. Line 126: Change `_tokenMaps.set(newParams, tokenMap)` → `newParams[_CLOAKLLM_TOKEN_MAP] = tokenMap`
4. Line 137: Change `_tokenMaps.get(params)` → `params[_CLOAKLLM_TOKEN_MAP]`
5. Line 179 (wrapStream): Same change as line 137
6. Update cleanup: After desanitization, `delete params[_CLOAKLLM_TOKEN_MAP]` to allow GC

### 1.3 Tests for Phase 1

**Python — add to `tests/test_shield.py`:**

```python
def test_litellm_multi_choice_desanitization():
    """P1: All n>1 choices must be desanitized, not just the first."""
    from unittest.mock import MagicMock, patch
    import cloakllm

    config = ShieldConfig(audit_enabled=False)
    cloakllm.enable(config)

    # Simulate n=3 response
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(message=MagicMock(content="Contact [EMAIL_0] today")),
        MagicMock(message=MagicMock(content="Reach out to [EMAIL_0]")),
        MagicMock(message=MagicMock(content="Email [EMAIL_0] now")),
    ]

    # ... patch litellm.completion to return mock_response
    # ... call with messages containing "john@acme.com"
    # Assert ALL choices have "john@acme.com", not "[EMAIL_0]"
    for choice in result.choices:
        assert "[EMAIL_0]" not in choice.message.content
        assert "john@acme.com" in choice.message.content

    cloakllm.disable()
```

**JS — add to `test/test_vercel_middleware.js`:**

```javascript
test('J1: desanitization works even if params are spread between hooks', async (t) => {
    const middleware = createCloakLLMMiddleware({ auditEnabled: false });
    const params = {
        prompt: [{ role: 'user', content: [{ type: 'text', text: 'Email john@acme.com' }] }],
    };

    // transformParams
    const transformed = await middleware.transformParams({ params, type: 'generate', model: {} });

    // Simulate SDK spreading the params (breaks WeakMap)
    const spreadParams = { ...transformed };

    // wrapGenerate with the spread copy
    const result = await middleware.wrapGenerate({
        doGenerate: async () => ({
            content: [{ type: 'text', text: 'Contact [EMAIL_0]' }],
        }),
        params: spreadParams,
        model: {},
    });

    // Should still desanitize despite the spread
    assert.strictEqual(result.content[0].text, 'Contact john@acme.com');
});
```

---

## Phase 2: Correctness Fixes (v0.2.4)

**Priority:** HIGH — affects audit accuracy and long-running services
**Effort:** Medium (3-4 hours)
**Bugs fixed:** P4, P5, J4, J5, J7, J8, J9

### 2.1 Fix Metrics Using Cumulative Categories (P4)

**File:** `cloakllm-py/cloakllm/shield.py`
**Problem:** Line 138 passes `token_map.categories` to `_accumulate_metrics`, but since P3 was fixed (detections cleared per call at line 112), this is now correct — `categories` reflects only the current call's detections. **Verify this is actually fixed in v0.2.2** by checking the test.

If it's still broken (e.g., multi-turn with reused token_map where `categories` counts from `detections` which accumulate):

```python
# Fix: Compute categories from current detections before accumulating
current_categories = {}
for det in detections:
    current_categories[det.category] = current_categories.get(det.category, 0) + 1

self._accumulate_metrics(
    "sanitize", elapsed_ms, detection_timing,
    tokenization_ms, len(detections), current_categories,
)
```

### 2.2 Add Bounded Cache to JS LLM Detector (P5 equivalent in JS)

**File:** `cloakllm-js/src/llm-detector.js`
**Problem:** `this._cache` is an unbounded `Map`. In a long-running Node.js server, every unique text query adds an entry that is never evicted.

**Fix: Simple LRU eviction**

```javascript
// Add at class level:
static MAX_CACHE_SIZE = 256;

// In detect(), after caching a new entry:
_queryAndCache(text) {
    const entities = this._queryOllama(text);
    this._cache.set(text, entities);

    // Evict oldest if over capacity
    if (this._cache.size > LlmDetector.MAX_CACHE_SIZE) {
        const oldestKey = this._cache.keys().next().value;
        this._cache.delete(oldestKey);
    }

    return entities;
}
```

`Map` preserves insertion order, so `keys().next().value` gives the oldest entry. This is a simple FIFO eviction — good enough for a cache that's only used to avoid redundant Ollama queries.

### 2.3 Fix JS `.sort()` Mutating Cached Array (J7)

**File:** `cloakllm-js/src/llm-detector.js`, lines 155-163
**Problem:** `entities.sort()` mutates the cached array in place.

**Fix: Clone before sorting**

```javascript
// BEFORE:
let entities;
if (this._cache.has(text)) {
    entities = this._cache.get(text);
} else {
    entities = this._queryOllama(text);
    this._cache.set(text, entities);
}
entities.sort((a, b) => (b.value?.length ?? 0) - (a.value?.length ?? 0));

// AFTER:
let entities;
if (this._cache.has(text)) {
    entities = [...this._cache.get(text)];  // Clone cached array
} else {
    entities = this._queryOllama(text);
    this._cache.set(text, entities);
}
entities.sort((a, b) => (b.value?.length ?? 0) - (a.value?.length ?? 0));
```

### 2.4 Fix JS PHONE Filter Not Stripping `+` (J8)

**File:** `cloakllm-js/src/detector.js`, lines 141-144

```javascript
// BEFORE:
if (name === 'PHONE') {
    const digits = match[0].replace(/[-.\s()]/g, '');
    if (digits.length < 7) continue;
}

// AFTER:
if (name === 'PHONE') {
    const digits = match[0].replace(/[-.\s()+]/g, '');  // Also strip '+'
    if (digits.length < 7) continue;
}
```

### 2.5 Fix JS `_patchedClients` Preventing GC (J9)

**File:** `cloakllm-js/src/middleware.js`, line 32

```javascript
// BEFORE:
const _patchedClients = new Set();

// AFTER:
const _patchedClients = new WeakSet();
```

`WeakSet` allows clients to be garbage-collected when the caller drops their reference. The only place `_patchedClients` is used is `.has()` (line 148) and `.add()` (line 243), which `WeakSet` supports.

Note: `disable()` currently iterates `_patchedClients` to restore original functions. With `WeakSet`, iteration is not possible. But `disable()` already uses `_originalFunctions` (a `WeakMap`) and `_clientRefs` for this purpose, so `_patchedClients` only needs `.has()` and `.add()`.

### 2.6 Fix JS Null Token Maps Stored for Non-PII Calls (J4)

**File:** `cloakllm-js/src/middleware.js`, line 75

```javascript
// BEFORE (stores null for every call, even non-PII):
_activeMaps.set(callKey, tokenMap);

// AFTER (only store if there's something to desanitize):
if (tokenMap && tokenMap.entityCount > 0) {
    _activeMaps.set(callKey, tokenMap);
}
```

The downstream `_desanitizeResponse` already handles `tokenMap` being `undefined` (line 111), so this is safe.

---

## Phase 3: MCP Feature Parity (v0.2.5)

**Priority:** SOON — MCP is a second-class citizen
**Effort:** Medium (3-4 hours)
**Bugs fixed:** M1, M2, M3, M4, M5, M6, M7

### 3.1 Fix `provider` and `metadata` Being Dropped (M1, M4)

**File:** `cloakllm-mcp/server.py`
**Problem:** `sanitize()` accepts `provider` and `metadata` params but never passes them to `shield.sanitize()`. Also, `metadata` is typed as `str` but Shield expects `dict`.

The metadata JSON parsing was actually added at line 162, but `provider` is still not passed:

```python
# BEFORE (line 164-166):
sanitized, token_map = shield.sanitize(
    text, model=model or None, provider=provider or None,
    metadata=metadata_dict, token_map=existing_map
)
```

Wait — reading the code again, `provider` IS passed at line 165. Let me verify `sanitize_batch`:

```python
# Line 267-269 — sanitize_batch:
sanitized_texts, token_map = shield.sanitize_batch(
    texts, model=model or None, provider=provider or None,
    metadata=metadata_dict, token_map=existing_map
)
```

Both pass `provider` and `metadata_dict`. **M1 may already be fixed in v0.2.2.** Verify with a test.

### 3.2 Fix Category Counting Inconsistency (M3)

**File:** `cloakllm-mcp/server.py`
**Problem:** In tokenize mode (line 190-191), `entity_count` uses `token_map.entity_count` (unique entities in forward map). In redact mode (line 173), it uses `len(token_map.detections)` (total detections). These can differ when the same entity appears multiple times.

**Fix: Use consistent counting**

```python
# For both modes, use len(token_map.detections) for entity_count
# and token_map.categories for categories (both derive from detections)

# Tokenize mode return (lines 187-193):
return {
    "sanitized": sanitized,
    "token_map_id": map_id,
    "entity_count": len(token_map.detections),  # Was: token_map.entity_count
    "categories": token_map.categories,
    "entity_details": token_map.entity_details,
}
```

### 3.3 Add `entity_details` to `sanitize_batch` Response (M6)

**File:** `cloakllm-mcp/server.py`, lines 289-294

```python
# BEFORE:
return {
    "sanitized": sanitized_texts,
    "token_map_id": map_id,
    "entity_count": token_map.entity_count,
    "categories": token_map.categories,
}

# AFTER:
return {
    "sanitized": sanitized_texts,
    "token_map_id": map_id,
    "entity_count": len(token_map.detections),
    "categories": token_map.categories,
    "entity_details": token_map.entity_details,
}
```

### 3.4 Fix Module Docstring (M5)

**File:** `cloakllm-mcp/server.py`, top of file

Update docstring to mention all 4 tools:

```python
"""
CloakLLM MCP Server — PII protection middleware for Claude Desktop.

Exposes 4 tools:
  - sanitize: Detect and cloak PII in text
  - sanitize_batch: Batch sanitize multiple texts with shared token map
  - desanitize: Restore original values from tokens
  - analyze: Detect PII without cloaking
"""
```

### 3.5 Fix `desanitize` Using Global Shield (M7)

**File:** `cloakllm-mcp/server.py`, line 325
**Problem:** `desanitize` always calls `_shield.desanitize()`, but `sanitize` may have created a custom Shield instance (e.g., for redact mode or entity hashing). However, `desanitize` only needs the token_map, and `shield.desanitize()` is stateless — it just calls `tokenizer.detokenize()`. So the global `_shield` is fine here.

**Verdict:** M7 is not actually a bug — `desanitize()` doesn't use any Shield config, only the token_map. No fix needed. Add a comment:

```python
# Note: desanitize uses global _shield, which is correct —
# desanitize() only uses the tokenizer (stateless) and audit logger.
restored = _shield.desanitize(text, token_map)
```

---

## Phase 4: Streaming Desanitization (v0.3.0)

**Priority:** NEXT — significant UX improvement
**Effort:** Large (1-2 days)
**Scope:** Both SDKs + Vercel middleware

### 4.1 Design: Incremental Token-Aware Streaming

Current behavior: buffer entire response, desanitize at end, yield single chunk.
Target behavior: stream text through, only buffer when a potential token is detected.

**State machine for the stream parser:**

```
PASSTHROUGH ─── '[' ──→ BUFFERING ─── ']' ──→ CHECK_TOKEN ──→ PASSTHROUGH
                                   ─── other ──→ (flush buffer) ──→ PASSTHROUGH
```

### 4.2 Python Implementation

**New file:** `cloakllm-py/cloakllm/stream_desanitizer.py`

```python
import re

class StreamDesanitizer:
    """
    Incremental desanitizer for streaming LLM responses.
    Buffers only potential token patterns, passes everything else through.
    """

    # Matches [CATEGORY_N] or [CATEGORY_REDACTED]
    _TOKEN_PATTERN = re.compile(r'^\[([A-Z][A-Z0-9_]*?)(?:_(\d+|REDACTED))\]$')
    _MAX_TOKEN_LEN = 64  # Safety: flush buffer if it exceeds this

    def __init__(self, token_map):
        self._token_map = token_map
        self._buffer = ""
        self._in_bracket = False

    def feed(self, chunk: str) -> str:
        """
        Feed a chunk of streamed text. Returns the portion
        that can be safely emitted (already desanitized).
        """
        output = []

        for char in chunk:
            if self._in_bracket:
                self._buffer += char
                if char == ']':
                    # End of potential token — check if it's real
                    replacement = self._token_map.reverse.get(self._buffer)
                    if replacement:
                        output.append(replacement)
                    else:
                        output.append(self._buffer)  # Not a real token
                    self._buffer = ""
                    self._in_bracket = False
                elif len(self._buffer) > self._MAX_TOKEN_LEN:
                    # Too long to be a token — flush
                    output.append(self._buffer)
                    self._buffer = ""
                    self._in_bracket = False
            else:
                if char == '[':
                    self._in_bracket = True
                    self._buffer = char
                else:
                    output.append(char)

        return "".join(output)

    def flush(self) -> str:
        """Flush any remaining buffer (call at stream end)."""
        remaining = self._buffer
        self._buffer = ""
        self._in_bracket = False
        return remaining
```

### 4.3 JavaScript Implementation

**New file:** `cloakllm-js/src/stream-desanitizer.js`

```javascript
class StreamDesanitizer {
    static MAX_TOKEN_LEN = 64;

    constructor(tokenMap) {
        this._tokenMap = tokenMap;
        this._buffer = '';
        this._inBracket = false;
    }

    /**
     * Feed a chunk. Returns text safe to emit.
     * @param {string} chunk
     * @returns {string}
     */
    feed(chunk) {
        const output = [];

        for (const char of chunk) {
            if (this._inBracket) {
                this._buffer += char;
                if (char === ']') {
                    const replacement = this._tokenMap.reverse.get(this._buffer);
                    output.push(replacement ?? this._buffer);
                    this._buffer = '';
                    this._inBracket = false;
                } else if (this._buffer.length > StreamDesanitizer.MAX_TOKEN_LEN) {
                    output.push(this._buffer);
                    this._buffer = '';
                    this._inBracket = false;
                }
            } else {
                if (char === '[') {
                    this._inBracket = true;
                    this._buffer = char;
                } else {
                    output.push(char);
                }
            }
        }

        return output.join('');
    }

    /** Flush remaining buffer at stream end. */
    flush() {
        const remaining = this._buffer;
        this._buffer = '';
        this._inBracket = false;
        return remaining;
    }
}

module.exports = { StreamDesanitizer };
```

### 4.4 Integration into OpenAI Middleware (JS)

**File:** `cloakllm-js/src/middleware.js`

Replace the `bufferAndDesanitize` generator (lines 176-217):

```javascript
const { StreamDesanitizer } = require('./stream-desanitizer');

// In shieldedCreate, streaming path:
async function* streamAndDesanitize(stream) {
    const tokenMap = _activeMaps.get(streamCallKey);
    if (!tokenMap || tokenMap.entityCount === 0) {
        // No PII — pass through unchanged
        yield* stream;
        _activeMaps.delete(streamCallKey);
        return;
    }

    const desanitizer = new StreamDesanitizer(tokenMap);

    try {
        for await (const chunk of stream) {
            const delta = chunk.choices?.[0]?.delta;
            if (delta?.content) {
                const desanitized = desanitizer.feed(delta.content);
                if (desanitized) {
                    yield {
                        ...chunk,
                        choices: [{
                            ...chunk.choices[0],
                            delta: { ...delta, content: desanitized },
                        }],
                    };
                }
            } else {
                // Non-content chunks (finish_reason, etc.) — pass through
                const finishReason = chunk.choices?.[0]?.finish_reason;
                if (finishReason) {
                    const remaining = desanitizer.flush();
                    if (remaining) {
                        yield {
                            ...chunk,
                            choices: [{
                                ...chunk.choices[0],
                                delta: { ...delta, content: remaining },
                                finish_reason: null,
                            }],
                        };
                        // Yield the actual finish chunk
                        yield chunk;
                    } else {
                        yield chunk;
                    }
                } else {
                    yield chunk;
                }
            }
        }
    } finally {
        _activeMaps.delete(streamCallKey);
    }
}
```

### 4.5 Edge Cases

1. **Token split across chunks:** `"Contact ["` + `"EMAIL_0] today"` — handled by the state machine buffering `[` until `]` is found.
2. **False bracket:** `"array[0] = 5"` — `[0]` doesn't match any token in `reverse`, so it's emitted as-is.
3. **Case insensitivity:** LLMs sometimes lowercase tokens (`[email_0]`). The `reverse` map lookup needs case-insensitive matching:

```javascript
feed(chunk) {
    // ... in the ']' handler:
    if (char === ']') {
        // Try exact match first, then case-insensitive
        let replacement = this._tokenMap.reverse.get(this._buffer);
        if (!replacement) {
            // Case-insensitive fallback
            for (const [token, original] of this._tokenMap.reverse) {
                if (token.toLowerCase() === this._buffer.toLowerCase()) {
                    replacement = original;
                    break;
                }
            }
        }
        output.push(replacement ?? this._buffer);
    }
```

4. **Fullwidth bracket unescaping:** After desanitization, call `_unescapeTokens()` on the final output. This can be done in `flush()`.

---

## Phase 5: Integration Tests

**Priority:** NEXT — prevents regression of middleware bugs
**Effort:** Medium (4-6 hours)

### 5.1 Python Integration Tests

**New file:** `cloakllm-py/tests/test_middleware_integration.py`

```python
"""
Integration tests for middleware round-trips.
Tests the full sanitize → LLM → desanitize path with mocked API responses.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from cloakllm import ShieldConfig
from cloakllm.integrations import litellm_middleware, openai_middleware


class TestLiteLLMMultiChoice:
    """Test n>1 choices with LiteLLM middleware."""

    def _make_response(self, contents: list[str]) -> MagicMock:
        response = MagicMock()
        response.choices = [
            MagicMock(message=MagicMock(content=c)) for c in contents
        ]
        return response

    def test_n3_all_choices_desanitized(self):
        config = ShieldConfig(audit_enabled=False)
        litellm_middleware.enable(config)

        mock_resp = self._make_response([
            "Email [EMAIL_0] about the project",
            "Send to [EMAIL_0] with details",
            "Contact [EMAIL_0] ASAP",
        ])

        with patch.object(litellm_middleware, '_original_completion', return_value=mock_resp):
            import litellm
            result = litellm.completion(
                model="gpt-4",
                messages=[{"role": "user", "content": "Draft email to john@acme.com"}],
            )

        for choice in result.choices:
            assert "john@acme.com" in choice.message.content
            assert "[EMAIL_0]" not in choice.message.content

        litellm_middleware.disable()


class TestOpenAIMultiChoice:
    """Test n>1 choices with OpenAI middleware."""

    def test_n3_all_choices_desanitized(self):
        client = MagicMock()
        original_create = MagicMock()

        mock_resp = MagicMock()
        mock_resp.choices = [
            MagicMock(message=MagicMock(content="Email [EMAIL_0] about the project")),
            MagicMock(message=MagicMock(content="Send to [EMAIL_0] with details")),
            MagicMock(message=MagicMock(content="Contact [EMAIL_0] ASAP")),
        ]
        original_create.return_value = mock_resp

        client.chat.completions.create = original_create
        openai_middleware.enable_openai(client, ShieldConfig(audit_enabled=False))

        result = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Draft email to john@acme.com"}],
        )

        for choice in result.choices:
            assert "john@acme.com" in choice.message.content
            assert "[EMAIL_0]" not in choice.message.content

        openai_middleware.disable_openai(client)


class TestStreamingDesanitization:
    """Test streaming responses are correctly desanitized."""

    def test_streaming_restores_pii(self):
        # Mock a streaming response that splits a token across chunks
        chunks = [
            MagicMock(choices=[MagicMock(delta=MagicMock(content="Contact "), finish_reason=None)]),
            MagicMock(choices=[MagicMock(delta=MagicMock(content="[EMA"), finish_reason=None)]),
            MagicMock(choices=[MagicMock(delta=MagicMock(content="IL_0]"), finish_reason=None)]),
            MagicMock(choices=[MagicMock(delta=MagicMock(content=" today"), finish_reason="stop")]),
        ]
        # ... test that assembled output contains "john@acme.com"


class TestMultiTurnConversation:
    """Test multi-turn conversations with shared token map."""

    def test_consistent_tokens_across_turns(self):
        # Turn 1: sanitize with john@acme.com → [EMAIL_0]
        # Turn 2: same email should get same token
        # Turn 3: new email gets [EMAIL_1]
        pass


class TestMixedPiiNoPii:
    """Test conversations with mixed PII and non-PII messages."""

    def test_no_pii_messages_pass_through(self):
        # Messages without PII should not be modified
        pass

    def test_mixed_messages_only_sanitize_pii(self):
        # Only messages with PII should be modified
        pass


class TestErrorPaths:
    """Test error handling in middleware."""

    def test_api_timeout_cleans_up_token_map(self):
        # API timeout should not leak token maps
        pass

    def test_malformed_response_no_crash(self):
        # Malformed response should not crash middleware
        pass
```

### 5.2 JavaScript Integration Tests

**New file:** `cloakllm-js/test/test_middleware_integration.js`

Same test scenarios as Python, adapted for the JS middleware API.

---

## Phase 6: Benchmark Suite

**Priority:** LATER — quality assurance for detection accuracy
**Effort:** Large (1-2 days)

### 6.1 Labeled Dataset

**New file:** `cloakllm-py/benchmarks/pii_dataset.json`

```json
[
    {
        "text": "Contact john.smith@acme.com for details",
        "entities": [
            {"value": "john.smith@acme.com", "category": "EMAIL", "start": 8, "end": 27}
        ]
    },
    {
        "text": "SSN: 123-45-6789, born Jan 15, 1990",
        "entities": [
            {"value": "123-45-6789", "category": "SSN", "start": 5, "end": 16},
            {"value": "Jan 15, 1990", "category": "DATE_OF_BIRTH", "start": 23, "end": 35}
        ]
    },
    {
        "text": "The server at 192.168.1.100 is down",
        "entities": [
            {"value": "192.168.1.100", "category": "IP_ADDRESS", "start": 14, "end": 27}
        ]
    },
    {
        "text": "Call me at (555) 123-4567",
        "entities": [
            {"value": "(555) 123-4567", "category": "PHONE", "start": 11, "end": 25}
        ]
    }
]
```

Target: 200+ labeled examples across all 9 regex categories + NER categories.

### 6.2 Benchmark Runner

**New file:** `cloakllm-py/benchmarks/run_benchmark.py`

```python
"""
Detection benchmark — measures precision, recall, F1 per category.
"""
import json
from collections import defaultdict
from cloakllm import Shield, ShieldConfig


def load_dataset(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def run_benchmark(dataset: list[dict], config: ShieldConfig = None):
    shield = Shield(config or ShieldConfig(audit_enabled=False))

    stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for sample in dataset:
        text = sample["text"]
        expected = {(e["value"], e["category"]) for e in sample["entities"]}

        # Run detection
        result = shield.analyze(text)
        detected = {(d["text"], d["category"]) for d in result["entities"]}

        for entity in detected:
            cat = entity[1]
            if entity in expected:
                stats[cat]["tp"] += 1
            else:
                stats[cat]["fp"] += 1

        for entity in expected:
            cat = entity[1]
            if entity not in detected:
                stats[cat]["fn"] += 1

    # Compute metrics
    results = {}
    for cat, counts in sorted(stats.items()):
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        results[cat] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "tp": tp, "fp": fp, "fn": fn,
        }

    return results


if __name__ == "__main__":
    dataset = load_dataset("benchmarks/pii_dataset.json")
    results = run_benchmark(dataset)

    print(f"\n{'Category':<20} {'Precision':>10} {'Recall':>8} {'F1':>6} {'TP':>4} {'FP':>4} {'FN':>4}")
    print("-" * 70)
    for cat, m in results.items():
        print(f"{cat:<20} {m['precision']:>10.3f} {m['recall']:>8.3f} {m['f1']:>6.3f} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4}")
```

### 6.3 Target Thresholds

| Category | Min Precision | Min Recall | Notes |
|----------|--------------|------------|-------|
| EMAIL | 0.99 | 0.99 | Regex, very reliable |
| SSN | 0.95 | 0.99 | False positives from 9-digit numbers |
| CREDIT_CARD | 0.95 | 0.99 | BIN validation helps |
| PHONE | 0.85 | 0.90 | Highest false positive risk |
| IP_ADDRESS | 0.95 | 0.99 | IPv4 only, reliable |
| API_KEY | 0.80 | 0.90 | Entropy-based, some false positives |
| PERSON | 0.80 | 0.85 | NER-dependent |
| ORG | 0.75 | 0.80 | NER-dependent, context-sensitive |

---

## Phase 7: Cryptographic Hardening (v0.3.x)

**Priority:** LATER — foundational for compliance claims and public workloads
**Effort:** Large (3-5 days)
**Scope:** Both SDKs, new verifier package

This phase addresses the gaps identified in PLAN.md (Phase 3: Cryptographic Attestation) and adds key management, Ed25519 signing, sanitization certificates, and Merkle batch proofs.

### 7.1 Ed25519 Audit Entry Signing

**Problem:** The SHA-256 hash chain is tamper-evident (detects modifications) but not tamper-proof. Anyone with file access can rewrite the entire chain from genesis and `verify_chain()` will pass. There's no proof of authorship.

**Solution:** Sign each audit entry with an Ed25519 deployment keypair.

**New file:** `cloakllm-py/cloakllm/attestation.py`

```python
"""
Cryptographic attestation for CloakLLM audit entries.

Ed25519 digital signatures provide:
- Tamper-proof: entries cannot be forged without the private key
- Non-repudiation: a signed entry proves which deployment created it
- Third-party verification: verifiers only need the public key
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

# Use PyNaCl (libsodium bindings) — widely available, audited
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder


@dataclass
class DeploymentKeyPair:
    """Ed25519 keypair for a CloakLLM deployment."""
    private_key: bytes   # 32 bytes
    public_key: bytes    # 32 bytes
    key_id: str          # Hex fingerprint of public key (first 16 chars)

    @classmethod
    def generate(cls) -> "DeploymentKeyPair":
        """Generate a new Ed25519 keypair."""
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key
        key_id = public_key.encode(encoder=HexEncoder).decode()[:16]
        return cls(
            private_key=bytes(signing_key),
            public_key=bytes(public_key),
            key_id=key_id,
        )

    @classmethod
    def from_file(cls, path: Path) -> "DeploymentKeyPair":
        """Load keypair from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls(
            private_key=bytes.fromhex(data["private_key"]),
            public_key=bytes.fromhex(data["public_key"]),
            key_id=data["key_id"],
        )

    def save(self, path: Path) -> None:
        """Save keypair to a JSON file (set restrictive permissions)."""
        data = {
            "private_key": self.private_key.hex(),
            "public_key": self.public_key.hex(),
            "key_id": self.key_id,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        # Restrict to owner-only read (Unix)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # Windows doesn't support chmod


def sign_entry(entry_data: dict, keypair: DeploymentKeyPair) -> str:
    """
    Sign an audit entry and return the base64-encoded signature.

    Signs the canonical JSON (sorted keys, no spaces) of the entry data.
    The signature covers all fields including entry_hash and prev_hash.
    """
    signing_key = SigningKey(keypair.private_key)
    canonical = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
    signed = signing_key.sign(canonical.encode("utf-8"))
    return base64.b64encode(signed.signature).decode("ascii")


def verify_signature(entry_data: dict, signature_b64: str, public_key: bytes) -> bool:
    """
    Verify an audit entry's signature against a public key.

    Returns True if the signature is valid, False otherwise.
    """
    try:
        verify_key = VerifyKey(public_key)
        signature = base64.b64decode(signature_b64)
        canonical = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        verify_key.verify(canonical.encode("utf-8"), signature)
        return True
    except Exception:
        return False
```

**Integration into audit.py:**

```python
# In AuditLogger.__init__:
def __init__(self, config: ShieldConfig, keypair: Optional[DeploymentKeyPair] = None):
    self.config = config
    self._keypair = keypair
    # ... existing init ...

# In AuditLogger.log(), after computing entry_hash:
entry_data["entry_hash"] = entry_hash

if self._keypair:
    entry_data["signature"] = sign_entry(entry_data, self._keypair)
    entry_data["key_id"] = self._keypair.key_id
```

**Integration into Shield:**

```python
# In Shield.__init__:
from cloakllm.attestation import DeploymentKeyPair

class Shield:
    def __init__(self, config=None, keypair=None):
        self.config = config or ShieldConfig()
        self._keypair = keypair
        self.audit = AuditLogger(self.config, keypair=keypair)
        # ... existing init ...

    @staticmethod
    def generate_keypair(path: Optional[Path] = None) -> DeploymentKeyPair:
        """Generate a new Ed25519 deployment keypair."""
        kp = DeploymentKeyPair.generate()
        if path:
            kp.save(path)
        return kp
```

**Usage:**

```python
from cloakllm import Shield, ShieldConfig
from cloakllm.attestation import DeploymentKeyPair
from pathlib import Path

# First run: generate keypair
keypair = Shield.generate_keypair(Path("./cloakllm_keys/deployment.json"))

# Subsequent runs: load keypair
keypair = DeploymentKeyPair.from_file(Path("./cloakllm_keys/deployment.json"))

# Create shield with signing enabled
shield = Shield(config=ShieldConfig(), keypair=keypair)
sanitized, token_map = shield.sanitize("Email john@acme.com")
# Audit entry now includes "signature" and "key_id" fields
```

### 7.2 Sanitization Certificates

**Purpose:** A compact, standalone proof that sanitization occurred. Can be attached to API requests for downstream verification.

```python
# In attestation.py:

import time

@dataclass
class SanitizationCertificate:
    """
    Compact proof that a specific text was sanitized by CloakLLM.
    Can be verified by anyone with the deployment public key.
    """
    version: str                      # "1.0"
    key_id: str                       # Deployment public key fingerprint
    timestamp: float                  # Unix timestamp
    input_hash: str                   # SHA-256 of original text
    output_hash: str                  # SHA-256 of sanitized text
    entity_count: int                 # Entities detected
    categories: dict[str, int]        # Category breakdown
    detection_passes: list[str]       # ["regex", "ner", "llm"]
    mode: str                         # "tokenize" or "redact"
    entity_hashes: list[str]          # HMAC hashes (if enabled)
    signature: str                    # Ed25519 signature (base64)

    def to_dict(self) -> dict:
        return {
            "v": self.version,
            "kid": self.key_id,
            "ts": self.timestamp,
            "in": self.input_hash,
            "out": self.output_hash,
            "n": self.entity_count,
            "cat": self.categories,
            "passes": self.detection_passes,
            "mode": self.mode,
            "eh": self.entity_hashes,
            "sig": self.signature,
        }

    def to_header(self) -> str:
        """Compact base64 representation for HTTP headers."""
        payload = json.dumps(self.to_dict(), separators=(",", ":"))
        return base64.b64encode(payload.encode()).decode()

    @classmethod
    def from_header(cls, header: str) -> "SanitizationCertificate":
        data = json.loads(base64.b64decode(header))
        return cls(
            version=data["v"], key_id=data["kid"],
            timestamp=data["ts"], input_hash=data["in"],
            output_hash=data["out"], entity_count=data["n"],
            categories=data["cat"], detection_passes=data["passes"],
            mode=data["mode"], entity_hashes=data.get("eh", []),
            signature=data["sig"],
        )


def create_certificate(
    input_hash: str, output_hash: str,
    entity_count: int, categories: dict,
    detection_passes: list[str], mode: str,
    entity_hashes: list[str],
    keypair: DeploymentKeyPair,
) -> SanitizationCertificate:
    """Create and sign a sanitization certificate."""
    cert_data = {
        "v": "1.0",
        "kid": keypair.key_id,
        "ts": time.time(),
        "in": input_hash,
        "out": output_hash,
        "n": entity_count,
        "cat": categories,
        "passes": detection_passes,
        "mode": mode,
        "eh": entity_hashes,
    }
    canonical = json.dumps(cert_data, sort_keys=True, separators=(",", ":"))
    signing_key = SigningKey(keypair.private_key)
    signed = signing_key.sign(canonical.encode("utf-8"))
    sig = base64.b64encode(signed.signature).decode("ascii")

    return SanitizationCertificate(**cert_data, signature=sig)


def verify_certificate(cert: SanitizationCertificate, public_key: bytes) -> bool:
    """Verify a sanitization certificate's signature."""
    cert_data = cert.to_dict()
    sig = cert_data.pop("sig")
    canonical = json.dumps(cert_data, sort_keys=True, separators=(",", ":"))
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(canonical.encode("utf-8"), base64.b64decode(sig))
        return True
    except Exception:
        return False
```

**Integration into Shield.sanitize():**

```python
def sanitize(self, text, token_map=None, model=None, provider=None,
             metadata=None, certify=False):
    # ... existing sanitize logic ...

    result = (sanitized, token_map)

    if certify and self._keypair:
        passes = ["regex"]
        if self.config.spacy_model:
            passes.append("ner")
        if self.config.llm_detection:
            passes.append("llm")

        cert = create_certificate(
            input_hash=hashlib.sha256(text.encode()).hexdigest(),
            output_hash=hashlib.sha256(sanitized.encode()).hexdigest(),
            entity_count=len(detections),
            categories=token_map.categories,
            detection_passes=passes,
            mode=self.config.mode,
            entity_hashes=[d.get("entity_hash", "") for d in token_map.entity_details]
                          if self.config.entity_hashing else [],
            keypair=self._keypair,
        )
        result = (sanitized, token_map, cert)

    return result
```

### 7.3 Key Management Utilities

```python
# In attestation.py:

import hashlib as _hashlib
import hmac as _hmac

def derive_entity_key(master_key: str, salt: str = "cloakllm-entity-v1") -> str:
    """
    Derive an entity hash key from a master key using HKDF-SHA256.

    This allows using a single master secret to derive purpose-specific keys.
    The salt ensures different deployments with the same master key
    produce different entity hash keys.
    """
    # HKDF-Extract
    prk = _hmac.new(salt.encode(), master_key.encode(), _hashlib.sha256).digest()
    # HKDF-Expand (single block, 32 bytes)
    info = b"cloakllm:entity-hashing:v1"
    okm = _hmac.new(prk, info + b"\x01", _hashlib.sha256).digest()
    return okm.hex()


def rotate_entity_key(
    old_key: str, new_key: str,
    entity_hashes: list[dict],
    original_values: list[str],
) -> list[dict]:
    """
    Re-hash entities with a new key.

    Requires access to original values (only possible during active session).
    Returns updated entity_details with new hashes.

    Note: This is a session-time operation. Once the session ends and
    original values are discarded, hashes cannot be re-keyed.
    """
    from cloakllm.tokenizer import TokenMap

    new_map = TokenMap(entity_hashing=True, entity_hash_key=new_key)
    updated = []
    for detail, original in zip(entity_hashes, original_values):
        new_hash = new_map._compute_entity_hash(detail["category"], original)
        updated.append({**detail, "entity_hash": new_hash})
    return updated
```

### 7.4 Merkle Trees for Batch Attestation

```python
# In attestation.py:

def build_merkle_tree(entry_hashes: list[str]) -> tuple[str, list[list[str]]]:
    """
    Build a Merkle tree from a list of entry hashes.

    Returns (root_hash, tree_levels) where tree_levels[0] = leaves.
    Enables O(log n) proof that a specific entry was part of a batch.
    """
    if not entry_hashes:
        return GENESIS_HASH, []

    # Pad to power of 2
    leaves = list(entry_hashes)
    while len(leaves) & (len(leaves) - 1):
        leaves.append(leaves[-1])  # Duplicate last leaf

    levels = [leaves]

    while len(leaves) > 1:
        next_level = []
        for i in range(0, len(leaves), 2):
            combined = leaves[i] + leaves[i + 1]
            parent = _hashlib.sha256(combined.encode()).hexdigest()
            next_level.append(parent)
        leaves = next_level
        levels.append(leaves)

    return levels[-1][0], levels


def generate_merkle_proof(
    tree_levels: list[list[str]], leaf_index: int
) -> list[tuple[str, str]]:
    """
    Generate a Merkle proof for a specific leaf.

    Returns list of (sibling_hash, direction) pairs.
    direction: "left" means sibling is on the left, "right" on the right.
    """
    proof = []
    idx = leaf_index

    for level in tree_levels[:-1]:  # Skip root
        if idx % 2 == 0:
            sibling = level[idx + 1] if idx + 1 < len(level) else level[idx]
            proof.append((sibling, "right"))
        else:
            sibling = level[idx - 1]
            proof.append((sibling, "left"))
        idx //= 2

    return proof


def verify_merkle_proof(
    leaf_hash: str, proof: list[tuple[str, str]], root_hash: str
) -> bool:
    """Verify a Merkle proof against a root hash."""
    current = leaf_hash
    for sibling, direction in proof:
        if direction == "left":
            combined = sibling + current
        else:
            combined = current + sibling
        current = _hashlib.sha256(combined.encode()).hexdigest()
    return current == root_hash
```

**Integration into batch processing:**

```python
# In Shield.sanitize_batch(), when certify=True:
from cloakllm.attestation import build_merkle_tree, create_certificate

# After processing all texts:
entry_hashes = [
    _hashlib.sha256(s.encode()).hexdigest() for s in sanitized_texts
]
merkle_root, tree = build_merkle_tree(entry_hashes)

batch_cert = create_certificate(
    input_hash=merkle_root,  # Root covers all texts
    output_hash=merkle_root,
    entity_count=total_entities,
    categories=token_map.categories,
    detection_passes=passes,
    mode=self.config.mode,
    entity_hashes=[],
    keypair=self._keypair,
)
# Attach tree for per-text proof generation
batch_cert.merkle_tree = tree
```

### 7.5 JavaScript Implementation

The JS SDK needs equivalent crypto. Use the built-in `crypto` module (Node.js 18+):

```javascript
// src/attestation.js
const crypto = require('node:crypto');

class DeploymentKeyPair {
    constructor(privateKey, publicKey) {
        this.privateKey = privateKey;  // Buffer (32 bytes)
        this.publicKey = publicKey;    // Buffer (32 bytes)
        this.keyId = publicKey.toString('hex').slice(0, 16);
    }

    static generate() {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
            privateKeyEncoding: { type: 'pkcs8', format: 'der' },
            publicKeyEncoding: { type: 'spki', format: 'der' },
        });
        return new DeploymentKeyPair(privateKey, publicKey);
    }

    sign(data) {
        const key = crypto.createPrivateKey({
            key: this.privateKey, format: 'der', type: 'pkcs8',
        });
        return crypto.sign(null, Buffer.from(data), key);
    }

    static verify(data, signature, publicKey) {
        const key = crypto.createPublicKey({
            key: publicKey, format: 'der', type: 'spki',
        });
        return crypto.verify(null, Buffer.from(data), key, signature);
    }
}
```

### 7.6 Verifier Package (Standalone)

**New package:** `cloakllm-verify` — lightweight, zero-dependency verifier.

```
cloakllm-verify/
├── verify.py          # Python: verify certificates + audit chains
├── verify.js          # Node.js: verify certificates + audit chains
├── pyproject.toml     # "pip install cloakllm-verify"
├── package.json       # "npm install cloakllm-verify"
└── README.md
```

This package imports only `nacl`/`crypto` and implements `verify_certificate()`, `verify_signature()`, and `verify_merkle_proof()`. No CloakLLM dependency — downstream systems can verify without installing the full SDK.

### 7.7 Dependencies

| SDK | New Dependency | Purpose | Size |
|-----|---------------|---------|------|
| Python | `PyNaCl>=1.5.0` | Ed25519 (libsodium bindings) | ~1.5 MB |
| JS | None (uses `node:crypto`) | Ed25519 built into Node.js 18+ | 0 |
| Verifier (Py) | `PyNaCl>=1.5.0` | Signature verification only | ~1.5 MB |
| Verifier (JS) | None | Uses `node:crypto` | 0 |

### 7.8 Config Changes

```python
# config.py additions:
@dataclass
class ShieldConfig:
    # ... existing fields ...

    # Cryptographic attestation
    signing_enabled: bool = False
    keypair_path: Optional[str] = None   # Path to deployment keypair JSON
    certify: bool = False                # Generate certificates on sanitize()

    # Key management
    entity_key_derivation: bool = False  # Use HKDF instead of raw key
    entity_master_key: str = ""          # Master key for HKDF derivation
```

### 7.9 Tests

```python
# tests/test_attestation.py

def test_keypair_generation():
    kp = DeploymentKeyPair.generate()
    assert len(kp.private_key) == 32
    assert len(kp.public_key) == 32
    assert len(kp.key_id) == 16

def test_sign_and_verify():
    kp = DeploymentKeyPair.generate()
    entry = {"seq": 0, "event_type": "sanitize", "entry_hash": "abc123"}
    sig = sign_entry(entry, kp)
    assert verify_signature(entry, sig, kp.public_key)

def test_tampered_entry_fails_verification():
    kp = DeploymentKeyPair.generate()
    entry = {"seq": 0, "event_type": "sanitize"}
    sig = sign_entry(entry, kp)
    entry["seq"] = 1  # Tamper
    assert not verify_signature(entry, sig, kp.public_key)

def test_certificate_roundtrip():
    kp = DeploymentKeyPair.generate()
    cert = create_certificate(
        input_hash="a" * 64, output_hash="b" * 64,
        entity_count=3, categories={"EMAIL": 2, "SSN": 1},
        detection_passes=["regex", "ner"],
        mode="tokenize", entity_hashes=[], keypair=kp,
    )
    assert verify_certificate(cert, kp.public_key)

    # Tamper with certificate
    cert.entity_count = 999
    assert not verify_certificate(cert, kp.public_key)

def test_certificate_header_encoding():
    kp = DeploymentKeyPair.generate()
    cert = create_certificate(...)
    header = cert.to_header()
    decoded = SanitizationCertificate.from_header(header)
    assert decoded.entity_count == cert.entity_count

def test_merkle_tree_proof():
    hashes = ["hash0", "hash1", "hash2", "hash3"]
    root, tree = build_merkle_tree(hashes)
    proof = generate_merkle_proof(tree, 2)
    assert verify_merkle_proof("hash2", proof, root)

def test_merkle_tampered_proof_fails():
    hashes = ["hash0", "hash1", "hash2", "hash3"]
    root, tree = build_merkle_tree(hashes)
    proof = generate_merkle_proof(tree, 2)
    assert not verify_merkle_proof("tampered", proof, root)

def test_hkdf_key_derivation():
    key1 = derive_entity_key("master-secret", "salt-a")
    key2 = derive_entity_key("master-secret", "salt-b")
    key3 = derive_entity_key("master-secret", "salt-a")
    assert key1 != key2          # Different salts → different keys
    assert key1 == key3          # Same inputs → deterministic
    assert len(key1) == 64       # 32 bytes hex-encoded

def test_keypair_save_load(tmp_path):
    kp = DeploymentKeyPair.generate()
    path = tmp_path / "key.json"
    kp.save(path)
    loaded = DeploymentKeyPair.from_file(path)
    assert loaded.private_key == kp.private_key
    assert loaded.public_key == kp.public_key
```

---

## Phase 8: Multi-Language PII Detection (v0.4.0)

**Priority:** Medium — blocks international adoption
**Effort:** 2-3 days
**Depends on:** None (can be done in parallel with other phases)

### 8.1 Locale-Aware Configuration

**Files:** `cloakllm-py/cloakllm/config.py`, `cloakllm-js/src/config.js`

Add a `locale` option to ShieldConfig that selects appropriate defaults:

```python
# config.py — add locale field
@dataclass
class ShieldConfig:
    # ... existing fields ...
    locale: str = "en"  # ISO 639-1 language code

    # Derived properties
    @property
    def spacy_model(self) -> str:
        """Return appropriate spaCy model for the configured locale."""
        LOCALE_MODELS = {
            "en": "en_core_web_sm",
            "de": "de_core_news_sm",
            "fr": "fr_core_news_sm",
            "es": "es_core_news_sm",
            "it": "it_core_news_sm",
            "pt": "pt_core_news_sm",
            "nl": "nl_core_news_sm",
            "ja": "ja_core_news_sm",
            "zh": "zh_core_web_sm",
        }
        return LOCALE_MODELS.get(self.locale, "en_core_web_sm")
```

### 8.2 Locale-Aware Regex Patterns

**Files:** `cloakllm-py/cloakllm/detector.py`, `cloakllm-js/src/detector.js`

Add locale-specific patterns for phone numbers, national IDs, and postal codes:

```python
# detector.py — locale pattern registry
LOCALE_PATTERNS = {
    "de": {
        "PHONE": r"\+49[\s\-]?\d{2,4}[\s\-]?\d{4,8}",
        "NATIONAL_ID": r"\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}",  # German Personalausweis
        "POSTAL_CODE": r"\b\d{5}\b",
    },
    "fr": {
        "PHONE": r"\+33[\s\-]?\d[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}",
        "NATIONAL_ID": r"\b\d{13}\b",  # French INSEE number
        "POSTAL_CODE": r"\b\d{5}\b",
    },
    "gb": {
        "PHONE": r"\+44[\s\-]?\d{4}[\s\-]?\d{6}",
        "NATIONAL_ID": r"[A-Z]{2}\d{6}[A-Z]",  # UK National Insurance
        "POSTAL_CODE": r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b",
    },
}
```

### 8.3 Ollama Prompt Templates for Non-English Text

**Files:** `cloakllm-py/cloakllm/llm_detector.py`, `cloakllm-js/src/llm-detector.js`

Add locale-aware system prompts:

```python
LOCALE_PROMPTS = {
    "en": "Analyze the following text and identify any PII...",
    "de": "Analysiere den folgenden Text und identifiziere alle personenbezogenen Daten...",
    "fr": "Analysez le texte suivant et identifiez toutes les données personnelles...",
}

def _build_prompt(self, text: str, locale: str = "en") -> str:
    base = LOCALE_PROMPTS.get(locale, LOCALE_PROMPTS["en"])
    return f"{base}\n\nText:\n{text}"
```

### 8.4 Documentation

**Files:** `CloakLLM/GUIDE.md`, `cloakllm-web/content/docs/guide.mdx`

Add a "Multi-Language Detection" section covering:
- How to select spaCy models for other languages
- Available locale presets and their coverage
- Limitations of regex patterns for non-Latin scripts
- Recommendations for Ollama model selection per language

---

## Phase 9: JS NER Feature Parity (v0.4.0)

**Priority:** Medium — JS SDK has a significant detection gap without Ollama
**Effort:** 2-3 days
**Depends on:** None

### 9.1 Evaluate JS NER Options

Research candidates:

| Library | Size | Accuracy | Dependencies | Notes |
|---------|------|----------|-------------|-------|
| `compromise` | ~200KB | Good for PERSON, ORG | Zero deps | Rule-based, fast |
| `wink-ner` | ~50KB | Moderate | Zero deps | Rule-based |
| ONNX Runtime | ~5MB | High | `onnxruntime-node` | Can run spaCy-exported models |

**Recommendation:** Start with `compromise` for zero-dep alignment with existing JS SDK philosophy. Add ONNX as an optional enhanced mode.

### 9.2 Implement JS NER Pass

**File:** `cloakllm-js/src/ner-detector.js` (new file)

```javascript
// ner-detector.js — lightweight NER using compromise
import nlp from 'compromise';

export class NERDetector {
  detect(text) {
    const doc = nlp(text);
    const entities = [];

    // People
    for (const person of doc.people().out('array')) {
      const idx = text.indexOf(person);
      if (idx !== -1) {
        entities.push({
          category: 'PERSON',
          start: idx,
          end: idx + person.length,
          value: person,
          confidence: 0.80,
          source: 'ner',
        });
      }
    }

    // Organizations
    for (const org of doc.organizations().out('array')) {
      const idx = text.indexOf(org);
      if (idx !== -1) {
        entities.push({
          category: 'ORG',
          start: idx,
          end: idx + org.length,
          value: org,
          confidence: 0.75,
          source: 'ner',
        });
      }
    }

    // Places
    for (const place of doc.places().out('array')) {
      const idx = text.indexOf(place);
      if (idx !== -1) {
        entities.push({
          category: 'GPE',
          start: idx,
          end: idx + place.length,
          value: place,
          confidence: 0.75,
          source: 'ner',
        });
      }
    }

    return entities;
  }
}
```

### 9.3 Integrate into Detection Pipeline

**File:** `cloakllm-js/src/detector.js`

```javascript
// detector.js — add NER as optional second pass
import { NERDetector } from './ner-detector.js';

class DetectionEngine {
  constructor(config) {
    this.config = config;
    this._nerDetector = null;

    // Only load NER if compromise is available
    if (config.enableNER !== false) {
      try {
        this._nerDetector = new NERDetector();
      } catch {
        // compromise not installed — NER pass disabled
      }
    }
  }

  detect(text) {
    // Pass 1: Regex (existing)
    const regexEntities = this._detectRegex(text);

    // Pass 2: NER (new, if available)
    const nerEntities = this._nerDetector
      ? this._nerDetector.detect(text)
      : [];

    // Pass 3: LLM (existing, if configured)
    // ... existing code ...

    return this._mergeEntities(regexEntities, nerEntities, llmEntities);
  }
}
```

### 9.4 Add Detection Gap Warning

**Files:** `cloakllm-js/src/shield.js`, `cloakllm-py/cloakllm/shield.py`

```javascript
// shield.js — warn when detection is limited
sanitize(text, options = {}) {
  if (!this._nerAvailable && !this._llmAvailable) {
    console.warn(
      '[cloakllm] Warning: Running regex-only detection. ' +
      'PERSON, ORG, and GPE entities may be missed. ' +
      'Install "compromise" for NER or configure Ollama for LLM detection.'
    );
  }
  // ... existing code ...
}
```

---

## Phase 10: Context-Based PII Leakage Analysis (v0.5.0)

**Priority:** Low — research-heavy, future differentiator
**Effort:** 1-2 weeks (research + prototype)
**Depends on:** Phase 6 (benchmark suite provides evaluation framework)

### 10.1 Threat Model

Even with perfect entity detection, sanitized text can leak PII through context:

1. **Relationship inference:** "The CEO of [ORG_0] married [PERSON_1] in [GPE_0]" — cross-referencing public records could identify both entities
2. **Uniqueness:** "The 7'2" basketball player from [GPE_0]" — physical attributes + location narrow to a single person
3. **Temporal correlation:** Multiple sanitized texts with the same token can be linked across sessions (partially addressed by entity hashing)

### 10.2 Proposed Analysis Pipeline

```python
# context_analyzer.py — post-sanitization risk assessment (prototype)
class ContextAnalyzer:
    """Evaluate re-identification risk of sanitized text."""

    def analyze(self, sanitized_text: str, entity_details: list[dict]) -> dict:
        """
        Returns a risk assessment:
        - token_density: ratio of tokens to total words (high = more context clues)
        - unique_identifiers: count of rare descriptors near tokens
        - relationship_graph: edges between co-occurring tokens
        - risk_score: 0.0 (safe) to 1.0 (high re-identification risk)
        """
        words = sanitized_text.split()
        token_count = sum(1 for w in words if w.startswith('[') and w.endswith(']'))
        token_density = token_count / max(len(words), 1)

        # High token density = more context for each token
        # Low token density = tokens are isolated, harder to correlate
        risk_score = min(1.0, token_density * 2)

        return {
            "token_density": round(token_density, 3),
            "token_count": token_count,
            "word_count": len(words),
            "risk_score": round(risk_score, 3),
            "risk_level": "high" if risk_score > 0.7 else "medium" if risk_score > 0.3 else "low",
        }
```

This is a research prototype. A production implementation would need:
- NLP-based relationship extraction
- Entropy measurement of surrounding context
- Integration with the `analyze()` API to surface risk scores

---

## Summary: Release Schedule

| Release | Phase | Contents | Effort |
|---------|-------|----------|--------|
| **v0.2.3** | Phase 1 | P1 LiteLLM multi-choice fix, J1 Vercel WeakMap fix | 1-2 hours |
| **v0.2.4** | Phase 2 | P4/P5/J4/J5/J7/J8/J9 correctness fixes | 3-4 hours |
| **v0.2.5** | Phase 3 | M1-M7 MCP feature parity | 3-4 hours |
| **v0.3.0** | Phase 4 | Incremental streaming desanitization | 1-2 days |
| ongoing | Phase 5 | Integration test suite | 4-6 hours |
| ongoing | Phase 6 | Detection benchmark suite | 1-2 days |
| **v0.3.2** | Phase 7 | Ed25519 signing, certificates, Merkle trees, key management | 3-5 days |
| **v0.4.0** | Phase 8 | Multi-language PII detection (locale config, i18n regex, prompts) | 2-3 days |
| **v0.4.0** | Phase 9 | JS NER feature parity (compromise library, detection gap warnings) | 2-3 days |
| **v0.5.0** | Phase 10 | Context-based PII leakage analysis (research + prototype) | 1-2 weeks |

### Commit Strategy

Each phase gets its own commits per repo:
- `fix: v0.2.3 — fix LiteLLM multi-choice PII leakage (P1)`
- `fix: v0.2.3 — fix Vercel WeakMap desanitization fragility (J1)`
- `fix: v0.2.4 — bounded LLM detector cache, GC-safe client refs`
- `feat: v0.3.0 — incremental streaming desanitization`

Follow existing version bump checklist in CLAUDE.md for each release.
