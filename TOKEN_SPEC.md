# CloakLLM Token Specification v1.0

**Applies to:** CloakLLM v0.5.1+
**Status:** Normative
**Date:** 2026-03-31

This document defines the canonical format, grammar, and behavior guarantees for CloakLLM tokens. Both the Python and JavaScript SDKs MUST conform to this specification. Third-party integrations can rely on these rules to parse, detect, and validate CloakLLM tokens.

---

## 1. Token Grammar

Tokens follow this ABNF grammar (RFC 5234):

```abnf
token           = "[" category "_" suffix "]"
category        = UPPER *(UPPER / DIGIT / "_")
suffix          = counter / "REDACTED"
counter         = 1*DIGIT
UPPER           = %x41-5A       ; A-Z
DIGIT           = %x30-39       ; 0-9
```

### Examples

| Token | Category | Suffix | Mode |
|-------|----------|--------|------|
| `[EMAIL_0]` | EMAIL | 0 | tokenize |
| `[PERSON_12]` | PERSON | 12 | tokenize |
| `[CREDIT_CARD_REDACTED]` | CREDIT_CARD | REDACTED | redact |
| `[DATE_OF_BIRTH_0]` | DATE_OF_BIRTH | 0 | tokenize |

### Constraints

- Category names MUST consist of uppercase ASCII letters (`A-Z`), digits (`0-9`), and underscores (`_`).
- Category names MUST start with an uppercase letter (`A-Z`).
- Counter values are non-negative integers with no leading zeros (except `0` itself).
- The suffix `REDACTED` is reserved for redaction mode and MUST NOT be used as a counter.
- Maximum token length: **40 characters** (including brackets). This constraint enables streaming buffer optimization.

---

## 2. Canonical Regex

The canonical regex for matching CloakLLM tokens:

```
\[([A-Z][A-Z0-9_]*_(?:\d+|REDACTED))\]
```

With named capture groups (for parsing):

```
\[(?P<category>[A-Z][A-Z0-9_]*)_(?P<suffix>\d+|REDACTED)\]
```

JavaScript equivalent:

```javascript
/\[([A-Z][A-Z0-9_]*_(?:\d+|REDACTED))\]/g
```

---

## 3. Modes

### Tokenize Mode (default)

- Each unique entity gets a unique token: `[CATEGORY_N]`
- Counter `N` is per-category, zero-based, monotonically increasing
- Same original value always maps to the same token within a session (deterministic)
- Tokens are reversible via the TokenMap

### Redact Mode

- All entities of a given category share the same token: `[CATEGORY_REDACTED]`
- Not reversible — original values are not stored
- The `REDACTED` suffix is reserved and MUST NOT appear in tokenize mode

---

## 4. Counter Rules

1. Each category maintains an independent zero-based counter.
2. Counters increment monotonically: 0, 1, 2, ...
3. The same original value (after whitespace-stripping) always maps to the same token within a TokenMap session.
4. Key normalization: `original.strip()` (leading/trailing whitespace removed).
5. Different original values with the same category get different counter values.

---

## 5. Token Injection Prevention (Escaping)

User-supplied text may contain strings that look like CloakLLM tokens. To prevent injection:

1. **Before tokenization:** All substrings matching the token regex in the input text are escaped by replacing ASCII brackets with fullwidth Unicode equivalents:
   - `[` (U+005B) becomes `\uFF3B` (fullwidth left bracket)
   - `]` (U+005D) becomes `\uFF3D` (fullwidth right bracket)

2. **After detokenization:** Fullwidth brackets are restored to ASCII brackets.

This ensures user text like `"Send [EMAIL_0] to support"` is preserved literally, not confused with a CloakLLM token.

---

## 6. Detokenization Rules

1. Tokens are replaced **case-insensitively** (LLMs may alter casing).
2. Tokens are sorted by length (longest first) before replacement, to avoid partial matches.
3. After token replacement, escaped fullwidth brackets are restored to ASCII.

---

## 7. Category Registry

### 7.1 Regex Categories (Pass 1)

Built-in categories detected by regex patterns. Enabled by default unless noted.

| Category | Description | Default |
|----------|-------------|---------|
| `EMAIL` | Email addresses | Enabled |
| `SSN` | US Social Security Numbers | Enabled |
| `CREDIT_CARD` | Credit card numbers (Visa, MC, Amex, Discover) | Enabled |
| `PHONE` | Phone numbers (international + US) | Enabled |
| `IP_ADDRESS` | IPv4 addresses | Enabled |
| `API_KEY` | API keys / tokens (high-entropy strings) | Enabled |
| `AWS_KEY` | AWS access keys (AKIA/ASIA prefix) | Enabled |
| `JWT` | JSON Web Tokens | Enabled |
| `IBAN` | International Bank Account Numbers | Enabled |
| `IL_ID` | Israeli ID numbers (9 digits) | Disabled |

### 7.2 NER Categories (Pass 2)

Categories detected by NER models (spaCy in Python, compromise in JS).

| Category | Description | Raw Labels Mapped |
|----------|-------------|-------------------|
| `PERSON` | Person names | PERSON, PER, PS, persName |
| `ORG` | Organizations | ORG, OG, orgName |
| `GPE` | Geopolitical entities (countries, cities) | GPE, LOC, LC, placeName, geogName |
| `FAC` | Facilities | FAC |
| `NORP` | Nationalities, religious, political groups | NORP |
| `MISC` | Miscellaneous entities | MISC |

### 7.3 LLM Categories (Pass 3, opt-in)

Categories detected by local LLM (Ollama). Only active when `llm_detection` is enabled.

| Category | Description |
|----------|-------------|
| `ADDRESS` | Physical / mailing addresses |
| `DATE_OF_BIRTH` | Dates of birth |
| `MEDICAL` | Medical information |
| `FINANCIAL` | Financial information |
| `NATIONAL_ID` | National identification numbers |
| `BIOMETRIC` | Biometric data references |
| `USERNAME` | Usernames / handles |
| `PASSWORD` | Passwords / passphrases |
| `VEHICLE` | Vehicle identification (plates, VINs) |

### 7.4 Locale-Specific Categories

Categories detected by locale-specific regex patterns. Active when the matching locale is configured.

| Category | Locale | Description |
|----------|--------|-------------|
| `PHONE_DE` | de | German mobile phone numbers |
| `PHONE_DE_LAND` | de | German landline numbers |
| `VAT_DE` | de | German VAT ID (USt-IdNr) |
| `PHONE_FR` | fr | French phone numbers |
| `NIR_FR` | fr | French social security (NIR) |
| `PHONE_ES` | es | Spanish phone numbers |
| `DNI_ES` | es | Spanish national ID (DNI) |
| `NIE_ES` | es | Spanish foreigner ID (NIE) |
| `PHONE_NL` | nl | Dutch phone numbers |
| `BSN_NL` | nl | Dutch citizen service number (BSN) |
| `POSTAL_NL` | nl | Dutch postal codes |
| `PHONE_IL` | he | Israeli mobile phone numbers |
| `PHONE_IL_LAND` | he | Israeli landline numbers |
| `PHONE_CN` | zh | Chinese phone numbers |
| `NATIONAL_ID_CN` | zh | Chinese national ID (18 digits) |
| `PHONE_JP` | ja | Japanese mobile phone numbers |
| `PHONE_JP_LAND` | ja | Japanese landline numbers |
| `MY_NUMBER_JP` | ja | Japanese My Number (12 digits) |
| `PHONE_RU` | ru | Russian phone numbers |
| `PHONE_RU_LAND` | ru | Russian landline numbers |
| `INN_RU` | ru | Russian taxpayer ID (INN) |
| `SNILS_RU` | ru | Russian insurance number (SNILS) |
| `PHONE_KR` | ko | Korean phone numbers |
| `PHONE_KR_LAND` | ko | Korean landline numbers |
| `RRN_KR` | ko | Korean resident registration number |
| `PHONE_IT` | it | Italian mobile phone numbers |
| `PHONE_IT_LAND` | it | Italian landline numbers |
| `CODICE_FISCALE_IT` | it | Italian fiscal code |
| `PHONE_PL` | pl | Polish phone numbers |
| `NIP_PL` | pl | Polish tax ID (NIP) |
| `PESEL_PL` | pl | Polish national ID (PESEL) |
| `PHONE_PT` | pt | Portuguese phone numbers |
| `PHONE_BR` | pt | Brazilian phone numbers |
| `CPF_BR` | pt | Brazilian CPF |
| `PHONE_IN` | hi | Indian phone numbers |
| `AADHAAR_IN` | hi | Indian Aadhaar number |
| `PAN_IN` | hi | Indian PAN card number |

### 7.5 Custom Categories

Users may define custom categories via:
- `custom_patterns`: regex-based detection (any category name)
- `custom_llm_categories`: LLM-based semantic detection

Custom category names MUST:
- Match the pattern `^[A-Z][A-Z0-9_]*$`
- Not collide with built-in category names (listed above)

---

## 8. Reserved Patterns

Any string matching `\[[A-Z][A-Z0-9_]*_(?:\d+|REDACTED)\]` is reserved as a CloakLLM token. Input text containing such patterns MUST be escaped (see Section 5).

---

## 9. Cross-SDK Conformance

Both the Python and JavaScript SDKs MUST:

1. Produce identical tokens for identical `(text, detections)` input
2. Use the same category names (uppercase, underscore-separated)
3. Use the same counter rules (per-category, zero-based, whitespace-stripped keys)
4. Use the same escaping mechanism (fullwidth brackets)
5. Support case-insensitive detokenization
6. Enforce the 40-character maximum token length for streaming
7. Validate custom category names against the `^[A-Z][A-Z0-9_]*$` pattern
