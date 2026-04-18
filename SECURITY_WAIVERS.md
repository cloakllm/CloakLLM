# Security Waivers — Dependency Vulnerabilities

This file tracks dependency vulnerabilities (CVEs / advisory IDs) that CI's `pip-audit` and `npm audit` steps explicitly ignore. Each entry must include: the ID, the affected package, why we ignore it, and a re-evaluation date.

**Re-review cadence:** every release. Remove any entry whose underlying issue has been resolved upstream.

---

## Active waivers

### Python (`cloakllm-py`, `cloakllm-mcp`)

| ID | Package | Severity | Reason for waiver | Added | Re-evaluate |
|---|---|---|---|---|---|
| `ECHO-ffe1-1d3c-d9bc` | `pip` | Low (advisory) | EchoAdvisor advisory ID, no upstream pip patch beyond version 25.2+echo.1 (vendor-pinned variant). The pip 26.0.1 line we ship via `pip install --upgrade pip` in CI does not have a matching fix release. Tracking upstream. | 2026-04-17 (v0.6.3) | v0.6.4 |
| `ECHO-7db2-03aa-5591` | `pip` | Low (advisory) | Same as above — EchoAdvisor advisory tied to a vendor variant of pip. No standard pip release addresses it. | 2026-04-17 (v0.6.3) | v0.6.4 |

### JavaScript (`cloakllm-js`)

None currently. `npm audit --audit-level=moderate` reports zero vulnerabilities.

---

## Process

1. **Adding a waiver:** edit this file AND the `--ignore-vuln <ID>` line in the relevant `ci.yml`. Both must reference the same ID.
2. **Removing a waiver:** when the upstream fix lands, bump the dependency floor in `pyproject.toml` (or `package.json`), remove the `--ignore-vuln` flag, and delete the row from this file. Run `pip-audit` / `npm audit` locally to confirm clean.
3. **Default:** never add a waiver without a date and re-evaluation milestone. Stale waivers become permanent silent exemptions — exactly the trap NEW-9 (v0.6.3) was meant to close.

---

**Author:** Initial creation 2026-04-17 alongside v0.6.3 P0-1.
