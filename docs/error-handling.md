# Error Handling & Graceful Degradation

How each detection layer handles failures, and what happens when things go wrong.

---

## Overview

The system is designed to **degrade gracefully**. If a layer fails, it is simply excluded from the weighted scoring — the remaining layers still produce a result.

---

## Layer-by-Layer Failure Modes

### Layer 1: Text Classification (DistilBERT)

| Failure | Cause | Behavior |
|---------|-------|----------|
| Model not loaded | Missing model files, OOM | API returns **503** — all analysis blocked |
| Inference error | Corrupted input, torch error | API returns **500** with error detail |

> **Impact**: Critical — no analysis possible without the model.

---

### Layer 2: URL Analysis

| Failure | Cause | Behavior |
|---------|-------|----------|
| WHOIS timeout | Domain registrar slow/unresponsive | Domain age marked as `None`, score unaffected |
| WHOIS rate limit | Too many queries in short time | Same as timeout — gracefully skipped |
| SSL check failure | Connection refused, invalid cert | `ssl_valid` set to `None`, may flag as suspicious |
| VirusTotal rate limit | Free tier: **4 requests/minute** | `vt_malicious` set to `None`, URL still scored on other signals |
| VirusTotal API key missing | No key in `.env` | VirusTotal check skipped entirely |
| Invalid URL format | Malformed URL string | URL skipped, logged as error |

> **Impact**: Low — URL analysis uses multiple signals, so individual failures reduce confidence slightly but don't break scoring.

---

### Layer 3: Web Crawling (Playwright)

| Failure | Cause | Behavior |
|---------|-------|----------|
| Playwright not installed | `playwright install chromium` not run | Crawl returns error; layer excluded from scoring |
| Page timeout | Slow/unresponsive site | `error` field set on crawl result, page skipped |
| Navigation error | DNS failure, refused connection | `error` field set, page skipped |
| Screenshot failure | Page prevents screenshots, render error | `screenshot_path` = `None`, visual analysis skipped for that URL |
| Subprocess crash | Multiprocessing issue on Windows | Crawl returns timeout error after 30s |

> **Impact**: Medium — affects both crawl and visual layers. Other layers still work.

---

### Layer 4: Visual Analysis (Heuristic)

| Failure | Cause | Behavior |
|---------|-------|----------|
| No screenshot available | Crawl failed or screenshots disabled | Layer skipped entirely |
| Image read error | Corrupted screenshot file | Layer skipped for that URL |
| No brand match | Page doesn't match any of the 12+ brand patterns | `is_fake_login = False`, risk_score = 0 |

> **Impact**: Low — visual analysis is always optional and tied to crawling.

---

### Layer 5: Link Checking

| Failure | Cause | Behavior |
|---------|-------|----------|
| Request timeout | Slow redirect chain | Link marked as checked, no suspicious flag |
| Too many redirects | Redirect loop (>10 hops) | Flagged as suspicious with `too_many_redirects` flag |
| Connection refused | Dead URL | Link logged as error, continues with other links |
| SSL error during redirect | Invalid cert in chain | Logged, redirect considered suspicious |

> **Impact**: Low — individual link failures don't break the overall check.

---

## Scoring When Layers Are Missing

The `deep_router.py` uses **dynamic weight redistribution**:

```
Base weights: Text 15% + URL 25% + Crawl 10% + Visual 20% + Links 20% = 90%
(+10% reserved for multi-layer boost)
```

When a layer is missing (failed or disabled), its weight is redistributed proportionally among the remaining active layers. For example:

- **Only Text + URL active** → Text gets ~34%, URL gets ~56%
- **All except Visual** → Text 19%, URL 32%, Crawl 13%, Links 26%

This ensures the risk score always uses the full 0–1 range regardless of how many layers run.

---

## API Error Responses

| Status | Meaning | Common Cause |
|--------|---------|--------------|
| **200** | Success | Analysis completed |
| **422** | Validation Error | Empty text, missing required fields |
| **500** | Internal Server Error | Unexpected exception during analysis |
| **503** | Service Unavailable | ML model not loaded |

All error responses follow this format:
```json
{
  "detail": "Human-readable error message"
}
```

---

## Recommendations

1. **Always check `/api/v1/health`** before sending analysis requests
2. **Set a VirusTotal API key** in `.env` for better URL analysis (free tier = 4 req/min)
3. **Run `playwright install chromium`** after installing requirements
4. **Monitor logs** — all failures are logged with `logger.error()` in each analyzer
