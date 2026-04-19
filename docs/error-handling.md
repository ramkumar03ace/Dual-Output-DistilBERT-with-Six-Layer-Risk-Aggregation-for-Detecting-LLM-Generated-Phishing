# 🛡️ Dual-Output DistilBERT — Error Handling & Graceful Degradation

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

### Layer 6: Email Header Forensics

| Failure | Cause | Behavior |
|---------|-------|----------|
| No headers provided | `raw_headers` field omitted in request | Layer skipped; `header_analysis = null` in response |
| Header parse error | Malformed / truncated header block | Error logged; partial results returned with a `parsing_error` flag |
| Missing Authentication-Results | Older mail servers, internal relays | Falls back to `Received-SPF` and `DKIM-Signature` presence check |
| Date parse failure | Malformed `Date` header | Date anomaly check skipped; other checks still run |

> **Impact**: Low — layer is optional. When absent, its 15% weight is redistributed across the remaining active layers.

---

### AI Authorship Detection (Signal Modifier)

| Failure | Cause | Behavior |
|---------|-------|----------|
| Very short text (<2 sentences) | Subject-only or brief snippet | Signals set to empty list; `ai_authorship_score` defaults to 0.5 (uncertain) |
| Import error (unlikely) | Missing nltk / numpy | Detector falls back to returning `is_ai_generated = False` with a warning signal |

> **Impact**: Minimal — AI authorship is a modifier (+0.08 boost when confirmed AI-generated phishing), not a standalone layer.

---

### XAI Explainer (Metadata Only)

| Failure | Cause | Behavior |
|---------|-------|----------|
| Attention extraction fails | Model internals unavailable | `available = False`; empty token list returned |
| LOO perturbation fails | Second inference call fails | `top_token_confidence_delta = 0.0`; rest of explanation still returned |
| Rule-based categories empty | Short or ambiguous text | `risk_categories = []`, `explanation` describes unavailability |

> **Impact**: None on scoring — XAI is explanatory output only.

---

## Scoring When Layers Are Missing

The `deep_router.py` uses **dynamic weight redistribution** across the 6-layer pipeline.

### Calibrated base weights (full pipeline active)

| Layer | Base Weight |
|-------|------------|
| Text (DistilBERT) | 20% |
| URL analysis | 20% |
| Header forensics | 15% |
| Link checking | 15% |
| Visual analysis | 15% |
| Web crawling | 10% |
| Sender analysis | 5% |
| **Total** | **100%** |

When a layer is absent, its weight is redistributed proportionally among the remaining active layers. Examples:

- **Text + URL only** → Text 50%, URL 50%
- **Text + URL + Headers** → Text 36%, URL 36%, Headers 27%
- **All layers except crawl + visual** → Text 27%, URL 27%, Headers 20%, Links 20%, Sender 7%

### Boost logic (additive, capped at 1.0)

| Flagging layers | Boost |
|----------------|-------|
| ≥ 2 layers flagging | +0.10 |
| ≥ 3 layers flagging | +0.15 |

**Flagging thresholds per layer:**

| Layer | Flag threshold |
|-------|---------------|
| Text (DistilBERT) | `is_phishing = True` |
| URL | `risk_score ≥ 0.35` |
| Headers | `risk_score ≥ 0.25` |
| Links | `risk_score ≥ 0.30` |
| Visual | `risk_score ≥ 0.40` |
| Crawl | `risk_score ≥ 0.40` |
| Sender | `risk_score ≥ 0.30` |

### AI authorship modifier

When `is_ai_generated = True` **and** `is_phishing = True`, the combined score receives an additional **+0.08**. This reflects the elevated threat of AI-crafted phishing (bypasses traditional keyword filters and has lower perplexity, uniform structure, and high formality).

### Verdict thresholds

| Score range | Verdict |
|------------|---------|
| ≥ 0.65 | PHISHING |
| 0.30 – 0.64 | SUSPICIOUS |
| < 0.30 | SAFE |

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
4. **Pass `raw_headers`** in deep-analyze requests whenever available — Layer 6 adds significant signal
5. **Monitor logs** — all failures are logged with `logger.error()` in each analyzer
