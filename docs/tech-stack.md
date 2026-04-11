# 🛠️ Tech Stack — Hybrid AI Defense

> Complete technology stack used across all components of the project.

---

## Stack Overview

```
┌─────────────────────────────────────────────────┐
│                   FRONTEND                       │
│  HTML5 · CSS3 · Vanilla JavaScript               │
├─────────────────────────────────────────────────┤
│               CHROME EXTENSION                   │
│  Manifest V3 · Content Scripts · Service Worker  │
├─────────────────────────────────────────────────┤
│                  BACKEND API                     │
│  Python 3.12 · FastAPI · Uvicorn · Pydantic      │
├─────────────────────────────────────────────────┤
│              ML / NLP ENGINE                     │
│  PyTorch · Transformers · DistilBERT             │
├─────────────────────────────────────────────────┤
│             ANALYZERS & SERVICES                 │
│  Playwright · python-whois · VirusTotal API      │
│  email.parser · requests · ssl · re              │
├─────────────────────────────────────────────────┤
│               TRAINING (COLAB)                   │
│  PyTorch · Transformers · scikit-learn · Pandas  │
└─────────────────────────────────────────────────┘
```

---

## 1. Machine Learning & NLP

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **PyTorch** | ≥ 2.0.0 | Deep learning framework — model inference & training |
| **Transformers** (Hugging Face) | 4.36.2 | DistilBERT model loading, tokenization, and fine-tuning |
| **Accelerate** | ≥ 0.25.0 | Hardware-optimized model loading (GPU/CPU dispatch) |
| **DistilBERT** | `distilbert-base-uncased` | Base transformer architecture — 66M params, 6 layers, 12 heads |
| **NumPy** | ≥ 1.24.0 | Numerical operations, softmax computation, array handling |
| **Pandas** | ≥ 2.0.0 | Dataset loading, preprocessing, CSV handling |

---

## 2. Backend Framework

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **Python** | 3.12.6 | Core language for entire backend |
| **FastAPI** | 0.109.0 | Async REST API framework — auto-generated OpenAPI docs |
| **Uvicorn** | 0.27.0 (standard) | ASGI server — runs FastAPI with hot reload |
| **Pydantic** | 2.5.3 | Request/response validation, settings management |
| **Pydantic Settings** | 2.1.0 | `.env` file loading via `BaseSettings` |
| **Starlette** | ≥ 0.35.0 | CORS middleware, static file serving (FastAPI dependency) |
| **python-multipart** | 0.0.6 | Form data parsing support |
| **python-dotenv** | 1.0.0 | Environment variable loading from `.env` files |

---

## 3. URL & Network Analysis

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **python-whois** | 0.9.4 | WHOIS lookups — domain age, registrar info |
| **requests** | ≥ 2.31.0 | HTTP client — VirusTotal API, redirect chain following |
| **ssl** (stdlib) | — | SSL/TLS certificate validation and inspection |
| **socket** (stdlib) | — | Low-level TCP connections to port 443 for cert checks |
| **urllib3** | (bundled) | Connection pooling, insecure request warning suppression |
| **VirusTotal API v3** | — | URL reputation checking (optional, free tier) |

---

## 4. Web Crawling & Browser Automation

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **Playwright** | ≥ 1.40.0 | Headless Chromium browser automation |
| **Chromium** (via Playwright) | — | Headless browser engine for safe URL visiting |
| **multiprocessing** (stdlib) | — | Process isolation — separate Playwright from FastAPI event loop |
| **asyncio** (stdlib) | — | Async I/O — non-blocking crawl orchestration |

---

## 5. Email Parsing & Header Analysis

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **email.parser** (stdlib) | — | RFC-compliant email header parsing |
| **email.policy** (stdlib) | — | Modern email parsing policy (UTF-8 headers) |
| **email.utils** (stdlib) | — | Date parsing (`parsedate_to_datetime`) |
| **re** (stdlib) | — | Regex — URL extraction, pattern matching, SPF/DKIM parsing |
| **unicodedata** (stdlib) | — | Unicode character identification (zero-width detection) |

---

## 6. Frontend — Web Dashboard

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **HTML5** | — | Page structure, semantic elements |
| **CSS3** | — | Dark-mode styling, animations, gradients, glassmorphism |
| **Vanilla JavaScript** (ES6+) | — | Application logic, Fetch API, DOM manipulation |
| **SVG** | — | Circular risk gauge, AI authorship ring, bar charts |
| **LocalStorage API** | — | Client-side analysis history (last 10 scans) |
| **Fetch API** | — | REST communication with backend (`localhost:8001`) |
| **ContentEditable** | — | Rich email input (preserves HTML links for href extraction) |

> **No frameworks, no bundlers, no npm.** The entire frontend is vanilla HTML/CSS/JS served via `python -m http.server`.

---

## 7. Chrome Extension

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **Chrome Extension Manifest V3** | 3 | Extension configuration and permissions |
| **Content Scripts** | — | Injected into Gmail to extract email body + headers |
| **Service Worker** | — | Background script for extension lifecycle |
| **Chrome Scripting API** | — | Programmatic script injection into active tab |
| **Chrome Messaging API** | — | Popup ↔ Content Script communication |
| **Fetch API** | — | API calls from popup to backend |

### Permissions Used

| Permission | Purpose |
|-----------|---------|
| `activeTab` | Access to the currently focused Gmail tab |
| `scripting` | Inject content scripts programmatically |
| `https://mail.google.com/*` | Host permission for Gmail DOM access |
| `http://localhost:8001/*` | Host permission for backend API calls |

---

## 8. Testing

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **pytest** | ≥ 7.4.0 | Test runner and framework |
| **httpx** | ≥ 0.25.0 | Async HTTP client for FastAPI test client |
| **anyio[trio]** | ≥ 3.7.0 | Async test support, event loop management on Windows |

---

## 9. Model Training (Google Colab)

> Training was done on Google Colab — these dependencies are **NOT** installed in the local project environment.

| Technology | Version | Purpose |
|-----------|:-------:|---------|
| **Google Colab** | — | Cloud notebook environment with free GPU |
| **Tesla T4 GPU** | 16 GB VRAM | Training hardware (CUDA) |
| **Transformers Trainer** | 4.36.2 | Fine-tuning pipeline (AdamW, warmup, FP16) |
| **PyTorch** | ≥ 2.0.0 | Training backend (CUDA-accelerated) |
| **scikit-learn** | — | Metrics: accuracy, precision, recall, F1, confusion matrix |
| **matplotlib** | — | Training loss/accuracy visualization |
| **seaborn** | — | Confusion matrix heatmap |
| **Pandas** | — | Dataset loading, preprocessing, CSV operations |

---

## 10. AI & NLP Techniques (No External Libraries)

These features are implemented using **pure Python + standard library** — no additional dependencies required.

| Technique | Module | Libraries Used |
|-----------|--------|---------------|
| AI Authorship Detection | `ai_authorship.py` | `math`, `re`, `collections` (stdlib only) |
| Explainable AI (XAI) | `xai_explainer.py` | PyTorch (attention extraction), `re` |
| Adversarial Robustness | `adversarial_tester.py` | `re`, `unicodedata` (stdlib only) |
| Sender Analysis | `sender_analyzer.py` | `re` (stdlib only) |
| Visual Analysis | `visual_analyzer.py` | `re` (stdlib only) |
| Header Forensics | `header_analyzer.py` | `email.parser`, `re`, `datetime` (stdlib only) |

---

## 11. DevOps & Infrastructure

| Aspect | Technology | Notes |
|--------|-----------|-------|
| **Version Control** | Git + GitHub | Repository hosting and collaboration |
| **Package Manager** | pip | Python dependency management |
| **Virtual Environment** | venv | Isolated Python environment |
| **Server** | Uvicorn (local) | Development server with hot reload |
| **Frontend Server** | `python -m http.server` | Simple static file serving |
| **Container** | None | No Docker — runs directly on local machine |
| **CI/CD** | None | Manual testing and deployment |
| **Cloud** | None (except Colab) | Fully local-first architecture |

---

## 12. Python Standard Library Usage

The project makes extensive use of Python's standard library to minimize external dependencies:

| Module | Usage |
|--------|-------|
| `re` | Regex for URL/email extraction, pattern matching, SPF/DKIM parsing |
| `ssl` | SSL certificate inspection |
| `socket` | TCP connections for cert checks |
| `email.parser` | RFC-compliant header parsing |
| `email.policy` | Modern email handling policy |
| `email.utils` | Date parsing |
| `logging` | Structured module-level logging |
| `asyncio` | Async operations in FastAPI |
| `multiprocessing` | Process isolation for Playwright crawler |
| `dataclasses` | Lightweight data containers for analysis results |
| `datetime` | Timezone-aware date calculations |
| `collections` | Counter for bigram/word frequency analysis |
| `math` | Log calculations for entropy/burstiness |
| `unicodedata` | Unicode character name resolution |
| `uuid` | Screenshot filenames |
| `json` | Data serialization |
| `pathlib` | Cross-platform file paths |
| `typing` | Type hints (Optional, List, Dict, Tuple) |

---

## 13. Full Dependency Tree

```
Python 3.12.6
│
├── FastAPI 0.109.0
│   ├── Starlette ≥ 0.35.0
│   ├── Pydantic 2.5.3
│   │   └── pydantic-settings 2.1.0
│   └── Uvicorn 0.27.0 [standard]
│
├── Transformers 4.36.2
│   ├── Tokenizers 0.15.2
│   └── Accelerate ≥ 0.25.0
│
├── PyTorch ≥ 2.0.0
│   └── CUDA (optional, for GPU inference)
│
├── Playwright ≥ 1.40.0
│   └── Chromium (installed via `playwright install chromium`)
│
├── python-whois 0.9.4
├── requests ≥ 2.31.0
├── numpy ≥ 1.24.0
├── pandas ≥ 2.0.0
├── python-dotenv 1.0.0
├── python-multipart 0.0.6
│
└── Dev / Testing
    ├── pytest ≥ 7.4.0
    ├── httpx ≥ 0.25.0
    └── anyio[trio] ≥ 3.7.0
```

---

## 14. External APIs

| API | Usage | Required? | Free Tier |
|-----|-------|:---------:|-----------|
| **VirusTotal v3** | URL reputation checking | Optional | 4 requests/minute |

> No other external APIs are required. The system is fully self-contained.

---

## Summary

| Category | Count |
|----------|:-----:|
| Python packages (requirements.txt) | 14 |
| Standard library modules used | 18+ |
| External APIs | 1 (optional) |
| Frontend frameworks | 0 (vanilla) |
| CSS frameworks | 0 (custom) |
| Bundlers / Build tools | 0 |
| Databases | 0 |
| Docker / Containers | 0 |
| Cloud services | 0 (local-first) |
| **Total project cost** | **₹0** |

---

*The entire project runs locally with zero cloud dependencies (except Google Colab for one-time model training). No paid APIs, no SaaS subscriptions, no infrastructure costs.*
