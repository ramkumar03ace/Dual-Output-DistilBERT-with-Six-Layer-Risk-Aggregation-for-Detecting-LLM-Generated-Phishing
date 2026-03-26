# Tech Stack Report

> Generated on: 2026-03-24
> Project: Hybrid AI Defense — Closing the Detection Gap Against AI-Generated Phishing

## Summary

A Python-based AI security project that uses a fine-tuned DistilBERT model combined with a
5-layer phishing detection pipeline (NLP classification, URL intelligence, WHOIS lookup, headless
web crawling via Playwright, and visual/sender analysis) exposed through a FastAPI backend, a
vanilla-JS web frontend, and a Chrome Manifest V3 browser extension targeting Gmail.

---

## Runtime & Language

| Technology | Specified (requirements.txt) | Installed (venv) | Latest Version | Status |
|------------|------------------------------|------------------|----------------|--------|
| Python | 3.12.x (pyvenv.cfg) | 3.12.6 | 3.13.2 | ⚠️ Outdated (one minor behind) |

---

## Framework

| Technology | Specified | Installed (venv) | Latest Version | Status |
|------------|-----------|------------------|----------------|--------|
| FastAPI | ==0.109.0 | 0.109.0 | 0.115.x | ⚠️ Outdated |
| Uvicorn (standard) | ==0.27.0 | 0.27.0 | 0.34.x | ⚠️ Outdated |
| Starlette | >=0.35.0 | 0.35.1 | 0.46.x | ⚠️ Outdated |
| Pydantic | ==2.5.3 | 2.5.3 | 2.11.x | ⚠️ Outdated |
| Pydantic Settings | ==2.1.0 | 2.1.0 | 2.9.x | ⚠️ Outdated |

---

## ML / AI

| Technology | Specified | Installed (venv) | Latest Version | Status |
|------------|-----------|------------------|----------------|--------|
| Transformers (HuggingFace) | ==4.36.2 | 4.36.2 | 4.52.x | ⚠️ Outdated |
| PyTorch | >=2.0.0 | 2.10.0 | 2.7.x | ⚠️ Outdated (training notebook ran on 2.9.0+cu126 in Colab) |
| Accelerate (HuggingFace) | >=0.25.0 | 1.12.0 | 1.7.x | ✅ Up to date |
| Tokenizers (HuggingFace) | (transitive) | 0.15.2 | 0.21.x | ⚠️ Outdated |
| Safetensors | (transitive) | 0.7.0 | 0.5.x | ⚠️ Outdated |
| HuggingFace Hub | (transitive) | 0.36.2 | 0.33.x | ❓ venv version exceeds apparent release series — verify at PyPI |
| Sentencepiece | (transitive) | 0.2.1 | 0.2.1 | ✅ Up to date |

**Pretrained model used at runtime:** `cybersectony/phishing-email-detection-distilbert_v2.4.1` (loaded from HuggingFace Hub)
**Model architecture:** DistilBERT for Sequence Classification (fine-tuned binary classifier, 66.9M parameters)
**Training environment (Colab):** PyTorch 2.9.0+cu126, Tesla T4 GPU, `transformers` Trainer API

---

## Data Processing

| Technology | Specified | Installed (venv) | Latest Version | Status |
|------------|-----------|------------------|----------------|--------|
| NumPy | >=1.24.0 | 2.4.2 | 2.4.x | ✅ Up to date |
| Pandas | >=2.0.0 | 3.0.0 | 3.0.x | ✅ Up to date |
| Regex | (transitive) | 2026.1.15 | 2024.11.x | ✅ Up to date |

**Notebook-only dependencies (Google Colab, not in local venv):**

| Technology | Version used in Colab | Notes |
|------------|----------------------|-------|
| HuggingFace Datasets | latest at training time | Used for `Dataset` / `DatasetDict` |
| scikit-learn | latest at training time | Metrics: accuracy, precision, recall, F1, confusion matrix |
| Matplotlib | latest at training time | Training visualisation plots |
| Seaborn | latest at training time | Confusion matrix heatmap |
| Google Colab (`google.colab`) | N/A (platform) | File upload/download helpers |

---

## URL Analysis & Web Intelligence

| Technology | Specified | Installed (venv) | Latest Version | Status |
|------------|-----------|------------------|----------------|--------|
| python-whois | ==0.9.4 | 0.9.4 | 0.9.5 | ⚠️ Patch behind |
| Requests | >=2.31.0 | 2.32.5 | 2.32.x | ✅ Up to date |
| Playwright (Python) | >=1.40.0 | 1.58.0 | 1.52.x | ✅ Up to date |
| psutil | (transitive) | 7.2.2 | 7.0.x | ✅ Up to date |
| pyee | (transitive / Playwright) | 13.0.0 | 13.0.x | ✅ Up to date |

**External API integrated (optional, key-gated):** VirusTotal API v3 (`https://www.virustotal.com/api/v3/`)

---

## HTTP Client & Networking

| Technology | Specified | Installed (venv) | Latest Version | Status |
|------------|-----------|------------------|----------------|--------|
| httpx | >=0.25.0 | 0.28.1 | 0.28.x | ✅ Up to date |
| httpcore | (transitive) | 1.0.9 | 1.0.x | ✅ Up to date |
| httptools | (transitive / uvicorn) | 0.7.1 | 0.6.x | ✅ Up to date |
| urllib3 | (transitive) | 2.6.3 | 2.4.x | ✅ Up to date |
| certifi | (transitive) | 2026.1.4 | 2025.x | ✅ Up to date |
| charset-normalizer | (transitive) | 3.4.4 | 3.4.x | ✅ Up to date |
| idna | (transitive) | 3.11 | 3.10 | ✅ Up to date |
| websockets | (transitive / uvicorn) | 16.0 | 15.x | ✅ Up to date |
| watchfiles | (transitive / uvicorn) | 1.1.1 | 1.0.x | ✅ Up to date |

---

## Validation & Serialisation

| Technology | Specified | Installed (venv) | Latest Version | Status |
|------------|-----------|------------------|----------------|--------|
| python-multipart | ==0.0.6 | 0.0.6 | 0.0.20 | ⚠️ Outdated |
| python-dotenv | ==1.0.0 | 1.0.0 | 1.1.x | ⚠️ Outdated |
| annotated-types | (transitive / pydantic) | 0.7.0 | 0.7.x | ✅ Up to date |
| pydantic-core | (transitive) | 2.14.6 | 2.33.x | ⚠️ Outdated |
| typing-extensions | (transitive) | 4.15.0 | 4.13.x | ✅ Up to date |

---

## Testing

| Technology | Specified | Installed (venv) | Latest Version | Status |
|------------|-----------|------------------|----------------|--------|
| pytest | >=7.4.0 | 9.0.2 | 8.3.x | ✅ Up to date |
| anyio (trio extra) | >=3.7.0 | 4.12.1 | 4.9.x | ✅ Up to date |
| httpx | >=0.25.0 | 0.28.1 | 0.28.x | ✅ Up to date (also used for test client) |
| pluggy | (transitive / pytest) | 1.6.0 | 1.5.x | ✅ Up to date |
| iniconfig | (transitive / pytest) | 2.3.0 | 2.1.x | ✅ Up to date |

---

## Package Management & Build Tooling

| Technology | Version | Latest Version | Status |
|------------|---------|----------------|--------|
| pip | 26.0.1 (venv) | 25.1.1 | ❓ venv pip version appears ahead of PyPI — verify at PyPI |
| setuptools | 82.0.0 (venv) | 80.x | ✅ Up to date |
| Python venv | built-in | N/A | 📌 |

No lock file (e.g., `pip-lock`, `poetry.lock`, `pip-tools` `.txt` pin file) is present beyond the `requirements.txt` in `backend/`. Versions for transitive dependencies above are taken from the installed `.dist-info` directories inside `.venv/`.

---

## Frontend (Web UI)

| Technology | Version | Notes |
|------------|---------|-------|
| HTML5 | N/A | `frontend/index.html` — standalone single-page UI |
| CSS3 | N/A | `frontend/styles.css` — custom styles |
| Vanilla JavaScript (ES2020+) | N/A | `frontend/app.js` — no build step, no framework |

No npm `package.json`, no bundler (Webpack/Vite), no JS framework (React/Vue/Angular).
The frontend communicates with the backend via the Fetch API (`http://localhost:8001/api/v1`).

---

## Browser Extension

| Technology | Version / Spec | Notes |
|------------|---------------|-------|
| Chrome Extension Manifest V3 | manifest_version: 3 | Latest Chrome extension platform standard |
| Vanilla JavaScript | N/A | `popup.js`, `content.js`, `background.js` |
| Service Worker | N/A | `background.js` registered as service worker per MV3 spec |
| Content Scripts | N/A | `content.js` injected into `https://mail.google.com/*` |
| Host Permissions | localhost:8001, mail.google.com | Extension targets Gmail + local backend |

---

## Infrastructure & Deployment

| Technology | Notes |
|------------|-------|
| No Docker / docker-compose | No `Dockerfile` or `docker-compose.yml` found |
| No CI/CD pipelines | No `.github/workflows/`, `.gitlab-ci.yml`, or equivalent found |
| No cloud IaC | No Terraform, Pulumi, or serverless configs found |
| Google Colab | Used for model training (hosted Jupyter notebook environment, GPU: Tesla T4) |

The project is designed to be run locally. Backend serves on port 8001; the browser extension hardcodes `http://localhost:8001/api/v1` as its API base.

---

## Dependency Graph Summary

```
Python 3.12.6
├── FastAPI 0.109.0
│   ├── Starlette 0.35.1
│   ├── Pydantic 2.5.3
│   │   └── pydantic-core 2.14.6
│   └── Uvicorn 0.27.0
│       ├── httptools 0.7.1
│       ├── uvloop (not present on Windows)
│       ├── watchfiles 1.1.1
│       └── websockets 16.0
├── Transformers 4.36.2
│   ├── HuggingFace Hub 0.36.2
│   ├── Tokenizers 0.15.2
│   ├── Safetensors 0.7.0
│   └── Accelerate 1.12.0
├── PyTorch 2.10.0
│   ├── networkx 3.6.1
│   ├── sympy 1.14.0
│   ├── fsspec 2026.2.0
│   └── filelock 3.20.3
├── NumPy 2.4.2
├── Pandas 3.0.0
├── Playwright 1.58.0
│   └── pyee 13.0.0
├── python-whois 0.9.4
├── Requests 2.32.5
│   ├── urllib3 2.6.3
│   ├── certifi 2026.1.4
│   ├── charset-normalizer 3.4.4
│   └── idna 3.11
└── pytest 9.0.2 (dev)
```

---

## Notes

1. **Version data accuracy:** Latest version data is based on knowledge as of August 2025 and compared against installed `.dist-info` versions in the local `.venv`. Verify current latest releases at [PyPI](https://pypi.org/) before upgrading.

2. **No lock file present:** Only `backend/requirements.txt` defines dependencies with a mix of pinned (`==`) and range (`>=`) specifiers. There is no `pip-compile`-generated lock file or `poetry.lock`. This means reproducible installs depend on the ranges resolving consistently over time. Consider adding `pip-tools` or `uv` to generate a fully-pinned lock file.

3. **Transformers version gap:** The locally installed `transformers==4.36.2` is significantly behind the current 4.52.x series. The training notebook ran with `transformers` 5.0.0 (per `config.json` `transformers_version` field), which may indicate the saved model was produced in an environment different from the local venv — this is generally safe for inference but worth noting.

4. **PyTorch on Windows:** `uvloop` is not installed (Windows-incompatible). Uvicorn falls back to the default asyncio event loop, which is expected. The web crawler uses `multiprocessing` explicitly to work around Windows event loop restrictions with Playwright.

5. **python-multipart outdated:** `python-multipart==0.0.6` is far behind the current `0.0.20`. Earlier versions had known security issues with form parsing. Upgrade is recommended.

6. **No CI/CD or containerisation:** The project has no Docker, GitHub Actions, or any other automated pipeline. This is typical for an academic project but means deployment and reproducibility are entirely manual.

7. **External service dependency:** The VirusTotal API v3 integration is optional and key-gated via the `VIRUSTOTAL_API_KEY` environment variable. Without a key, URL reputation checks are skipped silently.

8. **Notebook-only ML dependencies:** `scikit-learn`, `matplotlib`, `seaborn`, and `huggingface/datasets` are used only inside the Google Colab training notebooks and are **not** installed in the local `.venv`. They do not need to be added to `requirements.txt` unless local training is desired.

9. **Browser extension targets Manifest V3:** This is the current and required standard for Chrome extensions as of Chrome 127+ (Manifest V2 deprecated). The extension is not published to the Chrome Web Store — it is loaded as an unpacked extension for local development.
