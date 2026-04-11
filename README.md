# 🛡️ Hybrid AI Defense — Closing the Detection Gap Against AI-Generated Phishing

> Multi-layer phishing detection system that combines NLP, URL intelligence, web crawling, and visual analysis

**Author:** Ramkumar  
**University:** VIT Vellore (B.Tech CSE)  
**Timeline:** 5 Weeks  
**Credits:** 5

---

## 📋 Project Overview

A comprehensive phishing detection system that goes beyond simple text analysis. This project uses multi-layer analysis including:

- **Email text analysis** (NLP with transformer models)
- **URL analysis** (reputation, domain age, SSL, patterns)
- **Website crawling** (actually visits and analyzes linked sites)
- **Visual analysis** (detects fake login pages, brand spoofing)
- **Recursive link checking** (follows redirect chains to catch hidden threats)

### 🎯 Unique Selling Point (Novelty)

Most phishing detectors catch traditional, human-written phishing emails. This project specifically targets **AI-generated phishing emails** — a growing threat as LLMs become more accessible.

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     INCOMING EMAIL TEXT                       │
│         POST /api/v1/deep-analyze                            │
└────────────────────────┬─────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────────┐
          ▼              ▼                  │
   ┌─────────────┐  ┌──────────────┐        │
   │ LAYER 1     │  │ EMAIL PARSER │        │
   │ DistilBERT  │  │ extract URLs │        │
   │ Text (35%)  │  │ extract meta │        │
   └──────┬──────┘  └──────┬───────┘        │
          │                │                │
          │                ▼                │
          │   ┌────────────────────────┐    │
          │   │ LAYER 2: URL ANALYZER  │    │
          │   │ (20% weight)           │    │
          │   │ • WHOIS domain age     │    │
          │   │ • SSL certificate      │    │
          │   │ • VirusTotal (70+ AVs) │    │
          │   │ • Pattern matching     │    │
          │   │ • Brand impersonation  │    │
          │   └────────────┬───────────┘    │
          │                │                │
          │                ▼                │
          │   ┌────────────────────────┐    │
          │   │ LAYER 3: WEB CRAWLER   │    │
          │   │ (Playwright + Process) │    │
          │   │ • Headless Chromium    │    │
          │   │ • Screenshot capture   │    │
          │   │ • Form/login detection │    │
          │   │ • Redirect tracking    │    │
          │   └────────────┬───────────┘    │
          │                │                │
          │                ▼                │
          │   ┌────────────────────────┐    │
          │   │ LAYER 4: VISUAL        │    │
          │   │ ANALYZER (25% weight)  │    │
          │   │ • Fake login detection │    │
          │   │ • Brand impersonation  │    │
          │   │   (12+ brands)         │    │
          │   │ • Credential harvesting│    │
          │   └────────────┬───────────┘    │
          │                │                │
          │                ▼                │
          │   ┌────────────────────────┐    │
          │   │ LAYER 5: LINK CHECKER  │    │
          │   │ (10% weight)           │    │
          │   │ • Follow redirects     │    │
          │   │ • Domain change detect │    │
          │   │ • URL shortener detect │    │
          │   └────────────┬───────────┘    │
          │                │                │
          ▼                ▼                ▼
   ┌───────────────────────────────────────────────┐
   │          WEIGHTED RISK AGGREGATOR             │
   │  Score = Text×0.15 + URL×0.25 + Crawl×0.10    │
   │          + Visual×0.20 + Links×0.20 + bonus   │
   │  2+ layers flagged → +0.15 boost              │
   └───────────────────────┬───────────────────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │  ≥0.65 → 🔴 PHISHING │
                │  ≥0.30 → 🟡 SUSPICIOUS│
                │  <0.30 → 🟢 SAFE     │
                └─────────────────────┘
```

---

## 🔍 Component Details

| Layer | Component | Weight | What it checks | Technology |
|-------|-----------|--------|----------------|------------|
| 1 | `email_classifier.py` | 15% | Email text — urgency, threats, AI-generated patterns | DistilBERT (fine-tuned, 99.17%) |
| 2 | `url_analyzer.py` | 25% | Domain age, SSL, VirusTotal reputation, suspicious patterns | python-whois + ssl + VirusTotal API |
| 3 | `web_crawler.py` | 10% | Actually visits URLs in sandboxed browser, takes screenshots | Playwright Chromium (multiprocessing) |
| 4 | `visual_analyzer.py` | 20% | Detects fake login pages, brand impersonation (12+ brands) | Heuristic rules |
| 5 | `link_checker.py` | 20% | Follows redirects, detects domain changes, URL shorteners | requests + redirect chain analysis |
| 6 | `header_analyzer.py` | 10% | SPF/DKIM/DMARC auth, Reply-To mismatch, Received chain hops, display-name spoofing, Return-Path mismatch | email.parser (stdlib) |
| — | `ai_authorship.py` | — | Detects AI-generated email text (perplexity, burstiness) | Statistical NLP (dual output scorer) |
| — | `xai_explainer.py` | — | Token attribution + human-readable risk explanations | DistilBERT attention + LOO perturbation + rule-based categories |
| — | `adversarial_tester.py` | — | Evasion attack test suite — homoglyph, ZWC, URL obfuscation, prompt injection | Heuristic rules + DistilBERT re-scoring per variant |
| — | `deep_router.py` | — | Combines all layers into weighted risk score | Weighted aggregation + boost logic |

---

## 📊 ML Model Details

### Architecture
- **Base Model:** DistilBERT (66M parameters, 6 transformer layers)
- **Type:** Fine-tuned binary text classification
- **Output:** Phishing vs Legitimate with confidence score (0–1)
- **Thresholds:** ≥0.85 = HIGH risk, ≥0.50 = MEDIUM risk

### Model Versions
| Version | Accuracy | Dataset | Notes |
|---------|----------|---------|-------|
| V1 | 98.63% | Human-generated only | Baseline |
| V2 | **99.17%** | Human + LLM generated | Current production model |

### Why DistilBERT?
- 40% smaller than BERT, 60% faster
- Retains 97% of BERT's performance
- Perfect for deployment (extension + web app)
- Understands context, not just keywords

---

## 📁 Dataset (V2)

### Training Data — 9,600 samples
| Source | Samples | Type |
|--------|---------|------|
| Enron Email Corpus | 2,993 | Legitimate |
| LLM-Generated | 1,990 | Phishing + Legitimate |
| Phishing Email Dataset | 1,500 | Phishing |
| SpamAssassin Corpus | 1,000 | Mixed |
| Nigerian Fraud | 995 | Phishing |
| Nazario Corpus | 991 | Phishing |
| Human-Generated | 131 | Mixed |

**Label Distribution:** 4,983 legitimate (0) • 4,617 phishing (1)

### Novel Contribution
- **AI-Generated Phishing Emails** — Custom LLM-generated dataset (1,990 samples)
- Multi-source dataset combining 7 different corpora
- Compares detection of human-written vs AI-written phishing
- Total: **9,600 samples** across all categories

---

## 🛠️ Tech Stack (100% FREE)

| Component | Technology | Status |
|-----------|------------|--------|
| NLP Model | HuggingFace DistilBERT (fine-tuned) | ✅ |
| Backend API | Python 3.12 + FastAPI + Uvicorn | ✅ |
| URL Intelligence | python-whois + ssl + VirusTotal API | ✅ |
| Web Crawling | Playwright Chromium (headless) | ✅ |
| Visual Detection | Heuristic rules (12+ brands) | ✅ |
| Link Analysis | requests + redirect chain tracking | ✅ |
| Frontend | HTML + CSS + JS (dark mode) | ✅ |
| Chrome Extension | Manifest V3 (Gmail integration) | ✅ |
| AI Authorship Detection | Statistical NLP (perplexity + burstiness) | ✅ |
| Explainable AI (XAI) | DistilBERT attention attribution + LOO perturbation + rule-based risk categories | ✅ |
| Header Forensics | email.parser stdlib (SPF/DKIM/DMARC + display-name spoof + Return-Path) | ✅ |
| Adversarial Robustness | Homoglyph + ZWC + URL obfuscation + prompt-evasion test suite | ✅ |
| Sender Reputation | SQLite reputation store + homoglyph scorer | ⬜ Planned |

**Total Cost: ₹0**

---

## 📅 Timeline (5 Weeks)

### Week 1: Data & Model ✅
- [x] Download existing datasets (Nazario, Enron, SpamAssassin)
- [x] Generate AI phishing samples using LLM
- [x] Preprocess and clean all data
- [x] Fine-tune DistilBERT — V1 (98.63%), V2 (99.17%)
- [x] Evaluate and tune model performance

### Week 2: Backend & URL Analysis ✅
- [x] Set up FastAPI backend
- [x] Implement email parsing (extract text, URLs, headers)
- [x] Build URL analyzer (WHOIS, SSL, VirusTotal integration)
- [x] Create API endpoints (`/analyze`, `/analyze-url`, `/full-analyze`)
- [x] Basic testing

### Week 3: Web Crawler & Visual Analysis ✅
- [x] Set up Playwright for safe web crawling (multiprocessing for Windows)
- [x] Implement screenshot capture (saved in `backend/screenshots/`)
- [x] Build visual analyzer (fake login detection for 12+ brands)
- [x] Implement recursive link checker (redirects, URL shorteners)
- [x] Integrate all into `/deep-analyze` endpoint (5-layer pipeline)

### Week 4: Frontend & Polish ✅
- [x] Build web app UI (dashboard to paste & analyze emails)
- [x] Create Chrome extension (Gmail integration)
- [x] Connect everything to backend
- [x] Rebalance scoring weights (Text 35%→15%, URL 20%→30%, Links 10%→20%)
- [x] Testing and bug fixes

### Week 5: Advanced Layers, XAI & Paper Prep ✅

#### Priority 1 — AI-Generated Text Detection Layer (Highest novelty) ✅
- [x] Implement perplexity scoring to distinguish AI-written vs human-written email text
- [x] Add burstiness detection (sentence length variance — humans vary more than LLMs)
- [x] Token frequency distribution analysis as an AI-authorship signal
- [x] Expose dual classification output: `is_phishing` + `is_ai_generated` (both scored 0–1)
- [x] Add `ai_authorship_score` to `/deep-analyze` response schema

#### Priority 2 — Explainable AI (XAI) Dashboard ✅
- [x] Token-level attribution via DistilBERT CLS-averaged attention weights (last transformer layer)
- [x] Leave-one-out (LOO) perturbation on top token — measures confidence delta when key token is removed
- [x] Rule-based risk category detection: urgency, credential request, threat, reward lure, brand impersonation, suspicious URL
- [x] Human-readable explanation in API response ("flagged because: urgency + credential request + brand impersonation")
- [x] XAI dashboard panel in frontend: highlighted tokens (red/amber/purple), top-token bar chart, LOO delta, full explanation text

#### Priority 3 — Email Header Forensics Layer ✅
- [x] Parse SPF / DKIM / DMARC from Authentication-Results + Received-SPF + DKIM-Signature headers
- [x] Detect Reply-To vs From domain mismatch (strong phishing signal)
- [x] Detect Return-Path vs From domain mismatch
- [x] Count Received chain hops (>7 = relay abuse; 0 = spoofed)
- [x] Display-name spoofing detection (claims known brand but domain doesn't match)
- [x] X-Mailer / User-Agent phishing toolkit fingerprinting
- [x] Date header anomaly detection (future-dated or very old emails)
- [x] Added as Layer 6 (10% weight) in the weighted aggregator
- [x] Frontend: Raw Headers textarea input, SPF/DKIM/DMARC auth badges, 📋 Headers layer card

#### Priority 4 — Adversarial Robustness Testing ✅
- [x] Test detection rate against homoglyph substitution attacks (`paypa1.com`, Cyrillic lookalikes for 10 target brands)
- [x] Test against zero-width character injection in email body (U+200B, U+200C, U+FEFF, U+2060)
- [x] Test against URL obfuscation (hex encoding, IP-based URLs, Unicode IDN domains, @ trick, URL shorteners, subdomain deception)
- [x] Test against prompt-style evasion in LLM-generated phishing text (8 evasion phrase patterns)
- [x] Heuristic detection layer for each attack type (homoglyph brand scanner, ZWC detector, URL obfuscation rules, evasion phrase regex)
- [x] `POST /api/v1/adversarial-test` endpoint — structured resilience report with per-variant results
- [x] Frontend: ⚔️ Adversarial Robustness Test panel — resilience score, evasion rate, per-type breakdown pills, full results table

#### Final ✅
- [x] Re-tune weighted aggregator for 6-layer pipeline
- [x] Update test suite for new layers
- [x] Documentation & presentation prep
- [x] Paper draft (novel contributions: AI authorship detection + XAI + adversarial robustness)
---

## 📂 Project Structure

```
Hybrid-AI-Defense/
├── README.md
├── requirements.txt
│
├── data/
│   ├── raw/                    # Original datasets
│   │   ├── human-generated/    # Human phishing + legit emails
│   │   └── llm-generated/      # AI-generated phishing + legit
│   └── processed/              # Cleaned data
│
├── backend/
│   ├── main.py                 # FastAPI app
│   ├── config.py               # Settings (API keys, thresholds)
│   ├── .env.example            # Environment variable template
│   ├── analyzers/
│   │   ├── email_parser.py     # URL/email extraction from text
│   │   ├── url_analyzer.py     # WHOIS + SSL + VirusTotal + patterns
│   │   ├── web_crawler.py      # Playwright crawler (subprocess)
│   │   ├── crawl_worker.py     # Isolated crawl process
│   │   ├── visual_analyzer.py  # Fake login page detection
│   │   ├── link_checker.py     # Recursive redirect analysis
│   │   ├── header_analyzer.py  # SPF/DKIM/DMARC + Received chain (Layer 6)
│   │   ├── adversarial_tester.py# Evasion attack suite (homoglyph, ZWC, URL obfusc, prompt)
│   │   └── sender_reputation.py# Homoglyph scoring + local reputation store
│   ├── services/
│   │   ├── email_classifier.py # DistilBERT model service
│   │   ├── ai_authorship.py    # AI-generated text detector (perplexity + burstiness)
│   │   └── xai_explainer.py    # SHAP/LIME token attribution + risk explanations
│   ├── routers/
│   │   ├── email_router.py        # /analyze endpoint
│   │   ├── url_router.py          # /analyze-url, /full-analyze
│   │   ├── deep_router.py         # /deep-analyze (6-layer)
│   │   └── adversarial_router.py  # /adversarial-test
│   ├── models/
│   │   └── schemas.py          # Pydantic request/response schemas
│   ├── tests/                  # Pytest test suite
│   │   ├── conftest.py         # Shared fixtures
│   │   ├── test_health.py      # Health endpoint tests
│   │   ├── test_email_router.py # Email analysis tests
│   │   └── test_deep_router.py  # Deep analysis tests
│   └── screenshots/            # Crawled page screenshots
│
├── frontend/
│   ├── index.html              # Dashboard with progress stepper + history
│   ├── styles.css              # Dark mode styles
│   └── app.js                  # Logic + history + JSON export
│
├── extension/                  # Chrome Extension (Gmail)
│   ├── manifest.json           # Manifest V3 config
│   ├── popup.html              # Extension popup UI
│   ├── popup.css               # Dark mode styles
│   ├── popup.js                # Popup logic (API calls)
│   ├── content.js              # Gmail email extractor
│   ├── background.js           # Service worker
│   └── icons/                  # Shield icons (16/48/128px)
│
├── docs/
│   └── error-handling.md       # Layer failure modes & graceful degradation
│
└── notebooks/
    └── training.ipynb          # Colab notebook for training
```

---

## 🎯 Deliverables

1. **ML Model** — Fine-tuned DistilBERT for phishing detection ✅
2. **Backend API** — FastAPI service with all analyzers ✅
3. **Web Application** — Dark mode dashboard with 5-layer results, history & export ✅
4. **Chrome Extension** — Gmail integration for real-time scanning ✅
5. **Test Suite** — Pytest tests for all API endpoints ✅
6. **Documentation** — Error handling & architecture docs ✅
7. **AI Authorship Detector** — Dual classifier: is_phishing + is_ai_generated ✅
8. **Explainable AI (XAI)** — Token attribution + human-readable risk explanations ✅
9. **Header Forensics Layer** — SPF/DKIM/DMARC + Received chain analysis (Layer 6) ✅
10. **Adversarial Robustness Report** — Detection rates under evasion attacks ✅
11. **Paper** — Research paper for ICCCNT / ICACCS / IJERT ✅

---

## 📄 Paper Potential

### Possible Venues
- ICCCNT (International Conference on Computing, Communication and Networking Technologies)
- ICACCS (International Conference on Advanced Computing and Communication Systems)
- IJERT / IRJET (Indian Journals)

### Novel Contributions
1. Custom dataset of AI-generated phishing emails (1,990 LLM-generated samples)
2. Dual classification output — phishing detection + AI-authorship detection (simultaneous)
3. Multi-modal 6-layer detection (text + URL + crawl + visual + links + header forensics)
4. Explainable AI — token-level SHAP attribution for phishing classification decisions
5. Adversarial robustness evaluation — detection rates under homoglyph, zero-width, and evasion attacks
6. Recursive redirect chain analysis
7. Focus on LLM-generated threats vs traditional human-written phishing (comparative analysis)

---

## 🚀 Quick Start (Commands)

### 1. Setup and Run Backend (Terminal 1)
```bash
# Clone the repo
git clone <repo-url>

# Set up virtual environment
python -m venv .venv
.venv\Scripts\activate       # Windows

# Install dependencies
cd backend
pip install -r requirements.txt
playwright install chromium

# Run backend
uvicorn main:app --reload --port 8001

# API docs available at: http://localhost:8001/docs
```

### 2. Run Frontend (Terminal 2)
```bash
# From the project root, start a simple HTTP server
cd frontend
python -m http.server 3000

# Open in browser: http://localhost:3000
```

### 3. Load Chrome Extension
1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `/extension` folder from this repository.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/analyze` | ML text classification only |
| POST | `/api/v1/analyze-url` | URL static analysis (WHOIS, SSL, VT) |
| POST | `/api/v1/full-analyze` | Text + URL analysis combined |
| POST | `/api/v1/deep-analyze` | **Full 6-layer pipeline** (text + URL + crawl + visual + links + headers) |
| POST | `/api/v1/adversarial-test` | **Adversarial robustness test** — homoglyph, ZWC, URL obfuscation, prompt-evasion variants |
| GET | `/api/v1/health` | Health check |

---

*Last Updated: April 11, 2026 — Week 5 complete. Re-tuned 6-layer weighted aggregator (Text 20%, URL 20%, Headers 15%, Links 15%, Visual 15%, Crawl 10%, Sender 5%; graduated boost at 2+ and 3+ flagging layers; AI-authorship +0.08 modifier); expanded test suite (header forensics tests, AI authorship/XAI layer tests, adversarial robustness endpoint tests, scoring consistency assertions); updated error-handling docs to reflect 6-layer pipeline and new weight table; paper draft complete (`docs/paper-draft.md`) covering dataset, architecture, ablation, adversarial evaluation, and discussion.*
