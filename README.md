# 🛡️ Hybrid AI Defense — Closing the Detection Gap Against AI-Generated Phishing

> A **6-layer + 2 auxiliary** hybrid detection pipeline that combines NLP, URL intelligence, web crawling, visual analysis, link checking, email header forensics, AI authorship detection, and Explainable AI — purpose-built to catch AI-generated phishing emails that bypass traditional filters.

**Author:** Ramkumar A D  
**University:** VIT Vellore (B.Tech CSE)  
**Timeline:** 5 Weeks · 5 Credits  
**Cost:** ₹0 (100% free and open-source)

---

## 📋 Problem Statement

As Large Language Models (LLMs) become more accessible, AI-generated phishing emails are becoming a growing threat. These emails bypass traditional keyword-based filters because they produce grammatically correct, contextually appropriate text with no spelling mistakes or obvious red flags.

## 💡 Solution

A multi-modal, multi-layer detection system that analyzes emails across **7 weighted dimensions** + 2 auxiliary modules:

| # | Layer | Weight | What It Does |
|:-:|-------|:------:|--------------|
| 1 | **Text Classification** | 20% | Custom-trained DistilBERT — phishing vs legitimate |
| 2 | **URL Intelligence** | 20% | WHOIS domain age, SSL certs, VirusTotal, pattern matching |
| 3 | **Web Crawling** | 10% | Headless Chromium visits URLs, captures screenshots |
| 4 | **Visual Analysis** | 15% | Detects fake login pages, brand impersonation (12+ brands) |
| 5 | **Link Checking** | 15% | Follows redirect chains, detects domain changes |
| 6 | **Header Forensics** | 15% | SPF/DKIM/DMARC, Reply-To mismatch, display-name spoofing |
| 7 | **Sender Analysis** | 5% | Domain mismatch, typosquatting, lookalike detection |
| — | **AI Authorship** | modifier | Detects AI-generated text (burstiness, perplexity, formality) |
| — | **Explainable AI (XAI)** | — | Token-level attribution + human-readable risk explanations |

---

## 🎯 Key Features & Novelty

- ✅ **Custom-trained DistilBERT** — fine-tuned on 9,600 samples including 1,990 AI-generated emails → **99.17% accuracy**
- ✅ **Dual classification** — `is_phishing` + `is_ai_generated` simultaneously
- ✅ **6-layer weighted detection** — text, URL, crawl, visual, links, headers + sender
- ✅ **Explainable AI** — token-level attention attribution (no SHAP/LIME needed)
- ✅ **Adversarial robustness testing** — homoglyph, zero-width, URL obfuscation, prompt-evasion
- ✅ **Dynamic weight redistribution** — skipped layers redistribute their weight proportionally
- ✅ **Multi-layer boost** — 2+ layers flagging → +0.10; 3+ layers → +0.15
- ✅ **Chrome Extension** — real-time Gmail scanning via Manifest V3
- ✅ **Web Dashboard** — dark-mode UI with risk gauge, layer cards, XAI panel, history, JSON export

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
   │ Text (20%)  │  │ extract meta │        │
   └──────┬──────┘  └──────┬───────┘        │
          │                │                │
          │    ┌───────────┴────────────┐   │
          │    ▼                        ▼   │
          │  ┌──────────┐  ┌──────────────┐ │
          │  │ SENDER   │  │ LAYER 2: URL │ │
          │  │ ANALYSIS │  │ ANALYZER     │ │
          │  │ (5%)     │  │ (20%)        │ │
          │  └──────────┘  └──────┬───────┘ │
          │                       │         │
          │                       ▼         │
          │  ┌────────────────────────┐     │
          │  │ LAYER 3: WEB CRAWLER   │     │
          │  │ (Playwright + Process) │     │
          │  │ (10% weight)           │     │
          │  └────────────┬───────────┘     │
          │               │                 │
          │               ▼                 │
          │  ┌────────────────────────┐     │
          │  │ LAYER 4: VISUAL        │     │
          │  │ ANALYZER (15% weight)  │     │
          │  └────────────┬───────────┘     │
          │               │                 │
          │               ▼                 │
          │  ┌────────────────────────┐     │
          │  │ LAYER 5: LINK CHECKER  │     │
          │  │ (15% weight)           │     │
          │  └────────────┬───────────┘     │
          │               │                 │
          │               ▼                 │
          │  ┌────────────────────────┐     │
          │  │ LAYER 6: HEADERS       │     │
          │  │ (15% weight)           │     │
          │  │ • SPF/DKIM/DMARC      │     │
          │  │ • Reply-To mismatch   │     │
          │  └────────────┬───────────┘     │
          │               │                 │
          ▼               ▼                 ▼
   ┌───────────────────────────────────────────────┐
   │          WEIGHTED RISK AGGREGATOR             │
   │  Text×20% + URL×20% + Headers×15%            │
   │  + Links×15% + Visual×15% + Crawl×10%        │
   │  + Sender×5%                                  │
   │  AI-generated phishing → +0.08 boost          │
   │  2+ layers flagged → +0.10                    │
   │  3+ layers flagged → +0.15                    │
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

## 🔍 Detection Layers — Detailed

### Layer 1: Text Classification (DistilBERT) — 20%

| Property | Value |
|----------|-------|
| Architecture | DistilBERT — 66M parameters, 6 transformer layers |
| Training Data | 9,600 samples (7 corpora + 1,990 AI-generated) |
| Accuracy | **99.17%** (V2) |
| Precision / Recall / F1 | 98.92% / 99.35% / 99.14% |
| Output | 4-class → binary mapping (phishing indices {1, 3}) |

### Layer 2: URL Intelligence — 20%

9 pattern checks (IP address, suspicious TLD, brand impersonation, excessive subdomains, long URL, @ symbol, double slashes, homograph, no HTTPS) + WHOIS domain age + SSL certificate validation + VirusTotal reputation.

### Layer 3: Web Crawler — 10%

Playwright headless Chromium in isolated child process (multiprocessing). Captures screenshots, detects login forms, password fields, redirect chains, external links.

### Layer 4: Visual Analysis — 15%

Heuristic detection of fake login pages and brand impersonation for **12+ brands** (Google, Microsoft, Apple, Amazon, PayPal, Netflix, Facebook, Instagram, Twitter, LinkedIn, Chase, Wells Fargo). Checks urgency language, data theft patterns, form credential harvesting.

### Layer 5: Link Checker — 15%

Follows up to 20 links recursively, tracks redirect chains, detects domain changes, URL shortener usage, suspicious TLDs, HTTPS→HTTP downgrades.

### Layer 6: Header Forensics — 15%

10 forensic checks: SPF/DKIM/DMARC authentication, Reply-To mismatch, Return-Path mismatch, Received chain hops, display-name spoofing (21 brands), X-Mailer fingerprinting, date anomalies, free/throwaway domain detection.

### Sender Analysis — 5%

6 checks: domain mismatch (From vs Mailed-by), DKIM mismatch, no TLS, display-name spoofing, free email provider, lookalike/typosquat domain detection (27 brands).

### AI Authorship Detection (Auxiliary)

5 statistical NLP signals with weighted scoring:

| Signal | Weight | AI Pattern |
|--------|:------:|-----------|
| Burstiness | 30% | Uniform sentence lengths |
| Perplexity proxy | 25% | Predictable word choices |
| Vocabulary richness | 15% | Repetitive vocabulary |
| Repetition score | 15% | High bigram repetition |
| Formality score | 15% | Dense formal discourse markers |

Threshold: `≥ 0.55` → AI-generated. Monitors 29 formal connectors + 12 urgency phrases.

### Explainable AI / XAI (Auxiliary)

3 attribution techniques: DistilBERT attention (60%) + rule-based pattern scoring (40%) + Leave-One-Out perturbation. Detects 6 risk categories: urgency, credential request, threat, reward, brand impersonation, suspicious URL. Produces token-level highlights and human-readable explanations.

---

## 📊 ML Model Performance

### Confusion Matrix (Test Set, n=961)

| | Predicted Legitimate | Predicted Phishing |
|--|---:|---:|
| **Actual Legitimate** | TN = 494 | FP = 5 |
| **Actual Phishing** | FN = 3 | TP = 459 |

### Per-Source Accuracy

| Source | Accuracy | Samples |
|--------|:--------:|:-------:|
| Enron (legit) | 98.27% | 289 |
| phishing_email | 100.00% | 170 |
| **LLM-generated** | **99.49%** | **197** |
| SpamAssassin | 100.00% | 111 |
| Nigerian Fraud | 97.89% | 95 |
| Nazario | 100.00% | 90 |

**Key result:** 99.49% accuracy on AI-generated emails — only 1 misclassification out of 197.

---

## 📁 Dataset (V2) — 9,600 Samples

| Source | Samples | Type |
|--------|:-------:|------|
| Enron Email Corpus | 2,993 | Legitimate |
| LLM-Generated (custom) | 1,990 | Phishing (1,000) + Legitimate (990) |
| Phishing Email Dataset | 1,500 | Phishing |
| SpamAssassin Corpus | 1,000 | Mixed |
| Nigerian Fraud (419) | 995 | Phishing |
| Nazario Corpus | 991 | Phishing |
| Human-Generated | 131 | Mixed |

**Split:** 80% train (7,679) · 10% validation (960) · 10% test (961) — stratified, seed 42.

---

## ⚔️ Adversarial Robustness Testing

Tests the pipeline's resilience against 4 attack categories:

| Attack Type | Variants | Detection Method |
|-------------|:--------:|-----------------|
| **Homoglyph substitution** | 10 brands × Cyrillic/Unicode lookalikes | Brand-variant scanner |
| **Zero-width character injection** | U+200B, U+200C, U+200D, U+FEFF, U+2060 | ZWC presence detector |
| **URL obfuscation** | Hex encoding, IP URLs, @ trick, IDN, shorteners | 7 heuristic rules |
| **Prompt-style evasion** | 8 LLM bypass phrases | 7 regex pattern detectors |

Evasion is only successful when BOTH the classifier is fooled AND the heuristic layer misses it.

---

## 🛠️ Tech Stack (100% Free)

| Component | Technology |
|-----------|-----------|
| **NLP Model** | Custom-trained DistilBERT (fine-tuned on custom dataset) |
| **Backend API** | Python 3.12 + FastAPI 0.109 + Uvicorn 0.27 |
| **URL Intelligence** | python-whois + ssl + VirusTotal API v3 |
| **Web Crawling** | Playwright Chromium (headless, multiprocessing) |
| **Visual Detection** | Heuristic rules (12+ brands) |
| **Link Analysis** | requests + redirect chain tracking |
| **Header Forensics** | email.parser (SPF/DKIM/DMARC + display-name spoof) |
| **AI Authorship** | Statistical NLP (perplexity + burstiness) |
| **XAI** | DistilBERT attention + LOO perturbation + rule-based categories |
| **Adversarial Testing** | Homoglyph + ZWC + URL obfuscation + prompt-evasion suite |
| **Frontend** | HTML + CSS + JS (vanilla, dark mode, no framework) |
| **Chrome Extension** | Manifest V3 (Gmail integration) |
| **Validation** | Pydantic 2.5 |
| **Testing** | pytest + httpx + anyio |

---

## 📂 Project Structure

```
Hybrid-AI-Defense/
├── README.md
│
├── data/
│   ├── raw/                     # Original datasets
│   │   ├── human-generated/
│   │   └── llm-generated/
│   └── processed/               # Cleaned CSV data
│
├── backend/
│   ├── main.py                  # FastAPI app entry point + lifespan
│   ├── config.py                # Settings (API keys, thresholds, CORS)
│   ├── .env.example             # Environment variable template
│   ├── requirements.txt         # Python dependencies
│   ├── analyzers/
│   │   ├── email_parser.py      # URL/email extraction from text + HTML
│   │   ├── url_analyzer.py      # WHOIS + SSL + VirusTotal + patterns
│   │   ├── web_crawler.py       # Playwright crawler orchestrator
│   │   ├── crawl_worker.py      # Isolated Playwright process
│   │   ├── visual_analyzer.py   # Fake login page / brand impersonation
│   │   ├── link_checker.py      # Recursive redirect analysis
│   │   ├── header_analyzer.py   # SPF/DKIM/DMARC + Received chain
│   │   ├── sender_analyzer.py   # Sender metadata + homoglyph scorer
│   │   └── adversarial_tester.py # Evasion attack test suite
│   ├── services/
│   │   ├── email_classifier.py  # Custom DistilBERT model service
│   │   ├── ai_authorship.py     # AI-generated text detector
│   │   └── xai_explainer.py     # Token attribution + risk explanations
│   ├── routers/
│   │   ├── email_router.py      # /analyze, /batch, /health
│   │   ├── url_router.py        # /analyze-url, /full-analyze
│   │   ├── deep_router.py       # /deep-analyze (6-layer pipeline)
│   │   └── adversarial_router.py # /adversarial-test
│   ├── models/
│   │   └── schemas.py           # Pydantic request/response schemas
│   ├── utils/
│   │   └── text_preprocessor.py # clean_text() + combine_subject_and_body()
│   ├── tests/                   # Pytest test suite
│   └── screenshots/             # Crawled page screenshots
│
├── frontend/
│   ├── index.html               # Dashboard (single-page app)
│   ├── styles.css               # Dark mode styles
│   └── app.js                   # Logic + history + JSON export
│
├── extension/                   # Chrome Extension (Gmail)
│   ├── manifest.json            # Manifest V3 config
│   ├── popup.html / .css / .js  # Extension popup
│   ├── content.js               # Gmail email body + header extractor
│   ├── background.js            # Service worker
│   └── icons/                   # Shield icons (16/48/128px)
│
├── docs/
│   ├── project-details.md       # Complete A-to-Z documentation
│   ├── project-documentation.md # Full technical reference
│   ├── tech-stack.md            # Detailed technology stack
│   ├── error-handling.md        # Failure modes & graceful degradation
│   └── paper-draft.md           # Research paper draft
│
├── notebooks/
│   └── training.ipynb           # Colab notebook for model training
│
└── scripts/
    └── preprocess_data_v2.py    # Dataset cleaning & preprocessing
```

---

## 🚀 Quick Start

### 1. Setup Backend

```bash
git clone https://github.com/ramkumar03ace/Hybrid-AI-Defense-Closing-the-Detection-Gap-Against-AI-Generated-Phishing.git
cd Hybrid-AI-Defense-Closing-the-Detection-Gap-Against-AI-Generated-Phishing

python -m venv .venv
.venv\Scripts\activate         # Windows

cd backend
pip install -r requirements.txt
playwright install chromium

# Optional: add VirusTotal API key
cp .env.example .env

uvicorn main:app --reload --port 8001
# API docs → http://localhost:8001/docs
```

### 2. Run Frontend

```bash
cd frontend
python -m http.server 3000
# Open → http://localhost:3000
```

### 3. Load Chrome Extension

1. Navigate to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder
4. Open Gmail and click the extension icon on any email

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/health` | Health check — model load status |
| `POST` | `/api/v1/analyze` | Text-only DistilBERT classification |
| `POST` | `/api/v1/batch` | Batch text classification |
| `POST` | `/api/v1/analyze-url` | Single URL static analysis |
| `POST` | `/api/v1/full-analyze` | Text + URL combined (60/40 weight) |
| `POST` | `/api/v1/deep-analyze` | **Full 6-layer pipeline** + AI authorship + XAI |
| `POST` | `/api/v1/adversarial-test` | **Adversarial robustness test** report |

---

## 🎯 Deliverables

| # | Deliverable | Status |
|:-:|-------------|:------:|
| 1 | **ML Model** — Custom-trained DistilBERT (99.17% accuracy) | ✅ |
| 2 | **Backend API** — FastAPI with 7 endpoints + 9 analyzers | ✅ |
| 3 | **Web Dashboard** — Dark mode, risk gauge, layer cards, history, JSON export | ✅ |
| 4 | **Chrome Extension** — Gmail integration via Manifest V3 | ✅ |
| 5 | **AI Authorship Detector** — Dual output: `is_phishing` + `is_ai_generated` | ✅ |
| 6 | **Explainable AI (XAI)** — Token attribution + human-readable explanations | ✅ |
| 7 | **Header Forensics** — SPF/DKIM/DMARC + display-name spoofing (Layer 6) | ✅ |
| 8 | **Adversarial Robustness** — 4 attack categories, resilience scoring | ✅ |
| 9 | **Test Suite** — pytest for all endpoints | ✅ |
| 10 | **Documentation** — Error handling, tech stack, full project docs | ✅ |
| 11 | **Research Paper** — Draft targeting ICCCNT / ICACCS / IJERT | ✅ |

---

## 📄 Research Contributions

### Target Venues

- ICCCNT (International Conference on Computing, Communication and Networking Technologies)
- ICACCS (International Conference on Advanced Computing and Communication Systems)
- IJERT / IRJET (Indian Journals)

### 7 Novel Contributions

1. **Custom-trained DistilBERT** — fine-tuned from scratch on a 9,600-sample multi-source dataset including 1,990 AI-generated emails
2. **Dual classification output** — phishing detection + AI-authorship detection simultaneously
3. **Multi-modal 6-layer detection** — text + URL + crawl + visual + links + header forensics
4. **Explainable AI** — token-level attention attribution for phishing decisions (no SHAP/LIME needed)
5. **Adversarial robustness evaluation** — detection rates under homoglyph, zero-width, and prompt-evasion attacks
6. **Recursive redirect chain analysis** — URL shortener expansion and domain-change detection
7. **Comparative analysis** — LLM-generated threats vs traditional human-written phishing (99.49% accuracy on AI-generated samples)

---

## 📅 Development Timeline

| Week | Focus | Status |
|:----:|-------|:------:|
| 1 | Dataset curation (9,600 samples) + DistilBERT training (V1 → V2) | ✅ |
| 2 | FastAPI backend + email parser + URL analyzer | ✅ |
| 3 | Playwright web crawler + visual analyzer + link checker | ✅ |
| 4 | Frontend dashboard + Chrome extension + weight tuning | ✅ |
| 5 | AI authorship + XAI + header forensics + adversarial testing + paper | ✅ |

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [`docs/project-details.md`](docs/project-details.md) | Complete A-to-Z project documentation |
| [`docs/project-documentation.md`](docs/project-documentation.md) | Full technical reference (all code details) |
| [`docs/tech-stack.md`](docs/tech-stack.md) | Detailed technology stack |
| [`docs/error-handling.md`](docs/error-handling.md) | Layer failure modes & graceful degradation |
| [`docs/paper-draft.md`](docs/paper-draft.md) | Research paper draft |

---

*Built with ❤️ at VIT Vellore · April 2026*
