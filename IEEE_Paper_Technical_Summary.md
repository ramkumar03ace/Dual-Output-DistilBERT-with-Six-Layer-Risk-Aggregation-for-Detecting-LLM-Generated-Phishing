# IEEE Paper Technical Summary — Hybrid AI Defense: Closing the Detection Gap Against AI-Generated Phishing

---

## 1. Dataset Specifications

| Metric | Value |
|--------|-------|
| **Total Samples** | 9,600 |
| **Legitimate Emails** | 4,983 (51.9%) |
| **Phishing Emails** | 4,617 (48.1%) |
| **Train / Validation / Test Split** | 80% / 10% / 10% (stratified) |
| **Train** | 7,679 samples |
| **Validation** | 960 samples |
| **Test** | 961 samples |
| **Random Seed** | 42 |

### Data Sources

| Source | Type | Count |
|--------|------|-------|
| Enron Corpus | Legitimate | 2,993 |
| SpamAssassin (ham) | Legitimate | 1,000 |
| LLM-Generated | Legitimate | 990 |
| phishing_email dataset | Phishing | 1,500 |
| LLM-Generated | Phishing | 1,000 |
| Nigerian Fraud (419) | Phishing | 995 |
| Nazario Corpus | Phishing | 991 |
| Human-Generated | Phishing | 131 |

**AI-Generated Emails:** Yes — **1,990 total** (990 legitimate + 1,000 phishing), generated via LLM to test detection of AI-crafted attacks.

---

## 2. Feature Engineering & Architecture

### Preprocessing Pipeline

Text cleaning (scripts/preprocess_data_v2.py):

1. HTML tag removal: `re.sub(r'<[^>]+>', '', text)`
2. URL replacement with `[URL]` token
3. Email anonymization with `[EMAIL]` token
4. Special character removal (`\xa0`, `\r\n`, etc.)
5. Whitespace normalization

### Tokenization

- **Tokenizer:** `distilbert-base-uncased` (WordPiece)
- **Max sequence length:** 512 tokens
- **Padding:** `max_length`
- **Truncation:** `True`

### Model Architecture

- **Base model:** DistilBERT (`distilbert-base-uncased`)
- **Parameters:** 66,955,010
- **Architecture:** 6 Transformer encoder layers (vs. BERT's 12), ~40% fewer parameters
- **Task head:** `AutoModelForSequenceClassification` with `num_labels=2`
- **Labels:** `{0: "LEGITIMATE", 1: "PHISHING"}`

### Training Hyperparameters

| Parameter | Value |
|-----------|-------|
| Epochs | 3 |
| Train batch size | 16 |
| Eval batch size | 32 |
| Learning rate | 2e-5 |
| Weight decay | 0.01 |
| Warmup steps | 500 |
| Total training steps | 1,440 (480/epoch) |
| Mixed precision (FP16) | Enabled |
| Optimizer | AdamW (default HF Trainer) |
| Best model selection | By validation metric |
| GPU | Tesla T4 (Google Colab) |
| Training runtime | 388.2 seconds |

---

## 3. Final Empirical Results

### Overall Test Set Performance

| Metric | Score |
|--------|-------|
| **Accuracy** | **99.17%** |
| **Precision** | **98.92%** |
| **Recall** | **99.35%** |
| **F1-Score** | **99.14%** |

### Confusion Matrix (Test Set, n=961)

|  | Predicted Legitimate | Predicted Phishing |
|--|---------------------:|-------------------:|
| **Actual Legitimate** | TN = 494 | FP = 5 |
| **Actual Phishing** | FN = 3 | TP = 459 |

### Per-Source Accuracy (Human vs. AI-Generated Phishing)

| Source | Accuracy | Test Samples |
|--------|----------|-------------|
| Enron (legit) | 98.27% | 289 |
| phishing_email | 100.00% | 170 |
| **LLM-generated** | **99.49%** | 197 |
| SpamAssassin | 100.00% | 111 |
| Nigerian Fraud | 97.89% | 95 |
| Nazario | 100.00% | 90 |
| Human-generated | 100.00% | 9 |

**Key finding:** The model achieves **99.49% accuracy on LLM-generated emails** (197 test samples), compared to 98.27%-100% on traditional human-authored datasets. Only 1 misclassification out of 197 AI-generated samples — demonstrating the model effectively closes the detection gap against AI-generated phishing.

---

## 4. System & Tech Stack

### System Architecture

A **5-layer hybrid detection pipeline** served via FastAPI with a vanilla-JS web dashboard and Chrome Extension (Manifest V3):

| Layer | Technique | Weight |
|-------|-----------|--------|
| 1. Text Classification | Fine-tuned DistilBERT | 15% |
| 2. URL Intelligence | WHOIS age, SSL, VirusTotal, brand impersonation patterns | 25% |
| 3. Web Crawling | Playwright headless browser, screenshot capture, form detection | 10% |
| 4. Visual Analysis | Fake login page detection, brand spoofing (12+ brands) | 20% |
| 5. Link Checking | Recursive redirect following, URL shortener expansion | 20% |
| +Sender Analysis | DKIM/SPF verification, domain mismatch | 10% |

Weights are **dynamically redistributed** when layers are skipped. A **multi-layer boost** of +0.15 is applied when 2+ layers flag the email.

### UI

- **No Streamlit.** Custom single-page web dashboard (frontend/index.html) + Chrome Extension (extension/)
- Features: real-time risk gauge (0-100%), per-layer risk cards, screenshot gallery, JSON export, analysis history

### Explainable AI (XAI)

- **No SHAP/LIME libraries** are used
- Interpretability is achieved through **layer-decomposed risk attribution**: each of the 5 layers outputs individual risk scores and human-readable flags/risk factors, allowing users to see *which* layer flagged *what* (e.g., "Domain registered 3 days ago", "Fake Google login detected", "3 redirects before final URL")

### Primary Libraries & Versions

| Library | Version | Purpose |
|---------|---------|---------|
| `transformers` | 4.36.2 | DistilBERT model & tokenizer |
| `torch` | >=2.0.0 (2.9.0 on Colab) | Deep learning backend |
| `fastapi` | 0.109.0 | REST API framework |
| `uvicorn` | 0.27.0 | ASGI server |
| `pydantic` | 2.5.3 | Request/response validation |
| `playwright` | >=1.40.0 | Headless browser crawling |
| `python-whois` | 0.9.4 | Domain age lookup |
| `requests` | >=2.31.0 | HTTP client |
| `numpy` | >=1.24.0 | Numerical computation |
| `pandas` | >=2.0.0 | Data processing |
| `scikit-learn` | (training) | Metrics computation |
| `accelerate` | >=0.25.0 | GPU acceleration |
| `pytest` | >=7.4.0 | Testing |
| `httpx` | >=0.25.0 | Async HTTP testing |
