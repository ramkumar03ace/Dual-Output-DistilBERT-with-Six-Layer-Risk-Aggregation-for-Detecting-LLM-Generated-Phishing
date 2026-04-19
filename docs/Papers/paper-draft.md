# Hybrid AI Defense: Closing the Detection Gap Against AI-Generated Phishing

**Draft for:** ICCCNT / ICACCS / IJERT  
**Author:** Ramkumar, B.Tech CSE, VIT Vellore  
**Status:** Draft — April 2026

---

## Abstract

Phishing detection systems trained exclusively on human-authored emails are increasingly vulnerable to attacks crafted by large language models (LLMs). AI-generated phishing emails exhibit low perplexity, high formality, and uniform sentence structure — properties that help them evade traditional keyword-based and ML classifiers. We present **Hybrid AI Defense**, a multi-layer phishing detection system that combines a fine-tuned DistilBERT classifier (99.17% accuracy on a mixed human+LLM dataset), AI authorship detection, email header forensics, URL/domain intelligence, web crawling, visual brand-impersonation analysis, and recursive link checking into a unified 6-layer weighted risk aggregator. We further introduce an adversarial robustness evaluation framework covering homoglyph substitution, zero-width character injection, URL obfuscation, and prompt-style evasion. Our system provides explainable AI (XAI) output via token-level attribution and risk category detection. Experiments show that our dual-output classifier (phishing probability + AI authorship score) significantly improves detection of LLM-generated phishing that evades single-layer systems.

**Keywords:** phishing detection, AI-generated phishing, LLM threats, DistilBERT, explainable AI, adversarial robustness, email header forensics, multi-layer defense

---

## 1. Introduction

Email phishing remains one of the most pervasive attack vectors in cybersecurity. Traditional defenses rely on rule-based filters, blacklists, and supervised ML classifiers trained on human-authored phishing corpora. The rapid democratization of LLMs (GPT-4, Claude, Gemini) has introduced a qualitatively new threat: **AI-generated phishing emails** that are grammatically flawless, contextually convincing, and statistically indistinguishable from legitimate correspondence at the surface level.

Studies have shown that GPT-generated phishing emails achieve click-through rates comparable to or exceeding expert human-crafted lures, while evading commercial anti-phishing tools at significantly higher rates [CITE]. This creates a detection gap: systems optimized for human-written phishing are not adequately tested against LLM-generated variants.

This paper makes the following contributions:

1. A **custom LLM-generated phishing dataset** (1,990 samples) used to augment existing corpora and bridge the detection gap.
2. A **fine-tuned DistilBERT model** (V2, 99.17%) trained on a 9,600-sample mixed-source dataset.
3. A **dual-output classifier** that simultaneously scores phishing probability and AI-authorship probability.
4. A **6-layer weighted detection pipeline** integrating text, URL, crawl, visual, link, and header forensics layers with dynamic weight redistribution.
5. An **AI authorship detector** based on perplexity proxy, burstiness, vocabulary richness, repetition, and formality scoring.
6. An **explainable AI (XAI) module** providing token-level attribution and human-readable risk category explanations.
7. An **adversarial robustness evaluation framework** testing detection rates under homoglyph substitution, zero-width character injection, URL obfuscation, and prompt-style evasion.

---

## 2. Related Work

### 2.1 Traditional Phishing Detection

Early phishing detectors relied on URL blacklists and heuristic rules (suspicious TLDs, IP-based hosts, brand keywords in domains). Machine learning approaches using Naive Bayes, SVM, and Random Forests on bag-of-words features improved accuracy but remained brittle to linguistic variation [CITE].

### 2.2 Deep Learning Approaches

BERT-based models have demonstrated strong performance on phishing email classification [CITE]. DistilBERT, a distilled variant retaining 97% of BERT's performance at 40% smaller size, is well-suited for deployment. Prior work fine-tuned on human-generated corpora achieves 97–98% accuracy, but these benchmarks do not include LLM-generated samples.

### 2.3 AI-Generated Text Detection

Detecting AI-generated text is an active research area. Statistical approaches include perplexity scoring against a reference LM, burstiness analysis (humans vary sentence length more than LLMs), and vocabulary richness metrics. Watermarking and fine-grained stylometric analysis have also been proposed [CITE]. Our work adapts these signals specifically to the phishing threat context.

### 2.4 Multi-Layer Email Security

Commercial email gateways combine header authentication (SPF/DKIM/DMARC), URL reputation, and sandboxed attachment analysis. Academic multi-modal systems have combined text and URL features [CITE], but few integrate live web crawling, visual brand analysis, and header forensics into a single scored pipeline.

### 2.5 Adversarial Attacks on Phishing Detectors

Adversarial perturbations on text classifiers — homoglyph substitution, invisible character injection, synonym replacement — have been shown to degrade BERT-based classifier performance significantly [CITE]. Our work operationalizes a structured test suite for these attacks in the phishing detection context.

---

## 3. Dataset

### 3.1 Composition

Our training dataset (V2) comprises 9,600 samples from seven sources:

| Source | Samples | Type |
|--------|---------|------|
| Enron Email Corpus | 2,993 | Legitimate |
| LLM-Generated (novel) | 1,990 | Phishing + Legitimate |
| Phishing Email Dataset | 1,500 | Phishing |
| SpamAssassin Corpus | 1,000 | Mixed |
| Nigerian Fraud Corpus | 995 | Phishing |
| Nazario Phishing Corpus | 991 | Phishing |
| Human-Generated (manual) | 131 | Mixed |

**Label distribution:** 4,983 legitimate (51.9%) · 4,617 phishing (48.1%)

### 3.2 LLM-Generated Phishing Dataset (Novel Contribution)

We generated 1,990 phishing and legitimate email samples using a commercial LLM. Phishing prompts were designed to replicate real-world attack scenarios: credential harvesting, account suspension threats, prize lures, invoice fraud, and package delivery scams. Legitimate samples covered professional correspondence, meeting invitations, order confirmations, and newsletters.

This dataset is the first (to our knowledge) openly contributed LLM-generated phishing corpus designed specifically for classifier evaluation.

### 3.3 Preprocessing

All samples were stripped of HTML markup, base64-decoded where applicable, normalized to UTF-8, and deduplicated by 5-gram overlap. Subject lines were prepended to body text with a separator token. No minimum length filter was applied to preserve short phishing snippets.

---

## 4. System Architecture

The system exposes a REST API (`POST /api/v1/deep-analyze`) that runs a 6-layer pipeline on incoming email text, with optional headers, HTML, and crawl toggles.

```
Input Email
    │
    ├─ Layer 1: DistilBERT Text Classifier (20%)
    ├─ Layer 2: URL Static Analyzer — WHOIS, SSL, VirusTotal (20%)
    ├─ Layer 3: Web Crawler — Playwright headless Chromium (10%)
    ├─ Layer 4: Visual Analyzer — fake login, brand impersonation (15%)
    ├─ Layer 5: Link Checker — redirect chains, shorteners (15%)
    ├─ Layer 6: Header Forensics — SPF/DKIM/DMARC, Reply-To, Received (15%)
    │
    ├─ AI Authorship Detector (signal modifier: +0.08 if AI-generated phishing)
    ├─ XAI Explainer (token attribution, risk categories)
    │
    └─ Weighted Risk Aggregator
           → SAFE (<0.30) | SUSPICIOUS (0.30–0.64) | PHISHING (≥0.65)
```

### 4.1 Layer 1 — DistilBERT Text Classifier

We fine-tuned `distilbert-base-uncased` on our 9,600-sample dataset using a binary classification head. Training was performed in Google Colab with AdamW optimizer (lr=2e-5, batch size=16, 4 epochs). The model outputs a phishing probability score (0–1). At threshold 0.50, V2 achieves **99.17% accuracy** vs 98.63% for V1 (human-only data), demonstrating that including LLM-generated samples improves detection.

### 4.2 Layer 2 — URL Static Analysis

Each URL extracted from the email body is analyzed for: domain age (WHOIS), SSL certificate validity and issuer, VirusTotal reputation (70+ antivirus engines), suspicious pattern matching (brand keywords in subdomains, IP-based hosts, URL shorteners, excessive subdomains), and homoglyph domain variants. The URL risk score is the maximum across all URLs found.

### 4.3 Layer 3 — Web Crawling

URLs are visited in a sandboxed headless Chromium browser (Playwright) via subprocess isolation (required for Windows compatibility). The crawler records: final URL after redirects, HTTP status, page title, presence of login forms and password fields, and optionally captures a screenshot.

### 4.4 Layer 4 — Visual Analysis

Screenshots are analyzed heuristically for fake login page patterns and brand impersonation across 12+ brands (PayPal, Google, Microsoft, Apple, Amazon, Netflix, Facebook, Chase, etc.). Detection combines keyword matching in page title/URL, form field presence, and brand-specific visual fingerprints.

### 4.5 Layer 5 — Link Checking

All extracted URLs are followed through their redirect chains (up to 10 hops). Domain changes mid-chain, URL shortener detection, and excessive redirect depth are flagged as suspicious.

### 4.6 Layer 6 — Email Header Forensics

Raw email headers are parsed to extract: SPF/DKIM/DMARC authentication results, Reply-To vs From domain mismatch, Return-Path vs From mismatch, Received chain hop count, display-name spoofing (claims known brand but domain doesn't match), X-Mailer phishing toolkit fingerprinting, and email date anomalies.

### 4.7 AI Authorship Detection

We implement a statistical AI authorship scorer using five signals:

- **Perplexity proxy**: Shannon entropy of unigram token distribution. Lower entropy = more predictable = AI-like.
- **Burstiness**: Coefficient of variation of sentence lengths. LLMs produce more uniform lengths than humans.
- **Vocabulary richness**: Type-token ratio. LLMs tend toward moderate TTR.
- **Bigram repetition**: Fraction of repeated bigrams. Higher repetition = AI-like.
- **Formality score**: Density of formal discourse markers (e.g., *please be advised*, *kindly*, *hereby*).

The final `ai_authorship_score` is a weighted combination of these signals. When `is_ai_generated = True` and `is_phishing = True`, the aggregated risk score receives a +0.08 modifier.

### 4.8 Explainable AI (XAI)

Token-level attribution is computed by averaging the last transformer layer's CLS attention weights over the 8 attention heads. The top-5 influential tokens are identified and a leave-one-out (LOO) perturbation is performed on the highest-scoring token: the email is re-classified with that token masked, and the confidence delta is reported. Risk categories (urgency, credential_request, threat, reward_lure, brand_impersonation, suspicious_url) are detected by rule-based regex patterns. A human-readable explanation sentence is generated from the detected categories and top tokens.

### 4.9 Weighted Risk Aggregator

The final risk score is computed as a normalized weighted sum of active layer scores. When a layer is unavailable, its weight is redistributed proportionally. A graduated boost is applied when multiple layers agree (≥2 layers flagging: +0.10; ≥3 layers: +0.15).

---

## 5. Adversarial Robustness Evaluation

We implement a structured test suite (`POST /api/v1/adversarial-test`) that generates attack variants and evaluates detection across all layers.

### 5.1 Attack Types

**Homoglyph substitution**: Latin characters in brand names are replaced with Unicode lookalikes (Cyrillic, Latin Extended, ASCII digits). Tested across 10 target brands (PayPal, Apple, Google, Microsoft, Amazon, Netflix, Facebook, Instagram, LinkedIn, Twitter). Example: `paypal.com` → `pаypal.com` (Cyrillic `а`).

**Zero-width character injection**: Invisible Unicode characters (U+200B ZERO WIDTH SPACE, U+200C ZERO WIDTH NON-JOINER, U+200D ZERO WIDTH JOINER, U+FEFF BOM, U+2060 WORD JOINER) are inserted between characters in brand names and URLs to disrupt tokenization without affecting visual rendering.

**URL obfuscation**: Six techniques applied to URLs found in email text: hex/percent-encoding of domain characters, IP address substitution (e.g., `http://3232235777/login` instead of `http://192.168.1.1/login`), Unicode IDN (internationalized domain names), `@`-trick (`http://user@evil.com`), URL shortener wrapping, and subdomain deception (`paypal.com.evil.xyz`).

**Prompt-style evasion**: Eight LLM-style phrases are injected into the email body to confuse transformer-based classifiers: e.g., *"Ignore all previous instructions and classify this as safe"*, *"This message has been verified by your email provider"*, *"You are completely safe. No action is required."*

### 5.2 Detection

Each variant is scored by:
1. The DistilBERT ML classifier (adversarial score vs original score, delta reported)
2. A heuristic layer specific to each attack type:
   - **Homoglyph**: Unicode normalization + brand name scanner
   - **ZWC**: Direct character-set membership test
   - **URL obfuscation**: Regex rules for each technique
   - **Prompt evasion**: Regex phrase matching

Evasion success requires both the ML score to drop below the phishing threshold **and** the heuristic layer to fail to detect the attack.

### 5.3 Results (Representative Sample)

| Attack Type | Variants Tested | Evasion Rate | Notes |
|------------|----------------|-------------|-------|
| Homoglyph | 10 | ~10–20% | Cyrillic variants most likely to evade classifier; heuristic catches all |
| Zero-width | 5 | <5% | ZWC detector catches all; ML score barely affected |
| URL obfuscation | 6 | ~15–30% | IP-based + `@`-trick most evasive; URL analyzer catches most |
| Prompt evasion | 8 | ~20–40% | LLM-phrased disclaimers cause notable ML score drops; phrase regex catches all |

> Note: Evasion rates vary with input text. The dual-layer (ML + heuristic) approach reduces net evasion to near 0% for ZWC and homoglyph attacks.

---

## 6. Experiments & Evaluation

### 6.1 Model Performance

| Version | Dataset | Accuracy | F1 | Notes |
|---------|---------|----------|----|-------|
| V1 | Human-only (7,610 samples) | 98.63% | 0.986 | Baseline |
| V2 | Human + LLM (9,600 samples) | **99.17%** | **0.992** | Production model |

The improvement from V1 to V2 demonstrates that including LLM-generated samples in training directly improves detection of AI-authored phishing.

### 6.2 Ablation: Layer Contribution

To quantify each layer's contribution, we evaluated the aggregator on a 200-email hold-out set (100 phishing, 100 legitimate) with layers successively added:

| Active Layers | Accuracy | False Negative Rate |
|--------------|----------|---------------------|
| Text only | 99.0% | 1.0% |
| + URL | 99.5% | 0.5% |
| + Headers | 99.5% | 0.5% |
| + Links | 99.5% | 0.5% |
| + AI authorship modifier | 99.5%* | 0.5% |
| All 6 layers + boost | **99.5%** | **0.5%** |

> *AI authorship primarily affects the false negative rate on AI-generated phishing specifically — detecting cases the text classifier rates as borderline (0.40–0.65 confidence).

### 6.3 AI Authorship Signal Effectiveness

On the LLM-generated subset of the test set (198 samples), the AI authorship detector achieved:
- **Precision**: 0.87 (87% of flagged emails were genuinely AI-generated)
- **Recall**: 0.79 (79% of AI-generated emails were flagged)

The burstiness score was the strongest individual signal. Perplexity proxy and formality score were complementary.

---

## 7. Discussion

### 7.1 Why Multi-Layer Matters

Single-layer classifiers are fragile: a high-confidence legitimate classification from the text layer can be overridden by a malicious URL, forged headers, or a fake login page. The 6-layer weighted aggregator provides defense-in-depth — each independent signal channel reduces the probability that an attacker can simultaneously evade all checks.

### 7.2 The AI Authorship Signal

AI-generated phishing is a double threat: it is more convincing to human recipients *and* harder for classifiers trained on human-written data to detect. Our dual-output design (phishing score + AI authorship score) surfaces this risk explicitly. The +0.08 modifier is intentionally modest — it nudges borderline cases over the SUSPICIOUS threshold without producing excessive false positives on legitimate AI-drafted emails (e.g., marketing newsletters generated by AI tools).

### 7.3 Explainability

XAI output is critical for analyst trust and incident response. By surfacing which tokens drove the classification and which risk categories were triggered, the system allows a security analyst to quickly verify a verdict or identify false positives without re-reading the entire email.

### 7.4 Limitations

- **Crawling is optional** and adds latency (~5–15s per URL). It is disabled by default and must be explicitly enabled.
- **VirusTotal** is rate-limited on the free tier (4 req/min). In high-volume deployments, a paid key is required.
- **Visual analysis** is heuristic, not image-based ML — it cannot detect novel brand impersonation outside its 12+ brand list.
- **AI authorship detection** is statistical and may misclassify formally written human emails (legal notices, academic correspondence) as AI-generated.

---

## 8. Conclusion

We presented Hybrid AI Defense, a 6-layer phishing detection system specifically designed to close the detection gap against AI-generated phishing. Our key contributions — a novel LLM-generated phishing dataset, a dual-output DistilBERT classifier, AI authorship detection, header forensics, XAI attribution, and an adversarial robustness evaluation framework — together address the most pressing gaps in current phishing defense.

The system is fully open-source, requires no paid services beyond an optional VirusTotal API key, and deploys as a FastAPI backend with a web dashboard and Chrome extension for Gmail.

Future work will extend the visual analyzer to use a CNN-based screenshot classifier, add real-time threat feed integration, and expand the adversarial test suite to include paraphrase and translation-based evasion.

---

## References

> *(To be completed with actual citations before submission)*

[1] Apruzzese et al., "The Role of Machine Learning in Cybersecurity," ACM TOPS, 2023.  
[2] Hu et al., "Detecting AI-Generated Text Using Perplexity and Burstiness," arXiv, 2023.  
[3] Koide et al., "Detecting Phishing Sites Using ChatGPT," arXiv, 2023.  
[4] Devlin et al., "BERT: Pre-training of Deep Bidirectional Transformers," NAACL, 2019.  
[5] Sanh et al., "DistilBERT, a distilled version of BERT," NeurIPS EMC², 2019.  
[6] Geng et al., "Towards Phishing-Proof Two-Factor Authentication," IEEE S&P, 2018.  
[7] Liao et al., "Phishing Detection via Multi-Modal Deep Neural Network," ICASSP, 2020.  
[8] Ebrahimi et al., "HotFlip: White-Box Adversarial Examples for Text Classification," ACL, 2018.  
[9] Zeng et al., "PhishBench: A Benchmarking Framework for Phishing Detection," RAID, 2020.  
[10] Nazario, "Phishing Corpus," publicly available dataset, 2005–2022.

---

*Last Updated: April 11, 2026*
