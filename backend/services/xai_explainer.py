"""
Explainable AI (XAI) Service — Priority 2

Provides token-level attribution and human-readable risk explanations for
DistilBERT phishing predictions without requiring SHAP/LIME (which need large
dependencies). Uses two complementary techniques:

1. Attention-based attribution — extracts the [CLS]-averaged attention weights
   from the last DistilBERT transformer layer and maps them back to tokens.
   High attention weight → token contributed more to the classification.

2. Leave-one-out (LOO) perturbation — for the top-N suspicious tokens found via
   attention, masks each token with [MASK] and measures the confidence delta.
   Positive delta (confidence drops) → token was helping drive phishing label.

3. Human-readable explanation builder — maps high-attribution token clusters to
   named risk categories (urgency, credential_request, brand_impersonation, etc.)
   and composes a plain-English explanation sentence.

No external model download required beyond the already-loaded DistilBERT.
"""

import re
import logging
import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Risk phrase categories for rule-based enrichment
# These complement attention attribution with deterministic signal labelling.
# -------------------------------------------------------------------------

_URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bwithin \d+ hours?\b",
    r"\bexpires?\b", r"\bdeadline\b", r"\bas soon as possible\b", r"\basap\b",
    r"\blimited time\b", r"\blast chance\b", r"\bfinal (notice|warning|reminder)\b",
]

_CREDENTIAL_PATTERNS = [
    r"\bverify\b", r"\bconfirm\b", r"\bvalidate\b", r"\bupdate (your )?account\b",
    r"\bclick here\b", r"\bsign in\b", r"\blog in\b", r"\bpassword\b",
    r"\bpin\b", r"\bcredentials?\b", r"\bsecurity code\b", r"\botp\b",
    r"\bsocial security\b", r"\bcredit card\b",
]

_THREAT_PATTERNS = [
    r"\bsuspended?\b", r"\bterminated?\b", r"\bblocked?\b", r"\bcompromised?\b",
    r"\bunauthorized\b", r"\bfraud\b", r"\bbreached?\b", r"\bdetected\b",
    r"\bviolat\w+\b", r"\bsuspicious activity\b", r"\baccount (will be|has been)\b",
]

_REWARD_PATTERNS = [
    r"\bwon\b", r"\bwinner\b", r"\bcongratulations?\b", r"\bprize\b",
    r"\breward\b", r"\bgift\b", r"\bfree\b", r"\bunclaimed\b", r"\bcash\b",
    r"\blottery\b", r"\bselected\b",
]

_BRAND_PATTERNS = [
    r"\bpaypal\b", r"\bamazon\b", r"\bnetflix\b", r"\bapple\b", r"\bmicrosoft\b",
    r"\bgoogle\b", r"\bfacebook\b", r"\binstagram\b", r"\btwitter\b", r"\bchase\b",
    r"\bbank of america\b", r"\bwells fargo\b", r"\bciti\b", r"\bbarclays\b",
    r"\bdhl\b", r"\bfedex\b", r"\bups\b", r"\blinkedin\b", r"\bdropbox\b",
]

_URL_PATTERNS = [
    r"https?://\S+", r"\bclick\b.*\blink\b", r"\bbelow\b.*\blink\b",
    r"\bfollowing link\b", r"\bbutton below\b",
]

_CATEGORY_LABELS = {
    "urgency":            "urgency / time pressure",
    "credential_request": "credential / account request",
    "threat":             "threat / account suspension",
    "reward":             "reward / prize lure",
    "brand_impersonation":"brand impersonation",
    "suspicious_url":     "suspicious URL / link",
}


# -------------------------------------------------------------------------
# Data classes
# -------------------------------------------------------------------------

@dataclass
class TokenAttribution:
    token: str
    score: float          # 0.0 – 1.0, higher = more responsible for classification
    is_highlighted: bool  # True if score > threshold


@dataclass
class XAIExplanation:
    # Token-level attribution
    tokens: List[TokenAttribution] = field(default_factory=list)

    # Top influential tokens (already filtered, sorted by score desc)
    top_tokens: List[str] = field(default_factory=list)

    # Detected risk categories (keys from _CATEGORY_LABELS)
    risk_categories: List[str] = field(default_factory=list)

    # Plain-English explanation
    explanation: str = ""

    # Short one-liner for the API response
    summary: str = ""

    # Confidence delta from LOO on top token (how much removing it drops score)
    top_token_confidence_delta: float = 0.0

    # Whether XAI ran successfully
    available: bool = True


# -------------------------------------------------------------------------
# Rule-based signal extraction (no model required)
# -------------------------------------------------------------------------

def _detect_risk_categories(text: str) -> List[str]:
    """Return list of risk category keys found in text."""
    text_l = text.lower()
    cats = []
    if any(re.search(p, text_l) for p in _URGENCY_PATTERNS):
        cats.append("urgency")
    if any(re.search(p, text_l) for p in _CREDENTIAL_PATTERNS):
        cats.append("credential_request")
    if any(re.search(p, text_l) for p in _THREAT_PATTERNS):
        cats.append("threat")
    if any(re.search(p, text_l) for p in _REWARD_PATTERNS):
        cats.append("reward")
    if any(re.search(p, text_l) for p in _BRAND_PATTERNS):
        cats.append("brand_impersonation")
    if any(re.search(p, text_l) for p in _URL_PATTERNS):
        cats.append("suspicious_url")
    return cats


def _highlight_spans(text: str) -> List[Tuple[str, float]]:
    """
    Returns list of (word, attribution_score) pairs from rule-based matching.
    Words matching risk patterns get high scores; others get low scores.
    """
    words = re.findall(r"\S+", text)
    text_l = text.lower()
    all_patterns = (
        _URGENCY_PATTERNS
        + _CREDENTIAL_PATTERNS
        + _THREAT_PATTERNS
        + _REWARD_PATTERNS
        + _BRAND_PATTERNS
    )

    result = []
    for word in words:
        word_clean = re.sub(r"[^\w]", "", word).lower()
        score = 0.05  # baseline
        for pat in all_patterns:
            if re.search(pat, word_clean):
                score = max(score, 0.85)
                break
            # Partial match — word appears inside the pattern match region
            if re.search(pat, text_l) and word_clean in text_l:
                m = re.search(pat, text_l)
                if m and word_clean in m.group(0):
                    score = max(score, 0.75)
        result.append((word, round(score, 3)))
    return result


# -------------------------------------------------------------------------
# Attention-based attribution (uses loaded DistilBERT model)
# -------------------------------------------------------------------------

def _attention_attribution(
    text: str,
    classifier,
    max_tokens: int = 512,
) -> List[Tuple[str, float]]:
    """
    Extract token-level attribution using CLS-averaged attention from the
    last DistilBERT transformer layer.

    Returns list of (token_str, normalised_score) sorted by original position.
    """
    try:
        import torch
        from utils.text_preprocessor import clean_text

        model = classifier.model
        tokenizer = classifier.tokenizer
        device = classifier.device

        cleaned = clean_text(text)
        inputs = tokenizer(
            cleaned,
            return_tensors="pt",
            truncation=True,
            max_length=max_tokens,
            padding=True,
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs, output_attentions=True)

        # outputs.attentions: tuple of (n_layers,) each shape (batch, heads, seq, seq)
        # Use last layer, average across heads, take CLS (index 0) attention row
        last_layer_attn = outputs.attentions[-1]          # (1, heads, seq, seq)
        cls_attn = last_layer_attn[0].mean(dim=0)[0]      # (seq,) — CLS attends to each token

        tokens = tokenizer.convert_ids_to_tokens(inputs["input_ids"][0])
        scores = cls_attn.cpu().tolist()

        # Normalise to [0, 1]
        max_s = max(scores) if scores else 1.0
        min_s = min(scores) if scores else 0.0
        rng = max_s - min_s or 1.0
        normed = [(t, round((s - min_s) / rng, 4)) for t, s in zip(tokens, scores)]

        # Filter special tokens
        normed = [(t, s) for t, s in normed if t not in ("[CLS]", "[SEP]", "[PAD]", "<s>", "</s>")]
        return normed

    except Exception as e:
        logger.warning("Attention attribution failed: %s", e)
        return []


def _merge_wordpiece_tokens(token_scores: List[Tuple[str, float]]) -> List[Tuple[str, float]]:
    """
    Merge DistilBERT word-piece sub-tokens (those starting with '##') into
    whole words and take the max score across sub-tokens.
    """
    merged = []
    buf_word = ""
    buf_score = 0.0
    for tok, score in token_scores:
        if tok.startswith("##"):
            buf_word += tok[2:]
            buf_score = max(buf_score, score)
        else:
            if buf_word:
                merged.append((buf_word, buf_score))
            buf_word = tok
            buf_score = score
    if buf_word:
        merged.append((buf_word, buf_score))
    return merged


# -------------------------------------------------------------------------
# LOO perturbation for top token
# -------------------------------------------------------------------------

def _loo_delta(text: str, top_token: str, classifier) -> float:
    """
    Leave-one-out: remove top_token from text and measure confidence change.
    Returns delta (positive = token was driving phishing confidence up).
    """
    try:
        original_confidence = classifier.predict(text)[1]
        masked_text = re.sub(r"\b" + re.escape(top_token) + r"\b", "", text, flags=re.IGNORECASE)
        masked_text = re.sub(r"\s{2,}", " ", masked_text).strip()
        masked_confidence = classifier.predict(masked_text)[1]
        return round(original_confidence - masked_confidence, 4)
    except Exception:
        return 0.0


# -------------------------------------------------------------------------
# Human-readable explanation builder
# -------------------------------------------------------------------------

def _build_explanation(
    risk_categories: List[str],
    top_tokens: List[str],
    is_phishing: bool,
    confidence: float,
) -> Tuple[str, str]:
    """
    Returns (full_explanation, short_summary).
    """
    if not is_phishing:
        summary = "Email appears legitimate — no strong phishing signals detected."
        explanation = (
            f"The model classified this email as LEGITIMATE with {confidence:.0%} confidence. "
            "No significant urgency language, credential requests, or suspicious patterns were found."
        )
        return explanation, summary

    cat_labels = [_CATEGORY_LABELS[c] for c in risk_categories if c in _CATEGORY_LABELS]
    top_tok_str = ", ".join(f'"{t}"' for t in top_tokens[:5]) if top_tokens else "multiple phrases"

    parts = []
    if cat_labels:
        parts.append(f"flagged because: {' + '.join(cat_labels)}")
    if top_tokens:
        parts.append(f"key trigger words: {top_tok_str}")

    summary = "Flagged: " + ("; ".join(parts) if parts else "high phishing signal")

    explanation_lines = [
        f"The model classified this email as PHISHING with {confidence:.0%} confidence."
    ]
    if "urgency" in risk_categories:
        explanation_lines.append("• Urgency / time-pressure language detected — a hallmark of phishing emails designed to rush the recipient.")
    if "credential_request" in risk_categories:
        explanation_lines.append("• Credential or account-action request found — phishing emails frequently ask recipients to verify, confirm, or log in.")
    if "threat" in risk_categories:
        explanation_lines.append("• Threat / account-suspension language detected — fear-based manipulation is a common social engineering tactic.")
    if "reward" in risk_categories:
        explanation_lines.append("• Reward / prize lure present — unexpected winnings are a classic phishing hook.")
    if "brand_impersonation" in risk_categories:
        explanation_lines.append("• Known brand name detected — phishing emails commonly impersonate trusted brands to gain credibility.")
    if "suspicious_url" in risk_categories:
        explanation_lines.append("• Suspicious link or click-through instruction present — phishing relies on directing victims to fraudulent pages.")
    if top_tokens:
        explanation_lines.append(f"• Highest-attribution tokens: {top_tok_str}.")

    return "\n".join(explanation_lines), summary


# -------------------------------------------------------------------------
# Main XAI Explainer class
# -------------------------------------------------------------------------

HIGHLIGHT_THRESHOLD = 0.55   # tokens above this score get highlighted
TOP_N_TOKENS = 10            # max tokens to return in top_tokens list


class XAIExplainer:
    """
    Generates token-level attributions and human-readable risk explanations.
    Thread-safe (stateless after init).
    """

    def explain(
        self,
        text: str,
        subject: Optional[str],
        is_phishing: bool,
        confidence: float,
        classifier,          # EmailClassifier instance (may be None in tests)
    ) -> XAIExplanation:
        """
        Run full XAI pipeline:
        1. Attention attribution (if model available)
        2. Rule-based category detection
        3. Token scoring (attention + rule merge)
        4. LOO delta on top token
        5. Build explanation text

        Args:
            text: Email body
            subject: Optional subject
            is_phishing: Model prediction
            confidence: Model confidence score
            classifier: Loaded EmailClassifier (for attention + LOO)

        Returns:
            XAIExplanation
        """
        full_text = f"{subject or ''} {text}".strip()

        try:
            # --- Step 1: Attention attribution ---
            attn_scores: List[Tuple[str, float]] = []
            if classifier is not None and classifier.is_loaded():
                raw_attn = _attention_attribution(full_text, classifier)
                attn_scores = _merge_wordpiece_tokens(raw_attn)

            # --- Step 2: Rule-based categories ---
            risk_categories = _detect_risk_categories(full_text)

            # --- Step 3: Rule-based word scores ---
            rule_scores = dict(_highlight_spans(full_text))

            # --- Step 4: Merge attention + rule scores ---
            # If attention available: blend 60% attention + 40% rule
            # Otherwise: 100% rule-based
            if attn_scores:
                attn_dict = {t.lower().lstrip("##"): s for t, s in attn_scores}
                merged: List[Tuple[str, float]] = []
                for word, rule_s in _highlight_spans(full_text):
                    word_key = word.lower().lstrip("##")
                    attn_s = attn_dict.get(word_key, rule_s * 0.5)
                    blended = round(attn_s * 0.6 + rule_s * 0.4, 4)
                    merged.append((word, blended))
            else:
                merged = list(_highlight_spans(full_text))

            # Normalise merged scores to [0, 1]
            if merged:
                max_m = max(s for _, s in merged) or 1.0
                merged = [(w, round(s / max_m, 4)) for w, s in merged]

            # Build TokenAttribution list
            token_attrs = [
                TokenAttribution(
                    token=w,
                    score=s,
                    is_highlighted=s >= HIGHLIGHT_THRESHOLD,
                )
                for w, s in merged
            ]

            # Top tokens (unique, stripped of punctuation, score-sorted)
            seen = set()
            top_tokens = []
            for ta in sorted(token_attrs, key=lambda x: x.score, reverse=True):
                clean_tok = re.sub(r"[^\w]", "", ta.token).lower()
                if len(clean_tok) > 2 and clean_tok not in seen and ta.is_highlighted:
                    seen.add(clean_tok)
                    top_tokens.append(ta.token)
                    if len(top_tokens) >= TOP_N_TOKENS:
                        break

            # --- Step 5: LOO delta on single most influential token ---
            delta = 0.0
            if top_tokens and is_phishing and classifier is not None and classifier.is_loaded():
                delta = _loo_delta(full_text, top_tokens[0], classifier)

            # --- Step 6: Build explanation ---
            explanation, summary = _build_explanation(
                risk_categories, top_tokens, is_phishing, confidence
            )

            return XAIExplanation(
                tokens=token_attrs,
                top_tokens=top_tokens,
                risk_categories=risk_categories,
                explanation=explanation,
                summary=summary,
                top_token_confidence_delta=delta,
                available=True,
            )

        except Exception as e:
            logger.error("XAI explanation failed: %s", e)
            return XAIExplanation(
                available=False,
                explanation="XAI explanation unavailable.",
                summary="XAI unavailable.",
            )


# Module-level singleton
xai_explainer = XAIExplainer()
