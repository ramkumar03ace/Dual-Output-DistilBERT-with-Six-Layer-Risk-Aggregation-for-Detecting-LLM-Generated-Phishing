"""
AI Authorship Detection Service

Detects whether an email was written by an AI (LLM) vs a human using
statistical NLP signals:
  1. Burstiness     — humans vary sentence length more than LLMs
  2. Perplexity proxy — LLMs produce unnaturally uniform, low-entropy text
  3. Vocabulary richness — LLMs overuse certain tokens; TTR is higher in humans
  4. Repetition score — bigram/trigram repetition is higher in AI text
  5. Formality markers — LLMs overuse formal discourse connectors
  6. Punctuation uniformity — AI text uses punctuation more predictably

No external model download required — pure statistical analysis.
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import List, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Formal discourse connectors that LLMs overuse
# ---------------------------------------------------------------------------
_FORMAL_CONNECTORS = {
    "furthermore", "moreover", "however", "therefore", "consequently",
    "additionally", "nevertheless", "nonetheless", "subsequently",
    "accordingly", "henceforth", "hereby", "in conclusion", "to summarize",
    "in summary", "it is important", "please note", "kindly", "do not hesitate",
    "should you have", "rest assured", "as per", "at your earliest convenience",
    "we regret to inform", "we are pleased to inform", "we wish to bring",
    "your immediate attention", "dear valued", "sincerely yours",
}

# Urgency / fear phrases (overlap with phishing but LLMs use them formulaically)
_URGENCY_PHRASES = {
    "act now", "immediately", "within 24 hours", "within 48 hours",
    "account will be suspended", "account has been compromised",
    "verify your account", "confirm your identity", "click here to",
    "limited time", "expires soon", "urgent action required",
}


@dataclass
class AIAuthorshipResult:
    is_ai_generated: bool
    ai_authorship_score: float          # 0.0 (human) → 1.0 (AI)
    confidence: float                   # same value, named for schema consistency
    signals: List[str] = field(default_factory=list)
    burstiness_score: float = 0.0       # low = AI-like (uniform sentence lengths)
    perplexity_proxy: float = 0.0       # low = AI-like (low entropy / high predictability)
    vocabulary_richness: float = 0.0    # low TTR = AI-like
    repetition_score: float = 0.0       # high = AI-like
    formality_score: float = 0.0        # high = AI-like


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tokenize_sentences(text: str) -> List[str]:
    """Split text into sentences using punctuation boundaries."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s.strip() for s in sentences if len(s.strip()) > 5]


def _tokenize_words(text: str) -> List[str]:
    """Lowercase word tokens, strip punctuation."""
    return re.findall(r"\b[a-z]{2,}\b", text.lower())


def _burstiness(sentence_lengths: List[int]) -> float:
    """
    Burstiness = (std - mean) / (std + mean)  (Goh & Barabasi, 2008)
    Range: [-1, 1]. Humans ≈ 0.3–0.8, AI ≈ -0.3–0.2
    Returns a normalised score where 1.0 = highly AI-like (low burstiness).
    """
    if len(sentence_lengths) < 3:
        return 0.5  # not enough data

    n = len(sentence_lengths)
    mean = sum(sentence_lengths) / n
    variance = sum((x - mean) ** 2 for x in sentence_lengths) / n
    std = math.sqrt(variance) if variance > 0 else 0.0

    if std + mean == 0:
        return 0.5

    b = (std - mean) / (std + mean)  # in [-1, 1]

    # Normalise: low burstiness (b near -1) → high AI score
    # Human text b ≈ 0.3+, AI text b ≈ -0.2 or lower
    # Map b from [-1, 1] to ai_score [1, 0]
    ai_score = max(0.0, min(1.0, (0.3 - b) / 1.0))
    return round(ai_score, 4)


def _perplexity_proxy(words: List[str]) -> float:
    """
    Proxy for perplexity using unigram entropy of the word distribution.
    AI text has lower entropy (more predictable word choices).
    Returns normalised score: 1.0 = low entropy = AI-like.
    """
    if len(words) < 10:
        return 0.5

    freq: dict = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1

    total = len(words)
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())

    # Typical human email: entropy ≈ 7–10 bits
    # AI email: entropy ≈ 4–7 bits (less lexical diversity, more repetition)
    # Normalise: entropy < 5 → score ≈ 1.0; entropy > 9 → score ≈ 0.0
    ai_score = max(0.0, min(1.0, (9.0 - entropy) / 5.0))
    return round(ai_score, 4)


def _vocabulary_richness(words: List[str]) -> float:
    """
    Type-Token Ratio (TTR) = unique words / total words.
    Low TTR → repetitive vocabulary → more AI-like.
    Returns ai_score: 1.0 = low TTR = AI-like.
    """
    if len(words) < 5:
        return 0.5

    # Use root TTR (RTTR = unique / sqrt(total)) for longer texts
    ttr = len(set(words)) / math.sqrt(len(words))

    # RTTR: AI ≈ 3–6, Human ≈ 6–12
    ai_score = max(0.0, min(1.0, (7.0 - ttr) / 5.0))
    return round(ai_score, 4)


def _repetition_score(words: List[str]) -> float:
    """
    Bigram repetition: ratio of repeated bigrams to total bigrams.
    High repetition → AI-like.
    """
    if len(words) < 4:
        return 0.0

    bigrams = [(words[i], words[i + 1]) for i in range(len(words) - 1)]
    total = len(bigrams)
    unique = len(set(bigrams))
    repeated_ratio = 1.0 - (unique / total)
    # Scale: ratio > 0.4 → very repetitive
    ai_score = max(0.0, min(1.0, repeated_ratio / 0.4))
    return round(ai_score, 4)


def _formality_score(text: str, words: List[str]) -> float:
    """
    Fraction of text covered by known AI/formal discourse markers.
    High coverage → AI-like.
    """
    if not words:
        return 0.0

    text_lower = text.lower()
    connector_hits = sum(1 for c in _FORMAL_CONNECTORS if c in text_lower)
    urgency_hits = sum(1 for u in _URGENCY_PHRASES if u in text_lower)
    total_hits = connector_hits + urgency_hits

    # Normalise against text length (per 100 words)
    hits_per_100 = (total_hits / len(words)) * 100
    ai_score = max(0.0, min(1.0, hits_per_100 / 8.0))
    return round(ai_score, 4)


# ---------------------------------------------------------------------------
# Composite scorer
# ---------------------------------------------------------------------------

# Weights for each signal
_WEIGHTS = {
    "burstiness":   0.30,
    "perplexity":   0.25,
    "vocabulary":   0.15,
    "repetition":   0.15,
    "formality":    0.15,
}

_AI_THRESHOLD = 0.55  # composite score above this → classified as AI-generated


class AIAuthorshipDetector:
    """
    Stateless detector. Call `analyze(text)` to get an AIAuthorshipResult.
    Thread-safe (no mutable state).
    """

    def analyze(self, text: str, subject: str | None = None) -> AIAuthorshipResult:
        """
        Analyse text for AI-authorship signals.

        Args:
            text: Email body
            subject: Optional subject line (prepended for richer analysis)

        Returns:
            AIAuthorshipResult with composite score and per-signal breakdown
        """
        full_text = f"{subject or ''} {text}".strip()

        sentences = _tokenize_sentences(full_text)
        words = _tokenize_words(full_text)

        if len(words) < 10:
            # Too short to analyse reliably
            return AIAuthorshipResult(
                is_ai_generated=False,
                ai_authorship_score=0.0,
                confidence=0.0,
                signals=["Text too short for reliable AI authorship analysis"],
            )

        sentence_lengths = [len(_tokenize_words(s)) for s in sentences]

        # --- Compute individual signals ---
        b_score = _burstiness(sentence_lengths)
        p_score = _perplexity_proxy(words)
        v_score = _vocabulary_richness(words)
        r_score = _repetition_score(words)
        f_score = _formality_score(full_text, words)

        # --- Weighted composite ---
        composite = (
            b_score * _WEIGHTS["burstiness"]
            + p_score * _WEIGHTS["perplexity"]
            + v_score * _WEIGHTS["vocabulary"]
            + r_score * _WEIGHTS["repetition"]
            + f_score * _WEIGHTS["formality"]
        )
        composite = round(min(1.0, composite), 4)

        is_ai = composite >= _AI_THRESHOLD

        # --- Human-readable signals ---
        signals: List[str] = []
        if b_score >= 0.60:
            signals.append(
                f"Low sentence-length burstiness ({b_score:.2f}) — uniform structure typical of LLMs"
            )
        if p_score >= 0.60:
            signals.append(
                f"Low lexical entropy ({p_score:.2f}) — predictable word choices typical of AI"
            )
        if v_score >= 0.60:
            signals.append(
                f"Low vocabulary richness ({v_score:.2f}) — limited lexical diversity"
            )
        if r_score >= 0.50:
            signals.append(
                f"High bigram repetition ({r_score:.2f}) — repeated phrase patterns"
            )
        if f_score >= 0.50:
            signals.append(
                f"High formal/AI discourse marker density ({f_score:.2f})"
            )
        if not signals and is_ai:
            signals.append("Multiple weak AI-authorship signals detected")
        if not signals:
            signals.append("No strong AI-authorship signals detected")

        logger.debug(
            "AI authorship: composite=%.4f is_ai=%s b=%.4f p=%.4f v=%.4f r=%.4f f=%.4f",
            composite, is_ai, b_score, p_score, v_score, r_score, f_score,
        )

        return AIAuthorshipResult(
            is_ai_generated=is_ai,
            ai_authorship_score=composite,
            confidence=composite,
            signals=signals,
            burstiness_score=b_score,
            perplexity_proxy=p_score,
            vocabulary_richness=v_score,
            repetition_score=r_score,
            formality_score=f_score,
        )


# Module-level singleton
ai_authorship_detector = AIAuthorshipDetector()
