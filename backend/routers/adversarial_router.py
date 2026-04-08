"""
Adversarial Robustness Testing API router.

POST /api/v1/adversarial-test
  → Runs homoglyph, zero-width, URL obfuscation, and prompt-evasion
    attack variants against the full detection stack and returns a
    structured resilience report.
"""

import asyncio
import logging
from fastapi import APIRouter, HTTPException

from models.schemas import AdversarialRobustnessRequest, AdversarialRobustnessResponse, AdversarialAttackResult
from analyzers.adversarial_tester import adversarial_tester
from services.email_classifier import classifier
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix=settings.API_V1_PREFIX, tags=["Adversarial Robustness"])


@router.post("/adversarial-test", response_model=AdversarialRobustnessResponse)
async def adversarial_robustness_test(request: AdversarialRobustnessRequest):
    """
    Run a battery of adversarial evasion attacks against the detection pipeline.

    Tests four attack categories:
    - **Homoglyph substitution** — replace chars in brand names with Unicode lookalikes
    - **Zero-width injection** — embed invisible Unicode characters in the body
    - **URL obfuscation** — hex encoding, IP hosts, @ trick, IDN, shorteners
    - **Prompt-style evasion** — prepend LLM prompt phrases to confuse the classifier

    Returns per-variant results and an aggregate resilience score.
    """
    if not classifier.is_loaded():
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please try again later."
        )

    try:
        report = await asyncio.to_thread(
            adversarial_tester.run_tests,
            request.text,
            request.subject,
            classifier,
        )

        return AdversarialRobustnessResponse(
            total_tests=report.total_tests,
            evasion_successes=report.evasion_successes,
            evasion_rate=report.evasion_rate,
            resilience_score=report.resilience_score,
            summary=report.summary,
            attack_breakdown=report.attack_breakdown,
            results=[
                AdversarialAttackResult(
                    attack_type=r.attack_type,
                    variant_name=r.variant_name,
                    original_score=r.original_score,
                    adversarial_score=r.adversarial_score,
                    score_delta=r.score_delta,
                    evasion_success=r.evasion_success,
                    detection_notes=r.detection_notes,
                )
                for r in report.results
            ],
        )

    except Exception as e:
        logger.error(f"Adversarial test error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error during adversarial testing: {str(e)}"
        )
