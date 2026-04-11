"""Tests for the /deep-analyze 6-layer pipeline endpoint."""

import pytest


@pytest.fixture
async def model_loaded(client):
    """Check if the ML model is loaded."""
    res = await client.get("/api/v1/health")
    return res.json().get("model_loaded", False)


# ---------------------------------------------------------------------------
# Response shape & basic pipeline
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_deep_analyze_response_shape(client, model_loaded):
    """Deep analysis should return all expected top-level fields."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Dear user, your PayPal account has been limited. Log in at http://paypal-secure.xyz to restore access.",
        "subject": "PayPal Account Limited",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    data = response.json()

    for field in (
        "text_analysis", "urls_found", "urls_list",
        "overall_verdict", "overall_risk_score",
        "risk_factors", "analysis_layers",
        "ai_authorship", "xai_explanation",
    ):
        assert field in data, f"Missing field: {field}"

    assert isinstance(data["urls_found"], int)
    assert isinstance(data["urls_list"], list)
    assert data["overall_verdict"] in ("SAFE", "SUSPICIOUS", "PHISHING")
    assert 0 <= data["overall_risk_score"] <= 1
    assert isinstance(data["analysis_layers"], list)
    assert "text_classification" in data["analysis_layers"]


@pytest.mark.anyio
async def test_deep_analyze_no_urls(client, model_loaded):
    """Deep analysis on text without URLs should still work."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Hi team, please review the attached document and provide feedback by Friday.",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    data = response.json()
    assert data["urls_found"] == 0
    assert data["url_analysis"] is None


@pytest.mark.anyio
async def test_deep_analyze_with_urls_no_crawl(client, model_loaded):
    """URLs present but crawling disabled — crawl/visual layers should be empty."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Check out https://www.google.com for more information.",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    data = response.json()
    assert data["urls_found"] >= 1
    assert data["crawl_results"] == []
    assert data["visual_analysis"] == []


@pytest.mark.anyio
async def test_deep_analyze_empty_text_rejected(client):
    """Empty text should be rejected with 422."""
    response = await client.post("/api/v1/deep-analyze", json={"text": ""})
    assert response.status_code == 422


@pytest.mark.anyio
async def test_deep_analyze_text_analysis_shape(client, model_loaded):
    """Text analysis sub-object should have all required fields."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Congratulations! You've won a free iPhone. Claim now!",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    text = response.json()["text_analysis"]
    for field in ("is_phishing", "confidence", "label", "risk_level"):
        assert field in text, f"Missing field in text_analysis: {field}"
    assert 0 <= text["confidence"] <= 1
    assert text["label"] in ("PHISHING", "LEGITIMATE")


# ---------------------------------------------------------------------------
# AI Authorship Detection layer
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_ai_authorship_present_in_response(client, model_loaded):
    """ai_authorship object must always be in the deep-analyze response."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Please verify your account immediately by clicking the link below.",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    auth = response.json()["ai_authorship"]
    assert auth is not None

    for field in (
        "is_ai_generated", "ai_authorship_score",
        "burstiness_score", "perplexity_proxy",
        "vocabulary_richness", "repetition_score", "formality_score",
        "signals",
    ):
        assert field in auth, f"Missing ai_authorship field: {field}"

    assert isinstance(auth["is_ai_generated"], bool)
    assert 0 <= auth["ai_authorship_score"] <= 1
    assert isinstance(auth["signals"], list)


@pytest.mark.anyio
async def test_ai_authorship_layer_in_analysis_layers(client, model_loaded):
    """ai_authorship_detection should always appear in analysis_layers."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Your account requires verification. Please click here.",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    assert "ai_authorship_detection" in response.json()["analysis_layers"]


# ---------------------------------------------------------------------------
# XAI Explanation layer
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_xai_explanation_present(client, model_loaded):
    """xai_explanation must be present and have required fields."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Urgent: click http://phishingsite.xyz to verify your account.",
        "subject": "Verify now",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    xai = response.json()["xai_explanation"]
    assert xai is not None

    for field in (
        "available", "tokens", "top_tokens",
        "risk_categories", "explanation", "summary",
        "top_token_confidence_delta",
    ):
        assert field in xai, f"Missing xai_explanation field: {field}"

    assert isinstance(xai["tokens"], list)
    assert isinstance(xai["top_tokens"], list)
    assert isinstance(xai["risk_categories"], list)
    assert isinstance(xai["explanation"], str)


@pytest.mark.anyio
async def test_xai_layer_in_analysis_layers(client, model_loaded):
    """xai_explanation should always appear in analysis_layers."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Click here to verify your bank account.",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    assert "xai_explanation" in response.json()["analysis_layers"]


# ---------------------------------------------------------------------------
# Layer 6: Header Forensics
# ---------------------------------------------------------------------------

PHISHING_HEADERS = """\
From: PayPal Security <security@paypa1-support.com>
Reply-To: harvest@evil.ru
Return-Path: <bounce@spammer.xyz>
Received: from mail1.relay.ru (mail1.relay.ru [185.220.101.1]) by mx.example.com
Received: from mail2.relay.ru (mail2.relay.ru [185.220.101.2]) by mail1.relay.ru
Received: from origin.evil.com by mail2.relay.ru
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-support.com; dkim=fail; dmarc=fail
Date: Mon, 01 Jan 2024 12:00:00 +0000
Subject: Your PayPal account is limited
"""

CLEAN_HEADERS = """\
From: GitHub <noreply@github.com>
Reply-To: noreply@github.com
Return-Path: <noreply@github.com>
Received: from smtp.github.com (smtp.github.com [192.30.252.1]) by mx.example.com
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=github.com; dkim=pass; dmarc=pass
Date: Mon, 01 Jan 2024 12:00:00 +0000
Subject: GitHub notification
"""


@pytest.mark.anyio
async def test_header_forensics_with_suspicious_headers(client, model_loaded):
    """Phishing headers should produce a non-zero header_analysis risk score."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Your PayPal account has been limited. Verify now.",
        "subject": "Your PayPal account is limited",
        "raw_headers": PHISHING_HEADERS,
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    data = response.json()
    assert data["header_analysis"] is not None

    ha = data["header_analysis"]
    for field in (
        "spf_result", "dkim_result", "dmarc_result",
        "reply_to_mismatch", "return_path_mismatch",
        "is_suspicious", "risk_score", "flags",
    ):
        assert field in ha, f"Missing header_analysis field: {field}"

    assert ha["risk_score"] > 0
    assert ha["is_suspicious"] is True
    assert "header_forensics" in data["analysis_layers"]


@pytest.mark.anyio
async def test_header_forensics_spf_dkim_dmarc_parsed(client, model_loaded):
    """SPF/DKIM/DMARC results should be correctly parsed from phishing headers."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Click to verify your account.",
        "raw_headers": PHISHING_HEADERS,
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    ha = response.json()["header_analysis"]
    assert ha["spf_result"] == "fail"
    assert ha["dkim_result"] == "fail"
    assert ha["dmarc_result"] == "fail"


@pytest.mark.anyio
async def test_header_forensics_reply_to_mismatch(client, model_loaded):
    """Reply-To mismatch should be flagged for phishing headers."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Verify your account now.",
        "raw_headers": PHISHING_HEADERS,
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    ha = response.json()["header_analysis"]
    assert ha["reply_to_mismatch"] is True


@pytest.mark.anyio
async def test_header_forensics_clean_headers_low_risk(client, model_loaded):
    """Clean/legitimate headers should produce a low risk score."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "This is your GitHub notification.",
        "raw_headers": CLEAN_HEADERS,
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    ha = response.json()["header_analysis"]
    assert ha["risk_score"] < 0.40


@pytest.mark.anyio
async def test_header_forensics_absent_when_no_headers(client, model_loaded):
    """header_analysis should be None when raw_headers is not provided."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Your account requires verification.",
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    assert response.json()["header_analysis"] is None


# ---------------------------------------------------------------------------
# Weighted aggregator / scoring
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_risk_score_is_bounded(client, model_loaded):
    """Combined risk score must always be in [0, 1]."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "URGENT: Your account is suspended. Verify at http://evil-login.xyz now!",
        "subject": "Account suspended",
        "raw_headers": PHISHING_HEADERS,
        "crawl_urls": False,
        "take_screenshots": False,
    })

    assert response.status_code == 200
    score = response.json()["overall_risk_score"]
    assert 0 <= score <= 1


@pytest.mark.anyio
async def test_phishing_email_with_headers_scores_higher(client, model_loaded):
    """Phishing email + phishing headers should score higher than text alone."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    payload_base = {
        "text": "Dear customer, verify your PayPal account at http://paypal-secure.xyz or it will be closed.",
        "subject": "Account verification required",
        "crawl_urls": False,
        "take_screenshots": False,
    }

    r_no_headers = await client.post("/api/v1/deep-analyze", json=payload_base)
    r_with_headers = await client.post("/api/v1/deep-analyze", json={
        **payload_base, "raw_headers": PHISHING_HEADERS,
    })

    assert r_no_headers.status_code == 200
    assert r_with_headers.status_code == 200

    score_no_headers = r_no_headers.json()["overall_risk_score"]
    score_with_headers = r_with_headers.json()["overall_risk_score"]

    assert score_with_headers >= score_no_headers, (
        f"Adding phishing headers should raise the score "
        f"({score_no_headers:.3f} → {score_with_headers:.3f})"
    )


@pytest.mark.anyio
async def test_verdict_matches_risk_score(client, model_loaded):
    """Verdict thresholds must be consistent with overall_risk_score."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    for text in [
        "Hi team, meeting at 10 AM tomorrow.",
        "Your account is limited. Click http://phish.xyz to verify.",
    ]:
        response = await client.post("/api/v1/deep-analyze", json={
            "text": text,
            "crawl_urls": False,
            "take_screenshots": False,
        })
        assert response.status_code == 200
        data = response.json()
        score = data["overall_risk_score"]
        verdict = data["overall_verdict"]

        if score >= 0.65:
            assert verdict == "PHISHING", f"score={score:.3f} should be PHISHING"
        elif score >= 0.30:
            assert verdict == "SUSPICIOUS", f"score={score:.3f} should be SUSPICIOUS"
        else:
            assert verdict == "SAFE", f"score={score:.3f} should be SAFE"


# ---------------------------------------------------------------------------
# Adversarial robustness endpoint
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_adversarial_test_response_shape(client, model_loaded):
    """Adversarial test endpoint should return a structured robustness report."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/adversarial-test", json={
        "text": "Your PayPal account has been limited. Verify immediately at http://paypal-secure.xyz",
        "subject": "Account Limited",
    })

    assert response.status_code == 200
    data = response.json()

    for field in (
        "total_tests", "evasion_successes", "evasion_rate",
        "resilience_score", "summary", "attack_breakdown", "results",
    ):
        assert field in data, f"Missing adversarial response field: {field}"

    assert data["total_tests"] > 0
    assert 0 <= data["evasion_rate"] <= 1
    assert 0 <= data["resilience_score"] <= 1
    assert abs(data["evasion_rate"] + data["resilience_score"] - 1.0) < 0.001
    assert isinstance(data["results"], list)
    assert isinstance(data["attack_breakdown"], dict)


@pytest.mark.anyio
async def test_adversarial_test_attack_types_present(client, model_loaded):
    """All four attack categories should appear in the breakdown."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/adversarial-test", json={
        "text": "URGENT: Verify your Microsoft account at http://microsoft-login.xyz or be locked out.",
    })

    assert response.status_code == 200
    breakdown = response.json()["attack_breakdown"]
    for attack_type in ("homoglyph", "zero_width", "url_obfuscation", "prompt_evasion"):
        assert attack_type in breakdown, f"Missing attack type in breakdown: {attack_type}"


@pytest.mark.anyio
async def test_adversarial_test_per_variant_result_shape(client, model_loaded):
    """Each variant result should have the required fields."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/adversarial-test", json={
        "text": "Click here to reset your Apple ID password at http://apple.xyz.",
    })

    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) > 0

    for r in results:
        for field in (
            "attack_type", "variant_name",
            "original_score", "adversarial_score",
            "score_delta", "evasion_success", "detection_notes",
        ):
            assert field in r, f"Missing per-variant field: {field}"
        assert 0 <= r["original_score"] <= 1
        assert 0 <= r["adversarial_score"] <= 1
        assert isinstance(r["evasion_success"], bool)
        assert isinstance(r["detection_notes"], list)


@pytest.mark.anyio
async def test_adversarial_test_short_text_rejected(client):
    """Text shorter than 10 chars should be rejected with 422."""
    response = await client.post("/api/v1/adversarial-test", json={
        "text": "short",
    })
    assert response.status_code == 422
