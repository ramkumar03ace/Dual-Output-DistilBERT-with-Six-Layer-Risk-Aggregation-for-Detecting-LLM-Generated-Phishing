"""Tests for the /deep-analyze 5-layer pipeline endpoint."""

import pytest


@pytest.fixture
async def model_loaded(client):
    """Check if the ML model is loaded."""
    res = await client.get("/api/v1/health")
    return res.json().get("model_loaded", False)


@pytest.mark.anyio
async def test_deep_analyze_response_shape(client, model_loaded):
    """Deep analysis should return all expected fields."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Dear user, your PayPal account has been limited. Log in at http://paypal-secure.xyz to restore access.",
        "subject": "PayPal Account Limited",
        "crawl_urls": False,
        "take_screenshots": False
    })

    assert response.status_code == 200
    data = response.json()

    # Check all expected top-level fields
    assert "text_analysis" in data
    assert "urls_found" in data
    assert "urls_list" in data
    assert "overall_verdict" in data
    assert "overall_risk_score" in data
    assert "risk_factors" in data
    assert "analysis_layers" in data

    # Verify types
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
        "take_screenshots": False
    })

    assert response.status_code == 200
    data = response.json()
    assert data["urls_found"] == 0
    assert data["url_analysis"] is None


@pytest.mark.anyio
async def test_deep_analyze_with_urls_no_crawl(client, model_loaded):
    """Deep analysis with URLs but crawling disabled should skip crawl/visual layers."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Check out https://www.google.com for more information.",
        "crawl_urls": False,
        "take_screenshots": False
    })

    assert response.status_code == 200
    data = response.json()
    assert data["urls_found"] >= 1
    assert data["crawl_results"] == []
    assert data["visual_analysis"] == []


@pytest.mark.anyio
async def test_deep_analyze_empty_text_rejected(client):
    """Empty text should be rejected."""
    response = await client.post("/api/v1/deep-analyze", json={
        "text": ""
    })

    assert response.status_code == 422


@pytest.mark.anyio
async def test_deep_analyze_text_analysis_included(client, model_loaded):
    """Text analysis sub-object should have correct shape."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/deep-analyze", json={
        "text": "Congratulations! You've won a free iPhone. Claim now!",
        "crawl_urls": False,
        "take_screenshots": False
    })

    assert response.status_code == 200
    text = response.json()["text_analysis"]
    assert "is_phishing" in text
    assert "confidence" in text
    assert "label" in text
    assert "risk_level" in text
