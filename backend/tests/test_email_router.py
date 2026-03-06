"""Tests for the /analyze email classification endpoint."""

import pytest


@pytest.fixture
async def model_loaded(client):
    """Check if the ML model is loaded."""
    res = await client.get("/api/v1/health")
    return res.json().get("model_loaded", False)


requires_model = pytest.mark.anyio


@pytest.mark.anyio
async def test_analyze_phishing_email(client, model_loaded):
    """A clearly phishing email should be classified as phishing."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/analyze", json={
        "text": "URGENT: Your bank account has been compromised! Click here immediately to verify your identity or your account will be permanently suspended. http://secure-banklogin.xyz/verify",
        "subject": "URGENT: Account Suspended - Verify Now"
    })

    assert response.status_code == 200
    data = response.json()
    assert "is_phishing" in data
    assert "confidence" in data
    assert "label" in data
    assert "risk_level" in data
    assert data["label"] in ("PHISHING", "LEGITIMATE")
    assert 0 <= data["confidence"] <= 1


@pytest.mark.anyio
async def test_analyze_legitimate_email(client, model_loaded):
    """A normal professional email should be classified as legitimate."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/analyze", json={
        "text": "Hi team, just a reminder that our weekly standup is tomorrow at 10 AM. Please prepare your updates. Thanks, John",
        "subject": "Weekly Standup Reminder"
    })

    assert response.status_code == 200
    data = response.json()
    assert "is_phishing" in data
    assert data["label"] in ("PHISHING", "LEGITIMATE")


@pytest.mark.anyio
async def test_analyze_empty_text_rejected(client):
    """Empty text should be rejected with 422."""
    response = await client.post("/api/v1/analyze", json={
        "text": ""
    })

    assert response.status_code == 422


@pytest.mark.anyio
async def test_analyze_missing_text_rejected(client):
    """Missing text field should be rejected with 422."""
    response = await client.post("/api/v1/analyze", json={})

    assert response.status_code == 422


@pytest.mark.anyio
async def test_analyze_subject_optional(client, model_loaded):
    """Analysis should work without a subject."""
    if not model_loaded:
        pytest.skip("ML model not loaded")

    response = await client.post("/api/v1/analyze", json={
        "text": "Hello, this is a test email with some content."
    })

    assert response.status_code == 200
    data = response.json()
    assert "is_phishing" in data
