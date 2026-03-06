"""Tests for the /health endpoint."""

import pytest


@pytest.mark.anyio
async def test_health_returns_200(client):
    """Health check should always return 200."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_health_response_shape(client):
    """Health response must contain status, model_loaded, and version."""
    response = await client.get("/api/v1/health")
    data = response.json()

    assert "status" in data
    assert "model_loaded" in data
    assert "version" in data
    assert data["status"] in ("healthy", "degraded")
    assert isinstance(data["model_loaded"], bool)
