"""
API route definitions for NetSentry-AI.

Only the health check is implemented for now. Additional endpoints (alert
ingestion, incident grouping, recommendations, escalation, etc.) will be
added here in later steps.
"""

from fastapi import APIRouter

from src.config import APP_NAME

router = APIRouter()


@router.get("/api/health")
def health() -> dict:
    """Health check endpoint used to verify the service is running."""
    return {"status": "ok", "project": APP_NAME}
