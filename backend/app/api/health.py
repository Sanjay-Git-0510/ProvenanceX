"""Liveness and readiness endpoints."""

import logging
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.db.database import check_database, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/health", tags=["health"])


class LivenessResponse(BaseModel):
    status: Literal["ok"]
    version: str


class ReadinessResponse(BaseModel):
    status: Literal["ready"]
    db: Literal["ok"]
    version: str


@router.get("", response_model=LivenessResponse)
def liveness() -> LivenessResponse:
    return LivenessResponse(status="ok", version=get_settings().scanner_version)


@router.get("/ready", response_model=ReadinessResponse)
def readiness(db: Session = Depends(get_db)) -> ReadinessResponse:  # noqa: B008
    try:
        check_database(db)
    except SQLAlchemyError as exc:
        logger.error("Readiness check failed: database unreachable: %s", exc.__class__.__name__)
        raise AppError(
            code="database_unavailable",
            message="Database is not reachable",
            status_code=503,
        ) from exc
    return ReadinessResponse(status="ready", db="ok", version=get_settings().scanner_version)
