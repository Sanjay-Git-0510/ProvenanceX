"""Versioned API router (/api/v1)."""

from fastapi import APIRouter

from app.api import blockchain, health, scans

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(blockchain.router)
