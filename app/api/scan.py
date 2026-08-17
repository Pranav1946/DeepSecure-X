"""Deprecated scan API module.

Scanner-related endpoints live in app.api.scanner. This file is intentionally
left empty to avoid duplicate history routes and keep the API surface clean.
"""

from fastapi import APIRouter


router = APIRouter(
    prefix="/scans",
    tags=["Deprecated"],
)

# Intentionally no routes here. The active scanner/history APIs are defined in
# app.api.scanner and should remain the single source of truth.
