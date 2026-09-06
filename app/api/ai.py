import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies import get_current_user
from app.models.scan import Scan
from app.models.user import User
from app.services.ai_analysis import AIAnalysisService, AIConfigurationError, AIServiceError

logger = logging.getLogger("deepsecure.api.ai")

router = APIRouter(prefix="/ai", tags=["AI Analysis"])


class AnalyzeRequest(BaseModel):
    scan_id: int


@router.post("/analyze")
async def analyze_scan(
    request: AnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan).where(
            Scan.id == request.scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    try:
        stored_results = json.loads(scan.results) if scan.results else {}
        analysis = await AIAnalysisService().analyze({
            "scan_id": scan.id,
            "language": scan.language,
            "status": scan.status,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "results": stored_results,
        })
    except AIConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except AIServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error(f"Unexpected error in analyze_scan: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate AI analysis.",
        ) from exc

    return {
        "scan_id": scan.id,
        "analysis": analysis,
    }