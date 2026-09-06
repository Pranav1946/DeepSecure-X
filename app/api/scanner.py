import json
import os
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies import get_current_user
from app.models.scan import Scan
from app.models.user import User
from app.scanner import (
    EXTENSION_TO_LANGUAGE,
    SUPPORTED_LANGUAGES,
    detect_language,
    get_scanner_for_language,
    normalize_language,
)
from app.scanner.risk_engine import SecurityRiskEngine

router = APIRouter(
    prefix="/scanner",
    tags=["Security Scanner"]
)

MAX_CODE_LENGTH = 500_000  # 500 KB character limit
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB binary limit


class ScanRequest(BaseModel):
    code: str = Field(..., description="Source code to analyze")


def run_scanner_engine(code: str, language: Optional[str] = None) -> tuple[str, list, str]:
    """
    Executes static security analysis as pure data without executing user-submitted code.
    Returns (canonical_language, findings, status).
    Raises HTTPException(400) if code is empty, invalid, or language is unsupported.
    """
    cleaned_code = code.strip()
    if not cleaned_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code cannot be empty."
        )

    if len(code) > MAX_CODE_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Source code exceeds the maximum allowed length of {MAX_CODE_LENGTH} characters."
        )

    canonical_lang = normalize_language(language) if language else detect_language(code)
    if not canonical_lang:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Language is not supported. Please provide valid Python, JavaScript, C, C++, Java, HTML, or CSS code."
            )
        )

    scanner = get_scanner_for_language(canonical_lang)
    if not scanner:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Language is not supported: '{language}'."
        )

    result = scanner.scan(code)
    if result.get("status") == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Analysis error: {result.get('message', 'Failed to scan code')}."
        )

    return canonical_lang, result.get("findings", []), result.get("status", "completed")


async def execute_and_persist_scan(
    code: str,
    language: Optional[str] = None,
    user_id: int = 0,
    db: AsyncSession = None,
    filename: Optional[str] = None
) -> dict:
    canonical_lang, findings, scan_status = run_scanner_engine(code, language)
    risk_engine = SecurityRiskEngine()
    risk = risk_engine.calculate(findings)

    prior_count_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == user_id)
    )
    scan_number = (prior_count_result.scalar() or 0) + 1

    scan = Scan(
        user_id=user_id,
        language=canonical_lang,
        code=code,
        status=scan_status,
        vulnerabilities_found=len(findings),
        results=json.dumps({
            "security_score": risk["security_score"],
            "risk_level": risk["risk_level"],
            "severity_counts": risk["severity_counts"],
            "findings": findings
        })
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    response_data = {
        "scan_id": scan.id,
        "scan_number": scan_number,
        "user_id": user_id,
        "status": scan_status,
        "language": canonical_lang,
        "vulnerabilities_found": len(findings),
        "security_score": risk["security_score"],
        "risk_level": risk["risk_level"],
        "severity_counts": risk["severity_counts"],
        "findings": findings
    }
    if filename:
        response_data["filename"] = filename

    return response_data


# ==============================================================================
# Unified Code Scan Endpoint
# ==============================================================================
@router.post("/scan")
async def scan_code_unified(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await execute_and_persist_scan(
        code=request.code,
        language=None,
        user_id=current_user.id,
        db=db
    )


# ==============================================================================
# Dedicated Language Code Endpoints
# ==============================================================================
@router.post("/python")
async def scan_python_code(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await execute_and_persist_scan(
        code=request.code,
        language="python",
        user_id=current_user.id,
        db=db
    )


@router.post("/javascript")
async def scan_javascript_code(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await execute_and_persist_scan(
        code=request.code,
        language="javascript",
        user_id=current_user.id,
        db=db
    )


@router.post("/c")
async def scan_c_code(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await execute_and_persist_scan(
        code=request.code,
        language="c",
        user_id=current_user.id,
        db=db
    )


@router.post("/cpp")
async def scan_cpp_code(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await execute_and_persist_scan(
        code=request.code,
        language="cpp",
        user_id=current_user.id,
        db=db
    )


@router.post("/java")
async def scan_java_code(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await execute_and_persist_scan(
        code=request.code,
        language="java",
        user_id=current_user.id,
        db=db
    )


@router.post("/html")
async def scan_html_code(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await execute_and_persist_scan(
        code=request.code,
        language="html",
        user_id=current_user.id,
        db=db
    )


@router.post("/css")
async def scan_css_code(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await execute_and_persist_scan(
        code=request.code,
        language="css",
        user_id=current_user.id,
        db=db
    )


# ==============================================================================
# File Upload Processing & Endpoints
# ==============================================================================
async def process_file_upload(
    file: UploadFile,
    expected_language: Optional[str] = None
) -> tuple[str, str, str]:
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is missing."
        )

    # Sanitize basename to prevent directory traversal
    safe_filename = os.path.basename(file.filename)
    _, ext = os.path.splitext(safe_filename.lower())

    detected_lang = EXTENSION_TO_LANGUAGE.get(ext)
    if not detected_lang:
        supported_exts = ", ".join(sorted(EXTENSION_TO_LANGUAGE.keys()))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Supported extensions: {supported_exts}."
        )

    if expected_language:
        canonical_expected = normalize_language(expected_language)
        if detected_lang != canonical_expected:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Uploaded file extension '{ext}' does not match expected language '{expected_language}'."
            )

    try:
        content = await file.read()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to read uploaded file."
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File size exceeds maximum limit of {MAX_FILE_SIZE // (1024 * 1024)}MB."
        )

    try:
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to decode file. Please upload a valid UTF-8 encoded text file."
        )

    if not code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty."
        )

    return code, detected_lang, safe_filename


@router.post("/file")
async def scan_file_unified(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    code, language, safe_filename = await process_file_upload(file)
    return await execute_and_persist_scan(
        code=code,
        language=language,
        user_id=current_user.id,
        db=db,
        filename=safe_filename
    )


@router.post("/python/file")
async def scan_python_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    code, language, safe_filename = await process_file_upload(file, expected_language="python")
    return await execute_and_persist_scan(
        code=code,
        language=language,
        user_id=current_user.id,
        db=db,
        filename=safe_filename
    )


@router.post("/javascript/file")
async def scan_javascript_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    code, language, safe_filename = await process_file_upload(file, expected_language="javascript")
    return await execute_and_persist_scan(
        code=code,
        language=language,
        user_id=current_user.id,
        db=db,
        filename=safe_filename
    )


@router.post("/c/file")
async def scan_c_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    code, language, safe_filename = await process_file_upload(file, expected_language="c")
    return await execute_and_persist_scan(
        code=code,
        language=language,
        user_id=current_user.id,
        db=db,
        filename=safe_filename
    )


@router.post("/cpp/file")
async def scan_cpp_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    code, language, safe_filename = await process_file_upload(file, expected_language="cpp")
    return await execute_and_persist_scan(
        code=code,
        language=language,
        user_id=current_user.id,
        db=db,
        filename=safe_filename
    )


@router.post("/java/file")
async def scan_java_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    code, language, safe_filename = await process_file_upload(file, expected_language="java")
    return await execute_and_persist_scan(
        code=code,
        language=language,
        user_id=current_user.id,
        db=db,
        filename=safe_filename
    )


@router.post("/html/file")
async def scan_html_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    code, language, safe_filename = await process_file_upload(file, expected_language="html")
    return await execute_and_persist_scan(
        code=code,
        language=language,
        user_id=current_user.id,
        db=db,
        filename=safe_filename
    )


@router.post("/css/file")
async def scan_css_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    code, language, safe_filename = await process_file_upload(file, expected_language="css")
    return await execute_and_persist_scan(
        code=code,
        language=language,
        user_id=current_user.id,
        db=db,
        filename=safe_filename
    )


# ==============================================================================
# Dashboard, Analytics & History Endpoints
# ==============================================================================
@router.get("/dashboard")
async def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id

    summary_result = await db.execute(
        select(
            func.count(Scan.id).label("total_scans"),
            func.coalesce(func.sum(Scan.vulnerabilities_found), 0).label(
                "total_vulnerabilities"
            ),
        )
        .where(Scan.user_id == user_id)
    )
    summary = summary_result.one()

    scans_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.id.desc())
    )
    scans = scans_result.scalars().all()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    security_scores = []
    latest_risk_level = "UNKNOWN"

    for scan in scans:
        if not scan.results:
            continue

        try:
            parsed_results = json.loads(scan.results)
        except (json.JSONDecodeError, TypeError):
            continue

        if isinstance(parsed_results, dict):
            risk_level = parsed_results.get("risk_level")
            if risk_level:
                latest_risk_level = risk_level

            score = parsed_results.get("security_score")
            if score is not None:
                security_scores.append(float(score))

            findings = parsed_results.get("findings", [])
            if isinstance(findings, list):
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue

                    severity = str(
                        finding.get("severity", "LOW")
                    ).upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

        elif isinstance(parsed_results, list):
            for item in parsed_results:
                if not isinstance(item, dict):
                    continue

                sev = str(item.get("severity", "LOW")).upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1

                score = item.get("security_score")
                if score is not None:
                    security_scores.append(float(score))

    if scans and scans[0].results:
        try:
            latest_result = json.loads(scans[0].results)
            if isinstance(latest_result, dict):
                latest_risk_level = latest_result.get(
                    "risk_level",
                    latest_risk_level,
                )
        except (json.JSONDecodeError, TypeError):
            latest_risk_level = "UNKNOWN"

    average_security_score = round(
        sum(security_scores) / len(security_scores), 2
    ) if security_scores else 0.0

    return {
        "user_id": user_id,
        "total_scans": summary.total_scans,
        "total_vulnerabilities": sum(
            severity_counts.values()
        ),
        "severity_counts": {
            "CRITICAL": severity_counts["CRITICAL"],
            "HIGH": severity_counts["HIGH"],
            "MEDIUM": severity_counts["MEDIUM"],
            "LOW": severity_counts["LOW"],
        },
        "average_security_score": average_security_score,
        "latest_risk_level": latest_risk_level,
    }


@router.get("/analytics")
async def get_scan_analytics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id

    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.id.desc())
    )
    scans = result.scalars().all()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    risk_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }
    vulnerability_counts = {}
    security_scores = []
    scan_activity = []

    for scan in scans:
        if not scan.results:
            continue

        try:
            parsed_results = json.loads(scan.results)
        except (json.JSONDecodeError, TypeError):
            continue

        if not isinstance(parsed_results, dict):
            continue

        risk_level = str(parsed_results.get("risk_level", "UNKNOWN")).upper()
        if risk_level in risk_distribution:
            risk_distribution[risk_level] += 1

        score = parsed_results.get("security_score")
        if score is not None:
            security_scores.append(float(score))

        findings = parsed_results.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            severity = str(finding.get("severity", "LOW")).upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

            rule_id = finding.get("rule_id", "UNKNOWN")
            vulnerability_counts[rule_id] = (
                vulnerability_counts.get(rule_id, 0) + 1
            )

        scan_activity.append({
            "scan_id": scan.id,
            "language": scan.language,
            "vulnerabilities": len(findings),
            "security_score": parsed_results.get("security_score", 0),
            "risk_level": risk_level,
        })

    top_vulnerabilities = sorted(
        [
            {
                "rule_id": rule_id,
                "count": count,
            }
            for rule_id, count in vulnerability_counts.items()
        ],
        key=lambda item: item["count"],
        reverse=True,
    )[:5]

    average_security_score = round(
        sum(security_scores) / len(security_scores),
        2,
    ) if security_scores else 0.0

    total_vulnerabilities = sum(severity_counts.values())

    return {
        "user_id": user_id,
        "total_scans": len(scans),
        "total_vulnerabilities": total_vulnerabilities,
        "average_security_score": average_security_score,
        "severity_counts": severity_counts,
        "risk_distribution": risk_distribution,
        "top_vulnerabilities": top_vulnerabilities,
        "scan_activity": scan_activity,
    }


@router.get("/history")
async def get_scan_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id

    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.id.asc())
    )

    scans = result.scalars().all()

    scan_items = []
    for index, scan in enumerate(scans, start=1):
        score = 0
        risk_lvl = "UNKNOWN"
        if scan.results:
            try:
                parsed = json.loads(scan.results)
                if isinstance(parsed, dict):
                    score = parsed.get("security_score", 0)
                    risk_lvl = parsed.get("risk_level", "UNKNOWN")
            except (json.JSONDecodeError, TypeError):
                pass

        scan_items.append({
            "scan_id": scan.id,
            "scan_number": index,
            "language": scan.language,
            "status": scan.status,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "security_score": score,
            "risk_level": risk_lvl,
        })

    return {
        "user_id": user_id,
        "total_scans": len(scans),
        "scans": scan_items
    }


@router.get("/history/{scan_id}")
async def get_scan_details(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id

    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.id.asc())
    )
    scans = result.scalars().all()

    scan = next((item for item in scans if item.id == scan_id), None)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    scan_number = scans.index(scan) + 1

    try:
        parsed_results = json.loads(scan.results)
    except (json.JSONDecodeError, TypeError):
        parsed_results = {}

    if isinstance(parsed_results, dict):
        findings = parsed_results.get("findings", [])
        security_score = parsed_results.get("security_score", 0)
        risk_level = parsed_results.get("risk_level", "UNKNOWN")
        severity_counts = parsed_results.get("severity_counts", {})
    else:
        findings = parsed_results if isinstance(parsed_results, list) else []
        security_score = 0
        risk_level = "UNKNOWN"
        severity_counts = {}

    return {
        "scan_id": scan.id,
        "scan_number": scan_number,
        "user_id": scan.user_id,
        "language": scan.language,
        "code": scan.code,
        "status": scan.status,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "security_score": security_score,
        "risk_level": risk_level,
        "severity_counts": severity_counts,
        "findings": findings
    }


@router.delete("/history/{scan_id}")
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id

    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == user_id
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    await db.delete(scan)
    await db.commit()

    return {
        "message": "Scan deleted successfully",
        "scan_id": scan_id
    }