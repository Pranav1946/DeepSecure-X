from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
import json

from app.core.database import get_db
from app.core.security import security, decode_access_token
from app.models.scan import Scan
from app.scanner.python_scanner import PythonSecurityScanner
from app.scanner.risk_engine import SecurityRiskEngine


router = APIRouter(
    prefix="/scanner",
    tags=["Security Scanner"]
)


class ScanRequest(BaseModel):
    code: str


async def get_authenticated_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    payload = decode_access_token(token)

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return int(user_id)


@router.post("/python")
async def scan_python_code(
    request: ScanRequest,
    user_id: int = Depends(get_authenticated_user_id),
    db: AsyncSession = Depends(get_db),
):
    scanner = PythonSecurityScanner()
    result = scanner.scan(request.code)
    findings = result.get("findings", [])
    risk_engine = SecurityRiskEngine()
    risk = risk_engine.calculate(findings)

    scan = Scan(
        user_id=user_id,
        language="python",
        code=request.code,
        status=result["status"],
        vulnerabilities_found=result.get(
            "vulnerabilities_found",
            0
        ),
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

    return {
        "scan_id": scan.id,
        "user_id": user_id,
        "status": result["status"],
        "language": "python",
        "vulnerabilities_found": result.get(
            "vulnerabilities_found",
            0
        ),
        "security_score": risk["security_score"],
        "risk_level": risk["risk_level"],
        "severity_counts": risk["severity_counts"],
        "findings": findings
    }


@router.get("/dashboard")
async def get_dashboard_summary(
    user_id: int = Depends(get_authenticated_user_id),
    db: AsyncSession = Depends(get_db),
):
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
    user_id: int = Depends(get_authenticated_user_id),
    db: AsyncSession = Depends(get_db),
):
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
    user_id: int = Depends(get_authenticated_user_id),
    db: AsyncSession = Depends(get_db),
):

    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.id.desc())
    )

    scans = result.scalars().all()

    return {
        "user_id": user_id,
        "total_scans": len(scans),
        "scans": [
            {
                "scan_id": scan.id,
                "language": scan.language,
                "status": scan.status,
                "vulnerabilities_found": scan.vulnerabilities_found,
            }
            for scan in scans
        ]
    }


@router.get("/history/{scan_id}")
async def get_scan_details(
    scan_id: int,
    user_id: int = Depends(get_authenticated_user_id),
    db: AsyncSession = Depends(get_db),
):

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

    parsed_results = json.loads(scan.results)

    if isinstance(parsed_results, dict):
        findings = parsed_results.get("findings", [])
        security_score = parsed_results.get("security_score", 0)
        risk_level = parsed_results.get("risk_level", "UNKNOWN")
        severity_counts = parsed_results.get("severity_counts", {})
    else:
        findings = parsed_results
        security_score = 0
        risk_level = "UNKNOWN"
        severity_counts = {}

    return {
        "scan_id": scan.id,
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


@router.post("/python/file")
async def scan_python_file(
    file: UploadFile = File(...),
    user_id: int = Depends(get_authenticated_user_id),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".py"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only Python (.py) files are supported."
        )

    try:
        content = await file.read()
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to read file. Please upload a UTF-8 encoded Python file."
        )

    scanner = PythonSecurityScanner()
    result = scanner.scan(code)
    findings = result.get("findings", [])
    risk_engine = SecurityRiskEngine()
    risk = risk_engine.calculate(findings)

    scan = Scan(
        user_id=user_id,
        language="python",
        code=code,
        status=result["status"],
        vulnerabilities_found=result.get("vulnerabilities_found", 0),
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

    return {
        "scan_id": scan.id,
        "user_id": user_id,
        "filename": file.filename,
        "status": result["status"],
        "language": "python",
        "vulnerabilities_found": result.get("vulnerabilities_found", 0),
        "security_score": risk["security_score"],
        "risk_level": risk["risk_level"],
        "severity_counts": risk["severity_counts"],
        "findings": findings
    }


@router.delete("/history/{scan_id}")
async def delete_scan(
    scan_id: int,
    user_id: int = Depends(get_authenticated_user_id),
    db: AsyncSession = Depends(get_db),
):
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