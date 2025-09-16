from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, HttpUrl
from typing import Optional
import uuid
from datetime import datetime

from ..core.database import get_db
from ..models.analysis import AnalysisJob
from ..services.url_analyzer import URLAnalyzer

router = APIRouter()


class AnalyzeURLRequest(BaseModel):
    url: str
    user_id: Optional[str] = None


class AnalysisResponse(BaseModel):
    job_id: str
    status: str
    url: str
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    evidence: Optional[list] = None
    artifacts: Optional[dict] = None
    swedish_summary: Optional[str] = None
    timestamp: Optional[datetime] = None


@router.post("/analyze/url", response_model=dict)
async def analyze_url(
    request: AnalyzeURLRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    job_id = str(uuid.uuid4())

    # Create job record
    job = AnalysisJob(
        id=job_id,
        url=request.url,
        user_id=request.user_id,
        status="queued"
    )

    db.add(job)
    await db.commit()

    # Start analysis in background
    background_tasks.add_task(analyze_url_task, job_id, request.url)

    return {"job_id": job_id, "status": "queued"}


@router.get("/results/{job_id}", response_model=AnalysisResponse)
async def get_analysis_result(job_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Include screenshot data in artifacts
    artifacts = job.artifacts or {}
    if job.analysis_data and "steps" in job.analysis_data:
        screenshot_data = job.analysis_data.get("steps", {}).get("screenshot_analysis", {})
        if screenshot_data.get("screenshot_base64"):
            artifacts["screenshot_base64"] = screenshot_data["screenshot_base64"]
        if screenshot_data.get("page_title"):
            artifacts["page_title"] = screenshot_data["page_title"]

    # Include Swedish summary if available
    swedish_summary = None
    if job.analysis_data and "swedish_summary" in job.analysis_data:
        swedish_summary = job.analysis_data["swedish_summary"]

    return AnalysisResponse(
        job_id=job.id,
        status=job.status,
        url=job.url,
        verdict=job.verdict,
        confidence=job.confidence,
        evidence=job.evidence,
        artifacts=artifacts,
        swedish_summary=swedish_summary,
        timestamp=job.created_at
    )


@router.get("/artifacts/{artifact_id}")
async def get_artifact(artifact_id: str):
    # TODO: Implement artifact retrieval from MinIO
    return {"artifact_id": artifact_id, "message": "Artifact retrieval not implemented yet"}


async def analyze_url_task(job_id: str, url: str):
    """Background task to analyze URL"""
    from ..core.database import AsyncSessionLocal
    from sqlalchemy import update
    from datetime import datetime

    async with AsyncSessionLocal() as db:
        try:
            # Update status to processing
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_id)
                .values(status="processing")
            )
            await db.commit()

            # Run analysis
            analyzer = URLAnalyzer()
            result = await analyzer.analyze(url, job_id)

            # Extract risk assessment
            risk_assessment = result.get("risk_assessment", {})

            # Update job with results
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_id)
                .values(
                    status="completed",
                    verdict=risk_assessment.get("verdict"),
                    confidence=risk_assessment.get("confidence"),
                    evidence=risk_assessment.get("evidence", []),
                    analysis_data=result,
                    completed_at=datetime.utcnow()
                )
            )
            await db.commit()

        except Exception as e:
            print(f"Analysis failed for job {job_id}: {e}")
            # Update job with error status
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_id)
                .values(
                    status="failed",
                    error_message=str(e),
                    completed_at=datetime.utcnow()
                )
            )
            await db.commit()