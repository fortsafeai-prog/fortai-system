import asyncio
import logging
from celery import Celery
from .core.config import settings
from .services.url_analyzer import URLAnalyzer
from .core.database import AsyncSessionLocal
from .models.analysis import AnalysisJob
from sqlalchemy import update
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Celery app
celery_app = Celery(
    "fortai_worker",
    broker=settings.redis_url,
    backend=settings.redis_url
)


@celery_app.task
def analyze_url_task(job_id: str, url: str):
    """Background task to analyze URL"""
    return asyncio.run(_analyze_url_async(job_id, url))


async def _analyze_url_async(job_id: str, url: str):
    """Async implementation of URL analysis"""
    async with AsyncSessionLocal() as db:
        try:
            logger.info(f"Starting analysis for job {job_id}: {url}")

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

            logger.info(f"Analysis completed for job {job_id}. Verdict: {risk_assessment.get('verdict')}")

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

            return {"status": "completed", "job_id": job_id}

        except Exception as e:
            logger.error(f"Analysis failed for job {job_id}: {e}")
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
            return {"status": "failed", "job_id": job_id, "error": str(e)}


if __name__ == "__main__":
    celery_app.start()