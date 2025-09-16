from sqlalchemy import Column, String, Integer, DateTime, Float, Text, JSON, Boolean
from sqlalchemy.sql import func
from ..core.database import Base
import uuid


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    url = Column(Text, nullable=False)
    user_id = Column(String, nullable=True)
    status = Column(String, default="queued")  # queued, processing, completed, failed
    verdict = Column(String, nullable=True)  # safe, suspicious, dangerous
    confidence = Column(Float, nullable=True)
    evidence = Column(JSON, nullable=True)
    artifacts = Column(JSON, nullable=True)
    analysis_data = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)