from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    database_url: str = "postgresql://fortai_user:fortai_pass@localhost:5432/fortai_db"
    redis_url: str = "redis://localhost:6379"
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "fortai_access"
    minio_secret_key: str = "fortai_secret123"
    minio_bucket_name: str = "fortai-artifacts"
    openai_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    phishtank_api_key: Optional[str] = None

    class Config:
        env_file = ".env"


settings = Settings()