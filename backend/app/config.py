from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parents[1]
ENV_FILE = BASE_DIR / ".env"


class Settings(BaseSettings):
    # Always load backend/.env no matter the current working directory.
    model_config = SettingsConfigDict(env_file=str(ENV_FILE), extra="ignore")

    anthropic_api_key: str = ""
    openai_api_key: str = ""
    database_url: str = "postgresql+asyncpg://dev:dev@localhost:5432/ragscan"
    nvd_api_key: str = ""
    jwt_secret: str = "dev-secret-change-in-prod"
    environment: str = "dev"
    cors_origins: str = ""

    # LLM
    llm_model: str = "claude-sonnet-4-6"
    embedding_model: str = "text-embedding-3-small"
    embedding_dims: int = 1536

    # Risk score weights
    weight_cvss: float = 0.4
    weight_epss: float = 0.4
    weight_kev: float = 0.2

    # RAG
    retrieval_k: int = 10
    risk_gap_threshold: float = 40.0

    @field_validator("database_url", mode="before")
    @classmethod
    def ensure_async_database_driver(cls, value: str) -> str:
        if not isinstance(value, str):
            return value

        if value.startswith("postgres://"):
            return value.replace("postgres://", "postgresql+asyncpg://", 1)

        if value.startswith("postgresql://") and "+asyncpg" not in value:
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)

        return value

    @property
    def allowed_cors_origins(self) -> list[str]:
        if self.cors_origins.strip():
            return [
                origin.strip().rstrip("/")
                for origin in self.cors_origins.split(",")
                if origin.strip()
            ]

        if self.environment == "dev":
            return [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://0.0.0.0:3000",
            ]

        return []


settings = Settings()
