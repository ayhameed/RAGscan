from pathlib import Path

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


settings = Settings()
