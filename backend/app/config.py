from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = BASE_DIR.parent
BACKEND_ENV_FILE = BASE_DIR / ".env"
ROOT_ENV_FILE = ROOT_DIR / ".env"
ENV_FILE = ROOT_ENV_FILE if ROOT_ENV_FILE.exists() else BACKEND_ENV_FILE


class Settings(BaseSettings):
    # Prefer the repo-root .env so local Docker, Render, and manual runs share one source.
    model_config = SettingsConfigDict(env_file=str(ENV_FILE), extra="ignore")

    anthropic_api_key: str = ""
    openai_api_key: str = ""
    database_url: str = "postgresql+asyncpg://dev:dev@localhost:5432/ragscan"
    nvd_api_key: str = ""
    jwt_secret: str = "dev-secret-change-in-prod"
    environment: str = "dev"
    cors_origins: str = ""
    frontend_url: str = ""
    cors_origin_regex: str = ""

    # LLM
    llm_model: str = "claude-sonnet-4-6"
    fallback_llm_model: str = "openai/gpt-oss-20b"
    fallback_llm_models: str = "openai/gpt-oss-120b,llama-3.3-70b-versatile"
    fallback_llm_api_key: str = ""
    fallback_llm_base_url: str = "https://api.groq.com/openai/v1"
    eval_judge_model: str = "gpt-4.1-mini"
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

        if value.startswith("ppostgres://"):
            value = value.replace("ppostgres://", "postgresql+asyncpg://", 1)

        if value.startswith("ppostgresql://"):
            value = value.replace("ppostgresql://", "postgresql+asyncpg://", 1)

        if value.startswith("postgres://"):
            value = value.replace("postgres://", "postgresql+asyncpg://", 1)

        if value.startswith("postgresql://") and "+asyncpg" not in value:
            value = value.replace("postgresql://", "postgresql+asyncpg://", 1)

        parts = urlsplit(value)
        if not parts.query:
            return value

        query_items = []
        changed = False
        for key, query_value in parse_qsl(parts.query, keep_blank_values=True):
            if key == "sslmode":
                query_items.append(("ssl", query_value))
                changed = True
            elif key == "channel_binding":
                # asyncpg does not accept channel_binding in connect kwargs
                changed = True
            else:
                query_items.append((key, query_value))

        if not changed:
            return value

        return urlunsplit(parts._replace(query=urlencode(query_items)))

    @property
    def allowed_cors_origins(self) -> list[str]:
        if self.cors_origins.strip():
            return [
                origin.strip().rstrip("/")
                for origin in self.cors_origins.split(",")
                if origin.strip()
            ]

        if self.frontend_url.strip():
            return [self.frontend_url.strip().rstrip("/")]

        if self.environment == "dev":
            return [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://0.0.0.0:3000",
            ]

        return []

    @property
    def allowed_cors_origin_regex(self) -> str | None:
        if self.cors_origin_regex.strip():
            return self.cors_origin_regex.strip()

        # Production fallback for Vercel-hosted frontend deployments and previews.
        if self.environment == "prod":
            return r"https://.*\.vercel\.app"

        return None


settings = Settings()
