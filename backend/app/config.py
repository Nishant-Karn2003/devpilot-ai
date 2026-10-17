from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEVELOPMENT_JWT_SECRET = "local-development-secret-change-this-value"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DEVPILOT_", extra="ignore")

    database_url: str = "sqlite:///./devpilot.db"
    jwt_secret: str = Field(default=DEVELOPMENT_JWT_SECRET, min_length=24)
    access_token_minutes: int = 60
    environment: Literal["development", "production"] = "development"
    frontend_origin: str = "http://127.0.0.1:5173"
    max_source_bytes: int = 100_000
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None

    @model_validator(mode="after")
    def validate_production_secret(self) -> Self:
        if self.environment == "production" and (
            self.jwt_secret == DEVELOPMENT_JWT_SECRET or len(self.jwt_secret) < 32
        ):
            raise ValueError("Production requires a non-development JWT secret of at least 32 characters")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
