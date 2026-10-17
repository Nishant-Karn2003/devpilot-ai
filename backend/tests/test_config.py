import pytest
from pydantic import ValidationError

from app.config import DEVELOPMENT_JWT_SECRET, Settings


def test_production_requires_a_strong_non_development_jwt_secret():
    with pytest.raises(ValidationError, match="non-development JWT secret"):
        Settings(_env_file=None, environment="production", jwt_secret=DEVELOPMENT_JWT_SECRET)
    with pytest.raises(ValidationError, match="non-development JWT secret"):
        Settings(_env_file=None, environment="production", jwt_secret="x" * 31)

    settings = Settings(_env_file=None, environment="production", jwt_secret="x" * 32)
    assert settings.environment == "production"


def test_development_keeps_the_local_jwt_secret_default():
    settings = Settings(_env_file=None)
    assert settings.environment == "development"
    assert settings.jwt_secret == DEVELOPMENT_JWT_SECRET
