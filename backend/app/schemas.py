from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user: UserResponse


class AnalysisRequest(BaseModel):
    code: str = Field(min_length=1, max_length=100_000)
    language: Literal["python", "javascript", "typescript"]
    file_name: str = Field(default="pasted-source", min_length=1, max_length=255)
    fail_on_severity: Literal["critical", "high", "medium", "low"] = "high"

    @field_validator("code")
    @classmethod
    def reject_blank_code(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Source code cannot be blank")
        return value

    @field_validator("file_name")
    @classmethod
    def validate_file_name(cls, value: str) -> str:
        posix = PurePosixPath(value)
        windows = PureWindowsPath(value)
        if "\x00" in value or posix.is_absolute() or windows.is_absolute() or windows.drive:
            raise ValueError("File name must be a relative path")
        if any(part in {".", ".."} for part in posix.parts) or any(part in {".", ".."} for part in windows.parts):
            raise ValueError("File name cannot traverse directories")
        return value


class FindingResponse(BaseModel):
    id: str
    file_path: str | None
    line: int | None
    column: int | None
    end_line: int | None
    end_column: int | None
    rule_id: str
    analyzer: str
    severity: str
    category: str
    title: str
    description: str
    evidence: str | None
    remediation: str | None
    origin: str
    model_config = ConfigDict(from_attributes=True)


class PatchSuggestionResponse(BaseModel):
    id: str
    analysis_id: str
    finding_id: str
    patch: str
    explanation: str
    status: str
    created_at: datetime
    reviewed_at: datetime | None
    model_config = ConfigDict(from_attributes=True)


class AnalysisResponse(BaseModel):
    id: str
    status: str
    language: str
    source_name: str
    mode: str
    gate_threshold: str
    summary: dict
    quality_gate: dict
    error_message: str | None
    created_at: datetime
    completed_at: datetime | None
    findings: list[FindingResponse] = []
    patch_suggestions: list[PatchSuggestionResponse] = []
    model_config = ConfigDict(from_attributes=True)


class DiffRequest(BaseModel):
    diff: str = Field(min_length=1, max_length=100_000)
    fail_on_severity: Literal["critical", "high", "medium", "low"] = "high"


class GateConfig(BaseModel):
    fail_on_severity: Literal["critical", "high", "medium", "low"] = "high"
    fail_on_syntax_error: bool = True


class PatchDecision(BaseModel):
    decision: Literal["accepted", "rejected"]


class AIReviewItem(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=2000)
    severity: Literal["critical", "high", "medium", "low", "info"]
    category: Literal["correctness", "security", "performance", "maintainability", "reliability"]
    line: int | None = Field(default=None, ge=1)
    evidence: str = Field(min_length=1, max_length=500)
    remediation: str = Field(min_length=5, max_length=1000)


class AIReviewResponse(BaseModel):
    findings: list[AIReviewItem] = Field(max_length=20)


class DependencyScanRequest(BaseModel):
    ecosystem: Literal["python", "npm"]
    manifest: str = Field(min_length=1, max_length=1_000_000)
    lockfile: str | None = Field(default=None, max_length=2_000_000)


class DependencyScanResponse(BaseModel):
    id: str
    ecosystem: str
    status: str
    inventory: list[dict]
    vulnerabilities: list[dict]
    warnings: list[str]
    error_message: str | None
    created_at: datetime
    completed_at: datetime | None
    model_config = ConfigDict(from_attributes=True)
