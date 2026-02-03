from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanOptions(BaseModel):
    max_pages: int = Field(default=15, ge=1, le=200)
    timeout_seconds: int = Field(default=10, ge=3, le=60)
    include_ai: bool = False
    allowlist: List[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    target_url: HttpUrl
    options: ScanOptions = ScanOptions()


class Finding(BaseModel):
    id: str
    category: str
    title: str
    severity: Literal["low", "medium", "high", "info"]
    description: str
    evidence: Optional[Dict[str, Any]] = None
    recommendation: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: Literal["queued", "running", "completed", "failed"]
    findings: List[Finding] = Field(default_factory=list)
    pages_scanned: int = 0
    errors: List[str] = Field(default_factory=list)
    ai_summary: Optional[str] = None


class ScanStatus(BaseModel):
    scan_id: str
    status: Literal["queued", "running", "completed", "failed"]
    progress: int
    pages_scanned: int
    errors: List[str]
    findings: List[Finding]
    ai_summary: Optional[str] = None


class ScanSummary(BaseModel):
    scan_id: str
    target_url: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: Literal["queued", "running", "completed", "failed"]
    findings_count: int
