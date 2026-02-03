from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict

import csv
import io

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .ai import generate_ai_summary
from .models import ScanRequest, ScanResult, ScanStatus, ScanSummary
from .scanner import Scanner

app = FastAPI(title="OWASP AI Scanner", version="0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/", StaticFiles(directory="static", html=True), name="static")

executor = ThreadPoolExecutor(max_workers=4)
scan_store: Dict[str, ScanResult] = {}
scan_locks: Dict[str, threading.Lock] = {}
scan_meta: Dict[str, int] = {}


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanStatus)
async def start_scan(request: ScanRequest) -> ScanStatus:
    scan_id = str(uuid.uuid4())
    result = ScanResult(
        scan_id=scan_id,
        target_url=str(request.target_url),
        started_at=datetime.utcnow(),
        status="queued",
    )
    scan_store[scan_id] = result
    scan_locks[scan_id] = threading.Lock()
    scan_meta[scan_id] = request.options.max_pages

    def run_scan() -> None:
        scan = Scanner(request.options)
        with scan_locks[scan_id]:
            scan_store[scan_id].status = "running"

        result = scan.scan(str(request.target_url))
        with scan_locks[scan_id]:
            scan_store[scan_id] = result
            if request.options.include_ai:
                try:
                    ai_summary = generate_ai_summary(result.findings, str(request.target_url))
                    scan_store[scan_id].ai_summary = ai_summary
                except Exception as exc:
                    scan_store[scan_id].errors.append(f"AI summary failed: {exc}")

    executor.submit(run_scan)

    return ScanStatus(
        scan_id=scan_id,
        status="queued",
        progress=0,
        pages_scanned=0,
        errors=[],
        findings=[],
    )


@app.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str) -> ScanStatus:
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    with scan_locks[scan_id]:
        result = scan_store[scan_id]
        max_pages = max(1, scan_meta.get(scan_id, 1))
        progress = min(int((result.pages_scanned / max_pages) * 100), 100)
        if result.status in {"completed", "failed"}:
            progress = 100

        return ScanStatus(
            scan_id=scan_id,
            status=result.status,
            progress=progress,
            pages_scanned=result.pages_scanned,
            errors=result.errors,
            findings=result.findings,
            ai_summary=result.ai_summary,
        )


@app.get("/api/scan/{scan_id}/report", response_model=ScanResult)
async def get_scan_report(scan_id: str) -> ScanResult:
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    with scan_locks[scan_id]:
        return scan_store[scan_id]


@app.get("/api/scans", response_model=list[ScanSummary])
async def list_scans() -> list[ScanSummary]:
    summaries: list[ScanSummary] = []
    for scan_id, result in scan_store.items():
        summaries.append(
            ScanSummary(
                scan_id=scan_id,
                target_url=result.target_url,
                started_at=result.started_at,
                finished_at=result.finished_at,
                status=result.status,
                findings_count=len(result.findings),
            )
        )
    summaries.sort(key=lambda item: item.started_at, reverse=True)
    return summaries


@app.get("/api/scan/{scan_id}/export")
async def export_scan(scan_id: str, format: str = Query(default="csv")) -> Response:
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    with scan_locks[scan_id]:
        result = scan_store[scan_id]

    if format.lower() == "json":
        return Response(content=result.model_dump_json(), media_type="application/json")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_id",
            "target_url",
            "category",
            "title",
            "severity",
            "description",
            "evidence",
        ]
    )
    for finding in result.findings:
        writer.writerow(
            [
                result.scan_id,
                result.target_url,
                finding.category,
                finding.title,
                finding.severity,
                finding.description,
                finding.evidence or "",
            ]
        )

    filename = f"scan-{scan_id}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
