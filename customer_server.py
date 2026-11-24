"""Customer-Installable Local Server (VARINULL Local Scout #2: Unofficial AI Usage & Compliance Readiness Check).

Runs on your localhost (127.0.0.1:9102) with no account login or automatic file uploads.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

import engine

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title='VARINULL Local Scout #2: Unofficial AI Usage & Compliance Readiness Check', version="1.0.0")


@app.get("/", response_class=HTMLResponse)
async def root() -> FileResponse:
    return FileResponse(BASE_DIR / "client-assessment.html")


@app.get("/demo")
async def demo_redirect() -> RedirectResponse:
    return RedirectResponse(url="/?mode=demo")


@app.get("/api/demo")
async def api_demo() -> JSONResponse:
    import json
    fixture_path = BASE_DIR / "fixtures" / "demo_payload.json"
    if not fixture_path.exists():
        raise HTTPException(status_code=404, detail="Demo fixture not included in blank repository.")
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    return JSONResponse(engine.evaluate_intake(payload, mode="demo"))


@app.post("/api/assess")
async def api_assess(request: Request) -> JSONResponse:
    payload: Dict[str, Any] = await request.json()
    mode = str(payload.get("mode") or "production")
    return JSONResponse(engine.evaluate_intake(payload, mode=mode))


@app.post("/api/scan-local")
async def api_scan_local(request: Request) -> JSONResponse:
    body: Dict[str, Any] = await request.json()
    target = str(body.get("path") or body.get("directory") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Provide a local folder path to scan.")
    if hasattr(engine, "scan_local_directory"):
        return JSONResponse(engine.scan_local_directory(target))
    raise HTTPException(status_code=501, detail="Local scanner not available.")


@app.get("/api/templates/{filename}")
async def get_template(filename: str) -> FileResponse:
    safe_name = Path(filename).name
    fp = BASE_DIR / "templates" / safe_name
    if not fp.exists():
        raise HTTPException(status_code=404, detail="Template not found")
    return FileResponse(fp, filename=safe_name)


if __name__ == "__main__":
    print("==========================================================")
    print('VARINULL Local Scout #2: Unofficial AI Usage & Compliance Readiness Check')
    print("Localhost Mode: http://127.0.0.1:9102")
    print("Runs locally on your machine with no automatic uploads.")
    print("==========================================================")
    uvicorn.run(app, host="127.0.0.1", port=9102)
