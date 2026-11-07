"""Private HR API. Employee records require an admin token; never embed it in public frontend code."""
import os
import hmac
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
import psycopg

DATABASE_URL = os.getenv("DATABASE_URL", "")
ADMIN_TOKEN = os.getenv("HR_ADMIN_TOKEN", "")
ORIGIN = os.getenv("HR_FRONTEND_ORIGIN", "")
app = FastAPI(title="HR Employees API")
app.add_middleware(CORSMiddleware, allow_origins=[ORIGIN] if ORIGIN else [], allow_credentials=False, allow_methods=["GET"], allow_headers=["X-Admin-Token"])

def authorize(token: str | None):
    if not ADMIN_TOKEN or not token or not hmac.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/health/db")
def database_health(x_admin_token: str | None = Header(default=None)):
    authorize(x_admin_token)
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=5) as conn:
            conn.execute("SELECT 1").fetchone()
        return {"database": "connected"}
    except psycopg.Error:
        raise HTTPException(status_code=503, detail="Database unavailable")

@app.get("/employees")
def employees(x_admin_token: str | None = Header(default=None)):
    authorize(x_admin_token)
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT employee_number, full_name, job_title FROM employees ORDER BY employee_number")
                rows = cur.fetchall()
    except psycopg.errors.UndefinedTable:
        raise HTTPException(status_code=503, detail="Employee table not initialized")
    except psycopg.Error:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"employees": [{"employee_number": r[0], "full_name": r[1], "job_title": r[2]} for r in rows], "count": len(rows)}

@app.get("/directory", include_in_schema=False)
def directory():
    return FileResponse(Path(__file__).with_name("directory.html"), headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
