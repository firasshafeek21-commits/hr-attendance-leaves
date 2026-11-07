"""Private HR API. Employee records require an admin token; never embed it in public frontend code."""
import os
import hmac
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from backend.auth import router as auth_router, init_db
from fastapi.responses import JSONResponse
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

app.include_router(auth_router)

@app.middleware("http")
async def reject_cross_origin_writes(request, call_next):
    if request.url.path.startswith("/api/") and request.method in {"POST","PUT","PATCH","DELETE"}:
        origin = request.headers.get("origin")
        expected = str(request.base_url).rstrip("/")
        if origin and origin != expected:
            return JSONResponse({"detail":"Cross-origin writes forbidden"},status_code=403)
    return await call_next(request)

@app.on_event("startup")
def initialize_accounts():
    init_db()

@app.get("/login",include_in_schema=False)
def login_page():
    return FileResponse(Path(__file__).with_name("portal.html"),headers={"Cache-Control":"no-store"})
