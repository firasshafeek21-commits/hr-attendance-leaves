"""Private employee API. Run behind HTTPS with HR_ADMIN_TOKEN configured."""
import os
import sqlite3
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

DB_PATH = Path(os.environ.get("HR_DB_PATH", "private/hr_employees_import.sqlite"))
ADMIN_TOKEN = os.environ.get("HR_ADMIN_TOKEN", "")
ORIGIN = os.environ.get("HR_FRONTEND_ORIGIN", "")
app = FastAPI(title="HR Employees API")
app.add_middleware(CORSMiddleware, allow_origins=[ORIGIN] if ORIGIN else [], allow_credentials=False, allow_methods=["GET"], allow_headers=["X-Admin-Token"])

def authorize(token):
    if not ADMIN_TOKEN or not token or token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/employees")
def employees(x_admin_token: str | None = Header(default=None)):
    authorize(x_admin_token)
    if not DB_PATH.is_file():
        raise HTTPException(status_code=503, detail="Employee database not installed")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT empno, name, "Combo16" AS job_title FROM employees ORDER BY empno').fetchall()
    return {"employees": [dict(row) for row in rows], "count": len(rows)}
