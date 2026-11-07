"""Role-based HR accounts. Initial admin created only from private Render environment settings."""
import os, secrets, hashlib, hmac
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from contextlib import contextmanager
import psycopg
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api")
ROLES = {"employee", "manager", "accountant", "admin"}

@contextmanager
def db():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise HTTPException(503, "Database not configured")
    with psycopg.connect(url, connect_timeout=8) as conn:
        yield conn

def hash_password(password, salt=None):
    if len(password) < 12 or len(password) > 256:
        raise HTTPException(422, "Password must be 12-256 characters")
    salt = salt or secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return salt.hex() + ":" + key.hex()

def verify(password, stored):
    try:
        salt, key = stored.split(":")
        computed = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310000)
        return hmac.compare_digest(computed, bytes.fromhex(key))
    except (ValueError, TypeError):
        return False

def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS hr_users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('employee','manager','accountant','admin')),
                employee_number TEXT UNIQUE REFERENCES employees(employee_number),
                active BOOLEAN NOT NULL DEFAULT TRUE
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS hr_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES hr_users(id) ON DELETE CASCADE,
                expires_at TIMESTAMPTZ NOT NULL
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS hr_leaves (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                employee_number TEXT NOT NULL REFERENCES employees(employee_number),
                kind TEXT NOT NULL,
                starts DATE NOT NULL,
                ends DATE NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
                decided_by BIGINT REFERENCES hr_users(id),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CHECK(ends >= starts)
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS hr_attendance (\n                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,\n                employee_number TEXT NOT NULL REFERENCES employees(employee_number),\n                work_date DATE NOT NULL,\n                check_in TIMESTAMPTZ NOT NULL,\n                check_out TIMESTAMPTZ,\n                UNIQUE(employee_number,work_date),\n                CHECK(check_out IS NULL OR check_out >= check_in)\n            )""")
            cur.execute("ALTER TABLE hr_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE")
            email=os.getenv("HR_BOOTSTRAP_EMAIL","").strip().lower()
            password=os.getenv("HR_BOOTSTRAP_PASSWORD","")
            if email and password:
                cur.execute("SELECT 1 FROM hr_users LIMIT 1")
                if cur.fetchone() is None:
                    cur.execute("INSERT INTO hr_users(email,password_hash,role) VALUES (%s,%s,'admin')",
                                (email,hash_password(password)))

def session_user(request, roles=None):
    token=request.cookies.get("hr_session","")
    if not token:
        raise HTTPException(401,"Login required")
    digest=hashlib.sha256(token.encode()).hexdigest()
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT u.id,u.email,u.role,u.employee_number,u.must_change_password FROM hr_sessions s
                JOIN hr_users u ON u.id=s.user_id
                WHERE s.token_hash=%s AND s.expires_at>NOW() AND u.active=TRUE""",(digest,))
            user=cur.fetchone()
    if not user:
        raise HTTPException(401,"Session expired")
    if user[4] and request.url.path not in {"/api/me","/api/change-password","/api/logout"}:
        raise HTTPException(403,"Password change required")
    if roles and user[2] not in roles:
        raise HTTPException(403,"Insufficient permissions")
    return {"id":user[0],"email":user[1],"role":user[2],"employee_number":user[3],"must_change_password":user[4]}

class Login(BaseModel):
    email: str
    password: str

@router.post("/login")
def login(data:Login,response:Response):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,password_hash FROM hr_users WHERE (email=%s OR (employee_number=%s AND role='employee')) AND active=TRUE",(data.email.strip().lower(),data.email.strip()))
            user=cur.fetchone()
            if not user or not verify(data.password,user[1]):
                raise HTTPException(401,"Invalid credentials")
            token=secrets.token_urlsafe(40)
            cur.execute("INSERT INTO hr_sessions(token_hash,user_id,expires_at) VALUES (%s,%s,%s)",
                        (hashlib.sha256(token.encode()).hexdigest(),user[0],datetime.now(timezone.utc)+timedelta(hours=8)))
    response.set_cookie("hr_session",token,httponly=True,secure=True,samesite="lax",max_age=28800,path="/")
    return {"ok":True}

@router.post("/logout")
def logout(request:Request,response:Response):
    token=request.cookies.get("hr_session","")
    if token:
        with db() as conn:
            conn.execute("DELETE FROM hr_sessions WHERE token_hash=%s",(hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie("hr_session",path="/")
    return {"ok":True}

@router.get("/me")
def me(request:Request):
    return session_user(request)

class NewUser(BaseModel):
    email: str = ""
    password: str
    role: str
    employee_number: str | None = None

@router.post("/users")
def create_user(data:NewUser,request:Request):
    session_user(request,{"admin"})
    if data.role not in ROLES:
        raise HTTPException(422,"Invalid role")
    if data.role=="employee" and not data.employee_number:
        raise HTTPException(422,"Employee number required")
    if data.role!="employee" and not data.email.strip():
        raise HTTPException(422,"Email required for staff roles")
    if data.role=="employee" and (not data.employee_number.isdigit() or len(data.employee_number)>40):
        raise HTTPException(422,"Employee number must contain digits only")
    login_email = ("employee-"+data.employee_number+"@accounts.invalid") if data.role=="employee" else data.email.strip().lower()
    try:
        with db() as conn:
            conn.execute("INSERT INTO hr_users(email,password_hash,role,employee_number) VALUES (%s,%s,%s,%s)",
                         (login_email,hash_password(data.password),data.role,data.employee_number or None))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409,"Email or employee account already exists")
    except psycopg.errors.ForeignKeyViolation:
        raise HTTPException(422,"Unknown employee number")
    return {"ok":True}

@router.get("/staff")
def staff(request:Request):
    session_user(request,{"admin","manager","accountant"})
    with db() as conn:
        rows=conn.execute("SELECT employee_number,full_name,job_title FROM employees ORDER BY employee_number").fetchall()
    return {"count":len(rows),"employees":[{"employee_number":r[0],"full_name":r[1],"job_title":r[2]} for r in rows]}

class Leave(BaseModel):
    kind: str = Field(min_length=1,max_length=80)
    starts: str
    ends: str
    reason: str = Field(default="",max_length=2000)

@router.post("/leaves")
def create_leave(data:Leave,request:Request):
    user=session_user(request,{"employee"})
    try:
        from datetime import date
        start=date.fromisoformat(data.starts); end=date.fromisoformat(data.ends)
        if end<start: raise ValueError()
    except ValueError:
        raise HTTPException(422,"Invalid date range")
    with db() as conn:
        conn.execute("INSERT INTO hr_leaves(employee_number,kind,starts,ends,reason) VALUES (%s,%s,%s,%s,%s)",
                     (user["employee_number"],data.kind,start,end,data.reason))
    return {"ok":True}

@router.get("/leaves")
def list_leaves(request:Request):
    user=session_user(request,{"employee","manager","accountant","admin"})
    sql="""SELECT l.id,l.employee_number,e.full_name,l.kind,l.starts,l.ends,l.reason,l.status
        FROM hr_leaves l JOIN employees e ON e.employee_number=l.employee_number"""
    args=()
    if user["role"]=="employee":
        sql+=" WHERE l.employee_number=%s";args=(user["employee_number"],)
    elif user["role"]=="accountant":
        sql+=" WHERE l.status='approved'"
    sql+=" ORDER BY l.id DESC LIMIT 500"
    with db() as conn: rows=conn.execute(sql,args).fetchall()
    return {"leaves":[{"id":r[0],"employee_number":r[1],"name":r[2],"kind":r[3],"starts":str(r[4]),"ends":str(r[5]),"reason":r[6],"status":r[7]} for r in rows]}

@router.post("/leaves/{leave_id}/{decision}")
def decide_leave(leave_id:int,decision:str,request:Request):
    user=session_user(request,{"manager","admin"})
    if decision not in {"approved","rejected"}:
        raise HTTPException(422,"Invalid decision")
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE hr_leaves SET status=%s,decided_by=%s WHERE id=%s AND status='pending' RETURNING id",
                        (decision,user["id"],leave_id))
            if not cur.fetchone(): raise HTTPException(404,"Pending request not found")
    return {"ok":True}

class ResetEmployeePassword(BaseModel):
    employee_number: str
    new_password: str

@router.post("/employees/reset-password")
def reset_employee_password(data:ResetEmployeePassword,request:Request):
    session_user(request,{"admin"})
    if not data.employee_number.isdigit() or len(data.employee_number)>40:
        raise HTTPException(422,"Invalid employee number")
    new_hash=hash_password(data.new_password)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM hr_users WHERE employee_number=%s AND role='employee' FOR UPDATE",(data.employee_number,))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"Employee account not found")
            cur.execute("UPDATE hr_users SET password_hash=%s WHERE id=%s",(new_hash,row[0]))
            cur.execute("DELETE FROM hr_sessions WHERE user_id=%s",(row[0],))
    return {"ok":True}


@router.post("/employees/create-all-accounts")
def create_all_employee_accounts(request:Request):
    session_user(request,{"admin"})
    created=[]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT e.employee_number,e.full_name FROM employees e
                WHERE NOT EXISTS (SELECT 1 FROM hr_users u WHERE u.employee_number=e.employee_number)
                ORDER BY e.employee_number FOR UPDATE OF e""")
            for number,name in cur.fetchall():
                if not number.isdigit() or len(number)>40:
                    continue
                password=secrets.token_urlsafe(18)
                cur.execute("""INSERT INTO hr_users(email,password_hash,role,employee_number,must_change_password)
                    VALUES (%s,%s,'employee',%s,TRUE) ON CONFLICT DO NOTHING RETURNING id""",
                    ("employee-"+number+"@accounts.invalid",hash_password(password),number))
                if cur.fetchone():
                    created.append({"employee_number":number,"full_name":name,"temporary_password":password})
    return {"created_count":len(created),"credentials":created,
            "note":"Temporary passwords are shown once. Save securely."}

class ChangeOwnPassword(BaseModel):
    current_password: str
    new_password: str

@router.post("/change-password")
def change_own_password(data:ChangeOwnPassword,request:Request):
    user=session_user(request)
    new_hash=hash_password(data.new_password)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM hr_users WHERE id=%s FOR UPDATE",(user["id"],))
            row=cur.fetchone()
            if not row or not verify(data.current_password,row[0]):
                raise HTTPException(401,"Current password is incorrect")
            if verify(data.new_password,row[0]):
                raise HTTPException(422,"New password must be different")
            cur.execute("UPDATE hr_users SET password_hash=%s,must_change_password=FALSE WHERE id=%s",
                        (new_hash,user["id"]))
            token=request.cookies.get("hr_session","")
            cur.execute("DELETE FROM hr_sessions WHERE user_id=%s AND token_hash<>%s",
                        (user["id"],hashlib.sha256(token.encode()).hexdigest()))
    return {"ok":True}


IRAQ_TZ=ZoneInfo("Asia/Baghdad")

@router.post("/attendance/check-in")
def attendance_check_in(request:Request):
    user=session_user(request,{"employee"})
    now=datetime.now(timezone.utc)
    today=now.astimezone(IRAQ_TZ).date()
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO hr_attendance(employee_number,work_date,check_in)
                VALUES (%s,%s,%s) ON CONFLICT (employee_number,work_date) DO NOTHING RETURNING id""",
                (user["employee_number"],today,now))
            if not cur.fetchone():
                raise HTTPException(409,"Attendance already recorded today")
    return {"ok":True}

@router.post("/attendance/check-out")
def attendance_check_out(request:Request):
    user=session_user(request,{"employee"})
    now=datetime.now(timezone.utc)
    today=now.astimezone(IRAQ_TZ).date()
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE hr_attendance SET check_out=%s
                WHERE employee_number=%s AND work_date=%s AND check_out IS NULL
                RETURNING id""",(now,user["employee_number"],today))
            if not cur.fetchone():
                raise HTTPException(409,"Check in first, or check out already recorded")
    return {"ok":True}

@router.get("/attendance")
def list_attendance(request:Request):
    user=session_user(request,{"employee","manager","accountant","admin"})
    sql="""SELECT a.employee_number,e.full_name,a.work_date,a.check_in,a.check_out
        FROM hr_attendance a JOIN employees e ON e.employee_number=a.employee_number"""
    args=()
    if user["role"]=="employee":
        sql+=" WHERE a.employee_number=%s"
        args=(user["employee_number"],)
    sql+=" ORDER BY a.work_date DESC,a.check_in DESC LIMIT 500"
    with db() as conn:
        rows=conn.execute(sql,args).fetchall()
    return {"attendance":[{"employee_number":r[0],"name":r[1],"date":str(r[2]),
        "check_in":r[3].astimezone(IRAQ_TZ).strftime("%H:%M:%S"),
        "check_out":r[4].astimezone(IRAQ_TZ).strftime("%H:%M:%S") if r[4] else None} for r in rows]}


@router.get("/attendance/monthly-report")
def monthly_attendance_report(request:Request,month:str):
    session_user(request,{"admin","manager","accountant"})
    from datetime import date
    import calendar
    try:
        if len(month)!=7 or month[4]!="-":
            raise ValueError()
        year=int(month[:4]); month_number=int(month[5:])
        if date(year,month_number,1).strftime("%Y-%m")!=month:
            raise ValueError()
    except ValueError:
        raise HTTPException(422,"Invalid month (YYYY-MM)")
    start=date(year,month_number,1)
    end=date(year,month_number,calendar.monthrange(year,month_number)[1])
    with db() as conn:
        employees=conn.execute("""SELECT employee_number,full_name FROM employees
            WHERE employee_number ~ '^[0-9]+$' ORDER BY employee_number""").fetchall()
        records=conn.execute("""SELECT a.employee_number,a.work_date,a.check_in,a.check_out
            FROM hr_attendance a JOIN employees e ON e.employee_number=a.employee_number
            WHERE a.work_date BETWEEN %s AND %s AND e.employee_number ~ '^[0-9]+$'
            ORDER BY a.work_date,a.employee_number""",(start,end)).fetchall()
    totals={number:{"employee_number":number,"name":name,"days_present":0,
        "days_late":0,"late_minutes":0,"early_departure_minutes":0,
        "worked_seconds":0} for number,name in employees}
    details=[]
    for number,day,check_in,check_out in records:
        local_in=check_in.astimezone(IRAQ_TZ)
        local_out=check_out.astimezone(IRAQ_TZ) if check_out else None
        start_time=datetime.combine(day,datetime.min.time(),IRAQ_TZ)+timedelta(hours=8,minutes=30)
        end_time=datetime.combine(day,datetime.min.time(),IRAQ_TZ)+timedelta(hours=19,minutes=30)
        late=max(0,int((local_in-start_time).total_seconds()//60))
        early=max(0,int((end_time-local_out).total_seconds()//60)) if local_out else None
        worked=max(0,int((check_out-check_in).total_seconds())) if check_out else None
        totals[number]["days_present"]+=1
        totals[number]["days_late"]+=int(late>0)
        totals[number]["late_minutes"]+=late
        if early is not None:
            totals[number]["early_departure_minutes"]+=early
        if worked is not None:
            totals[number]["worked_seconds"]+=worked
        details.append({"employee_number":number,"name":totals[number]["name"],
            "date":str(day),"check_in":local_in.strftime("%H:%M:%S"),
            "check_out":local_out.strftime("%H:%M:%S") if local_out else None,
            "late_minutes":late,"early_departure_minutes":early,"worked_seconds":worked})
    return {"month":month,"official_start":"08:30","official_end":"19:30",
        "summary":list(totals.values()),"details":details,
        "note":"Only recorded attendance is counted; absence, holidays, breaks and approved leave are not classified."}
