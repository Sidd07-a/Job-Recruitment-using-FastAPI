from fastapi import FastAPI, Request, Form, Depends, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, String, Text, select, DateTime, Enum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
import shutil
from typing import Optional
import enum

# ==========================================
# 1. SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "recruitment_secret_key_for_development"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

RESUME_DIR = "static/uploads/resumes"
os.makedirs(RESUME_DIR, exist_ok=True)

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8')[:72], hashed_password.encode('utf-8'))

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8')[:72], bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 2. DATABASE SETUP
# ==========================================
engine = create_engine("sqlite:///recruitment.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class UserRole(str, enum.Enum):
    candidate = "candidate"
    recruiter = "recruiter"

class AppStatus(str, enum.Enum):
    applied = "applied"
    reviewing = "reviewing"
    interview_scheduled = "interview_scheduled"
    accepted = "accepted"
    rejected = "rejected"

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    email: Mapped[str] = mapped_column(String(100), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(20), default="candidate")  # "candidate" or "recruiter"
    # Candidate fields
    skills: Mapped[Optional[str]] = mapped_column(Text, nullable=True)           # comma-separated
    resume_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    bio: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Recruiter fields
    company: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(150))
    company: Mapped[str] = mapped_column(String(100))
    location: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    required_skills: Mapped[str] = mapped_column(Text)   # comma-separated
    salary_range: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    job_type: Mapped[str] = mapped_column(String(30), default="Full-time")  # Full-time, Part-time, Contract, Remote
    recruiter_id: Mapped[int] = mapped_column()
    created_at: Mapped[str] = mapped_column(String(30), default=lambda: datetime.now().strftime("%b %d, %Y"))

class Application(Base):
    __tablename__ = "applications"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column()
    candidate_id: Mapped[int] = mapped_column()
    status: Mapped[str] = mapped_column(String(30), default="applied")
    cover_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    match_score: Mapped[Optional[int]] = mapped_column(nullable=True)   # 0-100
    interview_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    interview_time: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    applied_at: Mapped[str] = mapped_column(String(30), default=lambda: datetime.now().strftime("%b %d, %Y"))

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="Frontend")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except jwt.InvalidTokenError:
        return None
    user = db.scalars(select(User).where(User.email == email)).first()
    return user

# ==========================================
# SKILL MATCHING HELPER
# ==========================================
def compute_match_score(candidate_skills: str, required_skills: str) -> int:
    if not candidate_skills or not required_skills:
        return 0
    c_skills = {s.strip().lower() for s in candidate_skills.split(",") if s.strip()}
    r_skills = {s.strip().lower() for s in required_skills.split(",") if s.strip()}
    if not r_skills:
        return 0
    matched = c_skills & r_skills
    return round(len(matched) / len(r_skills) * 100)

# ==========================================
# 4. AUTH ROUTES
# ==========================================

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html")

@app.post("/signup")
def signup_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    company: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    existing = db.scalars(select(User).where(User.email == email)).first()
    if existing:
        return templates.TemplateResponse(request=request, name="signup.html", context={"error": "Email already registered."})
    new_user = User(
        name=name, email=email,
        hashed_password=get_password_hash(password),
        role=role,
        company=company if role == "recruiter" else None
    )
    db.add(new_user)
    db.commit()
    access_token = create_access_token(data={"sub": new_user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="frontend/login.html")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.scalars(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid email or password."})
    access_token = create_access_token(data={"sub": user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response

# ==========================================
# 5. DASHBOARD (HOME)
# ==========================================

@app.get("/", response_class=HTMLResponse)
def home_page(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if current_user.role == "recruiter":
        # Recruiter sees their posted jobs + all applications to those jobs
        jobs = db.scalars(select(Job).where(Job.recruiter_id == current_user.id)).all()
        job_ids = [j.id for j in jobs]
        applications = db.scalars(select(Application).where(Application.job_id.in_(job_ids))).all() if job_ids else []
        # Enrich applications with candidate + job info
        enriched = []
        for app in applications:
            candidate = db.get(User, app.candidate_id)
            job = db.get(Job, app.job_id)
            enriched.append({"app": app, "candidate": candidate, "job": job})
        return templates.TemplateResponse(request=request, name="recruiter_dashboard.html", context={
            "current_user": current_user,
            "jobs": jobs,
            "applications": enriched,
            "total_apps": len(applications),
            "pending": sum(1 for a in applications if a.status == "applied"),
            "interviews": sum(1 for a in applications if a.status == "interview_scheduled"),
        })
    else:
        # Candidate sees all jobs with match scores
        all_jobs = db.scalars(select(Job)).all()
        my_applications = db.scalars(select(Application).where(Application.candidate_id == current_user.id)).all()
        applied_job_ids = {a.job_id for a in my_applications}
        jobs_with_scores = []
        for job in all_jobs:
            score = compute_match_score(current_user.skills or "", job.required_skills)
            jobs_with_scores.append({"job": job, "score": score, "applied": job.id in applied_job_ids})
        jobs_with_scores.sort(key=lambda x: x["score"], reverse=True)
        # Enrich my applications with job info
        my_apps_enriched = []
        for app in my_applications:
            job = db.get(Job, app.job_id)
            my_apps_enriched.append({"app": app, "job": job})
        return templates.TemplateResponse(request=request, name="candidate_dashboard.html", context={
            "current_user": current_user,
            "jobs_with_scores": jobs_with_scores,
            "my_applications": my_apps_enriched,
        })

# ==========================================
# 6. PROFILE (Candidate)
# ==========================================

@app.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="profile.html", context={"current_user": current_user})

@app.post("/profile")
async def profile_update(
    request: Request,
    bio: str = Form(""),
    skills: str = Form(""),
    resume: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    user = db.get(User, current_user.id)
    user.bio = bio
    user.skills = skills

    if resume and resume.filename:
        ext = os.path.splitext(resume.filename)[1]
        unique_name = f"{current_user.id}_{datetime.now().timestamp()}{ext}"
        save_path = os.path.join(RESUME_DIR, unique_name)
        with open(save_path, "wb") as buf:
            shutil.copyfileobj(resume.file, buf)
        user.resume_path = f"uploads/resumes/{unique_name}"

    db.commit()
    return RedirectResponse(url="/", status_code=303)

# ==========================================
# 7. JOBS (Recruiter CRUD)
# ==========================================

@app.get("/jobs/create", response_class=HTMLResponse)
def create_job_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user or current_user.role != "recruiter": return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request=request, name="create_job.html", context={"current_user": current_user})

@app.post("/jobs/create")
def create_job_post(
    request: Request,
    title: str = Form(...),
    location: str = Form(...),
    description: str = Form(...),
    required_skills: str = Form(...),
    salary_range: str = Form(""),
    job_type: str = Form("Full-time"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "recruiter": return RedirectResponse(url="/", status_code=303)
    job = Job(
        title=title, company=current_user.company or current_user.name,
        location=location, description=description,
        required_skills=required_skills, salary_range=salary_range,
        job_type=job_type, recruiter_id=current_user.id
    )
    db.add(job)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/jobs/{job_id}/edit", response_class=HTMLResponse)
def edit_job_page(request: Request, job_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user or current_user.role != "recruiter": return RedirectResponse(url="/", status_code=303)
    job = db.get(Job, job_id)
    return templates.TemplateResponse(request=request, name="edit_job.html", context={"job": job, "current_user": current_user})

@app.post("/jobs/{job_id}/edit")
def edit_job_post(
    job_id: int,
    title: str = Form(...),
    location: str = Form(...),
    description: str = Form(...),
    required_skills: str = Form(...),
    salary_range: str = Form(""),
    job_type: str = Form("Full-time"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "recruiter": return RedirectResponse(url="/", status_code=303)
    job = db.get(Job, job_id)
    if job and job.recruiter_id == current_user.id:
        job.title = title; job.location = location; job.description = description
        job.required_skills = required_skills; job.salary_range = salary_range; job.job_type = job_type
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/jobs/{job_id}/delete")
def delete_job(job_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user or current_user.role != "recruiter": return RedirectResponse(url="/", status_code=303)
    job = db.get(Job, job_id)
    if job and job.recruiter_id == current_user.id:
        db.delete(job)
        db.commit()
    return RedirectResponse(url="/", status_code=303)

# ==========================================
# 8. APPLICATIONS (Candidate)
# ==========================================

@app.post("/jobs/{job_id}/apply")
def apply_to_job(
    job_id: int,
    cover_note: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "candidate": return RedirectResponse(url="/", status_code=303)
    # Check not already applied
    existing = db.scalars(select(Application).where(
        Application.job_id == job_id, Application.candidate_id == current_user.id
    )).first()
    if not existing:
        job = db.get(Job, job_id)
        score = compute_match_score(current_user.skills or "", job.required_skills if job else "")
        app_obj = Application(
            job_id=job_id, candidate_id=current_user.id,
            cover_note=cover_note, match_score=score
        )
        db.add(app_obj)
        db.commit()
    return RedirectResponse(url="/", status_code=303)

# ==========================================
# 9. APPLICATION MANAGEMENT (Recruiter)
# ==========================================

@app.get("/applications/{app_id}", response_class=HTMLResponse)
def view_application(request: Request, app_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user: return RedirectResponse(url="/login", status_code=303)
    application = db.get(Application, app_id)
    candidate = db.get(User, application.candidate_id) if application else None
    job = db.get(Job, application.job_id) if application else None
    return templates.TemplateResponse(request=request, name="application_detail.html", context={
        "current_user": current_user,
        "application": application,
        "candidate": candidate,
        "job": job,
    })

@app.post("/applications/{app_id}/status")
def update_status(
    app_id: int,
    status: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "recruiter": return RedirectResponse(url="/", status_code=303)
    application = db.get(Application, app_id)
    if application:
        application.status = status
        db.commit()
    return RedirectResponse(url=f"/applications/{app_id}", status_code=303)

@app.post("/applications/{app_id}/schedule")
def schedule_interview(
    app_id: int,
    interview_date: str = Form(...),
    interview_time: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "recruiter": return RedirectResponse(url="/", status_code=303)
    application = db.get(Application, app_id)
    if application:
        application.interview_date = interview_date
        application.interview_time = interview_time
        application.status = "interview_scheduled"
        db.commit()
    return RedirectResponse(url=f"/applications/{app_id}", status_code=303)
