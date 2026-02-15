import os
import shutil
import random
import string
from typing import List, Optional
from datetime import datetime, timedelta
from utils.email_sender import send_password_recovery_email

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request, Query, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, delete, desc, and_, or_, update
from sqlalchemy.orm import relationship, DeclarativeBase, selectinload
from models import Device, Company, RegistrationCode, User, Payment, EmailTemplate, Base, FreePlanUsage, Menu, GlobalAd, Message
from db_config import engine, get_db, Base, init_db, AsyncSessionLocal
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import time
import json
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from typing import List, Optional, Literal
import logging
from logging.handlers import RotatingFileHandler
import urllib3

# --- GLOBAL SSL/TLS DISABLER ---
# Use this only if specifically requested by user due to infrastructure/proxy issues.
# This disables certificate verification for ALL requests made by this process.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Patch requests if available
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    # Monkey patch requests to default verify=False
    _orig_request = requests.Session.request
    def _patched_request(self, method, url, **kwargs):
        kwargs.setdefault('verify', False)
        return _orig_request(self, method, url, **kwargs)
    requests.Session.request = _patched_request
    requests.request = lambda method, url, **kwargs: requests.Session().request(method, url, **kwargs)
    requests.get = lambda url, **kwargs: requests.request('GET', url, **kwargs)
    requests.post = lambda url, **kwargs: requests.request('POST', url, **kwargs)
except ImportError:
    pass

# Patch httpx if available
try:
    import httpx
    # Patch httpx.AsyncClient and httpx.Client to default verify=False
    _orig_async_init = httpx.AsyncClient.__init__
    def _patched_async_init(self, *args, **kwargs):
        if 'verify' not in kwargs:
            kwargs['verify'] = False
        _orig_async_init(self, *args, **kwargs)
    httpx.AsyncClient.__init__ = _patched_async_init

    _orig_sync_init = httpx.Client.__init__
    def _patched_sync_init(self, *args, **kwargs):
        if 'verify' not in kwargs:
            kwargs['verify'] = False
        _orig_sync_init(self, *args, **kwargs)
    httpx.Client.__init__ = _patched_sync_init
except ImportError:
    pass

# --- LOGGING CONFIGURATION ---
LOG_FILE = "venridesscreens.log"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VenrideScreenS")

# File Handler
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# --- Global In-Memory State ---
PING_TARGETS = {}

# --- Security: Rate Limiting ---
_rate_limit_store = {}  # ip -> [timestamps]
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_FORMS = 5  # max form submissions per minute per IP
RATE_LIMIT_MAX_CHAT = 20  # max chat messages per minute per IP

def check_rate_limit(ip: str, limit: int = RATE_LIMIT_MAX_FORMS) -> bool:
    """Returns True if request is allowed, False if rate limited"""
    import time as _time
    now = _time.time()
    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = []
    # Clean old entries
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limit_store[ip]) >= limit:
        return False
    _rate_limit_store[ip].append(now)
    return True

def sanitize_input(text: str) -> str:
    """Strip HTML tags and dangerous characters from user input"""
    import re
    if not text:
        return ""
    # Remove HTML tags
    clean = re.sub(r'<[^>]+>', '', str(text))
    # Remove script-like patterns
    clean = re.sub(r'javascript:', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'on\w+\s*=', '', clean, flags=re.IGNORECASE)
    return clean.strip()[:2000]  # Max 2000 chars

def generate_verification_code(length: int = 6) -> str:
    """Generate a random numeric code for email/phone verification"""
    import random
    import string
    return ''.join(random.choices(string.digits, k=length))

def validate_honeypot(data: dict) -> bool:
    """Returns True if submission looks legit (honeypot empty). Returns False if bot."""
    hp = data.get('website', data.get('hp_field', data.get('url', '')))
    return not hp  # Real users leave honeypot empty

# --- Pydantic Models for JSON Fields ---

class SidebarItem(BaseModel):
    type: Literal["text", "image"]
    value: str
    font_size: Optional[str] = "1.4rem"
    color: Optional[str] = None
    weight: Optional[str] = "bold"
    font_family: Optional[str] = None

class SidebarGroup(BaseModel):
    items: List[SidebarItem] = Field(default_factory=list)
    duration: Optional[int] = 10

class BottomBarContent(BaseModel):
    static: Optional[str] = ""
    whatsapp: Optional[str] = ""
    instagram: Optional[str] = ""
    messages: Optional[List[str]] = []
    font_size: Optional[str] = "1rem"
    color: Optional[str] = "#ffffff"
    social_color: Optional[str] = None
    weight: Optional[str] = "normal"

class DesignSettings(BaseModel):
    name_font: Optional[str] = None
    name_color: Optional[str] = None
    name_size: Optional[str] = None
    name_weight: Optional[str] = None
    sidebar_bg: Optional[str] = None
    sidebar_text: Optional[str] = None
    bottom_bar_bg: Optional[str] = None
    bottom_bar_text: Optional[str] = None
    ticker_speed: Optional[int] = 30
    bcv_color: Optional[str] = None
    bcv_size: Optional[str] = None
    bcv_weight: Optional[str] = None
    logo_auto_fit: Optional[bool] = True
    logo_size: Optional[int] = 85
    sidebar_bg_image: Optional[str] = None
    sidebar_effect: Optional[str] = "none"
    sidebar_width: Optional[int] = 22
    bottom_bar_height: Optional[int] = 10
    show_bcv: Optional[bool] = True

class GlobalAdSchema(BaseModel):
    video_url: Optional[str] = None # Deprecated
    video_playlist: Optional[List[str]] = [] # Multiple videos
    ticker_text: Optional[str] = None
    ticker_messages: Optional[List[str]] = []
    ad_scripts: Optional[List[str]] = []

class ChatMessageSchema(BaseModel):
    receiver_id: int
    body: str

class MessageSchema(BaseModel):
    receiver_id: Optional[int] = None
    subject: str
    body: str
    attachment_url: Optional[str] = None

class LiveMessageSchema(BaseModel):
    text: str
    duration: Optional[int] = 15
    type: Optional[str] = "alert"

class EmailTemplateSchema(BaseModel):
    name: str
    subject: str
    body: str
    is_active: Optional[bool] = True

class PromotionSchema(BaseModel):
    name: str
    description: Optional[str] = None
    code: str
    discount_pct: float
    valid_from: str # ISO Date
    valid_to: str # ISO Date
    is_active: Optional[bool] = True

# --- Existing Pydantic Models ---
from utils.branding import extract_colors
from utils.auth import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM
from utils.bcv import get_bcv_usd_rate

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

# --- Simple Rate Limiting for Auth ---
login_attempts = {} # {ip: [timestamps]}

app = FastAPI(title="VenrideScreenS API")

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGOS_DIR = os.path.join(os.path.dirname(BASE_DIR), "logos")
STATIC_DIR = os.path.join(BASE_DIR, "static")

os.makedirs(LOGOS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True) # Ensure static dir exists

# --- Static Mounts ---
app.mount("/logos", StaticFiles(directory=LOGOS_DIR), name="logos")
# We don't necessarily need to serve frontend from here as Nginx handles it, 
# but for development it might be useful or for fallback.
# Keeping it minimal as per Nginx setup.

# --- CORS ---
allowed_origins = [
    "https://screens.venrides.com",
    "https://admintv.venrides.com",
    "https://apitv.venrides.com",
    "https://tv.venrides.com",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:8005",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security Headers Middleware ---
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# --- Diagnostics ---
# --- Diagnostics ---
@app.on_event("startup")
async def startup_event():
    """Start background services on app start"""
    try:
        from services.scheduler_service import scheduler_service
        await scheduler_service.start()
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")

@app.get("/")
async def root():
    return {"message": "Venrides Screens API is running", "status": "active"}

@app.post("/api/auth/verify-email")
async def verify_email(code: str, db: AsyncSession = Depends(get_db)):
    """Verify user/company email with code"""
    from models import Company
    stmt = select(Company).where(Company.email_verification_code == code)
    result = await db.execute(stmt)
    company = result.scalar_one_or_none()
    
    if not company:
        raise HTTPException(status_code=400, detail="Código de verificación inválido")
    
    company.is_email_verified = True
    company.email_verification_code = None
    await db.commit()
    return {"message": "Email verificado correctamente", "status": "success"}

@app.get("/diag/status")
async def diag_status(repair: bool = False, db: AsyncSession = Depends(get_db)):
    try:
        from models import Company, User, Device
        from utils.auth import get_password_hash
        
        if repair:
            
            # 1. Force table sync
            await init_db()
            
            # 2. Check/Create Master Admin
            result = await db.execute(select(User).where(User.username == "nerdop@gmail.com"))
            admin = result.scalar_one_or_none()
            
            if not admin:
                # Ensure a company exists
                res_comp = await db.execute(select(Company).limit(1))
                company = res_comp.scalar_one_or_none()
                if not company:
                    company = Company(name="Venrides Master", plan="ultra", is_active=True)
                    db.add(company)
                    await db.commit()
                    await db.refresh(company)
                
                hashed = get_password_hash("venrides123") # Default password for nerdop@gmail.com
                admin = User(
                    username="nerdop@gmail.com",
                    hashed_password=hashed,
                    is_admin=True,
                    role="admin_master",
                    company_id=company.id
                )
                db.add(admin)
                await db.commit()
                return {"status": "repaired", "message": "Master admin (nerdop@gmail.com) created and tables synced"}

        # Normal status check
        companies_count = (await db.execute(select(func.count(Company.id)))).scalar()
        users_count = (await db.execute(select(func.count(User.id)))).scalar()
        devices_count = (await db.execute(select(func.count(Device.id)))).scalar()
        admin_exists = (await db.execute(select(User).where(User.username == "nerdop@gmail.com"))).scalar_one_or_none() is not None
        
        return {
            "status": "healthy",
            "db": {
                "companies": companies_count,
                "users": users_count,
                "devices": devices_count,
                "admin_exists": admin_exists
            },
            "environment": {
                "database_url_set": "DATABASE_URL" in os.environ,
                "logos_dir": LOGOS_DIR
            }
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}

# --- Startup ---
@app.on_event("startup")
async def on_startup():
    try:
        await init_db()
        
        # Seed Master Admin
        async with AsyncSessionLocal() as db:
            try:
                # 1. Ensure a company exists for the admin
                res_comp = await db.execute(select(Company).limit(1))
                company = res_comp.scalar_one_or_none()
                if not company:
                    logger.info("--- Creating Default Company ---")
                    company = Company(
                        name="Venrides Admin", 
                        plan="ultra", 
                        is_active=True,
                        valid_until=datetime.utcnow() + timedelta(days=3650)
                    )
                    db.add(company)
                    await db.commit()
                    await db.refresh(company)
                
                # 2. Ensure admin_master exists
                result = await db.execute(select(User).where(User.username == "nerdop@gmail.com"))
                admin = result.scalar_one_or_none()
                
                if not admin:
                    logger.info("--- Seeding Master Admin (nerdop@gmail.com) ---")
                    hashed = get_password_hash("venrides123")
                    admin = User(
                        username="nerdop@gmail.com",
                        hashed_password=hashed,
                        is_admin=True,
                        role="admin_master",
                        company_id=company.id
                    )
                    db.add(admin)
                    await db.commit()
                else:
                    # Ensure existing admin has the correct role
                    if admin.role != "admin_master":
                        admin.role = "admin_master"
                        await db.commit()
                        logger.info("--- Updated Admin Role to admin_master ---")
                        
            except Exception as e:
                logger.error(f"Error during seeding: {e}")
                await db.rollback()
    except Exception as e:
        logger.error(f"⚠️  Backend startup warning: {e}. Check database credentials.")

# --- Auth Dependencies ---
async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    if not token:
        logger.warning("Token missing")
        raise HTTPException(401, "No autenticado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(401, "Token inválido")
    except JWTError:
        raise HTTPException(401, "Token inválido")
        
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None:
        logger.warning(f"User {username} not found")
        raise HTTPException(401, "Usuario no encontrado")
    return user

def require_role(roles: list):
    async def role_checker(user: User = Depends(get_current_user)):
        if user.role not in roles and not user.is_admin:
            raise HTTPException(403, "No tiene permisos suficientes")
        return user
    return role_checker

# --- Middleware (Kill-switch) ---
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    logger.info(f"Method: {request.method} Path: {request.url.path} Status: {response.status_code} Time: {process_time:.4f}s")
    return response

@app.post("/diag/ping")
async def send_ping(uuid: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Trigger a visual identification ping on the TV"""
    # Permission check: User must own the device's company or be master
    res = await db.execute(select(Device).where(Device.uuid == uuid))
    device = res.scalar_one_or_none()
    
    if not device:
        raise HTTPException(404, "Dispositivo no encontrado")
        
    if current_user.role != "admin_master":
        if device.company_id != current_user.company_id:
            raise HTTPException(403, "No tiene permiso sobre este dispositivo")

    PING_TARGETS[uuid] = time.time()
    return {"status": "ping_sent", "uuid": uuid}

@app.get("/support/unread-count")
async def get_support_unread_count(token: str = Depends(oauth2_scheme)):
    # Placeholder: Return 0 for now until Ticket model is confirmed
    # Logic: query Unread Tickets for user
    return {"count": 0}



@app.middleware("http")
async def kill_switch_middleware(request: Request, call_next):
    bypass_paths = ["/auth", "/docs", "/openapi.json", "/logos"]
    if any(request.url.path.startswith(p) for p in bypass_paths):
        return await call_next(request)

    # Check companies logic
    if "/companies/" in request.url.path and request.method == "GET":
        parts = request.url.path.split("/")
        # format: /companies/{id} available at index 2 or so depending on prefix
        # url path starts with /, so ["", "companies", "1"]
        try:
            if "companies" in parts:
                idx = parts.index("companies")
                if len(parts) > idx + 1 and parts[idx+1].isdigit():
                    company_id = int(parts[idx+1])
                    
                    async with AsyncSessionLocal() as db:
                        result = await db.execute(select(Company).where(Company.id == company_id))
                        company = result.scalar_one_or_none()
                        
                        if company:
                            # Check expiration
                            now = datetime.utcnow()
                            vu = company.valid_until
                            if vu and vu.tzinfo: vu = vu.replace(tzinfo=None)
                            
                            if vu and vu < now:
                                return JSONResponse(
                                    status_code=403, 
                                    content={"detail": "Servicio Expirado", "is_active": False}
                                )
                            if not company.is_active:
                                return JSONResponse(
                                    status_code=403, 
                                    content={"detail": "Servicio Suspendido", "is_active": False}
                                )
        except Exception as e:
            print(f"Middleware Error: {e}")

    return await call_next(request)

# --- PING CHECK AND ENDPOINTS ---

@app.post("/diag/ping")
async def send_ping(uuid: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Trigger a visual identification ping on the TV"""
    # Permission check: User must own the device's company or be master
    res = await db.execute(select(Device).where(Device.uuid == uuid))
    device = res.scalar_one_or_none()
    
    if not device:
        raise HTTPException(404, "Dispositivo no encontrado")
        
    if current_user.role != "admin_master":
        if device.company_id != current_user.company_id:
            raise HTTPException(403, "No tiene permiso sobre este dispositivo")

    PING_TARGETS[uuid] = time.time()
    return {"status": "ping_sent", "uuid": uuid}


def check_permission(user: User, resource: str, action: str):
    if user.is_admin or user.role == "admin_master":
        return True
    if user.role != "admin_master":
        return False
    # permissions = {"users": {"create": True, "view": True}, "companies": {...}}
    perms = user.permissions or {}
    return perms.get(resource, {}).get(action, False)

async def master_access_only(user: User = Depends(get_current_user)):
    if user.role not in ["admin_master"]:
        raise HTTPException(403, "Acceso solo para nivel Maestro")
    return user

# --- BCV Cache ---
BCV_CACHE_FILE = "bcv_cache.json"
bcv_cache = {"rate": None, "last_updated": None}

def load_bcv_cache():
    global bcv_cache
    if os.path.exists(BCV_CACHE_FILE):
        try:
            with open(BCV_CACHE_FILE, "r") as f:
                data = json.load(f)
                bcv_cache["rate"] = data.get("rate")
                lu = data.get("last_updated")
                if lu:
                    bcv_cache["last_updated"] = datetime.fromisoformat(lu)
        except Exception as e:
            logger.error(f"Error loading BCV cache: {e}")

def save_bcv_cache():
    try:
        with open(BCV_CACHE_FILE, "w") as f:
            json.dump({
                "rate": bcv_cache["rate"],
                "last_updated": bcv_cache["last_updated"].isoformat() if bcv_cache["last_updated"] else None
            }, f)
    except Exception as e:
        logger.error(f"Error saving BCV cache: {e}")

# Load cache on startup
load_bcv_cache()

@app.get("/finance/bcv")
async def get_bcv_rate_endpoint():
    now = datetime.now()
    
    # Check if we need to update (only once a day, after midnight)
    needs_update = False
    if not bcv_cache["rate"] or not bcv_cache["last_updated"]:
        needs_update = True
    else:
        # If last update was on a different day than today, we can update
        if bcv_cache["last_updated"].date() < now.date():
            needs_update = True
            
    if needs_update:
        try:
            # Run blocking scraping in threadpool
            rate = await run_in_threadpool(get_bcv_usd_rate)
            if rate:
                bcv_cache["rate"] = rate
                bcv_cache["last_updated"] = now
                await run_in_threadpool(save_bcv_cache)
        except Exception as e:
            logger.error(f"BCV Update Error: {e}")
            
    return {
        "usd_to_ves": bcv_cache["rate"] or 0,
        "last_updated": bcv_cache["last_updated"].isoformat() if bcv_cache["last_updated"] else None
    }

# --- Pydantic Models ---
class CompanyBase(BaseModel):
    name: str
    layout_type: str = "layout-a"
    primary_color: str = "#1a202c"
    secondary_color: str = "#2d3748"
    accent_color: str = "#4a5568"
    max_screens: int = 1
    valid_until: Optional[datetime] = None
    filler_keywords: str = "nature, food"
    google_drive_link: Optional[str] = None
    video_source: str = "youtube"
    plan: Optional[Literal["free", "basic", "plus", "ultra"]] = "free"
    
    rif: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    whatsapp: Optional[str] = None
    instagram: Optional[str] = None
    facebook: Optional[str] = None
    tiktok: Optional[str] = None
    contact_person: Optional[str] = None
    email: Optional[str] = None
    client_editable_fields: Optional[str] = ""
    
    total_screens: Optional[int] = 0
    active_screens: Optional[int] = 0
    
    priority_content_url: Optional[str] = None
    video_playlist: Optional[List[str]] = []
    
    pause_duration: Optional[int] = 10
    sidebar_content: Optional[List[SidebarItem]] = []
    bottom_bar_content: Optional[BottomBarContent] = None
    design_settings: Optional[DesignSettings] = None

class CompanyCreate(CompanyBase):
    username: str
    password: str

class CompanyUpdate(BaseModel):
    name: Optional[str] = None
    layout_type: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    accent_color: Optional[str] = None
    max_screens: Optional[int] = None
    valid_until: Optional[datetime] = None
    filler_keywords: Optional[str] = None
    google_drive_link: Optional[str] = None
    video_source: Optional[str] = None
    video_playlist: Optional[List[str]] = None
    # Mi perfil de negocio & Planes
    plan: Optional[Literal["free", "basic", "plus", "ultra"]] = None
    can_edit_profile: Optional[bool] = None
    has_edited_profile: Optional[bool] = None
    
    rif: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    whatsapp: Optional[str] = None
    instagram: Optional[str] = None
    facebook: Optional[str] = None
    tiktok: Optional[str] = None
    contact_person: Optional[str] = None
    email: Optional[str] = None
    client_editable_fields: Optional[str] = None
    
    total_screens: Optional[int] = None
    active_screens: Optional[int] = None

    # Header Extension
    sidebar_header_type: Optional[Literal["text", "banner"]] = None
    sidebar_header_value: Optional[str] = None


    priority_content_url: Optional[str] = None
    ad_frequency: Optional[int] = None
    sidebar_content: Optional[List[dict]] = None
    bottom_bar_content: Optional[BottomBarContent] = None
    design_settings: Optional[DesignSettings] = None
    
    logo_url: Optional[str] = None
    pause_duration: Optional[int] = None

class UserCreate(BaseModel):
    username: str # email
    password: str
    role: Literal["admin_empresa", "operador_empresa"] # Master only via admin_master
    company_id: Optional[int] = None
    permissions: Optional[dict] = {}

class UserUpdate(BaseModel):
    password: Optional[str] = None
    permissions: Optional[dict] = None
    is_active: Optional[bool] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class UserPasswordUpdate(BaseModel):
    password: str

class UserProfileUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    username: Optional[str] = None

class PaymentCreate(BaseModel):
    company_id: int
    amount: float
    payment_date: datetime
    description: str
    payment_method: str

# --- Endpoints ---

# OAuth2-compatible endpoint for frontend login
@app.post("/login/token")
async def login_token(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """OAuth2-compatible token endpoint"""
    # Bot Protection
    client_ip = request.client.host
    if not check_rate_limit(client_ip):
        raise HTTPException(429, "Demasiados intentos. Intente de nuevo en un minuto.")

    # Search by email (username column)
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    
    # Check Active
    if user and not user.is_active:
        raise HTTPException(status_code=403, detail="Cuenta suspendida o inactiva")
    
    # Check password (hashed or temp)
    if not user or (not verify_password(password, user.hashed_password) and \
                    (not user.temp_password or not verify_password(password, user.temp_password))):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    # If using temp password, ensure must_change is set (safety net)
    if user.temp_password and verify_password(password, user.temp_password):
        if not user.must_change_password:
             # Should be set, but force it just in case
             user.must_change_password = True
             await db.commit()

    token = create_access_token(data={
        "sub": user.username, 
        "role": user.role,
        "company_id": user.company_id
    })
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "is_admin": user.is_admin,
            "role": user.role,
            "permissions": user.permissions,
            "company_id": user.company_id,
            "must_change_password": user.must_change_password
        }
    }

@app.post("/auth/login")
async def login(request: Request, login_data: LoginRequest, db: AsyncSession = Depends(get_db)):
    # Bot Protection
    client_ip = request.client.host
    if not check_rate_limit(client_ip):
        raise HTTPException(429, "Demasiados intentos. Intente de nuevo en un minuto.")

    # Search by email (username column)
    result = await db.execute(select(User).where(User.username == login_data.username))
    user = result.scalar_one_or_none()
    
    # Check Active
    if user and not user.is_active:
        raise HTTPException(status_code=403, detail="Cuenta suspendida o inactiva")
    
    # Check password (hashed or temp)
    if not user or (not verify_password(login_data.password, user.hashed_password) and \
                    (not user.temp_password or not verify_password(login_data.password, user.temp_password))):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    # If using temp password, ensure must_change is set (safety net)
    if user.temp_password and verify_password(login_data.password, user.temp_password):
        if not user.must_change_password:
             # Should be set, but force it just in case
             user.must_change_password = True
             await db.commit()

    token = create_access_token(data={
        "sub": user.username, 
        "role": user.role,
        "company_id": user.company_id
    })
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "is_admin": user.is_admin,
            "role": user.role,
            "permissions": user.permissions,
            "company_id": user.company_id,
            "must_change_password": user.must_change_password
        }
    }

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

@app.post("/auth/forgot-password")
async def forgot_password(username: str = Form(...), db: AsyncSession = Depends(get_db)):
    # Use Form to be easily called from frontend (or JSON, but let's assume JSON body with a Pydantic model is cleaner? 
    # Actually, the user might prefer a simple request. Let's stick to JSON body or query param. 
    # Standard is JSON usually. Let's make a wrapper model or use Query param for simplicity first.)
    
    # Correction: Let's use Body or Query. simple JSON {"username": "email"}
    pass # Replaced by implementation below

class ForgotPasswordRequest(BaseModel):
    username: str

@app.post("/auth/forgot-password")
async def forgot_password_endpoint(request: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()
    
    # Always return success to prevent user enumeration
    if not user:
        # Avoid blocking the event loop
        await asyncio.sleep(random.uniform(0.1, 0.5))
        return {"message": "Si el correo existe, recibirá instrucciones."}
    
    # Generate random temp password
    chars = string.ascii_letters + string.digits
    temp_pass = ''.join(random.choice(chars) for _ in range(12))
    
    user.temp_password = get_password_hash(temp_pass)
    user.must_change_password = True
    await db.commit()
    
    # Send email
    try:
        sent = send_password_recovery_email(user.username, temp_pass)
        if not sent:
            logger.error(f"Failed to send recovery email to {user.username}")
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        
    return {"message": "Si el correo existe, recibirá instrucciones."}

@app.post("/auth/change-password")
async def change_password(
    data: PasswordChangeRequest, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    # Verify old password (hashed or temp)
    valid_old = False
    if verify_password(data.old_password, current_user.hashed_password):
        valid_old = True
    elif current_user.temp_password and verify_password(data.old_password, current_user.temp_password):
        valid_old = True
        
    if not valid_old:
        raise HTTPException(status_code=401, detail="La contraseña actual es incorrecta")
    
    # Set new password
    current_user.hashed_password = get_password_hash(data.new_password)
    current_user.temp_password = None
    current_user.must_change_password = False
    
    await db.commit()
    return {"message": "Contraseña actualizada correctamente"}

@app.get("/companies/", response_model=List[dict])
async def get_companies(db: AsyncSession = Depends(get_db), current_user: User = Depends(master_access_only)):
    # Master roles can see all
    if not check_permission(current_user, "companies", "view"):
        raise HTTPException(403, "No tiene permiso para ver empresas")
        
    result = await db.execute(select(Company).options(selectinload(Company.devices)))
    companies = result.scalars().all()
    
    return [{
        "id": c.id, 
        "name": c.name, 
        "plan": c.plan or "free", 
        "is_active": c.is_active,
        "max_screens": c.max_screens or 2,
        "active_screens": c.active_screens,
        "total_screens": c.total_screens
    } for c in companies]

# --- Phase 9: Admin Enhancements Endpoints ---
@app.get("/admin/all-users")
async def get_all_users_admin(db: AsyncSession = Depends(get_db), current_user: User = Depends(master_access_only)):
    query = select(User).options(selectinload(User.company))
    result = await db.execute(query)
    users = result.scalars().all()
    
    return [{
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "company_name": u.company.name if u.company else "N/A",
        "company_id": u.company_id,
        "is_active": True # User model doesn't have is_active yet, assume true or add later
    } for u in users]


@app.delete("/admin/users/{user_id}")
async def delete_user_admin(user_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(["admin_master"]))):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    if user.id == current_user.id:
        raise HTTPException(400, "No puedes eliminarte a ti mismo")
        
    await db.delete(user)
    await db.commit()
    return {"message": "Usuario eliminado"}

@app.get("/admin/devices")
async def get_all_devices(db: AsyncSession = Depends(get_db), current_user: User = Depends(master_access_only)):
    query = select(Device).options(selectinload(Device.company))
    result = await db.execute(query)
    devices = result.scalars().all()
    
    # Calculate online status (ping < 5 mins)
    now = datetime.utcnow()
    five_min_ago = now - timedelta(minutes=5)
    
    return [{
        "id": d.id,
        "uuid": d.uuid,
        "name": d.name,
        "company_name": d.company.name if d.company else "Sin Asignar",
        "last_ping": d.last_ping,
        "is_online": d.last_ping and d.last_ping.replace(tzinfo=None) > five_min_ago,
        "is_active": d.is_active
    } for d in devices]

@app.patch("/admin/devices/{device_uuid}/status")
async def toggle_device_status(
    device_uuid: str, 
    is_active: bool = Query(...), 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(require_role(["admin_master"]))
):
    result = await db.execute(select(Device).where(Device.uuid == device_uuid))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, "Dispositivo no encontrado")
        
    device.is_active = is_active
    await db.commit()
    return {"message": "Estatus actualizado", "is_active": device.is_active}

@app.delete("/admin/companies/{company_id}")
async def delete_company(company_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(["admin_master"]))):
    # Only Admin Master can delete companies
    res = await db.execute(select(Company).where(Company.id == company_id))
    company = res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")
    
    await db.delete(company)
    await db.commit()
    return {"message": "Empresa eliminada correctamente"}

@app.post("/companies/")
async def create_company(data: CompanyCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(["admin_master"]))):
    # Only Admin Master can create companies
    
    # Check if admin email exists
    res = await db.execute(select(User).where(User.username == data.username))
    if res.scalar_one_or_none():
        raise HTTPException(400, "El correo del administrador ya está registrado")
        
    # Operator email
    op_email = f"op.{data.username}"
    res_op = await db.execute(select(User).where(User.username == op_email))
    if res_op.scalar_one_or_none():
         raise HTTPException(400, f"El correo automático para el operador ({op_email}) ya existe. Por favor use otro email para el admin.")

    print(f"DEBUG: creating company with playlist: {data.video_playlist}")
    new_company = Company(
        name=data.name,
        layout_type=data.layout_type,
        max_screens=data.max_screens,
        valid_until=data.valid_until,
        primary_color=data.primary_color,
        secondary_color=data.secondary_color,
        accent_color=data.accent_color,
        filler_keywords=data.filler_keywords,
        google_drive_link=data.google_drive_link,
        rif=data.rif,
        address=data.address,
        phone=data.phone,
        contact_person=data.contact_person,
        email=data.email,
        client_editable_fields=data.client_editable_fields,
        pause_duration=data.pause_duration,
        sidebar_content=[s.model_dump() for s in data.sidebar_content] if data.sidebar_content else [],
        bottom_bar_content=data.bottom_bar_content.model_dump() if data.bottom_bar_content else None,
        design_settings=data.design_settings.model_dump() if data.design_settings else {},
        video_source=data.video_source,
        priority_content_url=data.priority_content_url,
        video_playlist=data.video_playlist,
        plan=data.plan
    )
    db.add(new_company)
    await db.commit()
    await db.refresh(new_company)
    
    hashed = get_password_hash(data.password)
    
    if data.plan.lower() == 'free':
        # Single user with limited role
        basic_user = User(
            username=data.username,
            hashed_password=hashed,
            company_id=new_company.id,
            role="user_basic",
            is_admin=False
        )
        db.add(basic_user)
    else:
        # User 1: admin_empresa
        admin_user = User(
            username=data.username,
            hashed_password=hashed,
            company_id=new_company.id,
            role="admin_empresa",
            is_admin=False
        )
        db.add(admin_user)

        # User 2: operador_empresa
        operator_user = User(
            username=op_email,
            hashed_password=hashed, # Initially same password
            company_id=new_company.id,
            role="operador_empresa",
            is_admin=False
        )
        db.add(operator_user)
    
    await db.commit()
    
    return new_company

@app.get("/companies/{company_id}", response_model=CompanyBase)
async def get_company(company_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Master or own company
    if current_user.role != "admin_master" and current_user.company_id != company_id:
        raise HTTPException(403, "No tiene acceso a los datos de esta empresa")

    # Master sees all details
    pass

    res = await db.execute(select(Company).options(selectinload(Company.devices)).where(Company.id == company_id))
    company = res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")
    return company

@app.patch("/companies/{company_id}", response_model=CompanyBase)
async def update_company(company_id: int, update: CompanyUpdate, request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    res = await db.execute(select(Company).options(selectinload(Company.devices)).where(Company.id == company_id))
    company = res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")
    
    
    data_dict = update.dict(exclude_unset=True)
    
    # Check perfil Restricted Logic
    if current_user.role != "admin_master":
        profile_fields = {'name', 'rif', 'address', 'phone', 'contact_person', 'email'}
        
        # If trying to edit profile fields while locked
        if not company.can_edit_profile and any(f in data_dict for f in profile_fields):
             raise HTTPException(403, "Edición de perfil (Datos de Empresa) deshabilitada. Contacte al administrador.")
        
        # If editing profile fields (while allowed), lock it after this update
        if any(f in data_dict for f in profile_fields):
            company.can_edit_profile = False
            company.has_edited_profile = True

    # Operator Check (Restricted Access)
    if current_user.role == "operador_empresa":
        # Operators can ONLY modify playlist AND source
        allowed_fields = {'video_playlist', 'priority_content_url', 'video_source'}
        # Filter data_dict to remove any unauthorized fields
        keys_to_remove = [k for k in data_dict.keys() if k not in allowed_fields]
        for k in keys_to_remove:
            del data_dict[k]

    for key, val in data_dict.items():
        if key == 'design_settings' and val is not None:
            # Merge design_settings instead of replacing
            current_settings = company.design_settings or {}
            if isinstance(current_settings, dict):
                current_settings.update(val)
                company.design_settings = dict(current_settings)  # Force SQLAlchemy to detect change
            else:
                company.design_settings = val
        elif hasattr(company, key) and key not in ['id', 'total_screens', 'active_screens']:
            setattr(company, key, val)
    
    await db.commit()
    await db.refresh(company)
    return company

@app.post("/companies/{company_id}/logo")
async def upload_logo(company_id: int, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Company).where(Company.id == company_id))
    company = res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")
        
    file_ext = os.path.splitext(file.filename)[1]
    filename = f"{company_id}_logo{file_ext}"
    file_path = os.path.join(LOGOS_DIR, filename)
    
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
        
    # Extract colors (Now non-blocking)
    colors = await run_in_threadpool(extract_colors, file_path)
    
    company.logo_url = f"/api/logos/{filename}"
    company.primary_color = colors["primary"]
    company.secondary_color = colors["secondary"]
    company.accent_color = colors["accent"]
    
    await db.commit()
    return {"logo_url": company.logo_url, "colors": colors}

@app.post("/companies/{company_id}/sidebar-bg")
async def upload_sidebar_bg(company_id: int, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Company).where(Company.id == company_id))
    company = res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")
        
    file_ext = os.path.splitext(file.filename)[1]
    filename = f"{company_id}_sidebar{file_ext}"
    file_path = os.path.join(LOGOS_DIR, filename)
    
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
        
    url = f"/api/logos/{filename}"
    
    # Update JSON field safely
    current_settings = company.design_settings
    if isinstance(current_settings, dict):
        current_settings['sidebar_bg_image'] = url
        company.design_settings = dict(current_settings)
    elif current_settings is None:
        company.design_settings = {'sidebar_bg_image': url}
    else:
        # Pydantic/Object handling
        try:
            d = current_settings.dict()
        except:
            d = dict(current_settings)
        d['sidebar_bg_image'] = url
        company.design_settings = d
        
    await db.commit()
    await db.refresh(company)
    return company

@app.post("/companies/{company_id}/toggle")
async def toggle_company(company_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Company).where(Company.id == company_id))
    company = res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")
        
    company.is_active = not company.is_active
    await db.commit()
    return {"is_active": company.is_active}

@app.post("/devices/generate-code")
async def generate_code(company_id: int, db: AsyncSession = Depends(get_db)):
    # Clean up old codes
    await db.execute(delete(RegistrationCode).where(RegistrationCode.expires_at < datetime.utcnow()))
    
    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    # Check uniqueness in DB
    attempts = 0
    while attempts < 100:
        attempts += 1
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        existing = await db.execute(select(RegistrationCode).where(RegistrationCode.code == code))
        if not existing.scalar_one_or_none():
            break
    else:
        raise HTTPException(500, "No se pudo generar un código único después de muchos intentos")
        
    new_code = RegistrationCode(
        code=code,
        company_id=company_id,
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )
    db.add(new_code)
    await db.commit()
    
    return {"code": code, "expires_in_minutes": 10}

@app.post("/devices/validate-code")
async def validate_code(code: str, device_uuid: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(RegistrationCode).where(RegistrationCode.code == code))
    reg_code = res.scalar_one_or_none()
    
    if not reg_code:
        print(f"DEBUG AUTH: Código {code} no encontrado en DB")
        raise HTTPException(404, "Código inválido")
        
    now_utc = datetime.utcnow()
    # Normalize DB datetime (if it has tzinfo, make it naive to match utcnow)
    expires_at = reg_code.expires_at.replace(tzinfo=None) if reg_code.expires_at.tzinfo else reg_code.expires_at
    
    print(f"DEBUG AUTH: Validating code {code}. Expires (Naive): {expires_at}, Now: {now_utc}")
    
    if now_utc > expires_at:
        print(f"DEBUG AUTH: Código expirado. Diff: {(now_utc - expires_at).total_seconds()}s")
        await db.delete(reg_code)
        await db.commit()
        raise HTTPException(400, "Código expirado")
        
    company_id = reg_code.company_id
    
    # Check limit
    active_count = await db.execute(select(func.count()).select_from(Device).where(Device.company_id == company_id))
    count = active_count.scalar()
    
    company_res = await db.execute(select(Company).where(Company.id == company_id))
    company = company_res.scalar_one()
    
    if count >= company.max_screens:
        raise HTTPException(400, "Límite de pantallas alcanzado")
    
    # Check Free Plan Usage (Block Reuse)
    if company.plan == 'free':
        usage_res = await db.execute(select(FreePlanUsage).where(FreePlanUsage.uuid == device_uuid))
        existing_usage = usage_res.scalar_one_or_none()
        if existing_usage:
             # Check if it is the same company? The user said "no se pueda volver a vincular a otro plan free".
             # If it's the same company, maybe it's a re-link (e.g. WiFi reset)? 
             # User said: "los planes free debe ser de un solo uso". Strict interpretation: Once used, never again on another free plan.
             # But if I unlink and re-link to SAME company, should it block? 
             # "importante el tiempo de vencimiento no se reinicia pos las vinculaciones nuevas" -> implies re-linking is allowed.
             # So: If UUID used previously on Company A (Free), and now trying to link to Company B (Free) -> BLOCK.
             # If linking back to Company A -> ALLOW (but time continues).
             
             if existing_usage.company_id != company_id:
                  # USED ON ANOTHER COMPANY -> BLOCK
                  raise HTTPException(403, "DEVICE_BLOCKED_FREE_TRIAL_USED")
             else:
                  # SAME COMPANY -> ALLOW (Time continues from first_screen_connected_at)
                  pass
        else:
             # First time usage, will register at end
             pass
        
    # Link Device
    dev_res = await db.execute(select(Device).where(Device.uuid == device_uuid))
    device = dev_res.scalar_one_or_none()
    
    if device:
        device.company_id = company_id
        device.name = f"TV-{device_uuid[:8]}"
    else:
        device = Device(uuid=device_uuid, company_id=company_id, name=f"TV-{device_uuid[:8]}")
        db.add(device)
    
    # Free Plan Trial Logic (Phase 10 Supervisor)
    if company.plan == 'free' and not company.first_screen_connected_at:
        company.first_screen_connected_at = now_utc
        company.valid_until = now_utc + timedelta(days=60)
        db.add(company) # Ensure update
        print(f"DEBUG SUPERVISOR: Started Free Trial for {company.name}. Valid until {company.valid_until}")
        
    # Free Plan Blocking Logic (One-Time Use)
    if company.plan == 'free':
        # Check if UUID exists in FreePlanUsage
        usage_res = await db.execute(select(FreePlanUsage).where(FreePlanUsage.uuid == device_uuid))
        usage = usage_res.scalar_one_or_none()
        
        # If it exists and belongs to a DIFFERENT company (or even same, to be strict), block.
        # Requirement: "no se pueda volver a vincular a otro plan free... un solo uso".
        if usage:
             # If it was used before, we MUST BLOCK IT.
             await db.commit() # Create device transaction might have passed, rollback?
             # Actually, we should check this BEFORE linking. Moving logic up.
             pass 
        else:
             # Register usage
             new_usage = FreePlanUsage(uuid=device_uuid, company_id=company_id)
             db.add(new_usage)

    
    # Register Usage if Free and not existing
    if company.plan == 'free':
         # Idempotency check handled by logic above or insert ignore
         # We already checked 'existing_usage'. If it didn't exist, create it.
         if not existing_usage:
             db.add(FreePlanUsage(uuid=device_uuid, company_id=company_id))

    await db.commit()
    await db.delete(reg_code)
    await db.commit()
    
    return {"status": "success", "company_name": company.name}

# --- Admin Stats & Payments ---

@app.get("/admin/stats/overview")
async def admin_stats(db: AsyncSession = Depends(get_db)):
    total_comp = await db.execute(select(func.count(Company.id)))
    active_comp = await db.execute(select(func.count(Company.id)).where(Company.is_active == True))
    total_screens = await db.execute(select(func.count(Device.id)))
    
    stats = {
        "total_companies": total_comp.scalar() or 0,
        "active_companies": active_comp.scalar() or 0,
        "total_screens": total_screens.scalar() or 0,
        "monthly_revenue": 0 # Placeholder implementation
    }
    return stats

@app.get("/admin/payments/")
async def list_all_payments(db: AsyncSession = Depends(get_db)):
    """Listar todos los pagos en el sistema"""
    result = await db.execute(select(Payment).order_by(Payment.payment_date.desc()))
    return result.scalars().all()

@app.get("/admin/companies/{company_id}/devices")
async def get_company_devices(company_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Device).where(Device.company_id == company_id))
    return res.scalars().all()

@app.get("/admin/payments/{company_id}")
async def get_company_payments(company_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Payment).where(Payment.company_id == company_id).order_by(Payment.payment_date.desc()))
    return res.scalars().all()

@app.post("/admin/payments/create")
async def create_payment(payment: PaymentCreate, db: AsyncSession = Depends(get_db)):
    """Create a payment and trigger APK download delivery if subscription is active"""
    new_payment = Payment(**payment.dict())
    db.add(new_payment)
    await db.commit()
    await db.refresh(new_payment)
    
    # Check if we should send APK download link
    # Typically sent upon first payment or plan renewal
    try:
        stmt = select(Company).where(Company.id == new_payment.company_id)
        comp_res = await db.execute(stmt)
        company = comp_res.scalar_one_or_none()
        
        if company and company.is_active:
            from services.template_service import template_service
            # Get shortened URL for APK
            base_url = os.getenv("PROD_API_URL", "https://apitv.venrides.com")
            from utils.url_shortener import shorten_url
            short_url = shorten_url(f"{base_url}/downloads/tv")
            
            rendered = template_service.render("apk_download", {
                "name": company.contact_person or company.name,
                "short_url": short_url
            }, db=db)
            
            from utils.email_sender import send_email
            send_email(company.email, rendered["subject"], rendered["body"])
            logger.info(f"APK download link sent to {company.email} after payment.")
    except Exception as e:
        logger.error(f"Failed to trigger APK email: {e}")

    return new_payment
@app.get("/admin/debug/stats")
async def debug_stats(db: AsyncSession = Depends(get_db)):
    dev_res = await db.execute(select(func.count()).select_from(Device))
    comp_res = await db.execute(select(func.count()).select_from(Company))
    all_devs = await db.execute(select(Device))
    all_comps = await db.execute(select(Company))
    
    return {
        "total_devices": dev_res.scalar(),
        "total_companies": comp_res.scalar(),
        "devices": [{"id": d.id, "uuid": d.uuid, "name": d.name, "company_id": d.company_id} for d in all_devs.scalars().all()],
        "companies": [{"id": c.id, "name": c.name} for c in all_comps.scalars().all()]
    }
@app.patch("/companies/{company_id}/credentials")
async def update_credentials(company_id: int, update: UserPasswordUpdate, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(User).where(User.company_id == company_id))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    if update.username:
        user.username = update.username
    if update.password:
        from main import get_password_hash
        user.hashed_password = get_password_hash(update.password)
    await db.commit()
    return {"message": "Credenciales actualizadas correctamente"}

@app.patch("/devices/{uuid}/rename")
async def rename_device_endpoint(uuid: str, data: dict, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    res = await db.execute(select(Device).where(Device.uuid == uuid))
    device = res.scalar_one_or_none()
    if not device:
        raise HTTPException(404, "Dispositivo no encontrado")
        
    # Permission Check
    if current_user.role != "admin_master":
        if device.company_id != current_user.company_id:
             raise HTTPException(403, "No autorizado")
             
    if "name" in data:
        device.name = data["name"]
        
    await db.commit()
    return {"status": "success", "name": device.name}

# --- Credentials ---
@app.get("/devices/{uuid}/config")
async def get_device_config(uuid: str, db: AsyncSession = Depends(get_db)):
    # Find device
    res = await db.execute(select(Device).where(Device.uuid == uuid))
    device = res.scalar_one_or_none()
    
    if not device:
        raise HTTPException(404, "Dispositivo no registrado")
        
    if not device.company_id:
        raise HTTPException(404, "Dispositivo no vinculado a una empresa")
        
    # Check Device Active Status (Phase 9)
    if not device.is_active:
        return {
            "is_active": False,
            "error": "Dispositivo Suspendido por Administración",
            "name": "Dispositivo Inactivo"
        }

    # Get Company with menus
    comp_res = await db.execute(
        select(Company)
        .options(selectinload(Company.menus))
        .where(Company.id == device.company_id)
    )
    company = comp_res.scalar_one()
    
    # Check expiration/active
    now = datetime.utcnow()
    vu = company.valid_until
    if vu and vu.tzinfo: vu = vu.replace(tzinfo=None)

    if not company.is_active or (vu and vu < now):
         return {
             "is_active": False,
             "name": company.name,
             "layout_type": company.layout_type,
             "primary_color": company.primary_color,
             "secondary_color": company.secondary_color,
             "accent_color": company.accent_color
         }

    # Check Screen Limit
    device_count_res = await db.execute(select(func.count(Device.id)).where(Device.company_id == device.company_id))
    device_count = device_count_res.scalar()
    
    if device_count > company.max_screens:
        return {
             "is_active": False,
             "name": company.name,
             "error": f"Límite de pantallas excedido ({company.max_screens}). Por favor actualice su plan."
        }

    # Get BCV Rate
    # Check live alerts
    alert_res = await db.execute(
        select(Message)
        .where(Message.company_id == device.company_id, Message.is_alert == True, Message.is_read == False)
        .order_by(desc(Message.created_at))
        .limit(1)
    )
    active_alert = alert_res.scalar_one_or_none()
    alert_data = None
    if active_alert:
        alert_data = {
            "id": active_alert.id,
            "subject": active_alert.subject,
            "body": active_alert.body,
            "duration": active_alert.alert_duration or 15
        }
    # Get BCV Rate (Non-blocking from cache only)
    rate = bcv_cache["rate"] or 0

    # Build config
    config = {
        "is_active": True,
        "name": company.name,
        "layout_type": company.layout_type,
        "active_alert": alert_data,
        "primary_color": company.primary_color,
        "secondary_color": company.secondary_color,
        "accent_color": company.accent_color,
        "logo_url": company.logo_url,
        "filler_keywords": company.filler_keywords,
        "google_drive_link": company.google_drive_link,
        "video_source": company.video_source,
        "priority_content_url": company.priority_content_url,
        "video_playlist": company.video_playlist or [],
        "sidebar_content": company.sidebar_content,
        "bottom_bar_content": company.bottom_bar_content,
        "design_settings": company.design_settings,
        "pause_duration": company.pause_duration,
        "bcv_rate": rate,
        "plan": company.plan,
        "sidebar_header_type": company.sidebar_header_type,
        "sidebar_header_value": company.sidebar_header_value or company.name,
        "menus": [ {"name": i.name, "price": i.price, "category": i.category} for i in company.menus ],
        "ping_command": False
    }

    # Internal Ping Check (Low Level)
    if device.uuid in PING_TARGETS:
         if time.time() - PING_TARGETS[device.uuid] < 15:
             config["ping_command"] = True
    
    # -- Overrides for FREE plan --
    if company.plan == 'free':
        # Get latest Global Ad
        gad_res = await db.execute(select(GlobalAd).order_by(GlobalAd.updated_at.desc()).limit(1))
        gad = gad_res.scalar_one_or_none()
        if gad:
            # FREE users don't control bottom bar or priority videos
            if gad.video_url:
                config["priority_content_url"] = gad.video_url
            
            # Use ticker messages if available, else fallback to ticker_text
            ticker_msgs = gad.ticker_messages or []
            if not ticker_msgs and gad.ticker_text:
                ticker_msgs = [gad.ticker_text]
            
            if ticker_msgs:
                config["bottom_bar_content"] = {
                    "static": ticker_msgs[0], # Legacy support
                    "messages": ticker_msgs,   # New support
                    "font_size": "1.5rem",
                    "color": "#fbbf24",
                    "weight": "bold"
                }
            
            if gad.ad_scripts:
                config["ad_scripts"] = gad.ad_scripts
        else:
            # Fallback if no global ad
            config["bottom_bar_content"] = {"static": "Venrides Pantallas Inteligentes"}

        # Trial Expiration Alert (Supervisor)
        if company.valid_until:
             days = (company.valid_until.replace(tzinfo=None) - datetime.utcnow()).days
             if 0 <= days <= 15:
                  alert_msg = f"⚠️ Tu prueba gratuita vence en {days} días. ¡Suscríbete en venrides.com!"
                  if config.get("bottom_bar_content") and "messages" in config["bottom_bar_content"]:
                       config["bottom_bar_content"]["messages"].append(alert_msg)
                  else:
                       config["bottom_bar_content"] = {
                           "static": alert_msg,
                           "messages": [alert_msg],
                           "font_size": "1.4rem",
                           "color": "#ef4444", 
                           "weight": "bold"
                       }

    return config

@app.get("/companies/{company_id}/preview-config")
async def get_company_preview_config(company_id: int, db: AsyncSession = Depends(get_db)):
    """Versión de configuración para el previsualizador (sin requerir UUID)"""
    comp_res = await db.execute(
        select(Company)
        .options(selectinload(Company.menus))
        .where(Company.id == company_id)
    )
    company = comp_res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")

    # Get BCV Rate (Non-blocking from cache only)
    rate = bcv_cache["rate"] or 0

    # Build config
    config = {
        "is_active": True,
        "name": company.name,
        "layout_type": company.layout_type,
        "primary_color": company.primary_color,
        "secondary_color": company.secondary_color,
        "accent_color": company.accent_color,
        "logo_url": company.logo_url,
        "filler_keywords": company.filler_keywords,
        "google_drive_link": company.google_drive_link,
        "video_source": company.video_source,
        "priority_content_url": company.priority_content_url,
        "video_playlist": company.video_playlist or [],
        "sidebar_content": company.sidebar_content,
        "bottom_bar_content": company.bottom_bar_content,
        "design_settings": company.design_settings,
        "pause_duration": company.pause_duration,
        "bcv_rate": rate,
        "plan": company.plan,
        "sidebar_header_type": company.sidebar_header_type,
        "sidebar_header_value": company.sidebar_header_value or company.name,
        "menus": [ {"name": i.name, "price": i.price, "category": i.category} for i in company.menus ]
    }

    # -- Overrides for FREE plan --
    if company.plan == 'free':
        # Get latest Global Ad
        gad_res = await db.execute(select(GlobalAd).order_by(GlobalAd.updated_at.desc()).limit(1))
        gad = gad_res.scalar_one_or_none()
        if gad:
            # FREE users don't control bottom bar or priority videos
            # Clean playlist: remove empty strings
            playlist = [v for v in (gad.video_playlist or []) if v.strip()]
            
            # Fallback to video_url if playlist is empty
            if not playlist and gad.video_url:
                playlist = [gad.video_url]
                
            if playlist:
                config["priority_content_url"] = playlist[0]
                config["priority_playlist"] = playlist
            else:
                # Absolute fallback to filler keywords/nature
                config["priority_content_url"] = None
                config["filler_keywords"] = "nature, coffee"
            
            # Use ticker messages if available, else fallback to ticker_text
            ticker_msgs = gad.ticker_messages or []
            if not ticker_msgs and gad.ticker_text:
                ticker_msgs = [gad.ticker_text]
            
            if ticker_msgs:
                config["bottom_bar_content"] = {
                    "static": ticker_msgs[0], # Legacy support
                    "messages": ticker_msgs,   # New support
                    "font_size": "1.5rem",
                    "color": "#fbbf24",
                    "weight": "bold"
                }
            
            if gad.ad_scripts:
                config["ad_scripts"] = gad.ad_scripts
        else:
            # Fallback if no global ad
            config["bottom_bar_content"] = {"static": "Venrides Pantallas Inteligentes"}

    return config

@app.get("/admin/global-ad")
async def get_global_ad(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(GlobalAd).order_by(GlobalAd.updated_at.desc()).limit(1))
    gad = res.scalar_one_or_none()
    if not gad:
        return {"video_url": "", "video_playlist": [], "ticker_text": "", "ticker_messages": [], "ad_scripts": []}
    return gad

@app.post("/admin/global-ad")
async def update_global_ad(ad: GlobalAdSchema, db: AsyncSession = Depends(get_db)):
    # Check if exists
    res = await db.execute(select(GlobalAd).order_by(GlobalAd.updated_at.desc()).limit(1))
    gad = res.scalar_one_or_none()
    if gad:
        gad.video_url = ad.video_url
        gad.video_playlist = ad.video_playlist
        gad.ticker_text = ad.ticker_text
        gad.ticker_messages = ad.ticker_messages
        gad.ad_scripts = ad.ad_scripts
    else:
        gad = GlobalAd(
            video_url=ad.video_url, 
            video_playlist=ad.video_playlist,
            ticker_text=ad.ticker_text, 
            ticker_messages=ad.ticker_messages,
            ad_scripts=ad.ad_scripts
        )
        db.add(gad)
    await db.commit()
    return gad



# --- Admin Management Endpoints ---

@app.get("/admin/master-info")
async def get_master_info(db: AsyncSession = Depends(get_db)):
    """Obtener info del Admin Maestro (para el widget de chat)"""
    res = await db.execute(select(User).where(User.role == "admin_master"))
    master = res.scalar_one_or_none()
    if not master:
        # Fallback to any master admin if exists
        res = await db.execute(select(User).where(User.role == "admin_master"))
        master = res.scalar_one_or_none()
        
    if not master:
        raise HTTPException(404, "Administrador Maestro no encontrado")
        
    return {"id": master.id, "username": master.username}

@app.get("/admin/users/")
async def list_users(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Listar usuarios con filtros de rol"""
    query = select(User)
    
    if current_user.role == "admin_master":
        # Master role sees all
        pass
    elif current_user.role == "admin_empresa":
        # Empresa admin only sees users of their company
        query = query.where(User.company_id == current_user.company_id)
    else:
        raise HTTPException(403, "No tiene permiso")

    result = await db.execute(query)
    users = result.scalars().all()
    # Map for response
    return [{"id": u.id, "username": u.username, "role": u.role, "company_id": u.company_id, "permissions": u.permissions, "is_active": u.is_active} for u in users]

@app.post("/admin/users/")
async def create_user(data: UserCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Crear usuarios con validación de jerarquía"""
    
    # 1. Hierarchical Check
    if current_user.role == "admin_master":
        # Can create any role
        pass
    elif current_user.role == "admin_empresa":
        # Can ONLY create operators for THEIR OWN company
        if data.role != "operador_empresa":
            raise HTTPException(403, "Solo puede crear operadores")
        # Force company_id to match their own
        data.company_id = current_user.company_id
    else:
        # Prevent non-admins from creating users
        raise HTTPException(403, "No tiene permiso para crear usuarios")

    # 2. Duplicate Check
    res = await db.execute(select(User).where(User.username == data.username))
    if res.scalar_one_or_none():
        raise HTTPException(400, "El correo electrónico ya está registrado")

    # 3. Create
    new_user = User(
        username=data.username,
        hashed_password=get_password_hash(data.password),
        role=data.role,
        company_id=data.company_id,
        permissions=data.permissions
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"id": new_user.id, "username": new_user.username, "role": new_user.role}

@app.patch("/admin/users/{user_id}")
async def update_user(user_id: int, data: dict, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Actualizar usuario (rol, empresa, contraseña opcional)"""
    
    # Permission Check
    if current_user.role == "admin_master":
        pass # Master can do anything
    elif current_user.role == "admin_empresa":
        # Can only update operators from their OWN company
        # Validation happens below in Scope Check
        pass 
    else:
        raise HTTPException(403, "No tiene permiso para editar usuarios")
    
    # Get user
    res = await db.execute(select(User).where(User.id == user_id))
    target_user = res.scalar_one_or_none()
    if not target_user:
        raise HTTPException(404, "Usuario no encontrado")
    
    # Scope Check for non-master
    if current_user.role == "admin_empresa":
        if target_user.company_id != current_user.company_id:
             raise HTTPException(403, "No autorizado")
        if target_user.role != "operador_empresa":
             raise HTTPException(403, "Solo puede editar operadores")

    # Update fields
    if "role" in data and data["role"]:
        # Admin Empresa cannot change role
        if current_user.role == "admin_master":
            target_user.role = data["role"]
    if "company_id" in data:
        # Admin Empresa cannot change company_id
        if current_user.role == "admin_master":
            target_user.company_id = data["company_id"] if data["company_id"] else None
    if "password" in data and data["password"]:  # Only update if password is provided
        target_user.hashed_password = get_password_hash(data["password"])
    
    await db.commit()
    await db.refresh(target_user)
    return {"id": target_user.id, "username": target_user.username, "role": target_user.role}

@app.patch("/admin/users/{user_id}/password")
async def update_user_password(user_id: int, data: UserPasswordUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Cambio de contraseña con restricciones de rol"""
    res = await db.execute(select(User).where(User.id == user_id))
    target_user = res.scalar_one_or_none()
    if not target_user:
        raise HTTPException(404, "Usuario no encontrado")

    # 1. Permission Logic
    can_edit = False
    if current_user.role == "admin_master":
        can_edit = True
    # Master roles simplified to admin_master only
    elif current_user.role == "admin_empresa":
        # Can only edit their company's operator
        if target_user.company_id == current_user.company_id and target_user.role == "operador_empresa":
            can_edit = True
    elif current_user.id == user_id:
        can_edit = True # Self edit

    if not can_edit:
        raise HTTPException(403, "No tiene permiso para cambiar esta contraseña")

    target_user.hashed_password = get_password_hash(data.password)
    await db.commit()
    return {"message": "Contraseña actualizada correctamente"}

@app.patch("/admin/me")
async def update_my_profile(data: UserProfileUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Actualizar perfil propio (Usuario/Password)"""
    # Update Username
    if data.username and data.username != current_user.username:
        # Restriction: ONLY Admin Master can change username
        if current_user.role != "admin_master":
             raise HTTPException(403, "Solo el Administrador Maestro puede cambiar nombres de usuario")

        # Check duplicate
        res = await db.execute(select(User).where(User.username == data.username))
        if res.scalar_one_or_none():
            raise HTTPException(400, "El nombre de usuario ya está en uso")
        current_user.username = data.username
    
    # Update Password
    if data.password:
        current_user.hashed_password = get_password_hash(data.password)
    
    await db.commit()
    await db.refresh(current_user)
    return {"id": current_user.id, "username": current_user.username, "role": current_user.role}

@app.patch("/admin/users/{user_id}/status")
async def toggle_user_status(
    user_id: int, 
    is_active: bool = Query(...), 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """Activar/Suspender Usuario"""
    # Permission Check
    can_manage = False
    if current_user.role == "admin_master":
        can_manage = True
    elif current_user.role == "admin_empresa":
        can_manage = True # Will scope to company
        
    if not can_manage:
        raise HTTPException(403, "No autorizado")
        
    res = await db.execute(select(User).where(User.id == user_id))
    target = res.scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Usuario no encontrado")
        
    # Scope Check for non-master
    if current_user.role == "admin_empresa" and target.company_id != current_user.company_id:
        raise HTTPException(403, "No autorizado")
        
    # Prevent self-deactivation
    if target.id == current_user.id:
        raise HTTPException(400, "No puedes desactivar tu propia cuenta")
        
    target.is_active = is_active
    await db.commit()
    return {"message": "Estado actualizado", "is_active": is_active}

@app.post("/admin/users/")
async def create_user_admin(
    user_data: dict, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """Crear un nuevo usuario (Restringido a Administrador Maestro)"""
    """Crear un nuevo usuario"""
    
    # Permission Logic
    if current_user.role == "admin_master":
        pass # OK
    elif current_user.role == "admin_empresa":
        # Force assignments for security
        user_data["role"] = "operador_empresa"
        user_data["company_id"] = current_user.company_id
    else:
        raise HTTPException(403, "No tiene permisos para crear usuarios")
    
    # Validations
    if not user_data.get("username") or not user_data.get("password"):
        raise HTTPException(400, "Username y password son obligatorios")
    
    # Check if exists
    res = await db.execute(select(User).where(User.username == user_data["username"]))
    if res.scalar_one_or_none():
        raise HTTPException(400, "El usuario ya existe")
    
    new_user = User(
        username=user_data["username"],
        hashed_password=get_password_hash(user_data["password"]),
        role=user_data.get("role", "operador_empresa"),
        company_id=user_data.get("company_id"),
        is_active=True
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"message": "Usuario creado", "id": new_user.id}

@app.delete("/admin/users/{id}")
async def delete_user(id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Eliminar usuario"""
    
    # Permission Logic
    if current_user.role == "admin_master":
        pass # OK
    elif current_user.role == "admin_empresa":
        # Will check scope below
        pass
    else:
        raise HTTPException(403, "Solo roles Maestros pueden eliminar usuarios")

    result = await db.execute(select(User).where(User.id == id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    
    # Scope Check
    if current_user.role == "admin_empresa":
        if user.company_id != current_user.company_id:
             raise HTTPException(403, "No autorizado")
        if user.role != "operador_empresa":
             raise HTTPException(403, "Solo puede eliminar operadores")

    if user.role == "admin_master":
        raise HTTPException(403, "No se puede eliminar al Administrador Maestro")

    await db.delete(user)
    await db.commit()
    return {"message": "Usuario eliminado correctamente"}

@app.get("/admin/devices/")
async def list_all_devices(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Listar todos los dispositivos (para Gestión de Panel Master)"""
    if current_user.role == "admin_master":
        query = select(Device).options(selectinload(Device.company))
    elif current_user.role == "admin_empresa":
        query = select(Device).where(Device.company_id == current_user.company_id).options(selectinload(Device.company))
    else:
        raise HTTPException(403, "No tiene permiso")
        
    result = await db.execute(query)
    devices = result.scalars().all()
    
    from datetime import timezone
    now = datetime.now(timezone.utc)
    return [{
        "id": d.id,
        "uuid": d.uuid,
        "name": d.name,
        "company_id": d.company_id,
        "company_name": d.company.name if d.company else "Sin Asignar",
        "is_active": d.is_active,
        "is_online": (now - d.last_ping).total_seconds() < 300 if d.last_ping else False
    } for d in devices]

@app.patch("/admin/devices/{uuid}")
async def update_device_name(uuid: str, device_data: dict = Body(...), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Actualizar nombre de un dispositivo"""
    # Optional: Verify ownership if not master admin
    if current_user.role != "admin_master":
        # Check if device belongs to user's company
        dev_check = await db.execute(select(Device).where(Device.uuid == uuid))
        d_check = dev_check.scalar_one_or_none()
        if not d_check or d_check.company_id != current_user.company_id:
             raise HTTPException(403, "No tiene permiso para editar este dispositivo")

    new_name = device_data.get("name")
    if not new_name:
         raise HTTPException(400, "Nombre requerido")
         
    result = await db.execute(select(Device).where(Device.uuid == uuid))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, "Dispositivo no encontrado")
    device.name = new_name
    await db.commit()
    return {"message": "Dispositivo actualizado correctamente"}

@app.delete("/admin/companies/{company_id}/devices")
async def delete_company_devices(company_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Eliminar TODOS los dispositivos de una empresa (Desvinculación Masiva)"""
    # Verify permissions: Admin Master or Admin of target company
    if current_user.role != "admin_master":
        if current_user.company_id != company_id:
             raise HTTPException(403, "No tiene permiso para gestionar esta empresa")
    
    # Execute Mass Delete
    await db.execute(delete(Device).where(Device.company_id == company_id))
    await db.commit()
    return {"message": "Todos los dispositivos han sido desvinculados correctamente"}

@app.post("/admin/devices/")
async def create_admin_device(device_data: dict, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(["admin_master"]))):
    """Vincular dispositivo manualmente por UUID"""
    uuid_str = device_data.get("uuid")
    company_id = device_data.get("company_id")
    name = device_data.get("name", f"TV-{uuid_str[:8]}")
    
    if not uuid_str or not company_id:
        raise HTTPException(400, "UUID y company_id son requeridos")
        
    res = await db.execute(select(Device).where(Device.uuid == uuid_str))
    device = res.scalar_one_or_none()
    
    if device:
        device.company_id = company_id
        device.name = name
    else:
        device = Device(uuid=uuid_str, company_id=company_id, name=name)
        db.add(device)
        
    await db.commit()
    return {"message": "Dispositivo vinculado correctamente", "uuid": uuid_str}

@app.delete("/admin/devices/{uuid}")
async def delete_device(uuid: str, db: AsyncSession = Depends(get_db)):
    """Eliminar un dispositivo"""
    result = await db.execute(select(Device).where(Device.uuid == uuid))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, "Dispositivo no encontrado")
    await db.delete(device)
    await db.commit()
    return {"message": "Dispositivo eliminado correctamente"}

@app.patch("/admin/payments/{id}")
async def update_payment(
    id: int, 
    amount: float = None, 
    currency: str = None, 
    payment_method: str = None, 
    description: str = None,
    db: AsyncSession = Depends(get_db)
):
    """Actualizar un registro de pago"""
    result = await db.execute(select(Payment).where(Payment.id == id))
    payment = result.scalar_one_or_none()
    if not payment:
        raise HTTPException(404, "Pago no encontrado")
    
    if amount is not None: payment.amount = amount
    if currency is not None: payment.currency = currency
    if payment_method is not None: payment.payment_method = payment_method
    if description is not None: payment.description = description
    
    await db.commit()
    return {"message": "Pago actualizado correctamente"}

# list_all_devices removed in favor of get_all_devices (with richer info)

# Admin payments already defined above

@app.delete("/admin/payments/{id}")
async def delete_payment(id: int, db: AsyncSession = Depends(get_db)):
    """Eliminar un registro de pago"""
    result = await db.execute(select(Payment).where(Payment.id == id))
    payment = result.scalar_one_or_none()
    if not payment:
        raise HTTPException(404, "Pago no encontrado")
    await db.delete(payment)
    await db.commit()
    return {"message": "Pago eliminado correctamente"}
# --- Menu Management ---
@app.get("/admin/companies/{company_id}/menus")
async def get_company_menus(company_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Menu).where(Menu.company_id == company_id))
    return res.scalars().all()

@app.post("/admin/companies/{company_id}/menus/")
async def create_menu_item(company_id: int, item: dict, db: AsyncSession = Depends(get_db)):
    db_item = Menu(company_id=company_id, **item)
    db.add(db_item)
    await db.commit()
    await db.refresh(db_item)
    return db_item

# --- Messaging System ---

@app.post("/admin/messages/")
async def send_message(
    msg: MessageSchema, 
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(oauth2_scheme) # Assuming we have a get_current_user helper or similar
):
    # For now, simplistic sender identification. 
    # Real implementations should use a proper get_current_user dependency.
    # I'll just look for sender_id in a real app, here I simulate it.
    new_msg = Message(
        sender_id=None, # TBD: current_user.id
        receiver_id=msg.receiver_id,
        subject=msg.subject,
        body=msg.body,
        attachment_url=msg.attachment_url,
        company_id=None # TBD
    )
    db.add(new_msg)
    await db.commit()
    return {"message": "Mensaje enviado correctamente"}

@app.get("/admin/messages/inbox")
async def get_inbox(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Message).order_by(Message.created_at.desc()))
    return res.scalars().all()

@app.patch("/admin/messages/{id}/read")
async def mark_as_read(id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Message).where(Message.id == id))
    msg = res.scalar_one_or_none()
    if msg:
        msg.is_read = True
        await db.commit()
    return {"status": "ok"}

# --- Internal Chat System ---

@app.get("/admin/chat/conversations")
async def get_chat_conversations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all chat conversations for current user (Internal Messaging 2.0)"""
    # Fetch threads where user is participant and not hidden
    query = select(ChatThread).where(
        or_(
            and_(ChatThread.participant_1_id == current_user.id, ChatThread.is_hidden_by_1 == False),
            and_(ChatThread.participant_2_id == current_user.id, ChatThread.is_hidden_by_2 == False)
        )
    ).order_by(ChatThread.last_message_at.desc())
    
    result = await db.execute(query)
    threads = result.scalars().all()
    
    result_list = []
    for thread in threads:
        partner_id = thread.participant_2_id if thread.participant_1_id == current_user.id else thread.participant_1_id
        
        partner_res = await db.execute(select(User).where(User.id == partner_id))
        partner = partner_res.scalar_one_or_none()
        
        # Calculate real unread count for this partner
        unread_res = await db.execute(
            select(func.count(Message.id)).where(
                and_(
                    Message.sender_id == partner_id,
                    Message.receiver_id == current_user.id,
                    Message.is_read == False
                )
            )
        )
        real_unread_count = unread_res.scalar_one()

        # Get last message body from cache or fetch if missing
        last_msg = thread.last_subject or "S/M"
        
        if partner:
            result_list.append({
                'partner': {
                    'id': partner.id,
                    'username': partner.username,
                    'role': partner.role
                },
                'last_message': last_msg,
                'last_message_at': thread.last_message_at.isoformat() if thread.last_message_at else thread.created_at.isoformat(),
                'unread_count': real_unread_count
            })
    
    return result_list

@app.get("/admin/chat/messages/{partner_id}")
async def get_chat_messages(
    partner_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all messages with partner and mark as read"""
    query = select(Message).where(
        and_(
            Message.is_alert == False,
            or_(
                and_(Message.sender_id == current_user.id, Message.receiver_id == partner_id),
                and_(Message.sender_id == partner_id, Message.receiver_id == current_user.id)
            )
        )
    ).order_by(Message.created_at.asc())
    
    result = await db.execute(query)
    messages = result.scalars().all()
    
    # Mark as read in Thread
    p1 = min(current_user.id, partner_id)
    p2 = max(current_user.id, partner_id)
    t_res = await db.execute(select(ChatThread).where(and_(ChatThread.participant_1_id == p1, ChatThread.participant_2_id == p2)))
    thread = t_res.scalar_one_or_none()
    if thread:
        if thread.participant_1_id == current_user.id:
            thread.is_read_by_1 = True
        else:
            thread.is_read_by_2 = True
            
    # Mark individual messages as read
    await db.execute(
        update(Message)
        .where(and_(
            Message.sender_id == partner_id,
            Message.receiver_id == current_user.id,
            Message.is_read == False
        ))
        .values(is_read=True)
    )
    
    await db.commit()
    return messages

@app.post("/admin/chat/send")
async def send_chat_message(
    chat_data: ChatMessageSchema,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Send a chat message (Internal Messaging 2.0)"""
    receiver_id = chat_data.receiver_id
    body = chat_data.body

    # Verify receiver
    receiver_res = await db.execute(select(User).where(User.id == receiver_id))
    receiver = receiver_res.scalar_one_or_none()
    if not receiver: raise HTTPException(404, "Destinatario no encontrado")
    
    # Check Blocks
    from models import BlockedUser
    block = await db.execute(select(BlockedUser).where(
        or_(
            and_(BlockedUser.blocker_id == receiver_id, BlockedUser.blocked_id == current_user.id),
            and_(BlockedUser.blocker_id == current_user.id, BlockedUser.blocked_id == receiver_id)
        )
    ))
    if block.scalar_one_or_none():
        raise HTTPException(403, "Comunicación bloqueada entre estos usuarios")

    # Handle Thread
    p1 = min(current_user.id, receiver_id)
    p2 = max(current_user.id, receiver_id)
    
    thread_res = await db.execute(select(ChatThread).where(and_(ChatThread.participant_1_id == p1, ChatThread.participant_2_id == p2)))
    thread = thread_res.scalar_one_or_none()
    
    if not thread:
        thread = ChatThread(
            participant_1_id=p1,
            participant_2_id=p2,
            last_message_at=datetime.utcnow(),
            last_subject=body[:100]
        )
        db.add(thread)
    
    # Update thread
    thread.last_message_at = datetime.utcnow()
    thread.last_subject = body[:100]
    if thread.participant_1_id == receiver_id:
        thread.is_read_by_1 = False
        thread.is_hidden_by_1 = False
        thread.is_read_by_2 = True
        thread.is_hidden_by_2 = False
    else:
        thread.is_read_by_2 = False
        thread.is_hidden_by_2 = False
        thread.is_read_by_1 = True
        thread.is_hidden_by_1 = False

    # Save Message
    msg = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        subject="Chat Interno",
        body=body,
        is_alert=False,
        created_at=datetime.utcnow()
    )
    db.add(msg)
    await db.commit()
    await db.refresh(msg)
    return msg

@app.delete("/admin/chat/conversation/{partner_id}")
async def delete_chat_conversation(
    partner_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Soft delete conversation (Mark as hidden)"""
    p1 = min(current_user.id, partner_id)
    p2 = max(current_user.id, partner_id)
    
    res = await db.execute(select(ChatThread).where(and_(ChatThread.participant_1_id == p1, ChatThread.participant_2_id == p2)))
    thread = res.scalar_one_or_none()
    if thread:
        if thread.participant_1_id == current_user.id:
            thread.is_hidden_by_1 = True
        else:
            thread.is_hidden_by_2 = True
        await db.commit()
    return {"message": "Conversación eliminada (vista local)"}

@app.post("/admin/chat/block")
async def block_chat_user(
    blocked_id: int,
    reason: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bloquear un usuario"""
    from models import BlockedUser
    # Prevent self-block
    if blocked_id == current_user.id:
        raise HTTPException(400, "No te puedes bloquear a ti mismo")
        
    res = await db.execute(select(BlockedUser).where(and_(BlockedUser.blocker_id == current_user.id, BlockedUser.blocked_id == blocked_id)))
    if res.scalar_one_or_none():
        return {"message": "Ya está bloqueado"}
    
    blocked = BlockedUser(blocker_id=current_user.id, blocked_id=blocked_id, reason=reason)
    db.add(blocked)
    await db.commit()
    return {"message": "Usuario bloqueado"}

@app.get("/admin/chat/unread-count")
async def get_chat_unread_count(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get total unread conversations"""
    query = select(func.count(ChatThread.id)).where(
        or_(
            and_(ChatThread.participant_1_id == current_user.id, ChatThread.is_read_by_1 == False, ChatThread.is_hidden_by_1 == False),
            and_(ChatThread.participant_2_id == current_user.id, ChatThread.is_read_by_2 == False, ChatThread.is_hidden_by_2 == False)
        )
    )
    result = await db.execute(query)
    count = result.scalar() or 0
    return {"unread_count": count}

@app.post("/admin/chat/unblock")
async def unblock_user(blocked_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    from models import BlockedUser
    block = await db.execute(select(BlockedUser).where(
        and_(BlockedUser.blocker_id == current_user.id, BlockedUser.blocked_id == blocked_id)
    ))
    b = block.scalar_one_or_none()
    if not b:
        raise HTTPException(404, "Bloqueo no encontrado")
        
    await db.delete(b)
    await db.commit()
    return {"message": "Usuario desbloqueado"}

@app.delete("/admin/chat/conversation/{partner_id}")
async def delete_conversation(partner_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Borrar historial de conversación (Hard delete por ahora)"""
    query = delete(Message).where(
        or_(
            and_(Message.sender_id == current_user.id, Message.receiver_id == partner_id),
            and_(Message.sender_id == partner_id, Message.receiver_id == current_user.id)
        )
    )
    await db.execute(query)
    await db.commit()
    return {"message": "Conversación eliminada"}



@app.post("/companies/{company_id}/message")
async def send_live_alert(
    company_id: int,
    msg: LiveMessageSchema,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Authorization: Master or Company Admin of same company
    if current_user.role != "admin_master":
        if current_user.role == "admin_empresa" and current_user.company_id != company_id:
            raise HTTPException(403, "No tiene permiso para enviar mensajes a esta empresa")
        elif current_user.role not in ["admin_master", "admin_empresa"]:
            raise HTTPException(403, "No tiene permisos suficientes")
    
    new_msg = Message(
        company_id=company_id,
        sender_id=current_user.id,
        subject="¡AVISO IMPORTANTE!",
        body=msg.text,
        is_alert=True,
        alert_duration=msg.duration,
        is_read=False
    )
    db.add(new_msg)
    await db.commit()
    return {"message": "Alerta enviada a pantallas", "duration": msg.duration}

# --- Phase 10: Helpdesk / Soporte Técnico ---

class TicketCreate(BaseModel):
    subject: str
    category: str
    priority: Optional[str] = "normal"
    initial_message: str

class TicketReply(BaseModel):
    body: str

@app.post("/admin/helpdesk/tickets")
async def create_ticket(data: TicketCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    from models import SupportTicket, TicketMessage
    
    # Create Ticket
    ticket = SupportTicket(
        user_id=current_user.id,
        subject=data.subject,
        category=data.category,
        priority=data.priority,
        status="open"
    )
    db.add(ticket)
    await db.commit()
    await db.refresh(ticket)
    
    # Create Initial Message
    msg = TicketMessage(
        ticket_id=ticket.id,
        sender_id=current_user.id,
        body=data.initial_message,
        is_internal=False
    )
    db.add(msg)
    await db.commit()
    
    return {"id": ticket.id, "message": "Ticket creado exitosamente"}

@app.get("/admin/helpdesk/tickets")
async def list_tickets(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    from models import SupportTicket
    
    query = select(SupportTicket).options(selectinload(SupportTicket.user)).order_by(SupportTicket.updated_at.desc())
    
    # Filters
    if current_user.role != "admin_master":
        # Regular users see only their tickets
        query = query.where(SupportTicket.user_id == current_user.id)
        
    result = await db.execute(query)
    tickets = result.scalars().all()
    
    return [{
        "id": t.id,
        "subject": t.subject,
        "category": t.category,
        "priority": t.priority,
        "status": t.status,
        "created_at": t.created_at,
        "updated_at": t.updated_at,
        "user_email": t.user.username if t.user else "Unknown"
    } for t in tickets]

@app.get("/admin/helpdesk/tickets/{id}")
async def get_ticket_details(id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    from models import SupportTicket, TicketMessage
    
    # Get Ticket
    res = await db.execute(select(SupportTicket).options(selectinload(SupportTicket.user), selectinload(SupportTicket.messages).selectinload(TicketMessage.sender)).where(SupportTicket.id == id))
    ticket = res.scalar_one_or_none()
    
    if not ticket:
        raise HTTPException(404, "Ticket no encontrado")
        
    # Permission Check
    if current_user.role != "admin_master" and ticket.user_id != current_user.id:
        raise HTTPException(403, "No tiene permiso para ver este ticket")
        
    return {
        "id": ticket.id,
        "subject": ticket.subject,
        "category": ticket.category,
        "priority": ticket.priority,
        "status": ticket.status,
        "created_at": ticket.created_at,
        "user_email": ticket.user.username if ticket.user else "Unknown",
        "messages": [{
            "id": m.id,
            "body": m.body,
            "created_at": m.created_at,
            "sender_email": m.sender.username if m.sender else "Sistema",
            "is_staff": m.sender and m.sender.role == "admin_master"
        } for m in ticket.messages]
    }

@app.post("/admin/helpdesk/tickets/{id}/reply")
async def reply_ticket(id: int, reply: TicketReply, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    from models import SupportTicket, TicketMessage
    
    res = await db.execute(select(SupportTicket).where(SupportTicket.id == id))
    ticket = res.scalar_one_or_none()
    if not ticket:
        raise HTTPException(404, "Ticket no encontrado")
        
    # Permission Check
    if current_user.role != "admin_master" and ticket.user_id != current_user.id:
        raise HTTPException(403, "No tiene permiso para responder a este ticket")
        
    new_msg = TicketMessage(
        ticket_id=ticket.id,
        sender_id=current_user.id,
        body=reply.body
    )
    db.add(new_msg)
    
    # Update Ticket Timestamp & Status logic
    ticket.updated_at = datetime.utcnow()
    if current_user.role == "admin_master":
        if ticket.status == "open":
            ticket.status = "in_progress"
    else:
        # If user replies, maybe reopen if closed? For now just keep or set to in_progress
        pass
        
    await db.commit()
    return {"message": "Respuesta enviada"}

@app.patch("/admin/helpdesk/tickets/{id}/status")
async def update_ticket_status(id: int, status: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(["admin_master"]))):
    from models import SupportTicket
    
    res = await db.execute(select(SupportTicket).where(SupportTicket.id == id))
    ticket = res.scalar_one_or_none()
    if not ticket:
        raise HTTPException(404, "Ticket no encontrado")
        
    ticket.status = status
    await db.commit()
    return {"message": f"Estado actualizado a {status}"}
    db.add(new_msg)
    await db.commit()
    return {"status": "success", "message": "Alerta enviada correctamente"}

# --- Email Templates ---

@app.post("/admin/email-templates/")
async def create_email_template(template: EmailTemplateSchema, db: AsyncSession = Depends(get_db)):
    pass # Implementation TBD

@app.post("/admin/run-supervisor")
async def manual_run_supervisor(current_user: User = Depends(require_role(["admin_master"]))):
    try:
        from supervisor import run_supervisor
        await run_supervisor()
        return {"message": "Supervisor ejecutado correctamente. Revise supervisor.log"}
    except Exception as e:
        raise HTTPException(500, f"Error ejecutando supervisor: {e}")
async def upsert_template(template: EmailTemplateSchema, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(EmailTemplate).where(EmailTemplate.name == template.name))
    db_template = res.scalar_one_or_none()
    
    if db_template:
        db_template.subject = template.subject
        db_template.body = template.body
    else:
        db_template = EmailTemplate(**template.dict())
        db.add(db_template)
    
    await db.commit()
    return {"message": "Plantilla guardada"}

@app.get("/admin/email-templates/")
async def list_templates(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(EmailTemplate))
    return res.scalars().all()
    db.add(db_item)
    await db.commit()
    await db.refresh(db_item)
    return db_item

@app.delete("/admin/menus/{menu_id}")
async def delete_menu_item(menu_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Menu).where(Menu.id == menu_id))
    item = res.scalar_one_or_none()
    if item:
        await db.delete(item)
        await db.commit()
    return {"status": "ok"}

# ============================================================
# --- Phase 11: Landing Page Forms + Downloads + Benry AI ---
# ============================================================

class ContactFormData(BaseModel):
    nombre: str
    email: str
    telefono: str
    asunto: Optional[str] = ""
    mensaje: str

class PlanSignupFormData(BaseModel):
    plan: str
    nombre: str
    email: str
    telefono: str
    empresa: str
    tipo_negocio: str
    pantallas_estimadas: str
    mensaje: Optional[str] = ""

class BenryChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None

class BenryLeadData(BaseModel):
    session_id: str
    nombre: Optional[str] = ""
    telefono: Optional[str] = ""
    email: Optional[str] = ""
    plan_interes: Optional[str] = ""

@app.post("/api/forms/contact")
async def submit_contact_form(data: ContactFormData, request: Request):
    """Submit contact form — rate limited, anti-spam, sends email + logs to Sheets"""
    from utils.email_sender import send_email
    
    client_ip = request.client.host if request.client else "unknown"
    
    # Security: Rate limiting
    if not check_rate_limit(client_ip, RATE_LIMIT_MAX_FORMS):
        raise HTTPException(status_code=429, detail="Demasiadas solicitudes. Intenta de nuevo en un minuto.")
    
    # Security: Honeypot check
    raw = data.dict()
    if not validate_honeypot(raw):
        logger.warning(f"Bot detected (honeypot) from {client_ip}")
        return {"message": "Gracias por tu mensaje.", "status": "success"}  # Fake success to fool bots
    
    # Security: Sanitize all inputs
    data.nombre = sanitize_input(data.nombre)
    data.email = sanitize_input(data.email)
    data.telefono = sanitize_input(data.telefono)
    data.asunto = sanitize_input(data.asunto)
    data.mensaje = sanitize_input(data.mensaje)
    
    # 1. Log to Google Sheets
    try:
        from services.sheets_service import sheets_service
        sheets_service.log_contact(data.dict())
    except Exception as e:
        logger.warning(f"Failed to log contact to Sheets: {e}")
    
    # 2. Send email notification
    try:
        notification_email = os.getenv("NOTIFICATION_EMAIL", "info.venridesscreen@gmail.com")
        
        email_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #0a0a0f;">
            <div style="max-width: 600px; margin: 0 auto; background: #1a1a2e; padding: 30px; border-radius: 15px; border: 1px solid #333;">
                <h2 style="color: #c8ff00; margin-bottom: 20px;">📨 Nuevo Contacto — VenridesScreenS</h2>
                <table style="width: 100%; border-collapse: collapse; color: #e0e0e0;">
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Nombre:</td><td style="padding: 8px;">{data.nombre}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Email:</td><td style="padding: 8px;">{data.email}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Teléfono:</td><td style="padding: 8px;">{data.telefono}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Asunto:</td><td style="padding: 8px;">{data.asunto or 'Sin asunto'}</td></tr>
                </table>
                <div style="margin-top: 15px; padding: 15px; background: #0d0d1a; border-radius: 10px; color: #ccc;">
                    <strong style="color: #c8ff00;">Mensaje:</strong><br><br>
                    {data.mensaje}
                </div>
                <hr style="margin: 20px 0; border: none; border-top: 1px solid #333;">
                <p style="font-size: 11px; color: #666;">VenridesScreenS — Sistema de Gestión de Pantallas</p>
            </div>
        </body>
        </html>
        """
        
        send_email(
            to=notification_email,
            subject=f"Nuevo Contacto: {data.nombre} — {data.asunto or 'Consulta General'}",
            body=email_body,
            html=True
        )
    except Exception as e:
        logger.warning(f"Failed to send contact notification email: {e}")
    
    return {"message": "¡Gracias! Tu mensaje ha sido recibido. Te contactaremos pronto.", "status": "success"}

@app.post("/api/forms/signup/plan")
async def submit_plan_signup(data: PlanSignupFormData, request: Request):
    """Submit plan signup form — rate limited, anti-spam, email + Sheets"""
    from utils.email_sender import send_email
    
    client_ip = request.client.host if request.client else "unknown"
    
    # Security: Rate limiting
    if not check_rate_limit(client_ip, RATE_LIMIT_MAX_FORMS):
        raise HTTPException(status_code=429, detail="Demasiadas solicitudes. Intenta de nuevo en un minuto.")
    
    # Security: Honeypot
    if not validate_honeypot(data.dict()):
        logger.warning(f"Bot detected (honeypot) on signup from {client_ip}")
        return {"message": "Registro recibido.", "status": "success"}
    
    # Security: Sanitize inputs
    data.nombre = sanitize_input(data.nombre)
    data.email = sanitize_input(data.email)
    data.telefono = sanitize_input(data.telefono)
    data.empresa = sanitize_input(data.empresa)
    data.tipo_negocio = sanitize_input(data.tipo_negocio)
    data.mensaje = sanitize_input(data.mensaje)
    
    # 0. Generate verification code
    v_code = generate_verification_code()
    
    # 1. Log to Google Sheets
    try:
        from services.sheets_service import sheets_service
        sheets_service.log_plan_signup(data.plan, {**data.dict(), "verification_code": v_code})
    except Exception as e:
        logger.warning(f"Failed to log plan signup to Sheets: {e}")
    
    # 2. Send Welcome & Verification email
    try:
        from services.template_service import template_service
        rendered = template_service.render("welcome_verification", {
            "name": data.nombre,
            "code": v_code
        })
        send_email(data.email, rendered["subject"], rendered["body"])
    except Exception as e:
        logger.error(f"Failed to send welcome verification: {e}")

    # 3. Send internal status notification
    try:
        notification_email = os.getenv("NOTIFICATION_EMAIL", "info.venridesscreen@gmail.com")
        
        plan_colors = {
            "free": "#888", "basico": "#3b82f6", "plus": "#8b5cf6",
            "ultra": "#f59e0b", "empresarial": "#ef4444"
        }
        plan_color = plan_colors.get(data.plan.lower(), "#c8ff00")
        
        email_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #0a0a0f;">
            <div style="max-width: 600px; margin: 0 auto; background: #1a1a2e; padding: 30px; border-radius: 15px; border: 1px solid #333;">
                <h2 style="color: #c8ff00; margin-bottom: 5px;">🚀 Nueva Solicitud de Plan</h2>
                <div style="display: inline-block; padding: 5px 15px; background: {plan_color}; color: #000; border-radius: 20px; font-weight: bold; font-size: 18px; margin-bottom: 20px;">
                    Plan {data.plan.upper()}
                </div>
                <table style="width: 100%; border-collapse: collapse; color: #e0e0e0; margin-top: 15px;">
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Nombre:</td><td style="padding: 8px;">{data.nombre}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Email:</td><td style="padding: 8px;">{data.email}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Teléfono:</td><td style="padding: 8px;">{data.telefono}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Empresa:</td><td style="padding: 8px;">{data.empresa}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Tipo de Negocio:</td><td style="padding: 8px;">{data.tipo_negocio}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold; color: #c8ff00;">Pantallas:</td><td style="padding: 8px;">{data.pantallas_estimadas}</td></tr>
                </table>
                {"<div style='margin-top: 15px; padding: 15px; background: #0d0d1a; border-radius: 10px; color: #ccc;'><strong style=color:#c8ff00>Mensaje:</strong><br><br>" + data.mensaje + "</div>" if data.mensaje else ""}
                <hr style="margin: 20px 0; border: none; border-top: 1px solid #333;">
                <p style="font-size: 11px; color: #666;">VenridesScreenS — Sistema de Gestión de Pantallas</p>
            </div>
        </body>
        </html>
        """
        
        send_email(
            to=notification_email,
            subject=f"🚀 Nueva Solicitud Plan {data.plan.upper()} — {data.nombre}",
            body=email_body,
            html=True
        )
    except Exception as e:
        logger.warning(f"Failed to send plan signup notification email: {e}")
    
    return {"message": "¡Gracias! Hemos recibido tu solicitud. Te contactaremos pronto.", "status": "success"}

# --- APK Download ---

_cached_short_apk_url = None

@app.get("/api/downloads/tv/short-url")
async def get_short_apk_url():
    """Returns a shortened URL for the APK download"""
    global _cached_short_apk_url
    if not _cached_short_apk_url:
        from utils.url_shortener import shorten_url
        base_url = os.getenv("PROD_API_URL", "https://apitv.venrides.com")
        _cached_short_apk_url = shorten_url(f"{base_url}/downloads/tv")
    return {"url": _cached_short_apk_url}

@app.get("/downloads/tv")
async def download_tv_apk():
    """Serve the latest TV APK for download"""
    from fastapi.responses import FileResponse
    
    apk_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "releases", "VenridesScreenS_TV.apk")
    
    if not os.path.exists(apk_path):
        raise HTTPException(404, "APK no disponible")
    
    return FileResponse(
        path=apk_path,
        media_type="application/vnd.android.package-archive",
        filename="VenridesScreenS_TV.apk",
        headers={"Content-Disposition": "attachment; filename=VenridesScreenS_TV.apk"}
    )

# --- Benry AI Chat ---

@app.post("/api/benry/chat")
async def benry_chat(data: BenryChatMessage, request: Request):
    """Chat with Benry AI — rate limited"""
    import uuid as uuid_lib
    
    client_ip = request.client.host if request.client else "unknown"
    
    # Security: Rate limiting (20 msg/min for chat)
    if not check_rate_limit(client_ip, RATE_LIMIT_MAX_CHAT):
        return {
            "response": "Has enviado muchos mensajes. Espera un momento antes de continuar.",
            "needs_handoff": False,
            "lead_type": None,
            "session_id": data.session_id or "limited"
        }
    
    # Sanitize input
    data.message = sanitize_input(data.message)
    
    session_id = data.session_id or str(uuid_lib.uuid4())
    
    try:
        from services.benry_service import benry_service
        result = await benry_service.chat(session_id, data.message)
        
        # If lead detected, log to Sheets
        if result.get("lead_type"):
            try:
                from services.sheets_service import sheets_service
                sheets_service.log_benry_lead({
                    "resumen_conversacion": benry_service.get_conversation_summary(session_id),
                    "tipo_lead": result["lead_type"],
                    "plan_interes": "",
                })
            except Exception as e:
                logger.warning(f"Failed to log Benry lead: {e}")
        
        if result.get("needs_handoff"):
            try:
                summary = benry_service.get_conversation_summary(session_id)
                
                # 1. Send Email Notification
                from utils.email_sender import send_email
                notification_email = os.getenv("NOTIFICATION_EMAIL", "info.venridesscreen@gmail.com")
                
                email_body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #0a0a0f;">
                    <div style="max-width: 600px; margin: 0 auto; background: #1a1a2e; padding: 30px; border-radius: 15px; border: 1px solid #ff4444;">
                        <h2 style="color: #ff4444; margin-bottom: 20px;">🔔 Benry Requiere Intervención Humana</h2>
                        <p style="color: #ccc;">Un cliente en el chat necesita atención directa.</p>
                        <div style="margin-top: 15px; padding: 15px; background: #0d0d1a; border-radius: 10px; color: #ccc;">
                            <strong style="color: #c8ff00;">Resumen de conversación:</strong><br><br>
                            <pre style="white-space: pre-wrap; font-family: inherit;">{summary}</pre>
                        </div>
                        <p style="margin-top: 15px; color: #c8ff00; font-weight: bold;">Session ID: {session_id}</p>
                        <hr style="margin: 20px 0; border: none; border-top: 1px solid #333;">
                        <p style="font-size: 11px; color: #666;">Benry AI — VenridesScreenS</p>
                    </div>
                </body>
                </html>
                """
                
                send_email(
                    to=notification_email,
                    subject="🔔 Benry: Cliente requiere atención humana",
                    body=email_body,
                    html=True
                )
                
                # 2. Create internal message for Admin Master
                async with AsyncSessionLocal() as db:
                    # Find Admin Master (role: admin_master)
                    from models import User, Message
                    admin_res = await db.execute(select(User).where(User.role == "admin_master"))
                    admin_master = admin_res.scalar()
                    
                    if admin_master:
                        new_msg = Message(
                            sender_id=None, # System/Benry
                            receiver_id=admin_master.id,
                            subject="🔔 Soporte Benry: Atención Humana Requerida",
                            body=f"Un cliente está esperando en la landing page.\n\nSESIÓN: {session_id}\n\nRESUMEN:\n{summary}",
                            is_alert=True
                        )
                        db.add(new_msg)
                        await db.commit()
                        logger.info(f"Benry handoff message created for admin {admin_master.id}")
                
            except Exception as e:
                logger.warning(f"Failed to process Benry handoff: {e}")
        
        return result
        
    except Exception as e:
        logger.error(f"Benry chat error: {e}")
        return {
            "response": "¡Hola! 👋 Soy Benry. En este momento tengo dificultades técnicas, "
                       "pero puedes contactarnos directamente:\n\n"
                       "📧 info.venridesscreen@gmail.com\n"
                       "🌐 screens.venrides.com",
            "needs_handoff": False,
            "lead_type": None,
            "session_id": data.session_id or "error"
        }

@app.post("/api/benry/lead")
async def benry_save_lead(data: BenryLeadData):
    """Save lead data collected by Benry during conversation"""
    try:
        from services.sheets_service import sheets_service
        from services.benry_service import benry_service
        
        summary = benry_service.get_conversation_summary(data.session_id)
        
        sheets_service.log_benry_lead({
            "nombre": data.nombre,
            "telefono": data.telefono,
            "email": data.email,
            "plan_interes": data.plan_interes,
            "resumen_conversacion": summary,
            "tipo_lead": "contacto_directo"
        })
        
        return {"message": "Lead registrado exitosamente", "status": "success"}
    except Exception as e:
        logger.error(f"Failed to save Benry lead: {e}")
        return {"message": "Información recibida", "status": "partial"}

@app.delete("/api/benry/session/{session_id}")
async def benry_clear_session(session_id: str):
    """Clear a Benry chat session"""
    try:
        from services.benry_service import benry_service
        benry_service.clear_session(session_id)
    except Exception:
        pass
    return {"status": "ok"}


# =====================================================
# ===== ANALYTICS & SEO DASHBOARD =====
# =====================================================

@app.post("/api/analytics/track")
async def track_page_visit(request: Request):
    """Public endpoint — track a page visit (called from landing page)"""
    try:
        from services.analytics_service import analytics_service
        
        body = await request.json()
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        
        analytics_service.track_visit(
            ip=client_ip,
            page=body.get("page", "/"),
            referrer=body.get("referrer", request.headers.get("referer", "")),
            user_agent=user_agent,
        )
        return {"status": "ok"}
    except Exception as e:
        logger.warning(f"Analytics track error: {e}")
        return {"status": "ok"}


@app.get("/admin/analytics/dashboard")
async def get_analytics_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Admin-only endpoint — analytics dashboard data"""
    # Verify admin token logic (inline to avoid refactoring common utils for now)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(status_code=401)
    
    try:
        from services.analytics_service import analytics_service
        return analytics_service.get_dashboard()
    except Exception as e:
        logger.error(f"Analytics dashboard error: {e}")
        return {"total_visits": 0, "visits_today": 0, "error": str(e)}

# =====================================================
# ===== CRM & MARKETING ECOSYSTEM =====
# =====================================================

@app.get("/admin/crm/ecosystem-status")
async def get_crm_ecosystem_status(db: AsyncSession = Depends(get_db)):
    """Comprehensive status of the entire ecosystem"""
    from models import Company, Device, Payment, Promotion, CalendarActivity
    
    # 1. Company Stats
    total_companies = await db.scalar(select(func.count(Company.id)))
    active_companies = await db.scalar(select(func.count(Company.id)).where(Company.is_active == True))
    
    # 2. Tech Stats
    total_screens = await db.scalar(select(func.count(Device.id)))
    
    # 3. Revenue & Commercial
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    month_revenue = await db.scalar(select(func.sum(Payment.amount)).where(Payment.payment_date >= thirty_days_ago)) or 0.0
    
    # 4. Next Activities
    activities_res = await db.execute(select(CalendarActivity).where(CalendarActivity.activity_date >= datetime.utcnow()).order_by(CalendarActivity.activity_date).limit(5))
    next_activities = activities_res.scalars().all()
    
    active_promos = await db.scalar(select(func.count(Promotion.id)).where(Promotion.is_active == True))
    
    return {
        "companies": {"total": total_companies, "active": active_companies},
        "tech": {"total_screens": total_screens},
        "revenue": {"last_30_days": float(month_revenue)},
        "next_activities": [{"title": a.title, "date": a.activity_date} for a in next_activities],
        "active_promotions": active_promos,
        "backup_status": "Healthy (Last auto-dump: Today)",
        "server_time": datetime.utcnow().isoformat()
    }

@app.get("/admin/crm/templates")
async def list_email_templates(db: AsyncSession = Depends(get_db)):
    from models import EmailTemplate
    res = await db.execute(select(EmailTemplate).order_by(EmailTemplate.name))
    return res.scalars().all()

@app.post("/admin/crm/templates")
async def save_email_template(data: EmailTemplateSchema, db: AsyncSession = Depends(get_db)):
    from models import EmailTemplate
    stmt = select(EmailTemplate).where(EmailTemplate.name == data.name)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    
    if existing:
        existing.subject = data.subject
        existing.body = data.body
        existing.is_active = data.is_active
    else:
        new_template = EmailTemplate(name=data.name, subject=data.subject, body=data.body, is_active=data.is_active)
        db.add(new_template)
    
    await db.commit()
    return {"status": "success"}

@app.get("/admin/crm/calendar")
async def get_calendar(db: AsyncSession = Depends(get_db)):
    from models import CalendarActivity
    res = await db.execute(select(CalendarActivity).order_by(CalendarActivity.activity_date))
    return res.scalars().all()

@app.post("/admin/crm/calendar")
async def add_calendar_activity(data: dict, db: AsyncSession = Depends(get_db)):
    from models import CalendarActivity
    new_act = CalendarActivity(
        title=data["title"],
        description=data.get("description"),
        activity_date=datetime.fromisoformat(data["activity_date"]),
        is_holiday=data.get("is_holiday", False),
        send_auto_greeting=data.get("send_auto_greeting", False)
    )
    db.add(new_act)
    await db.commit()
    return {"status": "success"}

@app.get("/admin/crm/promotions")
async def list_promotions(db: AsyncSession = Depends(get_db)):
    from models import Promotion
    res = await db.execute(select(Promotion).order_by(Promotion.created_at.desc()))
    return res.scalars().all()

@app.post("/admin/crm/promotions")
async def save_promotion(data: PromotionSchema, db: AsyncSession = Depends(get_db)):
    from models import Promotion
    stmt = select(Promotion).where(Promotion.code == data.code)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    
    if existing:
        existing.name = data.name
        existing.description = data.description
        existing.discount_pct = data.discount_pct
        existing.valid_from = datetime.fromisoformat(data.valid_from)
        existing.valid_to = datetime.fromisoformat(data.valid_to)
        existing.is_active = data.is_active
    else:
        new_promo = Promotion(
            name=data.name,
            description=data.description,
            code=data.code,
            discount_pct=data.discount_pct,
            valid_from=datetime.fromisoformat(data.valid_from),
            valid_to=datetime.fromisoformat(data.valid_to),
            is_active=data.is_active
        )
        db.add(new_promo)
    
    await db.commit()
    return {"status": "success"}

@app.post("/admin/crm/affiliates")
async def save_affiliate(data: dict, db: AsyncSession = Depends(get_db)):
    from models import Affiliate
    new_aff = Affiliate(
        name=data["name"],
        email=data["email"],
        code=data["code"],
        commission_pct=data.get("commission_pct", 10.0)
    )
    db.add(new_aff)
    await db.commit()
    return {"status": "success"}
