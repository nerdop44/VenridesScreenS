import os
import shutil
import random
import string
from typing import List, Optional
from datetime import datetime, timedelta
from utils.email_sender import send_password_recovery_email

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, delete, desc
from sqlalchemy.orm import selectinload
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import time
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Literal
import logging
from logging.handlers import RotatingFileHandler

# --- LOGGING CONFIGURATION ---
LOG_FILE = "venridesscreens.log"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VenrideScreenS")

# File Handler
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

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
    video_url: Optional[str] = None
    ticker_text: Optional[str] = None

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

# --- Existing Pydantic Models ---
from models import Base, Company, User, Device, Payment, Menu, RegistrationCode, GlobalAd, Message
from utils.branding import extract_colors
from utils.auth import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM
from utils.bcv import get_bcv_usd_rate
from db_config import get_db, init_db, AsyncSessionLocal

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

# --- Simple Rate Limiting for Auth ---
login_attempts = {} # {ip: [timestamps]}
def check_rate_limit(ip: str):
    now = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = []
    # Keep only last minute
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 60]
    if len(login_attempts[ip]) >= 5: # 5 attempts per minute
        return False
    login_attempts[ip].append(now)
    return True

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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Diagnostics ---
# --- Diagnostics ---
@app.get("/diag/status")
async def diag_status(repair: bool = False, db: AsyncSession = Depends(get_db)):
    try:
        if repair:
            from models import Company, User
            from utils.auth import get_password_hash
            
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

app.middleware("http")(logging_middleware)

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
# --- Permissions Helper for Operador Master ---
def check_permission(user: User, resource: str, action: str):
    if user.is_admin or user.role == "admin_master":
        return True
    if user.role != "operador_master":
        return False
    # permissions = {"users": {"create": True, "view": True}, "companies": {...}}
    perms = user.permissions or {}
    return perms.get(resource, {}).get(action, False)

async def master_access_only(user: User = Depends(get_current_user)):
    if user.role not in ["admin_master", "operador_master"]:
        raise HTTPException(403, "Acceso solo para nivel Maestro")
    return user

# --- BCV Cache ---
bcv_cache = {"rate": None, "last_updated": None}

@app.get("/finance/bcv")
def get_bcv_rate_endpoint():
    # Helper synchronous wrapper or async transformation
    # Since scraping is sync (requests), we can run it directly or in threadpool.
    # For simplicity, running sync is fine for low traffic, but better in thread.
    now = datetime.now()
    if not bcv_cache["rate"] or not bcv_cache["last_updated"] or (now - bcv_cache["last_updated"]).total_seconds() > 3600:
        try:
            rate = get_bcv_usd_rate()
            if rate:
                bcv_cache["rate"] = rate
                bcv_cache["last_updated"] = now
        except Exception:
            pass
            
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
    contact_person: Optional[str] = None
    email: Optional[str] = None
    client_editable_fields: Optional[str] = ""
    
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
    max_screens: Optional[int] = None

    # Header Extension
    sidebar_header_type: Optional[Literal["text", "banner"]] = None
    sidebar_header_value: Optional[str] = None


    priority_content_url: Optional[str] = None
    ad_frequency: Optional[int] = None
    sidebar_content: Optional[List[SidebarGroup]] = None
    bottom_bar_content: Optional[BottomBarContent] = None
    design_settings: Optional[DesignSettings] = None

class UserCreate(BaseModel):
    username: str # email
    password: str
    role: Literal["operador_master", "admin_empresa", "operador_empresa"]
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

@app.post("/auth/login")
async def login(request: Request, login_data: LoginRequest, db: AsyncSession = Depends(get_db)):
    # Bot Protection
    client_ip = request.client.host
    if not check_rate_limit(client_ip):
        raise HTTPException(429, "Demasiados intentos. Intente de nuevo en un minuto.")

    # Search by email (username column)
    result = await db.execute(select(User).where(User.username == login_data.username))
    user = result.scalar_one_or_none()
    
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
        # Fake delay to prevent timing attacks
        time.sleep(random.uniform(0.1, 0.5))
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
        "active_screens": len([d for d in c.devices if d.is_active])
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

@app.patch("/admin/users/{user_id}/status")
async def toggle_user_status(user_id: int, status: bool, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(["admin_master"]))):
    # For now, we don't have is_active on User, so we might skip or Implement later. 
    # User request asked for Suspend/Active, so let's stick to deleting for now or just acknowledge command.
    # Actually, let's implement Delete since that was requested.
     pass

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
async def toggle_device_status(device_uuid: str, is_active: bool, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(["admin_master"]))):
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

@app.get("/companies/{company_id}")
async def get_company(company_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Master or own company
    if current_user.role not in ["admin_master", "operador_master"] and current_user.company_id != company_id:
        raise HTTPException(403, "No tiene acceso a los datos de esta empresa")

    if current_user.role == "operador_master" and not check_permission(current_user, "companies", "view"):
        raise HTTPException(403, "No tiene permiso para ver detalles de empresa")

    res = await db.execute(select(Company).where(Company.id == company_id))
    company = res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")
    return company

@app.patch("/companies/{company_id}")
async def update_company(company_id: int, update: CompanyUpdate, request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    res = await db.execute(select(Company).where(Company.id == company_id))
    company = res.scalar_one_or_none()
    if not company:
        raise HTTPException(404, "Empresa no encontrada")
    
    
    data_dict = update.dict(exclude_unset=True)
    
    # Check perfil Restricted Logic
    if current_user.role not in ["admin_master", "operador_master"]:
        # Client trying to update
        if not company.can_edit_profile:
             raise HTTPException(403, "Edición de perfil deshabilitada. Contacte al administrador.")
        
        # If editing branding/profile fields, mark as edited
        profile_fields = {'name', 'rif', 'address', 'phone', 'contact_person', 'email'}
        if any(f in data_dict for f in profile_fields):
            company.can_edit_profile = False
            company.has_edited_profile = True

    for key, val in data_dict.items():
        if key == 'design_settings' and val is not None:
            # Merge design_settings instead of replacing
            current_settings = company.design_settings or {}
            if isinstance(current_settings, dict):
                current_settings.update(val)
                company.design_settings = dict(current_settings)  # Force SQLAlchemy to detect change
            else:
                company.design_settings = val
        else:
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
        
    # Extract colors
    colors = extract_colors(file_path)
    
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
    while (await db.execute(select(RegistrationCode).where(RegistrationCode.code == code))).scalar_one_or_none():
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
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
        
    # Link Device
    dev_res = await db.execute(select(Device).where(Device.uuid == device_uuid))
    device = dev_res.scalar_one_or_none()
    
    if device:
        device.company_id = company_id
        device.name = f"TV-{device_uuid[:8]}"
    else:
        device = Device(uuid=device_uuid, company_id=company_id, name=f"TV-{device_uuid[:8]}")
        db.add(device)
        
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
    new_payment = Payment(**payment.dict())
    db.add(new_payment)
    await db.commit()
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
    rate = 0
    try:
        from utils.bcv import get_bcv_usd_rate
        rate = get_bcv_usd_rate()
    except:
        pass

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
        "menus": [ {"name": i.name, "price": i.price, "category": i.category} for i in company.menus ]
    }
    
    # -- Overrides for FREE plan --
    if company.plan == 'free':
        # Get latest Global Ad
        gad_res = await db.execute(select(GlobalAd).order_by(GlobalAd.updated_at.desc()).limit(1))
        gad = gad_res.scalar_one_or_none()
        if gad:
            # FREE users don't control bottom bar or priority videos
            if gad.video_url:
                config["priority_content_url"] = gad.video_url
            if gad.ticker_text:
                config["bottom_bar_content"] = {
                    "static": gad.ticker_text,
                    "font_size": "1.5rem",
                    "color": "#fbbf24",
                    "weight": "bold"
                }
        else:
            # Fallback if no global ad
            config["bottom_bar_content"] = {"static": "Venrides Pantallas Inteligentes"}

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

    # Get BCV Rate
    rate = 0
    try:
        from utils.bcv import get_bcv_usd_rate
        rate = get_bcv_usd_rate()
    except:
        pass

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
        gad_res = await db.execute(select(GlobalAd).order_by(GlobalAd.updated_at.desc()).limit(1))
        gad = gad_res.scalar_one_or_none()
        if gad:
            if gad.video_url:
                config["priority_content_url"] = gad.video_url
            if gad.ticker_text:
                config["bottom_bar_content"] = {
                    "static": gad.ticker_text,
                    "font_size": "1.5rem",
                    "color": "#fbbf24",
                    "weight": "bold"
                }

    return config

@app.get("/admin/global-ad")
async def get_global_ad(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(GlobalAd).order_by(GlobalAd.updated_at.desc()).limit(1))
    return res.scalar_one_or_none() or {"video_url": "", "ticker_text": ""}

@app.post("/admin/global-ad")
async def update_global_ad(ad: GlobalAdSchema, db: AsyncSession = Depends(get_db)):
    # Check if exists
    res = await db.execute(select(GlobalAd).order_by(GlobalAd.updated_at.desc()).limit(1))
    gad = res.scalar_one_or_none()
    if gad:
        gad.video_url = ad.video_url
        gad.ticker_text = ad.ticker_text
    else:
        gad = GlobalAd(video_url=ad.video_url, ticker_text=ad.ticker_text)
        db.add(gad)
    await db.commit()
    return gad



# --- Admin Management Endpoints ---

@app.get("/admin/users/")
async def list_users(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Listar usuarios con filtros de rol"""
    query = select(User)
    
    if current_user.role in ["admin_master", "operador_master"]:
        if current_user.role == "operador_master" and not check_permission(current_user, "users", "view"):
             raise HTTPException(403, "No tiene permiso para ver usuarios")
        # Master roles see all
        pass
    elif current_user.role == "admin_empresa":
        # Empresa admin only sees users of their company
        query = query.where(User.company_id == current_user.company_id)
    else:
        raise HTTPException(403, "No tiene permiso")

    result = await db.execute(query)
    users = result.scalars().all()
    # Map for response
    return [{"id": u.id, "username": u.username, "role": u.role, "company_id": u.company_id, "permissions": u.permissions} for u in users]

@app.post("/admin/users/")
async def create_user(data: UserCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Crear usuarios con validación de jerarquía"""
    
    # 1. Hierarchical Check
    if current_user.role == "admin_master":
        # Can create any role
        pass
    elif current_user.role == "operador_master":
        if not check_permission(current_user, "users", "create"):
            raise HTTPException(403, "No tiene permiso para crear usuarios")
        if data.role in ["admin_master", "operador_master"]:
            raise HTTPException(403, "Un operador no puede crear roles Maestros")
    else:
        raise HTTPException(403, "No tiene permiso para crear usuarios manualmente")

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
    elif current_user.role == "operador_master":
        if check_permission(current_user, "users", "edit"):
             if target_user.role not in ["admin_master", "operador_master"] or target_user.id == current_user.id:
                 can_edit = True
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

@app.delete("/admin/users/{id}")
async def delete_user(id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Eliminar usuario (Nivel Maestro únicamente)"""
    if current_user.role not in ["admin_master", "operador_master"]:
        raise HTTPException(403, "Solo roles Maestros pueden eliminar usuarios")
    
    if current_user.role == "operador_master" and not check_permission(current_user, "users", "delete"):
        raise HTTPException(403, "No tiene permiso de eliminación")

    result = await db.execute(select(User).where(User.id == id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    
    if user.role == "admin_master":
        raise HTTPException(403, "No se puede eliminar al Administrador Maestro")

    await db.delete(user)
    await db.commit()
    return {"message": "Usuario eliminado correctamente"}

@app.patch("/admin/devices/{uuid}")
async def update_device_name(uuid: str, name: str, db: AsyncSession = Depends(get_db)):
    """Actualizar nombre de un dispositivo"""
    result = await db.execute(select(Device).where(Device.uuid == uuid))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, "Dispositivo no encontrado")
    device.name = name
    await db.commit()
    return {"message": "Dispositivo actualizado correctamente"}

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
    """Get all chat conversations for current user"""
    # Get messages where user is sender or receiver (excluding alerts)
    query = select(Message).where(
        and_(
            Message.is_alert == False,
            or_(
                Message.sender_id == current_user.id,
                Message.receiver_id == current_user.id
            )
        )
    ).order_by(Message.created_at.desc())
    
    result = await db.execute(query)
    messages = result.scalars().all()
    
    # Group by conversation partner
    conversations = {}
    for msg in messages:
        partner_id = msg.receiver_id if msg.sender_id == current_user.id else msg.sender_id
        if partner_id not in conversations:
            conversations[partner_id] = {
                'partner_id': partner_id,
                'messages': [],
                'unread_count': 0,
                'last_message_at': msg.created_at
            }
        conversations[partner_id]['messages'].append(msg)
        if msg.receiver_id == current_user.id and not msg.is_read:
            conversations[partner_id]['unread_count'] += 1
    
    # Get partner details
    result_list = []
    for partner_id, conv in conversations.items():
        partner_result = await db.execute(select(User).where(User.id == partner_id))
        partner = partner_result.scalar_one_or_none()
        if partner:
            result_list.append({
                'partner': {
                    'id': partner.id,
                    'username': partner.username,
                    'role': partner.role
                },
                'last_message': conv['messages'][0].body[:100],
                'last_message_at': conv['last_message_at'].isoformat(),
                'unread_count': conv['unread_count']
            })
    
    return result_list

@app.get("/admin/chat/messages/{partner_id}")
async def get_chat_messages(
    partner_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all messages with a specific user"""
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
    
    # Mark received messages as read
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    await db.commit()
    
    return [{
        'id': msg.id,
        'sender_id': msg.sender_id,
        'receiver_id': msg.receiver_id,
        'subject': msg.subject,
        'body': msg.body,
        'created_at': msg.created_at.isoformat(),
        'is_read': msg.is_read
    } for msg in messages]

@app.post("/admin/chat/send")
async def send_chat_message(
    receiver_id: int,
    body: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Send a chat message to another user"""
    # Verify receiver exists
    receiver_result = await db.execute(select(User).where(User.id == receiver_id))
    receiver = receiver_result.scalar_one_or_none()
    if not receiver:
        raise HTTPException(404, "Usuario destinatario no encontrado")
    
    # Check Block Status
    from models import BlockedUser
    block_check = await db.execute(select(BlockedUser).where(
        or_(
            and_(BlockedUser.blocker_id == receiver_id, BlockedUser.blocked_id == current_user.id), # Receiver blocked sender
            and_(BlockedUser.blocker_id == current_user.id, BlockedUser.blocked_id == receiver_id)  # Sender blocked receiver
        )
    ))
    if block_check.scalar_one_or_none():
        raise HTTPException(403, "No puedes enviar mensajes a este usuario (Bloqueo activo)")

    # Create message
    new_msg = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        subject="Chat Interno",
        body=body,
        is_alert=False,
        is_read=False
    )
    db.add(new_msg)
    await db.commit()
    await db.refresh(new_msg)
    
    return {
        'id': new_msg.id,
        'sender_id': new_msg.sender_id,
        'receiver_id': new_msg.receiver_id,
        'body': new_msg.body,
        'created_at': new_msg.created_at.isoformat()
    }

@app.post("/admin/chat/block")
async def block_user(blocked_id: int, reason: str = None, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    from models import BlockedUser
    # Prevent self-block
    if blocked_id == current_user.id:
        raise HTTPException(400, "No te puedes bloquear a ti mismo")
        
    # Check if already blocked
    existing = await db.execute(select(BlockedUser).where(
        and_(BlockedUser.blocker_id == current_user.id, BlockedUser.blocked_id == blocked_id)
    ))
    if existing.scalar_one_or_none():
        return {"message": "Usuario ya está bloqueado"}
        
    block = BlockedUser(blocker_id=current_user.id, blocked_id=blocked_id, reason=reason)
    db.add(block)
    await db.commit()
    return {"message": "Usuario bloqueado"}

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

@app.get("/admin/chat/unread-count")
async def get_unread_chat_count(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get count of unread chat messages"""
    query = select(func.count(Message.id)).where(
        and_(
            Message.receiver_id == current_user.id,
            Message.is_read == False,
            Message.is_alert == False
        )
    )
    result = await db.execute(query)
    count = result.scalar()
    return {'unread_count': count}


@app.post("/companies/{company_id}/message")
async def send_live_alert(
    company_id: int,
    msg: LiveMessageSchema,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Authorization: Master or Company Admin of same company
    if current_user.role not in ["admin_master", "operador_master"]:
        if current_user.role == "admin_empresa" and current_user.company_id != company_id:
            raise HTTPException(403, "No tiene permiso para enviar mensajes a esta empresa")
        elif current_user.role not in ["admin_master", "operador_master", "admin_empresa"]:
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
    if current_user.role not in ["admin_master", "operador_master"]:
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
    if current_user.role not in ["admin_master", "operador_master"] and ticket.user_id != current_user.id:
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
            "is_staff": m.sender and m.sender.role in ["admin_master", "operador_master"]
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
    if current_user.role not in ["admin_master", "operador_master"] and ticket.user_id != current_user.id:
        raise HTTPException(403, "No tiene permiso para responder a este ticket")
        
    new_msg = TicketMessage(
        ticket_id=ticket.id,
        sender_id=current_user.id,
        body=reply.body
    )
    db.add(new_msg)
    
    # Update Ticket Timestamp & Status logic
    ticket.updated_at = datetime.utcnow()
    if current_user.role in ["admin_master", "operador_master"]:
        if ticket.status == "open":
            ticket.status = "in_progress"
    else:
        # If user replies, maybe reopen if closed? For now just keep or set to in_progress
        pass
        
    await db.commit()
    return {"message": "Respuesta enviada"}

@app.patch("/admin/helpdesk/tickets/{id}/status")
async def update_ticket_status(id: int, status: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(["admin_master", "operador_master"]))):
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
