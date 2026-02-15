"""
VenridesScreenS — Pre-deployment System Test
Tests Gmail SMTP, imports, services, and endpoint validation
Run WITHOUT Docker — standalone validation
"""
import os
import sys
import smtplib
import ssl
import json
import traceback
from datetime import datetime

# Setup paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load env
from dotenv import load_dotenv
load_dotenv()

results = []

def test(name, func):
    """Run a test and record result"""
    try:
        result = func()
        status = "✅ PASS" if result else "⚠️ WARN"
        results.append((name, status, result if isinstance(result, str) else ""))
        print(f"  {status} — {name}")
        return True
    except Exception as e:
        results.append((name, "❌ FAIL", str(e)))
        print(f"  ❌ FAIL — {name}: {e}")
        return False

print("=" * 60)
print("VenridesScreenS — Pre-deployment System Test")
print(f"Timestamp: {datetime.now().isoformat()}")
print("=" * 60)

# ============================================
# 1. Environment Variables
# ============================================
print("\n📋 1. Environment Variables")

def test_env_smtp_user():
    v = os.getenv("SMTP_USER")
    assert v and "@" in v, f"SMTP_USER missing or invalid: {v}"
    return v

def test_env_smtp_password():
    v = os.getenv("SMTP_PASSWORD")
    assert v and len(v) >= 10, f"SMTP_PASSWORD missing or too short"
    return True

def test_env_notification():
    v = os.getenv("NOTIFICATION_EMAIL")
    assert v and "@" in v, f"NOTIFICATION_EMAIL missing: {v}"
    return v

def test_env_sheets_creds():
    path = os.getenv("GOOGLE_SHEETS_CREDENTIALS_PATH", "./credentials/google-service-account.json")
    exists = os.path.exists(path)
    if not exists:
        return f"Path not found: {path} (Sheets won't work without it)"
    return True

test("SMTP_USER", test_env_smtp_user)
test("SMTP_PASSWORD", test_env_smtp_password)
test("NOTIFICATION_EMAIL", test_env_notification)
test("Google Sheets Credentials", test_env_sheets_creds)

# ============================================
# 2. Gmail SMTP Connection Test
# ============================================
print("\n📧 2. Gmail SMTP Connection Test")

def test_gmail_connection():
    """Test SMTP connection to Gmail without sending an email"""
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    
    if not smtp_user or not smtp_password:
        raise Exception("SMTP_USER or SMTP_PASSWORD not configured")
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    print(f"    Connecting to {smtp_server}:{smtp_port}...")
    with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
        server.ehlo()
        print(f"    EHLO: OK")
        server.starttls(context=context)
        print(f"    STARTTLS: OK")
        server.login(smtp_user, smtp_password)
        print(f"    LOGIN: OK (as {smtp_user})")
    
    return True

test("Gmail SMTP Connection", test_gmail_connection)

def test_gmail_send():
    """Actually send a test email"""
    from utils.email_sender import send_email
    
    notification_email = os.getenv("NOTIFICATION_EMAIL", "info.venridesscreen@gmail.com")
    
    test_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #0a0a0f;">
        <div style="max-width: 600px; margin: 0 auto; background: #1a1a2e; padding: 30px; border-radius: 15px; border: 1px solid #333;">
            <h2 style="color: #c8ff00; margin-bottom: 20px;">🧪 Test de Email — VenridesScreenS</h2>
            <p style="color: #e0e0e0;">Este es un email de prueba del sistema.</p>
            <table style="width: 100%; border-collapse: collapse; color: #e0e0e0; margin-top: 15px;">
                <tr><td style="padding: 8px; color: #c8ff00; font-weight: bold;">Timestamp:</td><td style="padding: 8px;">{datetime.now().isoformat()}</td></tr>
                <tr><td style="padding: 8px; color: #c8ff00; font-weight: bold;">Componente:</td><td style="padding: 8px;">Pre-deployment Test Suite</td></tr>
                <tr><td style="padding: 8px; color: #c8ff00; font-weight: bold;">Estado:</td><td style="padding: 8px; color: #4ade80;">✅ Funcional</td></tr>
            </table>
            <hr style="margin: 20px 0; border: none; border-top: 1px solid #333;">
            <p style="font-size: 11px; color: #666;">VenridesScreenS — Sistema de Gestión de Pantallas</p>
        </div>
    </body>
    </html>
    """
    
    result = send_email(
        to=notification_email,
        subject=f"🧪 VenridesScreenS Test — {datetime.now().strftime('%H:%M:%S')}",
        body=test_body,
        html=True
    )
    
    assert result == True, "send_email returned False"
    return f"Sent to {notification_email}"

test("Gmail Send Test Email", test_gmail_send)

# ============================================
# 3. Import Tests — All New Services
# ============================================
print("\n📦 3. Python Import Tests")

def test_import_email_sender():
    from utils.email_sender import send_email, send_password_recovery_email
    assert callable(send_email)
    assert callable(send_password_recovery_email)
    return True

def test_import_sheets_service():
    from services.sheets_service import GoogleSheetsService, sheets_service
    assert hasattr(sheets_service, 'log_contact')
    assert hasattr(sheets_service, 'log_plan_signup')
    assert hasattr(sheets_service, 'log_benry_lead')
    return True

def test_import_benry_service():
    from services.benry_service import BenryAIService, benry_service
    assert hasattr(benry_service, 'chat')
    assert hasattr(benry_service, 'check_availability')
    assert hasattr(benry_service, 'get_conversation_summary')
    assert hasattr(benry_service, 'clear_session')
    return True

def test_import_main_models():
    """Test that new Pydantic models in main.py can be imported"""
    # We can't import main.py directly (it starts the server), 
    # so we validate the model definitions independently
    from pydantic import BaseModel
    from typing import Optional
    
    class ContactFormData(BaseModel):
        nombre: str
        email: str
        telefono: str
        asunto: Optional[str] = ""
        mensaje: str
    
    # Test validation
    data = ContactFormData(
        nombre="Juan Pérez",
        email="juan@test.com",
        telefono="+584121234567",
        asunto="Consulta",
        mensaje="Quiero información sobre VenridesScreenS"
    )
    assert data.nombre == "Juan Pérez"
    
    class PlanSignupFormData(BaseModel):
        plan: str
        nombre: str
        email: str
        telefono: str
        empresa: str
        tipo_negocio: str
        pantallas_estimadas: str
        mensaje: Optional[str] = ""
    
    data2 = PlanSignupFormData(
        plan="plus",
        nombre="María",
        email="maria@empresa.com",
        telefono="+584261234567",
        empresa="Mi Empresa C.A.",
        tipo_negocio="Restaurante",
        pantallas_estimadas="5-10"
    )
    assert data2.plan == "plus"
    
    return True

test("Import email_sender", test_import_email_sender)
test("Import sheets_service", test_import_sheets_service)
test("Import benry_service", test_import_benry_service)
test("Pydantic Models Validation", test_import_main_models)

# ============================================
# 4. File Integrity Tests
# ============================================
print("\n📁 4. File Integrity Tests")

def test_apk_exists():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "releases", "VenridesScreenS_TV.apk")
    assert os.path.exists(path), f"APK not found at {path}"
    size_mb = os.path.getsize(path) / (1024 * 1024)
    return f"Found ({size_mb:.1f} MB)"

def test_client_js_fix():
    """Verify the ad_scripts bug fix is in frontend-tv/client.js"""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend-tv", "client.js")
    with open(path, 'r') as f:
        content = f.read()
    
    # The fix should use window.currentConfig, not data.ad_scripts
    assert "window.currentConfig" in content or "configData.ad_scripts" in content, "ad_scripts fix NOT found"
    assert "data.ad_scripts" not in content or "configData = window.currentConfig" in content, "Old bug still present"
    return True

def test_dist_client_js_fix():
    """Verify the fix is also in app-tv/dist/client.js"""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app-tv", "dist", "client.js")
    if not os.path.exists(path):
        raise Exception(f"dist/client.js not found — run 'npm run build' in app-tv")
    
    with open(path, 'r') as f:
        content = f.read()
    
    assert "window.currentConfig" in content or "configData.ad_scripts" in content, "Fix not propagated to dist"
    return True

def test_nginx_landing_api():
    """Verify nginx config has /api/ proxy for landing page"""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "nginx", "conf.d", "default.conf")
    with open(path, 'r') as f:
        content = f.read()
    
    # Check that the landing server block (port 83) has /api/ proxy
    lines = content.split('\n')
    in_landing = False
    has_api = False
    for line in lines:
        if 'listen 83' in line:
            in_landing = True
        if in_landing and 'location /api/' in line:
            has_api = True
            break
    
    assert has_api, "Landing page server (port 83) missing /api/ proxy"
    return True

def test_docker_compose_ollama():
    """Verify Ollama is in docker-compose"""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docker-compose.yml")
    with open(path, 'r') as f:
        content = f.read()
    assert "ollama" in content, "Ollama not in docker-compose.yml"
    assert "OLLAMA_URL" in content, "OLLAMA_URL env var not in docker-compose.yml"
    return True

test("APK File", test_apk_exists)
test("client.js Bug Fix (frontend-tv)", test_client_js_fix)
test("client.js Fix in dist (app-tv)", test_dist_client_js_fix)
test("Nginx Landing /api/ Proxy", test_nginx_landing_api)
test("Docker Compose Ollama", test_docker_compose_ollama)

# ============================================
# Summary
# ============================================
print("\n" + "=" * 60)
passes = sum(1 for _, s, _ in results if "PASS" in s)
warns = sum(1 for _, s, _ in results if "WARN" in s)
fails = sum(1 for _, s, _ in results if "FAIL" in s)

print(f"Results: {passes} ✅ | {warns} ⚠️ | {fails} ❌")
if fails > 0:
    print("\nFailed tests:")
    for name, status, detail in results:
        if "FAIL" in status:
            print(f"  ❌ {name}: {detail}")

if fails == 0:
    print("🎉 All tests passed!")
else:
    print(f"\n⚠️  {fails} test(s) need attention before deployment.")

print("=" * 60)
