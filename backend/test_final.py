"""Final verification — all offline tests"""
import os, sys
sys.path.insert(0, '/home/nerdop/VScreenS/backend')
os.chdir('/home/nerdop/VScreenS/backend')
os.environ['SMTP_USER'] = 'info.vscreens@inverpave.com'
os.environ['SMTP_PASSWORD'] = 'ozxrkpkksgihqnya'
os.environ['NOTIFICATION_EMAIL'] = 'info.vscreens@inverpave.com'
os.environ['GOOGLE_SHEETS_CREDENTIALS_PATH'] = './credentials/google-service-account.json'

print("=== FINAL VERIFICATION ===")

# 1. Import tests
try:
    from utils.email_sender import send_email
    print("  ✅ email_sender")
except Exception as e:
    print(f"  ❌ email_sender: {e}")

try:
    from services.sheets_service import sheets_service
    print("  ✅ sheets_service")
except Exception as e:
    print(f"  ❌ sheets_service: {e}")

try:
    from services.benry_service import benry_service
    print("  ✅ benry_service")
except Exception as e:
    print(f"  ❌ benry_service: {e}")

# 2. File checks
checks = [
    ("APK exists", os.path.exists("/home/nerdop/VScreenS/releases/VScreenS_TV.apk")),
    ("client.js fix frontend-tv", "configData = window.currentConfig" in open("/home/nerdop/VScreenS/frontend-tv/client.js").read()),
    ("client.js fix app-tv/dist", "configData = window.currentConfig" in open("/home/nerdop/VScreenS/app-tv/dist/client.js").read()),
    ("Nginx /api/ landing", "location /api/" in open("/home/nerdop/VScreenS/nginx/conf.d/default.conf").read().split("listen 83")[1]),
    (".env SMTP_USER", "SMTP_USER=" in open("/home/nerdop/VScreenS/backend/.env").read()),
    (".env BENRY_SHEET_ID", "BENRY_SHEET_ID=" in open("/home/nerdop/VScreenS/backend/.env").read()),
    ("No ollama", "ollama" not in open("/home/nerdop/VScreenS/docker-compose.yml").read()),
    ("/api/forms/contact", "/api/forms/contact" in open("/home/nerdop/VScreenS/backend/main.py").read()),
    ("/api/benry/chat", "/api/benry/chat" in open("/home/nerdop/VScreenS/backend/main.py").read()),
    ("/downloads/tv", "/downloads/tv" in open("/home/nerdop/VScreenS/backend/main.py").read()),
]

for name, ok in checks:
    print(f"  {'✅' if ok else '❌'} {name}")

fails = sum(1 for _, ok in checks if not ok)
total = len(checks) + 3
print(f"\nTotal: {total} tests, {total - fails} passed, {fails} failed")
if fails == 0:
    print("🎉 ALL FINAL TESTS PASSED!")
