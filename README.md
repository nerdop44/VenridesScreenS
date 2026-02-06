# VenridesScreenS

Sistema completo de gestión de pantallas para negocios, con backend FastAPI, múltiples frontends (TV, Admin, Landing, Mobile) y arquitectura Dockerizada.

## 🚀 Stack Tecnológico

- **Backend**: FastAPI + PostgreSQL + Redis
- **Frontend Admin**: React + Vite
- **Frontend TV**: Vanilla JS (ultra-ligero)
- **Frontend Landing**: React + Vite + Tailwind CSS
- **Mobile**: Capacitor (iOS/Android)
- **Infraestructura**: Docker + Nginx

## 📋 Requisitos

- Docker & Docker Compose
- Node.js 18+ (para desarrollo local)
- Python 3.11+ (para desarrollo local)
- PostgreSQL 15 (si no usas Docker)

## ⚙️ Configuración Inicial

### 1. Clonar el Repositorio

```bash
git clone <repository-url>
cd VenridesScreenS
```

### 2. Configurar Variables de Entorno

Crea un archivo `.env` en el directorio `backend/`:

```bash
cp backend/.env.example backend/.env
```

Edita `backend/.env` con tus valores:

```env
DATABASE_URL=postgresql+asyncpg://venrides_user:venrides_password@db/venrides_db
SECRET_KEY=<genera-una-clave-secreta-fuerte>
GMAIL_APP_PASSWORD=<tu-gmail-app-password>
SMTP_USER=<tu-email>
```

> ⚠️ **NUNCA** subas el archivo `.env` a Git. Solo `.env.example`

### 3. Configurar Credenciales de Google Sheets (Opcional)

Si usas Google Sheets para formularios:

1. Crea un Service Account en Google Cloud Console
2. Descarga el JSON de credenciales
3. Guárdalo como `backend/credentials/google-service-account.json`

## 🐳 Desarrollo con Docker

### Iniciar todos los servicios

```bash
docker compose up -d
```

Servicios disponibles:
- **Backend API**: http://localhost:8000
- **Admin Panel**: http://localhost:8081
- **TV Client**: http://localhost:8080
- **Landing Page**: http://localhost:8090
- **Mobile App**: http://localhost:8082
- **PostgreSQL**: localhost:5433
- **Redis**: localhost:6379

### Ver logs

```bash
docker compose logs -f backend
docker compose logs -f frontend-admin
```

### Reconstruir servicios

```bash
docker compose build
docker compose up -d
```

## 💻 Desarrollo Local (Sin Docker)

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Admin

```bash
cd frontend-admin
npm install
npm run dev  # Desarrollo
npm run build  # Producción
```

### Frontend Landing

```bash
cd frontend-landing
npm install
npm run dev  # Desarrollo
npm run build  # Producción
```

## 🌐 Despliegue en Producción (VPS)

Ver documentación detallada en:
- [CONFIGURACION_ENTORNOS.md](./CONFIGURACION_ENTORNOS.md) - Configuración de variables de entorno
- `.gemini/antigravity/brain/*/screens_deployment.md` - Guía de nginx

### Resumen de Despliegue

1. **Configurar DNS** para los dominios:
   - `admintv.venrides.com` → Admin Panel
   - `apitv.venrides.com` → Backend API  
   - `tv.venrides.com` → TV Client
   - `screens.venrides.com` → Landing Page

2. **Configurar Nginx Proxy Manager**:

| Dominio | Destination | SSL |
|---------|-------------|-----|
| admintv.venrides.com | `http://venrides_admin:80` | Let's Encrypt |
| apitv.venrides.com | `http://venrides_api:8000` | Let's Encrypt |
| tv.venrides.com | `http://venrides_tv:80` | Let's Encrypt |
| screens.venrides.com | `http://venrides_landing:80` | Let's Encrypt |

3. **Deploy**:

```bash
# En el VPS
git pull origin main
docker compose pull
docker compose build
docker compose up -d
```

## 📁 Estructura del Proyecto

```
VenridesScreenS/
├── backend/              # FastAPI backend
│   ├── credentials/      # Service account keys (git-ignored)
│   ├── utils/           # Utilidades (email, auth, etc.)
│   ├── main.py          # Punto de entrada
│   └── requirements.txt
├── frontend-admin/       # Panel de administración (React)
├── frontend-tv/         # Cliente TV (Vanilla JS)
├── frontend-landing/    # Landing page (React + Tailwind)
├── app-mobile/          # App móvil (Capacitor)
├── nginx/               # Configuraciones nginx
├── docker-compose.yml   # Orquestación de servicios
└── .gitignore
```

## 🔒 Seguridad

- ✅ Todas las credenciales están en `.gitignore`
- ✅ Secrets en variables de entorno
- ✅ HTTPS obligatorio en producción
- ✅ JWT para autenticación
- ✅ CORS configurado

## 🧪 Testing

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend-admin
npm test
```

## 📝 Scripts Útiles

```bash
# Backup de base de datos
./backup_containers.sh

# Migración de datos
cd backend
python migrate_venrides.py
```

## 🐛 Troubleshooting

### Puerto 5433 en uso
```bash
docker compose down
docker compose up -d
```

### Base de datos no inicializa
```bash
docker compose down -v  # ⚠️ Esto borra los datos
docker compose up -d
```

### Problemas con logs
```bash
# Limpiar logs
find . -name "*.log" -delete
```

## 📜 Licencia

Privado - Venrides © 2026

## 👥 Contacto

Para soporte, contactar a: nerdop@gmail.com
