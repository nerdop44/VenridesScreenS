# Configuración de Entornos - VenridesScreenS

Este proyecto utiliza variables de entorno para gestionar las URLs de desarrollo y producción automáticamente.

## 📁 Archivos de Configuración

Cada frontend tiene dos archivos de configuración:

- **`.env.development`**: URLs para desarrollo local (localhost)
- **`.env.production`**: URLs para producción en VPS (screens.venrides.com)

## 🔄 Cambio Automático de Entorno

**Vite detecta automáticamente el entorno:**

### Desarrollo Local
```bash
npm run dev
# Usa .env.development automáticamente
# URLs apuntan a localhost:XXXX
```

### Build de Producción
```bash
npm run build
# Usa .env.production automáticamente
# URLs apuntan a los dominios finales
```

## 🌐 Variables Disponibles

### Frontend Landing & Admin
- `VITE_API_BASE_URL`: URL del backend API
- `VITE_ADMIN_PANEL_URL`: URL del panel de administración
- `VITE_LANDING_URL`: URL de la landing page
- `VITE_TV_URL`: URL de la app TV
- `VITE_MOBILE_URL`: URL de la app móvil

## ✏️ Cambiar URLs

### Para Desarrollo Local
Edita `frontend-*/,env.development`:
```env
VITE_ADMIN_PANEL_URL=http://localhost:8081
```

### Para Producción
Edita `frontend-*/.env.production`:
```env
VITE_ADMIN_PANEL_URL=https://admintv.venrides.com
```

## 💡 Uso en el Código

En cualquier componente React/JSX:

```jsx
// ❌ ANTES (hardcodeado)
<a href="http://localhost:8081">Panel</a>

// ✅ AHORA (dinámico)
<a href={import.meta.env.VITE_ADMIN_PANEL_URL}>Panel</a>
```

## 🔒 Seguridad

- Los archivos `.env.development` y `.env.production` están en git
- Para configuraciones sensibles locales, crea `.env.local` (git-ignored)
- Las variables que comienzan con `VITE_` son embebidas en el build y **visibles en el cliente**
- **NO** pongas credenciales o secretos en variables `VITE_*`

## 🚀 Deploy en VPS

Cuando hagas `docker compose build` en el VPS:

```bash
# Docker ejecuta 'npm run build' que automáticamente usa .env.production
sudo docker compose build frontend-admin frontend-landing
sudo docker compose up -d
```

Las URLs de producción ya estarán configuradas sin cambiar nada.

## 📝 Checklist de Migración

- [x] Variables de entorno creadas para todos los frontends
- [x] URLs hardcodeadas reemplazadas por variables
- [ ] Verificar que no queden URLs hardcodeadas en otros componentes
- [ ] Probar build local con `npm run build`
- [ ] Probar build en VPS

## ⚙️ Override Local (Opcional)

Si necesitas URLs personalizadas sin afectar los archivos .env, crea `.env.local`:

```bash
# frontend-admin/.env.local (git-ignored)
VITE_API_BASE_URL=http://192.168.1.100:8000
```

Este archivo tiene **prioridad máxima** y nunca se sube a git.
