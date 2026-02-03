# Flujo de Trabajo: Desarrollo y Producción VenridesScreenS

Este documento explica cómo trabajar de forma segura entre tu entorno local y el servidor VPS, garantizando que **Odoo** permanezca intacto.

## 1. Desarrollo Local
Trabaja en tu computadora como siempre. 
- Las aplicaciones web están configuradas para detectar si estás en `localhost` y usar el puerto 8000 local.
- No borres el archivo `.env` local, ya que este maneja tu configuración de desarrollo.

## 2. Sincronización (Git)
Cuando termines una mejora y quieras llevarla al servidor:
1. Haz tus commits locales (ya configuré todo para que sea fácil).
2. Sube los cambios a GitHub:
   ```bash
   git add .
   git commit -m "Descripción de tu mejora"
   git push origin main
   ```

## 3. Despliegue en Producción (VPS)
Entra a tu servidor VPS vía SSH y ejecuta estos comandos para aplicar las mejoras:
```bash
cd /opt/VenridesScreenS
git pull origin main
docker compose up -d --build
```

**Beneficios de este flujo:**
- **Seguridad:** Los secretos y contraseñas de producción están en el archivo `/opt/VenridesScreenS/.env` del VPS, el cual Git ignora por seguridad.
- **Limpieza:** Al usar Docker, no ensuciaremos el sistema operativo principal ni chocaremos con las instalaciones de Odoo.
- **Rapidez:** Solo descargas lo que cambió en el código.

## 4. Apps Móviles y TV
He actualizado las aplicaciones para que, por defecto, intenten conectarse a:
- `https://apitv.venrides.com`

Si necesitas probar contra un servidor de desarrollo diferente en la app móvil, recuerda que tienes la opción de cambiar la URL en el panel de configuración de la app.
