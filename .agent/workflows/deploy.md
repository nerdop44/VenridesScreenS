---
description: despliegue automático de VenridesScreenS al VPS
---

Este workflow automatiza la sincronización de cambios desde el entorno local al servidor de producción.

// turbo-all
1. Subir cambios locales al repositorio:
   ```bash
   git add . && git commit -m "update: automatic deployment" && git push origin main
   ```

2. Ejecutar despliegue remoto vía SSH:
   > [!NOTE]
   > El script asume que `sshpass` está instalado y que la IP del VPS es `37.60.242.112`.

   ```bash
   SSHPASS='14304044np1' sshpass -e ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password root@37.60.242.112 "cd /opt/VenridesScreenS && git pull origin main && docker compose build backend frontend-admin frontend-landing && docker compose up -d"
   ```

3. Verificar estado de los contenedores en el VPS:
   ```bash
   SSHPASS='14304044np1' sshpass -e ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password root@37.60.242.112 "docker compose ps"
   ```
