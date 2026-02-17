---
name: continuity
description: Instrucciones obligatorias para retomar el hilo de trabajo al iniciar una nueva sesión o cambiar de agente para VenridesScreenS.
---

# Skill de Continuidad (Catch-Up) - VenridesScreenS

Este skill debe ser invocado por cualquier nuevo agente que tome el control del proyecto VenridesScreenS para evitar redundancia y garantizar la coherencia técnica.

## Pasos de Activación Inmediata
Al iniciar, el agente DEBE:

1. **Revisar Conocimientos**: Leer `/home/nerdop/laboratorio/deposito de conocimientos antigravity/PROYECTO_VENRIDESSCREENS.md` y `CREDENCIALES_Y_ENTORNOS_VENRIDESSCREENS.md`.
2. **Historial de Tareas**: Revisar el último `task.md` y `walkthrough.md` en el directorio de `brain` de la conversación actual.
3. **Estado del VPS**: Verificar la conexión al VPS `37.60.242.112` (root/14304044np1) y el estado de los contenedores Docker si hay despliegues pendientes.
4. **Contexto de Errores**: Buscar en los logs de la conversación anterior los errores de "CORS", "Inyección de variables" o "Sincronización de Ticker", que son hitos críticos ya resueltos para VenridesScreenS.

## Reglas de Oro
- **No reinventar**: Si una URL está fallando, verifica primero si es un problema de inyección de variables `VITE_` en el `docker-compose.yml`.
- **Caché**: Siempre usa versiones en los assets (ej: `?v=1.7`) para forzar la actualización en Smart TVs.
- **Permisos**: Recuerda que el rol `admin_master` tiene privilegios especiales en el código que no dependen exclusivamente de la base de datos.
- **Ubicación de Conocimientos**: La base de conocimiento está en `/home/nerdop/laboratorio/deposito de conocimientos antigravity/`.
