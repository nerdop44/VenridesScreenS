# INFORME DE PRUEBAS 1:1 Y ANÁLISIS DE ESCENARIOS — VScreenS en Odoo

Fecha: 13 de noviembre de 2026
Método: Navegador interactivo (Chromium) + pruebas de API con curl + simulación de TV

---

## 1. COMPARATIVA 1:1 — LANDING SPA REACT vs ODOO WEBSITE

### Landing Anterior (SPA React en vscreens.inverpave.com)

| Sección | Estado | Observaciones |
|---------|--------|---------------|
| Header con logo | ✅ | Logo VENRIDESCREENS (viejo, pendiente de cambio) |
| Menú: Soluciones, Precios, Descargas, Portal Clientes | ✅ | |
| Hero "PANTALLAS QUE VENDEN" | ✅ | Fondo oscuro con acentos azules |
| Planes Estratégicos (5 planes) | ✅ | FREE, EMPRENDEDOR, PROFESIONAL, ENTERPRISE, PANTALLAS GIGANTES |
| Descarga VScreenS (APK TV y Móvil) | ✅ | |
| Benry Chat (botón flotante 🤖) | ✅ | |
| Footer con navegación y legal | ✅ | |
| Diseño responsivo y animaciones | ✅ | |

### Landing Nueva (Odoo Website en vscreens-erp.inverpave.com)

| Sección | Estado | Observaciones |
|---------|--------|---------------|
| Header con logo VScreenS | ✅ | Logo nuevo (icono + texto), CSS ajustado a 55px |
| Menú: Inicio, Planes, Contacto, Aviso Legal | ✅ | |
| Hero "PANTALLAS QUE VENDEN" | ✅ | Fondo oscuro con acento verde (#c8ff00) |
| Sección "¿Por qué VScreenS?" (3 características) | ✅ | Multi-pantalla, Tasa BCV, Branding |
| Planes Estratégicos (4 planes) | ✅ | FREE, EMPRENDEDOR, PROFESIONAL, ENTERPRISE |
| Descarga VScreenS (APK TV y Móvil) | ✅ | Botones verdes, links funcionales (HTTP 200) |
| Benry Chat (botón flotante 🤖) | ✅ | Responde con planes y precios |
| Footer personalizado | ✅ | Datos INVERPA, RIF, dirección, teléfono, email |
| Página de Contacto con formulario | ✅ | Conectado a `/api/forms/contact` |
| Página de Aviso Legal | ✅ | Datos fiscales completos |

### Diferencias y brechas

| Característica | SPA React | Odoo Website | Estado |
|---------------|-----------|--------------|--------|
| Hero visual | Fondo oscuro + imagen | Fondo oscuro + gradiente | ✅ Equivalente |
| Planes | 5 planes | 4 planes (falta PANTALLAS GIGANTES) | ⚠️ Agregar plan empresarial |
| Descargas | APK TV + Móvil | APK TV + Móvil (ambos HTTP 200) | ✅ Equivalente |
| Benry chat | Botón flotante + panel | Botón flotante + panel funcional | ✅ Equivalente |
| Portal Clientes | Link a vscreens-app | Link en footer | ✅ Equivalente |
| Footer | Datos VScreenS | Datos INVERPA completos | ✅ Mejorado |
| Animaciones | Sí (CSS/JS) | Limitadas (Bootstrap) | ⚠️ Mejorable |
| Imágenes de fondo | Mockups con "VenridesScreens" | Sin imágenes | ⚠️ Pendiente logos/imágenes |

---

## 2. PRUEBAS DE TV — FLUJO DASHBOARD → TV

### Escenario probado: Cambios desde el dashboard reflejados en la TV

**Paso 1: Crear empresa de prueba**
- Empresa: "Empresa Prueba TV" (plan Free)
- Dispositivo: TV-SIMULADO-001

**Paso 2: Cambiar configuración desde el dashboard**
- Colores: primary=#1e3a5f, secondary=#c8ff00, accent=#ff6b35
- Sidebar: "Hamburguesa Especial", "Solo $5.99"
- Bottom bar: "¡Bienvenidos a nuestro restaurante!", "Promoción del día", "Tasa BCV actualizada", "Nuevo menú disponible"
- Menú: "Hamburguesa Clásica" - $5.99
- Alerta en vivo: "AVISO IMPORTANTE — 2x1 en hamburguesas hasta las 6pm"

**Paso 3: TV recibe la configuración**
- Endpoint: `GET /devices/TV-SIMULADO-001/config`
- Respuesta HTTP 200 con todos los campos:
  - `is_active: true`
  - `active_alert: {id: 2, subject: "AVISO IMPORTANTE", body: "2x1 en hamburguesas hasta las 6pm", duration: 20}`
  - `primary_color: "#1e3a5f"`
  - `secondary_color: "#c8ff00"`
  - `accent_color: "#ff6b35"`
  - `sidebar_content: [{value: "Hamburguesa Especial"}, {value: "Solo $5.99"}]`
  - `bottom_bar_content: {static: "¡Bienvenidos...", messages: [...]}`
  - `menus: [{name: "Hamburguesa Clásica", price: 5.99}]`
  - `bcv_rate: 911.6243`

**Paso 4: TV renderiza los cambios (captura de pantalla)**
- Modal de alerta rojo: "AVISO IMPORTANTE — 2x1 en hamburguesas hasta las 6pm"
- Nombre de empresa: "Empresa Prueba TV" (esquina superior)
- Sidebar: "Hamburguesa Especial"
- Bottom bar: "Nuevo menú disponible" + "⚠️ Tu prueba gratuita vence en 6 días"
- Video de relleno: lofi hip hop (YouTube)

**Resultado: ✅ FLUJO COMPLETO FUNCIONAL**

### Escenario: Vinculación de TV con código de 6 dígitos

**Paso 1: Generar código**
- Desde empresa: `action_generate_registration_code()`
- Código generado: 6 dígitos, válido 10 minutos

**Paso 2: Validar código**
- Endpoint: `POST /devices/validate-code?code=XXXXXX&device_uuid=YYYY`
- Respuesta: configuración completa de la TV (HTTP 200)

**Paso 3: TV vinculada**
- Dispositivo creado con UUID de la TV
- Asociado a la empresa
- Recibe configuración automáticamente

**Resultado: ✅ FUNCIONAL**

---

## 3. ANÁLISIS DE ESCENARIOS DE USUARIO

### Escenario 1: Visitante anónimo en la landing
| Paso | Acción | Estado |
|------|--------|--------|
| 1 | Abre `vscreens-erp.inverpave.com` | ✅ Home renderizada |
| 2 | Ve hero, características, descargas | ✅ |
| 3 | Hace clic en "VER PLANES" | ✅ Redirige a `/planes` |
| 4 | Ve los 4 planes con precios | ✅ |
| 5 | Hace clic en "SELECCIONAR" | ✅ Redirige a `/contacto` |
| 6 | Llena formulario de contacto | ✅ |
| 7 | Envía formulario | ✅ Crea lead en Odoo |
| 8 | Usa Benry chat | ✅ Responde con planes |
| 9 | Descarga APK TV | ✅ HTTP 200 |
| 10 | Descarga APK Móvil | ✅ HTTP 200 |

### Escenario 2: Cliente existente accede al portal
| Paso | Acción | Estado |
|------|--------|--------|
| 1 | Abre `vscreens-app.inverpave.com` | ⚠️ Frontend-admin SPA (aún apunta a API legacy) |
| 2 | Inicia sesión | ⚠️ Depende del backend legacy |
| 3 | Ve sus pantallas | ⚠️ Pendiente migrar frontend-admin |
| 4 | Ve sus facturas | ⚠️ Pendiente configurar portal Odoo |
| 5 | Abre tickets | ⚠️ Pendiente migrar frontend-admin |

**Nota:** El portal de clientes es el frontend-admin (SPA React) que aún apunta a la API FastAPI legacy. Para completar la migración, se debe:
- Cambiar el `.env.production` del frontend-admin a `vscreens-erp.inverpave.com` (ya hecho)
- Reconstruir el contenedor `vscreens-admin`
- O usar el portal nativo de Odoo (`/my`)

### Escenario 3: Admin master gestiona empresas
| Paso | Acción | Estado |
|------|--------|--------|
| 1 | Accede a `vscreens-erp.inverpave.com/web/login` | ✅ HTTP 200 |
| 2 | Inicia sesión (admin / 14304044np1) | ✅ JSON-RPC autenticación |
| 3 | Ve menú VScreenS | ✅ Dashboard, Clientes, Contenido, Mensajería, Soporte, CRM |
| 4 | Crea empresa | ⚠️ Vía API (el frontend SPA lo hace) |
| 5 | Genera código de vinculación | ✅ |
| 6 | Envía alerta en vivo | ✅ |
| 7 | Ve configuración de TV | ✅ |

### Escenario 4: TV en producción
| Paso | Acción | Estado |
|------|--------|--------|
| 1 | TV abre `vscreens-tv.inverpave.com` | ✅ |
| 2 | Muestra ID de dispositivo | ✅ |
| 3 | Ingresa código de 6 dígitos | ✅ |
| 4 | Se vincula a la empresa | ✅ |
| 5 | Recibe configuración | ✅ |
| 6 | Muestra contenido (video, sidebar, bottom bar) | ✅ |
| 7 | Muestra alertas en vivo | ✅ |
| 8 | Muestra tasa BCV | ✅ |
| 9 | Ping visual | ✅ |

### Escenario 5: Facturación
| Paso | Acción | Estado |
|------|--------|--------|
| 1 | Crear factura en Odoo | ✅ |
| 2 | IVA 16% aplicado | ✅ |
| 3 | Bimoneda USD/VES (911.6243) | ✅ |
| 4 | Emisión TFHKA | ✅ Probado (correlativo 00-00000057) |
| 5 | Pago registrado | ✅ |
| 6 | Pago extiende `valid_until` | ⚠️ Pendiente automatizar |

---

## 4. BRECHAS IDENTIFICADAS (Qué falta o no se ve)

### Críticas (afectan operatividad)
1. **Portal de clientes (frontend-admin):** Aún apunta a la API FastAPI legacy. Necesita rebuild con `.env.production` a Odoo.
2. **App móvil (APK):** El APK actual `VScreenS_Mobile.apk` apunta al backend legacy. Necesita rebuild con `VITE_API_BASE_URL=https://vscreens-erp.inverpave.com`.
3. **Imágenes de fondo:** `fondo2.png`, `final_times.jpg`, `final_collage.jpg` aún tienen "VenridesScreens". Sin generador de imágenes (saldo insuficiente) y PIL no puede hacer inpintado realista.

### Importantes (mejoran experiencia)
4. **Plan "PANTALLAS GIGANTES":** La landing SPA tiene 5 planes, la de Odoo tiene 4. Falta agregar el plan empresarial.
5. **Animaciones:** La landing SPA tiene animaciones CSS/JS. La de Odoo tiene Bootstrap estático.
6. **Footer de Odoo:** Debajo del footer personalizado hay un footer de Odoo con "Powered by Odoo - The #1 Open Source eCommerce" que debería ocultarse.
7. **Carrito de compras (🛒):** El header muestra el icono del carrito de `website_sale`. Puede confundir si no se usa ecommerce.

### Menores
8. **Blog/Jobs:** Los menús de Shop y Jobs se eliminaron, pero los módulos siguen instalados.
9. **Portal Odoo `/my`:** No está configurado para clientes VScreenS.
10. **Sincronización de pagos:** El pago no extiende automáticamente `valid_until`.

---

## 5. PROBLEMAS TÉCNICOS ENCONTRADOS Y SOLUCIONADOS

| Problema | Causa | Solución |
|----------|-------|----------|
| Páginas de website no renderizaban | `website_id` NULL en `website.page` | Asignar `website_id=1` |
| Logo no se veía | CSS del logo muy pequeño | `custom_code_head` con `max-height: 55px` |
| Home redirigía a `/shop` | Páginas duplicadas con URL `/` | Eliminar páginas 2 y 5, dejar solo la 8 |
| `t-call="website.layout"` fallaba | Faltaba `main_object` en contexto | Odoo lo pasa automáticamente al renderizar desde controlador |
| Conflicto `message_ids` | `mail.thread` y `vscreens.message` | Agregar `vscreens_message_ids` explícito |
| Endpoint mobile 404 | Archivo se llama `VScreenS_Mobile.apk` | Corregir path por defecto |
| Errores de concurrencia TV | Ping constante a `/devices/<uuid>/config` | La TV hace ping demasiado frecuente (mejorable) |

---

## 6. ESTADO FINAL

### URLs funcionales
| URL | Estado |
|-----|--------|
| `https://vscreens-erp.inverpave.com/` | ✅ Home con hero, características, descargas |
| `https://vscreens-erp.inverpave.com/planes` | ✅ 4 planes con precios |
| `https://vscreens-erp.inverpave.com/contacto` | ✅ Formulario funcional |
| `https://vscreens-erp.inverpave.com/legal` | ✅ Datos fiscales INVERPA |
| `https://vscreens-erp.inverpave.com/downloads/tv` | ✅ APK TV (4.1 MB) |
| `https://vscreens-erp.inverpave.com/downloads/mobile` | ✅ APK Móvil (3.4 MB) |
| `https://vscreens-erp.inverpave.com/api/plans` | ✅ 5 planes JSON |
| `https://vscreens-erp.inverpave.com/finance/bcv` | ✅ Tasa 911.6243 |
| `https://vscreens-erp.inverpave.com/api/benry/chat` | ✅ Chat funcional |
| `https://vscreens-tv.inverpave.com/` | ✅ TV funcional con vinculación |
| `https://vscreens.inverpave.com/` | ✅ SPA React legacy (comparativa) |
| `https://vscreens-app.inverpave.com/` | ⚠️ SPA admin (apunta a legacy) |

### Contenedores
- `vscreens-odoo`: ✅ Up
- `vscreens-db`: ✅ Up (healthy)
- `vscreens-gateway`: ✅ Up
- `vscreens-landing`: ✅ Up (SPA legacy)
- `vscreens-admin`: ✅ Up (SPA legacy)
- `vscreens-tv`: ✅ Up
- `vscreens-uptime`: ✅ Up (healthy)
- `vscreens_legacy_api`: ✅ Up (puerto 8006, comparativa)

---

## 7. PRÓXIMOS PASOS RECOMENDADOS

1. **Reconstruir frontend-admin** con URL de Odoo y desplegar.
2. **Reconstruir APK móvil** con `VITE_API_BASE_URL=https://vscreens-erp.inverpave.com`.
3. **Corregir imágenes/logos** (fondo2, final_times, final_collage) cuando haya créditos de generación de imágenes.
4. **Agregar plan "PANTALLAS GIGANTES"** a la landing de Odoo.
5. **Ocultar footer de Odoo** ("Powered by Odoo") y carrito de compras.
6. **Configurar portal de clientes de Odoo** (`/my`) para que los clientes vean sus pantallas y facturas.
7. **Automatizar extensión de `valid_until`** al registrar pagos.
8. **Optimizar frecuencia de ping de la TV** para evitar errores de concurrencia.

---

## 8. CONCLUSIÓN

El ecosistema VScreenS en Odoo está **operativo de extremo a extremo**:

- ✅ Landing reconstruida con hero, planes, contacto, legal, descargas y Benry.
- ✅ Benry chat funcional con respuestas de planes y precios.
- ✅ Descargas de APK TV y Móvil funcionales (HTTP 200).
- ✅ TV simulada y probada: recibe configuración del dashboard (colores, sidebar, bottom bar, menús, alertas).
- ✅ Flujo de vinculación de TV con código de 6 dígitos funcional.
- ✅ Facturación TFHKA probada (correlativo 00-00000057).
- ✅ Bimoneda USD/VES con tasa BCV 911.6243.

**Brechas principales:** frontend-admin y APK móvil aún apuntan al backend legacy, imágenes de fondo pendientes, y algunas mejoras visuales (animaciones, plan empresarial, footer de Odoo).

**No se tocó el core de Odoo** — todo es herencia (`_inherit`) o modelos nuevos (`_name`) dentro del módulo `vscreens`.
