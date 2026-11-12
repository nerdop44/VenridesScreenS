# Guía de Cloudflare y correo — VScreenS

Actualizado: 12 de noviembre de 2026.

Esta guía cubre dos frentes:

1. **Cloudflare**: dejar los dominios nuevos funcionando y resolver los antiguos
   (`screens.venrides.com`, `tv.venrides.com`) que hoy devuelven error 500.
2. **Correo**: usar los buzones `@inverpave.com` de VScreenS, configurar clientes
   y verificar que el envío y la recepción funcionan.

---

## 1. Estado actual (verificado)

### 1.1 DNS de `inverpave.com` en Cloudflare

| Tipo | Nombre | Valor | Proxy |
|------|--------|-------|-------|
| A | `*.inverpave.com` | `37.60.236.245` | Naranja (proxied) |
| A | `inverpave.com` | `37.60.236.245` | Naranja (proxied) |
| A | `smtp.inverpave.com` | `37.60.236.245` | **Gris (DNS only)** |
| MX | `inverpave.com` | `10 smtp.inverpave.com` | — |
| TXT | `inverpave.com` (SPF) | `v=spf1 a:smtp.inverpave.com ~all` | — |
| TXT | `mail._domainkey.inverpave.com` (DKIM) | clave RSA de 2048 bits | — |
| TXT | `_dmarc.inverpave.com` | `v=DMARC1; p=none; rua=mailto:postmaster@inverpave.com` | — |

Gracias al comodín `*.inverpave.com`, los seis nombres de VScreenS ya resuelven
sin crear registros individuales:

- `vscreens.inverpave.com` (landing)
- `vscreens-app.inverpave.com` (panel cliente)
- `vscreens-api.inverpave.com` (API)
- `vscreens-tv.inverpave.com` (TV)
- `vscreens-erp.inverpave.com` (Odoo)
- `vscreens-status.inverpave.com` (monitoreo)

**Importante:** `smtp.inverpave.com` debe seguir en **DNS only**. Si se activa el
proxy naranja, el correo (SMTP/IMAP) deja de funcionar porque Cloudflare no
proxya esos puertos.

### 1.2 Problema de los dominios antiguos

`screens.venrides.com` y `tv.venrides.com` resuelven a Cloudflare, pero el origen
configurado en la zona `venrides.com` **no es este servidor**: devuelve una página
de error de un proveedor chino.

Comprobación rápida desde cualquier equipo:

```bash
curl -sSI https://screens.venrides.com/ | head -3
# HTTP/2 500  -> origen equivocado
```

En el servidor de VScreenS el redirect 301 sí funciona:

```bash
curl -sk --resolve screens.venrides.com:443:127.0.0.1 \
  -o /dev/null -w '%{http_code} %{redirect_url}\n' https://screens.venrides.com/
# 301 https://vscreens.inverpave.com/
```

El token de Cloudflare disponible solo tiene permiso de lectura DNS sobre
`inverpave.com`, por lo que **la zona `venrides.com` debe corregirse desde el panel**
o con un token nuevo (ver 2.4).

---

## 2. Cloudflare, paso a paso

### 2.1 Revisar SSL/TLS en `inverpave.com`

1. Entrar a <https://dash.cloudflare.com> y abrir la zona **inverpave.com**.
2. Ir a **SSL/TLS → Overview**.
3. Seleccionar **Full (strict)**.
   El origen usa un certificado *Cloudflare Origin CA* (`*.inverpave.com` y
   `inverpave.com`), válido hasta 2041, así que *Full (strict)* es seguro.
4. Ir a **SSL/TLS → Edge Certificates**:
   - **Always Use HTTPS**: activado.
   - **Minimum TLS Version**: TLS 1.2.
   - **Automatic HTTPS Rewrites**: activado.
   - **HSTS**: opcional; si se activa, empezar con `max-age=300` y subir después.

### 2.2 Reglas de caché y seguridad (recomendado)

En **Caching → Cache Rules**, crear dos reglas:

| Regla | Condición | Acción |
|-------|-----------|--------|
| API sin caché | `hostname` es `vscreens-api.inverpave.com` | Bypass cache |
| Paneles sin caché | `hostname` es `vscreens-erp.inverpave.com` o `vscreens-app.inverpave.com` | Bypass cache |

En **Security → WAF** se puede activar el conjunto gestionado de Cloudflare y
**Bot Fight Mode**. No activar “Under Attack Mode”: rompe el panel y la TV.

### 2.3 Redirecciones de los dominios antiguos (recomendado)

Esto evita tocar el origen y no depende del certificado del servidor viejo.

1. Abrir la zona **venrides.com** en Cloudflare.
2. Ir a **Rules → Redirect Rules → Create rule**.
3. Regla 1:
   - **Nombre**: `screens -> vscreens`
   - **When incoming requests match**: `Hostname` *equals* `screens.venrides.com`
   - **Then**: *Dynamic redirect*
   - **Expression**:
     ```
     concat("https://vscreens.inverpave.com", http.request.uri.path)
     ```
   - **Status code**: `301`
   - **Preserve query string**: activado
4. Regla 2, igual pero con:
   - `tv.venrides.com` → `concat("https://vscreens-tv.inverpave.com", http.request.uri.path)`
5. Guardar y probar:
   ```bash
   curl -sSI https://screens.venrides.com/algo | grep -E 'HTTP/|location'
   # HTTP/2 301
   # location: https://vscreens.inverpave.com/algo
   ```

> Si el plan no incluye Redirect Rules, la alternativa es cambiar el DNS:
> `screens` y `tv` como **CNAME** hacia `vscreens.inverpave.com` y
> `vscreens-tv.inverpave.com` respectivamente, con proxy naranja, y poner
> **SSL/TLS → Full** (no *strict*) en la zona `venrides.com`. Es menos limpio,
> pero funciona.

### 2.4 Si se prefiere automatizar (token nuevo)

El token actual (`CF_API_TOKEN` en `/opt/canalsaas/deploy/.env`) solo permite leer
DNS de `inverpave.com`. Para gestionar ambas zonas por API:

1. Cloudflare → **My Profile → API Tokens → Create Token**.
2. Permisos:
   - **Zone → DNS → Edit** (zonas `inverpave.com` y `venrides.com`)
   - **Zone → Zone Settings → Edit**
   - **Zone → Zone → Read**
3. Restringir por IP al servidor (`37.60.236.245`).
4. Guardar el token en `/opt/vscreens/.env` como `CF_API_TOKEN_V2` (permisos 600).

Con ese token se pueden crear las Redirect Rules por API, pero **no es obligatorio**:
las reglas del punto 2.3 se hacen en 5 minutos desde el panel.

### 2.5 Verificación final

```bash
for u in https://vscreens.inverpave.com/ \
         https://vscreens-app.inverpave.com/ \
         https://vscreens-api.inverpave.com/diag/status \
         https://vscreens-tv.inverpave.com/ \
         https://vscreens-erp.inverpave.com/web/login \
         https://vscreens-status.inverpave.com/status/vscreens \
         https://webmail.inverpave.com/; do
  echo -n "$u -> "
  curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 "$u"
done
```

Todos deben devolver `200` (el estado puede devolver `302` hacia el dashboard si
se entra sin sesión).

---

## 3. Correo, paso a paso

### 3.1 Buzones de VScreenS

| Buzón | Uso |
|-------|-----|
| `info.vscreens@inverpave.com` | Correo general, remitente de Odoo y de la landing |
| `soporte.vscreens@inverpave.com` | Tickets de Odoo (IMAP) |
| `pagos.vscreens@inverpave.com` | Facturación y pagos |
| `privacidad.vscreens@inverpave.com` | Privacidad y protección de datos |
| `seguridad.vscreens@inverpave.com` | Incidentes de seguridad |

Las contraseñas están en el servidor, con permisos restringidos:

- `/opt/vscreens/keystores/mailboxes.txt` (buzones nuevos)
- `/opt/vscreens/mail.env` y `/opt/vscreens/.env` (`MAIL_USER`,
  `MAIL_PASSWORD`, `MAIL_SUPPORT_USER`, `MAIL_SUPPORT_PASSWORD`)

Para verlas:

```bash
ssh root@37.60.236.245
cat /opt/vscreens/keystores/mailboxes.txt
grep -E '^MAIL_(USER|PASSWORD|SUPPORT_USER|SUPPORT_PASSWORD)=' /opt/vscreens/.env
```

No se deben copiar a chats, correos ni repositorios.

### 3.2 Ajustes para cualquier cliente de correo

| Ajuste | Valor |
|--------|-------|
| Servidor IMAP | `smtp.inverpave.com` |
| Puerto IMAP | `993` |
| Seguridad IMAP | SSL/TLS |
| Servidor SMTP | `smtp.inverpave.com` |
| Puerto SMTP | `587` |
| Seguridad SMTP | STARTTLS |
| Usuario | el buzón completo, p. ej. `info.vscreens@inverpave.com` |
| Contraseña | la del buzón |

`mail.inverpave.com` e `imap.inverpave.com` resuelven por el comodín y pasan por
Cloudflare, por lo que **no sirven para IMAP**. Usar siempre
`smtp.inverpave.com` (DNS only).

### 3.3 Webmail

Roundcube está publicado en:

**<https://webmail.inverpave.com>**

Se entra con el buzón completo y su contraseña. Sirve para revisar los buzones
sin configurar un cliente y para comprobar entregas.

### 3.4 Configurar un cliente (ejemplos)

**Thunderbird**

1. **Account Settings → Account Actions → Add Mail Account**.
2. Nombre, el correo y la contraseña → **Continue**.
3. Si la autodetección falla, elegir **Manual config**:
   - IMAP: `smtp.inverpave.com`, `993`, SSL/TLS, autenticación normal.
   - SMTP: `smtp.inverpave.com`, `587`, STARTTLS, autenticación normal.
4. Usuario: el correo completo en ambos casos.

**Gmail (Android/iOS)**

1. Ajustes → **Añadir cuenta → Otro**.
2. Introducir el correo → **Configuración manual → IMAP**.
3. Contraseña → servidor IMAP `smtp.inverpave.com`, puerto `993`, SSL/TLS.
4. SMTP `smtp.inverpave.com`, puerto `587`, STARTTLS.

**Apple Mail**

1. **Ajustes → Correo → Cuentas → Añadir cuenta → Otra cuenta de correo**.
2. Correo y contraseña → elegir **IMAP**.
3. Servidor entrante y saliente: `smtp.inverpave.com`; activar SSL en ambos.

**Outlook**

1. **Archivo → Agregar cuenta → Configuración manual**.
2. **POP o IMAP** → IMAP `smtp.inverpave.com:993` SSL.
3. SMTP `smtp.inverpave.com:587` STARTTLS.

### 3.5 Odoo (ya configurado)

- **Servidor saliente**: `VScreens SMTP`, `smtp.inverpave.com:587`, STARTTLS,
  usuario `info.vscreens@inverpave.com`, activo.
- **Fetchmail**: `VScreenS Soporte IMAP`, `smtp.inverpave.com:993`, SSL,
  buzón `soporte.vscreens@inverpave.com`, activo. Los correos entrantes crean
  tickets de helpdesk.
- Enviar un correo de prueba desde **Ajustes → Técnico → Correo → Servidores
  salientes → Probar conexión**.

Firma DKIM comprobada: `d=inverpave.com`, selector `mail`.

### 3.6 Verificar entrega y autenticación

Desde el servidor:

```bash
# IMAP de cada buzón
python3 - <<'PY'
import imaplib
for user, pw in [("info.vscreens@inverpave.com", "PASSWORD")]:
    m = imaplib.IMAP4_SSL("smtp.inverpave.com", 993, timeout=15)
    m.login(user, pw)
    print(user, "IMAP OK")
    m.logout()
PY
```

```bash
# SMTP con STARTTLS
python3 - <<'PY'
import smtplib
s = smtplib.SMTP("smtp.inverpave.com", 587, timeout=15)
s.starttls()
s.login("info.vscreens@inverpave.com", "PASSWORD")
print("SMTP OK")
s.quit()
PY
```

Para revisar SPF/DKIM/DMARC de un correo recibido, abrir el mensaje completo en
Roundcube o Thunderbird y buscar `Authentication-Results`. Debe incluir
`spf=pass`, `dkim=pass` y `dmarc=pass`.

### 3.7 Endurecer DMARC (opcional, tras 2–4 semanas de tráfico)

El registro actual es `p=none` (solo observación). Cuando los informes confirmen
que todo el correo legítimo pasa SPF y DKIM, cambiar en Cloudflare (zona
`inverpave.com`) el TXT `_dmarc` a:

```
v=DMARC1; p=quarantine; rua=mailto:postmaster@inverpave.com; adkim=s; aspf=s; pct=100
```

Más adelante se puede subir a `p=reject`. No hacerlo el mismo día: primero
observar.

### 3.8 Buenas prácticas

- No reutilizar la contraseña de `info.vscreens` en otros servicios.
- Rotar contraseñas si se compartieron por chat o correo.
- Mantener `smtp.inverpave.com` en DNS only.
- No publicar `mailboxes.txt` ni `mail.env`.
- Copia de seguridad: los buzones están en `/var/mail/vhosts/inverpave.com/` y
  deben incluirse en el respaldo del servidor de correo.

---

## 4. Datos pendientes para cerrar el sitio legal

La landing ya tiene publicadas las páginas:

- `/aviso-legal`
- `/terminos`
- `/privacidad`
- `/cookies`
- `/devoluciones`
- `/seguridad`

Faltan cuatro datos del titular en `frontend-landing/src/config/site.js`:

| Campo | Valor actual |
|-------|--------------|
| `rif` | `[COMPLETAR RIF]` |
| `address` | `[COMPLETAR DOMICILIO FISCAL]` |
| `phone` | `[COMPLETAR TELÉFONO]` |
| `whatsapp` | `[COMPLETAR WHATSAPP]` |

En cuanto se confirmen, se reemplazan, se reconstruye el contenedor de la landing
y se verifica que las seis páginas siguen devolviendo `200`.

---

## 5. Checklist rápido

- [ ] SSL/TLS de `inverpave.com` en **Full (strict)** y Always Use HTTPS.
- [ ] Reglas de caché *bypass* para API y paneles.
- [ ] Redirect Rules 301 para `screens.venrides.com` y `tv.venrides.com`.
- [ ] Verificar los seis dominios VScreenS + webmail con `curl`.
- [ ] Probar IMAP/SMTP de `info.vscreens` y `soporte.vscreens`.
- [ ] Enviar correo de prueba desde Odoo y confirmar `dkim=pass`.
- [ ] Confirmar RIF, domicilio fiscal, teléfono y WhatsApp.
- [ ] (Opcional) subir DMARC a `quarantine` tras dos semanas.
