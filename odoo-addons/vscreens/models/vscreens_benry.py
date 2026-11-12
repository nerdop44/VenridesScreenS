import logging
import re

from odoo import api, fields, models

_logger = logging.getLogger(__name__)

FEATURES = [
    "Dashboard administrativo completo",
    "Gestión de branding personalizado (colores, logos, fuentes)",
    "Reproductor de video (YouTube y Google Drive)",
    "Sidebar con contenido rotativo (texto e imágenes)",
    "Barra inferior con ticker de noticias",
    "Integración de tasa BCV en tiempo real",
    "Sistema de alertas en vivo",
    "Gestión multi-pantalla",
    "Soporte técnico integrado (Helpdesk)",
    "Chat interno entre usuarios",
    "Aplicación Android TV dedicada",
]

FAQ = {
    "que_es": (
        "VScreenS es una plataforma SaaS de gestión de pantallas inteligentes para negocios. "
        "Permite gestionar contenido visual (videos, imágenes, tickers, menús) en Smart TVs "
        "desde un panel administrativo web. 📺"
    ),
    "como_funciona": (
        "Es muy sencillo:\n\n"
        "1️⃣ Elige un plan en nuestra web\n"
        "2️⃣ Recibe tus credenciales por email\n"
        "3️⃣ Descarga la app en tu Smart TV\n"
        "4️⃣ Vincula tu pantalla con un código\n"
        "5️⃣ ¡Personaliza tu contenido desde el panel!"
    ),
    "soporte": (
        "Puedes contactar soporte de varias formas:\n\n"
        "📧 Email: info.vscreens@inverpave.com\n"
        "💬 Chat de soporte integrado en el panel admin\n"
        "🎫 Sistema de tickets (Helpdesk) desde tu cuenta"
    ),
    "dispositivos": (
        "VScreenS funciona con:\n\n"
        "📺 **Smart TVs Android** — Nuestra app dedicada\n"
        "🖥️ **Cualquier pantalla con Android TV Box**\n"
        "💻 **Navegador web** — Para gestión desde el panel admin"
    ),
}

INTENT_PATTERNS = {
    "saludo": r"\b(hola|hello|hi|hey|buenas?|buenos?\s*(?:días|tardes|noches)|saludos|qué\s*tal)\b",
    "despedida": r"\b(adi[oó]s|bye|chao|hasta\s*luego|nos\s*vemos|gracias.*adiós)\b",
    "planes": r"\b(plan(?:es)?|precio|precios|cuánto\s*cuesta|costos?|tarifas?|cuanto.*vale|cuanto.*cuesta|mensual|pagar)\b",
    "free": r"\b(gratis|free|prueba|trial|gratuito|gratuita|sin\s*costo|probar)\b",
    "contratar": r"\b(contratar|comprar|adquirir|suscrib|registr|quiero\s*(?:el|un|empezar)|comenzar|inscrib|activar)\b",
    "que_es": r"\b(qué\s*es|qu[eé]\s*(?:es|hace)|para\s*qué\s*sirve|de\s*qué\s*se\s*trata|explíca|cuéntame|info(?:rmación)?(?:\s*sobre)?)\b",
    "como_funciona": r"\b(c[oó]mo\s*funciona|c[oó]mo\s*(?:se\s*)?usa|c[oó]mo\s*empiezo|pasos|procedimiento|proceso)\b",
    "features": r"\b(caracter[ií]sticas|funcionalidades|features|qué\s*(?:puedo|ofrece|incluye)|ventajas|beneficios)\b",
    "soporte": r"\b(soporte|ayuda|problema|error|no\s*funciona|bug|falla|técnico|asistencia)\b",
    "demo": r"\b(demo|demostración|mostrar|enseñar|ver\s*en\s*acción|presentación)\b",
    "dispositivos": r"\b(dispositivos?|tv|smart\s*tv|pantalla|televisor|android\s*tv|compatible|qué\s*tv)\b",
    "contacto": r"\b(contacto|contactar|teléfono|email|correo|escribir|llamar|comunicar)\b",
    "humano": r"\b(humano|persona\s*real|asesor|agente|hablar\s*con\s*alguien|representante|vendedor)\b",
    "gracias": r"\b(gracias|thank|genial|excelente|perfecto|super|buenísimo|vale|ok\b|entendido)\b",
    "negocio": r"\b(restaurante|hotel|tienda|comercio|negocio|empresa|oficina|consultorio|clínica|bar|café|gym|gimnasio|peluquería)\b",
}


def detect_intents(text):
    text_lower = (text or "").lower().strip()
    intents = [intent for intent, pattern in INTENT_PATTERNS.items() if re.search(pattern, text_lower, re.IGNORECASE)]
    return intents or ["unknown"]


class VscreensBenry(models.AbstractModel):
    _name = "vscreens.benry"
    _description = "Motor de reglas de Benry para VScreenS"

    @api.model
    def _plans_table(self):
        plans = self.env["vscreens.plan"].sudo().search([("active", "=", True), ("is_public", "=", True)], order="sequence, id")
        lines = ["📋 **Nuestros Planes:**\n"]
        for plan in plans:
            if plan.is_custom:
                price = "Personalizado"
            else:
                price = f"${plan.monthly_price:g}/mes"
            screens = "Ilimitadas" if plan.max_screens == 0 else f"{plan.max_screens}"
            lines.append(f"• **{plan.name}** — {screens} pantallas — {price}")
        lines.append("\n¿Cuál te interesa? Te puedo dar más detalles de cualquiera 😊")
        return "\n".join(lines)

    @api.model
    def _features(self):
        lines = ["✨ **VScreenS incluye:**\n"]
        lines.extend(f"• {feature}" for feature in FEATURES)
        lines.append("\n¿Quieres saber más sobre alguna función en particular?")
        return "\n".join(lines)

    @api.model
    def _generate_response(self, intents, user_msg):
        if "humano" in intents:
            return (
                "¡Por supuesto! 🙋 Un asesor humano se pondrá en contacto contigo muy pronto.\n\n"
                "Mientras tanto, puedes escribirnos a:\n"
                "📧 info.vscreens@inverpave.com\n\n"
                "¿Hay algo más en lo que pueda ayudarte?",
                None,
                True,
            )
        if "saludo" in intents and len(intents) == 1:
            return (
                "¡Hola! 👋 Soy **Benry**, el asistente de VScreenS.\n\n"
                "¿En qué puedo ayudarte hoy?\n\n"
                "🚀 Conocer nuestros **planes**\n"
                "✨ Ver las **características**\n"
                "📅 Agendar una **demo**\n"
                "❓ **Preguntas** generales",
                None,
                False,
            )
        if "despedida" in intents:
            return (
                "¡Hasta luego! 👋 Fue un placer atenderte. Si necesitas algo más, aquí estaré.\n\n"
                "📧 info.vscreens@inverpave.com\n"
                "🌐 vscreens.inverpave.com",
                None,
                False,
            )
        if "gracias" in intents and len(intents) == 1:
            return (
                "¡Con mucho gusto! 😊 Si necesitas algo más, no dudes en preguntar.\n\n"
                "Recuerda que puedes probar VScreenS **gratis por 7 días** 🚀",
                None,
                False,
            )
        if "contratar" in intents:
            if "free" in intents:
                return (
                    "¡Genial! 🎉 Para comenzar tu **prueba gratuita de 7 días** solo necesitas:\n\n"
                    "1️⃣ Ir a nuestra web y registrarte\n"
                    "2️⃣ Recibirás tus credenciales por email\n"
                    "3️⃣ Descarga la app en tu Smart TV\n\n"
                    "¿Quieres que un asesor te guíe en el proceso? 🙋",
                    "venta",
                    False,
                )
            return (
                "¡Excelente decisión! 🚀 Para activar tu cuenta necesitamos:\n\n"
                "📝 **Nombre completo**\n"
                "📧 **Email**\n"
                "📱 **Teléfono**\n"
                "🏢 **Nombre de tu empresa**\n\n"
                "Puedes completar el formulario en nuestra web o un asesor puede ayudarte directamente. ¿Qué prefieres?",
                "venta",
                False,
            )
        if "planes" in intents or "free" in intents:
            return self._plans_table(), None, False
        if "que_es" in intents:
            return FAQ["que_es"], None, False
        if "como_funciona" in intents:
            return FAQ["como_funciona"], None, False
        if "features" in intents:
            return self._features(), None, False
        if "soporte" in intents:
            return FAQ["soporte"], "soporte", False
        if "demo" in intents:
            return (
                "¡Con gusto! 📅 Podemos agendar una demo personalizada para mostrarte toda la plataforma.\n\n"
                "Para coordinarla necesitamos:\n"
                "• Tu nombre\n"
                "• Email de contacto\n"
                "• Tipo de negocio\n"
                "• Horario de preferencia\n\n"
                "¿Me puedes compartir esos datos? O si prefieres, un asesor te contactará directamente 🙋",
                "demo",
                False,
            )
        if "dispositivos" in intents:
            return FAQ["dispositivos"], None, False
        if "contacto" in intents:
            return FAQ["soporte"], None, False
        if "negocio" in intents:
            return (
                "¡Genial! VScreenS es perfecto para tu tipo de negocio. 🏢\n\n"
                "Muchos de nuestros clientes lo usan para:\n"
                "• Mostrar menús y promociones\n"
                "• Publicar horarios y eventos\n"
                "• Mostrar la tasa del día (BCV)\n"
                "• Rotar contenido visual atractivo\n\n"
                "¿Te gustaría ver nuestros **planes** o agendar una **demo**?",
                None,
                False,
            )
        if "saludo" in intents:
            others = [intent for intent in intents if intent != "saludo"]
            if others:
                return self._generate_response(others, user_msg)
        return (
            "Gracias por tu mensaje 😊 Puedo ayudarte con:\n\n"
            "📋 **Planes y precios** — Escribe \"planes\"\n"
            "✨ **Características** — Escribe \"funcionalidades\"\n"
            "📅 **Agendar demo** — Escribe \"demo\"\n"
            "❓ **Qué es VScreenS** — Escribe \"qué es\"\n"
            "🙋 **Hablar con un asesor** — Escribe \"asesor\"\n\n"
            "¿En qué te puedo ayudar?",
            None,
            False,
        )

    @api.model
    def chat(self, session_id, message, company=None):
        session = self.env["vscreens.benry.session"].sudo().search([("session_id", "=", session_id)], limit=1)
        if not session:
            session = self.env["vscreens.benry.session"].sudo().create({
                "session_id": session_id,
                "company_id": company.id if company else False,
            })
        self.env["vscreens.benry.message"].sudo().create({
            "session_id": session_id,
            "role": "user",
            "body": message or "",
        })
        intents = detect_intents(message)
        response, lead_type, needs_handoff = self._generate_response(intents, message)
        self.env["vscreens.benry.message"].sudo().create({
            "session_id": session_id,
            "role": "assistant",
            "body": response,
        })
        session.sudo().write({
            "last_message_at": fields.Datetime.now(),
            "summary": self.summary(session_id),
            "needs_handoff": needs_handoff,
            "lead_type": lead_type or "",
        })
        if needs_handoff:
            self._notify_handoff(session_id, message)
        return {
            "response": response,
            "needs_handoff": needs_handoff,
            "lead_type": lead_type,
            "session_id": session_id,
        }

    @api.model
    def summary(self, session_id):
        messages = self.env["vscreens.benry.message"].sudo().search(
            [("session_id", "=", session_id)], order="create_date desc", limit=6
        )
        lines = []
        for msg in reversed(messages):
            role = "Cliente" if msg.role == "user" else "Benry"
            lines.append(f"{role}: {(msg.body or '')[:120]}")
        return "\n".join(lines)

    @api.model
    def _notify_handoff(self, session_id, message):
        try:
            master = self.env["res.users"].sudo().search(
                [("group_ids", "in", self.env.ref("vscreens.group_vscreens_master").id)], limit=1
            )
            if master:
                self.env["vscreens.message"].sudo().create({
                    "sender_id": False,
                    "receiver_id": master.id,
                    "session_id": session_id,
                    "subject": "Soporte Benry: atención requerida",
                    "body": f"Cliente esperando atención.\n\nRESUMEN:\n{self.summary(session_id)}",
                    "is_alert": True,
                })
            email_to = self.env["ir.config_parameter"].sudo().get_str(
                "vscreens.notification_email", "info.vscreens@inverpave.com"
            )
            self.env["mail.mail"].sudo().create({
                "subject": f"SOPORTE: Cliente esperando ({session_id[:8]})",
                "body_html": f"<p>Cliente esperando atención.</p><pre>{self.summary(session_id)}</pre>",
                "email_to": email_to,
                "email_from": email_to,
            }).send()
        except Exception as exc:
            _logger.warning("No se pudo notificar el handoff de Benry: %s", exc)

    @api.model
    def clear_session(self, session_id):
        self.env["vscreens.benry.message"].sudo().search([("session_id", "=", session_id)]).unlink()
        self.env["vscreens.benry.session"].sudo().search([("session_id", "=", session_id)]).unlink()
        return True
