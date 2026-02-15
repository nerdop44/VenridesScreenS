import logging
import re
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from models import EmailTemplate

logger = logging.getLogger("VenrideScreenS.TemplateService")

class TemplateService:
    """Service to manage and render dynamic HTML email templates"""

    DEFAULT_TEMPLATES = {
        "welcome_verification": {
            "subject": "¡Bienvenido a VenridesScreenS! Verifica tu cuenta",
            "body": """
                <div style="font-family: sans-serif; padding: 20px; color: #1a202c;">
                    <h1 style="color: #3b82f6;">¡Hola, {{name}}!</h1>
                    <p>Gracias por unirte a la red más fluida de pantallas publicitarias en Venezuela.</p>
                    <p>Tu código de verificación es: <strong style="font-size: 1.5rem;">{{code}}</strong></p>
                    <p>Por favor, ingrésalo en el panel para activar tu cuenta.</p>
                </div>
            """
        },
        "apk_download": {
            "subject": "Tu App VenridesScreenS para Smart TV",
            "body": """
                <div style="font-family: sans-serif; padding: 20px; color: #1a202c;">
                    <h1 style="color: #10b981;">¡Pago Verificado!</h1>
                    <p>Ya puedes instalar VenridesScreenS en tu Smart TV.</p>
                    <p><strong>Pasos para instalar:</strong></p>
                    <ol>
                        <li>Instala la app 'Downloader' en tu TV.</li>
                        <li>Ingresa este código o URL corta: <strong>{{short_url}}</strong></li>
                        <li>¡Listo! Vincula tu pantalla con el código que aparecerá en TV.</li>
                    </ol>
                </div>
            """
        },
        "payment_confirmation": {
            "subject": "Confirmación de Pago - VenridesScreenS",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <h2>Hemos recibido tu pago</h2>
                    <p>Referencia: {{ref}}</p>
                    <p>Monto: {{amount}} {{currency}}</p>
                    <p>Estado: <strong>Validado ✅</strong></p>
                </div>
            """
        },
        "expiry_reminder": {
            "subject": "Aviso de Vencimiento: {{days}} días restantes",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <h2>¡Hola, {{name}}!</h2>
                    <p>Te recordamos que tu plan <strong>{{plan}}</strong> vence en {{days}} días.</p>
                    <p>Para evitar interrupciones en tus pantallas, realiza tu pago pronto.</p>
                    <p>Tasa del día (BCV): Bs. {{bcv_rate}}</p>
                </div>
            """
        },
        "birthday_greeting": {
            "subject": "¡Feliz Cumpleaños de parte de VenridesScreenS!",
            "body": """
                <div style="font-family: sans-serif; padding: 20px; text-align: center;">
                    <h1 style="color: #f43f5e;">🎂 ¡Felicidades, {{name}}!</h1>
                    <p>Queremos celebrar contigo. Usa el cupón <strong>HBDRY20</strong> para un 20% de descuento en tu próxima renovación.</p>
                </div>
            """
        },
        "holiday_greeting": {
            "subject": "¡VenridesScreenS te desea un feliz {{holiday_title}}!",
            "body": """
                <div style="font-family: sans-serif; padding: 20px; text-align: center; border: 2px solid #3b82f6; border-radius: 15px;">
                    <h1 style="color: #3b82f6;">🇻🇪 ¡Feliz {{holiday_title}}!</h1>
                    <p>Hoy es un día especial en Venezuela y queremos celebrarlo contigo.</p>
                    <p>Gracias por ser parte de nuestra red de pantallas.</p>
                </div>
            """
        }
    }

    def render(self, template_name: str, context: Dict[str, Any], db: Optional[Session] = None) -> Dict[str, str]:
        """
        Renders a template from database or defaults.
        Returns {'subject': '...', 'body': '...'}
        """
        subject = ""
        body = ""

        # Try to find in DB first
        if db:
            from sqlalchemy import select
            stmt = select(EmailTemplate).where(EmailTemplate.name == template_name)
            res = db.execute(stmt).scalar_one_or_none()
            if res:
                subject = res.subject
                body = res.body

        # Fallback to defaults
        if not body and template_name in self.DEFAULT_TEMPLATES:
            subject = self.DEFAULT_TEMPLATES[template_name]["subject"]
            body = self.DEFAULT_TEMPLATES[template_name]["body"]

        if not body:
            logger.warning(f"Template '{template_name}' not found.")
            return {"subject": "Aviso de VenridesScreenS", "body": "Contenido no disponible."}

        # Replace placeholders {{key}}
        for key, value in context.items():
            pattern = re.compile(f"\\{{\\{{\\s*{key}\\s*\\}}\\}}")
            subject = pattern.sub(str(value), subject)
            body = pattern.sub(str(value), body)

        return {"subject": subject, "body": body}

# Singleton
template_service = TemplateService()
