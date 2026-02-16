import logging
import re
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from models import EmailTemplate

logger = logging.getLogger("VenrideScreenS.TemplateService")

class TemplateService:
    """Service to manage and render dynamic HTML email templates"""

    DEFAULT_TEMPLATES = {
        "welcome_verification": { # Used for Auth flow
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
        "welcome_crm": { # New Welcome to CRM
            "subject": "¡Bienvenido a VenridesScreenS! 📺",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <h1 style="color: #3b82f6;">Hola {{contacto}} de {{nombre_empresa}}</h1>
                    <p>Es un placer darte la bienvenida a <strong>VenridesScreenS</strong>.</p>
                    <p>Con nuestra plataforma podrás gestionar tus pantallas, programar contenido y monetizar tu audiencia de manera sencilla.</p>
                    <p>Si tienes dudas, nuestro equipo de soporte está listo para ayudarte: <a href="https://wa.me/584120000000">Contactar Soporte</a></p>
                </div>
            """
        },
        "sales_proposal": { # New Sales Proposal
            "subject": "Propuesta Comercial para {{nombre_empresa}} 📊",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <h2 style="color: #10b981;">Potencia tu marca con VenridesScreenS</h2>
                    <p>Estimado/a {{contacto}},</p>
                    <p>Hemos analizado el potencial de {{nombre_empresa}} y creemos que nuestras soluciones de Digital Signage pueden aumentar tus ventas significativamente.</p>
                    <p><strong>Beneficios:</strong></p>
                    <ul>
                        <li>Control total de tu contenido en remoto.</li>
                        <li>Posibilidad de vender espacios publicitarios.</li>
                        <li>Integración con redes sociales.</li>
                    </ul>
                    <p>Quedo atento para agendar una demo.</p>
                </div>
            """
        },
        "follow_up": { # New Follow Up
            "subject": "¿Sigues interesado en modernizar tus pantallas? 🤔",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <p>Hola {{contacto}},</p>
                    <p>Hace unos días conversamos sobre cómo VenridesScreenS puede ayudar a {{nombre_empresa}}.</p>
                    <p>¿Tienes alguna duda o te gustaría ver una demostración en vivo?</p>
                    <p>Responde a este correo y coordinamos.</p>
                </div>
            """
        },
        "recovery": { # New Recovery
            "subject": "¡Te extrañamos en VenridesScreenS! 💔",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <h2 style="color: #f43f5e;">{{contacto}}, queremos que vuelvas</h2>
                    <p>Notamos que tu cuenta de {{nombre_empresa}} está inactiva.</p>
                    <p>Hemos mejorado nuestra plataforma con nuevas funciones de Inteligencia Artificial.</p>
                    <p><strong>Oferta de Regreso:</strong> Usa el código <code>COMEBACK20</code> para un 20% de descuento en tu reactivación.</p>
                </div>
            """
        },
        "apk_download": {
            "subject": "Tu App VenridesScreenS para Smart TV 📺",
            "body": """
                <div style="font-family: sans-serif; padding: 20px; color: #1a202c;">
                    <h1 style="color: #10b981;">¡Pago Verificado!</h1>
                    <p>Hola {{contacto}}, ya puedes instalar VenridesScreenS en tu Smart TV.</p>
                    <p><strong>Pasos para instalar:</strong></p>
                    <ol>
                        <li>Instala la app 'Downloader' en tu TV (Android TV / Google TV / Fire TV).</li>
                        <li>Abre Downloader e ingresa uno de los siguientes:</li>
                        <ul>
                            <li>Código: <strong>8744763</strong></li>
                            <li>URL Corta: <code>http://aftv.news/8744763</code></li>
                            <li>URL Directa: <code>https://screens.venrides.com/tv-app</code></li>
                        </ul>
                        <li>Instala y abre la App.</li>
                        <li>Verás un código de 6 dígitos en la pantalla.</li>
                        <li>Ingresa ese código en tu Panel Administrativo -> "Vincular Pantalla".</li>
                    </ol>
                </div>
            """
        },
        "payment_confirmation": {
            "subject": "Confirmación de Pago - VenridesScreenS ✅",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <h2>Hemos recibido tu pago</h2>
                    <p>Estimado/a {{contacto}},</p>
                    <p>Confirmamos la recepción de tu pago para la cuenta de <strong>{{nombre_empresa}}</strong>.</p>
                    <ul>
                        <li>Monto: {{monto_pago}}</li>
                        <li>Fecha: {{fecha_hoy}}</li>
                        <li>Estado: <strong>Validado Exitosamente</strong></li>
                    </ul>
                    <p>Gracias por tu preferencia.</p>
                </div>
            """
        },
        "payment_instructions": { # New Payment Instructions
            "subject": "Instrucciones de Pago y Validación 💰",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <h2>Datos Bancarios - VenridesScreenS</h2>
                    <p>Para activar o renovar tu plan, por favor realiza el pago a:</p>
                    <div style="background: #f3f4f6; padding: 15px; border-radius: 8px;">
                        <p><strong>Banco:</strong> Banco de Venezuela</p>
                        <p><strong>Titular:</strong> Venrides C.A.</p>
                        <p><strong>RIF:</strong> J-12345678-9</p>
                        <p><strong>Cuenta:</strong> 0102-0000-00-0000000000</p>
                        <p><strong>Pago Móvil:</strong> 0412-1234567 / J-123456789</p>
                    </div>
                    <p><strong>Importante:</strong> Una vez realizado, envía el comprobante a pagos@venrides.com o súbelo en tu panel.</p>
                    <p>Tasa del día (BCV): Bs. {{bcv_rate}}</p>
                </div>
            """
        },
        "expiry_reminder": {
            "subject": "⚠️ Aviso de Vencimiento: Tu plan vence pronto",
            "body": """
                <div style="font-family: sans-serif; padding: 20px;">
                    <h2>¡Hola, {{contacto}}!</h2>
                    <p>Te recordamos que el plan <strong>{{plan}}</strong> de {{nombre_empresa}} vence el <strong>{{fecha_vencimiento}}</strong>.</p>
                    <p>Para evitar interrupciones en la transmisión de tus pantallas, por favor realiza tu renovación a tiempo.</p>
                    <p><a href="https://admintv.venrides.com/payments" style="background: #3b82f6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Renovar Ahora</a></p>
                </div>
            """
        },
        "birthday_greeting": {
            "subject": "¡Feliz Cumpleaños de parte de VenridesScreenS! 🎂",
            "body": """
                <div style="font-family: sans-serif; padding: 20px; text-align: center;">
                    <h1 style="color: #f43f5e;">¡Felicidades, {{contacto}}!</h1>
                    <p>Queremos celebrar contigo en este día especial.</p>
                    <p>Usa el cupón <strong>HBDRY20</strong> para un 20% de descuento en tu próxima renovación.</p>
                </div>
            """
        },
        "holiday_greeting": {
            "subject": "¡VenridesScreenS te desea Felices Fiestas! 🎄",
            "body": """
                <div style="font-family: sans-serif; padding: 20px; text-align: center; border: 2px solid #3b82f6; border-radius: 15px;">
                    <h1 style="color: #3b82f6;">🇻🇪 ¡Felices Fiestas!</h1>
                    <p>En esta temporada especial, queremos agradecerte por confiar en nosotros.</p>
                    <p>Deseamos prosperidad y éxito para {{nombre_empresa}} en el próximo año.</p>
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
