"""
Email Sender Utility
Simple SMTP client for sending emails via Gmail
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
import logging

load_dotenv()

logger = logging.getLogger("VenrideScreenS.Email")

# SMTP Configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "info.venridesscreen@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")  # Gmail App Password

def send_email(to: str, subject: str, body: str, html: bool = True) -> bool:
    """
    Send an email via SMTP
    
    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body content
        html: Whether body is HTML (default True)
    
    Returns:
        True if sent successfully, False otherwise
    """
    if not SMTP_PASSWORD:
        logger.warning("SMTP_PASSWORD not configured, email not sent")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = SMTP_USER
        msg['To'] = to
        msg['Subject'] = subject
        
        # Attach body
        mime_type = 'html' if html else 'plain'
        msg.attach(MIMEText(body, mime_type))
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Email sent successfully to {to}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {e}")
        return False

def send_password_recovery_email(to: str, temp_password: str) -> bool:
    """Send password recovery email with temporary password"""
    subject = "Recuperación de Contraseña - VenrideScreenS"
    
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <h2 style="color: #6366f1; margin-bottom: 20px;">Recuperación de Contraseña</h2>
            <p>Hola,</p>
            <p>Has solicitado recuperar tu contraseña para VenrideScreenS.</p>
            <p>Tu contraseña temporal es:</p>
            <div style="background: #f0f0f0; padding: 15px; border-radius: 5px; font-size: 18px; font-weight: bold; text-align: center; margin: 20px 0;">
                {temp_password}
            </div>
            <p><strong>Importante:</strong> Por seguridad, deberás cambiar esta contraseña temporal al iniciar sesión.</p>
            <p>Si no solicitaste este cambio, por favor ignora este correo.</p>
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
            <p style="font-size: 12px; color: #666;">
                VenrideScreenS - Sistema de Gestión de Pantallas<br>
                <a href="mailto:info.venridesscreen@gmail.com">info.venridesscreen@gmail.com</a>
            </p>
        </div>
    </body>
    </html>
    """
    
    return send_email(to, subject, body, html=True)
