"""
Benry AI Service — VenridesScreenS Commercial Chatbot
Lightweight rule-based agent — ZERO external LLM dependencies.
Pattern matching + keyword detection + decision tree for commercial conversations.
"""
import os
import re
import json
import logging
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("VenrideScreenS.Benry")

# Notification email for human handoff
NOTIFICATION_EMAIL = os.getenv("NOTIFICATION_EMAIL", "info.venridesscreen@gmail.com")

# In-memory conversation store
_conversations = {}
MAX_CONVERSATION_LENGTH = 20

# ============================================
# Knowledge Base (External & Static)
# ============================================

BENRY_KNOWLEDGE_DOC_ID = os.getenv("BENRY_KNOWLEDGE_DOC_ID")
_kb_cache = {"content": "", "last_updated": 0}
KB_CACHE_TTL = 1800  # 30 minutes

async def fetch_knowledge_base():
    """Fetch knowledge base content from Google Doc if ID is provided"""
    import time
    from googleapiclient.discovery import build
    from google.oauth2 import service_account
    
    global _kb_cache
    now = time.time()
    
    if not BENRY_KNOWLEDGE_DOC_ID:
        return ""
        
    if now - _kb_cache["last_updated"] < KB_CACHE_TTL and _kb_cache["content"]:
        return _kb_cache["content"]
        
    try:
        creds_path = os.getenv("GOOGLE_SHEETS_CREDENTIALS_PATH")
        if not creds_path or not os.path.exists(creds_path):
            logger.warning("No credentials found for Google Docs KB")
            return ""
            
        creds = service_account.Credentials.from_service_account_file(
            creds_path, scopes=['https://www.googleapis.com/auth/documents.readonly']
        )
        service = build('docs', 'v1', credentials=creds)
        doc = service.documents().get(documentId=BENRY_KNOWLEDGE_DOC_ID).execute()
        
        # Extract text from doc structure
        full_text = ""
        for content in doc.get('body', {}).get('content', []):
            if 'paragraph' in content:
                for element in content.get('paragraph', {}).get('elements', []):
                    if 'textRun' in element:
                        full_text += element.get('textRun', {}).get('content', "")
        
        _kb_cache = {"content": full_text, "last_updated": now}
        logger.info(f"Benry KB updated from Google Doc: {BENRY_KNOWLEDGE_DOC_ID}")
        return full_text
    except Exception as e:
        logger.error(f"Error fetching Benry KB: {e}")
        return _kb_cache["content"]

def search_knowledge_base(query: str, kb_content: str) -> Optional[str]:
    """Search for relevant paragraphs in the KB content"""
    if not kb_content:
        return None
        
    # Split by paragraphs (approx)
    paragraphs = [p.strip() for p in re.split(r'\n\n+', kb_content) if len(p.strip()) > 20]
    
    # Simple semantic-ish search (keyword overlap)
    keywords = [w.lower() for w in re.findall(r'\w{4,}', query) if w.lower() not in ["hola", "benry", "venrides"]]
    
    best_match = None
    best_score = 0
    
    for p in paragraphs:
        score = 0
        p_lower = p.lower()
        for kw in keywords:
            if kw in p_lower:
                score += 1
        
        if score > best_score:
            best_score = score
            best_match = p
            
    if best_score > 0:
        return best_match
    return None


PLANS = {
    "free": {"nombre": "Free", "pantallas": "Hasta 2", "precio": "Gratis", "duracion": "7 días de prueba", "color": "#888"},
    "basico": {"nombre": "Básico", "pantallas": "Hasta 5", "precio": "$15/mes", "duracion": "Mensual", "color": "#3b82f6"},
    "plus": {"nombre": "Plus", "pantallas": "Hasta 10", "precio": "$25/mes", "duracion": "Mensual", "color": "#8b5cf6"},
    "ultra": {"nombre": "Ultra", "pantallas": "Hasta 20", "precio": "$40/mes", "duracion": "Mensual", "color": "#f59e0b"},
    "empresarial": {"nombre": "Empresarial", "pantallas": "Personalizado", "precio": "Contactar Ventas", "duracion": "Personalizado", "color": "#ef4444"},
}

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
        "VenridesScreenS es una plataforma SaaS de gestión de pantallas inteligentes para negocios. "
        "Permite gestionar contenido visual (videos, imágenes, tickers, menús) en Smart TVs desde un panel administrativo web. 📺"
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
        "📧 Email: info.venridesscreen@gmail.com\n"
        "💬 Chat de soporte integrado en el panel admin\n"
        "🎫 Sistema de tickets (Helpdesk) desde tu cuenta"
    ),
    "dispositivos": (
        "VenridesScreenS funciona con:\n\n"
        "📺 **Smart TVs Android** — Nuestra app dedicada\n"
        "🖥️ **Cualquier pantalla con Android TV Box**\n"
        "💻 **Navegador web** — Para gestión desde el panel admin"
    ),
}

# ============================================
# Intent Detection (Pattern Matching)
# ============================================

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
    """Detect all matching intents from user text"""
    text_lower = text.lower().strip()
    intents = []
    for intent, pattern in INTENT_PATTERNS.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            intents.append(intent)
    return intents if intents else ["unknown"]


# ============================================
# Response Generator
# ============================================

def format_plans_table():
    """Format plans as a readable list"""
    lines = ["📋 **Nuestros Planes:**\n"]
    for key, plan in PLANS.items():
        emoji = {"free": "🆓", "basico": "📦", "plus": "⭐", "ultra": "🚀", "empresarial": "🏢"}.get(key, "📌")
        lines.append(f"{emoji} **{plan['nombre']}** — {plan['pantallas']} pantallas — {plan['precio']}")
    lines.append("\n¿Cuál te interesa? Te puedo dar más detalles de cualquiera 😊")
    return "\n".join(lines)


def format_features():
    """Format features list"""
    lines = ["✨ **VenridesScreenS incluye:**\n"]
    for f in FEATURES:
        lines.append(f"• {f}")
    lines.append("\n¿Quieres saber más sobre alguna función en particular?")
    return "\n".join(lines)


def generate_response(intents, user_msg, conv_history):
    """Generate response based on detected intents"""
    
    lead_type = None
    needs_handoff = False
    
    # Priority-based response selection
    
    # Human handoff request — top priority
    if "humano" in intents:
        needs_handoff = True
        return (
            "¡Por supuesto! 🙋 Un asesor humano se pondrá en contacto contigo muy pronto.\n\n"
            "Mientras tanto, puedes escribirnos a:\n"
            "📧 info.venridesscreen@gmail.com\n\n"
            "¿Hay algo más en lo que pueda ayudarte?",
            None, True
        )
    
    # Greeting
    if "saludo" in intents and len(intents) == 1:
        return (
            "¡Hola! 👋 Soy **Benry**, el asistente de VenridesScreenS.\n\n"
            "¿En qué puedo ayudarte hoy?\n\n"
            "🚀 Conocer nuestros **planes**\n"
            "✨ Ver las **características**\n"
            "📅 Agendar una **demo**\n"
            "❓ **Preguntas** generales",
            None, False
        )
    
    # Farewell
    if "despedida" in intents:
        return (
            "¡Hasta luego! 👋 Fue un placer atenderte. Si necesitas algo más, aquí estaré.\n\n"
            "📧 info.venridesscreen@gmail.com\n"
            "🌐 screens.venrides.com",
            None, False
        )
    
    # Thanks
    if "gracias" in intents and len(intents) == 1:
        return (
            "¡Con mucho gusto! 😊 Si necesitas algo más, no dudes en preguntar.\n\n"
            "Recuerda que puedes probar VenridesScreenS **gratis por 7 días** 🚀",
            None, False
        )
    
    # Contract/buy intent — lead detected
    if "contratar" in intents:
        lead_type = "venta"
        if "free" in intents:
            return (
                "¡Genial! 🎉 Para comenzar tu **prueba gratuita de 7 días** solo necesitas:\n\n"
                "1️⃣ Ir a nuestra web y registrarte\n"
                "2️⃣ Recibirás tus credenciales por email\n"
                "3️⃣ Descarga la app en tu Smart TV\n\n"
                "¿Quieres que un asesor te guíe en el proceso? 🙋",
                lead_type, False
            )
        return (
            "¡Excelente decisión! 🚀 Para activar tu cuenta necesitamos:\n\n"
            "📝 **Nombre completo**\n"
            "📧 **Email**\n"
            "📱 **Teléfono**\n"
            "🏢 **Nombre de tu empresa**\n\n"
            "Puedes completar el formulario en nuestra web o un asesor puede ayudarte directamente. ¿Qué prefieres?",
            lead_type, False
        )
    
    # Plans/pricing
    if "planes" in intents or "free" in intents:
        lead_type = "venta" if "contratar" in intents else None
        return format_plans_table(), lead_type, False
    
    # What is VenridesScreenS
    if "que_es" in intents:
        return FAQ["que_es"], None, False
    
    # How it works
    if "como_funciona" in intents:
        return FAQ["como_funciona"], None, False
    
    # Features
    if "features" in intents:
        return format_features(), None, False
    
    # Support
    if "soporte" in intents:
        lead_type = "soporte"
        return FAQ["soporte"], lead_type, False
    
    # Demo
    if "demo" in intents:
        lead_type = "demo"
        return (
            "¡Con gusto! 📅 Podemos agendar una demo personalizada para mostrarte toda la plataforma.\n\n"
            "Para coordinarla necesitamos:\n"
            "• Tu nombre\n"
            "• Email de contacto\n"
            "• Tipo de negocio\n"
            "• Horario de preferencia\n\n"
            "¿Me puedes compartir esos datos? O si prefieres, un asesor te contactará directamente 🙋",
            lead_type, False
        )
    
    # Devices
    if "dispositivos" in intents:
        return FAQ["dispositivos"], None, False
    
    # Contact
    if "contacto" in intents:
        return FAQ["soporte"], None, False
    
    # Business type mentioned — opportunity
    if "negocio" in intents:
        return (
            "¡Genial! VenridesScreenS es perfecto para tu tipo de negocio. 🏢\n\n"
            "Muchos de nuestros clientes lo usan para:\n"
            "• Mostrar menús y promociones\n"
            "• Publicar horarios y eventos\n"
            "• Mostrar la tasa del día (BCV)\n"
            "• Rotar contenido visual atractivo\n\n"
            "¿Te gustaría ver nuestros **planes** o agendar una **demo**?",
            None, False
        )
    
    # Greeting + something else
    if "saludo" in intents:
        other_intents = [i for i in intents if i != "saludo"]
        if other_intents:
            # Remove saludo and re-process
            return generate_response(other_intents, user_msg, conv_history)
    
    # Unknown — guide them
    return (
        "Gracias por tu mensaje 😊 Puedo ayudarte con:\n\n"
        "📋 **Planes y precios** — Escribe \"planes\"\n"
        "✨ **Características** — Escribe \"funcionalidades\"\n"
        "📅 **Agendar demo** — Escribe \"demo\"\n"
        "❓ **Qué es VenridesScreenS** — Escribe \"qué es\"\n"
        "🙋 **Hablar con un asesor** — Escribe \"asesor\"\n\n"
        "¿En qué te puedo ayudar?",
        None, False
    )


# ============================================
# Benry AI Service Class
# ============================================

class BenryAIService:
    """Lightweight rule-based chatbot for VenridesScreenS"""

    def __init__(self):
        self._available = True  # Always available — no external dependencies

    async def check_availability(self) -> bool:
        """Always available — no external LLM needed"""
        return True

    async def chat(self, session_id: str, user_message: str) -> dict:
        """
        Process a user message and return Benry's response.
        """
        # Get or create conversation
        if session_id not in _conversations:
            _conversations[session_id] = {
                "messages": [],
                "created_at": datetime.utcnow().isoformat(),
                "lead_detected": False,
                "contact_info": {}
            }

        conv = _conversations[session_id]
        conv["messages"].append({"role": "user", "content": user_message})

        # Trim history
        if len(conv["messages"]) > MAX_CONVERSATION_LENGTH:
            conv["messages"] = conv["messages"][-MAX_CONVERSATION_LENGTH:]

        # Detect intents and generate base response
        intents = detect_intents(user_message)
        response_text, lead_type, needs_handoff = generate_response(
            intents, user_message, conv["messages"]
        )
        
        # --- Fallback: Search Knowledge Base if response is generic ---
        if response_text.startswith("Gracias por tu mensaje") or "unknown" in intents:
            kb_content = await fetch_knowledge_base()
            if kb_content:
                match = search_knowledge_base(user_message, kb_content)
                if match:
                    response_text = f"Encontré esto que te puede ayudar: \n\n{match}\n\n¿Tienes alguna otra duda? 😊"

        # Store response
        conv["messages"].append({"role": "assistant", "content": response_text})

        if lead_type:
            conv["lead_detected"] = True

        return {
            "response": response_text,
            "needs_handoff": needs_handoff,
            "lead_type": lead_type,
            "session_id": session_id
        }

    def get_conversation_summary(self, session_id: str) -> str:
        """Get a summary of the conversation for logging"""
        conv = _conversations.get(session_id)
        if not conv:
            return ""

        messages = conv.get("messages", [])
        if not messages:
            return ""

        summary_parts = []
        for msg in messages[-6:]:
            role = "Cliente" if msg["role"] == "user" else "Benry"
            summary_parts.append(f"{role}: {msg['content'][:100]}")

        return "\n".join(summary_parts)

    def clear_session(self, session_id: str):
        """Clear a conversation session"""
        if session_id in _conversations:
            del _conversations[session_id]


# Singleton
benry_service = BenryAIService()
