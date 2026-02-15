from datetime import datetime
from typing import List, Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func, select
from sqlalchemy.ext.hybrid import hybrid_property

class Base(DeclarativeBase):
    pass

class Company(Base):
    __tablename__ = "companies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    
    # Branding
    layout_type = Column(String, default="layout-a")
    primary_color = Column(String, default="#1a202c")
    secondary_color = Column(String, default="#2d3748")
    accent_color = Column(String, default="#4a5568")
    logo_url = Column(String, nullable=True)
    video_source = Column(String, default="youtube") # 'youtube' or 'drive'
    
    # Contenido Dinámico
    filler_keywords = Column(String, default="nature, coffee")
    google_drive_link = Column(String, nullable=True)
    priority_content_url = Column(String, nullable=True)
    video_playlist = Column(JSON, default=lambda: []) # ["url1", "url2", ...]
    sidebar_content = Column(JSON, default=lambda: []) # [{type: 'text'|'image', value: '...', duration: 5}]
    bottom_bar_content = Column(JSON, default=lambda: {}) # {static: '...', ticker: ['...']}
    design_settings = Column(JSON, default=lambda: {"sidebar_width": 22, "bottom_bar_height": 10, "show_bcv": True}) 
    pause_duration = Column(Integer, default=10) # Minutos
    ad_frequency = Column(Integer, default=30) # Segundos entre anuncios (Drive)
    
    # Membresía y Planes
    plan = Column(String, default="free") # free, basic, plus, ultra
    max_screens = Column(Integer, default=2) # Free: 2, Basic: 5, Plus: 10, Ultra: 20
    
    # Control de Edición (One-time use logic)
    can_edit_profile = Column(Boolean, default=False)
    has_edited_profile = Column(Boolean, default=False)

    # Sidebar Header Extension
    sidebar_header_type = Column(String, default="text") # text | banner
    sidebar_header_value = Column(String, nullable=True)
    
    # Control Maestro
    is_active = Column(Boolean, default=True, server_default="true")
    valid_until = Column(DateTime(timezone=True), nullable=True)
    
    # Información de Negocio
    rif = Column(String, nullable=True)
    address = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    whatsapp = Column(String, nullable=True)
    instagram = Column(String, nullable=True)
    facebook = Column(String, nullable=True)
    tiktok = Column(String, nullable=True)
    contact_person = Column(String, nullable=True)
    email = Column(String, nullable=True)
    
    # Permisos
    client_editable_fields = Column(String, default="")
    first_screen_connected_at = Column(DateTime(timezone=True), nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # CRM & Automation Settings
    birthday = Column(DateTime(timezone=True), nullable=True)
    is_email_verified = Column(Boolean, default=False)
    is_phone_verified = Column(Boolean, default=False)
    email_verification_code = Column(String, nullable=True)
    
    # Toggle individual auto-notifications
    # e.g., {"welcome": true, "expiry_7": true, "expiry_1": true, "birthday": false}
    auto_notification_settings = Column(JSON, default=lambda: {
        "welcome": True,
        "billing": True,
        "expiry_reminders": True,
        "birthday_greetings": True,
        "holiday_greetings": True
    })

    @hybrid_property
    def total_screens(self):
        return len(self.devices)

    @hybrid_property
    def active_screens(self):
        return len([d for d in self.devices if d.is_active])

    # Relaciones
    users = relationship("User", back_populates="company", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="company", cascade="all, delete-orphan")
    payments = relationship("Payment", back_populates="company", cascade="all, delete-orphan")
    menus = relationship("Menu", back_populates="company", cascade="all, delete-orphan")
    free_plan_usages = relationship("FreePlanUsage", back_populates="company", cascade="all, delete-orphan")
    messages = relationship("Message", back_populates="company", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=True)
    username = Column(String, unique=True, index=True) # Will store email
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False) # Legacy field, will keep for stability
    role = Column(String, default="operador_empresa") # admin_master, operador_master, admin_empresa, operador_empresa
    permissions = Column(JSON, default=lambda: {}) # For granular access
    is_active = Column(Boolean, default=True)

    # Password Recovery
    temp_password = Column(String, nullable=True)
    must_change_password = Column(Boolean, default=False)
    
    company = relationship("Company", back_populates="users")
    tickets = relationship("SupportTicket", back_populates="user", cascade="all, delete-orphan")

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String, unique=True, index=True)
    name = Column(String)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"))
    last_ping = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True) # New Phase 9
    
    company = relationship("Company", back_populates="devices")

class Payment(Base):
    __tablename__ = "payments"
    
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"))
    amount = Column(Float)
    currency = Column(String, default="USD")
    payment_method = Column(String)
    description = Column(String, nullable=True)
    payment_date = Column(DateTime(timezone=True), server_default=func.now())
    
    company = relationship("Company", back_populates="payments")

class Menu(Base):
    __tablename__ = "menus"
    
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"))
    name = Column(String)
    price = Column(Float)
    category = Column(String)
    is_available = Column(Boolean, default=True)
    
    company = relationship("Company", back_populates="menus")

class FreePlanUsage(Base):
    __tablename__ = "free_plan_usages"
    
    uuid = Column(String, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=True) # First company that used it
    used_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    company = relationship("Company", back_populates="free_plan_usages")

class RegistrationCode(Base):
    __tablename__ = "registration_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"))
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    company = relationship("Company")

class GlobalAd(Base):
    __tablename__ = "global_ads"
    id = Column(Integer, primary_key=True, index=True)
    video_url = Column(String, nullable=True) # Deprecated
    video_playlist = Column(JSON, default=lambda: []) # List of YouTube/Video URLs
    ticker_text = Column(String, nullable=True) # Deprecated, use ticker_messages
    ticker_messages = Column(JSON, default=lambda: []) # List of strings [msg1, msg2]
    ad_scripts = Column(JSON, default=lambda: []) # List of script snippets/embed codes
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    receiver_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=True)
    subject = Column(String)
    body = Column(String)
    attachment_url = Column(String, nullable=True)
    is_read = Column(Boolean, default=False)
    is_alert = Column(Boolean, default=False)
    alert_duration = Column(Integer, default=15) # Segundos a mostrar en TV
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    company = relationship("Company", back_populates="messages")
    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

class EmailTemplate(Base):
    __tablename__ = "email_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True) # e.g., 'cobro_vencimiento', 'aviso_mantenimiento'
    subject = Column(String)
    body = Column(String) # HTML content
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ChatThread(Base):
    """
    Tracks Gmail thread metadata for internal chat
    Does NOT store email content, only references to Gmail threads
    """
    __tablename__ = "chat_threads"
    
    id = Column(Integer, primary_key=True, index=True)
    gmail_thread_id = Column(String, unique=True, index=True)  # Gmail thread ID
    participant_1_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    participant_2_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    last_message_at = Column(DateTime(timezone=True))
    last_subject = Column(String, nullable=True)  # Cache for display
    is_read_by_1 = Column(Boolean, default=True)  # Read status for participant 1
    is_read_by_2 = Column(Boolean, default=True)  # Read status for participant 2
    is_hidden_by_1 = Column(Boolean, default=False) # Soft delete for participant 1
    is_hidden_by_2 = Column(Boolean, default=False) # Soft delete for participant 2
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    participant_1 = relationship("User", foreign_keys=[participant_1_id])
    participant_2 = relationship("User", foreign_keys=[participant_2_id])

# --- Phase 10 Models ---

class BlockedUser(Base):
    __tablename__ = "blocked_users"
    
    id = Column(Integer, primary_key=True, index=True)
    blocker_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    blocked_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    reason = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    blocker = relationship("User", foreign_keys=[blocker_id])
    blocked = relationship("User", foreign_keys=[blocked_id])

class SupportTicket(Base):
    __tablename__ = "support_tickets"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE")) # Creator
    category = Column(String) # technical, billing, general
    priority = Column(String, default="normal") # low, normal, high, urgent
    status = Column(String, default="open") # open, in_progress, resolved, closed
    subject = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())
    
    user = relationship("User", back_populates="tickets")
    messages = relationship("TicketMessage", back_populates="ticket", cascade="all, delete-orphan")

class TicketMessage(Base):
    __tablename__ = "ticket_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(Integer, ForeignKey("support_tickets.id", ondelete="CASCADE"))
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True) # Admin or User
    body = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_internal = Column(Boolean, default=False) # Helper notes for admins
    
    ticket = relationship("SupportTicket", back_populates="messages")
    sender = relationship("User")

# Update User relationships (monkey-patch style for now or manual update below)
# Note: Since User is defined above, we can't easily add relationships inside the class definition 
# without rewriting the whole class or using assignment. 
# Ideally, we should add `tickets = relationship("SupportTicket", ...)` inside User class.
# I will use replace_file_content to add it to User class as well in a separate or same call? 
# I can do it in a separate call or try to add it here if I am editing the whole file. 
# I am editing the end of file. I will just add the classes here.
# For User.tickets relationship, I'll need to update User class definition.

# --- Phase 13 CRM & Marketing Models ---

class Promotion(Base):
    __tablename__ = "promotions"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String, nullable=True)
    code = Column(String, unique=True, index=True)
    discount_pct = Column(Float, default=0.0)
    valid_from = Column(DateTime(timezone=True))
    valid_to = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Affiliate(Base):
    __tablename__ = "affiliates"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True)
    code = Column(String, unique=True, index=True)
    commission_pct = Column(Float, default=10.0)
    total_referred = Column(Integer, default=0)
    total_earned = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class CalendarActivity(Base):
    __tablename__ = "calendar_activities"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String, nullable=True)
    activity_date = Column(DateTime(timezone=True))
    is_holiday = Column(Boolean, default=False)
    send_auto_greeting = Column(Boolean, default=False)
    greeting_template_id = Column(Integer, ForeignKey("email_templates.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
