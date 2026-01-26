from datetime import datetime
from typing import List, Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func

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
    contact_person = Column(String, nullable=True)
    email = Column(String, nullable=True)
    
    # Permisos
    client_editable_fields = Column(String, default="")
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relaciones
    users = relationship("User", back_populates="company", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="company", cascade="all, delete-orphan")
    payments = relationship("Payment", back_populates="company", cascade="all, delete-orphan")
    menus = relationship("Menu", back_populates="company", cascade="all, delete-orphan")
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

    # Password Recovery
    temp_password = Column(String, nullable=True)
    must_change_password = Column(Boolean, default=False)
    
    company = relationship("Company", back_populates="users")

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String, unique=True, index=True)
    name = Column(String)
    company_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"))
    last_ping = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
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
    video_url = Column(String, nullable=True)
    ticker_text = Column(String, nullable=True)
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    participant_1 = relationship("User", foreign_keys=[participant_1_id])
    participant_2 = relationship("User", foreign_keys=[participant_2_id])
