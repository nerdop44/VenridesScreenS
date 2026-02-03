import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

from sqlalchemy import text
from models import Base

load_dotenv()

# Check if we are running inside Docker
def get_database_url():
    # Priority 1: Environment variable
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    
    # Priority 2: Try Docker 'db' hostname
    import socket
    try:
        socket.gethostbyname('db')
        return "postgresql+asyncpg://venrides_user:venrides_password@db/venrides_db"
    except socket.gaierror:
        # Priority 3: Fallback to localhost (running on Host)
        return "postgresql+asyncpg://venrides_user:venrides_password@localhost:5433/venrides_db"

DATABASE_URL = get_database_url()

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
        
        # Post-Init Migrations
        try:
            # We use IF NOT EXISTS to avoid errors if they already exist
            # Note: PostgreSQL 9.6+ supports ADD COLUMN IF NOT EXISTS? 
            # Actually, standard ALTER TABLE ADD COLUMN doesn't have IF NOT EXISTS in all versions.
            # But we can use a try-except block or check pg_attribute.
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS design_settings JSON DEFAULT '{}';"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS priority_content_url VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS plan VARCHAR DEFAULT 'free';"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS max_screens INTEGER DEFAULT 2;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS can_edit_profile BOOLEAN DEFAULT FALSE;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS has_edited_profile BOOLEAN DEFAULT FALSE;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS sidebar_header_type VARCHAR DEFAULT 'text';"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS sidebar_header_value VARCHAR;"))
            
            # Business Profile Fields
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS rif VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS address VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS phone VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS whatsapp VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS instagram VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS facebook VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS tiktok VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS contact_person VARCHAR;"))
            await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS email VARCHAR;"))
            
            # Users Table Migrations
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR DEFAULT 'operador_empresa';"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSON DEFAULT '{}';"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS temp_password VARCHAR;"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;"))
        except Exception as e:
            print(f"Migration error: {e}")
            pass
