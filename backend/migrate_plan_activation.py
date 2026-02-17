import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://venrides_user:venrides_password@db/venrides_db")

async def migrate():
    engine = create_async_engine(DATABASE_URL)
    async with engine.begin() as conn:
        print("Checking/Adding columns for plan activation and IP tracking...")
        
        # Add plan_activated_at to companies
        await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS plan_activated_at TIMESTAMP WITH TIME ZONE"))
        
        # Add last_ip to devices
        await conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_ip VARCHAR"))
        
        # Backfill plan_activated_at for companies that already have first_screen_connected_at
        await conn.execute(text("UPDATE companies SET plan_activated_at = first_screen_connected_at WHERE plan_activated_at IS NULL AND first_screen_connected_at IS NOT NULL"))
        
        print("Migration completed successfully.")

if __name__ == "__main__":
    asyncio.run(migrate())
