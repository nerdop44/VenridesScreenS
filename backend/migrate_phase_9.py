import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import os

# Database Config
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://venrides_user:venrides_password@localhost:5433/venrides_db")

async def migrate_phase_9():
    print(f"🔄 Starting Phase 9 Migration on {DATABASE_URL}...")
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    async with engine.begin() as conn:
        print("Checking and adding columns...")
        
        # 1. Add is_active to devices
        try:
            await conn.execute(text("ALTER TABLE devices ADD COLUMN is_active BOOLEAN DEFAULT TRUE"))
            print("✅ Added column 'is_active' to 'devices'")
        except Exception as e:
            print(f"⚠️  Column 'is_active' might already exist: {e}")

        # 2. Add ticker_messages to global_ads
        try:
            await conn.execute(text("ALTER TABLE global_ads ADD COLUMN ticker_messages JSONB DEFAULT '[]'"))
            print("✅ Added column 'ticker_messages' to 'global_ads'")
        except Exception as e:
            print(f"⚠️  Column 'ticker_messages' might already exist: {e}")

        # 3. Add ad_scripts to global_ads
        try:
            await conn.execute(text("ALTER TABLE global_ads ADD COLUMN ad_scripts JSONB DEFAULT '[]'"))
            print("✅ Added column 'ad_scripts' to 'global_ads'")
        except Exception as e:
            print(f"⚠️  Column 'ad_scripts' might already exist: {e}")

    await engine.dispose()
    print("✨ Phase 9 Migration Completed!")

if __name__ == "__main__":
    asyncio.run(migrate_phase_9())
