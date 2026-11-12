
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text, inspect
import os

# Database Config
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://vscreens_user:CHANGE_ME_DB_PASSWORD@localhost:5433/vscreens_db")

async def check_integrity():
    print(f"🔍 Checking Database Integrity on {DATABASE_URL}...")
    try:
        engine = create_async_engine(DATABASE_URL)
        async with engine.connect() as conn:
            # Check connection
            await conn.execute(text("SELECT 1"))
            print("✅ Database Connection: OK")
            
            # Check Tables
            tables_res = await conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"))
            tables = [row[0] for row in tables_res]
            print(f"📋 Tables found: {tables}")
            
            # Check for Phase 9 Columns (Devices)
            if 'devices' in tables:
                cols_res = await conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'devices'"))
                cols = [row[0] for row in cols_res]
                if 'is_active' in cols:
                    print("✅ Devices Table: 'is_active' column PRESENT")
                else:
                    print("⚠️  Devices Table: 'is_active' column MISSING (Pending Migration)")
            
            # Check Query Performance (Basic)
            await conn.execute(text("SELECT count(*) FROM companies"))
            print("✅ Basic Query Test: OK")

    except Exception as e:
        print(f"❌ Database Error: {e}")
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(check_integrity())
