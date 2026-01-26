import asyncio
from sqlalchemy import text
from db_config import engine

async def fix_database():
    async with engine.begin() as conn:
        print("Adding 'video_source' column to 'companies' table...")
        await conn.execute(text("ALTER TABLE companies ADD COLUMN IF NOT EXISTS video_source VARCHAR DEFAULT 'youtube'"))
        
        print("Deleting orphaned company ID 1...")
        await conn.execute(text("DELETE FROM companies WHERE id = 1"))
        
        print("Database fixed successfully.")

if __name__ == "__main__":
    asyncio.run(fix_database())
