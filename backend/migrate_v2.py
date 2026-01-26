import asyncio
from sqlalchemy import text
from db_config import engine

async def migrate():
    async with engine.begin() as conn:
        print("Checking for missing columns...")
        # Add design_settings
        try:
            await conn.execute(text("ALTER TABLE companies ADD COLUMN design_settings JSON DEFAULT '{}';"))
            print("Added design_settings column.")
        except Exception as e:
            print(f"design_settings might already exist: {e}")

        # Add priority_content_url if missing (it was added in models.py recently)
        try:
            await conn.execute(text("ALTER TABLE companies ADD COLUMN priority_content_url VARCHAR;"))
            print("Added priority_content_url column.")
        except Exception as e:
            print(f"priority_content_url might already exist: {e}")

if __name__ == "__main__":
    asyncio.run(migrate())
