import asyncio
from sqlalchemy import text
from db_config import engine

async def fix_schema():
    async with engine.begin() as conn:
        print("Checking free_plan_usages table...")
        # Check if id exists
        try:
            # Postgres syntax
            await conn.execute(text("ALTER TABLE free_plan_usages ADD COLUMN IF NOT EXISTS id SERIAL;"))
            await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_free_plan_id ON free_plan_usages (id);"))
            print("Added id column and index successfully.")
        except Exception as e:
            print(f"Error (might be SQLite?): {e}")
            # SQLite fallback (no SERIAL)
            try:
                # SQLite doesn't support adding AUTOINCREMENT column easily on existing table
                # We might need to recreate table, but for now let's assume Postgres on VPS.
                pass 
            except Exception as e2:
                print(f"SQLite fallback failed: {e2}")

if __name__ == "__main__":
    asyncio.run(fix_schema())
