import asyncio
from sqlalchemy import text
from db_config import engine

async def migrate_user_active():
    async with engine.begin() as conn:
        try:
            # Check if column exists
            result = await conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='is_active'"))
            if result.scalar():
                print("Column 'is_active' already exists in 'users'")
            else:
                print("Adding 'is_active' column to 'users'")
                await conn.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE"))
                print("Migration successful")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(migrate_user_active())
