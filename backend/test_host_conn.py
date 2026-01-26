import asyncio
from db_config import engine
from sqlalchemy import text

async def test_connection():
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT current_database();"))
            db_name = result.scalar()
            print(f"✅ Connected successfully to: {db_name}")
            
            # Check for users table
            result = await conn.execute(text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users');"))
            has_users = result.scalar()
            print(f"Table 'users' exists: {has_users}")
            
    except Exception as e:
        print(f"❌ Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())
