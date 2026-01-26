import asyncio
from sqlalchemy import text
from db_config import engine

async def migrate():
    print("STARTING MIGRATION: Add Recovery Fields to Users")
    try:
        async with engine.connect() as conn:
            # Check if column exists
            print("Checking current schema...")
            # Postgres specific check for temp_password
            res = await conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='temp_password';"))
            if res.scalar():
                print("✅ Column 'temp_password' already exists.")
            else:
                print("📝 Adding column: temp_password")
                await conn.execute(text("ALTER TABLE users ADD COLUMN temp_password VARCHAR"))
                print("✅ Added 'temp_password'")

            # Check for must_change_password
            res = await conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='must_change_password';"))
            if res.scalar():
                 print("✅ Column 'must_change_password' already exists.")
            else:
                print("📝 Adding column: must_change_password")
                await conn.execute(text("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT FALSE"))
                print("✅ Added 'must_change_password'")
            
            await conn.commit()
            print("Migration completed successfully.")
            return True
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

if __name__ == "__main__":
    asyncio.run(migrate())
