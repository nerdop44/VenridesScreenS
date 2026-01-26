import asyncio
from sqlalchemy import text
from db_config import engine

async def migrate():
    print("STARTING MIGRATION: Add Alert Fields to Messages")
    try:
        async with engine.connect() as conn:
            # Check if column exists
            print("Checking current schema...")
            # Postgres specific check
            res = await conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='messages' AND column_name='is_alert';"))
            if res.scalar():
                print("✅ Column 'is_alert' already exists.")
            else:
                print("📝 Adding column: is_alert")
                await conn.execute(text("ALTER TABLE messages ADD COLUMN is_alert BOOLEAN DEFAULT FALSE"))
                print("✅ Added 'is_alert'")

            res = await conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='messages' AND column_name='alert_duration';"))
            if res.scalar():
                 print("✅ Column 'alert_duration' already exists.")
            else:
                print("📝 Adding column: alert_duration")
                await conn.execute(text("ALTER TABLE messages ADD COLUMN alert_duration INTEGER DEFAULT 15"))
                print("✅ Added 'alert_duration'")
            
            await conn.commit()
            print("Migration completed successfully.")
            return True
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

if __name__ == "__main__":
    asyncio.run(migrate())
