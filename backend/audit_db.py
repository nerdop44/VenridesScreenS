import asyncio
from sqlalchemy import text
from db_config import engine

async def audit():
    # Use localhost if running outside docker network
    local_url = "postgresql+asyncpg://venrides_user:venrides_password@localhost/venrides_db"
    from sqlalchemy.ext.asyncio import create_async_engine
    local_engine = create_async_engine(local_url)
    async with local_engine.connect() as conn:
        print("--- AUDIT REPORT ---")
        
        # Companies
        res = await conn.execute(text("SELECT count(*) FROM companies"))
        print(f"Total Companies: {res.scalar()}")
        
        res = await conn.execute(text("SELECT id, name FROM companies LIMIT 5"))
        for row in res:
            print(f"  - [{row[0]}] {row[1]}")
            
        # Users
        res = await conn.execute(text("SELECT count(*) FROM users"))
        print(f"Total Users: {res.scalar()}")
        
        res = await conn.execute(text("SELECT id, username, role, is_admin FROM users"))
        for row in res:
            print(f"  - [{row[0]}] {row[1]} | Role: {row[2]} | Admin: {row[3]}")
            
        # Devices
        res = await conn.execute(text("SELECT count(*) FROM devices"))
        print(f"Total Devices: {res.scalar()}")

if __name__ == "__main__":
    asyncio.run(audit())
