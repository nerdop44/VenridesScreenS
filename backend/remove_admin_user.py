import asyncio
from sqlalchemy import text
from db_config import engine

async def remove_admin():
    async with engine.connect() as conn:
        print("Removing user: admin@venrides.com")
        await conn.execute(text("DELETE FROM users WHERE username = 'admin@venrides.com'"))
        await conn.commit()
        print("✅ User removed successfully.")

if __name__ == "__main__":
    asyncio.run(remove_admin())
