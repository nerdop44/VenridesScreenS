import asyncio
import sys
sys.path.append("/app")
from db_config import AsyncSessionLocal
from models import User
from main import get_password_hash
from sqlalchemy import select

async def main():
    async with AsyncSessionLocal() as db:
        stmt = select(User).where(User.username == "nerdop@gmail.com")
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if user:
            user.hashed_password = get_password_hash("admin")
            await db.commit()
            print("SUCCESS: Password reset to 'admin'")
        else:
            print("ERROR: User not found")

if __name__ == "__main__":
    asyncio.run(main())
