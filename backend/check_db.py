import asyncio
from sqlalchemy.future import select
from db_config import AsyncSessionLocal
from models import Device, Company, User

async def check_data():
    async with AsyncSessionLocal() as session:
        # Check Companies
        res = await session.execute(select(Company))
        companies = res.scalars().all()
        print(f"Total Companies in DB: {len(companies)}")
        for c in companies:
            print(f" - [{c.id}] {c.name}")
            
        # Check Users
        res = await session.execute(select(User))
        users = res.scalars().all()
        print(f"Total Users in DB: {len(users)}")
        for u in users:
            print(f" - [{u.id}] {u.username} | Role: {u.role}")

        # Check Devices
        res = await session.execute(select(Device))
        devices = res.scalars().all()
        print(f"Total Devices in DB: {len(devices)}")
        for d in devices:
            print(f" - Device UUID: {d.uuid}, Name: {d.name}, Company ID: {d.company_id}")

if __name__ == "__main__":
    asyncio.run(check_data())
