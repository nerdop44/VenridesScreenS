import asyncio
from models import Company
from db_config import AsyncSessionLocal
from sqlalchemy.future import select

async def migrate_data():
    async with AsyncSessionLocal() as db:
        print("--- Migrating VenridesCafe (ID 59) ---")
        res = await db.execute(select(Company).where(Company.id == 59))
        c = res.scalar_one_or_none()
        if c:
            if c.filler_keywords and (c.filler_keywords.startswith("http") or "youtube" in c.filler_keywords):
                print(f"Found YouTube URL in keywords: {c.filler_keywords}")
                if not c.video_playlist or len(c.video_playlist) == 0:
                    print("Moving URL to playlist field...")
                    c.video_playlist = [c.filler_keywords]
                    await db.commit()
                    print("Migration successful.")
                else:
                    print(f"Playlist already has content: {c.video_playlist}. Skipping auto-move.")
            else:
                print("No YouTube URL found in legacy keywords field.")
        else:
            print("VenridesCafe (ID 59) not found.")

if __name__ == "__main__":
    asyncio.run(migrate_data())
