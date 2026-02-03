
import asyncio
from sqlalchemy import text
from db_config import engine

async def update_schema():
    async with engine.begin() as conn:
        # Check columns for companies table
        res = await conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'companies'"))
        columns = [r[0] for r in res.fetchall()]
        
        new_cols = [
            ("whatsapp", "VARCHAR"),
            ("instagram", "VARCHAR"),
            ("facebook", "VARCHAR"),
            ("tiktok", "VARCHAR")
        ]
        
        for col_name, col_type in new_cols:
            if col_name not in columns:
                print(f"Adding column {col_name} to companies table...")
                await conn.execute(text(f"ALTER TABLE companies ADD COLUMN {col_name} {col_type}"))
            else:
                print(f"Column {col_name} already exists.")
        
        # Verify rif, address, phone, email, contact_person etc exist (they should, but let's be sure)
        base_cols = ["rif", "address", "phone", "email", "contact_person"]
        for col in base_cols:
            if col not in columns:
                print(f"Adding MISSING base column {col} to companies table...")
                await conn.execute(text(f"ALTER TABLE companies ADD COLUMN {col} VARCHAR"))

    print("Schema update complete.")

if __name__ == "__main__":
    asyncio.run(update_schema())
