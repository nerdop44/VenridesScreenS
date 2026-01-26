import asyncio
from sqlalchemy import text
from db_config import engine

async def add_indexes():
    print("Conectando a la base de datos para agregar índices...")
    async with engine.begin() as conn:
        # Índices para la tabla companies
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_companies_is_active ON companies(is_active)"))
        print("Índice idx_companies_is_active creado.")
        
        # Índices para la tabla users
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_users_company_id ON users(company_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)"))
        print("Índices para users creados.")
        
        # Índices para la tabla devices
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_company_id ON devices(company_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_uuid ON devices(uuid)"))
        print("Índices para devices creados.")
        
        # Índices para la tabla payments
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_payments_company_id ON payments(company_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(payment_date)"))
        print("Índices para payments creados.")
        
        # Índices para registration_codes
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_registration_codes_code ON registration_codes(code)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_registration_codes_expires ON registration_codes(expires_at)"))
        print("Índices para registration_codes creados.")

    print("Todos los índices han sido creados exitosamente.")

if __name__ == "__main__":
    asyncio.run(add_indexes())
