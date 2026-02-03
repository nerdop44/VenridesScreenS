import os
import sys
from sqlalchemy import create_engine, text

# Setup paths
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Database URL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://venrides_user:venrides_password@localhost:5433/venrides_db")

def migrate():
    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        print("Checking if 'free_plan_usages' table exists...")
        result = conn.execute(text("SELECT to_regclass('public.free_plan_usages')"))
        if result.scalar():
            print("Table 'free_plan_usages' already exists.")
        else:
            print("Creating table 'free_plan_usages'...")
            conn.execute(text("""
                CREATE TABLE free_plan_usages (
                    uuid VARCHAR PRIMARY KEY,
                    company_id INTEGER REFERENCES companies(id),
                    used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """))
            print("Table created successfully.")
            
            # Index
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_free_plan_usages_uuid ON free_plan_usages (uuid)"))

if __name__ == "__main__":
    migrate()
