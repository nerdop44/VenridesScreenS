from sqlalchemy import create_engine, text
import os

# Database URL
# Matches db_config.py fallback for localhost but using sync driver
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://venrides_user:venrides_password@localhost:5433/venrides_db")

def migrate():
    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        try:
            print("Checking if column 'first_screen_connected_at' exists in 'companies'...")
            result = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='companies' AND column_name='first_screen_connected_at'"))
            if not result.fetchone():
                print("Adding column 'first_screen_connected_at'...")
                conn.execute(text("ALTER TABLE companies ADD COLUMN first_screen_connected_at TIMESTAMP WITH TIME ZONE"))
                print("Column added successfully.")
            else:
                print("Column already exists.")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    migrate()
