from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from models import Base, EmailTemplate
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://venrides_user:venrides_password@localhost:5433/venrides_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def list_templates():
    db = SessionLocal()
    try:
        templates = db.execute(select(EmailTemplate)).scalars().all()
        print(f"Found {len(templates)} templates:")
        for t in templates:
            print(f"ID: {t.id} | Name: {t.name} | System: {t.is_system} | Subject: {t.subject}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    list_templates()
