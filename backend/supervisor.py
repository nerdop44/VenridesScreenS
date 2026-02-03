import asyncio
import logging
from datetime import datetime
import os
import sys

# Ensure backend path is in sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import select
from db_config import AsyncSessionLocal
from models import Company

# Setup logging
logging.basicConfig( 
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("supervisor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Supervisor")

async def run_supervisor():
    logger.info("--- Starting Supervisor Check ---")
    async with AsyncSessionLocal() as db:
        try:
            # 1. Fetch Active Companies with an Expiration Date
            stmt = select(Company).where(Company.is_active == True, Company.valid_until != None)
            result = await db.execute(stmt)
            companies = result.scalars().all()
            
            now = datetime.utcnow()
            suspended_count = 0
            
            for company in companies:
                # Remove timezone for comparison
                valid_until = company.valid_until.replace(tzinfo=None) if company.valid_until.tzinfo else company.valid_until
                
                # Check Expiration (Grace Period 1 Day)
                # If today is more than 1 day past valid_until
                days_overdue = (now - valid_until).days
                
                if days_overdue >= 1:
                    logger.warning(f"SUSPENDING: {company.name} (Plan: {company.plan}, ID: {company.id}). Valid Until: {valid_until}, Overdue: {days_overdue} days.")
                    
                    # Suspend Company (Blocks all screens)
                    company.is_active = False
                    suspended_count += 1
            
            if suspended_count > 0:
                await db.commit()
                logger.info(f"Summary: Suspended {suspended_count} companies.")
            else:
                logger.info("Summary: No companies suspended.")
                
        except Exception as e:
            logger.error(f"Critical Error in Supervisor: {e}")
            await db.rollback()
    
    logger.info("--- Supervisor Check Completed ---")

if __name__ == "__main__":
    if "win" in sys.platform:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_supervisor())
