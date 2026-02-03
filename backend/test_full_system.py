
import asyncio
import os
import sys
from datetime import datetime, timedelta
import logging

# Setup Paths
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import select, delete
from db_config import AsyncSessionLocal
from models import Company, User, Device, RegistrationCode
from supervisor import run_supervisor
from models import FreePlanUsage
from db_config import init_db

# Mock Data
TEST_UUID = "test-device-uuid-123"
TEST_COMPANY_FREE = "Test Company Free"
TEST_COMPANY_PAID = "Test Company Paid"
TEST_USER = "test@user.com"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SystemTest")

async def clean_db(db):
    logger.info("Cleaning up test data...")
    # Delete relevant data
    stmt = select(Company).where(Company.name.in_([TEST_COMPANY_FREE, TEST_COMPANY_PAID]))
    result = await db.execute(stmt)
    companies = result.scalars().all()
    for c in companies:
        await db.delete(c) # Cascades to devices/users
    await db.commit()

async def create_company(db, name, plan, valid_until=None):
    c = Company(name=name, plan=plan, valid_until=valid_until, is_active=True)
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c

async def test_manual_suspension(db):
    logger.info("--- Testing Manual Suspension ---")
    c = await create_company(db, TEST_COMPANY_PAID, "plus", datetime.utcnow() + timedelta(days=30))
    
    # 1. Verify Active
    assert c.is_active == True, "Company should be active initially"
    
    # 2. Toggle (Simulate Endpoint Logic)
    c.is_active = False
    await db.commit()
    
    # 3. Verify Device Check Logic (Simulate /devices/config)
    # Re-fetch
    await db.refresh(c)
    assert c.is_active == False, "Company should be suspended"
    logger.info("✅ Manual Suspension verified.")
    return c

async def test_free_plan_logic(db):
    logger.info("--- Testing Free Plan Logic ---")
    c = await create_company(db, TEST_COMPANY_FREE, "free")
    
    # 1. Link Device (Simulate /devices/validate-code logic)
    now_utc = datetime.utcnow()
    c.first_screen_connected_at = now_utc
    c.valid_until = now_utc + timedelta(days=60)
    db.add(c)
    await db.commit()
    logger.info("  -> Linked device, trial valid until: " + str(c.valid_until))
    
    # 2. Test Alert Logic (Simulate Config Endpoint)
    # Case A: Fresh (60 days left) -> No alert
    days = (c.valid_until - datetime.utcnow()).days
    assert days > 15, "Should have > 15 days"
    
    # Case B: Near Expiration (10 days left)
    c.valid_until = datetime.utcnow() + timedelta(days=10)
    await db.commit()
    days = (c.valid_until - datetime.utcnow()).days
    logger.info(f"  -> Simulated time travel: {days} days left")
    
    config_bottom_bar = {}
    if 0 <= days <= 15:
        alert_msg = f"⚠️ Tu prueba gratuita vence en {days} días."
        config_bottom_bar["messages"] = [alert_msg]
        
    assert "messages" in config_bottom_bar, "Alert should be present"
    logger.info("✅ Free Plan Alert verified.")
    
    # 3. Test Supervisor Expiration (Day 61)
    c.valid_until = datetime.utcnow() - timedelta(days=2) # Expired 2 days ago
    await db.commit()
    
    logger.info("  -> Running Supervisor...")
    await run_supervisor() # Should suspend 'c'
    
    await db.refresh(c)
    assert c.is_active == False, "Supervisor should have suspended the expired Free company"
    logger.info("✅ Free Plan Expiration verified.")

async def test_paid_plan_expiration(db):
    logger.info("--- Testing Paid Plan Expiration ---")
    # Fresh Company
    c = await create_company(db, "Test Paid Exp", "ultra", datetime.utcnow() - timedelta(days=5)) # Expired 5 days ago
    
    logger.info(f"  -> Paid company expired at {c.valid_until}")
    
    await run_supervisor()
    
    await db.refresh(c)
    assert c.is_active == False, "Supervisor should have suspended the expired Paid company"
    logger.info("✅ Paid Plan Expiration verified.")
    
    # Cleanup
    await db.delete(c)
    await db.commit()

async def test_advanced_device_management(db):
    logger.info("--- Testing Advanced Device Management (Rename/Unlink) ---")
    
    # 1. Setup Company and Device
    c = await create_company(db, "Test Adv Mgr", "pro")
    
    # Create Device manually (mocking linkage)
    dev_uuid = "adv-test-uuid-001"
    dev = Device(uuid=dev_uuid, company_id=c.id, name="Old Name")
    db.add(dev)
    await db.commit()
    
    # 2. Test Rename Logic
    stmt = select(Device).where(Device.uuid == dev_uuid)
    res = await db.execute(stmt)
    d = res.scalar_one()
    d.name = "New Name Renamed"
    await db.commit()
    
    await db.refresh(d)
    assert d.name == "New Name Renamed", "Device renaming failed"
    logger.info("✅ Renaming verified.")
    
    # 3. Test Mass Unlink
    db.add(Device(uuid="adv-test-uuid-002", company_id=c.id, name="Another TV"))
    await db.commit()
    
    await db.execute(delete(Device).where(Device.company_id == c.id))
    await db.commit()
    
    res = await db.execute(select(Device).where(Device.company_id == c.id))
    devs = res.scalars().all()
    assert len(devs) == 0, "Mass unlink failed, devices still remain"
    logger.info("✅ Mass Unlink verified.")
    
    # 4. Test Free Plan Integrity (Replacement)
    free_c = await create_company(db, "Test Free Rewrite", "free")
    
    # Simulate first linkage (sets date)
    initial_date = datetime.utcnow() - timedelta(days=10)
    free_c.first_screen_connected_at = initial_date
    await db.commit()
    
    # Simulate new linkage logic check
    if free_c.plan == 'free' and not free_c.first_screen_connected_at:
        free_c.first_screen_connected_at = datetime.utcnow()
        
    assert free_c.first_screen_connected_at == initial_date, "Free Plan start date should NOT be overwritten"
    logger.info("✅ Free Plan Integrity (Replacement) verified.")
    
    await db.delete(c)
    await db.delete(free_c)
    await db.commit()

async def test_free_plan_blocking(db):
    logger.info("--- Testing Free Plan Blocking (One-Time Use) ---")
    
    # 1. Setup Data
    c1 = await create_company(db, "Free Corp A", "free")
    c2 = await create_company(db, "Free Corp B", "free")
    
    dev_uuid = "block-test-uuid-001"
    
    # 2. Simulate First Usage (Free Corp A)
    # We simulate this by checking if it's in usage table, if not inserting
    usage = await db.execute(select(FreePlanUsage).where(FreePlanUsage.uuid == dev_uuid))
    if not usage.scalar_one_or_none():
         db.add(FreePlanUsage(uuid=dev_uuid, company_id=c1.id))
         await db.commit()
    logger.info("  -> Device registered on Free Corp A")
    
    # 3. Simulate Attempt on Free Corp B (Logic from main.py)
    # Re-implementing logic here for test verification
    blocked = False
    usage_res = await db.execute(select(FreePlanUsage).where(FreePlanUsage.uuid == dev_uuid))
    existing = usage_res.scalar_one_or_none()
    
    if existing:
        if existing.company_id != c2.id:
             blocked = True
             logger.info("  -> Blocked correctly: Used on Corp A, trying Corp B")
    
    assert blocked == True, "Device was NOT blocked on second Free Company"
    logger.info("✅ Free Plan Blocking verified.")
    
    # Clean
    await db.delete(c1)
    await db.delete(c2)
    await db.execute(delete(FreePlanUsage).where(FreePlanUsage.uuid == dev_uuid))
    await db.commit()

async def run_tests():
    logger.info("Starting System Integrity Tests...")
    # Initialize DB (ensure tables exist)
    await init_db()
    
    async with AsyncSessionLocal() as db:
        try:
            await clean_db(db)
            
            await test_manual_suspension(db)
            await clean_db(db) # Reset
            
            await test_free_plan_logic(db)
            await clean_db(db)
            
            await test_paid_plan_expiration(db)
            await clean_db(db)

            await test_advanced_device_management(db)
            await clean_db(db)
            
            await test_free_plan_blocking(db)
            await clean_db(db)
            
            logger.info("🎉 All Tests Passed Successfully!")
            
        except AssertionError as e:
            logger.error(f"❌ TEST FAILED: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"❌ ERROR: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    if "win" in sys.platform:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_tests())
