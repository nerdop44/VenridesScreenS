import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text, inspect
from db_config import DATABASE_URL
from models import Base, BlockedUser, SupportTicket, TicketMessage

async def migrate_phase_10():
    print("🚀 Starting Phase 10 Migration (Communication Suite)...")
    
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    async with engine.begin() as conn:
        # Check if tables exist
        def check_tables(connection):
            inspector = inspect(connection)
            return inspector.get_table_names()

        tables = await conn.run_sync(check_tables)
        
        # Create Blocked Users
        if "blocked_users" not in tables:
            print("Creating table 'blocked_users'...")
            await conn.run_sync(BlockedUser.__table__.create)
            print("✅ Table 'blocked_users' created.")
        else:
            print("ℹ️ Table 'blocked_users' already exists.")

        # Create Support Tickets
        if "support_tickets" not in tables:
            print("Creating table 'support_tickets'...")
            await conn.run_sync(SupportTicket.__table__.create)
            print("✅ Table 'support_tickets' created.")
        else:
            print("ℹ️ Table 'support_tickets' already exists.")

        # Create Ticket Messages
        if "ticket_messages" not in tables:
            print("Creating table 'ticket_messages'...")
            await conn.run_sync(TicketMessage.__table__.create)
            print("✅ Table 'ticket_messages' created.")
        else:
            print("ℹ️ Table 'ticket_messages' already exists.")

    await engine.dispose()
    print("✨ Phase 10 Migration Completed!")

if __name__ == "__main__":
    asyncio.run(migrate_phase_10())
