import asyncio
from sqlalchemy import select, update, delete
from db_config import engine, AsyncSessionLocal
from models import User, Company

async def fix_roles():
    async with AsyncSessionLocal() as db:
        print("🔍 Auditing User Roles...")
        
        # 1. Get all companies
        result = await db.execute(select(Company))
        companies = result.scalars().all()
        
        for company in companies:
            print(f"\nProcessing Company: {company.name} (Plan: {company.plan})")
            
            # Get users for this company
            res_users = await db.execute(select(User).where(User.company_id == company.id))
            users = res_users.scalars().all()
            
            if company.plan.lower() == 'free':
                # Should have only 1 user with role 'user_basic'
                if len(users) > 1:
                    print(f"⚠️  WARNING: Free company has {len(users)} users. Should have 1.")
                
                for user in users:
                    if user.role == 'admin_master':
                         print(f"   - Skipping Master Admin: {user.username}")
                         continue

                    if user.role != 'user_basic':
                        print(f"   - Updating user {user.username} (was {user.role}) -> user_basic")
                        user.role = 'user_basic'
                        user.is_admin = False
                        db.add(user)
            else:
                # Paid plans: Ensure roles are admin_empresa or operador_empresa
                for user in users:
                    if user.role == 'user_basic':
                        print(f"   - Updating user {user.username} (was {user.role}) -> admin_empresa (Paid Plan)")
                        user.role = 'admin_empresa'
                        user.is_admin = False
                        db.add(user)
                    elif user.role not in ['admin_empresa', 'operador_empresa', 'admin_master']:
                        print(f"   - Unknown role {user.role} for user {user.username}. Setting to operador_empresa.")
                        user.role = 'operador_empresa'
                        user.is_admin = False
                        db.add(user)
        
        await db.commit()
        print("\n✅ Role audit completed.")

if __name__ == "__main__":
    asyncio.run(fix_roles())
