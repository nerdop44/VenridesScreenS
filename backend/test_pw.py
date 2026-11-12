import asyncio
import asyncpg

async def try_conn(pw):
    try:
        conn = await asyncpg.connect(user='vscreens_user', password=pw, database='vscreens_db', host='127.0.0.1')
        print(f"✅ Success with password: {pw}")
        await conn.close()
        return True
    except Exception as e:
        # print(f"❌ Failed with {pw}: {e}")
        return False

async def main():
    passwords = ['CHANGE_ME_DB_PASSWORD', 'postgres', 'admin', 'password', '123456', '']
    for pw in passwords:
        if await try_conn(pw):
            return
    print("❌ All common passwords failed.")

if __name__ == "__main__":
    asyncio.run(main())
