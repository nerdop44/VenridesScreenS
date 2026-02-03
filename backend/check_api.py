
import asyncio
import httpx

async def check_api():
    async with httpx.AsyncClient() as client:
        # Get token
        res = await client.post("http://localhost:8000/token", data={"username": "nerdop@gmail.com", "password": "admin"})
        if res.status_code != 200:
            print("Failed to get token:", res.text)
            return
        token = res.json()["access_token"]
        
        # Get companies
        res = await client.get("http://localhost:8000/companies/", headers={"Authorization": f"Bearer {token}"})
        if res.status_code != 200:
            print("Failed to get companies:", res.text)
            return
        
        companies = res.json()
        if companies:
            print("First company sample:")
            print(companies[0])
            print("Keys:", list(companies[0].keys()))
        else:
            print("No companies found.")

if __name__ == "__main__":
    asyncio.run(check_api())
