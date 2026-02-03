
import asyncio
import httpx

async def test_patch():
    async with httpx.AsyncClient() as client:
        # Get token
        res = await client.post("http://localhost:8000/token", data={"username": "nerdop@gmail.com", "password": "admin"})
        token = res.json()["access_token"]
        
        # Get company ID
        res = await client.get("http://localhost:8000/companies/", headers={"Authorization": f"Bearer {token}"})
        company_id = res.json()[0]["id"]
        
        # Patch whatsapp
        test_val = "+584149999999"
        res = await client.patch(
            f"http://localhost:8000/companies/{company_id}", 
            headers={"Authorization": f"Bearer {token}"},
            json={"whatsapp": test_val}
        )
        print("PATCH status:", res.status_code)
        if res.status_code == 200:
            print("Response whatsapp:", res.json().get("whatsapp"))
            
        # Verify again
        res = await client.get(f"http://localhost:8000/companies/{company_id}", headers={"Authorization": f"Bearer {token}"})
        print("Verify whatsapp after GET:", res.json().get("whatsapp"))

if __name__ == "__main__":
    asyncio.run(test_patch())
