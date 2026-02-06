"""
Alternative Script to initialize Google Sheets
Creates sheets in user's My Drive instead of specific folders
"""
import os
import sys
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    pass
from dotenv import load_dotenv

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.sheets_service import GoogleSheetsService

# Load environment variables
load_dotenv()

def initialize_plans_sheet_simple():
    """Create plans spreadsheet without folder restrictions"""
    print("\n📊 Creating Plans Spreadsheet...")
    
    try:
        # Initialize service
        service = GoogleSheetsService()
        
        # Create spreadsheet without specifying folder
        title = "VenridesScreenS - Contrataciones"
        sheets = ["Free", "Basico", "Plus", "Ultra", "Empresarial"]
        
        spreadsheet = {
            'properties': {'title': title},
            'sheets': [{'properties': {'title': sheet_name}} for sheet_name in sheets]
        }
        
        result = service.sheets_service.spreadsheets().create(body=spreadsheet).execute()
        spreadsheet_id = result['spreadsheetId']
        
        print(f"✅ Created spreadsheet '{title}'")
        print(f"📋 Spreadsheet ID: {spreadsheet_id}")
        print(f"🔗 URL: https://docs.google.com/spreadsheets/d/{spreadsheet_id}")
        
        # Headers for plan sheets
        headers = [
            "Timestamp",
            "Nombre Completo",
            "Email",
            "Teléfono",
            "Empresa/Negocio",
            "Tipo de Negocio",
            "Pantallas Estimadas",
            "Mensaje/Comentarios",
            "Estado",
            "Fecha Actualización"
        ]
        
        # Setup headers for each sheet
        for sheet_name in sheets:
            service.setup_sheet_headers(spreadsheet_id, sheet_name, headers)
        
        print(f"\n✅ All sheets configured with headers!")
        return spreadsheet_id
        
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

def initialize_contact_sheet_simple():
    """Create contact spreadsheet without folder restrictions"""
    print("\n📊 Creating Contact Spreadsheet...")
    
    try:
        # Initialize service
        service = GoogleSheetsService()
        
        # Create spreadsheet without specifying folder
        title = "VenridesScreenS - Contactos"
        sheets = ["Contactos"]
        
        spreadsheet = {
            'properties': {'title': title},
            'sheets': [{'properties': {'title': sheet_name}} for sheet_name in sheets]
        }
        
        result = service.sheets_service.spreadsheets().create(body=spreadsheet).execute()
        spreadsheet_id = result['spreadsheetId']
        
        print(f"✅ Created spreadsheet '{title}'")
        print(f"📋 Spreadsheet ID: {spreadsheet_id}")
        print(f"🔗 URL: https://docs.google.com/spreadsheets/d/{spreadsheet_id}")
        
        # Headers for contact sheet
        headers = [
            "Timestamp",
            "Nombre Completo",
            "Email",
            "Teléfono",
            "Asunto",
            "Mensaje",
            "Estado",
            "Fecha Actualización"
        ]
        
        # Setup headers
        service.setup_sheet_headers(spreadsheet_id, "Contactos", headers)
        
        print(f"\n✅ Contact sheet configured with headers!")
        return spreadsheet_id
        
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

if __name__ == "__main__":
    print("=" * 70)
    print("🚀 VenridesScreenS - Google Sheets Initialization (Simple)")
    print("=" * 70)
    print("\nThis script creates sheets in your Google Drive.")
    print("You can move them to specific folders manually if needed.")
    print()
    
    try:
        plans_id = initialize_plans_sheet_simple()
        contact_id = initialize_contact_sheet_simple()
        
        print("\n" + "=" * 70)
        print("✅ All spreadsheets created successfully!")
        print("=" * 70)
        print("\n📝 Update your .env file with these values:")
        print(f"\nPLANS_SHEET_ID={plans_id}")
        print(f"CONTACT_SHEET_ID={contact_id}")
        print("\n" + "=" * 70)
        print("\n📌 OPTIONAL: Move the sheets to your folders:")
        print(f"1. Plans: https://drive.google.com/drive/folders/1vgeveIrbdo12egt-RG2NbdZppsnEmLty")
        print(f"2. Contacts: https://drive.google.com/drive/folders/1mQXnR10ijFX8oBcd7hUWXiMdyRhqR8ly")
        print("\n" + "=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
