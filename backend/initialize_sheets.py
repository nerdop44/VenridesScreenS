"""
Script to initialize Google Sheets for VScreenS Forms
Creates spreadsheets with proper structure and headers
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

from services.sheets_service import sheets_service

# Load environment variables
load_dotenv()

def initialize_plans_sheet():
    """Create and setup the plans spreadsheet"""
    print("\n📊 Creating Plans Spreadsheet...")
    
    folder_id = "1vgeveIrbdo12egt-RG2NbdZppsnEmLty"
    title = "VScreenS - Contrataciones"
    sheets = ["Free", "Basico", "Plus", "Ultra", "Empresarial"]
    
    spreadsheet_id = sheets_service.create_spreadsheet(title, folder_id, sheets)
    
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
        sheets_service.setup_sheet_headers(spreadsheet_id, sheet_name, headers)
    
    print(f"\n✅ Plans spreadsheet created!")
    print(f"📋 Spreadsheet ID: {spreadsheet_id}")
    print(f"🔗 URL: https://docs.google.com/spreadsheets/d/{spreadsheet_id}")
    print(f"\n⚠️  Add this to your .env file:")
    print(f"PLANS_SHEET_ID={spreadsheet_id}")
    
    return spreadsheet_id

def initialize_contact_sheet():
    """Create and setup the contact spreadsheet"""
    print("\n📊 Creating Contact Spreadsheet...")
    
    folder_id = "1mQXnR10ijFX8oBcd7hUWXiMdyRhqR8ly"
    title = "VScreenS - Contactos"
    sheets = ["Contactos"]
    
    spreadsheet_id = sheets_service.create_spreadsheet(title, folder_id, sheets)
    
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
    sheets_service.setup_sheet_headers(spreadsheet_id, "Contactos", headers)
    
    print(f"\n✅ Contact spreadsheet created!")
    print(f"📋 Spreadsheet ID: {spreadsheet_id}")
    print(f"🔗 URL: https://docs.google.com/spreadsheets/d/{spreadsheet_id}")
    print(f"\n⚠️  Add this to your .env file:")
    print(f"CONTACT_SHEET_ID={spreadsheet_id}")
    
    return spreadsheet_id

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 VScreenS - Google Sheets Initialization")
    print("=" * 60)
    
    try:
        plans_id = initialize_plans_sheet()
        contact_id = initialize_contact_sheet()
        
        print("\n" + "=" * 60)
        print("✅ All spreadsheets created successfully!")
        print("=" * 60)
        print("\n📝 Update your .env file with these values:")
        print(f"\nPLANS_SHEET_ID={plans_id}")
        print(f"CONTACT_SHEET_ID={contact_id}")
        print("\n" + "=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
