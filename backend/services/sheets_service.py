"""
Google Sheets Service
Handles reading and writing to Google Sheets for form data storage
"""
import os
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("VenrideScreenS.Sheets")

# Configuration
CREDENTIALS_PATH = os.getenv(
    "GOOGLE_SHEETS_CREDENTIALS_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "credentials", "google-service-account.json")
)
PLANS_SHEET_ID = os.getenv("PLANS_SHEET_ID", "")
CONTACT_SHEET_ID = os.getenv("CONTACT_SHEET_ID", "")
BENRY_SHEET_ID = os.getenv("BENRY_SHEET_ID", "")


class GoogleSheetsService:
    def __init__(self):
        self._sheets_service = None
        self._initialized = False

    @property
    def sheets_service(self):
        if not self._sheets_service:
            self._initialize()
        return self._sheets_service

    def _initialize(self):
        """Initialize Google Sheets API client"""
        try:
            from google.oauth2.service_account import Credentials
            from googleapiclient.discovery import build

            if not os.path.exists(CREDENTIALS_PATH):
                logger.warning(f"Google credentials not found at {CREDENTIALS_PATH}")
                return

            SCOPES = [
                'https://www.googleapis.com/auth/spreadsheets',
                'https://www.googleapis.com/auth/drive'
            ]

            creds = Credentials.from_service_account_file(CREDENTIALS_PATH, scopes=SCOPES)
            self._sheets_service = build('sheets', 'v4', credentials=creds)
            self._initialized = True
            logger.info("Google Sheets service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Google Sheets: {e}")
            self._initialized = False

    def setup_sheet_headers(self, spreadsheet_id: str, sheet_name: str, headers: list):
        """Set up headers for a sheet"""
        try:
            body = {"values": [headers]}
            self.sheets_service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1",
                valueInputOption="RAW",
                body=body
            ).execute()
            logger.info(f"Headers set for {sheet_name}")
        except Exception as e:
            logger.error(f"Failed to set headers: {e}")

    def append_row(self, spreadsheet_id: str, sheet_name: str, values: list) -> bool:
        """Append a row of data to a sheet"""
        if not spreadsheet_id:
            logger.warning(f"No spreadsheet ID configured for {sheet_name}")
            return False

        try:
            body = {"values": [values]}
            self.sheets_service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A:Z",
                valueInputOption="USER_ENTERED",
                insertDataOption="INSERT_ROWS",
                body=body
            ).execute()
            logger.info(f"Row appended to {sheet_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to append row to {sheet_name}: {e}")
            return False

    def log_contact(self, data: dict) -> bool:
        """Log a contact form submission"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        values = [
            timestamp,
            data.get("nombre", ""),
            data.get("email", ""),
            data.get("telefono", ""),
            data.get("asunto", ""),
            data.get("mensaje", ""),
            "Nuevo",
            ""
        ]
        return self.append_row(CONTACT_SHEET_ID, "Contactos", values)

    def log_plan_signup(self, plan: str, data: dict) -> bool:
        """Log a plan signup form submission"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        values = [
            timestamp,
            data.get("nombre", ""),
            data.get("email", ""),
            data.get("telefono", ""),
            data.get("empresa", ""),
            data.get("tipo_negocio", ""),
            data.get("pantallas_estimadas", ""),
            data.get("mensaje", ""),
            "Nuevo",
            ""
        ]
        return self.append_row(PLANS_SHEET_ID, plan.capitalize(), values)

    def log_benry_lead(self, data: dict) -> bool:
        """Log a Benry AI conversation that resulted in a lead"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        values = [
            timestamp,
            data.get("nombre", ""),
            data.get("telefono", ""),
            data.get("email", ""),
            data.get("plan_interes", ""),
            data.get("resumen_conversacion", ""),
            data.get("tipo_lead", ""),  # "venta", "soporte", "demo"
            "Nuevo",
            ""
        ]
        return self.append_row(BENRY_SHEET_ID, "Leads", values)


# Singleton instance
sheets_service = GoogleSheetsService()
