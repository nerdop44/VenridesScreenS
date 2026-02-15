import logging
import asyncio
from datetime import datetime, timedelta
from sqlalchemy import select, extract
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from models import Company, CalendarActivity, EmailTemplate
from services.template_service import template_service
from utils.email_sender import send_email
from db_config import AsyncSessionLocal as SessionLocal, engine

logger = logging.getLogger("VenrideScreenS.Scheduler")

class SchedulerService:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self._started = False

    async def start(self):
        if self._started:
            return
        
        # Job 1: Daily Expiry Check & Birthday Check (Run at 00:05 AM)
        self.scheduler.add_job(
            self.daily_crm_tasks,
            CronTrigger(hour=0, minute=5),
            id="daily_crm_tasks",
            replace_existing=True
        )
        
        # Job 2: Holiday/Special Dates Check (Run at 08:00 AM)
        self.scheduler.add_job(
            self.check_special_dates,
            CronTrigger(hour=8, minute=0),
            id="special_dates",
            replace_existing=True
        )

        self.scheduler.start()
        self._started = True
        logger.info("Scheduler started successfully.")

    async def daily_crm_tasks(self):
        """Run daily automated CRM notifications"""
        async with SessionLocal() as db:
            await self.check_expiries(db)
            await self.check_birthdays(db)

    async def check_expiries(self, db: AsyncSession):
        """Check for companies expiring in 7, 5, 3, or 1 days"""
        now = datetime.utcnow()
        targets = [7, 5, 3, 1]
        
        for days in targets:
            target_date = (now + timedelta(days=days)).date()
            stmt = select(Company).where(
                Company.is_active == True,
                # Simple date matching (ignoring time for the reminder)
                # In real PG, we'd use cast to date
            )
            result = await db.execute(stmt)
            companies = result.scalars().all()
            
            for company in companies:
                if not company.valid_until:
                    continue
                
                # Verify exactly N days before
                if company.valid_until.date() == target_date:
                    settings = company.auto_notification_settings or {}
                    if settings.get("expiry_reminders", True):
                        logger.info(f"Sending {days}-day expiry reminder to {company.name}")
                        
                        # Get BCV rate for the email
                        from services.currency_service import currency_service
                        bcv = currency_service.get_rate()
                        
                        rendered = template_service.render("expiry_reminder", {
                            "name": company.contact_person or company.name,
                            "plan": company.plan,
                            "days": str(days),
                            "bcv_rate": f"{bcv:.2f}"
                        }, db=db)
                        
                        send_email(company.email, rendered["subject"], rendered["body"])

    async def check_birthdays(self, db: AsyncSession):
        """Send birthday greetings to companies"""
        now = datetime.utcnow()
        # Filter by month and day
        stmt = select(Company).where(
            extract('month', Company.birthday) == now.month,
            extract('day', Company.birthday) == now.day
        )
        result = await db.execute(stmt)
        companies = result.scalars().all()
        
        for company in companies:
            settings = company.auto_notification_settings or {}
            if settings.get("birthday_greetings", True):
                logger.info(f"Sending birthday greeting to {company.name}")
                rendered = template_service.render("birthday_greeting", {
                    "name": company.contact_person or company.name
                }, db=db)
                send_email(company.email, rendered["subject"], rendered["body"])

    async def check_special_dates(self):
        """Check for holidays/manual calendar activities to notify"""
        async with SessionLocal() as db:
            now = datetime.utcnow()
            stmt = select(CalendarActivity).where(
                extract('month', CalendarActivity.activity_date) == now.month,
                extract('day', CalendarActivity.activity_date) == now.day,
                CalendarActivity.send_auto_greeting == True
            )
            result = await db.execute(stmt)
            activities = result.scalars().all()
            
            if not activities:
                return

            # For each active holiday, notify ALL active companies
            active_companies_stmt = select(Company).where(Company.is_active == True)
            comp_res = await db.execute(active_companies_stmt)
            all_companies = comp_res.scalars().all()

            for act in activities:
                for company in all_companies:
                    settings = company.auto_notification_settings or {}
                    if settings.get("holiday_greetings", True):
                        rendered = template_service.render("holiday_greeting", {
                            "name": company.contact_person or company.name,
                            "holiday_title": act.title
                        }, db=db)
                        send_email(company.email, rendered["subject"], rendered["body"])

# Singleton
scheduler_service = SchedulerService()
