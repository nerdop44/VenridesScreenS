#!/usr/bin/env python3
"""
Database Backup Script
Creates timestamped backup of SQLite database
"""
import shutil
import os
from datetime import datetime
from pathlib import Path

# Configuration
DB_PATH = "venrides.db"
BACKUP_DIR = "backups"
MAX_BACKUPS = 10  # Keep last 10 backups

def create_backup():
    """Create timestamped backup of database"""
    # Ensure backup directory exists
    Path(BACKUP_DIR).mkdir(exist_ok=True)
    
    # Check if database exists
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: Database file '{DB_PATH}' not found!")
        return False
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"venrides_backup_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    try:
        # Create backup
        print(f"📦 Creating backup: {backup_name}")
        shutil.copy2(DB_PATH, backup_path)
        
        # Verify backup
        if os.path.exists(backup_path):
            size = os.path.getsize(backup_path)
            print(f"✅ Backup created successfully!")
            print(f"   Location: {backup_path}")
            print(f"   Size: {size:,} bytes")
            
            # Cleanup old backups
            cleanup_old_backups()
            return True
        else:
            print(f"❌ Backup verification failed!")
            return False
            
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return False

def cleanup_old_backups():
    """Remove old backups, keeping only MAX_BACKUPS most recent"""
    try:
        backups = sorted(
            [f for f in os.listdir(BACKUP_DIR) if f.startswith("venrides_backup_")],
            reverse=True
        )
        
        if len(backups) > MAX_BACKUPS:
            print(f"\n🧹 Cleaning up old backups (keeping {MAX_BACKUPS} most recent)...")
            for old_backup in backups[MAX_BACKUPS:]:
                old_path = os.path.join(BACKUP_DIR, old_backup)
                os.remove(old_path)
                print(f"   Removed: {old_backup}")
                
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")

def list_backups():
    """List all available backups"""
    if not os.path.exists(BACKUP_DIR):
        print("No backups directory found.")
        return
    
    backups = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.startswith("venrides_backup_")],
        reverse=True
    )
    
    if not backups:
        print("No backups found.")
        return
    
    print(f"\n📋 Available backups ({len(backups)}):")
    for backup in backups:
        path = os.path.join(BACKUP_DIR, backup)
        size = os.path.getsize(path)
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        print(f"   {backup} - {size:,} bytes - {mtime.strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    print("=" * 60)
    print("VenrideScreenS Database Backup Tool")
    print("=" * 60)
    
    success = create_backup()
    
    if success:
        print("\n" + "=" * 60)
        list_backups()
        print("=" * 60)
        exit(0)
    else:
        exit(1)
