#!/usr/bin/env python3
"""
Rollback Script - Remove Alert Fields
Removes is_alert and alert_duration columns from messages table
WARNING: This will delete data in these columns!
"""
import sqlite3
import os
from datetime import datetime

DB_PATH = "venrides.db"
LOG_FILE = "rollback.log"

def log(message):
    """Log message to file and console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with open(LOG_FILE, "a") as f:
        f.write(log_msg + "\n")

def rollback():
    """Rollback migration by removing alert fields"""
    if not os.path.exists(DB_PATH):
        log(f"❌ Error: Database '{DB_PATH}' not found!")
        return False
    
    log("=" * 60)
    log("⚠️  WARNING: ROLLBACK OPERATION")
    log("=" * 60)
    log("This will remove is_alert and alert_duration columns")
    log("and DELETE all data in these columns!")
    log("")
    
    response = input("Are you sure you want to continue? (yes/no): ")
    if response.lower() != "yes":
        log("❌ Rollback cancelled by user")
        return False
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        log("\n📝 Starting rollback...")
        
        # SQLite doesn't support DROP COLUMN directly
        # We need to recreate the table without those columns
        
        # 1. Get current table schema
        cursor.execute("PRAGMA table_info(messages)")
        columns = cursor.fetchall()
        
        # 2. Filter out alert columns
        keep_columns = [col for col in columns if col[1] not in ['is_alert', 'alert_duration']]
        column_defs = []
        column_names = []
        
        for col in keep_columns:
            name = col[1]
            type_ = col[2]
            notnull = "NOT NULL" if col[3] else ""
            default = f"DEFAULT {col[4]}" if col[4] is not None else ""
            pk = "PRIMARY KEY" if col[5] else ""
            
            column_names.append(name)
            column_defs.append(f"{name} {type_} {notnull} {default} {pk}".strip())
        
        # 3. Create temporary table
        log("Creating temporary table...")
        create_temp = f"""
            CREATE TABLE messages_temp (
                {', '.join(column_defs)}
            )
        """
        cursor.execute(create_temp)
        
        # 4. Copy data
        log("Copying data to temporary table...")
        copy_sql = f"""
            INSERT INTO messages_temp ({', '.join(column_names)})
            SELECT {', '.join(column_names)} FROM messages
        """
        cursor.execute(copy_sql)
        
        # 5. Drop old table
        log("Dropping old table...")
        cursor.execute("DROP TABLE messages")
        
        # 6. Rename temp table
        log("Renaming temporary table...")
        cursor.execute("ALTER TABLE messages_temp RENAME TO messages")
        
        # Commit changes
        conn.commit()
        
        log("\n✅ Rollback completed successfully!")
        log("Alert fields have been removed from messages table")
        log("=" * 60)
        
        conn.close()
        return True
        
    except Exception as e:
        log(f"\n❌ Rollback failed: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("VenrideScreenS Database Rollback Tool")
    print("=" * 60 + "\n")
    
    success = rollback()
    exit(0 if success else 1)
