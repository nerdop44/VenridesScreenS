#!/usr/bin/env python3
"""
PostgreSQL Backup Utility
Exports the full database to a compressed SQL file.
Run this from the HOST machine.
"""
import os
import datetime
import subprocess

# Configuration
CONTAINER_NAME = "venrides_db" # From docker-compose
DB_USER = "venrides_user"
DB_NAME = "venrides_db"
BACKUP_DIR = "backups/postgres"

def backup_postgres():
    # Ensure backup dir exists
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"venrides_full_{timestamp}.sql.gz"
    filepath = os.path.join(BACKUP_DIR, filename)
    
    print(f"📦 Starting backup of {DB_NAME} from container {CONTAINER_NAME}...")
    
    # Command to run pg_dump inside container or via exec
    # We use docker exec to run pg_dump inside the container and pipe output to host
    cmd = f"docker exec {CONTAINER_NAME} pg_dump -U {DB_USER} {DB_NAME} | gzip > {filepath}"
    
    try:
        # Note: This requires sudo/docker permissions on host
        subprocess.run(cmd, shell=True, check=True)
        size = os.path.getsize(filepath)
        print(f"✅ Backup successful!")
        print(f"   File: {filepath}")
        print(f"   Size: {size / 1024 / 1024:.2f} MB")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Backup failed: {e}")
        return False
        
if __name__ == "__main__":
    backup_postgres()
