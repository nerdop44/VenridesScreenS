import os
import time
import shutil

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
BACKUPS_DIR = os.path.join(BACKEND_DIR, "backups")
POSTGRES_BACKUPS = os.path.join(BACKUPS_DIR, "postgres")

DAYS_TO_KEEP = 7
NOW = time.time()

def cleanup_logs():
    print("--- Cleaning Logs ---")
    for root, dirs, files in os.walk(BACKEND_DIR):
        for file in files:
            if file.endswith(".log"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'w') as f:
                        f.truncate(0)
                    print(f"Truncated: {file}")
                except Exception as e:
                    print(f"Could not truncate {file}: {e}")

def cleanup_backups():
    print("\n--- Cleaning Backups ---")
    cleanup_paths = [BACKUPS_DIR, POSTGRES_BACKUPS]
    
    for path in cleanup_paths:
        if not os.path.exists(path):
            continue
            
        for file in os.listdir(path):
            filepath = os.path.join(path, file)
            if not os.path.isfile(filepath):
                continue
                
            # 1. Remove 0-byte files
            if os.path.getsize(filepath) == 0:
                os.remove(filepath)
                print(f"Removed empty file: {file}")
                continue
                
            # 2. Remove old files
            file_age_days = (NOW - os.path.getmtime(filepath)) / (24 * 3600)
            if file_age_days > DAYS_TO_KEEP:
                os.remove(filepath)
                print(f"Removed old backup (>7 days): {file}")

if __name__ == "__main__":
    cleanup_logs()
    cleanup_backups()
    print("\nSystem maintenance completed.")
