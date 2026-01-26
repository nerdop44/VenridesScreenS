import sqlite3
import os

db_path = "backups/venrides_backup_20260125_115104.db"

def audit_sqlite():
    if not os.path.exists(db_path):
        print(f"❌ {db_path} not found")
        return
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print(f"--- SQLite Audit: {db_path} ---")
    
    # Tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cursor.fetchall()]
    print(f"Tables: {tables}")
    
    if 'users' in tables:
        cursor.execute("SELECT count(*) FROM users")
        print(f"Users count: {cursor.fetchone()[0]}")
        cursor.execute("SELECT username, role FROM users LIMIT 3")
        for row in cursor.fetchall():
            print(f"  - {row[0]} ({row[1]})")
            
    if 'companies' in tables:
        cursor.execute("SELECT count(*) FROM companies")
        print(f"Companies count: {cursor.fetchone()[0]}")
        cursor.execute("SELECT name FROM companies LIMIT 3")
        for row in cursor.fetchall():
            print(f"  - {row[0]}")
            
    conn.close()

if __name__ == "__main__":
    audit_sqlite()
