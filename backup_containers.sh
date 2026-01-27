#!/bin/bash

# Configuration
BACKUP_DIR="./backups/containers"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DB_CONTAINER="venrides_db"
VOLUME_NAME="venrides_screens_postgres_data"  # Check actual volume name with docker volume ls

mkdir -p "$BACKUP_DIR"

echo "Starting Full Container Backup at $TIMESTAMP..."

# 1. PostgreSQL SQL Dump (using existing python script for consistency)
echo "1. Exporting Database (SQL Dump)..."
cd backend
python3 backup_postgres.py
cd ..

# 2. Backup Logos (Bind Mount)
echo "2. Backing up Logos directory..."
tar -czf "$BACKUP_DIR/logos_$TIMESTAMP.tar.gz" logos/

# 3. Backup Postgres Data Volume (Binary)
# Note: It's best to stop the DB for a consistent binary backup, but we'll do a hot 'tar' via a helper container for now as a secondary snapshot.
# To be safe, we rely mainly on step 1.
echo "3. Backing up Postgres Data Volume (Binary Snapshot)..."
# We use a temporary container to mount the volume and tar it to our backup dir
docker run --rm \
  --volumes-from $DB_CONTAINER \
  -v $(pwd)/$BACKUP_DIR:/backup \
  alpine tar cvf /backup/postgres_data_$TIMESTAMP.tar /var/lib/postgresql/data

# Compress the tar (gzip outside to reduce container cpu load if needed, or just keep as tar)
gzip "$BACKUP_DIR/postgres_data_$TIMESTAMP.tar"

echo "Backup Completed! Files saved in $BACKUP_DIR"
ls -lh "$BACKUP_DIR"
