#!/bin/bash
# backup-honeypot.sh: copie consistentă a bazei de date, păstrată 14 zile
set -e
DEST="$HOME/honeypot-backup"
mkdir -p "$DEST"
docker exec honeypot-server dotnet Honeypot.dll backup /data/snapshot.db
docker cp honeypot-server:/data/snapshot.db "$DEST/honeypot-$(date +%F).db"
find "$DEST" -name 'honeypot-*.db' -mtime +14 -delete
