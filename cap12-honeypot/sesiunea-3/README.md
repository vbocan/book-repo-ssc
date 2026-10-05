# Honeypot: starea de la finalul sesiunii 3

**În carte:** capitolul 12, Aplicația practică 1, „Sesiunea 3”.

Containerizare: imagine multi-stage, utilizator non-root, sistem de fișiere read-only. Proiect complet; vezi `../README.md` pentru ce se adaugă în fiecare sesiune și pentru nota de etică.

```bash
docker compose up -d --build
```

## Rezultatul așteptat

Ieșirea comenzilor `docker exec honeypot-server id`, `ls -la /data` și `touch /app/test` (orele diferă la voi). Cartea tipărește doar prima și ultima linie.

```
uid=1654(app) gid=1654(app) groups=1654(app)
total 92
drwxr-xr-x    2 app      root          4096 Sep 23 12:17 .
drwxr-xr-x    1 root     root          4096 Sep 23 12:17 ..
-rw-r--r--    1 app      app           4096 Sep 23 12:17 honeypot.db
-rw-r--r--    1 app      app          32768 Sep 23 12:17 honeypot.db-shm
-rw-r--r--    1 app      app          45352 Sep 23 12:17 honeypot.db-wal
touch: /app/test: Read-only file system
```
