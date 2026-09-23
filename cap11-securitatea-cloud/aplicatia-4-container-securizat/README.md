# Aplicația practică 4: Securizarea și scanarea unui container .NET 10

**În carte:** capitolul 11, „Aplicații practice”, Aplicația practică 4.

Directorul `SecureApi/` conține aplicația minimală (raportează utilizatorul, capabilitățile efective și dacă poate scrie
în propriul director) și două imagini:

- `Dockerfile.nesigur`: **intenționat nesigur** (rulează ca root, livrează întregul SDK);
- `Dockerfile`: varianta multi-stage din secțiunea 11.3, cu `HEALTHCHECK` adăugat înainte de `ENTRYPOINT` (pasul 3).

**Cerințe:** Docker (Anexa C). Comenzile sunt pentru bash (în PowerShell, `\` de la final de rând devine `` ` ``).

```bash
cd SecureApi
docker build -f Dockerfile.nesigur -t api-nesigur:1.0 .
docker run -d --name api-nesigur -p 127.0.0.1:8081:8080 api-nesigur:1.0
curl http://127.0.0.1:8081/diagnostic
docker exec api-nesigur id
docker build -t api-sigur:1.0 .
docker images --format "{{.Repository}}:{{.Tag}}  {{.Size}}" | grep api-
docker run -d --name api-sigur -p 127.0.0.1:8080:8080 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 256m --cpus 0.5 --pids-limit 100 \
  api-sigur:1.0
docker ps --filter name=api-sigur --format "{{.Names}}  {{.Status}}"
curl http://127.0.0.1:8080/diagnostic
docker exec api-sigur id
docker exec api-sigur touch /app/x
```

Pașii 5–6 (efectul fiecărei măsuri, scanarea cu Trivy 0.74.0) și ieșirile așteptate sunt în carte.
La final: `docker rm -f api-sigur api-nesigur` și `docker rmi api-sigur:1.0 api-nesigur:1.0`.
