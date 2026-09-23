# Anexa C.4: imaginea Docker a unei aplicații consolă (SecurityLab)

**În carte:** Anexa C, secțiunea C.4, „Scrierea unui Dockerfile”.

Aplicația consolă minimă `SecurityLab` și Dockerfile-ul multi-stage din Anexa C.4. Procesul rulează ca utilizatorul
fără privilegii `app`. Fișierul `compose.yaml` pentru SQL Server din Anexa C.6 este în `cap10-securitatea-bazelor-de-date/`.

```bash
docker build -t securitylab:1.0 .
docker run --rm securitylab:1.0        # Rulez ca utilizatorul: app
docker rmi securitylab:1.0
```
