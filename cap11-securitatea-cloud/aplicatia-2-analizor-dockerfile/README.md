# Aplicația practică 2: Analizor de securitate Dockerfile (DockerfileLint)

**În carte:** capitolul 11, „Aplicații practice”, Aplicația practică 2.

Analizează două Dockerfile-uri incluse în program: unul **intenționat nesigur** (material de test) și varianta corectată
din secțiunea 11.3. **Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`. Ieșirea este deterministă; cartea tipărește doar începutul raportului pentru Dockerfile-ul nesigur, iar ieșirea completă este mai jos.

## Rezultatul așteptat

```
═══════════════════════════════════════════════════
   ANALIZA DE SECURITATE: DOCKERFILE NESIGUR
═══════════════════════════════════════════════════
[CRITIC] DKR-001 (General): Etapa finală rulează ca root (lipsește USER sau utilizatorul este root/UID 0).
    Recomandare: Imagini .NET: USER $APP_UID. Debian/Ubuntu: RUN useradd -r -u 10001 appuser. Alpine: RUN adduser -D -u 10001 appuser. Apoi USER.
[CRITIC] DKR-011 (Linia 3): Posibil secret (PASSWORD) scris în imagine; valoarea rămâne vizibilă în istoria imaginii.
    Recomandare: La rulare: fișiere montate (Docker/Kubernetes Secrets, Vault). La build: RUN --mount=type=secret.
[CRITIC] DKR-011 (Linia 4): Posibil secret (API_KEY) scris în imagine; valoarea rămâne vizibilă în istoria imaginii.
    Recomandare: La rulare: fișiere montate (Docker/Kubernetes Secrets, Vault). La build: RUN --mount=type=secret.
[CRITIC] DKR-013 (Linia 8): Script descărcat și executat direct (curl/wget | sh), fără nicio verificare.
    Recomandare: Descărcați fișierul, verificați suma de control sau semnătura, apoi executați-l.
[EROARE] DKR-002 (Linia 1): Imaginea 'ubuntu:latest' folosește tag-ul 'latest' sau nu are tag.
    Recomandare: Folosiți un tag explicit (ex: 'aspnet:10.0-alpine') și, pentru reproductibilitate, digest-ul @sha256.
[EROARE] DKR-006 (Linia 8): Descărcare fără verificarea certificatului TLS (vulnerabil la MITM).
    Recomandare: Eliminați -k/--insecure/--no-check-certificate.
[EROARE] DKR-007 (Linia 9): chmod 777 acordă permisiuni complete tuturor utilizatorilor.
    Recomandare: Folosiți permisiuni restrictive (ex: chmod 550 pentru executabile).
[EROARE] DKR-009 (Linia 11): ADD cu URL descarcă fișiere fără verificarea integrității.
    Recomandare: Folosiți ADD --checksum=sha256:..., sau RUN curl + verificarea sumei de control.
[EROARE] DKR-012 (Linia 16): Portul 22 (SSH) expus într-un container de aplicație.
    Recomandare: Eliminați EXPOSE pentru porturile de management.
[EROARE] DKR-012 (Linia 17): Portul 2375 (Docker API necriptat) expus într-un container de aplicație.
    Recomandare: Eliminați EXPOSE pentru porturile de management.
[AVERT] DKR-004 (Linia 7): Instalare APT fără curățarea cache-ului.
    Recomandare: Adăugați '&& rm -rf /var/lib/apt/lists/*' în aceeași instrucțiune RUN.
[AVERT] DKR-005 (Linia 7): apt-get install fără -y poate bloca build-ul așteptând confirmare.
    Recomandare: Folosiți 'apt-get install -y --no-install-recommends'.
[AVERT] DKR-008 (Linia 13): COPY . copiază întregul context de build, inclusiv .git, .env sau chei.
    Recomandare: Copiați doar fișierele necesare și folosiți .dockerignore.
[INFO] DKR-010 (General): Lipsește instrucțiunea HEALTHCHECK.
    Recomandare: Adăugați HEALTHCHECK (sau probe în Kubernetes) pentru monitorizarea stării.
Total: 14 probleme (critice: 4, erori: 6, avertismente: 3)

═══════════════════════════════════════════════════
   ANALIZA DE SECURITATE: DOCKERFILE CORECTAT
═══════════════════════════════════════════════════
Total: 0 probleme (critice: 0, erori: 0, avertismente: 0)
```
