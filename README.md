# 🔐 Securitatea sistemelor de calcul — cod însoțitor

![.NET](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)
![C#](https://img.shields.io/badge/C%23-14-178600?logo=csharp&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![SQL Server](https://img.shields.io/badge/SQL_Server-2025-CC2927?logo=microsoftsqlserver&logoColor=white)
![Licență](https://img.shields.io/badge/licen%C8%9B%C4%83-MIT-2F855A)
![CI](https://img.shields.io/badge/build-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)

Cod însoțitor pentru manualul **_Securitatea sistemelor de calcul_** de Valer Bocan (Editura Politehnica
Timișoara). Depozitul conține **aplicațiile practice** din capitolele 5–16, ca proiecte complete, gata de
rulat: 52 de proiecte .NET 10, scripturile T-SQL ale capitolului 10, fișierele Dockerfile și Docker
Compose ale laboratoarelor și honeypot-ul din capitolul 12, în câte un instantaneu pentru fiecare dintre cele
șase sesiuni. Codul este identic cu cel tipărit în carte și este **verificat că se compilează și rulează**
cu .NET 10; unde cartea tipărește doar un extras, fișierul complet se află aici, la calea indicată în text.

```bash
git clone https://github.com/vbocan/book-repo-ssc.git
```

## 📦 Structură

| | |
|---|---|
| 📁 `capNN-<subiect>/` | Un director pentru fiecare capitol cu aplicații practice (5–16) |
| 📁 `capNN-.../aplicatia-K-<subiect>/` | Aplicația practică K a capitolului, cu `README.md` (ce face, unde este în carte, cum se rulează, cerințe) |
| 📁 `cap12-honeypot/sesiunea-N/` | Honeypot-ul din capitolul 12 în starea de la finalul sesiunii N (1–6); `sesiunea-6` este proiectul final |
| 📁 `cap10-.../sql/` | Scripturile T-SQL din secțiunile 10.1–10.6, fiecare rulabil singur pe serverul din `compose.yaml` |
| 📁 `.../exemple/` | Programele complete din secțiunile teoretice ale capitolelor 9 și 10; manifestele Kubernetes din 11.4 sunt în `cap11-.../exemple-kubernetes/` |
| ⚠️ `.../vulnerabil/` | Cod **intenționat vulnerabil**, folosit pentru a demonstra un atac (vezi mai jos) |
| 📁 `anexe/` | Exemplul de Dockerfile din Anexa C |

## 🚀 Rularea unui exemplu

Cerințe: **.NET 10 SDK** (Anexa A din carte) și, pentru laboratoarele cu containere, **Docker** cu Docker
Compose v2 (Anexa C). Pentru capitolul 10, SQL Server 2025 pornește în container, fără instalare.

```bash
cd cap07-autentificare-acces/aplicatia-1-parole
dotnet run
```

Argumentele programului se scriu după `--`, de exemplu `dotnet run -- --demo`. Laboratoarele cu servicii:

```bash
cd cap10-securitatea-bazelor-de-date
cp .env.example .env               # parola contului sa, citită de compose.yaml
docker compose up -d --wait        # SQL Server 2025 Developer, doar pe 127.0.0.1
```

Fiecare director de aplicație are un `README.md` cu pașii exacți și cu trimiterea la ieșirea așteptată din carte.

## 📚 Harta capitolelor

| Cap. | Director | Subiect | Aplicații | Proiecte .NET | Scripturi SQL | Fișiere Compose |
|----:|---------|---------|:---------:|:-------------:|:-------------:|:---------------:|
| 5 | [`cap05-criptografie/`](cap05-criptografie/) | Criptografie | 4 aplicații | 12 | — | — |
| 6 | [`cap06-pki-protocoale/`](cap06-pki-protocoale/) | Infrastructura cheilor publice și protocoale criptografice | 2 aplicații | 2 | — | — |
| 7 | [`cap07-autentificare-acces/`](cap07-autentificare-acces/) | Autentificare și controlul accesului | 3 aplicații | 3 | — | — |
| 8 | [`cap08-securitatea-retelelor/`](cap08-securitatea-retelelor/) | Securitatea rețelelor | 3 aplicații | 3 | — | — |
| 9 | [`cap09-securitatea-aplicatiilor/`](cap09-securitatea-aplicatiilor/) | Securitatea aplicațiilor | 3 aplicații | 7 | — | — |
| 10 | [`cap10-securitatea-bazelor-de-date/`](cap10-securitatea-bazelor-de-date/) | Securitatea bazelor de date | 3 aplicații | 6 | 18 | 1 |
| 11 | [`cap11-securitatea-cloud/`](cap11-securitatea-cloud/) | Securitatea în cloud și containerizare | 5 aplicații | 4 | — | — |
| 12 | [`cap12-honeypot/`](cap12-honeypot/) | Monitorizarea securității și honeypot-uri | 6 sesiuni | 6 | — | 7 |
| 13 | [`cap13-managementul-incidentelor/`](cap13-managementul-incidentelor/) | Managementul incidentelor și criminalistică digitală | 3 aplicații | 3 | — | — |
| 14 | [`cap14-securitatea-fizica/`](cap14-securitatea-fizica/) | Securitatea fizică | 1 aplicație | 1 | — | — |
| 15 | [`cap15-aspecte-juridice/`](cap15-aspecte-juridice/) | Aspecte juridice și de conformitate | 1 aplicație | 1 | — | — |
| 16 | [`cap16-tendinte-securitate/`](cap16-tendinte-securitate/) | Tendințe și perspective în securitate | 2 aplicații | 3 | — | 1 |
| — | [`anexe/`](anexe/) | Anexa C: imaginea Docker a unei aplicații consolă | 1 exemplu | 1 | — | — |

## ⚖️ Etică și lege

Instrumentele din acest depozit (scanerul de porturi, scanerul IoT, honeypot-ul, programele de SQL injection)
se folosesc **numai pe infrastructura voastră** sau pe sisteme pentru care aveți autorizare scrisă. Accesul
fără drept la un sistem informatic, interceptarea datelor și perturbarea funcționării sistemelor sunt
infracțiuni în România (Codul penal, art. 360–366, capitolul 15 din carte), chiar dacă intenția este didactică.

- **Honeypot-ul** (capitolul 12) se expune pe internet doar de pe o instanță cloud dedicată, fără alte date,
  izolată cum descrie sesiunea 4 (egress blocat, container non-root, read-only). Accesul neautorizat rămâne
  infracțiune și când ținta este un honeypot (art. 360), iar operatorul nu are dreptul să „riposteze”.
  Adresele IP colectate sunt date cu caracter personal (GDPR): păstrați-le limitat în timp și securizat.
- **Scanerele** (capitolele 8 și 16) se rulează pe `127.0.0.1`, pe laboratorul simulat din Docker sau pe
  `scanme.nmap.org`, pe care proiectul Nmap o pune la dispoziție pentru teste. Scanerul IoT refuză implicit
  orice adresă care nu este locală.
- **Codul din directoarele `vulnerabil/`** și laboratoarele marcate „intenționat nesigure” (IoT, `Dockerfile.nesigur`)
  există ca să vedeți atacul și remedierea. Rulați-le doar local: porturile sunt legate de `127.0.0.1`.
  Nu le publicați și nu copiați codul lor în aplicații reale.

## ⚖️ Licență

Codul sursă din acest depozit este publicat sub [licența MIT](LICENSE). Textul cărții este
© Valer Bocan și **nu** este acoperit de această licență.
