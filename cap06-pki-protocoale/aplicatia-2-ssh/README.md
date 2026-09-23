# Aplicația practică 2: SSH cu autentificare prin chei publice

**În carte:** capitolul 6, „Aplicații practice”, Aplicația practică 2.

Directorul `lab-ssh/` conține `Dockerfile`-ul serverului OpenSSH de laborator (Debian trixie) și
`99-laborator.conf`, conținutul fișierului pe care îl scrieți în container la pasul 6.

**Cerințe:** Docker (Anexa C) și un client OpenSSH. În Git Bash, puneți `MSYS_NO_PATHCONV=1` în fața comenzilor `docker exec`.

**Pornire (pasul 1), din `lab-ssh/`:**

```bash
docker build -t ssc-sshd .
docker run -d --name ssc-sshd -p 127.0.0.1:2222:22 ssc-sshd
docker exec ssc-sshd sshd -V
```

Portul este publicat doar pe `127.0.0.1`. Parola `Lab-SSC-2026` a utilizatorului `student` există doar pentru
primii pași; la pasul 6 dezactivați autentificarea cu parolă. Pașii 2–7 sunt descriși în carte.
La final: `docker rm -f ssc-sshd`.
