# Aplicația practică 1: Scanner de porturi TCP (Lab8Scanner)

**În carte:** capitolul 8, „Aplicații practice”, Aplicația practică 1.

Scanare TCP connect concurentă (cu limită de paralelism și timeout) și identificarea serviciilor cunoscute.

> Scanați doar calculatorul propriu și gazda de test `scanme.nmap.org`, pe care proiectul Nmap o pune la dispoziție
> pentru asta. Scanarea altor sisteme fără autorizare scrisă este ilegală (capitolul 15, Codul penal art. 360–366).

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run` (ținta implicită `127.0.0.1`) sau `dotnet run -- scanme.nmap.org`.
Porturile găsite depind de sistem; formatul ieșirii este cel din carte.
