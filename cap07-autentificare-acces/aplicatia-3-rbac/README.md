# Aplicația practică 3: Sistem RBAC simplu (Lab7Rbac)

**În carte:** capitolul 7, „Aplicații practice”, Aplicația practică 3.

Core RBAC cu ierarhie de roluri (moștenirea permisiunilor) și separarea statică a sarcinilor (SoD).

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`. Ieșirea este deterministă; cartea tipărește doar atribuirea rolurilor și verificarea accesului, iar ieșirea completă este mai jos.

## Rezultatul așteptat

```
=== Definire roluri ===
  Rol definit: Angajat
  Rol definit: Dezvoltator (moștenește de la Angajat)
  Rol definit: TeamLead (moștenește de la Dezvoltator)
  Rol definit: Contabil (moștenește de la Angajat)
  Rol definit: Auditor (moștenește de la Angajat)
  Rol definit: Admin

=== Definire permisiuni ===
Permisiuni definite.

=== Constrângeri SSD ===
  Constrângere SSD: Contabil ↔ Auditor (mutual exclusive)

=== Atribuire roluri ===
  Utilizator 'ioana' -> rol 'TeamLead'
  Utilizator 'mihai' -> rol 'Dezvoltator'
  Utilizator 'elena' -> rol 'Contabil'
  Utilizator 'elena' -> rol 'Admin'
  REFUZAT: Utilizatorul 'elena' are deja rolul 'Contabil', incompatibil cu 'Auditor' (SSD).

  Permisiuni pentru 'ioana':
  Roluri atribuite: [TeamLead]
  Permisiuni efective:
    - Documente:Citire
    - Echipă:Gestionare
    - Pipeline:Execuție
    - Profil:Citire
    - Profil:Editare
    - Repository:Aprobare
    - Repository:Citire
    - Repository:Scriere

  Permisiuni pentru 'elena':
  Roluri atribuite: [Contabil, Admin]
  Permisiuni efective:
    - Documente:Citire
    - Facturi:Emitere
    - Financiar:Citire
    - Financiar:Scriere
    - Profil:Citire
    - Profil:Editare
    - Sistem:Configurare
    - Utilizatori:Gestionare

=== Verificare acces ===
  Sesiune creată: 'ioana' cu rolurile [TeamLead]
  Sesiune creată: 'mihai' cu rolurile [Dezvoltator]
  Sesiune creată: 'elena' cu rolurile [Contabil]
  Acces PERMIS: 'ioana' -> Repository:Aprobare (prin rolul 'TeamLead')
  Acces PERMIS: 'ioana' -> Documente:Citire (prin rolul 'TeamLead')
  Acces REFUZAT: 'mihai' -> Echipă:Gestionare
  Acces PERMIS: 'elena' -> Facturi:Emitere (prin rolul 'Contabil')
  Acces REFUZAT: 'elena' -> Repository:Citire
```
