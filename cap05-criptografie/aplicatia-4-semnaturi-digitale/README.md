# Aplicația practică 4: Semnături digitale

**În carte:** capitolul 5, „Aplicații practice”, Aplicația practică 4.

Fiecare parte are propriul proiect de consolă:

| Proiect | Partea | Ce face |
|---|---|---|
| `Lab5RsaPss/` | A | Semnătură RSA-PSS și detectarea documentului modificat |
| `Lab5Ecdsa/` | B | Semnătură ECDSA P-256, formatele IEEE P1363 și DER |
| `Lab5Performanta/` | C | Compararea timpilor RSA-2048 și ECDSA P-256 la semnare și verificare |

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run` (partea C: `dotnet run -c Release`, cu celelalte aplicații grele închise).
Timpii din partea C depind de procesor; comparați ordinele de mărime cu cele de mai jos.

## Rezultatul așteptat

### `Lab5RsaPss` (partea A)

Semnătura diferă la fiecare rulare, pentru că PSS folosește un salt aleator.

```
Document: Contract de prestări servicii nr. 123/2026. Valoare: 50.000 EUR.
Semnătură (256 octeți): bP3+EsFemWbJTpuwNEIKyT5HMDO4KVX/f0g5mblHy66ZKDySPSdmxHajTLGs...
Semnătură validă: True
Semnătură validă pe document modificat: False
```

### `Lab5Ecdsa` (partea B)

Valorile sunt aleatoare; lungimea DER este de regulă de 70–72 de octeți.

```
Semnătură ECDSA P1363 (64 octeți): 79A94B66F2261E046D9C0C520A25320AE583BBBCB1DDF0BAA96ABB757FB2...
Semnătură ECDSA DER (72 octeți): 3046022100B7F25221150B7A57F767B8EEA5EBC8597377D20537B50BD22D...
ECDSA validă (P1363): True, (DER): True
Semnăturile succesive sunt identice: False
```

### `Lab5Performanta` (partea C)

Un rezultat tipic, măsurat pe Linux, .NET 10, un nucleu x86-64 modern (timpii absoluți depind de procesor și de sistemul de operare):

```
RSA-2048 semnare        :    366.5 ms (1000 iterații,   366.5 µs/op)
RSA-2048 verificare     :     14.2 ms (1000 iterații,    14.2 µs/op)
ECDSA P-256 semnare     :     18.2 ms (1000 iterații,    18.2 µs/op)
ECDSA P-256 verificare  :     47.4 ms (1000 iterații,    47.4 µs/op)

Dimensiune semnătură RSA: 256 octeți
Dimensiune semnătură ECDSA: 64 octeți
```
