# Aplicația practică 5 (opțională): Pod Security Admission și Network Policies în kind

**În carte:** capitolul 11, „Aplicații practice”, Aplicația practică 5.

| Fișier | Pasul | Conținut |
|---|---|---|
| `namespace.yaml` | 2 | Namespace-ul `aplicatie`, etichetat pentru profilul PSS Restricted (exemplul din 11.5) |
| `pod-sigur.yaml` | 4 | Pod conform profilului Restricted, cu sistem de fișiere read-only și limite de resurse |
| `deny-all-ingress.yaml` | 6 | Politica default-deny din 11.5 |

**Cerințe:** aplicația 4 (imaginile `api-nesigur:1.0` și `api-sigur:1.0`), kind v0.33.0 și `kubectl`.

```bash
kind create cluster --name ssc
kind load docker-image api-nesigur:1.0 api-sigur:1.0 --name ssc
kubectl apply -f namespace.yaml
kubectl apply -f pod-sigur.yaml
kubectl expose pod api-sigur --port 8080 -n aplicatie
kubectl apply -f deny-all-ingress.yaml
kind delete cluster --name ssc
```

Politica de la pasul 7 este exercițiul vostru. Ieșirile așteptate sunt în carte.
