var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Date de test, păstrate în memorie
var comenzi = new List<Comanda>
{
    new(1, "ana", "Laptop", 4500m),
    new(2, "ion", "Monitor", 1200m),
    new(3, "ana", "Mouse", 90m),
};
var profiluri = new Dictionary<string, Profil>
{
    ["ana"] = new("ana", "Ana Popescu", "utilizator"),
    ["ion"] = new("ion", "Ion Ionescu", "utilizator"),
};

// Autentificare SIMULATĂ, doar pentru laborator: utilizatorul curent vine din
// header-ul X-Utilizator. Într-o aplicație reală identitatea vine din cookie-ul
// sau token-ul validat de middleware-ul de autentificare (HttpContext.User).
static string? UtilizatorCurent(HttpContext ctx) =>
    ctx.Request.Headers["X-Utilizator"].FirstOrDefault();

// ---------- VULNERABIL: BOLA / IDOR ----------
app.MapGet("/v1/comenzi/{id:int}", (int id, HttpContext ctx) =>
{
    if (UtilizatorCurent(ctx) is null) return Results.Unauthorized();
    var c = comenzi.FirstOrDefault(x => x.Id == id);
    return c is null ? Results.NotFound() : Results.Ok(c);   // nu verifică proprietarul!
});

// ---------- CORECT: verificarea proprietarului pe server ----------
app.MapGet("/v2/comenzi/{id:int}", (int id, HttpContext ctx) =>
{
    var user = UtilizatorCurent(ctx);
    if (user is null) return Results.Unauthorized();
    var c = comenzi.FirstOrDefault(x => x.Id == id && x.Proprietar == user);
    return c is null ? Results.NotFound() : Results.Ok(c);   // 404 și pentru „nu e a ta”
});

// ---------- VULNERABIL: mass assignment (BOPLA) ----------
// Modelul complet, inclusiv Rol, este legat direct din corpul cererii.
app.MapPut("/v1/profil", (Profil p, HttpContext ctx) =>
{
    var user = UtilizatorCurent(ctx);
    if (user is null) return Results.Unauthorized();
    profiluri[user] = p with { Username = user };
    return Results.Ok(profiluri[user]);
});

// ---------- CORECT: DTO cu doar câmpurile pe care clientul le poate modifica ----------
app.MapPut("/v2/profil", (ProfilUpdate dto, HttpContext ctx) =>
{
    var user = UtilizatorCurent(ctx);
    if (user is null) return Results.Unauthorized();
    profiluri[user] = profiluri[user] with { NumeComplet = dto.NumeComplet };
    return Results.Ok(profiluri[user]);
});

app.Run();

record Comanda(int Id, string Proprietar, string Produs, decimal Valoare);
record Profil(string Username, string NumeComplet, string Rol);
record ProfilUpdate(string NumeComplet);
