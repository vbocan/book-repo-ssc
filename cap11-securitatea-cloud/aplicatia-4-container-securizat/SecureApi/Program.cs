var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => "Salut din container!");

// Raportează identitatea procesului și ce poate face în container
app.MapGet("/diagnostic", () =>
{
    string uid = File.ReadLines("/proc/self/status")
        .First(l => l.StartsWith("Uid:"))
        .Split('\t', StringSplitOptions.RemoveEmptyEntries)[1];
    string capEff = File.ReadLines("/proc/self/status")
        .First(l => l.StartsWith("CapEff:"))
        .Split('\t', StringSplitOptions.RemoveEmptyEntries)[1];

    string scriere;
    try
    {
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "test.txt"), "x");
        scriere = "permisă";
    }
    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
    {
        scriere = $"refuzată ({ex.GetType().Name})";
    }

    return Results.Json(new
    {
        utilizator = Environment.UserName,
        uid,
        capabilitatiEfective = capEff,
        scriereInDirectorulAplicatiei = scriere
    });
});

app.Run();
