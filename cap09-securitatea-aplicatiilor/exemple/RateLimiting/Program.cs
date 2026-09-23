using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddSlidingWindowLimiter("api", o =>
    {
        o.PermitLimit = 100;                  // 100 de cereri...
        o.Window = TimeSpan.FromMinutes(1);   // ...pe minut
        o.SegmentsPerWindow = 6;              // fereastră împărțită în 6 segmente de 10 s
        o.QueueLimit = 0;                     // fără coadă: refuz imediat
    });
});

var app = builder.Build();
app.UseRateLimiter();

app.MapGet("/api/produse", () => new[] { "Laptop", "Monitor" })
   .RequireRateLimiting("api");

app.Run();
