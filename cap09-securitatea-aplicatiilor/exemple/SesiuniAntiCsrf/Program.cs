using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "__Host-App";              // prefix __Host-: doar HTTPS, fără Domain
        options.Cookie.HttpOnly = true;                  // inaccesibil din JavaScript
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // doar prin HTTPS
        options.Cookie.SameSite = SameSiteMode.Lax;      // nu pleacă în cereri POST cross-site
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        options.SlidingExpiration = true;                // expirare la inactivitate
    });
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();                       // token-uri anti-CSRF

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error");
    app.UseHsts();                                       // Strict-Transport-Security
}
app.UseHttpsRedirection();

app.Use(async (context, next) =>
{
    context.Response.Headers.ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    await next();
});

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();                                    // validează token-ul la formulare

app.MapGet("/", () => "OK");
app.Run();
