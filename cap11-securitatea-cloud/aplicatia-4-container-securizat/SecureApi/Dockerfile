# Etapa de build: SDK-ul complet, folosit doar la compilare
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY SecureApi.csproj .
RUN dotnet restore
COPY Program.cs .
RUN dotnet publish -c Release -o /app/publish --no-restore

# Etapa finală: doar runtime-ul ASP.NET Core, pe Alpine
# Tag-ul „10.0-alpine” este flotant: indică mereu cel mai recent patch 10.0.x.
# Pentru build-uri reproductibile, fixați digest-ul:
#   FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine@sha256:<digest>
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS final
WORKDIR /app

# Se copiază DOAR rezultatul compilării, nu întregul context de build
COPY --from=build /app/publish .

# Imaginile .NET oficiale conțin deja utilizatorul neprivilegiat „app”
# (UID 1654, disponibil în variabila APP_UID)
USER $APP_UID
EXPOSE 8080
HEALTHCHECK --interval=10s CMD wget -qO- http://127.0.0.1:8080/ || exit 1
ENTRYPOINT ["dotnet", "SecureApi.dll"]

# GREȘIT: FROM mcr.microsoft.com/dotnet/aspnet:latest  (nu știți ce primiți mâine)
# GREȘIT: lipsa directivei USER  (procesul rulează ca root)
# GREȘIT: COPY . .  în etapa finală  (ajung în imagine .git, .env, chei)
