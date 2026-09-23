# Etapa 1: compilare
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
COPY Honeypot.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app --no-restore

# Etapa 2: imagine de rulare, fără SDK și fără cod sursă
FROM mcr.microsoft.com/dotnet/runtime:10.0-alpine AS runtime
WORKDIR /app
COPY --from=build /app .

# Directorul bazei de date aparține utilizatorului non-root „app” (UID 1654)
RUN mkdir -p /data && chown $APP_UID /data
USER $APP_UID

ENV HONEYPOT_DB_PATH=/data/honeypot.db \
    DOTNET_EnableDiagnostics=0

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:9090/ || exit 1

ENTRYPOINT ["dotnet", "Honeypot.dll"]
