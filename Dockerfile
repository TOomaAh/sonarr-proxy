# Étape 1: Compiler l'application Go
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/sonarr-proxy .

# Étape 2: Image finale
FROM alpine:latest

# Installer les outils nécessaires pour le script d'entrée (openssl, bash)
# et ca-certificates pour les connexions sortantes du proxy si nécessaire.
RUN apk add --no-cache openssl bash ca-certificates

WORKDIR /app

# Copier l'exécutable compilé
COPY --from=builder /app/sonarr-proxy /app/sonarr-proxy

# Copier le script d'entrée
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Définir le répertoire pour les certificats (sera monté en volume)
# Et pour les fichiers de configuration
VOLUME ["/app/certs", "/app/config"]

# Exposer le port du proxy
EXPOSE 8990

# Utiliser le script d'entrée comme ENTRYPOINT
ENTRYPOINT ["/app/entrypoint.sh"]
# CMD est ce qui est passé comme argument à entrypoint.sh, ici c'est la commande pour lancer le proxy
CMD ["/app/sonarr-proxy"]