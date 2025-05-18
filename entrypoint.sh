#!/bin/bash
set -e # Arrêter le script en cas d'erreur

CERT_DIR="/app/certs"
CONFIG_DIR="/app/config" # Pour series_mappings.json, etc.

# Créer les répertoires s'ils n'existent pas (utile si les volumes ne sont pas pré-créés)
mkdir -p "$CERT_DIR"
mkdir -p "$CONFIG_DIR"
# S'assurer que l'application peut écrire dans le répertoire de config pour les fichiers JSON
# (Docker gère généralement bien les permissions des volumes montés, mais une vérification peut être utile)
# chown -R <user>:<group> "$CONFIG_DIR" # Si vous lancez l'appli avec un utilisateur non-root

CA_KEY="$CERT_DIR/mylocalca.key"
CA_CERT="$CERT_DIR/mylocalca.crt"
SERVER_KEY="$CERT_DIR/services.sonarr.tv.key"
SERVER_CERT="$CERT_DIR/services.sonarr.tv.crt"
SERVER_CSR="$CERT_DIR/services.sonarr.tv.csr" # Fichier temporaire
SERVER_EXT="$CERT_DIR/services.sonarr.tv.ext" # Fichier temporaire
CA_SERIAL="$CERT_DIR/mylocalca.srl"       # Fichier de série

# Vérifier si la CA existe déjà
if [ -f "$CA_CERT" ] && [ -f "$CA_KEY" ]; then
    echo "INFO: Utilisation de la CA locale existante trouvée dans $CERT_DIR."
else
    echo "INFO: Aucune CA locale trouvée. Génération d'une nouvelle CA dans $CERT_DIR..."
    # Générer la clé privée de la CA (sans mot de passe pour le lancement automatique)
    openssl genrsa -out "$CA_KEY" 4096
    # Générer le certificat racine de la CA
    openssl req -new -x509 -sha256 -days 3650 -key "$CA_KEY" -out "$CA_CERT" \
        -subj "/C=XX/ST=State/L=ProxyCity/O=SonarrProxyInstance/OU=LocalCA/CN=Sonarr Proxy Local CA $(date +%s)"
    echo "INFO: Nouvelle CA locale générée : $CA_CERT"
    echo "----------------------------------------------------------------------"
    echo "IMPORTANT: Vous devez installer le certificat de CA suivant sur la machine"
    echo "exécutant Sonarr pour qu'il fasse confiance à ce proxy pour les connexions HTTPS :"
    echo "$CA_CERT"
    echo "(Ce fichier est disponible dans le volume que vous avez monté sur $CERT_DIR)"
    echo "Contenu de $CA_CERT :"
    cat "$CA_CERT"
    echo "----------------------------------------------------------------------"
fi

# Vérifier si le certificat serveur existe déjà (et est valide, plus complexe à vérifier la validité ici)
# Pour simplifier, on régénère le cert serveur s'il manque ou si la CA a été (re)générée (ce qui ne devrait pas arriver après le 1er lancement si persisté)
# Une vérification de validité plus poussée pourrait utiliser `openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"`
if [ -f "$SERVER_CERT" ] && [ -f "$SERVER_KEY" ]; then
    echo "INFO: Utilisation du certificat serveur existant trouvé dans $CERT_DIR."
    # Optionnel : vérifier si le certificat serveur est toujours valide et signé par la CA actuelle
    if ! openssl verify -CAfile "$CA_CERT" "$SERVER_CERT" > /dev/null 2>&1; then
        echo "AVERTISSEMENT: Le certificat serveur existant n'est pas valide ou n'est pas signé par la CA actuelle. Régénération..."
        rm -f "$SERVER_KEY" "$SERVER_CERT" "$SERVER_CSR" "$SERVER_EXT" # Supprimer les anciens pour forcer la régénération
    fi
fi


if [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
    echo "INFO: Aucun certificat serveur valide trouvé ou CA mise à jour. Génération d'un nouveau certificat serveur..."
    openssl genrsa -out "$SERVER_KEY" 2048

    cat <<EOT > "$SERVER_EXT"
    authorityKeyIdentifier=keyid,issuer
    basicConstraints=CA:FALSE
    keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
    subjectAltName = @alt_names
    [alt_names]
    DNS.1 = services.sonarr.tv
EOT

    openssl req -new -sha256 -key "$SERVER_KEY" -out "$SERVER_CSR" \
        -subj "/C=XX/ST=State/L=ProxyCity/O=SonarrProxyInstance/OU=Server/CN=services.sonarr.tv"

    # S'assurer que le fichier de série est utilisé correctement
    if [ ! -f "$CA_SERIAL" ]; then
        echo "01" > "$CA_SERIAL" # Initialiser le fichier de série s'il n'existe pas
    fi

    openssl x509 -req -sha256 -in "$SERVER_CSR" \
        -CA "$CA_CERT" -CAkey "$CA_KEY" -CAserial "$CA_SERIAL" \
        -out "$SERVER_CERT" \
        -days 398 \
        -extfile "$SERVER_EXT"
    
    echo "INFO: Nouveau certificat serveur généré : $SERVER_CERT"
    rm -f "$SERVER_CSR" "$SERVER_EXT" # Nettoyer les fichiers temporaires
fi

echo "INFO: Vérification du certificat serveur..."
openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"

# S'assurer que les fichiers de configuration JSON existent (l'application Go les créera si absents mais le montage peut avoir des soucis de droits)
touch "$CONFIG_DIR/series_mappings.json"
touch "$CONFIG_DIR/interception_rules.json"

echo "INFO: Lancement de l'application proxy Sonarr..."
# Exécute la commande passée au Dockerfile (CMD)
exec "$@"