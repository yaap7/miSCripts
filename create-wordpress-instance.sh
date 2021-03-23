#!/bin/bash

# script de création d'une instance de wordpress vide
# est prévu pour fonctionner avec apache2 et mariaDB


function show_usage() {
    echo "Usage: $0 [-r] -n <instanceName> [-p|--passDB <DBPassw0rd>]"
    echo '  Mandatory argument:'
    echo '    -n, --name <instanceName>'
    echo '  Optionnal argument:'
    echo '    -r, --remove  : /!\\ remove all data'
    echo '    -c, --cert  : renew lets encrypt certificate using certbot'
    echo '    -p, --passDB <DBPassw0rd>'
    exit 1
}

function debug() {
  [[ "x$DEBUG" == "x1" ]] && echo "$@"
  echo -n ''
}

function info() {
  echo -e "\e[34mInfo\e[0m: $@"
}

function success() {
  echo -e "\e[32mSuccess\e[0m: $@"
}

function error() {
  echo -e "\e[31mError\e[0m: $@" >&2
}

# configuration
DEBUG='0'

# doit-on tout supprimer ?
remove='0'

# doit-on renouveller les certificats lets encrypt ?
cert='0'

# cette variable sera utilisée pour :
# * le sous domaine : $nom.3fu.me
# * le nom du répertoire : /var/www/$nom
# * le nom de la BDD
# * le nom de l'utilisateur de la BDD
nom='default'

# mot de passe de la BDD
passBDD='default'
# le numéro du fichier de configuration d'apache2
# exemple : /etc/apache2/sites-available/${numApache}-${nom}.conf
numApache='050'

# argument parsing
# see: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
POSITIONAL=()
while [[ $# -gt 0 ]] ; do
    key="$1"
    case $key in
        -h|--help)
        show_usage
        ;;
        -n|--name)
        nom="$2"
        shift # past argument
        shift # past value
        ;;
        -p|--passDB)
        passBDD="$2"
        shift # past argument
        shift # past value
        ;;
        -r|--remove)
        remove='1'
        shift # past argument
        ;;
        -c|--cert)
        cert='1'
        shift # past argument
        ;;
        -d|--debug)
        DEBUG='1'
        shift # past argument
        ;;
        *)    # unknown option
        POSITIONAL+=("$1") # save it in an array for later
        shift # past argument
        ;;
    esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [[ "x$nom" == "xdefault" ]] ; then
    show_usage
fi

debug "start of program"

if [[ "x$remove" == "x1" ]] ; then
    # supprimer la base de donnée
    info "Removing database…"
    sudo mysql -u root <<< "revoke all privileges, grant option from '${nom}'@'localhost';"
    sudo mysql -u root <<< "drop user '${nom}'@'localhost';"
    sudo mysql -u root <<< "drop database ${nom};"

    # supprimer les données dans /var/www
    info "Removing data in /var/www/${nom} …"
    sudo rm -r "/var/www/${nom}"

    # supprimer la configuration apache2
    info "Removing apache2 configuration…"
    sudo a2dissite "${numApache}-${nom}.conf"
    sudo rm "/etc/apache2/sites-available/${numApache}-${nom}.conf"

    success "${nom} configuration and data are completely erased!"
    exit 0
fi


if [[ "x$passBDD" == "xdefault" ]] ; then
    show_usage
fi


# création de la BDD avec un user dédié
info "creating database and dedicated user…"
sudo mysql -u root <<< "create database ${nom};"
sudo mysql -u root <<< "create user '${nom}'@'localhost' identified by '${passBDD}';"
sudo mysql -u root <<< "grant all privileges on ${nom}.* to '${nom}'@'localhost';"

# création du répertoire pour wordpress
info "creating wordpress data…"
sudo mkdir "/var/www/${nom}"
cd "/var/www/${nom}"
sudo wget 'https://fr.wordpress.org/latest-fr_FR.tar.gz'
sudo tar -zxf 'latest-fr_FR.tar.gz'
sudo mv wordpress/* ./
sudo rm 'latest-fr_FR.tar.gz' 'wordpress'
sudo chown -R www-data: .

# création du fichier de configuration pour apache
info "creating apache2 configuration…"
cat > "/tmp/${numApache}-${nom}.conf" << EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    # When redirecting everything you don't even need a DocumentRoot
    #DocumentRoot /var/www/${nom}
    Redirect / https://${nom}.3fu.me
    ServerName ${nom}.3fu.me

    # Enable HTTP/2
    Protocols h2 http/1.1

    <IfModule mod_brotli.c>
        BrotliCompressionQuality 10
        #AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/xml text/css text/javascript application/javascript
        SetOutputFilter BROTLI_COMPRESS
        SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png)$ no-brotli
    </IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    <Location "/">
        AllowMethods GET POST
    </Location>
RewriteEngine on
RewriteCond %{SERVER_NAME} =${nom}.3fu.me
RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<IfModule mod_ssl.c>
    <VirtualHost *:443>
        # Basic configuration
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/${nom}
        ServerName ${nom}.3fu.me

        # Enable HTTP/2
        Protocols h2 http/1.1

    <IfModule mod_brotli.c>
        BrotliCompressionQuality 10
        #AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/xml text/css text/javascript application/javascript
        SetOutputFilter BROTLI_COMPRESS
        SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png)$ no-brotli
    </IfModule>

        # Errors and logs
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        <Location "/">
            AllowMethods GET POST
        </Location>

        <Directory /var/www/${nom}>
            Options -Indexes
        </Directory>

        <IfModule mod_expires.c>
            <FilesMatch "\.(jpe?g|png|gif|js|css|woff2)$">
                ExpiresActive On
                ExpiresDefault "access plus 43 days"
            </FilesMatch>
        </IfModule>

        # SSL/TLS Configuration
        SSLEngine on

        # HSTS
        Header always set Strict-Transport-Security "max-age=15768000"
        Include /etc/letsencrypt/options-ssl-apache.conf
        SSLCertificateFile /etc/letsencrypt/live/3fu.me-0003/fullchain.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/3fu.me-0003/privkey.pem
    </VirtualHost>

    SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite          ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
    SSLHonorCipherOrder     on
    SSLCompression          off
    SSLSessionTickets       off

</IfModule>
EOF
sudo mv "/tmp/${numApache}-${nom}.conf" "/etc/apache2/sites-available/${numApache}-${nom}.conf"
sudo chown root:root "/etc/apache2/sites-available/${numApache}-${nom}.conf"
sudo chmod 644 "/etc/apache2/sites-available/${numApache}-${nom}.conf"

# activation du virtualhost
sudo a2ensite "${numApache}-${nom}.conf"
sudo systemctl reload apache2

if [[ "x$cert" == "x1" ]] ; then
    # renouvellement des certificats lets encrypt
    info "renewing lets encrypt certificate…"
    sudo certbot certonly -n --apache --expand -d $(grep -e '^[^#]*ServerName' -e '^[^#]*ServerAlias' /etc/apache2/sites-enabled/* | awk '{ print $3 }' | sort -u | tr '\n' '@' | sed 's_@_ -d _g;s_ -d $__' )
    sudo systemctl restart apache2
fi

success "WordPress instance named ${nom} is successfully installed!"

exit 0
