#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

[[ "$(id -u)" -ne 0 ]] && { echo "ERROR: run as root" >&2; exit 1; }

PRIMARY_IF=$(ip route show default | awk '/default/ { print $5; exit }')

configure_apt_sources() {
    ### Avoir les bons repos Bookworm
    cat << EOT > /etc/apt/sources.list
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware

deb http://deb.debian.org/debian-security/ bookworm-security main contrib non-free
deb-src http://deb.debian.org/debian-security/ bookworm-security main contrib non-free

deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware

# Decommenter pour la dernière version de PHP et signé
# deb https://packages.sury.org/php/ bookworm main
EOT
}

harden_sudo() {
    ### Secure SUDO
    chmod 710 /etc/sudoers.d/

    ### Install package apt-show-versions for patch management purposes [PKGS-7394]
    apt-get install -y apt-show-versions

    ### Replace DNS by GOOGLE dns
    cat <<EOT > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOT
}

generate_gpg_key() {
    ### installer la lib pour encrypter
    apt-get install -y gnupg
    gpg --full-generate-key
}

harden_ssh() {
    ### Modifier la config du serveur SSHD
    cp --preserve /etc/ssh/sshd_config /etc/ssh/sshd_config.$(date +"%Y%m%d%H%M%S")
    cat sshd_config | cat - /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
    sed -i 's/#\?Port .*/Port 666/g' /etc/ssh/sshd_config
    sed -i 's/#\?PermitRootLogin .*/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
    sed -i 's/#\?ClientAliveCountMax .*/ClientAliveCountMax 2/g' /etc/ssh/sshd_config
    ## Consider hardening of SSH configuration [SSH-7408]
    sed -i "s/#\?LogLevel .*/LogLevel VERBOSE/g" /etc/ssh/sshd_config
    sed -i "s/#\?TCPKeepAlive .*/TCPKeepAlive no/g" /etc/ssh/sshd_config
    sed -i "s/#\?X11Forwarding .*/X11Forwarding no/g" /etc/ssh/sshd_config
    service ssh restart
    service sshd restart

    ### Augmenter la sécurité de l'encryptage SSH
    cp --preserve /etc/ssh/moduli /etc/ssh/moduli.$(date +"%Y%m%d%H%M%S")
    awk '$5 >= 3071' /etc/ssh/moduli | tee /etc/ssh/moduli.tmp
    mv /etc/ssh/moduli.tmp /etc/ssh/moduli
}

configure_ntp() {
    ### Installer NTPsec et lui donner une règle de pool
    apt-get install -y ntpsec
    cp --preserve /etc/ntpsec/ntp.conf /etc/ntpsec/ntp.conf.$(date +"%Y%m%d%H%M%S")
    sed -i -r -e "s/^((server|pool).*)/# \1         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")/" /etc/ntpsec/ntp.conf
    echo -e "\npool pool.ntp.org iburst         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | tee -a /etc/ntpsec/ntp.conf
    service ntpsec restart
}

harden_proc() {
    ### Sécurisé le PROC
    cp --preserve /etc/fstab /etc/fstab.$(date +"%Y%m%d%H%M%S")
    echo -e "\nproc     /proc     proc     defaults,hidepid=2,gid=proc     0     0         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | tee -a /etc/fstab
}

configure_password_policy() {
    ### Imposer des mot de passes robustes
    apt-get install -y libpam-pwquality
    cp --preserve /etc/pam.d/common-password /etc/pam.d/common-password.$(date +"%Y%m%d%H%M%S")
    sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")\n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")/" /etc/pam.d/common-password
}

install_web_stack() {
    ### Install PHP + Apache + MYSQL Server + PHPMYADMIN + certbot + composer
    apt-get update
    apt-get upgrade -y
    apt-get install --no-install-recommends apache2 default-mysql-server sudo
    mysql_secure_installation
    apt-get install --no-install-recommends php8.2 libapache2-mod-php8.2 php8.2-mysql php8.2-curl php8.2-gd php8.2-intl php8.2-sqlite3 php8.2-gmp php8.2-mbstring php8.2-xml php8.2-zip php8.2-opcache php-apcu
    a2enmod rewrite
    apt-get install phpmyadmin
    apt-get install certbot
    apt-get install composer
    ### Renommer le phpmyadmin pour eviter les scan et les tentatives de bruteforce
    sed -i 's/Alias .*/Alias \/bdd \/usr\/share\/phpmyadmin/g' /etc/phpmyadmin/apache.conf
    service apache2 restart

    ### Apache 2 module anti DDOS
    apt-get install -y --no-install-recommends apache2-utils libapache2-mod-evasive
    cat << EOT > /etc/apache2/mods-enabled/evasive.conf
<IfModule mod_evasive20.c>
DOSHashTableSize 3097
DOSPageCount 20
DOSSiteCount 100
DOSPageInterval 1
DOSSiteInterval 1
DOSBlockingPeriod 10
DOSEmailNotify YOUR_EMAIL
DOSLogDir "/var/log/apache2/"
</IfModule>
EOT
    systemctl reload apache2

    ### Apache 2 mode security
    apt-get install -y libapache2-mod-security2
    service apache2 restart

    ### Ne pas exposer PHP
    sed -i 's/#\?expose_php.*/expose_php = Off/g' /etc/php/*/*/php.ini
    ### disable downloads via PHP
    sed -i 's/#\?allow_url_fopen.*/allow_url_fopen = Off/g' /etc/php/*/*/php.ini
}

configure_firewall() {
    ### Installer et configurer le firewall
    apt-get install -y ufw iptables
    iptables -A INPUT -m state --state INVALID -j DROP
    # paquet avec SYN et FIN à la fois
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
    # paquet avec SYN et RST à la fois
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
    # paquet avec FIN et RST à la fois
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
    # paquet avec FIN mais sans ACK
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
    # paquet avec URG mais sans ACK
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
    # paquet avec PSH mais sans ACK
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
    # paquet avec tous les flags à 1 <=> XMAS scan dans Nmap
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
    # paquet avec tous les flags à 0 <=> Null scan dans Nmap
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
    # paquet avec FIN,PSH, et URG mais sans SYN, RST ou ACK
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
    # paquet avec FIN,SYN,PSH,URG mais sans ACK ou RST
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
    # paquet avec FIN,SYN,RST,ACK,URG à 1 mais pas PSH
    iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
    # 1. en -t raw, les paquets TCP avec le flag SYN à destination des ports 666,80 ou 443 ne seront pas suivi par le connexion tracker (et donc traités plus rapidement)
    iptables -A PREROUTING -i "$PRIMARY_IF" -p tcp -m multiport --dports 666,80,443 -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CT --notrack
    # 2. en input-filter, les paquets TCP avec le flag SYN à destination des ports 666,80 ou 443 non suivi (UNTRACKED ou INVALID) et les fais suivre à SYNPROXY.
    # C'est à ce moment que synproxy répond le SYN-ACK à l'émeteur du SYN et créer une connexion à l'état ESTABLISHED dans conntrack, si et seulement si l'émetteur retourne un ACK valide.
    # Note : Les paquets avec un tcp-cookie invalides sont dropés, mais pas ceux avec des flags non-standard, il faudra les filtrer par ailleurs.
    iptables -A INPUT -i "$PRIMARY_IF" -p tcp -m multiport --dports 666,80,443 -m tcp -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
    # 3. en input-filter, la règles SYNPROXY doit être suivi de celle-ci pour rejeter les paquets restant en état INVALID.
    iptables -A INPUT -i "$PRIMARY_IF" -p tcp -m multiport --dports 666,80,443 -m tcp -m state --state INVALID -j DROP

    iptables -A INPUT -m recent --rcheck --seconds 86400 --name portscan --mask 255.255.255.255 --rsource -j DROP
    iptables -A INPUT -m recent --remove --name portscan --mask 255.255.255.255 --rsource
    iptables -A INPUT -p tcp -m multiport --dports 25,445,1433,3389 -m recent --set --name portscan --mask 255.255.255.255 --rsource -j DROP
    iptables -A PREROUTING -f -j DROP
    iptables -A PREROUTING -i "$PRIMARY_IF" -p tcp -m tcp --syn -m multiport --dports 666,80,443 -m hashlimit --hashlimit-above 200/sec --hashlimit-burst 1000 --hashlimit-mode srcip --hashlimit-name syn --hashlimit-htable-size 2097152 --hashlimit-srcmask 24 -j DROP
    iptables -A INPUT -i "$PRIMARY_IF" -p tcp -m connlimit --connlimit-above 100 -j REJECT
    ufw logging off
    ufw default allow incoming comment
    ufw default allow outgoing comment
    ufw enable

    ufw default deny incoming comment 'deny all incoming traffic'
    ufw default deny outgoing comment 'deny all outgoing traffic'

    ufw allow out 123/udp comment 'allow npd out'
    ufw allow out 53 comment 'allow npd out'
    ufw allow out http comment 'allow HTTP traffic'
    ufw allow out https comment 'allow HTTPS traffic'
    ufw allow out ftp comment 'allow FTP traffic'
    ufw allow out sftp comment 'allow sftp backup'
    ufw allow out ssh comment  'allow ssh backup'
    ufw allow out 666/tcp comment 'allow ssh devil'
    ufw allow out whois comment 'allow whois'
    ufw allow out 68 comment 'allow the DHCP client to update'
    ufw allow out mail comment 'allow the mail'
    ufw allow out 465/tcp comment 'allow the mail'
    ufw allow out 587/tcp comment 'allow the mail'

    ufw allow http comment 'allow HTTP traffic'
    ufw allow https comment 'allow HTTPS traffic'
    ufw allow ftp comment 'allow FTP traffic'
    ufw allow 123/udp comment 'allow npd'
    ufw allow 666/tcp comment 'allow ssh devil'
    iptables -A INPUT -j LOG --log-tcp-options --log-prefix "[IPTABLES] "
    iptables -A FORWARD -j LOG --log-tcp-options --log-prefix "[IPTABLES] "

    ufw reload
}

configure_psad() {
    # PSAD
    apt-get install -y psad
    cp --preserve /etc/psad/psad.conf /etc/psad/psad.conf.$(date +"%Y%m%d%H%M%S")
    sed -i 's/EMAIL_ADDRESSES .*/EMAIL_ADDRESSES             YOUR_EMAIL;/g' /etc/psad/psad.conf
    sed -i "s/HOSTNAME .*/HOSTNAME             $HOSTNAME;/g" /etc/psad/psad.conf
    sed -i "s/ENABLE_AUTO_IDS .*/ENABLE_AUTO_IDS             Y;/g" /etc/psad/psad.conf
    sed -i "s/ENABLE_AUTO_IDS_EMAILS .*/ENABLE_AUTO_IDS_EMAILS             Y;/g" /etc/psad/psad.conf
    sed -i "s/IPTABLES_BLOCK_METHOD .*/IPTABLES_BLOCK_METHOD             Y;/g" /etc/psad/psad.conf
    #sed -i "s/IMPORT_OLD_SCANS .*/IMPORT_OLD_SCANS             Y;/g" /etc/psad/psad.conf
    sed -i "s/EXPECT_TCP_OPTIONS .*/EXPECT_TCP_OPTIONS             Y;/g" /etc/psad/psad.conf
    sed -i "s/AUTO_IDS_DANGER_LEVEL .*/AUTO_IDS_DANGER_LEVEL       1;/g" /etc/psad/psad.conf
    sed -i "s/EMAIL_ALERT_DANGER_LEVEL .*/EMAIL_ALERT_DANGER_LEVEL       3;/g" /etc/psad/psad.conf
    sed -i "s/AUTO_BLOCK_TIMEOUT .*/AUTO_BLOCK_TIMEOUT       600000;/g" /etc/psad/psad.conf
    sed -i "s/IPT_SYSLOG_FILE .*/IPT_SYSLOG_FILE        /var/log/syslog;/g" /etc/psad/psad.conf

    psad -R
    psad --sig-update
    psad -H
    service psad start
}

configure_fail2ban() {
    ### FAIL2BAN
    apt-get install -y fail2ban
    cp jail.local /etc/fail2ban/
    cp scan-mysql.conf /etc/fail2ban/filter.d/
    cp phpmyadmin.conf /etc/fail2ban/filter.d/
    service fail2ban start
    fail2ban-client start
    fail2ban-client reload
}

install_lynis() {
    ### Lynis
    apt-get install -y git host
    rm -rf /usr/local/lynis
    git clone https://github.com/CISOfy/lynis /usr/local/lynis
    mkdir -p /var/www/html/lynis
    cat <<EOT >> /etc/apache2/sites-enabled/000-default.conf

<Directory "/var/www/html">
    AllowOverride All
</Directory>

EOT
    service apache2 restart
    cat <<EOT > /var/www/html/lynis/.htaccess
AuthType Basic
AuthName "Lynis"
AuthUserFile "/var/www/html/lynis/.htpasswd"
Require valid-user
EOT
    echo 'lynis:$apr1$AoXXpNJ2$E82n/O0IU7XY0vP/FaMCK0' > /var/www/html/lynis/.htpasswd
    lynis audit system | ansi2html > /var/www/html/lynis/index.html
}

configure_postfix() {
    ### Mail
    apt-get install -y mailutils postfix
    sed -i "s/inet_interfaces.*/inet_interfaces = loopback-only/g" /etc/postfix/main.cf
    sed -i "s/smtpd_banner.*/smtpd_banner = $myhostname ESMTP/g" /etc/postfix/main.cf
    systemctl restart postfix
    echo "This is the body of the email" | mail -s "This is the subject line" YOUR_EMAIL
}

configure_login_policy() {
    ### Changer la sécurité des login en 027
    sed -i "s/UMASK.*/UMASK           027/g" /etc/login.defs
}

cleanup_packages() {
    ### Purges les packets non utilisés
    apt-get purge `dpkg --list | grep ^rc | awk '{ print $2; }'`
    dpkg --list | grep "^rc" | cut -d " " -f 3 | xargs dpkg --purge

    ### Vérificateur de package
    apt-get install -y debsums
    apt-get install --reinstall $(dpkg-query -S $(debsums -c 2>&1 | sed -e "s/.*file \(.*\) (.*/\1/g") | cut -d: -f1 | sort -u)
}

configure_banners() {
    ## Add a legal banner to /etc/issue, to warn unauthorized users [BANN-7126]
    echo "Serveur managed by Folken with love, les indesirables ne sont pas les bienvenus ici." > /etc/issue

    ## Add legal banner to /etc/issue.net, to warn unauthorized users [BANN-7130]
    echo "Serveur managed by Folken with love, les indesirables ne sont pas les bienvenus ici." > /etc/issue.net
}

configure_monitoring() {
    ### Surveiller les users
    apt-get install -y acct
    touch /var/log/pacct
    accton /var/log/pacct
    /etc/init.d/acct start

    ## Enable sysstat to collect accounting (no results) [ACCT-9626]
    apt-get install -y sysstat
    sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
}

install_aide() {
    ### AIDE for check integrity config file
    apt-get install -y aide
    aide.wrapper --init
    ## pour tester l'integrité ensuite
    aide.wrapper --check
    ## pour accepter des changements
    aide.wrapper --update
}

install_rkhunter() {
    ### Rkhunter anti rootkit
    apt-get install -y rkhunter
    sed -i "s/#\?MAIL-ON-WARNING.*/MAIL-ON-WARNING=YOUR_EMAIL/g" /etc/rkhunter.conf
    service ssh restart
    rkhunter --propupdate
    rkhunter -c --sk --display-logfile
}

main() {
    configure_apt_sources
    harden_sudo
    generate_gpg_key
    harden_ssh
    configure_ntp
    harden_proc
    configure_password_policy
    install_web_stack
    configure_firewall
    configure_psad
    configure_fail2ban
    install_lynis
    configure_postfix
    configure_login_policy
    cleanup_packages
    configure_banners
    configure_monitoring
    install_aide
    install_rkhunter
}

main "$@"
