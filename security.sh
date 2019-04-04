#!/bin/bash

### Avoir les bon repo stretch
cat << EOT > /etc/apt/sources.list
deb http://deb.debian.org/debian stretch main contrib non-free
deb-src http://deb.debian.org/debian stretch main contrib non-free

deb http://deb.debian.org/debian-security/ stretch/updates main contrib non-free
deb-src http://deb.debian.org/debian-security/ stretch/updates main contrib non-free

deb http://deb.debian.org/debian stretch-updates main contrib non-free
deb-src http://deb.debian.org/debian stretch-updates main contrib non-free

# Decommenter pour la dernière version de PHP et signé
# deb https://packages.sury.org/php/ stretch main
EOT

### Secure SUDO
sudo chmod 710 /etc/sudoers.d/

### Install package apt-show-versions for patch management purposes [PKGS-7394] 
apt-get install -y apt-show-versions 
 
### Replace DNS by GOOGLE dns (scaleway online dns are fucking shit)
cat <<EOT > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOT

### installer la lib pour encrypter 
sudo apt install -y gnupg
sudo gpg --full-generate-key

### Modifier la config du serveur SSHD
sudo cp --preserve /etc/ssh/sshd_config /etc/ssh/sshd_config.$(date +"%Y%m%d%H%M%S")
sudo cat sshd_config | sudo cat - /etc/ssh/sshd_config > temp && sudo mv temp /etc/ssh/sshd_config
sudo sed -i 's/#\?Port .*/Port 666/g' /etc/ssh/sshd_config
sudo sed -i 's/#\?PermitRootLogin .*/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
sudo sed -i 's/#\?PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo sed -i 's/#\?ClientAliveCountMax .*/ClientAliveCountMax 2/g' /etc/ssh/sshd_config
## Consider hardening of SSH configuration [SSH-7408] 
sudo sed -i "s/#\?LogLevel .*/LogLevel VERBOSE/g" /etc/ssh/sshd_config
sudo sed -i "s/#\?TCPKeepAlive .*/TCPKeepAlive no/g" /etc/ssh/sshd_config
sudo sed -i "s/#\?X11Forwarding .*/X11Forwarding no/g" /etc/ssh/sshd_config
sudo sed -i "s/#\?UsePrivilegeSeparation .*/UsePrivilegeSeparation sandbox/g" /etc/ssh/sshd_config
sudo service ssh restart
sudo service sshd restart

### Augmenter la sécurité de l'encryptage SSH
sudo cp --preserve /etc/ssh/moduli /etc/ssh/moduli.$(date +"%Y%m%d%H%M%S")
sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp
sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli

### Installer NTP et lui donner une règle de pool
sudo apt install -y ntp
sudo cp --preserve /etc/ntp.conf /etc/ntp.conf.$(date +"%Y%m%d%H%M%S")
sudo sed -i -r -e "s/^((server|pool).*)/# \1         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")/" /etc/ntp.conf
echo -e "\npool pool.ntp.org iburst         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/ntp.conf
sudo service ntp restart

### Sécurisé le PROC
sudo cp --preserve /etc/fstab /etc/fstab.$(date +"%Y%m%d%H%M%S")
echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/fstab

### Imposer des mot de passes robustes
sudo apt install -y libpam-pwquality 
sudo cp --preserve /etc/pam.d/common-password /etc/pam.d/common-password.$(date +"%Y%m%d%H%M%S")
sudo sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")\n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")/" /etc/pam.d/common-password


### Install PHP + Apache + MYSQL Server + PHPMYADMIN + certbot + composer
sudo apt update
sudo apt-get upgrade
sudo apt install apache2 default-mysql-server sudo
sudo mysql_secure_installation
sudo apt install php7.2 libapache2-mod-php7.2 php7.2-mysql php7.2-curl php7.2-json php7.2-gd php7.2-intl php7.2-sqlite3 php7.2-gmp php7.2-mbstring php7.2-xml php7.2-zip php7.2-opcache php-apcu
sudo a2enmod rewrite
sudo apt install phpmyadmin
sudo apt install certbot
sudo apt install composer
### Renommer le phpmyadmin pour eviter les scan et les tentatives de bruteforce
sudo sed -i 's/Alias .*/Alias \/bdd \/usr\/share\/phpmyadmin/g' /etc/phpmyadmin/apache.conf
sudo service apache2 restart

### Apache 2 module anti DDOS
apt-get install -y apache2-utils libapache2-mod-evasive
cat << EOT > /etc/apache2/mods-enabled/evasive.conf
<IfModule mod_evasive20.c>
DOSHashTableSize 3097
DOSPageCount 2
DOSSiteCount 50
DOSPageInterval 1
DOSSiteInterval 1
DOSBlockingPeriod 10
DOSEmailNotify folken70@hotmail.com
DOSLogDir "/var/log/apache2/"
</IfModule>
EOT
sudo systemctl reload apache2

### Apache 2 mode security
sudo apt install -y libapache2-modsecurity
sudo service apache2 restart

### Ne pas exposer PHP
sudo sed -i 's/#\?expose_php.*/expose_php = Off/g' /etc/php/*/*/php.ini
### disable downloads via PHP
sudo sed -i 's/#\?allow_url_fopen.*/allow_url_fopen = Off/g' /etc/php/*/*/php.ini

### Installer et configurer le firewall
sudo apt install -y ufw iptables
sudo iptables -A INPUT -m state --state INVALID -j DROP
# paquet avec SYN et FIN à la fois
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
# paquet avec SYN et RST à la fois
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
# paquet avec FIN et RST à la fois
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
# paquet avec FIN mais sans ACK
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
# paquet avec URG mais sans ACK
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
# paquet avec PSH mais sans ACK
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
# paquet avec tous les flags à 1 <=> XMAS scan dans Nmap
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
# paquet avec tous les flags à 0 <=> Null scan dans Nmap
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
# paquet avec FIN,PSH, et URG mais sans SYN, RST ou ACK
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
# paquet avec FIN,SYN,PSH,URG mais sans ACK ou RST
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
# paquet avec FIN,SYN,RST,ACK,URG à 1 mais pas PSH
sudo iptables -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
# 1. en -t raw, les paquets TCP avec le flag SYN à destination des ports 22,80 ou 443 ne seront pas suivi par le connexion tracker (et donc traités plus rapidement)
sudo iptables -A PREROUTING -i eth0 -p tcp -m multiport --dports 22,80,443 -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CT --notrack
# 2. en input-filter, les paquets TCP avec le flag SYN à destination des ports 22,80 ou 443 non suivi (UNTRACKED ou INVALID) et les fais suivre à SYNPROXY.
# C'est à ce moment que synproxy répond le SYN-ACK à l'émeteur du SYN et créer une connexion à l'état ESTABLISHED dans conntrack, si et seulement si l'émetteur retourne un ACK valide.
# Note : Les paquets avec un tcp-cookie invalides sont dropés, mais pas ceux avec des flags non-standard, il faudra les filtrer par ailleurs. 
sudo iptables -A INPUT -i eth0 -p tcp -m multiport --dports 22,80,443 -m tcp -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
# 3. en input-filter, la règles SYNPROXY doit être suivi de celle-ci pour rejeter les paquets restant en état INVALID.
sudo iptables -A INPUT -i eth0 -p tcp -m multiport --dports 22,80,443 -m tcp -m state --state INVALID -j DROP

sudo iptables -A INPUT -m recent --rcheck --seconds 86400 --name portscan --mask 255.255.255.255 --rsource -j DROP
sudo iptables -A INPUT -m recent --remove --name portscan --mask 255.255.255.255 --rsource
sudo iptables -A INPUT -p tcp -m multiport --dports 25,445,1433,3389 -m recent --set --name portscan --mask 255.255.255.255 --rsource -j DROP
sudo iptables -A PREROUTING -f -j DROP
sudo iptables -A PREROUTING -i eth0 -p tcp -m tcp --syn -m multiport --dports 22,80,443 -m hashlimit --hashlimit-above 200/sec --hashlimit-burst 1000 --hashlimit-mode srcip --hashlimit-name syn --hashlimit-htable-size 2097152 --hashlimit-srcmask 24 -j DROP
sudo iptables -A INPUT -i eth0 -p tcp -m connlimit --connlimit-above 100 -j REJECT
sudo ufw logging off
sudo ufw default allow incoming comment 
sudo ufw default allow outgoing comment 
sudo ufw enable

sudo ufw default deny incoming comment 'deny all incoming traffic'
sudo ufw default deny outgoing comment 'deny all outgoing traffic'

sudo ufw allow out 123/udp comment 'allow npd out'
sudo ufw allow out 53 comment 'allow npd out'
sudo ufw allow out http comment 'allow HTTP traffic'
sudo ufw allow out https comment 'allow HTTPS traffic'
sudo ufw allow out ftp comment 'allow FTP traffic'
sudo ufw allow out sftp comment 'allow sftp backup'
sudo ufw allow out ssh comment  'allow ssh backup'
sudo ufw allow out 666/tcp comment 'allow ssh devil'
sudo ufw allow out whois comment 'allow whois'
sudo ufw allow out 68 comment 'allow the DHCP client to update'
sudo ufw allow out mail comment 'allow the mail'
sudo ufw allow out 465/tcp comment 'allow the mail'
sudo ufw allow out 587/tcp comment 'allow the mail'

sudo ufw allow http comment 'allow HTTP traffic'
sudo ufw allow https comment 'allow HTTPS traffic'
sudo ufw allow ftp comment 'allow FTP traffic'
sudo ufw allow 123/udp comment 'allow npd'
sudo ufw allow 666/tcp comment 'allow ssh devil'
sudo iptables -A INPUT -j LOG --log-tcp-options --log-prefix "[IPTABLES] "
sudo iptables -A FORWARD -j LOG --log-tcp-options --log-prefix "[IPTABLES] "

sudo ufw reload


# PSAD
sudo apt install -y psad
sudo cp --preserve /etc/psad/psad.conf /etc/psad/psad.conf.$(date +"%Y%m%d%H%M%S")
sudo sed -i 's/EMAIL_ADDRESSES .*/EMAIL_ADDRESSES             folken70@hotmail.com;/g' /etc/psad/psad.conf
sudo sed -i "s/HOSTNAME .*/HOSTNAME             $HOSTNAME;/g" /etc/psad/psad.conf
sudo sed -i "s/ENABLE_AUTO_IDS .*/ENABLE_AUTO_IDS             Y;/g" /etc/psad/psad.conf
sudo sed -i "s/ENABLE_AUTO_IDS_EMAILS .*/ENABLE_AUTO_IDS_EMAILS             Y;/g" /etc/psad/psad.
sudo sed -i "s/IPTABLES_BLOCK_METHOD .*/IPTABLES_BLOCK_METHOD             Y;/g" /etc/psad/psad.conf
#sudo sed -i "s/IMPORT_OLD_SCANS .*/IMPORT_OLD_SCANS             Y;/g" /etc/psad/psad.conf
sudo sed -i "s/EXPECT_TCP_OPTIONS .*/EXPECT_TCP_OPTIONS             Y;/g" /etc/psad/psad.conf
sudo sed -i "s/AUTO_IDS_DANGER_LEVEL .*/AUTO_IDS_DANGER_LEVEL       1;/g" /etc/psad/psad.conf
sudo sed -i "s/EMAIL_ALERT_DANGER_LEVEL .*/EMAIL_ALERT_DANGER_LEVEL       3;/g" /etc/psad/psad.conf
sudo sed -i "s/AUTO_BLOCK_TIMEOUT .*/AUTO_BLOCK_TIMEOUT       600000;/g" /etc/psad/psad.conf
sudo sed -i "s/IPT_SYSLOG_FILE .*/IPT_SYSLOG_FILE        /var/log/syslog;/g" /etc/psad/psad.conf

sudo psad -R
sudo psad --sig-update
sudo psad -H
sudo service psad start

### FAIL2BAN
sudo apt install -y fail2ban
sudo cp jail.local /etc/fail2ban/
sudo cp scan-mysql.conf /etc/fail2ban/filter.d/
sudo cp phpmyadmin.conf /etc/fail2ban/filter.d/
sudo service fail2ban start
sudo fail2ban-client start
sudo fail2ban-client reload

### Lynis
sudo apt install -y git host kbtin
sudo rm -rf /usr/local/lynis
cd /usr/local/
sudo git clone https://github.com/CISOfy/lynis
sudo mkdir -p /var/www/html/lynis
cat <<EOT >> /etc/apache2/sites-enabled/000-default.conf

<Directory "/var/www/html">
    AllowOverride All
</Directory>

EOT
sudo service apache2 restart
cat <<EOT > /var/www/html/lynis/.htaccess
AuthType Basic
AuthName "Lynis"
AuthUserFile "/var/www/html/lynis/.htpasswd"
Require valid-user
EOT
echo 'lynis:$apr1$AoXXpNJ2$E82n/O0IU7XY0vP/FaMCK0' > /var/www/html/lynis/.htpasswd
lynis audit system | ansi2html > /var/www/html/lynis/index.html

### Mail
sudo apt-get install -y mailutils postfix
sudo sed -i "s/inet_interfaces.*/inet_interfaces = loopback-only/g" /etc/postfix/main.cf
sudo sed -i "s/smtpd_banner.*/smtpd_banner = $myhostname ESMTP/g" /etc/postfix/main.cf
sudo systemctl restart postfix
echo "This is the body of the email" | mail -s "This is the subject line" folken70@hotmail.com

### Changer la sécurité des login en 023
sudo sed -i "s/UMASK.*/UMASK           027/g" /etc/login.defs

### Purges les packets non utilisés
sudo apt purge `dpkg --list | grep ^rc | awk '{ print $2; }'`
dpkg --list | grep "^rc" | cut -d " " -f 3 | xargs sudo dpkg --purge

### Vérificateur de package
sudo apt-get install -y debsums
sudo apt-get install --reinstall $(dpkg-query -S $(sudo debsums -c 2>&1 | sed -e "s/.*file \(.*\) (.*/\1/g") | cut -d: -f1 | sort -u)

## Add a legal banner to /etc/issue, to warn unauthorized users [BANN-7126] 
echo "Serveur managed by Folken with love, les indesirables ne sont pas les bienvenus ici." > /etc/issue
 
## Add legal banner to /etc/issue.net, to warn unauthorized users [BANN-7130] 
echo "Serveur managed by Folken with love, les indesirables ne sont pas les bienvenus ici." > /etc/issue.net

### Surveiller les users
sudo apt-get install -y acct
sudo touch /var/log/pacct
sudo accton /var/log/pacct
sudo /etc/init.d/acct start

## Enable sysstat to collect accounting (no results) [ACCT-9626] 
sudo apt-get install -y sysstat
sudo sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat

### Aide for check integrity config file
sudo apt-get -y aide
sudo aide.wrapper --init
## pour tester l'integrité ensuite
sudo aide.wrapper --check
## pour accepter des changement
sudo aide.wrapper --update

### Rkhunter anti rootkit
sudo apt-get install -y rkhunter
sudo sed -i "s/#\?MAIL-ON-WARNING.*/MAIL-ON-WARNING=folken70@hotmail.com/g" /etc/rkhunter.conf
sudo service ssh restart
sudo rkhunter --propupdate
rkhunter -c --sk --display-logfile 