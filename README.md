### Modifier la config du serveur SSHD
```shell
sudo cp --preserve /etc/ssh/sshd_config /etc/ssh/sshd_config.$(date +"%Y%m%d%H%M%S")
sudo sed -i 's/#\?Port .*/Port 666/g' /etc/ssh/sshd_config
sudo sed -i 's/#\?PermitRootLogin .*/PermitRootLogin without-password/g' /etc/ssh/sshd_config
sudo sed -i 's/#\?#PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config

sudo service ssh restart
sudo service sshd restart
```

### Augmenter la sécurité de l'encryptage SSH
```shell
sudo cp --preserve /etc/ssh/moduli /etc/ssh/moduli.$(date +"%Y%m%d%H%M%S")
sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp
sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli
```

### Installer NTP et lui donner une règle de pool
```shell
sudo apt install -y ntp
sudo cp --preserve /etc/ntp.conf /etc/ntp.conf.$(date +"%Y%m%d%H%M%S")
sudo sed -i -r -e "s/^((server|pool).*)/# \1         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")/" /etc/ntp.conf
echo -e "\npool pool.ntp.org iburst         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/ntp.conf
sudo service ntp restart
```

### Sécurisé le PROC
```shell
sudo cp --preserve /etc/fstab /etc/fstab.$(date +"%Y%m%d%H%M%S")
echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/fstab
```

### Imposer des mot de passes robustes
```shell
sudo apt install -y libpam-pwquality 
sudo cp --preserve /etc/pam.d/common-password /etc/pam.d/common-password.$(date +"%Y%m%d%H%M%S")
sudo sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")\n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")/" /etc/pam.d/common-password
```

### Installer et configurer le firewall
```shell
sudo apt install -y ufw
sudo ufw reset
sudo ufw default deny incoming comment 'deny all incoming traffic'
sudo ufw default deny outgoing comment 'deny all outgoing traffic'

sudo ufw allow out 53 comment 'allow DNS calls out'
sudo ufw allow out 123 comment 'allow NTP out'
sudo ufw allow out http comment 'allow HTTP traffic out'
sudo ufw allow out https comment 'allow HTTPS traffic out'
sudo ufw allow out ftp comment 'allow FTP traffic out'
sudo ufw allow out sftp comment 'allow sftp backup'
sudo ufw allow out ssh comment  'allow ssh backup'
sudo ufw allow out 666/tcp comment 'allow ssh backup'
sudo ufw allow out whois comment 'allow whois'
sudo ufw allow out 68 comment 'allow the DHCP client to update'
sudo ufw allow out mail comment 'allow the mail'
sudo ufw allow out 465/tcp comment 'allow the mail'
sudo ufw allow out 587/tcp comment 'allow the mail'

sudo ufw allow 666/tcp comment 'allow devil ssh port'
sudo ufw disable
sudo ufw enable
```

### PSAD
```shell
sudo apt install -y psad
sudo cp --preserve /etc/psad/psad.conf /etc/psad/psad.conf.$(date +"%Y%m%d%H%M%S")
sudo sed -i 's/EMAIL_ADDRESSES .*/EMAIL_ADDRESSES             folken70@hotmail.com;/g' /etc/psad/psad.conf
sudo sed -i "s/HOSTNAME .*/HOSTNAME             $HOSTNAME;/g" /etc/psad/psad.conf
sudo sed -i "s/ENABLE_AUTO_IDS .*/ENABLE_AUTO_IDS             Y;/g" /etc/psad/psad.conf
sudo sed -i "s/ENABLE_AUTO_IDS_EMAILS .*/ENABLE_AUTO_IDS_EMAILS             Y;/g" /etc/psad/psad.conf
sudo sed -i "s/EXPECT_TCP_OPTIONS .*/EXPECT_TCP_OPTIONS             Y;/g" /etc/psad/psad.conf
sudo cp --preserve /etc/ufw/before.rules /etc/ufw/before.rules.$(date +"%Y%m%d%H%M%S")
sudo cp --preserve /etc/ufw/before6.rules /etc/ufw/before6.rules.$(date +"%Y%m%d%H%M%S")
sudo sed -i 's/^COMMIT/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo sed -i 's/^COMMIT.*/-A INPUT -j LOG --log-tcp-options --log-prefix "[IPTABLES] "\n-A FORWARD -j LOG --log-tcp-options --log-prefix "[IPTABLES] "\nCOMMIT/g' /etc/ufw/before.rules
sudo sed -i 's/^COMMIT.*/-A INPUT -j LOG --log-tcp-options --log-prefix "[IPTABLES] "\n-A FORWARD -j LOG --log-tcp-options --log-prefix "[IPTABLES] "\nCOMMIT/g' /etc/ufw/before6.rules
sudo ufw reload

sudo psad -R
sudo psad --sig-update
sudo psad -H
```

### FAIL2BAN
```shell
sudo apt install -y fail2ban
cat << EOF | sudo tee /etc/fail2ban/jail.d/ssh.local
[sshd]
enabled = true
banaction = ufw
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 5
EOF
sudo fail2ban-client start
sudo fail2ban-client reload
sudo fail2ban-client add sshd
```

### Lynis
```shell
sudo apt install apt-transport-https ca-certificates host
sudo wget -O - https://packages.cisofy.com/keys/cisofy-software-public.key | sudo apt-key add -
sudo echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
sudo apt update
sudo apt install -y lynis host
# TODO faire un scan et un envois des resultat par mails
# sudo lynis audit system
```

### Mail
```shell
sudo apt-get install -y mailutils postfix
sudo sed -i "s/inet_interfaces.*/inet_interfaces = loopback-only/g" /etc/postfix/main.cf
sudo systemctl restart postfix
echo "This is the body of the email" | mail -s "This is the subject line" folken70@hotmail.com
```
