### Modifier la config du serveur SSHD
```shell
sudo cp --preserve /etc/ssh/sshd_config /etc/ssh/sshd_config.$(date +"%Y%m%d%H%M%S")
sudo sed -i -r -e '/^#|^$/ d' /etc/ssh/sshd_config
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
sudo ufw default deny outgoing comment 'deny all outgoing traffic'
sudo ufw default allow incoming comment 'allow all incoming traffic'

# allow traffic out on port 53 -- DNS
sudo ufw allow out 53 comment 'allow DNS calls out'
# allow traffic out on port 123 -- NTP
sudo ufw allow out 123 comment 'allow NTP out'
# allow traffic out for HTTP, HTTPS, or FTP
# apt might needs these depending on which sources you're using
sudo ufw allow out http comment 'allow HTTP traffic out'
sudo ufw allow out https comment 'allow HTTPS traffic out'
sudo ufw allow out ftp comment 'allow FTP traffic out'
# allow whois
sudo ufw allow out whois comment 'allow whois'
# allow traffic out on port 68 -- the DHCP client
# you only need this if you're using DHCP
sudo ufw allow out 68 comment 'allow the DHCP client to update'
```
