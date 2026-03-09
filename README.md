# Sécurisation Debian 12 (Bookworm)

Script et configurations pour renforcer la sécurité d'un serveur Debian 12, couvrant : durcissement SSH, firewall iptables/ufw, fail2ban, PSAD, Lynis, rkhunter, Apache + PHP 8.2.

> Testé sur Debian 12 Bookworm.

---

## Stack / Outils couverts

- **SSH** — durcissement de sshd_config (algorithmes modernes, désactivation des options obsolètes)
- **UFW / iptables** — firewall applicatif + règles de protection contre les scans et flood
- **fail2ban** — bannissement automatique des IPs malveillantes (SSH, Apache, phpMyAdmin, MySQL…)
- **PSAD** — détection de scans de ports via les logs iptables
- **Lynis** — audit de sécurité du système
- **rkhunter** — détection de rootkits
- **AIDE** — vérification d'intégrité des fichiers
- **Apache 2 + PHP 8.2** — durcissement (mod_evasive, mod_security2, expose_php, allow_url_fopen)
- **MySQL** — installation sécurisée
- **Postfix** — MTA local (loopback only)
- **PAM / pwquality** — politique de mots de passe robuste
- **NTPsec** — synchronisation horaire sécurisée
- **sysstat / acct** — surveillance des activités système
- **debsums / apt-show-versions** — vérification d'intégrité des paquets

---

## Utilisation

```bash
git clone https://github.com/ohugonnot/security-debian.git
cd security-debian

# Personnaliser l'adresse e-mail avant de lancer le script
grep -r "YOUR_EMAIL" .

sudo bash security.sh
```

---

## Ce que fait le script

- Configure les dépôts officiels Debian 12 (Bookworm)
- Sécurise `sudo` (permissions sur `/etc/sudoers.d/`)
- Remplace les DNS par Google DNS
- Durcit la configuration SSH (port personnalisé, algorithmes modernes, sans directives obsolètes)
- Filtre les DH params faibles dans `/etc/ssh/moduli` (>= 3071 bits)
- Configure NTPsec pour la synchronisation horaire
- Protège `/proc` via `hidepid=2,gid=proc` dans `/etc/fstab`
- Impose une politique de mots de passe robuste via `libpam-pwquality`
- Installe Apache 2, PHP 8.2, MySQL, phpMyAdmin, certbot et composer
- Renomme l'alias phpMyAdmin pour éviter les scans automatiques
- Active mod_evasive (anti-DDoS) et mod_security2 (WAF) pour Apache
- Masque la version PHP (`expose_php = Off`, `allow_url_fopen = Off`)
- Configure UFW et iptables (règles anti-scan, SYN-proxy, rate limiting)
- Installe et configure PSAD (détection de scans de ports, blocage automatique)
- Installe et configure fail2ban avec des jails pour SSH, Apache, phpMyAdmin, MySQL, Postfix…
- Clone et exécute Lynis pour un audit de sécurité complet
- Configure Postfix en mode loopback-only
- Ajuste l'umask à 027 dans `/etc/login.defs`
- Purge les paquets orphelins
- Installe debsums pour vérifier l'intégrité des paquets
- Ajoute des bandeaux légaux dans `/etc/issue` et `/etc/issue.net`
- Active la comptabilité des processus (`acct`) et les statistiques système (`sysstat`)
- Installe et initialise AIDE pour la vérification d'intégrité des fichiers
- Installe rkhunter pour la détection de rootkits

---

## Configuration

Avant de lancer le script, remplacez le placeholder `YOUR_EMAIL` par votre adresse e-mail réelle dans les fichiers suivants :

- `security.sh` — utilisé pour les alertes PSAD, mod_evasive, rkhunter et Postfix
- `jail.local` — utilisé pour les alertes fail2ban

```bash
sed -i 's/YOUR_EMAIL/votre@email.com/g' security.sh jail.local
```

---

## Avant de lancer le script

> **Attention :** Le port SSH passe à 666. Vérifiez que votre firewall
> autorise ce port avant de couper votre session en cours.

## Avertissement

Ce script est fourni à titre éducatif. Adaptez-le à votre environnement avant de l'exécuter en production (interface réseau, ports, chemins, etc.).
