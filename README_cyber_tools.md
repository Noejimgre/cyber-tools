# 🔐 Cyber Security Tools

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Education](https://img.shields.io/badge/Purpose-Educational-blue?style=for-the-badge)

**Collection de 5 outils Python orientés cybersécurité offensive et défensive.**  
Développés dans le cadre de ma formation BTS CIEL et de ma pratique sur Hack The Box / TryHackMe.

[Outils](#-outils) · [Installation](#️-installation) · [Utilisation](#-utilisation-détaillée) · [Concepts](#-concepts-couverts) · [Auteur](#-auteur)

</div>

---

> ⚠️ **Disclaimer légal**  
> Ces outils sont développés **à des fins éducatives et de recherche uniquement**.  
> Toute utilisation sur des systèmes sans autorisation écrite explicite est **illégale** (article 323-1 du Code pénal français).  
> L'auteur décline toute responsabilité en cas d'utilisation malveillante.  
> **Testez uniquement sur vos propres systèmes ou dans des labs dédiés (HTB, THM, VulnHub).**

---

## 📋 Table des matières

- [Vue d'ensemble](#-vue-densemble)
- [Outils](#-outils)
- [Installation](#️-installation)
- [Utilisation détaillée](#-utilisation-détaillée)
  - [01 — recon.py](#01--reconpy)
  - [02 — osint_username.py](#02--osint_usernamepy)
  - [03 — ctf_toolkit.py](#03--ctf_toolkitpy)
  - [04 — log_analyzer.py](#04--log_analyzerpy)
  - [05 — password_auditor.py](#05--password_auditorpy)
- [Concepts couverts](#-concepts-couverts)
- [Structure du repo](#-structure-du-repo)
- [Ressources](#-ressources)
- [Auteur](#-auteur)

---

## 🎯 Vue d'ensemble

Ce repository regroupe des outils de cybersécurité que j'ai développés pour consolider ma compréhension des techniques offensives et défensives. Chaque outil correspond à une phase concrète d'un test d'intrusion ou à une compétence clé en sécurité informatique.

```
Phase pentest          →  Outil correspondant
─────────────────────────────────────────────
Reconnaissance         →  recon.py
OSINT                  →  osint_username.py
CTF / Crypto           →  ctf_toolkit.py
Analyse / Blue team    →  log_analyzer.py
Audit de mots de passe →  password_auditor.py
```

**Stack technique :** Python 3.8+ · stdlib · requests · threading · regex · socket

---

## 🛠 Outils

### 01 · recon.py — Reconnaissance automatisée
> Effectue une reconnaissance complète sur un domaine cible : DNS, WHOIS, headers HTTP, énumération de sous-domaines et scan de ports communs. Exporte un rapport JSON.

**Concepts :** Phase de reconnaissance (PTES), DNS enumeration, fingerprinting HTTP, port scanning

---

### 02 · osint_username.py — OSINT Username Finder
> Vérifie la présence d'un pseudonyme sur plus de 40 plateformes en parallèle grâce au multi-threading. Génère un rapport des profils trouvés.

**Concepts :** OSINT passif, HTTP requests, threading Python, reconnaissance de surface d'attaque

---

### 03 · ctf_toolkit.py — CTF Swiss Army Knife
> Outil tout-en-un pour les challenges CTF : encodage/décodage (Base64, Hex, Binary, Morse, URL), chiffrements classiques (Caesar, ROT13, Vigenère, XOR) et détection automatique de l'encodage.

**Concepts :** Cryptographie classique, encodages, analyse de données inconnues

---

### 04 · log_analyzer.py — Analyseur de logs sécurité
> Parse les logs d'accès Apache/Nginx et détecte automatiquement les attaques : SQLi, XSS, LFI/Path Traversal, brute-force, scanners web, user-agents suspects.

**Concepts :** Blue team, analyse forensique, détection d'intrusion, OWASP Top 10

---

### 05 · password_auditor.py — Auditeur de mots de passe
> Analyse la robustesse d'un mot de passe ou d'un fichier entier : score 0-100, calcul d'entropie, estimation du temps de crackage selon différents scénarios, vérification des politiques de sécurité.

**Concepts :** Cryptographie appliquée, entropie, keyspace, politiques NIST, John the Ripper / Hashcat

---

## ⚙️ Installation

### Prérequis

- Python 3.8 ou supérieur
- pip
- (Optionnel) nmap et whois pour `recon.py`

### Installation rapide

```bash
# 1. Cloner le repository
git clone https://github.com/Noejimgre/cyber-tools.git
cd cyber-tools

# 2. Installer les dépendances Python
pip install requests

# 3. Installer les outils système (pour recon.py)
sudo apt install nmap whois     # Debian/Ubuntu/Kali
brew install nmap whois         # macOS

# 4. Vérifier que tout fonctionne
python3 --version
python3 -c "import requests; print('requests OK')"
nmap --version
```

### Dans un environnement virtuel (recommandé)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

pip install requests
```

---

## 📖 Utilisation détaillée

---

### 01 — recon.py

**Reconnaissance automatisée sur un domaine**

```
Usage: python3 01_recon/recon.py <domain> [options]

Arguments:
  domain               Domaine cible (ex: example.com)

Options:
  --skip-whois         Ignorer la recherche WHOIS
  --skip-subdomains    Ignorer l'énumération des sous-domaines
  --skip-ports         Ignorer le scan de ports
  --skip-robots        Ignorer robots.txt et sitemap.xml
  --no-save            Ne pas sauvegarder le rapport JSON
```

**Exemples d'utilisation :**

```bash
# Recon complet
python3 01_recon/recon.py example.com

# Recon rapide (DNS + headers uniquement)
python3 01_recon/recon.py example.com --skip-whois --skip-subdomains --skip-ports

# Sans sauvegarde du rapport
python3 01_recon/recon.py example.com --no-save
```

**Ce que fait l'outil :**

```
1. DNS Lookup
   ├── Résolution A (IPv4)
   ├── Reverse DNS (PTR)
   ├── Enregistrements MX (serveurs mail)
   └── Enregistrements TXT (SPF, DMARC, etc.)

2. WHOIS
   ├── Registrar
   ├── Dates de création / expiration
   ├── Nameservers
   └── Organisation

3. Headers HTTP
   ├── Headers de sécurité manquants (HSTS, CSP, X-Frame-Options...)
   └── Headers info-leaking (Server, X-Powered-By, X-AspNet-Version)

4. Sous-domaines
   └── Test de 30+ sous-domaines communs (www, api, admin, dev, mail...)

5. Ports ouverts
   └── Scan des 18 ports les plus courants

6. Robots.txt & Sitemap
   └── Récupération et affichage du contenu
```

**Output exemple :**

```
──────────────────────────────────────────────────────
  🌐 DNS LOOKUP
──────────────────────────────────────────────────────
  [A    ] example.com → 93.184.216.34
  [PTR  ] 93.184.216.34 → 93.184.216.34
  [MX   ] mail exchanger = 10 mail.example.com

──────────────────────────────────────────────────────
  🔒 HTTP HEADERS & SECURITY
──────────────────────────────────────────────────────
  [✓] Strict-Transport-Security: max-age=31536000
  [✗] MISSING: Content-Security-Policy       ← HIGH
  [✗] MISSING: X-Frame-Options               ← MEDIUM
  [!] Server: Apache/2.4.41 (Ubuntu)         ← Info leak

──────────────────────────────────────────────────────
  🔍 SUBDOMAIN ENUMERATION
──────────────────────────────────────────────────────
  [FOUND] www.example.com          → 93.184.216.34
  [FOUND] mail.example.com         → 93.184.216.50
```

---

### 02 — osint_username.py

**Recherche OSINT d'un pseudonyme sur 40+ plateformes**

```
Usage: python3 02_osint_username/osint_username.py <username> [options]

Arguments:
  username             Pseudonyme à rechercher

Options:
  --threads N          Nombre de threads parallèles (défaut: 10)
  --no-save            Ne pas sauvegarder le rapport JSON
```

**Exemples d'utilisation :**

```bash
# Recherche standard
python3 02_osint_username/osint_username.py johndoe

# Recherche rapide avec 20 threads
python3 02_osint_username/osint_username.py johndoe --threads 20

# Sans sauvegarde
python3 02_osint_username/osint_username.py johndoe --no-save
```

**Plateformes couvertes (40+) :**

```
Réseaux sociaux    → GitHub, Twitter/X, Instagram, TikTok, Reddit,
                     Pinterest, Tumblr, LinkedIn, Facebook, Mastodon

Cybersécurité      → HackTheBox, TryHackMe, HackerOne, Bugcrowd

Dev / Tech         → GitLab, StackOverflow, Dev.to, Replit,
                     Codepen, Keybase, Pastebin, Medium

Gaming             → Steam, Twitch, Chess.com

Créatif            → Dribbble, Behance, Flickr, SoundCloud,
                     Spotify, Vimeo, Pinterest

Divers             → ProductHunt, Gravatar, About.me, Linktree,
                     Hackernews
```

**Output exemple :**

```
[✓] FOUND   GitHub               → https://github.com/johndoe
[✗] NOT FOUND Twitter/X
[✓] FOUND   HackTheBox           → https://app.hackthebox.com/users/profile/johndoe
[✓] FOUND   TryHackMe            → https://tryhackme.com/p/johndoe
[T] TIMEOUT  Instagram

  ✓ CONFIRMED PROFILES:
    → GitHub               https://github.com/johndoe
    → HackTheBox           https://app.hackthebox.com/users/profile/johndoe
    → TryHackMe            https://tryhackme.com/p/johndoe
```

---

### 03 — ctf_toolkit.py

**Couteau suisse pour les challenges CTF**

```
Usage: python3 03_ctf_toolkit/ctf_toolkit.py <commande> <input>

Encodage / Décodage:
  b64e / b64d          Base64 encode / decode
  b32e / b32d          Base32 encode / decode
  hexe / hexd          Hexadécimal encode / decode
  bine / bind          Binaire encode / decode
  urle / urld          URL encode / decode
  morse-e / morse-d    Morse encode / decode

Chiffrements:
  rot13                ROT13
  caesar               César (--shift N, défaut: 13)
  caesar-bf            Brute-force César (tous les décalages)
  vigenere --key K     Déchiffrement Vigenère
  xor --key K          XOR decode (hex ou texte)

Analyse:
  analyze              Détection automatique de l'encodage
  hash                 Calcul MD5 / SHA-1 / SHA-256 / SHA-512
```

**Exemples d'utilisation :**

```bash
# Décoder du Base64
python3 03_ctf_toolkit/ctf_toolkit.py b64d SGVsbG8gV29ybGQ=
# → Hello World

# Encoder en hexadécimal
python3 03_ctf_toolkit/ctf_toolkit.py hexe "flag{test}"
# → 666c61677b746573747d

# Décoder du binaire
python3 03_ctf_toolkit/ctf_toolkit.py bind "01001000 01100101 01101100 01101100 01101111"
# → Hello

# Brute-force César (très utile en CTF)
python3 03_ctf_toolkit/ctf_toolkit.py caesar-bf "Khoor Zruog"
# → Shift  3: Hello World  ← trouvé !

# Déchiffrer Vigenère
python3 03_ctf_toolkit/ctf_toolkit.py vigenere "Rijvs" --key key
# → Hello

# XOR decode
python3 03_ctf_toolkit/ctf_toolkit.py xor "2b 3c 1a" --key 5

# Analyser une chaîne inconnue automatiquement
python3 03_ctf_toolkit/ctf_toolkit.py analyze "U0dWc2JHOD0="
# → Détecte Base64 → décode → détecte Base64 encore → "Hello"

# Calculer les hashes d'une chaîne
python3 03_ctf_toolkit/ctf_toolkit.py hash "password"
# → MD5: 5f4dcc3b5aa765d61d8327deb882cf99
# → SHA-256: 5e884898...
```

---

### 04 — log_analyzer.py

**Analyse de logs Apache/Nginx pour détecter les attaques**

```
Usage: python3 04_log_analyzer/log_analyzer.py [logfile] [options]

Arguments:
  logfile              Chemin vers le fichier de log (Apache/Nginx format)

Options:
  --brute-threshold N  Seuil d'échecs auth pour brute-force (défaut: 20)
  --sample             Générer un log de démo et l'analyser
  --save               Sauvegarder le rapport JSON
```

**Exemples d'utilisation :**

```bash
# Analyser un log Apache
python3 04_log_analyzer/log_analyzer.py /var/log/apache2/access.log

# Analyser un log Nginx
python3 04_log_analyzer/log_analyzer.py /var/log/nginx/access.log

# Générer et analyser un log de démonstration
python3 04_log_analyzer/log_analyzer.py --sample

# Seuil brute-force personnalisé + sauvegarde rapport
python3 04_log_analyzer/log_analyzer.py access.log --brute-threshold 10 --save
```

**Attaques détectées :**

```
Catégorie              Signatures recherchées
──────────────────────────────────────────────────────────
SQL Injection        → ' " UNION SELECT DROP TABLE OR 1=1
XSS                  → <script alert( onerror= javascript:
Path Traversal       → ../ %2e%2e etc/passwd win/system32
Command Injection    → | ; ` $( && ||
Scanners connus      → nikto nmap sqlmap burp dirbuster
Brute-force          → 20+ erreurs 401/403 depuis la même IP
Scan de répertoires  → 15+ erreurs 404 depuis la même IP
User-agents suspects → sqlmap nikto curl wget python-requests
```

**Output exemple :**

```
  📊 GENERAL STATISTICS
  ──────────────────────────────────────────────────
  Total requests : 12,483
  200 OK         : 9,821
  404 Not Found  : 1,205
  401/403        : 312
  500 Errors     : 48

  🔐 ATTACK SIGNATURES DETECTED
  ──────────────────────────────────────────────────
  [  47x] SQL Injection        from 3 unique IP(s)
           IP=1.2.3.4  [500]  /search?q=1' OR '1'='1
  [  12x] Path Traversal       from 1 unique IP(s)
           IP=5.6.7.8  [404]  /../../../etc/passwd

  🔨 BRUTE-FORCE SUSPECTS
  ──────────────────────────────────────────────────
  10.0.0.50          → 87 failed auth attempts

  🤖 SUSPICIOUS USER-AGENTS
  ──────────────────────────────────────────────────
  [sqlmap        ] 1.2.3.4  sqlmap/1.6#stable
  [nikto         ] 5.6.7.8  nikto/2.1.6
```

---

### 05 — password_auditor.py

**Analyse de robustesse et audit de mots de passe**

```
Usage: python3 05_password_auditor/password_auditor.py [password] [options]

Arguments:
  password             Mot de passe à analyser (optionnel)

Options:
  --file FILE          Auditer un fichier (un mot de passe par ligne)
  --hide               Masquer le mot de passe dans l'output
  --show-passwords     Afficher les mots de passe lors d'un audit de fichier
```

**Exemples d'utilisation :**

```bash
# Analyser un mot de passe
python3 05_password_auditor/password_auditor.py "MonMotDePasse123!"

# Mode interactif (mot de passe masqué dans le terminal)
python3 05_password_auditor/password_auditor.py

# Auditer une liste de mots de passe (ex: dump d'une BDD)
python3 05_password_auditor/password_auditor.py --file passwords.txt

# Analyser sans afficher le mot de passe
python3 05_password_auditor/password_auditor.py "secret" --hide
```

**Métriques calculées :**

```
Analyse              Détail
──────────────────────────────────────────────────────────
Longueur           → Nombre de caractères
Variété            → Minuscules / Majuscules / Chiffres / Spéciaux
Entropie           → Bits (log2 × keyspace)
Score 0-100        → Pondération longueur + variété + entropie
Patterns           → Détection séquences, répétitions, années...
Top passwords      → Vérification dans la liste des 100 plus communs
Politiques         → Minimum / Standard / Strong / NIST SP 800-63B
Temps de crack     → Online throttled / Online / MD5 GPU / SHA-256 / bcrypt
HaveIBeenPwned     → Préfixe SHA-1 pour vérification manuelle
```

**Output exemple :**

```
═══════════════════════════════════════════════════
  Password    : MonMotDePasse123!
  Length      : 17 characters
  Entropy     : 101.4 bits
  Score       : 85/100  [█████████████████████████░░░░░]
  Strength    : 💪 VERY STRONG

  ⏱ Crack time estimates:
    Online (throttled)        > 1,000,000 years
    Online (no limit)         > 100,000 years
    MD5 (GPU)                 3 hours
    SHA-256 (GPU)             2 days
    bcrypt (GPU)              > 10,000 years

  📋 Policy compliance:
    [✓] Minimum
    [✓] Standard
    [✓] Strong
    [✓] NIST SP 800-63B
═══════════════════════════════════════════════════
```

---

## 📚 Concepts couverts

### Offensif (Red Team)
| Concept | Outil |
|---|---|
| Reconnaissance passive | `recon.py` — DNS, WHOIS |
| Reconnaissance active | `recon.py` — scan de ports, sous-domaines |
| OSINT | `osint_username.py` — empreinte numérique |
| Analyse cryptographique | `ctf_toolkit.py` — Caesar, Vigenère, XOR |

### Défensif (Blue Team)
| Concept | Outil |
|---|---|
| Détection SQLi / XSS / LFI | `log_analyzer.py` |
| Détection brute-force | `log_analyzer.py` |
| Analyse forensique de logs | `log_analyzer.py` |
| Politique de mots de passe | `password_auditor.py` — NIST SP 800-63B |
| Entropie et cryptographie | `password_auditor.py` |

### Compétences Python
- **Multi-threading** (`threading`, `Queue`) — `osint_username.py`
- **Regex avancées** (`re`) — `log_analyzer.py`, `password_auditor.py`
- **Sockets réseau** (`socket`) — `recon.py`
- **Subprocess** (`subprocess`) — `recon.py` (nmap, whois)
- **HTTP requests** (`requests`) — `osint_username.py`, `recon.py`
- **Cryptographie** (`hashlib`) — `password_auditor.py`, `ctf_toolkit.py`
- **JSON reporting** (`json`) — tous les outils
- **Argparse CLI** (`argparse`) — tous les outils

---

## 📁 Structure du repo

```
cyber-tools/
│
├── README.md
│
├── 01_recon/
│   ├── recon.py              # Outil principal
│   └── README.md             # Doc spécifique
│
├── 02_osint_username/
│   ├── osint_username.py
│   └── README.md
│
├── 03_ctf_toolkit/
│   ├── ctf_toolkit.py
│   └── README.md
│
├── 04_log_analyzer/
│   ├── log_analyzer.py
│   ├── sample_access.log     # Log de démo (généré avec --sample)
│   └── README.md
│
└── 05_password_auditor/
    ├── password_auditor.py
    └── README.md
```

---

## 📚 Ressources

Ces outils ont été développés en m'appuyant sur :

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — vulnérabilités web
- [PTES — Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — politiques de mots de passe
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3) — vérification de compromission
- [TryHackMe — Jr Penetration Tester](https://tryhackme.com/path/outline/jrpenetrationtester)
- [Hack The Box](https://www.hackthebox.com) — labs pratiques
- [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) — challenges Linux/crypto

---

## 🗺️ Roadmap

- [ ] Ajouter un scanner de CVE via l'API NVD
- [ ] Module de brute-force SSH (pour labs Metasploitable)
- [ ] Interface web Flask pour `log_analyzer`
- [ ] Intégration de l'API HaveIBeenPwned dans `password_auditor`
- [ ] Write-ups des machines HTB où ces outils ont été utilisés

---

## 👤 Auteur

**Noé Jimenez-Greverent**

Étudiant en **BTS CIEL** — Spécialisation Cybersécurité (CNED)  
Pratique active sur Hack The Box · TryHackMe · OverTheWire

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/noé-jimenez-greverent)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Noejimgre)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-212C42?style=for-the-badge&logo=tryhackme&logoColor=white)](https://tryhackme.com)
[![HackTheBox](https://img.shields.io/badge/HackTheBox-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black)](https://hackthebox.com)

---

<div align="center">

*"The quieter you become, the more you are able to hear."* — Kali Linux

**⭐ N'hésitez pas à star le repo si ces outils vous ont été utiles !**

</div>
