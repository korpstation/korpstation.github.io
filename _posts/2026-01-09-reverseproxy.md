---
layout: post
title: "Sensibilisation : La 2FA Ne Suffit Plus : Publier Gophish en HTTPS avec un reverse proxy Nginx (Série - Ép.2)"
date: 2025-01-01 09:00:00 +0100
categories: [cybersécurité, phishing, tutoriel,sensibilisation]
tags: [gophish, 2fa, authentification, sécurité, ubuntu, vps]
author: korpstation
image: /assets/posts/gophish/2FA.jpeg
toc: true
---


# Le Problème de Crédibilité

Imaginons que la victime Jean-Pierre MARTIN reçoive cet email :

```
De : Service Sécurité IT <securite@financesecure-sa.fr>
Objet : [URGENT] Vérification de sécurité requise

Bonjour Jean-Pierre,

Une activité suspecte a été détectée sur votre compte.
Veuillez vérifier immédiatement :

https://203.0.113.45:3333/verify
```

**Que va-t-il se passer ?**

Il va immédiatement identifier cet email comme suspect pour plusieurs raisons :

| Élément | Ce qu'il voit | Sa réaction |
|---------|---------------|-------------|
| URL avec IP | `203.0.113.45:3333` | 🚨 "Pourquoi une adresse IP ?" |
| Port visible | `:3333` | 🚨 "C'est quoi ce port bizarre ?" |
| Domaine absent | Pas de `.com` ou `.fr` | 🚨 "Où est le nom du site ?" |

**Résultat : L'attaque échoue avant même d'avoir commencé.**



## Ce Que Les Utilisateurs S'Attendent À Voir

Les utilisateurs sont habitués à voir des URLs comme :

✅ `https://portail.financesecure-sa.fr/login`  
✅ `https://login.microsoft.com/oauth2/authorize`  
✅ `https://accounts.google.com/signin`

**Caractéristiques communes :**
- Nom de domaine reconnaissable
- HTTPS avec cadenas vert
- Pas d'adresse IP visible
- Pas de port affcihé

> **C'est pour cela que les attaquants investissent dans des noms de domaine crédibles.**

---

# Pourquoi Nous Avons Besoin d'un Reverse Proxy

### Le Problème Actuel

Après l'installation de Gophish, nous avons :

```
Interface admin : https://VOTRE_IP_VPS:3333
Serveur phishing : http://VOTRE_IP_VPS:3334
```

**Problèmes :**

1. ❌ Adresse IP visible → Suspect
2. ❌ Port visible → Suspect
3. ❌ Pas de vrai nom de domaine → Suspect
4. ❌ Certificat SSL auto-signé → Avertissement navigateur
5. ❌ Pas d'HTTPS pour le serveur phishing → Alerte "Non sécurisé"

### La Solution : Nginx + Let's Encrypt

**Nginx** est un serveur web qui peut agir comme **reverse proxy**, c'est-à-dire qu'il :

1. Reçoit les requêtes HTTP/HTTPS
2. Les transmet à Gophish en interne
3. Renvoie les réponses au navigateur

**Let's Encrypt** fournit des **certificats SSL gratuits** pour avoir HTTPS.

**Avantages :**

1. ✅ **URL crédible** 
2. ✅ **Certificat SSL valide** :
3. ✅ **Pas d'IP visible** 


##  Installation et Configuration du Reverse Proxy

### Prérequis

Avant de commencer, vous devez :

1. ✅ **Acheter un nom de domaine** 

   Vous pouvez vous référez à ce post pour comprendre comment j'ai choisi le nom de domaine. 
   - Pour notre cas : `financesecure.com`

2. ✅ **Configurer les DNS** pour pointer vers votre VPS

![sous domaine](/assets/posts/gophish/sousdomaine.png)
   
   - Enregistrement A : `gophish.financesecure.com` → IP de votre VPS : pour la gestion de le serveur admin gophish
   - Enregistrement A : `portail.financesecure.com` → IP de votre VPS : pour le serveur de physing 

   Nous en créerons d'autres pour notre demo mais pour le moment ces deux suffisent pour mettre au point le reverse proxy et tester. 

3. ✅ **Attendre la propagation DNS** 

Généralement celà ne prends pas beaucoup de temps. 


### Étape 1 : Installation de Nginx

```bash
# Mettre à jour le système
sudo apt update

# Installer Nginx
sudo apt install -y nginx

# Vérifier que Nginx est actif
sudo systemctl status nginx
```

**Résultat attendu :**

```
● nginx.service - A high performance web server and a reverse proxy server
     Loaded: loaded
     Active: active (running)
```

### Étape 2 : Installation de Certbot (Let's Encrypt)

```bash
# Installer Certbot et le plugin Nginx
sudo apt install -y certbot python3-certbot-nginx
```

### Étape 3 : Configuration Nginx 

Remodifier le fichier de configuration de gophish comme ceci : 

```bash
sudo nano /opt/gophish/config.json
```

**Contenu du fichier :**

```bash

{
    "admin_server": {
        "listen_url": "127.0.0.1:3333",
        "use_tls": false,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key",
        "trusted_origins": []
    },
    "phish_server": {
        "listen_url": "127.0.0.1:3334",
        "use_tls": false,
        "cert_path": "phish.crt",
        "key_path": "phish.key"
    },
    "db_name": "sqlite3",
    "db_path": "gophish.db",
    "migrations_prefix": "db/db_",
    "contact_address": "",
    "logging": {
        "filename": "",
        "level": ""
    }
}
```

Configuration Nginx pour l'interface admin:

```bash
sudo nano /etc/nginx/sites-available/gophish.financesecure.com
```

**Contenu du fichier :**

```bash

upstream gophish_backend {
    server 127.0.0.1:3333;
}

server {
    listen 80;
    server_name gophish.financesecure.com;

    location / {
        proxy_pass http://gophish_backend;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

```

Configuration Nginx pour le serveur de physing

```bash
sudo nano /etc/nginx/sites-available/portail.financesecure.com
```

**Contenu du fichier :**

```bash
upstream portail_backend {
    server 127.0.0.1:3334;
}

server {
    listen 80;
    server_name portail.financesecure.com;

    location / {
        proxy_pass http://portail_backend;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Étape 4: Activer les configurations

```bash
# Créer les liens symboliques
sudo ln -s /etc/nginx/sites-available/ophish.financesecure.com /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/portail.financesecure.com /etc/nginx/sites-enabled/

# Tester la configuration Nginx
sudo nginx -t

# Redémarrer Nginx
sudo systemctl restart nginx
```

### Étape 5 : Redémarrer Gophish

```bash
sudo systemctl start gophish
sudo systemctl status gophish
```

### Étape 6 : Obtenir les certificats SSL avec Let's Encrypt

```bash
# Pour le domaine principal
sudo certbot --nginx -d portail.financesecure.com -d gophish.financesecure.com

```

**Certbot va vous poser quelques questions :**

1. **Email** : Votre email (pour les notifications d'expiration)
2. **Termes** : Accepter les conditions (A)
3. **Redirection HTTPS** : Oui (2)



### Étape 7 : Vérification

Ouvrez un navigateur et testez :

**Interface admin :**
   ```
   https://admin.portail-financesecure.com
   ```
   
   Vous devriez voir le login Gophish avec un **cadenas HTTPS vert** ✅
---


## Troubleshooting Reverse Proxy

### Problème : "502 Bad Gateway"

**Cause :** Nginx ne peut pas se connecter à Gophish.

**Solutions :**

```bash
# 1. Vérifier que Gophish est actif
sudo systemctl status gophish

# 2. Vérifier que Gophish écoute sur le bon port
sudo netstat -tulpn | grep gophish

# 3. Vérifier les logs Nginx
sudo tail -n 50 /var/log/nginx/error.log

# 4. Tester la connexion locale
curl http://127.0.0.1:3333
curl https://127.0.0.1:3334 -k
```

### Problème : "Certificat SSL non valide"

**Cause :** Let's Encrypt n'a pas pu obtenir le certificat.

**Solutions :**

```bash
# 1. Vérifier que le DNS pointe bien vers votre VPS
nslookup portail.financesecure.com

# 2. Relancer Certbot
sudo certbot --nginx -d portail-financesecure.com --force-renewal
```

### Problème : "Cannot access admin interface"

**Cause :** Configuration Nginx incorrecte pour l'admin.

**Solutions :**

```bash
# 1. Vérifier la configuration Nginx
sudo nginx -t

# 2. Vérifier les logs
sudo tail -f /var/log/nginx/error.log

# 3. Tester manuellement
curl https://admin.portail-financesecure.com
```

## Comparaison Avant/Après

| Élément | AVANT | APRÈS |
|---------|-------|-------|
| **Admin** | `https://203.0.113.45:3333` ❌ | `https://gophish-financesecure.com` ✅ |
| **SSL** | Certificat auto-signé ❌ | Let's Encrypt valide ✅ |

## Pourquoi C'est Dangereux

Un utilisateur qui reçoit maintenant un email avec le lien :

```
https://portail.financesecure.com/verify
```

Va voir :

1. ✅ Un nom de domaine qui ressemble au vrai
2. ✅ Un cadenas HTTPS vert
3. ✅ Aucun avertissement de sécurité
4. ✅ Une URL qui semble légitime


---

## Prochaines Étapes

**Vous avez maintenant :**

✅ Gophish installé et fonctionnel  
✅ Un domaine crédible avec SSL  
✅ Un reverse proxy Nginx configuré  
✅ Une infrastructure de phishing réaliste  


Dans le **prochain épisode**, nous allons :

- Préparer le contexte de l'attaque





## ⚠️ Disclaimer Légal et Éthique

Cette série est réalisée à des fins **STRICTEMENT pédagogiques** et de sensibilisation à la cybersécurité.

Toutes les démonstrations sont effectuées dans un environnement contrôlé et isolé, sur mes propres comptes de test dont je suis le propriétaire légitime.

**L'utilisation de ces techniques contre des tiers sans autorisation explicite est ILLÉGALE.**
