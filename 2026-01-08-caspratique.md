---
layout: post
title: "Sensibilisation : La 2FA Ne Suffit Plus : Techniques de Manipulation d'URL (Série - Ép.1)"
date: 2025-01-01 09:00:00 +0100
categories: [cybersécurité, phishing, tutoriel,sensibilisation]
tags: [gophish, 2fa, authentification, sécurité, ubuntu, vps]
author: korpstation
image: /assets/images/episode-1-gophish-cover.jpg
toc: true
---

## 12. Cas Pratique : FinanceSecure SA

### Domaine Légitime de l'Entreprise

```
Domaine principal : financesecure-sa.fr
Portail employé : portail.financesecure-sa.fr
```

### Options d'Attaque Possibles

En tant qu'attaquant, voici les domaines que nous pourrions enregistrer :

#### Option 1 : Typosquatting Simple

```
❌ portail.financesecure-sa.fr (légitime)
✅ portail.financesecure-sa.com (TLD différent)
✅ portail.financesecure.fr (tiret manquant)
✅ portail.financesecure-sa.net (TLD .net)
```

#### Option 2 : Combosquatting

```
✅ secure-financesecure.com
✅ login-financesecure.com
✅ verify-financesecure.com
✅ portal-financesecure.com
```

#### Option 3 : Subdomain Spoofing

```
✅ portail.financesecure.secure-verification.com
✅ login.financesecure-sa.verify-account.com
```

### Notre Choix pour la Démonstration

**Pour cette série, nous allons utiliser :**

```
Domaine malveillant : portail-financesecure.com
```

**Pourquoi ce choix :**

1. ✅ Visuellement très proche de l'original
2. ✅ Facile à confondre avec `portail.financesecure-sa.fr`
3. ✅ TLD `.com` = crédible (plus courant que `.fr`)
4. ✅ Un seul tiret déplacé = erreur imperceptible
5. ✅ Pas de caractères spéciaux = compatible tous navigateurs

**Comparaison visuelle :**

```
LÉGITIME   : portail.financesecure-sa.fr
MALVEILLANT: portail-financesecure.com
             ↑ tiret déplacé   ↑ TLD différent
```

**À quelle vitesse pouvez-vous voir la différence ?**

Faites le test : lisez ces deux URLs rapidement et comptez combien de temps il vous faut pour identifier la différence.

-----