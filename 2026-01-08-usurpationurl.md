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


# 1. Les Techniques de Manipulation d'URL

Les cybercriminels utilisent plusieurs techniques pour rendre leurs URLs malveillantes visuellement identiques ou très similaires aux URLs légitimes.

### Technique 1 : Le Typosquatting

**Principe :** Enregistrer un nom de domaine avec une faute de frappe volontaire.

**Exemples concrets :**

| Domaine Légitime | Domaine Malveillant | Technique |
|------------------|---------------------|-----------|
| `google.com` | `gooogle.com` | Lettre doublée |
| `microsoft.com` | `microsft.com` | Lettre manquante |
| `paypal.com` | `paypai.com` | Lettre remplacée (l → i) |
| `amazon.com` | `arnazon.com` | Lettre remplacée (m → rn) |
| `facebook.com` | `faceb00k.com` | Chiffres (o → 0) |

**Pourquoi ça marche :**

Notre cerveau lit les mots par reconnaissance de forme globale, pas lettre par lettre. Si vous lisez rapidement, vous ne remarquerez pas la différence entre :

- `microsoft.com` 
- `microsft.com`

### Technique 2 : Les Homographes Punycode

**Principe :** Utiliser des caractères d'alphabets différents (cyrillique, grec) qui ressemblent visuellement aux caractères latins.

**Exemple :**

```
Domaine légitime : apple.com
Domaine malveillant : аррӏе.com
```

**À première vue, ces deux URLs semblent IDENTIQUES.**

Mais regardez attentivement :

| Caractère | Alphabet Latin | Alphabet Cyrillique |
|-----------|----------------|---------------------|
| a | a (U+0061) | а (U+0430) |
| p | p (U+0070) | р (U+0440) |
| l | l (U+006C) | ӏ (U+04CF) |

**Protection des navigateurs :**

Certains navigateurs modernes (Chrome, Firefox, Safari) détectent ces attaques et affichent la version Punycode :

```
аррӏе.com → xn--80ak6aa92e.com
```

Mais les attaquants contournent cette protection en combinant plusieurs autres techniques.

### Technique 3 : Le Subdomain Spoofing

**Principe :** Créer un sous-domaine qui contient le nom du site cible.

**Exemple :**

```
URL légitime : https://login.microsoft.com
URL malveillante : https://login.microsoft.secure-verification.com
```

L'utilisateur voit "login.microsoft" et pense être sur le bon site.


### Technique 4 : La Variation de TLD

**Principe :** Utiliser un TLD (Top-Level Domain) différent mais crédible.

**Exemples :**

| Domaine Légitime | Variations TLD |
|------------------|----------------|
| `microsoft.com` | `microsoft.net`, `microsoft.org`, `microsoft.co` |
| `amazon.com` | `amazon.fr`, `amazon.co.uk`, `amazon.de` |
| `google.com` | `google.io`, `google.app`, `google.dev` |

**Cas particulier - Les TLDs pays :**

Certains TLDs pays sont visuellement proches de `.com` :

- `.co` (Colombie) au lieu de `.com`
- `.om` (Oman) au lieu de `.com`
- `.cm` (Cameroun) au lieu de `.com`

### Technique 5 : L'URL Wrapping

**Principe :** Masquer l'URL réelle derrière du texte cliquable.

**En HTML :**

```html
<a href="https://malicious-site.com">https://microsoft.com</a>
```

**Ce que l'utilisateur voit :** `https://microsoft.com` (en bleu, cliquable)  
**Où le lien redirige vraiment :** `https://malicious-site.com`

**Dans les emails :**

La plupart des clients email affichent le texte cliquable, pas l'URL réelle dans le code HTML.

---

