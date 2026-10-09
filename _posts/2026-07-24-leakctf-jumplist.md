---
title: L3AK CTF 2026 - Transcendent Renovation
time: 2026-07-25 12:00:00
categories: [ctf]
tags: [forensic, windows, jumplist, ole, lnk]
image: /assets/posts/l3akctf/cover.png
---


# Forensic

## Transcendent Renovation (Ghost Hunt)

### Contexte

Challenge « Ghost Hunt Terminal » : on se connecte à un service qui pose **7 questions** sur des artefacts **Jump List Windows**, et le flag n'est révélé qu'une fois **toutes** les réponses correctes.


```bash
ncat --ssl transcendent-renovation.instances.ctf.l3ak.team 1337
```

Livrable : `Administrator_JumpLists.zip`, qui contient deux dossiers :

```
AutomaticDestinations/   *.automaticDestinations-ms   (13 fichiers)
CustomDestinations/      *.customDestinations-ms      (7 fichiers)
```

Le fil rouge des questions est l'entrée `NoNeedToWonder`.

### Reconnaissance des artefacts

```bash
die AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms
# -> Composite Document File V2 (OLE Compound File)
```

Un `.automaticDestinations-ms` est un **conteneur OLE/CFB** : chaque **stream numéroté en hexadécimal** correspond à un LNK, et le stream **`DestList`** est l'index MRU.


Identifier le fichier qui contient `NoNeedToWonder` :

```bash
for f in AutomaticDestinations/*-ms; do
  strings -a "$f" | grep -q NoNeedToWonder && echo "$f"
done
# -> f01b4d95cf55d32a.automaticDestinations-ms   (AppID = Windows Explorer)
```

Parse complet de référence :

```bash
wine JLECmd.exe -f .../f01b4d95cf55d32a.automaticDestinations-ms --withDir --fd > result.txt
```

### Q1 à Q6 (directes)

| # | Question | Réponse | Comment |
|---|---|---|---|
| 1 | Format d'un Jump List | **`OLE CF`** | `file` → Composite Document / OLE Compound File |
| 2 | Fichier `.automaticDestinations` contenant l'entrée | **`f01b4d95cf55d32a.automaticDestinations-ms`** | grep sur les strings |
| 3 | Share path dans le fichier | **`\\tsclient\HauntedHouse`** | Entrée #69 : `Network share information → \\TSCLIENT\HAUNTEDHOUSE` |
| 4 | Stream qui contient la *rename data* de NoNeedToWonder | **`46`** | Entrée #70 (JLECmd) = stream **hexadécimal `0x46`** |
| 5 | File Droid GUID de NoNeedToWonder | **`ec2ab952-7e4d-11f1-89ad-a2dead7852ad`** | `Tracker database block → File Droid` |
| 6 | Hostname associé | **`logging-vm`** | `Tracker database block → Machine ID` |

**Fausse piste Q4** : j'ai essayé `0070` et `70` (l'*Entry #* décimal affiché par JLECmd), mais ils ont été refusés. Le challenge veut le **nom du stream en hexadécimal** : `0x46 = 70`, donc `46`.

Détails Q3, Q5 et Q6 depuis `result.txt` (entrée #70) :

```
Path: C:\Users\Administrator\Desktop\NoNeedToWonder
>> Tracker database block
   Machine ID:  logging-vm
   MAC Address: a2:de:ad:78:52:ad          <- "DEAD" caché dans la MAC :)
   File Droid:  ec2ab952-7e4d-11f1-89ad-a2dead7852ad
```

### Q7 : « nom original du dossier » (le morceau de bravoure)

SS View nous permet de lire le contenu du stream et de voir l'ancien nom.

Donc :

```
Q7 -> SoulSearching        (= SoulSearch + "ing")   Correct !
```

### Flag

```
Toutes les questions ont reçu une réponse ! Flag final :
L3AK{P4r4n0rm4l_P4r4ll3l_P47h5}
```