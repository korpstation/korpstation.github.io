---
title: HTB Sherlock - Phantom
time: 2026-10-24 09:00:00
categories: [ctf]
tags: [forensic, DFIR, linux, HTB, sherlock, volatility3, memory, rootkit]
image: /assets/posts/Phantom/cover.png
---

## Forensic

## Phantom

### Scénario

> Un serveur Linux de l'organisation présente un comportement suspect. La supervision réseau a détecté des connexions sortantes vers une adresse IP inconnue, et les administrateurs ont remarqué que plusieurs commandes de diagnostic standard renvoyaient des informations incomplètes. Un dump mémoire a été capturé avant l'isolement du serveur. Il faut l'analyser pour mettre en évidence l'infection par un rootkit sophistiqué, cartographier ses capacités et documenter tous les indicateurs de compromission.

---

### Préparation : comprendre ce qu'on a et ce qu'il manque

L'archive `Phantom.zip` contient un dump de la mémoire vive du serveur. 

Le dump a été produit avec **AVML**, on le verra plus loin : le binaire `./avml` apparaît dans les variables d'environnement d'une session root.

Pour l'analyse j'utilise **Volatility 3**. Contrairement à Windows, où le framework sait retrouver seul les symboles du noyau via les PDB de Microsoft, Linux pose un problème : la disposition en mémoire des structures (`task_struct`, `module`, `sock`...) dépend de la version exacte du noyau et de sa configuration de compilation. Volatility a donc besoin d'un fichier de symboles propre au noyau analysé, au format **ISF** (*Intermediate Symbol Format*), un JSON qui décrit les types, les offsets des champs et les adresses des symboles. Ce json nous a été fourni mais dans certains cas vous ne l'aurez pas. 

#### Étape 1 : identifier la version du noyau

Les « bannières » sont les chaînes `Linux version ...` que le noyau garde en mémoire. Le plugin `banners.Banners` les retrouve :

```bash
vol -f dump_srv.mem banners.Banners
```

```
Linux version 6.8.0-87-generic (buildd@lcy02-amd64-034) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #88-Ubuntu SMP PREEMPT_DYNAMIC Sat Oct 11 09:28:41 UTC 2025 (Ubuntu 6.8.0-87.88-generic 6.8.12)
```

On a donc un **Ubuntu 24.04** avec le noyau **6.8.0-87-generic**.

#### Étape 2 : retrouver les symboles de debug

Ubuntu publie, pour chaque noyau, un paquet `dbgsym` (`.ddeb`) qui contient le `vmlinux` non strippé, avec ses informations DWARF. C'est exactement ce que `dwarf2json` sait convertir en ISF. J'ai utilisé le script `ubuntu_symbols_finder.py`, qui prend la bannière en argument et cherche sur Launchpad le paquet correspondant à la version exacte :

```bash
python ~/Downloads/tools/ubuntu_symbols_finder.py 'Linux version 6.8.0-87-generic (buildd@lcy02-amd64-034) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #88-Ubuntu SMP PREEMPT_DYNAMIC Sat Oct 11 09:28:41 UTC 2025 (Ubuntu 6.8.0-87.88-generic 6.8.12)'
```

Il renvoie l'URL du paquet `linux-image-unsigned-6.8.0-87-generic-dbgsym_6.8.0-87.88_amd64.ddeb` et la procédure à suivre.

#### Étape 3 : générer l'ISF

```bash
wget http://launchpadlibrarian.net/823864715/linux-image-unsigned-6.8.0-87-generic-dbgsym_6.8.0-87.88_amd64.ddeb
dpkg-deb -x linux-image-unsigned-6.8.0-87-generic-dbgsym_6.8.0-87.88_amd64.ddeb extrait/
dwarf2json linux --elf extrait/usr/lib/debug/boot/vmlinux-6.8.0-87-generic | xz > Ubuntu_6.8.0-87-generic.json.xz
```

Le fichier obtenu est copié dans le dossier de symboles Linux de Volatility. Avec une installation pip, (j'ai volatility dans un env) le dossier `symbols/linux/` n'existe pas par défaut, il faut le créer :

```bash
SYMPATH=$(python3 -c "import volatility3,os; print(os.path.dirname(volatility3.__file__))")/symbols/linux
mkdir -p "$SYMPATH"
cp Ubuntu_6.8.0-87-generic.json.xz "$SYMPATH/"
```
---

### Q1 - What is the name of the hidden kernel module?

Sous Linux, les modules chargés sont chaînés dans une liste (`modules`) que parcourt `lsmod`. Un rootkit qui veut se cacher se retire de cette liste  : le code reste en mémoire et actif, mais n'apparaît plus ni dans `lsmod` ni dans `/proc/modules`.

Volatility 3 propose un plugin dédié, qui ne se contente pas de suivre la liste officielle mais recherche aussi en mémoire les structures `module` et signale celles qui n'y figurent pas. Vous pouvez lire cette publication qui le detaille très bien. `https://siemtune.com/kernel-backdoor-detection-lab/` et fourni certains plugins à utiliser pour la détection. 

![q1](/assets/posts/Phantom/Q1.png)

```bash
vol -f dump_srv.mem linux.malware.hidden_modules
Volatility 3 Framework 2.28.2
Progress:  100.00		Stacking attempts finished           
Offset	Module Name	Code Size	Taints	Load Arguments	File Output

0xffffc0b42640	singularity	0x19000	OOT_MODULE,UNSIGNED_MODULE		N/A
```
Un seul module est caché : **singularity**. C'est le nom du rootkit open source sophistiqué de niveau noyau (LKM) ciblant les noyaux Linux modernes (versions 6.x), conçu par le chercheur Matheus Alves (MatheuZSecurity) à des fins de recherche sur l'évasion et la détection. 

![q1](/assets/posts/Phantom/Q1-2.png) 

Réponse : **singularity**

---

### Q2 - What kernel taint flags are set for the rootkit module? (comma-separated, alphabetical order)

Le noyau Linux maintient un « taint » : un ensemble de drapeaux qui indiquent que le noyau tourne dans un état non supporté ou non fiable. Ici, la colonne `Taints` de la sortie précédente les donne directement :

- `OOT_MODULE` : module **hors arbre** (*out-of-tree*), c'est-à-dire compilé en dehors des sources officielles du noyau ;
- `UNSIGNED_MODULE` : module **non signé**, chargé sans signature valide reconnue par le noyau.

Réponse : **OOT_MODULE,UNSIGNED_MODULE**

---

### Q3 - At what exact time (in seconds since boot) was the rootkit module loaded

Le noyau écrit des messages dans son **ring buffer** (ce qu'on lit avec `dmesg`), préfixés par le temps écoulé depuis le démarrage en secondes.

Le plugin `linux.kmsg.Kmsg` lit ce ring buffer directement dans la mémoire. 

```bash
vol -f dump_srv.mem linux.kmsg > kernelog.csv 
```

![q3](/assets/posts/Phantom/Q3.png)

Réponse : **2490.473832**

---

### Q4 - What was the PID of the process that loaded the rootkit module?

Le PID est directement visible au niveau de la ligne dans les kmgs: 

![q4](/assets/posts/Phantom/Q3.png)

Réponse : **2669**

---

### Q5 - Which kernel tracepoint is hooked by the rootkit

- les **tracepoints** sont des points statiques placés par les développeurs du noyau à des endroits précis (création d'un processus, changement de contexte...). Un module peut y enregistrer une fonction qui sera appelée  ;

Volatility liste les callbacks enregistrés sur les tracepoints avec `CheckTracepoints` :

```bash
vol -f dump_srv.mem linux.tracing.tracepoints
Volatility 3 Framework 2.28.2
Progress:  100.00		Stacking attempts finished           
tracepoint	tracepoint address	Probe	Probe address	Probe priority	Module	Module address

sched_process_fork	0xffff961fbae0	-	0xffffc0b3a990	10	singularity	0xffffc0b42640

```
Une seule ligne, et elle appartient à `singularity`. 

Réponse : **sched_process_fork**

---

### Q6 - What is the IP address of the command and control server?

On utilise le plugin `linux.sockstat` 
```bash
vol -f dump_srv.mem linux.sockstat | grep ESTABLISHED
```

La majorité des lignes sont des sockets `AF_UNIX` (communication locale avec journald, dbus) et deux sessions SSH entrantes depuis `192.168.200.1`, ce qui est légitime. Les lignes qui retiennent l'attention sont celles de trois processus `bash` avec une connexion `AF_INET` sortante :

![q6](/assets/posts/Phantom/Q6.png)

La machine compromise est `192.168.200.177`, et le serveur C2 `192.168.200.164`.

Réponse : **192.168.200.164**

---

### Q7 - What port is the C2 server listening on?

Les trois connexions précédentes visent le même port distant.

Réponse : **8081**

---

### Q8 - What are the PIDs of the compromised bash processes connected to the C2 server? (comma-separated, ascending order)

Comme vu au niveau des connexions les processus liés sont des bash. Un simple `bash` n'a normalement aucune raison d'avoir un socket TCP ouvert. Ici, pour chacun des trois processus, les descripteurs de fichier **0, 1 et 2** (entrée, sortie et erreur standard) pointent vers le **même socket**. C'est la signature d'un reverse shell. 

```bash
vol -f dump_srv.mem linux.pslist | grep -E "2693|2695|2698"

0x8e7a008a8000.02693	2693	1	bash	0	0	0	0	2025-11-19 17:40:37.409864 UTC	Disabled
0x8e7a0bcbd180	2695	2695	1	bash	0	0	0	0	2025-11-19 17:40:38.409713 UTC	Disabled
0x8e7a05c75180	2698	2698	1	bash	0	0	0	0	2025-11-19 17:40:39.411410 UTC	Disabled
```

Réponse : **2693,2695,2698**

---

### Q9 - How many hooks has the rootkit installed?

**ftrace** est le mécanisme de traçage de fonctions du noyau. Au démarrage, le compilateur insère à l'entrée de presque chaque fonction noyau un appel factice (`nop`) réservé à ftrace. Quand un module enregistre une structure `ftrace_ops` sur une fonction, le noyau transforme ce `nop` en appel vers le callback du module. Combiné aux bons drapeaux, le callback peut **modifier le registre d'instruction (`rip`)** et rediriger l'exécution vers la fonction de son choix. C'est la technique de *hooking* préférée des rootkits modernes, puisqu'elle ne touche pas à la table des appels système (`sys_call_table`) que les outils de détection classiques surveillent.

Le plugin `CheckFtrace` de volatility liste les fonctions sur lesquelles un callback ftrace est enregistré et indique à quel module appartient ce callback :

```bash
 vol -f dump_srv.mem linux.tracing.ftrace
Volatility 3 Framework 2.28.2
Progress:  100.00		Stacking attempts finished           
ftrace_ops address	Callback	Callback address	Hooked symbols	Module	Module address

0xffffc0b422c0	-	0xffffc0b3aac0	icmp_rcv	singularity	0xffffc0b35000
0xffffc0b42160	-	0xffffc0b3aac0	__ia32_sys_bpf	singularity	0xffffc0b35000
0xffffc0b42080	-	0xffffc0b3aac0	__x64_sys_bpf	singularity	0xffffc0b35000
0xffffc0b41b80	-	0xffffc0b3aac0	__ia32_sys_readlink	singularity	0xffffc0b35000
0xffffc0b41aa0	-	0xffffc0b3aac0	__x64_sys_readlink	singularity	0xffffc0b35000
0xffffc0b419c0	-	0xffffc0b3aac0	__ia32_sys_chdir	singularity	0xffffc0b35000
0xffffc0b418e0	-	0xffffc0b3aac0	__x64_sys_chdir	singularity	0xffffc0b35000
0xffffc0b41800	-	0xffffc0b3aac0	__ia32_sys_io_uring_enter	singularity	0xffffc0b35000
0xffffc0b41720	-	0xffffc0b3aac0	__x64_sys_io_uring_enter	singularity	0xffffc0b35000
0xffffc0b41640	-	0xffffc0b3aac0	__ia32_sys_tee	singularity	0xffffc0b35000
0xffffc0b41560	-	0xffffc0b3aac0	__x64_sys_tee	singularity	0xffffc0b35000
0xffffc0b41480	-	0xffffc0b3aac0	__ia32_sys_vmsplice	singularity	0xffffc0b35000
0xffffc0b413a0	-	0xffffc0b3aac0	__x64_sys_vmsplice	singularity	0xffffc0b35000
0xffffc0b412c0	-	0xffffc0b3aac0	__ia32_sys_splice	singularity	0xffffc0b35000
0xffffc0b411e0	-	0xffffc0b3aac0	__x64_sys_splice	singularity	0xffffc0b35000
0xffffc0b41100	-	0xffffc0b3aac0	__ia32_sys_copy_file_range	singularity	0xffffc0b35000
0xffffc0b41020	-	0xffffc0b3aac0	__x64_sys_copy_file_range	singularity	0xffffc0b35000
0xffffc0b40f40	-	0xffffc0b3aac0	__ia32_compat_sys_sendfile64	singularity	0xffffc0b35000
0xffffc0b40e60	-	0xffffc0b3aac0	__ia32_compat_sys_sendfile	singularity	0xffffc0b35000
0xffffc0b40d80	-	0xffffc0b3aac0	__ia32_sys_sendfile64	singularity	0xffffc0b35000
0xffffc0b40ca0	-	0xffffc0b3aac0	__ia32_sys_sendfile	singularity	0xffffc0b35000
0xffffc0b40bc0	-	0xffffc0b3aac0	__x64_sys_sendfile64	singularity	0xffffc0b35000
0xffffc0b40ae0	-	0xffffc0b3aac0	__x64_sys_sendfile	singularity	0xffffc0b35000
0xffffc0b40a00	-	0xffffc0b3aac0	__ia32_sys_pwritev2	singularity	0xffffc0b35000
0xffffc0b40920	-	0xffffc0b3aac0	__ia32_sys_pwritev	singularity	0xffffc0b35000
0xffffc0b40840	-	0xffffc0b3aac0	__x64_sys_pwritev2	singularity	0xffffc0b35000
0xffffc0b40760	-	0xffffc0b3aac0	__x64_sys_pwritev	singularity	0xffffc0b35000
0xffffc0b40680	-	0xffffc0b3aac0	__x64_sys_ia32_pwrite64	singularity	0xffffc0b35000
0xffffc0b405a0	-	0xffffc0b3aac0	__x64_sys_pwrite64	singularity	0xffffc0b35000
0xffffc0b404c0	-	0xffffc0b3aac0	__ia32_sys_writev	singularity	0xffffc0b35000
0xffffc0b403e0	-	0xffffc0b3aac0	__x64_sys_writev	singularity	0xffffc0b35000
0xffffc0b40300	-	0xffffc0b3aac0	__ia32_sys_write	singularity	0xffffc0b35000
0xffffc0b40220	-	0xffffc0b3aac0	__x64_sys_write	singularity	0xffffc0b35000
0xffffc0b3f1c0	-	0xffffc0b3aac0	sched_debug_show	singularity	0xffffc0b35000
0xffffc0b3f0e0	-	0xffffc0b3aac0	__ia32_sys_preadv	singularity	0xffffc0b35000
0xffffc0b3f000	-	0xffffc0b3aac0	__x64_sys_preadv	singularity	0xffffc0b35000
0xffffc0b3ef20	-	0xffffc0b3aac0	__ia32_sys_readv	singularity	0xffffc0b35000
0xffffc0b3ee40	-	0xffffc0b3aac0	__x64_sys_readv	singularity	0xffffc0b35000
0xffffc0b3ed60	-	0xffffc0b3aac0	__ia32_sys_pread64	singularity	0xffffc0b35000
0xffffc0b3ec80	-	0xffffc0b3aac0	__x64_sys_pread64	singularity	0xffffc0b35000
0xffffc0b3eba0	-	0xffffc0b3aac0	__ia32_sys_read	singularity	0xffffc0b35000
0xffffc0b3eac0	-	0xffffc0b3aac0	__x64_sys_read	singularity	0xffffc0b35000
0xffffc0b3e920	-	0xffffc0b3aac0	__ia32_sys_finit_module	singularity	0xffffc0b35000
0xffffc0b3e840	-	0xffffc0b3aac0	__ia32_sys_init_module	singularity	0xffffc0b35000
0xffffc0b3e760	-	0xffffc0b3aac0	__x64_sys_finit_module	singularity	0xffffc0b35000
0xffffc0b3e680	-	0xffffc0b3aac0	__x64_sys_init_module	singularity	0xffffc0b35000
0xffffc0b3e5a0	-	0xffffc0b3aac0	tpacket_rcv	singularity	0xffffc0b35000
0xffffc0b3e4c0	-	0xffffc0b3aac0	tcp6_seq_show	singularity	0xffffc0b35000
0xffffc0b3e3e0	-	0xffffc0b3aac0	tcp4_seq_show	singularity	0xffffc0b35000
0xffffc0b400e0	-	0xffffc0b3aac0	__ia32_sys_newfstatat	singularity	0xffffc0b35000
0xffffc0b40000	-	0xffffc0b3aac0	__x64_sys_newfstatat	singularity	0xffffc0b35000
0xffffc0b3ff20	-	0xffffc0b3aac0	__ia32_sys_getpriority	singularity	0xffffc0b35000
0xffffc0b3fe40	-	0xffffc0b3aac0	__x64_sys_getpriority	singularity	0xffffc0b35000
0xffffc0b3fd60	-	0xffffc0b3aac0	__ia32_sys_newlstat	singularity	0xffffc0b35000
0xffffc0b3fc80	-	0xffffc0b3aac0	__x64_sys_newlstat	singularity	0xffffc0b35000
0xffffc0b3fba0	-	0xffffc0b3aac0	__ia32_sys_newstat	singularity	0xffffc0b35000
0xffffc0b3fac0	-	0xffffc0b3aac0	__x64_sys_newstat	singularity	0xffffc0b35000
0xffffc0b3f9e0	-	0xffffc0b3aac0	__ia32_sys_lstat	singularity	0xffffc0b35000
0xffffc0b3f900	-	0xffffc0b3aac0	__x64_sys_lstat	singularity	0xffffc0b35000
0xffffc0b3f820	-	0xffffc0b3aac0	__ia32_sys_stat	singularity	0xffffc0b35000
0xffffc0b3f740	-	0xffffc0b3aac0	__x64_sys_stat	singularity	0xffffc0b35000
0xffffc0b3f660	-	0xffffc0b3aac0	__ia32_sys_statx	singularity	0xffffc0b35000
0xffffc0b3f580	-	0xffffc0b3aac0	__x64_sys_statx	singularity	0xffffc0b35000
0xffffc0b3e300	-	0xffffc0b3aac0	__ia32_compat_sys_getdents	singularity	0xffffc0b35000
0xffffc0b3e220	-	0xffffc0b3aac0	__ia32_sys_getdents	singularity	0xffffc0b35000
0xffffc0b3e140	-	0xffffc0b3aac0	__ia32_sys_getdents64	singularity	0xffffc0b35000
0xffffc0b3e060	-	0xffffc0b3aac0	__x64_sys_getdents	singularity	0xffffc0b35000
0xffffc0b3df80	-	0xffffc0b3aac0	__x64_sys_getdents64	singularity	0xffffc0b35000
0xffffc0b3de40	-	0xffffc0b3aac0	__x64_sys_sysinfo	singularity	0xffffc0b35000
0xffffc0b3dd60	-	0xffffc0b3aac0	__x64_sys_sched_rr_get_interval	singularity	0xffffc0b35000
0xffffc0b3dc80	-	0xffffc0b3aac0	__x64_sys_sched_getscheduler	singularity	0xffffc0b35000
0xffffc0b3dba0	-	0xffffc0b3aac0	__x64_sys_sched_getparam	singularity	0xffffc0b35000
0xffffc0b3dac0	-	0xffffc0b3aac0	__x64_sys_sched_getaffinity	singularity	0xffffc0b35000
0xffffc0b3d9e0	-	0xffffc0b3aac0	__x64_sys_getsid	singularity	0xffffc0b35000
0xffffc0b3d900	-	0xffffc0b3aac0	__do_sys_getpgrp,__ia32_sys_getpgrp,__x64_sys_getpgrp	singularity	0xffffc0b35000
0xffffc0b3d820	-	0xffffc0b3aac0	__x64_sys_getpgid	singularity	0xffffc0b35000
0xffffc0b3d740	-	0xffffc0b3aac0	__do_sys_getuid,__ia32_sys_getuid,__x64_sys_getuid	singularity	0xffffc0b35000
0xffffc0b3d660	-	0xffffc0b3aac0	__x64_sys_kill	singularity	0xffffc0b35000
0xffffc0b41f60	-	0xffffc0b3aac0	__ia32_sys_readlinkat	singularity	0xffffc0b35000
0xffffc0b41e80	-	0xffffc0b3aac0	__x64_sys_readlinkat	singularity	0xffffc0b35000
0xffffc0b41da0	-	0xffffc0b3aac0	__ia32_sys_openat	singularity	0xffffc0b35000
0xffffc0b41cc0	-	0xffffc0b3aac0	__x64_sys_openat	singularity	0xffffc0b35000
0x8e7a03dec180	call_direct_funcs	0xffff93a8aa20	__hid_bpf_tail_call	__kernel__	0xffff93800000

```

Toutes les lignes renvoient vers `singularity` (base `0xffffc0b35000`). On compte **82 fonctions hookées**.

Réponse : **82**

---

### Q10 - Which function is hooked to hide IPv4 network connections?

Les outils `netstat` et `ss` affichent les connexions TCP en lisant `/proc/net/tcp`. Ce fichier virtuel est construit par le noyau, ligne par ligne, par la fonction `tcp4_seq_show`. En la hookant, le rootkit peut simplement ne pas écrire les lignes qui concernent sa propre connexion C2. Le côté IPv6 passe par une fonction distincte, `tcp6_seq_show`, également hookée.

C'est justement pour cela que  comme évoqué par le scénario les administrateurs ne voyaient rien d'anormal avec leurs outils. 
![q10](/assets/posts/Phantom/Q10.png)

Réponse : **tcp4_seq_show**

---

### Q11 - How many variants of getdents syscalls are hooked?



En filtrant la sortie de `CheckFtrace` sur `getdents` on a : 

![q11](/assets/posts/Phantom/Q11.png)

Réponse : **5**

---

### Q12 - Which function is hooked to enable an ICMP-based covert channel?

`icmp_rcv` est la fonction du noyau qui traite chaque paquet ICMP entrant (les « pings »). En s'y accrochant, le rootkit inspecte tous les paquets ICMP reçus. Si l'un d'eux contient un motif particulier, il peut déclencher une action, ici l'ouverture d'un reverse shell vers le C2. Un pare-feu laisse souvent passer l'ICMP, et aucun port n'est ouvert en écoute, donc rien n'apparaît dans un scan de ports.

Le plugin `Netfilter` confirme qu'aucun hook réseau passe par ce mécanisme :

```bash
vol -f dump_srv.mem linux.malware.netfilter
Volatility 3 Framework 2.28.2
Progress:  100.00		Stacking attempts finished           
Net NS	Proto	Hook	Priority	Handler	Module	Symbol	Is Hooked

4026531840	IPV4	POST_ROUTING	-225	0xffff93f60aa0	__kernel__	apparmor_ip_postroute	False
4026531840	IPV6	POST_ROUTING	-225	0xffff93f60aa0	__kernel__	apparmor_ip_postroute	False

```

On y voit uniquement des hooks AppArmor légitimes (`apparmor_ip_postroute`, `Is Hooked = False`). Toute la partie réseau du rootkit repose donc sur ftrace.

![q12](/assets/posts/Phantom/Q12.png)

Réponse : **icmp_rcv**

---

### Q13 - What is the memory address of the centralized callback function? (Format:0x************)

Dans la sortie de `CheckFtrace`, chaque ligne contient deux adresses : l'une varie, l'autre est **identique pour les 82 hooks**. La première correspond à la structure `ftrace_ops` propre à chaque hook. La seconde est la fonction appelée dans tous les cas : un unique callback centralisé qui sert de répartiteur et redirige vers le bon hook selon la fonction interceptée.


![q13](/assets/posts/Phantom/Q13.png)

Cette adresse est à l'intérieur de la plage du module (`0xffffc0b35000` + `0x19000`). Il ne faut pas la confondre avec le probe du tracepoint de la Q5 (`0xffffc0b3a990`), qui est un autre point d'entrée, enregistré par un autre mécanisme.

Réponse : **0xffffc0b3aac0**

---


### Q14 - What is the value of the suspicious environment variable which leads to the escalation of privileges?

Chaque processus Linux possède un bloc d'environnement copié au démarrage dans sa mémoire. Volatility le relit avec `linux.envars` :

```bash
vol -f dump_srv.mem linux.envars
```


Sur les trois shells du C2 (2693, 2695, 2698), l'environnement est vide de tout élément intéressant. La je balaie donc tous les processus bashs à la recherche d'une variable qui n'a rien à faire là et je suis tombé sur le procesus:

```
2792  2774  bash  OPERATOR  access
```

Le processus 2792 est un `bash` ouvert dans la session SSH de l'utilisateur non privilégié `workstation` (client `192.168.200.1:63600`, la machine victime identifié précedemment). `OPERATOR` n'est pas une variable standard et n'existe sur aucun autre processus du dump.

Réponse : **access**

---

