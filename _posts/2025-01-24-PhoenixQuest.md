---
title: Inscription au Phoenix Quest - Writeups
time: 2025-01-24 18:00:00
categories: [ctf]
tags: [web,crypto,stegano,forensic]
image: /assets/posts/phoenix/icon.png
---

Mes writeups pour les 4 challenges proposés lors de l'Inscription au Phoenix Quest

## Étape 1 : L'Éveil du Phénix [Web] 

On nous sommets à une page de connexion sans aucune information supplémentaire. 

![step1](/assets/posts/phoenix/step1.png)

Une page de connexion ? La première chose à essayer c'est une sqli. Alors j'essaye avec  ``username`` : admin'-- ; et ``password``: test. Et nous avons validé l'étape 1. 

![step1.1](/assets/posts/phoenix/step1.1.png)


##  Étape 2 : Les Flammes du Savoir [Crypto] 

``Description``: Les flammes du savoir brûlent pour ceux qui osent déchiffrer les énigmes du passé.

Téléchargez les fichiers nécessaires et soumettez le message déchiffré.

``File`` : [public_key.pem](/assets/posts/phoenix/public_key.pem) ; [encrypted_messages.b64](/assets/posts/phoenix/encrypted_messages.b64)

``Flag`` : `flames_of_knowledge_435681069`

Nous avons deux fichiers : 

`encrypted_messages.b64` contient deux lignes encodés en b64. Seule la deuxième ligne comportait une entrée b64 valide. 
   
   ``` bash 
┌──(kali㉿korpstation)-[~/CTF/Phoenix Quest/Step2]
└─$ cat encrypted_messages.b64                                  
aSkjLPQ98/zBYMiycD1Eeg==

Y3pocWVwX2NtX29ubGtzaWRkc18xMDIzNTg3MzY==                                                                                
```

`public_key.pem` contenant une clé publique PEM. Cette clé fait seulement 192 bits, ce qui la rend très vulnérable. J'ai utilisé ``RsaCtfTool`` pour trouver la clé privée correspondante. 

``` bash 
┌──(kali㉿korpstation)-[~/CTF/Phoenix Quest/Step2]
└─$ ./../../Tools/RsaCtfTool/RsaCtfTool.py --publickey ./public_key.pem  --private 
['./public_key.pem']

[*] Testing key ./public_key.pem.
attack initialized...
attack initialized...
[*] Performing rapid7primes attack on ./public_key.pem.
[+] Time elapsed: 0.0016 sec.
[*] Performing lucas_gcd attack on ./public_key.pem.
100%|███████████████████████████████████████████████████| 9999/9999 [00:00<00:00, 142135.71it/s]
[+] Time elapsed: 0.0859 sec.
[*] Performing mersenne_primes attack on ./public_key.pem.
 24%|████████████▉                                          | 12/51 [00:00<00:00, 151146.09it/s]
[+] Time elapsed: 0.0010 sec.
[*] Performing pastctfprimes attack on ./public_key.pem.
[+] Time elapsed: 0.0010 sec.
[*] Performing nonRSA attack on ./public_key.pem.
[+] Time elapsed: 0.0109 sec.
[*] Performing fibonacci_gcd attack on ./public_key.pem.
100%|███████████████████████████████████████████████████| 9999/9999 [00:00<00:00, 228115.71it/s]
[+] Time elapsed: 0.0476 sec.
[*] Performing smallq attack on ./public_key.pem.
[+] Time elapsed: 0.2568 sec.
[*] Performing factordb attack on ./public_key.pem.
[*] Attack success with factordb method !
[+] Total time elapsed min,max,avg: 0.0010/0.2568/0.0578 sec.

Results for ./public_key.pem:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MGECAQACEQCcqTF74D5nuVgRhuDD6o41AgMBAAECEAIBbH/AfCwJv0PJ8dh89WEC
CQC/HdoGCMWlGQIJANHYwqE8RZl9Agh4Mg0JmIC9GQIIa5/MUn1jBNECCFYaE9x3
PBqH
-----END RSA PRIVATE KEY-----

```
Par la suite j'ai utilisé la clé privée pour décrypter notre fichier crypté avec le script suivant :

``` bash 
                                                                                                
┌──(kali㉿korpstation)-[~/CTF/Phoenix Quest/Step2]
└─$ cat solve.py               
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

# The private key from RsaCtfTool output
private_key_pem = '''-----BEGIN RSA PRIVATE KEY-----
MGECAQACEQCcqTF74D5nuVgRhuDD6o41AgMBAAECEAIBbH/AfCwJv0PJ8dh89WEC
CQC/HdoGCMWlGQIJANHYwqE8RZl9Agh4Mg0JmIC9GQIIa5/MUn1jBNECCFYaE9x3
PBqH
-----END RSA PRIVATE KEY-----'''

encrypted_messages = [
    "aSkjLPQ98/zBYMiycD1Eeg==",
    "Y3pocWVwX2NtX29ubGtzaWRkc18xMDIzNTg3MzY=="
]

# Load the private key
key = RSA.importKey(private_key_pem)
cipher = PKCS1_v1_5.new(key)

# Decrypt each message
for msg in encrypted_messages:
    try:
        # Decode base64 and decrypt
        encrypted = base64.b64decode(msg)
        decrypted = cipher.decrypt(encrypted, None)
        print(f"Decrypted message: {decrypted.decode('utf-8')}")
    except:
        # If RSA decryption fails, try just base64 decode
        try:
            decoded = base64.b64decode(msg)
            print(f"Base64 decoded: {decoded.decode('utf-8')}")
        except:
            print(f"Failed to decrypt/decode: {msg}")
                                                                                                
┌──(kali㉿korpstation)-[~/CTF/Phoenix Quest/Step2]
└─$ python solve.py
Decrypted message: kBurn
Base64 decoded: czhqep_cm_onlksidds_102358736

```
Nous avons deux messages, un message court qui semble être une clé. Etant habitué à ce genre de challenge, j'ai pensé que c'était du vigénère.

![vigenere](/assets/posts/phoenix/cyberchef.png)

J'ai ensuite appliquée un Rot13 à la sortie pour avoir le flag. Sans oublier d'appliquer la rotation aux chiffres. 

![rot13](/assets/posts/phoenix/cyberchef2.png)



##  Étape 3 : Le Vol Clandestin [Stegano]


``Description``: Le Phénix prend son envol à travers des cieux dissimulés.

Téléchargez l'image et extrayez le message caché.

``File`` : [image](/assets/posts/phoenix/image.png) 

``Flag`` : `FLAG{hidden_flight_found_4580258}`

C'était un challenge plutôt facile. Mais j'ai passé plus de temps qu'il ne devrais la dessus. 

Bon on nous donne une image png de 15Mo. 

En utilisant ``stegoveritas`` sur l'image j'ai eu trois fichiers. Une image phoenix.jpg , un pdf et une archive rar. 

Le pdf et le phoenix.jpg étaient de fausses pistes.

En voulant extraire l'archive celà demande un mot de passe. C'est à ce niveau que j'ai passé beaucoup de temps à essayer de cracker le fichier rar sans gain de cause. 

Après des heures j'ai eu l'idée d'envoyer l'image sur ``aperisolve.com`` (j'aurais dû commencer par là) et j'ai eu le mot de passe de l'archive. 

![aperisolve](/assets/posts/phoenix/aperisolve.png)

En décompressant l'archive nous avons eu 5 images. J'ai utilisé ``zsteg`` sur la première image comme c'était un png. 

```bash
┌──(kali㉿korpstation)-[~/…/Phoenix Quest/Step3/RAR/1]
└─$ zsteg 210095.png     
[?] 60 bytes of extra data after image end (IEND), offset = 0x655dd
extradata:0         .. text: "RkxBR3swNDUyNjU0NTMyMV81ZTE4ODc1ODY1ZTg0ODQ1XzQ1ODUyMjU4fQ=="
  --SNIP--

┌──(kali㉿korpstation)-[~/…/Phoenix Quest/Step3/RAR/1]
└─$ echo "RkxBR3swNDUyNjU0NTMyMV81ZTE4ODc1ODY1ZTg0ODQ1XzQ1ODUyMjU4fQ==" | base64 -d
FLAG{04526545321_5e18875865e84845_45852258}    #fake flag

```

Comme le flag était faux j'ai continué à analyser les autres images avec ``stegoveritas``. La troisième image contenait le vrai flag. 

```bash
┌──(kali㉿korpstation)-[~/…/Phoenix Quest/Step3/RAR/3]
└─$ stegoveritas 230023.jpg
Running Module: SVImage
+------------------+-----
Trailing Data Discovered... Saving
b'RkxBR3toaWRkZW5fZmxpZ2h0X2ZvdW5kXzQ1ODAyNTh9'
Running Module: MultiHandler

┌──(kali㉿korpstation)-[~/…/Phoenix Quest/Step3/RAR/3]
└─$ echo "RkxBR3toaWRkZW5fZmxpZ2h0X2ZvdW5kXzQ1ODAyNTh9" | base64 -d                
FLAG{hidden_flight_found_4580258}  

```

##  Étape 4 : Les Cendres de la Vérité [Forensic]


``Description``: Dans les cendres du passé réside la vérité. Téléchargez le fichier à analyser.

Télécharger ashes.img

``File`` : [disk](/assets/posts/phoenix/ashes.img) 

``Flag`` : `FLAG{truth_in_ashes_final_80256841025}`

On nous donne une image disk DOS/MBR. La solution attendue c'était je crois de monter l'image et de chercher le flag. Mais en faisant juste un ``strings`` je suis tombé sur le flag encodé en b64. 

```bash 
┌──(kali㉿korpstation)-[~/CTF/Phoenix Quest/Step4]
└─$ file ashes.img
ashes.img: DOS/MBR boot sector; partition 1 : ID=0x83, start-CHS (0x10,0,1), end-CHS (0x9f,3,32), startsector 2048, 18432 sectors
                                                                                
┌──(kali㉿korpstation)-[~/CTF/Phoenix Quest/Step4]
└─$ strings ashes.img 
/mnt/mission_backup
lost+found
home
user1
user2
lost+found
home
documents
downloads
pictures
.ftp_transfer.pcap
/mnt/mission_backup
_[l<
user1
user2
documents
downloads
pictures
.ftp_transfer.pcap
220 Welcome to the FTP server
USER anonymous
331 User OK, need password
PASS anonymous@
230 Login successful
CWD /uploads
250 Directory changed
STOR file_with_flag.pdf
150 Opening data connection
%PDF-1.4
1 0 obj
<< /Type /Catalog
endobj
2 0 obj
<< /Type /Page /Parent 3 0 R /Resources 4 0 R /Contents 5 0 R
endobj
5 0 obj
<< /Length 56 >>
stream
RkxBR3t0cnV0aF9pbl9hc2hlc19maW5hbF84MDI1Njg0MTAyNX0NCg==
endstream
endobj
trailer
<< /Root 1 0 R
%%EOF
                                                                                
┌──(kali㉿korpstation)-[~/CTF/Phoenix Quest/Step4]
└─$ echo "RkxBR3t0cnV0aF9pbl9hc2hlc19maW5hbF84MDI1Njg0MTAyNX0NCg==" | base64 -d
FLAG{truth_in_ashes_final_80256841025}
```
