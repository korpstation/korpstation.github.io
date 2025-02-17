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

# Exposant public
e = 65537

m = bytes_to_long(flag)

# Chiffrement du flag avec les trois modules
c1 = pow(m, e, n1)
c2 = pow(m, e, n2)
c3 = pow(m, e, n3)

# Stockage des clés publiques et des chiffrés
data = {
    "n1": n1,
    "n2": n2,
    "n3": n3,
    "e": e,
    "c1": c1,
    "c2": c2,
    "c3": c3
}

with open("flag-encrypted.txt", "w") as f:
    json.dump(data, f, indent=4)

print("Public keys and ciphertexts have been saved to flag-encrypted.txt.")
