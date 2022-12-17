# Vježba 3 - MAC (Message Authentication Code)

Cilj vježbe bio je pokazati primjer praktične primjene MAC algoritma te onoga što pruža, tj. omogućuje. Za uspješno izvođenje vježbe i njezino razumijevanje, potrebno je znati što je MAC algoritam i koji su njegovi osnovni dijelovi. 

Kao što mu samo ime kaže, **MAC algoritam** ima svrhu omogućiti zaštitu integriteta poruke (sadržaja) i/ili omogućiti provjeru tog integriteta. Osnovni dijelovi su:

- **poruka (**m) - poruka (sadržaj) čiji se integritet želi zaštititi
- **K** - dijeljena zajednička tajna (ili dijeljeni tajni ključ) Naravno, smiju je znati samo strane u komunikaciji.
- **MAC algoritam** - algoritam za zaštitu integriteta koji na temelju dva argumenta, poruke i zajedničke tajne, stvara
- **MACk(m)** - MAC kod (tj. potpis) - jedinstveni niz bitova dobiven na osnovu poruke i zajedničke tajne, služi za provjeru autentičnosti.

Prvi dio vježbe bio je na jednostavnom primjeru prikazati što treba raditi MAC algoritam da bi ispunio svoju funkciju. Cilj je bio zaštititi integritet proizvoljne tekstualne datoteke generiranjem potpisa za tu datoteku, tj. generiranjem MAC koda, a taj kod generira sljedeća funkcija:

```python
def generate_MAC(key, message):
	if not isinstance(message, bytes):
		message = message.encode()

	h = hmac.HMAC(key, hashes.SHA256())
	h.update(message)
	signature = h.finalize()
	return signature
```

Inače, sintagma MAC algoritam se ne odnosi na jednu specifičnu funkciju ili algoritam, već za grupu algoritama koji na sličan način pokušavaju ostvariti isti cilj - zaštititi integritet. U ovom slučaju, potpis (MAC kod) jest hash vrijednost koju daje kriptografska hash funkcija kad joj se kao argument dade sadržaj i tajna. Ovo rješenje ima smisla ukoliko je hash funkcija otporna na koliziju, tj. gotovo je nemoguće mogućnost da hash vrijednost za dva različita ulaza bude ista.

Drugi važan dio jest provjera vjerodostojnosti (nepromijenjenosti) sadržaja, a funkcija koja to čini je:

```python
def verify_MAC(key, signature, message):
	if not isinstance(message, bytes):
		message = message.encode()
	
	h = hmac.HMAC(key, hashes.SHA256())
	h.update(message)
	try:
		h.verify(signature)
	except InvalidSignature:
    return False
	else:
    return True
```

Funkcija za argumente prima tajnu, potpis i sadržaj čija se vjerodostojnost ispituje. Na osnovu sadržaja (poruke) i tajne funkcija stvara hash vrijednost (potpis) na isti način na koji to radi funkcija generate_MAC. Stvoreni potpis se uspoređuje s potpisom proslijeđenim kao argument te se, ovisno o podudaranju dvaju potpisa, šalje povratna informacija je li sadržaj poruke vjerodostojan, tj. je li se očuvao integritet.

Cjeloviti kod za prvi dio vježbe izgledao je ovako:

```python
import re
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
	if not isinstance(message, bytes):
		message = message.encode()
	
	h = hmac.HMAC(key, hashes.SHA256())
	h.update(message)
	signature = h.finalize()
	return signature

def verify_MAC(key, signature, message):
	if not isinstance(message, bytes):
		message = message.encode()
	h = hmac.HMAC(key, hashes.SHA256())
	h.update(message)
	try:
    h.verify(signature)
	except InvalidSignature:
    return False
	else:
    return True

if __name__ == "___main__":

with open("poruka.txt", "rb") as file:
		content = file.read()

kljuc = "moja super tajna zaporka".encode()
potpis = generate_MAC(kljuc, content)
print(potpis)

with open("potpisana_poruka", "wb") as file:
		file.write(potpis)

with open("poruka.txt", "rb") as file:
		content2 = file.read()

with open("potpisana_poruka", "rb") as file:
		potpis2 = file.read()

kljuc2 = "moja super tajna zaporka".encode()
je_ok = verify_MAC(kljuc2, potpis2, content2)
print("Poruka je ok" if je_ok else "nije ok")
```

U drugom dijelu vježbe je trebalo sa lokalnog poslužitelja preuzeti 10 tekstualnih datoteka i po jedan potpis za svaku od njih, provjeriti vjerodostojnost svake od njih te sadržaj vjerodostojnih poruka upisati u niz poruka. Osnova za izvođenje te provjere jest već navedena i objašnjena funkcija veryfy_MAC, a korišteni su još neki alati kako bi se proces provjere automatizirao i poruke poredale potrebnim redoslijedom s obzirom na prirodu njihovog sadržaja. Kod za izvođenje drugog dijela vježbe je:

```python
import datetime
import re
from pathlib import Path
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
	if not isinstance(message, bytes):
		message = message.encode()
	h = hmac.HMAC(key, hashes.SHA256())
	h.update(message)
	signature = h.finalize()
	return signature

def verify_MAC(key, signature, message):
	if not isinstance(message, bytes):
	message = message.encode()
	h = hmac.HMAC(key, hashes.SHA256())
	h.update(message)
	try:
    h.verify(signature)
	except InvalidSignature:
    return False
	else:
    return True

if __name__ == "__main__":

kljuc = "cagalj_josip".encode()
PATH = "challenges/g1/cagalj_josip/mac_challenge/"
poruke = []
for ctr in range(1, 11):
    msg_filename = f"order_{ctr}.txt"
    sig_filename = f"order_{ctr}.sig"
    msg_file_path = Path(PATH + msg_filename)
    sig_file_path = Path(PATH + sig_filename)
    with open(msg_file_path, "rb") as file:
        poruka = file.read()

    with open(sig_file_path, "rb") as file:
        potpis = file.read()

    je_ok = verify_MAC(kljuc, potpis, poruka)
    if je_ok:
        poruke.append(poruka.decode())

poruke.sort(
    key=lambda m: datetime.datetime.fromisoformat(
        re.findall(r"\\(.*?\\)", m)[0][1:-1]
    )
)

for m in poruke:
    print(f'Poruka {m:45} {"OK":<6}>')
```