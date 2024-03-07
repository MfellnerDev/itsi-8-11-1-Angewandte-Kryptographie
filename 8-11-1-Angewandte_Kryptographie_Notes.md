***

**Autor**: Manuel Fellner
**Version**: 05.03.2024

#SYT #Labor #4BHIT #4-SoSe #Angewandte-Kryptographie


## 1. Einführung

### Vorgeschichte:

> Bei einem Ransomware-Angriff auf deinen Rechner wurden einige wichtige Dateien verschluesselt. Aus online verfuegbaren Analysen weisst du, dass die Taeter dabei wie folgt vorgingen (Diese Darstellung ist ein Wenig vereinfacht);

1. Angreifer generieren zunächst für jedes Opfer ein RSA 2048bit-Schlüsselpaar (public & private key)
2. Der public key wird zum opfer transferiert
3. Der private key bleibt unter der Kontrolle der Angreifer
4. Für jede zu verschlüsselnde Datei wird ein AES-128 Schlüssel generiert
5. Die Datei wird danach mit diesem im AES-CBC-Modus verschlüsselt
6. Der Schlüssel selbst wird mit dem RSA public key des Opfers verschlüsselt und an die verschlüsselte Datei angehängt

Zum Glück wurde auf der Plattform `nomoreransom.org` bekanntgegeben, wer die Ransomware betreibt - Dadurch haben wir den vom Angreifer verwendeten RSA key `key.pem`

### Aufgabenstellung:

- Rekonstruiere die Inhalte der verschlüsselten Datei `wichtig.enc`:
	- Extrahiere den verschlüsselten AES-Key aus der Datei
	- Entschlüssele diesen Key
	- Verwende den entschlüsselten Key zum Wiederherstellen der Daten
	- Erstelle ein Programm, das deine Wiederherstellungsschritte automatisiert und eine gegebene verschlüsselte Datei automatisch entschlüsseln kann
- Sind die verwendeten Algorithmen und Schlüssellängen (AES und RSA) zur Zeit als sicher eingestuft? - Begründe deine Antwort

### Hinweis:
>Der Initialisierungsvektor beim CBC-Modus ist nur relevant, wenn der selbe Key mehrfach verwendet wird. Ist dies nicht der Fall, so wird haeufig 0.....000 verwendet.


## 2. Durchführung

### 2.1 Manuelle Durchführung

- Der AES-128 Key ist hinten an der Datei angehängt
	- Wir müssen also die letzten Bytes vom `wichtig.enc` file nehmen
	- Wie viele Bytes? Dafür müssen wir uns die Verschlüsselungsalgorithmen genauer anschauen: Das `wichtig.enc` ist mittels RSA **2048bit** Verschlüsselt, was bedeutet, dass die Blockgröße von `wichtig.enc`= 2048bit = 256 Bytes ist.
	- Das bedeutet, dass wir einfach den letzten Block, also die letzten 256 Bytes von `wichtig.enc` nehmen und diese entschlüsseln müssen.


- Um uns die letzten Bytes eines Files zu holen, können wir `tail` verwenden.

![](https://uploads.mfellner.com/vCuDD2R3xAsi.png)

- Nun holen wir uns die letzten 256 Bytes des `wichtig.enc` files:
	- `cat wichtig.enc | tail -c 256 >> aes-key`
- Als nächstes Entschlüsseln wir den key, da dieser ja immer noch mittels RSA 2048bit verschlüsselt ist:
	- `openssl rsautl -decrypt -in aes-key.enc -out aes-key -inkey key.pem`
	- `aes-key`: 172abe01891111000deadbeef0000101 (Hex)

- Nun müssen wir die Nachricht an sich entschlüsseln:
	- Dafür müssen wir aber die letzten 256 Bytes von `wichtig.env` NICHT beachten, da in dem Block ja der AES-128 key drangehängt ist
	- Dafür können wir `head` verwenden:
![](https://uploads.mfellner.com/PVdqdleOe2Xa.png)


- Wir entfernen die letzten 256 Bytes: `cat wichtig.enc | head -c 1016320 >> wichtig-correct-size.enc `
- (geht bei `head` auf mit `-256` um die letzten 256 Bytes zu entfernen)

Als nächstes gehen wir auf https://gchq.github.io und entschlüsseln den Text mit folgender Eingabe:

![](https://uploads.mfellner.com/26MD0QTihzMl.png)

- `Key`: 172abe01891111000deadbeef0000101
- `IV`: 0000000000000000000000000000000
- `Mode`: CBC (weil aes-128-cbc)
- `Input`: Raw
- `Output`: Raw

- Der Inhalt ist ein "THE LORD OF THE RINGS" Buch


### 2.2 Automatisierte Durchführung

Nun automatisieren wir diesen Prozess des entschlüsselns.

Steps, die das Programm ausführen muss:

1. Die letzten 256 Byte des Files entfernen, in ein extra file speichern
2. Die gespeicherten 256 Bytes mit RSA entschlüsseln mit key.pem, speichern
3. Das file decrypten: `openssl enc -aes-128-cbc -nosalt -d -in wichtig-correct-size.enc -K '172abe01891111000deadbeef0000101' -iv '0000000000000000000000000000000' >> output`

Umgesetzt schaut das Python script dann folgendermaßen aus:

```python
import os  
  
from Crypto.PublicKey import RSA  
from Crypto.Cipher import AES, PKCS1_v1_5  
from Crypto.Random import get_random_bytes  
  
# step 1: remove the last 256 Bytes and store them  
  
with open('wichtig.enc', 'rb') as f_wichtig:  
    f_wichtig.seek(-256, os.SEEK_END)  
    last_256_bytes = f_wichtig.read()  
with open('aes-key.bin', 'wb') as aes_key_file:  
    aes_key_file.write(last_256_bytes)  
  
  
# step 2: decrypt the aes_key_file with RSA and the key.pem file  
  
rsa_private_key = RSA.import_key(open('key.pem').read())  
  
with open('aes-key.bin', 'rb') as aes_key_file_read:  
    enc_session_key = aes_key_file_read.read(rsa_private_key.size_in_bytes())  
    ciphertext = aes_key_file_read.read()  
  
sentinel = get_random_bytes(16)  
cipher_rsa = PKCS1_v1_5.new(rsa_private_key)  
aes_key = cipher_rsa.decrypt(enc_session_key, sentinel)  
  
# remove the last byte (new line)  
aes_key = aes_key[:-1]  
aes_key = bytes.fromhex(aes_key.decode())  
  
# in our case, the iv is 0  
iv = bytes(16)  
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)  
decrypted_data = cipher_aes.decrypt(ciphertext)  
  
# step 3: decrypt the entire data file  
  
with open('wichtig.enc', 'rb') as f_wichtig_correct_size:  
    cipher_text = f_wichtig_correct_size.read()  
  
cipher = AES.new(aes_key, AES.MODE_CBC, iv)  
message = cipher.decrypt(cipher_text)  
  
with open('decrypted-output.txt', 'w') as decrypted_output:  
    decrypted_output.write(message.decode('utf-8', 'replace'))
    
```

- Hier wird unten aber noch der Datenschrott (AES-128 Key) drangehängt

Wenn wir das Script ausführe, erhalten wir folgendes `decrypted_output.txt` file:

![](https://uploads.mfellner.com/8fRIXHhAQX6k.png)
**Frage**:

> Sind die verwendeten Algorithmen und Schluessellaengen (AES und RSA) zur Zeit als sicher eingestuft?

- Ja, beide Verschlüsselungsalgorithmen sind (Stand: 07.03.2024) noch sicher. Ebenso sind die Schlüssellängen von 128bit bzw. 2048bit immer noch sicher, auch wenn 128bit für die Zukunft vielleicht nicht mehr ausreichen wird.
- AES-128 hat eine Schlüssellänge von 2^128 = 340282366920938463463374607431768211456, diese Schlüssel sind also definitiv noch sicher.