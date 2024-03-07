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