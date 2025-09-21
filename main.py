from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import time

def key_bytes(key):
    try:
        #hex
        key_b=bytes.fromhex(key)
    except ValueError:
        #base64
        key_b=base64.b64decode(key)
    if len(key_b)!=16:
        raise ValueError('Key must be 128 bit')
    return key_b

def encrypt(plain, key_b):
    iv=os.urandom(16)
    cipher=Cipher(algorithms.AES(key_b),modes.CFB(iv),backend=default_backend())
    encryptor=cipher.encryptor()
    ciphertext=encryptor.update(plain.encode())+encryptor.finalize()
    return iv+ciphertext

def decrypt(ciphertext,key_b):
    iv=ciphertext[:16]
    actual_ct=ciphertext[16:]
    cipher=Cipher(algorithms.AES(key_b),modes.CFB(iv),backend=default_backend())
    decryptor=cipher.decryptor()
    plain=decryptor.update(actual_ct)+decryptor.finalize()
    return plain.decode()

#User input
key_input = input("Enter 128-bit key (hex or base64): ")
key_b= key_bytes(key_input)
plaintext=input("Enter plaintext: ")

start_enc_user=time.time()
ct=encrypt(plaintext, key_b)
end_enc_user=time.time()
enc_time_user=end_enc_user-start_enc_user

print("\nUser Input Encryption")
print("Ciphertext (Base64):", base64.b64encode(ct).decode())
start_dec_user=time.time()
pt_recovered=decrypt(ct, key_b)
end_dec_user=time.time()
dec_time_user=end_dec_user-start_dec_user
print("Recovered plaintext:", pt_recovered)
print(f"Encryption time: {enc_time_user:.4f} seconds")
print(f"Decryption time: {dec_time_user:.4f} seconds")

#Encrypt/Decrypt file
fp='text.txt'
with open(fp,'r',encoding='utf-8') as f:
    data=f.read()
file_size=os.path.getsize(fp)

start_enc=time.time()
encrypted=encrypt(data,key_b)
end_enc=time.time()
enc_time=end_enc-start_enc

with open("encrypted_file.bin", "wb") as f:
    f.write(encrypted)

ct_size=len(encrypted)
start_dec = time.time()
with open("encrypted_file.bin", "rb") as f:
    encrypted= f.read()

decrypted= decrypt(encrypted, key_b)
end_dec = time.time()
dec_time = end_dec-start_dec

with open("decrypted_file.txt", "w", encoding="utf-8") as f:
    f.write(decrypted)

#Summary table
print("\nFile encryption summary")
print(f"Encryption time: {enc_time:.4f} seconds")
print(f"Decryption time: {dec_time:.4f} seconds")
print(f"Ciphertext size: {ct_size} bytes")
print(f"File size: {file_size} bytes")


