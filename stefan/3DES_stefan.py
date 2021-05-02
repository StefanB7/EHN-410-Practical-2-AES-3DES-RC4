# EHN 410 - Practical 2 - 2021
# 3DES encryption and decryption
# Group 7
# Created: 2 May 2021 by Stefan Buys

import numpy as np

def TDEA_Encrypt(inspect_mode, plaintext, key1, key2, key3, ip):
    print("3DES Encryption")

def TDEA_Decrypt(inspect_mode, ciphertext, key1, key2, key3, inv_ip):
    print("3DES Decryption")

permutation = np.load("Practical 2 File package/DES_Initial_Permutation.npy")



string = "Hello, hoe gaan dit vandag?"

bytearr = np.empty(len(string),dtype=np.byte)
for i in range(len(string)):
    bytearr[i] = ord(string[i])

bytearr[0] &= 0xFF
print(bytearr)

toets = 0

stringEncoded = string.encode(encoding="ascii",errors="ignore")
print(stringEncoded)
stringEncoded = bytearray(stringEncoded)
stringEncoded[0] = stringEncoded[0]^255
print(stringEncoded)