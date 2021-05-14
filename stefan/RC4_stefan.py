# EHN 410 - Practical 2 - 2021
# RC4 Encryption and Decryption
# Group 7
# Created: 14 May 2021 by Stefan Buys

import numpy as np
import copy

from PIL import Image

##### MAIN CIPHER FUNCTIONS #####

def RC4_Enctrypt(plaintext, key):

    #Generate the required stream generation variables:
    S = bytearray(256)
    T = bytearray(256)

    #Transform key to bytearray:
    keyBytes = bytearray(len(key))
    for i in range(len(key)):
        keyBytes[i] = ord(key[i])

    #Initialization:
    for i in range(256):
        S[i] = i
        T[i] = keyBytes[i % len(key)]

    #Perform a permutation on S:
    temp = 0
    index = 0
    for i in range(255):
        index = (index + S[i] + T[i]) % 256
        temp = S[i]
        
        S[i] = S[index]
        S[index] = temp

    ### Plaintext Encoding ###

    # If the plaintext is a string to be encrypted:
    if (isinstance(plaintext, str)):
        cipherText = bytearray(len(plaintext))

        #Transform the plaintext input into a bytearray:
        plaintextBytes = bytearray(len(plaintext))
        for i in range(len(plaintext)):
            plaintextBytes[i] = ord(plaintext[i])

        #Encrypt the plaintext:
        i = 0
        j = 0

        for index in range(len(plaintextBytes)):
            #Generate the next stream element:
            i = (i+1) % 256
            j = (j+S[i]) % 256
            temp = S[i]
            S[i] = S[j]
            S[j] = temp

            streamElementIndex = (S[i] + S[j]) % 256
            streamElement = S[streamElementIndex]

            cipherText[index] = plaintextBytes[index] ^ streamElement

        cipherTextString = ''
        for i in range(len(cipherText)):
            cipherTextString = cipherTextString + chr(cipherText[i])

        return cipherTextString


def RC4_Decrypt(ciphertext, key):

    #Generate the required stream generation variables:
    S = bytearray(256)
    T = bytearray(256)

    #Transform key to bytearray:
    keyBytes = bytearray(len(key))
    for i in range(len(key)):
        keyBytes[i] = ord(key[i])

    #Initialization:
    for i in range(256):
        S[i] = i
        T[i] = keyBytes[i % len(key)]

    #Perform a permutation on S:
    temp = 0
    index = 0
    for i in range(255):
        index = (index + S[i] + T[i]) % 256
        temp = S[i]
        S[i] = S[index]
        S[index] = temp

    ### Text Decoding ###

    # If the ciphertext is a string to be encrypted:
    if (isinstance(ciphertext, str)):
        plainText = bytearray(len(ciphertext))

        #Transform the plaintext input into a bytearray:
        ciphertextBytes = bytearray(len(ciphertext))
        for i in range(len(ciphertext)):
            ciphertextBytes[i] = ord(ciphertext[i])

        #Decrypt the ciphertext:
        i = 0
        j = 0

        for index in range(len(ciphertextBytes)):
            #Generate the next stream element:
            i = (i+1) % 256
            j = (j+S[i]) % 256
            temp = S[i]
            S[i] = S[j]
            S[j] = temp

            streamElementIndex = (S[i] + S[j]) % 256
            streamElement = S[streamElementIndex]

            plainText[index] = ciphertextBytes[index] ^ streamElement

        plainTextString = ''
        for i in range(len(plainText)):
            plainTextString = plainTextString + chr(plainText[i])

        return plainTextString

    print("RC4 Decrypt")

encrypted = RC4_Enctrypt("Hello, hoe gaan dit met jou?", "stefan")
print(encrypted)
decrypted = RC4_Decrypt(encrypted,"stefan")
print(decrypted)