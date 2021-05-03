# EHN 410 - Practical 2 - 2021
# 3DES encryption and decryption
# Group 7
# Created: 2 May 2021 by Stefan Buys

import numpy as np
import copy

##### MAIN CIPHER FUNCTIONS #####

def TDEA_Encrypt(plaintext, inspect_mode = 0, key1 = 0, key2 = 0, key3 = 0, ip = 0):
    print("3DES Encryption")

    ### Plaintext Encoding ###

    # If the plaintext is a string to be encrypted:
    if (isinstance(plaintext, str)):
        # Convert the plaintext string to its bit representation
        plaintextEncoded = plaintext.encode(encoding="ascii",errors="ignore")
        plaintextEncoded = bytearray(plaintextEncoded)
        #Pad the plaintext such that the total number of bytes is an integral multiple of 64 (for DES)
        plaintextEncoded = pad(plaintextEncoded, 64)


        
        print("-----")
        print(plaintextEncoded)
        print(pad(plaintextEncoded,5))


def TDEA_Decrypt(inspect_mode, ciphertext, key1, key2, key3, inv_ip):
    print("3DES Decryption")

permutation = np.load("Practical 2 File package/DES_Initial_Permutation.npy")


###### HELPER FUNCTIONS #####

#Function pads the input bytearray, so that its length will divide the integral_number provided
#Pads the bytearray so that the last group of integral_number is full
#Default padding = 0x00
def pad(bytearr, integral_number = 64, padding = 0x00):
    bytearrayOutput = copy.deepcopy(bytearr)
    numShort = integral_number - (len(bytearr) % integral_number)
    for i in range(numShort):
        bytearrayOutput.append(padding)
    return bytearrayOutput


#This functions performs normal DES encryption:
def DES_Encryption(plaintext, inspect_mode = 0, key = 0, ip = 0):
    print("Hello")


#This helper function performs permutation on the bitarray according to the positions specified by
#an permutation array, that contains the locatons where bits should be allocated in the permuted array
def permutation(bytearr, permutationArray):
    outputByteArray = bytearray()
    







##### TESTING CODE ######

string = "Hello, hoe gaan dit vandag?"

bytearr = np.empty(len(string),dtype=np.byte)
for i in range(len(string)):
    bytearr[i] = ord(string[i])

bytearr[0] &= 0xFF
print(bytearr)

toets = 0

stringEncoded = string.encode(encoding="ascii",errors="ignore")
#print(stringEncoded)
stringEncoded = bytearray(stringEncoded)
stringEncoded[0] = stringEncoded[0]^255
#print(stringEncoded)

TDEA_Encrypt("Cat")