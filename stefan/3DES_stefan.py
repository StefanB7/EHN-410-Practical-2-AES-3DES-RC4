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
#an permutation array, that contains the locations where bits should be allocated in the permutated array
def permutation(bytearr, permutationArray):
    outputByteArray = bytearray(len(bytearr))
    permutationDec = np.arange(len(permutationArray))

    #Decrement each permutation values such that the values are indexes:
    for i in range(len(permutationArray)):
        permutationDec[i] = permutationArray[i] - 1

    #Iterate over every bit
    for i in range(len(bytearr)*8):
        #Permutation value:
        permuteValue = permutationDec[i]
        byteIndex = permuteValue // 8
        bitIndex = permuteValue % 8

        #If the bit at the permutation index is set, set the permuted bit in the output
        bSet = bytearr[byteIndex]
        value = 0x01 << (7-bitIndex)
        bSet = bytearr[byteIndex] & (0x01 << (7-bitIndex))

        #Since the output byte array is already all zeros, only set bit if need be
        if (bSet):
            outputByteArray[i//8] = outputByteArray[i//8] | (0x01 << (7-(i%8)))

    return outputByteArray













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

permutationL = np.load("Practical 2 File Package/DES_Initial_Permutation.npy")
permutationL = np.array(permutationL, dtype=int)
print(permutationL)

bytearr = bytearray("d",encoding="ascii")
print(bytearr)

print(permutation(bytearr, [3,4,7,6,5,2,8,1]))