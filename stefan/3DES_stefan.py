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
    status = copy.deepcopy(plaintext)

    #Create the keys:

    #Do the initial permutation
    status = permutation(status, ip)



#This helper function performs permutation on the bitarray according to the positions specified by
#an permutation array, that contains the locatons where bits should be allocated in the permuted array
def permutation(bytearr, permutationArray):
    #The output array should just be the size of the permutationArray divided by 8 (its bytes)
    outputByteArray = bytearray(len(permutationArray)//8)
    permutationDec = np.arange(len(permutationArray))

    #Decrement each permutation values such that the values are indexes:
    for i in range(len(permutationArray)):
        permutationDec[i] = permutationArray[i] - 1

    #Check if there are enough values:
    if (max(permutationDec) >= (len(bytearr)*8)):
        raise Exception("DES Permutation, but too few indexes in binary array.")

    #Iterate over every bit
    for i in range(len(outputByteArray)*8):
        #Permutation value:
        permuteValue = permutationDec[i]
        byteIndex = permuteValue // 8
        bitIndex = permuteValue % 8

        #If the bit at the permutation index is set, set the permuted bit in the output
        #Check bit value at the permutation position
        bSet = bytearr[byteIndex] & (0x01 << (7-bitIndex))

        #Since the output byte array is already all zeros, only set bit if need be
        if (bSet):
            outputByteArray[i//8] = outputByteArray[i//8] | (0x01 << (7-(i%8)))

    return outputByteArray

def keyGeneration(originalKey, permutationInitial, permutationRound):
    #Do the inital permutation on the original key:
    permutedKey = permutation(originalKey, permutationInitial)

    #Calculate the subkeys:

    oneBitShifts = [1, 2, 9, 16]
    subKeys = []
    statusKey = permutedKey

    for keyNum in range(16):
        if (keyNum+1) in oneBitShifts:
            numshifts = 1
        else:
            numshifts = 2

        #The key left shift function works by performing a circular left shift on each half of the key seperately:
        statusKey = shiftKeyHalvesLeft(statusKey, numshifts)

        #Perform a permutation on the statusKey to get the next subkey:
        subKeys.append(permutation(statusKey, permutationRound))

    return subKeys





#This function performs a circular left shift on the input bytearray
def shiftLeft(bytearr, numshifts):
    output = bytearray(len(bytearr))

    #Do one shifts for the number of shifts:
    for shiftnum in range(numshifts):
        for i in range(len(bytearr)-1,-1,-1):
            #Shift each byte in bytearray one position left
                                    # 0111 111 -> to ensure there is no bit higher than MSB
            output[i] = (bytearr[i] & 0x7F) << 1

            #Fetch the bit that should be shifted in to the LSB position (circular)
            if i == len(bytearr) - 1:
                insertbit = bytearr[0] & (0x01 << 7)
            else:
                insertbit = bytearr[i+1] & (0x01 << 7)

            #Insert the bit into the LSB position
            if insertbit > 0:           #0000 0001
                output[i] = output[i] | (0x01)
            else:                       #1111 1110
                output[i] = output[i] & (0xFE)

    return output

#This function performs a circular left shift on each half of the key
#The function requires a 56 bit (7 byte) input bytearray
def shiftKeyHalvesLeft(keyInput, numshifts):
    key = copy.deepcopy(keyInput)

    for numberofshifts in range(numshifts):

        output = bytearray(7)

        #Perform the circular left shift on the left half of the key:
        leftMSB = key[0] & (0x01 << 7)
        rightMSB = key[3] & (0x01 << 3)

        #Shift all bytes one bit position left, the most significant bits in each half will be corrected later
        for i in range(7):
            #Shift each byte in bytearray one position left
                                #0111 111 -> to ensure there is no bit higher than MSB
            output[i] = (key[i] & 0x7F) << 1

            #Fetch the bit that should be shifted in to the LSB position (circular)
            insertbit = 0x00
            if i < 6:       #The last byte is left as is
                insertbit = key[i+1] & (0x01 << 7)

            #Insert the bit into the LSB position
            if insertbit > 0:           #0000 0001
                output[i] = output[i] | (0x01)
            else:                       #1111 1110
                output[i] = output[i] & (0xFE)

        #Correct the MSB in each half:
        #The left MSB should be in position 4 in the middle byte (after a left shift)
        if (leftMSB):
            output[3] = output[3] | (0x01 << 4)
        else:                       #1110 1111
            output[3] = output[3] & (0xEF)

        if (rightMSB):              #0000 00001
            output[6] = output[6] | (0x01)
        else:                       #1111 1110
            output[6] = output[6] & (0xFE)

        key = copy.deepcopy(output)

    return key



##### TESTING CODE ######

# string = "Hello, hoe gaan dit vandag?"
#
# bytearr = np.empty(len(string),dtype=np.byte)
# for i in range(len(string)):
#     bytearr[i] = ord(string[i])
#
# bytearr[0] &= 0xFF
# print(bytearr)
#
# toets = 0
#
# stringEncoded = string.encode(encoding="ascii",errors="ignore")
# #print(stringEncoded)
# stringEncoded = bytearray(stringEncoded)
# stringEncoded[0] = stringEncoded[0]^255
# #print(stringEncoded)
#
# TDEA_Encrypt("Cat")
#
# permutationL = np.load("Practical 2 File Package/DES_Initial_Permutation.npy")
# permutationL = np.array(permutationL, dtype=int)
# print(permutationL)
#
# bytearr = bytearray("d",encoding="ascii")
# print(bytearr)
#
# print(permutation(bytearr, [3,4,7,6,5,2,8,1]))
#
# permutationChoice1 = np.load("Practical 2 File Package/DES_Permutation_Choice1.npy")
# print(permutationChoice1)
# print(len(permutationChoice1))
#
# bytearr = bytearray("de", encoding="ascii")
# print(shiftLeft(bytearray("hi", encoding="ascii"), 1))
# print("Hi")
#
# toets = bytearray(5)
# toets[1] = 5
# print(toets)


#Toets die key generation:

initKey = bytearray([0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1])
permuteKey = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
permuteRound = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

print(keyGeneration(initKey,permuteKey,permuteRound))

# testkey = bytearray([0xF0,0xCC,0xAA,0xF5,0x56,0x67,0x8F])
# print(shiftKeyHalvesLeft(testkey,1))



