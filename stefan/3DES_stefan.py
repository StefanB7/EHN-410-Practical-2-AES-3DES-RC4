# EHN 410 - Practical 2 - 2021
# 3DES encryption and decryption
# Group 7
# Created: 2 May 2021 by Stefan Buys

import numpy as np
import copy

from PIL import Image
from numpy import asarray

##### STATIC VARIABLES #####

keyInitialPermutationLocation = "Practical 2 File Package/DES_Permutation_Choice1.npy"
keyRoundPermutationLocation = "Practical 2 File Package/DES_Permutation_Choice2.npy"

##### MAIN CIPHER FUNCTIONS #####

def TDEA_Encrypt(plaintext, inspect_mode = 0, key1 = 'abcdefgh', key2 = 'abcdefgh', key3 = 'abcdefgh', ip = [0]):
    print("3DES Encryption")

    # Calculate the inverse of the initial permutation:
    inv_ip = np.zeros(len(ip))
    for i in range(1, len(ip) + 1):
        # Find index i in the initial permutation:
        inv_ip[i - 1] = ip.index(i) + 1

    ### Plaintext Encoding ###

    # If the plaintext is a string to be encrypted:
    if (isinstance(plaintext, str)):
        # Convert the plaintext string to its bit representation
        #plaintextEncoded = plaintext.encode(encoding="ascii",errors="ignore")
        # plaintextEncoded = bytearray(plaintextEncoded)
        plaintextEncoded = chartobyte(plaintext)

        #Pad the plaintext such that the total number of bytes is an integral multiple of 64 (for DES)
        plaintextEncoded = pad(plaintextEncoded, 8)

        #Divide the encoded plaintext into blocks of 64 bits each, to be encoded:
        plaintextBlocks = [bytearray(1)]*(len(plaintextEncoded)//8)
        for i in range(len(plaintextEncoded)//8):
            plaintextBlocks[i] = plaintextEncoded[i*8:(i+1)*8]

        #Permutation arrays used for key generation:
        keyInitialPermutation = np.load(keyInitialPermutationLocation)
        keyRoundPermutation = np.load(keyRoundPermutationLocation)

        status = [bytearray(1)]*(len(plaintextEncoded)//8)

        # ============================================
        #First triple DES round, encryption with key1:

        #Generate the subkeys:
        key1bytes = chartobyte(key1)
        subkeys = keyGeneration(key1bytes, keyInitialPermutation, keyRoundPermutation)

        #Perform first DES encryption on all blocks of 64 bits:
        for index in range(len(plaintextBlocks)):
            status[index], roundOutputEncryption1 = DES_Encryption(plaintextBlocks[index], subkeys, ip, inv_ip, inspect_mode)



        #Second triple DES round, decryption with key2:

        #Generate the subkeys:
        key2bytes = chartobyte(key2)
        subkeys = keyGeneration(key2bytes, keyInitialPermutation, keyRoundPermutation)

        #The subkeys should be swapped for decryption:
        subKeyTemp = copy.deepcopy(subkeys)
        subkeys = []
        for i in range(len(subKeyTemp)-1,-1,-1):
           subkeys.append(subKeyTemp[i])

        for index in range(len(status)):
            status[index], roundOutputDecryption = DES_Decryption(status[index], subkeys, ip, inv_ip, inspect_mode)


        #Third and final triple DES round, encryption with key3:

        #Generate the subkeys:
        key3bytes = chartobyte(key3)
        subkeys = keyGeneration(key3bytes, keyInitialPermutation, keyRoundPermutation)

        #Perform final DES encryption on all blocks of 64 bits:
        for index in range(len(status)):
            status[index], roundOutputEncryption2 = DES_Encryption(status[index], subkeys, ip, inv_ip, inspect_mode)

        print(status)

        ciphertextOutput = ""
        #Convert to and return chars
        for blockIndex in range(len(status)):
            for charIndex in range(8):
                ciphertextOutput = ciphertextOutput + chr(status[blockIndex][charIndex])

        return ciphertextOutput

    # If the plaintext is an image (ndarray) that needs to be encrypted:
    if (isinstance(plaintext, np.ndarray)):

        plaintextCopy = plaintext.copy()

        # Check the plaintext's dimentions:
        numRows = plaintext.shape[0]
        numColumns = plaintext.shape[1]
        numLayers = plaintext.shape[2]

        # Test if there is an AlphaLayer:
        bAlphaLayer = False
        if (numLayers > 3):
            bAlphaLayer = True
            numLayers = 3
            alpha_layer = np.array(plaintext[:, :, 3])

        # Ciphertext variable:
        cipherText = np.zeros((numRows, numColumns, numLayers), dtype='u1')

        for layer in range(numLayers):

            #Create a 1D bytearray of the 2D image:
            inputbytearray = [None]*(numRows*numColumns//8)
            for i in range((numRows*numColumns//8)):
                inputbytearray[i] = bytearray(8)

            index = 0
            indexIntoBytearray = 0
            maxElements = (numRows*numColumns//8)
            for row in range(numRows):
                for column in range(numColumns):
                    if (index < maxElements):
                        inputbytearray[index][indexIntoBytearray] = plaintextCopy[row][column][layer]
                        indexIntoBytearray += 1
                        if (indexIntoBytearray >= 8):
                            index += 1
                            indexIntoBytearray = 0

            # Permutation arrays used for key generation:
            keyInitialPermutation = np.load(keyInitialPermutationLocation)
            keyRoundPermutation = np.load(keyRoundPermutationLocation)

            status = [None] * (numRows * numColumns // 8)
            for i in range((numRows * numColumns // 8)):
                status[i] = bytearray(8)

            # ============================================
            # First triple DES round, encryption with key1:

            # Generate the subkeys:
            key1bytes = chartobyte(key1)
            subkeys = keyGeneration(key1bytes, keyInitialPermutation, keyRoundPermutation)

            # Perform first DES encryption on all blocks of 64 bits:
            for index in range(len(inputbytearray)):
                status[index], roundOutputEncryption1 = DES_Encryption(inputbytearray[index], subkeys, ip, inv_ip, inspect_mode)


            # Second triple DES round, decryption with key2:

            # Generate the subkeys:
            key2bytes = chartobyte(key2)
            subkeys = keyGeneration(key2bytes, keyInitialPermutation, keyRoundPermutation)

            # The subkeys should be swapped for decryption:
            subKeyTemp = copy.deepcopy(subkeys)
            subkeys = []
            for i in range(len(subKeyTemp) - 1, -1, -1):
                subkeys.append(subKeyTemp[i])

            for index in range(len(status)):
                status[index], roundOutputDecryption = DES_Decryption(status[index], subkeys, ip, inv_ip, inspect_mode)

            #Third and final triple DES round, encryption with key3:

            #Generate the subkeys:
            key3bytes = chartobyte(key3)
            subkeys = keyGeneration(key3bytes, keyInitialPermutation, keyRoundPermutation)

            #Perform final DES encryption on all blocks of 64 bits:
            for index in range(len(status)):
                status[index], roundOutputEncryption2 = DES_Encryption(status[index], subkeys, ip, inv_ip, inspect_mode)

            index = 0
            indexIntoBytearray = 0
            maxElements = (numRows*numColumns//8)
            for row in range(numRows):
                for column in range(numColumns):
                    if (index < maxElements):
                        cipherText[row][column][layer] = status[index][indexIntoBytearray]
                        indexIntoBytearray += 1
                        if (indexIntoBytearray >= 8):
                            index += 1
                            indexIntoBytearray = 0

        if bAlphaLayer:
            cipherText = np.dstack((cipherText, alpha_layer))

        return cipherText.astype(int)


def TDEA_Decrypt(inspect_mode, ciphertext, key1, key2, key3, ip):
    print("3DES Decryption")

    # Calculate the inverse of the initial permutation:
    inv_ip = np.zeros(len(ip))
    for i in range(1, len(ip) + 1):
        # Find index i in the initial permutation:
        inv_ip[i - 1] = ip.index(i) + 1

    ### Plaintext Encoding ###

    # If the plaintext is a string to be encrypted:
    if (isinstance(ciphertext, str)):
        # Convert the ciphertext string to its bit representation
        #ciphertextEncoded = plaintext.encode(encoding="ascii",errors="ignore")
        # ciphertextEncoded = bytearray(ciphertextEncoded)
        ciphertextEncoded = chartobyte(ciphertext)

        #Pad the ciphertext such that the total number of bytes is an integral multiple of 64 (for DES)
        ciphertextEncoded = pad(ciphertextEncoded, 8)

        #Divide the encoded ciphertext into blocks of 64 bits each, to be encoded:
        ciphertextBlocks = [bytearray(1)]*(len(ciphertextEncoded)//8)
        for i in range(len(ciphertextEncoded)//8):
            ciphertextBlocks[i] = ciphertextEncoded[i*8:(i+1)*8]

        #Permutation arrays used for key generation:
        keyInitialPermutation = np.load(keyInitialPermutationLocation)
        keyRoundPermutation = np.load(keyRoundPermutationLocation)

        status = [bytearray(1)]*(len(ciphertextEncoded)//8)

        # ============================================
        #First triple DES round, decryption with key1:

        #Generate the subkeys:
        key3bytes = chartobyte(key3)
        subkeys = keyGeneration(key3bytes, keyInitialPermutation, keyRoundPermutation)

        #The subkeys should be swapped for decryption:
        subKeyTemp = copy.deepcopy(subkeys)
        subkeys = []
        for i in range(len(subKeyTemp)-1,-1,-1):
           subkeys.append(subKeyTemp[i])

        #Perform first DES encryption on all blocks of 64 bits:
        for index in range(len(ciphertextBlocks)):
            status[index], roundOutputDecryption1 = DES_Decryption(ciphertextBlocks[index], subkeys, ip, inv_ip, inspect_mode)


        #Second triple DES round, encryption with key2:

        #Generate the subkeys:
        key2bytes = chartobyte(key2)
        subkeys = keyGeneration(key2bytes, keyInitialPermutation, keyRoundPermutation)

        for index in range(len(status)):
            status[index], roundOutputEncryption = DES_Encryption(status[index], subkeys, ip, inv_ip, inspect_mode)


        #Third and final triple DES round, encryption with key3:

        #Generate the subkeys:
        key1bytes = chartobyte(key1)
        subkeys = keyGeneration(key1bytes, keyInitialPermutation, keyRoundPermutation)

        #The subkeys should be swapped for decryption:
        subKeyTemp = copy.deepcopy(subkeys)
        subkeys = []
        for i in range(len(subKeyTemp)-1,-1,-1):
           subkeys.append(subKeyTemp[i])

        #Perform final DES encryption on all blocks of 64 bits:
        for index in range(len(status)):
            status[index], roundOutputDecryption2 = DES_Encryption(status[index], subkeys, ip, inv_ip, inspect_mode)

        print(status)

        plaintextOutput = ""
        #Convert to and return chars
        for blockIndex in range(len(status)):
            for charIndex in range(8):
                plaintextOutput = plaintextOutput + chr(status[blockIndex][charIndex])

        return plaintextOutput

    # If the ciphertext is an image (ndarray) that needs to be encrypted:
    if (isinstance(ciphertext, np.ndarray)):

        ciphertextCopy = ciphertext.copy()

        # Check the plaintext's dimentions:
        numRows = ciphertext.shape[0]
        numColumns = ciphertext.shape[1]
        numLayers = ciphertext.shape[2]

        # Test if there is an AlphaLayer:
        bAlphaLayer = False
        if (numLayers > 3):
            bAlphaLayer = True
            numLayers = 3
            alpha_layer = np.array(ciphertext[:, :, 3])

        # Ciphertext variable:
        plaintext = np.zeros((numRows, numColumns, numLayers), dtype='u1')

        for layer in range(numLayers):

            # Create a 1D bytearray of the 2D image:
            inputbytearray = [None] * (numRows * numColumns // 8)
            for i in range((numRows * numColumns // 8)):
                inputbytearray[i] = bytearray(8)

            index = 0
            indexIntoBytearray = 0
            maxElements = (numRows * numColumns // 8)
            for row in range(numRows):
                for column in range(numColumns):
                    if (index < maxElements):
                        inputbytearray[index][indexIntoBytearray] = ciphertextCopy[row][column][layer]
                        indexIntoBytearray += 1
                        if (indexIntoBytearray >= 8):
                            index += 1
                            indexIntoBytearray = 0

            # Permutation arrays used for key generation:
            keyInitialPermutation = np.load(keyInitialPermutationLocation)
            keyRoundPermutation = np.load(keyRoundPermutationLocation)

            status = [None] * (numRows * numColumns // 8)
            for i in range((numRows * numColumns // 8)):
                status[i] = bytearray(8)

            # ============================================
            # First triple DES round, decryption with key1:

            # Generate the subkeys:
            key3bytes = chartobyte(key3)
            subkeys = keyGeneration(key3bytes, keyInitialPermutation, keyRoundPermutation)

            # The subkeys should be swapped for decryption:
            subKeyTemp = copy.deepcopy(subkeys)
            subkeys = []
            for i in range(len(subKeyTemp) - 1, -1, -1):
                subkeys.append(subKeyTemp[i])

            # Perform first DES encryption on all blocks of 64 bits:
            for index in range(len(inputbytearray)):
                status[index], roundOutputDecryption1 = DES_Decryption(inputbytearray[index], subkeys, ip, inv_ip, inspect_mode)

            # Second triple DES round, encryption with key2:

            # Generate the subkeys:
            key2bytes = chartobyte(key2)
            subkeys = keyGeneration(key2bytes, keyInitialPermutation, keyRoundPermutation)

            for index in range(len(status)):
                status[index], roundOutputEncryption = DES_Encryption(status[index], subkeys, ip, inv_ip, inspect_mode)

            # Third and final triple DES round, encryption with key3:

            # Generate the subkeys:
            key1bytes = chartobyte(key1)
            subkeys = keyGeneration(key1bytes, keyInitialPermutation, keyRoundPermutation)

            # The subkeys should be swapped for decryption:
            subKeyTemp = copy.deepcopy(subkeys)
            subkeys = []
            for i in range(len(subKeyTemp) - 1, -1, -1):
                subkeys.append(subKeyTemp[i])

            # Perform final DES encryption on all blocks of 64 bits:
            for index in range(len(status)):
                status[index], roundOutputDecryption2 = DES_Encryption(status[index], subkeys, ip, inv_ip, inspect_mode)

            index = 0
            indexIntoBytearray = 0
            maxElements = (numRows * numColumns // 8)
            for row in range(numRows):
                for column in range(numColumns):
                    if (index < maxElements):
                        plaintext[row][column][layer] = status[index][indexIntoBytearray]
                        indexIntoBytearray += 1
                        if (indexIntoBytearray >= 8):
                            index += 1
                            indexIntoBytearray = 0

        if bAlphaLayer:
            cipherText = np.dstack((plaintext, alpha_layer))

        return plaintext.astype(int)


###### HELPER FUNCTIONS #####

#Function pads the input bytearray, so that its length will divide the integral_number provided
#Pads the bytearray so that the last group of integral_number is full
#Default padding = 0x00
def pad(bytearr, integral_number = 8, padding = 0x00):
    bytearrayOutput = copy.deepcopy(bytearr)

    #If no padding is needed, return:
    if len(bytearrayOutput) % integral_number == 0:
        return bytearrayOutput

    numShort = integral_number - (len(bytearr) % integral_number)
    for i in range(numShort):
        bytearrayOutput.append(padding)
    return bytearrayOutput

#This functions performs normal DES encryption:
def DES_Encryption(plaintext, subkeys,  ip = [0], inv_ip = [0], inspect_mode = 0):
    status = copy.deepcopy(plaintext)

    #Do the initial permutation
    status = permutation(status, ip)

    roundOutputs = []

    #Iterate over 16 rounds:
    for round in range(16):
        ciphertextLHS = status[0:4]
        ciphertextRHS = status[4:8]

        expansionPermutationArray = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
        ciphertextRHSexpanded = permutation(ciphertextRHS, expansionPermutationArray)

        newciphertextLHS = ciphertextRHS

        newciphertextRHS = F(ciphertextRHSexpanded, subkeys[round])
        for i in range(len(newciphertextRHS)):
            newciphertextRHS[i] = newciphertextRHS[i] ^ ciphertextLHS[i]

        status = newciphertextLHS + newciphertextRHS

        if inspect_mode:
            roundOutputs.append(status)

    #Perform a 32 bit swap on the output:
    status = status[4:8] + status[0:4]

    #The swapped status is the output of the 16th round
    if inspect_mode:
        roundOutputs[15] = status

    #Perform the inverse of the initial permutation:
    status = permutation(status, inv_ip)

    return status, roundOutputs


#This function performs DES decryption:
def DES_Decryption(ciphertext, subkeysIn, ip = [0], inv_ip = [0], inspect_mode = 0, subkeysAlreadyFlipped = True):
    if not(subkeysAlreadyFlipped):
        subkeys = copy.deepcopy(subkeysIn)
        #The subkeys should be swapped for decryption:
        subKeyTemp = copy.deepcopy(subkeys)
        subkeys = []
        for i in range(len(subKeyTemp)-1,-1,-1):
           subkeys.append(subKeyTemp[i])
    else:
        subkeys = subkeysIn


    #The DES Decryption is identical to DES encryption with the keys swapped
    return DES_Encryption(ciphertext, subkeys, ip, inv_ip, inspect_mode)



#Define S-Boxes:
S = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

#THE F function:
def F(RHS, subkey):
    answer = copy.deepcopy(RHS)
    output = bytearray(4)

    #Do a bitwise XOR of the RHS with the subkey:
    for i in range(len(answer)):
        answer[i] = answer[i] ^ subkey[i]

    #Iterate over all 8, 6-bit groups in the 48 bit results:
    for group in range(8):
        #Get the row index into the S table:
        rowIndex = 0x00
        bitIndexFirst = group*6
        #Check if first bit is set
        if answer[bitIndexFirst//8] & (0x01 << (7-(bitIndexFirst % 8))):
            rowIndex = rowIndex | 0x02
        if answer[(bitIndexFirst+5)//8] & (0x01 << (7-((bitIndexFirst+5) % 8))):
            rowIndex = rowIndex | 0x01

        #Get the column index into the S table:
        columnIndex = 0x00
        for i in range(4):
            if answer[(bitIndexFirst + (i+1)) // 8] & (0x01 << (7 - ((bitIndexFirst + (i+1)) % 8))):
                columnIndex = columnIndex | (0x01 << (3-i))

        if group % 2 == 0:
            output[group//2] = S[group][rowIndex][columnIndex] << 4
        else:
            output[group//2] = output[group//2] | S[group][rowIndex][columnIndex]

    #Perform the final P permutation on the S-box outputs
    finalPermutation = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
    output = permutation(output, finalPermutation)

    return output


#This helper function performs permutation on the bitarray according to the positions specified by
#an permutation array, that contains the locations where bits should be allocated in the permutated array
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

#This function translates a character array into a byte array:
def chartobyte(chararray):
    output = bytearray(len(chararray))

    for i in range(len(chararray)):
        if ord(chararray[i]) < 256:
            output[i] = ord(chararray[i])

    return output



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
#initKey = "4Wy¼ßñ"
permuteKey = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
permuteRound = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

# # Calculate the inverse of the initial permutation:
# inv_ip = np.zeros(len(IP))
# for i in range(1,len(IP)+1):
#     # Find index i in the initial permutation:
#     inv_ip[i-1] = IP.index(i) + 1
#
# print(IP)
# print(inv_ip)


print(keyGeneration(initKey,permuteKey,permuteRound))

# testkey = bytearray([0xF0,0xCC,0xAA,0xF5,0x56,0x67,0x8F])
# print(shiftKeyHalvesLeft(testkey,1))

subkeys = keyGeneration(initKey,permuteKey,permuteRound)

IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

inv_ip = np.zeros(len(IP))
for i in range(1,len(IP)+1):
    # Find index i in the initial permutation:
    inv_ip[i-1] = IP.index(i) + 1

print(IP)
print(inv_ip)

plaintext = bytearray([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF])

ciphertext, roundstuff = DES_Encryption(plaintext,subkeys,IP,inv_ip, 0)

plaintextDecrypted, roundstuff = DES_Decryption(ciphertext, subkeys, IP, inv_ip, 0, False)

print(ciphertext)
print(plaintextDecrypted)





#
#
# RHS = bytearray([0x7A,0x15,0x55,0x7A,0x15,0x55])
# #print(F(RHS,subkeys[0]))
#
# toetsalweer = [bytearray(1)]*5
# print(toetsalweer)
#
# print(list(np.load("Practical 2 File Package/DES_Permutation_Choice2.npy")))
# print(len(list(np.load("Practical 2 File Package/DES_Permutation_Choice2.npy"))))


print("\nHoof encrypt results:")

tdeaCiphertext = TDEA_Encrypt("HelloMan123345Hoe gaan dit?", 0, "abcdefgh", "abcdkfgh", "abxdefgh", IP)

tdeaPlaintextDecrypt = TDEA_Decrypt(0, tdeaCiphertext, "abcdefgh", "abcdkfgh", "abxdefgh", IP)

print(tdeaCiphertext)
print(tdeaPlaintextDecrypt)


#Test Image:
p_File = Image.open('office.png')
p_img = np.asarray(p_File)
imgENC = TDEA_Encrypt(p_img, 0, "abcdefgh", "abcdkfgh", "abxdefgh", IP)

Image.fromarray(imgENC.astype(np.uint8)).save('office_encrypted.png')

print("Image Encryption Done")

p_File = Image.open('office_encrypted.png')
p_img = np.asarray(p_File)
imgENC = TDEA_Decrypt(0, p_img, "abcdefgh", "abcdkfgh", "abxdefgh", IP)

Image.fromarray(imgENC.astype(np.uint8)).save('office_decrypted.png')