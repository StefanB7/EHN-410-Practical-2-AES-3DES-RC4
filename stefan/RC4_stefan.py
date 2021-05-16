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


    # If the plaintext is an image (ndarray) that needs to be encrypted:
    if (isinstance(plaintext, np.ndarray)):

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

        #Variables used in the stream cipher should persist over different layer encryption:
        i = 0
        j = 0

        for layer in range(numLayers):

            #Create an input plaintext bytearray for the current layer:
            index = 0
            plaintextBytes = bytearray(numRows*numColumns)
            cipherTextBytes = bytearray(numRows*numColumns)

            for i in range(numRows):
                for j in range(numColumns):
                    plaintextBytes[index] = plaintext[i][j][layer]
                    index += 1

            #Encrypt the plaintext:
            for index in range(len(plaintextBytes)):
                # Generate the next stream element:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                temp = S[i]
                S[i] = S[j]
                S[j] = temp

                streamElementIndex = (S[i] + S[j]) % 256
                streamElement = S[streamElementIndex]

                cipherTextBytes[index] = plaintextBytes[index] ^ streamElement

            #Transfer the calculated output to the ciphertext image ndarray variable:
            index = 0
            for i in range(numRows):
                for j in range(numColumns):
                    cipherText[i][j][layer] = cipherTextBytes[index]
                    index += 1

        if bAlphaLayer:
            cipherText = np.dstack((cipherText, alpha_layer))

        return cipherText.astype(int)


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



    # If the plaintext is an image (ndarray) that needs to be encrypted:
    if (isinstance(ciphertext, np.ndarray)):

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
        plainText = np.zeros((numRows, numColumns, numLayers), dtype='u1')

        # Variables used in the stream cipher should persist over different layer encryption:
        i = 0
        j = 0

        for layer in range(numLayers):

            # Create an input plaintext bytearray for the current layer:
            index = 0
            cipherTextBytes = bytearray(numRows * numColumns)
            plainTextBytes = bytearray(numRows * numColumns)

            for i in range(numRows):
                for j in range(numColumns):
                    cipherTextBytes[index] = ciphertext[i][j][layer]
                    index += 1

            # Encrypt the plaintext:
            for index in range(len(cipherTextBytes)):
                # Generate the next stream element:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                temp = S[i]
                S[i] = S[j]
                S[j] = temp

                streamElementIndex = (S[i] + S[j]) % 256
                streamElement = S[streamElementIndex]

                plainTextBytes[index] = cipherTextBytes[index] ^ streamElement

            # Transfer the calculated output to the ciphertext image ndarray variable:
            index = 0
            for i in range(numRows):
                for j in range(numColumns):
                    plainText[i][j][layer] = plainTextBytes[index]
                    index += 1

        if bAlphaLayer:
            cipherText = np.dstack((plainText, alpha_layer))

        return plainText.astype(int)

encrypted = RC4_Enctrypt("Hello, hoe gaan dit met jou?", "stefan")
print(encrypted)
decrypted = RC4_Decrypt(encrypted,"stefan")
print(decrypted)

#Test Image:
p_File = Image.open('office.png')
p_img = np.asarray(p_File)
imgENC = RC4_Enctrypt(p_img, "stefan")

Image.fromarray(imgENC.astype(np.uint8)).save('office_encrypted_rc4.png')

print("Image Encryption Done")

p_File = Image.open('office_encrypted_rc4.png')
p_img = np.asarray(p_File)
imgENC = RC4_Decrypt(p_img, "stefan")

Image.fromarray(imgENC.astype(np.uint8)).save('office_decrypted_rc4.png')

toets = bytearray(5)
toets2 = bytearray(1)
toets[2] = 139
toets2[0] = toets[2]
print(toets2.hex())