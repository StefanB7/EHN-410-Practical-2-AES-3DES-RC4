# EHN 410 - Practical 2 - 2021
# AES-256 (32 byte key) encryption and decryption (128 bit block size)
# Group 7

import numpy as np
 
############################ Main functions: ############################

def AES_Encrypt(inspect_mode, plaintext, iv, key, sbox_array):

    bits_key = getBitsandPad(key, True)

    # Generate random Initialization Vector if none is provided
    if iv == None or len(iv) == 0:
        InitVec = [1,2,3,4,5] # TODO: die moet random wees en iets nog

    # plaintext encryption
    if type(plaintext) is not np.ndarray:

        plain_bits = getBitsandPad(plaintext)

        prev_block = InitVec # of wat ookal hy later g
        while len(plain_bits) != 0:
            
            bits_block = plain_bits[:128]
            plain_bits = plain_bits[128:]

            ## Round 0:
            # XOR input block with Initialization Vector
            bits_block = XOR(bits_block, prev_block)
            
            # Key expansion

            # Add round key
            print('S')

            ## Round 1 to 13:
            for round in range(13):
                # Key expansion

                # SubBytes
                print("s")
                # ShiftRows

                # MixColumns

                # AddRoundKey


            ## Round 14 (final):
            # Key expansion

            # SubBytes

            # ShiftRows

            # MixColumns

            # AddRoundKey
            
            prev_block = bits_block




        # 128 bit blocks, pad if necessary, XOR input block met vorige cipher text, (aan die begin gebruik die intialization vector)

        # Since 256-bit encryption (32 byte key) -> 14 rounds 

        # output of each round is 4x4 matrix of bytes 

        # key expanded into 60 32-bit words, 128 bits used for round keys

        # Encryption:

            # 0 round: AddRoundKey

            # first 13 (N-1) rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey

            # final (14) round: SubBytes, ShiftRows, AddRoundKey

        

    # image encryption
    else:
        print("S")


        # input text or image to bits

        # 128 bit blocks, pad if necessary, XOR input block met vorige cipher text, (aan die begin gebruik die intialization vector)

        # Since 256-bit encryption (32 byte key) -> 14 rounds 

        # output of each round is 4x4 matrix of bytes 

        # key expanded into 60 32-bit words, 128 bits used for round keys

        # Encryption:

            # 0 round: AddRoundKey

            # first 13 (N-1) rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey

            # final (14) round: SubBytes, ShiftRows, AddRoundKey





def AES_Decrypt(inspect_mode, ciphertext, iv, key, inv_sbox_array):
    print("AES decryption")




    # plaintext decryption
    if type(ciphertext) is not np.ndarray:
        print("s")



    # image decryption
    else:
        print("S")





    # Decryption:

    #     0 round: AddRoundKey

    #     first 13 (N-1) rounds: Inv ShiftRows, Inv SubBytes, AddRoundKey, Inv MixColumns

    #     final (14) round: Inv ShiftRows, Inv SubBytes, AddRoundKey

    #     XOR output met die IV aan die begin, die volgende output word ge XOR met die vorige encrypted (ciphertext) blok




############################ Helper functions: ###########################

###### Encryption helper functions:

# Substistitute bytes based using a given s-box lookup table
def SubBytes():
    print("d")

    # matrix output generated with stage mapped to s-box value
    # 4 left bits indicate the row of s-box
    # 4 right bits indicate the column of s-box

    # moet ons ons eie s-boxes maak?

# Shift the rows of the stage matrix
def ShiftRows():
    print("d")


# Mix the columns of the stage matrix
def MixColumns():
    print("d")

    # onthou dit gebeur in die GF(2^8) space
    # maal is equation 4.14
    # plus is bitwise XOR


###### Decryption helper functions:

# Inverse of the substitution byte stage
def inv_SubBytes():
    print("d")
    # same as subbytes, just use the inverse s-box

# Inverse of the row shift stage
def inv_ShiftRows():
    print("d")

# Inverse of the column mix stage
def inv_MixColumns():
    print("d")


###### General helper functions:

# Add the key (XOR) for that round to the stage matrix
def AddRoundKey():
    print("d")

# Expand the key for each round
def keyExpansion():
    print("d")

# Bitwise XOR
def XOR(arg1, arg2): #arg1 arg2 en dalk nog een vir die IV doen random IV dalk ook hier? 
    print("D")

# Return bit representation of ASCII characters and pad bits to be a multiple of 128
def getBitsandPad(arg, key=False):
    bits = None
    try:
        bits = np.array(bytearray(arg.encode(encoding="ascii")),dtype=np.byte)
    except:
        raise Exception("\n\nERROR: Key or Plaintext must be ASCII, encryption / decryption will not execute.\n")

    # pad bits if necessary
    # key, key will be concatenated if larger than 256 bits
    if key == True:
        if len(bits) != 256*(len(bits)//256):
            bits = np.concatenate((bits, np.zeros(256, dtype=np.byte)),axis=None)
            bits = bits[:256]

    # plaintext or image
    else:
        if len(bits) != 128*(len(bits)//128):
            bits = np.concatenate((bits, np.zeros(128, dtype=np.byte)),axis=None)
            bits = bits[:128*((len(bits)-128)//128)+128]

    return bits

print(getBitsandPad("ABCDE", True))
#getBitsandPad("AB é")








#TODO: maak images groter sodat hlle in 128 bits pas en ook actually n image maak

# verduidelik in report hkm rijndael cool is want input bits is nie baie dieselfde as output bits nie kan dit vergelyk dalk met ander s-boxes,
#  en nie linear nie, check verwysing op bladsy 185

# byte = int('11111111', 2)

# s = "haai"

#print(bytearray(s.encode(encoding="ascii",errors="ignore"))[1])




### test AES

#encrypted_text = AES_Encrypt(False,"die is nie n lang sin nie",None,"Die is verkeerd",None)
