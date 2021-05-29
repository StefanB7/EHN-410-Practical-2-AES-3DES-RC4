# Stefan Buys (u18043098), Jacobus Oettle (u18000135) - University of Pretoria
# EHN 410 - 2021

from PIL import Image
import numpy as np
import importlib

TDES_Module = importlib.import_module("3DES")

txtENC = ""
txtDEC = ""

imgENC = None
imgDEC = None

IP_File = "Practical 2 File Package/DES_Initial_Permutation.npy"
INV_IP_File = "Practical 2 File Package/DES_Inverse_Initial_Permutation.npy"

IP= np.load(IP_File)
INV_IP = np.load(INV_IP_File)

IP = IP.tolist()
INV_IP = INV_IP.tolist()

#
# def toHex(inputString):
#     bytearr = bytearray(len(inputString))
#
#     for i in range(len(inputString)):
#         bytearr[i] = ord(inputString[i])
#
#     stringout = ""
#
#     for i in range(len(bytearr)):
#         singleByte = bytearray(1)
#         singleByte[0] = bytearr[i]
#         stringout = stringout + singleByte.hex().upper()
#
#     return stringout
#
#
# def toBytearray(string):
#     bytearr = bytearray(len(string))
#
#     for i in range(len(string)):
#         bytearr[i] = ord(string[i])
#
#     return bytearr
#
#
# def countsame(firstbytes, secondbytes):
#     byteIndex = 0
#     bitIndex = 0
#
#     numTheSame = 0
#
#     for byteIndex in range(len(firstbytes)):
#         for bitIndex in range(8):
#             first = firstbytes[byteIndex] & (0x01 << bitIndex)
#             second = secondbytes[byteIndex] & (0x01 << bitIndex)
#
#             if (second > 0) and (first > 0):
#                 numTheSame += 1
#             elif (second == 0) and (first == 0):
#                 numTheSame += 1
#
#     return numTheSame
#
if __name__ == "__main__":
#
    # One character of plaintext:
    print("\n____________________________________________________")
    print("\nTest (1/6): One character of plaintext (without inspect_mode):")
    print("\nInput:")
    print("Plaintext: a")
    print("Keys:")
    print("k1: stefanab")
    print("k2: jacobusa")
    print("k3: encrypti")
    print("\nOutput:")
    txtENC = TDES_Module.TDEA_Encrypt(False, "The quick brown fox jumps over the lazy dog!!!!!", 'stefanab', 'jacobusa', 'encrypti', IP)
    print("Encrypted text: ",txtENC)
    txtDEC = TDES_Module.TDEA_Decrypt(False, txtENC, 'stefanab', 'jacobusa', 'encrypti', INV_IP)
    print("Decrypted text: ",txtDEC)

    txtENC = "The quick brown fox fumps over the lazy dog!!!!!"

    values = []
    for i in range(len(txtENC)):
        values.append(ord(txtENC[i]))

    print(values)






#
#
#
#
#
#     Plaintext = "The quick brown fox jumps over the lazy dog!!!!!"
#
#
#
#     print(countsame(toBytearray(Plaintext), toBytearray(txtENC)))
#
#     txtENC2 = TDES_Module.TDEA_Encrypt(False, 'The quick krown fox jumps over the lazy dog!!!!!', 'stefanab', 'jacobusa', 'encrypti', IP)
#
#     txtDEC2 = TDES_Module.TDEA_Decrypt(False, txtENC2, 'stefanab', 'jacobusa', 'encrypti', INV_IP)
#
#     print(txtENC)
#     print(txtENC2)
#
#     print(toHex(txtENC))
#     print(toHex(txtENC2))
#
#     print(countsame(toBytearray(txtENC), toBytearray(txtENC2)))
#
#
#
#     print(toHex('s'))

    # # Plaintext with integral length of 8 bytes:
    # print("\n____________________________________________________")
    # print("\nTest (2/6): Plaintext with integral length of 8 bytes:")
    # print("\nInput:")
    # print("Plaintext: Did, you hear?! The quick, brown fox jumped, over the lazy dog!?")
    # print("Keys:")
    # print("k1: zeuszeus")
    # print("k2: achilles")
    # print("k3: apollo12")
    # print("\nOutput:")
    # txtENC = TDES_Module.TDEA_Encrypt(False, 'Did, you hear?! The quick, brown fox jumped, over the lazy dog!?', 'zeuszeus', 'achilles', 'apollo12', IP)
    # print("Encrypted text:")
    # print(txtENC)
    # txtDEC = TDES_Module.TDEA_Decrypt(False, txtENC, 'zeuszeus', 'achilles', 'apollo12', INV_IP)
    # print("Decrypted text: ")
    # print(txtDEC)
    #
    # # Plaintext with length not an integral number of 8 bytes:
    # print("\n____________________________________________________")
    # print("\nTest (3/6): Plaintext with length not an integral number of 8 bytes:")
    # print("\nInput:")
    # print("Plaintext: The quick brown fox jumps over the lazy dog")
    # print("Keys:")
    # print("k1: zeuszeus")
    # print("k2: achilles")
    # print("k3: apollo12")
    # print("\nOutput:")
    # txtENC = TDES_Module.TDEA_Encrypt(False, 'The quick brown fox jumps over the lazy dog', 'zeuszeus', 'achilles', 'apollo12', IP)
    # print("Encrypted text:")
    # print(txtENC)
    # txtDEC = TDES_Module.TDEA_Decrypt(False, txtENC, 'zeuszeus', 'achilles', 'apollo12', INV_IP)
    # print("Decrypted text: ")
    # print(txtDEC)
    #
    # # Plaintext with length an integral number of 8 bytes, and inspect mode = true:
    # print("\n____________________________________________________")
    # print("\nTest (4/6): Plaintext with length integral number of 8 bytes, and inspect mode = true:")
    # print("\nInput:")
    # print("Plaintext: ElonMusk")
    # print("Keys:")
    # print("k1: zeuszeus")
    # print("k2: achilles")
    # print("k3: apollo12")
    # print("\nOutput:")
    # txtENC = TDES_Module.TDEA_Encrypt(True, 'ElonMusk', 'zeuszeus', 'achilles', 'apollo12', IP)
    # print("----- Encryption: ------")
    # print("DES 1 Rounds Output: (Encryption)")
    # print(txtENC['DES1_Outputs'])
    # print("DES 2 Rounds Output: (Decryption)")
    # print(txtENC['DES2_Outputs'])
    # print("DES 3 Rounds Output: (Encryption)")
    # print(txtENC['DES3_Outputs'])
    # print("Ciphertext:")
    # print(txtENC["Ciphertext"])
    # txtDEC = TDES_Module.TDEA_Decrypt(True, txtENC["Ciphertext"], 'zeuszeus', 'achilles', 'apollo12', INV_IP)
    # print("----- Decryption: ------")
    # print("DES 1 Rounds Output: (Decryption)")
    # print(txtDEC['DES1_Outputs'])
    # print("DES 2 Rounds Output: (Encryption)")
    # print(txtDEC['DES2_Outputs'])
    # print("DES 3 Rounds Output: (Decryption)")
    # print(txtDEC['DES3_Outputs'])
    # print("Plaintext:")
    # print(txtDEC["Ciphertext"])
    #
    # # Test plaintext they have given us:
    # print("\n____________________________________________________")
    # print("\nTest (5/6): Plaintext given test:")
    # file = open("message.txt")
    # plaintext = file.read()
    # file.close()
    # print("\nInput:")
    # print("Plaintext: " + str(plaintext))
    # print("Keys:")
    # print("k1: zeuszeus")
    # print("k2: achilles")
    # print("k3: apollo12")
    # print("\nOutput:")
    # txtENC = TDES_Module.TDEA_Encrypt(False, plaintext, 'zeuszeus', 'achilles', 'apollo12', IP)
    # print("Encrypted text:")
    # print(txtENC)
    # txtDEC = TDES_Module.TDEA_Decrypt(False, txtENC, 'zeuszeus', 'achilles', 'apollo12', INV_IP)
    # print("Decrypted text: ")
    # print(txtDEC)
    #
    # Test image

    # print("\n____________________________________________________")
    # print("\nTest (6/6): Testing Image Encryption and Decryption")
    # print("\nInput:")
    # print("Keys:")
    # print("k1: EarthEar")
    # print("k2: MarsMars")
    # print("k3: PlutoPlu")
    # p_File = Image.open('EHN.png')
    # p_img = np.asarray(p_File)
    # imgENC = TDES_Module.TDEA_Encrypt(False, p_img, 'EarthEar', 'MarsMars', 'PlutoPlu', IP)
    # print("Encryption Done!")
    # Image.fromarray(imgENC.astype(np.uint8)).save('EHN_TDES_Encrypted.png')
    # imgDEC = TDES_Module.TDEA_Decrypt(False, imgENC, 'EarthEar', 'MarsMars', 'PlutoPlu', INV_IP)
    # Image.fromarray(imgDEC.astype(np.uint8)).save('EHN_TDES_Decrypted.png')
    # print("Decryption Done!")
    #
    # print("\n____________________________________________________")


