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

IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
INV_IP = [40.0, 8.0, 48.0, 16.0, 56.0, 24.0, 64.0, 32.0, 39.0, 7.0, 47.0, 15.0, 55.0, 23.0, 63.0, 31.0, 38.0, 6.0, 46.0, 14.0, 54.0, 22.0, 62.0, 30.0, 37.0, 5.0, 45.0, 13.0, 53.0, 21.0, 61.0, 29.0, 36.0, 4.0, 44.0, 12.0, 52.0, 20.0, 60.0, 28.0, 35.0, 3.0, 43.0, 11.0, 51.0, 19.0, 59.0, 27.0, 34.0, 2.0, 42.0, 10.0, 50.0, 18.0, 58.0, 26.0, 33.0, 1.0, 41.0, 9.0, 49.0, 17.0, 57.0, 25.0]

if __name__ == "__main__":

    # One character of plaintext:
    print("\n____________________________________________________")
    print("\nTest (1/5): One character of plaintext (without inspect_mode):")
    print("\nInput:")
    print("Plaintext: a")
    print("Keys:")
    print("k1: stefanab")
    print("k2: jacobusa")
    print("k3: encrypti")
    print("\nOutput:")
    txtENC = TDES_Module.TDEA_Encrypt(False, 'a', 'stefanab', 'jacobusa', 'encrypti', IP)
    print("Encrypted text: ",txtENC)
    txtDEC = TDES_Module.TDEA_Decrypt(False, txtENC, 'stefanab', 'jacobusa', 'encrypti', INV_IP)
    print("Decrypted text: ",txtDEC)

    # Plaintext with integral length of 8 bytes:
    print("\n____________________________________________________")
    print("\nTest (2/5): Plaintext with integral length of 8 bytes:")
    print("\nInput:")
    print("Plaintext: Did, you hear?! The quick, brown fox jumped, over the lazy dog!?")
    print("Keys:")
    print("k1: zeuszeus")
    print("k2: achilles")
    print("k3: apollo12")
    print("\nOutput:")
    txtENC = TDES_Module.TDEA_Encrypt(False, 'Did, you hear?! The quick, brown fox jumped, over the lazy dog!?', 'zeuszeus', 'achilles', 'apollo12', IP)
    print("Encrypted text:")
    print(txtENC)
    txtDEC = TDES_Module.TDEA_Decrypt(False, txtENC, 'zeuszeus', 'achilles', 'apollo12', INV_IP)
    print("Decrypted text: ")
    print(txtDEC)

    # Plaintext with length not an integral number of 8 bytes:
    print("\n____________________________________________________")
    print("\nTest (3/5): Plaintext with length not an integral number of 8 bytes:")
    print("\nInput:")
    print("Plaintext: The quick brown fox jumps over the lazy dog")
    print("Keys:")
    print("k1: zeuszeus")
    print("k2: achilles")
    print("k3: apollo12")
    print("\nOutput:")
    txtENC = TDES_Module.TDEA_Encrypt(False, 'The quick brown fox jumps over the lazy dog', 'zeuszeus', 'achilles', 'apollo12', IP)
    print("Encrypted text:")
    print(txtENC)
    txtDEC = TDES_Module.TDEA_Decrypt(False, txtENC, 'zeuszeus', 'achilles', 'apollo12', INV_IP)
    print("Decrypted text: ")
    print(txtDEC)

    # Plaintext with length an integral number of 8 bytes, and inspect mode = true:
    print("\n____________________________________________________")
    print("\nTest (4/5): Plaintext with length integral number of 8 bytes, and inspect mode = true:")
    print("\nInput:")
    print("Plaintext: ElonMusk")
    print("Keys:")
    print("k1: zeuszeus")
    print("k2: achilles")
    print("k3: apollo12")
    print("\nOutput:")
    txtENC = TDES_Module.TDEA_Encrypt(True, 'ElonMusk', 'zeuszeus', 'achilles', 'apollo12', IP)
    print("----- Encryption: ------")
    print("DES 1 Rounds Output: (Encryption)")
    print(txtENC['DES1_Outputs'])
    print("DES 2 Rounds Output: (Decryption)")
    print(txtENC['DES2_Outputs'])
    print("DES 3 Rounds Output: (Encryption)")
    print(txtENC['DES3_Outputs'])
    print("Ciphertext:")
    print(txtENC["Ciphertext"])
    txtDEC = TDES_Module.TDEA_Decrypt(True, txtENC["Ciphertext"], 'zeuszeus', 'achilles', 'apollo12', INV_IP)
    print("----- Decryption: ------")
    print("DES 1 Rounds Output: (Decryption)")
    print(txtDEC['DES1_Outputs'])
    print("DES 2 Rounds Output: (Encryption)")
    print(txtDEC['DES2_Outputs'])
    print("DES 3 Rounds Output: (Decryption)")
    print(txtDEC['DES3_Outputs'])
    print("Plaintext:")
    print(txtDEC["Ciphertext"])

    # Test image
    print("\n____________________________________________________")
    print("\nTest (5/5): Testing Image Encryption and Decryption")
    print("\nInput:")
    print("Keys:")
    print("k1: EarthEar")
    print("k2: MarsMars")
    print("k3: PlutoPlu")
    p_File = Image.open('berge.png')
    p_img = np.asarray(p_File)
    imgENC = TDES_Module.TDEA_Encrypt(False, p_img, 'EarthEar', 'MarsMars', 'PlutoPlu', IP)
    print("Encryption Done!")
    Image.fromarray(imgENC.astype(np.uint8)).save('berge_encrypted_TDES.png')
    imgDEC = TDES_Module.TDEA_Decrypt(False, imgENC, 'EarthEar', 'MarsMars', 'PlutoPlu', INV_IP)
    Image.fromarray(imgDEC.astype(np.uint8)).save('berge_decrypted_TDES.png')
    print("Decryption Done!")

    print("\n____________________________________________________")


