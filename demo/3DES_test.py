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

    # Test plaintext they have given us:
    print("\n____________________________________________________")
    print("\nTest (3/5): Plaintext given test:")
    file = open("message.txt")
    plaintext = file.read()
    file.close()
    print("\nInput:")
    print("Plaintext: " + str(plaintext))
    print("Keys:")
    print("k1: zeuszeus")
    print("k2: achilles")
    print("k3: apollo12")
    print("\nOutput:")
    txtENC = TDES_Module.TDEA_Encrypt(False, plaintext, 'zeuszeus', 'achilles', 'apollo12', IP)
    print("Encrypted text:")
    print(txtENC)
    txtDEC = TDES_Module.TDEA_Decrypt(False, txtENC, 'zeuszeus', 'achilles', 'apollo12', INV_IP)
    print("Decrypted text: ")
    print(txtDEC)

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


