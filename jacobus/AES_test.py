# Stefan Buys (u18043098), Jacobus Oettle (u18000135) - University of Pretoria
# EHN 410 - 2021

from PIL import Image
import numpy as np
import importlib

AES_Module = importlib.import_module("AES_jacobus")

txtENC = ""
txtDEC = ""

imgENC = None
imgDEC = None

if __name__ == "__main__":

    # load sbox and IV
    sbox = np.load('lookup_files\AES_Sbox_lookup.npy')

    sbox = sbox.reshape(1, -1)[0]
    sbox = np.array([int(str(value), 16) for value in sbox], dtype=np.ubyte)
    sbox = sbox.reshape(16, 16)


    inv_sbox = np.load('lookup_files\AES_Inverse_Sbox_lookup.npy')
    inv_sbox = inv_sbox.reshape(1, -1)[0]
    inv_sbox = np.array([int(str(value), 16)
                        for value in inv_sbox], dtype=np.ubyte)
    inv_sbox = inv_sbox.reshape(16, 16)

    iv = np.load('lookup_files\AES_CBC_IV.npy')
    iv = np.array([int(str(value), 16) for value in iv], dtype=np.ubyte)

    # # One character of plaintext:
    # print("\n____________________________________________________")
    # print("\nTest (1/5): One character of plaintext (without inspect_mode):")
    # print("\nInput:")
    # print("Plaintext: a")
    # print("Key: minecraft")
    # print("\nOutput:")
    # txtENC = AES_Module.AES_Encrypt(False,"a", iv, "minecraft", sbox)
    # print("Encrypted text: ",txtENC)
    # txtDEC = AES_Module.AES_Decrypt(False, txtENC, iv, "minecraft", inv_sbox)
    # print("Decrypted text: ",txtDEC)

    # # Plaintext with integral length of 8 bytes:
    # print("\n____________________________________________________")
    # print("\nTest (2/5): Plaintext with integral length of 8 bytes:")
    # print("\nInput:")
    # print("Plaintext: Did, you hear?! The quick, brown fox jumped, over the lazy dog!?")
    # print("Key: minecraft")
    # print("\nOutput:")
    # txtENC = AES_Module.AES_Encrypt(False,"Did, you hear?! The quick, brown fox jumped, over the lazy dog!?", iv, "minecraft", sbox)
    # print("Encrypted text:")
    # print(txtENC)
    # txtDEC = AES_Module.AES_Decrypt(False, txtENC, iv, "minecraft", inv_sbox)
    # print("Decrypted text: ")
    # print(txtDEC)

    # # Plaintext with length not an integral number of 8 bytes:
    # print("\n____________________________________________________")
    # print("\nTest (3/5): Plaintext with length not an integral number of 8 bytes:")
    # print("\nInput:")
    # print("Plaintext: The quick brown fox jumps over the lazy dog")
    # print("Key: minecraft")
    # print("\nOutput:")
    # txtENC = AES_Module.AES_Encrypt(False,"The quick brown fox jumps over the lazy dog", iv, "minecraft", sbox)
    # print("Encrypted text:")
    # print(txtENC)
    # txtDEC = AES_Module.AES_Decrypt(False, txtENC, iv, "minecraft", inv_sbox)
    # print("Decrypted text: ")
    # print(txtDEC)

    # # Plaintext with length an integral number of 8 bytes, and inspect mode = true:
    # print("\n____________________________________________________")
    # print("\nTest (4/5): Plaintext with length integral number of 8 bytes, and inspect mode = true:")
    # print("\nInput:")
    # print("Plaintext: ElonMusk")
    # print("Key: minecraft")
    # print("\nOutput:")
    # txtENC = AES_Module.AES_Encrypt(True,"ElonMusk", iv, "minecraft", sbox)
    # print("----- Encryption: ------")
    # print(txtENC['States'])
    # print(txtENC['Ciphertext'])
    # txtDEC = AES_Module.AES_Decrypt(True, txtENC, iv, "minecraft", inv_sbox)
    # print(txtDEC['States'])
    # print(txtDEC['Plaintext'])

    # Test image
    print("\n____________________________________________________")
    print("\nTest (5/5): Testing Image Encryption and Decryption")
    print("\nInput:")
    print("Key: startrekwasbeter")
<<<<<<< Updated upstream
    p_img = AES_Module.img2array('jacobus\images\\gebou_500.png')
    imgENC = AES_Module.AES_Encrypt(False, p_img, [4,20,6,9,4,20,6,9,4,20,6,9,4,20,6,9], "startrekwasbeter", sbox)
    print("Encryption Done!")
    AES_Module.array2img(imgENC,"jacobus\images\\gebou_500_enc.png")
    imgDEC = AES_Module.AES_Decrypt(False, imgENC, [4,20,6,9,4,20,6,9,4,20,6,9,4,20,6,9], "startrekwasbeter", inv_sbox)
    print("Decryption Done!")
    AES_Module.array2img(imgDEC,"jacobus\images\\gebou_500_dec.png")
=======
    p_img = AES_Module.img2array('berge_700.png')
    imgENC = AES_Module.AES_Encrypt(False, p_img, [4,20,6,9,4,20,6,9,4,20,6,9,4,20,6,9], "startrekwasbeter", sbox)
    print("Encryption Done!")
    AES_Module.array2img(imgENC,"berge_700_enc.png")
    imgDEC = AES_Module.AES_Decrypt(False, imgENC, [4,20,6,9,4,20,6,9,4,20,6,9,4,20,6,9], "startrekwasbeter", inv_sbox)
    print("Decryption Done!")
    AES_Module.array2img(imgDEC,"berge_700_dec.png")
>>>>>>> Stashed changes

    print("\n____________________________________________________")


