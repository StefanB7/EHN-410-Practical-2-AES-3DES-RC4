# Stefan Buys (u18043098), Jacobus Oettle (u18000135) - University of Pretoria
# EHN 410 - 2021

from PIL import Image
import numpy as np
import importlib

RC4_Module = importlib.import_module("RC4")

txtENC = ""
txtDEC = ""

imgENC = None
imgDEC = None

if __name__ == "__main__":

    np.set_printoptions(linewidth=300)

    print("\n--- RC4 Encryption and Decryption Test ---")

    # One character of plaintext:
    print("____________________________________________________")
    print("\nTest (1/6): One character of plaintext (without inspect_mode):")
    print("\nInput:")
    print("Plaintext: a")
    print("Key: I've got something very important to say")
    print("\nOutput:")
    txtENC = RC4_Module.RC4_Encrypt(False, 'a', 'Ive got something very important to say')
    print("Encrypted text: ",txtENC)
    txtDEC = RC4_Module.RC4_Decrypt(False, txtENC, 'Ive got something very important to say')
    print("Decrypted text: ",txtDEC)

    # Use a key with length of 1:
    print("____________________________________________________")
    print("\nTest (2/6): One character key (without inspect_mode):")
    print("\nInput:")
    print("Plaintext: We've got them boys!")
    print("Key: a")
    print("\nOutput:")
    txtENC = RC4_Module.RC4_Encrypt(False, "We've got them boys!", 'a')
    print("Encrypted text: ",txtENC)
    txtDEC = RC4_Module.RC4_Decrypt(False, txtENC, 'a')
    print("Decrypted text: ",txtDEC)

    # Use a key with length of more than 256 characters
    print("____________________________________________________")
    print("\nTest (3/6): Key with length more than 256 characters (without inspect_mode):")
    print("\nInput:")
    print("Plaintext: Meet me tomorrow 3 o'clock at the fountain in the middle of town")
    print("Key: The longest word in most dictionaries is: PNEUMONOULTRAMICROSCOPICSILICOVOLCANOCONIOSIS, followed by PSEUDOPSEUDOHYPOPARATHYROIDISM. I still don't have enough characters, yikes! Here is a filler sentance: The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")
    print("\nOutput:")
    txtENC = RC4_Module.RC4_Encrypt(False, "Meet me tomorrow 3 o'clock at the fountain in the middle of town", "The longest word in most dictionaries is: PNEUMONOULTRAMICROSCOPICSILICOVOLCANOCONIOSIS, followed by PSEUDOPSEUDOHYPOPARATHYROIDISM. I still don't have enough characters, yikes! Here is a filler sentance: The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")
    print("Encrypted text: ")
    print(txtENC)
    txtDEC = RC4_Module.RC4_Decrypt(False, txtENC, "The longest word in most dictionaries is: PNEUMONOULTRAMICROSCOPICSILICOVOLCANOCONIOSIS, followed by PSEUDOPSEUDOHYPOPARATHYROIDISM. I still don't have enough characters, yikes! Here is a filler sentance: The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")
    print("Decrypted text: ")
    print(txtDEC)

    # Plaintext with a length of 5 bytes, when inspect_mode = true
    print("____________________________________________________")
    print("\nTest (4/6): Plaintext with a length of 5 bytes, with inspect_mode):")
    print("\nInput:")
    print("Plaintext: acorn")
    print("Key: JacobusStefan")
    txtENC = RC4_Module.RC4_Encrypt(True, "acorn", "JacobusStefan")
    print("----- Encryption: ------")
    for i in range(len("acorn")):
        print("S-table after iteration: " + str(i+1) + " (Encryption)")
        print(txtENC['S-table'][i])
    print("Ciphertext:")
    print(txtENC["Ciphertext"])
    txtDEC = RC4_Module.RC4_Decrypt(True, txtENC["Ciphertext"], "JacobusStefan")
    print("----- Decryption: ------")
    for i in range(len("acorn")):
        print("S-table after iteration: " + str(i + 1) + " (Decryption)")
        print(txtDEC['S-table'][i])
    print("Plaintext:")
    print(txtDEC["Plaintext"])

    # Plaintext given:
    print("____________________________________________________")
    print("\nTest (5/6): Plaintext given:")
    file = open("message.txt")
    plaintext = file.read()
    file.close()
    print("\nInput:")
    print("Plaintext: " + str(plaintext))
    print("Key: I've got something very important to say")
    print("\nOutput:")
    txtENC = RC4_Module.RC4_Encrypt(False, plaintext, 'Ive got something very important to say')
    print("\nEncrypted text: ")
    print(txtENC)
    txtDEC = RC4_Module.RC4_Decrypt(False, txtENC, 'Ive got something very important to say')
    print("\nDecrypted text: ")
    print(txtDEC)

    # Test image
    print("\n____________________________________________________")
    print("\nTest (6/6): Testing Image Encryption and Decryption")
    print("\nInput:")
    print("Key: StefanJacobus")
    p_File = Image.open('berge.png')
    p_img = np.asarray(p_File)
    imgENC = RC4_Module.RC4_Encrypt(False, p_img, 'StefanJacobus')
    print("Encryption Done!")
    Image.fromarray(imgENC.astype(np.uint8)).save('berge_encrypted_RC4.png')
    imgDEC = RC4_Module.RC4_Decrypt(False, imgENC, 'StefanJacobus')
    Image.fromarray(imgDEC.astype(np.uint8)).save('berge_decrypted_RC4.png')
    print("Decryption Done!")

    print("\n____________________________________________________")
