# EHN 410 - Practical 2 - 2021
# AES-256 (32 byte key) encryption and decryption (128 bit block size)
# Group 7


# expanded key bytes == 240

# maak net seker orals waar ek plus en maal is dit wel in die GF(2^8)

import numpy as np
 
############################ Main functions: ############################

def AES_Encrypt(inspect_mode, plaintext, iv, key, sbox_array):

    bytes_key = getBitsandPad(key, True)
    
    # key expansion
    bytes_key = keyExpansion(bytes_key,sbox_array)

    # TODO: hmmm wat gaan ek doen by die decryption waar ek net die inverse sbox kry ?

    # Format the initialization vector
    iv = formatIV(iv, bytes_key)

    # plaintext encryption
    if type(plaintext) is not np.ndarray:

        plain_bytes = getBitsandPad(plaintext)
        encrypted_bytes = None

        prev_block = iv
        while plain_bytes.shape[1] != 0:
            
            bytes_block = plain_bytes[:,:4]
            plain_bytes = plain_bytes[:,4:]

            ## Round 0:
            # XOR input block with previous block, (IV for first block)
            bytes_block = XOR(bytes_block, prev_block)
            
            # Key selection from expansion
            k0 = bytes_key[:,0:4]
            # Add round key
            bytes_block = AddRoundKey(k0,bytes_block)

            ## Round 1 to 13:
            for round in range(13):
                # Key selection from expansion
                kn = bytes_key[:,4*round+4:4*round+8]
                # SubBytes
                bytes_block = SubBytes(bytes_block,sbox_array)
                # ShiftRows
                bytes_block = ShiftRows(bytes_block)
                # MixColumns
                bytes_block = MixColumns(bytes_block)
                # AddRoundKey
                bytes_block = AddRoundKey(kn,bytes_block)

            ## Round 14 (final):
            # Key selection form expansion
            k14 = bytes_key[:,56:60]
            # SubBytes
            bytes_block = SubBytes(bytes_block,sbox_array)
            # ShiftRows
            bytes_block = ShiftRows(bytes_block)
            # MixColumns
            bytes_block = MixColumns(bytes_block)
            # AddRoundKey
            bytes_block = AddRoundKey(k14,bytes_block)

            # Save previous encrypted block for CBC (Cipher block chaining)
            prev_block = bytes_block

            # save the encrypted block
            if encrypted_bytes is None:
                encrypted_bytes = bytes_block.reshape(1,-1)[0]
            else:
                encrypted_bytes = np.concatenate((encrypted_bytes,bytes_block.reshape(1,-1)[0]), axis=None)

        return encrypted_bytes
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

    # key expansion

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
def SubBytes(arg,sbox):
    # matrix output generated with stage mapped to s-box value
    # 4 left bits indicate the row of s-box
    # 4 right bits indicate the column of s-box

    temp = np.zeros((4,4),dtype=np.ubyte)

    for i in range(4):
        for j in range(4):
            # binary value of the argument
            b = bin(arg[i,j])[2:].zfill(8)

            # left 4 bits -> row
            i_row = int(b[:4],2)
            
            # right 4 bits -> column
            i_column = int(b[4:],2)

            temp[i,j] = sbox[i_row,i_column]

    return temp

# Shift the rows of the stage matrix
def ShiftRows(arg):
    temp = np.zeros((4,4),np.ubyte)

    # 1 byte circular left shift on second column
    # 2 byte circular left shift on third column
    # 3 byte circular left shift on fourth and final column
    temp[0,:] = arg[0,:]
    for i in range(1,4,1):
        temp[i,:] = np.concatenate((arg[i,i:],arg[i,:i]),axis=None)
    
    return temp

# Mix the columns of the stage matrix
def MixColumns(arg):
    # Dot product with the mix column matrix in the finite GF(2^8) field
    # meaning multiply is done in GF(2^8) and addition is XOR

    m = np.array([[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]])

    temp = np.zeros((4,4), np.ubyte)

    for i in range(4):
        temp[0,i] = XOR(XOR(GF_mul(m[0,0],arg[0,i]),GF_mul(m[0,1],arg[1,i])),XOR(GF_mul(m[0,2],arg[2,i]),GF_mul(m[0,3],arg[3,i])))
        temp[1,i] = XOR(XOR(GF_mul(m[1,0],arg[0,i]),GF_mul(m[1,1],arg[1,i])),XOR(GF_mul(m[1,2],arg[2,i]),GF_mul(m[1,3],arg[3,i])))
        temp[2,i] = XOR(XOR(GF_mul(m[2,0],arg[0,i]),GF_mul(m[2,1],arg[1,i])),XOR(GF_mul(m[2,2],arg[2,i]),GF_mul(m[2,3],arg[3,i])))
        temp[3,i] = XOR(XOR(GF_mul(m[3,0],arg[0,i]),GF_mul(m[3,1],arg[1,i])),XOR(GF_mul(m[3,2],arg[2,i]),GF_mul(m[3,3],arg[3,i])))

    return temp

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
def AddRoundKey(arg1,arg2):
    return XOR(arg1,arg2)

# Expand the key for each round
def keyExpansion(key,sbox):
    
    w = np.zeros((4,60), dtype=np.ubyte)

    # set the first values of w equal to the key
    temp_key = np.transpose(key.reshape(8,4))
    w[:4,:8] = temp_key

    for i in range(8,60,1):
        temp = w[:,i-1]
        if i % 8 == 0:
            # print("rcon : ", k_Rcon(int(i/8)))
            temp = XOR(k_SubWord(k_RotWord(temp),sbox),k_Rcon(int(i/8)))
            # print("XOR : ", np.array([hex(value) for value in temp]))
        
        w[:,i] = XOR(w[:,i-8],temp)
    
    return w

# Used during the key expansion: substitute words usings s-box
def k_SubWord(arg,sbox):
    
    temp = np.zeros(len(arg),dtype=np.ubyte)

    for i in range(len(arg)):
        # binary value of the argument
        b = bin(arg[i])[2:].zfill(8)

        # left 4 bits -> row
        i_row = int(b[:4],2)
        
        # right 4 bits -> column
        i_column = int(b[4:],2)

        temp[i] = sbox[i_row,i_column]

    #print("subword : ",np.array([hex(value) for value in temp]))
    return temp

# Used during the key expansion: Bit rotate word
def k_RotWord(arg):
    #print("rotword : ",np.array([hex(value) for value in np.concatenate((arg[1:],arg[0]),axis=None)]))
    return np.concatenate((arg[1:],arg[0]),axis=None)

# Used during the key expansion: Generate byte to be XOR'ed
def k_Rcon(arg):
    return np.array([rcon_recursive(arg),0,0,0],np.ubyte)

# Recursive function to determine the value of RC[j]
def rcon_recursive(j):
    if j == 1:
        return 1
    else:
        return GF_mul(2,rcon_recursive(j-1))

# Bitwise XOR of two input blocks
def XOR(arg1, arg2):
    return np.bitwise_xor(arg1,arg2)

# Return bit representation of ASCII characters and pad bits to be a multiple of 128
def getBitsandPad(arg, key=False):
    bits = None
    try:
        bits = np.array(bytearray(arg.encode(encoding="ascii")),dtype=np.ubyte)
    except:
        raise Exception("\n\nERROR: Key or Plaintext must be ASCII, encryption / decryption will not execute.\n")

    # pad bits if necessary
    # key, key will be concatenated if larger than 32 bytes
    if key == True:
        if len(bits) != 32*(len(bits)//32):
            bits = np.concatenate((bits, np.zeros(32, dtype=np.ubyte)),axis=None)
            bits = bits[:32]
            bits = bits.reshape(-1,4).transpose()

    # plaintext or image
    else:
        if len(bits) != 16*(len(bits)//16):
            bits = np.concatenate((bits, np.zeros(16, dtype=np.ubyte)),axis=None)
            bits = bits[:16*((len(bits)-16)//16)+16]
            bits = bits.reshape(-1,4).transpose()

    return bits

# Format the IV to be used in the AES algorithm
def formatIV(argIV, key):
    
    if argIV is None:
        argIV = np.array([], dtype=np.ubyte)
    else:
        argIV = np.array(argIV, dtype=np.ubyte)
    
    # if the initialisation vector is smaller than the cipher block, extend it with random bytes using the 
    # product of the key bytes as seed for the random number generator, mod with 2^32-1 to keep it within the seed value range
    if len(argIV.reshape(1,-1)) < 16:
        
        # seed 
        np.random.seed(int(np.prod(key))%(2*32-1))
        r_int = np.random.randint(0,256, size=16, dtype=np.ubyte)

        if argIV is not None:
            argIV = argIV.reshape(1,-1)
            argIV = np.concatenate((argIV,r_int), axis = None)
            argIV = argIV[:16]
        else:
            argIV = r_int
        
        argIV = argIV.reshape(4,4)

    # if the initialisation vector is larger than the cipher block, shorten it
    if len(argIV.reshape(1,-1)) > 16:
        argIV = argIV.reshape(1,-1)
        argIV = argIV[:16]
        argIV = argIV.reshape(4,4)

    return argIV

# Multiplication in the GF(2^8) Finite field using Russian Peasant Multiplication algorithm
def GF_mul(arg1, arg2):
    #https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael%27s_finite_field reference dit nog

    p = 0

    while arg1 and arg2:
        if arg2 & 1:
            p = p^arg1

        if arg1 & 128:
            arg1 = (arg1<<1) ^ 283
        else:
            arg1 = arg1*2
        
        arg2 = arg2 // 2 

    return p


# a = np.array([15, 21, 113, 201, 71, 217, 232, 89, 12, 183, 173, 214, 175, 127, 103, 152, 15, 21, 113, 201, 71, 217, 232, 89, 12, 183, 173, 214, 175, 127, 103, 152])

sbox = np.load('jacobus\AES_Sbox_lookup.npy')

sbox = sbox.reshape(1,-1)[0]

sbox =  np.array([int(str(value), 16) for value in sbox],dtype=np.ubyte)
sbox = sbox.reshape(16,16)

# r = keyExpansion(a,sbox)

# r = r.reshape(1,-1)[0]

# r = np.array([hex(value) for value in r])

# r = r.reshape(4,60)

# print(r.transpose())


enc_text = AES_Encrypt(False,"i met a man from an antique land who said two vast and trunkless legs stand in the dessert",None,"ozymandius deur percy", sbox)

print(enc_text)

enc_text =  np.array([chr(value) for value in enc_text])

print(enc_text)

#print(getBitsandPad("ABCDE", True))
#getBitsandPad("AB é")




# TODO: hex to ascii????

# TODO: IV en sbox input format en die ander npy file goed

#TODO: maak images groter sodat hlle in 128 bits pas en ook actually n image maak

# verduidelik in report hkm rijndael cool is want input bits is nie baie dieselfde as output bits nie kan dit vergelyk dalk met ander s-boxes,
#  en nie linear nie, check verwysing op bladsy 185

# byte = int('11111111', 2)

# s = "haai"

#print(bytearray(s.encode(encoding="ascii",errors="ignore"))[1])




### test AES

#encrypted_text = AES_Encrypt(False,"die is nie n lang sin nie",None,"Die is verkeerd",None)


# why CBC, because the same plaintext block will outpout different cipher text blocks en dan se iets van man in the middle attacks, check bl 216 repeating patterns
# kan nie detect wor d nie

# hulle noem dit n IV vecotr maar dis eintlink n blok met die selfde groote as die cipher block