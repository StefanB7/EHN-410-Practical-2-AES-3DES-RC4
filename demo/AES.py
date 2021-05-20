# EHN 410 - Practical 2 - 2021
# AES-256 (32 byte key) encryption and decryption (128 bit block size)
# Group 7

import numpy as np
from PIL import Image
import multiprocessing as mp
import multiprocessing
import multiprocessing.pool
import warnings


warnings.filterwarnings("ignore", category=DeprecationWarning)


############################ Main functions: ############################
# Multiprocessing Classes needed to create a process within another process
# Second/Massimiliano's solution used from the following stack overflow question: (https://stackoverflow.com/questions/6974695/python-process-pool-non-daemonic)
class NoDaemonProcess(multiprocessing.Process):
    @property
    def daemon(self):
        return False

    @daemon.setter
    def daemon(self, value):
        pass

class NoDaemonContext(type(multiprocessing.get_context())):
    Process = NoDaemonProcess

class NestablePool(multiprocessing.pool.Pool):
    def __init__(self, *args, **kwargs):
        kwargs['context'] = NoDaemonContext()
        super(NestablePool, self).__init__(*args, **kwargs)

# AES Encryption
def AES_Encrypt(inspect_mode, plaintext, iv, key, sbox_array):

    inspect_rounds_states = []

    encrypted_bytes0 = None
    encrypted_bytes1 = None
    encrypted_bytes2 = None

    # how many blocks to encrypt
    iblocks = 0

    # flag indicating not all blocks were encrypted
    imgFlag = False

    # number of data bytes not encrypted
    imgFlagNumber = 0

    # Prepare byte matrix for plaintext encryption
    if type(plaintext) is not np.ndarray:

        # First dimension is for plain text or Red channel, second for Green channel and third for Blue channel
        plain_bytes = [getBitsandPad(plaintext)]

        # how many blocks there is to encrypt
        iblocks = plain_bytes[0].shape[1] // 4 

        param0 = (key,sbox_array,iv,iblocks,plain_bytes[0],inspect_rounds_states, True)

        mylist = [param0]

    # # Prepare byte matrix for image encryption
    else:
        
        # exctract RGB
        P = plaintext
        
        r_channel = np.array(P[:,:,0]).reshape(1,P[:,:,0].shape[0]*P[:,:,0].shape[1])[0]
        g_channel = np.array(P[:,:,1]).reshape(1,P[:,:,1].shape[0]*P[:,:,1].shape[1])[0]
        b_channel = np.array(P[:,:,2]).reshape(1,P[:,:,2].shape[0]*P[:,:,2].shape[1])[0]

        iblocks = len(r_channel) // 16


        # check if not all blocks will be encrypted
        if len(r_channel) != 16 * (len(r_channel) // 16):
            imgFlag = True
            imgFlagNumber = len(r_channel) - (16 * (len(r_channel) // 16))
        
        plain_bytes = [getBitsandPad(r_channel, False, True),getBitsandPad(g_channel, False, True),getBitsandPad(b_channel, False, True)]


        param0 = (key,sbox_array,iv,iblocks,plain_bytes[0])
        param1 = (key,sbox_array,iv,iblocks,plain_bytes[1])
        param2 = (key,sbox_array,iv,iblocks,plain_bytes[2])

        mylist = [param0,param1,param2]


    p = mp.Pool(4)

    result = p.starmap_async(AES_Loop_MP_ENC, mylist)
    p.close()
    p.join()

    if type(plaintext) is not np.ndarray:
        encrypted_bytes0 = np.array(result.get()[0], dtype=object)
    else:    
        encrypted_bytes0 = np.array(result.get()[0][0])
        encrypted_bytes1 = np.array(result.get()[1][0])
        encrypted_bytes2 = np.array(result.get()[2][0])


    # Pixels that did not fit within the cipher block size
    # XOR with first encrypted block
    if imgFlag:

        r_left = np.array(P[:,:,0]).reshape(1,P[:,:,0].shape[0]*P[:,:,0].shape[1])[0]            
        g_left = np.array(P[:,:,1]).reshape(1,P[:,:,1].shape[0]*P[:,:,1].shape[1])[0]
        b_left = np.array(P[:,:,2]).reshape(1,P[:,:,2].shape[0]*P[:,:,2].shape[1])[0]

        r_left = r_left[len(r_left)-imgFlagNumber:]
        g_left = g_left[len(g_left)-imgFlagNumber:]
        b_left = b_left[len(b_left)-imgFlagNumber:]
        
        encrypted_bytes0 = np.concatenate((encrypted_bytes0, XOR(encrypted_bytes0[:imgFlagNumber],r_left)), axis=None)
        encrypted_bytes1 = np.concatenate((encrypted_bytes1, XOR(encrypted_bytes1[:imgFlagNumber],g_left)), axis=None)
        encrypted_bytes2 = np.concatenate((encrypted_bytes2, XOR(encrypted_bytes2[:imgFlagNumber],b_left)), axis=None)
        

    if encrypted_bytes2 is None:
        if inspect_mode:

            enc_t = bytearray(encrypted_bytes0[0]).decode(encoding='unicode_escape',errors='ignore')

            result = {"States" : np.array(encrypted_bytes0[1]),"Ciphertext" : enc_t}

            return result

        else:

            enc_t = bytearray(np.array(encrypted_bytes0[0])).decode(encoding='raw_unicode_escape',errors='ignore')
        
            return enc_t
    else:
        
        encrypted_bytes0 = encrypted_bytes0.reshape(P[:,:,0].shape[0],P[:,:,0].shape[1])
        encrypted_bytes1 = encrypted_bytes1.reshape(P[:,:,1].shape[0],P[:,:,1].shape[1])
        encrypted_bytes2 = encrypted_bytes2.reshape(P[:,:,2].shape[0],P[:,:,2].shape[1])


        if plaintext.shape[2] == 4:
            alpha_layer = np.array(plaintext[:,:,3])
            return np.dstack((encrypted_bytes0.astype(int),encrypted_bytes1.astype(int),encrypted_bytes2.astype(int),alpha_layer.astype(int)))
        else:
            return np.dstack((encrypted_bytes0.astype(int),encrypted_bytes1.astype(int),encrypted_bytes2.astype(int)))

# Each RGB channel is done in a different process 
def AES_Loop_MP_ENC(key,sbox_array,arg_iv,iblocks,plain_bytes,inspect_rounds_states = [], inspect_mode = False):

    encrypted_bytes = None

    bytes_key = getBitsandPad(key, True)

    # key expansion
    bytes_key = keyExpansion(bytes_key, sbox_array)

    # Format the initialization vector
    iv = formatIV(arg_iv, bytes_key)

    prev_block = iv
    for blocks in range(iblocks):
        
        bytes_block = plain_bytes[:, :4]
        plain_bytes = np.array(plain_bytes[:, 4:])

        # CBC step:
        # XOR input block with previous block, (IV for first block)
        bytes_block = XOR(bytes_block, prev_block)

        # Round 0:
        # Key selection from expansion
        k0 = bytes_key[:, 0:4]
        # Add round key
        bytes_block = AddRoundKey(k0, bytes_block)

        # Round 1 to 13:
        for round in range(13):
            # Key selection from expansion
            kn = bytes_key[:, 4*round+4:4*round+8]
            # SubBytes
            bytes_block = SubBytes(bytes_block, sbox_array)
            # ShiftRows
            bytes_block = ShiftRows(bytes_block)
            # MixColumns
            bytes_block = MixColumns(bytes_block)
            # AddRoundKey
            bytes_block = AddRoundKey(kn, bytes_block)

            # save round state
            if inspect_mode:
                inspect_rounds_states.append(bytes_block)

        # Round 14 (final):
        # Key selection form expansion
        k14 = bytes_key[:, 56:60]
        # SubBytes
        bytes_block = SubBytes(bytes_block, sbox_array)
        # ShiftRows
        bytes_block = ShiftRows(bytes_block)
        # AddRoundKey
        bytes_block = AddRoundKey(k14, bytes_block)

        # Save previous encrypted block for CBC (Cipher block chaining)
        prev_block = bytes_block

        # save the encrypted block
                
        if encrypted_bytes is None:
            encrypted_bytes = np.array(bytes_block.transpose().reshape(1, -1)[0])
        else:
            encrypted_bytes = np.concatenate((encrypted_bytes, np.array(bytes_block.transpose().reshape(1, -1)[0])), axis=None)

    return [encrypted_bytes,inspect_rounds_states]

# AES Decryption
def AES_Decrypt(inspect_mode, ciphertext, iv, key, inv_sbox_array):

    inspect_rounds_states = []

    decrypted_bytes0 = None
    decrypted_bytes1 = None
    decrypted_bytes2 = None

    # how many blocks to encrypt
    iblocks = 0

    # flag indicating not all blocks were encrypted
    imgFlag = False

    # number of data bytes not encrypted
    imgFlagNumber = 0

    # first cipher block of RGB for decrypting final bits that did not fit into a block
    firstCipherBlock = None

    # Prepare byte matrix for ciphertext decryption
    if type(ciphertext) is not np.ndarray:
        
        if type(ciphertext) is dict:
            cipher_bytes = [getBitsandPad(ciphertext['Ciphertext'])]
            
        else:
            # First dimension is for plain text or Red channel, second for Green channel and third for Blue channel
            cipher_bytes = [getBitsandPad(ciphertext)]

        # how many blocks there is to encrypt
        iblocks = cipher_bytes[0].shape[1] // 4 

        param0 = (key,inv_sbox_array,iv,iblocks,cipher_bytes[0])

        mylist = [param0]


    # Prepare byte matrix for image decryption
    else:

        # exctract RGB
        C = ciphertext
        
        r_channel = np.array(C[:,:,0]).reshape(1,C[:,:,0].shape[0]*C[:,:,0].shape[1])[0]
        g_channel = np.array(C[:,:,1]).reshape(1,C[:,:,1].shape[0]*C[:,:,1].shape[1])[0]
        b_channel = np.array(C[:,:,2]).reshape(1,C[:,:,2].shape[0]*C[:,:,2].shape[1])[0]

        iblocks = len(r_channel) // 16

        # check if not all blocks will be encrypted
        if len(r_channel) != 16 * (len(r_channel) // 16):
            imgFlag = True
            imgFlagNumber = len(r_channel) - (16 * (len(r_channel) // 16))
            firstCipherBlock = [r_channel[:imgFlagNumber],g_channel[:imgFlagNumber],b_channel[:imgFlagNumber]]

        cipher_bytes = [getBitsandPad(r_channel, False, True),getBitsandPad(g_channel, False, True),getBitsandPad(b_channel, False, True)]

        param0 = (key,inv_sbox_array,iv,iblocks,cipher_bytes[0])
        param1 = (key,inv_sbox_array,iv,iblocks,cipher_bytes[1])
        param2 = (key,inv_sbox_array,iv,iblocks,cipher_bytes[2])

        mylist = [param0,param1,param2]

    p = NestablePool(4)

    result = p.starmap_async(AES_Loop_MP_DEC, mylist)
    p.close()
    p.join()

    if type(ciphertext) is not np.ndarray:
        decrypted_bytes0 = np.array(result.get()[0], dtype=object)    
    else:
        decrypted_bytes0 = np.array(result.get()[0][0])
        decrypted_bytes1 = np.array(result.get()[1][0])
        decrypted_bytes2 = np.array(result.get()[2][0])


    # Pixels that did not fit within the cipher block size
    # XOR with first encrypted block
    if imgFlag:
        r_left = np.array(C[:,:,0]).reshape(1,C[:,:,0].shape[0]*C[:,:,0].shape[1])[0]            
        g_left = np.array(C[:,:,1]).reshape(1,C[:,:,1].shape[0]*C[:,:,1].shape[1])[0]
        b_left = np.array(C[:,:,2]).reshape(1,C[:,:,2].shape[0]*C[:,:,2].shape[1])[0]

        r_left = r_left[len(r_left)-imgFlagNumber:]
        g_left = g_left[len(g_left)-imgFlagNumber:]
        b_left = b_left[len(b_left)-imgFlagNumber:]
        
        decrypted_bytes0 = np.concatenate((decrypted_bytes0, XOR(firstCipherBlock[0],r_left)), axis=None)
        decrypted_bytes1 = np.concatenate((decrypted_bytes1, XOR(firstCipherBlock[1],g_left)), axis=None)
        decrypted_bytes2 = np.concatenate((decrypted_bytes2, XOR(firstCipherBlock[2],b_left)), axis=None)
        


    if decrypted_bytes2 is None:

        if inspect_mode:

            dec_t = bytearray(np.squeeze(decrypted_bytes0[0])).decode('unicode_escape')

            result = {"States" : np.array(decrypted_bytes0[1]),"Plaintext" : dec_t}

            return result

        else:
            dec_t = bytearray(np.squeeze(decrypted_bytes0[0])).decode('raw_unicode_escape')

            return dec_t
    else:
        
        decrypted_bytes0 = decrypted_bytes0.reshape(C[:,:,0].shape[0],C[:,:,0].shape[1])
        decrypted_bytes1 = decrypted_bytes1.reshape(C[:,:,1].shape[0],C[:,:,1].shape[1])
        decrypted_bytes2 = decrypted_bytes2.reshape(C[:,:,2].shape[0],C[:,:,2].shape[1])


        if ciphertext.shape[2] == 4:
            alpha_layer = np.array(ciphertext[:,:,3])
            return np.dstack((decrypted_bytes0.astype(int),decrypted_bytes1.astype(int),decrypted_bytes2.astype(int),alpha_layer.astype(int)))
        else:
            return np.dstack((decrypted_bytes0.astype(int),decrypted_bytes1.astype(int),decrypted_bytes2.astype(int)))

# Each RGB channel is done in a different process 
def AES_Loop_MP_DEC(key,inv_sbox_array,iv,iblocks,cipher_bytes):

    decrypted_bytes = None

    bytes_key = getBitsandPad(key, True)

    # key expansion
    bytes_key = keyExpansion(bytes_key, invert_sbox(inv_sbox_array))

    # Format the initialization vector
    iv = formatIV(iv, bytes_key)

    prev_block = [iv]

    listBlocks = []


    for blocks in range(iblocks):

        bytes_block = cipher_bytes[:, :4]
        prev_block.append(bytes_block)
        
        l_b = (bytes_block,bytes_key,inv_sbox_array,prev_block.pop(0))
    
        listBlocks.append(l_b)

        cipher_bytes = np.array(cipher_bytes[:, 4:])

    p = mp.Pool(4)    
    result = p.starmap_async(AES_Decrypt_blocks, listBlocks)
    p.close()
    p.join()

    rr = result.get()

    decrypted_bytes = np.array(rr[0][0].transpose().reshape(1, -1))

    for i in range(1,len(rr)):
        decrypted_bytes = np.concatenate((decrypted_bytes,np.array(rr[i][0].transpose().reshape(1, -1))), axis=None)

    return [decrypted_bytes,rr[0][1]]

# Each block is done in a different process
def AES_Decrypt_blocks(bytes_block,bytes_key,inv_sbox_array,xorBlock):
    inspect_rounds_states = []
    # Round 0:
    # Key selection from expansion
    k0 = bytes_key[:, 56:60]
    # Add round key
    bytes_block = AddRoundKey(k0, bytes_block)

    # Round 1 to 13:
    for round in range(13):
        # Key selection from expansion
        kn = bytes_key[:, 4*(12-round)+4:4*(12-round)+8]
        # Inverse ShiftRows
        bytes_block = inv_ShiftRows(bytes_block)
        # Inverse SubBytes
        bytes_block = inv_SubBytes(bytes_block, inv_sbox_array)
        # AddRoundKey
        bytes_block = AddRoundKey(kn, bytes_block)
        # Inverse MixColumns
        bytes_block = inv_MixColumns(bytes_block)

        # save round state
        inspect_rounds_states.append(bytes_block)

    # Round 14:
    # Key selection from expansion
    k14 = bytes_key[:, 0:4]
    # Inverse ShiftRows
    bytes_block = inv_ShiftRows(bytes_block)
    # Inverse SubBytes
    bytes_block = inv_SubBytes(bytes_block, inv_sbox_array)
    # AddRoundKey
    bytes_block = AddRoundKey(k14, bytes_block)

    # CBC step:
    bytes_block = XOR(bytes_block, xorBlock)

    return [bytes_block,inspect_rounds_states]

############################ Helper functions: ###########################

### Encryption helper functions:

# Substistitute bytes based using a given s-box lookup table
def SubBytes(arg, sbox):
    # matrix output generated with stage mapped to s-box value
    # 4 left bits indicate the row of s-box
    # 4 right bits indicate the column of s-box

    temp = np.zeros((4, 4), dtype=np.ubyte)

    for i in range(4):
        for j in range(4):
            # binary value of the argument
            b = bin(arg[i, j])[2:].zfill(8)

            # left 4 bits -> row
            i_row = int(b[:4], 2)

            # right 4 bits -> column
            i_column = int(b[4:], 2)

            temp[i, j] = sbox[i_row, i_column]

    return temp

# Shift the rows of the stage matrix
def ShiftRows(arg):
    temp = np.zeros((4, 4), np.ubyte)

    # 1 byte circular left shift on second column
    # 2 byte circular left shift on third column
    # 3 byte circular left shift on fourth and final column
    temp[0, :] = arg[0, :]
    for i in range(1, 4, 1):
        temp[i, :] = np.concatenate((arg[i, i:], arg[i, :i]), axis=None)

    return temp

# Mix the columns of the stage matrix
def MixColumns(arg):
    # Dot product with the mix column matrix in the finite GF(2^8) field
    # meaning multiply is done in GF(2^8) and addition is XOR

    m = np.array([[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]])

    temp = np.zeros((4, 4), np.ubyte)

    for i in range(4):
        temp[0, i] = XOR(XOR(GF_mul(m[0, 0], arg[0, i]), GF_mul(m[0, 1], arg[1, i])), XOR(
            GF_mul(m[0, 2], arg[2, i]), GF_mul(m[0, 3], arg[3, i])))
        temp[1, i] = XOR(XOR(GF_mul(m[1, 0], arg[0, i]), GF_mul(m[1, 1], arg[1, i])), XOR(
            GF_mul(m[1, 2], arg[2, i]), GF_mul(m[1, 3], arg[3, i])))
        temp[2, i] = XOR(XOR(GF_mul(m[2, 0], arg[0, i]), GF_mul(m[2, 1], arg[1, i])), XOR(
            GF_mul(m[2, 2], arg[2, i]), GF_mul(m[2, 3], arg[3, i])))
        temp[3, i] = XOR(XOR(GF_mul(m[3, 0], arg[0, i]), GF_mul(m[3, 1], arg[1, i])), XOR(
            GF_mul(m[3, 2], arg[2, i]), GF_mul(m[3, 3], arg[3, i])))

    return temp

### Decryption helper functions:

# Inverse of the substitution byte stage
def inv_SubBytes(arg, inv_sbox):
    # same as subbytes, just use the inverse s-box
    # matrix output generated with stage mapped to s-box value
    # 4 left bits indicate the row of s-box
    # 4 right bits indicate the column of s-box

    temp = np.zeros((4, 4), dtype=np.ubyte)

    for i in range(4):
        for j in range(4):
            # binary value of the argument
            b = bin(arg[i, j])[2:].zfill(8)

            # left 4 bits -> row
            i_row = int(b[:4], 2)

            # right 4 bits -> column
            i_column = int(b[4:], 2)

            temp[i, j] = inv_sbox[i_row, i_column]

    return temp

# Inverse of the row shift stage
def inv_ShiftRows(arg):
    temp = np.zeros((4, 4), np.ubyte)

    # 1 byte circular right shift on second column
    # 2 byte circular right shift on third column
    # 3 byte circular right shift on fourth and final column
    temp[0, :] = arg[0, :]
    for i in range(1, 4, 1):
        temp[i, :] = np.concatenate((arg[i, 4-i:], arg[i, :4-i]), axis=None)

    return temp

# Inverse of the column mix stage
def inv_MixColumns(arg):
    # Dot product with the mix column matrix in the finite GF(2^8) field
    # meaning multiply is done in GF(2^8) and addition is XOR

    inv_m = np.array([[14, 11, 13, 9], [9, 14, 11, 13],
                     [13, 9, 14, 11], [11, 13, 9, 14]])

    temp = np.zeros((4, 4), np.ubyte)

    for i in range(4):
        temp[0, i] = XOR(XOR(GF_mul(inv_m[0, 0], arg[0, i]), GF_mul(inv_m[0, 1], arg[1, i])), XOR(
            GF_mul(inv_m[0, 2], arg[2, i]), GF_mul(inv_m[0, 3], arg[3, i])))
        temp[1, i] = XOR(XOR(GF_mul(inv_m[1, 0], arg[0, i]), GF_mul(inv_m[1, 1], arg[1, i])), XOR(
            GF_mul(inv_m[1, 2], arg[2, i]), GF_mul(inv_m[1, 3], arg[3, i])))
        temp[2, i] = XOR(XOR(GF_mul(inv_m[2, 0], arg[0, i]), GF_mul(inv_m[2, 1], arg[1, i])), XOR(
            GF_mul(inv_m[2, 2], arg[2, i]), GF_mul(inv_m[2, 3], arg[3, i])))
        temp[3, i] = XOR(XOR(GF_mul(inv_m[3, 0], arg[0, i]), GF_mul(inv_m[3, 1], arg[1, i])), XOR(
            GF_mul(inv_m[3, 2], arg[2, i]), GF_mul(inv_m[3, 3], arg[3, i])))

    return temp

### General helper functions:

# Add the key (XOR) for that round to the stage matrix
def AddRoundKey(arg1, arg2):
    return XOR(arg1, arg2)

# Expand the key for each round
def keyExpansion(key, sbox):

    w = np.zeros((4, 60), dtype=np.ubyte)

    # set the first values of w equal to the key
    temp_key = key.reshape(4, 8)
    w[:4, :8] = temp_key

    for i in range(8, 60, 1):
        temp = w[:, i-1]
        if i % 8 == 0:
            temp = XOR(k_SubWord(k_RotWord(temp), sbox), k_Rcon(int(i/8)))

        w[:, i] = XOR(w[:, i-8], temp)

    return w

# Used during the key expansion: substitute words usings s-box
def k_SubWord(arg, sbox):

    temp = np.zeros(len(arg), dtype=np.ubyte)

    for i in range(len(arg)):
        # binary value of the argument
        b = bin(arg[i])[2:].zfill(8)

        # left 4 bits -> row
        i_row = int(b[:4], 2)

        # right 4 bits -> column
        i_column = int(b[4:], 2)

        temp[i] = sbox[i_row, i_column]

    return temp

# Used during the key expansion: Bit rotate word
def k_RotWord(arg):
    return np.concatenate((arg[1:], arg[0]), axis=None)

# Used during the key expansion: Generate byte to be XOR'ed
def k_Rcon(arg):
    return np.array([rcon_recursive(arg), 0, 0, 0], np.ubyte)

# Recursive function to determine the value of RC[j]
def rcon_recursive(j):
    if j == 1:
        return 1
    else:
        return GF_mul(2, rcon_recursive(j-1))

# Bitwise XOR of two input blocks
def XOR(arg1, arg2):
    return np.bitwise_xor(arg1, arg2)

# Return bit representation of ASCII characters and pad bits to be a multiple of 128
def getBitsandPad(arg, key=False, img=False):
    bits = None

    if img == False:
        bits = chartobyte(arg)
    else:
        bits = arg

    # pad bits if necessary
    # key, key will be concatenated if larger than 32 bytes
    if key == True:
        if len(bits) != 32*(len(bits)//32):
            bits = np.concatenate(
                (bits, np.zeros(32, dtype=np.ubyte)), axis=None)
            bits = bits[:32]
        bits = bits.reshape(-1, 4).transpose()

    # plaintext or image
    else:
        if len(bits) != 16*(len(bits)//16):
            bits = np.concatenate(
                (bits, np.zeros(16, dtype=np.ubyte)), axis=None)
            bits = bits[:16*((len(bits)-16)//16)+16]
        bits = bits.reshape(-1, 4).transpose()
        
    return bits

# Format the IV to be used in the AES algorithm
def formatIV(argIV, key):

    if argIV is None:
        argIV = np.array([], dtype=np.ubyte)
    else:
        argIV = np.array(argIV, dtype=np.ubyte)

    # if the initialisation vector is smaller than the cipher block, extend it with random bytes using the
    # product of the key bytes as seed for the random number generator, mod with 2^32-1 to keep it within the seed value range
    if len(argIV.reshape(1, -1)) < 16:

        # seed
        np.random.seed(int(np.prod(key)) % (2*32-1))
        r_int = np.random.randint(0, 256, size=16, dtype=np.ubyte)

        if argIV is not None:
            argIV = argIV.reshape(1, -1)
            argIV = np.concatenate((argIV, r_int), axis=None)
            argIV = argIV[:16]
        else:
            argIV = r_int

        argIV = argIV.reshape(4, 4)

    # if the initialisation vector is larger than the cipher block, shorten it
    if len(argIV.reshape(1, -1)) > 16:
        argIV = argIV.reshape(1, -1)
        argIV = argIV[:16]
        argIV = argIV.reshape(4, 4)

    argIV = argIV.transpose()
    return argIV

# Multiplication in the GF(2^8) Finite field using Russian Peasant Multiplication algorithm (https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael%27s_finite_field)
def GF_mul(arg1, arg2):
    p = 0

    while arg1 and arg2:
        if arg2 & 1:
            p = p ^ arg1

        if arg1 & 128:
            arg1 = (arg1 << 1) ^ 283
        else:
            arg1 = arg1*2

        arg2 = arg2 // 2

    return p

# Used to invert the sbox
def invert_sbox(arg):

    temp = np.zeros((arg.shape[0], arg.shape[1]), np.ubyte)

    for i in range(arg.shape[0]):
        for j in range(arg.shape[1]):
            # binary value of the argument
            b = bin(arg[i, j])[2:].zfill(8)

            # left 4 bits -> row
            i_row = int(b[:4], 2)

            # right 4 bits -> column
            i_column = int(b[4:], 2)

            temp[i_row, i_column] = int(
                '0x'+str(hex(i)[2:])+str(hex(j)[2:]), 16)

    return temp

# functions below can only be used if relative path is jacobus\images\*
# Image to ndarray:
def img2array(loc):
    return np.asarray(Image.open(loc))

# ndarray to image:
def array2img(arr, loc):
    Image.fromarray(arr.astype(np.uint8)).save(loc)

# convert char to byte array
def chartobyte(chararray):
    output = bytearray(len(chararray))

    for i in range(len(chararray)):
        if ord(chararray[i]) < 256:
            output[i] = ord(chararray[i])
    return np.array(output,dtype=np.ubyte)
