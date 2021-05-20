from numpy import byte

Plaintext = "The quick brown fox jumps over the lazy dog!!!!!"


AES = ""
DES = ""
RC4 = ""

def toHex(inputString):
    bytearr = bytearray(len(inputString))

    for i in range(len(inputString)):
        bytearr[i] = ord(inputString[i])

    stringout = ""

    for i in range(len(bytearr)):
        singleByte = bytearray(1)
        singleByte[0] = bytearr[i]
        stringout = stringout + singleByte.hex().upper()

    return stringout

def countsame(firstbytes, secondbytes):

    byteIndex = 0
    bitIndex = 0

    numTheSame = 0

    for byteIndex in range(len(firstbytes)):
        for bitIndex in range(8):
            first = firstbytes[byteIndex] & (0x01 << bitIndex)
            second = secondbytes[byteIndex] & (0x01 << bitIndex)

            if (second > 0) and (first > 0):
                numTheSame += 1
            elif (second == 0) and (first == 0):
                numTheSame += 1

    return numTheSame

test1 = bytearray(1)
test1[0] = 1

test2 = bytearray(1)
test2[0] = 2

print(countsame(test1,test2))
















