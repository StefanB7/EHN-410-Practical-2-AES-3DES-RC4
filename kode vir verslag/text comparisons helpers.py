from numpy import byte

Plaintext = "The quick brown fox jumps over the lazy dog!!!!!"


# AES = ""
# DES = "ÚR}Åx±sm©®é;¤ê3"
# RC4 = ""
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
# def countsame(firstbytes, secondbytes):
#
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
# test1 = bytearray(1)
# test1[0] = 1
#
# test2 = bytearray(1)
# test2[0] = 2
#
# print(countsame(test1,test2))
#
# print(toHex(Plaintext))



array =  [84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115, 32, 111, 118, 101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 100, 111, 103, 33, 33, 33, 33, 33]
hex_string = ""

for i in range(len(array)):
    hex_string = hex_string + hex(array[i])[2:].upper()

print(hex_string)

















