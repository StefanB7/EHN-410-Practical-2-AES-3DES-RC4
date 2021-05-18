import numpy as np

r = [0,1,2,3,4,0,1,2,177]

print(bytearray(r))
print(bytearray(r).decode('unicode_escape'))
print(bytearray(r).decode('unicode_escape').encode('utf-8'))


