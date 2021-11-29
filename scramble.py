import sys

result = [ord(c) for c in sys.argv[1]]
result.append(0)
for i in range(len(result)):
    result[i] = result[i] ^ (i & 0xff)
    
print(result)
