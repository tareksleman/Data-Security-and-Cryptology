from CAST128.cast128 import cast128
from CAST128.algorithm import *

"""
parameter : ptext - string , key - hex ,iv- hex 64bit
return ctext-hex
"""
def cbc_encrypt(ptext,key,iv):
    blocks = split_plaintext_to_hex_blocks(ptext)
    roundCbc = len(blocks)
    previous = iv
    ctext = ""
    for i in range(roundCbc):
        binary_value1 = bin(int(blocks[i], 16))[2:]
        binary_value2 = bin(int(previous, 16))[2:]
        max_length = max(len(binary_value1), len(binary_value2))
        binary_value1 = binary_value1.zfill(max_length)
        binary_value2 = binary_value2.zfill(max_length)
        xor = hex(int(binary_value1, 2) ^ int(binary_value2, 2))[2:]
        previous = cast128(xor,key,True)
        ctext += previous
    return ctext



"""
parameter : ctext - hex , key - hex ,iv- hex 64bit
return ptext-string
"""
def cbc_decrypt(ctext,key,iv):
    blocks = []
    roundCbc = len(ctext) // 16
    for i in range(roundCbc):
        blocks.append(ctext[16*i:(i+1)*16])

    previous = iv
    ptext = ""
    for i in range(roundCbc):
        decryptBlock = cast128(blocks[i], key, False)
        binary_value1 = bin(int(previous, 16))[2:]
        binary_value2 = bin(int(decryptBlock, 16))[2:]
        max_length = max(len(binary_value1), len(binary_value2))
        binary_value1 = binary_value1.zfill(max_length)
        binary_value2 = binary_value2.zfill(max_length)
        xor = hex(int(binary_value1, 2) ^ int(binary_value2, 2))[2:]
        ptext += xor
        previous = blocks[i]

    bytes_data = bytes.fromhex(ptext)
    return bytes_data.decode('utf-8')
