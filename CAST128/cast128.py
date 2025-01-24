from CAST128.algorithm import algorithm
from CAST128.keyGenerator import getKeySize, checkKeyFormat


"""function that encrypt/decrypt 64bit hex txt 
if encORdec is True mean encrypt else decrypt"""
def cast128(txt,key,encORdec):
    h_size = getKeySize(key)
    isKeyValid = checkKeyFormat(key)
    if h_size < 40:
        print("Key size must be grater than 40 bits!")
        exit(1)
    elif h_size % 8 != 0:
        print("Key size must be in 8-bit increments!")
        exit(1)
    elif h_size > 128:
        print("Key size must be less than 128 bits!")
        exit(1)
    elif not isKeyValid:
        print("Key must be in hexadecimal format!")
        exit(1)
    else:
        txtAfter = algorithm(txt, key, encORdec)
    return txtAfter

