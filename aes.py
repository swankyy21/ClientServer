from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generateKey():
    return get_random_bytes(16) 

def encrypt(inputText, key):
    cipher = AES.new(key.to_bytes(16, byteorder='big'), AES.MODE_CBC)
    cipherText = cipher.encrypt(pad(inputText.encode('utf-8'), AES.block_size))
    return cipherText, cipher.iv

def decrypt(cipherText, key, iv):
    cipher = AES.new(key.to_bytes(16, byteorder='big'), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(cipherText), AES.block_size)
    return decrypted_data.decode('utf-8')

