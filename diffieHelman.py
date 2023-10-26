import random

def diffieHellmanAlgorithm(prime, g):
    # Private key
    privateKey = random.randint(1, prime)
    # Public key
    publicKey = (g ** privateKey) % prime
    return privateKey, publicKey

def generateSharedKey(privateKey, otherPublicKey, prime):
    sharedKey = (otherPublicKey ** privateKey) % prime
    return sharedKey
