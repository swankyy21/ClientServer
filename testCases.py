import unittest
import diffieHelman
import rsa

class MyTestCase(unittest.TestCase):

    # Testing with different key lengths for diffie-Helman
    def test_symmetric_key_exchange(self):
        umarPrivateKey, umarPublicKey = diffieHelman.diffieHellmanAlgorithm(23, 5)
        shaheerPrivateKey, shaheerPublicKey = diffieHelman.diffieHellmanAlgorithm(23, 5)
        
        SharedKey1 = diffieHelman.generateSharedKey(umarPrivateKey, shaheerPublicKey, 23)
        SharedKey2 = diffieHelman.generateSharedKey(shaheerPrivateKey, umarPublicKey, 23)

        self.assertEqual(SharedKey1, SharedKey2)
        
    def test_symmetric_key_exchange2(self):
        umarPrivateKey, umarPublicKey = diffieHelman.diffieHellmanAlgorithm(17, 5)
        shaheerPrivateKey, shaheerPublicKey = diffieHelman.diffieHellmanAlgorithm(17, 5)
        
        SharedKey1 = diffieHelman.generateSharedKey(umarPrivateKey, shaheerPublicKey, 17)
        SharedKey2 = diffieHelman.generateSharedKey(shaheerPrivateKey, umarPublicKey, 17)

        self.assertEqual(SharedKey1, SharedKey2)
        
    def test_symmetric_key_exchange3(self):
        umarPrivateKey, umarPublicKey = diffieHelman.diffieHellmanAlgorithm(11, 3)
        shaheerPrivateKey, shaheerPublicKey = diffieHelman.diffieHellmanAlgorithm(11, 3)
        
        SharedKey1 = diffieHelman.generateSharedKey(umarPrivateKey, shaheerPublicKey, 11)
        SharedKey2 = diffieHelman.generateSharedKey(shaheerPrivateKey, umarPublicKey, 11)

        self.assertEqual(SharedKey1, SharedKey2)
    
    def test_symmetric_key_exchange4(self):
        umarPrivateKey, umarPublicKey = diffieHelman.diffieHellmanAlgorithm(97, 11)
        shaheerPrivateKey, shaheerPublicKey = diffieHelman.diffieHellmanAlgorithm(97, 11)
        
        SharedKey1 = diffieHelman.generateSharedKey(umarPrivateKey, shaheerPublicKey, 97)
        SharedKey2 = diffieHelman.generateSharedKey(shaheerPrivateKey, umarPublicKey, 97)

        self.assertEqual(SharedKey1, SharedKey2)
        
    def test_symmetric_key_exchange5(self):
        umarPrivateKey, umarPublicKey = diffieHelman.diffieHellmanAlgorithm(1087, 21)
        shaheerPrivateKey, shaheerPublicKey = diffieHelman.diffieHellmanAlgorithm(1087, 21)
        
        SharedKey1 = diffieHelman.generateSharedKey(umarPrivateKey, shaheerPublicKey, 1087)
        SharedKey2 = diffieHelman.generateSharedKey(shaheerPrivateKey, umarPublicKey, 1087)

        self.assertEqual(SharedKey1, SharedKey2)
    
    def test_symmetric_key_exchange6(self):
        umarPrivateKey, umarPublicKey = diffieHelman.diffieHellmanAlgorithm(6841, 102)
        shaheerPrivateKey, shaheerPublicKey = diffieHelman.diffieHellmanAlgorithm(6841, 102)
        
        SharedKey1 = diffieHelman.generateSharedKey(umarPrivateKey, shaheerPublicKey, 6841)
        SharedKey2 = diffieHelman.generateSharedKey(shaheerPrivateKey, umarPublicKey, 6841)

        self.assertEqual(SharedKey1, SharedKey2)
    
    
    # Incorrect parameters
    def test_symmetric_key_exchange7(self):
        umarPrivateKey, umarPublicKey = diffieHelman.diffieHellmanAlgorithm(23, 5)
        shaheerPrivateKey, shaheerPublicKey = diffieHelman.diffieHellmanAlgorithm(21, 7)
        
        SharedKey1 = diffieHelman.generateSharedKey(umarPrivateKey, shaheerPublicKey, 23)
        SharedKey2 = diffieHelman.generateSharedKey(shaheerPrivateKey, umarPublicKey, 21)
        
        self.assertNotEqual(SharedKey1, SharedKey2)

    def test_symmetric_key_exchange8(self):
        umarPrivateKey, umarPublicKey = diffieHelman.diffieHellmanAlgorithm(7873, 5)
        shaheerPrivateKey, shaheerPublicKey = diffieHelman.diffieHellmanAlgorithm(6569, 7)
        
        SharedKey1 = diffieHelman.generateSharedKey(umarPrivateKey, shaheerPublicKey, 7873)
        SharedKey2 = diffieHelman.generateSharedKey(shaheerPrivateKey, umarPublicKey, 6569)
        
        self.assertNotEqual(SharedKey1, SharedKey2)
    


    # Testing with different key lengths for RSA
    # Default Length : 2048 B
    def test_asymmetric_key_exchange(self):
        shaheerPrivateKey, shaheerPublicKey = rsa.genKeyPair()
        
        message = 'Hello Shaheer'
        sendMessagetoShaheer = rsa.encryptMessage(message, shaheerPublicKey)
        recieveMessage = rsa.decryptMessage(sendMessagetoShaheer, shaheerPrivateKey)
        
        self.assertEqual(recieveMessage, "Hello Shaheer")
    
    # Bare Minimum Length : 1024
    def test_asymmetric_key_exchange2(self):
        shaheerPrivateKey, shaheerPublicKey = rsa.genKeyPair(keySize=1024)
        
        message = 'Hello Shaheer'
        sendMessagetoShaheer = rsa.encryptMessage(message, shaheerPublicKey)
        recieveMessage = rsa.decryptMessage(sendMessagetoShaheer, shaheerPrivateKey)
        
        self.assertEqual(recieveMessage, "Hello Shaheer")
    
    def test_asymmetric_key_exchange3(self):
        shaheerPrivateKey, shaheerPublicKey = rsa.genKeyPair(keySize=4096)
        
        message = 'Hello Shaheer'
        sendMessagetoShaheer = rsa.encryptMessage(message, shaheerPublicKey)
        recieveMessage = rsa.decryptMessage(sendMessagetoShaheer, shaheerPrivateKey)
        
        self.assertEqual(recieveMessage, "Hello Shaheer")
    
    def test_asymmetric_key_exchange4(self):
        shaheerPrivateKey, shaheerPublicKey = rsa.genKeyPair(keySize=8192)
        
        message = 'Hello Shaheer'
        sendMessagetoShaheer = rsa.encryptMessage(message, shaheerPublicKey)
        recieveMessage = rsa.decryptMessage(sendMessagetoShaheer, shaheerPrivateKey)
        
        self.assertEqual(recieveMessage, message)
    
    def test_asymmetric_key_exchange5(self):
        shaheerPrivateKey, shaheerPublicKey = rsa.genKeyPair(keySize=16284)
        
        message = 'Hello Umar'
        sendMessagetoShaheer = rsa.encryptMessage(message, shaheerPublicKey)
        recieveMessage = rsa.decryptMessage(sendMessagetoShaheer, shaheerPrivateKey)
        
        self.assertEqual(recieveMessage, message)