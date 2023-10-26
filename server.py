from flask import Flask, render_template_string, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import cryptography
import requests
import diffieHelman
import aes
import sha256
import base64
import rsa
import pki


app = Flask(__name__)

serverHTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Server</title>
</head>
<body>
    <h1 style="text-align: center; margin-top: 100px; font-size:70px">I am Server</h>
    <p style="text-align: center; margin-top: 300px; font-size:40px; ">Message From Client: {{ clientMessage }}</p>
</body>
</html>
'''

serverPrivateKey1, serverPublicKey1 = diffieHelman.diffieHellmanAlgorithm(23, 5)
serverPrivateKey2, serverPublicKey2 = rsa.genKeyPair()

clientMessage = ''

@app.route('/')
def server():
    return render_template_string(serverHTML, clientMessage=clientMessage)

@app.route('/receive', methods=['POST'])
def receive():
    # Handshaking Stage 1: Negotiation of security methods and options
    global clientMessage
    encryptionType = request.form.get('cryptographyType')
    print("\nEncryption Type:", encryptionType)
    
    if encryptionType == 'symmetric':
        # Handshaking Stage 2: Authentication (mutual for symmetric)
        msgFromClient = base64.b64decode(request.form['encryptedMsg'])
        hashedMsgFromClient = request.form['hashedMsg']
        decodedIv = base64.b64decode(request.form['iv'])
        
        # Handshaking Stage 3: Secure Key Exchange
        # Diffie-Hellman
        clientPublicKey1 = int(requests.get('http://127.0.0.1:5000/get_symmetric_public_key').text)
        sharedKey = diffieHelman.generateSharedKey(serverPrivateKey1, clientPublicKey1, 23)
        print("Shared Key :", sharedKey)
        
        # AES
        decryptedMsg = aes.decrypt(msgFromClient, sharedKey, decodedIv)

        # SHA-256
        sha256.msg = decryptedMsg
        sha256.hashedMsg = sha256.sha256Algorithm(sha256.msg)

        # Integrity check
        if sha256.hashedMsg != hashedMsgFromClient:
            print("\nMessage has been tampered!")
            return 'Message has been tampered!'

        clientMessage = decryptedMsg
        print("Decrypted Message:", decryptedMsg)
        print()
        
    elif encryptionType == 'asymmetric':
        # Data from client
        msgFromClient = (request.form['encryptedMsg'])
        msgFromClient = base64.b64decode(msgFromClient)
        signedClientCertificate = request.form['signedClientCertificate']
        print("\nClient Certificate:", signedClientCertificate)
        
        # Load CA private key and certificate
        privateKeyCA, certificateCA = pki.loadCAKeys()
        publicKeyCA = certificateCA.public_key()
        signedClientCert = x509.load_pem_x509_certificate(signedClientCertificate.encode('utf-8'), default_backend())
        
        # Handshaking Stage 2: Authentication (Digital Signature)
        try:
            publicKeyCA.verifier(
                signature=signedClientCert.signature,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            print("\nSignature verified successfully.")
            print()
            
            # Handshaking Stage 3: Secure Key Exchange
            # RSA 
            # Decryption using private key
            decryptedMsg = rsa.decryptMessage(msgFromClient, serverPrivateKey2)
            clientMessage = decryptedMsg
            print("\nDecrypted Message:", decryptedMsg)
            print()     
        except cryptography.exceptions.InvalidSignature:
            print("\nSignature verification failed.")
            print("\n Message has been tempered")
            print()
        
    return 'Message received successfully!'

@app.route('/get_symmetric_public_key')
def get_symmetric_public_key():
    return str(serverPublicKey1)

@app.route('/get_asymmetric_public_key')
def get_asymmetric_public_key():
    serverPublicKeyBytes = serverPublicKey2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serverPublicKeyBytes

if __name__ == '__main__':
    app.run(debug=True, port=5001)
