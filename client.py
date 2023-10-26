from flask import Flask, render_template_string, request, redirect, url_for
from cryptography.hazmat.backends import default_backend
import requests
import sha256
import diffieHelman
import aes
import base64
import rsa
import pki
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

clientHTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Client</title>
</head>
<body>
    <h1 style="text-align: center; font-size: 70px; margin-top: 100px">I am Client</h1>
    
    <label for="crypt" style="text-align: center; margin-top: 300px; margin-left:850px; font-size:20px;">Select Cryptographic Type:</label>
    <select style="text-align: center; margin-top: 200px; font-size:20px;" id="crypt" name="crypt">
        <option value="symmetric">Symmetric</option>
        <option value="asymmetric">Asymmetric</option>
    </select>
    
    <form action="{{ url_for('send') }}" method="post">
        <label for="message" style="text-align: center; margin-top: 0px; margin-left:740px; font-size:20px;">Enter Message:</label>
        <input style="text-align: center; margin-top: 50px; font-size:20px;" type="text" id="message" name="message" required>

        <input type="hidden" name="crypt_type" id="crypt_type" value="">
        <button style= "font-size:20px;" type="submit">Send Message</button>
    </form>
    
    <script>
        var crypt = document.getElementById('crypt');
        var cryptTypeInput = document.getElementById('crypt_type');

        crypt.addEventListener('change', function() {
            cryptTypeInput.value = crypt.value;
            console.log(cryptTypeInput.value);
        });
        
        cryptTypeInput.value = crypt.value;
        console.log(cryptTypeInput.value);
    </script>
</body>
</html>
'''

clientPrivateKey1, clientPublicKey1 = diffieHelman.diffieHellmanAlgorithm(23, 5)
clientPrivateKey2=''
clientPublicKey2=''

@app.route('/')
def index():
    return render_template_string(clientHTML)

@app.route('/send', methods=['POST'])
def send():
    # Handshaking Stage 1: Negotiation of security methods and options
    message = request.form['message']
    cryptographyType = request.form['crypt_type']
    
    print("\nCryptographic Type:", cryptographyType)
    
    if cryptographyType == 'symmetric':
        # Handshaking Stage 2: Authentication (mutual for symmetric)
        # SHA-256
        sha256.msg = message
        sha256.hashedMsg = sha256.sha256Algorithm(sha256.msg)
        print("\nHashed Message:", sha256.hashedMsg)

        # Handshaking Stage 3: Secure Key Exchange and other secrets
        # Diffie-Hellman
        serverPublicKey1 = int(requests.get('http://127.0.0.1:5001/get_symmetric_public_key').text)
        sharedKey = diffieHelman.generateSharedKey(clientPrivateKey1, serverPublicKey1, 23)   
        print("Shared Key:", sharedKey)

        # AES
        encryptedMsg, iv = aes.encrypt(message, sharedKey)
        print("Encrypted Message:", encryptedMsg)
        print()

        #Sending to Server as one tuple
        encryptedMsg = base64.b64encode(encryptedMsg)
        encodedIv = base64.b64encode(iv).decode('utf-8')
        dictToSend = {'encryptedMsg': encryptedMsg, 'iv': encodedIv, 'hashedMsg': sha256.hashedMsg, 'cryptographyType': cryptographyType}

        requests.post('http://127.0.0.1:5001/receive', data=dictToSend)
        
    elif cryptographyType == 'asymmetric':
        # RSA
        # Generate RSA Key Pair
        clientPrivateKey2, clientPublicKey2 = rsa.genKeyPair()

        # Handshaking Stage 2: Authentication (Digital Signature)
        # CSR 
        clientCSR = pki.createCSR(clientPrivateKey2)
        print("\nClient CSR:", clientCSR)
        
        #Load CA keys
        privateKeyCA, certCA = pki.loadCAKeys()
        privateKeyCA = privateKeyCA.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm=serialization.NoEncryption()
        )
        certCA = certCA.public_bytes(encoding=serialization.Encoding.PEM)
        print("\nCA Certificate:", certCA)
        
        # Sign CSR
        signedClientCertificate = pki.signCSR(privateKeyCA, certCA, clientCSR)
        signedClientCertificate = signedClientCertificate.decode('utf-8')
        print("\nSigned Client Certificate:", signedClientCertificate)
        
        
        # Handshaking Stage 3: Secure Key Exchange and other secrets
        #Server Key
        serverPublicKeyBytes = requests.get('http://127.0.0.1:5001/get_asymmetric_public_key').content
        serverPublicKey2 = serialization.load_pem_public_key(serverPublicKeyBytes, backend=default_backend())

        #Encrypt with server's public key
        encryptedMsg = rsa.encryptMessage(message, serverPublicKey2)
        encryptedMsg = base64.b64encode(encryptedMsg).decode('utf-8')
        encryptedMsg = base64.b64encode(base64.b64decode(encryptedMsg)).decode('utf-8')
        print("\nEncrypted Message:", encryptedMsg)
        print()
        
        # Sending to Server 
        requests.post('http://127.0.0.1:5001/receive', data={'encryptedMsg': encryptedMsg, 'cryptographyType': cryptographyType, 'signedClientCertificate': signedClientCertificate})
        
    return redirect(url_for('index'))

@app.route('/get_symmetric_public_key')
def get_symmetric_public_key():
    return str(clientPublicKey1)

@app.route('/get_asymmetric_public_key')
def get_asymmetric_public_key():
    return str(clientPublicKey2)

if __name__ == '__main__':
    app.run(debug=True)
