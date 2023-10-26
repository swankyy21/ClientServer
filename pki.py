from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime


def createCSR(privateKey):
    clientCSR = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'CA'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'My Company'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'my common name'),
        ])
    ).sign(privateKey, hashes.SHA256(), default_backend())
    
    clientCSR = clientCSR.public_bytes(serialization.Encoding.PEM)
    
    return clientCSR


def loadCAKeys():
    # Generate CA private key
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create CA subject
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'CA'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'My CA'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'My CA'),
    ])

    # Create self-signed CA certificate
    caCert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years validity
    ).sign(
        ca_private_key,
        hashes.SHA256(),
        default_backend()
    )
    return ca_private_key, caCert


def signCSR(private_key, caCert, client_csr):
    # Load CA private key
    ca_private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )
    caCert = x509.load_pem_x509_certificate(caCert, default_backend())
    client_csr = x509.load_pem_x509_csr(client_csr, default_backend())

    # Sign the CSR with the CA private key
    signedClientCert = x509.CertificateBuilder().subject_name(
        client_csr.subject
    ).issuer_name(
        caCert.subject
    ).public_key(
        client_csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)  # Adjust validity period as needed
    ).sign(
        ca_private_key,
        hashes.SHA256(),
        default_backend()
    )
    client_cert_pem = signedClientCert.public_bytes(encoding=serialization.Encoding.PEM)

    return client_cert_pem

