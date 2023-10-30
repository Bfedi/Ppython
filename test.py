from socket import gethostname
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509



def keyGen():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    print("Clé generer avec succès")
    return key
key=keyGen()
def generate(key):
    cert = crypto.X509()
    cert.get_subject().C = 'TN'
    cert.get_subject().ST = 'TUNIS'
    cert.get_subject().L = 'TUNIS'
    cert.get_subject().O = 'SSIR'
    cert.get_subject().OU = 'SSIR2N'
    cert.get_subject().CN = gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')
    with open("Cert\\certificat\\certif.pem", 'wt') as fd:
        fd.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(f"Cert\\certificat\\key.pem", "wt", 'wt') as fd:
        fd.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


def ciferM():
    # Load the self-signed certificate and private key
    with open("Cert\\certificat\\certif.pem", "rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    with open("Cert\\certificat\\key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    # Message to be encrypted
    message = b"Hello, this is a secret message."

    # Encrypt the message using the public key from the certificate
    encrypted_message = certificate.public_key().encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the message using the private key
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Original Message:", message.decode("utf-8"))
    print("Crypted message:", encrypted_message.hex())
    print("Decrypted Message:", decrypted_message.decode("utf-8"))

#generate(key)