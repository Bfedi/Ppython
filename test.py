from socket import gethostname
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


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
generate(key)