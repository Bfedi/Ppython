from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def menuCer():
    key = ''
    #print(type(key))
    while True:
        print("---------Certificat----------")
        print("1-Generer une paire de clés")
        print("2-Generer un certificat autosigné")
        print("3-chiffrer un message de votre choix")
        print("q- Quitter")
        choix = input('Donnez votre choix : ')
        match choix:
            case '1':
                key=keyGen()
            case '2':
                if key!='':
                    generate_selfsigned_cert("any",key)
                else:
                    print("generer une clé avant de")
            case '3':
                print("En cours de construction")
            case 'q':
                break
            case _:
                print("Merci d'introduire soit 1,2,3,4,5 ou bien q pour quitter")


def keyGen():

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        print("Clé generer avec succès")
        return key

def generate_selfsigned_cert(hostname, key):

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
    alt_names = [x509.DNSName(hostname)]
    san = x509.SubjectAlternativeName(alt_names)
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(f"Cert\\certificat\\certif.pem", "wt") as cert:
        cert.write(cert_pem)
    cert.close()
    with open(f"Cert\\certificat\\key.pem", "wt") as cle:
        cle.write(key_pem)

    print("Certificat génerer avec succès")

    #return cert_pem, key_pem
