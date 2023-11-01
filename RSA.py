from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

#global Msg
#Menu Du chiffrement RSA
def mRsa():
    Sig=''
    while True:
        print("---------RSA----------")
        print("1-Generer une paire de clés")
        print("2-Chiffré un Message de votre Choix")
        print("3-Dechifrer un Message le Message")
        print("4-Signer un message")
        print("5-verifier Signature")
        print("q- Quitter")

        choix = input('Donnez votre choix : ')


        match choix:
            case '1':
                genkey()
            case '2':
                Msg=chiffrMsg()
            case '3':
                dechiffrMsg(Msg)
            case '4':
                Sig=signeMsg()

            case '5':
                if Sig!='':
                    verifigne(Sig)
                else:
                    print("Signer un message avant S'il vous plait!!")
            case 'q':
                break
            case _:
                print("Merci d'introduire soit 1,2,3,4,5 ou bien q pour quitter")

#Generation de clé
def genkey():
    pub = f"RSA\\public.pub"
    pri = f"RSA\\private.pem"
    key = RSA.generate(1024)
    k = key.exportKey('PEM')
    p = key.publickey().exportKey('PEM')
    with open(pub,"wb") as public:
        public.write(p)
    public.close()
    with open(pri,"wb") as private:
        private.write(k)
    private.close()

#chiffrement de clé
def chiffrMsg():
    pub = f"RSA\\public.pub"
    mot=input("entrer le mot a chifrer: ")
    with open(pub, "rb") as public:
        cle = RSA.import_key(public.read())
    cipher = PKCS1_OAEP.new(cle)
    ciphertext = cipher.encrypt(mot.encode())
    print(ciphertext.hex())
    public.close()
    return ciphertext

#Dechifrement
def dechiffrMsg(Msg):
    pri = f"RSA\\private.pem"
    with open(pri, "rb") as private:
        cle = RSA.import_key(private.read())
    cipher = PKCS1_OAEP.new(cle)
    message_dechiffre = cipher.decrypt(Msg)
    print(f"Le message Dechifrer: {message_dechiffre.decode("utf-8")}")
    private.close()

#signer un message
def signeMsg():
    mot = input("entrer le mot a signer: ")
    pri = f"RSA\\private.pem"
    with open(pri, "rb") as private:
        cle=RSA.import_key(private.read())
    signer=PKCS1_v1_5.new(cle)
    hash= SHA256.new(mot.encode())
    print(f"Signature de {mot} effectuer, Signature : {signer.sign(hash).hex()}")
    return  signer.sign(hash)

#verifier la signature
def verifigne(sign):
    pub = f"RSA\\public.pub"
    mot = input("entrer le mot a verifier : ")
    with open(pub, "rb") as public:
        cle=RSA.import_key(public.read())
    signer=PKCS1_v1_5.new(cle)
    digest=SHA256.new()
    digest.update(mot.encode())
    verified = signer.verify(digest,sign)
    if verified:
        print(f"Verification signature avec succès : {mot},Signature : {sign.hex()}")
    else:
        print("Verification signature echouée")


