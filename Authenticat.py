import hashlib
import maskpass
import Ajout
import Certif
import Hash
import RSA




def authentifier():
    a=input("entrer votre email: ")
    b=maskpass.askpass(mask="")
    b=hashlib.sha256(b.encode()).hexdigest()
    with open('SSIR.txt' ,'r') as file:
        lines = file.readlines()
        for line in lines :
            line = line.strip('\n')
            if  line == (f"{a};{b}") :
                print(f"bien venue {a}")
                menuS()
                break
        else:
            print("Merci de verifier le login/mot de pass ?")





def menuP():
    while True :
        print("1- Crée un compte")
        print("2- S'authentifier")
        print("q- Quitter")

        choix = input('Donnez votre choix : ')
        match choix:
            case '1':
                Ajout.ajoutEnregitrement()
            case '2':
                authentifier()
            case 'q':
                break
            case _:
                print("Merci d'introduire soit 1,2, ou bien 3")

def menuS():
    while True:
        print("---------RSA----------")
        print("1-Pour Menu Hashage")
        print("2-Pour Menu Chiffrement RSA")
        print("3-Certificat RSA")
        print("q- Quitter")
        choix = input('Donnez votre choix : ')
        match choix:
            case '1':
                Hash.mHachage()
            case '2':
                RSA.mRsa()
            case '3':
                Certif.menuCer()
            case 'q':
                break
            case _:
                print("Merci d'introduire soit 1,2,3 ou bien q pour quitter")














menuP()