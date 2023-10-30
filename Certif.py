import hashlib
import easygui
import bcrypt
import tqdm





def hashSha():
    mot=input("Votre mot a hacher : ")
    print(f"le haché de {mot} est {hashlib.sha256(mot.encode()).hexdigest()}")
def hashSalt():
    s = bcrypt.gensalt()
    mot = input("Votre mot a hacher : ")
    print(f"le haché de {mot} est {bcrypt.hashpw(mot.encode(), s).hex()} avec le Salt: {s.hex()}")
def attaqueDic():
    path = easygui.fileopenbox()
    with open(path,"r") as dic:
        mot=input("Votre mot a Attaquer : ")
        mot=hashlib.sha256(mot.encode()).hexdigest()
        lines = dic.readlines()
        tent=0
        for i in tqdm.tqdm(lines):
            tent+=1
            i=i.strip('\n')
            i=hashlib.sha256(i.encode()).hexdigest()
            if i == mot :
                return tent

def mHachage():

    while True:
        print("---------HACHAGE----------")
        print("1-Hacher avec SHA256")
        print("2-Hacher avec Bcrypt")
        print("3-Attaque dictionaire")
        print("q- Quitter")

        choix = input('Donnez votre choix : ')
        match choix:
            case '1':
                hashSha()
            case '2':
                hashSalt()
                break
            case '3':
                a = attaqueDic()

                if a == None:
                    print("J'ai rien Trouvé")

                else:
                    print(f"J'ai Trouver aprés {a} Tentaive")

            case 'q':
                    break
            case _:
                print("Merci d'introduire soit 1,2,3 ou bien q pour quitter")
