import re
import string
import maskpass
import hashlib


#Fonction pour valider l'email
def isValidEmail(email):
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    if re.fullmatch(regex, email):
        return True
#Fonction pour valider le Mot de Pass
def isValidPwd(pwd):
    valid=True
    if len(pwd) >=8:
        if any(car in string.digits for car in pwd):
            if any(car in string.ascii_uppercase for car in pwd):
                if any(car in string.ascii_lowercase for car in pwd):
                    if any(car in string.punctuation for car in pwd):
                        return True
                    else:
                        print("au min un cart spécial")
                else:
                    print("au minimum une lettre miniscule")
            else:
                print("Au min une lettre maj")
        else:
            print("Au min un numérique")
    else:
        print("long == 8 ")
def exist(email):
    with open("SSIR.txt", "r") as file:
        lines = file.readlines()
        for line in lines :
            line = line.strip('\n')
            e=line.split(';')
            if  e[0] == email :
                return False
        file.close()
        return True
def ajoutEnregitrement():
    while True :
        email=input("Donnez votre email : ")
        if isValidEmail(email) :
            if  exist(email):
                while True:
                    p = maskpass.askpass(mask="")
                    if isValidPwd(p):
                        p=hashlib.sha256(p.encode()).hexdigest()
                        with open("SSIR.txt","a") as file:
                            file.write(f"{email};{p}\n")
                            print(f"Comte de {email} creé avec succès")
                            break
                    else:
                        print("merci de respecter les critére")
                break
            else:
                print("Votre Email est Deja Utiliser")
        else :
            print("Merci d'introduire un email valide ")


