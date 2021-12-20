import base64
import hashlib
# from Crypto import Random
# from Crypto import AES
from Crypto.Cipher import AES
# from Crypto import get_random_bytes
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher(object):

    def __init__(self, key=None, hash_key=None, iv=None):
        # self.bs = AES.block_size
        # print('block size is set to: %s' % self.bs)
        # self.bs = 128
        if hash_key:
            self.key = hash_key
        else:
            self.key = hashlib.sha256(key.encode()).digest()
        # self.iv = None
        # self.cipher = None
        # self.generate_cipher()
        if not iv:
            iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        self.iv = iv

    def encrypt_part(self, raw):
        return self.cipher.encrypt(raw)

    def decrypt_part(self, enc):
        # return self._unpad(self.cipher.decrypt(enc))
        return self.cipher.decrypt(enc)

    def encrypt(self, raw):
        # iv = Random.new().read(AES.block_size)
        # iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        # print('iv is: %s' % iv)
        padded = pad(raw, 16)
        # print(f'padded: {padded}')
        # print(f'last byte: {ord(padded[len(padded)-1:])}')
        return base64.b64encode(self.iv + cipher.encrypt(padded))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        # iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(enc[AES.block_size:]), 16)
        # return cipher.decrypt(enc[AES.block_size:])

    @staticmethod
    def pad2(s):
        if len(s) % 16 != 0:
            length = 16 - (len(s) % 16)
            s += bytes([length]) * length
            # s += b'\x00' * length
        # else:
            # print('padding is not need (%s)' % (len(s) % 16))
        # return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
        # s += (0).to_bytes(length, byteorder='big')
        return s

    @staticmethod
    def pad(s):
        return pad(s, 16)

    @staticmethod
    def unpad(s):
        # return s[:-ord(s[len(s)-1:])]
        # return s[:-s[-1]]
        # print(f'trying to unpad: {s}')
        return unpad(s, 16)
