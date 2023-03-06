import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import os
from tinyec import registry
import secrets
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
import random
import string

#Ahmet BOZBAY	150119861
#Anıl Batuhan ASLAN 150119656
#Yasin ÇÖREKÇİ	150119858
#5) Message Authentication Codes not included

keyPair = RSA.generate(bits=1024)    #generates 1024 bit pair key
pubKey = keyPair.publickey()         #Public key
print(keyPair)
def ECDH():      # Elliptic-Curve Diffie Helman function
    def compress(pubKey):
        return hex(pubKey.x) + hex(pubKey.y % 2)[2:]
    curve = registry.get_curve('brainpoolP256r1')

    alicePrivKey = secrets.randbelow(curve.field.n)  #Priv key for alice
    alicePubKey = alicePrivKey * curve.g   #public key for alice
    print("Alice public key:", compress(alicePubKey))

    bobPrivKey = secrets.randbelow(curve.field.n)   #Priv key for bob
    bobPubKey = bobPrivKey * curve.g    #public key for bob
    print("Bob public key:", compress(bobPubKey))

    print("Now exchange the public keys (e.g. through Internet)")

    aliceSharedKey = alicePrivKey * bobPubKey      # for shared key alicepriv * bobpublickey
    print("Alice shared key:", compress(aliceSharedKey))

    bobSharedKey = bobPrivKey * alicePubKey     # for shared key bobpriv * alicepublickey
    print("Bob shared key:", compress(bobSharedKey))

    print("Equal shared keys:", aliceSharedKey == bobSharedKey)  # they have to be same shared keys it turns Boolean
ECDH()
def SymmetricKeys():
    IV_SIZE = 16  # 128 bit, fixed for the AES algorithm
    KEY_SIZE = 32  # 256 bit meaning AES-256, can also be 128 or 192 bit
    SALT_SIZE = 16  # This size is arbitrary

    cleartext = b'This text is encrypted'
    password = b'decyrpt password is password'
    salt = os.urandom(SALT_SIZE)   #to generate random key
    derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,   #to crypto the text
                                  dklen=IV_SIZE + KEY_SIZE)
    iv = derived[0:IV_SIZE]     #according to 128 bits head part
    key = derived[IV_SIZE:]     #according to 128 bits tail part

    encrypted = salt + AES.new(key, AES.MODE_CFB, iv).encrypt(cleartext) #encrypting text
    print("The encrypted message is : "+str(encrypted))
    salt = encrypted[0:SALT_SIZE] # update salt_size accoring to encrypted text
    password =b'decyrpt password is password'
    derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,                     #
                                  dklen=IV_SIZE + KEY_SIZE)                             #
    iv = derived[0:IV_SIZE]                                                             # for decyrpt exctly opposite of the
    key = derived[IV_SIZE:]                                                             # process
    decrypted = AES.new(key, AES.MODE_CFB, iv).decrypt(encrypted[SALT_SIZE:])           #
    print("The decrypted message is : "+str(decrypted))                                 #
SymmetricKeys()

def digitalsignature():
    # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
    msg = b'vVVWReWMCvgILxtgOVrLVcwbBjcIgvGJrcDHZIxXGYZQbZesodTlLoXuvhlUzAYlzajcNFsZKEmedIUsiGVisXeHzNCNyOwIkcmoNdFVEfse' \
          b'VXcxWuPOqfSPnoGeDcmGfKPunzaLmlmDbEWpspXEPAOaVYXUYstJTTMTkkCzdkVfoqEWdqKDQZhMkHhbWfFHHAnpKHPfnDsllrrvrOrNInmT' \
          b'kNRflpspyfCnGojWoIDQiblRrkkjOaWAjMdkvkYXsLxpTSSpaFBjXegcpJLmZUYpmyNGFADUQHlRHwxgFIpDmEOrBrFGzUOgBpQDBBrtoXZit' \
          b'VbxFyVDDsAJMksyUuAEXTeyFicpAUbotoVKNDihpkDMMkzcqiqsGJsKYEwmYjXAAezDhasdCamPqraMxDghScNZmVDZYDXaApNAXpbfeCiBs' \
          b'dRvvtFJDhSXLsNEGGrxJKTSrDimGuvFiKAMCiXrcpprPtrhYUOHLFjYpWMHCsNSxffxrnxpIXZBJwnujsdTMewiCFLiCVeOlbfAdrCuNPgE' \
          b'QTHMxttXtynagfDaXtFiYthTxgTspcwSvutAtyxojDwkXHdiYVBJpeXvVzukbLheiBEFGwGxzuFQaYtDahoeImGPWCWmlMbNZAALsULGNMgk' \
          b'IWOURORcnXoyIAQqcXPMEzNKrmoEMPTibKwSaWMDLGdDVJcRwMpLtroGcoAQtKeQRwNWTPnnCkZeWuKKmunmRJlNyaQzTYtxrHBAIudxAzZ' \
          b'RcrPTPgTLsYhOQxxPxLVhOejoMGQBLRfNhvFjvgwJohKFqCvbwaSIBPJuhuTWRQaOHHKoqXSpSCUFhpktuehrBsscuhOQMZMSQrSxuyRiPS' \
          b'iRYwryudbFzvCTdjElsoSilzkaduvDGGESxctEgoApTCgerknvzAzwUIeDjwuDVNjfYhNIysVUfEekTClVQxhFtiSmdBBOzpadIzzAGzyxfu' \
          b'ATTJLXralMqGkmBVNYIOwyPknCILTG'
    hash = SHA256.new(msg) #Hashing with 256 bit
    signer = PKCS115_SigScheme(keyPair) #signs to text with keypair
    signature = signer.sign(hash) #hashing the sign
    print("Signature:", binascii.hexlify(signature))

    # Verify valid PKCS#1 v1.5 signature (RSAVP1)
    msg = b'Message for RSA signing'  #signer key
    hash = SHA256.new(msg)  #hashing sign
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash, signature) #verify
        print("Signature is valid.")
    except:
        print("Signature is invalid.")

    # Verify invalid PKCS#1 v1.5 signature (RSAVP1)
    msg = b'A tampered message'
    hash = SHA256.new(msg)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash, signature)
        print("Signature is valid.")
    except:
        print("Signature is invalid.")
digitalsignature()

class AESCipher128(object):

    def __init__(self, key):
        self.bs = AES.block_size #fixed aes algorithm 128 bit block size
        self.key = key  #key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = b'\0'*16 #Default zero based bytes[16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(cipher.encrypt(raw.encode())) #returns encrypted message

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

key = b'keyneedto16words' #key for decrypting text
a = AESCipher128(key)

def random_char(y): #random text generator for 1MB function
    return "b'" + ''.join(random.choice(string.ascii_letters) for x in range(y)) + "'"
msg = random_char(8000000) # 1 MB = 8000000 bits
print('AES 128 bit key in CBC mode. Encrypted message is:'+str(a.encrypt(str(msg))))


class AESCipher256(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

key='256 bit'
b=AESCipher256(key)
print('AES 256 bit key in CBC mode. Encrypted message is:'+str(b.encrypt(str(msg))))
