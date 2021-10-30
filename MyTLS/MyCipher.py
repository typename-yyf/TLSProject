from Crypto.Cipher import AES
from MyTLS.MyTSLExceptions import WrongKeyException
from MyTLS.MyTypes import myCipherType
from MyTLS.Extras import *
from time import time
import rsa
import hmac

class MyAES:
    __mode = None
    __encodeKey  = None
    __encodeIV   = None
    __decodeKey  = None
    __decodeIV   = None

    __aesEncoder = None
    __aesDecoder = None

    def __init__(self,
                 enKey: bytes,
                 deKey: bytes,
                 enIV: bytes = None,
                 deIV: bytes = None,
                 mode: int = AES.MODE_ECB):

        self.__encodeKey = enKey
        self.__decodeKey = deKey
        self.__encodeIV = enIV
        self.__decodeIV = deIV
        self.__mode = mode

    def encrypt(self, msg: bytes) -> bytes:
        if not self.__aesEncoder:
            if self.__mode != AES.MODE_ECB:
                self.__aesEncoder = AES.new(self.__encodeKey, self.__mode, self.__encodeIV)
            else:
                self.__aesEncoder = AES.new(self.__encodeKey, self.__mode)

        tail = bytes(16 - ((msg.__len__() + 2) % 16))
        leng = bytes(short2bytes(msg.__len__()))

        return self.__aesEncoder.encrypt(leng + msg + tail)

    def decrypt(self, msg: bytes) -> bytes:
        if not self.__aesDecoder:
            if self.__mode != AES.MODE_ECB:
                self.__aesDecoder = AES.new(self.__decodeKey, self.__mode, self.__decodeIV)
            else:
                self.__aesDecoder = AES.new(self.__decodeKey, self.__mode)

        tmsg = self.__aesDecoder.decrypt(msg)
        leng = bytes2short(tmsg[0: 2])
        return tmsg[2: 2 + leng]

class MyRSA:
    __publicKey  = None
    __privateKey = None

    def __init__(self, keySet: tuple = myCipherType.RSA_NEWKEYSET):
        if not keySet[0]:
            (self.__publicKey, self.__privateKey) = rsa.newkeys(myCipherType.RSA_KEYLENGTH)
        else:
            (self.__publicKey, self.__privateKey) = keySet

    def encrypt(self, msg: bytes) -> bytes:
        return rsa.encrypt(msg, self.__publicKey)

    def decrypt(self, msg: bytes) -> bytes:
        if not self.__privateKey:
            raise WrongKeyException("错误：RSA私钥未初始化，不可用于解密")
        return rsa.decrypt(msg, self.__privateKey)

    def getPublicKey(self) -> rsa.PublicKey:
        return self.__publicKey

    def getPrivateKey(self) -> rsa.PrivateKey:
        return self.__privateKey

    @staticmethod
    def generatePublicKey(n: int, e: int) -> rsa.PublicKey:
        return rsa.key.PublicKey(n, e)

    @staticmethod
    def generatePrivateKey(n: int, e: int, d: int, p: int, q: int) -> rsa.PrivateKey:
        return rsa.key.PrivateKey(n, e, d, p, q)

class MyHMac:
    __method = None
    __key    = None
    __verKey = None
    __hashLength = None

    def __init__(self, key: bytes, verKey: bytes, method: str = "sha256"):
        self.__method = method
        self.__key    = key
        self.__verKey = verKey
        if method == "sha256":
            self.__hashLength = 32

    def digest(self, msg: bytes) -> bytes:
        return hmac.digest(self.__key, msg, self.__method)

    def verify(self, msg: bytes) -> bytes:
        return hmac.digest(self.__verKey, msg, self.__method)

    def digestAndConcact(self, msg: bytes) -> bytes:
        return msg + hmac.digest(self.__key, msg, self.__method)

    def verifyAndSeparate(self, msg: bytes) -> bytes:
        realMsgLength = msg.__len__() - self.__hashLength
        realMsg = msg[0: realMsgLength]

        oldHash = msg[realMsgLength:]
        newHash = self.verify(realMsg)

        if oldHash != newHash:
            raise WrongKeyException("错误：hmac检查不相等")
        return realMsg

class MyCert:
    publicKey = None
    privateKey = None
    owner = None
    time = None

    def __init__(self, __publicKey__, __privateKey__, __owner__, __time__):
        self.publicKey = __publicKey__
        self.privateKey = __privateKey__
        self.owner = __owner__
        self.time = __time__

def makeCert(filename: str, owner: str) -> None:
    fd = open(filename, "w")
    (publicKey, privateKey) = rsa.newkeys(myCipherType.RSA_KEYLENGTH)

    content = "publicKey:" + str(publicKey.n) + ":" +    \
              str(publicKey.e) + "\n" +    \
              "privateKey:" + str(privateKey.n) + ":" +   \
              str(privateKey.e) + ":" +   \
              str(privateKey.p) + ":" +   \
              str(privateKey.d) + ":" +   \
              str(privateKey.q) + "\n" +   \
              "owner:" + owner + "\n" +               \
              "time:" + str(int(time()))

    fd.write(content)

def loadCert(filename: str) -> MyCert:
    fd = open(filename, "r")

    buf = fd.readline(2048).split(":")
    pbkn = int(buf[1])
    pbke = int(buf[2])

    buf = fd.readline(2048).split(":")
    pvkn = int(buf[1])
    pvke = int(buf[2])
    pvkp = int(buf[3])
    pvkd = int(buf[4])
    pvkq = int(buf[5])

    buf = fd.readline(2048).split(":")
    owner = buf[1][:buf[1].__len__() - 1]

    buf = fd.readline(2048).split(":")
    ttime = int(buf[1])

    pbk = rsa.PublicKey(pbkn, pbke)
    pvk = rsa.PrivateKey(pvkn, pvke, pvkd, pvkp, pvkq)

    return MyCert(pbk, pvk, owner, ttime)
