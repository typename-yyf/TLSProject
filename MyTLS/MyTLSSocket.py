from socket import *
from typing.io import BinaryIO
import rsa
from MyTLS.MyTypes import ENCODE_METHOD, myTLSSocketType, messageType
from MyTLS.MyTSLExceptions import TCPSocketException
from MyTLS.MessageTypes import *
from time import time
from random import randint
from MyTLS.MyCipher import *


class TLSSocket:
    _encryMethod = None
    _keyMaker    = None
    _encoder     = None
    _hashEncoder = None

    _thisCert = None
    _oppCert  = None

    _tcpSocket = None

    _randNum1 = None
    _randNum2 = None
    _randNum3 = None

    __recvBuffer = None

    def __init__(self):
        self._tcpSocket = socket(AF_INET, SOCK_STREAM)
        self.__recvBuffer = bytes(0)

    def loadCert(self, certFile: str) -> None:
        self._thisCert = loadCert(certFile)

    def _setCert(self, cert: MyCert) -> None:
        self._thisCert = cert

    def __sendPackage(self, msg: bytes, end: int = 0) -> None:
        payload = self._hashEncoder.digestAndConcact(msg)
        payload = self._encoder.encrypt(payload)

        package = Payload.makeMessage(__payload__=payload, __end__=end)
        self._tcpSocket.send(package)

    def send(self, msg: bytes) -> None:
        msgLength = msg.__len__()
        i = 0

        if msg == b"":
            self.__sendPackage(msg, end=1)

        while i < msgLength:
            if i + myTLSSocketType.MAX_PACKAGE_LENGTH < msgLength:
                self.__sendPackage(msg[i: i + myTLSSocketType.MAX_PACKAGE_LENGTH])
            else:
                self.__sendPackage(msg[i:], end=1)
            i += myTLSSocketType.MAX_PACKAGE_LENGTH

    def sendFile(self, fd: BinaryIO):
        while True:
            buffer = fd.read(myTLSSocketType.MAX_PACKAGE_LENGTH)
            if buffer == b"":
                break
            self.send(buffer)

        self.send(bytes(0))


    def __recvPackage(self) -> bytes:
        header = self._tcpSocket.recv(messageType.HEADER_LENGTH)
        length = bytes2short(header[2: 4])
        if length == 0:
            return header
        body = self._tcpSocket.recv(length)
        return header + body

    def recv(self, nbytes: int, timeout: int = -1) -> bytes:
        recvBuffer = bytes(0)
        reservedValue = 0

        while reservedValue == 0:
            p = Payload(self.__recvPackage())

            payload = p.payload
            reservedValue = p.reserved

            payload = self._encoder.decrypt(payload)
            payload = self._hashEncoder.verifyAndSeparate(payload)
            recvBuffer += payload

        return recvBuffer

    def recvFile(self, fd: BinaryIO):
        while True:
            buffer = self.recv(4096)
            if buffer == b"":
                break
            fd.write(buffer)

    def close(self):
        self._tcpSocket.close()

    def _sendHelloMessage(self, randNum: int, encryMethod: int) -> None:
        helloMsg = HelloMessage.makeMessage(__time__=int(time()),
                                            __randomNum__=randNum,
                                            __encryMethod__=encryMethod)
        self._tcpSocket.send(helloMsg)
    def _recvHelloMessage(self) -> HelloMessage:
        return HelloMessage(self.__recvPackage())
    def _sendCertExchangeMessage(self, publicKey: rsa.PublicKey, owner: str, t: int) -> None:
        certMsg = certExchangeMessage.makeMessage(__publicKey__=publicKey, __owner__=owner, __time__=t)
        self._tcpSocket.send(certMsg)
    def _recvCertExchangeMessage(self) -> certExchangeMessage:
        return certExchangeMessage(self.__recvPackage())
    def _sendKeyExchangeMessage(self, key: bytes) -> None:
        keyMsg = keyExchangeMessage.makeMessage(__key__=key)
        self._tcpSocket.send(keyMsg)
    def _recvKeyExchangeMessage(self) -> keyExchangeMessage:
        return keyExchangeMessage(self.__recvPackage())
    def _sendHelloDoneMessage(self) -> None:
        self._tcpSocket.send(HelloDoneMessage.makeMessage())
    def _recvHelloDoneMessage(self) -> HelloDoneMessage:
        return HelloDoneMessage(self.__recvPackage())
    def _sendChangeCipherSpecMessage(self) -> None:
        self._tcpSocket.send(ChangeCipherSpecMessage.makeMessage())
    def _recvChangeCipherSpecMessage(self) -> ChangeCipherSpecMessage:
        return ChangeCipherSpecMessage(self.__recvPackage())
    def _sendFinishedMessage(self) -> None:
        fiMsg = "finished".encode(ENCODE_METHOD)
        fiMsg = self._hashEncoder.digestAndConcact(fiMsg)
        fiMsg = self._encoder.encrypt(fiMsg)
        fiMsg = FinishedMessage.makeMessage(fiMsg)
        self._tcpSocket.send(fiMsg)
    def _recvAndCheckFinishedMessage(self) -> FinishedMessage:
        fiMsg = FinishedMessage(self.__recvPackage())

        finishedMsg = self._encoder.decrypt(fiMsg.finishedMsg)
        finishedMsg = self._hashEncoder.verifyAndSeparate(finishedMsg)
        if finishedMsg != "finished".encode(ENCODE_METHOD):
            raise TCPSocketException("错误：finished报文验证错误，中断连接")

        return fiMsg

    def _setTCPSocket(self, tcpSocket: socket) -> None:
        self._tcpSocket = tcpSocket

    def __MyPRFBox(self, x: int, y: int, z: int) -> bytes:
        r = bytes(0)
        t = x
        for i in range(0, 4):
            t = (t * y) & 0xffffffff
            r += int2bytes(t ^ z)
        return r

    def __MyPRF(self, r1: int, r2: int, r3: int) -> (bytes, bytes, bytes, bytes, bytes, bytes):
        key1     = self.__MyPRFBox(r1, r2, r3)
        iv1      = self.__MyPRFBox(r1, r3, r2)
        hmacKey1 = self.__MyPRFBox(r2, r1, r3)
        key2     = self.__MyPRFBox(r2, r3, r1)
        iv2      = self.__MyPRFBox(r3, r1, r2)
        hmacKey2 = self.__MyPRFBox(r3, r2, r1)

        return key1, iv1, hmacKey1, key2, iv2, hmacKey2

    def _setUpEncodersAndDecoders(self, encryMethod: int, role: int) -> None:
        if encryMethod == messageType.ENCRY_METHOD_RSA_AES_SHA256:
            key1, iv1, hmacKey1, key2, iv2, hmacKey2 = self.__MyPRF(self._randNum1, self._randNum2, self._randNum3)
            if role == myTLSSocketType.ROLE_SERVER:
                self._encoder = MyAES(key1, key2, iv1, iv2, mode=AES.MODE_ECB)
                self._hashEncoder = MyHMac(hmacKey1, hmacKey2, method="sha256")
            elif role == myTLSSocketType.ROLE_CLIENT:
                self._encoder = MyAES(key2, key1, iv2, iv1, mode=AES.MODE_ECB)
                self._hashEncoder = MyHMac(hmacKey2, hmacKey1, method="sha256")
        else:
            pass
            #以后这里可以拓展

class TLSClient(TLSSocket):
    __isAnonymous = None
    __caConfirm   = None

    def __diffHandShakes(self) -> None:
        if self._encryMethod == messageType.ENCRY_METHOD_RSA_AES_SHA256:
            # =========================================================
            serverCert = self._recvCertExchangeMessage()
            self._oppCert = MyCert(serverCert.publicKey, None, serverCert.owner, serverCert.time)
            self._keyMaker = MyRSA((serverCert.publicKey, None))

            # =========================================================
            self._recvHelloDoneMessage()

            # =========================================================
            self._randNum3 = randint(1 << 31, 1 << 32)
            self._sendKeyExchangeMessage(key=self._keyMaker.encrypt(int2bytes(self._randNum3)))

            self._setUpEncodersAndDecoders(self._encryMethod, myTLSSocketType.ROLE_CLIENT)
        else:
            pass
            #以后这里可以拓展

    def __handShakes(self) -> None:
        if not self._tcpSocket:
            TCPSocketException("错误：未建立tcp套接字")

        if self.__isAnonymous == myTLSSocketType.SOCKET_NOT_ANONYMOUS:
            pass
            #以后这里可以拓展

        # =========================================================
        self._randNum1 = randint(1 << 31, 1 << 32)
        self._sendHelloMessage(randNum=self._randNum1, encryMethod=messageType.ENCRY_METHOD_RSA_AES_SHA256)

        # =========================================================
        serverHello = self._recvHelloMessage()
        self._randNum2 = serverHello.randomNum
        self._encryMethod = serverHello.encryMethod

        # =========根据不同加密套件来进行不同的通信协议==========
        self.__diffHandShakes()

        # =========================================================
        self._sendChangeCipherSpecMessage()

        # =========================================================
        self._sendFinishedMessage()

        # =========================================================
        self._recvChangeCipherSpecMessage()

        # =========================================================
        self._recvAndCheckFinishedMessage()

    def __init__(self,
                 isAnonymous = myTLSSocketType.SOCKET_ANONYMOUS,
                 caConfirm = myTLSSocketType.SOCKET_NOT_CACONFIRM):
        super().__init__()

        self.__isAnonymous = isAnonymous
        self.__caConfirm   = caConfirm

    def connect(self, addrTuple: tuple) -> None:
        self._tcpSocket.connect(addrTuple)
        self.__handShakes()

class TLSServer(TLSSocket):
    _port = None
    __connectTime = None

    def __init__(self):
        super().__init__()

    def __choseEncryptMethod(self, allMethods: int) -> int:
        return messageType.ENCRY_METHOD_RSA_AES_SHA256
        #以后这里可以拓展

    def __diffHandShakes(self) -> None:
        if self._encryMethod == messageType.ENCRY_METHOD_RSA_AES_SHA256:
            if not self._thisCert:
                raise TCPSocketException("错误：未加载证书")
            self._sendCertExchangeMessage(publicKey=self._thisCert.publicKey,
                                          owner=self._thisCert.owner,
                                          t=self._thisCert.time)
            self._sendHelloDoneMessage()
            self._keyMaker = MyRSA(keySet=(self._thisCert.publicKey, self._thisCert.privateKey))

            clientKeyExchange = self._recvKeyExchangeMessage()
            self._randNum3 = bytes2int(self._keyMaker.decrypt(clientKeyExchange.key))

            self._setUpEncodersAndDecoders(self._encryMethod, myTLSSocketType.ROLE_SERVER)
        else:
            pass
            #以后这里可以拓展

    def __handShakes(self) -> None:
        if not self._tcpSocket:
            raise Exception("错误：未建立tcp套接字")

        clientHello = self._recvHelloMessage()
        self._randNum1     = clientHello.randomNum
        self._encryMethod = self.__choseEncryptMethod(clientHello.encryMethod)
        self.__connectTime = clientHello.time

        self._randNum2 = randint(1 << 31, 1 << 32)
        self._sendHelloMessage(randNum=self._randNum2, encryMethod=self._encryMethod)

        self.__diffHandShakes()

        self._recvChangeCipherSpecMessage()

        self._recvAndCheckFinishedMessage()

        self._sendChangeCipherSpecMessage()

        self._sendFinishedMessage()

    def connect(self, addrTuple = None) -> None:
        if addrTuple:
            pass
            #以后这里可以拓展
        self.__handShakes()

    def bind(self, port: int) -> None:
        self._port = port
        self._tcpSocket.bind(("", port))

    def listen(self) -> None:
        self._tcpSocket.listen()

    def accept(self, autoConnect = myTLSSocketType.SERVER_AUTO_CONNECT):
        serverSocket, addr = self._tcpSocket.accept()
        tlsResponseSocket = TLSServer()
        tlsResponseSocket._setTCPSocket(serverSocket)
        tlsResponseSocket._setCert(self._thisCert)

        if autoConnect == myTLSSocketType.SERVER_AUTO_CONNECT:
            tlsResponseSocket.connect()

        return tlsResponseSocket
