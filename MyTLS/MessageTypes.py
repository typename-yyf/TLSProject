from MyTLS.MyTSLExceptions import WrongMessageException
from MyTLS.Extras import *
from MyTLS.MyTypes import *
import rsa

class AllMessages:
    version  = None
    type     = None
    reserved = None
    length   = None
    data     = None

    def __init__(self, msg: bytes):
        if msg.__len__() < 4:
            raise WrongMessageException("错误：报文长度过小")

        self.version  = msg[0] & 0xf0
        self.type     = msg[0] & 0x0f
        self.reserved = msg[1]
        self.length   = (msg[2] << 8) + msg[3]
        self.data     = msg[4:]

    def _getNextHeader(self, msg: bytes) -> (int, bytes):
        if msg.__len__() < 2:
            raise WrongMessageException("错误：报文头长度过小")

        length = (msg[0] << 8) + msg[1]
        if msg.__len__() < 2 + length:
            raise WrongMessageException("错误：错误的报文格式")

        nextHeader = msg[2: length + 2]

        return length, nextHeader

    def _getHeader(self) -> list:
        headerIndex = 0
        msgLength   = self.data.__len__()
        header      = []

        while headerIndex < msgLength:
            headerLength, nextHeader = self._getNextHeader(self.data[headerIndex:])
            headerIndex += 2 + headerLength
            header.append(nextHeader)

        return header

    @staticmethod
    def makeBasicMessage(__type__: int,
                         __length__: int,
                         __version__ = messageType.VERSION_MYTLS1,
                         __reserved__ = 0x0) -> bytes:
        return bytes([__version__ + __type__, __reserved__]) + short2bytes(__length__)

class HelloMessage(AllMessages):
    time        = None
    randomNum   = None
    encryMethod = None

    def __init__(self, msg: bytes):
        super().__init__(msg)

        if self.type != messageType.TYPE_HELLO:
            raise WrongMessageException("错误：Hello报文类型错误")

        header = self._getHeader()
        if header.__len__() != 3:
            raise WrongMessageException("错误：Hello报文格式错误")

        self.time        = bytes2int(header[0][0: 4])
        self.randomNum   = bytes2int(header[1][0: 4])
        self.encryMethod = bytes2int(header[2][0: 4])

    @staticmethod
    def makeMessage(__time__: int, __randomNum__: int, __encryMethod__: int) -> bytes:
        msg = AllMessages.makeBasicMessage(__type__=messageType.TYPE_HELLO,
                                           __length__=18)

        length_4 = short2bytes(4)
        msg += length_4 + int2bytes(__time__) + \
               length_4 + int2bytes(__randomNum__) + \
               length_4 + int2bytes(__encryMethod__)

        return msg

class certExchangeMessage(AllMessages):
    publicKey = None
    owner     = None
    time      = None

    def __init__(self, msg: bytes):
        super().__init__(msg)

        if self.type != messageType.TYPE_CERTEXCHANGE:
            raise WrongMessageException("错误：Certificate Exchange报文类型错误")

        header = self._getHeader()
        if header.__len__() != 3:
            raise WrongMessageException("错误：Certificate Exchange报文格式错误")

        t = header[0].decode(ENCODE_METHOD).split(" ")
        tn = int(t[0])
        te = int(t[1])

        self.publicKey = rsa.PublicKey(tn, te)
        self.owner     = header[1].decode(ENCODE_METHOD)
        self.time      = bytes2int(header[2][0: 4])

    @staticmethod
    def makeMessage(__publicKey__: rsa.PublicKey, __owner__: str, __time__: int) -> bytes:
        ttMsg = (str(__publicKey__.n) + " " + str(__publicKey__.e)).encode(ENCODE_METHOD)
        length_ = short2bytes(ttMsg.__len__())
        tMsg = length_ + ttMsg

        ttMsg = __owner__.encode(ENCODE_METHOD)
        length_ = short2bytes(ttMsg.__len__())
        tMsg += length_ + ttMsg

        ttMsg = int2bytes(__time__)
        length_ = short2bytes(4)
        tMsg += length_ + ttMsg

        msg = AllMessages.makeBasicMessage(__type__=messageType.TYPE_CERTEXCHANGE,
                                           __length__=tMsg.__len__())

        return msg + tMsg

class keyExchangeMessage(AllMessages):
    key = None

    def __init__(self, msg: bytes):
        super().__init__(msg)

        if self.type != messageType.TYPE_KEYEXCHANGE:
            raise WrongMessageException("错误：Key Exchange报文类型错误")

        header = self._getHeader()
        if header.__len__() != 1:
            raise WrongMessageException("错误：Key Exchange报文格式错误")

        self.key = header[0]

    @staticmethod
    def makeMessage(__key__: bytes) -> bytes:
        msg = AllMessages.makeBasicMessage(__type__=messageType.TYPE_KEYEXCHANGE,
                                           __length__=2 + __key__.__len__())

        msg += short2bytes(__key__.__len__()) + __key__
        return msg

class HelloDoneMessage(AllMessages):
    def __init__(self, msg: bytes):
        super().__init__(msg)
        if self.type != messageType.TYPE_HELLODONE:
            raise WrongMessageException("错误：Hello Done报文类型错误")

    @staticmethod
    def makeMessage() -> bytes:
        msg = AllMessages.makeBasicMessage(__type__=messageType.TYPE_HELLODONE,
                                           __length__=0)
        return msg

class ChangeCipherSpecMessage(AllMessages):
    def __init__(self, msg: bytes):
        super().__init__(msg)

        if self.type != messageType.TYPE_CHANGECIPHERSPEC:
            raise WrongMessageException("错误：Change Cipher Spec报文类型错误")

    @staticmethod
    def makeMessage() -> bytes:
        msg = AllMessages.makeBasicMessage(__type__=messageType.TYPE_CHANGECIPHERSPEC,
                                           __length__=0)
        return msg

class FinishedMessage(AllMessages):
    finishedMsg = None

    def __init__(self, msg: bytes):
        super().__init__(msg)
        if self.type != messageType.TYPE_FINISHED:
            raise WrongMessageException("错误：Finished报文类型错误")

        header = self._getHeader()
        if header.__len__() != 1:
            raise WrongMessageException("错误：Finished报文格式错误")

        self.finishedMsg = header[0]

    @staticmethod
    def makeMessage(__finishedMsg__: bytes) -> bytes:
        msg = AllMessages.makeBasicMessage(__type__=messageType.TYPE_FINISHED,
                                           __length__=2 + __finishedMsg__.__len__())
        return msg + short2bytes(__finishedMsg__.__len__()) + __finishedMsg__

class Payload(AllMessages):
    payload = None

    def __init__(self, msg: bytes):
        super().__init__(msg)
        if self.type != messageType.TYPE_PAYLOAD:
            raise WrongMessageException("错误：payload报文类型错误")

        self.payload = self.data

    @staticmethod
    def makeMessage(__payload__: bytes, __end__ = 0) -> bytes:
        msg = AllMessages.makeBasicMessage(__type__=messageType.TYPE_PAYLOAD,
                                           __length__=__payload__.__len__(),
                                           __reserved__=__end__)
        return msg + __payload__
