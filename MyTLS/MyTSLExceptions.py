class MyTLSExceptions(Exception):
    def __init__(self, info: str):
        super().__init__(info)

class WrongMessageException(MyTLSExceptions):
    def __init__(self, info: str):
        super().__init__(info)

class WrongKeyException(MyTLSExceptions):
    def __init__(self, info: str):
        super().__init__(info)

class TCPSocketException(MyTLSExceptions):
    def __init__(self, info: str):
        super().__init__(info)