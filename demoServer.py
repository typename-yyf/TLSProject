from MyTLS.MyTLSSocket import *

listenSocket = TLSServer()
listenSocket.loadCert("serverDir/ServerCert.mycert")
listenSocket.bind(8080)
listenSocket.listen()

while 1:
    connectSocket = listenSocket.accept()

    msg = connectSocket.recv(2048).decode("gbk")
    print("对方说：", msg)

    connectSocket.send("Ok，马上就来！".encode("gbk"))

    fd = open("serverDir/mokou.jpg", "rb")
    connectSocket.sendFile(fd)

    connectSocket.send("传输完毕！".encode("gbk"))

    connectSocket.close()
