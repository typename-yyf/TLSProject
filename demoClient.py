from MyTLS.MyTLSSocket import *

connectSocket = TLSClient()
connectSocket.connect(("localhost", 8080))

connectSocket.send("我需要mokou.jpg文件！".encode("gbk"))

msg = connectSocket.recv(2048).decode("gbk")
print("对方说：", msg)

fd = open("clientDir/mokou.jpg", "wb")
connectSocket.recvFile(fd)

msg = connectSocket.recv(2048).decode("gbk")
print("对方说：", msg)

connectSocket.close()