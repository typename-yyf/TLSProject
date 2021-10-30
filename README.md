# 简易TLS实现(^^
（老师要求的）

## 所有文件
    .
    ├── MyTLS
    │   ├── Extras.py
    │   ├── MessageTypes.py
    │   ├── MyCipher.py
    │   ├── MyTLSSocket.py
    │   ├── MyTSLExceptions.py
    │   ├── MyTypes.py
    │   └── __init__.py
    ├── README.md
    ├── clientDir
    ├── demoClient.py
    ├── demoServer.py
    ├── requirements.txt
    └── serverDir
        ├── ServerCert.mycert
        └── mokou.jpg

## demo

先运行demoServer.py，再运行demoClient.py

服务器和客户端之间会建立起一个自己实现的简单TLS连接，然后通过这个连接来传输一些文本信息和一个文件（在两个文件夹之间传输）

    python3 demoServer.py &
    python3 demoClient.py

## clientDir

需要自己在项目下创建一个空的clientDir文件夹

## 接口
MyTLS的使用方法和普通的python socket没有太大区别，看看demo就知道咋用了

## 之后还会更新一点点内容（还没做完）
