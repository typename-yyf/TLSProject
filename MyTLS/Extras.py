def int2bytes(a: int) -> bytes:
    return bytes([(a & 0xff000000) >> 24, (a & 0xff0000) >> 16, (a & 0xff00) >> 8, a & 0xff])

def bytes2int(a: bytes) -> int:
    return (a[0] << 24) + (a[1] << 16) + (a[2] << 8) + a[3]

def short2bytes(a: int) -> bytes:
    return bytes([(a & 0xff00) >> 8, a & 0xff])

def bytes2short(a: bytes) -> int:
    return (a[0] << 8) + a[1]