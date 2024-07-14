#!/usr/bin/python
import os, sys, socket, struct, select, time

ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.
socket.setdefaulttimeout(1)
host = sys.argv[1]

#second argument
port = int(sys.argv[2])

# 订阅链接设置
def portOpen(ip, port):
    print('\033[1m*Port\033[0m %s:%d' % (ip, port)),
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip, port))
        s.shutdown(2)
        print(f'{ip}:{port}\033[1;32m.... is OK.\033[0m')
        return True
    except:
        print(f'{ip}:{port}\033[1;31m.... is down!!!\033[0m')
        return False


portOpen(host, port)
