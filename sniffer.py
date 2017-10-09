# -*- coding: utf-8 -*-
# 注：windows下需要管理员权限运行
import socket, os, pdb

# 设置监听主机
#host = '10.3.8.211'
host = '10.108.224.9'
host1 = '192.168.1.1'

# host = '127.0.0.1'

# 创建原始套接字，并绑定在公开接口上
if os.name== 'nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP
#pdb.set_trace()
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# 设置在捕获的数据包中包含IP头
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# 在windows平台下，我们需要设置IOCTL以启用混杂模式
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# 读取但个数据包
print(sniffer.recvfrom(65565))

# 在windows平台下关闭混杂模式
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
