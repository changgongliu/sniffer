# -*- coding: utf-8 -*-
import socket, os, struct
from ctypes import *
import pdb
# 监听主机
#host= '10.108.224.90'
host = '10.108.224.9'
# 定义结构体
class DecodeIP(Structure):
    _fields_ = [
        ('ihl',             c_ubyte, 4),
        ('version',         c_ubyte, 4),
        ('tos',             c_ubyte),
        ('len',             c_ushort),
        ('id',              c_ushort),
        ('offset',          c_ushort),
        ('ttl',             c_ubyte),
        ('protocol_num',    c_ubyte),
        ('sum',             c_ushort),
        ('src',             c_ulong),
        ('dst',             c_ulong)
    ]
## 问题出在以上类型定义时，注意！！
## c有待复习一下了

    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer = None):
        # 协议字段与协议名称对应
        self.protocol_map = {1:'ICMP' , 6:'TCP', 17:'UDP'}

        # 可读性更强的IP地址
        self.src_address = socket.inet_ntoa(struct.pack('<L', self.src))
        self.dst_address = socket.inet_ntoa(struct.pack('<L', self.dst))

        # 协议类型
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


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

try:
    while True:
        # 读取数据包
        raw_buffer = sniffer.recvfrom(65565)[0]

        # 将缓冲区的钱20个字节按IP头进行解析
        ip_header = DecodeIP(raw_buffer[0:20])

        # 输出协议和通信双方IP地址
        print('Protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        # 处理CTRL-C
except KeyboardInterrupt:
    # 如果运行在windows上，关闭混杂模式
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
