# -*- coding: utf-8 -*-
import socket, os, struct
from ctypes import *
import threading ,time
from netaddr import *
import pdb

# 监听主机
host = '10.108.224.9'

# 扫描的目标子网
#subnet = '10.108.0.0/16'
subnet = '10.108.226.0/24'
# 自定义字符串，健在ICMP响应中进行核对
check_message = 'HELLOWORLD'

# 定义发送udp包函数
def udp_sender(subnet, check_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            print('send check_message to %s' % ip)
            sender.send(check_message, ('%s' % ip, 65212))
        except:
            pass

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

# 定义ICMP结构体
class ICMP(Structure):
    _fields_ = [
        ('type',            c_ubyte),
        ('code',            c_ubyte),
        ('checksum',        c_ushort),
        ('unused',          c_ushort),
        ('next_hop_mtu',    c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

## 主程序
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

# 新建线程发送数据
t = threading.Thread(target=udp_sender, args=(subnet, check_message))
t.start()

try:
    while True:
        # 读取数据包
        raw_buffer = sniffer.recvfrom(65565)[0]

        # 将缓冲区的钱20个字节按IP头进行解析
        ip_header = DecodeIP(raw_buffer[0:20])

        # 输出协议和通信双方IP地址
        #print('Protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        if ip_header.protocol == 'ICMP':
            offset = ip_header.ihl*4
            buf = raw_buffer[offset:offset+sizeof(ICMP)]

            # 解析ICMP数据
            icmp_header = ICMP(buf)
            print('ICMP -> type: %s code:%s' % (icmp_header.type, icmp_header.code))

            #检查ICMP类型和代码值是不是3
            if icmp_header.code == 3 and icmp_header.type == 3:
                # 确认是否在子网中
                if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                    if raw_buffer[len(raw_buffer)-len(check_message):] == check_message:
                        print('host up: %s' % ip_header.src_address)

# 处理CTRL-C
except KeyboardInterrupt:
    # 如果运行在windows上，关闭混杂模式
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
