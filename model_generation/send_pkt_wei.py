from scapy.all import *

# 构造 200 字节的数据包
pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2", len=900) / UDP(sport=12345, dport=80) / Raw(b"X" * 182)

# 指定网络接口 (eth0 只是示例，你可以改成自己的接口)
iface = "veth0"

# 发送 10 个数据包
for _ in range(10):
    sendp(pkt, iface=iface)
    time.sleep(0.1)  # 让 flow_iat_min 进入不同范围
