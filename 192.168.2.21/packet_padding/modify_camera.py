import subprocess
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
import random

mtu = 1500

# 创建四个字典来存储 seq、ack 和 len 信息
real_E_send = []
real_E_received = []
C_thinks_E_send = []
C_thinks_E_received = []

def generate_random_bytes(length):
    """生成指定长度的随机字节"""
    data_length = length - 2  # 留两个字节用于记录长度
    random_data = [random.randint(0, 255) for _ in range(data_length)]
    length_bytes = length.to_bytes(2, 'big')  # 转换为两个字节（大端序）
    print(f"[+] 最后两个字节固定为 {length_bytes}")
    return bytes(random_data) + length_bytes

def set_iptables_rules():
    """设置 iptables 规则"""
    try:
        print("[*] 正在设置 iptables 规则...")
        # 设置 iptables 规则，捕获目标地址或源地址为 192.168.2.204 的流量
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-d", "192.168.2.155", "-j", "NFQUEUE", "--queue-num", "1"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", "192.168.2.155", "-j", "NFQUEUE", "--queue-num", "1"], check=True)
        print("[*] iptables 规则已设置。")
    except subprocess.CalledProcessError as e:
        print(f"[!] 设置 iptables 规则失败: {e}")


def clear_iptables_rules():
    """清除 iptables 规则"""
    try:
        print("[*] 正在清除 iptables 规则...")
        subprocess.run(["sudo", "iptables", "-F"], check=True)  # 清除所有规则
        print("[*] iptables 规则已清除。")
    except subprocess.CalledProcessError as e:
        print(f"[!] 清除 iptables 规则失败: {e}")


def modify_tcp_packet(packet):
    """捕获并修改 TCP 数据包的负载"""
    scapy_pkt = IP(packet.get_payload())  # 解析原始数据包

    # 检查数据包是否包含 TCP 层和 Raw 数据层（即负载）
    if scapy_pkt.haslayer(TCP):
        print("[+] 捕获到 TCP 数据包，正在修改负载...")

        # 获取源 IP 地址
        source_ip = scapy_pkt[IP].src
        print(f"[+] 数据包源 IP: {source_ip}")

        # 获取 TCP 的 seq、ack 和 len 值
        seq = scapy_pkt[TCP].seq
        ack = scapy_pkt[TCP].ack
        modified_payload = b""

        if source_ip == "192.168.2.155":
            if real_E_send and not real_E_send[-1]['seq'] == -1:
                if scapy_pkt[TCP].seq != real_E_send[-1]['seq'] + real_E_send[-1]['len']:
                    print("可能发生重传")
                    scapy_pkt[IP].tos = 0x20
                    real_E_send.clear()
                    real_E_received.clear()
                    C_thinks_E_send.clear()
                    C_thinks_E_received.clear()
                    real_E_send.append({'seq': -1, 'ack': 0, 'len': 0})

            if real_E_send and real_E_send[-1]['seq'] == -1:
                if real_E_send[-1]['len'] < 10:
                    real_E_send[-1]['len'] += 1
                else:
                    scapy_pkt[IP].tos = 0x30
                    real_E_send.clear()

            if not real_E_send:
                if scapy_pkt.haslayer(Raw):
                    # 获取 TCP 数据包的负载内容
                    raw_payload = scapy_pkt[Raw].load
                    # 真实E发送
                    length = len(scapy_pkt[Raw].load)
                    real_E_send.append({'seq': seq, 'ack': ack, 'len': length})
                    print(f"[+] 存储到 真实E发送 表格：seq = {seq}, ack = {ack}, len = {length}")

                    if raw_payload[0] == 0x17:
                        print("[+] 检测到 TLS Application Data，正在修改负载...")

                        # 获取 raw_payload[3] 和 raw_payload[4] 并合并为一个 16 进制数
                        original_len_hex = raw_payload[3] << 8 | raw_payload[4]  # 16进制合并
                        original_len_dec = original_len_hex  # 转换为十进制
                        print(f"[+] 原始长度（十进制）: {original_len_dec}")

                        # 在十进制长度上加 5
                        ip_total_len = scapy_pkt[IP].len
                        max_padding = mtu - ip_total_len
                        random_add= random.randint(2, max_padding)
                        new_len_dec = original_len_dec + random_add
                        print(f"[+] 增加的载荷长度是: {random_add}")
                        print(f"[+] 修改后的长度（十进制）: {new_len_dec}")

                        # 转换回16进制
                        new_len_hex = new_len_dec.to_bytes(2, byteorder='big')
                        print(f"[+] 修改后的长度（16进制）: {new_len_hex.hex()}")

                        # 替换原始 raw_payload[3] 和 raw_payload[4] 为新的长度
                        raw_payload = raw_payload[:3] + new_len_hex + raw_payload[5:]

                        print("[+] 正在增加负载...")
                        modified_payload = raw_payload + generate_random_bytes(random_add)
                        scapy_pkt[Raw].load = modified_payload  # 设置新的负载

            else:
                if real_E_send and not real_E_send[-1]['seq'] == -1:
                    if not scapy_pkt.haslayer(Raw):
                        # 真实E发送
                        real_E_send.append({'seq': seq, 'ack': ack, 'len': 0})
                    if scapy_pkt.haslayer(Raw):
                        # 获取 TCP 数据包的负载内容
                        raw_payload = scapy_pkt[Raw].load
                        length = len(scapy_pkt[Raw].load)
                        # real_E_send[-1]['len'] = length
                        real_E_send.append({'seq': seq, 'ack': ack, 'len': length})
                        print(f"[+] 存储到 真实E发送 表格：seq = {seq}, ack = {ack}, len = {length}")
                        if raw_payload[0] == 0x17:
                            print("[+] 检测到 TLS Application Data，正在修改负载...")

                            # 获取 raw_payload[3] 和 raw_payload[4] 并合并为一个 16 进制数
                            original_len_hex = raw_payload[3] << 8 | raw_payload[4]  # 16进制合并
                            original_len_dec = original_len_hex  # 转换为十进制
                            print(f"[+] 原始长度（十进制）: {original_len_dec}")

                            # 在十进制长度上加 5
                            ip_total_len = scapy_pkt[IP].len
                            max_padding = mtu - ip_total_len
                            random_add = random.randint(2, max_padding)
                            print(f"[+] 增加的载荷长度是: {random_add}")
                            new_len_dec = original_len_dec + random_add
                            print(f"[+] 修改后的长度（十进制）: {new_len_dec}")

                            # 转换回16进制
                            new_len_hex = new_len_dec.to_bytes(2, byteorder='big')
                            print(f"[+] 修改后的长度（16进制）: {new_len_hex.hex()}")

                            # 替换原始 raw_payload[3] 和 raw_payload[4] 为新的长度
                            raw_payload = raw_payload[:3] + new_len_hex + raw_payload[5:]

                            print("[+] 正在增加负载...")
                            modified_payload = raw_payload + generate_random_bytes(random_add)
                            scapy_pkt[Raw].load = modified_payload  # 设置新的负载

            if real_E_send and not real_E_send[-1]['seq'] == -1:
                if not C_thinks_E_send:
                    if scapy_pkt.haslayer(Raw):
                        # 清除旧的校验和和长度字段，让 Scapy 自动重新计算
                        del scapy_pkt[IP].len
                        del scapy_pkt[IP].chksum
                        del scapy_pkt[TCP].chksum

                        # 更新 C认为E发送 表格（修改后的 seq、ack 和 len）
                        seq_new = scapy_pkt[TCP].seq
                        ack_new = scapy_pkt[TCP].ack
                        length_new = len(scapy_pkt[Raw].load)
                        C_thinks_E_send.append({'seq': seq_new, 'ack': ack_new, 'len': length_new})
                        print(f"[+] 存储到 C认为E发送 表格：seq = {seq_new}, ack = {ack_new}, len = {length_new}")
                else:
                    scapy_pkt[TCP].seq = C_thinks_E_send[-1]['seq'] + C_thinks_E_send[-1]['len']
                    if C_thinks_E_received:
                        scapy_pkt[TCP].ack = C_thinks_E_received[-1]['seq'] + C_thinks_E_received[-1]['len']
                    else:
                        scapy_pkt[TCP].ack = C_thinks_E_send[-1]['ack']
                    if not scapy_pkt.haslayer(Raw):
                        C_thinks_E_send.append({'seq': scapy_pkt[TCP].seq, 'ack': scapy_pkt[TCP].ack, 'len': 0})
                    if scapy_pkt.haslayer(Raw):
                        length_new = len(scapy_pkt[Raw].load)
                        #C_thinks_E_send[-1]['len'] = length_new
                        C_thinks_E_send.append({'seq': scapy_pkt[TCP].seq, 'ack': scapy_pkt[TCP].ack, 'len': length_new})
                        print(f"[+] 存储到 C认为E发送 表格：seq = {scapy_pkt[TCP].seq}, ack = {scapy_pkt[TCP].ack}, len = {length_new}")

        else:
            if scapy_pkt[IP].tos == 0x20:
                print("可能发生重传")
                scapy_pkt[IP].tos = 0x00
                real_E_send.clear()
                real_E_received.clear()
                C_thinks_E_send.clear()
                C_thinks_E_received.clear()
                real_E_send.append({'seq': -1, 'ack': 0, 'len': 0})

            if real_E_send and not real_E_send[-1]['seq'] == -1:
                if not scapy_pkt.haslayer(Raw):
                    # C认为E收到
                    C_thinks_E_received.append({'seq': seq, 'ack': ack, 'len': 0})
                if scapy_pkt.haslayer(Raw):
                    # 获取 TCP 数据包的负载内容
                    raw_payload = scapy_pkt[Raw].load
                    length = len(scapy_pkt[Raw].load)
                    #C_thinks_E_received[-1]['len'] = length
                    C_thinks_E_received.append({'seq': seq, 'ack': ack, 'len': length})
                    print(f"[+] 存储到 C认为E收到 表格：seq = {seq}, ack = {ack}, len = {length}")

                    if raw_payload[0] == 0x17:
                        # 获取 TLS Application Data 长度字段
                        original_len_hex = raw_payload[3] << 8 | raw_payload[4]  # raw_payload[3:5] 是长度字段
                        original_len_dec = original_len_hex
                        print(f"[+] 原始长度（十进制）: {original_len_dec}")

                        # 读取最后两字节作为 padding 长度
                        padding_length = int.from_bytes(raw_payload[-2:], byteorder='big')
                        print(f"[+] 删除的载荷长度是: {padding_length}")

                        # 计算修改后的长度
                        new_len_dec = original_len_dec - padding_length
                        print(f"[+] 修改后的长度（十进制）: {new_len_dec}")

                        # 转换为新的 TLS 长度字段（2字节）
                        new_len_hex = new_len_dec.to_bytes(2, byteorder='big')
                        print(f"[+] 修改后的长度（16进制）: {new_len_hex.hex()}")

                        # 替换原始 TLS 长度字段（raw_payload[3] 和 raw_payload[4]）
                        raw_payload = raw_payload[:3] + new_len_hex + raw_payload[5:]

                        print("[+] 检测到 TLS Application Data，正在移除填充字节")
                        modified_payload = raw_payload[:-padding_length]  # 去除最后 padding_length 字节
                        scapy_pkt[Raw].load = modified_payload  # 应用修改后的 payload

                if not real_E_received:
                    scapy_pkt[TCP].seq = C_thinks_E_received[-1]['seq']
                else:
                    scapy_pkt[TCP].seq = real_E_received[-1]['seq'] + real_E_received[-1]['len']
                scapy_pkt[TCP].ack = real_E_send[-1]['seq'] + real_E_send[-1]['len']
                if not scapy_pkt.haslayer(Raw):
                    real_E_received.append({'seq': scapy_pkt[TCP].seq, 'ack': scapy_pkt[TCP].ack, 'len': 0})
                if scapy_pkt.haslayer(Raw):
                    length_new = len(scapy_pkt[Raw].load)
                    #real_E_received[-1]['len'] = length_new
                    real_E_received.append({'seq': scapy_pkt[TCP].seq, 'ack': scapy_pkt[TCP].ack, 'len': length_new})
                    print(f"[+] 存储到 真实E收到 表格：seq = {scapy_pkt[TCP].seq}, ack = {scapy_pkt[TCP].ack}, len = {length_new}")

        # 清除旧的校验和和长度字段，让 Scapy 自动重新计算
        del scapy_pkt[IP].len
        del scapy_pkt[IP].chksum
        del scapy_pkt[TCP].chksum

        # 手动重新计算校验和，确保正确
        #scapy_pkt[IP].len = None
        scapy_pkt[TCP].chksum = None  # 清除 TCP 校验和，确保 Scapy 会重新计算
        scapy_pkt[IP].chksum = None  # 清除 IP 校验和，确保 Scapy 会重新计算

        # 将修改后的数据包重新写入
        packet.set_payload(bytes(scapy_pkt))  # 修改后的数据包需要回写到队列

    # 继续传递数据包
    packet.accept()


# 绑定到队列号 1，并启动 NetfilterQueue
nfqueue = NetfilterQueue()

try:
    # 设置 iptables 规则
    set_iptables_rules()

    # 启动 NetfilterQueue 捕获 TCP 数据包
    nfqueue.bind(1, modify_tcp_packet)
    print("[*] 启动 NetfilterQueue 捕获 TCP 数据包...")
    nfqueue.run()

except KeyboardInterrupt:
    print("[*] 停止 NetfilterQueue...")

finally:
    # 清除 iptables 规则
    clear_iptables_rules()
