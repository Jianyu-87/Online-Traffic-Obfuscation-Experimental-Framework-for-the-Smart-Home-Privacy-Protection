from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw, send
import subprocess
import random
from collections import deque

# 用于记录 ACK 号的表
ack_table = []
# 用于记录数据包状态的表（0 表示无 Raw 层，1 表示有 Raw 层）
record_table = []
# 用于存储需要延迟发送的无 Raw 层数据包
packet_queue = deque()

def set_iptables_rules():
    """设置 iptables 规则"""
    try:
        print("[*] 正在设置 iptables 规则...")
        subprocess.run(
            ["sudo", "iptables", "-A", "FORWARD", "-s", "192.168.2.155", "-j", "NFQUEUE", "--queue-num", "1"],
            check=True)
        subprocess.run(
            ["sudo", "iptables", "-A", "FORWARD", "-d", "192.168.2.155", "-j", "NFQUEUE", "--queue-num", "1"],
            check=True)
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


def generate_random_bytes(length=1):
    """生成指定长度的随机字节"""
    random_bytes = bytes([random.randint(0, 255) for _ in range(length)])
    print(f"生成的随机字节: {random_bytes}")  # 打印生成的随机字节
    return random_bytes

def send_queued_packets(scapy_pkt, random_length):
    """发送队列中的无 Raw 层数据包"""
    global packet_queue
    while packet_queue:
        queued_packet = packet_queue.popleft()

        # 确保是 TCP 包，并修改其 seq 号
        if queued_packet.haslayer(TCP):
            new_seq = scapy_pkt[TCP].seq + random_length
            queued_packet[TCP].seq = new_seq

            # 重新计算校验和
            del queued_packet[TCP].chksum
            if queued_packet.haslayer(IP):
                del queued_packet[IP].chksum

        send(queued_packet, verbose=False)

def modify_tcp_packet(packet):
    """捕获并修改 TCP 数据包的负载"""
    global ack_table, record_table, packet_queue  # 使用全局变量来记录 ACK 号、状态和数据包队列
    scapy_pkt = IP(packet.get_payload())  # 解析原始数据包

    # 检查数据包是否包含 TCP 层
    if scapy_pkt.haslayer(TCP):
        print("[+] 捕获到 TCP 数据包...")

        # 获取源 IP 地址和目的 IP 地址
        source_ip = scapy_pkt[IP].src
        dest_ip = scapy_pkt[IP].dst
        print(f"[+] 数据包源 IP: {source_ip}")
        print(f"[+] 数据包目的地 IP: {dest_ip}")

        # 根据源 IP 地址处理数据包
        if dest_ip == "192.168.2.155":
            if scapy_pkt.haslayer(Raw):
                raw_payload = scapy_pkt[Raw].load
                if scapy_pkt[IP].tos != 0x00:
                    # 将 raw_payload 转换为 bytearray 以便修改
                    raw_payload = bytearray(raw_payload)
                    raw_payload[0] = 0x17
                    raw_payload[3] = raw_payload[1]
                    raw_payload[4] = raw_payload[2]
                    raw_payload[1] = 0x03
                    raw_payload[2] = 0x03

                    # 修改后的负载
                    scapy_pkt[Raw].load = bytes(raw_payload)

                    # 清除旧的校验和和长度字段，让 Scapy 自动重新计算
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[TCP].chksum

                    # 重新计算校验和
                    scapy_pkt[IP].len = len(scapy_pkt)  # 更新 IP 总长度
                    scapy_pkt[TCP].chksum = None  # 清除 TCP 校验和，确保 Scapy 会重新计算
                    scapy_pkt[IP].chksum = None  # 清除 IP 校验和，确保 Scapy 会重新计算

                    # 更新数据包的负载并放回队列
                    packet.set_payload(bytes(scapy_pkt))
                    packet.accept()
                else:
                    packet.accept()
            else:
                packet.accept()

        # 根据目的 IP 地址处理数据包
        if source_ip == "192.168.2.155":
            # 检查是否有 Raw 层
            if scapy_pkt.haslayer(Raw):
                print("[+] 数据包有 Raw 层，记录状态为 1")
                record_table.append(1)  # 记录状态为 1
                current_ack = scapy_pkt[TCP].ack
                ack_table.append(current_ack)  # 记录 ACK 号

                # 如果上一个记录是 0，且表不为空，修改第一个分段的 ACK 号
                if len(ack_table) > 2 and len(record_table) > 2 and record_table[-2] == 0 and record_table[-3] == 1:
                    scapy_pkt[TCP].ack = ack_table[-2]  # 修改为上一个 ACK 号

                # 处理 Raw 层数据
                raw_payload = scapy_pkt[Raw].load
                if raw_payload[0] == 0x17:
                    raw_payload = bytearray(raw_payload)
                    raw_payload[0] = generate_random_bytes()[0]
                    raw_payload[1] = raw_payload[3]
                    raw_payload[2] = raw_payload[4]
                    scapy_pkt[IP].tos = 0x10

                    # 随机选择从 8 到 16 字节长度
                    random_length1 = random.randint(8, 16)
                    random_length2 = random.randint(8, 16)

                    # 获取 raw_payload[3] 和 raw_payload[4] 并合并为一个 16 进制数
                    original_len_hex = raw_payload[3] << 8 | raw_payload[4]  # 16进制合并
                    original_len_dec = original_len_hex  # 转换为十进制
                    print(f"[+] 原始长度（十进制）: {original_len_dec}")

                    # 在十进制长度上加 5
                    new_len_dec = random_length1 - 5
                    print(f"[+] 修改后的长度（十进制）: {new_len_dec}")

                    # 转换回16进制
                    new_len_hex = new_len_dec.to_bytes(2, byteorder='big')
                    print(f"[+] 修改后的长度（16进制）: {new_len_hex.hex()}")

                    # 替换原始 raw_payload[3] 和 raw_payload[4] 为新的长度
                    raw_payload = raw_payload[:3] + new_len_hex + raw_payload[5:]

                    modified_payload1 = raw_payload[:random_length1]  # 前 8 字节
                    modified_payload2 = raw_payload[random_length1:random_length1 + random_length2]
                    modified_payload3 = raw_payload[random_length1 + random_length2:]

                    # 修改第一个数据包的负载为前 8 字节
                    scapy_pkt[Raw].load = modified_payload1
                    # 清除旧的校验和和长度字段，让 Scapy 自动重新计算
                    del scapy_pkt[IP].len
                    del scapy_pkt[IP].chksum
                    del scapy_pkt[TCP].chksum

                    # 将修改后的第一个数据包重新写入
                    packet.set_payload(bytes(scapy_pkt))
                    packet.accept()

                    # 随机选择在发送第一个数据包后还是第二个数据包后调用逻辑
                    call_after_first = random.choice([True, False])
                    if call_after_first:
                        print("[+] 在发送第一个数据包后调用逻辑")
                        send_queued_packets(scapy_pkt, random_length1)

                    # 构造并发送剩余部分的数据包
                    if modified_payload2:
                        print("[+] 发送剩余部分的数据包...")
                        # 计算第二个数据包的序列号
                        new_seq = scapy_pkt[TCP].seq + random_length1
                        # 构造新的数据包
                        new_pkt = IP(src=scapy_pkt[IP].src, dst=scapy_pkt[IP].dst) / \
                                  TCP(sport=scapy_pkt[TCP].sport,
                                      dport=scapy_pkt[TCP].dport,
                                      seq=new_seq,  # 正确设置序列号
                                      ack=current_ack,  # 继承修改后的确认号
                                      flags=scapy_pkt[TCP].flags  # 继承原始数据包的标志位
                                      ) / \
                                  Raw(load=modified_payload2)
                        # 发送新的数据包
                        send(new_pkt, verbose=False)

                        if not call_after_first:
                            print("[+] 在发送第二个数据包后调用逻辑")
                            send_queued_packets(scapy_pkt, random_length1 + random_length2)

                    if modified_payload3:
                        print("[+] 发送剩余部分的数据包...")
                        # 计算第二个数据包的序列号
                        new_seq2 = scapy_pkt[TCP].seq + random_length1 + random_length2
                        # 构造新的数据包
                        new_pkt2 = IP(src=scapy_pkt[IP].src, dst=scapy_pkt[IP].dst) / \
                                   TCP(sport=scapy_pkt[TCP].sport,
                                       dport=scapy_pkt[TCP].dport,
                                       seq=new_seq2,  # 正确设置序列号
                                       ack=scapy_pkt[TCP].ack,  # 继承原始数据包的确认号
                                       flags=scapy_pkt[TCP].flags  # 继承原始数据包的标志位
                                       ) / \
                                   Raw(load=modified_payload3)
                        # 发送新的数据包
                        send(new_pkt2, verbose=False)
                else:
                    packet.accept()
            else:
                print("[+] 数据包无 Raw 层，记录状态为 0")
                record_table.append(0)  # 记录状态为 0

                if len(record_table) > 1 and record_table[-2] == 1:
                    packet_queue.append(scapy_pkt)
                else:
                    while packet_queue:
                        queued_packet = packet_queue.popleft()
                        send(queued_packet, verbose=False)
                    packet.accept()
    else:
        packet.accept()


def start_nfqueue():
    """启动 NetfilterQueue，监听并处理捕获的流量"""
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, modify_tcp_packet)
    try:
        print("[*] 正在启动 NetfilterQueue...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("[*] 停止 NetfilterQueue...")
        nfqueue.unbind()


if __name__ == "__main__":
    set_iptables_rules()  # 设置 iptables 规则
    start_nfqueue()  # 启动 NetfilterQueue
    clear_iptables_rules()  # 清除 iptables 规则