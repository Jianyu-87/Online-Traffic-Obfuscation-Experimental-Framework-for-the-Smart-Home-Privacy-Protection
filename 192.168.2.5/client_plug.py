import time
import os
import signal
from scapy.all import *

FIXED_CLIENT_IP = "192.168.2.5"
FIXED_SERVER_IP = "192.168.2.2"

def set_iptables_rule():
    rule = f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {FIXED_CLIENT_IP} -j DROP"
    print(f"[设置规则] {rule}")
    os.system(rule)

def remove_iptables_rule():
    rule = f"iptables -D OUTPUT -p tcp --tcp-flags RST RST -s {FIXED_CLIENT_IP} -j DROP"
    print(f"[删除规则] {rule}")
    os.system(rule)

def extract_server_packets(pcap_file, original_server_ip):
    packets = rdpcap(pcap_file)
    packet_list = []
    for pkt in packets:
        if IP in pkt and TCP in pkt and pkt[IP].src == original_server_ip:
            ip_layer = IP(src=FIXED_CLIENT_IP, dst=FIXED_SERVER_IP)
            tcp_layer = TCP(
                sport=pkt[TCP].sport,
                dport=pkt[TCP].dport,
                seq=pkt[TCP].seq,
                ack=pkt[TCP].ack,
                flags=pkt[TCP].flags
            )
            raw_data = Raw(load=pkt[Raw].load) if Raw in pkt else None
            full_pkt = ip_layer / tcp_layer / raw_data if raw_data else ip_layer / tcp_layer
            packet_list.append((float(pkt.time), full_pkt))  # 使用原始时间戳
    return packet_list

def wait_until_precise(target_time):
    """
    高精度等待，直到 target_time（绝对UNIX时间戳），
    精度控制在0.1ms级别以内。
    """
    while True:
        now = time.time()
        remaining = target_time - now
        if remaining <= 0:
            return
        elif remaining > 0.01:
            time.sleep(remaining - 0.005)
        else:
            # busy-wait for最后几毫秒（0.01s以内）
            while time.time() < target_time:
                pass
            return

def replay_by_absolute_time(packet_list):
    print(f"[系统时间] 当前UNIX时间戳：{time.time():.6f}")
    start_time = time.time()
    for pkt_time, pkt in packet_list:
        print(f"[等待发送] 目标时间戳 {pkt_time:.6f}")
        wait_until_precise(pkt_time)
        actual_send_time = time.time()
        send(pkt, verbose=0)
        delay = actual_send_time - pkt_time
        print(f"[已发送] 实际时间 {actual_send_time:.6f}, 目标 {pkt_time:.6f}, 误差 {delay*1000:.3f} ms")

def main():
    PCAP_FILE = "8.pcap"
    ORIGINAL_SERVER_IP = "192.168.2.120"

    set_iptables_rule()
    signal.signal(signal.SIGINT, lambda s, f: remove_iptables_rule() or exit(1))  # Ctrl+C 时清理规则
    try:
        packet_list = extract_server_packets(PCAP_FILE, ORIGINAL_SERVER_IP)
        if not packet_list:
            print("未提取到任何服务器包。请检查PCAP文件或IP地址设置。")
            return
        print(f"共提取 {len(packet_list)} 个包，等待其对应时间逐个发送...")
        replay_by_absolute_time(packet_list)
    finally:
        remove_iptables_rule()

if __name__ == "__main__":
    main()