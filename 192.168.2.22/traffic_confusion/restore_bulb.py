import subprocess
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

# 配置iptables规则，将符合条件的转发数据包入队并标记
import subprocess

def set_iptables_rules():
    """设置 iptables 规则"""
    try:
        print("[*] 正在设置 iptables 规则...")
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", "192.168.2.2", "-d", "192.168.2.5", "-j", "NFQUEUE", "--queue-num", "2"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", "192.168.2.194", "-d", "14.215.35.235", "-j", "NFQUEUE", "--queue-num", "2"], check=True)
        print("[*] iptables 规则已设置。")
    except subprocess.CalledProcessError as e:
        print(f"[!] 设置 iptables 规则失败: {e}")

def clear_iptables_rules():
    """只删除当前脚本添加的 iptables 规则"""
    try:
        print("[*] 正在删除脚本设置的 iptables 规则...")
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", "192.168.2.2", "-d", "192.168.2.5", "-j", "NFQUEUE", "--queue-num", "2"], check=True)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", "192.168.2.194", "-d", "14.215.35.235", "-j", "NFQUEUE", "--queue-num", "2"], check=True)
        print("[*] 脚本设置的 iptables 规则已清除。")
    except subprocess.CalledProcessError as e:
        print(f"[!] 清除 iptables 规则失败: {e}")

# 处理捕获到的数据包
def packet_handler(packet):
    """捕获并修改 IP 地址的包"""
    scapy_pkt = IP(packet.get_payload())  # 解析原始数据包

    # 检查数据包是否包含 TCP 层
    if scapy_pkt.haslayer(TCP):
        print("[+] 捕获到 TCP 数据包，正在修改源和目的 IP...")

        # 获取源 IP 地址和目的 IP 地址
        source_ip = scapy_pkt[IP].src
        dest_ip = scapy_pkt[IP].dst
        print(f"[+] 数据包源 IP: {source_ip}")
        print(f"[+] 数据包目的 IP: {dest_ip}")

        if source_ip == "192.168.2.2":
            # 修改 IP 地址：根据源和目的 IP 进行修改
            scapy_pkt[IP].src = "14.215.35.235"
            scapy_pkt[IP].dst = "192.168.2.194"
            print(f"[+] 修改源 IP 为 {scapy_pkt[IP].src}，目的 IP 为 {scapy_pkt[IP].dst}")

        if source_ip == "192.168.2.194":
            # 修改 IP 地址：根据源和目的 IP 进行修改
            scapy_pkt[IP].src = "192.168.2.5"
            scapy_pkt[IP].dst = "192.168.2.2"
            print(f"[+] 修改源 IP 为 {scapy_pkt[IP].src}，目的 IP 为 {scapy_pkt[IP].dst}")

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
        # 如果不是 TCP 数据包，直接放行
        packet.accept()

def start_nfqueue():
    """启动 NetfilterQueue，监听并处理捕获的流量"""
    nfqueue = NetfilterQueue()
    nfqueue.bind(2, packet_handler)
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