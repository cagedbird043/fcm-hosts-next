#!/usr/bin/env python3
"""
Sommelier: IP 筛选器与负载均衡器 (CN 环境运行)

1. 高并发 TCP Connect 测速 (50 threads)
2. 勃艮第算法筛选"特级园" IP
3. Round-Robin 分配到 9 个 FCM 域名
4. 生成三种 hosts 文件: IPv4 / Dual / IPv6
"""

import socket
import concurrent.futures
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Set
from threading import Lock
import time
from datetime import datetime, timezone

# FCM 目标域名列表
FCM_DOMAINS = [
    "mtalk.google.com",
    "alt1-mtalk.google.com",
    "alt2-mtalk.google.com",
    "alt3-mtalk.google.com",
    "alt4-mtalk.google.com",
    "alt5-mtalk.google.com",
    "alt6-mtalk.google.com",
    "alt7-mtalk.google.com",
    "alt8-mtalk.google.com",
]

FCM_PORT = 5228  # FCM 专用心跳端口

# 测速配置
TCP_TIMEOUT = 3.0
MAX_WORKERS = 50


@dataclass
class SpeedResult:
    """测速结果"""
    ip: str
    latency_ms: float
    success: bool
    error: Optional[str] = None


class TCPSpeedometer:
    """TCP 测速器"""

    def __init__(self, port: int = FCM_PORT, timeout: float = TCP_TIMEOUT):
        self.port = port
        self.timeout = timeout

    def measure(self, ip: str) -> SpeedResult:
        """
        测量单个 IP 的 TCP 延迟
        """
        sock = None
        start_time = time.perf_counter()

        try:
            # 根据 IP 版本选择地址族
            if ':' in ip:  # IPv6
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:  # IPv4
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(self.timeout)
            # IPv4 使用 2 元组，IPv6 使用 4 元组
            if ':' in ip:  # IPv6
                sock.connect((ip, self.port, 0, 0))
            else:  # IPv4
                sock.connect((ip, self.port))

            latency = (time.perf_counter() - start_time) * 1000
            return SpeedResult(ip=ip, latency_ms=latency, success=True)

        except socket.timeout:
            return SpeedResult(ip=ip, latency_ms=-1, success=False, error="timeout")
        except Exception as e:
            return SpeedResult(ip=ip, latency_ms=-1, success=False, error=str(e))
        finally:
            if sock:
                sock.close()


class BurgundyAlgorithm:
    """
    勃艮第算法: IP 筛选算法

    核心思想:
    1. 找到延迟最低的基准 (min_latency)
    2. 设定阈值 threshold = max(min_latency + 50ms, min_latency * 1.3)
    3. 选出所有低于阈值的 IP 作为"特级园"
    """

    def __init__(self, offset_ms: int = 50, multiplier: float = 1.3):
        self.offset_ms = offset_ms
        self.multiplier = multiplier

    def calculate_threshold(self, min_latency: float) -> float:
        """计算阈值"""
        threshold1 = min_latency + self.offset_ms
        threshold2 = min_latency * self.multiplier
        return max(threshold1, threshold2)

    def select_premium_ips(self, results: List[SpeedResult]) -> List[SpeedResult]:
        """筛选特级园 IP"""
        # 只保留成功的
        successful = [r for r in results if r.success]
        if not successful:
            return []

        # 按延迟排序
        sorted_results = sorted(successful, key=lambda x: x.latency_ms)

        # 获取最小延迟
        min_latency = sorted_results[0].latency_ms

        # 计算阈值
        threshold = self.calculate_threshold(min_latency)

        print(f"  Min latency: {min_latency:.2f}ms, Threshold: {threshold:.2f}ms")

        # 筛选低于阈值的
        premium = [r for r in sorted_results if r.latency_ms <= threshold]
        print(f"  Selected {len(premium)} premium IPs out of {len(sorted_results)}")

        return premium


class LoadBalancer:
    """负载均衡器: Round-Robin 分配 IP 到域名"""

    def __init__(self, ips: List[str]):
        self.ips = ips
        self.index = 0
        self.lock = Lock()

    def assign(self, domain: str) -> str:
        """为域名分配一个 IP (Round-Robin)"""
        if not self.ips:
            return ""

        with self.lock:
            ip = self.ips[self.index % len(self.ips)]
            self.index += 1
            return ip

    def generate_entries(self, domains: List[str]) -> List[Tuple[str, str]]:
        """生成 hosts 条目"""
        return [(self.assign(domain), domain) for domain in domains]


def load_ips(filepath: str) -> List[str]:
    """加载 IP 列表"""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[WARN] File not found: {filepath}")
        return []


def batch_measure(ips: List[str], port: int = FCM_PORT,
                  max_workers: int = MAX_WORKERS) -> List[SpeedResult]:
    """批量测速"""
    if not ips:
        return []

    speedometer = TCPSpeedometer(port)
    results = []

    print(f"  Measuring {len(ips)} IPs with {max_workers} threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(speedometer.measure, ip): ip for ip in ips}

        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            results.append(result)

    success_count = sum(1 for r in results if r.success)
    print(f"  Success: {success_count}, Failed: {len(results) - success_count}")

    return results


def generate_hosts_content(entries: List[Tuple[str, str]], ip_type: str) -> str:
    """生成 hosts 文件内容"""
    lines = [
        f"# Generated by Project Mjolnir",
        f"# Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"# Type: {ip_type}",
        f"#",
        f"# FCM Domains: {', '.join(FCM_DOMAINS[:3])}...",
        f"# Generated using Burgundy Algorithm for IP selection",
        f"#",
        "",
    ]

    for ip, domain in entries:
        if ip:
            lines.append(f"{ip} {domain}")

    return "\n".join(lines)


def main():
    """主入口"""
    print("=" * 60)
    print("FCM Sommelier - IP 筛选与负载均衡器")
    print("=" * 60)

    burgundy = BurgundyAlgorithm()
    all_results = {}

    # ===== IPv4 处理 =====
    print("\n[Step 1] Loading and measuring IPv4 IPs...")
    ipv4_ips = load_ips("raw_ips_v4.txt")
    print(f"  Loaded {len(ipv4_ips)} IPv4 IPs")

    if ipv4_ips:
        ipv4_results = batch_measure(ipv4_ips, port=5228)
        ipv4_premium = burgundy.select_premium_ips(ipv4_results)
        all_results['v4'] = [r.ip for r in ipv4_premium]
    else:
        all_results['v4'] = []
        print("  No IPv4 IPs to process")

    # ===== IPv6 处理 =====
    print("\n[Step 2] Loading and measuring IPv6 IPs...")
    ipv6_ips = load_ips("raw_ips_v6.txt")
    print(f"  Loaded {len(ipv6_ips)} IPv6 IPs")

    if ipv6_ips:
        ipv6_results = batch_measure(ipv6_ips, port=5228)
        ipv6_premium = burgundy.select_premium_ips(ipv6_results)
        all_results['v6'] = [r.ip for r in ipv6_premium]
    else:
        all_results['v6'] = []
        print("  No IPv6 IPs to process")

    # ===== 生成 hosts 文件 =====
    print("\n[Step 3] Generating hosts files...")

    # 生成 IPv4 only
    if all_results['v4']:
        lb_v4 = LoadBalancer(all_results['v4'])
        entries_v4 = lb_v4.generate_entries(FCM_DOMAINS)
        content_v4 = generate_hosts_content(entries_v4, "IPv4 Only")
        with open("fcm_ipv4.hosts", 'w') as f:
            f.write(content_v4)
        print(f"  Generated fcm_ipv4.hosts ({len(entries_v4)} entries)")
    else:
        print("  Skipping fcm_ipv4.hosts (no premium IPv4 IPs)")

    # 生成 IPv6 only
    if all_results['v6']:
        lb_v6 = LoadBalancer(all_results['v6'])
        entries_v6 = lb_v6.generate_entries(FCM_DOMAINS)
        content_v6 = generate_hosts_content(entries_v6, "IPv6 Only")
        with open("fcm_ipv6.hosts", 'w') as f:
            f.write(content_v6)
        print(f"  Generated fcm_ipv6.hosts ({len(entries_v6)} entries)")
    else:
        print("  Skipping fcm_ipv6.hosts (no premium IPv6 IPs)")

    # 生成 Dual-stack (IPv4 + IPv6 for each domain)
    if all_results['v4'] and all_results['v6']:
        entries_dual = []
        lb_v4 = LoadBalancer(all_results['v4'])
        lb_v6 = LoadBalancer(all_results['v6'])

        for domain in FCM_DOMAINS:
            entries_dual.append((lb_v4.assign(domain), domain))
            entries_dual.append((lb_v6.assign(domain), domain))

        content_dual = generate_hosts_content(entries_dual, "Dual Stack (IPv4 + IPv6)")
        with open("fcm_dual.hosts", 'w') as f:
            f.write(content_dual)
        print(f"  Generated fcm_dual.hosts ({len(entries_dual)} entries)")
    elif all_results['v6']:
        # IPv6 Only: 生成仅含 IPv6 的 Dual 文件
        lb_v6 = LoadBalancer(all_results['v6'])
        entries_dual = lb_v6.generate_entries(FCM_DOMAINS)
        content_dual = generate_hosts_content(entries_dual, "Dual Stack (IPv6 Only)")
        with open("fcm_dual.hosts", 'w') as f:
            f.write(content_dual)
        print(f"  Generated fcm_dual.hosts ({len(entries_dual)} entries) [IPv6 Only]")
    elif all_results['v4']:
        # 只有 IPv4，复制 IPv4 作为 fallback
        with open("fcm_ipv4.hosts", 'r') as f:
            content = f.read().replace("IPv4 Only", "Dual Stack (IPv4 only fallback)")
        with open("fcm_dual.hosts", 'w') as f:
            f.write(content)
        print("  Generated fcm_dual.hosts (IPv4 fallback)")
    else:
        print("  Skipping fcm_dual.hosts (no IPs available)")

    print("\n" + "=" * 60)
    print(f"Sommelier complete:")
    print(f"  Premium IPv4: {len(all_results['v4'])}")
    print(f"  Premium IPv6: {len(all_results['v6'])}")
    print("=" * 60)


if __name__ == "__main__":
    main()
