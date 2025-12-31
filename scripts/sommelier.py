#!/usr/bin/env python3
"""
Sommelier: IP 筛选器与负载均衡器 (CN 环境运行)

1. 高并发 TCP Connect 测速 (50 threads)
2. 多样性优先筛选 (废除勃艮第算法)
3. Shuffle + Round-Robin 分配到 9 个 FCM 域名
4. 生成三种 hosts 文件: IPv4 / Dual / IPv6
"""

import socket
import concurrent.futures
import random
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
TCP_TIMEOUT = 2.0  # 2秒握不上就放弃
MAX_WORKERS = 50

# 筛选配置 (高频更新策略)
MAX_LATENCY = 1000  # 只要成功且 < 1s 全部录取
MAX_SAMPLE_COUNT = 50
DIVERSITY_SAMPLE = 10


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


class DiversitySelector:
    """
    高频更新策略: 无差别录取 + 多样性优先

    核心思想:
    1. 只要 TCP 成功且延迟 < 1000ms，全部录取
    2. Shuffle 打乱顺序
    3. 如果过多，从不同网段抽样保证跨度
    """

    def __init__(self, max_latency: int = MAX_LATENCY,
                 max_sample: int = MAX_SAMPLE_COUNT,
                 diversity_sample: int = DIVERSITY_SAMPLE):
        self.max_latency = max_latency
        self.max_sample = max_sample
        self.diversity_sample = diversity_sample

    def get_ip_block(self, ip: str) -> str:
        """获取 IP 网段 (IPv4 取 C 段，IPv6 取 /64 段)"""
        if ':' in ip:  # IPv6: 取前 4 个 16 位组 (共 64 位)
            parts = ip.split(':')
            return ':'.join(parts[:4]) + ':'
        else:  # IPv4: 取 C 段 (前 3 个 octet)
            parts = ip.split('.')
            return '.'.join(parts[:3]) + '.'

    def select_ips(self, results: List[SpeedResult]) -> List[str]:
        """筛选 IP (Shuffle + 无差别录取)"""
        # 分类
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        if not successful:
            print(f"  No successful connections (failed: {len(failed)})")
            return []

        # 无差别录取: 成功且 < 1000ms
        qualified = [r for r in successful if r.latency_ms < self.max_latency]
        print(f"  Success: {len(successful)}, Qualified (<{self.max_latency}ms): {len(qualified)}")

        if not qualified:
            print(f"  All successful IPs exceeded latency threshold")
            return []

        # Shuffle 打乱
        random.shuffle(qualified)

        # 如果数量在范围内，全部保留
        if len(qualified) <= self.max_sample:
            ips = [r.ip for r in qualified]
            print(f"  Selected all {len(ips)} IPs (no sampling needed)")
            return ips

        # 数量过多，执行多样性抽样
        print(f"  Too many qualified IPs ({len(qualified)}), performing diversity sampling...")

        # 按网段分组
        blocks = {}
        for r in qualified:
            block = self.get_ip_block(r.ip)
            if block not in blocks:
                blocks[block] = []
            blocks[block].append(r)

        print(f"  Found {len(blocks)} unique network blocks")

        # 从每个网段抽样
        sampled = []
        for block, items in blocks.items():
            sample_count = min(self.diversity_sample, len(items))
            sampled.extend(random.sample(items, sample_count))
            print(f"    {block}: {len(items)} -> {sample_count} sampled")

        # 再次 Shuffle
        random.shuffle(sampled)

        # 如果抽样后仍然过多，缩减到上限
        if len(sampled) > self.max_sample:
            sampled = sampled[:self.max_sample]
            print(f"  Final pool reduced to {len(sampled)} IPs")

        ips = [r.ip for r in sampled]
        print(f"  Selected {len(ips)} IPs with network diversity")
        return ips


class LoadBalancer:
    """负载均衡器: Shuffle + Round-Robin 分配 IP 到域名"""

    def __init__(self, ips: List[str], shuffle: bool = True):
        if shuffle:
            random.shuffle(ips)
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
    """生成 hosts 文件内容 (去重)"""
    lines = [
        f"# Generated by Project Mjolnir",
        f"# Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"# Type: {ip_type}",
        f"#",
        f"# FCM Domains: {', '.join(FCM_DOMAINS[:3])}...",
        f"# Generated using Diversity-First algorithm with Shuffle",
        f"#",
        "",
    ]

    seen = set()
    for ip, domain in entries:
        if ip and (ip, domain) not in seen:
            seen.add((ip, domain))
            lines.append(f"{ip} {domain}")

    return "\n".join(lines)


def main():
    """主入口"""
    print("=" * 60)
    print("FCM Sommelier - IP 多样性筛选与负载均衡")
    print("=" * 60)

    selector = DiversitySelector()
    all_results = {}

    # ===== IPv4 处理 =====
    print("\n[Step 1] Loading and measuring IPv4 IPs...")
    ipv4_ips = load_ips("raw_ips_v4.txt")
    random.shuffle(ipv4_ips)  # 极致 shuffle
    print(f"  Loaded {len(ipv4_ips)} IPv4 IPs")

    if ipv4_ips:
        ipv4_results = batch_measure(ipv4_ips, port=5228)
        all_results['v4'] = selector.select_ips(ipv4_results)
    else:
        all_results['v4'] = []
        print("  No IPv4 IPs to process")

    # ===== IPv6 处理 =====
    print("\n[Step 2] Loading and measuring IPv6 IPs...")
    ipv6_ips = load_ips("raw_ips_v6.txt")
    random.shuffle(ipv6_ips)  # 极致 shuffle
    print(f"  Loaded {len(ipv6_ips)} IPv6 IPs")

    if ipv6_ips:
        ipv6_results = batch_measure(ipv6_ips, port=5228)
        all_results['v6'] = selector.select_ips(ipv6_results)
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

    # 生成 Dual-stack (每个域名至少一条记录)
    entries_dual = []

    # 优先使用 IPv4 (更稳定)，IPv6 备用
    if all_results['v4']:
        lb_v4 = LoadBalancer(all_results['v4'], shuffle=True)
        for domain in FCM_DOMAINS:
            entries_dual.append((lb_v4.assign(domain), domain))

    if all_results['v6']:
        lb_v6 = LoadBalancer(all_results['v6'], shuffle=True)
        for domain in FCM_DOMAINS:
            entries_dual.append((lb_v6.assign(domain), domain))

    if entries_dual:
        # 确定描述
        if all_results['v4'] and all_results['v6']:
            desc = "Dual Stack (IPv4 + IPv6)"
        elif all_results['v6']:
            desc = "Dual Stack (IPv6 Only)"
        else:
            desc = "Dual Stack (IPv4 Only)"

        content_dual = generate_hosts_content(entries_dual, desc)
        with open("fcm_dual.hosts", 'w') as f:
            f.write(content_dual)
        print(f"  Generated fcm_dual.hosts ({len(entries_dual)} entries) [{desc}]")
    else:
        print("  Skipping fcm_dual.hosts (no IPs available)")

    print("\n" + "=" * 60)
    print(f"Sommelier complete:")
    print(f"  Qualified IPv4: {len(all_results['v4'])}")
    print(f"  Qualified IPv6: {len(all_results['v6'])}")
    print("=" * 60)


if __name__ == "__main__":
    main()
