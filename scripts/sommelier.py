#!/usr/bin/env python3
"""
Sommelier: IP 筛选器与负载均衡器 (CN 环境运行) - Project Mjolnir 2.0

1. 高并发 TCP Connect 测速 (100 threads)
2. C 段爆破 + 自适应选优
3. 只保留前 9 名 (对应 9 个 FCM 域名)
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
TCP_TIMEOUT = 1.5  # 1.5秒握不上就放弃
MAX_WORKERS = 100  # 提升并发

# 选优配置
MIN_IPS_PER_DOMAIN = 1  # 每个域名至少分配 N 个 IP


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


class CSegmentExpander:
    """C 段爆破器"""

    @staticmethod
    def expand_c_segment(ip: str) -> List[str]:
        """扩展 IPv4 C 段: 1.2.3.4 -> 1.2.3.1 到 1.2.3.254"""
        parts = ip.split('.')
        if len(parts) != 4:
            return [ip]
        prefix = '.'.join(parts[:3]) + '.'
        return [f"{prefix}{i}" for i in range(1, 255)]

    @staticmethod
    def expand_ipv6_block(ip: str) -> List[str]:
        """扩展 IPv6 /124 段"""
        # 简化处理：取前 7 个 16 位组作为前缀
        parts = ip.split(':')
        if len(parts) < 2:
            return [ip]
        # 找到最后一个完整段的位置
        prefix_parts = parts[:7] if len(parts) >= 7 else parts
        prefix = ':'.join(prefix_parts)
        if not prefix.endswith(':'):
            prefix += ':'
        # 扩展最后 8 个地址
        return [f"{prefix}{i:x}" for i in range(8)]


class AdaptiveSelector:
    """
    自适应选优算法 - Project Mjolnir 2.0

    核心思想:
    1. C 段爆破: 发现成功 IP 后，扩展整个 C 段扫描
    2. 自适应排序: 按延迟从低到高排序
    3. 动态截断: 只保留前 9 名 (对应 9 个 FCM 域名)
    """

    def __init__(self, timeout: float = TCP_TIMEOUT, max_workers: int = MAX_WORKERS):
        self.timeout = timeout
        self.max_workers = max_workers

    def get_c_segment(self, ip: str) -> str:
        """获取 IPv4 C 段"""
        parts = ip.split('.')
        if len(parts) == 4:
            return '.'.join(parts[:3]) + '.'
        return ip

    def get_ipv6_block(self, ip: str) -> str:
        """获取 IPv6 /64 段"""
        parts = ip.split(':')
        if len(parts) >= 4:
            return ':'.join(parts[:4]) + ':'
        return ip

    def expand_and_rescan(self, initial_ips: List[str]) -> List[SpeedResult]:
        """C 段爆破 + 重新扫描"""
        # 首次扫描
        print(f"  Initial scan: {len(initial_ips)} IPs...")
        initial_results = batch_measure(initial_ips, timeout=self.timeout, max_workers=self.max_workers)

        # 找出成功的 IP，按网段分组
        successful = [r for r in initial_results if r.success]
        print(f"  First pass: {len(successful)} successful")

        if not successful:
            return initial_results

        # 按网段分组
        blocks = {}
        for r in successful:
            if ':' in r.ip:  # IPv6
                block = self.get_ipv6_block(r.ip)
            else:  # IPv4
                block = self.get_c_segment(r.ip)
            if block not in blocks:
                blocks[block] = []
            blocks[block].append(r)

        print(f"  Found {len(blocks)} successful blocks, expanding...")

        # 爆破每个成功的网段
        ips_to_rescan = []
        for block, success_ips in blocks.items():
            if ':' in block:  # IPv6
                # 取一个成功 IP 作为种子扩展
                seed = success_ips[0].ip
                expanded = CSegmentExpander.expand_ipv6_block(seed)
            else:  # IPv4
                # 取一个成功 IP 作为种子扩展
                seed = success_ips[0].ip
                expanded = CSegmentExpander.expand_c_segment(seed)

            # 过滤掉已经测过的
            tested = {r.ip for r in initial_results}
            new_ips = [ip for ip in expanded if ip not in tested]
            ips_to_rescan.extend(new_ips)
            print(f"    {block}: +{len(new_ips)} new IPs to scan")

        if not ips_to_rescan:
            print("  No new IPs to expand")
            return initial_results

        # 重新扫描新 IPs
        print(f"  Expanding scan: {len(ips_to_rescan)} new IPs...")
        expanded_results = batch_measure(ips_to_rescan, timeout=self.timeout, max_workers=self.max_workers)

        # 合并结果
        all_results = initial_results + expanded_results
        return all_results

    def select_top_ips(self, results: List[SpeedResult]) -> List[str]:
        """自适应选优: 按延迟排序，动态截断"""
        # 只保留成功的
        successful = [r for r in results if r.success]

        if not successful:
            print(f"  No successful connections")
            return []

        # 按延迟从低到高排序
        sorted_results = sorted(successful, key=lambda x: x.latency_ms)

        # 动态截断: 保留前 9 名 (对应 9 个 FCM 域名)
        target_count = len(FCM_DOMAINS) * MIN_IPS_PER_DOMAIN  # 至少 9 个

        if len(sorted_results) > target_count:
            top_ips = sorted_results[:target_count]
            dropped = len(sorted_results) - target_count
            print(f"  Selected top {len(top_ips)} IPs, dropped {dropped} slower IPs")
        else:
            top_ips = sorted_results
            print(f"  Selected all {len(top_ips)} successful IPs")

        # 再次 shuffle 避免固定顺序
        random.shuffle(top_ips)

        return [r.ip for r in top_ips]


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
                  max_workers: int = MAX_WORKERS,
                  timeout: float = TCP_TIMEOUT) -> List[SpeedResult]:
    """批量测速"""
    if not ips:
        return []

    speedometer = TCPSpeedometer(port, timeout)
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
        f"# Generated using Adaptive Ranking with C-Segment Expansion",
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
    print("FCM Sommelier - Project Mjolnir 2.0")
    print("=" * 60)

    selector = AdaptiveSelector(timeout=TCP_TIMEOUT, max_workers=MAX_WORKERS)
    all_results = {}

    # ===== IPv4 处理 =====
    print("\n[Step 1] C-Segment Expansion + Adaptive Ranking (IPv4)...")
    ipv4_ips = load_ips("raw_ips_v4.txt")
    random.shuffle(ipv4_ips)
    print(f"  Loaded {len(ipv4_ips)} seed IPs")

    if ipv4_ips:
        # C 段爆破 + 重新扫描
        ipv4_all_results = selector.expand_and_rescan(ipv4_ips)
        # 自适应选优: 只保留前 9 名
        all_results['v4'] = selector.select_top_ips(ipv4_all_results)
    else:
        all_results['v4'] = []
        print("  No IPv4 IPs to process")

    # ===== IPv6 处理 =====
    print("\n[Step 2] IPv6 Block Expansion + Adaptive Ranking (IPv6)...")
    ipv6_ips = load_ips("raw_ips_v6.txt")
    random.shuffle(ipv6_ips)
    print(f"  Loaded {len(ipv6_ips)} seed IPs")

    if ipv6_ips:
        # IPv6 /124 爆破 + 重新扫描
        ipv6_all_results = selector.expand_and_rescan(ipv6_ips)
        # 自适应选优: 只保留前 9 名
        all_results['v6'] = selector.select_top_ips(ipv6_all_results)
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

    # 生成 Dual-stack (1:1 分配: 每个域名分配 1 个 v4 + 1 个 v6)
    entries_dual = []

    if all_results['v4'] and all_results['v6']:
        # 双栈: 每个域名分配 v4 和 v6
        lb_v4 = LoadBalancer(all_results['v4'], shuffle=True)
        lb_v6 = LoadBalancer(all_results['v6'], shuffle=True)
        for domain in FCM_DOMAINS:
            entries_dual.append((lb_v4.assign(domain), domain))
            entries_dual.append((lb_v6.assign(domain), domain))
    elif all_results['v4']:
        # 只有 v4: 每个域名分配 1 个 v4
        lb_v4 = LoadBalancer(all_results['v4'], shuffle=True)
        for domain in FCM_DOMAINS:
            entries_dual.append((lb_v4.assign(domain), domain))
    elif all_results['v6']:
        # 只有 v6: 每个域名分配 1 个 v6
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
    print(f"Sommelier complete (Mjolnir 2.0):")
    print(f"  Top IPv4: {len(all_results['v4'])}")
    print(f"  Top IPv6: {len(all_results['v6'])}")
    print("=" * 60)


if __name__ == "__main__":
    main()
