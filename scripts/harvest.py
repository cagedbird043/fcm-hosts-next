#!/usr/bin/env python3
"""
Harvest: DNS 采集器 (US 环境运行)

使用 dnspython 构造带 EDNS Client Subnet (ECS) 的 DNS 查询，
从 Google 权威 DNS 获取 mtalk.google.com 的 IPv4 和 IPv6 地址。
"""

import dns.message
import dns.query
import dns.edns
import ipaddress
from typing import Set
from dns.rdatatype import RdataType


# DNS 服务器列表 (多源诱捕)
DNS_SERVERS = [
    # Google 权威 DNS
    "216.239.32.10",   # ns1.google.com
    "216.239.34.10",   # ns2.google.com
    "216.239.36.10",   # ns3.google.com
    "216.239.38.10",   # ns4.google.com
    # 台湾中华电信 DNS (台北机房诱饵)
    "168.95.192.1",    # HiNet Primary
    "168.95.1.1",      # HiNet Secondary
    # 国内外公共 DNS
    "1.1.1.1",         # Cloudflare
    "9.9.9.9",         # Quad9
    "101.101.101.101", # 台湾中华电信
    "8.8.8.8",         # Google Public DNS
]

# 中国核心骨干网 CIDR 列表 (用于生成 ECS 子网) - 扩展版
CHINA_BACKBONE_V4 = [
    # 教育网
    "202.112.0.0/16",
    "202.113.0.0/16",
    # 电信骨干网 (全国)
    "1.0.0.0/8",
    "14.1.0.0/16",
    "14.208.0.0/12",
    "111.206.0.0/16",
    "111.207.0.0/16",
    "111.208.0.0/14",
    "180.149.0.0/16",
    "180.150.0.0/15",
    "219.158.0.0/17",
    "219.158.128.0/17",
    "220.195.0.0/15",
    "221.12.0.0/16",
    "221.13.0.0/16",
    "221.176.0.0/12",
    "223.5.0.0/16",
    # 联通骨干网
    "202.106.0.0/16",
    "202.99.0.0/16",
    "202.106.192.0/14",
    "221.12.0.0/16",
    "221.13.0.0/16",
    # 移动骨干网
    "117.144.0.0/16",
    "117.128.0.0/10",
    "183.128.0.0/11",
    "223.0.0.0/12",
    # 铁通/鹏博士
    "43.254.0.0/16",
    "106.120.0.0/14",
    # 方正/长城等
    "111.206.0.0/16",
]

# 台湾省核心诱饵网段 (TAIWAN_HITS) - 台北机房优质 IP
TAIWAN_BACKBONE_V4 = [
    "1.160.0.0/12",    # 台湾中华电信
    "61.224.0.0/13",   # 台湾固网
    "111.240.0.0/12",  # 台湾大哥大
    "114.32.0.0/12",   # 台湾固网
    "220.136.0.0/13",  # 亚太电信
    "27.240.0.0/13",   # 台湾之星
    "39.8.0.0/13",     # 中华电信
    "42.72.0.0/13",    # 远传电信
    "140.112.0.0/12",  # 台湾学术网络
]

CHINA_BACKBONE_V6 = [
    # 教育网 IPv6
    "2001:da8::/32",
    # 电信骨干网 IPv6
    "240e::/12",
    # 联通骨干网 IPv6
    "2408::/12",
    # 移动骨干网 IPv6
    "2400::/12",
    "2402::/14",
    "2408::/10",
    # 铁通骨干网 IPv6
    "240c::/12",
    # 阿里云/腾讯云
    "2401:da00::/32",
    "2402:4e00::/22",
]

TARGET_DOMAIN = "mtalk.google.com"
OUTPUT_V4 = "raw_ips_v4.txt"
OUTPUT_V6 = "raw_ips_v6.txt"


def parse_subnet(subnet: str) -> tuple[str, int]:
    """
    解析子网字符串为 (address, prefix_len)

    Args:
        subnet: 子网字符串，如 "1.0.0.0/8" 或 "240e::/12"

    Returns:
        (地址, 前缀长度) 元组
    """
    network = ipaddress.ip_network(subnet, strict=False)
    return (str(network.network_address), network.prefixlen)


def create_ecs_option(subnet: str) -> dns.edns.ECSOption:
    """
    创建 EDNS Client Subnet OPT 记录

    Args:
        subnet: 子网字符串，如 "1.0.0.0/8" 或 "240e::/12"

    Returns:
        ECSOption 实例
    """
    address, prefix_len = parse_subnet(subnet)
    # ECSOption(address, srclen, scopelen)
    # srclen=None 表示使用默认值 (IPv4=24, IPv6=56)
    return dns.edns.ECSOption(address, srclen=prefix_len, scopelen=0)


def query_with_ecs(dns_server: str, qname: str, rdtype: RdataType,
                   ecs_subnet: str, timeout: float = 10.0) -> Set[str]:
    """
    使用指定 DNS 服务器和 ECS 子网查询记录

    Args:
        dns_server: DNS 服务器 IP
        qname: 查询域名
        rdtype: 记录类型 (A 或 AAAA)
        ecs_subnet: ECS 子网 (如 "1.0.0.0/8" 或 "240e::/12")
        timeout: 超时时间(秒)

    Returns:
        收集到的 IP 地址集合
    """
    msg = dns.message.make_query(qname, rdtype, want_dnssec=False)

    # 添加 ECS 选项
    ecs_opt = create_ecs_option(ecs_subnet)
    msg.use_edns(ednsflags=0, options=[ecs_opt])

    try:
        response = dns.query.udp(msg, dns_server, timeout=timeout, port=53)

        addrs = set()
        for rrset in response.answer:
            if rdtype == RdataType.A and rrset.rdtype == RdataType.A:
                for rr in rrset:
                    addrs.add(str(rr))
            elif rdtype == RdataType.AAAA and rrset.rdtype == RdataType.AAAA:
                for rr in rrset:
                    addrs.add(str(rr))

        return addrs
    except Exception as e:
        print(f"[WARN] Query {dns_server} for {qname} with ECS {ecs_subnet} failed: {e}")
        return set()


def query_all(dns_server: str, qname: str, rdtype: RdataType,
              ecs_subnets: list, timeout: float = 10.0) -> Set[str]:
    """
    使用指定 DNS 服务器轮询所有 ECS 子网

    Args:
        dns_server: DNS 服务器 IP
        qname: 查询域名
        rdtype: 记录类型 (RdataType.A 或 RdataType.AAAA)
        ecs_subnets: ECS 子网列表
        timeout: 超时时间

    Returns:
        收集到的 IP 地址集合
    """
    all_ips = set()
    rdtype_name = "A" if rdtype == RdataType.A else "AAAA"

    for ecs_subnet in ecs_subnets:
        ips = query_with_ecs(dns_server, qname, rdtype, ecs_subnet, timeout)
        all_ips.update(ips)
        print(f"  [{rdtype_name}] {dns_server} + {ecs_subnet}: +{len(ips)}, total: {len(all_ips)}")

    return all_ips


def harvest_v4() -> Set[str]:
    """采集 IPv4 地址 (包含台湾省诱饵网段)"""
    print("\n=== Harvesting IPv4 ===")
    all_ips = set()

    # 合并中国骨干网 + 台湾省诱饵网段
    all_subnets = CHINA_BACKBONE_V4 + TAIWAN_BACKBONE_V4
    print(f"  Subnets: {len(CHINA_BACKBONE_V4)} CN + {len(TAIWAN_BACKBONE_V4)} TW = {len(all_subnets)} total")

    for dns_server in DNS_SERVERS:
        ips = query_all(dns_server, TARGET_DOMAIN, RdataType.A, all_subnets)
        all_ips.update(ips)

    return all_ips


def harvest_v6() -> Set[str]:
    """采集 IPv6 地址"""
    print("\n=== Harvesting IPv6 ===")
    all_ips = set()

    for dns_server in DNS_SERVERS:
        ips = query_all(dns_server, TARGET_DOMAIN, RdataType.AAAA, CHINA_BACKBONE_V6)
        all_ips.update(ips)

    return all_ips


def save_ips(ips: Set[str], filepath: str):
    """保存 IP 列表到文件"""
    with open(filepath, 'w') as f:
        for ip in sorted(ips):
            f.write(f"{ip}\n")
    print(f"Saved {len(ips)} IPs to {filepath}")


def main():
    """主入口"""
    print("=" * 60)
    print("FCM Harvester - DNS 采集器")
    print("=" * 60)
    print(f"Target domain: {TARGET_DOMAIN}")
    print(f"DNS servers: {DNS_SERVERS}")
    print("-" * 60)

    # 采集 IPv4
    ipv4_ips = harvest_v4()
    save_ips(ipv4_ips, OUTPUT_V4)

    print("-" * 60)

    # 采集 IPv6
    ipv6_ips = harvest_v6()
    save_ips(ipv6_ips, OUTPUT_V6)

    print("=" * 60)
    print(f"Harvest complete: IPv4={len(ipv4_ips)}, IPv6={len(ipv6_ips)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
