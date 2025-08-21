
from __future__ import annotations
import ipaddress
from typing import Iterable, Set

PRIVATE_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"), # link-local
]
PRIVATE_V6 = [
    ipaddress.ip_network("fc00::/7"),     # unique local
    ipaddress.ip_network("fe80::/10"),    # link-local
    ipaddress.ip_network("::1/128"),      # loopback
]

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in PRIVATE_V4)
    else:
        return any(ip in net for net in PRIVATE_V6)

def filter_external(ips: Iterable[str]) -> Set[str]:
    return {ip for ip in ips if not is_private_ip(ip)}

def filter_internal(ips: Iterable[str]) -> Set[str]:
    return {ip for ip in ips if is_private_ip(ip)}
