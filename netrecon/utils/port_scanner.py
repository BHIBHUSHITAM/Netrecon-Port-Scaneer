"""
NetRecon - Port Scanner Module
Scans open TCP/UDP ports on a target IP with service detection.
"""

import socket
import concurrent.futures
import time
from dataclasses import dataclass
from typing import Optional

# Common ports with service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2181: "Zookeeper", 2375: "Docker",
    2376: "Docker TLS", 3000: "Dev Server", 3306: "MySQL",
    3389: "RDP", 4369: "RabbitMQ", 5000: "Flask/Dev",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes",
    7474: "Neo4j", 8000: "HTTP Alt", 8080: "HTTP Proxy",
    8081: "HTTP Alt", 8443: "HTTPS Alt", 8888: "Jupyter",
    9000: "PHP-FPM", 9092: "Kafka", 9200: "Elasticsearch",
    9300: "Elasticsearch", 27017: "MongoDB", 27018: "MongoDB",
    28017: "MongoDB HTTP"
}

# Risk levels for ports
HIGH_RISK = {23, 21, 445, 135, 137, 138, 139, 3389, 5900, 27017, 6379, 9200}
MEDIUM_RISK = {22, 3306, 5432, 1521, 1433, 11211, 2375, 7474, 5984}


@dataclass
class PortResult:
    port: int
    state: str  # open, closed, filtered
    service: str
    banner: Optional[str]
    risk: str  # high, medium, low
    response_time: float


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt to grab service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # Send generic probe
            try:
                s.send(b'HEAD / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200] if banner else None
            except Exception:
                return None
    except Exception:
        return None


def scan_port(host: str, port: int, timeout: float = 1.5) -> PortResult:
    """Scan a single port and return result."""
    service = COMMON_PORTS.get(port, "Unknown")
    
    if port in HIGH_RISK:
        risk = "high"
    elif port in MEDIUM_RISK:
        risk = "medium"
    else:
        risk = "low"
    
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            elapsed = round((time.time() - start) * 1000, 2)
            
            if result == 0:
                banner = grab_banner(host, port)
                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    risk=risk,
                    response_time=elapsed
                )
            else:
                return PortResult(
                    port=port, state="closed",
                    service=service, banner=None,
                    risk=risk, response_time=elapsed
                )
    except socket.timeout:
        return PortResult(
            port=port, state="filtered",
            service=service, banner=None,
            risk=risk, response_time=round((time.time() - start) * 1000, 2)
        )
    except Exception:
        return PortResult(
            port=port, state="error",
            service=service, banner=None,
            risk=risk, response_time=0
        )


def resolve_host(target: str) -> dict:
    """Resolve hostname to IP and get basic info."""
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = target if target != ip else None
        return {"ip": ip, "hostname": hostname, "error": None}
    except socket.gaierror as e:
        return {"ip": None, "hostname": None, "error": str(e)}


def scan_ports(target: str, port_range: str = "common", custom_ports: list = None,
               max_workers: int = 150, timeout: float = 1.5) -> dict:
    """
    Main port scanning function.
    port_range: 'common', 'top1000', 'full', 'custom'
    """
    # Resolve target
    resolved = resolve_host(target)
    if resolved["error"]:
        return {"error": f"Cannot resolve host: {resolved['error']}", "target": target}
    
    host = resolved["ip"]
    
    # Determine ports to scan
    if port_range == "common":
        ports = list(COMMON_PORTS.keys())
    elif port_range == "top1000":
        ports = list(range(1, 1001))
    elif port_range == "full":
        ports = list(range(1, 65536))
    elif port_range == "custom" and custom_ports:
        ports = custom_ports
    else:
        ports = list(COMMON_PORTS.keys())
    
    start_time = time.time()
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                result = future.result()
                results.append(result)
            except Exception:
                pass
    
    elapsed = round(time.time() - start_time, 2)
    
    open_ports = [r for r in results if r.state == "open"]
    open_ports.sort(key=lambda x: x.port)
    
    # Stats
    high_risk_open = [r for r in open_ports if r.risk == "high"]
    medium_risk_open = [r for r in open_ports if r.risk == "medium"]
    
    return {
        "target": target,
        "ip": host,
        "hostname": resolved["hostname"],
        "scan_time": elapsed,
        "total_scanned": len(ports),
        "open_count": len(open_ports),
        "stats": {
            "high_risk": len(high_risk_open),
            "medium_risk": len(medium_risk_open),
            "low_risk": len(open_ports) - len(high_risk_open) - len(medium_risk_open)
        },
        "open_ports": [
            {
                "port": r.port,
                "service": r.service,
                "state": r.state,
                "risk": r.risk,
                "banner": r.banner,
                "response_time": r.response_time
            }
            for r in open_ports
        ],
        "error": None
    }
