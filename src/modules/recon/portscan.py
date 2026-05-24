"""TCP port scan module — connect scan on top 100 ports with banner grabbing."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Top 100 TCP ports
TOP_PORTS: list[int] = [
    # Web / proxies
    80, 81, 443, 8080, 8443, 8888, 9000, 9443,
    # SSH / Telnet / RDP
    22, 23, 3389, 5900, 5901, 5999,
    # Mail
    25, 110, 143, 465, 587, 993, 995, 2525,
    # DNS / DHCP
    53, 67, 68,
    # FTP
    20, 21, 69, 989, 990,
    # Database
    1433, 1521, 1522, 2049, 27017, 3306, 5432, 6379, 7001, 9042,
    11211, 27018, 27019, 50000,
    # Windows services / SMB / AD
    135, 137, 139, 445, 464, 636, 3268, 3269, 49152, 49153, 49154,
    # LDAP / Kerberos
    389, 636, 3268, 3269,
    # Remote management
    8081, 8082, 9090, 9091, 10000, 10001, 20000, 65000,
    # NTP / SNMP / Syslog
    123, 161, 162, 514, 1645, 1646, 1812, 1813,
    # Messaging / queue
    5672, 5671, 61613, 61614, 61616, 1883, 8883,
    # File sharing
    873, 2049, 3690, 9418,
    # Gaming / RTC
    3478, 3479, 5349, 5350,
    # VNC / X11
    5900, 5901, 6000, 6001,
    # Kubernetes / containers
    6443, 10250, 10251, 10252, 10255, 2379, 2380,
    # Elasticsearch
    9200, 9300,
    # Redis
    6379, 6380,
    # Memcached
    11211,
    # Misc
    42, 79, 88, 106, 113, 119, 194, 220, 389, 443, 445, 464, 513, 520,
    # Additional HTTP alternatives
    3000, 4000, 5000, 8000, 8001, 8008, 8088, 8089,
    # Tomcat / Java
    8009, 8080, 8081, 8443, 9443,
    # Splunk
    8089, 9997,
    # SSL VPN
    443, 8443, 9443,
    # Oracle
    1521, 1522, 2483, 2484,
    # HP / iLO
    17988, 17990,
    # Printer
    515, 631, 9100,
]

# Common service-to-port mapping for banner identification
SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb",
}


def scan_ports(host: str, timeout: float = 1.0, max_workers: int = 20) -> list[dict]:
    """TCP connect scan on top 100 ports with optional banner grabbing.

    Args:
        host: Target hostname or IP address.
        timeout: Connection timeout in seconds per port (default 1.0).
        max_workers: Maximum concurrent scan threads (default 20).

    Returns:
        A list of dicts:
          [{"port": int, "state": str, "service": str, "banner": str}, ...]
    """
    if not host or not isinstance(host, str):
        logger.warning(f"Invalid host: {host!r}")
        return []

    # Resolve hostname to IP if needed
    target_ip = _resolve_host(host)
    if not target_ip:
        logger.warning(f"Could not resolve host: {host}")
        return []

    logger.info(f"Starting port scan on {host} ({target_ip}) — {len(TOP_PORTS)} ports")

    results: list[dict] = []
    futures = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for port in TOP_PORTS:
            future = executor.submit(
                _scan_port, target_ip, port, timeout
            )
            futures[future] = port

        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as exc:
                logger.debug(f"Port {port} scan exception: {exc}")

    # Sort results by port number
    results.sort(key=lambda r: r["port"])
    logger.info(f"Scan complete — {len(results)} open ports found on {host}")
    return results


def _resolve_host(host: str) -> str | None:
    """Resolve hostname to IP address. Returns None on failure."""
    # Check if already an IP
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _scan_port(host: str, port: int, timeout: float) -> dict | None:
    """Scan a single TCP port.

    Performs a TCP connect scan and attempts banner grabbing if the
    port belongs to a known text-protocol service.

    Returns:
        A result dict if the port is open, None otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((host, port))
        if result != 0:
            return None

        service = SERVICE_MAP.get(port, "unknown")
        banner = _grab_banner(sock, port, timeout)

        return {
            "port": port,
            "state": "open",
            "service": service,
            "banner": banner,
        }
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """Attempt to read a banner from an open port.

    For common text-protocol services, sends a probe and reads the
    initial response.
    """
    # Only grab banners on ports likely to speak text protocols
    banner_ports = {21, 22, 23, 25, 80, 110, 143, 389, 443, 993, 995,
                    8080, 8443, 5432, 3306, 6379, 27017}

    if port not in banner_ports:
        return ""

    try:
        sock.settimeout(timeout)

        # Send protocol-specific probes
        if port == 80 or port == 8080 or port == 8443:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass  # FTP server sends banner on connect
        elif port == 25 or port == 587:
            pass  # SMTP sends banner on connect
        elif port == 143 or port == 993:
            pass  # IMAP sends banner on connect
        elif port == 110 or port == 995:
            pass  # POP3 sends banner on connect
        elif port == 22:
            pass  # SSH sends banner on connect

        # Read up to 1 KB of banner data
        banner_data = sock.recv(1024)
        if banner_data:
            # Decode safely, strip non-printable chars
            decoded = banner_data.decode("utf-8", errors="replace")
            sanitized = "".join(c if c.isprintable() or c in "\n\r\t" else " " for c in decoded)
            return sanitized.strip()[:200]

    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass

    return ""


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"Scanning ports on: {target}")
    results = scan_ports(target, timeout=0.5)
    for r in results:
        banner_str = f" — {r['banner'][:60]}" if r["banner"] else ""
        print(f"  PORT {r['port']:<5d} {r['state']:<6s} {r['service']:<12s}{banner_str}")
    print(f"\nTotal: {len(results)} open ports")
