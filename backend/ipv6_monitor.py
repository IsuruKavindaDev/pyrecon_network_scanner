import socket
import psutil


def get_local_ipv6():

    addresses = []

    hostname = socket.gethostname()

    try:

        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_INET6
        )

        for result in results:

            ipv6 = result[4][0]

            if ipv6 not in addresses:
                addresses.append(ipv6)

    except Exception:
        pass

    return addresses


def monitor_ipv6_connections():

    results = []

    try:

        for conn in psutil.net_connections():

            if conn.raddr:

                remote_ip = conn.raddr.ip

                if ":" in remote_ip:

                    results.append({
                        "remote_ipv6": remote_ip,
                        "status": conn.status
                    })

    except Exception:
        pass

    return results