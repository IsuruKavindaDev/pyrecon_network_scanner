import socket
from rich.console import Console
from rich.table import Table

console = Console()

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:
            return True
        else:
            return False

    except Exception:
        return False

    finally:
        sock.close()

def main():
    target = input("Enter Target IP: ")

    table = Table(title=f"Open Ports on {target}")

    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("Status", style="red")

    for port, service in common_ports.items():

        if scan_port(target, port):
            table.add_row(str(port), service, "OPEN")

    console.print(table)

if __name__ == "__main__":
    main()