import socket
from rich.console import Console
from rich.table import Table

console = Console()

ports_to_scan = [21, 22, 23, 80, 443]

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)

        sock.connect((ip, port))

        if port == 80:
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")

        banner = sock.recv(1024)

        return banner.decode(errors="ignore").strip()

    except:
        return "No Banner"

    finally:
        sock.close()

def main():
    target = input("Enter Target IP: ")

    table = Table(title=f"Banner Grabbing Results for {target}")

    table.add_column("Port", style="cyan")
    table.add_column("Banner", style="green")

    for port in ports_to_scan:

        banner = grab_banner(target, port)

        table.add_row(str(port), banner[:80])

    console.print(table)

if __name__ == "__main__":
    main()