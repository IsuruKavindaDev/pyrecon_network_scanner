import socket
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table

console = Console()

open_ports = []

def scan_port(ip, port):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    except:
        pass

def main():

    target = input("Enter Target IP: ")

    start_port = int(input("Start Port: "))
    end_port = int(input("End Port: "))

    console.print(f"\n[cyan]Scanning {target}...[/cyan]\n")

    with ThreadPoolExecutor(max_workers=100) as executor:

        for port in range(start_port, end_port + 1):

            executor.submit(scan_port, target, port)

    table = Table(title=f"Open Ports on {target}")

    table.add_column("Port", style="green")
    table.add_column("Status", style="red")

    for port in sorted(open_ports):

        table.add_row(str(port), "OPEN")

    console.print(table)

if __name__ == "__main__":
    main()