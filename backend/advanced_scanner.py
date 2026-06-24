import socket
import json
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table

console = Console()

results = []

common_services = {
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

def grab_banner(ip, port):

    try:
        sock = socket.socket()
        sock.settimeout(2)

        sock.connect((ip, port))

        if port == 80:
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()

        return banner[:100]

    except:
        return "No Banner"

def scan_port(ip, port):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:

            service = common_services.get(port, "Unknown")

            banner = grab_banner(ip, port)

            results.append({
                "port": port,
                "service": service,
                "banner": banner
            })

        sock.close()

    except:
        pass

def save_results(target):

    filename = f"scan_{target.replace('.', '_')}.json"

    with open(filename, "w") as file:
        json.dump(results, file, indent=4)

    console.print(f"\n[green]Results saved to {filename}[/green]")

def main():

    target = input("Enter Target IP: ")

    start_port = int(input("Start Port: "))
    end_port = int(input("End Port: "))

    console.print(f"\n[cyan]Scanning {target}...[/cyan]\n")

    with ThreadPoolExecutor(max_workers=100) as executor:

        for port in range(start_port, end_port + 1):

            executor.submit(scan_port, target, port)

    table = Table(title=f"Advanced Scan Results for {target}")

    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("Banner", style="yellow")

    for item in sorted(results, key=lambda x: x["port"]):

        table.add_row(
            str(item["port"]),
            item["service"],
            item["banner"]
        )

    console.print(table)

    choice = input("\nSave results? (y/n): ")

    if choice.lower() == "y":
        save_results(target)

if __name__ == "__main__":
    main()