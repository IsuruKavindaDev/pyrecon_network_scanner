from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.table import Table

console = Console()

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []

    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices

def display_results(devices):
    table = Table(title="Discovered Devices")

    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="green")

    for device in devices:
        table.add_row(device["ip"], device["mac"])

    console.print(table)

if __name__ == "__main__":
    target = input("Enter IP Range (Example: 192.168.1.0/24): ")

    devices = scan_network(target)

    display_results(devices)