import subprocess
from concurrent.futures import ThreadPoolExecutor

alive_hosts = []

def ping_host(ip):
    command = f"ping -n 1 -w 1000 {ip}"
    
    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Decode output and check for actual reply
    output = result.stdout.decode('utf-8', errors='ignore')
    
    # REAL ping success contains "TTL="
    if result.returncode == 0 and "TTL=" in output.upper():
        alive_hosts.append({
            "ip": ip,
            "status": "ONLINE"
        })

def discover_hosts(network_prefix):
    alive_hosts.clear()
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        for i in range(1, 255):
            ip = f"{network_prefix}.{i}"
            executor.submit(ping_host, ip)
    
    return alive_hosts

if __name__ == "__main__":
    network = input("Enter Network Prefix (Example 192.168.1): ")
    results = discover_hosts(network)
    
    print("\nAlive Hosts:\n")
    for host in results:
        print(host)