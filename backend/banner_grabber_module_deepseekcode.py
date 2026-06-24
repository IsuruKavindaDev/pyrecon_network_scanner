# backend/banner_grabber.py
import socket
import threading
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Common ports to grab banners from
TARGET_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]

def grab_banner(ip, port, timeout=2):
    """Attempt to grab banner from a specific port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send appropriate probe based on port
        if port == 80 or port == 8080 or port == 8000:
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        elif port == 443:
            sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
        elif port == 21:  # FTP
            pass
        elif port == 22:  # SSH
            pass
        elif port == 25:  # SMTP
            sock.send(b"EHLO test\r\n")
        else:
            sock.send(b"\r\n")
        
        banner = sock.recv(256)
        sock.close()
        
        decoded = banner.decode('utf-8', errors='ignore').strip()
        # Clean up the banner
        decoded = decoded.replace('\n', ' ').replace('\r', ' ')[:60]
        return decoded if decoded else "Service detected (no banner)"
    
    except socket.timeout:
        return "Open - No banner"
    except ConnectionRefusedError:
        return "Closed"
    except Exception as e:
        return f"Error"

def analyze_banner(banner, port):
    """Extract intelligence from banner"""
    intelligence = []
    
    if not banner or len(banner) < 2 or banner in ["Closed", "Open - No banner", "Error"]:
        return intelligence
    
    banner_lower = banner.lower()
    
    # Web servers
    if 'apache' in banner_lower:
        intelligence.append("🌐 Apache Web Server")
    elif 'nginx' in banner_lower:
        intelligence.append("🌐 Nginx Web Server")
    elif 'iis' in banner_lower:
        intelligence.append("🌐 Microsoft IIS")
    
    # SSH
    if 'ssh' in banner_lower:
        intelligence.append("🔐 SSH Service")
        if 'dropbear' in banner_lower:
            intelligence.append("🔐 Dropbear SSH")
        elif 'openssh' in banner_lower:
            intelligence.append("🔐 OpenSSH")
    
    # FTP
    if 'ftp' in banner_lower:
        intelligence.append("📁 FTP Service")
        if 'vsftpd' in banner_lower:
            intelligence.append("📁 vsFTPd")
    
    # HTTP success
    if '200 ok' in banner_lower or 'http' in banner_lower:
        intelligence.append("✅ Web Server Responding")
    
    return intelligence

def scan_port(ip, port, results):
    """Scan a single port and store results"""
    banner = grab_banner(ip, port)
    analyses = analyze_banner(banner, port)
    
    results[port] = {
        'banner': banner,
        'analyses': analyses
    }

def main():
    console.print(Panel.fit("🔍 AI-Powered Banner Grabbing Module", style="bold cyan"))
    
    target = input("\n📡 Enter Target IP: ").strip()
    
    console.print(f"\n[bold yellow]🔄 Scanning {target}...[/bold yellow]\n")
    
    # Multi-threaded scanning
    results = {}
    threads = []
    
    for port in TARGET_PORTS:
        thread = threading.Thread(target=scan_port, args=(target, port, results))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads
    for thread in threads:
        thread.join()
    
    # Display results
    table = Table(title=f"📋 Banner Results for {target}", 
                  title_style="bold green")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="yellow")
    table.add_column("Banner/Response", style="white")
    table.add_column("Intel", style="green")
    
    for port in sorted(results.keys()):
        data = results[port]
        
        # Determine service name
        service = "Unknown"
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        service = service_map.get(port, "Unknown")
        
        intel_str = ", ".join(data['analyses']) if data['analyses'] else "—"
        banner_display = data['banner'][:50] if data['banner'] else "—"
        
        # Color code the banner based on status
        if "Closed" in banner_display:
            banner_display = f"[red]{banner_display}[/red]"
        elif "Open" in banner_display or "200 OK" in banner_display:
            banner_display = f"[green]{banner_display}[/green]"
        
        table.add_row(str(port), service, banner_display, intel_str[:40])
    
    console.print(table)
    
    # Risk Summary
    console.print("\n[bold yellow]⚠️ Security Analysis:[/bold yellow]")
    
    risk_found = False
    for port, data in results.items():
        banner = data['banner']
        
        if port == 21 and "Closed" not in banner:
            console.print(f"  🟡 Port 21 (FTP) - [yellow]Medium Risk: Unencrypted file transfer[/yellow]")
            risk_found = True
        elif port == 23 and "Closed" not in banner:
            console.print(f"  🔴 Port 23 (Telnet) - [red]HIGH Risk: Unencrypted remote access[/red]")
            risk_found = True
        elif port == 80 and "200 OK" in banner:
            console.print(f"  ℹ️  Port 80 (HTTP) - [blue]Info: Web interface accessible[/blue]")
            risk_found = True
    
    if not risk_found:
        console.print("  ✅ No high-risk services detected")
    
    # Summary
    open_ports = [p for p, d in results.items() if "Closed" not in d['banner'] and "Error" not in d['banner']]
    console.print(f"\n[bold cyan]📊 Summary:[/bold cyan] {len(open_ports)} responsive ports found")
    
    # Export option
    export = input("\n💾 Save results? (y/n): ").strip().lower()
    if export == 'y':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"banner_scan_{target}_{timestamp}.json"
        
        import json
        # Convert to JSON-serializable format
        export_data = {}
        for port, data in results.items():
            export_data[port] = {
                'banner': data['banner'],
                'intelligence': data['analyses']
            }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        console.print(f"[green]✅ Saved to {filename}[/green]")

if __name__ == "__main__":
    main()