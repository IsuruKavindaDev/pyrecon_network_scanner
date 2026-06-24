from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import socket
import subprocess
import threading

import psutil

from concurrent.futures import ThreadPoolExecutor
from getmac import get_mac_address

from public_ip_info import get_public_ip_info
from internet_monitor import check_internet

from fastapi.responses import FileResponse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter

import dns.resolver

import whois

from ipv6_monitor import get_local_ipv6
from ipv6_monitor import monitor_ipv6_connections

import os

app = FastAPI()

# =========================================
# CORS CONFIGURATION
# =========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================
# GLOBAL STORAGE
# =========================================

scan_results = []
scan_lock = threading.Lock()


# =========================================
# COMMON SUBDOMAIN WORDLIST
# =========================================

common_subdomains = [

    "www",
    "mail",
    "ftp",
    "smtp",
    "imap",
    "pop",
    "webmail",
    "ns1",
    "ns2",
    "vpn",
    "blog",
    "dev",
    "test",
    "api",
    "portal",
    "admin",
    "docs",
    "shop",
    "support",
    "accounts"

]

# =========================================
# COMMON SERVICES
# =========================================

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
    3389: "RDP",
    554: "RTSP",
    9100: "PRINTER",
    1883: "MQTT",
    8080: "WEB MANAGEMENT"
}

# =========================================
# VULNERABILITY DATABASE
# =========================================

vulnerability_db = {
    21: {
        "cve": "CVE-1999-0497",
        "vulnerability": "FTP Anonymous Login",
        "severity": "HIGH"
    },
    22: {
        "cve": "CVE-2018-15473",
        "vulnerability": "OpenSSH User Enumeration",
        "severity": "MEDIUM"
    },
    23: {
        "cve": "CVE-2020-10188",
        "vulnerability": "Telnet Insecure Protocol",
        "severity": "CRITICAL"
    },
    25: {
        "cve": "CVE-2011-1764",
        "vulnerability": "SMTP Command Injection",
        "severity": "MEDIUM"
    },
    53: {
        "cve": "CVE-2020-1350",
        "vulnerability": "DNS SIGRed Vulnerability",
        "severity": "CRITICAL"
    },
    80: {
        "cve": "CVE-2021-41773",
        "vulnerability": "Apache Path Traversal",
        "severity": "HIGH"
    },
    110: {
        "cve": "CVE-2018-19518",
        "vulnerability": "POP3 Buffer Overflow",
        "severity": "MEDIUM"
    },
    135: {
        "cve": "CVE-2017-0147",
        "vulnerability": "Windows RPC Remote Code Execution",
        "severity": "HIGH"
    },
    139: {
        "cve": "CVE-2003-0201",
        "vulnerability": "NetBIOS Enumeration",
        "severity": "HIGH"
    },
    143: {
        "cve": "CVE-2020-8616",
        "vulnerability": "IMAP Information Disclosure",
        "severity": "MEDIUM"
    },
    443: {
        "cve": "CVE-2014-0160",
        "vulnerability": "Heartbleed OpenSSL",
        "severity": "CRITICAL"
    },
    445: {
        "cve": "CVE-2017-0144",
        "vulnerability": "EternalBlue SMB",
        "severity": "CRITICAL"
    },
    3389: {
        "cve": "CVE-2019-0708",
        "vulnerability": "BlueKeep RDP",
        "severity": "CRITICAL"
    },
    554: {
        "cve": "CVE-2017-8225",
        "vulnerability": "RTSP Authentication Bypass",
        "severity": "HIGH"
    },
    9100: {
        "cve": "CVE-2018-5924",
        "vulnerability": "Printer Information Disclosure",
        "severity": "MEDIUM"
    },
    1883: {
        "cve": "CVE-2021-34429",
        "vulnerability": "MQTT Unauthenticated Access",
        "severity": "HIGH"
    },
    8080: {
        "cve": "CVE-2021-44228",
        "vulnerability": "Log4Shell RCE",
        "severity": "CRITICAL"
    }
}

# =========================================
# RISK ENGINE
# =========================================

critical_ports = [23, 53, 443, 445, 3389, 8080]
high_ports = [21, 80, 135, 139, 554, 1883]
medium_ports = [22, 25, 110, 143, 9100]

# =========================================
# MAC VENDOR DATABASE
# =========================================

mac_vendor_db = {
    "B8-27-EB": "Raspberry Pi",
    "FC-FB-FB": "Google",
    "3C-52-82": "Samsung",
    "00-1A-79": "Cisco",
    "F4-F5-E8": "Google Nest",
    "44-65-0D": "Xiaomi",
    "DC-A6-32": "Raspberry Pi",
    "00-14-22": "Dell",
    "A4-2B-B0": "Apple",
    "D8-3A-DD": "TP-Link",
    "EC-41-18": "Hikvision",
    "00-17-88": "Philips"
}

# =========================================
# HOME API
# =========================================

@app.get("/")
def home():
    return {
        "message": "PYRECON Backend Running",
        "version": "2.0",
        "features": [
            "Port Scanning",
            "CVE Vulnerability Detection",
            "Network Discovery",
            "Banner Grabbing",
            "OS Fingerprinting",
            "MAC Address Detection"
        ]
    }

# =========================================
# PUBLIC IP API
# =========================================

@app.get("/public-ip-info")
def public_ip_info():
    return get_public_ip_info()

# =========================================
# INTERNET STATUS API
# =========================================

@app.get("/internet-status")
def internet_status():
    return check_internet()

# =========================================
# BANNER GRABBING ENGINE
# =========================================

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        
        if port == 80 or port == 443 or port == 8080:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            sock.send(b"HELP\r\n")
        elif port == 22:
            sock.send(b"SSH-2.0-PYRECON\r\n")
        
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        
        if banner:
            return banner[:200]  # Limit banner length
    except:
        pass
    
    return "Unknown Banner"

# =========================================
# PORT SCANNER ENGINE WITH CVE DETECTION
# =========================================

def scan_port(ip, port):
    global scan_results
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            service = common_services.get(port, "Unknown")
            
            # Risk Classification
            if port in critical_ports:
                risk = "CRITICAL"
            elif port in high_ports:
                risk = "HIGH"
            elif port in medium_ports:
                risk = "MEDIUM"
            else:
                risk = "LOW"
            
            # Banner Grabbing
            banner = grab_banner(ip, port)
            
            # CVE Detection
            vuln_info = vulnerability_db.get(port)
            
            if vuln_info:
                cve = vuln_info["cve"]
                vulnerability = vuln_info["vulnerability"]
                severity = vuln_info["severity"]
            else:
                cve = "N/A"
                vulnerability = "No Known Vulnerability"
                severity = "SAFE"
            
            # Fix duplicate results
            with scan_lock:
                already_exists = any(result["port"] == port for result in scan_results)
                
                if not already_exists:
                    scan_results.append({
                        "port": port,
                        "service": service,
                        "status": "OPEN",
                        "risk": risk,
                        "banner": banner,
                        "cve": cve,
                        "vulnerability": vulnerability,
                        "severity": severity
                    })
        
        sock.close()
    except:
        pass

# =========================================
# MAC ADDRESS + VENDOR DETECTION
# =========================================

def get_vendor_from_mac(ip):
    try:
        mac = get_mac_address(ip=ip)
        if mac:
            mac = mac.upper().replace(":", "-")
            mac_prefix = mac[0:8]
            vendor = mac_vendor_db.get(mac_prefix, "Unknown Vendor")
            return mac, vendor
    except:
        pass
    
    return "UNKNOWN", "Unknown Vendor"

# =========================================
# DEVICE IDENTIFICATION ENGINE
# =========================================

def identify_device(ip, hostname="UNKNOWN"):
    detected_ports = []
    common_check_ports = [21, 22, 23, 80, 443, 445, 3389, 554, 9100, 1883, 8080]
    
    for port in common_check_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                detected_ports.append(port)
            sock.close()
        except:
            pass
    
    hostname_lower = hostname.lower()
    
    if "desktop" in hostname_lower:
        return "WINDOWS PC"
    elif "laptop" in hostname_lower:
        return "LAPTOP"
    elif "android" in hostname_lower:
        return "ANDROID DEVICE"
    elif "iphone" in hostname_lower:
        return "IPHONE"
    elif "printer" in hostname_lower:
        return "NETWORK PRINTER"
    elif "camera" in hostname_lower:
        return "IP CAMERA"
    elif "raspberry" in hostname_lower:
        return "RASPBERRY PI"
    elif "tv" in hostname_lower:
        return "SMART TV"
    elif "esp32" in hostname_lower:
        return "ESP32 IOT DEVICE"
    elif 445 in detected_ports and 3389 in detected_ports:
        return "WINDOWS PC"
    elif 80 in detected_ports and 443 in detected_ports:
        return "ROUTER"
    elif 22 in detected_ports:
        return "LINUX DEVICE"
    elif 9100 in detected_ports:
        return "NETWORK PRINTER"
    elif 554 in detected_ports:
        return "IP CAMERA"
    elif 1883 in detected_ports:
        return "MQTT IOT DEVICE"
    elif 8080 in detected_ports:
        return "WEB-BASED IOT DEVICE"
    else:
        return "UNKNOWN DEVICE"

# =========================================
# OS FINGERPRINTING
# =========================================

def detect_os(ip):
    try:
        output = subprocess.check_output(f"ping -n 1 {ip}", shell=True).decode()
        ttl = None
        
        if "TTL=" in output:
            ttl = int(output.split("TTL=")[1].split("\r")[0])
        
        if ttl:
            if ttl <= 64:
                return "LINUX/UNIX"
            elif ttl <= 128:
                return "WINDOWS"
            else:
                return "NETWORK DEVICE"
    except:
        pass
    
    return "UNKNOWN OS"

# =========================================
# HOST DISCOVERY ENGINE
# =========================================

def discover_hosts(network_prefix):
    alive_hosts = []
    
    def ping_host(ip):
        command = f"ping -n 1 {ip}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        
        if "TTL=" in output:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "UNKNOWN"
            
            device_type = identify_device(ip, hostname)
            os_type = detect_os(ip)
            mac_address, vendor = get_vendor_from_mac(ip)
            
            alive_hosts.append({
                "ip": ip,
                "hostname": hostname,
                "device_type": device_type,
                "operating_system": os_type,
                "mac_address": mac_address,
                "vendor": vendor,
                "status": "ONLINE"
            })
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        for i in range(1, 255):
            ip = f"{network_prefix}.{i}"
            executor.submit(ping_host, ip)
    
    return alive_hosts


# =========================================
# LOCAL IPV6 DISCOVERY
# =========================================

def get_local_ipv6():

    ipv6_list = []

    for interface, addresses in psutil.net_if_addrs().items():

        for addr in addresses:

            if addr.family == socket.AF_INET6:

                if not addr.address.startswith("::1"):

                    ipv6_list.append({

                        "interface": interface,

                        "ipv6": addr.address

                    })

    return ipv6_list

# =========================================
# PORT SCAN API
# =========================================

@app.get("/scan")
def scan(ip: str, start_port: int = 1, end_port: int = 1000):
    global scan_results
    scan_results.clear()
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port)
    
    # Wait a bit for all scans to complete
    import time
    time.sleep(2)
    
    return {
        "target": ip,
        "total_ports_scanned": end_port - start_port + 1,
        "open_ports": len(scan_results),
        "results": sorted(scan_results, key=lambda x: x["port"])
    }

# =========================================
# RESULTS API
# =========================================

@app.get("/results")
def results():
    return {
        "scan_results": scan_results,
        "total_open_ports": len(scan_results)
    }

# =========================================
# NETWORK DISCOVERY API
# =========================================

@app.get("/discover")
def discover(network: str):
    results = discover_hosts(network)
    return {
        "network": network,
        "total_devices": len(results),
        "devices": results
    }

# =========================================
# CVE VULNERABILITY SUMMARY API
# =========================================

@app.get("/vulnerability-summary")
def vulnerability_summary():
    """Get summary of vulnerabilities found in last scan"""
    if not scan_results:
        return {"message": "No scan results available. Please run a scan first."}
    
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "safe": 0,
        "vulnerabilities": []
    }
    
    for result in scan_results:
        severity = result.get("severity", "SAFE")
        
        if severity == "CRITICAL":
            summary["critical"] += 1
        elif severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        elif severity == "LOW":
            summary["low"] += 1
        else:
            summary["safe"] += 1
        
        if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            summary["vulnerabilities"].append({
                "port": result["port"],
                "service": result["service"],
                "vulnerability": result["vulnerability"],
                "severity": severity,
                "cve": result["cve"],
                "risk": result["risk"]
            })
    
    return summary

# =========================================
# CVE LOOKUP API
# =========================================

@app.get("/cve/{port}")
def get_cve_info(port: int):
    """Get vulnerability information for a specific port"""
    vuln = vulnerability_db.get(port)
    service = common_services.get(port, "Unknown")
    
    if vuln:
        return {
            "port": port,
            "service": service,
            "cve": vuln["cve"],
            "vulnerability": vuln["vulnerability"],
            "severity": vuln["severity"],
            "remediation": get_remediation(port)
        }
    else:
        return {
            "port": port,
            "service": service,
            "message": "No known vulnerabilities for this port",
            "severity": "SAFE"
        }

def get_remediation(port):
    """Provide remediation suggestions for vulnerable ports"""
    remediation = {
        21: "Disable anonymous FTP access and implement strong authentication",
        22: "Update OpenSSH to latest version and disable root login",
        23: "Disable Telnet and use SSH instead",
        80: "Update Apache/Nginx and implement WAF rules",
        443: "Update SSL/TLS certificates and disable weak ciphers",
        445: "Apply MS17-010 patch and disable SMBv1",
        3389: "Apply BlueKeep patch and enable Network Level Authentication",
        8080: "Update to latest version and implement proper authentication"
    }
    
    return remediation.get(port, "Review service configuration and apply latest security patches")

# =========================================
# HEALTH CHECK API
# =========================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "scan_results_count": len(scan_results),
        "vulnerability_db_size": len(vulnerability_db)
    }

# =========================================
# DNS INTELLIGENCE ENGINE
# =========================================

def get_dns_info(domain):

    dns_data = {}

    try:
        dns_data["A"] = [
            str(r)
            for r in dns.resolver.resolve(domain, "A")
        ]
    except:
        dns_data["A"] = []

    try:
        dns_data["AAAA"] = [
            str(r)
            for r in dns.resolver.resolve(domain, "AAAA")
        ]
    except:
        dns_data["AAAA"] = []

    try:
        dns_data["MX"] = [
            str(r.exchange)
            for r in dns.resolver.resolve(domain, "MX")
        ]
    except:
        dns_data["MX"] = []

    try:
        dns_data["NS"] = [
            str(r)
            for r in dns.resolver.resolve(domain, "NS")
        ]
    except:
        dns_data["NS"] = []

    try:
        dns_data["TXT"] = [
            str(r)
            for r in dns.resolver.resolve(domain, "TXT")
        ]
    except:
        dns_data["TXT"] = []

    return dns_data



# =========================================
# REVERSE DNS LOOKUP API
# =========================================

@app.get("/reverse-dns")
def reverse_dns(ip: str):

    try:

        hostname = socket.gethostbyaddr(ip)[0]

        return {
            "ip": ip,
            "hostname": hostname
        }

    except Exception as e:

        return {
            "ip": ip,
            "error": str(e)
        }

# =========================================
# DNS INFORMATION API
# =========================================

@app.get("/dns-info")
def dns_info(domain: str):

    return {
        "domain": domain,
        "dns_records": get_dns_info(domain)
    }

# =========================================
# WHOIS INTELLIGENCE API
# =========================================

@app.get("/whois")
def whois_lookup(domain: str):

    try:

        info = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": str(info.registrar),
            "creation_date": str(info.creation_date),
            "expiration_date": str(info.expiration_date),
            "updated_date": str(info.updated_date),
            "name_servers": info.name_servers,
            "emails": info.emails,
            "country": str(info.country),
            "org": str(info.org)
        }

    except Exception as e:

        return {
            "error": str(e)
        } 


# =========================================
# SUBDOMAIN ENUMERATION API
# =========================================

@app.get("/subdomains")
def enumerate_subdomains(domain: str):

    results = []

    for sub in common_subdomains:

        full_domain = f"{sub}.{domain}"

        try:

            ip = socket.gethostbyname(full_domain)

            results.append({

                "subdomain": full_domain,
                "ip_address": ip

            })

        except:

            pass

    return {

        "domain": domain,
        "total_found": len(results),
        "subdomains": results

    }       

# =========================================
# PROFESSIONAL PDF REPORT GENERATOR
# =========================================

@app.get("/generate-report")
def generate_report():

    if not scan_results:
        return {
            "message": "No scan results available"
        }

    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
        Image
    )

    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import letter
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF

    import datetime

    filename = "PYRECON_SECURITY_REPORT.pdf"

    doc = SimpleDocTemplate(
        filename,
        pagesize=letter
    )

    styles = getSampleStyleSheet()

    elements = []

    # =====================================
    # CALCULATIONS
    # =====================================

    total_ports = len(scan_results)

    critical = len([
        x for x in scan_results
        if x["risk"] == "CRITICAL"
    ])

    high = len([
        x for x in scan_results
        if x["risk"] == "HIGH"
    ])

    medium = len([
        x for x in scan_results
        if x["risk"] == "MEDIUM"
    ])

    low = len([
        x for x in scan_results
        if x["risk"] == "LOW"
    ])

    # =====================================
    # SECURITY SCORE ENGINE
    # =====================================

    score = 100

    score -= critical * 25
    score -= high * 15
    score -= medium * 8
    score -= low * 3

    if score < 0:
        score = 0

    # =====================================
    # RISK LEVEL
    # =====================================

    if score >= 80:
        overall_risk = "LOW RISK"
        risk_color = colors.green

    elif score >= 50:
        overall_risk = "MEDIUM RISK"
        risk_color = colors.orange

    else:
        overall_risk = "HIGH RISK"
        risk_color = colors.red

    # =====================================
    # COVER PAGE
    # =====================================

    title = Paragraph(
        """
        <font size=24 color='darkblue'>
        <b>PYRECON</b>
        </font>
        """,
        styles['Title']
    )

    subtitle = Paragraph(
        """
        <font size=18>
        Advanced Network Security Assessment Report
        </font>
        """,
        styles['Title']
    )

    date_text = Paragraph(
        f"""
        <br/><br/>
        <b>Generated:</b> {datetime.datetime.now()}
        <br/>
        <b>Framework:</b> PYRECON v2.0
        <br/>
        <b>Assessment Type:</b> Vulnerability Assessment
        """,
        styles['BodyText']
    )

    elements.append(title)
    elements.append(Spacer(1, 20))

    elements.append(subtitle)
    elements.append(Spacer(1, 40))

    elements.append(date_text)
    elements.append(PageBreak())

    # =====================================
    # EXECUTIVE SUMMARY
    # =====================================

    executive_title = Paragraph(
        "<font size=20><b>Executive Summary</b></font>",
        styles['Heading1']
    )

    executive_summary = Paragraph(
        f"""
        This report presents the results of the
        security assessment conducted using the
        PYRECON Cybersecurity Framework.

        The assessment identified
        <b>{total_ports}</b> open ports and
        several vulnerabilities including
        critical CVEs affecting exposed services.

        The overall security posture of the target
        is classified as:

        <font color='red'>
        <b>{overall_risk}</b>
        </font>
        """,
        styles['BodyText']
    )

    elements.append(executive_title)
    elements.append(Spacer(1, 20))
    elements.append(executive_summary)
    elements.append(Spacer(1, 30))

    # =====================================
    # SECURITY SCORE
    # =====================================

    score_title = Paragraph(
        "<font size=18><b>Security Score</b></font>",
        styles['Heading2']
    )

    score_text = Paragraph(
        f"""
        <font size=22 color='blue'>
        <b>{score}/100</b>
        </font>

        <br/><br/>

        Overall Rating:
        <font color='red'>
        <b>{overall_risk}</b>
        </font>
        """,
        styles['BodyText']
    )

    elements.append(score_title)
    elements.append(Spacer(1, 10))
    elements.append(score_text)
    elements.append(Spacer(1, 30))

    # =====================================
    # PIE CHART
    # =====================================

    chart_title = Paragraph(
        "<font size=18><b>Risk Distribution</b></font>",
        styles['Heading2']
    )

    elements.append(chart_title)
    elements.append(Spacer(1, 20))

    drawing = Drawing(400, 200)

    pie = Pie()

    pie.x = 150
    pie.y = 15
    pie.width = 150
    pie.height = 150

    pie.data = [
        critical,
        high,
        medium,
        low
    ]

    pie.labels = [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]

    pie.slices[0].fillColor = colors.red
    pie.slices[1].fillColor = colors.orange
    pie.slices[2].fillColor = colors.yellow
    pie.slices[3].fillColor = colors.green

    drawing.add(pie)

    elements.append(drawing)
    elements.append(Spacer(1, 30))

    # =====================================
    # SUMMARY TABLE
    # =====================================

    summary_title = Paragraph(
        "<font size=18><b>Scan Summary</b></font>",
        styles['Heading2']
    )

    elements.append(summary_title)
    elements.append(Spacer(1, 10))

    summary_data = [

        ["Metric", "Value"],

        ["Total Open Ports", str(total_ports)],
        ["Critical Risks", str(critical)],
        ["High Risks", str(high)],
        ["Medium Risks", str(medium)],
        ["Low Risks", str(low)],
        ["Security Score", f"{score}/100"]

    ]

    summary_table = Table(summary_data, colWidths=[250, 200])

    summary_table.setStyle(TableStyle([

        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),

        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),

        ('GRID', (0, 0), (-1, -1), 1, colors.black),

        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),

        ('BACKGROUND', (0, 1), (-1, -1), colors.beige)

    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 30))

    # =====================================
    # DETAILED VULNERABILITY TABLE
    # =====================================

    vuln_title = Paragraph(
        "<font size=18><b>Detailed Vulnerability Analysis</b></font>",
        styles['Heading2']
    )

    elements.append(vuln_title)
    elements.append(Spacer(1, 15))

    vuln_data = [[

        "Port",
        "Service",
        "Risk",
        "CVE",
        "Vulnerability"

    ]]

    for result in scan_results:

        vuln_data.append([

            str(result["port"]),
            result["service"],
            result["risk"],
            result["cve"],
            result["vulnerability"]

        ])

    vuln_table = Table(vuln_data, colWidths=[50, 90, 80, 110, 170])

    style = TableStyle([

        ('BACKGROUND', (0, 0), (-1, 0), colors.black),

        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),

        ('GRID', (0, 0), (-1, -1), 1, colors.gray),

        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold')

    ])

    # =====================================
    # COLORED RISK LEVELS
    # =====================================

    for i, result in enumerate(scan_results, start=1):

        if result["risk"] == "CRITICAL":

            style.add(
                'BACKGROUND',
                (2, i),
                (2, i),
                colors.red
            )

            style.add(
                'TEXTCOLOR',
                (2, i),
                (2, i),
                colors.white
            )

        elif result["risk"] == "HIGH":

            style.add(
                'BACKGROUND',
                (2, i),
                (2, i),
                colors.orange
            )

        elif result["risk"] == "MEDIUM":

            style.add(
                'BACKGROUND',
                (2, i),
                (2, i),
                colors.yellow
            )

        else:

            style.add(
                'BACKGROUND',
                (2, i),
                (2, i),
                colors.lightgreen
            )

    vuln_table.setStyle(style)

    elements.append(vuln_table)
    elements.append(Spacer(1, 30))

    # =====================================
    # RECOMMENDATIONS
    # =====================================

    recommendation_title = Paragraph(
        "<font size=18><b>Security Recommendations</b></font>",
        styles['Heading2']
    )

    recommendation_text = Paragraph(
        """
        • Apply latest security patches immediately.<br/><br/>
        • Disable unused services and ports.<br/><br/>
        • Replace insecure protocols such as Telnet.<br/><br/>
        • Implement firewall filtering rules.<br/><br/>
        • Enable IDS/IPS monitoring systems.<br/><br/>
        • Use strong authentication mechanisms.<br/><br/>
        • Regularly monitor network activity.<br/><br/>
        """,
        styles['BodyText']
    )

    elements.append(recommendation_title)
    elements.append(Spacer(1, 10))
    elements.append(recommendation_text)

    # =====================================
    # CONCLUSION
    # =====================================

    conclusion_title = Paragraph(
        "<font size=18><b>Conclusion</b></font>",
        styles['Heading2']
    )

    conclusion_text = Paragraph(
        f"""
        The assessment identified multiple
        vulnerabilities affecting the target system.

        The environment is currently classified as
        <b>{overall_risk}</b>.

        Immediate remediation actions are strongly
        recommended to improve the overall
        security posture.
        """,
        styles['BodyText']
    )

    elements.append(conclusion_title)
    elements.append(Spacer(1, 10))
    elements.append(conclusion_text)

    # =====================================
    # BUILD PDF
    # =====================================

    doc.build(elements)

    return FileResponse(
        path=filename,
        media_type='application/pdf',
        filename=filename
    )


@app.get("/ipv6-info")
def ipv6_info():

    return {

        "ipv6_addresses": get_local_ipv6()

    }

# =========================================
# IPV6 API
# =========================================

@app.get("/ipv6-info")
def ipv6_info():

    return {

        "ipv6_addresses": get_local_ipv6()

    }

# =========================================
# REVERSE DNS LOOKUP API
# =========================================

@app.get("/reverse-dns")
def reverse_dns(ip: str):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {
            "ip": ip,
            "hostname": hostname
        }
    except Exception as e:
        return {
            "ip": ip,
            "error": str(e)
        }
    


       