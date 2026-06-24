import socket
import subprocess

# ----------------------------------
# Common IoT Ports
# ----------------------------------

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT",
    5683: "CoAP",
    8080: "HTTP-ALT",
    8883: "MQTTS",
    9100: "PRINTER"
}


# ----------------------------------
# Get MAC Address
# ----------------------------------

def get_mac_address(ip):

    try:

        output = subprocess.check_output(
            "arp -a",
            shell=True
        ).decode(errors="ignore")

        for line in output.splitlines():

            if ip in line:

                parts = line.split()

                if len(parts) >= 2:

                    return parts[1]

    except:

        pass

    return "UNKNOWN"


# ----------------------------------
# Vendor Detection
# ----------------------------------

def detect_vendor(mac):

    if mac == "UNKNOWN":

        return "UNKNOWN"

    prefix = mac.upper().replace("-", ":")[0:8]

    vendors = {

        "84:F3:EB": "Espressif",

        "B8:27:EB": "Raspberry Pi",

        "00:1A:79": "Hikvision",

        "3C:52:82": "Apple",

        "DC:A6:32": "Samsung"

    }

    return vendors.get(prefix, "Unknown Vendor")


# ----------------------------------
# Scan Ports
# ----------------------------------

def scan_ports(ip):

    open_ports = []

    for port in COMMON_PORTS.keys():

        try:

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(0.3)

            result = s.connect_ex((ip, port))

            if result == 0:

                open_ports.append(port)

            s.close()

        except:

            pass

    return open_ports


# ----------------------------------
# Protocol Detection
# ----------------------------------

def detect_protocols(open_ports):

    protocols = []

    for port in open_ports:

        if port in COMMON_PORTS:

            protocols.append(COMMON_PORTS[port])

    return protocols


# ----------------------------------
# Device Identification
# ----------------------------------

def identify_device(vendor, open_ports):

    if vendor == "Espressif":

        return "NodeMCU / ESP Device"

    if vendor == "Raspberry Pi":

        return "Raspberry Pi"

    if vendor == "Hikvision":

        return "IP Camera"

    if 9100 in open_ports:

        return "Network Printer"

    if 554 in open_ports:

        return "Streaming Device"

    if 1883 in open_ports:

        return "MQTT IoT Device"

    if 445 in open_ports:

        return "Windows Computer"

    return "Unknown Device"


# ----------------------------------
# Main Function
# ----------------------------------

def identify_iot_device(ip):

    mac = get_mac_address(ip)

    vendor = detect_vendor(mac)

    ports = scan_ports(ip)

    protocols = detect_protocols(ports)

    device = identify_device(vendor, ports)

    return {

        "ip": ip,

        "mac": mac,

        "vendor": vendor,

        "device": device,

        "open_ports": ports,

        "protocols": protocols

    }