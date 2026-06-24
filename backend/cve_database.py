from cve_database import cve_database

cve_database = {

    "FTP": {
        "cve": "CVE-2015-3306",
        "severity": "HIGH",
        "description": "VSFTPD Backdoor Vulnerability"
    },

    "TELNET": {
        "cve": "CVE-2020-10188",
        "severity": "CRITICAL",
        "description": "Telnet Remote Access Vulnerability"
    },

    "SMB": {
        "cve": "CVE-2017-0144",
        "severity": "CRITICAL",
        "description": "EternalBlue SMB Vulnerability"
    },

    "RDP": {
        "cve": "CVE-2019-0708",
        "severity": "HIGH",
        "description": "BlueKeep RDP Vulnerability"
    },

    "HTTP": {
        "cve": "CVE-2021-41773",
        "severity": "HIGH",
        "description": "Apache Path Traversal"
    }

}