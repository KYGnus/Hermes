

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_session import Session
import paramiko
import os
import json
import re
from datetime import datetime, timedelta
import settings  # تغییر از config به settings
import logging
from logging.handlers import RotatingFileHandler
import threading
import time
import socket
import hashlib
from functools import lru_cache
import requests
from io import StringIO  # Add this import



app = Flask(__name__)
app.secret_key = 'Hermes_Analyzer'

# Load configuration from settings.py
app.config.update(
    SESSION_TYPE=settings.SESSION_TYPE,
    SESSION_FILE_DIR=settings.SESSION_FILE_DIR,
    SESSION_PERMANENT=settings.SESSION_PERMANENT,
    PERMANENT_SESSION_LIFETIME=settings.PERMANENT_SESSION_LIFETIME,
    MAX_CONTENT_LENGTH=settings.MAX_CONTENT_LENGTH,
    SSH_HOST=settings.SSH_HOST,
    SSH_PORT=settings.SSH_PORT,
    SSH_USERNAME=settings.SSH_USERNAME,
    SSH_PASSWORD=settings.SSH_PASSWORD,
    SSH_KEY=settings.SSH_KEY,
    SSH_CONNECTION_TIMEOUT=settings.SSH_CONNECTION_TIMEOUT,
    SSH_RETRY_COUNT=settings.SSH_RETRY_COUNT,
    LOG_DIR=settings.LOG_DIR,
    CVE_DB_PATH=os.path.join(settings.LOG_DIR, 'cve_db.json'),
    REPORT_DIR=os.path.join(settings.LOG_DIR, 'reports')
)

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
Session(app)

# Create required directories
os.makedirs(app.config['LOG_DIR'], exist_ok=True)
os.makedirs(app.config['REPORT_DIR'], exist_ok=True)

# ===================================================================
# USER AUTHENTICATION
# ===================================================================

class User(UserMixin):
    def __init__(self, id, username, password, role='analyst'):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

# Default user: admin / admin
users = {
    1: User(1, 'admin', bcrypt.generate_password_hash('admin').decode('utf-8'), 'admin')
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = next((user for user in users.values() if user.username == username), None)
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ===================================================================
# SSH CONNECTION MANAGER
# ===================================================================

class SSHConnectionManager:
    """Simple SSH connection manager for analysis"""
    
    def __init__(self):
        self.connections = {}
        self.lock = threading.Lock()
    
    def get_connection(self, host=None, username=None, password=None, key=None, port=None):
        """Get or create an SSH connection"""
        host = host or app.config['SSH_HOST']
        username = username or app.config['SSH_USERNAME']
        password = password or app.config['SSH_PASSWORD']
        key = key or app.config['SSH_KEY']
        port = port or app.config['SSH_PORT']
        
        conn_key = f"{username}@{host}:{port}"
        
        with self.lock:
            if conn_key in self.connections:
                conn = self.connections[conn_key]
                if self._is_alive(conn):
                    return conn
                else:
                    del self.connections[conn_key]
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                connect_kwargs = {
                    'hostname': host,
                    'port': port,
                    'username': username,
                    'timeout': app.config['SSH_CONNECTION_TIMEOUT'],
                    'allow_agent': False,
                    'look_for_keys': False,
                    'compress': True,
                    'auth_timeout': 10
                }
                
                if password:
                    connect_kwargs['password'] = password
                elif key:
                    if os.path.exists(key):
                        pkey = paramiko.RSAKey.from_private_key_file(key)
                    else:
                        pkey = paramiko.RSAKey.from_private_key(StringIO(key))
                    connect_kwargs['pkey'] = pkey
                else:
                    raise ValueError("Either password or key must be provided")
                
                ssh.connect(**connect_kwargs)
                self.connections[conn_key] = ssh
                return ssh
            except Exception as e:
                try:
                    ssh.close()
                except:
                    pass
                return None
    
    def _is_alive(self, ssh):
        try:
            transport = ssh.get_transport()
            return transport and transport.is_active()
        except:
            return False
    
    def close_all(self):
        for conn in self.connections.values():
            try:
                conn.close()
            except:
                pass
        self.connections.clear()

ssh_manager = SSHConnectionManager()

def run_command(cmd, timeout=60):
    """Execute a command and return output"""
    try:
        ssh = ssh_manager.get_connection()
        if not ssh:
            return "ERROR: Could not establish SSH connection"
        
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        
        if error:
            return f"ERROR: {error}"
        return output.strip()
    except Exception as e:
        return f"ERROR: {str(e)}"

# ===================================================================
# 1. VULNERABILITY SCANNER (CVE)
# ===================================================================

class CVEDatabase:
    """Manage CVE database with caching"""
    
    def __init__(self):
        self.db_path = app.config['CVE_DB_PATH']
        self.cves = {}
        self.last_update = None
        self._load_cache()
    
    def _load_cache(self):
        """Load cached CVE data"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    self.cves = data.get('cves', {})
                    self.last_update = data.get('last_update')
            except:
                pass
    
    def _save_cache(self):
        """Save CVE data to cache"""
        try:
            with open(self.db_path, 'w') as f:
                json.dump({
                    'cves': self.cves,
                    'last_update': datetime.now().isoformat()
                }, f)
        except:
            pass
    
    def update(self):
        """Update CVE database from NVD"""
        try:
            # Fetch latest CVEs (last 30 days)
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'pubStartDate': (datetime.now() - timedelta(days=30)).isoformat() + 'Z',
                'resultsPerPage': 2000
            }
            
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    if cve_id:
                        metrics = cve.get('metrics', {})
                        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                        
                        self.cves[cve_id] = {
                            'id': cve_id,
                            'description': cve.get('descriptions', [{}])[0].get('value', ''),
                            'severity': cvss_v3.get('baseSeverity', 'UNKNOWN'),
                            'score': cvss_v3.get('baseScore', 0),
                            'published': cve.get('published', ''),
                            'modified': cve.get('lastModified', '')
                        }
                
                self._save_cache()
                return True
        except Exception as e:
            pass
        return False
    
    def search(self, package_name, version):
        """Search for CVEs affecting a package"""
        results = []
        for cve_id, cve_data in self.cves.items():
            if package_name.lower() in cve_data.get('description', '').lower():
                results.append(cve_data)
        return results

cve_db = CVEDatabase()

def scan_vulnerabilities():
    """Scan system for vulnerabilities"""
    results = {
        'cves': [],
        'summary': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'scanned_packages': []
    }
    
    # Get installed packages
    packages_output = run_command("dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2, $3}' || rpm -qa 2>/dev/null")
    if "ERROR" in packages_output:
        return {'error': packages_output}
    
    # Update CVE database
    cve_db.update()
    
    # Scan each package
    for line in packages_output.split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2:
            package_name = parts[0]
            version = parts[1] if len(parts) > 1 else 'unknown'
            
            cvss = cve_db.search(package_name, version)
            if cvss:
                results['scanned_packages'].append({
                    'name': package_name,
                    'version': version,
                    'cves': cvss
                })
                
                for cve in cvss:
                    severity = cve.get('severity', 'UNKNOWN')
                    results['summary'][severity.lower()] = results['summary'].get(severity.lower(), 0) + 1
                    results['cves'].append(cve)
    
    return results

# ===================================================================
# 2. PORT SCANNER
# ===================================================================

SUSPICIOUS_PORTS = {

    # Remote administration
    22: "SSH (Brute-force target)",
    23: "Telnet (Insecure)",
    2323: "Alternative Telnet",
    3389: "RDP (Brute-force target)",
    5900: "VNC",
    5901: "VNC",
    5938: "TeamViewer",
    7070: "RealVNC",
    4899: "Remote Administrator (Radmin)",

    # Windows
    135: "MS RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    445: "SMB",
    593: "RPC over HTTP",

    # Databases
    1433: "Microsoft SQL Server",
    1434: "MS SQL Monitor",
    1521: "Oracle Database",
    3306: "MySQL",
    33060: "MySQL X Protocol",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    9042: "Cassandra",

    # File transfer
    20: "FTP Data",
    21: "FTP",
    69: "TFTP",
    2049: "NFS",

    # Web
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    8888: "Development/Web Console",

    # Email
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",

    # VPN
    500: "IPsec IKE",
    1701: "L2TP",
    1723: "PPTP",
    1194: "OpenVPN",
    51820: "WireGuard",

    # Proxy / Socks
    1080: "SOCKS Proxy",
    3128: "Squid Proxy",
    8080: "HTTP Proxy",

    # Tor
    9001: "Tor ORPort",
    9030: "Tor Directory",
    9050: "Tor SOCKS",
    9051: "Tor Control",
    9150: "Tor Browser SOCKS",

    # Kubernetes / Containers
    2375: "Docker API (Unencrypted)",
    2376: "Docker API TLS",
    2379: "etcd",
    2380: "etcd Peer",
    6443: "Kubernetes API",
    10250: "Kubelet",
    10255: "Read-only Kubelet",
    10257: "Controller Manager",
    10259: "Scheduler",

    # Virtualization
    16509: "libvirt",
    5900: "QEMU VNC",

    # Industrial / ICS
    502: "Modbus",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet",

    # Malware / RAT / Backdoors
    4444: "Metasploit Payload",
    5554: "Android Emulator / Backdoor",
    6660: "IRC",
    6661: "IRC",
    6662: "IRC",
    6663: "IRC",
    6664: "IRC",
    6665: "IRC",
    6666: "IRC",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",

    12345: "NetBus",
    12346: "NetBus",
    20034: "NetBus Pro",

    27374: "SubSeven",
    31337: "Back Orifice",
    31338: "Back Orifice",
    54321: "Back Orifice 2000",

    1234: "Generic RAT",
    6711: "DarkComet",
    1604: "Shivka-Burka",
    6969: "GateCrasher",
    2140: "DeepThroat",
    3150: "The Invasor",
    1243: "SubSeven Variant",
    6776: "Backdoor",
    10008: "Backdoor",
    37215: "Backdoor",
    52869: "Backdoor",

    # C2 commonly observed
    53: "DNS Tunneling Possible",
    4433: "Custom HTTPS C2",
    8081: "Alternative Web C2",
    8444: "Alternative HTTPS C2",
    9000: "Custom C2",
    9999: "Backdoor / Admin Console",

    # IoT
    7547: "TR-069 (Mirai Target)",
    7548: "TR-069 Variant",
    37215: "Huawei Backdoor",
    49152: "UPnP",
    52869: "JBL / Backdoor",

    # RPC / Misc
    111: "RPCbind",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    636: "LDAPS",
    873: "rsync",
    2049: "NFS",
}

COMMON_LEGITIMATE_PORTS = {

    # Web
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP Alternate",
    8081: "HTTP Alternate",
    8443: "HTTPS Alternate",

    # Remote Administration
    22: "SSH",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    5938: "TeamViewer",
    4899: "Radmin",

    # DNS
    53: "DNS",
    853: "DNS over TLS",

    # DHCP
    67: "DHCP Server",
    68: "DHCP Client",

    # NTP
    123: "NTP",

    # SNMP
    161: "SNMP",
    162: "SNMP Trap",

    # LDAP
    389: "LDAP",
    636: "LDAPS",

    # Kerberos
    88: "Kerberos",

    # File Transfer
    20: "FTP Data",
    21: "FTP",
    989: "FTPS Data",
    990: "FTPS Control",
    69: "TFTP",
    873: "rsync",

    # Email
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",

    # Databases
    1433: "Microsoft SQL Server",
    1434: "SQL Browser",
    1521: "Oracle",
    3306: "MySQL",
    33060: "MySQL X Protocol",
    5432: "PostgreSQL",
    6379: "Redis",
    9042: "Cassandra",
    9200: "Elasticsearch",
    9300: "Elasticsearch Transport",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",

    # Message Brokers
    5672: "RabbitMQ",
    5671: "RabbitMQ TLS",
    9092: "Apache Kafka",
    61616: "ActiveMQ",

    # Containers / Cloud
    2376: "Docker TLS",
    2379: "etcd",
    2380: "etcd Peer",
    6443: "Kubernetes API",
    10250: "Kubelet",

    # VPN
    500: "IKE/IPsec",
    1701: "L2TP",
    1723: "PPTP",
    1194: "OpenVPN",
    51820: "WireGuard",

    # Proxy
    1080: "SOCKS",
    3128: "Squid Proxy",

    # SMB / Windows
    135: "MS RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    445: "SMB",

    # RPC
    111: "RPCbind",

    # NFS
    2049: "NFS",

    # Printing
    515: "LPD",
    631: "IPP",

    # SIP / VoIP
    5060: "SIP",
    5061: "SIP TLS",

    # Virtualization
    16509: "libvirt",

    # Development
    3000: "Node.js",
    5000: "Flask Development",
    5001: "Flask Alternate",
    7001: "WebLogic",
    8000: "Python HTTP Server",
    8888: "Jupyter Notebook",

    # Monitoring
    9090: "Prometheus",
    9100: "Node Exporter",
    3001: "Grafana Agent",

    # Industrial
    502: "Modbus",
    44818: "EtherNet/IP",
    47808: "BACnet",

    # Misc
    5353: "mDNS",
    5355: "LLMNR",
    5357: "WSDAPI",
}

def scan_ports():
    """
    Enterprise Port Scanner

    Returns:
        {
            open_ports,
            suspicious_ports,
            statistics,
            risk_score
        }
    """

    results = {
        "open_ports": [],
        "suspicious_ports": [],
        "statistics": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        },
        "risk_score": 0
    }

    output = run_command("ss -tulnpH")

    if not output or "ERROR" in output:
        return {"error": output}

    seen = set()

    for line in output.splitlines():

        try:

            cols = line.split()

            protocol = cols[0].upper()

            local = cols[4]

            process = cols[-1]

            address = local.rsplit(":", 1)[0]
            port = int(local.rsplit(":", 1)[1])

        except Exception:
            continue

        if (protocol, port, process) in seen:
            continue

        seen.add((protocol, port, process))

        service = COMMON_LEGITIMATE_PORTS.get(
            port,
            SUSPICIOUS_PORTS.get(
                port,
                "Unknown Service"
            )
        )

        if port in SUSPICIOUS_PORTS:

            category = "Suspicious"

            risk = "Critical"

            recommendation = "Investigate immediately"

            results["statistics"]["critical"] += 1

            results["risk_score"] += 10

        elif port in COMMON_LEGITIMATE_PORTS:

            category = "Known"

            risk = "Low"

            recommendation = "Verify service is expected"

            results["statistics"]["low"] += 1

            results["risk_score"] += 1

        else:

            category = "Unknown"

            risk = "Medium"

            recommendation = "Review manually"

            results["statistics"]["unknown"] += 1

            results["risk_score"] += 4

        entry = {

            "protocol": protocol,

            "address": address,

            "port": port,

            "service": service,

            "process": process,

            "category": category,

            "risk": risk,

            "recommendation": recommendation,

            "loopback": (
                address.startswith("127.")
                or address == "::1"
            ),

            "external": (
                not address.startswith("127.")
                and address != "::1"
            )

        }

        results["open_ports"].append(entry)

        if category == "Suspicious":
            results["suspicious_ports"].append(entry)

        results["statistics"]["total"] += 1

    results["open_ports"].sort(
        key=lambda x: (
            {
                "Critical": 0,
                "High": 1,
                "Medium": 2,
                "Low": 3
            }.get(x["risk"], 4),
            x["port"]
        )
    )

    return results

# ===================================================================
# 3. SERVICE ANALYSIS
# ===================================================================

SERVICE_THREAT_RULES = {

    #
    # Known malicious service names
    #
    "known_services": {

        # C2 Frameworks
        "beacon.service":            ("Cobalt Strike", "Critical"),
        "teamserver.service":        ("Cobalt Strike", "Critical"),
        "sliver.service":            ("Sliver C2", "Critical"),
        "mythic.service":            ("Mythic C2", "Critical"),
        "havoc.service":             ("Havoc C2", "Critical"),
        "empire.service":            ("Empire C2", "Critical"),
        "merlin.service":            ("Merlin C2", "Critical"),
        "poshc2.service":            ("PoshC2", "Critical"),
        "koadic.service":            ("Koadic", "Critical"),

        # Payloads
        "meterpreter.service":       ("Meterpreter", "Critical"),
        "metsvc.service":            ("Meterpreter", "Critical"),

        # Tunnels
        "ligolo.service":            ("Ligolo", "High"),
        "chisel.service":            ("Chisel", "High"),
        "frpc.service":              ("Fast Reverse Proxy", "High"),
        "frps.service":              ("Fast Reverse Proxy", "High"),
        "ngrok.service":             ("Ngrok", "Medium"),
        "cloudflared.service":       ("Cloudflare Tunnel", "Medium"),
        "gsocket.service":           ("GSocket", "High"),

        # Miners
        "xmrig.service":             ("XMRig", "Critical"),
        "kinsing.service":           ("Kinsing", "Critical"),

        # Malware
        "mirai.service":             ("Mirai", "Critical"),
        "bpfdoor.service":           ("BPFDoor", "Critical"),
    },

    #
    # IOC Regex
    #
    "patterns": [

        # Hidden
        r'^\.',
        r'^\.system.*',
        r'^\.dbus.*',

        # Random names
        r'^[a-z0-9]{20,}\.service$',
        r'^[a-f0-9]{16,}\.service$',

        # Fake system services
        r'^systemd\d+\.service$',
        r'^systemd-update.*',
        r'^systemd-helper.*',
        r'^systemd-networkd\d+$',

        r'^dbusd\d*\.service$',
        r'^dbus-helper.*',

        r'^sshd\d+\.service$',
        r'^ssh-update.*',
        r'^ssh-helper.*',

        r'^crond\d+\.service$',
        r'^cron-update.*',

        # Malware keywords
        r'.*backdoor.*',
        r'.*payload.*',
        r'.*trojan.*',
        r'.*dropper.*',
        r'.*loader.*',
        r'.*inject.*',
        r'.*implant.*',

        # C2
        r'.*beacon.*',
        r'.*meterpreter.*',
        r'.*empire.*',
        r'.*sliver.*',
        r'.*havoc.*',
        r'.*mythic.*',
        r'.*merlin.*',
        r'.*poshc2.*',

        # Tunnel
        r'.*proxy.*',
        r'.*tunnel.*',
        r'.*reverse.*',
        r'.*bind.*',
        r'.*socks.*',
        r'.*ligolo.*',
        r'.*frpc.*',
        r'.*frps.*',
        r'.*chisel.*',

        # Stealers
        r'.*stealer.*',
        r'.*keylogger.*',
        r'.*credential.*',
        r'.*mimikatz.*',
        r'.*nanodump.*',

        # Crypto
        r'.*miner.*',
        r'.*xmrig.*',
        r'.*monero.*',
        r'.*cryptonight.*',

        # Rootkits
        r'.*rootkit.*',
        r'.*ghost.*',
        r'.*cloak.*',
        r'.*hidden.*'
    ],

    #
    # Suspicious install locations
    #
    "paths": [

        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/user",
        "/home",
        "/media",
        "/mnt",
        "/opt/tmp",
        "/usr/local/tmp"
    ],

    #
    # Known LOLBins
    #
    "abused_binaries": [

        "bash",
        "sh",
        "dash",
        "zsh",
        "python",
        "python3",
        "perl",
        "ruby",
        "lua",
        "php",
        "node",
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "socat"
    ]
}


def analyze_services():

    results = {
        "services": [],
        "suspicious": [],
        "summary": {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "critical": 0,
            "high": 0,
            "medium": 0
        }
    }

    output = run_command(
        "systemctl list-units --type=service --no-pager --no-legend"
    )

    if "ERROR" in output:
        return {"error": output}

    for line in output.splitlines():

        if not line.strip():
            continue

        cols = line.split()

        service = cols[0]

        state = cols[2]

        reasons = []

        severity = "Safe"

        #
        # Known IOC Database
        #
        if service in SERVICE_THREAT_RULES["known_services"]:

            family, severity = \
                SERVICE_THREAT_RULES["known_services"][service]

            reasons.append(
                f"Known malware service ({family})"
            )

        #
        # Regex IOC
        #
        for regex in SERVICE_THREAT_RULES["patterns"]:

            if re.search(regex, service, re.I):

                if severity == "Safe":
                    severity = "High"

                reasons.append(
                    f"Matched IOC: {regex}"
                )

        #
        # FragmentPath
        #
        fragment = run_command(
            f"systemctl show {service} "
            "-p FragmentPath --value"
        )

        if fragment:

            fragment = fragment.strip()

            for path in SERVICE_THREAT_RULES["paths"]:

                if fragment.startswith(path):

                    severity = "Critical"

                    reasons.append(
                        f"Loaded from suspicious path ({fragment})"
                    )

        info = {

            "service": service,

            "state": state,

            "severity": severity,

            "reasons": reasons,

            "fragment": fragment

        }

        results["services"].append(info)

        results["summary"]["total"] += 1

        if severity != "Safe":

            results["summary"]["suspicious"] += 1

            results["suspicious"].append(info)

            if severity == "Critical":
                results["summary"]["critical"] += 1

            elif severity == "High":
                results["summary"]["high"] += 1

            else:
                results["summary"]["medium"] += 1

        else:

            results["summary"]["safe"] += 1

    return results

# ===================================================================
# 4. PROCESS ANALYSIS
# ===================================================================

SUSPICIOUS_PROCESS_PATTERNS = [

    # Downloaders
    "wget",
    "curl",
    "aria2c",
    "fetch",
    "lynx",
    "links",

    # Network utilities
    "nc",
    "netcat",
    "ncat",
    "socat",
    "telnet",
    "sshpass",
    "proxychains",

    # Reverse shell
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i",
    "bash -c",
    "sh -c",
    "dash -c",
    "zsh -c",
    "mkfifo",
    "pty.spawn",

    # Scripting
    "python -c",
    "python3 -c",
    "python -m",
    "python3 -m",
    "perl -e",
    "php -r",
    "ruby -e",
    "lua -e",
    "node -e",

    # Encoded execution
    "base64",
    "eval",
    "exec(",
    "compile(",
    "marshal",
    "pickle.loads",

    # Crypto
    "openssl enc",
    "openssl aes",
    "gpg",
    "gpg --decrypt",

    # Persistence
    "systemctl enable",
    "systemctl daemon-reload",
    "crontab",
    "@reboot",

    # Malware keywords
    "backdoor",
    "payload",
    "dropper",
    "loader",
    "inject",
    "implant",
    "trojan",
    "rootkit",
    "keylogger",
    "stealer",
    "credential",

    # C2
    "meterpreter",
    "beacon",
    "cobalt",
    "sliver",
    "empire",
    "havoc",
    "mythic",
    "merlin",
    "poshc2",
    "covenant",
    "ligolo",
    "chisel",
    "frpc",
    "frps",

    # Credential dumping
    "mimikatz",
    "nanodump",
    "procdump",
    "secretsdump",
    "lsassy",

    # Cryptominers
    "miner",
    "crypto",
    "xmrig",
    "ethminer",
    "cpuminer",
    "phoenixminer",
    "lolminer",
    "nanominer",

    # Password cracking
    "hashcat",
    "john",
    "hydra",
    "medusa",
    "patator",

    # Recon
    "nmap",
    "masscan",
    "rustscan",
    "zmap",
    "amass",
    "subfinder",
    "ffuf",
    "gobuster",

    # Tunneling
    "cloudflared",
    "ngrok",
    "tailscale",
    "zerotier",
    "wireguard",

]





def analyze_processes():

    results = {
        "processes": [],
        "suspicious_processes": [],
        "summary": {
            "total": 0,
            "suspicious": 0,
            "safe": 0
        }
    }

    output = run_command("ps auxww --sort=-%cpu")

    if "ERROR" in output:
        return {"error": output}

    for line in output.splitlines()[1:]:

        if not line.strip():
            continue

        parts = line.split(None, 10)

        if len(parts) < 11:
            continue

        user = parts[0]
        pid = parts[1]

        try:
            cpu = float(parts[2])
        except:
            cpu = 0

        try:
            mem = float(parts[3])
        except:
            mem = 0

        command = parts[10]
        command_lower = command.lower()

        suspicious = False
        reasons = []

        #
        # IOC patterns
        #
        for pattern in SUSPICIOUS_PROCESS_PATTERNS:

            if pattern.lower() in command_lower:

                suspicious = True

                reasons.append(f"Matched IOC: {pattern}")

        #
        # Encoded payloads
        #
        if len(command) > 250:

            suspicious = True

            reasons.append("Very long command line")

        #
        # Base64 blobs
        #
        if "base64" in command_lower and len(command) > 120:

            suspicious = True

            reasons.append("Possible encoded payload")

        #
        # High CPU
        #
        if cpu >= 90:

            suspicious = True

            reasons.append(f"Extremely high CPU ({cpu:.1f}%)")

        elif cpu >= 70:

            reasons.append(f"High CPU ({cpu:.1f}%)")

        #
        # High Memory
        #
        if mem >= 80:

            suspicious = True

            reasons.append(f"Extremely high Memory ({mem:.1f}%)")

        elif mem >= 60:

            reasons.append(f"High Memory ({mem:.1f}%)")

        process_info = {

            "pid": pid,

            "user": user,

            "cpu": cpu,

            "mem": mem,

            "command": command[:120],

            "full_command": command,

            "suspicious": suspicious,

            "reason": "; ".join(reasons) if reasons else "None"

        }

        results["processes"].append(process_info)

        results["summary"]["total"] += 1

        if suspicious:

            results["suspicious_processes"].append(process_info)

            results["summary"]["suspicious"] += 1

        else:

            results["summary"]["safe"] += 1

    results["suspicious_processes"].sort(
        key=lambda x: (x["cpu"], x["mem"]),
        reverse=True
    )

    return results

# ===================================================================
# 5. KERNEL MODULE ANALYSIS
# ===================================================================

# ==========================================================
# Kernel Module IOC Database
# ==========================================================

SUSPICIOUS_MODULE_PATTERNS = [

    # Rootkits
    r'rootkit',
    r'root_kit',
    r'hide',
    r'hidden',
    r'stealth',
    r'phantom',
    r'ghost',
    r'cloak',
    r'invisible',

    # Hooks / Injection
    r'hook',
    r'syscall',
    r'ftrace',
    r'kprobe',
    r'uprobes',
    r'inject',
    r'inline',
    r'patch',

    # Malware
    r'backdoor',
    r'payload',
    r'dropper',
    r'loader',
    r'trojan',
    r'implant',
    r'rat',
    r'botnet',
    r'miner',
    r'crypt',
    r'keylog',
    r'credential',
    r'stealer',

    # Exploit
    r'exploit',
    r'privilege',
    r'overflow',

    # Suspicious names
    r'_hack$',
    r'_evil$',
    r'_ghost$',
    r'_cloak$',
    r'_hidden$',
    r'\.hidden$',

    # Random generated names
    r'^[a-f0-9]{16,}$',
    r'^[a-z0-9]{24,}$'
]

# ==========================================================
# Modules that deserve attention (not necessarily malicious)
# ==========================================================

SENSITIVE_KERNEL_MODULES = {

    # Network
    "tun",
    "tap",
    "bridge",
    "veth",
    "dummy",

    # Packet filtering
    "ip_tables",
    "ip6_tables",
    "x_tables",
    "nf_tables",
    "ebtables",
    "ebtable_filter",

    # Virtualization
    "kvm",
    "kvm_intel",
    "kvm_amd",
    "vhost",
    "vhost_net",

    # BPF
    "bpf",

    # Filesystem
    "overlay",
    "fuse",

    # VPN
    "wireguard",

    # Legacy protocols
    "dccp",
    "sctp",
    "tipc",

    # RDMA
    "rds"
}

# ==========================================================
# Suspicious module paths
# ==========================================================

SUSPICIOUS_MODULE_PATHS = [

    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run",
    "/home",
    "/media",
    "/mnt",
    "/opt",
    "/usr/local/tmp"

]

# ==========================================================
# Kernel Module Analysis
# ==========================================================

def analyze_kernel_modules():

    results = {

        "loaded_modules": [],
        "suspicious_modules": [],
        "all_modules": [],

        "summary": {

            "total_loaded": 0,

            "suspicious": 0,

            "unsigned": 0,

            "sensitive": 0

        }

    }

    output = run_command("lsmod")

    if "ERROR" in output:
        return {"error": output}

    modules = []

    for line in output.splitlines()[1:]:

        if not line.strip():
            continue

        name = line.split()[0]

        modules.append(name)

        results["loaded_modules"].append(name)

    results["summary"]["total_loaded"] = len(modules)

    for module in modules:

        info = {

            "name": module,

            "path": "",

            "signature": "Unknown",

            "signer": "",

            "builtin": False,

            "suspicious": False,

            "sensitive": False,

            "reasons": []

        }

        #
        # IOC Pattern Matching
        #
        for regex in SUSPICIOUS_MODULE_PATTERNS:

            if re.search(regex, module, re.IGNORECASE):

                info["suspicious"] = True

                info["reasons"].append(
                    f"Matched IOC pattern ({regex})"
                )

        #
        # Sensitive Module
        #
        if module in SENSITIVE_KERNEL_MODULES:

            info["sensitive"] = True

            results["summary"]["sensitive"] += 1

            info["reasons"].append(
                "Sensitive kernel module"
            )

        #
        # Module Path
        #
        path = run_command(
            f"modinfo -F filename {module} 2>/dev/null"
        ).strip()

        if path:

            info["path"] = path

            if path == "(builtin)":

                info["builtin"] = True

            else:

                for p in SUSPICIOUS_MODULE_PATHS:

                    if path.startswith(p):

                        info["suspicious"] = True

                        info["reasons"].append(
                            f"Loaded from suspicious path ({path})"
                        )

                        break

        #
        # Module Signature
        #
        signer = run_command(
            f"modinfo -F signer {module} 2>/dev/null"
        ).strip()

        if signer:

            info["signature"] = "Signed"

            info["signer"] = signer

        else:

            info["signature"] = "Unsigned"

            results["summary"]["unsigned"] += 1

            info["reasons"].append(
                "Unsigned kernel module"
            )

        #
        # Version
        #
        version = run_command(
            f"modinfo -F version {module} 2>/dev/null"
        ).strip()

        if version:
            info["version"] = version

        #
        # Description
        #
        description = run_command(
            f"modinfo -F description {module} 2>/dev/null"
        ).strip()

        if description:
            info["description"] = description

        #
        # License
        #
        license_name = run_command(
            f"modinfo -F license {module} 2>/dev/null"
        ).strip()

        if license_name:
            info["license"] = license_name

        results["all_modules"].append(info)

        if info["suspicious"]:

            results["summary"]["suspicious"] += 1

            results["suspicious_modules"].append(info)

    results["suspicious_modules"].sort(
        key=lambda x: x["name"].lower()
    )

    return results

# ===================================================================
# 6. INSTALLED SOFTWARE ANALYSIS
# ===================================================================

# ==========================================================
# Malware / Threat Intelligence Package Patterns
# ==========================================================

MALICIOUS_SOFTWARE_PATTERNS = [

    # Malware
    "backdoor",
    "trojan",
    "rootkit",
    "malware",
    "worm",
    "virus",
    "ransomware",
    "spyware",
    "adware",
    "dropper",
    "loader",
    "implant",
    "payload",
    "botnet",

    # Credential Theft
    "keylogger",
    "credential",
    "stealer",
    "infostealer",

    # C2 Frameworks
    "meterpreter",
    "metsvc",
    "beacon",
    "cobalt",
    "sliver",
    "empire",
    "havoc",
    "mythic",
    "merlin",
    "poshc2",
    "covenant",
    "koadic",

    # Cryptominers
    "xmrig",
    "cpuminer",
    "ethminer",
    "phoenixminer",
    "teamredminer",
    "nanominer",
    "lolminer",
    "miner",

    # Exploits
    "exploit",
    "shellcode",
    "privilege",

    # Password dumping
    "mimikatz",
    "nanodump",
    "secretsdump",
    "lsassy"
]

# ==========================================================
# Security / Pentest Tools
# ==========================================================

SECURITY_SOFTWARE = {

    "nmap",
    "masscan",
    "rustscan",
    "zmap",

    "hydra",
    "medusa",
    "patator",
    "hashcat",
    "john",

    "netcat",
    "ncat",
    "nc",
    "socat",

    "tcpdump",
    "wireshark",
    "tshark",

    "metasploit",
    "sqlmap",
    "nikto",

    "gobuster",
    "ffuf",

    "amass",
    "subfinder",

    "burpsuite",

    "enum4linux",

    "crackmapexec",

    "impacket",

    "aircrack-ng"
}

# ==========================================================
# Remote Access / Tunnel Software
# ==========================================================

REMOTE_ACCESS_SOFTWARE = {

    "ngrok",

    "cloudflared",

    "tailscale",

    "zerotier",

    "wireguard",

    "frpc",

    "frps",

    "ligolo",

    "chisel",

    "gsocket"

}

# ==========================================================
# Known Safe Packages
# ==========================================================

KNOWN_SAFE_SOFTWARE = {

    "bash",
    "coreutils",
    "glibc",
    "systemd",

    "linux",
    "linux-image",
    "linux-headers",

    "openssh",
    "openssl",

    "curl",
    "wget",

    "python",
    "python3",

    "perl",

    "php",

    "ruby",

    "golang",

    "gcc",

    "cmake",

    "make",

    "git",

    "sudo",

    "cron",

    "dbus",

    "docker",

    "containerd",

    "podman",

    "apache",
    "apache2",

    "nginx",

    "mysql",

    "mariadb",

    "postgresql",

    "redis",

    "nodejs",

    "openjdk",

    "NetworkManager"
}


# ==========================================================
# Software Analysis
# ==========================================================

def analyze_software():
    """Analyze installed software packages"""

    results = {

        "installed_packages": [],

        "suspicious_packages": [],

        "summary": {

            "total": 0,

            "safe": 0,

            "suspicious": 0,

            "security_tools": 0,

            "remote_access": 0,

            "unknown": 0

        }

    }

    package_managers = [

        ("dpkg -l 2>/dev/null | awk '/^ii/{print $2,$3}'", "dpkg"),

        ("rpm -qa --qf '%{NAME} %{VERSION}\n' 2>/dev/null", "rpm"),

        ("pacman -Q 2>/dev/null", "pacman"),

        ("apk list -I 2>/dev/null", "apk")

    ]

    packages = []

    manager = "Unknown"

    for cmd, pm in package_managers:

        output = run_command(cmd)

        if output and not output.startswith("ERROR"):

            manager = pm

            packages = output.splitlines()

            break

    if not packages:

        return {
            "error": "No supported package manager found."
        }

    for line in packages:

        if not line.strip():
            continue

        parts = line.split()

        pkg_name = parts[0]

        pkg_version = parts[1] if len(parts) > 1 else "Unknown"

        pkg_lower = pkg_name.lower()

        info = {

            "name": pkg_name,

            "version": pkg_version,

            "category": "Unknown",

            "suspicious": False,

            "reasons": []

        }

        #
        # Malware IOC
        #
        matched = False

        for pattern in MALICIOUS_SOFTWARE_PATTERNS:

            if pattern in pkg_lower:

                matched = True

                info["category"] = "Malware IOC"

                info["suspicious"] = True

                info["reasons"].append(
                    f"Matched malware pattern ({pattern})"
                )

        #
        # Security Tools
        #
        if pkg_name in SECURITY_SOFTWARE:

            info["category"] = "Security Tool"

            info["reasons"].append(
                "Security assessment tool installed"
            )

            results["summary"]["security_tools"] += 1

        #
        # Remote Access
        #
        elif pkg_name in REMOTE_ACCESS_SOFTWARE:

            info["category"] = "Remote Access"

            info["reasons"].append(
                "Remote access / tunneling software"
            )

            results["summary"]["remote_access"] += 1

        #
        # Safe Package
        #
        elif any(
            safe.lower() in pkg_lower
            for safe in KNOWN_SAFE_SOFTWARE
        ):

            info["category"] = "System Package"

        #
        # Unknown
        #
        else:

            results["summary"]["unknown"] += 1

        results["installed_packages"].append(info)

        results["summary"]["total"] += 1

        if info["suspicious"]:

            results["summary"]["suspicious"] += 1

            results["suspicious_packages"].append(info)

        else:

            results["summary"]["safe"] += 1

    results["package_manager"] = manager

    results["installed_packages"].sort(
        key=lambda x: x["name"].lower()
    )

    results["suspicious_packages"].sort(
        key=lambda x: x["name"].lower()
    )

    return results

# ===================================================================
# 7. USER ANALYSIS
# ===================================================================

def analyze_users():
    """Analyze system users and permissions"""
    results = {
        'users': [],
        'suspicious_users': [],
        'summary': {
            'total': 0,
            'root': 0,
            'sudo': 0,
            'normal': 0,
            'suspicious': 0
        }
    }
    
    users_output = run_command("getent passwd | grep -v '^\\s*$'")
    if "ERROR" in users_output:
        return {'error': users_output}
    
    sudo_output = run_command("getent group sudo | cut -d: -f4")
    sudo_users = sudo_output.split(',') if sudo_output and not sudo_output.startswith("ERROR") else []
    
    root_output = run_command("getent passwd | awk -F: '$3==0 {print $1}'")
    root_users = root_output.split('\n') if root_output and not root_output.startswith("ERROR") else []
    
    for line in users_output.split('\n'):
        if not line.strip():
            continue
        parts = line.split(':')
        if len(parts) >= 7:
            username = parts[0]
            uid = int(parts[2])
            gid = int(parts[3])
            home = parts[5]
            shell = parts[6]
            
            is_suspicious = False
            reasons = []
            
            if uid == 0:
                is_suspicious = True
                reasons.append('UID 0 (root privileges)')
            
            if shell in ['/bin/false', '/sbin/nologin', '/usr/sbin/nologin']:
                pass
            elif shell.startswith('/bin/') or shell.startswith('/usr/bin/'):
                if uid > 1000:
                    results['summary']['normal'] += 1
            else:
                is_suspicious = True
                reasons.append(f'Unusual shell: {shell}')
            
            if home.startswith('/home/') or home.startswith('/export/home/'):
                pass
            elif home != '/' and home != '/nonexistent':
                is_suspicious = True
                reasons.append(f'Unusual home directory: {home}')
            
            user_info = {
                'username': username,
                'uid': uid,
                'gid': gid,
                'home': home,
                'shell': shell,
                'sudo': username in sudo_users,
                'root': username in root_users,
                'suspicious': is_suspicious,
                'reasons': '; '.join(reasons) if reasons else 'None'
            }
            
            results['users'].append(user_info)
            results['summary']['total'] += 1
            
            if username in root_users:
                results['summary']['root'] += 1
            if username in sudo_users:
                results['summary']['sudo'] += 1
            if is_suspicious:
                results['suspicious_users'].append(user_info)
                results['summary']['suspicious'] += 1
    
    return results

# ===================================================================
# 8. SYSTEM HARDENING CHECK
# ===================================================================

def check_system_hardening():
    """Check system hardening status"""
    results = {
        'checks': [],
        'summary': {
            'passed': 0,
            'failed': 0,
            'warning': 0
        }
    }
    
    checks = [
        {
            'name': 'SELinux Status',
            'cmd': 'getenforce 2>/dev/null',
            'expected': 'Enforcing',
            'critical': True,
            'description': 'SELinux should be in enforcing mode'
        },
        {
            'name': 'AppArmor Status',
            'cmd': 'aa-status --enabled 2>/dev/null && echo "enabled" || echo "disabled"',
            'expected': 'enabled',
            'critical': True,
            'description': 'AppArmor should be enabled'
        },
        {
            'name': 'Firewall Status',
            'cmd': 'systemctl is-active ufw 2>/dev/null || systemctl is-active firewalld 2>/dev/null',
            'expected': 'active',
            'critical': True,
            'description': 'Firewall should be active'
        },
        {
            'name': 'SSH Password Authentication',
            'cmd': "grep -E '^PasswordAuthentication' /etc/ssh/sshd_config | awk '{print $2}'",
            'expected': 'no',
            'critical': True,
            'description': 'SSH password authentication should be disabled'
        },
        {
            'name': 'SSH Root Login',
            'cmd': "grep -E '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}'",
            'expected': 'no',
            'critical': True,
            'description': 'SSH root login should be disabled'
        },
        {
            'name': 'Kernel Hardening',
            'cmd': "grep -E '^kernel.randomize_va_space' /proc/sys/kernel/randomize_va_space | awk '{print $3}'",
            'expected': '2',
            'critical': True,
            'description': 'KASLR should be enabled'
        },
        {
            'name': 'Core Dumps',
            'cmd': "ulimit -c",
            'expected': '0',
            'critical': False,
            'description': 'Core dumps should be disabled'
        },
        {
            'name': 'Sysctl Hardening',
            'cmd': "sysctl net.ipv4.conf.all.accept_redirects | awk '{print $3}'",
            'expected': '0',
            'critical': False,
            'description': 'IPv4 redirects should be disabled'
        },
        {
            'name': 'Failed Login Attempts',
            'cmd': "grep -E '^maxretry' /etc/fail2ban/jail.local 2>/dev/null | awk '{print $3}'",
            'expected': '5',
            'critical': False,
            'description': 'Fail2ban should be configured'
        },
        {
            'name': 'Unattended Upgrades',
            'cmd': "dpkg -l | grep -q unattended-upgrades && echo 'installed' || echo 'not installed'",
            'expected': 'installed',
            'critical': True,
            'description': 'Unattended upgrades should be installed'
        }
    ]
    
    for check in checks:
        result = run_command(check['cmd'])
        status = 'warning'
        
        if "ERROR" not in result:
            if result == check['expected']:
                status = 'passed'
                results['summary']['passed'] += 1
            else:
                status = 'failed'
                results['summary']['failed'] += 1
                if check['critical']:
                    status = 'failed (critical)'
                    results['summary']['failed'] += 1
        else:
            results['summary']['failed'] += 1
        
        results['checks'].append({
            'name': check['name'],
            'result': result if result else 'N/A',
            'expected': check['expected'],
            'status': status,
            'critical': check['critical'],
            'description': check['description']
        })
    
    return results

# ===================================================================
# SYSTEM INFO HELPER
# ===================================================================

def get_system_info():
    """Get basic system information"""
    info = {
        'hostname': run_command("hostname"),
        'os': run_command("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'"),
        'kernel': run_command("uname -r"),
        'arch': run_command("uname -m"),
        'uptime': run_command("uptime -p"),
        'cpu': run_command("lscpu | grep 'Model name' | cut -d':' -f2 | sed 's/^[ \t]*//'"),
        'cpu_cores': run_command("nproc"),
        'memory_total': run_command("free -h | awk '/Mem:/ {print $2}'"),
        'memory_used': run_command("free -h | awk '/Mem:/ {print $3}'"),
        'disk_total': run_command("df -h / | awk 'NR==2 {print $2}'"),
        'disk_used': run_command("df -h / | awk 'NR==2 {print $3}'"),
        'load': run_command("cat /proc/loadavg | awk '{print $1, $2, $3}'")
    }
    return info

# ===================================================================
# REPORT GENERATION
# ===================================================================

def generate_html_report(results, report_id):
    """Generate HTML report from analysis results"""
    html = f"""
    <!DOCTYPE html>
    <html dir="rtl" lang="fa">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>گزارش تحلیل امنیت - Hermes</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
            .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; }}
            .card {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .summary {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 15px; }}
            .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
            .summary-card .number {{ font-size: 28px; font-weight: bold; }}
            .badge {{ padding: 3px 10px; border-radius: 15px; font-size: 12px; display: inline-block; }}
            .badge-critical {{ background: #dc3545; color: white; }}
            .badge-high {{ background: #fd7e14; color: white; }}
            .badge-medium {{ background: #ffc107; color: black; }}
            .badge-low {{ background: #28a745; color: white; }}
            .badge-passed {{ background: #28a745; color: white; }}
            .badge-failed {{ background: #dc3545; color: white; }}
            .badge-warning {{ background: #ffc107; color: black; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 10px; text-align: right; border-bottom: 1px solid #ddd; }}
            th {{ background: #f2f2f2; }}
            tr:hover {{ background: #f8f9fa; }}
            code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
            .footer {{ text-align: center; color: #666; margin-top: 30px; }}
            .btn {{ display: inline-block; padding: 10px 20px; background: #3498db; color: white; border: none; border-radius: 5px; text-decoration: none; }}
            .btn:hover {{ background: #2980b9; }}
            .btn-success {{ background: #27ae60; }}
            .btn-success:hover {{ background: #229954; }}
            .section-title {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ گزارش تحلیل امنیت Hermes</h1>
            <p>شناسه گزارش: {report_id}</p>
            <p>تاریخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>سیستم: {results.get('system_info', {}).get('hostname', 'Unknown')}</p>
        </div>

        <div class="container">
    """
    
    # System Info
    if 'system_info' in results:
        html += '<div class="card"><h3>🖥️ اطلاعات سیستم</h3><table>'
        for key, value in results['system_info'].items():
            html += f'<tr><td><strong>{key}</strong></td><td>{value}</td></tr>'
        html += '</table></div>'
    
    # Summary Cards
    html += '<div class="card"><h3>📊 خلاصه تحلیل</h3><div class="summary">'
    
    if 'vulnerabilities' in results and 'summary' in results['vulnerabilities']:
        vuln_summary = results['vulnerabilities']['summary']
        html += f'''
        <div class="summary-card">
            <div class="number" style="color: #dc3545;">{vuln_summary.get('critical', 0)}</div>
            <div>آسیب‌پذیری بحرانی</div>
        </div>
        <div class="summary-card">
            <div class="number" style="color: #fd7e14;">{vuln_summary.get('high', 0)}</div>
            <div>آسیب‌پذیری بالا</div>
        </div>'''
    
    if 'ports' in results and 'summary' in results['ports']:
        port_summary = results['ports']['summary']
        html += f'''
        <div class="summary-card">
            <div class="number" style="color: #dc3545;">{port_summary.get('malicious', 0)}</div>
            <div>پورت‌های مخرب</div>
        </div>'''
    
    if 'services' in results and 'summary' in results['services']:
        svc_summary = results['services']['summary']
        html += f'''
        <div class="summary-card">
            <div class="number" style="color: #dc3545;">{svc_summary.get('suspicious', 0)}</div>
            <div>سرویس‌های مشکوک</div>
        </div>'''
    
    if 'processes' in results and 'summary' in results['processes']:
        proc_summary = results['processes']['summary']
        html += f'''
        <div class="summary-card">
            <div class="number" style="color: #dc3545;">{proc_summary.get('suspicious', 0)}</div>
            <div>پروسه‌های مشکوک</div>
        </div>'''
    
    if 'kernel_modules' in results and 'summary' in results['kernel_modules']:
        kernel_summary = results['kernel_modules']['summary']
        html += f'''
        <div class="summary-card">
            <div class="number" style="color: #dc3545;">{kernel_summary.get('suspicious', 0)}</div>
            <div>ماژول‌های مشکوک</div>
        </div>'''
    
    if 'software' in results and 'summary' in results['software']:
        sw_summary = results['software']['summary']
        html += f'''
        <div class="summary-card">
            <div class="number" style="color: #dc3545;">{sw_summary.get('suspicious', 0)}</div>
            <div>نرم‌افزارهای مشکوک</div>
        </div>'''
    
    if 'users' in results and 'summary' in results['users']:
        user_summary = results['users']['summary']
        html += f'''
        <div class="summary-card">
            <div class="number" style="color: #dc3545;">{user_summary.get('suspicious', 0)}</div>
            <div>کاربران مشکوک</div>
        </div>'''
    
    html += '</div></div>'
    
    # Vulnerabilities
    if 'vulnerabilities' in results and results['vulnerabilities'].get('cves'):
        html += '<div class="card"><div class="section-title"><h3>🔍 آسیب‌پذیری‌های شناسایی شده</h3><span>تعداد: {}</span></div><table>'.format(len(results['vulnerabilities']['cves']))
        html += '<tr><th>شناسه</th><th>شدت</th><th>امتیاز</th><th>توضیحات</th></tr>'
        for cve in results['vulnerabilities']['cves'][:20]:
            severity_class = {
                'CRITICAL': 'badge-critical',
                'HIGH': 'badge-high',
                'MEDIUM': 'badge-medium',
                'LOW': 'badge-low'
            }.get(cve.get('severity', 'UNKNOWN'), 'badge-warning')
            html += f'<tr><td><a href="https://nvd.nist.gov/vuln/detail/{cve["id"]}" target="_blank">{cve["id"]}</a></td><td><span class="badge {severity_class}">{cve.get("severity", "UNKNOWN")}</span></td><td>{cve.get("score", 0)}</td><td>{cve.get("description", "")[:100]}...</td></tr>'
        html += '</table></div>'
    
    # Malicious Ports
    if 'ports' in results and results['ports'].get('SUSPICIOUS_PORTS'):
        html += '<div class="card"><div class="section-title"><h3>🌐 پورت‌های مخرب باز</h3><span>تعداد: {}</span></div><table>'.format(len(results['ports']['SUSPICIOUS_PORTS']))
        html += '<tr><th>پورت</th><th>پروسه</th><th>توضیحات</th></tr>'
        for port in results['ports']['SUSPICIOUS_PORTS']:
            html += f'<tr><td><span class="badge badge-critical">{port["port"]}</span></td><td>{port["process"]}</td><td>{port["description"]}</td></tr>'
        html += '</table></div>'
    
    # Suspicious Services
    if 'services' in results and results['services'].get('suspicious_services'):
        html += '<div class="card"><div class="section-title"><h3>⚙️ سرویس‌های مشکوک</h3><span>تعداد: {}</span></div><table>'.format(len(results['services']['suspicious_services']))
        html += '<tr><th>نام سرویس</th><th>وضعیت</th><th>دلیل</th></tr>'
        for svc in results['services']['suspicious_services']:
            html += f'<tr><td><span class="badge badge-critical">{svc["name"]}</span></td><td>{svc["active"]}</td><td>{svc["reason"]}</td></tr>'
        html += '</table></div>'
    
    # Suspicious Processes
    if 'processes' in results and results['processes'].get('suspicious_processes'):
        html += '<div class="card"><div class="section-title"><h3>🧩 پروسه‌های مشکوک</h3><span>تعداد: {}</span></div><table>'.format(len(results['processes']['suspicious_processes']))
        html += '<tr><th>PID</th><th>کاربر</th><th>CPU%</th><th>MEM%</th><th>دستور</th><th>دلیل</th></tr>'
        for proc in results['processes']['suspicious_processes'][:20]:
            html += f'<tr><td>{proc["pid"]}</td><td>{proc["user"]}</td><td>{proc["cpu"]:.1f}%</td><td>{proc["mem"]:.1f}%</td><td><code>{proc["command"]}</code></td><td>{proc["reason"]}</td></tr>'
        html += '</table></div>'
    
    # Suspicious Kernel Modules
    if 'kernel_modules' in results and results['kernel_modules'].get('suspicious_modules'):
        html += '<div class="card"><div class="section-title"><h3>🧠 ماژول‌های کرنل مشکوک</h3><span>تعداد: {}</span></div><table>'.format(len(results['kernel_modules']['suspicious_modules']))
        html += '<tr><th>نام ماژول</th><th>امضا</th><th>دلایل</th></tr>'
        for mod in results['kernel_modules']['suspicious_modules']:
            html += f'<tr><td><span class="badge badge-critical">{mod["name"]}</span></td><td>{mod.get("signature", "unknown")}</td><td>{"; ".join(mod.get("reasons", []))}</td></tr>'
        html += '</table></div>'
    
    # Suspicious Software
    if 'software' in results and results['software'].get('suspicious_packages'):
        html += '<div class="card"><div class="section-title"><h3>📦 نرم‌افزارهای مشکوک</h3><span>تعداد: {}</span></div><table>'.format(len(results['software']['suspicious_packages']))
        html += '<tr><th>نام بسته</th><th>نسخه</th><th>دلایل</th></tr>'
        for pkg in results['software']['suspicious_packages']:
            html += f'<tr><td><span class="badge badge-critical">{pkg["name"]}</span></td><td>{pkg["version"]}</td><td>{"; ".join(pkg["reasons"])}</td></tr>'
        html += '</table></div>'
    
    # Suspicious Users
    if 'users' in results and results['users'].get('suspicious_users'):
        html += '<div class="card"><div class="section-title"><h3>👤 کاربران مشکوک</h3><span>تعداد: {}</span></div><table>'.format(len(results['users']['suspicious_users']))
        html += '<tr><th>نام کاربری</th><th>UID</th><th>شل</th><th>خانه</th><th>sudo</th><th>دلایل</th></tr>'
        for user in results['users']['suspicious_users']:
            html += f'<tr><td><span class="badge badge-critical">{user["username"]}</span></td><td>{user["uid"]}</td><td>{user["shell"]}</td><td>{user["home"]}</td><td>{"✅" if user["sudo"] else "❌"}</td><td>{user["reasons"]}</td></tr>'
        html += '</table></div>'
    
    # Hardening
    if 'hardening' in results and results['hardening'].get('checks'):
        html += '<div class="card"><div class="section-title"><h3>🛡️ وضعیت سخت‌افزاری</h3><span>قبول: {} | رد: {} | هشدار: {}</span></div><table>'.format(
            results['hardening']['summary'].get('passed', 0),
            results['hardening']['summary'].get('failed', 0),
            results['hardening']['summary'].get('warning', 0)
        )
        html += '<tr><th>بررسی</th><th>نتیجه</th><th>مورد انتظار</th><th>وضعیت</th><th>بحرانی</th></tr>'
        for check in results['hardening']['checks']:
            status_class = {
                'passed': 'badge-passed',
                'failed': 'badge-failed',
                'failed (critical)': 'badge-critical',
                'warning': 'badge-warning'
            }.get(check['status'], 'badge-warning')
            html += f'<tr><td>{check["name"]}</td><td><code>{check["result"]}</code></td><td><code>{check["expected"]}</code></td><td><span class="badge {status_class}">{check["status"]}</span></td><td>{"✅" if check["critical"] else "❌"}</td></tr>'
        html += '</table></div>'
    
    html += f'''
            <div style="text-align: center; margin-top: 20px;">
                <a href="{url_for('dashboard')}" class="btn">🏠 بازگشت به داشبورد</a>
                <a href="{url_for('export_report', report_id=report_id)}" class="btn" style="background: #6c757d;">📥 دریافت JSON</a>
            </div>
            <div class="footer">
                <p>تولید شده توسط Hermes Security Analyzer</p>
                <p style="font-size: 12px;">این گزارش فقط برای اهداف تحلیلی است و هیچ تغییری در سیستم اعمال نمی‌کند</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return html

# ===================================================================
# ROUTES
# ===================================================================

@app.route('/')
@login_required
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/run_analysis')
@login_required
def run_analysis():
    """Run all analysis and generate report"""
    session['analysis_status'] = 'running'
    
    try:
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'system_info': get_system_info(),
            'vulnerabilities': scan_vulnerabilities(),
            'ports': scan_ports(),
            'services': analyze_services(),
            'processes': analyze_processes(),
            'kernel_modules': analyze_kernel_modules(),
            'software': analyze_software(),
            'users': analyze_users(),
            'hardening': check_system_hardening()
        }
        
        report_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(app.config['REPORT_DIR'], f'report_{report_id}.json')
        with open(report_path, 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        html_report = generate_html_report(analysis_results, report_id)
        html_path = os.path.join(app.config['REPORT_DIR'], f'report_{report_id}.html')
        with open(html_path, 'w') as f:
            f.write(html_report)
        
        session['analysis_status'] = 'complete'
        session['latest_report'] = report_id
        session['analysis_results'] = analysis_results
        
        flash(f'✅ تحلیل کامل شد! شناسه گزارش: {report_id}', 'success')
        
    except Exception as e:
        session['analysis_status'] = 'error'
        flash(f'❌ خطا در تحلیل: {str(e)}', 'error')
    
    return redirect(url_for('view_report'))

@app.route('/report')
@login_required
def view_report():
    """View the latest analysis report"""
    report_id = session.get('latest_report')
    if not report_id:
        flash('هیچ گزارشی موجود نیست. لطفاً ابتدا تحلیل را اجرا کنید.', 'warning')
        return redirect(url_for('dashboard'))
    
    results = session.get('analysis_results', {})
    if not results:
        report_path = os.path.join(app.config['REPORT_DIR'], f'report_{report_id}.json')
        if os.path.exists(report_path):
            with open(report_path, 'r') as f:
                results = json.load(f)
    
    return render_template('report.html', 
                         results=results, 
                         report_id=report_id,
                         timestamp=datetime.now())

@app.route('/report/<report_id>')
@login_required
def view_report_by_id(report_id):
    """View a specific report by ID"""
    report_path = os.path.join(app.config['REPORT_DIR'], f'report_{report_id}.json')
    if not os.path.exists(report_path):
        flash('گزارش یافت نشد', 'error')
        return redirect(url_for('dashboard'))
    
    with open(report_path, 'r') as f:
        results = json.load(f)
    
    return render_template('report.html', 
                         results=results, 
                         report_id=report_id,
                         timestamp=datetime.now())

@app.route('/reports')
@login_required
def list_reports():
    """List all available reports"""
    reports = []
    for filename in os.listdir(app.config['REPORT_DIR']):
        if filename.endswith('.json'):
            report_id = filename.replace('.json', '').replace('report_', '')
            filepath = os.path.join(app.config['REPORT_DIR'], filename)
            mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
            reports.append({
                'id': report_id,
                'date': mtime,
                'size': os.path.getsize(filepath)
            })
    reports.sort(key=lambda x: x['date'], reverse=True)
    return render_template('reports.html', reports=reports)

@app.route('/export_report/<report_id>')
@login_required
def export_report(report_id):
    """Export report as JSON"""
    report_path = os.path.join(app.config['REPORT_DIR'], f'report_{report_id}.json')
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report not found'}), 404
    
    with open(report_path, 'r') as f:
        results = json.load(f)
    
    return jsonify(results)

@app.route('/api/analysis')
@login_required
def api_analysis():
    """API endpoint for analysis results"""
    report_id = request.args.get('report_id')
    if report_id:
        report_path = os.path.join(app.config['REPORT_DIR'], f'report_{report_id}.json')
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report not found'}), 404
        with open(report_path, 'r') as f:
            results = json.load(f)
    else:
        results = session.get('analysis_results', {})
    
    return jsonify(results)

# ===================================================================
# MAIN
# ===================================================================

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler(
                os.path.join(app.config['LOG_DIR'], 'hermes_analyzer.log'),
                maxBytes=1000000,
                backupCount=5
            ),
            logging.StreamHandler()
        ]
    )
    
    try:
        cve_db.update()
    except:
        pass
    
    try:
        app.run(host='0.0.0.0', port=5050, debug=True)
    finally:
        ssh_manager.close_all()