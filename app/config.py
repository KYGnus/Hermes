# In config.py
import tempfile
import os

# Session Configuration
SESSION_TYPE = 'filesystem'
SESSION_FILE_DIR = tempfile.mkdtemp()
SESSION_PERMANENT = False
PERMANENT_SESSION_LIFETIME = 3600
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

# SSH Configuration
SSH_HOST = "128.140.116.175"
SSH_PORT = 22
SSH_USERNAME = "koosha"
SSH_PASSWORD = "K102030k"
SSH_KEY = None

# SSH Connection Pool Settings
SSH_POOL_MAX_SIZE = 10
SSH_KEEPALIVE_INTERVAL = 30
SSH_IDLE_TIMEOUT = 600
SSH_COMMAND_TIMEOUT = 60
SSH_CONNECTION_TIMEOUT = 10
SSH_RETRY_COUNT = 2

# Cache Settings
CACHE_TTL = 300  # 5 minutes
CACHE_MAX_SIZE = 100

# Paths
Hermes_SCAN_PATHS = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc', '/tmp', '/', '/home']
YARA_RULES_DIR = '.'
QUARANTINE_DIR = './tmp/quarantine'

if not os.path.exists(QUARANTINE_DIR):
    try:
        os.makedirs(QUARANTINE_DIR)
        print(f"Directory '{QUARANTINE_DIR}' created")
    except OSError as error:
        print(f"Creation of directory '{QUARANTINE_DIR}' failed: {error}")
else:
    print(f"Directory '{QUARANTINE_DIR}' already exists")

LOG_DIR = './tmp/Hermes'

if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
        print(f"Directory '{LOG_DIR}' created")
    except OSError as error:
        print(f"Creation of directory '{LOG_DIR}' failed: {error}")
else:
    print(f"Directory '{LOG_DIR}' already exists")

# Suricata Configuration
SURICATA_ENABLED = False
SURICATA_INTERFACE = 'eth0'
SURICATA_RULES_DIR = '/etc/suricata/rules'
SURICATA_LOGS = '/var/log/suricata'
SURICATA_DIR = '/etc/suricata'

# Fail2Ban Configuration
FAIL2BAN_ENABLED = False
FAIL2BAN_JAILS = ['sshd', 'apache', 'nginx']

# WinRM Configuration (if used)
WINRM_HOST = None
WINRM_USERNAME = None
WINRM_PASSWORD = None
WINRM_TRANSPORT = 'ntlm'
WINRM_SERVER_CERT_VALIDATION = 'ignore'