# Configuration
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_session import Session
import paramiko
from io import StringIO
import os
import json
import re
from datetime import datetime
import tempfile
import config
import logging
from logging.handlers import RotatingFileHandler
import yara
import threading
import time
import glob
import subprocess
import psutil
import signal
import datetime as mydate
import shlex
import traceback
from functools import lru_cache
import platform
import socket
from queue import Queue
import weakref

app = Flask(__name__)
app.secret_key = 'Hermes'

# Load configuration from config.py
app.config.update(
    SESSION_TYPE=config.SESSION_TYPE,
    SESSION_FILE_DIR=config.SESSION_FILE_DIR,
    SESSION_PERMANENT=config.SESSION_PERMANENT,
    PERMANENT_SESSION_LIFETIME=config.PERMANENT_SESSION_LIFETIME,
    MAX_CONTENT_LENGTH=config.MAX_CONTENT_LENGTH,
    SSH_HOST=config.SSH_HOST,
    SSH_PORT=config.SSH_PORT,
    SSH_USERNAME=config.SSH_USERNAME,
    SSH_PASSWORD=config.SSH_PASSWORD,
    SSH_KEY=config.SSH_KEY,
    SSH_POOL_MAX_SIZE=config.SSH_POOL_MAX_SIZE,
    SSH_KEEPALIVE_INTERVAL=config.SSH_KEEPALIVE_INTERVAL,
    SSH_IDLE_TIMEOUT=config.SSH_IDLE_TIMEOUT,
    SSH_COMMAND_TIMEOUT=config.SSH_COMMAND_TIMEOUT,
    SSH_CONNECTION_TIMEOUT=config.SSH_CONNECTION_TIMEOUT,
    SSH_RETRY_COUNT=config.SSH_RETRY_COUNT,
    Hermes_SCAN_PATHS=config.Hermes_SCAN_PATHS,
    YARA_RULES_DIR=config.YARA_RULES_DIR,
    QUARANTINE_DIR=config.QUARANTINE_DIR,
    LOG_DIR=config.LOG_DIR,
    SURICATA_ENABLED=config.SURICATA_ENABLED,
    SURICATA_INTERFACE=config.SURICATA_INTERFACE,
    SURICATA_RULES_DIR=config.SURICATA_RULES_DIR,
    SURICATA_LOGS=config.SURICATA_LOGS,
    SURICATA_DIR=config.SURICATA_DIR,
    FAIL2BAN_ENABLED=config.FAIL2BAN_ENABLED,
    FAIL2BAN_JAILS=config.FAIL2BAN_JAILS
)

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
Session(app)

# Logging functions
def log_event(event_type, level, message, details=None):
    """Log an event to the system log"""
    event_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"{event_time} | {event_type} | {level} | {message} | {details if details else ''}"
    with open("/tmp/Hermes.log", "a") as log_file:
        log_file.write(log_message + "\n")

def log_action(action, user_id=None):
    """Log actions with timestamp and user info"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    user_info = f"User:{user_id}" if user_id else "System"
    log_entry = f"[{timestamp}] {user_info} - {action}\n"
    
    try:
        with open("myNAS.log", "a") as log_file:
            log_file.write(log_entry)
    except IOError as e:
        print(f"Failed to write to log file: {str(e)}")

# User Model
class User(UserMixin):
    """User model for authentication"""
    def __init__(self, id, username, password, role='user'):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

# Mock user database
users = {
    1: User(1, 'admin', bcrypt.generate_password_hash('admin').decode('utf-8'), 'admin')
}

# ===================================================================
# OPTIMIZED SSH CONNECTION POOL
# ===================================================================

class SSHConnectionPool:
    """Optimized SSH connection pool with keep-alive and connection reuse"""
    
    def __init__(self, max_connections=10, keepalive_interval=30, idle_timeout=600):
        self.max_connections = max_connections
        self.keepalive_interval = keepalive_interval
        self.idle_timeout = idle_timeout
        self.connections = {}
        self.lock = threading.Lock()
        self.connection_usage = {}
        self._start_keepalive_thread()
        self._start_cleanup_thread()
    
    def get_connection(self, host=None, username=None, password=None, key=None, port=None, force_new=False):
        """Get or create a connection from the pool"""
        host = host or app.config['SSH_HOST']
        username = username or app.config['SSH_USERNAME']
        password = password or app.config['SSH_PASSWORD']
        key = key or app.config['SSH_KEY']
        port = port or app.config['SSH_PORT']
        
        conn_key = f"{username}@{host}:{port}"
        
        with self.lock:
            # Check if we have an active connection
            if not force_new and conn_key in self.connections:
                conn = self.connections[conn_key]
                if self._is_connection_alive(conn):
                    self.connection_usage[conn_key] = datetime.now()
                    return conn
                else:
                    # Connection is dead, remove it
                    self._close_connection(conn_key)
            
            # Check if we've reached max connections
            if len(self.connections) >= self.max_connections:
                # Remove the oldest unused connection
                oldest = min(self.connection_usage.items(), key=lambda x: x[1])
                self._close_connection(oldest[0])
            
            # Create new connection
            conn = self._create_connection(host, port, username, password, key)
            if conn:
                self.connections[conn_key] = conn
                self.connection_usage[conn_key] = datetime.now()
                return conn
            return None
    
    def _create_connection(self, host, port, username, password, key):
        """Create a new SSH connection with optimized settings"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connection parameters optimized for speed
            connect_kwargs = {
                'hostname': host,
                'port': port,
                'username': username,
                'timeout': app.config['SSH_CONNECTION_TIMEOUT'],
                'allow_agent': False,
                'look_for_keys': False,
                'compress': True,
                'auth_timeout': 5
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
            
            # Optimize transport settings
            transport = ssh.get_transport()
            if transport:
                transport.set_keepalive(self.keepalive_interval)
                transport.window_size = 2147483647
                transport.packetizer.REKEY_BYTES = pow(2, 40)
                
                # Set TCP_NODELAY for better performance
                try:
                    sock = transport.sock
                    if sock:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except:
                    pass
            
            return ssh
        except Exception as e:
            app.logger.error(f"SSH Connection failed to {host}: {str(e)}")
            try:
                ssh.close()
            except:
                pass
            return None
    
    def _is_connection_alive(self, ssh):
        """Check if connection is still alive"""
        try:
            transport = ssh.get_transport()
            if not transport or not transport.is_active():
                return False
            
            # Send a no-op to test
            transport.send_ignore()
            return True
        except:
            return False
    
    def _close_connection(self, conn_key):
        """Close and remove a connection"""
        if conn_key in self.connections:
            try:
                self.connections[conn_key].close()
            except:
                pass
            del self.connections[conn_key]
        if conn_key in self.connection_usage:
            del self.connection_usage[conn_key]
    
    def _start_keepalive_thread(self):
        """Start background thread for keepalive"""
        def keepalive_worker():
            while True:
                try:
                    time.sleep(30)
                    self._send_keepalive()
                except:
                    pass
        
        thread = threading.Thread(target=keepalive_worker, daemon=True)
        thread.start()
    
    def _send_keepalive(self):
        """Send keepalive to all active connections"""
        with self.lock:
            for conn_key, conn in list(self.connections.items()):
                try:
                    transport = conn.get_transport()
                    if transport and transport.is_active():
                        transport.send_ignore()
                    else:
                        self._close_connection(conn_key)
                except:
                    self._close_connection(conn_key)
    
    def _start_cleanup_thread(self):
        """Start background thread for cleanup"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(60)
                    self._cleanup_idle_connections()
                except:
                    pass
        
        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()
    
    def _cleanup_idle_connections(self):
        """Remove idle connections"""
        with self.lock:
            now = datetime.now()
            to_remove = []
            
            for conn_key, usage_time in self.connection_usage.items():
                if (now - usage_time).total_seconds() > self.idle_timeout:
                    to_remove.append(conn_key)
            
            for conn_key in to_remove:
                self._close_connection(conn_key)
    
    def close_all(self):
        """Close all connections"""
        with self.lock:
            for conn_key in list(self.connections.keys()):
                self._close_connection(conn_key)

# ===================================================================
# COMMAND CACHE
# ===================================================================

class CommandCache:
    """Cache for command results with TTL"""
    
    def __init__(self, ttl=300, max_size=100):
        self.cache = {}
        self.ttl = ttl
        self.max_size = max_size
        self.lock = threading.Lock()
    
    def get(self, key):
        """Get cached result"""
        with self.lock:
            if key in self.cache:
                result, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    return result
                else:
                    del self.cache[key]
            return None
    
    def set(self, key, value):
        """Set cached result"""
        with self.lock:
            # Clean up if cache is too large
            if len(self.cache) >= self.max_size:
                # Remove oldest entries
                sorted_items = sorted(self.cache.items(), key=lambda x: x[1][1])
                for old_key, _ in sorted_items[:10]:
                    del self.cache[old_key]
            
            self.cache[key] = (value, time.time())
    
    def clear(self):
        """Clear cache"""
        with self.lock:
            self.cache.clear()

# Initialize cache
command_cache = CommandCache(
    ttl=app.config.get('CACHE_TTL', 300),
    max_size=app.config.get('CACHE_MAX_SIZE', 100)
)

# ===================================================================
# OPTIMIZED SSH MANAGER
# ===================================================================

# Initialize connection pool
ssh_pool = SSHConnectionPool(
    max_connections=app.config['SSH_POOL_MAX_SIZE'],
    keepalive_interval=app.config['SSH_KEEPALIVE_INTERVAL'],
    idle_timeout=app.config['SSH_IDLE_TIMEOUT']
)

def run_sudo_command(cmd, timeout=60, use_cache=False):
    """
    Run a sudo command with proper password handling
    """
    # Ensure sudo doesn't ask for password (use the SSH password)
    if app.config.get('SSH_PASSWORD'):
        # Use -S flag to read password from stdin
        cmd = f"echo '{app.config['SSH_PASSWORD']}' | sudo -S {cmd}"
    
    return run_command(cmd, timeout=timeout, get_pty=True, use_cache=use_cache)




def run_command(cmd, timeout=60, get_pty=False, use_cache=False, cache_ttl=300):
    """
    Execute command with optimized connection management
    """
    # For commands that might need bash, explicitly use bash
    if not cmd.startswith('bash') and not cmd.startswith('sh'):
        # Only wrap if it's a complex command
        if any(char in cmd for char in ['|', '&', ';', '<', '>', '`', '$', '"', "'"]):
            cmd = f"bash -c {shlex.quote(cmd)}"
    
    # Check cache if enabled
    if use_cache:
        cache_key = f"{cmd}_{timeout}_{get_pty}"
        cached_result = command_cache.get(cache_key)
        if cached_result is not None:
            return cached_result
    
    max_retries = app.config.get('SSH_RETRY_COUNT', 2)
    last_error = None
    
    for attempt in range(max_retries + 1):
        try:
            ssh = ssh_pool.get_connection(force_new=(attempt > 0))
            if not ssh:
                if attempt < max_retries:
                    time.sleep(0.5)
                    continue
                return "ERROR: Could not establish SSH connection"
            
            transport = ssh.get_transport()
            if not transport or not transport.is_active():
                ssh_pool.get_connection(force_new=True)
                if attempt < max_retries:
                    time.sleep(0.5)
                    continue
                return "ERROR: SSH transport not active"
            
            # For sudo commands with password, use get_pty
            if 'sudo' in cmd and app.config.get('SSH_PASSWORD'):
                get_pty = True
            
            # Execute command
            stdin, stdout, stderr = ssh.exec_command(
                cmd,
                timeout=timeout,
                get_pty=get_pty
            )
            
            # Handle sudo password
            if get_pty and 'sudo' in cmd and app.config.get('SSH_PASSWORD'):
                stdin.write(f"{app.config['SSH_PASSWORD']}\n")
                stdin.flush()
            
            # Read output
            output = ""
            error = ""
            
            channel = stdout.channel
            channel.settimeout(timeout)
            
            # Read in chunks
            while True:
                try:
                    data = channel.recv(4096)
                    if not data:
                        break
                    output += data.decode('utf-8', errors='ignore')
                except paramiko.SSHException:
                    break
                except socket.timeout:
                    break
            
            # Read stderr
            error_data = stderr.read().decode().strip()
            if error_data:
                error = error_data
            
            # Check exit status
            exit_status = channel.recv_exit_status()
            
            if exit_status != 0:
                if attempt < max_retries and ("Broken pipe" in error or "Connection" in error):
                    ssh_pool.get_connection(force_new=True)
                    time.sleep(0.5)
                    continue
                result = f"ERROR: {error or output or 'Command failed with exit code ' + str(exit_status)}"
                if use_cache:
                    command_cache.set(cache_key, result)
                return result
            
            result = output.strip() if output else "Success"
            
            # Cache result if enabled
            if use_cache:
                command_cache.set(cache_key, result)
            
            return result
            
        except paramiko.SSHException as e:
            last_error = str(e)
            if attempt < max_retries:
                ssh_pool.get_connection(force_new=True)
                time.sleep(0.5)
                continue
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries:
                time.sleep(0.5)
                continue
    
    result = f"ERROR: {last_error or 'Unknown error'}"
    if use_cache:
        command_cache.set(cache_key, result)
    return result

def run_batch_commands(commands, timeout=60, use_cache=False):
    """
    Execute multiple commands in a single SSH session
    
    Args:
        commands: List of commands to execute
        timeout: Overall timeout
        use_cache: Whether to cache results
    
    Returns:
        List of command outputs
    """
    if not commands:
        return []
    
    # Check if all commands are cached
    if use_cache:
        cached_results = []
        all_cached = True
        for cmd in commands:
            cache_key = f"{cmd}_{timeout}_False"
            cached = command_cache.get(cache_key)
            if cached is not None:
                cached_results.append(cached)
            else:
                all_cached = False
                break
        
        if all_cached:
            return cached_results
    
    # Execute all commands in one session
    try:
        ssh = ssh_pool.get_connection()
        if not ssh:
            return ["ERROR: Could not establish SSH connection"] * len(commands)
        
        # Combine commands with a delimiter
        delimiter = "\n---CMD_SEPARATOR---\n"
        combined_cmd = delimiter.join(commands)
        
        # Execute combined command
        stdin, stdout, stderr = ssh.exec_command(
            combined_cmd,
            timeout=timeout,
            get_pty=False
        )
        
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        if error and "ERROR" in error:
            return [f"ERROR: {error}"] * len(commands)
        
        # Split results
        results = output.split(delimiter)
        
        # Ensure we have the right number of results
        while len(results) < len(commands):
            results.append("")
        
        # Cache results if enabled
        if use_cache:
            for cmd, result in zip(commands, results):
                cache_key = f"{cmd}_{timeout}_False"
                command_cache.set(cache_key, result)
        
        return results[:len(commands)]
        
    except Exception as e:
        return [f"ERROR: {str(e)}"] * len(commands)

def clear_command_cache():
    """Clear the command cache"""
    command_cache.clear()

# ===================================================================
# AUTHENTICATION ROUTES
# ===================================================================

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
        remember = True if request.form.get('remember') else False
        
        if not username or not password:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('login'))
        
        if len(username) > 20 or len(password) > 50:
            flash('Invalid input length', 'error')
            return redirect(url_for('login'))
            
        user = next((user for user in users.values() if user.username == username), None)
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=remember)
            log_action(f"User {username} logged in successfully", user.id)
            log_event("AUTH", "info", "Successful login", {
                "username": username,
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent')
            })
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            log_event("AUTH", "warning", "Failed login attempt", {
                "username": username,
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent')
            })
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action("User logged out", current_user.id)
    log_event("AUTH", "info", "User logged out", {
        "username": current_user.username,
        "ip": request.remote_addr
    })
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# ===================================================================
# DASHBOARD
# ===================================================================

@app.route('/')
@login_required
def dashboard():
    """Enhanced Hermes Dashboard with optimized data loading"""
    now = mydate.datetime.now()
    
    if not app.config['SSH_HOST']:
        flash("Please configure SSH connection first", "error")
        return redirect(url_for('configure_ssh'))
    
    # Initialize with default values
    system_info = {
        'hostname': 'Unknown',
        'os': 'Unknown',
        'kernel': 'Unknown',
        'uptime': 'Unknown',
        'load': 'Unknown',
        'memory': 'Unknown',
        'disk': 'Unknown',
        'cpu': 'Unknown',
        'cpu_cores': 'Unknown',
        'last_boot': 'Unknown'
    }
    
    services = {
        "clamav": {"status": "unknown", "version": "Unknown"},
        "fail2ban": {"status": "unknown", "jails": "None"},
        "suricata": {"status": "unknown", "version": "Unknown"},
        "yara": {"status": "inactive", "version": "Unknown"}
    }
    
    # Get system info with individual commands (safer)
    try:
        hostname = run_command("hostname", use_cache=True)
        if hostname and not hostname.startswith("ERROR"):
            system_info['hostname'] = hostname
        
        os_info = run_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'", use_cache=True)
        if os_info and not os_info.startswith("ERROR"):
            system_info['os'] = os_info
        
        kernel = run_command("uname -r", use_cache=True)
        if kernel and not kernel.startswith("ERROR"):
            system_info['kernel'] = kernel
        
        uptime = run_command("uptime -p", use_cache=True)
        if uptime and not uptime.startswith("ERROR"):
            system_info['uptime'] = uptime
        
        load = run_command("cat /proc/loadavg | awk '{print $1, $2, $3}'", use_cache=True)
        if load and not load.startswith("ERROR"):
            system_info['load'] = load
        
        memory = run_command("free -h | awk '/Mem:/ {print $3 \"/\" $2}'", use_cache=True)
        if memory and not memory.startswith("ERROR"):
            system_info['memory'] = memory
        
        disk = run_command("df -h / | awk 'NR==2 {print $3 \"/\" $2}'", use_cache=True)
        if disk and not disk.startswith("ERROR"):
            system_info['disk'] = disk
        
        cpu = run_command("lscpu | grep 'Model name' | cut -d':' -f2 | sed 's/^[ \t]*//'", use_cache=True)
        if cpu and not cpu.startswith("ERROR"):
            system_info['cpu'] = cpu
        
        cpu_cores = run_command("nproc", use_cache=True)
        if cpu_cores and not cpu_cores.startswith("ERROR"):
            system_info['cpu_cores'] = cpu_cores
        
        last_boot = run_command("who -b | awk '{print $3 \" \" $4}'", use_cache=True)
        if last_boot and not last_boot.startswith("ERROR"):
            system_info['last_boot'] = last_boot
    except Exception as e:
        app.logger.error(f"Error getting system info: {str(e)}")
    
    # Get service status with individual commands
    try:
        # ClamAV
        clamav_status = run_sudo_command("systemctl is-active clamav-daemon", use_cache=True)
        if clamav_status and not clamav_status.startswith("ERROR"):
            services['clamav']['status'] = clamav_status
        
        clamav_version = run_command("clamscan --version | awk '{print $2}'", use_cache=True)
        if clamav_version and not clamav_version.startswith("ERROR"):
            services['clamav']['version'] = clamav_version
        
        # Fail2Ban
        fail2ban_status = run_sudo_command("systemctl is-active fail2ban", use_cache=True)
        if fail2ban_status and not fail2ban_status.startswith("ERROR"):
            services['fail2ban']['status'] = fail2ban_status
        
        fail2ban_jails = run_command("fail2ban-client status | grep 'Jail list' | cut -d':' -f2 | sed 's/^[ \t]*//'", use_cache=True)
        if fail2ban_jails and not fail2ban_jails.startswith("ERROR"):
            services['fail2ban']['jails'] = fail2ban_jails
        
        # Suricata
        suricata_status = run_sudo_command("systemctl is-active suricata", use_cache=True)
        if suricata_status and not suricata_status.startswith("ERROR"):
            services['suricata']['status'] = suricata_status
        
        suricata_version = run_command("suricata --version 2>&1 | head -n1", use_cache=True)
        if suricata_version and not suricata_version.startswith("ERROR"):
            services['suricata']['version'] = suricata_version
        
        # YARA
        services['yara']['status'] = "active" if os.path.exists(app.config['YARA_RULES_DIR']) else "inactive"
        yara_version = run_command("yara --version", use_cache=True)
        if yara_version and not yara_version.startswith("ERROR"):
            services['yara']['version'] = yara_version
    except Exception as e:
        app.logger.error(f"Error getting service status: {str(e)}")
    
    # Get security alerts
    security_alerts = []
    try:
        root_logins = run_command("last root | head -n3", use_cache=True)
        if root_logins and not root_logins.startswith("ERROR"):
            for line in root_logins.split('\n'):
                if line.strip():
                    security_alerts.append(f"Root login: {line}")
    except Exception as e:
        app.logger.error(f"Error getting security alerts: {str(e)}")
    
    # Get recent events
    recent_events = []
    try:
        log_file = os.path.join(app.config['LOG_DIR'], 'Hermes_events.log')
        events_output = run_command(f"tail -n 10 {log_file} 2>/dev/null || echo 'No events found'", use_cache=True)
        if events_output and not events_output.startswith("ERROR"):
            recent_events = [line.strip() for line in events_output.split('\n') if line.strip()]
    except Exception as e:
        app.logger.error(f"Error reading recent events: {str(e)}")
    
    # Get updates info
    updates_info = {
        "available": "0",
        "last_update": "Never"
    }
    try:
        updates = run_command("apt list --upgradable 2>/dev/null | wc -l", use_cache=True)
        if updates and not updates.startswith("ERROR"):
            updates_info["available"] = updates.strip()
        
        last_update = run_command("stat -c %y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || echo 'Never'", use_cache=True)
        if last_update and not last_update.startswith("ERROR"):
            updates_info["last_update"] = last_update.strip()
    except Exception as e:
        app.logger.error(f"Error getting updates info: {str(e)}")
    
    return render_template('index.html',
                        system_info=system_info,
                        services=services,
                        recent_events=recent_events,
                        security_alerts=security_alerts,
                        updates_info=updates_info,
                        now=now)

# ===================================================================
# SSH CONFIGURATION
# ===================================================================

@app.route('/configure_ssh', methods=['GET', 'POST'])
@login_required
def configure_ssh():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('dashboard'))
    
    # Clear cache when changing SSH config
    clear_command_cache()
    
    # Close all connections before reconfiguring
    ssh_pool.close_all()
    
    if request.method == 'POST':
        ssh_host = request.form.get('ssh_host')
        ssh_port = request.form.get('ssh_port', '22')
        ssh_username = request.form.get('ssh_username')
        ssh_password = request.form.get('ssh_password')
        ssh_key = request.form.get('ssh_key')
        
        if not ssh_host or not ssh_username:
            flash('Host and username are required', 'error')
            return redirect(url_for('configure_ssh'))
            
        try:
            port = int(ssh_port)
            if port <= 0 or port > 65535:
                raise ValueError
        except ValueError:
            flash('Invalid port number', 'error')
            return redirect(url_for('configure_ssh'))
        
        app.config.update({
            'SSH_HOST': ssh_host,
            'SSH_PORT': port,
            'SSH_USERNAME': ssh_username,
            'SSH_PASSWORD': ssh_password if ssh_password else app.config['SSH_PASSWORD'],
            'SSH_KEY': ssh_key if ssh_key else app.config['SSH_KEY']
        })
        
        # Test connection with new settings
        test_result = run_command("echo 'SSH connection test successful'")
        
        if "ERROR" in test_result:
            flash(f"SSH Configuration Failed: {test_result}", "error")
            log_event("SSH", "error", "SSH configuration failed", {
                "host": ssh_host,
                "port": port,
                "username": ssh_username,
                "error": test_result
            })
        else:
            flash(f"SSH Configuration Successful", "success")
            log_action("Configured SSH connection", current_user.id)
            log_event("SSH", "info", "SSH configuration updated", {
                "host": ssh_host,
                "port": port,
                "username": ssh_username
            })
            return redirect(url_for('dashboard'))
    
    return render_template('configure_ssh.html',
                         current_config={
                             'host': app.config['SSH_HOST'],
                             'port': app.config['SSH_PORT'],
                             'username': app.config['SSH_USERNAME']
                         })

@app.route('/test_ssh')
@login_required
def test_ssh():
    """Test SSH connection and return debug info"""
    ssh = ssh_pool.get_connection(force_new=True)
    if not ssh:
        return jsonify({
            'status': 'error',
            'message': 'SSH connection failed',
            'config': {
                'host': app.config['SSH_HOST'],
                'port': app.config['SSH_PORT'],
                'username': app.config['SSH_USERNAME'],
                'password_set': bool(app.config['SSH_PASSWORD']),
                'key_set': bool(app.config['SSH_KEY'])
            }
        }), 400
    
    try:
        stdin, stdout, stderr = ssh.exec_command('echo "SSH Connection Successful"')
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        return jsonify({
            'status': 'success',
            'message': output or error,
            'connection': str(ssh.get_transport()) if ssh.get_transport() else 'No transport'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Command execution failed: {str(e)}"
        }), 500

# ===================================================================
# ANTIVIRUS
# ===================================================================

@app.route('/antivirus', methods=['GET', 'POST'])
@login_required
def antivirus():
    """Run antivirus scans"""
    if request.method == 'POST':
        scan_path = request.form.get('scan_path', '/').strip()
        scan_type = request.form.get('scan_type', 'quick')
        scanners = request.form.getlist('scanners') or (['clamav', 'rkhunter'] if scan_type == 'quick' else ['clamav', 'maldet', 'rkhunter', 'chkrootkit', 'yara'])
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp:
            results = {}
            
            if 'clamav' in scanners:
                results['clamav'] = run_command(f"clamscan --remove --recursive --infected --verbose {scan_path}", timeout=600)

            if 'maldet' in scanners:
                results['maldet'] = run_command(f"sudo /usr/local/sbin/maldet --scan-all {scan_path}", timeout=600, get_pty=True)

            if 'rkhunter' in scanners:
                results['rkhunter'] = run_command("sudo rkhunter --check --skip-keypress", timeout=300, get_pty=True)

            if 'chkrootkit' in scanners:
                results['chkrootkit'] = run_command("sudo chkrootkit", timeout=300, get_pty=True)

            if 'yara' in scanners:
                yara_rules = request.form.get('yara_rules', '/usr/local/share/yara-rules').strip()
                results['yara'] = run_command(f"yara -r {yara_rules} {scan_path}", timeout=600)
            
            json.dump(results, tmp)
            tmp_path = tmp.name
        
        log_action(f"Antivirus {scan_type} scan initiated on {scan_path}")
        session['scan_results_path'] = tmp_path
        return redirect(url_for('antivirus_results'))
    
    return render_template('antivirus.html')

@app.route('/antivirus/results')
@login_required
def antivirus_results():
    """Display antivirus scan results"""
    tmp_path = session.get('scan_results_path')
    if not tmp_path or not os.path.exists(tmp_path):
        flash("No scan results found or results expired.", "error")
        return redirect(url_for('antivirus'))
    
    try:
        with open(tmp_path) as f:
            results = json.load(f)
        os.unlink(tmp_path)
        session.pop('scan_results_path', None)
        
        formatted_results = "\n\n".join(
            f"=== {tool.upper()} ===\n{output}" 
            for tool, output in results.items()
        )
        return render_template('antivirus_results.html', results=formatted_results)
    except Exception as e:
        flash(f"Error reading scan results: {str(e)}", "error")
        return redirect(url_for('antivirus'))

@app.route('/antivirus/update')
@login_required
def antivirus_update():
    """Update antivirus databases"""
    tools = request.args.getlist('tools') or ['clamav', 'maldet', 'rkhunter']
    results = {}
    
    try:
        if 'clamav' in tools:
            results['clamav'] = run_command("sudo freshclam", timeout=300, get_pty=True)
        
        if 'maldet' in tools:
            results['maldet'] = run_command("sudo /usr/local/sbin/maldet -u", timeout=300, get_pty=True)
        
        if 'rkhunter' in tools:
            results['rkhunter'] = run_command("sudo rkhunter --update", timeout=300, get_pty=True)
        
        # Clear cache after updates
        clear_command_cache()
        
        log_action(f"Updated antivirus databases: {', '.join(tools)}")
        flash("Antivirus update completed", "success")
        
    except Exception as e:
        flash(f"Error during update: {str(e)}", "error")
        log_action(f"Antivirus update failed: {str(e)}")
    
    return render_template('antivirus_update.html', 
                         results=results,
                         now=datetime.now(),
                         selected_tools=tools)

# ===================================================================
# YARA RULES MANAGEMENT
# ===================================================================

@app.route('/yara_rules', methods=['GET', 'POST'])
@login_required
def manage_yara_rules():
    """Manage YARA rules"""
    if request.method == 'POST':
        if 'yara_rule' not in request.files:
            flash("No file uploaded", "error")
            return redirect(url_for('manage_yara_rules'))
        
        file = request.files['yara_rule']
        if file.filename == '':
            flash("No selected file", "error")
            return redirect(url_for('manage_yara_rules'))
        
        if not (file.filename.endswith('.yar') or file.filename.endswith('.yara')):
            flash("Invalid file type - must be .yar or .yara", "error")
            return redirect(url_for('manage_yara_rules'))
        
        try:
            content = file.read().decode('utf-8')
            try:
                yara.compile(source=content)
            except yara.SyntaxError as e:
                flash(f"Invalid YARA syntax: {str(e)}", "error")
                return redirect(url_for('manage_yara_rules'))
            
            temp_path = f"/tmp/{file.filename}"
            upload_cmd = f"echo '{content}' > {temp_path} && sudo mv {temp_path} {os.path.join(app.config['YARA_RULES_DIR'], file.filename)}"
            result = run_command(upload_cmd)
            
            if "ERROR" in result:
                flash(f"Failed to upload rule: {result}", "error")
            else:
                # Clear cache after rule update
                clear_command_cache()
                flash("YARA rule uploaded successfully", "success")
                log_action(f"Uploaded YARA rule: {file.filename}", current_user.id)
                log_event("YARA", "info", f"New YARA rule uploaded: {file.filename}")
            
        except Exception as e:
            flash(f"Error processing file: {str(e)}", "error")
            log_event("YARA", "error", "YARA rule upload failed", {"error": str(e)})
        
        return redirect(url_for('manage_yara_rules'))
    
    # List existing rules
    yara_rules = []
    if app.config['SSH_HOST']:
        rules_output = run_command(f"ls {app.config['YARA_RULES_DIR']}", use_cache=True)
        if rules_output and not rules_output.startswith("ERROR"):
            yara_rules = [rule for rule in rules_output.split('\n') if rule.endswith(('.yar', '.yara'))]
    
    return render_template('yara_rules.html', yara_rules=yara_rules)

@app.route('/delete_yara_rule', methods=['POST'])
@login_required
def delete_yara_rule():
    """Delete a YARA rule"""
    rule_name = request.form.get('rule_name')
    if not rule_name:
        flash("No rule specified", "error")
        return redirect(url_for('manage_yara_rules'))
    
    if '/' in rule_name or '..' in rule_name:
        flash("Invalid rule name", "error")
        return redirect(url_for('manage_yara_rules'))
    
    cmd = f"sudo rm {os.path.join(app.config['YARA_RULES_DIR'], rule_name)}"
    result = run_command(cmd)
    
    if "ERROR" in result:
        flash(f"Failed to delete rule: {result}", "error")
        log_event("YARA", "error", f"Failed to delete YARA rule: {rule_name}", {"error": result})
    else:
        clear_command_cache()
        flash("YARA rule deleted successfully", "success")
        log_action(f"Deleted YARA rule: {rule_name}", current_user.id)
        log_event("YARA", "info", f"YARA rule deleted: {rule_name}")
    
    return redirect(url_for('manage_yara_rules'))

# ===================================================================
# PROCESS MONITORING
# ===================================================================

@app.route('/processes')
@login_required
def process_monitoring():
    """Monitor running processes with advanced detection"""
    ps_output = run_command("ps aux --sort=-%cpu | head -n 30", use_cache=True)
    processes = []
    suspicious_processes = []

    suspicious_patterns = [
        "wget", "curl", "bash", "nc", "python", "perl", "php", "python3", 
        "java", "sh", "tar", "miner", "crypto", "xmrig"
    ]
    
    if ps_output and not ps_output.startswith("ERROR"):
        for line in ps_output.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 11:
                user = parts[0]
                pid = parts[1]
                cpu = parts[2]
                mem = parts[3]
                command = ' '.join(parts[10:])
                
                process_info = {
                    'user': user,
                    'pid': pid,
                    'cpu': cpu,
                    'mem': mem,
                    'command': command
                }
                
                # Check for suspicious patterns
                if any(pattern in command.lower() for pattern in suspicious_patterns):
                    suspicious_processes.append({**process_info, 'reason': 'Suspicious command detected'})
                
                # Check resource usage
                try:
                    if float(cpu) > 50.0:
                        suspicious_processes.append({**process_info, 'reason': 'High CPU usage'})
                    elif float(mem) > 50.0:
                        suspicious_processes.append({**process_info, 'reason': 'High memory usage'})
                except ValueError:
                    pass

                if user in ['root', 'admin'] and 'sudo' not in command.lower():
                    suspicious_processes.append({**process_info, 'reason': 'Running with elevated privileges'})

                processes.append(process_info)
    
    session['suspicious_processes'] = suspicious_processes
    
    return render_template('processes.html', 
                         processes=processes, 
                         suspicious_processes=suspicious_processes, 
                         current_year=datetime.now().year)

@app.route('/kill_process', methods=['POST'])
@login_required
def kill_process():
    """Kill a process and log malicious activities"""
    pid = request.form.get('pid')
    if not pid or not pid.isdigit():
        flash("Invalid PID", "error")
        return redirect(url_for('process_monitoring'))
    
    suspicious_processes = session.get('suspicious_processes', [])
    killed_process_info = None
    
    for proc in suspicious_processes:
        if proc['pid'] == pid:
            killed_process_info = proc
            break
    
    cmd = f"sudo kill -9 {pid}"
    result = run_command(cmd)
    
    if "ERROR" in result:
        flash(f"Failed to kill process: {result}", "error")
        log_event("PROCESS", "error", f"Failed to kill process {pid}", {"error": result})
    else:
        flash(f"Process {pid} killed successfully", "success")
        log_action(f"Killed process: {pid}", current_user.id)
        log_event("PROCESS", "warning", f"Process {pid} killed by admin")
        
        if killed_process_info:
            log_event("PROCESS", "warning", f"Malicious process {pid} killed", killed_process_info)
    
    return redirect(url_for('process_monitoring'))

# ===================================================================
# NETWORK MONITORING
# ===================================================================

@app.route('/network')
@login_required
def network_monitoring():
    """Monitor network connections and flag malicious ports and IPs"""
    malicious_ports = {
        '23', '69', '135', '137', '138', '139', '445', '1433', '3306', '4444',
        '5554', '6660', '6661', '6662', '6663', '6664', '6665', '6666', '6667',
        '6668', '6669', '31337', '12345', '27374', '2323', '8080', '9001',
        '37215', '52869'
    }

    malicious_ips = set()
    try:
        with open('malware_ips.txt', 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    malicious_ips.add(ip)
    except FileNotFoundError:
        pass

    # Use individual commands instead of batch for reliability
    listening = []
    suspicious_listening = []
    established = []
    suspicious_established = []

    # Get listening ports
    listen_output = run_command("ss -tulnp 2>/dev/null", use_cache=True)
    if listen_output and not listen_output.startswith("ERROR"):
        for line in listen_output.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6:
                local_address = parts[4]
                process = parts[5]
                # Extract port from local address
                port = local_address.split(':')[-1]
                
                pid = None
                # Extract PID from process info
                if "pid=" in process:
                    pid = process.split('pid=')[1].split(',')[0]
                elif "," in process:
                    pid = process.split(',')[-1]
                
                entry = {
                    'netid': parts[0],
                    'state': parts[1],
                    'local': local_address,
                    'process': process,
                    'port': port,
                    'pid': pid
                }

                if port in malicious_ports:
                    entry['reason'] = 'Known malicious listening port'
                    suspicious_listening.append(entry)

                listening.append(entry)

    # Get established connections
    est_output = run_command("ss -tupn 2>/dev/null", use_cache=True)
    if est_output and not est_output.startswith("ERROR"):
        for line in est_output.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6:
                local_address = parts[4]
                remote_address = parts[5]
                port = remote_address.split(':')[-1]
                remote_ip = remote_address.split(':')[0]
                process = parts[6] if len(parts) > 6 else 'N/A'
                
                pid = None
                if "pid=" in process:
                    pid = process.split('pid=')[1].split(',')[0]
                elif "," in process:
                    pid = process.split(',')[-1]
                
                entry = {
                    'netid': parts[0],
                    'state': parts[1],
                    'local': local_address,
                    'remote': remote_address,
                    'process': process,
                    'port': port,
                    'pid': pid
                }

                is_suspicious = False
                if port in malicious_ports:
                    entry['reason'] = 'Connected to known malicious port'
                    is_suspicious = True
                if remote_ip in malicious_ips:
                    entry['reason'] = 'Connected to known malicious IP'
                    is_suspicious = True

                if is_suspicious:
                    suspicious_established.append(entry)
                established.append(entry)

    return render_template('network.html',
                         listening=listening,
                         established=established,
                         suspicious_listening=suspicious_listening,
                         suspicious_established=suspicious_established,
                         malicious_ports=malicious_ports,
                         malicious_ips=malicious_ips,
                         current_year=datetime.now().year)

@app.route('/firewall/block_ip', methods=['POST'])
@login_required
def block_ip():
    """Block an IP address using firewall-cmd"""
    ip = request.form.get('ip')
    if not ip:
        return jsonify({'success': False, 'error': 'No IP provided'}), 400
    
    try:
        # Add the IP to firewall
        cmd = f"sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address={ip} drop'"
        result = run_command(cmd, get_pty=True)
        
        if "ERROR" in result:
            return jsonify({'success': False, 'error': result}), 500
        
        # Reload firewall
        reload_cmd = "sudo firewall-cmd --reload"
        reload_result = run_command(reload_cmd, get_pty=True)
        
        if "ERROR" in reload_result:
            return jsonify({'success': False, 'error': reload_result}), 500
        
        log_action(f"Blocked IP {ip}", current_user.id)
        return jsonify({'success': True, 'message': f'IP {ip} blocked successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ===================================================================
# FILE INTEGRITY
# ===================================================================

@app.route('/file_integrity', methods=['GET', 'POST'])
@login_required
def file_integrity():
    """File integrity monitoring"""
    if request.method == 'POST':
        action = request.form.get('action')
        file_path = request.form.get('file_path')
        
        if action == 'hash':
            if not file_path:
                flash("Please enter a file path", "error")
                return redirect(url_for('file_integrity'))
            
            cmd = f"sha256sum {file_path}"
            result = run_command(cmd)
            
            if "ERROR" in result:
                flash(f"Failed to get hash: {result}", "error")
            else:
                flash(f"Hash for {file_path}: {result.split()[0]}", "success")
                log_action(f"Checked hash for {file_path}", current_user.id)
        
        elif action == 'quarantine':
            if not file_path:
                flash("Please enter a file path", "error")
                return redirect(url_for('file_integrity'))
            
            cmd = f"sudo mv {file_path} {app.config['QUARANTINE_DIR']}"
            result = run_command(cmd)
            
            if "ERROR" in result:
                flash(f"Failed to quarantine file: {result}", "error")
                log_event("FIM", "error", f"Failed to quarantine {file_path}", {"error": result})
            else:
                clear_command_cache()
                flash(f"File {file_path} quarantined successfully", "success")
                log_action(f"Quarantined file: {file_path}", current_user.id)
                log_event("FIM", "warning", f"File quarantined: {file_path}")
        
        return redirect(url_for('file_integrity'))
    
    # List quarantined files
    quarantined = []
    if os.path.exists(app.config['QUARANTINE_DIR']):
        cmd = f"ls -la {app.config['QUARANTINE_DIR']}"
        result = run_command(cmd, use_cache=True)
        
        if result and not result.startswith("ERROR"):
            quarantined = [line.strip() for line in result.split('\n') if line.strip()]
    
    return render_template('file_integrity.html', quarantined=quarantined)

# ===================================================================
# LOG MANAGEMENT
# ===================================================================

@app.route('/logs')
@login_required
def log_management():
    """View security logs"""
    log_files = {
        'auth': '/var/log/auth.log',
        'syslog': '/var/log/syslog',
        'Hermes_events': os.path.join(app.config['LOG_DIR'], 'Hermes_events.log'),
        'admin_actions': os.path.join(app.config['LOG_DIR'], 'admin_actions.log')
    }
    
    selected_log = request.args.get('log', 'Hermes_events')
    log_content = []
    
    if selected_log in log_files:
        cmd = f"tail -n 100 {log_files[selected_log]}"
        result = run_command(cmd, use_cache=True)
        
        if result and not result.startswith("ERROR"):
            log_content = [line.strip() for line in result.split('\n') if line.strip()]
    
    return render_template('logs.html',
                         log_files=log_files.keys(),
                         selected_log=selected_log,
                         log_content=log_content)

# ===================================================================
# SERVICE MANAGEMENT
# ===================================================================

def is_suspicious_service(service_name):
    """Detect suspicious services based on name patterns"""
    suspicious_patterns = [
        r'^\.',
        r'^[a-z0-9]{12,}\.service$',
        r'^[A-Z0-9]{8,}\.service$',
        r'(backdoor|keylogger|reverse_shell|meterpreter|empire|revshell|rat)',
        r'(malware|exploit|infect|payload|trojan|dropper|bindshell|spysvc)',
        r'(auditbypass|disablelogs|antiav|rootkit|invis)',
        r'(hiddenservice|cloak|ghost|undetected)',
        r'(systemd\d+|init\d+|syslogd\d+)\.service$',
        r'(ssh\.service\.bak|cron\.service\.disabled|sshd\.1\.service)'
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, service_name, re.IGNORECASE):
            return True
    return False

@app.route('/services', methods=['GET', 'POST'])
@login_required
def service_management():
    now = mydate.datetime.now()
    suspicious_services = []

    if request.method == 'POST':
        service = request.form.get('service')
        action = request.form.get('action')

        if not service or not action:
            flash("Service and action are required", "error")
            return redirect(url_for('service_management'))

        valid_actions = ['start', 'stop', 'restart', 'enable', 'disable']
        if action not in valid_actions:
            flash("Invalid action", "error")
            return redirect(url_for('service_management'))

        service = shlex.quote(service)
        action = shlex.quote(action)

        cmd = f"sudo systemctl {action} {service}"
        result = run_command(cmd, get_pty=True)

        if "ERROR" in result:
            flash(f"Failed to {action} service: {result}", "error")
            log_event("SERVICE", "error", f"Failed to {action} {service}", {"error": result})
        else:
            clear_command_cache()
            flash(f"Service {service} {action}ed successfully", "success")
            log_action(f"{action}ed service: {service}", current_user.id)
            log_event("SERVICE", "info", f"Service {service} {action}ed")

        return redirect(url_for('service_management'))

    # List all services
    services = []
    cmd = "systemctl list-units --type=service --no-pager --no-legend"
    result = run_command(cmd, use_cache=True)

    if result and not result.startswith("ERROR"):
        for line in result.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    service_name = parts[0]
                    loaded = parts[1]
                    active = parts[2]
                    sub = parts[3]

                    is_suspicious = False
                    reason = ""

                    if is_suspicious_service(service_name):
                        is_suspicious = True
                        reason = 'Suspicious service name detected'

                    # Check path of unit file
                    path_cmd = f"systemctl show -p FragmentPath {service_name}"
                    path_result = run_command(path_cmd)
                    if "ERROR" not in path_result and "FragmentPath=" in path_result:
                        fragment_path = path_result.split('=')[1].strip()
                        if fragment_path.startswith('/tmp') or fragment_path.startswith('/var/tmp') or '/home/' in fragment_path:
                            is_suspicious = True
                            reason = f"Service file loaded from suspicious path: {fragment_path}"

                    allowlist = ["ssh.service", "nginx.service", "apache2.service", "docker.service"]
                    if service_name not in allowlist and active == "active" and sub == "running":
                        is_suspicious = True
                        reason = "Unknown active service"

                    if is_suspicious:
                        suspicious_services.append({
                            'name': service_name,
                            'loaded': loaded,
                            'active': active,
                            'sub': sub,
                            'reason': reason
                        })

                    services.append({
                        'name': service_name,
                        'loaded': loaded,
                        'active': active,
                        'sub': sub
                    })

    return render_template('services.html', services=services, suspicious_services=suspicious_services, now=now)

# ===================================================================
# FIREWALL
# ===================================================================

@app.route('/firewall', methods=['GET', 'POST'])
@login_required
def firewall():
    """Manage firewall rules"""
    if request.method == 'POST':
        action = request.form.get('action')
        port = request.form.get('port')
        service = request.form.get('service')
        zone = request.form.get('zone', 'public')

        if not action:
            flash("Action is required.", "error")
            return redirect(url_for('firewall'))
        
        if not port and not service:
            flash("Provide either a port or a service.", "error")
            return redirect(url_for('firewall'))

        if port and service:
            flash("Provide only a port or a service, not both.", "error")
            return redirect(url_for('firewall'))

        try:
            if port:
                port = port.strip()
                
                if action == "allow":
                    command = f"sudo firewall-cmd --zone={zone} --add-port={port}/tcp --permanent"
                elif action == "deny":
                    if not re.match(r'^\d+(-\d+)?$', port):
                        flash(f"Invalid port format: {port}. Use single port (80) or range (8000-9000)", "error")
                        return redirect(url_for('firewall'))
                    
                    check_cmd = f"sudo firewall-cmd --zone={zone} --query-port={port}/tcp"
                    port_exists = run_command(check_cmd, get_pty=True)
                    
                    if "yes" not in port_exists.lower():
                        flash(f"Port {port} doesn't exist in zone {zone}", "warning")
                        return redirect(url_for('firewall'))
                    
                    command = f"sudo firewall-cmd --zone={zone} --remove-port={port}/tcp --permanent"
                else:
                    raise ValueError("Invalid action")
                
                output = run_command(command, get_pty=True)
                
                if action == "allow":
                    flash(f"Successfully added port {port} to zone {zone}", "success")
                elif action == "deny":
                    flash(f"Successfully removed port {port} from zone {zone}", "success")
                
                log_action(f"Firewall {action} port {port}")
            
            elif service:
                if action == "allow":
                    command = f"sudo firewall-cmd --zone={zone} --add-service={service} --permanent"
                elif action == "deny":
                    check_cmd = f"sudo firewall-cmd --zone={zone} --query-service={service}"
                    service_exists = run_command(check_cmd, get_pty=True)
                    
                    if "yes" not in service_exists.lower():
                        flash(f"Service {service} doesn't exist in zone {zone}", "warning")
                        return redirect(url_for('firewall'))
                    command = f"sudo firewall-cmd --zone={zone} --remove-service={service} --permanent"
                else:
                    raise ValueError("Invalid action")
                
                output = run_command(command, get_pty=True)
                flash(f"Service {service} {action}ed in zone {zone}", "success")
                log_action(f"Firewall {action} service {service}")

            # Reload firewall
            reload_output = run_command("sudo firewall-cmd --reload", get_pty=True)
            if "success" not in reload_output.lower():
                raise Exception(f"Firewall reload failed: {reload_output}")
            
            clear_command_cache()

        except Exception as e:
            error_msg = str(e)
            flash(f"Firewall operation failed: {error_msg}", "error")
            log_action(f"Firewall error: {error_msg}")

        return redirect(url_for('firewall'))

    # Get firewall status
    try:
        runtime_status = run_command("sudo firewall-cmd --list-all", get_pty=True)
        permanent_status = run_command("sudo firewall-cmd --list-all --permanent", get_pty=True)
        
        firewall_status = f"=== Runtime Configuration ===\n{runtime_status}\n\n=== Permanent Configuration ===\n{permanent_status}"
        
        if "ERROR" in firewall_status:
            firewall_status = f"Error retrieving full status. Runtime config:\n{runtime_status}"
    except Exception as e:
        firewall_status = f"Error getting firewall status: {str(e)}"
    
    try:
        current_zone = run_command("sudo firewall-cmd --get-default-zone", get_pty=True)
    except:
        current_zone = "Unknown"
    
    return render_template('firewall.html', 
                         firewall_status=firewall_status,
                         current_zone=current_zone)

# ===================================================================
# FAIL2BAN
# ===================================================================

@app.route('/firewall/fail2ban', methods=['GET', 'POST'])
@login_required
def fail2ban():
    """Manage Fail2Ban jails and rules."""
    if request.method == 'POST':
        action = request.form.get('action')
        jail = request.form.get('jail')
        ip = request.form.get('ip')
        bantime = request.form.get('bantime')
        findtime = request.form.get('findtime')
        maxretry = request.form.get('maxretry')
        
        try:
            if action == "ban":
                if not ip:
                    flash("IP address is required for banning.", "error")
                    return redirect(url_for('fail2ban'))
                command = f"sudo fail2ban-client set {jail} banip {ip}"
                output = run_command(command, get_pty=True)
                log_action(f"Fail2Ban banned IP {ip} in jail {jail}")
                flash(f"IP {ip} banned in {jail}: {output}", "success")
                
            elif action == "unban":
                if not ip:
                    flash("IP address is required for unbanning.", "error")
                    return redirect(url_for('fail2ban'))
                command = f"sudo fail2ban-client set {jail} unbanip {ip}"
                output = run_command(command, get_pty=True)
                log_action(f"Fail2Ban unbanned IP {ip} in jail {jail}")
                flash(f"IP {ip} unbanned in {jail}: {output}", "success")
                
            elif action == "add_jail":
                if not jail or not bantime or not findtime or not maxretry:
                    flash("All fields are required to create a new jail.", "error")
                    return redirect(url_for('fail2ban'))
                
                jail_config = f"""
[{jail}]
enabled = true
port = ssh
filter = {jail}
logpath = /var/log/auth.log
bantime = {bantime}
findtime = {findtime}
maxretry = {maxretry}
"""
                jail_file = f"/etc/fail2ban/jail.d/{jail}.local"
                cmd = f"echo '{jail_config}' | sudo tee {jail_file}"
                output = run_command(cmd, get_pty=True)
                
                restart_output = run_command("sudo systemctl restart fail2ban", get_pty=True)
                clear_command_cache()
                log_action(f"Fail2Ban created new jail {jail}")
                flash(f"New jail {jail} created and Fail2Ban restarted", "success")
                
            return redirect(url_for('fail2ban'))
        
        except Exception as e:
            flash(f"Fail2Ban operation failed: {str(e)}", "error")
            log_action(f"Fail2Ban error: {str(e)}")
            return redirect(url_for('fail2ban'))
    
    # Get current Fail2Ban status
    try:
        status = run_command("sudo fail2ban-client status", get_pty=True, use_cache=True)
        jails_output = run_command("sudo fail2ban-client status | grep 'Jail list:'", get_pty=True, use_cache=True)
        jails = jails_output.split(':')[-1].strip().split(', ') if jails_output else []
        
        banned_ips = {}
        for jail in jails:
            jail = jail.strip()
            if jail:
                ips = run_command(f"sudo fail2ban-client get {jail} banip", get_pty=True, use_cache=True)
                banned_ips[jail] = ips.split() if ips else []
        
        return render_template('fail2ban.html', 
                            status=status, 
                            jails=jails, 
                            banned_ips=banned_ips)
    
    except Exception as e:
        flash(f"Error retrieving Fail2Ban status: {str(e)}", "error")
        return render_template('fail2ban_logs.html', 
                            status="Error", 
                            jails=[], 
                            banned_ips={})

@app.route('/firewall/fail2ban/logs')
@login_required
def fail2ban_logs():
    """View Fail2Ban logs."""
    try:
        logs = run_command("sudo tail -n 100 /var/log/fail2ban.log", get_pty=True)
        return render_template('fail2ban_logs.html', logs=logs)
    except Exception as e:
        flash(f"Error retrieving Fail2Ban logs: {str(e)}", "error")
        return render_template('fail2ban_logs.html', logs="Error loading logs")

# ===================================================================
# KERNEL MODULES
# ===================================================================

# Cache expiration time (5 minutes)
CACHE_EXPIRATION = 300

def remote_file_exists(path):
    """Check if file exists on remote system"""
    cmd = f"[ -f '{path}' ] && echo 'exists' || echo 'not found'"
    result = run_command(cmd, use_cache=True)
    return result == 'exists'

def remote_dir_exists(path):
    """Check if directory exists on remote system"""
    cmd = f"[ -d '{path}' ] && echo 'exists' || echo 'not found'"
    result = run_command(cmd, use_cache=True)
    return result == 'exists'

def remote_walk(path):
    """Simulate os.walk for remote system"""
    try:
        cmd = f"find '{path}' -type d -printf '%p\\n' 2>/dev/null"
        dirs = run_command(cmd).split('\n')
        
        result = []
        for d in dirs:
            if not d:
                continue
            files_cmd = f"find '{d}' -maxdepth 1 -type f -printf '%f\\n' 2>/dev/null"
            files = run_command(files_cmd).split('\n')
            subdirs_cmd = f"find '{d}' -maxdepth 1 -type d -printf '%f\\n' 2>/dev/null | tail -n +2"
            subdirs = run_command(subdirs_cmd).split('\n')
            result.append((d, [sd for sd in subdirs if sd], [f for f in files if f]))
        return result
    except Exception as e:
        log_event("REMOTE", "error", "Remote walk failed", {
            'path': path,
            'error': str(e)
        })
        return []

def remote_stat(path):
    """Get file stats from remote system"""
    cmd = f"stat -c '%a %u %g %s' '{path}' 2>/dev/null"
    result = run_command(cmd, use_cache=True)
    if result.startswith("ERROR"):
        return None
    try:
        mode, uid, gid, size = result.split()
        return {
            'mode': int(mode, 8),
            'uid': int(uid),
            'gid': int(gid),
            'size': int(size)
        }
    except:
        return None

@lru_cache(maxsize=1)
def get_kernel_release():
    """Get kernel release from remote system with caching"""
    result = run_command("uname -r", use_cache=True).strip()
    return result if not result.startswith("ERROR") else "unknown"

@lru_cache(maxsize=32)
def cached_kernel_data(func, *args, **kwargs):
    """Decorator for caching kernel data"""
    def wrapper():
        return func(*args, **kwargs)
    return wrapper

def check_module_signing():
    """Check module signing status"""
    try:
        cmd = """cat /proc/sys/kernel/module_sig_enforce /proc/sys/kernel/module_sig_all /proc/sys/kernel/modules_disabled 2>/dev/null"""
        output = run_command(cmd, use_cache=True)
        
        if output.startswith("ERROR"):
            raise Exception(output)
            
        values = output.split('\n')
        if len(values) >= 3:
            sig_enforce, sig_all, modules_disabled = values[0], values[1], values[2]
        else:
            sig_enforce = sig_all = modules_disabled = 'unknown'
        
        secureboot = run_command("[ -d /sys/firmware/efi/efivars ] && echo 'enabled' || echo 'disabled'", use_cache=True)
        if secureboot.startswith("ERROR"):
            secureboot = 'unknown'
        
        return {
            'modules_disabled': modules_disabled.strip(),
            'sig_enforce': sig_enforce.strip(),
            'sig_all': sig_all.strip(),
            'secureboot': secureboot.strip()
        }
    except Exception as e:
        log_event("KERNEL", "error", "Failed to check module signing", {'error': str(e)})
        return {
            'modules_disabled': 'unknown',
            'sig_enforce': 'unknown',
            'sig_all': 'unknown',
            'secureboot': 'unknown'
        }

def check_module_hijacking():
    """Optimized module hijacking check"""
    vulns = []
    paths_to_check = [
        '/lib/modules',
        '/usr/lib/modules',
        '/etc/modprobe.d',
        '/etc/modules-load.d',
        '/run/modprobe.d',
        '/usr/local/lib/modprobe.d',
        '/usr/lib/modprobe.d'
    ]
    
    try:
        for path in paths_to_check:
            if remote_dir_exists(path):
                for root, dirs, files in remote_walk(path):
                    for name in dirs:
                        full_path = os.path.join(root, name)
                        stat = remote_stat(full_path)
                        if stat and stat['mode'] & 0o002:
                            vulns.append({
                                'path': full_path,
                                'issue': 'World-writable module directory',
                                'severity': 'high',
                                'mode': oct(stat['mode']),
                                'owner': f"{stat['uid']}:{stat['gid']}"
                            })
        
        config_paths = [
            '/etc/modprobe.d',
            '/run/modprobe.d',
            '/usr/local/lib/modprobe.d',
            '/usr/lib/modprobe.d'
        ]
        
        for path in config_paths:
            if remote_dir_exists(path):
                for root, _, files in remote_walk(path):
                    for name in files:
                        full_path = os.path.join(root, name)
                        stat = remote_stat(full_path)
                        if stat and stat['mode'] & 0o002:
                            vulns.append({
                                'path': full_path,
                                'issue': 'World-writable modprobe configuration',
                                'severity': 'critical',
                                'mode': oct(stat['mode']),
                                'owner': f"{stat['uid']}:{stat['gid']}"
                            })
        
        return vulns
    except Exception as e:
        log_event("KERNEL", "error", "Failed to check module hijacking", {'error': str(e)})
        return []

def get_kernel_config():
    """Get kernel config"""
    config = {}
    kernel_release = get_kernel_release()
    config_paths = [
        '/proc/config.gz',
        f'/boot/config-{kernel_release}',
        f'/lib/modules/{kernel_release}/build/.config'
    ]
    
    try:
        for path in config_paths:
            if remote_file_exists(path):
                if path.endswith('.gz'):
                    cmd = f"zcat {path}"
                else:
                    cmd = f"cat {path}"
                
                output = run_command(cmd, use_cache=True)
                if not output.startswith("ERROR"):
                    for line in output.split('\n'):
                        if line.startswith('CONFIG_'):
                            key, val = line.split('=', 1)
                            config[key] = val.strip('"')
                    break
        
        important_params = {
            'CONFIG_MODULE_SIG': 'Module signing',
            'CONFIG_MODULE_SIG_FORCE': 'Force module signing',
            'CONFIG_MODULE_SIG_ALL': 'Sign all modules',
            'CONFIG_DEBUG_KERNEL': 'Kernel debugging',
            'CONFIG_STRICT_DEVMEM': 'Restrict /dev/mem access',
            'CONFIG_IO_STRICT_DEVMEM': 'Strict /dev/mem I/O',
            'CONFIG_SECURITY': 'Security framework',
            'CONFIG_SECURITY_YAMA': 'Yama security module',
            'CONFIG_SECURITY_SELINUX': 'SELinux',
            'CONFIG_SECURITY_APPARMOR': 'AppArmor',
            'CONFIG_CC_STACKPROTECTOR': 'Stack protector',
            'CONFIG_CC_STACKPROTECTOR_STRONG': 'Strong stack protector',
            'CONFIG_RANDOMIZE_BASE': 'KASLR (Address space randomization)',
            'CONFIG_STACKPROTECTOR': 'Stack protection',
            'CONFIG_SYN_COOKIES': 'SYN flood protection',
            'CONFIG_DEBUG_CREDENTIALS': 'Credential debugging'
        }
        
        return {desc: config.get(param, 'not set') for param, desc in important_params.items()}
    
    except Exception as e:
        log_event("KERNEL", "error", "Failed to read kernel config", {'error': str(e)})
        return {}

def get_all_kernel_modules():
    """Get all kernel modules"""
    try:
        kernel_release = get_kernel_release()
        module_dir = f"/lib/modules/{kernel_release}"
        
        cmd = f"find {module_dir} -type f \( -name '*.ko' -o -name '*.ko.xz' \) -printf '%p %s\\n' 2>/dev/null"
        output = run_command(cmd, use_cache=True)
        
        modules = []
        for line in output.split('\n'):
            if line.strip():
                try:
                    path, size = line.rsplit(' ', 1)
                    base = os.path.basename(path)
                    module_name = os.path.splitext(os.path.splitext(base)[0])[0]
                    modules.append({
                        'name': module_name,
                        'path': path,
                        'size': int(size)
                    })
                except ValueError:
                    continue
        
        return modules
        
    except Exception as e:
        log_event("KERNEL", "error", "Failed to get all kernel modules", {
            'error': str(e),
            'traceback': traceback.format_exc()
        })
        return []

def get_loaded_kernel_modules():
    """Get loaded kernel modules"""
    try:
        cmd = "lsmod | awk 'NR>1 {print $1,$2,$3}'"
        lsmod_output = run_command(cmd, use_cache=True)
        
        if lsmod_output.startswith("ERROR"):
            raise Exception(lsmod_output)
            
        modules = []
        module_names = []
        
        for line in lsmod_output.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    module = {
                        'name': parts[0],
                        'size': parts[1],
                        'refcount': parts[2],
                        'path': 'unknown',
                        'signature': 'unknown',
                        'status': 'loaded'
                    }
                    modules.append(module)
                    module_names.append(parts[0])
        
        if module_names:
            # Get paths for all modules
            paths_cmd = f"modinfo -F filename {' '.join(module_names)} 2>/dev/null"
            paths_output = run_command(paths_cmd, use_cache=True)
            paths = paths_output.split('\n') if paths_output else []
            
            # Get signature status
            sig_cmd = f"for m in {' '.join(module_names)}; do modinfo $m | grep -q '^sig_id:' && echo 'signed' || echo 'unsigned'; done 2>/dev/null"
            sig_output = run_command(sig_cmd, use_cache=True)
            signatures = sig_output.split('\n') if sig_output else []
            
            for i, module in enumerate(modules):
                if i < len(paths) and paths[i].strip():
                    module['path'] = paths[i].strip()
                if i < len(signatures) and signatures[i].strip():
                    module['signature'] = signatures[i].strip()
                module['tainted'] = check_if_tainted(module['name'])
        
        return modules
        
    except Exception as e:
        log_event("KERNEL", "error", "Failed to get loaded modules", {
            'error': str(e),
            'traceback': traceback.format_exc()
        })
        return []

def check_if_tainted(module_name):
    """Check if a module contributes to kernel tainting"""
    try:
        taint_output = run_command("cat /proc/sys/kernel/tainted 2>/dev/null", use_cache=True)
        if taint_output.isdigit():
            taint_flags = int(taint_output)
            if taint_flags & (1 << 11) or taint_flags & (1 << 12):
                mod_output = run_command(f"grep -l {module_name} /sys/module/*/taint 2>/dev/null", use_cache=True)
                return "Yes" if mod_output and not mod_output.startswith("ERROR") else "No"
        return "No"
    except:
        return "Unknown"

def detect_suspicious_modules():
    """Detect suspicious kernel modules"""
    try:
        modules = get_loaded_kernel_modules()
        
        MALICIOUS_PATTERNS = [
            re.compile(r'rootkit', re.IGNORECASE),
            re.compile(r'backdoor', re.IGNORECASE),
            re.compile(r'hid(e|den)', re.IGNORECASE),
            re.compile(r'stealth', re.IGNORECASE),
            re.compile(r'keylog', re.IGNORECASE),
            re.compile(r'hook', re.IGNORECASE),
            re.compile(r'inject', re.IGNORECASE),
            re.compile(r'\.hidden$', re.IGNORECASE),
            re.compile(r'_hack', re.IGNORECASE),
            re.compile(r'_mal(ware|icious)', re.IGNORECASE)
        ]
        
        VULNERABLE_MODULES = {
            'nvidia', 'vmware', 'virtualbox', 'dccp', 'sctp', 'tipc',
            'ath3k', 'bluetooth', 'cdc_ether', 'rds', 'iwlwifi'
        }
        
        suspicious = []
        
        for module in modules:
            reasons = []
            name = module.get('name', '').lower()
            path = module.get('path', '').lower()
            
            for pattern in MALICIOUS_PATTERNS:
                if pattern.search(name) or pattern.search(path):
                    reasons.append(f"Name/path matches pattern: {pattern.pattern}")
            
            if name in VULNERABLE_MODULES:
                reasons.append("Known vulnerable module")
            
            if module.get('signature') == 'unsigned':
                reasons.append("Unsigned module")
            
            if path and not any(p in path for p in ['/lib/modules/', '/usr/lib/modules/']):
                reasons.append(f"Unusual module path: {module.get('path')}")
            
            if not is_module_in_proc_modules(module['name']):
                reasons.append("Module hidden from /proc/modules")
            
            if reasons:
                suspicious.append({
                    'name': module['name'],
                    'reasons': reasons,
                    'size': module.get('size', 'unknown'),
                    'refcount': module.get('refcount', 'unknown'),
                    'path': module.get('path', 'unknown'),
                    'signature': module.get('signature', 'unknown'),
                    'tainted': module.get('tainted', 'unknown')
                })
        
        return suspicious
        
    except Exception as e:
        log_event("KERNEL", "error", "Suspicious module detection failed", {
            'error': str(e),
            'traceback': traceback.format_exc()
        })
        return []

def is_module_in_proc_modules(module_name):
    """Check if module appears in /proc/modules"""
    try:
        cmd = f"grep -q '^{module_name} ' /proc/modules && echo 'yes' || echo 'no'"
        result = run_command(cmd, use_cache=True)
        return result == 'yes'
    except:
        return True

@app.route('/kernel_modules')
@login_required
def manage_kernel_modules():
    """Kernel module management dashboard"""
    now = datetime.now()
    
    kernel_config = get_kernel_config()
    loaded_modules = get_loaded_kernel_modules()
    signing_status = check_module_signing()
    
    return render_template('kernel_modules.html',
        loaded_modules=loaded_modules,
        signing_status=signing_status,
        kernel_config=kernel_config,
        now=now,
        initial_load=True)

@app.route('/api/kernel_modules/full_data')
@login_required
def get_full_kernel_data():
    """Endpoint for loading full dataset asynchronously"""
    try:
        return jsonify({
            'all_modules': get_all_kernel_modules(),
            'suspicious_modules': detect_suspicious_modules(),
            'hijacking_vulns': check_module_hijacking(),
            'kernel_config': get_kernel_config()
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

# ===================================================================
# IDS MANAGEMENT
# ===================================================================

@app.route('/ids')
@login_required
def ids_dashboard():
    """IDS/IPS Management Dashboard"""
    now = mydate.datetime.now()
    
    if not app.config['SSH_HOST']:
        flash("Please configure SSH connection first", "error")
        return redirect(url_for('configure_ssh'))
    
    status = {
        'enabled': False,
        'running': False,
        'mode': 'IDS',
        'interface': 'eth0',
        'rules_count': 0,
        'alerts': [],
        'version': 'Unknown'
    }
    
    try:
        check_installed = run_command("which suricata", use_cache=True)
        if "ERROR" in check_installed or not check_installed.strip():
            flash("Suricata is not installed on the remote system", "warning")
            return render_template('ids.html', status=status)
        
        version_output = run_command("suricata -V", use_cache=True)
        if version_output and not version_output.startswith("ERROR"):
            version_line = version_output.split('\n')[0]
            status['version'] = version_line.split(' ')[1] if ' ' in version_line else version_line
        
        ps_output = run_command("ps aux | grep [s]uricata", use_cache=True)
        if ps_output and "suricata" in ps_output:
            status['running'] = True
            status['enabled'] = True
            if "--ips" in ps_output:
                status['mode'] = 'IPS'
            
            if "-i" in ps_output:
                try:
                    interface = ps_output.split("-i")[1].split()[0]
                    status['interface'] = interface
                except:
                    pass
        
        rules_output = run_command(f"find {app.config['SURICATA_RULES_DIR']} -name '*.rules' | wc -l", use_cache=True)
        if rules_output and not rules_output.startswith("ERROR"):
            status['rules_count'] = int(rules_output.strip())
        
        status['alerts'] = get_recent_alerts()
        
    except Exception as e:
        flash(f"Error checking Suricata status: {str(e)}", "error")
        log_event("IDS", "error", "Failed to check Suricata status", {"error": str(e)})
    
    return render_template('ids.html', status=status, now=now)

def get_recent_alerts(limit=50):
    """Get recent alerts from Suricata's eve.json"""
    alerts = []
    eve_log = os.path.join(app.config['SURICATA_LOGS'], 'eve.json')
    
    check_cmd = f"test -f {eve_log} && echo exists"
    if run_command(check_cmd, use_cache=True) != "exists":
        return alerts
    
    cmd = f"tail -n {limit} {eve_log} 2>/dev/null | grep '\"event_type\":\"alert\"'"
    output = run_command(cmd, use_cache=True)
    
    if output and not output.startswith("ERROR"):
        for line in output.split('\n'):
            try:
                alert = json.loads(line)
                
                standardized = {
                    'timestamp': alert.get('timestamp', ''),
                    'event_type': alert.get('event_type', 'alert'),
                    'src_ip': alert.get('src_ip', ''),
                    'src_port': alert.get('src_port', ''),
                    'dest_ip': alert.get('dest_ip', ''),
                    'dest_port': alert.get('dest_port', ''),
                    'proto': alert.get('proto', ''),
                    'alert': {
                        'signature': alert.get('alert', {}).get('signature', 'Unknown'),
                        'severity': alert.get('alert', {}).get('severity', 3),
                        'category': alert.get('alert', {}).get('category', 'Unknown')
                    }
                }
                
                if 'http' in alert:
                    standardized['http'] = {
                        'hostname': alert['http'].get('hostname', ''),
                        'url': alert['http'].get('url', ''),
                        'http_method': alert['http'].get('http_method', ''),
                        'http_user_agent': alert['http'].get('http_user_agent', '')
                    }
                
                alerts.append(standardized)
            except json.JSONDecodeError:
                continue
    
    return alerts

@app.route('/ids/rules', methods=['GET', 'POST'])
@login_required
def manage_ids_rules():
    """Manage IDS/IPS rules"""
    if not app.config['SSH_HOST']:
        flash("Please configure SSH connection first", "error")
        return redirect(url_for('configure_ssh'))
    
    if request.method == 'POST':
        rule_content = request.form.get('rule_content')
        rule_name = request.form.get('rule_name', 'custom.rules')
        
        if not rule_content:
            flash("No rule content provided", "error")
            return redirect(url_for('ids_dashboard'))
            
        try:
            if not rule_name.endswith('.rules'):
                rule_name += '.rules'
            
            if '/' in rule_name or '..' in rule_name:
                flash("Invalid rule name", "error")
                return redirect(url_for('ids_dashboard'))
            
            temp_path = f"/tmp/{rule_name}"
            upload_cmd = f"echo '{rule_content}' > {temp_path} && sudo mv {temp_path} {os.path.join(app.config['SURICATA_RULES_DIR'], rule_name)}"
            result = run_command(upload_cmd)
            
            if "ERROR" in result:
                flash(f"Failed to save rule: {result}", "error")
                log_event("IDS", "error", "Failed to save rule", {"rule": rule_name, "error": result})
            else:
                reload_suricata()
                clear_command_cache()
                flash("Rule added successfully", "success")
                log_action(f"Added IDS rule: {rule_name}", current_user.id)
                log_event("IDS", "info", f"New rule added: {rule_name}")
            
            return redirect(url_for('ids_dashboard'))
        except Exception as e:
            flash(f"Error processing rule: {str(e)}", "error")
            log_event("IDS", "error", "Rule addition failed", {"error": str(e)})
            return redirect(url_for('ids_dashboard'))
    
    rules = []
    if app.config['SSH_HOST']:
        rules_output = run_command(f"ls {app.config['SURICATA_RULES_DIR']}/*.rules", use_cache=True)
        if rules_output and not rules_output.startswith("ERROR"):
            rules = [os.path.basename(rule) for rule in rules_output.split('\n') if rule.strip()]
    
    return render_template('ids_rules.html', rules=rules)

@app.route('/ids/control', methods=['POST'])
@login_required
def ids_control():
    """Control Suricata service"""
    if not app.config['SSH_HOST']:
        return jsonify({'status': 'error', 'message': 'SSH not configured'}), 400
    
    action = request.form.get('action')
    mode = request.form.get('mode', 'ids')
    
    try:
        if action == 'start':
            success = start_suricata(mode == 'ips')
            if success:
                clear_command_cache()
                log_action(f"Started Suricata in {mode.upper()} mode", current_user.id)
                log_event("IDS", "info", f"Suricata started in {mode.upper()} mode")
                return jsonify({'status': 'success', 'message': 'Suricata started successfully'})
            else:
                log_event("IDS", "error", "Failed to start Suricata")
                return jsonify({'status': 'error', 'message': 'Failed to start Suricata'}), 500
                
        elif action == 'stop':
            success = stop_suricata()
            if success:
                clear_command_cache()
                log_action("Stopped Suricata", current_user.id)
                log_event("IDS", "info", "Suricata stopped")
                return jsonify({'status': 'success', 'message': 'Suricata stopped successfully'})
            else:
                log_event("IDS", "error", "Failed to stop Suricata")
                return jsonify({'status': 'error', 'message': 'Failed to stop Suricata'}), 500
                
        elif action == 'restart':
            stop_suricata()
            success = start_suricata(mode == 'ips')
            if success:
                clear_command_cache()
                log_action(f"Restarted Suricata in {mode.upper()} mode", current_user.id)
                log_event("IDS", "info", f"Suricata restarted in {mode.upper()} mode")
                return jsonify({'status': 'success', 'message': 'Suricata restarted successfully'})
            else:
                log_event("IDS", "error", "Failed to restart Suricata")
                return jsonify({'status': 'error', 'message': 'Failed to restart Suricata'}), 500
                
        else:
            return jsonify({'status': 'error', 'message': 'Invalid action'}), 400
            
    except Exception as e:
        log_event("IDS", "error", f"Control action failed: {action}", {"error": str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

def start_suricata(ips_mode=False):
    """Start Suricata service"""
    mode_flag = "--ips" if ips_mode else ""
    interface = app.config['SURICATA_INTERFACE']
    
    cmd = f"sudo suricata -c /etc/suricata/suricata.yaml -i {interface} {mode_flag} -D"
    output = run_command(cmd, get_pty=True)
    
    if "ERROR" in output:
        return False
    
    time.sleep(2)
    ps_output = run_command("ps aux | grep [s]uricata", use_cache=True)
    return ps_output and "suricata" in ps_output

def stop_suricata():
    """Stop Suricata service"""
    output = run_command("sudo pkill -15 suricata", get_pty=True)
    time.sleep(2)
    ps_output = run_command("ps aux | grep [s]uricata", use_cache=True)
    
    if ps_output and "suricata" in ps_output:
        run_command("sudo pkill -9 suricata", get_pty=True)
        time.sleep(1)
        ps_output = run_command("ps aux | grep [s]uricata", use_cache=True)
    
    return not (ps_output and "suricata" in ps_output)

def reload_suricata():
    """Reload Suricata rules without restarting"""
    if not app.config['SSH_HOST']:
        return False
    
    ps_output = run_command("ps aux | grep [s]uricata", use_cache=True)
    if not ps_output or "suricata" not in ps_output:
        return False
    
    output = run_command("sudo pkill -USR2 suricata", get_pty=True)
    return "ERROR" not in output

@app.route('/ids/alerts')
@login_required
def get_ids_alerts():
    """Get recent alerts (for AJAX updates)"""
    alerts = get_recent_alerts(50)
    return jsonify({'alerts': alerts})

@app.route('/ids/logs/live')
@login_required
def live_suricata_logs():
    """Stream live Suricata logs via SSE"""
    eve_log = os.path.join(app.config['SURICATA_LOGS'], 'eve.json')
    
    def generate():
        try:
            size_cmd = f"wc -c < {eve_log}" if run_command(f"test -f {eve_log} && echo exists", use_cache=True) == "exists" else "0"
            current_pos = int(run_command(size_cmd, use_cache=True) or 0)
            
            while True:
                if run_command(f"test -f {eve_log} && echo exists", use_cache=True) != "exists":
                    yield "data: " + json.dumps({'error': 'File not found'}) + "\n\n"
                    time.sleep(5)
                    continue
                
                new_size = int(run_command(f"wc -c < {eve_log}", use_cache=True) or 0)
                
                if new_size < current_pos:
                    current_pos = 0
                
                if new_size > current_pos:
                    cmd = f"tail -c +{current_pos + 1} {eve_log} | head -c {new_size - current_pos}"
                    new_content = run_command(cmd)
                    
                    if new_content and not new_content.startswith("ERROR"):
                        for line in new_content.split('\n'):
                            if line.strip():
                                try:
                                    entry = json.loads(line)
                                    yield "data: " + json.dumps(entry) + "\n\n"
                                except json.JSONDecodeError:
                                    continue
                        current_pos = new_size
                
                time.sleep(1)
        except Exception as e:
            log_event("ERROR", "high", "Live log streaming failed", {'error': str(e)})
            yield "data: " + json.dumps({'error': str(e)}) + "\n\n"
    
    return Response(generate(), mimetype="text/event-stream")

@app.route('/ids/update_rules')
@login_required
def update_ids_rules():
    """Update Suricata rules"""
    if not app.config['SSH_HOST']:
        return jsonify({'status': 'error', 'message': 'SSH not configured'}), 400
    
    try:
        cmd = "sudo suricata-update"
        output = run_command(cmd, timeout=300, get_pty=True)
        
        if "ERROR" in output:
            log_event("IDS", "error", "Failed to update rules", {"error": output})
            return jsonify({'status': 'error', 'message': output})
        
        reload_suricata()
        clear_command_cache()
        
        log_action("Updated Suricata rules", current_user.id)
        log_event("IDS", "info", "Rules updated successfully")
        
        return jsonify({
            'status': 'success',
            'message': 'Rules updated successfully',
            'output': output
        })
        
    except Exception as e:
        log_event("IDS", "error", "Rule update failed", {"error": str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ===================================================================
# MONITORING
# ===================================================================

@app.route("/monitoring")
@login_required
def monitoring():
    """Redirect to monitoring dashboard"""
    server_ip = app.config['SSH_HOST']
    if server_ip:
        return redirect(f"http://{server_ip}:19999")
    else:
        return "Server IP could not be determined.", 500

# ===================================================================
# WINRM MANAGER (if needed)
# ===================================================================

class WinRMManager:
    """Manages Windows Remote Management connections"""
    def __init__(self):
        self.sessions = {}
    
    def get_session(self, host=None, username=None, password=None, transport=None, force_new=False):
        """Get or create a WinRM session"""
        try:
            import winrm
        except ImportError:
            app.logger.error("WinRM module not installed")
            return None
        
        host = host or app.config.get('WINRM_HOST')
        username = username or app.config.get('WINRM_USERNAME')
        password = password or app.config.get('WINRM_PASSWORD')
        transport = transport or app.config.get('WINRM_TRANSPORT', 'ntlm')
        
        if not all([host, username, password]):
            return None
        
        conn_key = f"{username}@{host}"
        
        if force_new and conn_key in self.sessions:
            try:
                self.sessions[conn_key].close()
            except:
                pass
            del self.sessions[conn_key]
        
        if conn_key not in self.sessions or force_new:
            try:
                session = winrm.Session(
                    host,
                    auth=(username, password),
                    transport=transport,
                    server_cert_validation=app.config.get('WINRM_SERVER_CERT_VALIDATION', 'ignore')
                )
                self.sessions[conn_key] = session
            except Exception as e:
                error_msg = f"WinRM Connection failed to {host}: {str(e)}"
                app.logger.error(error_msg)
                return None
        
        return self.sessions[conn_key]
    
    def close_all(self):
        """Close all WinRM sessions"""
        for conn_key, session in list(self.sessions.items()):
            try:
                session.close()
            except:
                pass
            del self.sessions[conn_key]

winrm_manager = WinRMManager()

# ===================================================================
# MAIN
# ===================================================================

if __name__ == '__main__':
    # Setup logging
    os.makedirs(app.config['LOG_DIR'], exist_ok=True)
    os.makedirs(app.config['QUARANTINE_DIR'], exist_ok=True)
    
    handler = RotatingFileHandler(
        os.path.join(app.config['LOG_DIR'], 'Hermes.log'),
        maxBytes=1000000,
        backupCount=5
    )
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    
    try:
        app.run(host='0.0.0.0', port=5005, debug=True)
    finally:
        ssh_pool.close_all()
