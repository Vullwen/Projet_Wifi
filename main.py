import subprocess
import sys
import argparse
from scapy.all import *

def create_access_point(interface):
    print(f"Création d'un point d'accès WiFi sur l'interface {interface}")
    ssid = "FreeWifi :D"
    password = "test"
    
    # Création du fichier de configuration hostapd pour WPA2
    hostapd_conf = f"""
    interface={interface}
    driver=nl80211
    ssid={ssid}
    hw_mode=g
    channel=6
    wmm_enabled=1
    macaddr_acl=0
    auth_algs=1
    ignore_broadcast_ssid=0
    wpa=2
    wpa_passphrase={password}
    wpa_key_mgmt=WPA-PSK
    wpa_pairwise=TKIP
    rsn_pairwise=CCMP
        """
    
    config_file = "/tmp/hostapd.conf"
    try:
        with open(config_file, "w") as f:
            f.write(hostapd_conf)
        print(f"Fichier de configuration créé: {config_file}")
    except Exception as e:
        print(f"Erreur lors de la création du fichier de configuration: {e}")
        return
    
    # Configuration de l'interface réseau
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", interface], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        print(f"Interface {interface} configurée avec l'adresse 10.0.0.1/24")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la configuration de l'interface: {e}")
        return
    
    # Démarrage de hostapd avec le fichier de configuration
    try:
        print("Démarrage de hostapd avec WPA2...")
        subprocess.run(["hostapd", config_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du démarrage de hostapd: {e}")

        
    

def capture_packets():
    print("Capture de paquets")

def modify_packets(packets):
    print(f"Modification de {len(packets)} paquets")

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
        capture_packets()
    
    if args.redirect:
        redirect_requests()
        
        
if __name__ == "__main__":
    main()
        
    