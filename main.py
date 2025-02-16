import subprocess
import sys
import argparse
from scapy.all import *

def create_access_point(interface):
    print(f"Création d'un point d'acces wifi sur l'interface {interface}")
    ssid = "FreeWifi :D"
    password = "test"
    
    # Génération du fichier de configuration hostapd pour WPA (non WPA2)
    hostapd_config = f"""
interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
wpa=1
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
    """.strip()
    
    config_file = "hostapd.conf"
    try:
        with open(config_file, "w") as f:
            f.write(hostapd_config)
        print(f"Configuration hostapd écrite dans {config_file}")
        
        # Démarrage de hostapd avec le fichier de configuration généré
        subprocess.run(["hostapd", config_file], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du démarrage du point d'acces: {e}")
    except Exception as ex:
        print(f"Erreur lors de l'écriture de la configuration: {ex}")
        
    

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
        
    