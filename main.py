import subprocess
import sys
import argparse
from scapy.all import *

def create_access_point(interface):
    print(f"Création d'un point d'acces wifi sur l'interface {interface}")
    try:
        sender_mac = RandMAC()
        ssid = "FreeWifi :D" 
        # 802.11 frame
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
        # beacon layer
        beacon = Dot11Beacon()
        # putting ssid in the frame
        essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
        # stack all the layers and add a RadioTap
        frame = RadioTap()/dot11/beacon/essid
        # send the frame in layer 2 every 100 milliseconds forever
        # using the `iface` interface
        sendp(frame, inter=0.1, iface=interface, loop=1)
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du démarrage du point d'acces: {e}")
        
    

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
        print(f"Création d'un point d'acces wifi sur l'interface {args.interface}")
        create_access_point(args.interface)
    
    if args.capture:
        capture_packets()
    
    if args.redirect:
        redirect_requests()
        
        
if __name__ == "__main__":
    main()
        
    