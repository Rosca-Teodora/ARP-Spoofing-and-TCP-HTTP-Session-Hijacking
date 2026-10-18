# Configurare Arp Spoofing

## Cum se vad efectiv pachetele de middle  

Comenzile de intrare in fiecare serviciu: 
```bash
docker compose --profile tcp up -d # merge si http profile
docker compose exec server bash # router sau middle sau client
```

Din middle: (pt a observa procesul in sine de ARP spoofing)
```bash
tcpdump -SntvXX -i any  
```

Inainte de ARP spoofing un request simplu/ legitim de pe server arata ceva de genul: 
```bash
root@f07f445e178c:/# tcpdump -SntvXX -i any
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
ARP, Ethernet (len 6), IPv4 (len 4), Request who-has 198.7.0.1 tell 198.7.0.2, length 28
	0x0000:  0001 0001 0006 9676 aef4 10ce 0000 0806  .......v........
	0x0010:  0001 0800 0604 0001 9676 aef4 10ce c607  .........v......
	0x0020:  0002 0000 0000 0000 c607 0001            ............
```
asta dupa ce pe server am rulat fix comanda din README.md: ```wget http://old.fmi.unibuc.ro``` (site la care n-am putut intra nici de pe browser :(( ) si am primit mesajul ```Connecting to old.fmi.unibuc.ro (old.fmi.unibuc.ro)|193.226.51.15|:80... failed: Connection refused``` 

Pentru a rula propriu-zis codul de ARP spoofing: 
```bash
# din docker exec-ul service-ului middle
python3 /elocal/src/arp_spoofing.py

# din docker exec-ul service-ului server intr-un alt terminal
# am ales un alt http decat cel din README pentru ca nu mai primea request-uri 
wget http://httpforever.com/

# pt a-l citi se ia cu tpcdump din service-ul middle 
tcpdump -SntvXX -i any
```

# Configurare TCP hijacking 
- [modify packet](https://byt3bl33d3r.github.io/using-nfqueue-with-python-the-right-way.html)
- [injecting code](https://thepythoncode.com/article/injecting-code-to-html-in-a-network-scapy-python)

## Faza 1

Mai intai trebuie sa isi trimita mesaje unul altuia, din containerele respective trebuie rulat: 
```bash
# server
docker compose exec server bash
python3 /elocal/r26bis-da-ne-semnal/src/tcp_server.py 

# client
docker compose exec client bash
python3 /elocal/r26bis-da-ne-semnal/src/tcp_client.py 
```

Pentru a observa (fara a le modifica inca) efectiv mesajele dintre client si server se foloseste fix scriptul anterior (arp_spoofing.py) de pe middle. Dintr-un alt container middle, pt a vedea mesajele tcp (dupa ce pe primul container middle se porneste arp_spoofing.py): 
```bash
tcpdump -SntvXX -i any tcp port 10000
```

Ok dupa ce se vad mesajele ca sunt trimise dintr-o masina in alta e timpul sa poata fi schimbate. Totusi protocolul TCP in acknowledgement pastreaza lungimea pachetelor, atunci cand se modifica un pachet in middleman trebuie de fapt sa se creeze un pachet nou cu scapy si sa fie sters cel primit initial. Netfilterqueue permite fix chestia asta (acceptarea, stergerea(drop) sau modificarea pachetelor)


Iptables = firewall din linux; sunt pastrate toate pachetele din retea si filtrate. Are mai multe moduri de organizare a pachetului (chain): 
* INPUT = cand pachetul este pentru procesele de pe masina
* FORWARD = cand pachetul doar trece prin masina spre alta destinatie
* OUTPUT = cand pachetul a fost facut pe masina 

Default cand construiesti un pachet este OUTPUT, dar in cazul tcp hijacking ului trebuie sa fie date mai departe pachetele (forward): 
```bash
iptables -I FORWARD -p tcp --dport 10000 -j NFQUEUE --queue-num 0
iptables -I FORWARD -p tcp --sport 10000 -j NFQUEUE --queue-num 0
```

Flag-urile: 
```bash
-I FORWARD = regula insertata in lantul forward
-p tcp = aplicat doar pe pachetele tcp
--dport 10000 = portul destinatie 
--sport 10000 = portul sursa 
(in ambele cazuri e portul serverului)
-j NFQUEUEE --queue-num 0 = preluarea propriu-zsia a pachetului catre queue pe pozitia 0 ca sa poata fi modificat
```
Deci extrem de important faptul ca nu i se da accept/drop direct si flag-ul ```-j NFQUEUE --queue-num 0``` il trimite mai departe in coada userspace nr 0!!!


Functionare TCP: 
* tcp numara octeti
* SEQ = sequence number, deci octetii incep de la nr specificat
* ACK = acknowledgement, deci confirma ca a primit tot pana la octetul de la nr specificat si asteapta in continuare

Pentru modificarea lungimii pachetelor trebuie modificate si SEQ ACK pentru ca altfel conexiunea este intrerupta

## Rularea propriu-zisa a fazei 1
Se deschid cele 2 containere server si client in terminale diferite, se ruleaza scriptul de server aferent se ruleaza de pe middle arp_spoofing si dupa tcp_hijack si dupa ruleaza serverul de client. Pt a vedea mesajele se observa de pe un alt exec middle cu tcpdump
Impprtant e ca am pus faza 1 si faza 2 ambele pe acelasi server address deci trebuie specificat inainte de rularea containerelor profilul pe care se face totul: (si serverul si firefox sunt pe 198.7.0.2 dar nu pot functiona simultan asa)
```bash
docker compose --profile tcp up -d
```

Pornirea serverului
```bash
docker compose exec server bash
python3 elocal/r26bis-da-ne-semnal/src/tcp_server.py
```

Pornire si executare arp spoofing repsectiv tcp hijack in terminale separate

```bash
docker compose exec middle bash
python3 elocal/r26bis-da-ne-semnal/src/arp_spoofing.py
python3 elocal/r26bis-da-ne-semnal/src/tcp_hijack.py # din alt terminal de middle
```
Pornirea clientului ca sa inceapa flow ul de mesaje
```bash
docker compose exec client bash
python3 elocal/r26bis-da-ne-semnal/src/tcp_client.py
```

Mai simplu: 
```bash
docker compose --profile tcp up -d
docker compose exec server python3 /elocal/r26bis-da-ne-semnal/src/tcp_server.py     # terminal 1
docker compose exec middle python3 /elocal/r26bis-da-ne-semnal/src/arp_spoofing.py   # terminal 2
docker compose exec middle python3 /elocal/r26bis-da-ne-semnal/src/tcp_hijack.py     # terminal 3
docker compose exec client python3 /elocal/r26bis-da-ne-semnal/src/tcp_client.py     # terminal 4
```

## Faza 2
Faza 2 intial trebuia sa modifice si ea lungimea header ului de imagine dar pana la urma am pastrat-o identic pentru ca ceva (nu stiu ce) pur si simplu chiar nu voia...

Pasi de rulare: 

Pornirea tuturor containerelor:
```bash
docker compose --profile http up -d
```
Aici se booteaza firefoxul pe portul 5800
Trebuie sa ii fie setat default route-ul pentru ca altfel e by default prin docker:  
```bash
docker compose exec firefox sh -c "ip route del default; ip route add default via 198.7.0.1"
```

Faza de ARP spoofing pe middle la fel ca pana acum
```bash
docker compose exec middle bash
python3 elocal/r26bis-da-ne-semnal/src/arp_spoofing.py
```
Si dupa in alt container middle http_hijak.py:  (partea asta serveste imaginea propriu-zis as well)
```bash
docker compose exec middle bash
python3 elocal/r26bis-da-ne-semnal/src/http_hijack.py
```

Speram ca totul merge si deschidem de pe host machine http://localhost:5800 dupa se cauta link-ul efectiv pe care am lucrat: http://80.96.21.96/


Mai simplu: 
```bash
docker compose --profile http up -d
docker compose exec firefox sh -c "ip route del default; ip route add default via 198.7.0.1"
docker compose exec middle python3 /elocal/r26bis-da-ne-semnal/src/arp_spoofing.py   # mereu dupa ce firfox deja merge
docker compose exec middle python3 /elocal/r26bis-da-ne-semnal/src/http_hijack.py
# deschide http://localhost:5800 si cauta http://80.96.21.96/
```

Chestii observate in testing: 
* la recrearea containerului firefox se schimba MAC-ul deci TREBUIE restartat arp_spoofing
* nu ruleaza mai multe http_hijack uri pentru ca sunt binded pe NFQUEUE 0 si portul 80
* mereeeuuu trebuie specificat profilul altfel: ```Traceback (most recent call last):
  File "/elocal/r26bis-da-ne-semnal/src/tcp_client.py", line 19, in <module>
    sock.connect(server_address) # asta e efectiv 3-way handshake-ul 
ConnectionRefusedError: [Errno 111] Connection refused```
* schimbarea profilului se face dupa ce se inchid containerele cu tot cu profilele aferente```docker compose --profile tcp --profile http down``` neaparat

