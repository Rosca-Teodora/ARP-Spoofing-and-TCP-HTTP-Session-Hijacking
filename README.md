
<a name="arpspoof"></a> 
## ARP Spoofing și TCP Hijacking 

Pentru rezolvarea acestor exerciții trebuie să folosiți docker pe linux pentru că nu funcționează iptables și netfilterqueue pe alte sisteme de operare. Dacă nu doriți să folosiți linux, puteți folosi un router real și laptopurile voastre pe post de middle, server și client. Dar va trebui să faceți de mână toate configurațiile.


## Structura containerelor
Partea asta se rezolvă folosind aceeași structură de containere ca în capitolul3. Pentru a construi containerele, rulăm `docker compose up -d`.
Imaginea este construită pe baza fișierul `docker/Dockerfile`, dacă facem modificări în fișier sau în scripturile shell, putem rula `docker-compose build --no-cache` pentru a reconstrui imaginile containerelor.


### Observații
1. E posibil ca tabelel ARP cache ale containerelor `router` și `server` să se updateze mai greu. Ca să nu dureze câteva ore până verificați că funcționează, puteți să le curățați în timp ce sau înainte de a declanșa atacul folosind [comenzi de aici](https://linux-audit.com/how-to-clear-the-arp-cache-on-linux/) `ip -s -s neigh flush all`
2. Orice bucată de cod pe care o luați de pe net trebuie înțeleasă, altfel nu va fi puncată.
3. Atacurile implementante aici au un scop didactic, nu încercați să folosiți aceste metode pentru a ataca alte persoane de pe o rețea locală, puteți fi prinși cu ușurință.



## ARP Spoofing 
[ARP spoofing](https://samsclass.info/124/proj11/P13xN-arpspoof.html) presupune trimiterea unui pachet ARP de tip reply către o țintă pentru a o informa greșit cu privire la adresa MAC pereche pentru un IP. [Aici](https://medium.com/@ismailakkila/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242) și [aici](https://www.youtube.com/watch?v=hI9J_tnNDCc) puteți urmări cum se execută un atac de otrăvire a tabelei cache ARP stocată pe diferite mașini.

Arhitectura containerelor este definită aici, împreună cu schema prin care `middle` îi informează pe `server` și pe `router` cu privire la locația fizică (adresa MAC) unde se găsesc IP-urile celorlalți. 


```
            MIDDLE------------\
        subnet2: 198.7.0.3     \
        MAC: 02:42:c6:0a:00:02  \
               forwarding        \ 
              /                   \
             /                     \
Poison ARP 198.7.0.1 is-at         Poison ARP 198.7.0.2 is-at 
           02:42:c6:0a:00:02         |         02:42:c6:0a:00:02
           /                         |
          /                          |
         /                           |
        /                            |
    SERVER <---------------------> ROUTER <---------------------> CLIENT
net2: 198.7.0.2                      |                           net1: 172.7.0.2
MAC: 02:42:c6:0a:00:03               |                            MAC eth0: 02:42:ac:0a:00:02
                           subnet1:  172.7.0.1
                           MAC eth0: 02:42:ac:0a:00:01
                           subnet2:  198.7.0.1
                           MAC eth1: 02:42:c6:0a:00:01
                           subnet1 <------> subnet2
                                 forwarding
```

Fiecare container execută la secțiunea command în `docker-compose.yml` un shell script prin care se configurează rutele. [Cient](https://github.com/retele-2023/proiect/blob/main/src/client.sh) și [server](https://github.com/retele-2023/proiect/blob/main/src/server.sh) setează ca default gateway pe router (anulând default gateway din docker). 

În plus, adaugă ca nameserver 8.8.8.8, dacă vreți să testați [DNS spoofing](https://networks.hypha.ro/capitolul6/#scapy_dns_spoofing). 

[Middle](https://github.com/retele-2023/proiect/blob/main/src/middle.sh) setează `ip_forwarding=1` și regula: `iptables -t nat -A POSTROUTING -j MASQUERADE` pentru a permite mesajelor care sunt [forwardate de el să iasă din rețeaua locală](https://askubuntu.com/questions/466445/what-is-masquerade-in-the-context-of-iptables). Puteți modifica să nu facă NAT, dacă aveți probleme cu asta.


Rulati procesul de otrăvire a tabelei ARP din diagrama de mai sus pentru containerele `server` și `router` în mod constant, cu un time.sleep de câteva secunde pentru a nu face flood de pachete. (Hint: puteți folosi două [thread-uri](https://realpython.com/intro-to-python-threading/#starting-a-thread) pentru otrăvirea routerului și a serverului).


Pe lângă print-urile și mesajele de logging din programele voastre, rulați în containerul middle: `tcpdump -SntvXX -i any` iar pe `server` faceți un `wget http://old.fmi.unibuc.ro`. Dacă middle este capabil să vadă conținutul HTML din request-ul server-ului, înseamnă că atacul a reușit. Altfel încercați să curățați cache-ul ARP al serverului.







<a name="tcphij"></a> 
## TCP Hijacking 


### Faza 1 (0.5p)

Modificați `tcp_server.py` și `tcp_client.py` din repository `src` și rulați-le pe containerul `server`, respectiv `client` ca să-și trimită în continuu unul altuia mesaje random (generați text sau numere, ce vreți voi). Puteți folosi time.sleep de o secundă/două să nu facă flood. Folosiți soluția de la exercițiul anterior pentru a vă interpune în conversația dintre `client` și `server`.
După ce ați reușit atacul cu ARP spoofing și interceptați toate mesajele, modificați conținutul mesajelor trimise de către client și de către server și inserați voi un mesaj adițional în payload-ul de TCP. Trebuie să funcționeze și atunci când lungimea mesajului se schimbă după ce a fost interceptat.
Dacă atacul a funcționat atât clientul cât și serverul afișează mesajul pe care l-ați inserat. Atacul acesta se numeșete [TCP hijacking](https://www.geeksforgeeks.org/session-hijacking/) pentru că atacatorul devine un [proxy](https://en.wikipedia.org/wiki/Proxy_server) pentru conexiunea TCP dintre client și server.


### Faza 2 (1p)
Dacă atacul a funcționat între client și server, acum trebuie să folosiți acest atac pentru a modifica conținut arbitrar dintr-o pagină HTML cerută de client. Asta presupune următoarele:
1. atacul ARP spoofing este activ
1. clientul cere o pagină HTTP (portul 80), de exemplu http://80.96.21.96/
1. middle interceptează această pagină și înlocuiește imaginea din header (de exemplu [asta](http://80.96.21.96/unibuc_fisiere/header.jpg)) cu o altă imagine, de exemplu [asta](https://haveibeenpwned.com/Images/Hero.svg) sau cu [un hyrax](https://www.reddit.com/r/hyrax/comments/1g2a72n/what_are_your_favorite_hyrax_picturesaccountsmemes/)
1. pentru început, folosiți `wget` pentru a downloada pagina ca să vedeți că atacul funcționează corect
1. pentru un atac complet, trebuie să modificați imaginea folosită de către containerul client să fie acest [firefox](https://hub.docker.com/r/jlesage/firefox)
1. atunci când accesăm pagina de firefox care rulează în container, pe orice link din pagină aș apăsa trebuie să rămână imaginea nouă vizibilă
1. dacă nu vă place site-ul respectiv, căutați altul pe [shodan](https://www.shodan.io/search?query=port%3A80+country%3ARO+http.status%3A200+org%3A%22Universitatea+din+Bucuresti%22&page=4)



### Indicații de rezolvare

1. Puteți urmări exemplul din curs despre [Netfilter Queue](https://networks.hypha.ro/capitolul6/#scapy_nfqueue) pentru a pune mesajele care circulă pe rețeaua voastră într-o coadă ca să le procesați cu scapy. Atenție! netfilterqueu nu va funcționa cu windows sau mac.
1. Urmăriți exemplul [DNS Spoofing](https://networks.hypha.ro/capitolul6/#scapy_dns_spoofing) pentru a vedea cum puteți altera mesajele care urmează a fi redirecționate într-o coadă și pentru a le modifica payload-ul înainte de a le trimite (adică să modificați payload-ul înainte de a apela `packet.accept()`). 
1. Atenție că atunci când modificați lungimea unui pachet, acesta nu va mai fi trimis mai departe cu `accept`, ci va trebui să dați un `send()` nou.
1. Verificați dacă pachetele trimise/primite au flag-ul PUSH setat. Are sens să alterați `SYN` sau `FIN`?
1. Țineți cont de lungimea mesajului pe care îl introduceți pentru ajusta `Sequence Number` (sau `Acknowledgement Number`?), dacă e necesar.
1. Puteți face tot atacul de pe containerul router pentru a testa TCP hijacking apoi puteți combina exercițiul ARP spoofing.
1. La Faza 2 va fi nevoie să interpretați conținutul HTTP ca să vedeți când vine cererea pentru imaginea țintă.
1. Scrieți pe teams orice întrebări aveți, indiferent de cât de simple sau complicate vi se par.
