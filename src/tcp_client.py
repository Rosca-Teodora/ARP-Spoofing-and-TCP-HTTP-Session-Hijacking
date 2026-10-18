# TCP client
import random
import socket
import logging
import time
import sys

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
mesaje = ["ce faci?", "mai cam nimic ma chinuiam sa invat", "poate o sa mearga candva conexiunea", "hai sa jucam uno", "mi-e somn :(", "dada", "nunu", "random", "5biti", "se modifica mesajul?"]

try:
    logging.info('Handshake cu %s', str(server_address))
    sock.connect(server_address) # asta e efectiv 3-way handshake-ul 
    time.sleep(3)
    # se face conexiunea o singura data si dupa se trimit mesajele random 

    while True: 
        index_mesaj = random.randint(0, len(mesaje)-1)
        mesaj = mesaje[index_mesaj]
        sock.send(mesaj.encode('utf-8'))
        logging.info('Se trimite mesajul: "%s"', mesaj)

        data = sock.recv(1024) # primeste inapoi acknowledgement de la server pt mesaj
        if not data:
            logging.info('Nu s-a primit niciun mesaj de la server')
            break

        logging.info('Content primit: "%s"', data)
        time.sleep(4) # time.sleep ul mentionat si in readme pt a preveni flooding

finally:
    logging.info('closing socket')
    sock.close()
