# TCP Server
import socket
import logging
import time
import random

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

# definire socket cu protocol tcp
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # lasa serverul sa refoloseasca adresa pt ca tot primeam eroarea: OSError: [Errno 98] Address already in use 

# adresa si portul pe care asculta server ul
port = 10000
adresa = '0.0.0.0'
server_address = (adresa, port)
raspunsuri = ["destul de ok", "tu?", "stiu cum e", "da sincer hai un uno", "dragut!", "si mie mi-e somn o fi de la vreme?", "raspuns", "ceva cuvant", "5biti"]

sock.bind(server_address) # unde asculta efectiv server-ul = adresa '0.0.0.0' protul 10000
logging.info("Serverul a pornit pe %s si portnul portul %d", adresa, port)
sock.listen(5) # primeste max 5 conexiuni

while True: # loop-ul asta primeste conexiuni noi 
    logging.info('Asteptam conexiui...')
    conexiune, address = sock.accept()
    logging.info("Handshake cu %s", address)
    time.sleep(2) 

    try: 
        while True: 
            data = conexiune.recv(1024) # ce date primeste de la client
            if not data: # tb verificat daca inca mai trimite clientul mesaje, altfel se inchide conexiunea cu el
                logging.info('Se inchide conexiunea')
                break
            logging.info('Content primit: "%s"', data)

            index_raspuns = random.randint(0, len(raspunsuri)-1)
            raspuns = raspunsuri[index_raspuns]
            conexiune.send(b"Server a primit mesajul: " + data + b" si raspunde: " + raspuns.encode('utf-8'))
            time.sleep(2)
    finally:
        conexiune.close()
