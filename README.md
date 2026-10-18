<a name="top"></a>
# ARP Spoofing and TCP/HTTP Session Hijacking

A controlled laboratory exercise in man-in-the-middle (MITM) network attacks, implemented for educational and defensive research purposes only. The project reconstructs, in a fully isolated Docker topology, the two classic phases of an attack against a local area network:

1. **ARP cache poisoning**: redirects layer 2 traffic so that an attacker host is inserted on the path between the two victims
2. **TCP and HTTP session hijacking**: intercepting, rewriting, and reinjecting the application payloads that flow across the poisoned path

**NOTE:** Every technique here is demonstrated against containers I own, on private bridge networks that never touch production infrastructure. The attacks are illustrative and mustn't be used against hosts or networks for which you lack explicit authorization. Unauthorized interception of network traffic is illegal.

---

## Table of Contents

- [ARP Spoofing and TCP/HTTP Session Hijacking](#arp-spoofing-and-tcphttp-session-hijacking)
  - [Table of Contents](#table-of-contents)
  - [Development Environment](#development-environment)
  - [How does it work?](#how-does-it-work)
    - [Address Resolution Protocol (ARP)](#address-resolution-protocol-arp)
    - [IP Forwarding \& NAT](#ip-forwarding--nat)
    - [TCP as a Byte Stream](#tcp-as-a-byte-stream)
    - [Netfilter, `iptables` Chains, and NFQUEUE](#netfilter-iptables-chains-and-nfqueue)
  - [Network Topology](#network-topology)
  - [Repository Layout](#repository-layout)
  - [Configuration](#configuration)
  - [Build \& Run](#build--run)
    - [Phase 0 — ARP Poisoning Only](#phase-0--arp-poisoning-only)
    - [Phase 1 — TCP Payload Hijacking](#phase-1--tcp-payload-hijacking)
    - [Phase 2 — HTTP Content Injection](#phase-2--http-content-injection)
  - [Observed Behaviour and Troubleshooting](#observed-behaviour-and-troubleshooting)
  - [References](#references)

---

<a name="environment"></a>
## Development Environment

This project was designed and developed **exclusively on a UNIX-based operating system** (specifically Linux Mint) and depends on kernel level networking dependencies that are unavailable or behave weirdly on Windows and macOS.

The hard dependencies are:

- **`iptables`**: the Linux packet filtering framework (built on Netfilter). The hijacking stage installs `FORWARD` and `raw` table rules dynamically
- **`libnetfilter_queue` / `python-netfilterqueue`**: the userspace library that lets a Python process pull packets out of the kernel, mutate them, and reinject them. This is a subsystem for Linux only 
- **The Linux networking stack**, driven through standard UNIX utilities: `ip` (iproute2), `tcpdump`, `wget`, `sysctl`, and `bash`.

Because `iptables` and `netfilterqueue` have no functional equivalent on other platforms, the entire laboratory is encapsulated in **Docker containers running a Linux base image**, so that it can be reproduced on any UNIX host with a working Docker Engine. If Docker is not an option, the same topology can in principle be rebuilt with a physical router and three laptops (attacker / server / client), at the cost of performing every route and ARP configuration by hand.

The following UNIX commands recur throughout the workflow and are worth internalizing:

| Command | Role in this project |
|---------|----------------------|
| `ip route {add,del} …` | Override each container's default gateway so traffic is forced through the router. |
| `ip -s -s neigh flush all` | Flush the ARP neighbour cache to accelerate convergence during testing. |
| `sysctl -w net.ipv4.ip_forward=1` | Enable kernel IP forwarding on the attacker so intercepted packets are relayed. |
| `tcpdump -SntvXX -i any` | Capture and inspect raw frames to confirm the attacker is on-path. |
| `iptables -I FORWARD … -j NFQUEUE --queue-num 0` | Divert forwarded packets into a userspace queue for rewriting. |
| `wget http://…` | Generate legitimate client traffic to drive the attack. |

---

<a name="concepts"></a>
## How does it work? 

### Address Resolution Protocol (ARP)
ARP maps an IPv4 address to the MAC (hardware) address that owns it on a local segment. It is stateless and unauthenticated: a host accepts an unsolicited `ARP reply` ("`198.7.0.1 is-at 02:42:…`") and overwrites its cache accordingly. **ARP spoofing** abuses this by continuously sending forged replies to two victims, each claiming that the *other's* IP lives at the **attacker's** MAC. Both victims then transmit to the attacker, who forwards the frames — placing itself invisibly on the path.

### IP Forwarding & NAT
For the MITM to be transparent, the attacker must relay what it intercepts. `net.ipv4.ip_forward=1` instructs the kernel to route packets between interfaces instead of dropping those not addressed to it. Crucially, forwarded MITM traffic **must retain its original source IP** so that each victim still believes it is talking to the other; `MASQUERADE` (source NAT) is therefore applied *only* to traffic originating on the attacker itself, never to forwarded flows.

### TCP as a Byte Stream
TCP numbers **bytes**, not packets. The **Sequence Number (SEQ)** marks the offset of the first byte in a segment; the **Acknowledgement Number (ACK)** confirms every byte received up to that point. If an on-path attacker **changes the length** of a payload, every subsequent SEQ/ACK the endpoints exchange becomes inconsistent and the connection stalls or resets. The hijack therefore maintains, per connection and per direction, a running **byte offset** and rewrites SEQ/ACK on every segment to keep both endpoints synchronized. Control segments (`SYN` without `ACK`, `RST`) carry no data and are passed through untouched.

### Netfilter, `iptables` Chains, and NFQUEUE
`iptables` organizes packets into **chains** by their journey through the host:

- **INPUT** — destined for a local process,
- **OUTPUT** — generated by a local process,
- **FORWARD** — merely transiting the host toward another destination.

Intercepted MITM traffic lives in **FORWARD**. The rule `-j NFQUEUE --queue-num 0` does *not* accept or drop a packet; it hands the packet to **userspace queue 0**, where the Python callback may `accept()`, `drop()`, or rewrite-and-reinject it. When a packet's length changes it cannot simply be `accept()`-ed — the original is `drop()`-ped and a freshly built Scapy packet is `send()`-t in its place. A `raw`-table `NOTRACK` rule is applied to the hijacked port so that Linux **connection tracking (conntrack)** does not treat the dropped original and the reinjected replacement as two conflicting flows and invalidate them.

---

<a name="topology"></a>
## Network Topology

Four services span two bridge subnets. The **router** is dual-homed and bridges `subnet1` (clients) to `subnet2` (servers); **middle** is the attacker, co-located with the server on `subnet2`. The arrows show how `middle` poisons both the `server` and the `router` so that each believes the other resides at `middle`'s MAC address.

Note: I am aware the attacker is theoretically interposed between router and client, however I started the project with this topology and decided it had the same implementation methods and therefore had no need to change it at a later development state. 

```
            MIDDLE------------\        (attacker / man-in-the-middle)
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

Each container runs a bootstrap shell script (declared under `command:` / init hooks) that fixes its routing:

- **`client.sh` / `server.sh`** remove Docker's default gateway and set the **router** as the default gateway, then add `8.8.8.8` as a nameserver (useful if extending the exercise toward DNS spoofing).
- **`router.sh`** enables forwarding between the two subnets and masquerades egress traffic.
- **`middle.sh`** enables `ip_forward` and installs `iptables -t nat -A POSTROUTING … -j MASQUERADE` scoped so that forwarded MITM traffic keeps its original source address.
- **`firefox-init.sh`** (Phase 2) forces the browser container's default route through the router, since its Alpine base would otherwise egress straight through the Docker bridge and bypass the attacker.

Because the `server` and the `firefox` victim both occupy `198.7.0.2`, they are placed on **mutually exclusive Docker Compose profiles** (`tcp` and `http`) and are never run simultaneously.

---

<a name="layout"></a>
## Repository Layout

```
.
├── docker-compose.yml          # four-service topology, two subnets, tcp/http profiles
├── docker/Dockerfile           # Linux image + iptables, iproute2, libnetfilter-queue, scapy
├── src/
│   ├── arp_spoofing.py         # ARP cache poisoning (dual-threaded, with network restore)
│   ├── tcp_hijack.py           # Phase 1: length-changing TCP payload rewrite via NFQUEUE
│   ├── http_hijack.py          # Phase 2: length-preserving HTTP image injection + image server
│   ├── tcp_server.py           # demo TCP server (port 10000)
│   ├── tcp_client.py           # demo TCP client
│   ├── client.sh / server.sh   # per-container routing bootstrap
│   ├── router.sh / middle.sh   # forwarding + NAT bootstrap
│   └── firefox-init.sh         # forces the browser victim's route through the router
└── www/                        # replacement image served by the HTTP hijack
```

---

<a name="configuration"></a>
## Configuration

| Parameter | Value | Where |
|-----------|-------|-------|
| Client subnet (`net1`) | `172.7.0.0/16`, gateway `172.7.1.1` | `docker-compose.yml` |
| Server subnet (`net2`) | `198.7.0.0/16`, gateway `198.7.1.1` | `docker-compose.yml` |
| Router addresses | `172.7.0.1` (net1), `198.7.0.1` (net2) | `docker-compose.yml` |
| Server / Firefox victim | `198.7.0.2` | `docker-compose.yml` |
| Attacker (`middle`) | `198.7.0.3` | `docker-compose.yml` |
| Client | `172.7.0.2` | `docker-compose.yml` |
| ARP poison targets | gateway `198.7.0.1`, target `198.7.0.2` | `arp_spoofing.py` |
| TCP demo port | `10000` | `tcp_hijack.py`, `tcp_server.py` |
| HTTP port | `80` | `http_hijack.py` |
| Original image path | `unibuc_fisiere/header.jpg` | `http_hijack.py` |
| Replacement image URL | `http://198.7.0.3/hyra.jpg` | `http_hijack.py` |

Containers are granted `NET_ADMIN`, `NET_RAW`, and `SYS_ADMIN` capabilities (and `privileged` on the server) so that they may manipulate `iptables` rules and craft raw packets. These privileges are the reason the lab must stay inside a disposable, isolated environment.

**Note on the HTTP injection constraint.** The replacement image URL is deliberately chosen to be the **same byte length** as the original (`http://198.7.0.3/hyra.jpg` vs. `unibuc_fisiere/header.jpg`). Phase 2 rewrites the payload *in place* (`set_payload`) rather than resizing it, which keeps SEQ/ACK untouched and sidesteps the stream-reconstruction complexity required in Phase 1. The code enforces this with an `assert` on both the image string and the `Accept-Encoding` header rewrite.

---

<a name="run"></a>
## Build & Run

**Prerequisites:** a UNIX/Linux host with Docker Engine and the Docker Compose plugin.

Build the images (rebuild with `--no-cache` after editing the Dockerfile or any bootstrap script):

```bash
docker compose build            # or: docker compose build --no-cache
```

The `router` and `middle` services carry no profile and start in every phase; `server`/`client` (profile `tcp`) and `firefox` (profile `http`) are selected per phase. **Always tear a profile down before switching:**

```bash
docker compose --profile tcp --profile http down
```

---

<a name="phase0"></a>
### Phase 0 — ARP Poisoning Only

Confirm that `middle` can place itself on-path before touching payloads.

```bash
docker compose --profile tcp up -d
docker compose exec middle bash

# On middle, run the poisoner:
python3 /elocal/src/arp_spoofing.py
```

In a second shell, generate legitimate traffic from the server and watch it surface on the attacker:

```bash
# On the server:
docker compose exec server wget http://httpforever.com/

# On another middle shell:
tcpdump -SntvXX -i any
```

If `middle` can see the server's HTTP request contents, poisoning succeeded. `arp_spoofing.py` runs two threads — one poisoning the router, one the server — sleeping a couple of seconds between forged replies to avoid flooding. On `Ctrl-C` it **restores** the network by broadcasting the correct MAC/IP bindings and disabling IP forwarding.

---

<a name="phase1"></a>
### Phase 1 — TCP Payload Hijacking

The demo client and server exchange random text messages over TCP port `10000`. With ARP poisoning active, `tcp_hijack.py` pulls every segment into NFQUEUE, **rewrites the payload (changing its length)**, and corrects SEQ/ACK in both directions so neither endpoint notices the stream was altered. A successful run shows injected markers appearing in both the client's and the server's logs.

Four shells (startup order matters — the server must be listening, the attacker on-path, then the client connects):

```bash
docker compose --profile tcp up -d
docker compose exec server python3 /elocal/src/tcp_server.py     # terminal 1
docker compose exec middle python3 /elocal/src/arp_spoofing.py   # terminal 2
docker compose exec middle python3 /elocal/src/tcp_hijack.py     # terminal 3
docker compose exec client python3 /elocal/src/tcp_client.py     # terminal 4
```

Optionally inspect the rewritten stream from a fifth `middle` shell:

```bash
tcpdump -SntvXX -i any tcp port 10000
```

---

<a name="phase2"></a>
### Phase 2 — HTTP Content Injection

Replace an image inside a live web page as it is delivered to a real browser. `http_hijack.py` both (a) serves the replacement image from `middle` over a small built-in HTTP server and (b) rewrites forwarded HTTP traffic: it breaks the client's `Accept-Encoding` header (forcing an uncompressed, rewritable response) and swaps the target image path for its own — all **length-preserving**.

```bash
docker compose --profile http up -d

# Force the browser victim's default route through the router:
docker compose exec firefox sh -c "ip route del default; ip route add default via 198.7.0.1"

docker compose exec middle python3 /elocal/src/arp_spoofing.py   # always after firefox is up
docker compose exec middle python3 /elocal/src/http_hijack.py
```

Then, from the host, open **http://localhost:5800** (the Firefox container's UI on port `5800`) and browse to the target page, e.g. **http://80.96.21.96/**. The header image is replaced on the fly.

---

<a name="troubleshooting"></a>
## Observed Behaviour and Troubleshooting

- **Slow ARP convergence.** The `router` and `server` caches may take a long time to update. Flush them before or during the attack:
  ```bash
  ip -s -s neigh flush all
  ```
- **Recreating the Firefox container changes its MAC** — you **must restart** `arp_spoofing.py` afterwards, or poisoning will target a stale MAC.
- **Only one hijack at a time.** `http_hijack.py` binds NFQUEUE 0 and port 80; a second instance cannot start.
- **`ConnectionRefusedError: [Errno 111]`** from the client almost always means the wrong Compose profile is active — the server isn't up. Bring the correct profile up first.
- **Switching profiles** requires a full teardown of all active profiles (`docker compose --profile tcp --profile http down`) before bringing the other up, because `server` and `firefox` share `198.7.0.2`.
- **Connection resets.** The bootstrap scripts install `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP` so the kernel's own RST does not kill the hand-crafted TCP flows.
- Any public site used for Phase 2 may change or go offline; alternative Romanian university hosts on port 80 can be discovered via Shodan.

---

<a name="references"></a>
## References

- ARP cache poisoning with Scapy: <https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242>
- Using NFQUEUE with Python the right way: <https://byt3bl33d3r.github.io/using-nfqueue-with-python-the-right-way.html>
- Injecting code into HTML on a network with Scapy: <https://thepythoncode.com/article/injecting-code-to-html-in-a-network-scapy-python>
- Netfilter Queue & DNS spoofing examples: <https://networks.hypha.ro/capitolul6/>
- Clearing the ARP cache on Linux: <https://linux-audit.com/how-to-clear-the-arp-cache-on-linux/>
- Session hijacking overview: <https://www.geeksforgeeks.org/session-hijacking/>

