import base64
import collections
import datetime
import json
import os
import random
import socket
import ssl
import threading
import time

import bitcoin
import coreapi
import requests
from bitcoin.core import b2lx, lx
from bitcoin.core.serialize import SerializationTruncationError
from bitcoin.messages import (MsgSerializable, msg_addr, msg_alert,
                              msg_getaddr, msg_getheaders, msg_inv, msg_ping,
                              msg_pong, msg_verack, msg_version)
from bitcoin.net import CAddress, CInv

# Send a ping twice a minute
PING_INTERVAL = 30
# Send some addresses every minute
ADDR_INTERVAL = 60
# Send the latest block hash once every two minutes
INV_INTERVAL = 120

ENABLE_IPV6 = True

MAX_PEERS = 800


BLOCK_TYPE = 2

bitcoin.SelectParams('mainnet')

# This is a really dumb way of doing this, but it forces an IPv4/6 connection
# ipv4 only has an A record, ipv6 only has an AAAA record
print("Getting info on IP addresses")
my_ipv4 = requests.get('https://ipv4.api.useipv6.com/').json()["ip"]
print("My IPv4 address is {}".format(my_ipv4))
my_ipv6 = requests.get('https://ipv6.api.useipv6.com/').json()["ip"] if ENABLE_IPV6 else my_ipv4
print("My IPv6 address is {}".format(my_ipv6))

my_port = 8333

def is_ipv6(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False

def version_pkt(server_ip, server_port, ipv4=True):
    msg = msg_version()
    msg.nVersion = 60002
    msg.addrTo.ip = server_ip
    msg.addrTo.port = server_port
    msg.addrFrom.ip = my_ipv4 if ipv4 else my_ipv6
    msg.addrFrom.port = my_port
    return msg

class SocketFile(socket.socket):
    def read(self, n):
        return self.recv(n)
    def write(self, data):
        return self.send(data)

addresses = []

address_lock = threading.Lock()

class Address:
    def __init__(self, ip, port, services=0x00):
        self.ip = ip
        self.port = port
        self.services = services

    def __eq__(self, other):
        return self.ip == other.ip and self.port == other.port

    def __repr__(self):
        return "{}:{}".format(self.ip, self.port)

def discover_new_addresses(new_addresses):
    global addresses
    new_addr = [Address(address.ip, address.port, address.nServices) for address in new_addresses]
    with address_lock:
        addresses += [addr for addr in new_addr if addr not in addresses]

# Simple way to guess the last block:
# Initiate a circular buffer and push the block hash every time we get a new block
latest_blocks = collections.deque(maxlen=200)
latest_blocks_lock = threading.Lock()

# Add the genesis block to make sure we start with something meaningful
for i in range(100):
    latest_blocks.append(lx("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"))

def guess_latest_block():
    """
    Returns most common block in the last 20 block encountered
    """
    with latest_blocks_lock:
        return max(set(latest_blocks), key=latest_blocks.count)

def append_latest_block(hash_):
    with latest_blocks_lock:
        latest_blocks.append(hash_)

temp_lock = threading.Lock()

pushes = []

# Push new data to server
def push(data):
    with temp_lock:
        pushes.append(data)

class Server(threading.Thread):
    def __init__(self, address, name=None):
        super().__init__()
        self.addr = address

        self.name = name or ""

        self.s = SocketFile(socket.AF_INET6, socket.SOCK_STREAM) if is_ipv6(self.addr.ip) else SocketFile(socket.AF_INET, socket.SOCK_STREAM)

        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        self.s.settimeout(10)

        self.s.bind(("", my_port))

        self.lastping = 0
        self.lastaddr = 0
        self.lastinv = 0

        self._stop_request = threading.Event()

    def stop(self):
        self._stop_request.set()

    def connected(self):
        return self.isAlive()

    def log(self, message):
        print("{}, {}: {}".format(datetime.datetime.now(), self.name, message))

    def run(self):
        try:
            self.s.connect((self.addr.ip, self.addr.port))
            version_pkt(self.addr.ip, self.addr.port).stream_serialize(self.s)
        except Exception as e:
            print(e)
            print("{}, {}: Version handshake failed with {}:{}".format(datetime.datetime.now(), self.name, self.addr.ip, self.addr.port))
            self._stop_request.set()

        # Make sure we dont send an addr or inv straight away
        self.lastaddr = time.time()
        self.lastinv = time.time()

        while not self._stop_request.is_set():
            # Send at most one of these three
            if time.time() - self.lastping > PING_INTERVAL:
                msg_ping(random.getrandbits(64)).stream_serialize(self.s)
                self.lastping = time.time()
            elif time.time() - self.lastaddr > ADDR_INTERVAL:
                out = msg_addr()
                # Grab 10 random addresses
                with address_lock:
                    random_addresses = random.sample(addresses, min(10, len(addresses)))
                for address in random_addresses:
                    caddr = CAddress()
                    # Lie a bit
                    caddr.nTime = int(time.time()) - random.randrange(300)
                    caddr.nServices = address.services
                    caddr.port = address.port
                    caddr.ip = address.ip
                    out.addrs.append(caddr)
                out.stream_serialize(self.s)
                self.lastaddr = time.time()
            elif time.time() - self.lastinv > INV_INTERVAL:
                out = msg_inv()
                out_inv = CInv()
                out_inv.type = BLOCK_TYPE
                out_inv.hash = guess_latest_block()
                out.inv = [out_inv]
                out.stream_serialize(self.s)
                self.lastinv = time.time()
            try:
                msg = MsgSerializable.stream_deserialize(self.s)
                t = time.time()

                if isinstance(msg, msg_version):
                    msg_verack().stream_serialize(self.s)
                elif isinstance(msg, msg_verack):
                    print("{}, {}: Version handshake complete".format(datetime.datetime.now(), self.name))
                elif isinstance(msg, msg_ping):
                    result = push({
                        "me": {
                            "ip": my_ipv4,
                            "port": my_port
                        },
                        "time": t,
                        "type": "ping",
                        "peer": {
                            "ip": self.addr.ip,
                            "port": self.addr.port
                        },
                        "last": {
                            "ping": self.lastping,
                            "inv": self.lastinv,
                            "addr": self.lastaddr
                        },
                        "raw": base64.b64encode(msg.to_bytes()).decode('utf-8'),
                        "data": msg.nonce
                    })
                    msg_pong(nonce=msg.nonce).stream_serialize(self.s)
                elif isinstance(msg, msg_pong):
                    result = push({
                        "me": {
                            "ip": my_ipv4,
                            "port": my_port
                        },
                        "time": t,
                        "type": "pong",
                        "peer": {
                            "ip": self.addr.ip,
                            "port": self.addr.port
                        },
                        "last": {
                            "ping": self.lastping,
                            "inv": self.lastinv,
                            "addr": self.lastaddr
                        },
                        "raw": base64.b64encode(msg.to_bytes()).decode('utf-8'),
                        "data": msg.nonce
                    })
                elif isinstance(msg, msg_getheaders):
                    pass
                elif isinstance(msg, msg_alert):
                    pass
                elif isinstance(msg, msg_inv):
                    if any(item.type == BLOCK_TYPE for item in msg.inv):
                        result = push({
                            "me": {
                                "ip": my_ipv4,
                                "port": my_port
                            },
                            "time": t,
                            "type": "inv",
                            "peer": {
                                "ip": self.addr.ip,
                                "port": self.addr.port
                            },
                            "last": {
                                "ping": self.lastping,
                                "inv": self.lastinv,
                                "addr": self.lastaddr
                            },
                            "raw": base64.b64encode(msg.to_bytes()).decode('utf-8'),
                            "data": [
                                {
                                    "type": "block" if item.type == BLOCK_TYPE else "tx",
                                    "hash": b2lx(item.hash)
                                } for item in msg.inv
                            ]
                        })
                    for inv in msg.inv:
                        if inv.type == BLOCK_TYPE:
                            append_latest_block(inv.hash)
                elif isinstance(msg, msg_addr):
                    discover_new_addresses(msg.addrs)
                else:
                    print("{}, {}: Unhandled message type: {}".format(datetime.datetime.now(), self.name, msg.command.decode('utf-8')))
            except socket.timeout:
                continue
            except SerializationTruncationError:
                print("{}, {}: **************** Socket closed. ****************".format(datetime.datetime.now(), self.name))
                break
        self.s.close()
        print("{}, {}: Stopped.".format(datetime.datetime.now(), self.name))

class Pusher(threading.Thread):
    def __init__(self, name=None):
        super().__init__()
        self.name = name or ""

        self._stop_request = threading.Event()

    def stop(self):
        self._stop_request.set()

    def connected(self):
        return self.isAlive()

    def log(self, message):
        print("{}, {}: {}".format(datetime.datetime.now(), self.name, message))

    def run(self):
        while not self._stop_request.is_set():
            try:
                data = []
                with temp_lock:
                    global pushes
                    if len(pushes) > 2000:
                        data = pushes
                        pushes = []

                if len(data) > 0:
                    if not os.path.exists('dumps'):
                        os.makedirs('dumps')
                    with open("dumps/{}.dump".format(time.time()), "w") as f:
                        f.write("\n".join([json.dumps(d) for d in data]))


            except:
                self.log("Uhh-oh, excepted")

            # Wait a bit
            time.sleep(1)

# Some good seed addresses from bitcoin.sipa.be
addresses = [Address("47.88.57.29", 8333), Address("116.126.142.195", 8333), Address("45.55.234.179", 8333), Address("159.203.67.157", 8333), Address("45.76.233.215", 8333), Address("188.166.249.143", 8333), Address("113.29.183.143", 8333), Address("104.207.132.42", 8333), Address("159.203.122.25", 8333), Address("207.154.210.67", 8333), Address("107.191.60.255", 8333), Address("34.231.234.150", 8333), Address("159.203.241.242", 8333), Address("67.210.228.203", 8333), Address("62.112.10.75", 8333), Address("178.62.34.210", 8333), Address("47.52.232.80", 8333), Address("64.79.88.125", 8333), Address("217.23.14.74", 8333), Address("52.51.118.175", 8333), Address("192.175.59.140", 8333), Address("47.89.48.243", 8333), Address("88.99.2.99", 9001), Address("54.234.19.60", 48333), Address("37.48.124.83", 8333), Address("128.199.50.89", 8333), Address("47.153.42.24", 8333), Address("94.23.250.222", 9443), Address("159.203.177.227", 8333), Address("78.47.108.156", 8333), Address("88.99.64.76", 8333), Address("195.154.223.131", 8333), Address("93.190.142.127", 8333), Address("51.254.44.148", 8333), Address("62.138.3.214", 6666), Address("46.105.102.36", 8333), Address("47.91.74.77", 8333), Address("148.251.82.174", 8333), Address("88.99.107.117", 8333), Address("173.212.247.250", 8333), Address("95.211.189.3", 8333), Address("89.36.223.97", 8333), Address("54.154.44.169", 8333), Address("158.69.24.124", 8333), Address("5.189.134.4", 8333), Address("188.138.112.60", 8333), Address("195.154.176.135", 8333), Address("40.114.88.206", 8333), Address("185.25.48.184", 8333), Address("92.222.89.170", 8333), Address("5.9.11.209", 8333), Address("217.64.47.138", 8333), Address("45.59.68.75", 8333), Address("192.3.11.24", 8333), Address("23.239.5.226", 8333), Address("13.228.237.222", 8333), Address("52.23.242.147", 8333), Address("46.4.101.162", 8333), Address("174.138.35.229", 8333), Address("94.23.250.222", 9445), Address("37.187.152.121", 8333), Address("144.76.136.19", 8333), Address("194.14.246.86", 8333), Address("82.221.105.202", 8333), Address("159.89.16.222", 8333), Address("95.211.214.31", 8333), Address("62.75.210.81", 8333), Address("88.99.146.100", 8333), Address("138.68.20.197", 8333), Address("52.90.118.201", 8333), Address("144.76.175.139", 8333), Address("138.68.117.247", 8333), Address("52.203.228.89", 8333), Address("178.62.242.100", 8333), Address("45.32.170.30", 8333), Address("138.201.50.84", 8333), Address("178.62.73.148", 8333), Address("13.231.20.249", 8333), Address("91.134.232.205", 8333), Address("139.162.238.40", 8333), Address("176.9.46.231", 12121), Address("88.99.186.22", 8333), Address("78.47.61.83", 8333), Address("198.211.102.227", 8333), Address("107.182.230.230", 8333), Address("148.251.191.74", 8333), Address("35.165.198.33", 8333), Address("162.255.117.213", 8333), Address("46.4.101.137", 8333), Address("194.14.246.85", 8333), Address("45.59.68.76", 8333), Address("188.226.202.220", 8333), Address("88.86.125.50", 8333), Address("88.99.139.98", 8333), Address("165.227.34.56", 8333), Address("47.91.77.119", 8333), Address("176.9.46.231", 10000), Address("92.222.180.15", 8333), Address("88.99.187.210", 8333), Address("46.166.148.218", 8333), Address("213.239.212.246", 6666), Address("151.80.21.57", 8333), Address("138.201.30.201", 8333), Address("52.208.102.52", 8338), Address("94.130.229.41", 8333), Address("54.87.203.198", 8338), Address("13.115.219.176", 8338), Address("52.87.232.209", 8338), Address("82.165.23.226", 8333), Address("65.49.51.61", 8333), Address("185.22.235.115", 38333), Address("212.47.166.152", 8333), Address("172.110.8.233", 8333), Address("34.235.48.110", 8333), Address("138.68.15.191", 8333), Address("138.201.51.131", 8333), Address("38.102.134.85", 8333), Address("213.222.208.234", 9333), Address("52.68.50.5", 8338), Address("178.63.94.143", 9199), Address("62.152.58.16", 9421), Address("52.50.215.208", 8338), Address("51.255.85.180", 8333), Address("54.169.173.154", 8333), Address("46.101.133.247", 8333), Address("94.130.222.201", 9354), Address("66.180.64.95", 8333), Address("13.229.134.39", 8333), Address("35.176.123.96", 8338), Address("82.197.211.136", 8333), Address("18.195.194.174", 8338), Address("13.90.157.16", 8333), Address("149.202.83.78", 8333), Address("138.201.33.232", 8333), Address("143.208.11.7", 8333), Address("104.196.214.158", 8333), Address("92.222.180.14", 8333), Address("204.9.50.25", 8333), Address("144.76.108.6", 8444), Address("91.222.128.59", 8333), Address("158.109.79.13", 34821), Address("5.189.165.102", 8333), Address("45.58.49.35", 8333), Address("52.58.201.62", 8338), Address("18.196.79.108", 8333), Address("74.114.121.104", 8312), Address("96.95.112.237", 8333), Address("89.22.96.132", 8333), Address("138.197.109.21", 8333), Address("78.46.78.206", 8333), Address("212.24.108.3", 8333), Address("163.172.171.119", 8333), Address("91.121.75.30", 8333), Address("47.88.192.215", 8333), Address("139.162.160.232", 8333), Address("195.201.60.246", 8333), Address("185.28.76.179", 8333), Address("98.127.130.17", 8333), Address("188.65.212.138", 8333), Address("87.79.68.86", 8333), Address("46.166.139.42", 8333), Address("178.239.61.212", 8333), Address("86.87.200.41", 8333), Address("207.154.247.235", 8333), Address("87.233.181.146", 8333), Address("195.154.164.243", 8333), Address("188.40.73.130", 8333), Address("82.102.10.251", 8333), Address("2a01:4f8:c0c:d1b::2", 8333), Address("2001:41d0:8:d844:1337::1017", 8333), Address("fd87:d87e:eb43:92f3:5cd0:3082:89af:295d", 8333), Address("2a02:c207:2018:4790::1", 8333), Address("2001:470:5:41e::3001", 8333), Address("2001::9d38:90d7:3080:202:d0b4:43aa", 8333)]

peers = []

info_freq = 20
info_c = 0

pushers = []
max_pushers = 2


# Main loop
while True:
    try:
        # Forget about unconnected peers
        peers = [peer for peer in peers if peer.connected()]
        # Check which addresses we are connected to
        connected_addresses = [peer.addr for peer in peers]
        unconnected_addresses = [address for address in addresses if address not in connected_addresses]

        # If we have more addresses and haven't hit max peers, randomly pick a new peer
        if len(peers) < MAX_PEERS and len(unconnected_addresses) > 0:
            new_address = random.choice(unconnected_addresses)
            new_peer = Server(new_address, "peer ({})".format(str(new_address)))
            new_peer.start()
            peers.append(new_peer)
            print("{}: Connecting to new peer {}".format(datetime.datetime.now(), str(new_address)))

        pushers = [pusher for pusher in pushers if pusher.connected()]
        if len(pushers) < max_pushers:
            print("{}: Spawning new pusher. ".format(datetime.datetime.now()))
            pusher = Pusher("Pusher {}".format(datetime.datetime.now()))
            pusher.start()
            pushers.append(pusher)

        info_c += 1
        if info_c % info_freq == 0:
            print("{}: Currently connected to {} nodes, have {} addresses, and {} jobs.".format(datetime.datetime.now(), len(peers), len(addresses), len(pushes)))
    except:
        print("{}: Uhhoh, excepted".format(datetime.datetime.now()))

    # Wait a bit
    time.sleep(0.1)
