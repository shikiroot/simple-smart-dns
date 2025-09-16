#!/usr/bin/env python3

import socket
import ipaddress
import requests
import time
from dnslib import DNSRecord, QTYPE, DNSQuestion
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53
CHINA_DNS = "223.5.5.5"
FOREIGN_DNS = "8.8.8.8"
CHINA_IP_LIST_URL = "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt"
MAX_PACKET_SIZE = 1024
TIMEOUT = 1
CACHE_SIZE = 2000
CACHE_TTL = 600


class LRUCache:
    def __init__(self, capacity):
        self.cache = OrderedDict()
        self.capacity = capacity

    def get(self, key):
        if key in self.cache:
            value, expire = self.cache.pop(key)
            if time.time() < expire:
                self.cache[key] = (value, expire)
                return value
        return None

    def put(self, key, value, ttl=CACHE_TTL):
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.capacity:
            self.cache.popitem(last=False)
        self.cache[key] = (value, time.time() + ttl)


def get_china_ip_list():
    try:
        r = requests.get(CHINA_IP_LIST_URL, timeout=30)
        return [ipaddress.ip_network(line.strip()) for line in r.text.splitlines() if line.strip()]
    except:
        return []


def is_china_ip(ip, networks):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in networks)
    except:
        return False


def query_dns(domain, server, qtype):
    record = DNSRecord()
    record.add_question(DNSQuestion(domain, getattr(QTYPE, qtype)))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(record.pack(), (server, 53))
        reply, _ = sock.recvfrom(MAX_PACKET_SIZE)
        return DNSRecord.parse(reply)
    except:
        return None
    finally:
        sock.close()


class DNSServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LISTEN_IP, LISTEN_PORT))
        self.networks = get_china_ip_list()
        self.cache = LRUCache(CACHE_SIZE)

    def handle(self, data, addr):
        try:
            req = DNSRecord.parse(data)
            qname = str(req.q.qname)
            qtype = QTYPE[req.q.qtype]
            key = f"{qname}:{qtype}"

            resp = self.cache.get(key)
            if not resp:
                with ThreadPoolExecutor(max_workers=2) as ex:
                    f1 = ex.submit(query_dns, qname, CHINA_DNS, qtype)
                    f2 = ex.submit(query_dns, qname, FOREIGN_DNS, qtype)
                    cn, foreign = f1.result(), f2.result()

                resp = foreign or cn
                if qtype == "A" and cn and foreign:
                    cn_ips = [str(rr.rdata) for rr in cn.rr if rr.rtype == QTYPE.A]
                    if any(is_china_ip(ip, self.networks) for ip in cn_ips):
                        resp = cn

                if resp:
                    self.cache.put(key, resp)

            if resp:
                resp.header.id = req.header.id
                self.sock.sendto(resp.pack(), addr)
        except:
            pass

    def run(self):
        print(f"DNS server listening on {LISTEN_IP}:{LISTEN_PORT}")
        while True:
            data, addr = self.sock.recvfrom(MAX_PACKET_SIZE)
            self.handle(data, addr)


if __name__ == "__main__":
    DNSServer().run()
