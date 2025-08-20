#!/usr/bin/env python3

import socket
import ipaddress
import os
import time
import requests
import signal
from threading import Lock, Event
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, AAAA, DNSQuestion

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53
CHINA_DNS = "223.5.5.5"
FOREIGN_DNS = "8.8.8.8"
FALLBACK_DNS = ["8.8.4.4", "1.1.1.1"]
CHINA_IP_LIST_URL = (
    "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt"
)
CHINA_IP_CACHE_FILE = "/tmp/.china_ip_list.txt"
CACHE_DURATION = 24 * 60 * 60
TIMEOUT = 3
DNS_CACHE_SIZE = 5000
IP_CACHE_SIZE = 2000
MAX_THREADS = 30


class SimpleCache:
    def __init__(self, capacity):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.lock = Lock()

    def get(self, key):
        with self.lock:
            if key in self.cache:
                value, timestamp = self.cache.pop(key)
                if time.time() < timestamp:
                    self.cache[key] = (value, timestamp)
                    return value
                del self.cache[key]
        return None

    def put(self, key, value, ttl=1800):
        with self.lock:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)
            self.cache[key] = (value, time.time() + ttl)


class NetworkMatcher:
    def __init__(self):
        self.ipv4_networks = []
        self.lock = Lock()

    def add_networks(self, ipv4_list):
        with self.lock:
            self.ipv4_networks = [ipaddress.ip_network(net) for net in ipv4_list]
            self.ipv4_networks.sort(key=lambda x: x.network_address)

    def is_china_ip(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version != 4:
                return False

            for network in self.ipv4_networks:
                if ip_obj in network:
                    return True
                if ip_obj < network.network_address:
                    break
            return False
        except:
            return False


class SmartDNSServer:
    def __init__(self):
        self.shutdown_event = Event()
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_THREADS)
        self.network_matcher = NetworkMatcher()
        self.dns_cache = SimpleCache(DNS_CACHE_SIZE)
        self.ip_cache = SimpleCache(IP_CACHE_SIZE)
        self.udp_sock = None

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print(f"Received signal {signum}, shutting down...")
        self.shutdown_event.set()

    def _read_china_ip_file(self, cache_file):
        try:
            with open(cache_file, "r") as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except:
            return []

    def get_china_ip_list(self):
        cache_file = CHINA_IP_CACHE_FILE

        if os.path.exists(cache_file):
            if time.time() - os.path.getmtime(cache_file) < CACHE_DURATION:
                return self._read_china_ip_file(cache_file)

        try:
            print("Updating China IP list...")
            response = requests.get(CHINA_IP_LIST_URL, timeout=30)
            if response.status_code == 200:
                ip_list = [
                    line.strip()
                    for line in response.text.split("\n")
                    if line.strip() and not line.startswith("#")
                ]

                with open(cache_file, "w") as f:
                    f.write("\n".join(ip_list))
                print(f"China IP list updated: {len(ip_list)} networks")
                return ip_list
        except Exception as e:
            print(f"Error updating China IP list: {e}")

        return self._read_china_ip_file(cache_file)

    def preload_china_networks(self):
        china_ip_list = self.get_china_ip_list()
        self.network_matcher.add_networks(china_ip_list)
        print(f"Loaded {len(china_ip_list)} China IP networks")

    def is_cn_ip(self, ip):
        cached_result = self.ip_cache.get(ip)
        if cached_result is not None:
            return cached_result

        result = self.network_matcher.is_china_ip(ip)
        self.ip_cache.put(ip, result, 3600)
        return result

    def query_dns_server(self, domain, dns_server, record_type):
        cache_key = f"{domain}:{record_type}:{dns_server}"
        cached_result = self.dns_cache.get(cache_key)
        if cached_result is not None:
            return cached_result, True

        servers_to_try = [dns_server] + FALLBACK_DNS

        for server in servers_to_try:
            try:
                record = DNSRecord()
                record.add_question(DNSQuestion(domain, getattr(QTYPE, record_type)))
                packet = record.pack()

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(TIMEOUT)
                    sock.sendto(packet, (server, 53))
                    reply_packet, _ = sock.recvfrom(1024)
                    reply = DNSRecord.parse(reply_packet)

                self.dns_cache.put(cache_key, reply)
                return reply, False

            except Exception as e:
                print(f"Error querying {server}: {e}")
                continue

        return None, False

    def concurrent_dns_query(self, domain, record_type):
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                "china": executor.submit(
                    self.query_dns_server, domain, CHINA_DNS, record_type
                ),
                "foreign": executor.submit(
                    self.query_dns_server, domain, FOREIGN_DNS, record_type
                ),
            }

            results = {}
            for name, future in futures.items():
                try:
                    results[name] = future.result(timeout=TIMEOUT)
                except:
                    results[name] = (None, False)

            return (
                results["china"][0],
                results["foreign"][0],
                results["china"][1] or results["foreign"][1],
            )

    def _extract_ips(self, reply, qtype):
        if not reply or not reply.rr:
            return []
        return [str(rr.rdata) for rr in reply.rr if rr.rtype == getattr(QTYPE, qtype)]

    def handle_dns_request(self, data, client_addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = QTYPE[request.q.qtype]

            if qtype in ("A", "AAAA"):
                cn_reply, foreign_reply, cache_hit = self.concurrent_dns_query(
                    qname, qtype
                )

                cn_ips = self._extract_ips(cn_reply, qtype)
                foreign_ips = self._extract_ips(foreign_reply, qtype)

                cn_ips_in_china = [ip for ip in cn_ips if self.is_cn_ip(ip)]

                if cn_ips_in_china:
                    response = cn_reply
                elif foreign_ips:
                    response = foreign_reply
                elif cn_ips:
                    response = cn_reply
                else:
                    response = foreign_reply if foreign_reply else cn_reply
            else:
                response = self.query_dns_server(qname, FOREIGN_DNS, qtype)

            if response:
                response.header.id = request.header.id
                self.udp_sock.sendto(response.pack(), client_addr)
            else:
                response = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, ra=1), q=request.q
                )
                self.udp_sock.sendto(response.pack(), client_addr)

        except Exception as e:
            print(f"Error handling request: {e}")

    def run_dns_server(self):
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((LISTEN_IP, LISTEN_PORT))
            print(f"DNS server listening on {LISTEN_IP}:{LISTEN_PORT}")

            while not self.shutdown_event.is_set():
                try:
                    self.udp_sock.settimeout(1.0)
                    data, addr = self.udp_sock.recvfrom(1024)
                    self.thread_pool.submit(self.handle_dns_request, data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.shutdown_event.is_set():
                        print(f"Server error: {e}")

        except Exception as e:
            print(f"Fatal error: {e}")
        finally:
            if self.udp_sock:
                self.udp_sock.close()
            self.thread_pool.shutdown(wait=True)


if __name__ == "__main__":
    server = SmartDNSServer()
    server.preload_china_networks()
    server.run_dns_server()
