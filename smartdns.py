#!/usr/bin/env python3

import socket
import threading
import ipaddress
import os
import time
import requests
import signal
import atexit
from threading import Lock, Event
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, DNSQuestion

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
MAX_PACKET_SIZE = 1024
TIMEOUT = 1
DNS_CACHE_SIZE = 10000
DNS_CACHE_TTL = 1800
IP_CACHE_SIZE = 10000
MAX_THREADS = 50


class LRUCache:
    def __init__(self, capacity):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.lock = Lock()

    def get(self, key):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                value, timestamp = self.cache[key]
                return value, timestamp
            return None, None

    def put(self, key, value, ttl=DNS_CACHE_TTL):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            elif len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)

            timestamp = time.time() + ttl
            self.cache[key] = (value, timestamp)

    def is_expired(self, timestamp):
        return time.time() > timestamp

    def cleanup_expired(self):
        with self.lock:
            current_time = time.time()
            expired_keys = [
                key
                for key, (value, timestamp) in self.cache.items()
                if current_time > timestamp
            ]
            for key in expired_keys:
                self.cache.pop(key, None)
            return len(expired_keys)


class NetworkMatcher:
    def __init__(self):
        self.ipv4_networks = []
        self.lock = Lock()

    def add_networks(self, ipv4_list):
        with self.lock:
            self.ipv4_networks = [ipaddress.ip_network(net) for net in ipv4_list]

    def is_china_ip(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for network in self.ipv4_networks:
                if ip_obj in network:
                    return True
            return False
        except:
            return False


class DNSServer:
    def __init__(self):
        self.shutdown_event = Event()
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_THREADS)
        self.network_matcher = NetworkMatcher()
        self.dns_cache = LRUCache(DNS_CACHE_SIZE)
        self.ip_cache = LRUCache(IP_CACHE_SIZE)
        self.udp_sock = None
        self.cleanup_thread = None

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        atexit.register(self.cleanup)

    def _signal_handler(self, signum, frame):
        print(f"Received signal {signum}, gracefully shutting down...")
        self.shutdown_event.set()

    def get_china_ip_list(self):
        if os.path.exists(CHINA_IP_CACHE_FILE):
            file_age = time.time() - os.path.getmtime(CHINA_IP_CACHE_FILE)
            if file_age < CACHE_DURATION:
                with open(CHINA_IP_CACHE_FILE, "r") as f:
                    return [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]

        try:
            response = requests.get(CHINA_IP_LIST_URL, timeout=30)
            ip_list = [
                line.strip()
                for line in response.text.split("\n")
                if line.strip() and not line.startswith("#")
            ]

            with open(CHINA_IP_CACHE_FILE, "w") as f:
                f.write("\n".join(ip_list))
            print(f"IP list updated, {len(ip_list)} records")
            return ip_list
        except Exception as e:
            print(f"Error getting China IP list: {e}")

        return []

    def preload_china_networks(self):
        print("Preloading China IP list...")
        china_ip_list = self.get_china_ip_list()
        self.network_matcher.add_networks(china_ip_list)
        print(f"Preload completed: {len(china_ip_list)} networks")

    def is_cn_ip(self, ip):
        cached_result, timestamp = self.ip_cache.get(ip)
        if cached_result is not None and not self.ip_cache.is_expired(timestamp):
            return cached_result

        result = self.network_matcher.is_china_ip(ip)
        self.ip_cache.put(ip, result, 3600)
        return result

    def forward_dns_request(self, domain, dns_server, record_type):
        servers_to_try = [dns_server] + FALLBACK_DNS

        for server in servers_to_try:
            try:
                cache_key = f"{domain}:{record_type}:{server}"
                cached_result, timestamp = self.dns_cache.get(cache_key)
                if cached_result is not None and not self.dns_cache.is_expired(
                    timestamp
                ):
                    return cached_result, True

                record = DNSRecord()
                record.add_question(DNSQuestion(domain, getattr(QTYPE, record_type)))
                packet = record.pack()

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(TIMEOUT)

                try:
                    sock.sendto(packet, (server, 53))
                    reply_packet, _ = sock.recvfrom(MAX_PACKET_SIZE)
                    reply = DNSRecord.parse(reply_packet)

                    self.dns_cache.put(cache_key, reply)
                    return reply, False
                finally:
                    sock.close()

            except Exception as e:
                print(f"Error querying {server} for {domain} ({record_type}): {e}")
                continue

        return None, False

    def concurrent_dns_query(self, domain, record_type):
        with ThreadPoolExecutor(max_workers=2) as executor:
            cn_future = executor.submit(
                self.forward_dns_request, domain, CHINA_DNS, record_type
            )
            foreign_future = executor.submit(
                self.forward_dns_request, domain, FOREIGN_DNS, record_type
            )

            try:
                cn_reply, cn_cached = cn_future.result(timeout=TIMEOUT)
            except:
                cn_reply, cn_cached = None, False

            try:
                foreign_reply, foreign_cached = foreign_future.result(timeout=TIMEOUT)
            except:
                foreign_reply, foreign_cached = None, False

        return cn_reply, foreign_reply, cn_cached or foreign_cached

    def handle_dns_request(self, data, client_addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = QTYPE[request.q.qtype]

            print(f"Query: {qname} ({qtype}) from {client_addr[0]}")

            if qtype == "A":
                cn_reply, foreign_reply, cache_hit = self.concurrent_dns_query(
                    qname, qtype
                )

                cn_ips = []
                if cn_reply and cn_reply.rr:
                    cn_ips = [
                        str(rr.rdata) for rr in cn_reply.rr if rr.rtype == QTYPE.A
                    ]

                foreign_ips = []
                if foreign_reply and foreign_reply.rr:
                    foreign_ips = [
                        str(rr.rdata) for rr in foreign_reply.rr if rr.rtype == QTYPE.A
                    ]

                cn_ips_in_china = [ip for ip in cn_ips if self.is_cn_ip(ip)]

                if cn_ips_in_china:
                    print(f"Using China DNS for {qname}")
                    response = cn_reply
                elif foreign_ips:
                    print(f"Using foreign DNS for {qname}")
                    response = foreign_reply
                elif cn_ips:
                    print(f"Default to China DNS for {qname}")
                    response = cn_reply
                else:
                    print(f"Default to foreign DNS for {qname}")
                    response = foreign_reply if foreign_reply else cn_reply
            else:
                response, cache_hit = self.forward_dns_request(
                    qname, FOREIGN_DNS, qtype
                )
                if not response:
                    response, cache_hit = self.forward_dns_request(
                        qname, CHINA_DNS, qtype
                    )

            if response:
                response.header.id = request.header.id
                self.udp_sock.sendto(response.pack(), client_addr)
            else:
                response = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=0, ra=1), q=request.q
                )
                self.udp_sock.sendto(response.pack(), client_addr)

        except Exception as e:
            print(f"Error handling request: {e}")

    def cleanup_expired_cache(self):
        while not self.shutdown_event.wait(300):
            dns_cleaned = self.dns_cache.cleanup_expired()
            ip_cleaned = self.ip_cache.cleanup_expired()

            if dns_cleaned + ip_cleaned > 0:
                print(f"Cleaned {dns_cleaned + ip_cleaned} expired cache entries")

    def run_dns_server(self):
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((LISTEN_IP, LISTEN_PORT))
            print(f"DNS server listening on {LISTEN_IP}:{LISTEN_PORT} (UDP)")

            self.cleanup_thread = threading.Thread(
                target=self.cleanup_expired_cache, daemon=True
            )
            self.cleanup_thread.start()

            while not self.shutdown_event.is_set():
                try:
                    self.udp_sock.settimeout(1.0)
                    data, addr = self.udp_sock.recvfrom(MAX_PACKET_SIZE)
                    self.thread_pool.submit(self.handle_dns_request, data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.shutdown_event.is_set():
                        print(f"Server error: {e}")

        except Exception as e:
            print(f"Fatal server error: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        print("Cleaning up resources...")
        self.shutdown_event.set()

        if self.thread_pool:
            self.thread_pool.shutdown(wait=True, timeout=10)

        if self.udp_sock:
            self.udp_sock.close()

        print("Cleanup completed")


if __name__ == "__main__":

    print("Starting DNS server...")

    server = DNSServer()
    server.preload_china_networks()
    server.run_dns_server()
