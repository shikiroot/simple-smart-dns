#!/usr/bin/env python3

import socket
import threading
import ipaddress
import os
import time
import requests
import json
import asyncio
import concurrent.futures
import signal
import atexit
import gc
from threading import Lock, Event
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, AAAA, DNSQuestion

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53
CHINA_DNS = "223.5.5.5"
FOREIGN_DNS = "8.8.8.8"
FALLBACK_DNS = ["8.8.4.4", "1.1.1.1"]
CHINA_IP_LIST_URL = "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt"
CHINA_IPV6_LIST_URL = "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute_v6.txt"
CHINA_IP_CACHE_FILE = "/tmp/.china_ip_list.txt"
CHINA_IPV6_CACHE_FILE = "/tmp/.china_ipv6_list.txt"
CACHE_DURATION = 7 * 24 * 60 * 60
MAX_PACKET_SIZE = 1024
TIMEOUT = 3
DNS_CACHE_SIZE = 10000
DNS_CACHE_TTL = 1800
IP_CACHE_SIZE = 10000
MAX_THREADS = 50
CONNECTION_POOL_SIZE = 20

class ImprovedLRUCache:
    def __init__(self, capacity):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.lock = Lock()
        self.hit_count = defaultdict(int)
        self.access_time = {}

    def get(self, key):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                value, timestamp = self.cache[key]
                self.hit_count[key] += 1
                self.access_time[key] = time.time()
                return value, timestamp
            return None, None

    def put(self, key, value, ttl=None):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            elif len(self.cache) >= self.capacity:
                self._evict_least_valuable()
            
            adaptive_ttl = self._calculate_adaptive_ttl(key, ttl or DNS_CACHE_TTL)
            timestamp = time.time() + adaptive_ttl
            self.cache[key] = (value, timestamp)
            self.access_time[key] = time.time()

    def _calculate_adaptive_ttl(self, key, base_ttl):
        hits = self.hit_count.get(key, 0)
        if hits > 10:
            return base_ttl * 2
        elif hits > 5:
            return base_ttl * 1.5
        return base_ttl

    def _evict_least_valuable(self):
        current_time = time.time()
        min_score = float('inf')
        worst_key = None
        
        for key in list(self.cache.keys())[:10]:
            hits = self.hit_count.get(key, 1)
            last_access = self.access_time.get(key, current_time)
            age = current_time - last_access
            score = hits / (age + 1)
            
            if score < min_score:
                min_score = score
                worst_key = key
        
        if worst_key:
            self.cache.pop(worst_key, None)
            self.hit_count.pop(worst_key, None)
            self.access_time.pop(worst_key, None)
        else:
            self.cache.popitem(last=False)

    def is_expired(self, timestamp):
        return time.time() > timestamp

    def cleanup_expired(self):
        with self.lock:
            current_time = time.time()
            expired_keys = [
                key for key, (value, timestamp) in self.cache.items()
                if current_time > timestamp
            ]
            for key in expired_keys:
                self.cache.pop(key, None)
                self.hit_count.pop(key, None)
                self.access_time.pop(key, None)
            return len(expired_keys)

class OptimizedNetworkMatcher:
    def __init__(self):
        self.ipv4_networks = []
        self.ipv6_networks = []
        self.ipv4_sorted = False
        self.ipv6_sorted = False
        self.lock = Lock()

    def add_networks(self, ipv4_list, ipv6_list):
        with self.lock:
            self.ipv4_networks = [ipaddress.ip_network(net) for net in ipv4_list]
            self.ipv6_networks = [ipaddress.ip_network(net) for net in ipv6_list]
            self._optimize_networks()

    def _optimize_networks(self):
        self.ipv4_networks.sort(key=lambda x: (x.network_address, -x.prefixlen))
        self.ipv6_networks.sort(key=lambda x: (x.network_address, -x.prefixlen))
        self.ipv4_sorted = True
        self.ipv6_sorted = True

    def is_china_ip(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            networks = self.ipv4_networks if ip_obj.version == 4 else self.ipv6_networks
            
            for network in networks:
                if ip_obj in network:
                    return True
                if ip_obj < network.network_address:
                    break
            return False
        except:
            return False

class ImprovedConnectionPool:
    def __init__(self, max_size=CONNECTION_POOL_SIZE):
        self.pools = defaultdict(list)
        self.pool_stats = defaultdict(lambda: {'created': 0, 'reused': 0})
        self.max_size = max_size
        self.lock = Lock()
        self.health_check_time = defaultdict(float)

    def get_connection(self, server):
        with self.lock:
            pool = self.pools[server]
            
            while pool:
                sock = pool.pop()
                if self._is_connection_healthy(sock, server):
                    self.pool_stats[server]['reused'] += 1
                    return sock
                else:
                    sock.close()

            sock = self._create_new_connection(server)
            self.pool_stats[server]['created'] += 1
            return sock

    def return_connection(self, server, sock):
        with self.lock:
            if len(self.pools[server]) < self.max_size:
                self.pools[server].append(sock)
            else:
                sock.close()

    def _create_new_connection(self, server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        return sock

    def _is_connection_healthy(self, sock, server):
        last_check = self.health_check_time.get(id(sock), 0)
        current_time = time.time()
        
        if current_time - last_check < 30:
            return True
        
        try:
            sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            self.health_check_time[id(sock)] = current_time
            return True
        except:
            return False

    def cleanup_connections(self):
        with self.lock:
            for server, pool in self.pools.items():
                healthy_connections = []
                for sock in pool:
                    if self._is_connection_healthy(sock, server):
                        healthy_connections.append(sock)
                    else:
                        sock.close()
                self.pools[server] = healthy_connections

class DNSMetrics:
    def __init__(self):
        self.query_count = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.response_times = []
        self.error_count = 0
        self.china_dns_count = 0
        self.foreign_dns_count = 0
        self.lock = Lock()

    def record_query(self, response_time, cache_hit=False, dns_type='unknown', error=False):
        with self.lock:
            self.query_count += 1
            self.response_times.append(response_time)
            
            if len(self.response_times) > 1000:
                self.response_times = self.response_times[-500:]
            
            if cache_hit:
                self.cache_hits += 1
            else:
                self.cache_misses += 1
            
            if error:
                self.error_count += 1
            elif dns_type == 'china':
                self.china_dns_count += 1
            elif dns_type == 'foreign':
                self.foreign_dns_count += 1

    def get_stats(self):
        with self.lock:
            if not self.response_times:
                avg_response_time = 0
            else:
                avg_response_time = sum(self.response_times) / len(self.response_times)
            
            cache_hit_rate = 0
            if self.cache_hits + self.cache_misses > 0:
                cache_hit_rate = self.cache_hits / (self.cache_hits + self.cache_misses)
            
            return {
                'total_queries': self.query_count,
                'cache_hit_rate': cache_hit_rate,
                'avg_response_time': avg_response_time,
                'error_rate': self.error_count / max(self.query_count, 1),
                'china_dns_usage': self.china_dns_count,
                'foreign_dns_usage': self.foreign_dns_count
            }

class GracefulDNSServer:
    def __init__(self):
        self.shutdown_event = Event()
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_THREADS)
        self.connection_pool = ImprovedConnectionPool()
        self.network_matcher = OptimizedNetworkMatcher()
        self.dns_cache = ImprovedLRUCache(DNS_CACHE_SIZE)
        self.ip_cache = ImprovedLRUCache(IP_CACHE_SIZE)
        self.metrics = DNSMetrics()
        self.udp_sock = None
        self.cleanup_thread = None
        self.stats_thread = None
        
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        atexit.register(self.cleanup)

    def _signal_handler(self, signum, frame):
        print(f"Received signal {signum}, gracefully shutting down...")
        self.shutdown_event.set()

    def get_china_ip_list(self, is_ipv6=False):
        url = CHINA_IPV6_LIST_URL if is_ipv6 else CHINA_IP_LIST_URL
        cache_file = CHINA_IPV6_CACHE_FILE if is_ipv6 else CHINA_IP_CACHE_FILE

        if os.path.exists(cache_file):
            file_age = time.time() - os.path.getmtime(cache_file)
            if file_age < CACHE_DURATION:
                with open(cache_file, 'r') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]

        for attempt in range(3):
            try:
                print(f"Updating {'IPv6' if is_ipv6 else 'IPv4'} list (attempt {attempt + 1})...")
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    ip_list = [line.strip() for line in response.text.split('\n')
                              if line.strip() and not line.startswith('#')]
                    
                    with open(cache_file, 'w') as f:
                        f.write('\n'.join(ip_list))
                    print(f"{'IPv6' if is_ipv6 else 'IPv4'} list updated, {len(ip_list)} records")
                    return ip_list
                else:
                    if attempt == 2 and os.path.exists(cache_file):
                        with open(cache_file, 'r') as f:
                            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                print(f"Error getting China IP list (attempt {attempt + 1}): {e}")
                if attempt == 2 and os.path.exists(cache_file):
                    with open(cache_file, 'r') as f:
                        return [line.strip() for line in f if line.strip() and not line.startswith('#')]
                time.sleep(2 ** attempt)
        
        return []

    def preload_china_networks(self):
        print("Preloading China IP list...")
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            ipv4_future = executor.submit(self.get_china_ip_list, False)
            ipv6_future = executor.submit(self.get_china_ip_list, True)
            
            china_ip_list = ipv4_future.result()
            china_ipv6_list = ipv6_future.result()
        
        self.network_matcher.add_networks(china_ip_list, china_ipv6_list)
        print(f"Preload completed: {len(china_ip_list)} IPv4 networks, {len(china_ipv6_list)} IPv6 networks")

    def is_cn_ip(self, ip):
        cached_result, timestamp = self.ip_cache.get(ip)
        if cached_result is not None and not self.ip_cache.is_expired(timestamp):
            return cached_result

        result = self.network_matcher.is_china_ip(ip)
        self.ip_cache.put(ip, result, 3600)
        return result

    def forward_dns_request_with_fallback(self, domain, dns_server, record_type):
        servers_to_try = [dns_server] + FALLBACK_DNS
        
        for server in servers_to_try:
            try:
                cache_key = f"{domain}:{record_type}:{server}"
                cached_result, timestamp = self.dns_cache.get(cache_key)
                if cached_result is not None and not self.dns_cache.is_expired(timestamp):
                    return cached_result, True

                record = DNSRecord()
                record.add_question(DNSQuestion(domain, getattr(QTYPE, record_type)))
                packet = record.pack()

                sock = self.connection_pool.get_connection(server)
                
                try:
                    sock.sendto(packet, (server, 53))
                    reply_packet, _ = sock.recvfrom(MAX_PACKET_SIZE)
                    reply = DNSRecord.parse(reply_packet)
                    
                    self.dns_cache.put(cache_key, reply)
                    return reply, False
                finally:
                    self.connection_pool.return_connection(server, sock)
                    
            except Exception as e:
                print(f"Error querying {server} for {domain} ({record_type}): {e}")
                continue
        
        return None, False

    def concurrent_dns_query(self, domain, record_type):
        with ThreadPoolExecutor(max_workers=2) as executor:
            cn_future = executor.submit(self.forward_dns_request_with_fallback, domain, CHINA_DNS, record_type)
            foreign_future = executor.submit(self.forward_dns_request_with_fallback, domain, FOREIGN_DNS, record_type)
            
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
        start_time = time.time()
        cache_hit = False
        dns_type = 'unknown'
        error = False

        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = QTYPE[request.q.qtype]

            print(f"Query: {qname} ({qtype}) from {client_addr[0]}")

            if qtype in ('A', 'AAAA'):
                cn_reply, foreign_reply, cache_hit = self.concurrent_dns_query(qname, qtype)

                cn_ips = []
                if cn_reply and cn_reply.rr:
                    cn_ips = [str(rr.rdata) for rr in cn_reply.rr if rr.rtype == getattr(QTYPE, qtype)]

                foreign_ips = []
                if foreign_reply and foreign_reply.rr:
                    foreign_ips = [str(rr.rdata) for rr in foreign_reply.rr if rr.rtype == getattr(QTYPE, qtype)]

                cn_ips_in_china = []
                if cn_ips:
                    with ThreadPoolExecutor(max_workers=min(len(cn_ips), 10)) as executor:
                        futures = {executor.submit(self.is_cn_ip, ip): ip for ip in cn_ips}
                        for future in concurrent.futures.as_completed(futures):
                            ip = futures[future]
                            if future.result():
                                cn_ips_in_china.append(ip)

                if cn_ips_in_china:
                    print(f"Using China DNS for {qname} ({qtype})")
                    response = cn_reply
                    dns_type = 'china'
                elif foreign_ips:
                    print(f"Using foreign DNS for {qname} ({qtype})")
                    response = foreign_reply
                    dns_type = 'foreign'
                elif cn_ips:
                    print(f"Default to China DNS for {qname} ({qtype})")
                    response = cn_reply
                    dns_type = 'china'
                else:
                    print(f"Default to foreign DNS for {qname} ({qtype})")
                    response = foreign_reply if foreign_reply else cn_reply
                    dns_type = 'foreign'
            else:
                response, cache_hit = self.forward_dns_request_with_fallback(qname, FOREIGN_DNS, qtype)
                if not response:
                    response, cache_hit = self.forward_dns_request_with_fallback(qname, CHINA_DNS, qtype)
                dns_type = 'foreign'

            if response:
                response.header.id = request.header.id
                self.udp_sock.sendto(response.pack(), client_addr)
            else:
                response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=0, ra=1), q=request.q)
                self.udp_sock.sendto(response.pack(), client_addr)
                error = True

        except Exception as e:
            print(f"Error handling request: {e}")
            error = True
        
        finally:
            response_time = time.time() - start_time
            self.metrics.record_query(response_time, cache_hit, dns_type, error)

    def cleanup_expired_cache(self):
        while not self.shutdown_event.wait(300):
            dns_cleaned = self.dns_cache.cleanup_expired()
            ip_cleaned = self.ip_cache.cleanup_expired()
            
            if dns_cleaned + ip_cleaned > 0:
                print(f"Cleaned {dns_cleaned + ip_cleaned} expired cache entries")
            
            self.connection_pool.cleanup_connections()
            gc.collect()

    def print_stats(self):
        while not self.shutdown_event.wait(60):
            stats = self.metrics.get_stats()
            print(f"Stats: Queries={stats['total_queries']}, Cache Hit Rate={stats['cache_hit_rate']:.2%}, "
                  f"Avg Response={stats['avg_response_time']:.3f}s, Error Rate={stats['error_rate']:.2%}")

    def run_dns_server(self):
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((LISTEN_IP, LISTEN_PORT))
            print(f"DNS server listening on {LISTEN_IP}:{LISTEN_PORT} (UDP)")

            self.cleanup_thread = threading.Thread(target=self.cleanup_expired_cache, daemon=True)
            self.cleanup_thread.start()

            self.stats_thread = threading.Thread(target=self.print_stats, daemon=True)
            self.stats_thread.start()

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
    try:
        import dnslib
    except ImportError:
        print("Please install dependencies: pip install dnslib requests")
        exit(1)

    print("Starting optimized DNS server...")
    
    server = GracefulDNSServer()
    server.preload_china_networks()
    server.run_dns_server()
