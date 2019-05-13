

from scapy.layers.inet import *
from scapy.layers.dns import *
import time
import DNSRequestSender
import threading

thread_builder = DNSRequestSender.DNS_Sender()
destination_ip = "192.168.56.101"
destination_port = 53
query_name = "bankofallan.co.uk."
dns_req = IP(dst=destination_ip, src="10.211.55.10") / UDP(dport=destination_port) / DNS(id=0, rd=1, qd=DNSQR(qname=query_name))
thread_builder.set_packet(dns_req)
thread = thread_builder.get_thread()
thread.start()
# time.sleep(5)
# thread_builder.end_thread()