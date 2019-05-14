from scapy.all import  *
from scapy.layers.dns import *
import threading
class DNS_Sender:
    dns_packet = DNS()
    #if 0 or less means infinity packets
    number_of_packets = 1000
    has_to_run = True
    def set_packet(self, new_packet):
        self.dns_packet = new_packet
    def get_thread(self):
        thread = threading.Thread(target=self.send_dns_request, args=(self.dns_packet ,))
        return thread
    def set_number_of_packets_to_send(self, number):
        self.number_of_packets = number
    def send_dns_request(self, dns_packet):
         count = 0
         print(self.number_of_packets)
         while self.has_to_run and (count < self.number_of_packets or self.number_of_packets <= 0):
             print("sending packet")
             sr1(dns_packet)
             count+=1
        # answer = sr1(dns_req, verbose=2)
        # manage_answer(answer)
    def end_thread(self):
        self.has_to_run = False
