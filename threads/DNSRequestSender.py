from scapy.all import  *
from scapy.layers.dns import *
import threading
class DNS_Sender:
    dns_packet = DNS()
    has_to_run = True
    def set_packet(self, new_packet):
        self.dns_packet = new_packet
    def get_thread(self):
        thread = threading.Thread(target=self.send_dns_request, args=(self.dns_packet ,))
        return thread
    def send_dns_request(self, dns_packet):
         while self.has_to_run:
            send(dns_packet)
        # answer = sr1(dns_req, verbose=2)
        # manage_answer(answer)
    def end_thread(self):
        self.has_to_run = False
