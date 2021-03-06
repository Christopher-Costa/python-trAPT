import handler.handler
import scapy.all
import time
import tools.nmap
import random

class Ip(handler.handler.Handler):

    host_table = {}
    
    def __init__(self, frame, trapt, interface):
        handler.handler.Handler.__init__(self, frame, trapt, interface)

        self.src_ip = self.frame[scapy.all.IP].src
        self.dst_ip = self.frame[scapy.all.IP].dst

        self.trapt = trapt
        self.interface = interface

    def ip_id (self):
        """
        Function to return a valid IP Identifier for this host, to use 
        in the IP Header.
        """

        if not self.dst_ip in Ip.host_table:
            Ip.host_table[self.dst_ip] = {}
       
        if 'last_id' in Ip.host_table[self.dst_ip]:
            last_id = Ip.host_table[self.dst_ip]['last_id']
            Ip.host_table[self.dst_ip]['last_id'] = (last_id + 1) % 65536
        else:
            Ip.host_table[self.dst_ip]['last_id'] = 1024

        return (Ip.host_table[self.dst_ip]['last_id'])

    def initial_seq_number(self):
        """
        Function to return a valid TCP Initial Sequence Number for this host, 
        to use in the TCP Header.  

        This information is tracked in the IP module since there may be a 
        relationship/pattern to ISN initialtization at the IP layer, and 
        it isn't neccesarily strictly random.
        """

        current_time = time.time()

        if not self.dst_ip in Ip.host_table:
            Ip.host_table[self.dst_ip] = {}
       
        if 'last_isn' in Ip.host_table[self.dst_ip]:
            last_isn = Ip.host_table[self.dst_ip]['last_isn']
            last_time = Ip.host_table[self.dst_ip]['last_isn_time']

            Ip.host_table[self.dst_ip]['last_isn'] = (last_isn + int(268 * (current_time - last_time))) % 0xFFFFFFFF
        else:
            Ip.host_table[self.dst_ip]['last_isn'] = 1000000

        Ip.host_table[self.dst_ip]['last_isn_time'] = current_time
        return (random.randrange(0XFFFFFFFF))
        #return (Ip.host_table[self.dst_ip]['last_isn'])
       
    def send_packet (self, payload):
        """
        Function to assemble complete IP Packets, with payload passed from
        inheriting modules, and enqueue these packets for transmission.
        """

        latency = self.latency(self.dst_ip)
        ip_packet = scapy.all.IP(src = self.dst_ip,
                                 dst = self.src_ip,
                                 id = self.ip_id(),
                                 ttl = 127,
                                 flags = self.ip_snd_flags())
 
        self.interface.transmitter.enqueue({ 'frame' : ip_packet/payload, 'latency' : latency })

    def ip_rcv_flags(self):
        return self.frame[scapy.all.IP].flags

    def ip_snd_flags(self):
        try:
            if self.trigger:
                if tools.nmap.is_scan_packet_u1(self.trigger):
                    return ''

        except AttributeError:
            pass

        if self.is_icmp():
            if tools.nmap.is_scan_packet_ie1(self) or tools.nmap.is_scan_packet_ie2(self):
                return ''

        return 'DF'

    def ip_rcv_tos(self):
        return self.frame[scapy.all.IP].tos

    def ip_rcv_proto(self):
        return self.frame[scapy.all.IP].proto

    def ip_rcv_id(self):
        return self.frame[scapy.all.IP].id

    def is_icmp(self):
        return self.frame.haslayer(scapy.all.ICMP)
