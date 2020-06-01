import handler.handler
import scapy.all

class Ip(handler.handler.Handler):

    host_table = {}
    
    def __init__(self, frame, trapt, interface):
        handler.handler.Handler.__init__(self, frame, trapt, interface)

        self.src_ip = self.frame[scapy.all.IP].src
        self.dst_ip = self.frame[scapy.all.IP].dst

    def ip_id (self):
       if self.dst_ip in Ip.host_table:
           last_id = Ip.host_table[self.dst_ip]['last_id']
           Ip.host_table[self.dst_ip]['last_id'] = (last_id + 1) % 65536
       else:
           Ip.host_table[self.dst_ip] = {}
           Ip.host_table[self.dst_ip]['last_id'] = 1024

       return (Ip.host_table[self.dst_ip]['last_id'])
       
    def send_packet (self, payload):
        latency = self.latency(self.dst_ip)
        ip_packet = scapy.all.IP(src = self.dst_ip,
                                 dst = self.src_ip,
                                 id = self.ip_id())
        self.interface.transmitter.enqueue({ 'frame' : ip_packet/payload, 'latency' : latency })
      
