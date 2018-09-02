import scapy.all

class Icmp():

    TYPE_ECHO_REPLY = 0
    TYPE_ECHO_REQUEST = 8
    
    def __init__(self, frame, trapt):
        self.frame = frame
        self.trapt = trapt

        self.handle()

    def handle(self):
        """
        Function to process ICMP messages and handles accordingly.
        Actions may include filtering, generate one or more response,
        or invoking other handlers.
        """

        src_ip = self.frame[scapy.all.IP].src
        dst_ip = self.frame[scapy.all.IP].dst
        icmp_id = self.frame[scapy.all.ICMP].id
        icmp_seq = self.frame[scapy.all.ICMP].seq
        payload = self.frame[scapy.all.Raw].load
        
        if self.frame[scapy.all.ICMP].type == self.TYPE_ECHO_REQUEST:
            reply = {}
            reply['IP'] = scapy.all.IP(src=dst_ip
                                        , dst = src_ip)            
            reply['ICMP'] = scapy.all.ICMP(type=self.TYPE_ECHO_REPLY
                                            , code=0
                                            , id=icmp_id
                                            , seq=icmp_seq)

            icmp_reply = reply['IP']/reply['ICMP']/scapy.all.Raw(payload)
            self.trapt.transmitter.enqueue(icmp_reply)
