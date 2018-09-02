import scapy.all

class Arp():

    OPCODE_REQUEST = 1
    OPCODE_RESPONSE = 2
    
    def __init__(self, frame, trapt):
        self.frame = frame
        self.trapt = trapt

        self.handle()

    def handle(self):
        """
        Function to process ARP messages, and handle accordingly.
        """

        if self.frame[scapy.all.ARP].op == self.OPCODE_REQUEST:
            src_mac = self.frame[scapy.all.Ether].src

            src_ip = self.frame[scapy.all.ARP].psrc
            dst_ip = self.frame[scapy.all.ARP].pdst

            reply = {}
            reply['Ether'] = scapy.all.Ether(src = '00:00:01:02:03:04'
                                                , dst = src_mac)            
            reply['ARP'] = scapy.all.ARP(op = self.OPCODE_RESPONSE
                                            , hwsrc = '00:00:01:02:03:04'
                                            , hwdst = src_mac
                                            , psrc = dst_ip
                                            , pdst = src_ip)

            arp_reply = reply['Ether']/reply['ARP']
            self.trapt.transmitter.enqueue(arp_reply)
