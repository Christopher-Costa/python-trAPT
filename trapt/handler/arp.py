import scapy.all

class Arp():

    def __init__(self, frame, trapt):
        self.frame = frame
        self.trapt = trapt

        self.handle()

    def handle(self):
        """
        Function to process ARP messages and handle accordingly.
        Actions may include filtering, generate one or more response,
        or invoking other handlers.
        """

        if not self.frame.haslayer(scapy.all.ARP):
            return

        self.ether_src_mac = self.frame[scapy.all.Ether].src
        self.ether_dst_mac = self.frame[scapy.all.Ether].dst
        self.arp_src_ip = self.frame[scapy.all.ARP].psrc
        self.arp_dst_ip = self.frame[scapy.all.ARP].pdst
        self.arp_src_mac = self.frame[scapy.all.ARP].hwsrc
        self.arp_dst_mac = self.frame[scapy.all.ARP].hwdst
        self.arp_opcode = self.frame[scapy.all.ARP].op

        self.log_packet(self.arp_opcode, 'received'
                        , self.arp_src_ip, self.arp_src_mac
                        , self.arp_dst_ip, self.arp_dst_mac)

        if self.is_arp_request():
            if self.should_reply():
                reply_src_mac = '00:00:01:02:03:04'
                packet = {}
                packet['Ether'] = scapy.all.Ether(
                                        src = reply_src_mac
                                        , dst = self.ether_src_mac)
            
                packet['ARP'] = scapy.all.ARP(
                                        op=2
                                        , hwsrc = reply_src_mac
                                        , hwdst = self.ether_src_mac
                                        , psrc = self.arp_dst_ip
                                        , pdst = self.arp_src_ip)

                self.log_packet('2', 'sent'
                                , self.arp_dst_ip, reply_src_mac
                                , self.arp_src_ip, self.arp_src_mac)
                arp_reply = packet['Ether']/packet['ARP']
                self.trapt.transmitter.enqueue(arp_reply)

    def should_reply(self):
        """
        Function to return whether or not trAPT should generate and ARP
        Reply.  This is determined by checking the host and router
        interface tables for "external" IP addresses.

        """
        if self.arp_dst_ip in self.trapt.config['host'].interfaces:
            if self.trapt.config['host'].is_external(self.arp_dst_ip):
                return True
        elif self.arp_dst_ip in self.trapt.config['router'].interfaces:
            if self.trapt.config['router'].is_external(self.arp_dst_ip):
                return True
        return False    

    def is_arp_request(self):
        """
        Function to return whether or not the received frame is an ARP
        Request.
        """

        if self.arp_opcode == 1:
            return True
        return False

    def is_arp_response(self):
        """
        Function to return whether or not the received frame is an ARP
        Reply.
        """

        if self.arp_opcode == 2:
            return True
        return False

    def opcode_name(self, opcode):
        """
        Function to return the name of the ARP opcode from the pass parameter.
        """

        names = {
            '1' : 'request' ,
            '2' : 'response'
        }

        return names[str(opcode)]

    def log_packet (self, opcode, direction, src_ip, src_mac, dst_ip, dst_mac):
        """
        Function to generate a log message to the trAPT network log message based
        on provided parameters.
        """

        log_message = 'ARP {0} {1}: {2} ({3}) -> {4} ({5})'.format(
                self.opcode_name(opcode), direction, src_ip, src_mac, dst_ip, dst_mac)

        self.trapt.logger['network'].logger.info(log_message)
