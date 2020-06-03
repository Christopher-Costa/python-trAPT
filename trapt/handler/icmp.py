import handler.ip
import scapy.all
import tools.nmap

class Icmp(handler.ip.Ip):
    
    def __init__(self, frame, trapt, interface):
        handler.ip.Ip.__init__(self, frame, trapt, interface)

        self.frame = frame

        # It's possible that a non-ICMP frame can trigger an
        # ICMP response.  Don't try to handle those.
        if frame.haslayer(scapy.all.ICMP):
            self.handle()

    def handle(self):
        """
        Function to process ICMP messages and handles accordingly.
        Actions may include filtering, generate one or more response,
        or invoking other handlers.
        """

        self.log_packet(self.icmp_rcv_type(), self.icmp_rcv_code()
                        , self.icmp_rcv_id(), self.icmp_rcv_seq(), 'received'
                        , self.src_ip, self.dst_ip)

        if tools.nmap.is_scan_packet_ie1(self):
            self.send_echo_reply()
            return

        if tools.nmap.is_scan_packet_ie2(self):
            self.send_echo_reply()
            return

        if self.is_echo_request():
            if self.should_reply():
                self.send_echo_reply() 


    def send_echo_reply(self):
        icmp_packet = scapy.all.ICMP(type = 0
                                   , code = 0
                                   , id = self.icmp_rcv_id()
                                   , seq = self.icmp_rcv_seq())

        self.send_packet(icmp_packet/scapy.all.Raw(self.icmp_rcv_payload())) 
        self.log_packet("0", "0", self.icmp_rcv_id(), self.icmp_rcv_seq()
                        , 'sent' , self.dst_ip, self.src_ip)

    def send_dest_port_unreachable(self):
        payload_bytes = self.frame[scapy.all.IP].ihl * 4 + 64

        icmp_packet = scapy.all.ICMP(type = 3, code = 3, id = 1, seq = 1)
        icmp_payload = scapy.all.Raw(bytes(self.frame[scapy.all.IP])[0:payload_bytes])

        print(icmp_payload.show())
        self.send_packet(icmp_packet / icmp_payload)
        self.log_packet("0", "0", "1", "1", 'sent', self.dst_ip, self.src_ip)

    def is_echo_request(self):
        """
        Function to return whether or not the received frame is an 
        ICMP Echo Request.
        """

        return str(self.icmp_rcv_type()) == '8'

    def is_echo_reply(self):
        """
        Function to return whether or not the received frame is an 
        ICMP Echo Reply.
        """

        return str(self.icmp_rcv_type()) == '0'

    def should_reply(self):
        """
        Function to return whether or not trAPT should reply to 
        the received frame via ICMP.  This is determined by 
        checking the host and router interface tables.
        """

        for table in ('host', 'router'):
            if self.dst_ip in self.trapt.config[table].interfaces:
                interfaces = self.trapt.config[table].interfaces[self.dst_ip]
                if 'ports' in interfaces:
                    if 'icmp' in interfaces['ports']:
                        if 'state' in interfaces['ports']['icmp']:
                            if interfaces['ports']['icmp']['state'] == 'open':
                                return True
                
                if 'default_state' in interfaces:
                    if interfaces['default_state'] == 'open':
                        return True
        return False

    def icmp_name(self, type, code):
        """
        Function to return the name of the ICMP message baced on the 
        passed type and code parameters.
        """

        if str(type) == '0':
            return "Echo Reply"
        elif str(type) == '8':
            return "Echo Request"
        else:
            return "Unknown"


    def log_packet (self, type, code, id, seq, direction, src_ip, dst_ip):
        """
        Function to generate a log message to the trAPT network log message based
        on provided parameters.
        """

        log_message = 'ICMP {0} {1}: {2} -> {3}, id={4} seq={5}'.format(
                Icmp.icmp_name(self, type, code), direction, src_ip, dst_ip, id, seq)

        self.trapt.logger['network'].logger.info(log_message)

    def icmp_rcv_code(self):
        return self.frame[scapy.all.ICMP].code

    def icmp_rcv_type(self):
        return self.frame[scapy.all.ICMP].type

    def icmp_rcv_seq(self):
        return self.frame[scapy.all.ICMP].seq

    def icmp_rcv_len(self):
        if self.frame.haslayer(scapy.all.Raw):
            return len(self.frame[scapy.all.Raw].load)
        else:
            return 0 

    def icmp_rcv_id(self):
        return self.frame[scapy.all.ICMP].id

    def icmp_rcv_seq(self):
        return self.frame[scapy.all.ICMP].seq

    def icmp_rcv_type(self):
        return self.frame[scapy.all.ICMP].type

    def icmp_rcv_code(self):
        return self.frame[scapy.all.ICMP].code

    def icmp_rcv_payload(self):
        if self.frame.haslayer(scapy.all.Raw):
            return self.frame[scapy.all.Raw].load
        else:
            return ''
