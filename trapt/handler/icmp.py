import handler.handler
import scapy.all

class Icmp(handler.handler.Handler):
    
    def __init__(self, frame, trapt, interface):
        handler.handler.Handler.__init__(self, frame, trapt, interface)

        self.src_ip = self.frame[scapy.all.IP].src
        self.dst_ip = self.frame[scapy.all.IP].dst
        self.icmp_id = self.frame[scapy.all.ICMP].id
        self.icmp_seq = self.frame[scapy.all.ICMP].seq
        self.icmp_type = self.frame[scapy.all.ICMP].type
        self.icmp_code = self.frame[scapy.all.ICMP].code
        self.payload = self.frame[scapy.all.Raw].load

        self.handle()

    def handle(self):
        """
        Function to process ICMP messages and handles accordingly.
        Actions may include filtering, generate one or more response,
        or invoking other handlers.
        """

        self.log_packet(self.icmp_type, self.icmp_code
                        , self.icmp_id, self.icmp_seq, 'received'
                        , self.src_ip, self.dst_ip)

        if self.is_echo_request():
            if self.should_reply():
                latency = self.latency(self.dst_ip)
                packet = {}
                packet['IP'] = scapy.all.IP(src = self.dst_ip
                                            , dst = self.src_ip) 

                packet['ICMP'] = scapy.all.ICMP(type = 0
                                                , code = 0
                                                , id = self.icmp_id
                                                , seq = self.icmp_seq)

                self.log_packet("0", "0"
                                , self.icmp_id, self.icmp_seq, 'sent'
                                , self.dst_ip, self.src_ip)
 
 
                icmp_reply = packet['IP']/packet['ICMP']/scapy.all.Raw(self.payload)
                self.interface.transmitter.enqueue({ 'frame' : icmp_reply, 'latency' : latency })

    def is_echo_request(self):
        """
        Function to return whether or not the received frame is an 
        ICMP Echo Request.
        """

        return str(self.icmp_type) == '8'

    def is_echo_reply(self):
        """
        Function to return whether or not the received frame is an 
        ICMP Echo Reply.
        """

        return str(self.icmp_type) == '0'

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
                self.icmp_name(type, code), direction, src_ip, dst_ip, id, seq)

        self.trapt.logger['network'].logger.info(log_message)
