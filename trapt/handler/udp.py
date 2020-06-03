import handler.ip
import scapy.all
import tools.nmap
import handler.udp
import handler.icmp

class Udp(handler.ip.Ip):
    
    def __init__(self, frame, trapt, interface):
        handler.ip.Ip.__init__(self, frame, trapt, interface)

        self.frame = frame

        self.udp_sport = self.frame[scapy.all.UDP].sport
        self.udp_dport = self.frame[scapy.all.UDP].dport

        if self.port_disposition() != 'blocked':
            self.handle()

    def handle(self):
        """
        Function to process UDP messages and handles accordingly.
        Actions may include filtering, generate one or more response,
        or invoking other handlers.
        """

        if tools.nmap.is_scan_packet_u1(self):
            icmp_response = handler.icmp.Icmp(self.frame, self.trapt, self.interface)
            icmp_response.send_dest_port_unreachable()

        self.log_packet('received', self.dst_ip, self.udp_dport, self.src_ip, self.udp_sport)

    def log_packet (self, direction, src_ip, sport, dst_ip, dport):
        """
        Function to generate a log message to the trAPT network log message based
        on provided parameters.
        """

        log_message = 'UDP {0}: {1}:{2} -> {3}:{4}'.format(
                direction, src_ip, sport, dst_ip, dport)

        self.trapt.logger['network'].logger.info(log_message)

    def port_disposition(self):
        """
        Function to return whether or not trAPT should handle
        the received frame via UDP.  This is determined by
        checking the host and router interface tables.
        """

        for table in ('host', 'router'):
            if self.dst_ip in self.trapt.config[table].interfaces:
                interfaces = self.trapt.config[table].interfaces[self.dst_ip]
                if 'ports' in interfaces:
                    if 'udp' in interfaces['ports']:
                        if self.udp_dport in interfaces['ports']['udp']:
                            return interfaces['ports']['udp'][self.udp_dport]['state']

                if 'default_state' in interfaces:
                    return interfaces['default_state']
        return 'blocked'

    def udp_rcv_len(self):
        payload_len = 0

        if self.frame.haslayer(scapy.all.Raw):
            payload_len = len(self.frame[scapy.all.Raw].load)

        return payload_len
