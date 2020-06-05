import config.identity
import handler.handler
import handler.ip
import tools.nmap
import scapy.all
import random
import time

def connection_exists(frame):
    """
    Helper function to check the Tcp class connection_table for an 
    existing connection matching the frame four tuple.

    Return True if a connection is found, otherwise return False.
    """

    if connection_key(frame) in Tcp.connection_table:
        return True
    return False

def connection_key(frame):
    """
    Helper function to return a properly formatted connection_table
    key.
    """

    src_ip = frame[scapy.all.IP].src
    dst_ip = frame[scapy.all.IP].dst
    src_port = str(frame[scapy.all.TCP].sport)
    dst_port = str(frame[scapy.all.TCP].dport)

    return src_ip + '_' + src_port + '_' + dst_ip + '_' + dst_port

class Tcp(handler.ip.Ip):

    connection_table = {}
    
    def __init__(self, frame, trapt, interface):
        handler.ip.Ip.__init__(self, frame, trapt, interface)

        self.frame = frame
        self.tcp_sport = self.frame[scapy.all.TCP].sport
        self.tcp_dport = self.frame[scapy.all.TCP].dport
        self.last_sent = 0
        self.tcp_state = 'LISTEN'

        self.tcp_snd_seq = 0
        self.tcp_snd_ack = 0

        if self.port_disposition() != 'blocked':
            self.add_connection()
            self.handle(self.frame)

    def handle(self, frame):
        """
        Function to process TCP messages and handle accordingly.
        Actions may include filtering, generate one or more response,
        or invoking other handlers.
        """

        self.frame = frame
        self.log_packet('received', self.src_ip, self.tcp_sport, self.dst_ip, self.tcp_dport
                        , self.tcp_rcv_flags(), self.tcp_rcv_seq(), self.tcp_rcv_ack())


        if tools.nmap.is_scan_packet_t2(self):
            self.send_scan_t2_response()
            return

        if tools.nmap.is_scan_packet_t3(self):
            self.send_scan_t3_response()
            return

        if tools.nmap.is_scan_packet_t4(self):
            self.send_scan_t4_response()
            return

        if tools.nmap.is_scan_packet_t5(self):
            self.send_scan_t5_response()
            return

        if tools.nmap.is_scan_packet_t6(self):
            self.send_scan_t6_response()
            return

        if tools.nmap.is_scan_packet_t7(self):
            self.send_scan_t7_response()
            return

        if tools.nmap.is_scan_packet_ecn(self):
            self.send_scan_ecn_response()
            return

        if self.port_disposition() == 'reset':
            self.send_rst_ack()
            return

        if self.should_establish_connection():
            self.send_syn_ack()

        if self.is_tcp_rcv_flags_RA():
            self.send_rst_ack()

        if self.is_tcp_rcv_flags_R():
            self.send_rst()

        if self.is_tcp_rcv_flags_FA():
            self.send_fin_ack()

    def tcp_snd_options(self):
        snd_options = list()       
        option_ordering = list()

        identity = self.trapt.config['host'].interfaces[self.dst_ip]['identity']

        if (tools.nmap.is_scan_packet_1(self)):
            option_ordering = config.identity.identities[identity]['Options']['O1']
        elif (tools.nmap.is_scan_packet_2(self)):
            option_ordering = config.identity.identities[identity]['Options']['O2']
        elif (tools.nmap.is_scan_packet_3(self)):
            option_ordering = config.identity.identities[identity]['Options']['O3']
        elif (tools.nmap.is_scan_packet_4(self)):
            option_ordering = config.identity.identities[identity]['Options']['O4']
        elif (tools.nmap.is_scan_packet_5(self)):
            option_ordering = config.identity.identities[identity]['Options']['O5']
        elif (tools.nmap.is_scan_packet_6(self)):
            option_ordering = config.identity.identities[identity]['Options']['O6']
        elif (tools.nmap.is_scan_packet_ecn(self)):
            option_ordering = config.identity.identities[identity]['Options']['ECN']

        for option in option_ordering:
            if option == 'M':
                snd_options.append(('MSS', self.tcp_snd_mss()))
            if option == 'N':
                snd_options.append(('NOP', None))
            if option == 'W':
                snd_options.append(('WScale', self.tcp_snd_wscale()))
            if option == 'S':
                snd_options.append(('SAckOK', b''))
            if option == 'T':
                snd_options.append(('Timestamp', (self.tcp_snd_timestamp(), self.tcp_rcv_timestamp())))

        return snd_options

    def send_fin_ack(self):
        tcp_packet = scapy.all.TCP(sport = self.tcp_dport
                                 , dport = self.tcp_sport
                                 , seq = self.tcp_snd_seq
                                 , ack = self.tcp_rcv_seq() + self.tcp_rcv_len()
                                 , options = self.tcp_snd_options()
                                 , window = self.tcp_snd_window()
                                 , flags = 'FA')

        self.send_packet(tcp_packet)
        self.remove_connection()
        self.log_packet('sent', self.dst_ip, self.tcp_dport, self.src_ip, self.tcp_sport
                        , 'FA', self.tcp_snd_seq, self.tcp_snd_ack)
        

    def send_rst(self):
        tcp_packet = scapy.all.TCP(sport = self.tcp_dport
                                 , dport = self.tcp_sport
                                 , seq = self.tcp_snd_seq
                                 , options = self.tcp_snd_options()
                                 , window = self.tcp_snd_window()
                                 , flags = 'R')

        self.send_packet(tcp_packet)
        self.remove_connection()
        self.log_packet('sent', self.dst_ip, self.tcp_dport, self.src_ip, self.tcp_sport
                        , 'R', self.tcp_snd_seq, self.tcp_snd_ack)
        
    def send_rst_ack(self):
        if (self.tcp_snd_seq == 0):
            window = 0
        else:
            window = self.tcp_snd_window()

        tcp_packet = scapy.all.TCP(sport = self.tcp_dport
                                 , dport = self.tcp_sport
                                 , seq = self.tcp_snd_seq
                                 , ack = self.tcp_rcv_seq() + self.tcp_rcv_len() 
                                 , options = self.tcp_snd_options()
                                 , window = window
                                 , flags = 'RA')

        self.send_packet(tcp_packet)
        self.remove_connection()
        self.log_packet('sent', self.dst_ip, self.tcp_dport, self.src_ip, self.tcp_sport
                        , 'RA', self.tcp_snd_seq, self.tcp_snd_ack)
        

    def send_syn_ack(self):
        """
        Function to create a properly formatted SYN-ACK packet and
        place in the transmit queue.
        """

        self.state = 'SYN-RECEIVED'
        self.tcp_snd_seq = self.initial_seq_number()
        self.send_tcp_packet(flags = 'SA')
        self.tcp_snd_seq += 1

    def port_disposition(self):
        """
        Function to return whether or not trAPT should handle 
        the received frame via TCP.  This is determined by 
        checking the host and router interface tables.
        """

        for table in ('host', 'router'):
            if self.dst_ip in self.trapt.config[table].interfaces:
                interfaces = self.trapt.config[table].interfaces[self.dst_ip]
                if 'ports' in interfaces:
                    if 'tcp' in interfaces['ports']:
                        if self.tcp_dport in interfaces['ports']['tcp']:
                            return interfaces['ports']['tcp'][self.tcp_dport]['state']
                
                if 'default_state' in interfaces:
                    return interfaces['default_state']
        return 'blocked'

    def should_establish_connection(self):
        """
        Function to check the received frame and determine if it is a valid
        connection establishment attempt (SYN) packet.

        Return True if so, False if not.
        """

        if (self.tcp_state == 'LISTEN' and
            self.is_tcp_rcv_flags_S()):
                return True
        return False

    def tcp_snd_window(self):
        """
        Function to return a suitable TCP Window Size
        """
        identity = self.trapt.config['host'].interfaces[self.dst_ip]['identity']
        return config.identity.identities[identity]['Window']

    def log_packet (self, direction, src_ip, sport, dst_ip, dport, flags, seq, ack):
        """
        Function to generate a log message to the trAPT network log message based
        on provided parameters.
        """

        log_message = 'TCP {0}: {1}:{2} -> {3}:{4}, flags={5}, seq={6} ack={7}'.format(
                direction, src_ip, sport, dst_ip, dport, flags, seq, ack)

        self.trapt.logger['network'].logger.info(log_message)

    def add_connection(self):
        """
        Function to add a new connection to the class connection_table.
        """

        self.connection_table[connection_key(self.frame)] = self

    def remove_connection(self):
        self.connection_table.pop(connection_key(self.frame))

    def tcp_rcv_timestamp(self):
        for option in self.tcp_rcv_options():
            if option[0] == 'Timestamp':
                return option[1][0]
        return 0

    def tcp_snd_timestamp(self):
        timestamp = int(time.time() * 100) % 0xFFFFFFFF
        return (timestamp)

    def is_tcp_rcv_flags_S(self):
        if ('S' in self.frame[scapy.all.TCP].flags
            and not 'A' in self.frame[scapy.all.TCP].flags
            and not 'F' in self.frame[scapy.all.TCP].flags
            and not 'R' in self.frame[scapy.all.TCP].flags
            and not 'P' in self.frame[scapy.all.TCP].flags
            and not 'U' in self.frame[scapy.all.TCP].flags):
                return True
        return False

    def is_tcp_rcv_flags_SEC(self):
        if ('S' in self.frame[scapy.all.TCP].flags
            and not 'A' in self.frame[scapy.all.TCP].flags
            and not 'F' in self.frame[scapy.all.TCP].flags
            and not 'R' in self.frame[scapy.all.TCP].flags
            and not 'P' in self.frame[scapy.all.TCP].flags
            and not 'U' in self.frame[scapy.all.TCP].flags
            and 'E' in self.frame[scapy.all.TCP].flags
            and 'C' in self.frame[scapy.all.TCP].flags):
                return True
        return False

    def is_tcp_rcv_flags_A(self):
        if ('A' in self.frame[scapy.all.TCP].flags
            and not 'S' in self.frame[scapy.all.TCP].flags
            and not 'F' in self.frame[scapy.all.TCP].flags
            and not 'R' in self.frame[scapy.all.TCP].flags
            and not 'P' in self.frame[scapy.all.TCP].flags
            and not 'U' in self.frame[scapy.all.TCP].flags):
                return True
        return False

    def has_tcp_rcv_flags_S(self):
        if 'S' in self.frame[scapy.all.TCP].flags:
            return True
        return False

    def has_tcp_rcv_flags_A(self):
        if 'A' in self.frame[scapy.all.TCP].flags:
            return True
        return False

    def has_tcp_rcv_flags_F(self):
        if 'F' in self.frame[scapy.all.TCP].flags:
            return True
        return False

    def is_tcp_rcv_flags_R(self):
        if ('R' in self.frame[scapy.all.TCP].flags
            and not 'A' in self.frame[scapy.all.TCP].flags
            and not 'F' in self.frame[scapy.all.TCP].flags
            and not 'S' in self.frame[scapy.all.TCP].flags
            and not 'P' in self.frame[scapy.all.TCP].flags
            and not 'U' in self.frame[scapy.all.TCP].flags):
                return True
        return False

    def is_tcp_rcv_flags_FA(self):
        if ('F' in self.frame[scapy.all.TCP].flags
            and 'A' in self.frame[scapy.all.TCP].flags
            and not 'R' in self.frame[scapy.all.TCP].flags
            and not 'S' in self.frame[scapy.all.TCP].flags
            and not 'P' in self.frame[scapy.all.TCP].flags
            and not 'U' in self.frame[scapy.all.TCP].flags):
                return True
        return False

    def is_tcp_rcv_flags_RA(self):
        if ('R' in self.frame[scapy.all.TCP].flags
            and 'A' in self.frame[scapy.all.TCP].flags
            and not 'F' in self.frame[scapy.all.TCP].flags
            and not 'S' in self.frame[scapy.all.TCP].flags
            and not 'P' in self.frame[scapy.all.TCP].flags
            and not 'U' in self.frame[scapy.all.TCP].flags):
                return True
        return False

    def is_tcp_rcv_flags_FPSU(self):
        if ('F' in self.frame[scapy.all.TCP].flags
            and 'S' in self.frame[scapy.all.TCP].flags
            and 'P' in self.frame[scapy.all.TCP].flags
            and 'U' in self.frame[scapy.all.TCP].flags
            and not 'A' in self.frame[scapy.all.TCP].flags
            and not 'R' in self.frame[scapy.all.TCP].flags):
                return True
        return False

    def is_tcp_rcv_flags_FPU(self):
        if ('F' in self.frame[scapy.all.TCP].flags
            and not 'S' in self.frame[scapy.all.TCP].flags
            and 'P' in self.frame[scapy.all.TCP].flags
            and 'U' in self.frame[scapy.all.TCP].flags
            and not 'A' in self.frame[scapy.all.TCP].flags
            and not 'R' in self.frame[scapy.all.TCP].flags):
                return True
        return False

    def tcp_rcv_seq(self):
        return self.frame[scapy.all.TCP].seq

    def tcp_rcv_ack(self):
        return self.frame[scapy.all.TCP].ack
        
    def tcp_rcv_flags(self):
        return self.frame[scapy.all.TCP].flags

    def tcp_rcv_window(self):
        return self.frame[scapy.all.TCP].window

    def tcp_rcv_options(self):
        return self.frame[scapy.all.TCP].options

    def tcp_rcv_urgptr(self):
        return self.frame[scapy.all.TCP].urgptr

    def tcp_rcv_reserved(self):
        return self.frame[scapy.all.TCP].reserved

    def tcp_rcv_len(self):
        len = 0

        if self.frame.haslayer(scapy.all.Raw):
            len = len(frame[scapy.all.Raw].load)

        # SYN and FIN count as a byte for purposes of acknowledging
        if (self.has_tcp_rcv_flags_S()):
            len += 1

        if (self.has_tcp_rcv_flags_F()):
            len += 1

        return len

    def tcp_snd_mss(self):
        identity = self.trapt.config['host'].interfaces[self.dst_ip]['identity']
        return config.identity.identities[identity]['MSS']

    def tcp_snd_wscale(self):
        identity = self.trapt.config['host'].interfaces[self.dst_ip]['identity']
        return config.identity.identities[identity]['WScale']

    def send_scan_t2_response(self):
        seq = 0
        ack = self.tcp_rcv_seq()
        window = 0
        flags = 'RA'

        tcp_packet = scapy.all.TCP(sport = self.tcp_dport
                                 , dport = self.tcp_sport
                                 , seq = seq
                                 , ack = ack
                                 , window = window
                                 , flags = flags)

        self.send_packet(tcp_packet)
        self.log_packet('sent NMAP T2 response', self.dst_ip, self.tcp_dport, self.src_ip, self.tcp_sport
                        , flags, seq, ack)

    def send_scan_t3_response(self):
        seq = 0
        ack = 1
        window = 0
        flags = 'RA'

        tcp_packet = scapy.all.TCP(sport = self.tcp_dport
                                 , dport = self.tcp_sport
                                 , seq = seq
                                 , ack = ack
                                 , window = window
                                 , flags = flags)

        self.send_packet(tcp_packet)
        self.log_packet('sent NMAP T3 response', self.dst_ip, self.tcp_dport, self.src_ip, self.tcp_sport
                        , flags, seq, ack)

    def send_scan_t4_response(self):
        seq = self.tcp_rcv_ack()
        ack = 1
        window = 0
        flags = 'R'

        tcp_packet = scapy.all.TCP(sport = self.tcp_dport
                                 , dport = self.tcp_sport
                                 , seq = seq
                                 , ack = ack
                                 , window = window
                                 , flags = flags)

        self.send_packet(tcp_packet)
        self.log_packet('sent NMAP T4 response', self.dst_ip, self.tcp_dport, self.src_ip, self.tcp_sport
                        , flags, seq, ack)

    def send_scan_t5_response(self):
        seq = 0
        ack = self.tcp_rcv_seq() + 1
        window = 0
        flags = 'RA'

        tcp_packet = scapy.all.TCP(sport = self.tcp_dport
                                 , dport = self.tcp_sport
                                 , seq = seq
                                 , ack = ack
                                 , window = window
                                 , flags = flags)

        self.send_packet(tcp_packet)
        self.log_packet('sent NMAP T5 response', self.dst_ip, self.tcp_dport, self.src_ip, self.tcp_sport
                        , flags, seq, ack)

    def send_scan_t6_response(self):
        seq = self.tcp_rcv_ack()
        ack = 1
        window = 0
        flags = 'R'

        tcp_packet = scapy.all.TCP(sport = self.tcp_dport
                                 , dport = self.tcp_sport
                                 , seq = seq
                                 , ack = ack
                                 , window = window
                                 , flags = flags)

        self.send_packet(tcp_packet)
        self.log_packet('sent NMAP T6 response', self.dst_ip, self.tcp_dport, self.src_ip, self.tcp_sport
                        , flags, seq, ack)

    def send_scan_t7_response(self):
        self.send_tcp_packet(flags = 'RA', window = 0, description = 'NMAP T7 response')

    def send_scan_ecn_response(self):
        self.state = 'SYN-RECEIVED'
        self.tcp_snd_seq = self.initial_seq_number()
        self.send_tcp_packet(flags = 'SAE', description = 'NMAP ECN response')
        self.tcp_snd_seq += 1

    def send_tcp_packet(self, flags, sport = None, dport = None, seq = None, ack = None
                                   , window = None, options = None, description = None):
        
        tcp_packet = scapy.all.TCP()
        tcp_packet.sport = sport or self.tcp_dport
        tcp_packet.dport = dport or self.tcp_sport
        tcp_packet.seq = seq or self.tcp_snd_seq
        tcp_packet.ack = ack or self.tcp_rcv_seq() + self.tcp_rcv_len()
        tcp_packet.window = self.tcp_snd_window() if window is None else window
        tcp_packet.options = options or self.tcp_snd_options()
        tcp_packet.flags = flags

        print (tcp_packet.window)

        direction = 'sent'
        if description:
            direction += ' ' + description

        self.send_packet(tcp_packet)
        self.log_packet(direction, self.dst_ip, tcp_packet.dport, self.src_ip, tcp_packet.sport
                                 , tcp_packet.flags, tcp_packet.seq, tcp_packet.ack)
