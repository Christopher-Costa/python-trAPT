import handler.handler
import scapy.all
import random

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

class Tcp(handler.handler.Handler):

    connection_table = {}
    
    def __init__(self, frame, trapt):
        handler.handler.Handler.__init__(self, frame, trapt)

        self.src_ip = self.frame[scapy.all.IP].src
        self.dst_ip = self.frame[scapy.all.IP].dst
        self.tcp_sport = self.frame[scapy.all.TCP].sport
        self.tcp_dport = self.frame[scapy.all.TCP].dport
        self.tcp_state = 'LISTEN'

        if self.should_handle():
            self.add_connection()
            self.handle(self.frame)

    def handle(self, frame):
        """
        Function to process TCP messages and handle accordingly.
        Actions may include filtering, generate one or more response,
        or invoking other handlers.
        """

        self.tcp_rcv_seq = frame[scapy.all.TCP].seq
        self.tcp_rcv_ack = frame[scapy.all.TCP].ack
        self.tcp_rcv_flags = frame[scapy.all.TCP].flags
        tcp_options = frame[scapy.all.TCP].options
        
        self.log_packet('received', self.src_ip, self.tcp_sport, self.dst_ip, self.tcp_dport
                        , self.tcp_rcv_flags, self.tcp_rcv_seq, self.tcp_rcv_ack)

        if self.should_establish_connection():
            self.send_syn_ack()

    def send_syn_ack(self):
        """
        Function to create a properly formatted SYN-ACK packet and
        place in the transmit queue.
        """

        latency = self.latency(self.dst_ip)

        self.tcp_snd_seq = self.sequence_number()
        self.tcp_snd_ack = self.tcp_rcv_seq + 1
        self.state = 'SYN-RECEIVED'

        packet = {}
        packet['IP'] = scapy.all.IP(src = self.dst_ip
                                    , dst = self.src_ip) 

        packet['TCP'] = scapy.all.TCP(sport = self.tcp_dport
                                        , dport = self.tcp_sport
                                        , seq = self.tcp_snd_seq
                                        , ack = self.tcp_snd_ack
                                        , flags = 'SA')
 
        tcp_reply = packet['IP']/packet['TCP']
        self.trapt.transmitter.enqueue({ 'frame' : tcp_reply, 'latency' : latency })

    def should_handle(self):
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
                        if str(self.tcp_dport) in interfaces['ports']['tcp']:
                            if interfaces['ports']['tcp'][str(self.tcp_dport)]['state'] == 'open':
                                return True
                
                if 'default_state' in interfaces:
                    if interfaces['default_state'] == 'open':
                        return True
        return False

    def should_establish_connection(self):
        """
        Function to check the received frame and determine if it is a valid
        connection establishment attempt (SYN) packet.

        Return True if so, False if not.
        """

        flags = str(self.tcp_rcv_flags)
        if self.tcp_state == 'LISTEN':
            if ('S' in flags 
                    and not 'A' in flags
                    and not 'F' in flags
                    and not 'R' in flags
                    and not 'P' in flags):
                return True
        return False

    def sequence_number(self):
        """
        Function to return a suitable initial sequence number (ISN)
        """

        return random.randint(100000,10000000)

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
