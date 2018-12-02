import scapy.all
import handler.arp
import handler.icmp
import handler.tcp
import configparser
import time

class Receiver():

    def __init__ (self, trapt):
        self.trapt = trapt
        self.interface = self.trapt.config['main'].settings['general']['interface']
        self.filter = self.trapt.config['main'].settings['general']['filter']

    def frame_handler(self, frame):
        """ 
        Function to parse the sniffed frames and pass to the appropriate 
        protocol handler.
        """

        if frame.haslayer(scapy.all.ARP):
            handler.arp.Arp(frame, self.trapt)

        elif frame.haslayer(scapy.all.ICMP):
            handler.icmp.Icmp(frame, self.trapt)

        elif frame.haslayer(scapy.all.TCP):
            if handler.tcp.connection_exists(frame):
                connection_key = handler.tcp.connection_key(frame)
                existing_connection = handler.tcp.Tcp.connection_table[connection_key]
                existing_connection.handle(frame)
            else:
                handler.tcp.Tcp(frame, self.trapt)

    def start(self):
        """
        Process to begin the capture process on the configured network interface
        and pass any frames matching the configured filter to the handler function.
        """

        self.trapt.logger['app'].logger.info("Starting capture on interface {0}".format(self.interface))
        scapy.all.sniff(prn = self.frame_handler, store=0, filter=self.filter, iface=self.interface)
