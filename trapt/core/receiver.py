import threading
import scapy.all
import handler.arp
import handler.icmp
import handler.tcp
import handler.udp
import configparser
import time

class Receiver():

    def __init__ (self, interface, trapt):
        self.trapt = trapt
        self.interface = interface
        self.filter = self.trapt.config['interfaces'].settings[self.interface.name]['filter']


        self.trapt.logger['app'].logger.info("Starting capture on interface {0}".format(self.interface.name))
        self.worker = threading.Thread(target=self.start_capture, args=())
        self.worker.setDaemon(False)
        self.worker.start()
        self.trapt.logger['app'].logger.info("Capture started on interface {0}".format(self.interface.name))

    def frame_handler(self, frame):
        """ 
        Function to parse the sniffed frames and pass to the appropriate 
        protocol handler.
        """

        if frame.haslayer(scapy.all.ARP):
            handler.arp.Arp(frame, self.trapt, self.interface)

        elif frame.haslayer(scapy.all.ICMP):
            handler.icmp.Icmp(frame, self.trapt, self.interface)

        elif frame.haslayer(scapy.all.UDP):
            handler.udp.Udp(frame, self.trapt, self.interface)

        elif frame.haslayer(scapy.all.TCP):
            if handler.tcp.connection_exists(frame):
                connection_key = handler.tcp.connection_key(frame)
                existing_connection = handler.tcp.Tcp.connection_table[connection_key]
                existing_connection.handle(frame)
            else:
                handler.tcp.Tcp(frame, self.trapt, self.interface)

    def start_capture(self):
        """
        Process to begin the capture process on the configured network interface
        and pass any frames matching the configured filter to the handler function.
        """

        scapy.all.sniff(prn = self.frame_handler, store=0, filter=self.filter, iface=self.interface.name)
