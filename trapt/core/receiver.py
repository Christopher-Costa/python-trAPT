from scapy.all import sniff
import configparser
import time

class Receiver:

    def __init__ (self, trapt):
        self.trapt = trapt
        self.interface = self.trapt.config['main'].settings['general']['interface']
        self.filter = self.trapt.config['main'].settings['general']['filter']

    def packet_handler(self, packet):
        """ 
        Parse the packets and pass to the appropriate protocol handler
        """
        
        #print(self.interface + ": " + packet.summary())

    def start(self):
        """
        Begin the capture process on the configured network interface.  Pass any packets
        matching the configured filter to the handler function.
        """

        self.trapt.logger['app'].logger.info("Starting capture on interface {0}".format(self.interface))
        sniff(prn = self.packet_handler, store=0, filter=self.filter, iface=self.interface)
