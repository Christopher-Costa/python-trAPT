from scapy.all import sniff
import configparser
import time

class Receiver:

    def __init__ (self, trapt):
        self.trapt = trapt

    def packet_handler(self, packet):
        """ 
        Parse the packets and pass to the appropriate protocol handler
        """
        
        #print(self.trapt.config['main'].interface + ": " + packet.summary())

    def start(self):
        """
        Begin the capture process on the configured network interface.  Pass any packets
        matching the configured filter to the handler function.
        """

        self.trapt.logger.logger.info("Starting capture on interface {0}".format(self.trapt.config['main'].interface))
        sniff(prn = self.packet_handler
                , store=0
                , filter=self.trapt.config['main'].filter
                , iface=self.trapt.config['main'].interface)
