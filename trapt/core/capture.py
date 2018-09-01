from scapy.all import sniff
import configparser
import time

class Capture:

    def __init__ (self, config):
        self.config = config

    def packet_handler(self, packet):
        """ 
        Parse the packets and pass to the appropriate protocol handler
        """
        
        #print(self.config.interface + ": " + packet.summary())

    def start(self):
        """
        Begin the capture process on the configured network interface.  Pass any packets
        matching the configured filter to the handler function.
        """

        print("Starting capture on interface " + self.config.interface + "...")
        sniff(prn = self.packet_handler, store=0, filter=self.config.filter, iface=self.config.interface)
