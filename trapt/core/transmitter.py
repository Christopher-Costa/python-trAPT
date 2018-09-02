import scapy.all
import queue
import threading

class Transmitter():

    def __init__(self, trapt):
        self.trapt = trapt
        self.interface = self.trapt.config['main'].settings['general']['interface']
        self.tx_queue = queue.Queue(maxsize=256)

        self.worker = threading.Thread(target=self.process_queue, args=())
        self.worker.setDaemon(True)
        self.worker.start()

        self.trapt.logger['app'].logger.info("Process started")

    def process_queue(self):
        """
        Worker thread function to process frames in the tx_queue 
        and send them on the wire. 

        If the frame has an Ethernet header use the L2 scapy send
        function 'sendp', otherwise use the normal L3 scay send 
        function 'send'.
        """

        while True:
            frame = self.tx_queue.get()
            if frame.haslayer(scapy.all.Ether):
                scapy.all.sendp(frame, iface=self.interface, verbose=False)
            else:
                scapy.all.send(frame, verbose=False)

    def enqueue(self, frame):
        """
        Function for handlers to add to the queue.
        """

        self.tx_queue.put(frame)
