import scapy.all
import queue
import time
import threading

class Transmitter():

    def __init__(self, trapt):
        self.trapt = trapt
        self.interface = self.trapt.config['main'].settings['general']['interface']
        self.tx_queue = queue.Queue(maxsize=256)

        self.worker = threading.Thread(target=self.monitor_queue, args=())
        self.worker.setDaemon(True)
        self.worker.start()

        self.trapt.logger['app'].logger.info("Process started")

    def monitor_queue(self):
        """
        Worker thread function to process frames in the tx_queue 
        and send them on the wire. 

        If the frame has an Ethernet header use the L2 scapy send
        function 'sendp', otherwise use the normal L3 scay send 
        function 'send'.
        """

        while True:
            item = self.tx_queue.get()
            job = threading.Thread(target=self.dequeue, args=(item,))
            job.setDaemon(True)
            job.start()
            #self.dequeue(frame)

    def enqueue(self, frame):
        """
        Function for handlers to add to the queue.
        """

        self.tx_queue.put(frame)

    def dequeue(self, item):
        """
        Function to send the dequeue item as a dict structure containing a frame
        and an integer latency value, representing how many milliseconds to 
        pause before transmitting..
        """

        frame = item['frame']
        latency = item['latency']    

        time.sleep(int(latency)/1000)
        if frame.haslayer(scapy.all.Ether):
            scapy.all.sendp(frame, iface=self.interface, verbose=False)
        else:
            scapy.all.send(frame, verbose=False)
