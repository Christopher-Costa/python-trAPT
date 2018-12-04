import core.receiver
import core.transmitter

class Interface():

    def __init__(self, trapt, name):
        self.name = name
        self.trapt = trapt
        self.transmitter = core.transmitter.Transmitter(self, trapt)
        self.receiver = core.receiver.Receiver(self, trapt)
