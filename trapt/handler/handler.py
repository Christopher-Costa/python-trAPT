class Handler():

    def __init__(self, frame, trapt):
        self.frame = frame
        self.trapt = trapt

    def handle(self):
        """
        This function is expected to be overloaded in subclasses.
        """

        return True

    def latency(self, address):
        """
        Function to look up the latency in the trAPT configuration data for
        a provided IP address.  If the host couldn't be looked up, simply
        return 0.
        """

        for table in ('host', 'router'):
            if address in self.trapt.config[table].interfaces:
                return self.trapt.config[table].interfaces[address]['latency']
        return 0


