import configparser

class Main():

    def __init__(self, config):
        self.config = config

        self.parse_configuration()

    def parse_configuration(self):
        cp = configparser.ConfigParser()
        cp.read(self.config)

        self.interface = cp.get('general', 'interface')

        try:
            self.filter = cp.get('general', 'filter')
        except configparser.NoOptionError:
            self.filter = ''
