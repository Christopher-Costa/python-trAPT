import configparser

class Main():

    def __init__(self, trapt):
        self.trapt = trapt

        self.parse_configuration()

    def parse_configuration(self):
        cp = configparser.ConfigParser()
        cp.read(self.trapt.arguments.config)

        self.interface = cp.get('general', 'interface')

        try:
            self.filter = cp.get('general', 'filter')
        except configparser.NoOptionError:
            self.filter = ''

        try:
            self.log_path = cp.get('logging', 'log_path')
        except configparser.NoOptionError:
            self.log_path = '/var/log/trapt'

        try:
            self.log_name = cp.get('logging', 'log_name')
        except configparser.NoOptionError:
            self.log_name = 'trapt.log'
