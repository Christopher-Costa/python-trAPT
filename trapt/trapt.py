import argparse
import core.interface
import logger.app
import logger.network
import config.config
import config.router
import config.host

class TrAPT():

    def __init__(self, argv):
        self.argv = argv
        self.parse_arguments()

        self.config = {}
        self.config['main']       = config.config.Config(self, self.arguments.config)
        self.config['interfaces'] = config.config.Config(self, self.arguments.interfaces)

        self.logger = {}
        self.logger['app'] = logger.app.App(self)
        self.logger['network'] = logger.network.Network(self)

        self.config['router'] = config.router.Router(self)
        self.config['host'] = config.host.Host(self)        

        self.initialize_interfaces()

    def initialize_interfaces(self):
        self.interface = {}
        for interface in self.config['interfaces'].settings:
            self.interface[interface] = core.interface.Interface(self, interface)

    def parse_arguments(self):

        ap = argparse.ArgumentParser( description='Run the trAPT virtual deception network environment')
        ap.add_argument('-c', '--config',     default='etc/config.ini' , help='path to configuration file')
        ap.add_argument('-i', '--interfaces', default='etc/interfaces.ini' , help='path to configuration file')
        ap.add_argument('-r', '--routers',    default='etc/routers.ini', help='path to router definitions file')
        ap.add_argument('-o', '--hosts',      default='etc/hosts.ini'  , help='path to host definitions file')

        self.arguments = ap.parse_args(self.argv)
