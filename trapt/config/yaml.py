import tools.ip
import yaml
import sys

class Yaml(): 

    def __init__(self, trapt, config_file):
        self.trapt = trapt
        self.config_file = config_file
        self.parse_config()
        self.validate_config()

    def parse_config(self):
        try:
            with open(self.config_file) as config_file:
                self.config = yaml.load(config_file, Loader=yaml.FullLoader)
        except ValueError as error:
            self.trapt.logger['app'].logger.error("Unable to load configuration from {0}: {1}".format(self.config_file, error))
            sys.exit()  

    def validate_config(self):
        return True

    def validate_port_configuration(self, port_config):
        for protocol in ('tcp', 'udp'): 
            if protocol in port_config:
                for ports in port_config[protocol]:
                    if not tools.port.is_port(ports) and not tools.port.is_port_range(ports):
                        error_message = '"{0}" is not a valid port or port range.' 
                        self.errors.append(error_message.format(ports))

                    if not port_config[protocol][ports] in ('open', 'blocked', 'reset'):
                        error_message = '"{0}" {1} port state of {2} is invalid.'
                        self.errors.append(error_message.format(hosts, protocol, self.config[hosts][protocol]))
    
        for protocol in ('icmp',):
            if protocol in port_config:
                if not port_config[protocol] in ('open', 'blocked'):
                    error_message = '"{0}" icmp port state of {1} is invalid.'
                    self.errors.append(error_message.format(hosts, self.config[hosts][protocol]))
