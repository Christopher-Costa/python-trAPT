import config.json
import tools.ip
import tools.port
import sys

class Host(config.json.Json):

    def __init__(self, trapt):
        self.trapt = trapt

        self.trapt.logger['app'].logger.info("Loading host configuration...")
        config.json.Json.__init__(self, trapt, trapt.arguments.hosts)
        self.trapt.logger['app'].logger.info("Loading complete...")

        self.trapt.logger['app'].logger.info("Building host interface table...")
        self.build_interface_table()
        self.trapt.logger['app'].logger.info("Complete")

    def validate_config(self):
        """
        Verify that the supplied host configuration contains
        reasonable and valid information, to the extent
        possible.

        Host configurations are expected in the following format:

            {
                "<address or address range> : {
                    "gateway": "XXX.XXX.XXX.XXX",
                    "default_state": "<blocked|open|reset>",
                    "ports" : {
                        "<port or port range> : { "state" : <blocked|open|reset> },
                        ...
                    }
                },
                ...
            }

        If problems are detected, Print an informative message 
        and exit the program.
        """

        errors = []
        for hosts in self.config:
            if (not tools.ip.is_ipv4_address(hosts) 
                    and not tools.ip.is_ipv4_range(hosts)):
                error_message = 'host "{0}" is not a valid IPv4 address or IPv4 range.'
                errors.append(error_message.format(hosts))

            gateway = self.config[hosts]['gateway']    
            if not tools.ip.is_ipv4_address(gateway):
                error_message = 'gateway "{0}" is not a valid IPv4 address.'
                errors.append(error_message.format(gateway))

            if (not gateway in self.trapt.config['router'].interfaces and
                    not gateway == '0.0.0.0'):
                error_message = 'gateway "{0}" does not exist in router configuration.'
                errors.append(error_message.format(gateway))
           
            for ports in self.config[hosts]['ports']:
                if not tools.port.is_port(ports) and not tools.port.is_port_range(ports):
                    error_message = '"{0}" is not a valid port or port range.'
                    errors.append(error_message.format(ports))

        if errors:
            for error in errors:
                error_message = 'Error in host config: {0}'
                self.trapt.logger['app'].logger.error(error_message.format(error))
            sys.exit()

    def build_interface_table(self):
        self.interfaces = {}
        for hosts in self.config:
            gateway = self.config[hosts]['gateway']
            if gateway in self.trapt.config['router'].interfaces:
                network = self.trapt.config['router'].interfaces[gateway]['network']
                latency = self.trapt.config['router'].route_table[network]['latency']
                external = self.trapt.config['router'].route_table[network]['external']

            elif gateway == '0.0.0.0':
                latency = 0
                external = 1

            else:
                error_message = 'gateway "{0}" does not exist in router configuration.'
                self.trapt.logger['app'].logger.error(error_message.format(error))
                sys.exit()

            for host in tools.ip.ipv4_address_list(hosts):
                self.interfaces[host] = {}
                self.interfaces[host]['latency'] = latency
                self.interfaces[host]['external'] = external

    def is_external(self, address):
        return self.interfaces[address]['external']
