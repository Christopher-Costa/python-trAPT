import config.yaml
import config.identity
import tools.ip
import tools.port
import sys

class Host(config.yaml.Yaml):

    def __init__(self, trapt):
        self.trapt = trapt

        self.trapt.logger['app'].logger.info("Loading host configuration...")
        config.yaml.Yaml.__init__(self, trapt, trapt.arguments.hosts)
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

            <IP address or address range>:
                identity: <type of host (OS)>
                gateway: <next hop IP address>
                default_state: <blocked|open|reset>
                ports:
                  <protocol>
                      <port or port range>: <blocked|open|reset>
                      ...
                  ...

        If problems are detected, Print an informative message 
        and exit the program.
        """
        main_config = self.trapt.config['main']
        self.errors = []

        for hosts in self.config:
            #identity = None
            if (not 'identity' in self.config[hosts]):
                if (not 'default_identity' in main_config.settings['general']):
                    error_message = 'host "{0}" does not have an identity, and no default is defined.'
                    self.errors.append(error_message.format(hosts))
                else:
                    identity = main_config.settings['general']['default_identity']
            else:
                identity = self.config[hosts]['identity']

            if not identity in config.identity.identities:
                error_message = 'host "{0}" associates with an undefined identity "{1}".'
                self.errors.append(error_message.format(hosts, identity))

            if (not tools.ip.is_ipv4_address(hosts) 
                    and not tools.ip.is_ipv4_range(hosts)):
                error_message = 'host "{0}" is not a valid IPv4 address or IPv4 range.'
                self.errors.append(error_message.format(hosts))

            gateway = self.config[hosts]['gateway']    
            if not tools.ip.is_ipv4_address(gateway):
                error_message = 'gateway "{0}" is not a valid IPv4 address.'
                self.errors.append(error_message.format(gateway))

            if (not gateway in self.trapt.config['router'].interfaces and
                    not gateway == '0.0.0.0'):
                error_message = 'gateway "{0}" does not exist in router configuration.'
                self.errors.append(error_message.format(gateway))

            self.validate_port_configuration(self.config[hosts]['ports'])

        if self.errors:
            for error in self.errors:
                error_message = 'Error in host config: {0}'
                self.trapt.logger['app'].logger.error(error_message.format(error))
            sys.exit()

    def build_interface_table(self):
        self.interfaces = {}
        for hosts in self.config:
            gateway = self.config[hosts]['gateway']
            default_state = self.config[hosts]['default_state']
            ports = self.config[hosts]['ports']

            if 'identity' in self.config[hosts]:
                identity = self.config[hosts]['identity']
            else:
                identity = self.trapt.config['main'].settings['general']['default_identity']

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
                self.interfaces[host]['ports'] = {}
                self.interfaces[host]['latency'] = latency
                self.interfaces[host]['external'] = external
                self.interfaces[host]['default_state'] = default_state
                self.interfaces[host]['identity'] = identity

                for protocol in ('tcp', 'udp'): 
                    if protocol in ports:
                        self.interfaces[host]['ports'][protocol] = {}

                        for port_range in ports[protocol]:
                            state = ports[protocol][port_range]

                            port_list = tools.port.port_list(port_range)
                            for port in port_list:
                                self.interfaces[host]['ports'][protocol][port] = {}
                                self.interfaces[host]['ports'][protocol][port]['state'] = state 

                for protocol in ('icmp',):
                    if protocol in ports:
                        state = ports[protocol]
                        self.interfaces[host]['ports'][protocol] = {}
                        self.interfaces[host]['ports'][protocol]['state'] = state 

    def is_external(self, address):
        return self.interfaces[address]['external']
