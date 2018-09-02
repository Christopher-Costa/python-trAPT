import config.json
import tools.ip
import tools.port
import tools.number
import ipaddress
import sys

class Router(config.json.Json):

    def __init__(self, trapt):
        self.trapt = trapt
        self.route_table = {}
        self.interfaces = {}

        self.trapt.logger['app'].logger.info("Loading routing configuration")
        config.json.Json.__init__(self, trapt, trapt.arguments.routers)
        self.trapt.logger['app'].logger.info("Complete")

        self.trapt.logger['app'].logger.info("Building route table...")
        self.build_interface_table()
        self.build_route_table()
        self.trapt.logger['app'].logger.info("Complete")

    def validate_config(self):
        """
        Verify that the supplied router configuration contains
        reasonable and valid information, to the extent
        possible.

        Router configurations are expected in the following format:

            {
                "<router identifier - ip address or name> : {
                    "links" : [
                        { 
                            "network" : "<ip CIDR range or subnet>", 
                            "address" : "<local subnet address>", 
                            "latency" : "<added latency in ms>",
                            "external" : "<0 or 1, optional>
                        },
                        ...
                    ],
                    "upstream" : "<next hop IP address>"
                },
                ...
            }

        If problems are detected, Print an informative message 
        and exit the program.  An upstream of "0.0.0.0" refers
        to the physical monitored network.
        """

        errors = []
        for router in self.config:
            for link in self.config[router]['links']:
                network = link['network']
                address = link['address']
                latency = link['latency']
                external = link['external'] if 'external' in link else 0

                if not tools.ip.is_ipv4_network(network):
                    error_message = 'link network "{0}" is not a valid IPv4 network.'
                    errors.append(error_message.format(network))

                if not tools.ip.is_ipv4_address(address):
                    error_message = 'link address "{0}" is not a valid IPv4 address.' 
                    errors.append(error_message.format(address))

                if not (tools.number.is_integer(latency) and int(latency) > 0):
                    error_message = 'latency value "{0}" is not a postive integer.'
                    errors.append(error_message.format(latency))

                if not (int(external) == 0 or int(external) == 1):
                    error_message = 'external value "{0}" should be 0 or 1.'
                    errors.append(error_message.format(external))

            upstream = self.config[router]['upstream']
            if not tools.ip.is_ipv4_network(upstream):
                error_message = 'route network "{0}" is not a valid IPv4 address.'
                errors.append(error_message.format(upstream))

            for protocol in ('tcp', 'udp'): 
                if protocol in self.config[router]['ports']:
                    for ports in self.config[router]['ports'][protocol]:
                        if not tools.port.is_port(ports) and not tools.port.is_port_range(ports):
                            error_message = '"{0}" is not a valid port or port range.'
                            errors.append(error_message.format(ports))

                        if not 'state' in self.config[router]['ports'][protocol][ports]:
                            error_message = '"{0}" {1} port "{2}" definition missing "state".'
                            errors.append(error_message.format(router, protocol, ports))
                        elif not self.config[router]['ports'][protocol][ports]['state'] in ('open', 'blocked', 'reset'):
                            error_message = '"{0}" {1} port state of {2} is invalid.'
                            errors.append(error_message.format(router, protocol, self.config[router][protocol]))
        
            for protocol in ('icmp'):
                if protocol in self.config[router]:
                    if not 'state' in self.config[router]['ports'][protocol]:
                        error_message = '"{0}" icmp port definition missing "state".'
                        errors.append(error_message.format(router))
                    elif not self.config[router][protocol]['ports'][protocol]['state'] in ('open', 'blocked'):
                        error_message = '"{0}" icmp port state of {1} is invalid.'
                        errors.append(error_message.format(router, self.config[router][protocol]))


        if errors:
            for error in errors:
                error_message ='Error validating router config: {0}'
                self.trapt.logger['app'].logger.error(error_message.format(error))
            sys.exit()

    def build_interface_table(self):
        """
        From the router config, assemble a table of all router interfaces,
        upstreams, and interface latency.
        
        """
        
        for router in self.config:
            links = self.config[router]['links']
            upstream = self.config[router]['upstream']

            for link in links:
                address = link['address']
                self.interfaces[address] = {}
                self.interfaces[address]['upstream'] = upstream
                self.interfaces[address]['network'] = link['network']
                self.interfaces[address]['latency'] = int(link['latency'])
                try:
                    self.interfaces[address]['external'] = int(link['external'])
                except KeyError:
                    self.interfaces[address]['external'] = 0
        
    def build_route_table(self):
        """
        From the router config and router interface table build a table
        of the cummulative latency of all interfaces and their path
        to the outside.
        """

        errors = []    

        for route in self.interfaces:
            network = self.interfaces[route]['network']
            latency = self.interfaces[route]['latency']
            upstream = self.interfaces[route]['upstream']
            external = self.interfaces[route]['external']

            recursions = 0
            while upstream != '0.0.0.0':
                if recursions > 64:
                    error_message = 'Failed on upstream "{0}":  Too many recursions.'
                    errors.append(error_message.format(upstream))
                    break
                recursions += 1

                try:
                    if upstream == self.interfaces[upstream]['upstream']:
                        error_message = 'upstream "{0}" references itself.'
                        errors.append(error_message.format(upstream))
                        break

                    latency += self.interfaces[upstream]['latency']
                    upstream = self.interfaces[upstream]['upstream']

                except KeyError:
                    error_message = 'Error with upstream "{0}":  No such router interface.'
                    errors.append(error_message.format(upstream))
            
            self.route_table[network] = {}
            self.route_table[network]['latency'] = latency
            self.route_table[network]['external'] = external

        if errors:
            for error in errors:
                error_message = 'Error building route table: {0}'
                self.trapt.logger['app'].logger.error(error_message.format(error))
            sys.exit()

    def is_external(self, address):
        return self.interfaces[address]['external']
