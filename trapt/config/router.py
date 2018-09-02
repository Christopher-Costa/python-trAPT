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

        print("Loading routing configuration...")
        config.json.Json.__init__(self, trapt.arguments.routers)
        print("Complete...")

        print("Building route table...")
        self.build_interface_table()
        self.build_route_table()
        print("Complete...")

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
                            "latency" : "<added latency in ms>"
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

                if not tools.ip.is_ipv4_network(network):
                    errors.append('link network "{0}" is not a valid IPv4 network.'.format(network))

                if not tools.ip.is_ipv4_address(address):
                    errors.append('link address "{0}" is not a valid IPv4 address.'.format(address))

                if not (tools.number.is_integer(latency) and int(latency) > 0):
                    errors.append('latency value "{0}" is not a postive integer.'.format(latency))

            upstream = self.config[router]['upstream']
            if not tools.ip.is_ipv4_network(upstream):
                errors.append('route network "{0}" is not a valid IPv4 address.'.format(upstream))

        if errors:
            print('Error validating router config:')
            for error in errors:
                print('  ' + error)
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
                self.interfaces[address]['latency'] = int(link['latency'])
        
    def build_route_table(self):
        """
        From the router config and router interface table build a table
        of the cummulative latency of all interfaces and their path
        to the outside.
        """

        errors = []    

        for route in self.interfaces:
            latency = self.interfaces[route]['latency']
            upstream = self.interfaces[route]['upstream']

            recursions = 0
            while upstream != '0.0.0.0':
                if recursions > 64:
                    errors.append('Failed on upstream "{0}:  Too many recursions.'.format(upstream))
                    break
                recursions += 1

                try:
                    if upstream == self.interfaces[upstream]['upstream']:
                        errors.append('upstream "{0}" references itself.'.format(upstream))
                        break

                    latency += self.interfaces[upstream]['latency']
                    upstream = self.interfaces[upstream]['upstream']

                except KeyError:
                    errors.append('Error with upstream "{0}":  No such router interface.'.format(upstream))
            
        self.route_table[route] = latency

        if errors:
            print('Error building route table:')
            for error in errors:
                print('  ' + error)
            sys.exit()
                
