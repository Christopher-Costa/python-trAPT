import config.json
import tools.ip
import tools.port
import tools.number
import sys

class Router(config.json.Json):

    def __init__(self, config_file):
        print("Loading routing configuration...")
        config.json.Json.__init__(self, config_file)
        print("Loading complete...")

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
                    "routes": [
                        { 
                            "network" : "<CIDR range>" , 
                            "next_hop" : "<next hop IP address>" 
                        },
                        ...
                    ]
                },
                ...
            }

        If problems are detected, Print an informative message 
        and exit the program.
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

            for route in self.config[router]['routes']:
                network = route['network']
                next_hop = route['next_hop']

                if not tools.ip.is_ipv4_network(network):
                    errors.append('route network "{0}" is not a valid IPv4 network.'.format(network))
                
                if not tools.ip.is_ipv4_address(next_hop):
                    errors.append('next-hop address "{0}" is not a valid IPv4 address.'.format(next_hop))

        if errors:
            print('Error validating router config:')
            for error in errors:
                print('  ' + error)
            sys.exit()

