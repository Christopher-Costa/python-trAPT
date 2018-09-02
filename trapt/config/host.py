import config.json
import tools.ip
import tools.port
import sys

class Host(config.json.Json):

    def __init__(self, trapt):
        self.trapt = trapt

        print("Loading host configuration...")
        config.json.Json.__init__(self, trapt.arguments.hosts)
        print("Loading complete...")

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
                errors.append('host "{0}" is not a valid IPv4 address or IPv4 range.'.format(hosts))

            gateway = self.config[hosts]['gateway']    
            if not tools.ip.is_ipv4_address(gateway):
                errors.append('gateway "{0}" is not a valid IPv4 address.'.format(gateway))

            if not gateway in self.trapt.config['router'].interfaces:
                errors.append('gateway "{0}" does not exist in router configuration.'.format(gateway))
           
            for ports in self.config[hosts]['ports']:
                if not tools.port.is_port(ports) and not tools.port.is_port_range(ports):
                    errors.append('"{0}" is not a valid port or port range.'.format(ports))

        if errors:
            print('Error validating host config:')
            for error in errors:
                print('  ' + error)
            sys.exit()
