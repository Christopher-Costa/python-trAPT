import config.json
import tools.ip
import sys

class Host(config.json.Json):

    def __init__(self, config_file, router_config):
        self.router_config = router_config

        print("Loading host configuration...")
        config.json.Json.__init__(self, config_file)
        print("Loading complete...")

        self.validate_host_config()

    def validate_host_config(self):
        for host_range in self.config:
            if (not tools.ip.is_ipv4_address(host_range) and not tools.ip.is_ipv4_range(host_range)):
                print ('"' + host_range + '" is not a valid IPv4 address or IPv4 range')
                sys.exit()

#            if not self.config[host_range]['gateway'] in self.router_config.config:
#                raise Exception('host range "' + host_range + '" references non-existant gateway')
            
            for host in tools.ip.ipv4_address_list(host_range):
                pass
