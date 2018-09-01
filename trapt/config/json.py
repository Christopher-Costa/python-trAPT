import json

class Json(): 

    def __init__(self, config_file):
        self.config_file = config_file
        self.parse_config()

    def parse_config(self):
        with open(self.config_file) as config_file:
            self.config = json.load(config_file)
