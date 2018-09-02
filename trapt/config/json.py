import json
import sys

class Json(): 

    def __init__(self, trapt, config_file):
        self.trapt = trapt
        self.config_file = config_file
        self.parse_config()
        self.validate_config()

    def parse_config(self):
        try:
            with open(self.config_file) as config_file:
                self.config = json.load(config_file)
        except ValueError as error:
            self.trapt.logger.logger.error("Unable to load configuration from {0}: {1}".format(self.config_file, error))
            sys.exit()  

    def validate_config(self):
        return True
