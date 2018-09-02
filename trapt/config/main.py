import configparser

class Main():

    def __init__(self, trapt):
        self.trapt = trapt
        self.parse_configuration()

    def parse_configuration(self):
        cp = configparser.ConfigParser()
        cp.read(self.trapt.arguments.config)

        self.settings = {}
        for section in cp.sections():
            self.settings[section] = {}
            for option in cp.options(section):
                self.settings[section][option] = cp.get(section, option)
