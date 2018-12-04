import configparser

class Config():

    def __init__(self, trapt, file):
        self.trapt = trapt
        self.file = file
        self.parse_configuration()

    def parse_configuration(self):
        cp = configparser.ConfigParser()
        cp.read(self.file)

        self.settings = {}
        for section in cp.sections():
            self.settings[section] = {}
            for option in cp.options(section):
                self.settings[section][option] = cp.get(section, option)
