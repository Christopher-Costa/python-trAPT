import config.json

class Router(config.json.Json):

    def __init__(self, config_file):
        print("Loading routing configuration...")
        config.json.Json.__init__(self, config_file)
        print("Loading complete...")
