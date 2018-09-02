import logger.logger

class App(logger.logger.Logger):

    def __init__(self, trapt):
        self.trapt = trapt
        self.log_name = self.trapt.config['main'].settings['app_logging']['log_name']
        self.log_path = self.trapt.config['main'].settings['app_logging']['log_path']

        logger.logger.Logger.__init__(self, self.log_path, self.log_name)
