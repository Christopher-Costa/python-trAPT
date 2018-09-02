import logging

class Logger():

    def __init__(self, trapt):
        self.trapt = trapt

        self.start_logger()

    def start_logger(self):
        log_path = self.trapt.config['main'].log_path
        log_name = self.trapt.config['main'].log_name

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(filename='{0}/{1}'.format(log_path, log_name))
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter(fmt='%(asctime)s: %(pathname)s %(levelname)s: %(message)s'
                                        , datefmt="%Y-%m-%d %H:%M:%S")
        fh.setFormatter(formatter)

        self.logger.addHandler(fh)
