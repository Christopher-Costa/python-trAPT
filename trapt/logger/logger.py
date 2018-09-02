import logging

class Logger():

    def __init__(self, log_path, log_name):
        self.log_path = log_path
        self.log_name = log_name
        self.start_logger()

    def start_logger(self):
        self.logger = logging.getLogger('{0}_{1}'.format(self.log_path, self.log_name))

        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(filename='{0}/{1}'.format(self.log_path, self.log_name))
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter(fmt='%(asctime)s: %(pathname)s %(levelname)s: %(message)s'
                                        , datefmt="%Y-%m-%d %H:%M:%S")
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
