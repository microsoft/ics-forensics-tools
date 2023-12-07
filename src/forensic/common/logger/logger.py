import logging

class LoggerHandler(object):
    def __init__(self, name, formatter):
        self.name = name
        self.formatter = formatter
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.DEBUG)
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(self.formatter))
        self.logger.addHandler(console)

    def get_logger(self):
        return self.logger

    def create_log_file(self, file_name):
        file = logging.FileHandler(file_name)
        file.setFormatter(logging.Formatter(self.formatter))
        self.logger.addHandler(file)
