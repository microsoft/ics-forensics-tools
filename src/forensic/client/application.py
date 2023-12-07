import os
import forensic.common.constants.constants as constants
from forensic.common.constants.constants import Parallelism
from forensic.common.logger.logger import LoggerHandler
from forensic.interfaces.plugin import PluginConfig
import forensic.plugins
import forensic.analyzers
from multiprocessing import Pool
from pathlib import Path
from typing import List


class Application(object):
    def __init__(self):
        self.logger_handler = LoggerHandler(constants.LOG_FILE_NAME, constants.LOGS_FORMATTER)
        self.logger = self.logger_handler.get_logger()

    def _exec(self, config):
        forensic.__resources__[config.name](config, constants.OUTPUT_DIR, constants.VERBOSE).run()

    def execute_by_config(self, configs: List[PluginConfig]):
        if constants.PARALLELISM == constants.Parallelism.MULTIPROCESSING:
            with Pool(processes=len(configs)) as p:
                p.starmap(self._exec, [(config, ) for config in configs])
        elif constants.PARALLELISM == constants.Parallelism.OFF:
            for config in configs:
                self._exec(config)

    def scan(self, config: List[PluginConfig], multiprocess: bool = False, output_dir: Path = None, verbose:Path = None):
        try:
            if verbose:
                constants.VERBOSE = verbose
                Path(constants.LOGS_DIR).mkdir(parents=True, exist_ok=True)
                self.logger_handler.create_log_file(os.path.join(os.getcwd(), constants.LOGS_DIR, constants.LOG_FILE_NAME))
            if output_dir:
                constants.OUTPUT_DIR = output_dir
            if multiprocess:
                constants.PARALLELISM = Parallelism.MULTIPROCESSING
                self.logger.info("Enabled multiprocessing")
            if config:
                analyzers_config = PluginConfig.get_analyzers_config(config)
                if analyzers_config:
                    self.logger.info("Started analyzing...")
                    self.execute_by_config(analyzers_config)
                    self.logger.info("Finished analyzing...")
                else:
                    self.logger.info("Started scanning...")
                    self.execute_by_config(config)
                    self.logger.info("Finished scanning...")
        except Exception as e:
            self.logger.exception(e)
