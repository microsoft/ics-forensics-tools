from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict
from collections import defaultdict
from forensic.common.logger.logger import LoggerHandler
import forensic.common.constants.constants as constants
import os


class AnalyzerInterface(ABC):
    def __init__(self, config: AnalyzerConfig, output_dir: Path, verbose: bool):
        self.config = config
        self.output_dir = output_dir
        self.logger_handler = LoggerHandler(self.config.name, constants.LOGS_FORMATTER)
        self.logger = self.logger_handler.get_logger()
        if verbose:
            self.logger_handler.create_log_file(os.path.join(os.getcwd(), constants.LOGS_DIR, f'{self.config.name}Analyzer.log'))

    def run(self):
        try:
            self.analyze()
        except Exception as e:
            self.logger.exception(e)

    def create_output_dir(self, plugin_name):
        self.output_dir = self.output_dir.joinpath(plugin_name, self.config.name)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def analyze(self):
        pass


class AnalyzerCLI(ABC):

    @abstractmethod
    def flags(self, parser):
        pass


class AnalyzerConfig(object):
    def __init__(self, name: str, parameters: Dict):
        self.name = name
        self.parameters = defaultdict(int, parameters)

    def to_json(self):
        return {"name": self.name, "parameters": self.parameters}

    @staticmethod
    def from_json(json: Dict) -> AnalyzerConfig:
        return AnalyzerConfig(
            name=json["name"],
            parameters=json["parameters"]
        )
    def validate_config(self):
        if not isinstance(self.name, str) or not self.name.strip:
            raise ValueError("Analyzer name must not be a empty string.")
        if not isinstance(self.parameters, dict):
            raise ValueError("The Parameter must be a dictonary.")


