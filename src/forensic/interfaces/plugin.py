from __future__ import annotations
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List
from forensic.common.logger.logger import LoggerHandler
from forensic.interfaces.analyzer import AnalyzerConfig, AnalyzerInterface
from forensic.scanner.discover import Discover
from forensic.common.constants.constants import Transport
import forensic.common.constants.constants as constants
import forensic.common.modules as modules
import json
import os


class PluginInterface(ABC):
    def __init__(self, config: PluginConfig, output_dir: Path, verbose: bool):
        self.config = config
        self.output_dir = output_dir.joinpath(self.config.name)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger_handler = LoggerHandler(self.config.name, constants.LOGS_FORMATTER)
        self.logger = self.logger_handler.get_logger()
        if verbose:
            self.logger_handler.create_log_file(os.path.join(os.getcwd(), constants.LOGS_DIR, f'{self.config.name}Plugin.log'))

    def run(self):
        if not self.config.addresses:
            raise Exception("IP addresses were not provided")
        extracted = []
        discover = Discover()
        sockets = discover.get_socket_addresses(self.config.addresses)
        addresses = [socket["ip"] for socket in sockets]
        if self.config.transport == Transport.TCP.value:
            self.logger.info(f"Discovering addresses: {', '.join(addresses)}...")
            sockets = discover.scan(sockets, self.config.port)
            self.logger.info(f"Discovered addresses: {', '.join(addresses)}")
        with ThreadPoolExecutor(max_workers=30) as executor:
            for socket in sockets:
                executor.submit(self._exec, socket, extracted)
        self.logger.info(f'Found {len(extracted)} devices in port {self.config.port}')
        if extracted:
            self.export(extracted)

    def _exec(self, address: str, extracted: List):
        try:
            result = self.connect(address)
            if result:
                extracted.append(result)
        except Exception as e:
            self.logger.exception(e)

    @abstractmethod
    def connect(self, address: str):
        pass

    @abstractmethod
    def export(self, extracted):
        if self.config.cb_event is not None:
            self.config.cb_event("export", extracted)


class PluginCLI(ABC):
    def __init__(self, folder_name):
        self.folder_name = folder_name

    @abstractmethod
    def flags(self, parser):
        pass

    def get_analyzer_choices(self):
        analyzers = modules.list_subclasses(AnalyzerInterface,
                                            f"{constants.APPLICATION}.analyzers.{self.folder_name}.")
        return [analyzer.split('.')[1] for analyzer in analyzers.keys()]

    def base_flags(self, parser, port, transport):
        parser.add_argument("--ip",
                            help="Addresses file path, CIDR or IP addresses csv, add more columns for additional info about each ip (username, pass, etc...)",
                            type=Path)
        parser.add_argument("--port",
                            help=f"Port number, default is {port}",
                            default=port,
                            metavar="",
                            type=int)
        parser.add_argument("--transport",
                            help=f"tcp/udp, default is {transport.value}",
                            choices=[Transport.TCP.value, Transport.UDP.value],
                            default=transport.value,
                            type=str)
        parser.add_argument("--analyzer",
                            help="Analyzer name to run",
                            choices=self.get_analyzer_choices(),
                            type=str)


class PluginConfig(object):
    def __init__(self, name: str, addresses: List[dict], port: int, transport: Transport,
                 parameters: Dict, analyzers: List[AnalyzerConfig], cb_event: Callable[[str, Any], None] = None):
        self.name = name
        self.addresses = addresses
        self.port = port
        self.transport = transport
        self.parameters = parameters
        self.analyzers = analyzers
        self.cb_event = cb_event

    def create_config_file(self, config_file: Path):
        with open(config_file, 'w') as f:
            json.dump([self.to_json()], f, indent=4)

    @staticmethod
    def read_config_file(config_file: Path):
        with open(config_file, 'r') as f:
            return [PluginConfig.from_json(conf) for conf in json.load(f)]

    def to_json(self):
        return {"name": self.name, "port": self.port, "transport": Transport(self.transport).value,
                "addresses": self.addresses, "parameters": self.parameters,
                "analyzers": [analyzer.to_json() for analyzer in self.analyzers]}

    @staticmethod
    def from_json(json: Dict) -> PluginConfig:
        return PluginConfig(
            name=json["name"],
            addresses=json["addresses"],
            port=json["port"],
            transport=Transport(json["transport"]),
            parameters=json["parameters"],
            analyzers=[AnalyzerConfig.from_json(analyzer) for analyzer in json["analyzers"]]
        )

    @staticmethod
    def get_analyzers_config(plugin_configs):
        analyzers_config = []
        for plugin_config in plugin_configs:
            if plugin_config.analyzers:
                analyzers_config.extend(plugin_config.analyzers)
        return analyzers_config
