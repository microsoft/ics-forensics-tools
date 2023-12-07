import argparse
import forensic.common.modules as modules
import forensic.common.constants.constants as constants
from forensic.client.application import Application
from forensic.interfaces.plugin import PluginConfig, PluginCLI
from forensic.interfaces.analyzer import AnalyzerConfig, AnalyzerCLI
from forensic.scanner.discover import Discover
from pathlib import Path
from typing import Dict, Any, List

class ForensicCLI(Application):
    def __init__(self):
        super().__init__()
        self.parser = argparse.ArgumentParser()
        self.parser._optionals.title = 'Application Options'

    @staticmethod
    def get_parameters(args: Dict[str, Any]):
        return {key: value for key, value in args.items() if key not in constants.ARGUMENTS and value is not None and value}

    def application_arguments(self):
        self.parser.add_argument("-s",
                                 "--save-config",
                                 help="Save config file to local folder to be edit and used later",
                                 action='store_true')
        self.parser.add_argument("-c",
                                 "--config",
                                 help="Config file path, default is config.json",
                                 metavar="",
                                 type=Path)
        self.parser.add_argument("-p",
                                 "--multiprocess",
                                 help="Number of processes to run when in use with multiple plugins/analyzers",
                                 action='store_true')
        self.parser.add_argument("-o",
                                 "--output-dir",
                                 help=f"Directory in which to output any generated files, default is {constants.OUTPUT_DIR}",
                                 default=constants.OUTPUT_DIR,
                                 metavar="",
                                 type=Path)
        self.parser.add_argument("-v",
                                 "--verbose",
                                 help="Log output to a file as well as the console",
                                 action='store_true')

    def command_arguments(self):
        plugins = modules.list_subclasses(PluginCLI, f"{constants.APPLICATION}.plugins.")
        analyzers = modules.list_subclasses(AnalyzerCLI, f"{constants.APPLICATION}.analyzers.")
        subparser = self.parser.add_subparsers(title='Available Commands', help="Description", dest="plugin",
                                               metavar="<Command>")
        for plugin in plugins:
            plugin_folder_name, plugin_class_name = plugin.split('.')
            plugin_cli = plugins[plugin](plugin_folder_name)
            plugin_parser = subparser.add_parser(plugin_cli.name, help=plugin_cli.description)
            plugin_parser._optionals.title = f'{plugin_cli.name} Command Options'
            plugin_cli.flags(plugin_parser)
            for analyzer in analyzers:
                analyzer_folder_name, analyzer_class_name = analyzer.split('.')
                if plugin_folder_name == analyzer_folder_name:
                    analyzers[analyzer]().flags(plugin_parser)


    def scan(self, config: List[PluginConfig] = None, multiprocess: bool = False, output_dir: Path = None, verbose:Path = None):
        self.application_arguments()
        self.command_arguments()
        args = self.parser.parse_args()
        if args.config:
            config = PluginConfig.read_config_file(args.config)
            super().scan(config, args.multiprocess, args.output_dir, args.verbose)
        if args.plugin:
            addresses = None
            if args.ip:
                addresses = Discover.get_addresses_from_file(args.ip)
            parameters = self.get_parameters(vars(args))
            analyzers = []
            if args.analyzer:
                analyzers = [AnalyzerConfig(args.analyzer, parameters)]
                parameters = dict()
            plugin_config = PluginConfig(args.plugin, addresses, args.port, args.transport, parameters, analyzers)
            if args.save_config:
                plugin_config.create_config_file(constants.CONFIG_FILE)
                self.logger.info("Successfully created config.json file")
            super().scan([plugin_config], args.multiprocess, args.output_dir, args.verbose)
