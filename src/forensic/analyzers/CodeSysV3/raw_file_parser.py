import os
from pathlib import Path
from forensic.interfaces.analyzer import AnalyzerInterface, AnalyzerCLI
from forensic.analyzers.CodeSysV3.app_parser import parse_app


class CS3RawFileParserCLI(AnalyzerCLI):
    def flags(self, parser):
        pass


class CS3RawFileParser(AnalyzerInterface):
    def __init__(self, config, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.plugin_name = 'CodeSysV3'
        self.create_output_dir(self.plugin_name)

    def analyze(self):
        raw_device_dir = self.output_dir.parent.joinpath('CS3RawFileParser')
        for device in os.listdir(raw_device_dir):
            for app in os.listdir(os.path.join(raw_device_dir, device)):
                for app_fname in os.listdir(os.path.join(raw_device_dir, device, app)):
                    if app_fname.endswith(".app"):
                        self.logger.info(f'Loading file: {app}')
                        app_analyze_files_dir = Path(os.path.join(self.output_dir, device, app))
                        app_analyze_files_dir.mkdir(parents=True, exist_ok=True)
                        parse_app(os.path.join(raw_device_dir, device, app, app_fname), app_analyze_files_dir)
                        self.logger.info(f'App: {app_fname} was analyzed and the results at: {app_analyze_files_dir}')
