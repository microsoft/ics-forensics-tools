import os
import json
import pandas as pd
from pathlib import Path
from forensic.interfaces.analyzer import AnalyzerInterface, AnalyzerCLI


class CS3BlockLogicCLI(AnalyzerCLI):
    def flags(self, parser):
        parser.add_argument('--logic_all', help='Execute all logics for CS3BlockLogic analyzer', action='store_true')
        parser.add_argument('--logic_author', help='Execute author logic for CS3BlockLogic analyzer',
                            action='store_true')
        parser.add_argument('--logic_dates', help='Execute date logic for CS3BlockLogic analyzer', action='store_true')
        parser.add_argument('--logic_project_info', help='Execute project info logic for CS3BlockLogic analyzer',
                            action='store_true')
        parser.add_argument('--logic_network', help='Execute network logics for CS3BlockLogic analyzer',
                            action='store_true')
        parser.add_argument('--logic_tasks', help='Execute tasks logic for CS3BlockLogic analyzer', action='store_true')


class CS3BlockLogic(AnalyzerInterface):
    def __init__(self, config, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.plugin_name = 'CodeSysV3'

        self.create_output_dir(self.plugin_name)
        self.parsed_devices_data = self.get_parsed_devices_data()

    def analyze(self):
        if self.parsed_devices_data:
            logic_all = self.config.parameters.get("logic_all")
            logic_author = self.config.parameters.get("logic_author")
            logic_dates = self.config.parameters.get("logic_dates")
            logic_project_info = self.config.parameters.get("logic_project_info")
            logic_network = self.config.parameters.get("logic_network")
            logic_tasks = self.config.parameters.get("logic_tasks")

            self.logger.info('Start executing block logics')

            if logic_all or logic_author:
                self.author_check()
            if logic_all or logic_dates:
                self.dates_check()
            if logic_all or logic_project_info:
                self.project_info_check()
            if logic_all or logic_network:
                self.network_check()
            if logic_all or logic_tasks:
                self.tasks_check()

    def get_parsed_devices_data(self):
        devices_dir = self.output_dir.parent.joinpath('CS3RawFileParser')
        if not devices_dir.is_dir():
            self.logger.error('Please run CS3RawFileParser analyzer first')
            return {}
        devices_project_info = {}
        devices_tasks = {}
        devices_symbols = {}

        for device in os.listdir(devices_dir):
            device_ip = device.replace("_", ".")
            devices_project_info[device_ip] = {}
            devices_tasks[device_ip] = {}
            devices_symbols[device_ip] = {}
            for app in os.listdir(os.path.join(devices_dir, device)):
                for out in os.listdir(os.path.join(devices_dir, device, app)):
                    if out == "project_info.json":
                        with open(os.path.join(devices_dir, device, app, out), 'r') as f:
                            devices_project_info[device_ip][app] = json.load(f)
                    if out == "taskinfo.json":
                        with open(os.path.join(devices_dir, device, app, out), 'r') as f:
                            devices_tasks[device_ip][app] = json.load(f)
                    if out == "symbols.csv":
                        devices_symbols[device_ip][app] = pd.read_csv(
                            os.path.join(devices_dir, device, app, out), names=['pointer', 'name'])

        return {'devices_project_info': devices_project_info,
                'devices_tasks': devices_tasks,
                'devices_symbols': devices_symbols}

    def tasks_check(self):
        self.logger.debug('executing tasks check')
        for device in self.parsed_devices_data['devices_tasks'].keys():
            str = f'Check tasks for IP: {device}'
            for app in self.parsed_devices_data['devices_tasks'][device].keys():
                if self.parsed_devices_data['devices_tasks'][device][app]:
                    tasks_amount = len(self.parsed_devices_data['devices_tasks'][device][app])
                    str += f'\n\t{app} has {tasks_amount} configured tasks'
                    for task in self.parsed_devices_data['devices_tasks'][device][app]:
                        str += '\n\tTask name: {}, parameters: {}'.format(task['name'], task['taskinfo'])
                else:
                    str += f'\n\tNo tasks were found for app: {app}'
                self.logger.info(str)

    def load_netlibs(self):
        with open(Path(os.path.dirname(__file__)).joinpath('mapping', 'network_libraries.json'), 'rb') as f:
            return json.loads(f.read())

    def network_check(self):
        self.logger.debug('executing block network check')
        netlibs_mapping = self.load_netlibs()
        netlib_names = netlibs_mapping.keys()

        for device in self.parsed_devices_data['devices_symbols'].keys():
            str = f'Check network libraries usage for IP: {device}'
            for app in self.parsed_devices_data['devices_symbols'][device].keys():
                symbols_df = self.parsed_devices_data['devices_symbols'][device][app]
                used_netlibs = symbols_df.loc[symbols_df['name'].isin(netlib_names)]
                if not used_netlibs.empty:
                    str += '\n\tApp: {} have usage of network libraries: {}'.format(app, used_netlibs.name.tolist())
                else:
                    str += f'\n\tNo network libraries were found for app: {app}'
                self.logger.info(str)

    def dates_check(self):
        self.logger.debug('executing project dates check')
        for device in self.parsed_devices_data['devices_project_info'].keys():
            str = f'Check projects build dates for IP: {device}'
            for app in self.parsed_devices_data['devices_project_info'][device].keys():
                project_info = self.parsed_devices_data['devices_project_info'][device][app]
                if 'project_build_datetime' in project_info.keys():
                    str += '\n\tApp: {}, build datetime: {}'.format(app, project_info['project_build_datetime'])
                else:
                    str += '\n\tNo build datetime found for app: {}'.format(app)
                self.logger.info(str)

    def project_info_check(self):
        self.logger.debug('executing project information check')
        for device in self.parsed_devices_data['devices_project_info'].keys():
            str = f'Check projects info for IP: {device}'
            for app in self.parsed_devices_data['devices_project_info'][device].keys():
                str += '\n\tApp: {}, project information: {}'.format(app,
                                                                     self.parsed_devices_data['devices_project_info'][
                                                                         device][app])
                self.logger.info(str)

    def author_check(self):
        self.logger.debug('executing block author check')
        for device in self.parsed_devices_data['devices_project_info'].keys():
            str = f'Check projects authors for IP: {device}'
            for app in self.parsed_devices_data['devices_project_info'][device].keys():
                project_info = self.parsed_devices_data['devices_project_info'][device][app]
                if 'author' in project_info.keys():
                    str += '\n\tApp: {}, author: {}'.format(app, project_info['author'])
                else:
                    str += '\n\tNo author found for app: {}'.format(app)
                self.logger.info(str)
