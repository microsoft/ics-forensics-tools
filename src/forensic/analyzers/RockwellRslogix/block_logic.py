import os
import json
from pathlib import Path
from forensic.interfaces.analyzer import AnalyzerInterface, AnalyzerCLI


class RockwellRslogixBlockLogicCLI(AnalyzerCLI):
    def flags(self, parser):
        parser.add_argument('--logic_all', help='Execute all logics for RockwellRslogixBlockLogic analyzer',
                            action='store_true')
        parser.add_argument('--logic_project_info',
                            help='Execute project info logic for RockwellRslogixBlockLogic analyzer',
                            action='store_true')
        parser.add_argument('--logic_tasks', help='Execute tasks logic for RockwellRslogixBlockLogic analyzer',
                            action='store_true')


class RockwellRslogixBlockLogic(AnalyzerInterface):
    def __init__(self, config, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.plugin_name = 'RockwellRslogix'

        self.create_output_dir(self.plugin_name)
        self.parsed_devices_data = self.get_parsed_devices_data()

    def analyze(self):
        if self.parsed_devices_data:
            logic_all = self.config.parameters.get("logic_all")
            logic_project_info = self.config.parameters.get("logic_project_info")
            logic_tasks = self.config.parameters.get("logic_tasks")

            self.logger.info('Start executing block logics')

            if logic_all or logic_project_info:
                self.project_info_check()
            if logic_all or logic_tasks:
                self.tasks_check()

    def get_parsed_devices_data(self):
        devices_dir = self.output_dir.parent.joinpath('RockwellRslogixRawFileParser')
        if not devices_dir.is_dir():
            self.logger.error('Please run RockwellRslogixRawFileParser analyzer first')
            return {}
        devices_project_info = {}
        devices_tasks = {}

        for device in os.listdir(devices_dir):
            device_ip = Path(device.replace('_', '.')).stem
            devices_project_info[device_ip] = []
            devices_tasks[device_ip] = []
            with open(os.path.join(devices_dir, device, device + '.json'), 'r') as f:
                device_ext_data = json.load(f)
            for module in device_ext_data:
                devices_project_info[device_ip].append(module["Identity"])
                if 'tasks' in module.keys():
                    devices_tasks[device_ip].append(module['tasks'])

        return {'devices_project_info': devices_project_info, 'devices_tasks': devices_tasks}

    def tasks_check(self):
        self.logger.debug('executing tasks check')
        for device in self.parsed_devices_data['devices_tasks'].keys():
            str = f'Check projects info for IP: {device}'
            module_count = 1
            for module in self.parsed_devices_data['devices_tasks'][device]:
                str += '\n\tModule: {}'.format(module_count)
                for task in module:
                    str += '\n\t\tTask details: {}'.format(task)
                module_count += 1
            self.logger.info(str)

    def project_info_check(self):
        self.logger.debug('executing project information check')
        for device in self.parsed_devices_data['devices_project_info'].keys():
            str = f'Check projects info for IP: {device}'
            module_count = 1
            for module in self.parsed_devices_data['devices_project_info'][device]:
                str += '\n\tModule {}, project information:'.format(module_count)
                for attr in module.keys():
                    str += '\n\t\t{}: {}'.format(attr, module[attr])
                module_count += 1
            self.logger.info(str)
