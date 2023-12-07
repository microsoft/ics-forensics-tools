import os
import json
import networkx as nx
from pathlib import Path
from forensic.interfaces.analyzer import AnalyzerInterface, AnalyzerCLI


class RockwellRslogixRawFileParserCLI(AnalyzerCLI):
    def flags(self, parser):
        pass


class RockwellRslogixRawFileParser(AnalyzerInterface):
    def __init__(self, config, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.plugin_name = 'RockwellRslogix'
        self.create_output_dir(self.plugin_name)

    @staticmethod
    def _get_calling_task_by_program_instance(tasks: list, program_instance: int) -> str:
        for task in tasks:
            if program_instance in task['programs_instances']:
                return 'Task:' + task['name']
        return 'Task:Unknown'

    @staticmethod
    def _parse_project_flow(device_output_dir: str, device_output: dict):
        call_graph_dir = os.path.join(device_output_dir, "call_graph")
        Path(call_graph_dir).mkdir(parents=True, exist_ok=True)

        module_count = 1
        for module in device_output:
            nx_graph = nx.DiGraph()
            nx_graph.add_nodes_from(map(lambda task: 'Task:' + task['name'], module['tasks']))
            if 'programs' in module.keys():
                for program in module['programs']:
                    program_name = 'Program:{}'.format(program['name'])
                    nx_graph.add_node(program_name)
                    calling_task_name = RockwellRslogixRawFileParser._get_calling_task_by_program_instance(
                        module['tasks'], program['instance'])
                    nx_graph.add_edge(calling_task_name, program_name)
                    for routine in program['routines']:
                        routine_name = 'Routine:{}'.format(routine['name'])
                        nx_graph.add_node(routine_name)
                        nx_graph.add_edge(program_name, routine_name)

            nx.write_gexf(nx_graph, os.path.join(call_graph_dir, f'module_{module_count}.gexf'))
            module_count += 1

    def analyze(self):
        raw_device_dir = self.output_dir.parent.joinpath('RockwellRslogixRawFileParser')
        for device_ip_str in os.listdir(raw_device_dir):
            device_ip = device_ip_str.replace('_', '.')
            device_output_dir = os.path.join(raw_device_dir, device_ip_str)
            self.logger.info('Loading file: ' + os.path.join(device_output_dir, device_ip_str + '.json'))
            with open(os.path.join(device_output_dir, device_ip_str + '.json'), 'r') as f:
                device_output = json.load(f)
            self._parse_project_flow(device_output_dir, device_output)
            self.logger.info(f'The device: {device_ip} was analyzed and the results at: {raw_device_dir}')
