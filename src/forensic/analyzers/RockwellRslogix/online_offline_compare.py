import os
import socket
import json
from typing import Union
from pathlib import Path
from forensic.analyzers.RockwellRslogix.acd.project_file import ACDFile
from forensic.analyzers.RockwellRslogix.structs import ComparedRoutine
from forensic.analyzers.RockwellRslogix.acd.dat_parser import Controller, Program
from forensic.common.stream.stream import data_struct_serializer
from forensic.interfaces.analyzer import AnalyzerInterface, AnalyzerConfig, AnalyzerCLI


class RockwellRslogixOnlineOfflineCompareCLI(AnalyzerCLI):
    def flags(self, parser):
        parser.add_argument('--compare_ip', help='PLC IP to be compared')
        parser.add_argument('--project_file', help='Path to the project (ACD file)')


class RockwellRslogixOnlineOfflineCompare(AnalyzerInterface):
    def __init__(self, config: AnalyzerConfig, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.plugin_name = 'RockwellRslogix'
        self.create_output_dir(self.plugin_name)

    def analyze(self) -> None:
        ip = self.config.parameters.get("compare_ip")
        project_file = self.config.parameters.get("project_file")
        if not ip:
            self.logger.debug(f'Please provide a PLC IP address using --compare_ip.')
            return
        if not project_file:
            self.logger.debug(f'Please provide a project file path using --project_file.')
            return
        if not os.path.exists(project_file):
            self.logger.debug(f'The specified project file does not exist.')
            return
        if not is_valid_ip(ip):
            self.logger.debug(f'Please provide a valid PLC IP address using --compare_ip.')
            return
        self.logger.info(
            f'Starting online/offline project comparison: online programs from: {ip}, project file path: {project_file}')
        online_data = self.get_device_data(ip)
        if not online_data:
            raise Exception(f'No programs to compare were found for given ip: {ip}')
        acd_file = ACDFile(project_file, self.logger)
        offline_data = acd_file.get_controller()
        compared_routines = self.compare_routines_from_projects(online_data, offline_data)
        self.export_compare_results(ip, project_file, compared_routines, self.output_dir)

    def load_device_data(ip) -> Union[dict, None]:
        # Load data from a JSON file corresponding to the device's IP address
        # Convert IP address to a valid file name by replacing dots with underscores
        file_name = ip.replace('.', '_') + '.json'
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                device_data = json.load(file)
                return device_data
        else:
            return None

    def compare_routines_from_projects(self, online_data: dict, offline_data: Controller) -> list[ComparedRoutine]:
        # Compare the high level data from the online and offline projects
        # Return a list of differences
        compared_routines = []

        for online_controller in online_data:
            # Need to find the controller in the right slot that matches the offline data
            if online_controller["Identity"]["project_name"] == offline_data.name:
                for online_program in online_controller["programs"]:
                    if (
                            program_index := self.find_program_in_offline_project(online_program["name"],
                                                                                  offline_data)) == -1:
                        self.logger.info(
                            f"Program {online_program['name']} was found in the online project but not in the offline project.")
                        for routine in online_program["routines"]:
                            compared_routines.append(
                                ComparedRoutine(online_program["name"], routine["name"], "Online Only"))
                    else:
                        for routine in online_program["routines"]:
                            if (routine_index := self.find_routine_in_offline_program(routine["name"],
                                                                                      offline_data.programs[
                                                                                          program_index])) == -1:
                                compared_routines.append(
                                    ComparedRoutine(online_program["name"], routine["name"], "Online Only"))
                            else:
                                compared_routines.append(
                                    ComparedRoutine(online_program["name"], routine["name"], "Online and Offline",
                                                    offline_code=offline_data.programs[program_index].routines[
                                                        routine_index].get_code()))

        return compared_routines

    def find_program_in_offline_project(self, online_program_name: str, offline_project: Controller) -> bool:
        for idx, offline_program in enumerate(offline_project.programs):
            if online_program_name == offline_program.name:
                return idx
        return -1

    def find_routine_in_offline_program(self, online_routine_name: str, offline_program: Program) -> bool:
        for idx, offline_routine in enumerate(offline_program.routines):
            if online_routine_name == offline_routine.name:
                return idx
        return -1

    def export_compare_results(self, ip: str, project_file: str, compared_routines: list[ComparedRoutine],
                               output_dir: Path):
        # Export the list of compared routines to a JSON file
        # Convert IP address to a valid file name by replacing dots with underscores
        project_name = os.path.basename(project_file)
        file_name = ip.replace('.', '_') + f'_proj-{project_name}.json'
        out_path = output_dir.joinpath(file_name)

        compare_results = {"ip": ip, "project_file": project_file, "compared_routines": compared_routines}

        with open(out_path, 'w') as file:
            json.dump(compare_results, file, default=data_struct_serializer, indent=4)
            self.logger.info(f'Comparison results exported to {out_path}')

    def get_device_data(self, ip: str) -> Union[dict, None]:
        # Load the extracted project data from a JSON file corresponding to the device's IP address
        device_ip = ip.replace('.', '_')
        raw_device_dir = self.output_dir.parent.joinpath('RockwellRslogixRawFileParser')
        device_output_dir = os.path.join(raw_device_dir, device_ip, device_ip + '.json')
        if os.path.exists(device_output_dir):
            with open(device_output_dir, 'r') as file:
                device_data = json.load(file)
                return device_data
        else:
            return None


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False
