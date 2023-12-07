import os
import glob
import struct
import json
import pandas as pd
from pathlib import Path
from forensic.interfaces.analyzer import AnalyzerInterface, AnalyzerCLI


class S7OnlineOfflineCompareCLI(AnalyzerCLI):
    def flags(self, parser):
        parser.add_argument('--compare_ip', help='PLC IP with online blocks to compare')
        parser.add_argument('--project_dir', help='Offline projects directory (optional)')
        parser.add_argument('--project_name', help='Offline project directory name (optional)')


class S7OnlineOfflineCompare(AnalyzerInterface):
    def __init__(self, config, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.plugin_name = 'S7'
        self.create_output_dir(self.plugin_name)

    def analyze(self):
        project_dir_path = self.config.parameters.get("project_dir")
        ip = self.config.parameters.get("compare_ip")
        project_name = self.config.parameters.get("project_name")
        if not project_dir_path:
            project_dir_path = r"C:\ProgramData\Siemens\Automation\Step7\S7Proj"
        if not os.path.exists(project_dir_path):
            self.logger.debug(f'Projects directory: {project_dir_path} does not exist. use --offline_project_dir to change directory path')
            return
        if not ip:
            self.logger.debug(f'IP to compare not provided. use --compare_ip')
            return
        self.logger.info(f'Start offline/online project comparison: online blocks from: {ip}, projects directory path: {project_dir_path}')
        blocks =  self.get_device_raw_data(ip)
        if not blocks:
            self.logger.debug('No blocks to compare were found for given ip: {}'.format(ip))
            return

        if not project_name:
            self.logger.debug('No project directory name was given: compare to all found project directories')
            projects = glob.glob(project_dir_path)
        else:
            project_path = os.path.join(project_dir_path, project_name)
            if not os.path.exists(project_path):
                self.logger.error('Project path: {} does not exist'.format(project_path))
                return
            projects = [project_path]

        for project_path in projects:
            self.logger.debug('Compare to project: {}'.format(os.path.join(project_path)))
            offline_project_files_path = os.path.join(project_path, 'ombstx', 'offline', '*')
            self.compare_project(ip, blocks, project_path, offline_project_files_path, self.output_dir)

        if projects:
            self.logger.debug('Comparison results were saved at: {}'.format(self.output_dir))

    def get_device_raw_data(self, device_ip):
        parsed_data = []
        device_dir = self.output_dir.parent.joinpath('S7RawFileParser')
        device_file = f"{device_ip.replace('.', '_')}.json"
        with open(device_dir.joinpath(device_file), 'r') as f:
            device_output = json.load(f)
        for slot_rack in device_output:
            row_prefix = {'ip': device_file, 'rack': slot_rack['rack'], 'slot': slot_rack['slot']}
            if slot_rack['identity']:
                df = pd.json_normalize(slot_rack['identity'], sep='_')
                row_prefix.update(df.to_dict(orient='records')[0])
            self.logger.info(f'loading blocks: {device_ip}')
            for block in slot_rack['blocks']:
                df = pd.json_normalize(block, sep='_')
                block_row = df.to_dict(orient='records')[0]
                block_row.update(row_prefix)
                parsed_data.append(block_row)

        return parsed_data

    @staticmethod
    def get_ip_blocks(ip, parsed_devices_data):
        ip_blocks = []
        if parsed_devices_data:
            ip_rows = list(filter(lambda row: row['ip'] == ip, parsed_devices_data))
            if ip_rows:
                ip_blocks = list(map(lambda row: row['blocks'], ip_rows))
        return ip_blocks

    @staticmethod
    def extract_offset(blocks_data, offset):
        if offset:
            offset = int(offset)
            padding = struct.unpack('<H', blocks_data[offset * 512 + 2:offset * 512 + 4])[0]
            size = struct.unpack('<I', blocks_data[offset * 512 + 4:offset * 512 + 8])[0]
            return blocks_data[offset * 512 + 8:offset * 512 + 8 + size - padding]
        return b''

    def extract_blocks(self, path):
        res = []
        if os.path.exists(os.path.join(path, 'SUBBLK.DBT')) and os.path.join(path, 'SUBBLK.DBF'):
            with open(os.path.join(path, 'SUBBLK.DBT'), 'rb') as f:
                blocks_data = f.read()
            with open(os.path.join(path, 'SUBBLK.DBF'), 'rb') as f:
                f.read(833)
                data = f.read(192)
                while len(data) == 192:
                    # block_type = int(data[17:22])
                    # block_num = int(data[22:27])
                    offset1 = self.extract_offset(blocks_data, data[162:172].strip())
                    offset2 = self.extract_offset(blocks_data, data[172:182].strip())
                    offset3 = self.extract_offset(blocks_data, data[182:192].strip())
                    block_data = offset1 + offset2 + offset3
                    res.append(block_data.hex())
                    data = f.read(192)

        return res

    def compare_project(self, ip, blocks, project_path, offline_project_files_path, block_comparison_directory):
        all_offline_blocks_data = []
        for path in glob.glob(offline_project_files_path):
            all_offline_blocks_data += self.extract_blocks(path)

        res = {'ip': ip, 'project_path': project_path, 'online_blocks': dict()}

        for block in blocks:
            block_row = dict.fromkeys(['type', 'can_compare', 'match_to_offline'])
            block_row['block_type'] = block['type']
            block_row['can_compare'] = False
            block_row['match_to_offline'] = False

            if block['type'] in ('FB', 'FC', 'OB'):
                block_row['can_compare'] = True
                if 'interface_len' in block.keys():
                    block_size = block['interface_len'] + block['segment_length'] + block['mc7_length']
                else:
                    block_size = block['body_length'] + block['segment_length'] + block['data_length']
                if block['data'] not in list(
                        map(lambda offline_block: offline_block[block_size:], all_offline_blocks_data)):
                    block_row['match_to_offline'] = True

            block_id = block['type'] + '_' + str(block['block_num'])
            res['online_blocks'][block_id] = block_row

        ip_str = ip.replace('.', '_')
        with open(os.path.join(block_comparison_directory,
                               'ip-{}_proj-{}'.format(ip_str, os.path.basename(project_path))),
                  'w') as f:
            json.dump(res, f)