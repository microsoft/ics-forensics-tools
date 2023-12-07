import os
import json
from pathlib import Path
from base64 import b64decode
from forensic.interfaces.analyzer import AnalyzerInterface, AnalyzerCLI
from forensic.analyzers.s7.mc7.mc7_parser import MC7Parser
from forensic.common.stream.stream import StreamNotEnoughData
from forensic.plugins.s7.s7_szl import SZL_INDEX_NAMES


class S7RawFileParserCLI(AnalyzerCLI):
    def flags(self, parser):
        pass


class S7RawFileParser(AnalyzerInterface):
    def __init__(self, config, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.plugin_name = 'S7'
        self.create_output_dir(self.plugin_name)

    def parse_blocks(self, parsed_slot_rack, blocks):
        for block_name, block in blocks.items():
            try:
                parsed_slot_rack["blocks"].append(MC7Parser().parse(b64decode(block["data"].encode())))
            except StreamNotEnoughData:
                self.logger.error(f'Stream not enough data for block: {block_name}')

    def parse_szl(self, parsed_slot_rack, szl_values):
        for szl_id, szl_value_list in szl_values.items():
            for szl_value in szl_value_list:
                try:
                    if 'index' in szl_value:
                        szl_index_name = SZL_INDEX_NAMES[szl_id][szl_value['index']]
                        szl_value.pop('index')
                    else:
                        szl_index_name = SZL_INDEX_NAMES[szl_id][-1]
                    parsed_slot_rack['identity'].update({szl_index_name: szl_value})
                except Exception as e:
                    self.logger.exception(e)

    def analyze(self):
        device_dir = self.output_dir.parent.joinpath('S7RawFileParser')
        for device in os.listdir(device_dir):
            parsed_device = []
            self.logger.info(f'Loading file: {device}')
            with open(device_dir.joinpath(device), 'r') as f:
                device_output = json.load(f)
            parsed_slot_rack = dict()
            for slot_rack in device_output:
                parsed_slot_rack = {"slot": slot_rack["slot"], "rack": slot_rack["rack"], "identity": dict(),
                                    "blocks": []}
                self.parse_szl(parsed_slot_rack, slot_rack["szl"])
                self.parse_blocks(parsed_slot_rack, slot_rack["blocks"])
            if parsed_slot_rack:
                parsed_device.append(parsed_slot_rack)
            with open(self.output_dir.joinpath(device), 'w') as f:
                json.dump(parsed_device, f, indent=4, default=str)
