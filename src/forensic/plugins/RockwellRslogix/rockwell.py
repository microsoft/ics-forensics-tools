import os
import json
from pathlib import Path
from collections import defaultdict
from forensic.interfaces.plugin import PluginInterface, PluginConfig, PluginCLI
from forensic.common.constants.constants import Transport
from forensic.plugins.RockwellRslogix.rockwell_client import LogixConn, ModuleComm
from forensic.common.stream.stream import data_struct_serializer


class LogixCLI(PluginCLI):
    def __init__(self, folder_name):
        super().__init__(folder_name)
        self.name = "RockwellRslogix"
        self.description = "Rockwell Rslogix Plugin"
        self.port = 44818
        self.transport = Transport.TCP

    def flags(self, parser):
        self.base_flags(parser, self.port, self.transport)


class Logix(PluginInterface):
    def __init__(self, config: PluginConfig, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)

    def connect(self, address):
        files = defaultdict(list)
        self._conn(files, address)
        self.logger.info(f"{self.config.name} connect")
        return files

    def _conn(self, files, address):
        path = "{}:{}".format(address["ip"], self.config.port)

        with LogixConn(self.logger, path) as plc:
            modules = plc.modules
            for module in modules:
                self.logger.info(f"Module: {module}")
                module_comm = ModuleComm(self.logger, plc.conn, module, plc.all_user_tags)
                data = module_comm.dump_module()
                if data:
                    files[address["ip"]].append(data)
                    self.logger.info(f'Successfully connected to IP: {address["ip"]}, '
                                     f'TCPPort: {self.config.port}')

    def export(self, extracted):
        super().export(extracted)
        raw_files_dir = self.output_dir.joinpath('RockwellRslogixRawFileParser')
        raw_files_dir.mkdir(parents=True, exist_ok=True)

        for addresses in extracted:
            for address, data in addresses.items():
                address_str = address.replace(".", "_")
                address_dir = Path(os.path.join(raw_files_dir, address_str))
                address_dir.mkdir(parents=True, exist_ok=True)
                with open(os.path.join(address_dir, f'{address_str}.json'), 'w') as f:
                    f.write(json.dumps(data, default=data_struct_serializer, indent=4))
