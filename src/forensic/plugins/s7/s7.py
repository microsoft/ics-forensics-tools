import json
import socket
from tenacity import retry, retry_if_exception_type, stop_after_attempt
from pathlib import Path
from forensic.plugins.s7.s7_client import S7Conn, InvalidS7RackSlot
from forensic.plugins.s7.s7_parser import S7Error
from forensic.common.constants.constants import Transport
from forensic.interfaces.plugin import PluginInterface, PluginConfig, PluginCLI
from forensic.common.stream.stream import data_struct_serializer
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict


class S7CLI(PluginCLI):
    def __init__(self, folder_name):
        super().__init__(folder_name)
        self.name = "S7"
        self.description = "S7 Plugin"
        self.port = 102
        self.transport = Transport.TCP

    def flags(self, parser):
        self.base_flags(parser, self.port, self.transport)


class S7(PluginInterface):
    def __init__(self, config: PluginConfig, output_dir: Path, verbose: bool):
        super().__init__(config, output_dir, verbose)
        self.MAX_RACK = config.parameters.get("max_racks", 8)
        self.MAX_SLOT = config.parameters.get("max_slots", 32)

    @retry(retry=(retry_if_exception_type(TimeoutError) | retry_if_exception_type(S7Error)), stop=stop_after_attempt(3))
    def _conn(self, files, address, rack, slot):
        try:
            address = address["ip"]
            with S7Conn(self.logger, address, self.config.port, rack, slot) as s7:
                data = s7.dump_plc()
                if data:
                    files[address].append(data)
                    self.logger.info(f'Successfully connected to IP: {address}, '
                                     f'Port: {self.config.port}, Rack: {rack}, Slot: {slot}')
        except InvalidS7RackSlot:
            self.logger.info(f'Invalid S7 rack slot for IP: {address}, '
                             f'Port: {self.config.port}, Rack: {rack}, Slot: {slot}')
        except socket.timeout:
            self.logger.info(f'Timeout error for IP: {address}, '
                             f'Port: {self.config.port}, Rack: {rack}, Slot: {slot}')
            raise TimeoutError
        except ConnectionResetError:
            self.logger.info(f'Connection reset error for IP: {address}, '
                             f'Port: {self.config.port}, Rack: {rack}, Slot: {slot}')
        except Exception as e:
            self.logger.exception(f'{e} for IP: {address}, '
                                  f'Port: {self.config.port}, Rack: {rack}, Slot: {slot}')
            raise S7Error

    def connect(self, address: str):
        files = defaultdict(list)
        with ThreadPoolExecutor(max_workers=30) as executor:
            for rack in range(0, self.MAX_RACK):
                for slot in range(0, self.MAX_SLOT):
                    executor.submit(self._conn, files, address, rack, slot)
        return files

    def export(self, extracted):
        super().export(extracted)
        raw_files_dir = self.output_dir.joinpath('S7RawFileParser')
        raw_files_dir.mkdir(parents=True, exist_ok=True)

        for addresses in extracted:
            for address, data in addresses.items():
                file_name = f'{address.replace(".", "_")}.json'
                with open(raw_files_dir.joinpath(file_name), 'w') as f:
                    f.write(json.dumps(data, default=data_struct_serializer, indent=4))
